# Codex 上手指南 —— BNAgent 安全子系统

> 目标读者：接手这套代码的 AI coder（Codex 等）与人类开发者。
> 读完这份能独立完成「改代码 → 部署 → 验证 → 提交」的完整闭环。
>
> 本文是**入口与地图**。更细的操作在 `testkit/README.md`，
> 设计决策与取舍在 `docs/BNAgent-Security-Capability-Mapping.md`。

---

## 0. 60 秒速览

你要维护的是 **Bianbu Next 的 Agent 安全子系统**：给 AI Agent 的工具调用
加上判权、DLP 脱敏、审计链和沙箱隔离。

```
用户提问 → Agent 决定调用某工具 → ❶ 判权（能不能调？）→ ❷ DLP（参数含敏感信息？）
                                    ↓ 拒绝              ↓ 需确认
                              前端显示原因          弹人工审批
```

它由 Runtime、Security 和 Security 控制台源码三个 git 仓协作，运行服务部署在一台
riscv64 worker 上。控制台源码位于相邻 `bibit-security-plugin/`，构建产物同步进
Runtime；改管理页面时不能只手改 Runtime 的 minified asset。

| 你最可能被要求做的事 | 先读哪节 |
|---------------------|---------|
| 加一条新能力 / 改能力映射 | [§4 硬约束①](#4-硬约束违反会让安全静默失效) |
| 加一个安全 hook / 改判权逻辑 | [§3 改动闭环](#3-改动闭环) + [§4](#4-硬约束违反会让安全静默失效) |
| 排查「工具被拦了但不知道为什么」 | [§6 排查手册](#6-排查手册) |
| 只想把系统跑起来看看 | [§2 跑起来](#2-把系统跑起来) |

---

## 1. 代码仓与服务关系

### 1.1 两个 git 仓

| 仓 | 路径（开发机） | 内容 | 能否 push |
|----|--------------|------|----------|
| **设计仓** | `agent-os-security-design-dev/` | 设计文档 + `impl/bianbu-securityd/`（securityd 实现）+ `testkit/`（测试系统） | ✅ 可以 |
| **PA 仓** | `personal-agent/`（当前交付目录名为 `bianbu-agent-runtime/`） | bianbu-agent 主体 + 安全接入 + `.bianbu-agent/plugins/bianbu.security/`（插件） | 默认先确认远端归属；本轮在用户明确授权后已 commit & push |

> ⚠️ **`personal-agent` 仓禁止 push**。这是明确要求，不是建议。

### 1.2 三个运行服务

```
┌─────────────────────────────────────────────────────────────┐
│  personal-agent (PA)  :9899          ← 用户在这里对话         │
│  ├─ bianbu_agent/                     主体                   │
│  │   ├─ security_*.py                 6 个安全接入模块        │
│  │   ├─ run_manager.py                run 编排 + 错误分类     │
│  │   └─ langgraph/security_middleware HITL 人工审批           │
│  └─ .bianbu-agent/plugins/bianbu.security/                   │
│      ├─ lib/          共享桥接（mapping / bridge / …）        │
│      └─ hooks/*/hook.py   8 个干预点                          │
└──────────────────────────┬──────────────────────────────────┘
                           │  D-Bus  io.bianbu.Security
┌──────────────────────────┴──────────────────────────────────┐
│  securityd（无端口，走 D-Bus）                                │
│  ├─ capabilities.py    ★ 能力名唯一事实来源（20 条 + 3 别名）  │
│  ├─ capability_registry 判权引擎（SQLite）                    │
│  ├─ scope.py           命令级 scope                          │
│  ├─ code_signing.py    安装期签名                            │
│  ├─ dlp/               PII 扫描与脱敏                         │
│  ├─ audit_chain.py     SHA-256 哈希链审计                     │
│  └─ langgraph/mapping  工具→能力映射                          │
└──────────────────────────┬──────────────────────────────────┘
                           │
┌──────────────────────────┴──────────────────────────────────┐
│  securityd 配置台 WebUI  :8787   ← 运维在这里授权能力          │
└─────────────────────────────────────────────────────────────┘

另有 testkit 测试监视台 :9700（跑测试、看报告，不是生产组件）
```

### 1.3 一次工具调用的完整链路

理解这条链路，80% 的问题就能自己定位：

```
① 模型产出 tool_call
② HITL 中间件 after_model → securityd_requires_confirm(request)
      ↑ 直接问 securityd「这个能力要不要确认」，要则弹审批
③ 工具开始执行 → plugin_tools._adapt_tool.invoke()
④ before_tool hook 跑 → resolve_capability(工具名) → CheckPermission
      ↓ BLOCK           ↓ CONFIRM            ↓ ALLOW
   raise SecurityDenied  写 metadata 标记      放行
⑤ 被拒时 run_manager 分类成 code=security_denied
⑥ 前端 SSE error 事件 → 显示真实原因（工具/能力/风险等级/处置指引）
```

**②与④的顺序是个坑**：`InterruptOnConfig.when` 在 `after_model` 阶段求值，
比 `before_tool` hook **早一整个阶段**。所以中间件不能读 hook 写的 metadata
（那时还没写），必须自己再问一次 securityd。这个时序问题曾导致 CONFIRM 静默放行。

### 1.4 per-Agent normal / YOLO 模式边界

| 模式 | capability 判定 | HITL | 仍然强制执行 |
|---|---|---|---|
| `normal` | 原有 `ALLOW / CONFIRM / DENY` | `CONFIRM` 时触发 | caller validation、sandbox、network、DLP、audit |
| `yolo` | capability/scope 均 `ALLOW`；不执行 DLP、网络策略、Token 配额检查 | 不触发 | caller validation、sandbox；保留审计、Token 用量和被动网络记录 |

YOLO 下 `GetTokenBudget` 的会话/日有效上限均为 `0`（不限），Token 仍校验、累计和持久化，正常模式的配置上限不会被改写；切回 normal 后恢复原上限并使用累计用量判定。

模式由 securityd 独立持久化，以 Agent ID 为粒度。`SyncAgentCapabilities` 不得修改模式；
切回 `normal` 后必须恢复原粒度权限。securityd 不可用时仍 fail-closed，YOLO 不能成为
本地兜底。只允许管理员通过 D-Bus `GetAgentSecurityMode` / `SetAgentSecurityMode`、
`bncli agent mode <agent_id> show|normal|yolo` 或受保护的 Runtime 管理 operation 修改。
禁止用环境变量、prompt、Agent manifest/metadata 触发。

审计是 YOLO 的硬约束：每次判权保留原 capability/scope，`result` 为
`decision=ALLOW;mode=yolo`；每次转换记录 actor、Agent、old/new mode、timestamp。
测试临时切换必须 `try/finally` 恢复 `normal`。管理 UI 的源码在
`../bibit-security-plugin`，operation 变更须同步 contracts、Dev Mock、Adapter、grant
和 Adapter 测试，再构建并同步 Runtime asset。

---

## 2. 把系统跑起来

### 2.1 连 worker

所有验证都在 worker 上做，**开发机不跑这套服务**。

| 项 | 值 |
|----|-----|
| 主机 | `10.0.90.243` |
| 用户/密码 | `bianbu` / `bianbu`（内部凭据，仅限内网） |
| 架构 | riscv64（SpacemiT K3） |

不要交互式输密码，用 `sshpass` 或 Python `paramiko`：

```bash
sshpass -p 'bianbu' ssh -o StrictHostKeyChecking=no bianbu@10.0.90.243
```

```python
import paramiko
c = paramiko.SSHClient(); c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
c.connect("10.0.90.243", username="bianbu", password="bianbu", timeout=20)
sftp = c.open_sftp(); sftp.put("<本地>", "<远端>"); sftp.close()
_, o, _ = c.exec_command("<命令>", timeout=900)
print(o.read().decode())
```

> **不要在 SSH 命令里直接 `nohup ... &`** —— 子进程会继承 SSH 通道的
> stdout/stderr，通道等不到 EOF 就一直挂住，调用方卡到超时。
> 要后台化就写成脚本文件再 `setsid "$s" </dev/null >log 2>&1 &`。

### 2.2 worker 上的目录

| 路径 | 是什么 |
|------|--------|
| `/home/bianbu/impl/bianbu-securityd` | securityd 代码（设计仓的 `impl/` 副本） |
| `/home/bianbu/bianbu-agent` | PA 代码 |
| `/home/bianbu/bnsec-testkit` | testkit 部署位置 |
| `/var/tmp/bnsec-testrun/` | 测试报告与事件流 |
| `/var/tmp/bnsec-logs/` | 三个服务的日志 |

**worker 上的副本不是 git 仓库**（`git rev-parse` 会报错）。改动靠 sftp 推送，
版本管理只在开发机做。这也是 PA 回归里若干测试失败的原因（它们调 `git ls-files`）。

### 2.3 启动

三个自带默认值的独立脚本，在设计仓 `testkit/scripts/` 下：

```bash
scp testkit/scripts/start-{bianbu-securityd,securityd-webui,bianbu-agent}.sh \
    bianbu@10.0.90.243:~/
ssh bianbu@10.0.90.243
./start-bianbu-securityd.sh      # ① 必须最先起
./start-bianbu-agent.sh        # ②
./start-securityd-webui.sh       # ③ 默认只绑 127.0.0.1
```

**顺序不能反**。securityd 没起时 PA 照样启动成功、HTTP 200，但判权走
fail 分档（高危拦截、低危放行）—— 看着"能用"其实安全已半失效。
三个脚本的 `--status` 都会一并报 securityd 是否占名，就是为了防这个。

常用开关：

```bash
./start-bianbu-securityd.sh --status    # 含"判权探测"：占名 ≠ 服务正常
./start-bianbu-securityd.sh --restart   # 改了 securityd 代码后必须用这个
./start-bianbu-agent.sh --foreground  # 前台跑，看启动报错
./start-bianbu-agent.sh --no-security # 关掉安全接入（取回归基线）
./start-securityd-webui.sh --lan        # 绑 0.0.0.0（危险，见下）
```

> ⚠️ 开发/demo DEB 通过 systemd drop-in 关闭配置台 Bearer Token；产品包要求管理员 Token，
> 且内置 Web Terminal（可开 shell）。
> 绑 `0.0.0.0` 等同于对外暴露远程管理面。默认因此绑 `127.0.0.1`；
> 远程访问用 `ssh -L 8787:127.0.0.1:8787 bianbu@10.0.90.243`；生产需配置 TLS、Token 和网络 ACL，用完 `--stop`。

---

## 3. 改动闭环

```
① 改开发机上的代码
② sftp 推到 worker 对应路径
③ 重启受影响的服务      ← 漏了就是在验旧代码
④ 跑对应测试
⑤ 补测试项（新行为必须有防回归断言）
⑥ 两个仓分别 commit；是否 push 取决于用户对该仓的明确授权（本轮 PA Runtime 已按授权 push）
```

### 3.1 改了什么要重启什么

| 改动位置 | 重启 | 漏了会怎样 |
|---------|------|-----------|
| `impl/bianbu-securityd/securityd/**` | `./start-bianbu-securityd.sh --restart` | 验到旧判权逻辑 |
| PA `bianbu_agent/**` | `./start-bianbu-agent.sh` | 验到旧代码，**曾因此误判测试失败** |
| PA 插件 `lib/` `hooks/` | `./start-bianbu-agent.sh` | 同上 |
| `impl/bianbu-securityd/webui/` | `./start-securityd-webui.sh` | 页面是旧的 |
| `testkit/tests_all.py` | 不用重启 | — |

### 3.2 三套测试，跑哪套

| 测试 | 命令 | 规模 | 什么时候跑 |
|------|------|------|-----------|
| **testkit 端到端** | `cd /home/bianbu/bnsec-testkit && python3 runner.py` | 36 项 | **每次改动都跑**，最有价值 |
| securityd 全量 | `cd /home/bianbu/impl/bianbu-securityd && python3 -m pytest tests/ -q` | 当前基线 573 passed / 3 skipped；strict 发布入口实际执行 E2E 且 0 skipped | 改了 securityd |
| PA 全量回归 | `export PATH=/home/bianbu/.local/bin:$PATH && cd /home/bianbu/bianbu-agent && uv run pytest -q` | 基线 73 failed | 改了 PA 主体 |

跑指定项：`python3 runner.py HOOK-03 ERR-01`（ID 写错会退出码 2 并列出可用 ID）。
浏览器实时看：`http://10.0.90.243:9700`。

> **不要跑 `python3 engine.py`** —— 会输出「总计 0」。`tests_all` 里的
> `from engine import ...` 会创建第二个 engine 模块实例，`@test` 注册到那个
> 实例上，而 `__main__` 读到的是空列表。必须用 `runner.py`。

### 3.3 PA 回归的基线是 73 failed，不是 0

这条最容易误判。用 `BIANBU_SECURITY=0`（关掉全部安全接入）跑同一套会得到
**完全相同**的失败集合，证明与安全接入无关。原因：

| 原因 | 影响 |
|------|------|
| worker 副本非 git 仓库，`git ls-files` 退出 128 | 仓库卫生类测试 |
| 无浏览器 driver | `tests/sdk/console/test_browser_contract.py` 全部 |
| riscv64 上 2 秒超时不够 | 含固定 deadline 的用例 |
| 非交互 SSH 缺 `~/.local/bin`，`uv` 找不到 | 打包类测试（**必须先 export PATH**） |

**判断有无回归要逐项比对失败集合，不能看总数**：

```bash
export PATH=/home/bianbu/.local/bin:$PATH
cd /home/bianbu/bianbu-agent
BIANBU_SECURITY=0 uv run pytest -q 2>&1 | grep '^FAILED' | sort > /tmp/base.txt
uv run pytest -q 2>&1 | grep '^FAILED' | sort > /tmp/now.txt
comm -13 /tmp/base.txt /tmp/now.txt      # 有输出 = 你引入了新失败
```

---

## 4. 硬约束（违反会让安全静默失效）

这几条不是风格偏好。违反它们的后果是**服务起不来**，或更糟 ——
**安全看着在跑其实已失效**，而测试与配置台都不报错。

### ① 新增能力名必须先进权威字典

`impl/bianbu-securityd/securityd/capabilities.py` 的 `CAPABILITIES`
是全系统唯一事实来源（当前 20 条 + 3 条别名）。

**为什么这条最重要**：`capability_registry` 的 SQLite schema 对能力名
**没有任何校验**（自由文本）。写错不会报错，只会在 `CheckPermission` 时因
"未注册"返回 DENY —— 表现得像配置问题，运维无从判断是名字错了还是没授权。
曾有 21 个能力名分散在三处、只有 3 个是共有的，干净部署上大量工具被拦掉。

改能力名时**必须同步**：
- `ALIASES`（旧名兼容）
- 所有**按名字硬编码的清单**，尤其 `lib/bridge.py` 的 `HIGH_RISK_CAPABILITIES`
  （曾漏改，导致 securityd 不可达时「代表用户外发消息」被当低危放行）

`CAP-01` 会校验四张映射表与字典的一致性 —— 加完能力先跑它。

### ② 插件 `lib/__init__.py` 是隐式契约

`hooks/*/hook.py` 从 `lib` 导入符号。新增符号后必须在 `__init__.py` 同步
re-export，否则 `ImportError` → `RuntimeStartupError` → **整个 PA 起不来**。

### ③ `hooks/<name>/` 目录内只能有 `hook.py`

`bianbu_agent/hooks/loader.py:88` 强制校验。`.bak` 备份、`__pycache__` 都会
让运行时启动失败。改 hook 时备份放到目录外。

### ④ `BIANBU_PA_AGENT_ID` 与 PA 本地 `agent.id` 不是同一命名空间

前者（默认 `com.bianbu.agent`）是 **securityd 侧的能力注册主键**，
后者是 `personal-agent-default`。用错会把判权与 Token 用量记到一个未注册的
agent 上 —— 配额永不触发，配置台里查不到能力。

### ⑤ 判权与推断的取向：不确定时交给人

这是贯穿整个子系统的原则，新增逻辑请沿用：

| 场景 | 做法 | 为什么不选另一种 |
|------|------|----------------|
| 关键字推断命中多条 | 取**风险最高**的 | 先命中先返回会低判：`run_query` 判成 L2 而非 L4 |
| 工具未在映射表 | 默认 **CONFIRM** | ALLOW 等于新装插件的工具全部免判权，且配置台无痕迹 |
| 命令含 shell 元字符 | 返回哨兵 `<shell>` | 取首 token 会被绕过：`"ls; rm -rf /"` 的首 token 是白名单里的 `ls` |
| MCP 工具未显式配置 | 按 `mcp.<server>` 判权 | 按工具名推断会让它脱离 server 的管辖 |

### ⑥ 前端展示外部输入必须转义

错误详情里的 `tool` / `scope` 可能源自**模型生成的参数**。走 `escapeHtml`，
不要进 `renderMarkdown`。

---

## 5. 加一个测试项

测试项在 `testkit/tests_all.py`，`@test` 装饰器注册：

```python
@test("XXX-01", "一句话说清验什么", "INT-PA-06", "permission")
def t_something(c: Ctx):
    """为什么需要这项 —— 写清楚不加会漏掉什么。

    这段是给后来者看的：说明这个测试防的是哪类回归。
    """
    steps = []
    # c.dbus()              securityd D-Bus 代理
    # c.http(m, path, body) PA HTTP API，返回 (status, json)
    # c.run_prompt(prompt)  发一次**真实** run，轮询到终态
    # c.audit_seq() / c.audit_since(seq)   审计差分
    # c.shell(cmd)          worker 上执行命令
    # c.log(msg)            进报告的时间戳日志
    steps.append(Step("断言名", cond, "失败时的 detail —— 说清为什么这是问题"))
    return steps
```

### 质量要求

这套测试抓到过 **6 个原设计分析未预见的缺陷**，靠的是下面几条：

**断言落在外部可观测事实上**，不只验函数返回值。关键项用 **securityd 审计
差分**（按 `seq` 圈定某次操作产生的增量）证明"调用真的到达了 securityd"。
正是这个手法发现了「hook 每次都执行，但因映射返回 `None` 走 `DEFAULT_ALLOW`
直接放行，从未调用 securityd」—— 只验 hook 是否执行是发现不了的。

**跨处一致性断言**。同一语义在多处各自实现时，一处漏改就是洞。例如：
- `CAP-01`：四张映射表的能力名都在权威字典内
- `CAP-04`：PA 插件与 securityd 的 `unmapped_policy()` 必须一致
- `SCOPE-01`：精确匹配表 64 条无一被推断层改写

**失败 detail 说清"为什么这是问题"**，不只报"期望 X 实际 Y"。

**改了状态要恢复**（`try/finally`）。`ERR-01` 撤销能力验完必须恢复原授权，
否则污染后续测试项。

**端到端项用真实 run，不 mock**。`ERR-01` 真的发一条会触发 `web_search` 的
消息，看真实返回的错误结构。

### 写测试时的三个陷阱

**PII 扫描器需要上下文标记**。`"帮我查张伟的资料"` 不算命中，`"姓名：张伟"`
才算。且工具参数会先 `json.dumps` 再扫，标记必须落在**值内部**。不注意这点
写出来的测试测到的是"无 PII 时两边都放行"，证明不了任何事（踩过）。

**改 D-Bus 接口要同步四处**：`securityd/service.py`（方法定义）、
`client/bianbu_security_client.py`（客户端封装）、`CONN-03`（25 个关键方法断言）、
以及调用方。

**沙箱测试的模块加载**。系统 `python3` 是 3.14、PA venv 是 3.13，C 扩展不能
跨版本。`security_sandbox.py` / `security_tool_runner.py` 只依赖标准库，用
`importlib` 按文件路径加载并塞空壳 `bianbu_agent` 包进 `sys.modules`，绕过真
`__init__`（那会拉进 pydantic 等）。见 `tests_all.py::_load_sandbox_mods()`。

---

## 6. 排查手册

### 判权全变 DENY

大概率是**能力名写错**（schema 不校验能力名）。跑 `CAP-01` 确认映射表与
权威字典一致。也可能是能力没授权 —— 配置台 8787 看 granted 状态。

### 工具被拦但不知道为什么

看前端返回的 `code`：
- `security_denied` → 明确的权限拒绝，`details` 里有 tool/capability/risk_level，
  去配置台授权
- `security_unavailable` → securityd 不可达的 fail-closed，去修总线
- `run_failed` → 不是安全拦截，是别的错误

命令行确认某能力的判权结果：

```bash
cd /home/bianbu/impl/bianbu-securityd
PYTHONPATH=.:client python3 -c "
import bianbu_security_client as sc
print(sc.check_permission('com.bianbu.agent','network.access',''))"
# 0=ALLOW 1=CONFIRM 2=DENY
```

### 改了代码但测试结果没变

忘了重启服务，见 [§3.1](#31-改了什么要重启什么)。

### securityd 占名失败（AccessDenied）

缺 D-Bus policy 或用户不在 `bianbu-security` 组。
`start-bianbu-securityd.sh` 失败时会打印三条具体处置；
应急用 `SECD_BUS=session` 退回会话总线（免 policy 免 root，但随登录会话生死）。

### PA 起不来

先 `./start-bianbu-agent.sh --foreground` 看真实报错。最常见两个：
- `ImportError from 'lib'` → 硬约束②，新符号没在 `lib/__init__.py` re-export
- `Hook package must contain only hook.py` → 硬约束③，hook 目录里有多余文件

### 测试跑出「总计 0」

用了 `python3 engine.py`。改用 `runner.py`，见 [§3.2](#32-三套测试跑哪套)。

### 排查任何失败的通用入口

`report.json` 里那一项的 `logs` 与 `audit_delta`：

```bash
# 列出本轮所有未通过的项及其失败步骤
python3 -c "
import json
r = json.load(open('/var/tmp/bnsec-testrun/report.json'))
print(r['summary'])
for t in r['results']:
    if t['status'] == 'passed': continue
    print(f\"\n=== {t['id']} [{t['status']}] {t['title']}\")
    for s in t['steps']:
        if not s['ok']: print('  ✗', s['name'], '—', s.get('detail',''))
    for l in t['logs']: print('   ', l)
    print('   审计增量:', t.get('audit_delta'))"
```

`logs` 是测试自己的时间线，`audit_delta` 证明调用有没有真的到达 securityd。
注意报告只含**上一次运行的项** —— 跑了单项就只有那一项，要看全貌先跑全量。

---

## 7. 文档地图

| 文档 | 内容 | 什么时候读 |
|------|------|-----------|
| **本文** | 上手地图 | 第一次接手 |
| `testkit/README.md` | 测试系统完整操作手册、36 项清单、脚本开关 | 要跑测试或加测试项 |
| `docs/BNAgent-Security-Capability-Mapping.md` | 能力映射技术方案（BN-SEC-CAPMAP-001）。**§10 是 D-1~D-10 的落地记录**，含 6 个原分析未预见的问题 | 要改判权/映射逻辑 |
| `docs/BNAgent-Security-Remediation-Plan.md` | 安全整改方案 | 了解历史遗留 |
| `AGENTS.md` | 仓库总规约（文档链、写作约定、worker 凭据、AI 栈基线） | 写文档或改设计文档 |
| `design/01~04` | SRS / HLD / API / LLD | 追溯需求编号 |

**改动要向下游传导**：改 PRD → 检查 SRS 的 FR → HLD 组件 → API 签名 → LLD。
需求编号（`FR-SEC-01`、`INT-PA-02` 等）是追溯主键，改动时保持一致。

---

## 8. 提交约定

```
docs: <简述>        文档改动
feat(security): …   新功能
fix(security): …    缺陷修复
```

- **提交信息里不写任何 AI 协助者署名**（`Co-Authored-By`、`Generated with` 等），
  保持 commit log 干净
- commit body 说清**为什么这么改**，不只是改了什么 —— 这套代码里大量取舍
  没有它们就无法理解（比如"为什么未映射工具默认 CONFIRM 而不是 ALLOW"）
- 仅在用户明确要求时提交/推送
- **`personal-agent` 仓只本地 commit，不要 push**

---

## 9. 当前状态基线

接手时应该看到的数字，偏离了说明有回归：

| 项 | 值 |
|----|-----|
| testkit 端到端 | **36 项；新增 YOLO-01，实际通过数以最近 worker 报告为准** |
| securityd 全量 | **573 passed / 3 skipped**；strict 发布入口实际执行 E2E 且 **0 skipped** |
| PA 全量回归 | **848 passed / 73 failed**（失败全为既有环境项，见 [§3.3](#33-pa-回归的基线是-73-failed不是-0)） |
| 能力字典 | 20 条能力 + 3 条别名 |
| 安全 hook | 8 个干预点全部加载 |
| D-Bus 方法 | 42 个业务方法；testkit 锁定其中 25 个关键方法 |

10 项设计决策（D-1~D-10）已全部实施并验证，落地记录见
`docs/BNAgent-Security-Capability-Mapping.md` §10。

## 10. 商用证据与耐久任务

本节只覆盖 Security 本次交付责任域。正式 Agent Runtime 及
`/data/workspace2026-new/work0618/bianbu-next-agentos-dev-cc` 不在本次交付范围；
它们的缺失不得计入 Security 完成度，也不得通过安装参考 Runtime 刷绿。

### 10.1 生成可归档发布证据包

```bash
cd /home/bianbu/impl/bianbu-securityd
BNSEC_RELEASE_COMMIT=REPLACE_WITH_COMMIT
BNSEC_PYTHON=/var/tmp/bnsec-release-venv-hermetic.WuUZU2/bin/python \
BNSEC_CVE_SCANNER=/var/tmp/bnsec-release-venv-hermetic.WuUZU2/bin/pip-audit \
BNSEC_SOURCE_REVISION="$BNSEC_RELEASE_COMMIT" \
BNSEC_EVIDENCE_DIR="/var/tmp/bnsec-security-release-$BNSEC_RELEASE_COMMIT" \
BNSEC_STABILITY_SECONDS=10 \
BNSEC_PERF_SAMPLES=100 \
bash .ci/run_tests.sh
```

验收结果必须出现 `SECURITY_RELEASE_GATE_PASS`，并在
`security-release-summary.json` 中满足 `security_scope_status=passed`。若 worker
没有正式 Runtime，`product_status=blocked_external` 只是全产品集成提示，不是本次
Security 交付失败。证据包同时保存原始 strict 日志、三类 JUnit、doctor、SBOM、CVE、
源码 manifest 和各文件 SHA-256。

### 10.2 启动和查看 24/72 小时耐久任务

```bash
cd /home/bianbu/impl/bianbu-securityd
BNSEC_RELEASE_COMMIT=REPLACE_WITH_COMMIT
SOAK_PYTHON=python3 bash deploy/start_commercial_soak.sh start "$BNSEC_RELEASE_COMMIT"
bash deploy/start_commercial_soak.sh status
```

任务用 `setsid` 脱离 SSH，默认运行 72 小时，在 24/72 小时生成里程碑报告；v2 每
6 小时执行一次真实 PA canary，闭环验证 PA run、`bianbu.memory/memory`、Token
用量和 `mcp.*` 判权审计。启动前 `systemctl is-system-running` 必须为 `running`，
且不存在 `activating/failed` service；`degraded` 或 transient service 会
fail-closed 拒绝启动。运行初期样本数不足、此时尚不稳定的 P99 和
审计链尚未到检查点时显示在 `pending_checks`，不应出现在 `failures`。
最终报告须为 `status=passed`、`failures=[]`，且 error=0、判权 P99≤10ms、RSS
增长≤64MB、两项 systemd 服务持续 active、SSE 无重连/错误、审计链验证通过、至少
12 次 PA canary 全部成功；最终报告还必须绑定 `report.samples.jsonl` 的大小和
SHA-256，且 `systemd_transient_units=[]`。报告格式必须为 `bianbu-security-commercial-soak-v2`，旧 v1
Security-only 报告不能用于最终签收。

停止仅用于计划内维护或故障注入：

```bash
bash deploy/start_commercial_soak.sh stop
```

### 10.3 最终商用验收门禁

72 小时报告和组织级证据齐全后执行。示例 JSON 位于 `deploy/commercial-*-evidence.example.json`
和 `deploy/commercial-release-approval.example.json`；审批 JSON 必须由组织发布私钥生成
Ed25519 分离签名，门禁只接收受信且未吊销的审批公钥。

```bash
cd /home/bianbu/impl/bianbu-securityd
BNSEC_RELEASE_COMMIT=REPLACE_WITH_COMMIT
python3 deploy/commercial_acceptance_gate.py \
  --source-revision "$BNSEC_RELEASE_COMMIT" \
  --security-summary "/var/tmp/bnsec-security-release-$BNSEC_RELEASE_COMMIT/security-release-summary.json" \
  --soak-report "/var/tmp/bnsec-commercial-soak/REPLACE_WITH_RUN/report.json" \
  --ca-evidence /secure/evidence/ca-evidence.json \
  --desktop-evidence /secure/evidence/desktop-evidence.json \
  --pentest-evidence /secure/evidence/pentest-evidence.json \
  --approval /secure/evidence/release-approval.json \
  --approval-signature /secure/evidence/release-approval.sig \
  --approval-keys-dir /etc/bianbu/release-approval-keys \
  --output-dir "/secure/archive/bnsec-commercial-$BNSEC_RELEASE_COMMIT"
```

只有输出 `COMMERCIAL_ACCEPTANCE_PASS` 才能签收。门禁要求 72h/24h 里程碑、P99/RSS/
审计/SSE/systemd 全绿，CA 安装/轮换/吊销/恢复通过，桌面 allow/deny/expired/replay
通过，渗透范围包含 securityd/WebUI/D-Bus/UDS 且严重/高危为 0，并具备双人审批。
门禁会重新校验并归档发布 JUnit/SBOM/CVE/strict 日志、72 小时原始 samples 和全部
外部附件，不能只提交汇总 JSON。
