# BNAgent Security 测试系统

securityd（判权/DLP/审计/沙箱）与 personal-agent（PA）安全接入的端到端验证。
通过 PA 的 HTTP API + securityd 的 D-Bus 接口做真实调用，带动态监视 WebUI 与详细报告。

| 项 | 值 |
|----|-----|
| 测试项 | **35 项，7 大类** |
| 运行环境 | worker（`10.0.90.243`）系统 `python3`（需 `dbus`，**不是** PA 的 venv） |
| 部署位置 | `/home/bianbu/bnsec-testkit/`（`scripts/deploy.sh` 装） |
| 测试 WebUI | `http://10.0.90.243:9700` |
| 输出目录 | `/var/tmp/bnsec-testrun/` |

> **面向后续 AI coder**：本文档是继续开发这套安全子系统的**唯一操作入口**。
> 「[怎么改代码](#怎么改代码)」一节给出改动 → 部署 → 验证 → 提交的完整闭环，
> 以及若干**必须遵守的约束**（违反会导致服务起不来或安全静默失效）。
> 设计决策与取舍见仓库 `docs/BNAgent-Security-Capability-Mapping.md`。

---

## 三个仓/三个服务的关系

```
personal-agent（PA）                     securityd
├─ bianbu_agent/                         ├─ securityd/          判权引擎、DLP、审计、沙箱
│  ├─ security_*.py         安全接入点     │  ├─ capabilities.py  ★工具目录（唯一事实来源）
│  ├─ run_manager.py        错误分类       │  ├─ permissions.py   五组安全权限设置
│  └─ langgraph/            HITL 中间件    │  ├─ code_signing.py  安装期签名
└─ .bianbu-agent/plugins/                 │  └─ langgraph/mapping.py  工具名恒等映射
   └─ bianbu.security/      插件           ├─ hermes_plugin/      hermes 侧工具名
      ├─ lib/               共享桥接       ├─ client/             D-Bus 客户端封装
      └─ hooks/*/hook.py    8 个干预点     └─ webui/              配置台（8787）
```

三者靠 **D-Bus `io.bianbu.Security`** 连接。PA 的 hook 在工具调用前经
`bianbu_security_client` 调 securityd 判权，结果决定放行/确认/拦截。

**策略维度只有一个：工具名。** `securityd/capabilities.py` 的 `TOOLS` 是按框架
（runtime / hermes）分表的工具目录，既是全系统工具名的唯一事实来源，也是默认
策略（allow/ask/deny）的定义处。`resolve_capability()` 已退化为恒等映射 ——
不再有"工具 → 能力名"的第二套命名（曾经 `system.exec` 与 `system.execute`
同义不同名，干净部署上大量工具被 fail-closed 拦掉）。对接某框架的 Agent 时，
配置台只显示该框架的工具。这条由 `CAP-01` / `CAP-03` 守住。

---

## 文件构成

| 文件 | 职责 |
|------|------|
| `engine.py` | 测试引擎：`Ctx`（HTTP/D-Bus/审计差分/run 编排）、`Step`、`Emitter`、`run_all` |
| `tests_all.py` | 35 个测试项定义（`@test` 装饰器注册） |
| `runner.py` | **运行入口**（不要直接跑 `engine.py`，见下） |
| `webui.py` | 零依赖 WebUI（标准库 `http.server`） |
| `scripts/` | 部署与启停脚本 |

### 为什么必须用 `runner.py`

直接 `python3 engine.py` 会跑出「总计 0」：`tests_all` 里的
`from engine import ...` 会创建**第二个** engine 模块实例，`@test` 注册到
那个实例的 `TESTS`，而 `__main__` 里的 `run_all` 读到的是空列表。
`runner.py` 让两者都作为普通模块导入，共用同一实例。

---

## 怎么跑系统

### 独立启动脚本（推荐，不依赖 deploy）

三个 `start-<全名>.sh` 是**自带默认值的独立脚本**，拷到目标机上直接跑即可。
`scripts/` 下同名短版（`start-pa.sh` / `start-securityd.sh` /
`start-sec-webui.sh`）功能相同但 `source env.sh`，必须先 deploy 整套 testkit。

| 独立脚本 | 起什么 | 端口 |
|---------|--------|------|
| `start-bianbu-securityd.sh` | securityd 判权服务（D-Bus） | — |
| `start-securityd-webui.sh` | securityd 配置台 | 8787（正式安装以 `/etc/bianbu/webui.env` 的 `BIANBU_WEBUI_PORT` 为准，testkit 会自动读取） |
| `start-bianbu-agent.sh` | personal-agent | 9899 |

**启动顺序固定**：securityd → PA / 配置台。securityd 没起时 PA 仍能启动，
但判权走 fail 分档（高危拦截、低危放行）—— 看着"能用"其实安全已半失效，
所以三个脚本的 `--status` 都会一并报 securityd 是否占名。

```bash
scp testkit/scripts/start-{bianbu-securityd,securityd-webui,bianbu-agent}.sh \
    bianbu@10.0.90.243:~/
ssh bianbu@10.0.90.243
./start-bianbu-securityd.sh      # 已占名会跳过，不误杀
./start-bianbu-agent.sh
./start-securityd-webui.sh       # 默认只绑 127.0.0.1
```

`start-bianbu-securityd.sh` 的开关：

```bash
./start-bianbu-securityd.sh              # 已占名则跳过
./start-bianbu-securityd.sh --restart    # 改了 securityd 代码后必须用这个
./start-bianbu-securityd.sh --status     # 含"判权探测"，占名≠服务正常
./start-bianbu-securityd.sh --stop
./start-bianbu-securityd.sh --foreground
SECD_BUS=session ./start-bianbu-securityd.sh   # 系统总线占名失败时应急
```

**为什么默认不重启**：两个 securityd 实例会各写一份 `capabilities.db`，
判权结果取决于哪个先占名，排查极难。所以无参数时已占名就跳过，
要换代码必须显式 `--restart`。

`start-securityd-webui.sh` 的开关：

```bash
./start-securityd-webui.sh          # 绑 127.0.0.1（默认）
./start-securityd-webui.sh --lan    # 绑 0.0.0.0（危险，见下）
./start-securityd-webui.sh --status # 会报实际监听地址
./start-securityd-webui.sh --get-token # 输出当前管理员认证 token
./start-securityd-webui.sh --stop
```

> ⚠️ 开发/demo DEB 通过 systemd drop-in 关闭配置台 Bearer Token；产品包默认要求
> 管理员 Token，且内置 Web Terminal（可开 shell）。无论哪种模式，绑 `0.0.0.0`
> 都等同于对外暴露远程管理面。默认因此绑 `127.0.0.1`，远程访问请用
> `ssh -L 8787:127.0.0.1:8787 bianbu@<worker>`；确需内网开放才用 `--lan`，
> 并在生产配置 TLS、Token 和网络 ACL，用完 `--stop`。

`start-bianbu-agent.sh` 的开关：

```bash
BA_CONFIG=.bianbu-agent/config.yaml BIANBU_SANDBOX=agent \
  ./start-bianbu-agent.sh              # 安全启动：run.sh + bwrap
./start-bianbu-agent.sh --status
./start-bianbu-agent.sh --stop
./start-bianbu-agent.sh --foreground # 前台跑，便于看启动报错
./start-bianbu-agent.sh --no-security # 关掉安全接入并使用 host 基线

# host 模式（仅在 security.runtime 返回 host 时使用）
BIANBU_SANDBOX=off ./start-bianbu-agent.sh
```

安全启用时脚本实际执行的是 PA 的 `run.sh`，由它统一完成 SearXNG 检查、旧进程清理
和可选 bwrap 入口：

```bash
cd /home/bianbu/bianbu-agent
BIANBU_AGENT_CONFIG=.bianbu-agent/config.yaml BIANBU_SANDBOX=agent \
  /home/bianbu/bianbu-agent/run.sh serve
```

不要直接用 `uv run --no-dev bianbu-agent ... serve` 替代该入口：当 security.runtime
裁决为 sandbox 时，PA 会因缺少 `BIANBU_SANDBOX_ACTIVE=1` 按 fail-closed 拒绝启动。

脚本会在 `/run/bianbu/securityd.sock` 存在时自动选择正式 systemd UDS，并让 testkit
读取 `/var/log/bianbu/audit`；否则回退用户目录的开发实例。两者都可分别用
`BIANBU_SEC_UDS`、`BNSEC_AUDIT_DB` 显式覆盖，避免生产服务已安装后仍误读开发数据。

路径与开关都能用同名环境变量覆盖，例如
`BA_HOME=/opt/bianbu-agent BA_PORT=9900 ./start-bianbu-agent.sh`。

PA 启动前必须存在 `../bianbu-agent-memory/sdk/python`。缺失时脚本会拒绝启动；仅
开发验证可以显式设置 `BA_UV_NO_SYNC=1` 复用已有 venv，该开关不属于商用部署方案。

### 用 testkit 的成套脚本

```bash
./scripts/deploy.sh                 # 首次：装到 /home/bianbu/bnsec-testkit
cd /home/bianbu/bnsec-testkit/scripts
./start-all.sh                      # 起三个服务（顺序已处理）
./status.sh                         # 体检
./stop-all.sh                       # 停（securityd 默认保留，加 --secd 才停）
```

**为什么不用 `/tmp`**：worker 的 `/tmp` 是 tmpfs（重启即失），且
systemd-tmpfiles 配了 `q /tmp … 10d`。早期版本放 `/tmp`，重启后脚本全丢。

---

## 怎么跑测试

### 三条路径

```bash
# ① 命令行（最常用）
cd /home/bianbu/bnsec-testkit && python3 runner.py                  # 全量 35 项
cd /home/bianbu/bnsec-testkit && python3 runner.py HOOK-03 ERR-01   # 指定项

# ② testkit 脚本（等价，但会 source env.sh 设好环境变量）
cd /home/bianbu/bnsec-testkit/scripts && ./run-tests.sh
./run-tests.sh CAP-01 SYSCALL-01

# ③ 浏览器：http://10.0.90.243:9700 点「开始测试」，实时看每项状态
```

退出码：全通过 `0`，有失败/错误 `1`，测试 ID 写错 `2`（并列出可用 ID）。

2026-09-14 起，Runtime 源码插件目录为 `resources/plugins/`。验证 DEB 安装产物时设置
`BNSEC_SECURITY_PLUGIN_ROOT=/usr/share/bianbu-agent-runtime/plugins/bianbu.security`，
`PA_ROOT` 指向与安装包同版本的源码，避免继续读取旧 `.bianbu-agent/plugins/`。
`HOOK-03`、`ERR-01` 可按用例显式批准当前 Run 的 `read_file` / `terminal` 无害探针；
此审批只处理 Runtime 通用工具确认，不能覆盖 securityd 的 deny 策略。`ERR-01` 必须继续
断言被拒工具零执行、结构化错误与判权审计存在。其他用例默认不自动批准。


### 从开发机远程跑

worker 上的仓库副本不是 git 仓库，改动靠 sftp 推送：

```python
import paramiko
c = paramiko.SSHClient(); c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
c.connect("10.0.90.243", username="bianbu", password="bianbu", timeout=20)
sftp = c.open_sftp()
sftp.put("<本地路径>", "<worker 路径>")
sftp.close()
_, o, _ = c.exec_command("cd /home/bianbu/bnsec-testkit && python3 runner.py", timeout=900)
print(o.read().decode())
```

**不要在 SSH 命令里直接 `nohup ... &`** —— 子进程会继承 SSH 通道的
stdout/stderr，通道等不到 EOF 就一直挂住，调用方卡到超时。要后台化就把命令
写成脚本文件再 `setsid "$script" </dev/null >log 2>&1 &`（启动脚本都这么做的）。

### 另外两套测试

```bash
# securityd 默认测试；3 条专用 E2E 默认跳过，完整验收必须补跑下方隔离入口
cd /home/bianbu/impl/bianbu-securityd && python3 -m pytest tests/ -q

# PA 全量回归（必须先 export PATH，见下）
export PATH=/home/bianbu/.local/bin:$PATH
cd /home/bianbu/bianbu-agent && uv run pytest -q
```

**Security 完整验收不能把 skip 当作通过。** 2026-09-14 修复后，worker 上
单元/集成为 793 passed，独立 E2E 为 3 passed。使用当前源码目录执行：

```bash
cd /home/bianbu/impl/bianbu-securityd
python3 -m pytest tests/ --ignore=tests/e2e --import-mode=importlib -q
(
  set -eu
  task_e2e_root=$(mktemp -d /var/tmp/bnsec-e2e.XXXXXX)
  trap 'rm -rf "$task_e2e_root"' EXIT
  dbus-run-session -- env \
    BIANBU_E2E=1 BIANBU_SEC_ROOT="$task_e2e_root" \
    BIANBU_SEC_UDS="$task_e2e_root/run/bianbu/securityd.sock" \
    PYTHONPATH="$PWD:$PWD/client" \
    python3 -m pytest tests/e2e --import-mode=importlib -q
)
```

两组均须退出 0，第二组必须实际执行 3 项且 0 skipped。它们使用本仓客户端和
测试驱动，不依赖 worker 上的外部 Hermes 项目，也不复用生产 D-Bus/UDS 或数据目录。
`deploy/verify_all.sh --strict` 已使用同样的隔离方式；该入口还包含生产签名等其他门禁。

审计断言只读取 `YYYYMM.db` 主审计库，不能用 `next(glob('*.db'))`，否则会选中
`syscall-events.db` 等独立数据库。WebUI token 单测须隔离进程发现和系统配置文件，
不能读取运行中服务的真实 token。详见
[`修复与回归记录`](../docs/test/runtime-security-regression-fixes-20260914.md)。

**PA 回归必须先 `export PATH`**：非交互 SSH 不带 `~/.local/bin`，而部分测试会
subprocess 调 `uv`，缺了会误报几十个失败（踩过，一度以为是接入引入的回归）。

**PA 回归的基线是 73 failed，不是 0 failed。** 用 `BIANBU_SECURITY=0`
（关掉全部安全接入）跑同一套会得到**完全相同**的失败集合，证明与安全接入无关。
原因：worker 副本非 git 仓库（`git ls-files` 退出 128）、无浏览器 driver、
riscv64 上 2 秒超时不够。**判断有无回归要逐项比对失败集合，不能只看总数**：

```bash
BIANBU_SECURITY=0 uv run pytest -q 2>&1 | grep '^FAILED' | sort > /tmp/base.txt
uv run pytest -q 2>&1 | grep '^FAILED' | sort > /tmp/now.txt
comm -13 /tmp/base.txt /tmp/now.txt      # 有输出 = 引入了新失败
```

### Security 商用证据与长期稳定性

本入口只验本次 Security 交付责任域；范围外 Agent Runtime 的缺失只记录为外部集成
状态，不计入本项目测试完成度。

```bash
# 生成发布证据包：strict 原始日志 + JUnit + doctor + SBOM/CVE + 源码清单和哈希
cd /home/bianbu/impl/bianbu-securityd
BNSEC_RELEASE_COMMIT=REPLACE_WITH_COMMIT
BNSEC_PYTHON=/var/tmp/bnsec-release-venv-hermetic.WuUZU2/bin/python \
BNSEC_CVE_SCANNER=/var/tmp/bnsec-release-venv-hermetic.WuUZU2/bin/pip-audit \
BNSEC_SOURCE_REVISION="$BNSEC_RELEASE_COMMIT" \
BNSEC_EVIDENCE_DIR="/var/tmp/bnsec-security-release-$BNSEC_RELEASE_COMMIT" \
bash .ci/run_tests.sh

# 默认 72 小时，24/72 小时自动生成里程碑报告；v2 每 6 小时执行一次真实 PA canary
# （创建 run、bianbu.memory/memory、Token 用量和 mcp.* 判权审计）
SOAK_PYTHON=python3 bash deploy/start_commercial_soak.sh start "$BNSEC_RELEASE_COMMIT"
bash deploy/start_commercial_soak.sh status
```

发布证据验收：`SECURITY_RELEASE_GATE_PASS` 且汇总中
`security_scope_status=passed`。耐久运行中尚未到检查点的项目位于
`pending_checks`；最终必须 `status=passed`、`failures=[]`。v2 报告格式为
`bianbu-security-commercial-soak-v2`，最终至少需要 12 次 PA canary 全部成功，
每次均有正 Token 用量和 `mcp.*` `check_permission` 审计；旧的 Security-only
`v1` 报告不能通过最终验收门禁。启动前 `systemctl is-system-running` 必须为
`running` 且不存在 `activating/failed` service；`degraded` 或 transient service
环境会 fail-closed 拒绝启动。

72 小时及组织证据齐全后，使用 `deploy/commercial_acceptance_gate.py` 做最终签收。
该门禁校验外部报告附件哈希、双人审批和组织 Ed25519 签名；模板位于
`deploy/commercial-*-evidence.example.json`。外部证据缺失或签名不可信时必须失败，
不能用 testkit、内部渗透或自签说明替代。

---

## 怎么改代码

### 闭环

```
改本地代码
  → sftp 推到 worker（securityd / PA / testkit 三个目标路径）
  → 重启受影响的服务（见下表，漏了会验到旧代码）
  → 跑对应测试
  → 补测试项（新行为必须有防回归断言）
  → 两个仓分别 commit
```

**哪些改动需要重启什么**：

| 改了什么 | 要重启 | 漏了会怎样 |
|---------|--------|-----------|
| `securityd/**`（判权、DLP、审计） | `./start-bianbu-securityd.sh --restart` | 验到旧判权逻辑 |
| PA `bianbu_agent/**` | `./start-bianbu-agent.sh` | 验到旧代码，**曾因此误判测试失败** |
| PA 插件 `lib/` `hooks/` | `./start-bianbu-agent.sh` | 同上 |
| `webui/` | `./start-securityd-webui.sh` | 页面是旧的 |
| `testkit/tests_all.py` | 不用（每次跑重新导入） | — |

### 必须遵守的约束

违反下列任一条会导致服务起不来、或安全**静默失效**（比报错更危险）：

**① 新增工具必须先进权威目录，并标清框架。**
`securityd/capabilities.py` 的 `_RUNTIME_TOOLS` / `_HERMES_TOOLS` 是唯一事实来源。
`capability_registry` 的 SQLite schema 对工具名**没有任何校验**（自由文本），
写错不报错，只会按 `unmapped_policy()` 走默认 ask —— 看起来像"没配置"。
漏标框架会让配置台把工具挂错框架。`CAP-01` 会校验目录与框架划分自洽。

**② 插件 `lib/__init__.py` 是隐式契约。**
`hooks/*/hook.py` 从 `lib` 导入符号，新增了必须在 `__init__.py` 同步 re-export，
否则 `ImportError` → `RuntimeStartupError`，整个 PA 起不来（踩过）。

**③ `hooks/<name>/` 目录内只能有 `hook.py`。**
`bianbu_agent/hooks/loader.py:88` 强制校验。`.bak` 备份、`__pycache__` 都会让
运行时启动失败。改 hook 时备份要放到目录外。

**④ `BIANBU_PA_AGENT_ID` 与 PA 本地 `agent.id` 必须显式理解并保持一致。**

testkit 默认将两者都设为 `bianbu-agent-default`，以匹配当前 Runtime Session
API；部署使用不同 Agent 时，必须同时设置 `PA_AGENT_ID` 和
`BIANBU_PA_AGENT_ID`，避免策略写入一个 Agent 而执行请求使用另一个 Agent。
两者分别控制安全策略注册和 Runtime Session 目标；用错会把判权记到另一个 agent 上，
配置台里查不到工具策略。

**⑤ 判权处置取向：不确定时交给人。**
未映射工具默认 ask（不是 allow）；判定拿不准就交用户确认。
`CAP-03` / `CAP-04` 断言 securityd 与 PA 插件两侧策略一致，且生产模式下
`BIANBU_SECURITY_UNMAPPED=allow` 被忽略（那是开发期便利开关，不能成为
生产环境里新工具免判权的后门）。

**⑥ 前端展示外部输入必须转义。**
错误详情里的 `tool` 可能源自模型生成的参数，走 `escapeHtml`，
不进 `renderMarkdown`。

**⑦ 「自定义」权限组不得被策略重算冲掉。**
`permissions.py` 的 `custom` 是运维手写的自由 JSON，独立存储、不参与任何预设
重算 —— 重设三态策略或重新应用预设时丢了它，等于把用户的手工配置清零。
`SET-01` 会写 custom 再改 read 组，断言 custom 原样保留。

### 加一个测试项

```python
@test("XXX-01", "一句话说清验什么", "INT-PA-06", "permission")
def t_something(c: Ctx):
    """为什么需要这项 —— 写清楚不加会漏掉什么。

    这里是给后来者看的：说明这个测试防的是哪类回归。
    """
    steps = []
    # c.dbus()              securityd D-Bus 代理（GetCapabilities / CheckPermission / …）
    # c.http(m, path, body)  PA HTTP API，返回 (status, json)
    # c.run_prompt(prompt)   发一次**真实** run，轮询到终态，返回 run 详情
    # c.check_permission(cap, scope)   判权结果的字符串形式
    # c.audit_seq() / c.audit_since(seq)   审计差分（证明调用到达了 securityd）
    # c.shell(cmd)           在 worker 上执行命令，返回 (rc, output)
    # c.log(msg)             进报告 logs 的时间戳日志行
    steps.append(Step("断言名", cond, "失败时的 detail —— 说清为什么这是问题"))
    return steps
```

**测试项的质量要求**（这套测试抓到过 6 个原分析未预见的缺陷，靠的是这几条）：

- **断言落在外部可观测事实上**，不只验函数返回值。关键项用 **securityd 审计
  差分**（按 `seq` 圈定某次操作的增量）证明"调用真的到达了 securityd"。
  正是这个手法发现了「hook 执行了但从未调用 securityd」。
- **跨处一致性断言**。同一语义在多处各自实现时，一处漏改就是洞。例如 `CAP-04`
  断言 PA 插件与 securityd 的 `unmapped_policy()` 必须一致，`CAP-03` 断言
  工具名恒等映射、没有第二套命名。
- **失败 detail 要说清"为什么这是问题"**，不只报"期望 X 实际 Y"。
- **改了状态要恢复**（`try/finally`）。`ERR-01` 把工具策略改成 deny 验完必须恢复
  原策略，否则污染后续测试项。
- **端到端项要用真实 run**，不 mock。`ERR-01` 真的发一条会触发 `web_search`
  的消息，看真实返回的错误结构。

### 常见陷阱

**PII 扫描器需要上下文标记**。`"帮我查张伟的资料"` 不算命中，`"姓名：张伟"` 才算。
且工具参数会先 `json.dumps` 再扫，标记必须落在**值内部**。写 DLP 测试时不注意
这点，测到的会是"无 PII 时两边都放行"，证明不了任何事（踩过）。

**两个 Python 环境的依赖不同**。系统 `python3` 是 3.14（有 `dbus`，无
`jsonschema`），PA venv 是 3.13（`jsonschema` 齐全，`dbus` 后来也补装了 1.4.0）。
**C 扩展不能跨版本**，所以不能指望一个环境导入另一个环境的模块。

沙箱模块因此用 `importlib` 按文件路径加载 + 塞空壳 `bianbu_agent` 包进
`sys.modules`，绕过真 `__init__`（那会拉进 pydantic 等 C 扩展依赖），
让系统 `python3` 也能跑沙箱测试。见 `tests_all.py::_load_sandbox_mods()`。

推荐用**系统 `python3`** 跑 testkit（脚本默认如此）。

**改 D-Bus 接口要同步四处**：`securityd/service.py`（方法定义）、
`client/bianbu_security_client.py`（客户端封装）、`CONN-03`（方法数断言）、
以及调用方。

---

## 测试项清单（35 项）

### connectivity（3）— 基础连通性
| ID | 验什么 |
|----|--------|
| CONN-01 | personal-agent HTTP 服务可达 |
| CONN-02 | securityd 占用 `io.bianbu.Security` 且 `CheckPermission` 可调 |
| CONN-03 | 关键 D-Bus 方法全部导出；token 配额方法不得复活 |

### permission（12）— 工具策略判权、权限设置与映射
| ID | 验什么 |
|----|--------|
| PERM-01 | `RegisterCapabilities` 生效，五个工具三态策略可查 |
| PERM-02 | 判权三态 ALLOW/ASK/DENY，含未声明→ASK 的保守兜底 |
| PERM-03 | 非三态策略值被拒绝（只接受 allow/ask/deny） |
| PERM-04 | 撤销工具策略后判权转为 DENY |
| SET-01 | 五组安全权限设置（可读/可写/网络/系统调用/自定义）可读写；自定义组不被冲掉 |
| CAP-01 | 工具目录与框架划分（runtime/hermes）自洽 |
| CAP-02 | MCP 工具按 server 判权，不被工具名绕过（D-3） |
| CAP-03 | 工具名即策略键：映射退化为恒等映射，无第二套命名 |
| CAP-04 | 未映射工具默认 ask，不静默放行（D-5） |
| MCP-01 | MCP 层 1 fail-closed：未授权 server 拦截并登记待授权（D-2） |
| CODE-01 | Hook/Tool/Skill 安装期签名校验（D-6） |
| SYSCALL-01 | 系统调用黑名单：全局强制项 + Agent 追加项，重置不影响强制项 |
| YOLO-01 | 管理员开启 YOLO 后已撤销/不再声明的工具均放行并逐次审计，关闭后恢复原 DENY |

`YOLO-01` 使用临时注册、绑定的专用 Agent，经真实 D-Bus 管理面切换模式；测试在
`finally` 中恢复 `normal` 并注销。不要拿 `com.bianbu.agent` 直接给 testkit 进程调用
`CheckPermission`，caller binding 会正确拒绝冒充。YOLO 不执行工具策略拒绝、DLP 扫描
或网络策略检查；测试仍须保留 sandbox、caller validation 和 audit；
审计判据是 `decision=ALLOW;mode=yolo`。

### hook（5）— hook 派发端到端
| ID | 验什么 |
|----|--------|
| HOOK-01 | 8 个 security hook 全部加载且 `enabled=True` |
| HOOK-02 | 纯对话 run 可完成（hook 不阻断正常流程） |
| HOOK-03 | **工具调用必须在 securityd 审计留下 `check_permission`** |
| HOOK-04 | 工具名即策略键：MCP 按 server、本地工具按名判权 |
| ERR-01 | 安全拦截的原因透传到前端（不再是「发送失败，请稍后再试」） |

HOOK-03 是决定性测试：它验的不是"hook 是否执行"，而是"hook 是否**真的调用了
securityd**"。二者可以分离 —— 实测中 hook 每次都执行，但判权被跳过、直接放行，
从未调用 securityd。

### dlp（6）— DLP/PII、中央策略与数据出境
| ID | 验什么 |
|----|--------|
| DLP-01 | 8 类 PII 实体全部可检出 |
| DLP-02 | 非法身份证/卡号不误报（校验和 + BIN 前缀） |
| DLP-03 | 逐字泄露双信号（追加字符规避仍能检出） |
| DLP-04 | **PA 大于 4KB 的 DLP 文本走正式 UDS `dlp.scan`，并使用 securityd 中央策略；大于 1KB 的完整治理载荷走 `audit.batch`** |
| EGRESS-01 | 远端 MCP 数据出境提档确认（D-9） |
| SKILL-01 | Skill 文本过 DLP，不随 prompt 外发密钥（D-10） |

`SKILL-01` 的职责是验证 PA `security_skill_dlp` 的 mask/block/cache 适配逻辑。
它不会让 testkit 进程使用临时 Agent ID 直接连接正式 UDS；正式 UDS 会校验
`SO_PEERCRED` 和 caller binding。该项使用版本化 `bianbu_security_client` 的受控
fake adapter，真实 PA→securityd 数据面由 `DLP-04` 验证。生产代码不得因为测试夹具
而绕过 `BIANBU_PA_AGENT_ID` 身份绑定。

### sandbox（5）— 沙箱
| ID | 验什么 |
|----|--------|
| SBX-01 | bwrap 可用，argv 含 `--unshare-*` / `--cap-drop` / `--die-with-parent` |
| SBX-02 | 沙箱内可执行且 PID 被重编号 |
| SBX-03 | `net=false` 阻断出网 |
| SBX-04 | 单工具沙箱：参数与**返回值**不可序列化都须显式拒绝 |
| SBX-05 | `net=true` 时沙箱内 DNS 可解析（resolv.conf 符号链接） |

### audit（3）— 审计链
| ID | 验什么 |
|----|--------|
| AUDIT-01 | 审计记录写入且含哈希链字段 |
| AUDIT-02 | 哈希链连续可校验（防篡改） |
| AUDIT-03 | `ExportAudit` 可导出且文件非空 |

---

## 输出产物

| 文件 | 内容 |
|------|------|
| `$BNSEC_OUT/events.jsonl` | 事件流（WebUI 按行偏移增量拉取） |
| `$BNSEC_OUT/report.json` | 完整报告：每项的断言、日志、审计增量、堆栈 |
| `$BNSEC_OUT/runner.log` | WebUI 启动的那次运行的 stdout |
| `$BNSEC_LOG_DIR/{securityd,pa,sec-webui,webui}.log` | 各服务日志 |

（`BNSEC_OUT` 默认 `/var/tmp/bnsec-testrun`，`BNSEC_LOG_DIR` 默认 `/var/tmp/bnsec-logs`）

`report.json` 结构：

```json
{
  "summary": {"total":36,"passed":36,"failed":0,"error":0,"duration_ms":31500},
  "results": [{
    "id":"ERR-01", "title":"...", "requirement":"INT-PA-06",
    "status":"passed", "duration_ms":6300,
    "steps":[{"name":"...","ok":true,"detail":"","data":null}],
    "logs":["[12:47:32] POST /api/v1/runs → 202", "..."],
    "audit_delta":[{"seq":4062,"op_type":"check_permission","result":"deny"}],
    "error":""
  }]
}
```

排查失败先看 `report.json` 里那一项的 `logs` 与 `audit_delta` —— 前者是测试
自己的时间线，后者证明调用有没有真的到达 securityd。

---

## 常见问题

**跑出「总计 0」** → 用了 `python3 engine.py`。改用 `runner.py`。

**`ModuleNotFoundError: dbus`** → 该 Python 环境没装 `dbus`。用系统 `python3`
（脚本默认），或给当前环境装上。

**`ModuleNotFoundError: jsonschema`** → 沙箱测试走了 `import bianbu_agent`
而非 `_load_sandbox_mods()`。

**`FileNotFoundError: 'uv'`（PA 回归）** → 非交互 SSH 缺 `~/.local/bin`。
先 `export PATH=/home/bianbu/.local/bin:$PATH`。

**SSH 通道挂住** → 后台启动要用 `setsid ... </dev/null >log 2>&1 &`，
把脚本写成文件再 `setsid` 调用，不要在 SSH 命令里直接 `nohup`。

**`Hook package must contain only hook.py`** →
`hooks/<name>/` 内只能有 `hook.py`，备份/`__pycache__` 都要清掉
（`bianbu_agent/hooks/loader.py:88`）。

**改了代码但测试结果没变** → 忘了重启对应服务，见「怎么改代码」的重启表。

**securityd 占名失败（AccessDenied）** → 缺 D-Bus policy 或用户不在
`bianbu-security` 组。`start-bianbu-securityd.sh` 失败时会打印三条具体处置；
应急可 `SECD_BUS=session` 退回会话总线。

**判权结果不符合预期** → 先 `CAP-01` 确认工具在目录内且框架标注正确；目录外工具
一律走 `unmapped_policy()`（默认 ask），`CAP-03` / `CAP-04` 可进一步定位。

---

**第一次接手这套代码** → 先读 `../Collaboration/CODEX-ONBOARDING.md`
（代码仓关系、一次工具调用的完整链路、改动闭环、硬约束、排查手册）。

更细的实现说明见 [GUIDE.md](GUIDE.md)；
设计决策与取舍见仓库 `docs/BNAgent-Security-Capability-Mapping.md`（§10 是落地记录）。

### K3 确定性内核审计验收（不依赖云端模型）

若模型拒绝无害探针，不能把模型拒绝记为内核拦截。可在 Worker 执行：

```bash
python3 scripts/kernel_probe.py --out /var/tmp/bnsec-kernel-probe.json --keep-agent
```

脚本建立临时本地模型端点、Provider 与 sandbox Agent，走真实 Runtime terminal 工具，仅调用 `finit_module(-1, 0, 0)`，不会加载模块。验收要求 syscall 返回 EPERM，且 eBPF 事件同时匹配本次新建 Agent、实例、lease、syscall 与 deny（工具 PID 属于沙箱命名空间，审计 PID 属于宿主，不能直接比较）；否则失败。YOLO 仅用于消除能力确认，沙箱与内核约束保持开启。

默认自动删除临时 Agent/Provider；`--keep-agent` 仅成功时保留，供两端系统调用页面按输出 Agent ID 检查本次事件。检查后通过 Runtime API 删除输出中的 agent_id 和 provider_id。本地模型端点结束后已关闭，保留的测试 Agent 不可用于普通聊天。
