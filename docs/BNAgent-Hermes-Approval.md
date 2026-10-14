# hermes 自带权限审批（Approval）机制梳理

| 项 | 内容 |
|----|------|
| 文档编号 | BN-SEC-APPROVAL-001 |
| 版本 | V1.0 |
| 来源 | worker 10.0.90.243 实测 hermes 源码 `/usr/lib/hermes-agent/src/tools/approval.py`（918 行）+ 各调用点 |
| 日期 | 2026-07-21 |
| 状态 | 与 worker 上 hermes 实现同步 |
| 关联 | BN-SEC-HERMES-001（bianbu-security 接入方案，§3 审批仲裁） |

> 本文梳理 **hermes 自身内建**的危险命令审批（approval）机制——它与 bianbu-security 的
> 确认门禁是**两套独立系统**。理解它是配置 `BIANBU_SEC_APPROVAL_MODE` 仲裁开关的前提。
> 所有结论基于 worker 上 hermes 真实源码，非通用推测。

---

## 1. 定位与触发点

hermes approval 是**工具执行前的危险命令守卫**：`terminal_tool`（跑 shell 命令）、
`file_tools`（写文件）在真正 execve / 写盘**之前**，调用唯一决策入口：

```
check_dangerous_command(command, env_type, approval_callback) -> {"approved": bool, ...}
```

- `approved=True` → 继续执行
- `approved=False` → 把拒绝消息返回给模型（模型看到 BLOCKED 不再重试该命令）

危险与否由 `detect_dangerous_command()` 的**正则模式库** `DANGEROUS_PATTERNS` 判定
（`rm -rf`、`dd`、`mkfs`、fork 炸弹 `:(){:|:&};:` 等），**普通安全命令不触发审批**。

---

## 2. 决策链（check_dangerous_command，从上到下短路）

| 序 | 条件 | 结果 |
|----|------|------|
| ① | env_type 为 docker/modal 等隔离后端 | 直接 approved（容器内无所谓） |
| ② | `HERMES_YOLO_MODE` 环境变量 或 会话 yolo 已开 | 直接 approved（**全放行**） |
| ③ | 命令不匹配任何危险正则 | 直接 approved（安全命令不打扰） |
| ④ | 该危险模式本会话已批准过（`is_approved`） | 直接 approved（不重复问） |
| ⑤ | 既非 CLI 也非 gateway（纯 API 调用） | 直接 approved |
| ⑥ | **gateway 会话**（飞书/TG/Slack/Web） | 挂 pending，返回 `approval_required` → 异步审批 |
| ⑦ | **CLI 交互会话** | `prompt_dangerous_approval` → 终端同步提问 |

---

## 3. 三条审批 UI 路径

### 路径 A：CLI 交互（终端同步 input）

`prompt_dangerous_approval()`（approval.py:406）：

```
  ⚠️  DANGEROUS COMMAND: recursive delete
      rm -rf /tmp/x
      [o]nce  |  [s]ession  |  [a]lways  |  [d]eny
      Choice [o/s/a/D]:
```

- 用**独立线程 + `thread.join(timeout)`** 读 `input()`，超时（默认 60s）自动 **deny**
- CLI 若注册了 `approval_callback`（prompt_toolkit 富交互）优先用它，否则退回裸 `input()`
- 返回 `once` / `session` / `always` / `deny`

### 路径 B：Gateway / IM 按钮（飞书 / Telegram / Slack，异步阻塞）

- gateway 会话下，`check_dangerous_command` 把请求 `submit_pending` 塞进**该会话 FIFO 队列**，
  agent 线程在 `threading.Event` 上**阻塞等待**
- IM 侧把请求渲染成审批按钮（源码有 `test_feishu/telegram/slack_approval_buttons`）
- 用户点按钮 → gateway 的 `/approve`·`/deny` handler 调
  `resolve_gateway_approval(session_key, choice)`（approval.py:253）：
  - 取队列最旧一条（FIFO），`entry.result = choice; entry.event.set()` → **唤醒阻塞线程**
  - `/approve all` 一次解除该会话所有 pending
- 源码注释原话：*mirrors CLI's synchronous input() flow*（异步事件精确镜像 CLI 同步语义）

### 路径 C：Web GUI

`hermes_cli/web_server.py` 复用 gateway 的 pending/resolve 机制，浏览器点按钮解除阻塞。

---

## 4. 审批粒度（四选项存储）

| 选项 | 函数 | 范围 | 存储 |
|------|------|------|------|
| `[o]nce` | （直接返回 approved） | 仅这一次 | 不存 |
| `[s]ession` | `approve_session` | 整会话内该模式免问 | `_session_approved[session_key]` 内存集合 |
| `[a]lways` | `approve_permanent` + `save_permanent_allowlist` | **永久跨会话** | 落盘永久 allowlist 文件 |
| `[d]eny` | — | 拒绝且告诉模型别重试 | 不存 |

会话级批准命中决策链第 ④ 步；永久 allowlist 启动时 `load_permanent_allowlist` 载入内存。

---

## 5. 审批模式（config 配置）

`~/.hermes/config.yaml` 的 `approvals` 块，由 `_get_approval_mode()` 读取：

```yaml
approvals:
  mode: manual    # manual(默认,危险命令必问) | smart(规则/模型辅助判定) | off(全关)
  timeout: 60     # CLI 提示超时秒数,超时视为 deny
```

- `mode: off` → `check_all_command_guards` 直接放行
- `smart` → `_smart_approve()`（approval.py:531）用规则/模型辅助判定
- **YAML 坑**：裸词 `off` 被 YAML 1.1 解析成布尔 `False`，`_normalize_approval_mode()`
  专门把 `False` 归一化回字符串 `"off"`（否则会误落回 manual）

---

## 6. 全局旁路：YOLO 模式（bianbu 接入的关键抓手）

决策链第 ② 步，三个短路点任一生效即**全放行、不审批**：

| # | 触发方式 | 作用域 | 用途 |
|---|---------|--------|------|
| 1 | `HERMES_YOLO_MODE=1` 环境变量 | **进程级**（import 时冻结） | CLI `--yolo`；**bianbu 启动器注入** |
| 2 | `enable_session_yolo(session_key)` | **会话级**（可运行时开关） | gateway `/yolo` 命令 |
| 3 | config `mode: off` | 全局 | 永久关闭 |

**bianbu-security 正是利用旁路点 #1**：`hermes_sandbox_launch.py` 启动 hermes 前设
`HERMES_YOLO_MODE=1`，关掉 hermes 自带 approval，让 bianbu-security 成为唯一审批权威
（详见 §8 与 BN-SEC-HERMES-001 §3）。

---

## 7. 完整时序图

### 7.1 CLI 路径（终端同步 input，阻塞在 input() 上）

```
 模型            terminal_tool        approval.py                    用户(终端)
  │                  │                    │                             │
  │ 调用 terminal    │                    │                             │
  │ (rm -rf /tmp/x)  │                    │                             │
  ├─────────────────>│                    │                             │
  │                  │ check_dangerous_command(cmd, env, cb)            │
  │                  ├───────────────────>│                             │
  │                  │                    │ ① env 隔离? 否               │
  │                  │                    │ ② YOLO? 否                   │
  │                  │                    │ ③ detect_dangerous → 命中!   │
  │                  │                    │ ④ is_approved? 否            │
  │                  │                    │ ⑦ CLI 会话 →                 │
  │                  │                    │   prompt_dangerous_approval  │
  │                  │                    │  ┌─ 打印 [o/s/a/d] ─────────>│
  │                  │                    │  │  线程 join(timeout=60s)    │
  │                  │                    │  │      阻塞等 input()         │
  │                  │                    │  │<──── 用户键入 's'(session)──┤
  │                  │                    │  └─ approve_session()         │
  │                  │                    │     记入 _session_approved    │
  │                  │<─ {"approved":True}─┤                             │
  │                  │ 执行命令 execve     │                             │
  │<─ 命令输出 ───────┤                    │                             │
  │                  │                    │  (同会话再遇同模式 → ④ 命中,不再问)
```

### 7.2 Gateway / GUI 路径（异步事件唤醒，阻塞在 Event 上）

```
 模型         tool         approval.py          gateway/web       IM/浏览器  用户
  │            │               │                    │                │        │
  │ terminal   │               │                    │                │        │
  ├───────────>│ check_dangerous_command            │                │        │
  │            ├──────────────>│                    │                │        │
  │            │               │ ①②③④ 同上,命中危险  │                │        │
  │            │               │ ⑥ gateway 会话 →    │                │        │
  │            │               │   submit_pending()  │                │        │
  │            │               │   入会话 FIFO 队列   │                │        │
  │            │               │   agent 线程阻塞在   │                │        │
  │            │               │   threading.Event   │                │        │
  │            │               │═══ 阻塞等待 ═══      │                │        │
  │            │               │                    │ 推送审批卡片      │        │
  │            │               │                    ├───────────────>│ 按钮   │
  │            │               │                    │                ├───────>│
  │            │               │                    │                │<─ 点[批准]┤
  │            │               │                    │<─ /approve ─────┤        │
  │            │               │ resolve_gateway_approval(key,choice) │        │
  │            │               │<───────────────────┤                │        │
  │            │               │ 取 FIFO 最旧一条     │                │        │
  │            │               │ entry.result=choice │                │        │
  │            │               │ entry.event.set() ──┤ 唤醒阻塞线程     │        │
  │            │               │══ 线程被唤醒 ══      │                │        │
  │            │<─{"approved":T}┤                    │                │        │
  │            │ execve         │                    │                │        │
  │<─ 输出 ─────┤               │                    │                │        │
  │       (/approve all 一次解除该会话所有 pending)    │                │        │
```

**两条路径的对称性**：CLI 阻塞在 `input()`、gateway 阻塞在 `threading.Event`；
前者由键盘输入解除、后者由 `/approve` 回调 `event.set()` 解除。源码注释明确二者语义等价。

---

## 8. 与 bianbu-security 的关系（两套独立审批 + 仲裁）

hermes approval 与 bianbu-security 确认门禁是**两套独立系统**，都在工具执行前拦截，判据不同：

| 维度 | hermes 自带 approval | bianbu-security 确认门禁 |
|------|---------------------|------------------------|
| 判据 | 危险命令**正则模式**（rm -rf 等固定黑名单） | Agent **能力注册 + 风险等级**（system.exec L4 等） |
| 状态 | 会话/永久 allowlist（内存 + 文件） | SQLite 能力库（granted + confirm 策略，可 WebUI 改） |
| 粒度 | 命令模式级 | 能力 × scope（目录粒度） |
| UI | CLI input / IM 按钮 / Web | WebUI 确认门禁 Tab / D-Bus 信号；交互式 CLI 交回 hermes TUI（§10） |
| 审计 | 无链式审计 | SHA-256 哈希链，可离线验证 |
| 灵活性 | 固定正则，改需动源码 | WebUI 增删改能力，即时生效 |

### 仲裁开关 `BIANBU_SEC_APPROVAL_MODE`（避免双重弹窗）

| 值 | 行为 | hermes approval | 场景 |
|----|------|-----------------|------|
| **`securityd`**（默认） | bianbu 门禁为准 | 注入 `HERMES_YOLO_MODE=1` **关闭** | 生产 |
| `both` | 两套叠加 | 保留（双确认） | 高安全 |
| `hermes` | 仅 hermes | 保留；bianbu CONFIRM 降级放行 | 过渡/兼容 |

**为何默认 `securityd` 模式关掉 hermes approval**：hermes 正则黑名单是**固定**的，
无法按 Agent、按能力、按目录灵活管控，也无防篡改审计。bianbu-security 的能力模型
（域 × L1-L4 × 确认策略 + 哈希链审计 + WebUI 实时配置）是策略权威，二者叠加只会双重
弹窗扰民。故 `hermes_sandbox_launch.py` 用旁路点 #1（§6）让 hermes 全放行，由 bianbu 独管。

---

## 9. 关键文件与函数索引

| 文件 | 关键符号 | 作用 |
|------|---------|------|
| `tools/approval.py:583` | `check_dangerous_command` | 决策主入口（§2 决策链） |
| `tools/approval.py:181` | `detect_dangerous_command` | 危险正则匹配 |
| `tools/approval.py:406` | `prompt_dangerous_approval` | CLI 同步提问（路径 A） |
| `tools/approval.py:253` | `resolve_gateway_approval` | gateway 解除阻塞（路径 B） |
| `tools/approval.py:288` | `submit_pending` | 请求入会话 FIFO 队列 |
| `tools/approval.py:300` | `enable_session_yolo` | 会话级 YOLO（旁路 #2） |
| `tools/approval.py:329` | `is_approved` | 会话已批准查询（决策链 ④） |
| `tools/approval.py:373/391` | `load/save_permanent_allowlist` | 永久 allowlist 持久化 |
| `tools/terminal_tool.py` / `file_tools.py` | — | 调用方（执行前守卫） |
| `hermes_cli/gateway.py` / `web_server.py` | — | 路径 B/C 的 UI 载体 |

---

## 附：本文档与代码同步性

本文所有行号、函数名、决策顺序均取自 worker 10.0.90.243 上
`/usr/lib/hermes-agent/src/tools/approval.py`（918 行）实测。hermes 升级后若 approval.py
变动，需重新核对 §2 决策链与 §9 行号。bianbu 侧仲裁逻辑见 BN-SEC-HERMES-001 §3。

---

## 10. CLI 场景的确认：主动调 hermes TUI 审批弹框（真机验证通过）

**目标**：CLI（hermes chat）里 bianbu 判"需确认(CONFIRM)"的操作，弹出 hermes 原生
`[Allow once / for this session / permanent / Deny]` TUI 框让用户选。

### 走过的弯路（记录，避免重蹈）

1. **裸 input() 弹框** —— ❌ 不可行。hermes chat 是 prompt_toolkit 全屏 App 接管
   stdin，插件裸 `input()` 会挂死（hermes 源码注释 `skills_hub.py:1128` "input() hangs"）。
2. **被动 `return None` 交回 hermes** —— ❌ 不够。hermes 只对**命中自己危险正则**
   （rm -rf 等）的命令弹框；bianbu 判需确认但不危险的命令（如 echo 走 system.exec）
   hermes 不会弹，直接执行。

### 最终方案：主动调用 hermes 已注册的审批回调（✅ 真机通过）

hermes CLI 启动时经 `terminal_tool.set_approval_callback(cb)` 注册了那个弹 TUI 框的
函数（`callbacks.approval_callback`，走 `cli._app` prompt_toolkit）。插件在 CONFIRM 时
**主动取用并调用它**，即可弹框，且不受 hermes 危险正则范围限制。

```
 hermes工具   插件 pre_tool_call        securityd          hermes TUI(cli._app)   用户
   │ CONFIRM   │ CheckPermission ───────>│ 判 CONFIRM        │                     │
   │           │<────────────────────────┤                   │                     │
   │           │ cli_confirm.hermes_tui_approve(cmd, desc)    │                     │
   │           │   = terminal_tool._approval_callback(...) ──>│ 弹 [Allow once/..] ─>│
   │           │                          │                   │<── 选 Allow once ────┤
   │           │<─ "once" ────────────────────────────────────┤                     │
   │           │ 审计 confirm_hermes_tui:once → 放行(None)     │                     │
   │<─ 执行 ────┤                          │                   │                     │
   │       (选 Deny → block；securityd 始终是判权权威)          │                     │
```

实现（`cli_confirm.hermes_tui_approve` + `__init__.py` CONFIRM 分支）：
- 取 `tools.terminal_tool._approval_callback`，以 `(command, description, allow_permanent=True)`
  调用，返回 `once/session/always/deny`；`!= deny` 放行、`deny` 拦截。
- 审计记 `confirm_hermes_tui:<choice>`。
- 拿不到回调（headless/非 CLI）→ 优雅返回 None：`mode=hermes` 则放行交回 hermes 自身流程，
  否则回退 securityd 信号路径（WebUI 确认门禁 Tab 经 RespondConfirm 响应）。

### 确认路由总表

| 形态 / mode | CONFIRM 承接方 |
|-------------|---------------|
| 交互式 CLI（hermes chat），有审批回调 | 主动调 hermes TUI 弹 [Allow once/…/Deny] |
| headless/gateway + WebUI 在线（mode=securityd/both） | securityd 信号 → WebUI 确认门禁 Tab 点批准 |
| 拿不到回调且 mode=hermes | 放行交回 hermes 自身危险命令流程 |

securityd 始终是**判权权威**（是否 CONFIRM、DENY 恒由 CheckPermission 决定）；
mode 与形态只决定"CONFIRM 的确认 UI 由谁承接"。**DENY 在任何情况下都由 bianbu 硬拦**。

### 真机验证

```bash
sshpass -p bianbu ssh -t bianbu@10.0.90.243        # -t：真 TTY
cd ~/impl/bianbu-securityd
export DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus
export PYTHONPATH=$PWD:$PWD/client:$PWD/hermes_plugin
export BIANBU_SEC_SESSION=1 BIANBU_HERMES_AGENT_ID=com.hermes.agent
export BIANBU_SEC_APPROVAL_MODE=hermes
/usr/bin/hermes chat
# 配好 system.exec(granted=1,L4=CONFIRM) 后，让 agent 执行命令
# → 弹出 hermes 原生 [Allow once/session/permanent/Deny] 框，选择即生效
```
worker 真机验证通过：弹框正常、选择生效、bianbu 侧审计记录 confirm_hermes_tui:<choice>。

> 说明：cli_confirm.py 仅保留 `is_cli_interactive()` 形态探测与 `hermes_tui_approve()`
> 回调调用；早期 TerminalConfirmResponder / 裸 input() 方案已废弃。
