# bianbu-security — hermes 接入（插件 + 进程沙箱）

把 hermes agent 接入 `bianbu-securityd` 的两层方案，**零 hermes 改动、不复用 hermes 代码**
（AGENTS.md 复用边界）。两层构成纵深防御。

## 层 ①：调用级管控（hermes 插件）

`bianbu_security/` 是标准 hermes 插件（`plugin.yaml` + `register(manager)`），接三个钩子：

| 钩子 | 作用 | 对接 securityd |
|------|------|---------------|
| `pre_tool_call` | 工具执行前判权/确认门禁，返回 `{"action":"block"}` 拦截 | `CheckPermission`→DENY 拦；CONFIRM→`RequestConfirm` 门禁，拒则拦 |
| `post_tool_call` | 执行后写审计链（观察者） | `AuditLog` |
| `on_session_end` | 会话结束记一条审计 | `AuditLog` |

工具名→能力映射在 `bianbu_security/mapping.py`（可编辑）。未映射工具默认放行
（`DEFAULT_ALLOW`），不误伤 hermes 大量只读内部工具。

另注册 CLI 命令（若该 hermes 版本支持）：`securityd-install <pkg>`、`securityd-audit-export`。

### 部署（软链，不改 hermes 目录内容）

```bash
export BIANBU_SECURITYD_HOME=<...>/impl/bianbu-securityd
ln -s $BIANBU_SECURITYD_HOME/hermes_plugin/bianbu_security \
      ~/aiws/hermes-agent/plugins/bianbu-security
# hermes 启动即自动 discover_and_load
```

环境变量：
- `BIANBU_HERMES_AGENT_ID`（默认 `com.hermes.agent`）：本会话对应的 securityd Agent id
- `BIANBU_SEC_SESSION=1`：客户端走会话总线（测试）；否则系统总线（生产）
- `BIANBU_SECURITY_FAIL_OPEN=1`：securityd 不可达时放行（默认 0 = fail-closed 拦截）
- `BIANBU_SECURITYD_HOME`：指向本实现根，供插件 import client 封装

### 审批仲裁开关 `BIANBU_SEC_APPROVAL_MODE`（用户可控）

决定 securityd 确认门禁与 hermes 自带 approval 的关系：

| 值 | 行为 | 适用 |
|----|------|------|
| `securityd`（默认，推荐） | **securityd 确认门禁为准**，自动关闭 hermes 自带 approval，避免双重确认 | 生产 |
| `both` | securityd 判权/确认 + hermes approval **叠加**（双确认，更严） | 高安全场景 |
| `hermes` | 仅用 hermes approval；securityd 的 CONFIRM **降级为放行**（只判权 DENY + 审计） | 过渡/兼容 |

**关闭 hermes approval 的实现**（`securityd` 模式）：
- 首选进程级：`hermes_sandbox_launch` 在启动 hermes 前注入 `HERMES_YOLO_MODE=1`
  （hermes 在 import 时冻结此值，全程 approval 短路为 approved）——**最可靠**。
- 运行时兜底：插件 `on_session_start` 调 `approval.enable_session_yolo(session_key)`。
- 若两者都未生效，插件日志会提示"请在启动 hermes 前设 HERMES_YOLO_MODE=1"，
  此时 securityd 门禁仍为准（只是 hermes 侧可能重复弹一次）。

> 用 `hermes_sandbox_launch` 启动时无需手动设 `HERMES_YOLO_MODE`——启动器按
> `BIANBU_SEC_APPROVAL_MODE` 自动处理。仅当你**不经启动器、直接跑 hermes**时，才需
> 自己 `export HERMES_YOLO_MODE=1`（或依赖运行时兜底）。

## 层 ②：进程级 bwrap 沙箱（真隔离）

hermes 无"逐工具进沙箱"的插件缝隙（`pre_tool_call` 只能 block、不能改写命令；
`_create_environment` 硬编码无插件注册点）。故按设计 §3.7 用**整进程沙箱**：
`hermes_sandbox_launch.py` 经 `BuildSandboxPolicy` 取 seccomp，用 bwrap 包裹**整个
hermes 进程**启动。seccomp/cap-drop/文件视图随 fork-exec 被 hermes 及其 spawn 的
每个工具进程继承（已在 worker 验证：子进程 reboot 被 EPERM 拦截）。

```bash
export BIANBU_SECURITYD_HOME=<...>/impl/bianbu-securityd HERMES_HOME=~/aiws/hermes-agent
python hermes_plugin/hermes_sandbox_launch.py --agent com.hermes.agent \
  -- python ~/aiws/hermes-agent/run_agent.py [hermes args...]
```

## 两层关系

- ① 细粒度授权（哪个 Agent、哪个能力、要不要用户确认）——策略权威在 securityd。
- ② 兜底隔离（即便某工具绕过 ①，危险 syscall 仍被内核 seccomp 拦住）。
- ①、② 可独立启用；生产建议同时开。

## 验证

```bash
# 调用级（模拟 hermes 钩子分发，无需装 hermes）
dbus-run-session -- python tests/integration/hermes_plugin_demo.py   # HERMES_PLUGIN_PASS 6/6
# 进程级沙箱（worker，需 userns）
python -m pytest tests/integration/test_hermes_sandbox.py -v
# 并入 smoke（阶段 5/6、6/6）与 e2e（BIANBU_E2E=1）
```
