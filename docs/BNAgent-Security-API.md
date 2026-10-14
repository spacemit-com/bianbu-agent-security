# AgentSecurityD 对外接口文档（API Reference）

| 项 | 内容 |
|----|------|
| 文档编号 | BN-SEC-API-001 |
| 版本 | V1.0 |
| 来源 | `impl/bianbu-securityd` 实现（service.py / client / webui / cli / hermes_plugin）+ worker 实测 |
| 日期 | 2026-07-22 |
| 状态 | 与实现同步 |
| 关联 | BN-SEC-DEV-001（开发指南）/ BN-SEC-HERMES-001（接入）/ BN-SEC-APPROVAL-001（审批） |

> 本文汇总 AgentSecurityD 的**全部对外接口**，供调用方（hermes / SDK / GUI / 第三方 Agent）
> 集成。共五类：① D-Bus 接口（权威）② Python 客户端封装 ③ WebUI REST/SocketIO
> ④ bncli 命令行 ⑤ hermes 插件钩子与环境变量。决策码统一：**0=ALLOW / 1=CONFIRM / 2=DENY**。

---

## 1. D-Bus 接口（io.bianbu.Security，权威）

- 总线：系统总线（生产）/ 会话总线（`BIANBU_SEC_SESSION=1`，测试）
- 服务名 `io.bianbu.Security`，对象路径 `/io/bianbu/Security`，接口 `io.bianbu.Security`
- 签名记法：s=string, i=int32, x=int64, b=bool, a=数组, {sv}=字典, ()=结构

### 1.1 方法（26）

| 方法 | in → out | 说明 |
|------|----------|------|
| `VerifyManifest` | s → b,s,aa{sv} | 验签+解析权限，返回 (valid, reason, perms) |
| `RegisterCapabilities` | s,aa{sv} → b | 写入能力（增量，ON CONFLICT 覆盖），默认 granted=1 |
| `BindAgent` | s → b | 由 Agent Runtime 建立当前 D-Bus caller 与 agent_id 的可信绑定 |
| `BindAgentV2` | s,a{sv} → b | 建立绑定并传递 session_id/run_id 追踪上下文（sender 凭据仍由服务端解析） |
| `CheckPermission` | s,s,s → i | 判权 (agent,cap,scope)→0/1/2 |
| `CheckPermissionV2` | s,s,s,a{sv} → i | 带 session_id/run_id 的判权，支持 once_per_session |
| `RequestConfirm` | s,s,s → b | 确认门禁（异步，L4 二次），等 RespondConfirm |
| `RequestConfirmV2` | s,s,s,a{sv} → b | 带 session_id/run_id 的确认门禁 |
| `RespondConfirm` | s,b → b | GUI/前端回传用户决定，唤醒 RequestConfirm |
| `RevokePermission` | s,s → b | 撤销授权（granted=-1）并清 session_trust |
| `BuildSandboxPolicy` | s → s,s | 生成 (seccomp_path, netfilter_rules) |
| `MeterTokens` | s,x,s → b,x | 计量 (agent,tokens,scope)→(within, remaining) |
| `AuditLog` | s,s,s,s → x | 写审计链 (agent,op,target,result)→seq |
| `ExportAudit` | s,s → s | 导出 (filter_json, fmt)→路径 |
| `VerifyAuditChain` | s → b | 离线验证哈希链完整性 |
| `SetNetworkPolicy` | s,as,s → b | 网络白名单 (agent,domains,mode) |
| `GetCapabilities` | s → aa{sv} | 查询已注册能力 |
| `SuspendAgent` | s,s → b | 管理面兼容操作/告警记录；Token 超限时由 `TokenExceeded`/`SecurityAlert` 通知 Agent Runtime/agent，securityd 不直接停止 Agent 服务 |
| `InstallPackage` | s → a{sv} | 完整安装，返回 {ok,reason,agent_id,count} |
| `ListAgents` | — → aa{sv} | 列所有 agent（含 name/version/status/能力数） |
| `SetCapabilityGranted` | s,s,s,i → b | 单条改授权态 (agent,cap,scope,granted:1/0/-1) |
| `GetAgentInfo` | s → a{sv} | agent 详情（manifest+能力+配额+网络，JSON） |
| `GetTokenBudget` | s → a{sv} | 查配额+用量 |
| `SetTokenBudget` | s,x,x,s → b | 设配额 (agent,conv,day,on_exceed) |
| `GetNetworkPolicy` | s → a{sv} | 查网络白名单（JSON） |

### 1.2 信号（4）

| 信号 | 载荷 | 触发时机 |
|------|------|---------|
| `SecurityAlert` | s,s,s (agent,type,detail) | 越权/审计失败/暂停等 |
| `ConfirmRequest` | s,s,s,s (agent,cap,detail,request_id) | RequestConfirm 触发，通知 UI |
| `ConfirmResponse` | s,b (request_id,approved) | RespondConfirm 后广播 |
| `TokenExceeded` | s,s,x,x (agent,scope,used,limit) | token 超限 |

### 1.3 错误码域 `io.bianbu.Error.*`

`PermissionDenied` / `ConfirmRequired` / `QuotaExceeded` / `InvalidManifest` /
`AuditFailure`（Fail-Closed） / `SandboxBuildFailed` / `NotFound` / `InvalidArgument` / `Internal`

---

## 2. Python 客户端封装（client/bianbu_security_client.py）

hermes / 第三方经此调 D-Bus，每个 D-Bus 方法一个同义函数。`BIANBU_SEC_SESSION=1`
走会话总线，否则系统总线。返回值已转为 Python 原生类型（dict/list/int/bool）。

```python
import bianbu_security_client as sc

# 判权与确认
sc.check_permission(agent_id, capability, scope="") -> int          # 0/1/2
sc.request_confirm(agent_id, capability, detail, timeout=60.0) -> bool
sc.respond_confirm(request_id, approved) -> bool

# 安装与能力
sc.verify_manifest(pkg_path) -> {"valid","reason","permissions"}
sc.install_package(pkg_path) -> {"ok","reason","agent_id","count"}
sc.register_capabilities(agent_id, perms:list[dict]) -> bool
sc.get_capabilities(agent_id) -> list[dict]
sc.set_capability_granted(agent_id, capability, scope, granted:int) -> bool
sc.revoke_permission(agent_id, capability) -> bool

# 列表与详情
sc.list_agents() -> list[dict]   # 字段见 2.1
sc.get_agent_info(agent_id) -> {"agent_id","manifest","capabilities","token_budget","network"}

# 配额 / 网络
sc.get_token_budget(agent_id) -> dict
sc.set_token_budget(agent_id, limit_conv, limit_day, on_exceed="pause_and_notify") -> bool
sc.meter_tokens(agent_id, tokens, scope="conv") -> {"within_limit","remaining"}
sc.get_network_policy(agent_id) -> dict
sc.set_network_policy(agent_id, domains:list, mode="whitelist") -> bool

# 沙箱 / 审计
sc.build_sandbox_policy(agent_id) -> {"seccomp_path","netfilter_rules"}
sc.audit_log(agent_id, op_type, target, result) -> int   # seq
sc.export_audit(filter_json, fmt="json") -> str          # 导出路径
sc.verify_audit_chain(export_path) -> bool
```

### 2.1 `list_agents()` 字段（WebUI Agent 清单）

| 字段 | 含义 |
|------|------|
| `agent_id` | Agent 主键 |
| `name` / `version` / `status` / `installed_at` | manifest 元信息；能力表里有、manifest 里没有的 Agent 不会有这几个键 |
| `capability_count` / `granted_count` | 能力总数与已授权数 |
| `last_seen` | **最近活动时间**（ISO-8601 UTC、毫秒），WebUI「最近活动」列格式化成本地时间展示 |
| `installed_at` | 安装时间（ISO-8601 UTC、毫秒）。与 `last_seen` 同一格式，前端按带时区时间解析，不会差时区 |

`last_seen` 取三类**真实活动**证据中的最新时间，securityd 不维护额外心跳表：

1. 审计链里该 Agent 最近一条记录（判权、Hook、管理动作等）；
2. 独立 syscall 审计链里最近一条拦截事件（`agent_id` 或 `worker_agent_id` 命中）；
3. `agent_binding.bound_at`：最近一次被 Runtime 拉起/绑定。

没有活动证据的 Agent（例如装了但从没跑过）返回空串，由展示层写成「暂无活动」：
manifest 的 `installed_at` **不是**活动证据，把它当成最近活动会让一个从没跑过的
Agent 显示成"最近活跃"，用户拿它和实际使用时间一对就对不上。

审计按月分片（`/var/log/bianbu/audit/YYYYMM.db`），读取时从当前分片向前回溯，最多 6 个分片；
任一路读取失败只降级该路证据，不影响清单本身。

---

## 3. WebUI REST / SocketIO（webui/app.py）

Flask 后端，默认 `0.0.0.0:8787`（跨主机；`LOCAL=1` 仅回环）。全部经客户端调 D-Bus。

### 3.1 REST 端点

| 方法 路径 | body / 参数 | 返回 |
|-----------|-------------|------|
| GET `/api/health` | — | {ok} |
| GET `/api/agents` | — | {agents:[...]} |
| GET `/api/agents/<aid>` | — | agent 详情 |
| POST `/api/install` | {pkg_path} | {ok,agent_id,count,reason} |
| POST `/api/agents/<aid>/capabilities/grant` | {capability,scope,granted} | {ok} |
| POST `/api/agents/<aid>/capabilities/add` | {capability,domain,risk_level,confirm,scope,granted} | {ok} |
| POST `/api/check` | {agent_id,capability,scope} | {decision,label} |
| POST `/api/agents/<aid>/suspend` | {reason} | {ok} |
| POST `/api/confirm/<request_id>` | {approved} | {ok} |
| GET `/api/audit?agent=<id>` | — | {records,chain_anchor,intact} |
| GET/POST `/api/agents/<aid>/token` | {limit_conv,limit_day,on_exceed} | 配额 / {ok} |
| GET/POST `/api/agents/<aid>/network` | {domains,mode} | 策略 / {ok} |
| GET/POST `/api/agents/<aid>/sandbox` | — | seccomp/netfilter 路径+内容 |
| POST `/api/sandbox/launch` | {agent_id,cmd} | {ok,output,returncode} |
| GET `/api/sandbox/processes` | — | {processes,count} |
| GET `/api/sandbox/demo/list` | — | {probes:[...]} |
| POST `/api/sandbox/demo/run` | {agent_id,probe_id} | {sandbox,host,...} 对比 |
| GET `/api/mapping` | — | {tools,capabilities,default_allow} |
| GET `/api/events` | — | SSE 流（SecurityAlert/ConfirmRequest/TokenExceeded） |

### 3.2 SocketIO（Web Terminal）

| 事件 | 方向 | 载荷 |
|------|------|------|
| `terminal_start` | 前→后 | {mode: shell/sandbox/hermes, agent_id} |
| `terminal_ready` | 后→前 | {pid,mode,agent_id} |
| `terminal_output` | 后→前 | {data} |
| `terminal_input` | 前→后 | {data} |
| `terminal_resize` | 前→后 | {rows,cols} |

---

## 4. 命令行（cli/bncli.py）

本地直调 SecurityEngine（不经 D-Bus），自举 sys.path。非 root 数据落
`~/.local/share/bianbu-securityd`（勿设 BIANBU_SEC_ROOT，否则连隔离根）。

| 命令 | 说明 |
|------|------|
| `bncli install <pkg_path>` | 验签+注册 Agent 包 |
| `bncli capability list <agent_id>` | 列出能力（JSON） |
| `bncli capability revoke <agent_id> <capability>` | 撤销能力 |
| `bncli audit export --agent <id> [--format json\|csv]` | 导出审计 |
| `bncli audit verify <export_path>` | 校验哈希链完整性 |

---

## 5. hermes 插件接口（hermes_plugin/bianbu_security）

### 5.1 钩子（register(manager) 注册）

| 钩子 | 行为 | 对接 |
|------|------|------|
| `pre_tool_call(tool_name,args,...)` | 判权+确认门禁；返回 `{"action":"block","message":...}` 拦截，`None` 放行 | CheckPermission；CONFIRM→hermes TUI/RequestConfirm |
| `post_tool_call(tool_name,args,result,...)` | 写审计链（观察者） | AuditLog |
| `on_session_end(...)` | 会话结束记审计 | AuditLog |

工具→能力映射见 `mapping.py`（GET `/api/mapping` 可查），覆盖 hermes 全部 47 工具。

### 5.2 环境变量

| 变量 | 默认 | 作用域 | 说明 |
|------|------|--------|------|
| `BIANBU_HERMES_AGENT_ID` | com.hermes.agent | 插件 | 会话对应的 securityd Agent id |
| `BIANBU_SEC_APPROVAL_MODE` | securityd | 插件 | **仅对 CONFIRM 生效**：securityd(WebUI 点批准，关 hermes approval)/ hermes(交 hermes TUI 弹框)/ both(叠加)。ALLOW/DENY 不受影响 |
| `BIANBU_SECURITY_FAIL_OPEN` | 0 | 插件 | securityd 不可达：0 拦截 / 1 放行 |
| `BIANBU_SEC_CLI_CONFIRM` | (未设) | 插件 | =0 强制视为非交互（回退信号路径） |
| `BIANBU_SEC_SESSION` | (未设) | 客户端/服务 | =1 走会话总线（测试） |
| `BIANBU_SECURITYD_HOME` | — | 插件/启动器 | 指向实现根，供 import client/mapping |
| `HERMES_YOLO_MODE` | — | hermes | securityd 模式下启动器注入=1，关 hermes 自带 approval |
| `BIANBU_SEC_ROOT` | (未设) | 服务/CLI | 隔离数据根（测试）；非 root 未设则用 XDG |
| `BIANBU_SEC_APPROVAL_MODE=hermes` 场景 | — | — | 交互式 CLI(hermes chat) 唯一可行的确认方式（详见 BN-SEC-APPROVAL-001 §10） |

### 5.3 沙箱启动器 `hermes_sandbox_launch.py`

| 参数 | 默认 | 说明 |
|------|------|------|
| `--agent <id>` | com.hermes.agent | securityd Agent id |
| `--rw-dir <dir>` | AGENTS_HOME/<id>/rw | 私有可写目录 |
| `--hermes-config <dir>` | ~/.hermes | 配置目录（可写绑定进沙箱） |
| `--net` / `--no-net` | `--net` | 联网（共享宿主网络+DNS+CA）/ 禁网 |
| `--batch` | 关（默认交互） | 批处理捕获输出 / 交互继承 tty |
| `--quiet` | 关 | 抑制启动详情打印（供纯净捕获） |

---

## 6. 调用速查（典型集成）

```python
# hermes 插件判权流（pre_tool_call 内）
cap, scope = mapping.resolve(tool_name, args)       # 工具→能力
d = sc.check_permission(agent_id, cap, scope)       # 0/1/2
if d == 2: return {"action":"block", ...}           # DENY 硬拦
if d == 1: ...                                       # CONFIRM：按 APPROVAL_MODE 走 TUI/WebUI
# ALLOW 放行；执行后 sc.audit_log(...) 记账
```

*BN-SEC-API-001 · 与 impl/bianbu-securityd 实现同步。决策码 0=ALLOW/1=CONFIRM/2=DENY。*
