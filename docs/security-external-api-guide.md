# Bianbu Security 对外接口指南

本文档面向 Bianbu Agent Runtime、Worker、WebUI、插件开发者和 AI Agent，汇总当前 securityd 已实现的对外接口。

## 1. 接口总览

| 接口面 | 传输 | 服务/对象 | 主要调用方 | 说明 |
|---|---|---|---|---|
| Security 主接口 | 用户会话 D-Bus | `io.bianbu.Security`，通常为 `/io/bianbu/Security` | Runtime、管理台、安装器 | 身份、能力、判权、确认、审计、DLP、Token、策略 |
| Runtime 接口 | 用户会话 D-Bus | `io.bianbu.Security.Runtime`，对象 `/io/bianbu/Security/Runtime` | Runtime 控制面和 Worker Supervisor | Worker 启动租约、沙箱策略、提交/撤销和状态 |
| Runtime 管理接口 | 系统/用户 D-Bus | `io.bianbu.Runtime` | Runtime 生命周期消费者 | Agent 启停、暂停、检查点、资源和消息 |
| Worker 数据面 | Unix Domain Socket | 默认 `${BIANBU_SEC_UDS}` | 受认证的 Agent Worker | 判权、DLP、审计、Token、确认和能力读取 |
| 管理 WebUI | HTTP | securityd WebUI，默认 `:8787` | 管理员浏览器/自动化管理工具 | 登录、Agent/能力/策略/审计/DLP/沙箱管理 |
| Python 客户端 | Python | `client/bianbu_security_client.py` | Runtime/插件 | D-Bus/UDS 的类型转换和兼容封装 |

XML 定义是 D-Bus 签名的权威来源：`data/io.bianbu.Security.xml`、`data/io.bianbu.Runtime.xml`。源码行为和权限以 `securityd/service.py`、`runtime/runtime_service.py` 为准。

## 2. 通用约定

### 2.1 D-Bus 类型

常见签名：

- `s`：UTF-8 字符串。
- `b`：布尔值。
- `i`：32 位整数。
- `x`：64 位整数。
- `as`：字符串数组。
- `a{sv}`：字符串到 Variant 的字典。
- `aa{sv}`：字典数组。

Python 客户端应使用 `_sv()` 将值转换为 `dbus.Dictionary(..., signature="sv")`，不要直接传普通嵌套 dict。

### 2.2 身份和权限

securityd 不信任请求体中的 `agent_id`。它通过 D-Bus sender 的 UID、PID、可执行文件、cgroup 和已登记 binding 验证调用者。

- Runtime 管理调用通常要求 `bianbu-security` 或 `bianbu-admin` 组，生产环境不应设置 `BIANBU_SECURITY_TEST_ADMIN=1`。
- Agent 自身只能访问已绑定身份对应的资源。
- 管理员/root 可执行管理操作，但管理员写能力不会覆盖 Agent 的运行 binding。
- UDS 使用 `SO_PEERCRED`，并在存在 Worker lease 时校验 PID、cgroup、instance_id 和 lease_id。
- 变更、判权、确认、DLP 和 Runtime 启动事件均应产生审计记录；审计失败时按各接口定义拒绝或降级。

### 2.3 错误处理

D-Bus 错误以 `dbus.exceptions.DBusException` 返回；UDS 错误响应为 `{ "ok": false, "error": "..." }`；HTTP 通常返回 JSON 错误和 4xx/5xx 状态码。

高危能力在 securityd 不可达时默认 fail-closed。开发态 `optional` 只影响启动兼容，不应被理解为绕过工具判权。

## 3. `io.bianbu.Security` D-Bus 接口

### 3.1 代码和 manifest 校验

| 方法 | 签名 | 作用 |
|---|---|---|
| `VerifyManifest` | `s -> (b,s,aa{sv})` | 校验 Agent 包 manifest、签名和声明能力。返回 `valid/reason/perms`。 |
| `VerifyCodePackage` | `ss -> a{sv}` | 校验 hook/tool/skill 包路径。返回 `allowed/signed/valid/digest/policy/reason/key_id`。 |
| `VerifyCodeDigest` | `sss -> a{sv}` | 对调用方提供的摘要、签名和包类型进行跨 mount namespace 验签。 |

`kind` 通常为 `hook`、`tool` 或 `skill`。安装器应以 `allowed` 为最终安装门槛，并把 `reason` 展示给用户。

### 3.2 Agent 与能力 CRUD

| 方法 | 签名 | 语义 |
|---|---|---|
| `RegisterAgent` | `sa{sv} -> a{sv}` | 创建或 upsert Agent 基础身份；当前更新 `name/version/status`。 |
| `UnregisterAgent` | `s -> b` | 删除 Agent manifest、能力、binding、session trust 和安全模式。 |
| `RegisterCapabilities` | `saa{sv} -> b` | 增量注册能力；每项可带 `granted`、`scope`、`risk_level` 等字段。 |
| `SyncAgentCapabilities` | `saa{sv} -> a{sv}` | 全量替换 Agent 能力声明，Runtime 同步配置时使用。返回 `agent_id/count/status`。 |
| `GetCapabilities` | `s -> aa{sv}` | 读取 Agent 当前能力声明。 |
| `RevokePermission` | `ss -> b` | 撤销 Agent 的指定能力。 |
| `SetCapabilityGranted` | `sssi -> b` | 修改单项能力授权状态，`granted=0/1`。 |
| `ListAgents` | `` -> aa{sv}` | 返回非敏感 Agent 清单。 |
| `GetAgentInfo` | `s -> a{sv}` | 返回 Agent 安全相关信息。 |

推荐 Runtime 流程：先 `RegisterAgent`，绑定后调用 `SyncAgentCapabilities`；不要用多次增量注册模拟全量同步。

### 3.3 身份绑定和判权

| 方法 | 签名 | 作用 |
|---|---|---|
| `BindAgent` | `s -> b` | 以服务端解析的 D-Bus caller 身份建立 Agent binding。 |
| `BindAgentV2` | `sa{sv} -> b` | 带 session/run 上下文的绑定；上下文不能伪造 sender 凭据。 |
| `ResetAgentBinding` | `ss -> b` | 管理员/root 清理升级或异常遗留 binding；必须提供原因。 |
| `CheckPermission` | `ss s -> i` | 检查 `agent_id/capability/scope`；返回安全决策码。 |
| `CheckPermissionV2` | `sssa{sv} -> i` | 带会话、运行和请求上下文的判权。 |
| `GrantSessionTrustV2` | `sssa{sv} -> b` | 为指定 session 授予能力信任。 |
| `RequestConfirm` | `sss -> b` | 请求用户确认高风险操作。 |
| `RequestConfirmV2` | `sssa{sv} -> b` | 带上下文的用户确认请求。 |
| `RespondConfirm` | `sb -> b` | 管理前端提交确认结果，按 request_id 唤醒等待方。 |

判权返回值的具体数值由 securityd 策略定义；调用方应使用客户端常量/策略映射，不要硬编码“非零即允许”。

### 3.4 沙箱、网络和资源策略

| 方法 | 签名 | 作用 |
|---|---|---|
| `BuildSandboxPolicy` | `s -> (s,s)` | 根据 Agent 策略生成 seccomp 路径和网络过滤规则。 |
| `SetNetworkPolicy` | `sas -> b` | 设置 Agent 网络域名列表和模式：`agent_id, domains, mode`。 |
| `GetNetworkPolicy` | `s -> a{sv}` | 读取网络策略。 |
| `GetSandboxPolicy` | `s -> a{sv}` | 按 Runtime lease 读取沙箱策略，详见 Runtime 接口。 |
| `SuspendAgent` | `ss -> b` | 暂停 Agent；原因进入审计链。 |

网络模式和域名白名单必须由策略生成器解释；Worker 不应自行扩大白名单。

### 3.5 Token、审计和事件

| 方法 | 签名 | 作用 |
|---|---|---|
| `MeterTokens` | `sx s -> (b,x)` | 按 scope 计量 Token，返回是否在限额内和剩余量。 |
| `MeterTokensV2` | `sxsa{sv} -> (b,x)` | 带 session/run 上下文的 Token 计量。 |
| `GetTokenBudget` | `s -> a{sv}` | 读取 Token 限额。 |
| `SetTokenBudget` | `sxxs -> b` | 设置会话/每日限额及超限策略。 |
| `AuditLog` | `ssss -> x` | 写入一条审计记录，返回链上序号。 |
| `ExportAudit` | `ss -> s` | 按 JSON filter 和格式导出审计文件，返回路径。 |
| `VerifyAuditChain` | `s -> b` | 校验导出文件或审计链完整性。 |

信号：

- `SecurityAlert(agent_id, type, detail)`：安全告警。
- `ConfirmRequest(agent_id, capability, detail, request_id)`：待用户确认。
- `ConfirmResponse(request_id, approved)`：确认结果。
- `TokenExceeded(agent_id, scope, used, limit)`：兼容版 Token 超限事件。
- `TokenExceededV2(agent_id, event)`：包含 session/run/policy 上下文的超限事件。

### 3.6 包和管理台辅助方法

| 方法 | 签名 | 作用 |
|---|---|---|
| `InstallPackage` | `s -> a{sv}` | 管理员安装已校验的安全包。返回 `ok/reason/agent_id/count`。 |
| `GetAgentSecurityMode` | `s -> a{sv}` | 读取 `normal/yolo` 等安全模式。 |
| `SetAgentSecurityMode` | `ss -> a{sv}` | 管理员修改 Agent 安全模式并审计。 |

## 4. `io.bianbu.Security.Runtime` D-Bus 接口

该接口是 Worker 的启动信任边界，不是普通能力 CRUD。

| 方法 | 签名 | 使用时机 |
|---|---|---|
| `PrepareStart` | `sa{sv} -> a{sv}` | Runtime 请求一次性启动 lease。请求包含 `requested_mode`、数据根、socket 根、entrypoint 等。 |
| `GetSandboxPolicy` | `s -> a{sv}` | Worker Supervisor 根据 lease 获取 bwrap/seccomp/网络挂载策略。 |
| `CommitStart` | `ssxsa{sv} -> a{sv}` | Worker 成功启动后提交 `instance_id/pid/cgroup/attestation`。 |
| `AbortStart` | `ss -> b` | 启动失败、超时或模式不匹配时释放 lease。 |
| `RevokeAgent` | `ss -> b` | 管理员/Runtime 撤销 Agent 的运行资格。 |
| `GetRuntimeState` | `s -> a{sv}` | 查询 Agent 当前 Runtime 状态。 |
| `ListRuntimeInstances` | `s -> aa{sv}` | 查询 Agent 的所有运行实例。 |

典型流程：

```text
PrepareStart
    -> effective_mode/backend/sandbox_required
    -> (sandbox) GetSandboxPolicy
    -> 创建 host-process 或 bwrap Worker
    -> CommitStart
    -> Worker UDS worker.identity
```

lease 是一次性的；重复提交、PID/cgroup 不匹配、模式与实际 namespace 不匹配都应失败并审计。

## 5. `io.bianbu.Runtime` 管理 D-Bus 接口

这是 Runtime 生命周期兼容接口，定义于 `data/io.bianbu.Runtime.xml`：

| 方法 | 作用 |
|---|---|
| `Register(agent_id, name, metadata)` | 注册 Agent。 |
| `Start(agent_id)` / `Pause(agent_id, snapshot)` / `Resume(agent_id)` | 启停和暂停恢复。 |
| `Stop(agent_id)` / `Terminate(agent_id)` | 正常停止或强制终止。 |
| `Checkpoint(agent_id)` / `Restore(agent_id, checkpoint_id)` | 创建和恢复检查点。 |
| `ListCheckpoints(agent_id)` | 列出检查点。 |
| `GetResourceStats(agent_id)` | 获取资源统计。 |
| `ExportResourceHistory(agent_id, format)` | 导出资源历史。 |
| `List()` | 列出 Agent。 |
| `SendMessage(from, to, payload)` | Agent 间消息。 |
| `CanCall(agent_id, session_id, operation)` | 检查 Agent 是否可调用某操作。 |

信号：`StateChanged(agent_id, old, new)`、`ResourceExceeded(agent_id, resource, value)`。

## 6. Worker UDS 数据面

### 6.1 协议

默认 socket 由 `BIANBU_SEC_UDS` 指定。帧格式：4 字节大端长度 + UTF-8 JSON；请求和响应一一对应。实现见 `securityd/uds_protocol.py` 和 `client/bianbu_security_uds.py`。

除 `ping` 外，每个请求都应包含 `agent_id`。Worker lease 请求还需由客户端自动附带内部字段 `_worker_instance_id`、`_worker_lease_id`，这些字段不能由 HTTP 请求直接提供。

### 6.2 操作清单

| op | 必要字段 | 返回 | 说明 |
|---|---|---|---|
| `ping` | 无 | `pong/peer_uid/peer_pid` | 连通性和 peer 凭据探测。 |
| `permission.check` | `agent_id, capability`；可选 `scope, session_id` | `decision` | Worker 判权。 |
| `session.trust` | `agent_id, capability, session_id` | `accepted` | 授予 session 信任。 |
| `confirm.request` | `agent_id, capability, detail` | `approved` | 请求用户确认。 |
| `token.meter` | `agent_id, tokens, scope` | `within_limit, remaining` | Token 计量。 |
| `dlp.policy` | `agent_id` | `effective_policy` | 读取中央 DLP 策略，只读。 |
| `dlp.scan` | `agent_id, text` | `has_pii, findings, masked_text, max_risk, effective_policy, audit_seq` | 扫描并脱敏；响应不返回 finding 原文。 |
| `audit.log` | `agent_id, op_type`；可选 `target,result` | `audit_seq` | 写单条审计。 |
| `audit.batch` | `agent_id, _request_id, entries[1..100]` | `audit_seq, accepted` | 批量审计，每批最多 100 条。 |
| `capabilities.list` | `agent_id` | `capabilities` | 读取 Agent 能力目录。 |
| `worker.identity` | `agent_id` + 内部 lease 字段 | `authorized, agent_id, pid, cgroup` | Worker 启动握手和身份证明。 |

UDS 服务器会限制 payload 大小、校验字段类型，并在 `SO_PEERCRED` 不可用或 caller/binding 不匹配时拒绝请求。

## 7. securityd WebUI HTTP 接口

默认启动方式见 `webui/run.sh`/`run-system-bus.sh`，默认端口 `8787`。除健康检查和静态资源外，接口需要 WebUI 登录 session 或本地管理员认证。

### 7.1 登录与基础

| 方法 | 路径 | 作用 |
|---|---|---|
| `POST` | `/api/auth` | 管理员登录。 |
| `POST` | `/api/auth/local` | 本地开发登录。 |
| `GET` | `/api/health` | 健康检查。 |
| `GET` | `/api/events` | 管理事件流。 |

### 7.2 Agent、能力和策略

| 方法 | 路径 | 作用 |
|---|---|---|
| `GET` | `/api/agents` | Agent 列表。 |
| `GET` | `/api/agents/<aid>` | Agent 详情。 |
| `GET/POST` | `/api/agents/<aid>/security-mode` | 读取/修改安全模式。 |
| `POST` | `/api/install` | 安装安全包。 |
| `POST` | `/api/agents/<aid>/capabilities/grant` | 设置单项能力授权。 |
| `POST` | `/api/agents/<aid>/capabilities/add` | 增加能力声明。 |
| `POST` | `/api/agents/<aid>/suspend` | 暂停 Agent。 |
| `GET/POST` | `/api/agents/<aid>/token` | 读取/修改 Token 限额。 |
| `GET/POST` | `/api/agents/<aid>/network` | 读取/修改网络策略。 |
| `GET/POST` | `/api/agents/<aid>/sandbox` | 读取/修改沙箱策略。 |
| `POST` | `/api/check` | 管理台判权测试。 |

### 7.3 审计、确认、DLP 和沙箱

| 方法 | 路径 | 作用 |
|---|---|---|
| `GET` | `/api/audit` | 查询审计记录。 |
| `GET` | `/api/audit/hook-points` | 查询 Hook 点。 |
| `POST` | `/api/confirm/<request_id>` | 提交确认结果。 |
| `GET` | `/api/dlp/matrix` | DLP 生效矩阵。 |
| `POST/DELETE` | `/api/dlp/policy` | 新增/删除 DLP 策略。 |
| `GET` | `/api/dlp/policies` | 列出 DLP 策略。 |
| `POST` | `/api/dlp/scan` | 管理台 DLP 扫描。 |
| `GET` | `/api/dlp/stats` | DLP 统计。 |
| `POST` | `/api/sandbox/launch` | 启动沙箱演示/测试进程。 |
| `GET` | `/api/sandbox/processes` | 沙箱进程列表。 |
| `GET` | `/api/sandbox/demo/list` | 演示项列表。 |
| `POST` | `/api/sandbox/demo/run` | 执行沙箱演示。 |
| `GET` | `/api/langgraph/interrupts` | 查询 LangGraph 中断。 |
| `POST` | `/api/langgraph/resume` | 恢复 LangGraph 中断。 |
| `POST` | `/api/langgraph/graphs/<graph_id>/register` | 注册 LangGraph 图。 |
| `GET` | `/api/mapping` | 查看工具/能力映射。 |

HTTP 路由最终通过 D-Bus security service 执行，不能把 WebUI 认证当成绕过 D-Bus caller 校验的方式。

## 8. Runtime Python 客户端封装

`client/bianbu_security_client.py` 当前提供的主要函数：

```python
register_agent(agent_id, metadata=None)
unregister_agent(agent_id)
sync_agent_capabilities(agent_id, capabilities)
register_capabilities(agent_id, perms)
bind_agent(agent_id)
bind_agent_v2(agent_id, context=None)
reset_agent_binding(agent_id, reason="")
check_permission(agent_id, capability, scope="")
check_permission_v2(agent_id, capability, scope="", context=None)
prepare_runtime_start(agent_id, requested_mode="auto", **request)
get_runtime_sandbox_policy(lease_id)
commit_runtime_start(lease_id, instance_id, pid, cgroup_path, attestation=None)
abort_runtime_start(lease_id, reason)
revoke_runtime_agent(agent_id, reason)
get_runtime_state(agent_id)
list_runtime_instances(agent_id)
verify_manifest(agent_pkg_path)
verify_code_package(pkg_path, kind="hook")
```

当 Worker UDS 已启用时，`bind_agent`、`check_permission` 等函数会自动切换到 UDS 数据面；调用方不应自行猜测或拼接内部 socket 请求。

## 9. Agent Runtime 推荐集成流程

### 注册和同步

```text
Runtime 启动
  -> RegisterAgent(agent_id, {name, version})
  -> BindAgent/BindAgentV2
  -> SyncAgentCapabilities(agent_id, full_capability_list)
```

### 启动 Worker

```text
读取 Agent requested_mode(host/sandbox)
  -> PrepareStart
  -> sandbox 时获取 GetSandboxPolicy
  -> 创建 host-process 或 bwrap
  -> CommitStart
  -> Worker 通过 UDS worker.identity 完成握手
```

### 工具调用

```text
Worker -> permission.check
      -> 必要时 confirm.request
      -> 执行工具前后 audit.log/audit.batch
      -> 高风险或 DLP 失败按 fail-closed 处理
```

### 删除

```text
停止 Worker
  -> RevokeAgent/AbortStart（如有 lease）
  -> UnregisterAgent
```

## 10. 安全注意事项

1. 不要把 `agent_id`、`granted`、`sandboxed` 或 `effective_mode` 仅当作客户端声明；最终值必须由 securityd/内核凭据证明。
2. 不要在生产环境设置 `BIANBU_SECURITY_TEST_ADMIN=1`、`BIANBU_SECURITY_SKIP_DIGEST=1` 或允许 unmanaged fallback。
3. `RegisterAgent` 是 upsert，不是授权接口；能力授权必须使用 `SyncAgentCapabilities`、`RegisterCapabilities` 或管理接口。
4. `SetAgentSecurityMode(yolo)` 只改变安全判定模式，不等于跳过审计；所有请求仍应记录 yolo 上下文。
5. `BIANBU_SANDBOX=agent` 是开发启动选择，不应替代 Agent 元数据中的 per-Agent `requested_mode`。
6. securityd 不可达时，低风险只读功能可显示 degraded；高风险工具必须保持 fail-closed。

## 11. 版本和事实来源

本文档对应当前源码快照。发布接口变更时必须同时更新：

- `data/io.bianbu.Security.xml`
- `data/io.bianbu.Runtime.xml`
- `securityd/service.py` 或 `runtime/runtime_service.py`
- `client/bianbu_security_client.py`
- 本文档和相关集成测试

可用以下命令快速核对接口是否漂移：

```bash
busctl --user introspect io.bianbu.Security /io/bianbu/Security
busctl --user introspect io.bianbu.Security /io/bianbu/Security/Runtime
```
