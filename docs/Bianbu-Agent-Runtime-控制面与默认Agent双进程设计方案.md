# Bianbu Agent Runtime 控制面与默认 Agent 双进程设计方案

| 项 | 内容 |
|---|---|
| 文档编号 | BN-SEC-RUNTIME-CPDP-001 |
| 版本 | V0.1 |
| 来源 | Bianbu Next PRD V0.9、SRS/HLD/LLD、`BN-SEC-RUNTIME-001`、PA `bianbu-agent-runtime` 当前实现 |
| 日期 | 2026-08-21 |
| 状态 | P0～P4 代码与定向测试已完成；Worker 开发态双进程与 bwrap 已实机验证；商用交付待正式签名材料与安装验收 |
| 适用对象 | `bianbu-agent-runtime`、`bianbu-securityd`、安装器、systemd、测试与交付团队 |
| 当前对接对象 | PA Bianbu Agent Runtime：`/data/workspace2026-new/work0618/bianbu-agent-security/bianbu-agent-runtime` |

## 1. 结论摘要

当前 `bianbu-agent serve` 是一个单进程 Runtime：同一进程既提供 HTTP/API 控制面，
又加载默认 Agent、模型、Skill、Tool、Plugin 并执行对话。该形态适合开发验证，但不
适合商用地表达“Runtime 负责管理 Agent，Agent 按策略运行在 host 或 sandbox 中”。

本方案将 Runtime 拆为两个长期职责明确的进程：

```text
bianbu-agent-runtime-control       控制面（Runtime Manager）
        │ HTTP/API、会话路由、策略、生命周期、审计、健康检查
        │ Unix Socket RPC
        ▼
bianbu-agent-runtime-agent         默认 Agent 数据面（Worker）
        │ LangGraph、模型、Skill、Tool、Plugin、Run 执行
        ├─ HostProcessBackend：宿主机受控进程
        └─ Bwrap/OCIBackend：隔离进程
```

推荐的商用默认值是：

| 进程 | 默认位置 | 是否可配置 | 说明 |
|---|---|---|---|
| Runtime 控制面 | host | 可选，但不建议默认 sandbox | 持有 `9899`、管理 Worker 和所有外部请求 |
| 默认 Agent Worker | 由 `security.runtime` 决定 | `auto`/`sandbox`/`host` | 由用户请求、设备策略和 Agent 信任状态共同裁决 |

因此，用户可以在 Runtime 启动时选择默认 Agent 的运行偏好：

```yaml
runtime:
  default_agent:
    execution:
      requested_mode: sandbox   # auto | sandbox | host
```

`requested_mode` 只是请求，不是授权结果。最终使用的 `effective_mode`、后端、挂载、
网络、资源和租约必须由 `security.runtime` 返回。控制面不得因为用户请求 `host` 而
绕过安全策略；Worker 不得自行修改策略或创建同级容器。

控制面也可以单独配置是否在 sandbox 中运行，但这是独立于默认 Agent 的第二个开关：

```yaml
runtime:
  control:
    execution:
      requested_mode: host       # host | sandbox；商用默认 host
```

控制面进入 sandbox 时，必须由受信 Runtime Manager 解决 `9899` 的入口转发、systemd
生命周期和安全服务访问，不能简单地把现有 `run.sh` 套在整个程序外面。第一阶段建议
固定控制面 host，仅让默认 Agent Worker 选择 host/sandbox；控制面 sandbox 作为后续
增强项，未经独立验收不得作为生产默认值。

本方案不把 `io.bianbu.Runtime` 作为当前实现入口。当前实际对接对象仍是 PA 仓库中的
`bianbu_agent`，PA 通过 `bianbu_security_client` 调用 `io.bianbu.Security.Runtime`。

## 2. 背景与问题

### 2.1 当前单进程形态

当前代码的主要启动链路是：

```text
systemd 或 run.sh
  └─ bianbu-agent serve
       └─ BianbuAgentRuntime
            ├─ FastAPI/Uvicorn（9899）
            ├─ AgentManager / SessionManager / RunManager
            ├─ Plugin/Tool/Skill/MCP 加载
            ├─ LangGraph Engine 和模型调用
            └─ SecurityRuntimeClient / ExecutionCoordinator
```

`BianbuAgentRuntime.start()` 目前会加载默认 Agent，并执行进程级
`PrepareStart → CommitStart` 证明；`ExecutionCoordinator` 已具备启动受控 child 的
host/bwrap 后端和生命周期记录，但普通对话仍然在当前 Runtime 进程内运行。换言之，
当前 child 执行能力是双进程架构的基础，但还没有把默认 Agent 对话迁移到独立 Worker。

### 2.2 单进程商用风险

| 风险 | 后果 |
|---|---|
| 控制面和 Agent 代码共用地址空间 | Tool/Plugin/Skill 代码故障可能影响 HTTP 控制面 |
| 控制面持有所有执行对象 | Agent 代码天然接触 API、会话和更多运行时状态 |
| `systemd` 直接启动 `bianbu-agent serve` | 能管理进程，但不能让默认 Agent 自动成为独立 sandbox Worker |
| `run.sh` 负责整进程 bwrap | 能验证隔离，不能绑定某个 Agent 包、租约和策略快照 |
| HTTP 请求和执行命令边界不清晰 | 容易把用户输入误当成进程启动参数 |
| Runtime 重启与 Agent 重启耦合 | 控制面升级、API 连接断开会同时终止对话执行 |
| 默认 Agent 运行模式无独立实例记录 | 难以审计 PID、cgroup、namespace、policy digest 和 worker 状态 |

### 2.3 设计目标

1. 控制面和默认 Agent 数据面进程隔离，控制面不加载不可信 Tool/Plugin 执行代码。
2. Runtime 启动时可声明控制面和默认 Agent 的模式偏好；最终模式由 securityd 裁决。
3. 控制面持有公网 HTTP，Worker 只通过受限 Unix Socket 与控制面通信。
4. 每个 Worker 启动都绑定签名 Agent manifest、配置摘要、策略摘要和一次性 lease。
5. sandbox/host 两种 Worker 均由 Runtime 创建、停止、撤销、监控和回收。
6. securityd 不可用、握手失败、策略无法应用或证明不一致时 fail-closed。
7. 保留现有 `/api/v1/runs` 兼容外部客户端，内部转发到 Worker。
8. `run.sh` 保留为开发入口，不成为商用生命周期的安全根。

### 2.4 非目标

- 本方案不让 securityd 直接 `fork/exec` 第三方 Agent。
- 第一阶段不要求 Docker/containerd；K3 使用 bwrap，后续可增加 OCIBackend。
- 本方案不改变 capability、Confirm、DLP、Token 和审计的既有业务语义。
- 本方案不把远端 HTTP MCP 伪装成本地容器进程；远端访问仍由网络策略和 DLP 管控。

## 3. 术语与边界

| 术语 | 定义 |
|---|---|
| 控制面（Control Plane） | `bianbu-agent-runtime-control`，对外提供 API，负责路由、策略、生命周期和观测 |
| 默认 Agent Worker | `bianbu-agent-runtime-agent`，加载一个默认 Agent 配置并执行对��和工具 |
| Runtime | 本文默认指 PA `bianbu-agent-runtime`，不是 securityd 仓库中的参考 `io.bianbu.Runtime` |
| requested_mode | 用户或配置声明的偏好：`auto`、`sandbox`、`host` |
| effective_mode | securityd 根据策略返回的最终模式：`sandbox` 或 `host` |
| control instance | 控制面自身的 systemd/user service 实例 |
| agent instance | 一次 Worker 启动，对应一个 `instance_id` 和一个一次性 lease |
| Worker RPC | 控制面与 Worker 间版本化 Unix Socket 协议 |
| Runtime Endpoint | Worker 获取安全身份、取消、审批、模型代理和健康信息的受限接口 |

## 4. 目标架构

### 4.1 逻辑架构

```text
                          外部客户端/桌面入口
                                  │ HTTP 9899
                                  ▼
┌──────────────────────────────────────────────────────────────┐
│ bianbu-agent-runtime-control                                  │
│                                                              │
│  HTTP API / Auth boundary                                    │
│  Session & Run Router                                        │
│  Agent Manifest/Config Reader（只读元数据）                  │
│  SecurityRuntimeClient（Prepare/Commit/Revoke）              │
│  ExecutionCoordinator / Backend Selector                     │
│  Worker Supervisor / Health / Orphan Reaper                  │
│  Audit Correlator / Metrics                                  │
└───────────────┬─────────────────────────┬────────────────────┘
                │ control RPC (UDS)       │ security client
                │                         ▼
                │               securityd / security.runtime
                │               D-Bus + restricted UDS
                ▼
┌──────────────────────────────────────────────────────────────┐
│ bianbu-agent-runtime-agent (default Agent Worker)             │
│                                                              │
│  Worker RPC server / Run executor                            │
│  Agent config + model resolver                               │
│  LangGraph Engine                                            │
│  Tools / Skills / Plugins / MCP                             │
│  Security middleware（带 instance/session 身份）             │
└──────────────────────────────────────────────────────────────┘
                ▲
                │ HostProcessBackend 或 Bwrap/OCIBackend
                ▼
      host process / sandbox namespace / cgroup / proxy
```

### 4.2 物理部署视图

推荐的生产部署：

```text
systemd --user
  └─ bianbu-agent-runtime-control.service
       ├─ /usr/bin/bianbu-agent-runtime --role control
       └─ 受控 Worker（按实例启动）
            └─ /usr/bin/bianbu-agent-runtime --role agent-worker ...

systemd system service
  └─ bianbu-securityd.service

端口/Socket：
  0.0.0.0:9899                      控制面 HTTP（可配置）
  $XDG_RUNTIME_DIR/bianbu-agent/    控制面和 Worker 私有 Socket
  /run/bianbu/securityd.sock         securityd 数据面 UDS
  io.bianbu.Security                 securityd 控制面 D-Bus
```

控制面默认运行在 host 的原因：

- 需要稳定持有 HTTP 监听端口和桌面启动入口；
- 需要管理 Worker 的 PID/cgroup/namespace，并在控制面重启后回收孤儿；
- 不加载第三方 Tool/Plugin，攻击面小于 Agent Worker；
- 控制面若进入 bwrap，必须额外设计 host 端口代理和 supervisor，不能仅靠环境变量。

### 4.3 控制面 sandbox 的可选形态

设计上允许：

```text
runtime.control.execution.requested_mode = sandbox
```

但此时应由 systemd/Runtime Manager 创建控制面 sandbox，并通过以下方式之一提供
外部入口：

1. systemd socket activation：宿主监听 `9899`，控制面只接收已打开的 FD；
2. 宿主反向代理：宿主小型 ingress 将请求转发到控制面 UDS；
3. 专用 loopback 代理：宿主代理将端口映射到 sandbox 内服务。

控制面 sandbox 不得直接通过 bwrap 绑定完整 `/run/dbus/system_bus_socket`，只允许
安全客户端所需的最小接口。第一阶段不实现该路径，不将其纳入生产默认验收。

## 5. 运行模式模型

### 5.1 两层模式选择

控制面和默认 Agent Worker 使用两个独立配置项：

```yaml
runtime:
  control:
    execution:
      requested_mode: host
  default_agent:
    execution:
      requested_mode: sandbox
```

含义如下：

| 配置项 | 作用对象 | 推荐默认值 | 安全裁决 |
|---|---|---:|---|
| `runtime.control.execution.requested_mode` | Runtime 控制面 | `host` | 安装/设备策略；sandbox 需入口代理能力 |
| `runtime.default_agent.execution.requested_mode` | 默认 Agent Worker | `auto` 或 `sandbox` | `security.runtime.PrepareStart` |

### 5.2 配置优先级

生产环境采用以下优先级，越靠前越高：

1. 安装包/设备强制策略（不可被用户覆盖）；
2. 受信 Runtime Manager 启动参数；
3. `runtime.default_agent.execution.requested_mode`；
4. Agent manifest 的 `metadata.execution.requested_mode`；
5. 开发环境兼容变量 `BIANBU_SANDBOX=agent`；
6. 默认 `auto`。

HTTP 请求只能选择 `requested_mode` 偏好，不能提交 command、entrypoint、mount、
digest、seccomp 或 network。控制面将偏好传给 securityd，不能本地升权。

### 5.3 Security Runtime 裁决

```text
requested_mode
      │
      ▼
      │
      ├─ 低风险、已登记 manifest、摘要匹配、host 约束可用
      │       └─ effective_mode=host / backend=host-process
      │
      ├─ 用户请求 sandbox，或高风险/不可信/设备强制隔离
      │       └─ effective_mode=sandbox / backend=bwrap 或 oci
      │
      └─ 策略/客户端/摘要/后端不可用
              └─ 拒绝启动（fail-closed）
```

securityd 返回的 policy 必须至少包含：

```json
{
  "agent_id": "com.bianbu.agent",
  "requested_mode": "auto",
  "effective_mode": "sandbox",
  "backend": "bwrap",
  "sandbox_required": true,
  "entrypoint": ["/usr/bin/bianbu-agent-runtime", "--role", "agent-worker"],
  "readonly_mounts": ["/usr", "/etc"],
  "writable_mounts": [{"host": "/var/lib/bianbu-agents/com.bianbu.agent", "target": "/home/agent"}],
  "deny_paths": ["/root", "/etc/shadow", "/etc/ssh"],
  "network": {"mode": "whitelist", "domains": [], "default": "drop"},
  "resources": {"memory_max": "2G", "cpu_quota": "100%", "tasks_max": 256},
}
```

### 5.4 host 与 sandbox 的行为差异

| 项 | Worker host | Worker sandbox |
|---|---|---|
| 进程 | 宿主机受控进程 | bwrap/OCI namespace 进程 |
| 文件 | 只允许策略声明工作目录/约束 | 只读系统挂载 + 策略声明 writable mount |
| 网络 | host 也必须受 egress/端口策略约束 | namespace、域名白名单或默认 DROP |
| cgroup | 必须加入 Runtime 专属 scope | 必须加入 Runtime 专属 scope |
| 能力 | 无额外 capability | `CAP_*` 默认全部丢弃 |
| 安全服务 | 受限 client/endpoint | 受限 UDS/Runtime endpoint，不挂完整系统总线 |
| 外部端口 | 由控制面代理 | 不直接绑定公网，由控制面代理 |
| 失败处置 | 不能退化成裸进程 | bwrap 应用失败即拒绝，不裸跑 |

## 6. 进程职责与信任边界

### 6.1 控制面职责

控制面允许加载可信的 Runtime 代码和 Agent manifest 元数据，但不加载默认 Agent
的 Tool、Skill、Plugin 实现。职责包括：

- 监听 HTTP/API，验证请求格式和用户会话；
- 管理 Agent、Session、Run 的路由记录；
- 读取默认 Agent 的已验签 manifest 和配置摘要；
- 调用 `SecurityRuntimeClient` 的 Prepare/Commit/Abort/Revoke；
- 选择 `HostProcessBackend`、`BwrapBackend` 或未来 `OCIBackend`；
- 建立 Worker 私有目录、UDS、cgroup、端口代理；
- 将 Run、审批、取消、流式事件转发给 Worker；
- 监控 Worker 心跳、PID、cgroup、policy digest 和状态；
- 控制面重启时识别并回收孤儿 Worker；
- 将启动、停止、失败、撤销、升级和回收事件关联到 audit 记录。

控制面不得：

- 接受 HTTP 请求中的任意 shell/entrypoint/bwrap 参数；
- 直接执行 Agent Tool/Plugin 代码；
- 修改 securityd 返回的 policy；
- 在 securityd 不可用时将生产请求降级为 host；
- 将完整模型 API Key 注入 Worker 的普通环境变量；
- 直接把 Worker 的公网端口暴露给外部客户端。

### 6.2 默认 Agent Worker 职责

Worker 只加载一个已选定的默认 Agent：

- 加载 Agent instructions、模型、Skill、Tool、Plugin 和 MCP；
- 执行 LangGraph/Run；
- 为每次 Tool 调用携带 `agent_id`、`instance_id`、`session_id` 和 `run_id`；
- 通过受限安全客户端发起 capability、Confirm、DLP、Token 和审计请求；
- 通过 Worker RPC 返回事件和结果；
- 接收控制面发送的 cancel、approval result、shutdown；
- 定期上报健康、版本、当前 generation 和资源摘要。

Worker 不得：

- 对外监听 `0.0.0.0:9899`；
- 接受外部提交的命令或策略；
- 创建同级 Worker 或新容器；
- 修改自身的 package/config/policy digest；
- 访问控制面之外的完整文件存储、系统 D-Bus 或安全数据库。

### 6.3 信任边界

```text
可信边界 A：systemd + kernel + securityd + Runtime control
  ├─ 能创建/停止 Worker
  ├─ 能持有 lease 和策略摘要
  └─ 能接收并验证 Worker 证明

受控边界 B：Agent Worker
  ├─ Agent 代码、Skill、Tool、Plugin、MCP
  ├─ 仅有策略声明的 workspace/网络/资源
  └─ 只能通过 Runtime endpoint 使用安全能力
```

## 7. 启动与生命周期

### 7.1 控制面启动

```text
1. systemd 启动 bianbu-agent-runtime-control
2. ExecStartPre 创建/升级用户 data_dir 和只读默认 profile
3. 控制面读取 runtime.control 配置和 default_agent 元数据
4. 控制面绑定自身安全身份（仅用于控制面管理操作）
5. 校验 securityd 可用、Worker entrypoint 和配置摘要
6. HTTP/API 开始监听（仅表示控制面 ready，不表示 Agent ready）
7. 按配置启动默认 Agent Worker
8. Worker 建立私有 UDS，发送 Hello
9. 控制面核对 Worker 身份/版本/摘要，提交 CommitStart
10. 控制面发布 Agent ready，接受对话 Run
```

控制面应区分两个健康状态：

| 状态 | 含义 | API 行为 |
|---|---|---|
| `CONTROL_READY` | HTTP 和控制面自身可用 | 允许查询状态，Run 返回 Worker 尚未就绪 |
| `AGENT_READY` | 默认 Agent Worker 已 Commit 且心跳正常 | 允许创建对话 Run |
| `DEGRADED` | Worker 失败或 securityd 暂时不可用 | 禁止新 Run，保留诊断/停止接口 |

### 7.2 Worker 启动事务

```text
Control Plane
  │
  ├─ PrepareStart(requested_mode)
  │       └─ lease_id + immutable policy + effective_mode
  ├─ 校验 policy digest、backend、entrypoint 和边界字段
  ├─ 创建实例目录、日志 FD、UDS、cgroup/端口代理准备
  ├─ Backend.start(policy)
  │       ├─ host：systemd transient scope + 固定 entrypoint
  │       └─ sandbox：bwrap/OCI + mount/net/resource 约束
  ├─ 等待 Worker Hello（实例/租约/摘要/安全身份）
  ├─ CommitStart(lease_id, attestation)
  └─ 标记 AGENT_READY
```

任一步失败：

```text
停止 Worker → 关闭端口代理 → 删除临时 Socket/目录 → Abort 或 Revoke lease
→ 写失败审计 → 对外返回可诊断错误
```

### 7.3 Worker 状态机

```text
NEW
 │ PrepareStart 成功
 ▼
POLICY_READY
 │ Backend.start
 ▼
STARTING
 ├─ 启动失败 ───────────────► FAILED → CLEANUP
 │ Hello 超时
 ▼
HANDSHAKING
 ├─ 身份/摘要/版本不匹配 ────► FAILED → REVOKE/CLEANUP
 │ CommitStart 成功
 ▼
RUNNING
 ├─ 心跳超时/证明失效 ───────► REVOKED → STOPPING
 ├─ 控制面 stop ─────────────► STOPPING
 └─ 进程退出 ───────────────► STOPPED/FAILED
```

### 7.4 控制面和 Worker 重启策略

| 事件 | 处理 |
|---|---|
| Worker 崩溃 | 标记 `FAILED`，撤销 lease，按退避策略重启；正在运行的 Run 返回可重试错误 |
| Worker 心跳超时 | 先发送 graceful shutdown，宽限期后 SIGTERM/SIGKILL，并写 Revoke |
| 控制面正常重启 | 读取 execution ledger，核对 PID/cgroup/lease，接管合法 Worker |
| 控制面异常退出 | Worker 由 `--die-with-parent`/systemd scope 回收；不能遗留可执行孤儿 |
| securityd 重启 | 禁止新 Worker；已有 Worker 按租约宽限期处理，无法重新证明则撤销 |
| 配置变更 | 新 generation 启动新 Worker；旧 Worker 处理现有 Run 后优雅停止 |
| 升级回滚 | 新 Worker 健康检查失败时保留旧包，不能用未验签新包继续运行 |

## 8. 进程间通信设计

### 8.1 Socket 目录

```text
$XDG_RUNTIME_DIR/bianbu-agent/
├── control.sock                         # 控制面内部管理 Socket（0600）
├── instances/
│   └── <instance_id>/
│       ├── worker.sock                   # 控制面 ↔ Worker（0600）
│       ├── events.sock                   # 可选流式事件旁路
│       ├── pid
│       └── metadata.json                 # 非敏感运行摘要
└── locks/
```

目录和 Socket 必须属于服务用户，权限 `0700/0600`。Worker 不能通过路径名猜测或
打开其他 Agent 的 Socket；控制面在 accept 后还需校验 `SO_PEERCRED` 和实例 token。

### 8.2 Worker Hello

Worker 启动后必须在启动超时（目标 10 秒）内发送：

```json
{
  "type": "hello",
  "protocol": 1,
  "instance_id": "com.bianbu.agent-20260820-abc",
  "agent_id": "com.bianbu.agent",
  "lease_id": "lease-...",
  "pid": 1234,
  "sandboxed": true,
  "container_id": "bwrap:1234",
  "capabilities": ["file.read", "file.write"]
}
```

控制面核对：

- `instance_id`、`lease_id` 是启动参数/环境注入值，不允许 Worker 自选；
- package/config/policy digest 与控制面启动记录完全一致；
- `sandboxed` 与 `effective_mode` 一致；
- PID 属于 Backend 创建的进程，cgroup 与策略要求一致；
- Worker 只声明已安装 generation 的能力；
- `protocol` 在支持范围内，否则停止 Worker。

### 8.3 RPC 消息类型

| 消息 | 方向 | 用途 |
|---|---|---|
| `hello` | Worker → Control | 启动证明和协议协商 |
| `health` | 双向 | 心跳、资源和 generation 状态 |
| `run.start` | Control → Worker | 创建一次对话 Run |
| `run.event` | Worker → Control | token、tool、confirm、状态事件 |
| `run.cancel` | Control → Worker | 取消 Run |
| `approval.request` | Worker → Control | 将确认请求转至 HTTP/UI |
| `approval.result` | Control → Worker | 用户批准/拒绝结果 |
| `run.result` | Worker → Control | 最终结果或结构化错误 |
| `shutdown` | Control → Worker | 优雅停止 |
| `shutdown.ack` | Worker → Control | 停止确认 |

每条消息必须包含 `protocol_version`、`request_id`、`instance_id`；Run 事件额外包含
`session_id`、`run_id`、单调递增 `sequence`。控制面检测到重复、跳号或错误实例时，
应关闭连接并记录安全事件。

### 8.4 对外 HTTP 兼容

外部客户端继续使用：

```text
POST /api/v1/runs
GET  /api/v1/runs/{run_id}/events
GET  /api/v1/runs/{run_id}/followups
```

控制面不把 Worker RPC 暴露到公网。现有 child 管理 API：

```text
/api/v1/agents/{agent_id}/executions
/api/v1/executions
```

在双进程架构中作为控制面管理接口，生产环境应增加管理员认证，不允许普通对话用户
提交任意 `command`、`cwd` 或 bwrap 参数。

## 9. 配置设计

### 9.1 建议配置

```yaml
schema_version: 2
data_dir: /home/bianbu/.bianbu-agent
default_agent_id: bianbu-agent-default

service:
  host: 0.0.0.0
  port: 9899

runtime:
  control:
    execution:
      requested_mode: host
    worker_socket_root: /run/user/1000/bianbu-agent/instances
    startup_timeout_seconds: 10
    handshake_timeout_seconds: 10
    heartbeat_interval_seconds: 5
    heartbeat_timeout_seconds: 15
    restart_policy:
      enabled: true
      max_restarts: 5
      backoff_seconds: [1, 2, 5, 10, 30]
  default_agent:
    id: bianbu-agent-default
    execution:
      requested_mode: sandbox
    worker:
      entrypoint:
      - /usr/bin/bianbu-agent-runtime
      - --role
      - agent-worker
      - --config
      - /home/bianbu/.bianbu-agent/config.yaml
      startup_timeout_seconds: 10
      max_concurrent_runs: 4

security:
  required: true
  agent_id: com.bianbu.agent
  securityd_uds: /run/bianbu/securityd.sock
```

### 9.2 配置约束

- `worker.entrypoint` 生产环境由已签名 manifest 提供，配置只能引用，不能覆盖；
- `runtime.default_agent.id` 必须存在且处于 active generation；
- `requested_mode` 只允许 `auto`、`sandbox`、`host`；
- `control.requested_mode=sandbox` 时必须同时配置 socket activation/host proxy；
- `security.required=true` 时 securityd、client、UDS 缺失即拒绝启动 Worker；
- API Key 不写进普通 YAML；使用 systemd credentials、受限 secret provider 或
  securityd token broker；

### 9.3 兼容旧配置

旧配置只包含：

```yaml
service:
  host: 0.0.0.0
  port: 9899
```

升级器生成：

```yaml
runtime:
  control:
    execution:
      requested_mode: host
  default_agent:
    execution:
      requested_mode: auto
```

旧 Agent manifest 的：

```yaml
metadata:
  sandbox:
    mode: agent
```

仍只用于开发态整进程/MCP/Tool 沙箱兼容逻辑；商用 Worker 模式以
`metadata.execution.requested_mode` 或 Runtime 配置为准，不能将两者混为一谈。

## 10. systemd 与手动启动

### 10.1 商用 user unit（建议）

控制面 unit：

```ini
[Unit]
Description=Bianbu Agent Runtime control plane
After=network-online.target

[Service]
Type=simple
UMask=0077
WorkingDirectory=%h
Environment=BIANBU_RUNTIME_ROLE=control
Environment=BIANBU_RUNTIME_MODE=production
Environment=BIANBU_RUNTIME_MANAGED=1
Environment=BIANBU_RUNTIME_SECURITY=required
Environment=BIANBU_PA_AGENT_ID=com.bianbu.agent
Environment=BIANBU_SEC_UDS=/run/bianbu/securityd.sock
ExecStartPre=/usr/lib/bianbu-agent-runtime/venv/bin/python \
  /usr/lib/bianbu-agent-runtime/provision-user.py \
  --profile /usr/share/bianbu-agent-runtime/default-profile --home %h
ExecStart=/usr/bin/bianbu-agent-runtime --role control \
  --config %h/.bianbu-agent/config.yaml
Restart=on-failure
RestartSec=2s
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
RestrictSUIDSGID=true

[Install]
WantedBy=default.target
```

启动：

```bash
systemctl --user daemon-reload
systemctl --user enable --now bianbu-agent-runtime-control.service
systemctl --user status bianbu-agent-runtime-control.service --no-pager
journalctl --user -u bianbu-agent-runtime-control.service -f
```

控制面启动 Worker 时，不使用用户可编辑的任意命令，而是调用内部
`ExecutionCoordinator.start_registered()`，由已登记 manifest 提供固定 entrypoint。

### 10.2 手动开发启动

开发态可使用一个明确的 control 入口：

```bash
cd /home/bianbu/bianbu-agent
export PATH=/home/bianbu/.local/bin:$PATH
export BIANBU_RUNTIME_ROLE=control
export BIANBU_RUNTIME_MODE=development
export BIANBU_RUNTIME_MANAGED=1
export BIANBU_RUNTIME_SECURITY=required
export BIANBU_SECURITYD_HOME=/home/bianbu/impl/bianbu-securityd
export BIANBU_SEC_UDS=/run/bianbu/securityd.sock
export BIANBU_PA_AGENT_ID=com.bianbu.agent

uv run --locked --no-dev bianbu-agent-runtime \
  --role control --config .bianbu-agent/config.yaml
```

若尚未完成双进程 Worker 迁移，当前代��的兼容入口仍是：

```bash
BIANBU_SANDBOX=agent ./run.sh serve
```

该命令只证明整进程 bwrap 开发链路，不能冒充双进程商用架构。

## 11. 安全设计

### 11.1 身份模型

三种 ID 必须分开：

| ID | 示例 | 用途 |
|---|---|---|
| PA 本地 Agent ID | `bianbu-agent-default` | 配置、Session、Run 路由 |
| Security Agent ID | `com.bianbu.agent` | securityd capability、DLP、Token、租约 |
| Worker Instance ID | `com.bianbu.agent-<uuid>` | 一次具体进程、PID/cgroup/审计关联 |

控制面为 Worker 注入 `agent_id` 和 `instance_id`，Worker 不能从用户请求覆盖。安全
客户端调用必须带 `instance_id/session_id/run_id`，防止多个默认 Agent 实例混用配额或
审计记录。

### 11.2 安全服务访问

推荐路径：

```text
Worker → restricted security client / Runtime endpoint → securityd UDS
Control → SecurityRuntimeClient → security.runtime D-Bus + UDS
```

Worker 不应获得完整 system D-Bus。若第一阶段仍由 Worker 直接调用正式 UDS：

- Socket 必须通过专用 group/peer credential 控制；
- securityd 必须校验 Worker 的 instance/lease 绑定；
- Worker 只能调用 capability、Confirm、DLP、Token、Audit 所需方法；
- 不允许导入 `securityd` 内部 Python 包；
- securityd 失联时生产请求 fail-closed。

### 11.3 文件与密钥

- 控制面仅读 manifest、配置元数据和运行 ledger；
- Worker 工作目录按 `agent_id/instance_id` 分隔；
- sandbox 不挂载 `/root`、`/etc/shadow`、`/etc/ssh` 等拒绝路径；
- host 也不能因为没有 namespace 而获得整个 `data_dir`；
- provider API Key 通过 secret FD/受限 broker 提供，不出现在 Worker 普通环境、
  `/proc/<pid>/environ`、日志和 Hello 消息中；
- 控制面 HTTP 响应不得返回 lease secret、provider secret 或完整 policy 中的敏感字段。

### 11.4 网络与端口

- 公网端口只由控制面持有；
- Worker 的服务端口通过控制面 loopback proxy 暴露；
- Worker 不能在 `0.0.0.0` 上自行监听；
- sandbox 默认网络策略为 whitelist/DROP，host 也必须由 egress broker/eBPF 或等效
  机制执行；
- 端口代理在 `CommitStart` 成功前不开放；
- 控制面 sandbox 需要 host socket activation/代理，不能直接依赖 bwrap 网络设置。

### 11.5 代码与策略绑定

每个 Worker 的启动证明至少绑定：

```text
agent_id
entrypoint digest
lease_id
instance_id
PID/cgroup
sandboxed/container_id
```

任何一项不匹配都导致：停止 Worker、撤销 lease、关闭代理、写审计、返回失败。

## 12. Run 与审批流程

### 12.1 普通对话

```text
Client
  └─ POST /api/v1/runs
       └─ Control 校验 session/agent
            └─ Worker RPC run.start
                 └─ LangGraph 执行
                      ├─ Tool 判权 → securityd
                      ├─ 需要确认 → approval.request → Control/UI
                      ├─ 用户批准 → approval.result → Worker
                      └─ run.event/run.result → Control → Client
```

控制面只做路由和生命周期，不重新实现 Tool 判权。Worker 必须继续使用当前安全
middleware 的 `CheckPermissionV2`、`RequestConfirmV2`、DLP、Token 和审计路径。

### 12.2 连接断开

- 客户端断开不立即杀 Worker；Run 按 session 策略继续或取消；
- 控制面断开 Worker RPC 时，Worker进入 `DEGRADED`，超过宽限期自动停止；
- Worker 不能将最终结果写入控制面之外的公网连接；
- Event sequence 持久化到控制面，重连时从最后确认序列继续或明确返回不可恢复。

## 13. 可观测性与审计

### 13.1 控制面指标

至少提供：

```text
runtime_control_up
runtime_control_http_requests_total{route,status}
runtime_worker_instances{state,mode}
runtime_worker_start_seconds{mode,result}
runtime_worker_handshake_seconds{mode,result}
runtime_worker_restarts_total{reason}
runtime_worker_orphans_reaped_total
runtime_worker_heartbeat_failures_total
runtime_security_prepare_total{mode,result}
runtime_security_commit_total{mode,result}
```

### 13.2 日志字段

所有控制面/Worker 关键日志统一包含：

```text
timestamp, component, agent_id, instance_id, session_id, run_id,
pid, cgroup_path, sandboxed, event, result, error_code
```

敏感 prompt、API Key、完整 Skill secret 和完整环境变量不得写入日志。

### 13.3 审计事件

以下事件必须进入 securityd 审计链或可验证关联事件：

- `runtime.prepare_start`
- `runtime.worker_spawn`
- `runtime.worker_hello`
- `runtime.commit_start`
- `runtime.mode_upgrade`
- `runtime.approval_request/result`
- `runtime.worker_stop`
- `runtime.worker_revoke`
- `runtime.worker_crash`
- `runtime.orphan_reaped`
- `runtime.policy_mismatch`

PA 本地日志只能作为诊断，不能替代 securityd 哈希链审计。

## 14. 失败处理与安全降级

| 场景 | 处理 | 禁止行为 |
|---|---|---|
| securityd 不可用 | 控制面可保持诊断状态；禁止启动新 Worker | 自动改为 host |
| PrepareStart 返回 sandbox | 必须调用 Bwrap/OCI Backend | 直接 HostProcessBackend |
| bwrap 不可用 | Worker 启动失败并记录原因 | 裸跑 Worker |
| Host 约束不可用 | 拒绝 host，按策略升级 sandbox 或拒绝 | 无 cgroup/代理裸跑 |
| package/config digest 不匹配 | Abort/Revoke 并拒绝 | 重新计算客户端摘要冒充已签名值 |
| Worker Hello 超时 | 停止进程、清理资源、撤销租约 | 标记 ready 后继续 |
| CommitStart 失败 | 关闭代理并清理 Worker | 保留已运行进程 |
| 控制面收到未知 RPC | 关闭连接并告警 | 兼容执行未知命令 |
| Agent 请求创建子容器 | 拒绝并审计 | 继承 Agent 的 bwrap 参数 |

## 15. 对现有 `bianbu-agent-runtime` 的改造映射

| 当前代码/目录 | 双进程目标职责 | 改造方向 |
|---|---|---|
| `bianbu_agent/server/runtime.py` | 控制面 Runtime Manager | 保留生命周期/路由骨架，移除默认 Agent 的执行加载 |
| `bianbu_agent/api/*.py` | 控制面 HTTP API | 保留对外契约，Run 转 Worker RPC |
| `bianbu_agent/runs/manager.py` | Worker Run 执行器或 Worker-side facade | 将 LangGraph 执行移入 Worker |
| `bianbu_agent/engines/default.py` | Worker | 只在 Worker 加载 Tool/Skill/Plugin/模型 |
| `bianbu_agent/security/execution_runtime.py` | 控制面 Backend/Coordinator | `start_registered()` 成为默认 Worker 唯一启动路径 |
| `bianbu_agent/security/security_runtime.py` | 控制面安全适配 | Prepare/Commit/Revoke 绑定 Worker instance |
| `bianbu_agent/security/security_middleware.py` | Worker | 保持 Tool 判权、Confirm 和审计语义 |
| `bianbu_agent/security/security_skill_dlp.py` | Worker | 通过正式 client/UDS 扫描 Skill 文本 |
| `bianbu_agent/mcp/client.py` | Worker | MCP 子进程继承 Worker 的 sandbox；控制面不加载 MCP |
| `run.sh` | 开发兼容入口 | 继续整进程 bwrap，标记为非商用 |
| `debian/*.service` | 控制面 unit | 新增 control unit；Worker 使用 transient scope/实例 unit |

### 15.1 必须删除或迁移的单进程行为

1. 控制面启动时不再构造默认 Agent 的 LangGraph Engine。
2. 控制面不再在同一进程内执行普通 `/api/v1/runs`。
3. 进程级 `_prepare_security_runtime()` 改为 Worker 启动事务；控制面只绑定控制面身份。
4. `build_default_engine()`、PluginManager 的不可信实现加载移入 Worker 入口。
5. Worker 的 entrypoint、cwd、env、mount、network 全部由控制面和 policy 固定。
6. 现有 child execution API 改为内部控制面调用，外部管理 API 做认证和字段收敛。

### 15.2 分阶段实施

| 阶段 | 产出 | 退出条件 |
|---|---|---|
| P0 契约 | 配置 schema、Worker RPC、状态/错误码、ledger schema | 契约测试通过，旧 API 不回归 |
| P1 Worker 壳 | 新 Worker 入口、Hello/health/shutdown、控制面 supervisor | 能启动空 Worker 并回收 |
| P2 执行迁移 | LangGraph、Run、Tool/Skill/Plugin/MCP 移入 Worker | 普通对话经 RPC 完成，审批/DLP/Token 不回归 |
| P3 安全绑定 | Worker lease、instance attestation、UDS 身份、策略执行 | sandbox/host 各有完整 Prepare→Commit 证据 |
| P4 systemd 交付 | control user unit、安装器、升级/回滚、孤儿回收 | worker 重启/控制面重启无孤儿 |
| P5 可选控制面 sandbox | socket activation/代理和独立策略 | 控制面 sandbox 通过全部入口/故障测试 |

## 16. 测试与验收计划

### 16.1 功能验收

| 编号 | 场景 | 可测标准 |
|---|---|---|
| CP-ACC-01 | 控制面启动 | systemd 启动成功率 100%，HTTP ready ≤ 3 秒（基线机器） |
| CP-ACC-02 | 默认 Worker sandbox | 返回 `effective_mode=sandbox`、`backend=bwrap`、`sandboxed=true`，namespace 证据齐全 |
| CP-ACC-03 | 默认 Worker host | 策略允许时 `effective_mode=host`、`sandboxed=false`，仍有专属 cgroup/审计 |
| CP-ACC-04 | host 强制升级 | 高风险或摘要不可信时 100% 升级 sandbox 或拒绝，不得 host 裸跑 |
| CP-ACC-05 | 普通对话 | `/api/v1/runs` 100% 经 Worker RPC，结果/event sequence 无丢失 |
| CP-ACC-06 | Tool 判权 | read/write/execute 及其他 capability 的 ALLOW/CONFIRM/DENY 语义与单进程基线一致 |
| CP-ACC-07 | Confirm | 请求、弹窗、批准/拒绝、超时均能跨 RPC 完成，错误率 0 |
| CP-ACC-08 | Skill DLP | Worker Skill 文本敏感信息扫描 100% 走正式 security UDS；securityd 不可用时 fail-closed |
| CP-ACC-09 | Token/审计 | agent/session/run/instance 归属正确，重复或串实例计量为 0 |
| CP-ACC-10 | Worker 崩溃 | 控制面 ≤ 15 秒发现；无遗留端口、cgroup、lease 或可执行孤儿 |
| CP-ACC-11 | 控制面重启 | 合法 Worker 可接管或全部安全停止；孤儿识别/回收率 100% |
| CP-ACC-12 | Worker 握手攻击 | 伪造 digest、lease、instance、协议版本的 Worker 100% 被拒绝 |
| CP-ACC-13 | 文件隔离 | sandbox 未声明路径访问阻断率 100%；host 越界访问按策略阻断或审计 |
| CP-ACC-14 | 网络隔离 | 未授权域名/公网监听阻断率 100%；Worker 不直接持有 9899 |
| CP-ACC-15 | 控制面 API | 未认证管理请求、未知字段、command/cwd/bwrap 注入 100% 拒绝 |

### 16.2 性能目标

以下为验收目标，需在 worker 上锁定 baseline 后最终确认：

| 指标 | 目标 |
|---|---:|
| 控制面冷启动到 `CONTROL_READY` | P95 ≤ 3 秒 |
| Worker host 冷启动到 `AGENT_READY` | P95 ≤ 5 秒 |
| Worker bwrap 冷启动到 `AGENT_READY` | P95 ≤ 10 秒 |
| `run.start` RPC 额外开销 | P95 ≤ 50 ms（不含模型首 token） |
| 心跳检测故障发现 | ≤ 15 秒 |
| 停止/撤销到 Worker 退出 | P95 ≤ 5 秒，超时强制回收 |
| 控制面内存增长 | 24 小时无 Run 泄漏，增长 ≤ 10% |

### 16.3 必须保留的现有回归

- `bianbu-agent-runtime` Security Runtime/ExecutionCoordinator 定向测试；
- PA 的 read、write、execute capability 验收；
- Confirm/HITL、DLP、Token、审计和 MCP 安全测试；
- `testkit/runner.py` 35 项端到端测试；
- systemd unit、安装器、配置迁移、旧 HTTP API 兼容测试。

## 17. 发布与回滚

### 17.1 发布物

至少包含：

```text
/usr/bin/bianbu-agent-runtime
/usr/lib/bianbu-agent-runtime/venv/
/usr/lib/systemd/user/bianbu-agent-runtime-control.service
/usr/lib/bianbu-agent-runtime/provision-user.py
/usr/share/bianbu-agent-runtime/default-profile/
/usr/lib/bianbu-securityd/client/
```

发布包不得依赖 worker 上的源码路径 `BIANBU_SECURITYD_HOME`；该变量只允许开发态。

### 17.2 回滚原则

- 控制面和 Worker 协议版本必须支持至少一个兼容版本；
- 新 Worker 未达到健康阈值时不切换默认 generation；
- 回滚必须停止新 Worker、撤销新 lease、关闭代理，再恢复旧 Worker；
- 不删除旧 session/run/ledger；审计事件保���完整链路；
- 配置 schema 回滚需保留备份，不能覆盖用户自建 Agent 元数据。

## 18. 风险、取舍与待确认项

| 项 | 风险/取舍 | 建议 |
|---|---|---|
| 控制面是否 sandbox | sandbox 提升隔离但增加公网入口/代理复杂度 | 第一阶段控制面 host，Worker 可选 sandbox |
| Worker 直接访问 security UDS | 简单但需严格 peer/instance 认证 | 先使用受限 UDS；后续统一 Runtime endpoint |
| Run 状态存储位置 | 控制面存储便于恢复，Worker 存储便于封装 | ledger/会话元数据在控制面，模型上下文在 Worker 按策略保存 |
| 多 Agent | 一个控制面管理多个 Worker 会增加身份和资源复杂度 | 先完成默认 Agent，再扩展每 Agent 独立实例 |
| 模型连接 | Worker 需要 API Key 或本地模型设备访问 | 采用 secret broker/FD 和模型 capability，不把密钥发给控制面日志 |
| systemd user 与 system | user unit 贴合桌面用户，system unit 更适合无登录设备 | 当前 PA 交付使用 user unit；设备级产品再评估 system manager |
| bwrap 与 OCI | bwrap 轻量但能力和发行版差异较大 | K3 第一版 bwrap；OCI 作为替换后端，不改变 Runtime 契约 |

待确认项：

1. 控制面是否必须支持 `requested_mode=sandbox`，还是产品固定 host；
2. Worker 安全调用采用受限 UDS 直连还是控制面代理；
3. 默认 Agent 的 workspace 和模型缓存由控制面还是 Worker 负责持久化；
4. Worker 崩溃后的自动重启次数、退避和用户可见错误语义；
5. 无登录场景是否启用 user lingering，或改为产品专属 system service；
6. 多 Agent 是否共享控制面、共享模型缓存和共享安全配额；
7. 端口代理是否只允许 loopback，还是支持受 securityd 策略保护的 LAN 映射。

## 19. 设计结论

双进程设计解决了当前单进程 Runtime 的职责混杂问题：

```text
控制面 = 可管理、可恢复、可审计、持有公网入口
默认 Agent Worker = 可替换、可隔离、按策略选择 host/sandbox
securityd = 最终安全裁决和审计权威
```

## 20. 当前实现与交付证据

| 验收项 | 当前证据 | 状态 |
|---|---|---|
| 控制面不加载 Tool/Skill/Plugin/MCP | `BianbuAgentRuntime(role="control")` 使用 `EmptyGeneration`/`ControlPluginFacade` | 已实现 |
| Worker RPC 与 Hello/Activate/Run/Cancel/Shutdown | `bianbu_agent/security/runtime_process/{protocol,worker_rpc,worker}.py` | 已实现；定向测试通过 |
| Prepare→Backend→Hello→Commit | `WorkerSupervisor` + `ExecutionCoordinator.start_registered()` | 已实现；需 Worker 实机验收 |
| host/bwrap 策略边界 | `HostProcessBackend`、`BwrapBackend`，固定 entrypoint、cgroup、挂载和 deny path | 已实现；需 Worker 实机验收 |
| 控制面状态 API | `GET /api/v1/runtime/status`、`GET /api/health` | 已实现；API 测试通过 |
| 商用 user unit | `debian/bianbu-agent-runtime.user.service`，并安装 `bianbu-agent-runtime-control.service` 兼容别名 | 已实现；需 Debian 包安装验收 |
| Security 发布资产 | `python3 impl/bianbu-securityd/deploy/verify_install_assets.py` → `INSTALL_ASSETS_PASS` | 已通过离线校验 |
| Runtime 回归 | `uv run pytest -q tests/runtime tests/sdk/test_config.py tests/test_api_docs.py tests/sdk/api/test_inventory.py tests/sdk/test_package_layout.py tests/sdk/test_project_definitions.py tests/test_run_script.py` → `127 passed, 3 skipped` | 已通过 |
| Worker 双进程商用运行 | Worker 当前仍为旧 `run.sh + bwrap + bianbu-agent serve`；正式 Runtime unit/manifest 未部署 | 待部署 |
| signed manifest | Worker 信任根存在；开发机/Worker 未发现匹配发布私钥，不能生成正式 manifest | 待签名系统提供材料 |

正式交付的阻断条件只有签名与目标机部署：不得使用临时密钥、`/etc/bianbu/keys/master.key`
或 `BIANBU_SECURITY_CODESIGN=off/warn` 绕过门禁。签名材料到位后，按第 16 节逐项保留
HTTP 响应、systemd `MainPID/ControlGroup`、`/proc/<pid>/ns`、securityd 审计和失败回收
原始输出，才能将本文状态更新为“Worker 商用验收通过”。

在商用第一阶段，应采用：

```text
systemd 启动控制面（host）
控制面调用 security.runtime
控制面通过 ExecutionCoordinator 启动默认 Agent Worker
默认 Agent Worker 按 effective_mode 运行在 host 或 bwrap
普通对话、Tool、Skill、DLP、Confirm、Token、审计全部经 Worker 执行
```

当前 `run.sh + BIANBU_SANDBOX=agent` 仍然有效，但它是单进程开发/集成验证入口，
不能作为商用交付证据。PA Runtime 已实现 Worker RPC、lease 证明、systemd user
control unit、状态 API、故障回收和 host/bwrap 后端；Runtime 仓库定向测试为
`127 passed, 3 skipped`，Security 发布资产离线校验为 `INSTALL_ASSETS_PASS`。
商用发布仍必须在签名系统提供与 Worker `/etc/bianbu/codesign-keys/worker-validation.pub`
匹配的 Ed25519 私钥后，生成并注册 signed manifest，再在 Worker 完成 CP-ACC-01～15
的真实 systemd/PID/cgroup/namespace/安全链路验收。当前 Worker 上仍运行旧的
`run.sh + bwrap + bianbu-agent serve`，不能把它标记为双进程商用验收通过。

### 20.1 2026-08-21 补充验证记录

本轮修复和实机验证已形成以下可复现证据：

| 项目 | 证据 | 结论 |
|---|---|---|
| Runtime 定向回归 | `uv run pytest -q tests/runtime tests/sdk/test_config.py tests/test_api_docs.py tests/sdk/api/test_inventory.py tests/sdk/test_package_layout.py tests/sdk/test_project_definitions.py tests/test_run_script.py` → `127 passed, 3 skipped` | 通过 |
| Worker Runtime 定向回归 | Worker 独立交付目录 `runtime-delivery-3b30ea8` 安装到 Python 3.14 venv 后，执行同一测试集合 → `130 passed` | 通过 |
| Security Runtime 受影响回归 | `test_runtime_policy.py` + `test_runtime_engine.py` → `20 passed` | 通过 |
| Worker host 双进程开发验证 | Worker `10.0.90.243` 隔离 profile：控制面 HTTP `19995` 返回 `AGENT_READY`；本轮控制面 PID `1057596`、Worker PID `1057659`；Worker 私有 UDS Hello/Activate/Health 成功，精确停止后无残留 | 通过（开发态，不是商用证据） |
| Worker bwrap 后端探针 | Worker 实测 `bwrap` 进程创建 user/pid/mnt/ipc/uts/net namespace，加入 transient cgroup；工作目录写入成功，停止后进程退出 | 通过（后端探针，未绑定正式 manifest） |
| Worker Debian 包布局烟测 | Worker 执行 `timeout 180 ./debian/tests/test-desktop-package.sh /home/bianbu/bianbu-agent-runtime_0.1.0+systemd2_riscv64.deb`，退出码 `0` | 通过（开发验证包布局；包内 manifest 为占位测试材料，不是商用签名） |
| 生产 fail-closed | 未注册 Runtime manifest 时，生产 Worker 启动返回 `RuntimeExecutionError: security.runtime 策略未声明固定 Agent entrypoint` | 通过 |
| Worker Security 全量 | Worker `cd /home/bianbu/impl/bianbu-securityd && /usr/lib/bianbu-securityd/venv/bin/python -m pytest tests/ -q` → `587 passed, 3 skipped` | 通过 |

本轮 Runtime 仓库新增提交为 `cde7391`、`fa61820`、`9e05159`、`77e38eb`、`1b9375e`、`5ae5201`、`3b30ea8`，分别修复开发
fallback 的 lease/Hello 身份、host fallback 的 canonical config 路径和 Worker UDS
启动竞态，增加控制面到 Worker 的 Run/event/result 转发回归，隔离不可用 Security
客户端的环境依赖测试，并保留 Debian 发布脚本的可执行权限；最新源包契约校验
`./debian/tests/validate-source-package.sh` 已通过。
生产路径仍不允许使用 fallback。

商用交付仍有两个硬阻断，不能用开发态证据替代：

1. Worker 信任根为 `/etc/bianbu/codesign-keys/worker-validation.pub`，当前未找到
   与其匹配的 Ed25519 私钥，不能生成正式 `manifest.toml.sig`。
2. Worker `/etc/bianbu/capabilities.db` 的 `agent_manifest` 为空，正式 Runtime
   Debian 包尚未安装和注册；当前 `9899` 仍由旧的 `run.sh + bwrap + bianbu-agent serve`
   占用。

在上述材料和安装动作完成前，本文状态只能保持“开发态实机验证通过、商用交付待签名
与部署”，不得更新为“Worker 商用验收通过”。

### 20.2 2026-08-21 14:02 交付复核

本次交付复核确认代码仓与 Worker 状态没有改变：

| 项目 | 当前证据 | 结论 |
|---|---|---|
| Security 设计仓 | `master == origin/master == 9ee620b` | 已同步 |
| Runtime 仓 | `main == origin/main == 3f6fd31`；manifest 生成测试已跟随项目自有 Bibit 默认 Agent 源文件 | 已同步 |
| Runtime 定向回归 | `uv run pytest -q tests/runtime tests/sdk/test_config.py tests/test_api_docs.py tests/sdk/api/test_inventory.py tests/sdk/test_package_layout.py tests/sdk/test_project_definitions.py tests/test_run_script.py` → `127 passed, 3 skipped` | 通过 |
| Debian 源包契约 | `./debian/tests/validate-source-package.sh` → `Debian source package contract is valid.` | 通过 |
| Worker user unit | `bianbu-agent-runtime.service` 与 `bianbu-agent-runtime-control.service` 均不存在 | 商用部署未开始 |
| Worker Runtime manifest | `/etc/bianbu/capabilities.db` 的 `agent_manifest` 为空 | 未注册 |
| Worker 9899 进程 | 仍为旧 `run.sh + bwrap + uv run + bianbu-agent serve` | 非双进程商用入口 |
| Worker 签名材料 | `/etc/bianbu/codesign-keys/worker-validation.pub` 仍存在，但未提供匹配私钥 | 无法生成正式签名包 |

本次复核未向 Worker 安装开发包、未替换信任根、未关闭签名强制策略，也未停止当前
用户正在使用的旧 PA。待正式签名私钥由签名系统提供后，仍须按 §16 的 CP-ACC-01～15
顺序安装并保留原始 systemd、PID/cgroup、namespace、Security 审计和回滚证据。
