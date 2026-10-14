# Bianbu Security Runtime 商用设计方案

| 项 | 内容 |
|---|---|
| 文档编号 | BN-SEC-RUNTIME-001 |
| 版本 | V0.6 |
| 来源 | Bianbu Next PRD V0.9、SRS、HLD、LLD、BN-SEC-CAPMAP-001 |
| 日期 | 2026-08-20 |
| 状态 | worker 安全接入与 35 项验收通过；商用增强项待补证 |
| 适用范围 | `bianbu-securityd`、`security.runtime`、`bianbu-agent-runtime`、Agent 执行模式与生命周期管理 |
| 当前对接对象 | PA Bianbu Agent Runtime：`../bianbu-agent-runtime` |

## 1. 摘要与结论

### 1.1 本文术语约定

| 术语 | 本文含义 |
|---|---|
| PA Runtime | PA Bianbu Agent Runtime 仓库 `/data/workspace2026-new/work0618/bianbu-agent-security/bianbu-agent-runtime`，代码包名 `bianbu_agent`；当前 Agent API、Run 调度和安全客户端调用方 |
| `security.runtime` | `impl/bianbu-securityd` 中拟提供的安全策略/租约能力；负责裁决，不负责启动 PA Agent |
| `io.bianbu.Runtime` | securityd 仓库中的参考 Runtime D-Bus 服务/未来标准化合约；不是当前 PA 的对接入口 |

后文未加前缀的“Runtime”在启动、执行、停止、回收等语境下均指 PA Runtime；
涉及 D-Bus 接口时会明确写出 `io.bianbu.Runtime`，避免把参考服务误认为当前实现。

本方案将 Agent 执行与安全控制拆成两个职责清晰的部分，并支持双执行模式：

```text
security.runtime       负责安全策略、准入、租约、校验、撤销和审计
bianbu-agent-runtime   负责执行模式调度、进程生命周期、隔离后端、端口代理和健康检查
```

`security.runtime` 是安全策略的权威来源，但不直接 `fork/exec` 第三方 Agent；
PA `bianbu-agent-runtime` 是当前 Agent API、Run 调度和安全客户端调用入口，未来也
应成为 Agent 生命周期的唯一生产启动入口，依据 `security.runtime` 签发的策略在
sandbox/container 或宿主机 host 模式中创建 Agent。
用户只能提交执行模式偏好，不能以此绕过安全策略：Runtime 将请求交给
`security.runtime` 校验后得到最终的 `effective_mode`。

当前 PA 已实现的安全对接链路是：

```text
PA bianbu-agent-runtime（`../bianbu-agent-runtime`）
        │
        ├─ bianbu_agent/server/runtime.py
        │    └─ BindAgentV2 / MCP 入口判权
        ├─ bianbu_agent/engines/langgraph/security_middleware.py
        │    └─ CheckPermissionV2 / RequestConfirmV2 / GrantSessionTrustV2
        ├─ bianbu_agent/security_codesign.py
        │    └─ VerifyCodePackage / VerifyCodeDigest
             └─ bianbu_agent/security_skill_dlp.py
                    └─ 通过版本化 client/正式 UDS 调 securityd DLP
                    │
                    ▼
        bianbu_security_client → securityd（io.bianbu.Security / UDS）
```

商用执行模式的目标链路在此基础上增加 `security.runtime` 启动策略调用：

```text
PA bianbu-agent-runtime 的执行协调器
        │ requested_mode: auto | sandbox | host
        ├─ SecurityRuntimeClient.PrepareStart()
        ├─ 按 effective_mode 选择 SandboxExecutor 或 HostProcessExecutor
        ├─ SecurityRuntimeClient.CommitStart()
        └─ 持续上报/接收撤销、健康和审计事件
```

这里的 `bianbu-agent-runtime` 指 PA 的运行时仓库
`/data/workspace2026-new/work0618/bianbu-agent-security/bianbu-agent-runtime`，
实际目录通常作为本仓的相邻仓 `../bianbu-agent-runtime` 使用。它是当前 Agent
启动、调度和安全客户端调用方。当前真正调用 securityd 的是该仓库中的 PA Runtime
代码及其 `bianbu_security_client` 适配层，不是 `io.bianbu.Runtime`。
`io.bianbu.Runtime` 仅可作为未来标准化的 Runtime D-Bus 合约或 securityd 仓库中的
参考 Runtime 服务，不能拿来描述当前已接通的实现。

当前通过 `run.sh` 直接启动 bwrap 的方式保留为开发和集成验证入口，不能作为
最终商用启动入口。它可以验证 PA 与 securityd 的接入，但不能替代
`bianbu-agent-runtime` 的生命周期、策略绑定和绕过防护。

## 2. 背景与问题定义

### 2.1 当前实现

当前 worker 上的运行形态是：

```text
用户执行 run.sh
  → run.sh 拼接 bwrap 参数
  → bianbu-agent 在 bwrap 中运行
  → bianbu-agent 通过 D-Bus / UDS 访问宿主机 securityd
```

这种方式已经能够验证：

- bwrap 的 PID、IPC、UTS、user namespace 隔离；
- PA 工具调用前的 capability 判权和人工确认；
- securityd DLP、Token 计量和审计链；
- 基础网络和文件挂载行为。

但它不满足商用沙箱管理要求：

| 问题 | 影响 |
|---|---|
| 启动由 `run.sh` 控制 | 用户可绕过安全启动链，直接执行裸 PA |
| bwrap 参数由脚本固定 | 没有绑定到某次 Agent 的 securityd 策略和 digest |
| `BuildSandboxPolicy` 未进入启动提交 | seccomp、网络规则和挂载声明可能只生成不执行 |
| 进程级 PA 已接入 `ExecutionCoordinator`，但独立生产 Runtime Manager 尚未作为系统包交付 | child 的 Start/Stop/Revoke/孤儿回收已有统一状态模型；生产 systemd Manager、升级和长期运行证据仍缺 |
| 没有启动租约 | 无法证明“该 PID 对应这次授权的 Agent 包” |
| 执行实例身份未回报校验 | 进程可能被替换、脱离 cgroup 或成为孤儿进程 |
| PA 直接导入 securityd 源码 | Agent 执行实例被迫暴露安全实现代码，不利于最小权限和升级 |
| 直接挂载系统 D-Bus | Agent 可能观察或尝试访问与 securityd 无关的系统服务 |

### 2.2 商用目标

商用版本必须满足：

1. 所有生产 Agent 均由 `bianbu-agent-runtime` 启动和回收；是否进入容器由用户请求和安全策略共同决定；
2. 每次启动均有 security.runtime 签发的、一次性、短时有效租约；
3. 运行实例的 package digest、policy digest、PID、cgroup 以及 sandbox 时的容器 ID 可校验；
4. securityd 不可用、策略不完整或执行实例校验失败时，Agent 不得启动或继续运行；
5. Agent 只能使用安全客户端访问 securityd，不挂载 securityd 源码；
6. `run.sh` 和裸 `uv run bianbu-agent` 不能绕过生产启动策略；
7. 启动、停止、失败、撤销和孤儿回收均进入防篡改审计链。

## 3. 设计原则与非目标

### 3.1 设计原则

- **安全权威集中**：Capability、网络白名单、DLP、资源和沙箱策略由
  `security.runtime`/securityd 决定，PA Runtime 不自行放宽策略。
- **执行与决策分离**：securityd 不执行第三方代码，PA Runtime 不修改安全决策。
- **默认拒绝**：租约缺失、过期、digest 不匹配、策略无法应用或证明失败时拒绝启动。
- **最小暴露面**：Agent 只获得声明的文件、网络、IPC 和安全 API，不暴露完整系统总线。
- **可证明运行**：每个运行实例都有可查询的策略摘要和容器证明信息。
- **可回滚**：策略或后端升级失败时清理临时容器、cgroup 和租约，不留下半运行状态。

### 3.2 非目标

- 本期不让 securityd 直接负责第三方 Agent 的进程创建；
- 本期不要求立即引入 Docker/containerd；
- 本期不把远端 HTTP MCP 当作本地容器进程，远端数据出境仍由 DLP 和网络策略控制；
- 本期不把 `run.sh` 设计成生产兼容入口。

## 4. 组件职责与信任边界

### 4.1 组件职责

| 组件 | 类型 | 商用职责 | 明确不负责的内容 |
|---|---|---|---|
| `securityd` | system daemon | Capability、Confirm、DLP、Token、审计和安全数据面 | 不启动第三方 Agent |
| `security.runtime` | securityd 子模块/接口（目标商用能力） | manifest 校验、策略编译、启动租约、证明、撤销 | 不直接管理 Agent 进程 |
| PA `bianbu-agent-runtime`（`../bianbu-agent-runtime`） | PA 运行时服务/进程 | Agent API、Run 调度、`ExecutionCoordinator`、sandbox/host 后端、cgroup、端口代理、健康检查和孤儿回收 | 不改变 security.runtime 策略；不把 `io.bianbu.Runtime` 当作当前依赖 |
| `BwrapBackend` | PA Runtime 插件 | 在 K3 上执行第一版轻量 Agent sandbox | 不自行生成授权策略 |
| `HostProcessBackend` | PA Runtime 插件 | 在宿主机启动受 PA Runtime 管理的 Agent 进程，并应用 host 约束 | 不绕过 capability、DLP、Confirm、Token 或审计 |
| `OCIBackend` | PA Runtime 插件 | 在需要标准 OCI 的部署中执行隔离 Agent | 不自行生成授权策略 |
| Agent | 受 Runtime 管理的执行实例 | 处理对话和受控工具调用 | 不创建同级容器、不修改策略 |
| PA security client | Agent 内客户端 | 通过受限 API 访问判权、DLP、Token、审计 | 不导入 securityd 源码 |
| `run.sh` | 开发脚本 | 本地调试和开发验证 | 不作为生产启动链 |

### 4.2 信任边界

```text
宿主机安全边界
├── securityd / security.runtime（信任根）
├── PA bianbu-agent-runtime（受信执行编排器，当前对接方）
└── systemd / kernel / bwrap（隔离执行基础设施）

Agent 执行边界（sandbox 或 host）
├── Agent 代码和插件
├── Agent workspace
└── 受限 security client / runtime endpoint
```

securityd 运行在宿主机 systemd 服务中；sandbox Agent 只能访问专用 security UDS
和经过过滤的运行时接口，不应获得完整 `/run/dbus/system_bus_socket`。host Agent
同样只能通过 Runtime 注入的受限 endpoint 访问安全服务，不因位于宿主机而获得
额外权限。

## 5. `security.runtime` 设计

### 5.1 模块布局

建议在 securityd 中新增：

```text
impl/bianbu-securityd/securityd/runtime/
├── __init__.py
├── policy.py          # SandboxPolicy 数据模型和 digest
├── compiler.py        # capability → mount/seccomp/network/resource 编译
├── lease.py           # LaunchLease 签发、消费和过期
├── attestation.py     # PID/cgroup/container/policy 校验
├── lifecycle.py       # 运行状态、撤销和孤儿记录
└── audit.py           # runtime 事件审计适配
```

现有 `securityd/sandbox.py` 的 bwrap 参数构造可以复用为策略执行基础，但生产
调用路径应由 Runtime Backend 使用，不能让 PA 或 `run.sh` 直接决定最终策略。

### 5.2 ExecutionPolicy（含 SandboxPolicy）

`ExecutionPolicy` 是不可变、带版本和摘要的启动策略；sandbox 模式下的隔离字段
构成 `SandboxPolicy`。用户提交 `requested_mode`，但它不是授权结果。策略引擎根据
Agent 风险级别、能力集合、包签名、设备策略和资源约束，返回最终的
`effective_mode`：

| 请求模式 | 含义 | 安全策略处理 |
|---|---|---|
| `auto` | 用户不指定模式 | 由 Runtime 和 security.runtime 选择风险最低的可用模式 |
| `sandbox` | 请求容器/隔离运行 | 策略允许时使用 `BwrapBackend`/`OCIBackend` |
| `host` | 请求宿主机进程运行 | 仅低风险、已签名且策略允许的 Agent 可采用；否则拒绝或升级为 `sandbox` |

建议序列化为 JSON，使用

```json
{
  "version": 1,
  "requested_mode": "auto",
  "effective_mode": "sandbox",
  "backend": "bwrap",
  "sandbox_required": true,
  "agent_id": "com.bianbu.agent",
  "entrypoint": ["/usr/bin/python3", "-m", "bianbu_agent"],
  "readonly_mounts": ["/usr", "/etc"],
  "writable_mounts": [
    {"host": "/var/lib/bianbu-agents/com.bianbu.agent", "target": "/home/agent"}
  ],
  "deny_paths": ["/etc/shadow", "/etc/sudoers", "/root", "/etc/ssh"],
  "namespaces": ["user", "pid", "mnt", "ipc", "uts", "net"],
  "capabilities": [],
  "seccomp_profile": {"path": "/run/bianbu/sandbox/com.bianbu.agent/seccomp.bpf", "digest": "sha256:..."},
  "network": {
    "mode": "whitelist",
    "domains": ["api.rvcompute.com"],
    "default": "drop"
  },
  "resources": {
    "memory_max": "2G",
    "cpu_quota": "100%",
    "tasks_max": 256,
    "io_weight": 100
  },
  "environment_allowlist": [
    "BIANBU_AGENT_ID",
    "BIANBU_RUNTIME_ENDPOINT",
    "BIANBU_SECURITY_ENDPOINT"
  ],
  "host_constraints": {
    "environment_allowlist": ["BIANBU_AGENT_ID", "BIANBU_RUNTIME_ENDPOINT", "BIANBU_SECURITY_ENDPOINT"],
    "working_directory": "/var/lib/bianbu-agents/com.bianbu.agent/workspace",
    "resource_cgroup_required": true,
    "port_proxy_required": true,
    "egress_enforcement": "security-broker-or-ebpf",
    "landlock_required": false,
    "seccomp_required": false,
    "system_dbus_allowed": false
  },
}
```

约束：

- `entrypoint` 必须来自已安装且已验签的 Agent 包，Runtime 不接受用户在启动请求中替换；
- `readonly_mounts`、`writable_mounts`、网络域名和资源限额均不得由 Agent 执行实例修改；
- `effective_mode=host` 时不创建容器，但必须通过 `HostProcessBackend` 启动，应用
  `host_constraints`、专属 cgroup、环境白名单、端口代理、生命周期监控和同等安全审计；
- host 的出站网络必须由 security broker、cgroup/eBPF 防火墙或等效内核机制执行，
  不能只依赖 Agent 自觉遵守；需要文件路径隔离时必须启用 Landlock/AppArmor 等强制机制，
  若设备不具备相应能力则拒绝 host 或升级为 sandbox；
- `sandbox_required=true` 时不得接受 host 模式；若用户请求 host，必须拒绝或记录
  原因后自动升级为 sandbox；
- `net=whitelist` 时默认 DROP，策略生成或应用失败按 fail-closed 处理；
- securityd 生成的 seccomp 文件必须存在且 digest 匹配，不能只记录路径。

### 5.3 LaunchLease

`LaunchLease` 将一次安全授权绑定到一次具体启动：

```text
lease_id
agent_id
issued_at
expires_at
boot_id
expires_monotonic
state: issued | committed | aborted | expired | revoked
runtime_instance_id（Commit 后写入）
```

建议默认 TTL 为 30 秒，且满足：

- 同一个 lease 只能 Commit 一次；
- agent、package、config、policy 任一摘要不匹配即拒绝；
- 过期 lease 不得启动；过期以签发时记录的**单调时钟**截止点（`expires_monotonic`）判定，
  墙上时钟仅用于展示和旧记录回退——NTP 首次校时前跳会让墙上时钟判定的 TTL 提前失效，
  把仍在启动窗口内的租约误判为过期。跨越重启的 `issued` 租约（`boot_id` 不同）一律按过期处理；
- Abort、Expire、Revoke 后不得复用；
- lease 事件写入 audit chain。

### 5.4 执行模式裁决

执行模式采用“用户请求、Runtime 调度、security.runtime 最终裁决”的三段式模型：

```text
用户/管理界面设置 requested_mode
        │
        ▼
bianbu-agent-runtime 读取 manifest、风险级别和设备可用后端
        │
        ▼
security.runtime 校验签名、能力、网络/文件约束和系统强制策略
        │
        ├─ 允许 host      → effective_mode=host，选择 HostProcessBackend
        ├─ 允许 sandbox   → effective_mode=sandbox，选择 Bwrap/OCIBackend
        └─ host 不安全    → 拒绝，或升级为 sandbox 并记录原因
```

`requested_mode` 只能取 `auto`、`sandbox`、`host`。当用户不指定时使用 `auto`。
`effective_mode` 必须由 `PrepareStart` 返回，并写入 lease、运行状态和审计事件；
Runtime 不得根据本地便利性自行把 `host` 改成放宽策略的启动方式。

host 模式只适用于低风险、已验签、能力集合受控且不要求 namespace 级文件/网络隔离
的 Agent。下列任一条件成立时必须使用 sandbox：高风险能力、未签名或来源不可信、
策略要求隐藏宿主路径、策略要求网络默认 DROP、系统/企业策略强制隔离，或
`HostProcessBackend` 无法满足资源与审计约束。

## 6. 生命周期与接口

### 6.1 目标启动时序（由 PA `bianbu-agent-runtime` 执行）

```text
PA Runtime.Start(agent_id, requested_mode)
  1. 读取已安装 Agent manifest、包摘要和运行配置摘要
  2. 由 PA Runtime 的 `SecurityRuntimeClient` 调 security.runtime.PrepareStart(requested_mode)
  4a. sandbox：创建私有 root/workspace、namespace、cgroup 和隔离进程
  4b. host：创建专属 workspace/cgroup，设置环境白名单和宿主进程约束
  5. 以固定 entrypoint 启动 Agent
  6. 获取 instance_id、PID、cgroup、（sandbox 时）container_id/namespace 和端口信息
  7. 由 PA Runtime 的 `SecurityRuntimeClient` 调 security.runtime.CommitStart()
  8. 校验通过后状态置为 RUNNING，并对外提供端口代理
```

上述任一步失败，PA Runtime 必须停止进程、删除临时容器（如有）和 cgroup、调用
`AbortStart`，然后返回错误；不得启动裸 Agent 作为降级方案。

### 6.2 Runtime 状态机

```text
INSTALLED ──Start──> STARTING ──Commit──> RUNNING
    ▲                  │  │                  │
    │                  │  └─失败────────────┘
    │                  ▼                     │
    └────清理──────  FAILED <──Stop── STOPPING
                                           │
                                           ▼
                                        STOPPED
```

生产状态至少包括：`INSTALLED`、`STARTING`、`RUNNING`、`PAUSED`、`STOPPING`、
`STOPPED`、`FAILED`、`REVOKED`、`TERMINATED`。状态迁移必须由 Runtime 串行化，

### 6.3 `security.runtime` 安全接口（由 PA Runtime 客户端调用）

目标是在同一个 securityd 进程上提供受限的 Runtime 安全接口。传输继续使用
securityd 现有的系统 D-Bus/UDS 数据面，调用方固定为 PA
`../bianbu-agent-runtime` 中的 `SecurityRuntimeClient`，而不是另起一个
`io.bianbu.Runtime` 服务。PA 当前已经使用的 `CheckPermissionV2`、
`RequestConfirmV2`、`MeterTokensV2`、`BindAgentV2` 等安全接口继续保留。
`PrepareStart/CommitStart` 已在 securityd 和 PA Runtime 中实现，并由 worker
验收链路实际调用；下表是当前实现的控制面契约：

| 方法 | 签名 | 说明 |
|---|---|---|
| `CommitStart` | `s lease_id, s instance_id, x pid, s cgroup_path, a{sv} attestation → a{sv}` | 绑定实际进程证明信息；PID/cgroup 由可信 sender 坐标补全并校验 |
| `AbortStart` | `s lease_id, s reason → b` | 启动失败或主动回滚 |
| `RevokeAgent` | `s agent_id, s reason → b` | 撤销运行授权并发出告警/审计事件 |
| `GetRuntimeState` | `s agent_id → a{sv}` | 查询 lease、instance、PID、cgroup 和策略摘要 |
| `ListRuntimeInstances` | `s agent_id → aa{sv}` | 列出当前及历史实例摘要 |

兼容保留现有 `io.bianbu.Security.BuildSandboxPolicy`，但新生产链路必须使用
`PrepareStart`，因为单独生成策略无法证明它被某次启动实际采用。

PA Runtime 侧建议新增一个内部适配层（不要求暴露为 D-Bus）：

```python
class SecurityRuntimeClient(Protocol):
    def prepare_start(self, request: StartRequest) -> StartDecision: ...
    def commit_start(self, attestation: StartAttestation) -> None: ...
    def abort_start(self, lease_id: str, reason: str) -> None: ...
    def revoke_agent(self, agent_id: str, reason: str) -> None: ...
```

适配层负责把 Python 数据模型转换成 securityd 的 D-Bus/UDS 调用；执行后端和
PA 的 HTTP `/api/v1/runs`、会话、模型调度仍由
`../bianbu-agent-runtime/bianbu_agent/` 自身负责。这样可以避免把 securityd
仓库中的参考 `runtime/runtime_service.py` 误当成 PA 的实际 Runtime 实现。

### 6.4 当前 PA Runtime 对接边界

当前方案不部署、不调用 `io.bianbu.Runtime`，也不要求启动
`impl/bianbu-securityd/runtime/runtime_service.py`。PA Runtime 的实际边界如下：

| PA Runtime 位置 | 当前职责 | 商用改造后的职责 |
|---|---|---|
| `bianbu_agent/server/runtime.py:BianbuAgentRuntime.start()` | 启动 PA Runtime、绑定 Agent 身份、加载模型/插件/会话/Run 服务 | 在 PA Runtime 启动协调器中读取 `requested_mode`，调用 `SecurityRuntimeClient.prepare_start()`，再启动对应执行后端 |
| `bianbu_agent/engines/langgraph/security_middleware.py` | Tool 前调用 `CheckPermissionV2`、确认和 session trust | 保持工具级判权；执行实例身份和 lease 由 PA Runtime 统一注入 |
| `bianbu_agent/security_skill_dlp.py` | Skill 文本 DLP；使用 `BIANBU_PA_AGENT_ID` 调版本化 client/正式 UDS，并在 securityd 不可用时 fail-closed | 保持版本化 security client，避免 Agent 直接导入 securityd 内部模块 |
| `bianbu_agent/api/runs.py:RunBroker`、`/api/v1/runs` | 接收 PA 对话 Run 并驱动 `BianbuAgentRuntime.runs` | 继续负责对话/Run；不直接决定 sandbox/host，不直接拼接 bwrap 参数 |

因此，本文的 `Start/Commit/Stop/Revoke` 均是 PA Runtime 内部协调器需要实现的
Python/进程控制动作；如果未来要对外提供 D-Bus 生命周期接口，应另行定义 API，
不能直接套用 `io.bianbu.Runtime` 的参考实现。

## 7. PA `bianbu-agent-runtime` 执行后端

### 7.1 统一后端接口

```python
class SandboxExecutor(Protocol):
    def create(self, policy: SandboxPolicy) -> ContainerHandle: ...
    def start(self, handle: ContainerHandle) -> None: ...
    def inspect(self, handle: ContainerHandle) -> ContainerAttestation: ...
    def stop(self, handle: ContainerHandle, timeout: float) -> None: ...
    def kill(self, handle: ContainerHandle) -> None: ...
    def cleanup(self, handle: ContainerHandle) -> None: ...
```

PA Runtime 同时提供不创建容器的宿主机后端。两类后端均必须返回统一的实例句柄和
证明信息，供 `CommitStart` 校验：

```python
class HostProcessExecutor(Protocol):
    def start(self, policy: ExecutionPolicy) -> HostProcessHandle: ...
    def inspect(self, handle: HostProcessHandle) -> ProcessAttestation: ...
    def stop(self, handle: HostProcessHandle, timeout: float) -> None: ...
    def kill(self, handle: HostProcessHandle) -> None: ...
    def cleanup(self, handle: HostProcessHandle) -> None: ...
```

### 7.2 第一阶段 `BwrapBackend`

worker K3 第一阶段使用 bubblewrap，统一抽象为 Agent Container。Backend 只能
从 `SandboxPolicy` 生成命令行，至少应用：

- user、PID、mount、IPC、UTS、NET namespace；
- `--cap-drop ALL`、`--die-with-parent`；
- policy 指定的只读/可写挂载和 deny path；
- policy 指定的 seccomp fd；
- policy 指定的 cgroup；
- 默认 DROP 的网络白名单；
- 固定 `HOME`、`BIANBU_AGENT_ID` 和安全端点环境变量。

PA Runtime 的 `BwrapBackend` 不读取用户额外的 bwrap 参数，也不允许 Agent 自己附加 bind、
capability 或 namespace 选项。

### 7.3 `HostProcessBackend`（非容器模式）

当 `effective_mode=host` 且安全策略明确允许时，PA Runtime 直接以固定 entrypoint
创建宿主机进程，不创建 bwrap/OCI 容器。该模式仍必须满足：

- 进程归属于 Runtime 创建的专属 systemd scope/cgroup，设置 memory、CPU、PIDs 和 IO 限额；
- 使用策略给出的最小环境白名单和工作目录，清理继承的凭据、代理和调试变量；
- 不允许用户替换 entrypoint、增加 capability、挂载路径或打开系统 D-Bus；
- 按策略启用 seccomp、Landlock/AppArmor 和 egress 防火墙；任一强制约束不可用时不启动 host；
- 生产端口必须经 Runtime 端口代理，在 `CommitStart` 成功前不对外开放；
- capability 判权、Confirm/HITL、DLP、Token 计量和审计路径与 sandbox 模式完全一致；
- PA Runtime 负责健康检查、停止、撤销、崩溃重启策略和孤儿进程回收。

host 模式的差异仅是进程不进入容器 namespace；它不是“绕过 securityd”或“用户自行
运行 Agent”。高风险 Agent、含高危能力的 Agent、未验签包或系统强制隔离时，
`HostProcessBackend` 必须拒绝请求或由策略将 `effective_mode` 改为 `sandbox`。

### 7.4 第二阶段 OCI 后端

如商用部署需要标准 OCI bundle，再增加 `OCIBackend`（例如 crun）。对外保持
`SandboxExecutor` 接口不变，Runtime 根据平台能力选择：

```text
K3 基础版：BwrapBackend
标准容器版：OCIBackend
```

“容器”是产品抽象；第一阶段不把 Docker daemon 作为运行依赖。

## 8. PA 安全接入改造（sandbox 与 host 通用）

### 8.1 目标

Agent 执行实例不应直接挂载或继承：

```text
/home/bianbu/impl/bianbu-securityd
/run/dbus/system_bus_socket
```

当前为解决 PA import 问题而挂载 securityd 源码和系统 D-Bus，只能作为过渡验证
方案，不能用于商用交付。host 模式同样不能因为没有容器边界而直接导入
securityd 内部模块或连接完整系统 D-Bus。

### 8.2 客户端模式

PA 应仅依赖可版本化的 `bianbu_security_client`：

```text
PA security client
  ├─ CheckPermission / Confirm       → 受限 security endpoint
  ├─ DLP scan / mask                 → securityd UDS 数据面
  ├─ MeterTokens                     → 受限控制接口
  ├─ AuditLog                        → securityd UDS / broker
  └─ GetRuntimeIdentity              → Runtime endpoint
```

实现选择按安全性排序：

1. 专用 security UDS，协议层按 operation 白名单限制；
2. 受限 D-Bus broker，只暴露 `io.bianbu.Security` 必需方法；
3. 不直接把完整系统 D-Bus socket 暴露给 Agent。

客户端须能在 sandbox 或 host 执行实例内完成所有必要功能，不依赖导入 securityd 的 `securityd.dlp`、
`securityd.langgraph` 等内部 Python 包。securityd 内部模块只允许宿主 daemon 使用。

### 8.3 Runtime Endpoint

Agent 与 Runtime 的交互通过版本化的专用 socket 或受限代理完成，用于：

- 查询自己的 instance/lease 状态；
- 请求 graceful stop；
- 接收 TokenExceeded、Revoke、SecurityAlert 等事件；
- 上报健康状态和退出原因。

Agent 不能通过该 endpoint 请求放宽 mount、network、seccomp 或 capability。

## 9. 端口、网络与文件系统

### 9.1 Agent 端口

Agent 不直接把生产服务绑定到宿主机 `0.0.0.0:9899`。Runtime 应负责：

1. sandbox 实例使用容器内部端口；host 实例使用 Runtime 分配的本机回环/专属端口；
2. 由宿主端口代理转发到健康实例；
3. 只在 CommitStart 成功后开放外部访问；
4. Stop/Revoke/健康检查失败时立即撤销转发。

开发模式仍可使用 `run.sh` 直接监听 `9899`，但必须显示标记为非生产模式。

### 9.2 文件系统

默认只读：`/usr`、必要的 `/etc` 和经审核的运行时依赖。

默认可写：

```text
/var/lib/bianbu-agents/<agent_id>/workspace
/var/lib/bianbu-agents/<agent_id>/sessions
/var/lib/bianbu-agents/<agent_id>/cache
```

`/etc/shadow`、`/etc/gshadow`、`/etc/sudoers`、`/root`、`/etc/ssh` 等强制拒绝
路径必须由 Backend 无条件覆盖或隐藏。真实凭据不应通过普通 bind 挂入 sandbox，
也不应直接注入 host 进程环境。

## 10. 故障、撤销与绕过防护

### 10.1 Fail-closed 规则

以下情况不得启动新 Agent：

- securityd 或 security.runtime 不可达；
- package/config/policy digest 无法校验；
- lease 过期、重复使用或状态不正确；
- 请求的执行后端不可用；
- sandbox 模式下 seccomp、cgroup、mount、network 任一步应用失败；
- host 模式下 cgroup、环境白名单、端口代理或进程约束任一步应用失败；
- CommitStart 的 PID、cgroup、（sandbox 时）容器 ID 与预期不一致。

运行中出现以下情况，PA Runtime 应在策略规定的宽限期内停止 Agent：

- 收到 security.runtime 的 Revoke 通知；
- cgroup 丢失或资源限制不再生效；
- sandbox 进程脱离父进程、host 进程脱离 Runtime scope 或 PID 不再匹配；
- 安全 endpoint 失联超过配置的最大宽限期。

### 10.2 防止生产绕过

- 生产 Agent 只由 PA `bianbu-agent-runtime` 服务/进程启动；
- Agent 包的 entrypoint 不提供用户自定义命令覆盖；
- `run.sh` 在生产包中不安装，或检测 `BIANBU_RUNTIME_MODE=production` 后拒绝启动；
- PA 启动时要求存在 Runtime 注入的 `instance_id`、`lease_id` 和安全 endpoint；
- 裸执行 `uv run bianbu-agent` 时返回明确错误，不进入服务监听；
- PA Runtime 定期扫描并回收不属于已提交 lease 的 Agent 进程和 cgroup。

### 10.3 撤销时序

```text
security.runtime.RevokeAgent(agent_id)
  → 写 Revoke 审计并通知 PA Runtime
  → PA Runtime 撤销端口代理
  → graceful stop（短超时）
  → PA Runtime kill sandbox 或 host 进程
  → 删除 cgroup / 临时 root（如有）/ socket
  → Commit 状态改为 REVOKED
```

## 11. 审计与可观测性

每个 runtime 事件至少包含：

```text
event_id
timestamp
agent_id
instance_id
lease_id
container_id（sandbox 时必填，host 时为空）
pid
cgroup_path
backend
requested_mode
effective_mode
operation
result
reason
```

必审计事件：

- `prepare_start`、`policy_compiled`、`container_created`、`agent_started`；
- `commit_start`、`start_failed`、`abort_start`；
- `pause`、`resume`、`stop`、`terminate`、`revoke`；
- `policy_mismatch`、`attestation_failed`、`orphan_reaped`；
- securityd 不可用、策略应用失败和资源限制失效。

PA Runtime 日志不能替代 securityd 哈希链审计；关键事件必须通过 securityd 的审计
接口写入防篡改链，日志中只保留可关联的 event_id。

## 12. 分阶段落地计划

| 阶段 | 交付内容 | 退出条件 |
|---|---|---|
| P0 当前验证 | `run.sh` + bwrap；PA + securityd 判权、DLP、Token、审计 | testkit 沙箱和安全接入测试通过；明确标注非商用 |
| P1 策略与租约 | `securityd/runtime/policy.py`、`lease.py`、`PrepareStart/CommitStart` | lease 过期/重复/digest 不匹配均拒绝 |
| P2 PA Runtime 后端 | `../bianbu-agent-runtime` 中的 `BwrapBackend`、`HostProcessBackend`、`ExecutionCoordinator`、cgroup、端口代理 | sandbox/host 后端与全链路控制面已完成开发；worker 已验证 bwrap/安全接入，独立 child、生产 Manager 和重启回收仍待证 |
| P3 最小客户端 | PA 移除 securityd 源码依赖，使用受限 security client/UDS | 容器不挂 securityd 源码和系统 D-Bus，DLP/Token/判权仍可用 |
| P4 生产封装 | systemd 服务、安装器、生产绕过防护、孤儿回收、升级回滚 | PA 裸启动门禁、失败清理和孤儿回收逻辑已实现；独立 Runtime Manager 安装包、生产 transient unit、升级回滚证据仍待补 |
| P5 商用增强 | OCI 后端、签名/证明强化、性能和长期稳定性 | Bwrap/OCI 后端互换不改上层 API |

## 13. 商用验收标准

| 编号 | 验收项 | 可测量标准 |
|---|---|---|
| RT-ACC-01 | 启动授权 | 100% 生产启动具有有效 lease；无 lease 启动数为 0 |
| RT-ACC-02 | 策略一致性 | 100% RUNNING 实例的 package/config/policy digest 与 Commit 记录一致 |
| RT-ACC-03 | 安全故障 | securityd 不可达时新 Agent 启动成功数为 0 |
| RT-ACC-04 | 文件隔离 | sandbox 未声明路径访问阻断率 100%；host 仅允许策略声明的工作目录/文件，越权访问阻断或告警率 100% |
| RT-ACC-05 | 网络隔离 | sandbox 未声明域名连接阻断率 100%；host 所有生产流量经端口代理且未授权出站连接阻断率 100% |
| RT-ACC-06 | seccomp | sandbox 黑名单 syscall 阻断率 100%；host 按策略要求启用等效 syscall 限制，未满足则不得启动 |
| RT-ACC-07 | 最小权限 | sandbox 不持有 `CAP_SYS_ADMIN` 等非必要 capability；host 进程不获得 Runtime 之外的额外 capability |
| RT-ACC-08 | 资源限制 | memory/cpu/pids 限额在 cgroup 文件和实际行为中均生效 |
| RT-ACC-09 | 撤销 | Revoke 到端口撤销 ≤1s，进程终止 ≤3s |
| RT-ACC-10 | 审计完整性 | 启动、失败、停止、撤销和孤儿回收 100% 有链式记录 |
| RT-ACC-11 | 绕过防护 | 直接执行 `run.sh` 或裸 `uv run` 在生产模式下启动成功数为 0 |
| RT-ACC-12 | 启动性能 | 冷启动（含策略、执行后端和健康检查）P95 ≤200ms；以 worker 实测为准 |
| RT-ACC-13 | 故障恢复 | PA Runtime 重启后 100% 孤儿实例可识别并清理，不能遗留活动 Agent |
| RT-ACC-14 | 客户端最小权限 | Agent sandbox 不挂载、host 不继承 securityd 源码和完整系统 D-Bus，判权/DLP/Token 功能保持可用 |
| RT-ACC-15 | host 模式选择 | 策略允许时请求 `host` 的实例 `effective_mode=host` 且不进入容器；判权、DLP、Token、审计 100% 可用 |
| RT-ACC-16 | host 强制隔离 | 请求 `host` 但 `sandbox_required=true` 时，100% 被拒绝或升级为 `sandbox`，并记录策略原因 |
| RT-ACC-17 | 双模式生命周期 | sandbox/host 实例均由 PA Runtime 创建、停止、撤销和回收；PA Runtime 重启后孤儿进程识别率 100% |

## 14. 测试计划

### 14.1 单元测试

- `ExecutionPolicy`/`SandboxPolicy` 字段校验、canonical JSON 和 digest 稳定性；
- lease 签发、过期、重复 Commit、Abort、Revoke；
- package/config/policy digest 不一致；
- Runtime 状态机非法迁移；
- bwrap/OCI 参数生成不允许用户注入额外选项；
- attestation 的 PID、cgroup、namespace 和容器 ID 校验。

### 14.2 集成测试

```text
security.runtime.PrepareStart
  → PA Runtime 按 effective_mode 选择 BwrapBackend 或 HostProcessBackend
  → executor.start
  → inspect
  → security.runtime.CommitStart
```

覆盖：

- 正常启动和停止；
- requested_mode=auto/sandbox/host 的策略裁决和 effective_mode 返回；
- host 模式不创建容器但受 cgroup、端口代理、生命周期和安全审计约束；
- host 请求被强制升级为 sandbox 或拒绝时记录原因；
- securityd 不可用；
- seccomp/cgroup/network/mount 任一失败；
- lease 过期和 policy digest 修改；
- PA Runtime 崩溃后孤儿回收；
- Revoke 后端口、进程和 cgroup 均清理。

### 14.3 Worker 端到端测试

当前阶段可继续运行：

```bash
cd /home/bianbu/bnsec-testkit
python3 runner.py SBX-01 SBX-02 SBX-03 SBX-04 SBX-05
```

商用 Runtime 接入后增加：

```text
RT-01 只能经 PA Runtime 内部启动协调器启动
RT-02 无 lease 启动失败
RT-03 policy digest 篡改启动失败
RT-04 cgroup / namespace / seccomp 证明一致
RT-05 Revoke 在规定时间内终止并审计
RT-06 裸 run.sh 和 uv 启动被生产模式拒绝
```

## 15. 当前实现差距与交付口径

| 能力 | 当前状态 | 商用口径 |
|---|---|---|
| PA + securityd 判权 | 已实现并可在 worker 验证 | 可作为安全接入交付项 |
| DLP / Token / 审计 | 已实现并可在 worker 验证 | 可作为 securityd 能力交付项 |
| `run.sh` bwrap | 已实现，支持开发验证 | 非生产沙箱管理器 |
| PA Runtime host 模式 | `HostProcessBackend` 已实现：策略裁决、systemd transient unit、cgroup/环境约束、停止和孤儿回收 | worker 必须实测 systemd 属性；生产端口只经 loopback 代理 |
| `security.runtime` 租约 | 已实现策略裁决、SQLite 启动租约、PID/cgroup/policy/backend/sandbox 证明及 D-Bus `io.bianbu.Security.Runtime` 控制面；已通过本机私有 session bus 生命周期驱动 | 仍需 worker systemd 生产安装后复验 |
| PA Runtime 统一启动 | `ExecutionCoordinator` 已接入 `BianbuAgentRuntime` 生命周期，执行 Prepare → backend → Commit；支持 stop/revoke、端口代理和启动失败清理 | worker 需验证真实进程和重启回收；PA 进程级过渡证明仍兼容保留 |
| securityd 策略实际应用 | `PrepareStart` 返回不可变 policy snapshot；PA 执行器校验 digest、backend、entrypoint，并下沉 mount/network/resource/env 约束 | seccomp FD 继承与 host egress broker 仍需 worker 能力证据 |
| PA 最小安全客户端 | Skill DLP 已切换版本化 client；部分历史 PA 插件仍有源码导入过渡路径 | P3 继续清理并提供独立客户端包 |
| 生产绕过阻断 | `BIANBU_RUNTIME_MODE=production` 下裸 `run.sh`/`bianbu-agent serve` 已在副作用前拒绝；需受信 Manager 注入 marker | P4 发布门禁；仍需独立 Manager 安装包和系统级证据 |

在 P1～P4 完成前，发布说明必须明确写成：

> 已完成 PA 与 securityd 的安全接入、security.runtime 启动租约控制面及 PA Runtime
> 双模式执行器开发实现（含 cgroup、端口代理、撤销和孤儿回收）；worker 生产安装、
> seccomp/egress 能力和长期 soak 仍需证据，`run.sh` 仍仅是开发入口。
