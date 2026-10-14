# Bianbu Agent Runtime 与 Security 交互评审

| 项 | 内容 |
|----|------|
| 文档编号 | BN-SEC-REVIEW-RUNTIME-001 |
| 版本 | V1.1 |
| 日期 | 2026-08-14 |
| 评审对象 | PA 应用 Runtime、bianbu-securityd，以及作为外部依赖的正式 bianbu-agent-runtimed 接口边界 |
| 评审类型 | 架构边界、交互时序、需求追溯、生产接入差距评审 |
| 状态 | 已完成仓库级交互分析；正式 Runtime 生产接入仍待验收 |

## 1. 目的与术语

本评审用于澄清三个名称相近但职责不同的组件，避免把 PA 已有的应用层 Runtime
误计为 `io.bianbu.Runtime` 生产服务，也避免让 securityd 越权承担 Runtime 的暂停、
终止或服务管理职责。

> **交付范围声明：** `/data/workspace2026-new/work0618/bianbu-next-agentos-dev-cc`
> 及其 Runtime 实现不在本次交付范围内，不作为本项目的实现来源、测试基线或完成度
> 证据。本次只交付 Securityd 侧的事件契约、审计、当前计量拒绝和接入说明；真实暂停、
> 终止及服务生命周期管理由正式 Agent Runtime/agent 项目自行实现和验收。

| 组件 | 代码位置 | 所属层 | 核心职责 |
|------|----------|--------|----------|
| PA Runtime | `../personal-agent/bianbu_agent/service_runtime.py`、`runtime.py`、`run_manager.py` | 应用执行层 | HTTP 服务、Session/Run、模型、LangGraph、插件、工具和应用级取消/恢复 |
| Securityd | `impl/bianbu-securityd/securityd/` | 安全治理层 | Capability 判权、Confirm、DLP、Token 计量、审计、沙箱策略和安全事件 |
| 系统 Agent Runtime | 正式目标为 `bianbu-agent-runtimed`，本次仅定义其与 Securityd 的接口契约 | L3 系统运行时层 | Agent 生命周期、沙箱/cgroup、Checkpoint、资源监控、Token 事件消费和跨 Agent 控制；实现与交付由 Runtime 项目负责 |

最终产品关系是“系统 Runtime 管理或承载 PA Runtime”，不是两个互相竞争的 Agent
Runtime。系统 Runtime 不运行 LLM 推理；PA Runtime 不替代系统级 cgroup、沙箱和
生产身份边界。

## 2. 需求追溯

| 交互能力 | PRD | SRS | 主要接口/证据 |
|----------|-----|-----|---------------|
| Agent 状态机、启动、暂停、恢复、停止、终止 | `RTE-01~06` | `FR-RTE-01~06` | `io.bianbu.Runtime`：`Start/Pause/Resume/Stop/Terminate` |
| Checkpoint、Restore、保留策略、崩溃恢复 | `RTE-07~11` | `FR-RTE-07~11` | `Checkpoint/Restore/ListCheckpoints` |
| CPU/内存统计、资源超限、历史导出 | `RTE-12~14` | `FR-RTE-12~14` | `GetResourceStats/ResourceExceeded/ExportResourceHistory` |
| Agent 间受控通信 | `RTE-15` | `FR-RTE-15` | `SendMessage` |
| 文件、cgroup、网络、seccomp、capability 沙箱 | `SBX-01~07` | `FR-SBX-01~07` | Runtime 启动时创建并应用沙箱；Security `BuildSandboxPolicy` 提供策略 |
| Token 超限和暂停/终止事件 | `SEC-04` | `FR-SEC-04` | Security `MeterTokensV2`、`TokenExceededV2`；Runtime/agent 消费并改变自身状态 |
| 网络白名单 | `SEC-07` | `FR-SEC-07` | Security 策略 + Runtime/systemd 强制 |

PA 的 `BianbuAgentRuntime` 对应应用执行和 Run 编排能力，但不能单独关闭上述
`FR-RTE-*`/`FR-SBX-*` 系统需求。需求归属以 `io.bianbu.Runtime` 和正式
`bianbu-agent-runtimed` 为准。

## 3. 责任边界

### 3.1 PA Runtime

- 接收 HTTP/API 请求并创建 `Session`、`Run`；
- 选择模型，驱动 LangGraph 和工具；
- 加载和执行插件、Hook、MCP 工具；
- 在模型/工具入口执行本地 Runtime 门禁；
- 展示确认、拒绝、暂停等面向用户的结果；
- 将能力判权、DLP、审计和 Token 计量请求送往 Securityd。

PA Runtime 不应自行伪造 UID、PID、cgroup 或 `agent_id` 身份，也不应绕过系统
Runtime 直接创建生产 sandbox/cgroup。

### 3.2 Securityd

- 从 D-Bus sender 或 UDS `SO_PEERCRED` 获取可信调用者身份；
- 执行 Capability 判权和 session trust 判定；
- 执行 DLP 扫描、脱敏和策略判断；
- 原子执行 Token 计量，拒绝当前超限请求；
- 写入哈希链审计并发送 `SecurityAlert/TokenExceededV2`；
- 生成 seccomp、网络和沙箱策略。

Securityd 不负责启动 PA，不执行 PA 工具，不调用
`io.bianbu.Runtime.Pause/Stop/Terminate`，也不通过停止 systemd 服务实现 Token
超限处理。

### 3.3 系统 Agent Runtime

- 以系统服务和专用 UID/cgroup 管理 Agent 生命周期；
- 创建和销毁沙箱、资源限制和网络隔离；
- 绑定 Agent 的可信 Runtime caller 和 `session_id/run_id`；
- 订阅并校验 `TokenExceededV2`；
- 将超限事件转换为自身 FSM 的 `PAUSED` 或 `TERMINATED`；
- 在模型/工具调度前阻断已暂停/终止的上下文；
- 负责 Checkpoint、Restore、资源统计和崩溃恢复。

## 4. 通信面与调用方向

| 通道 | 发起方 | 接收方 | 用途 |
|------|--------|--------|------|
| D-Bus `io.bianbu.Security` | PA/Runtime/管理端 | Securityd | 身份绑定、判权、Confirm、Token、控制面审计 |
| D-Bus `io.bianbu.Security` signal | Securityd | Runtime/PA/UI | Confirm、SecurityAlert、TokenExceededV2、审计相关事件 |
| UDS `/run/bianbu/securityd.sock` | PA/Runtime | Securityd | 大文本 `dlp.scan`、大审计载荷 `audit.batch` |
| D-Bus `io.bianbu.Runtime` | GUI/CLI/系统服务 | 系统 Runtime | Register、Start、Pause、Resume、Stop、Terminate、Checkpoint、Restore |
| Runtime 内部受控 IPC/进程管理 | 系统 Runtime | PA/Agent | 启动、回收、状态通知和调度门禁；正式接口需由 Runtime 产品冻结 |

关键调用方向固定为：

```text
PA/Runtime ──请求/调用──> Securityd
Securityd ──事件信号──> Runtime/PA/UI
GUI/CLI ──生命周期请求──> io.bianbu.Runtime
Runtime ──进程/沙箱/状态管理──> PA/Agent
```

Securityd 不反向调用 Runtime 的控制方法。

## 5. 启动与身份绑定时序

```text
1. systemd 启动 bianbu-securityd
   ├─ 占用 io.bianbu.Security
   ├─ 创建并设置 securityd.sock
   └─ 初始化 capability/DLP/token/audit 存储

2. systemd 启动 bianbu-agent-runtimed
   ├─ 以 bianbu-runtime 运行
   ├─ 加入 bianbu-security 补充组
   ├─ 注册 io.bianbu.Runtime
   └─ 订阅 TokenExceededV2

3. Runtime 注册 Agent
   ├─ Register(agent_id, name, metadata)
   ├─ 创建/分配 session_id、run_id
   ├─ 用自身 D-Bus sender 调 Security.BindAgentV2
   ├─ 建立 sandbox/cgroup/network 资源
   └─ 启动或承载 PA Runtime

4. PA 初始化
   ├─ 加载配置、模型、插件和 Hook
   ├─ 注册能力声明
   └─ 通过正式 Runtime 的安全入口使用 Securityd
```

Securityd 只接受服务端解析出的 UID/PID/executable/cgroup；V2 context 中的
`session_id/run_id` 只用于运行上下文和 session trust，不能替代内核凭据。

### 身份绑定约束

一个 `agent_id` 不能被 Runtime 进程和 PA 进程分别作为两个不相关的 caller 直接
绑定。正式产品必须冻结以下一种模型：

1. Runtime 承载 PA 执行，Runtime caller 作为唯一安全主体；或
2. Runtime 作为安全代理，PA 通过受控 IPC 使用 Runtime 身份访问 Securityd；或
3. Runtime 与 PA 共享稳定的 systemd service/cgroup，并在 Securityd 中明确允许
   该进程组的身份模型。

不能让 PA 用一个 caller 绑定、Runtime 再用另一个 caller 覆盖同一个 `agent_id`。

## 6. 一次 Run 的交互流程

```text
用户 → PA HTTP API → PA BianbuAgentRuntime → RunManager 创建 Run
                                      │
                                      ├─ input hook → Security DLP
                                      ├─ before_model → Security DLP/策略
                                      ├─ LLM 调用 → MeterTokensV2
                                      ├─ before_tool → CheckPermission/DLP/审计
                                      ├─ HITL Confirm（需要时）
                                      ├─ 工具执行
                                      ├─ after_tool → 返回值 DLP/审计
                                      ├─ after_model → 输出 DLP/审计
                                      └─ after_run → 清理 session 映射/最终审计
```

### 6.1 工具判权

```text
PA before_tool
  → Security.CheckPermission(V2)
  → Security DLP pre_tool_call
  → Security audit handler
  → ALLOW / CONFIRM / BLOCK
```

- `ALLOW`：PA 执行工具；
- `CONFIRM`：PA 进入 HITL 等待，UI/管理端调用 `RespondConfirm`，Securityd 唤醒请求；
- `BLOCK`：PA 抛出结构化 `SecurityDenied`，RunManager 向前端发布拒绝原因，工具不执行。

工具返回值进入模型上下文前必须再次过 DLP。大于 4KB 的文本使用 UDS
`dlp.scan`，响应只返回脱敏文本、finding 类型/位置/策略，不返回原始 PII value。

### 6.2 Confirm

```text
Security.RequestConfirm(V2)
  → Securityd 发 ConfirmRequest
  → UI/管理端显示确认
  → 管理端 RespondConfirm(request_id, approved)
  → Securityd 校验管理员/seat/发起 caller
  → 返回 approved/denied
  → PA/Runtime 继续或结束当前工具调用
```

Securityd 负责确认请求的等待、一次性消费和授权校验；PA/Runtime 负责把结果映射
到自己的 Run/用户体验。

## 7. Token 超限交互流程

```text
PA/Runtime
  → Security.MeterTokensV2(agent_id, tokens, scope,
                            {session_id, run_id})
  → Securityd 原子更新 conversation/day 用量
```

未超限时返回 `within=true`。超限时 Securityd 同时完成：

1. 当前请求返回 `within=false`；
2. 写入 `token_meter/exceed` 审计；
3. 发送兼容的 `TokenExceeded`；
4. 发送带完整上下文的 `TokenExceededV2`；
5. 发送 `SecurityAlert`。

随后：

```text
TokenExceededV2
  → RuntimeSecurityConsumer 校验 agent/session/run、used>limit、policy_version
  → runtime-token.db 事件去重和状态持久化
  → Runtime 回调自身 FSM
  → PAUSED 或 TERMINATED
  → 模型入口 assert_can_call() 拒绝
  → 工具入口 assert_can_call() 拒绝
```

重复事件不得重复触发状态回调；Runtime 重启后读取持久化状态，仍不得放行被阻断
的上下文。暂停/终止动作由 Runtime 自己完成，Securityd 不调用 Runtime 的 Pause、
Stop 或 Terminate。

## 8. 生命周期、恢复和关闭

### 8.1 普通暂停/恢复

```text
GUI/CLI → Runtime.Pause(agent_id, snapshot)
        → 可选创建 checkpoint
        → Runtime FSM: RUNNING → PAUSED

GUI/CLI → Runtime.Resume(agent_id)
        → Runtime 检查 token/security 状态
        → 非 token-blocked 上下文才允许 PAUSED → RUNNING
```

Token 超限形成的 `PAUSED` 不能简单恢复同一个超限 Run；应新建上下文、调整配额或
按产品策略转为终止。

### 8.2 Runtime 重启

```text
Runtime 重启
  → 读取 Agent 记录和 runtime-token.db
  → 恢复 RUNNING/PAUSED 记录
  → 重新 BindAgentV2
  → 重新订阅 TokenExceededV2
  → 缺失安全绑定时降级 STOPPED，禁止无门禁运行
```

Securityd 重启时，审计链和 request id 持久化保证安全事件、UDS 审计重放和调用者
绑定不会被无条件伪造或重复写入。

### 8.3 停止/终止

```text
Runtime.Stop       → 停止 Agent、释放运行资源，可保留记录
Runtime.Terminate  → 终止 Agent、清理关联数据和运行资源
```

Securityd 只记录相关安全审计，不直接执行上述服务控制动作。

## 9. 当前实现状态与差距

| 项目 | 当前状态 | 不能宣称完成的原因 |
|------|----------|--------------------|
| PA 应用 Runtime | 已实现 | 主要是应用层 Run/模型/工具编排，不是系统级 `io.bianbu.Runtime` |
| Securityd D-Bus 控制面 | 已实现并在 worker 验证 | 正式 Runtime 的 UID/cgroup/生产总线身份矩阵仍待验收 |
| Securityd UDS 数据面 | 已接入正式 securityd service，PA 产品链路已完成 | `DLP-04` 已验证大于 4KB 走 `dlp.scan`、大于 1KB 走 `audit.batch`；剩余仅生产不同 UID/socket group 证据 |
| 参考 Runtime | 已实现并有 `RUNTIME_SERVICE_E2E_PASS` | `Start` 等参考实现证据不能替代正式 Runtime 产品和 systemd 身份 |
| 正式 Runtime 消费方 | 不在本次交付范围 | 正式 Runtime/agent 需自行订阅 `TokenExceededV2`、更新 FSM，并在模型/工具入口执行门禁 |
| Token consumer/guard 参考适配 | 本仓已有接口参考和私有 D-Bus 契约测试 | 仅用于说明消费语义，不计为正式 Runtime 实现或本次 Runtime 交付 |
| 生产 systemd Runtime | 未在 worker 完成 | `runtime_production_probe.py` 仍正确返回 `RUNTIME_PRODUCTION_BLOCKED` |
| 沙箱/cgroup/network | 仓库有策略和模板，部分 worker 强制能力已验证 | 正式 Runtime 创建并登记实际 unit、ControlGroup 和 UID 后才能关闭门禁 |

当前最重要的产品化缺口不是再增加一个 PA Runtime，也不是安装参考 Runtime 让探针
“变绿”，而是完成 PA 与正式
`bianbu-agent-runtimed` 的安全边界冻结：由谁持有 Agent caller、PA 如何接受 Runtime
的状态门禁、正式不同 UID 如何访问 UDS，以及 Runtime 如何实际创建/回收 sandbox。

### 9.1 2026-08-14 Security-only worker 验证

worker 在没有 `bianbu-agent-runtimed.service`、系统总线也未注册
`io.bianbu.Runtime` 的状态下，已执行真实 Securityd 控制面验证：

```text
BindAgentV2
  → SetTokenBudget(conv=1, day=10, on_exceed=pause_and_notify)
  → MeterTokensV2(tokens=2, session_id=sec-notify-session,
                   run_id=sec-notify-run)
  → within=false / remaining=0
  → 收到 TokenExceededV2
```

事件包含 `agent_id/session_id/run_id/scope/used/limit/reason/policy_version`，并得到
`SECURITY_TOKEN_NOTIFY_ONLY_PASS`。验证期间 `bianbu-securityd.service` 保持 active，
Runtime unit 为 not found。这证明 P0-4/P0-05 的 **Security 侧职责已完成**：超限判定、
审计、当前计量拒绝和通知均不依赖 Runtime 服务，也不会调用或停止 Runtime。

真实 `PAUSED/TERMINATED`、模型/工具后续拒绝和 Runtime 重启恢复属于正式 Runtime/agent
的外部验收项，不计入本次交付完成度。正式 Runtime 缺失时，生产探针继续返回
`RUNTIME_PRODUCTION_BLOCKED` 是正确的 fail-closed 行为。

## 10. 生产验收闭环

必须在正式目标镜像保存以下证据，才能关闭 P0-01/P0-05 和相关 P1 项：

1. `systemctl show bianbu-agent-runtimed.service`：`ActiveState`、`MainPID`、`User`、
   `Group`、`ControlGroup` 与部署矩阵一致；
2. `BindAgentV2` 审计：UID、executable、cgroup、session/run 与 Runtime unit 一致；
3. 真实 `MeterTokensV2 → TokenExceededV2 → PAUSED/TERMINATED`，1 秒内完成；
4. 超限后模型和工具调用 100% 拒绝，重复事件不重复回调，Runtime 重启后仍阻断；
5. Securityd 日志证明没有调用 `io.bianbu.Runtime.Pause/Stop/Terminate`；
6. 正式 systemd/cgroup/network 属性和 OOM/资源超限探针通过；
7. PA 真实大载荷 DLP/审计选路和断线重试通过；
8. 外部产品 E2E `0 skipped`，并保存命令、时间、镜像版本和原始报告。

在这些证据齐全前，整体状态保持“商用候选/不通过 GA”，不能将参考 Runtime 或 PA
Runtime 的单测结果写成正式 Runtime 生产接入完成。
