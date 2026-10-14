# Bianbu Security 子系统 IPD 阶段评估与产品化 Review

| 项 | 内容 |
|----|------|
| 文档编号 | BN-SEC-REVIEW-IPD-001 |
| 版本 | V2.0 |
| 日期 | 2026-08-14（初评）；2026-08-17（当前复验） |
| 评审对象 | Bianbu Security 子系统（securityd、bianbu-agent 集成、LangGraph 集成、DLP、沙箱、管理工具） |
| 评审类型 | IPD 阶段评估、完成度评估、遗留功能识别、产品化优化建议 |
| 评审状态 | Security 责任域发布证据门禁已通过；范围外 Runtime 只记录集成状态，不计入本次完成度 |
| 评审结论 | 仓库侧功能和验证完成，达到 Security 商用候选；24/72 小时及组织级运营证据待收口 |

> 本报告只评估 Bianbu Security 子系统，不把 Bianbu Next 其他 AI、记忆、日历、Skill 或 Agent Runtime 服务的未实现内容直接计入 Security 完成度。
>
> 评估采用三个口径：功能是否编码、是否有可复核验证证据、是否满足产品化发布条件。三者不能混为一个“完成/未完成”状态。
>
> `/data/workspace2026-new/work0618/bianbu-next-agentos-dev-cc` 不在本次交付范围内。
> 正式 Runtime 的实现、安装、暂停/终止和生命周期测试属于外部责任域；本项目只交付
> Securityd 的安全事件生产端与验收契约。
>
> **V2.0 口径优先级：** 本文保留部分历史验证记录用于追溯；凡旧计数、旧缺口或
> “Runtime 阻断 Security 交付”的表述与 §5.6.6、§7.4.0、§9 的当前结论冲突，均以
> V2.0 当前结论为准。

## 1. 结论摘要

当前项目最准确的状态是：

> Security 仓库侧功能、worker 验证、生产安装和可归档发布证据门禁已经完成，当前处于
> TR6 候选收口阶段。完成 24/72 小时耐久、组织级 CA/密钥运营、桌面 seat 授权和第三方
> 渗透证据后，可提交正式 ADCP/商用签收。

### 1.1 分口径完成度

| 口径 | 评估值 | 说明 |
|------|--------|------|
| 核心功能编码 | 100%（86/86） | Capability、确认、审计、沙箱、DLP、Hook、LangGraph、UDS、PA 接入及生产 WebUI 均已有实现 |
| 需求验证 | 约 99% | worker `557 passed / 3 skipped`，strict `543+14+3` 且 E2E 0 skip，testkit 35/35；仅正式长期耐久报告待生成 |
| 产品化交付 | 约 96% | hermetic venv、Gunicorn、专用身份、正式 UDS、polkit、SBOM/CVE=0、安装/升级/回滚和 Security 证据门禁已通过；组织级运营证据待收口 |
| IPD 综合判断 | TR6 候选 | Security 商用候选；尚不宣称无条件 GA |

### 1.2 当前不能直接发布的原因

本次 Security 交付进入正式商用签收前仍需关闭：

1. 正式 24/72 小时耐久报告；
2. 组织级签名 CA、密钥托管、轮换和吊销运营证据；
3. 真实桌面 seat/polkit 的允许、拒绝、过期和重放日志；
4. 第三方渗透报告；
5. 正式版本/tag、发布流水线原始报告和审批归档。

正式 Runtime 身份、网络/cgroup、Token 后续暂停和模型/工具门禁属于范围外系统集成项，
可影响完整 Bianbu Next 产品集成状态，但不计入本次 Security 完成度或剩余工作。

## 2. 评审范围与证据

### 2.1 评审范围

本次纳入评估的模块如下：

| 模块 | 评估内容 |
|------|----------|
| `securityd` | Manifest、Capability、确认门禁、Token、审计、seccomp、网络策略、Key Vault、D-Bus 服务 |
| 沙箱 | bubblewrap 文件/namespace/capability 隔离、seccomp、cgroup、fail-closed、agent/mcp/tool 模式 |
| 干预点框架 | 8 个 HookPoint、handler 链、决策合并、短路、审计透明 |
| DLP | PII 检测、输入/模型/工具/输出处理、逐字泄露、远端 MCP 出境提升、策略 WebUI |
| Agent 集成 | bianbu-agent Hook、LangGraph ToolNode/HITL/Token、MCP 两层判权 |
| 管理面 | D-Bus、Python client、`bncli`、WebUI、实时信号和 Web Terminal |
| 工程交付 | 测试、worker 验证、安装资产、打包、升级和生产部署资料 |

### 2.2 主要证据文件

- 产品需求：[docs/BNAgent-Security-PRD-Table.md](../BNAgent-Security-PRD-Table.md)
- 安全 SRS：[docs/BNAgent-Security-SRS.md](../BNAgent-Security-SRS.md)
- 需求汇总：[docs/BNAgent-Security-SRS-Table.md](../BNAgent-Security-SRS-Table.md)
- 方案：[docs/BNAgent-Security-solution.md](../BNAgent-Security-solution.md)
- API：[docs/BNAgent-Security-API.md](../BNAgent-Security-API.md)
- 实现进度：[docs/IMPL-PROGRESS.md](../IMPL-PROGRESS.md)
- 验证待办：[docs/BNAgent-Security-VerifyBacklog.md](../BNAgent-Security-VerifyBacklog.md)
- 整改计划：[docs/BNAgent-Security-Remediation-Plan.md](../BNAgent-Security-Remediation-Plan.md)
- 完成报告：[docs/BNAgent-Security-Final-Report.md](../BNAgent-Security-Final-Report.md)
- Runtime 交互评审：[BNAgent-Runtime-Security-Interaction-Review.md](BNAgent-Runtime-Security-Interaction-Review.md)
- 正式 Runtime 验收清单：[Runtime-Production-Integration-Checklist.md](Runtime-Production-Integration-Checklist.md)
- 实现目录：[impl/bianbu-securityd](../../impl/bianbu-securityd)

### 2.3 证据可信度说明

当前报告中存在多个历史口径：68/80/86 条 SRS、68/138/324 个测试、799/798/805 项外部回归等。它们来自不同阶段，不能直接相加或互相替代。

本报告遵循以下优先级：

1. 当前代码和当前提交可检查内容；
2. 带测试名称、脚本、平台和结果的 worker 验证记录；
3. 需求/设计文档中的状态字段；
4. 仅有“全部完成/可商用”字样、但缺少证据的汇总结论。

## 3. IPD 阶段判断

### 3.1 阶段总览

| IPD 阶段 | 当前判断 | 证据与差距 |
|----------|----------|------------|
| 概念阶段 | 已完成 | 安全目标、Capability 模型、L1–L4 风险、沙箱、DLP、审计边界已定义 |
| 计划阶段 | 已完成 | PRD、SRS、方案、API、工作量、里程碑和当前范围已冻结 |
| 开发阶段 | 已完成 | Security 86/86 仓库侧需求已实现 |
| 验证阶段 | 后期收口 | worker 默认/strict/testkit/PA、故障恢复和发布证据门禁已通过；24/72 小时与第三方渗透待完成 |
| 发布阶段 | 候选通过 | WebUI/身份/供应链/安装/升级/回滚通过；组织 CA、桌面授权、长期耐久和审批待收口 |
| 生命周期阶段 | 已建立基线 | 已有依赖锁、CVE 扫描、数据库迁移和发布清单；24/72 小时运营与正式补丁流程仍需落地 |

### 3.2 TR5/TR6 判定

当前为 **TR6 候选**：仓库侧开发与验证完成，等待长期可靠性和组织级运营证据后提交
ADCP/正式商用签收。

进入 TR6 前至少需要：

- 24/72 小时耐久报告通过；
- 组织级 CA/密钥、桌面 seat/polkit 和第三方渗透证据齐全；
- 正式 tag、变更单和审批记录关联同一版本基线。

## 4. 已完成能力

以下能力已经有代码实现，且大部分有单测或 worker 验证证据：

| 需求域 | 已完成内容 | 当前判断 |
|--------|------------|----------|
| SEC-01 | Manifest 解析、权限声明、签名验证、安装登记 | 已实现并验证 |
| SEC-02 | Capability 注册、授权/撤销、风险等级、scope 前缀匹配 | 已实现并验证 |
| SEC-03 | CONFIRM、超时拒绝、L4 二次确认、UI/CLI/Hermes 路径 | 主路径和 V2 session trust 已验证；生产桌面授权仍待验收 |
| SEC-04 | conversation/day Token 计量、持久化、跨日重置、告警信号 | securityd、Runtime guard 和可嵌入 Runtime bridge 已实现；正式 Runtime 进程接入仍待验收 |
| SEC-05 | x86_64/riscv64 seccomp BPF、危险 syscall 拦截、子进程继承 | 已验证 |
| SEC-06 | SQLite 审计、SHA-256 哈希链、过滤导出、离线校验 | 已验证 |
| SEC-07 | 域名解析和 iptables 规则产物、策略查询/配置 | 规则生成完成，内核强制受环境限制 |
| SBX-01~04 | bwrap 文件、敏感路径、namespace、Capability 裁剪 | 已验证 |
| SBX-05 | cgroup v2 配置入口和 systemd transient 降级 | 部分实现 |
| SBX-06 | bwrap 启动性能已有 worker 数据 | 证据存在，但正式 SRS 状态未同步 |
| SBX-07 | fail-closed 启动 | 已验证 |
| SEC-HOOK | 8 个干预点、handler 顺序、短路、MODIFY、CONFIRM、审计 trace | 已实现并验证 |
| DLP-01~10 | PII 扫描、策略、输入/输出/工具链路、逐字泄露、远端出境提升、WebUI | 已实现并有专项验证 |
| ARCH-01 | D-Bus 控制面 + UDS 数据面、长度帧、peer credential、性能基准 | 已实现并验证 |
| INT-LG | ToolNode、映射、动态 HITL、审计、Token callback、沙箱 | personal-agent 路径已验证；独立 WebUI resume 未交付 |
| INT-PA | bianbu-agent Hook、DLP、HITL、MCP、三种沙箱模式 | 主路径已验证 |
| MGT | D-Bus、Python 客户端、bncli、WebUI、实时信号、Web Terminal | 功能存在；生产暴露边界不合格 |
| D-1~D-7 | 能力字典归一化、MCP fail-closed、风险最高推断、未知工具确认、代码签名、命令级 scope | 已实现并纳入 worker 461 项单测及 12 项集成回归；代码签名安装器与生产 unit 门禁已验证，设备信任根部署仍待验收 |

## 5. 尚待产品化收口或范围外集成的项目

本章同时保留 Security 自身运营缺口和全产品外部接口风险。标有“范围外”的 Runtime
内容仅用于接口移交与整机风险识别，不计入本次交付完成率。

### 5.1 P0：安全边界未闭合

#### 5.1.1 D-Bus 调用者与 Agent 身份绑定

旧版接口曾仅使用调用方提供的 `agent_id`。当前实现已在 V2/服务端增加 caller context，并强制校验：

- D-Bus sender UID/PID；
- Agent 进程可执行文件或安装包；
- cgroup/systemd unit；
- Agent manifest 与实际运行实例。

当前仓库已覆盖 UID/PID/executable/cgroup 绑定、稳定身份不可覆盖、解析失败不空值放行、管理能力更新不覆盖运行绑定，并有伪造身份单测。剩余风险是正式 Runtime/systemd 启动链尚未在目标系统接入，需完成真实 unit/cgroup/四类身份矩阵验收。

**已实现与待验收：**

1. 服务端获取 D-Bus sender unique name 和 Unix credentials；（已实现）
2. 安装/启动阶段建立 `agent_id → uid/pid/cgroup/unit` 绑定；（已实现，可由 Runtime 提供 unit）
3. 每次判权校验 sender 是否属于绑定实体；（已实现）
4. 管理操作只允许专用 admin 组或 polkit；（服务端授权已实现，polkit/桌面集成待验收）
5. 绑定变化、进程重启和 PID 复用均写审计；（已有测试，需正式 Runtime 回归）

**验收标准：**

- 伪造其他 `agent_id` 的判权请求 100% 被拒；
- 非 admin 进程无法为自己写入 `granted=1`；
- PID 复用和进程重启不会继承旧 Agent 身份。

#### 5.1.2 Confirm 响应者绑定

`RespondConfirm(request_id, approved)` 已完成一次性 request 校验、重复/重放拒绝和 V2 session context 传递。当前仍需补：

- 生产桌面 UI 的 UID/seat/session 与 polkit 授权校验；
- 在目标镜像完成真实 UI/Runtime E2E；
- 审计实际响应者与策略版本的发布验收。

#### 5.1.3 WebUI 认证和 Web Terminal 隔离

WebUI 已增加 localhost 默认监听、token/CSRF 防护和 shell 默认关闭，并已在 worker
用专用服务身份、生产 env、Gunicorn 和正式 systemd unit 部署。strict doctor 的
WebUI 认证、session secret、传输、shell、env 权限和 service 身份均已通过；远程 TLS/
反向代理和桌面 seat 仍需在正式产品网络中验收。生产要求至少：

- 默认仅监听 localhost；
- 显式启用时才开放远程访问；
- OIDC/Basic Auth + CSRF + session cookie 安全属性；
- 管理员角色和审计；
- 普通 shell 默认禁用；
- Hermes chat、沙箱 shell、普通 shell 分权限；
- 终端命令和会话全部审计。

**验收标准：** 未认证请求 100% 返回 401/403；普通用户不能获得 PTY；跨站请求不能执行管理操作。

### 5.2 P1：跨模块控制闭环不完整

#### 5.2.1 Token 超限事件通知与 Runtime/agent 消费

职责边界应明确为：

| 组件 | 责任 |
|------|------|
| `bianbu-securityd` | 计量 conversation/day Token；判定超限；写审计；发送 `TokenExceeded`/`SecurityAlert`；在当前请求返回超限结果，阻止本次继续消耗 |
| Agent Runtime / `bianbu-agent` | 订阅或接收超限事件；将 Agent/Run 切换为 PAUSED/TERMINATED；停止后续模型调用和工具调度；向用户显示原因 |

securityd **不直接调用** `io.bianbu.Runtime.Pause`，也不负责停止 Agent 服务。当前仓库已完成通知契约和可嵌入 Runtime guard；剩余工作是接入正式 Runtime 进程并在目标镜像验收，而不是把运行时控制逻辑塞回 securityd：

- 固化 `TokenExceeded` 事件字段：`agent_id`、`session_id`、`run_id`、`scope`、`used`、`limit`、`reason`、`policy_version`；
- 明确事件投递方式（D-Bus 信号为控制面，必要时 UDS/本地回调承载附加上下文）；（已实现）
- Agent Runtime/agent 订阅事件并执行状态切换；（`runtime_token_guard.py` 已实现，正式 Runtime 接入待验收）
- 超限后新增模型调用在 Runtime/agent 侧被拒绝；（已实现并测试）
- securityd 重启、事件重复和消费方暂时不可用时，事件可审计、可查询、可恢复；（重复事件与 guard 重启已测，消费方不可用恢复待正式 Runtime 验收）
- 完成 securityd → Agent Runtime/agent 的跨模块端到端验证；（私有 D-Bus SDK/guard 已测，正式 Runtime 进程仍待验收）

#### 5.2.2 `once_per_session` D-Bus 语义

V2 D-Bus 控制接口已通过 `a{sv} context` 传递 session/run/caller 信息，并验证同 session 不重复确认、跨 session 重新确认。正式 Runtime 仍需统一生成并持续传递以下字段：

```text
session_id, run_id, user_id, caller_uid, source
```

#### 5.2.3 cgroup 强制执行

普通用户模式存在降级，生产应由 runtimed/systemd 统一创建 cgroup。需要验证 MemoryMax、CPUQuota、TasksMax、IOWeight 和 OOM 状态传播。

### 5.3 环境受限或部分实现

#### 5.3.1 网络白名单内核强制

`FR-SEC-07-02` 目前是“受限”，不是完整完成。K3 上已验证 systemd transient unit 的
`IPAddressDeny/Allow` 可阻断非白名单流量，但正式 Agent Runtime unit 尚未接入登记；
`network_policy` 仅生成规则产物时不代表流量被阻断。

需要选择并冻结一种产品方案：

- 正式 Agent Runtime 统一使用 systemd unit 网络属性（当前 K3 已验证），或目标镜像启用 nftables；
- egress proxy；
- eBPF connect hook；
- 网络 namespace + 受控 DNS/代理。

如果当前 K3 硬件无法支持，应将该需求标为“目标平台限制”，不能写进无条件 GA 能力。

#### 5.3.2 软件 Key Vault

当前使用加密文件方案，满足无 TEE 环境的降级基线，但不具备硬件安全世界保护。需要明确产品标签为“软件密钥库”，补充密钥轮换、备份恢复、卸载擦除和 root 威胁模型。

#### 5.3.3 独立 LangGraph WebUI resume

仓库已补齐独立 LangGraph 的跨进程恢复链路：Agent/Runtime 进程注册真实 graph
并启动 0600 Unix broker；`interrupt()` 发布带 `graph_id/run_id/agent_id` 的 pending；
WebUI 通过 `/api/langgraph/interrupts` 轮询、由管理员通过 `/api/langgraph/resume`
提交一次性批准/拒绝；broker 在 graph 所在进程调用 `update_state`。WebUI 不注册、
不持有或伪造 graph。已覆盖错 run/agent、重复/过期、未注册和普通文件覆盖拒绝，以及
跨进程真实 `update_state` 单测。正式 Agent Runtime 仍需在目标镜像注册 broker 并完成
正向、拒绝、重放和跨 agent E2E，故该项是“仓库已实现、生产部署待验收”，不是 GA 自动通过。

### 5.4 供应链和发布能力

代码签名 `securityd/code_signing.py` 的仓库实现已收口：生产 unit 默认
`BIANBU_SECURITY_CODESIGN=enforce`，独立信任根 `/etc/bianbu/codesign-keys` 与运行期密钥
分离，支持吊销清单、全量吊销时 fail-closed、防回滚和安装资产门禁；worker 已验证
`enforce_ready()`、真实安装、成功升级和切换后故障自动回滚。仍缺的不是代码路径，
而是用组织级正式发布 CA 替换 worker 验证根、密钥托管/轮换运营，以及正式 Runtime、
24/72 小时和渗透证据。

### 5.5 评估证据仍需补强

以下内容已有部分记录，但尚未形成正式发布证据：

- 24/72 小时稳定性测试（当前仅完成 10 秒门禁，统一入口已纳入稳定性脚本）；
- service 重启、D-Bus 断线、UDS 重连、SQLite WAL/磁盘满/只读已有自动化证据；仍需生产告警与恢复时间报告；
- WebUI 认证、角色、CSRF、Gunicorn WebSocket 和 UDS 重启隔离已通过；仍需正式并发压测与桌面 seat；
- DLP 混淆输入、Unicode、Base64、跨 chunk 流式检测；
- hermetic venv、安装 smoke、成功升级和切换后故障回滚已通过；仍需正式跨版本/tag 的流水线归档；
- 24/72 小时稳定性和外部渗透测试；依赖 CVE、SBOM、许可证检查已在仓库级门禁完成；
- 外部安全渗透测试。

### 5.6 Worker 实机执行证据（最新 2026-08-14；历史基线 final38/final-current6/final-current9）

#### 5.6.1 2026-08-14 当前部署回归（本轮权威增量证据）

本轮将当前工作树精确同步到 worker 的真实部署目录
`/home/bianbu/impl/bianbu-securityd`、`/home/bianbu/bnsec-testkit` 和
`/home/bianbu/bianbu-agent`，逐文件 SHA-256 一致后按
`securityd → personal-agent` 顺序重启。该证据验证当前集成部署，不替代下文
独立发布目录的安装包、SBOM、性能和迁移证据。

| 验证项 | 命令/范围 | 结果 | 说明 |
|------|-----------|------|------|
| securityd 默认全量 | `python3 -m pytest tests/ -q` | 通过 | `548 passed / 3 skipped`；3 个 skip 仅为默认模式外部 E2E |
| securityd strict | `verify_all.sh --strict` | 仓库项通过、外部门禁预期阻断 | `534 passed` unit、`14 passed` integration、`3 passed` E2E，`skipped=0`；最终仅 `doctor,runtime_production` 阻断 |
| Runtime 边界专项 | `pytest test_security_runtime_boundary.py test_failure_recovery.py test_runtime_production_probe.py -q` | 通过 | `19 passed`；禁止 Securityd 调用 Runtime Pause/Stop/Terminate，并覆盖 systemd 259/用户名及 root UID 探针兼容 |
| 安全 E2E | `cd /home/bianbu/bnsec-testkit && python3 runner.py` | 通过 | `35/35`，0 failed、0 error；新增 `DLP-04` 验证 PA 大载荷正式 UDS、中央策略和完整审计 |
| PA 定向回归 | `uv run pytest -q tests/runtime/test_security_uds_transport.py tests/runtime/test_service.py` | 通过 | UDS + Runtime 定向共 `10 passed` |
| PA 全量回归 | `uv run pytest -q` | 基线一致 | `848 passed, 73 failed`；比原基线新增 3 个通过，失败仍为 Playwright 动态库、worker 多进程条件、部署目录无 Git 元数据等既有环境项 |
| caller 身份 | PA 重启 + capability DB 检查 | 通过 | `com.bianbu.agent` 绑定为 PA venv 绝对 argv[0]；易变 SSH session cgroup 被规范化为稳定 user slice |
| 未绑定调用 | 启动脚本探针 + `CONN-02` | 通过 | 未绑定 Agent 继续 `PermissionDenied`，testkit 改用独立 `com.bianbu.agent.testkit` 身份，不冒充 PA |
| 管理只读授权 | E2E + 单测 | 通过 | 管理员可读取 Agent capability/token/network 信息；业务判权仍要求绑定 Agent |
| Token 输入收紧 | unit/integration/E2E | 通过 | 负 token、负预算、非法 scope/on_exceed、空 V2 session/run、伪造未超限事件均 fail-closed |
| Security-only Token 超限 | worker 系统总线：`BindAgentV2 → SetTokenBudget → MeterTokensV2` | 通过 | Runtime unit 不存在且 `io.bianbu.Runtime` 未注册时，返回 `within=false/remaining=0` 并收到字段完整的 `TokenExceededV2`；`SECURITY_TOKEN_NOTIFY_ONLY_PASS` |
| Runtime 生产探针 | `python3 deploy/runtime_production_probe.py --json` | 正确阻断 | rc=2；正式 unit inactive、`io.bianbu.Runtime` 未注册，继续保持 `RUNTIME_PRODUCTION_BLOCKED` |

本轮还修复了一个仅在真实部署重启链路暴露的问题：旧绑定使用
`/proc/<pid>/exe + session-N.scope`，Python/SSH session 变化后会把合法 PA 误判为其他
caller。现在优先记录绝对 argv[0] 以保留 PA venv 身份，cgroup 去除易变 login session
编号；旧系统 Python 路径只允许向指向同一解释器的绝对 venv 路径单向迁移。若解释器
版本确实变化，则仅 `bianbu-admin`/root 可以显式重绑，并写管理审计；普通 Runtime
仍不能覆盖其他 Agent 绑定。

#### 5.6.2 strict 商用发布门禁审计（本轮新增）

本轮新增正式入口 `deploy/verify_all.sh`；`tests/testkit_verify_all.sh` 仅保留为兼容
包装器。完整脚本进入 `pyproject.toml` wheel data-files 和安装 staging，安装资产校验
不再错误依赖未随安装包复制的 `tests/` 路径。strict 模式采用“全部执行、累计失败、
末尾统一阻断”，避免 doctor 首项失败后掩盖外部 E2E、供应链和正式 Runtime 缺口。

worker `10.0.90.243` 实测结果如下：

| 验证项 | 命令/范围 | 结果 | 说明 |
|------|-----------|------|------|
| 安装/doctor 专项 | `pytest test_failure_recovery.py test_install_flow.py` | 通过 | 覆盖 hardened WebUI、Gunicorn 生产启动器、占位凭据/复用 secret 拒绝、polkit action 和 strict 脚本资产 |
| strict unit | hermetic venv `pytest tests/unit -q` | 通过 | `534 passed`；LangGraph 依赖已进入冻结环境，不再借用用户 site-packages |
| strict integration/E2E | `verify_all.sh --strict` | 通过 | `14 passed` integration、`3 passed` E2E，`STRICT_E2E_PASS skipped=0` |
| strict 统一入口（hermetic venv） | `PYTHON=/var/tmp/bnsec-release-venv-hermetic.WuUZU2/bin/python CVE_SCANNER=.../bin/pip-audit STABILITY_SECONDS=1 PERF_SAMPLES=10 bash deploy/verify_all.sh --strict` | 正确阻断 | unit/integration/E2E/Smoke/DLP/UDS/性能/短稳/SBOM/CVE 全绿；最终仅 `BNSEC_VERIFY_ALL_STRICT_FAIL gates=doctor,runtime_production` |
| wheel 发布资产 | `python3 -m pip wheel . --no-deps` + ZIP 内容校验 | 通过 | `WHEEL_VERIFY_ALL_PASS`；`share/bianbu-securityd/deploy/verify_all.sh` 已进入 wheel |

strict doctor 已明确识别以下生产缺口：

| 门禁 | worker 实况 | 关闭动作 |
|------|-------------|----------|
| 网络强制 | `artifact_only` | 由正式 Runtime/systemd unit 下发并复核网络属性 |
| Runtime 身份矩阵 | 正式 unit/UID/cgroup 缺失 | 安装正式 `bianbu-agent-runtimed.service`，验证四类身份和专属 cgroup |
| 签名信任根 | worker 验证根与 `enforce` 已通过 | 换用组织级正式发布 CA/密钥托管，并完成轮换/吊销运营演练 |
| WebUI 与 Security | **worker 已关闭** | 专用身份、生产 env、Gunicorn、polkit、UDS `0660:bianbu-security`、401/200/403 均有实测；仅桌面 seat 交互另行验收 |
| 外部 E2E | **仓库 strict 已关闭 skip** | 3 条 E2E 在独立 D-Bus 与隔离数据根真实执行；正式 Runtime 自身的产品 E2E仍由 Runtime 责任方提供 |
| 严格供应链 | **仓库级已关闭**：冻结发布 venv 按 lockfile 通过 SBOM、CVE=0 和 release gate | 发布时固化同等 venv/镜像及原始报告；不得退回漂移的系统解释器 |
| 正式 Runtime | unit inactive，`io.bianbu.Runtime` 未注册 | 由 Runtime 仓/系统镜像交付正式服务并通过生产探针 |

同时确认 worker 已具备 `pkcheck`、cgroup v2，WebUI 默认回环监听且普通 shell 关闭，
D-Bus/安装发布资产、仓库 unit/integration、Smoke、性能和短时稳定性均通过。因此本轮
strict 失败只反映正式 Runtime 身份与网络强制两个外部阻断，不是仓库脚本错误，也不能通过降低门禁变绿。

#### 5.6.3 P1-05 故障恢复与正式 UDS 数据面（本轮新增）

本轮将原先独立存在的 UDS server/client 接入正式 `securityd.service` 生命周期，注册
`ping`、`dlp.scan`、`audit.batch` 三个产品 handler，并让 D-Bus 与 UDS 共用基于
`/proc` 和内核 peer credential 的 caller 身份解析。请求体中的 `agent_id` 仅用于声明
目标身份，不能替代 `SO_PEERCRED`；缺少可信 peer PID/UID 时，Agent 数据面 fail-closed。
服务启动时先建立 UDS 再占用 D-Bus 名，退出时停止接收新连接、关闭活跃连接、等待线程
退出并移除 socket，已通过 testkit `--restart` 验证删除和重建行为。

审计恢复链路增加 SQLite `quick_check`、启动时全链哈希验证、持久
`audit_request` 去重索引、写失败 rollback、并发数据库锁和优雅排空。相同 request id
且相同载荷在断线重试或 securityd 重启后返回原 audit seq；相同 id 但载荷不同会拒绝。
数据库损坏、哈希链篡改或 request 索引被篡改均以 `AuditFailure` fail-closed。UDS 服务端
同时防止第二实例 unlink 活跃 socket，并以“peer UID + request id + 请求指纹”保证并发
重复请求只执行一次；超过响应缓存上限时保留已执行墓碑，避免大响应重放产生重复副作用。

worker `10.0.90.243` 当前部署实测如下：

| 验证项 | 结果 | 证据/结论 |
|------|------|-----------|
| UDS/DLP/install/failure 专项 | `52 passed` | 覆盖协议、中央策略、Agent-aware 选路、安装资产和真实 SQLite 故障恢复 |
| audit/Confirm/failure 专项 | `26 passed` | 覆盖 SQLITE_FULL、运行中只读、启动只读、未决 Confirm 关闭唤醒与重启旧请求拒绝 |
| securityd strict | `534 unit + 14 integration + 3 E2E passed` | strict E2E 使用独立 D-Bus/隔离数据根，`skipped=0` |
| 安全 E2E | `35/35 passed` | 在最新 securityd 重启后运行真实 PA + 真实 securityd；`DLP-04` 验证正式 UDS 产品选路 |
| 正式 UDS socket | 通过 | 生产路径 `/run/bianbu/securityd.sock`，`0660:bianbu-security`；Security 重启重建、WebUI 重启保持均通过 |
| `dlp.scan` | 通过 | `手机号 13812345678` 返回 `手机号 [PII-手机号-001]`；finding 不回传原始 PII value |
| `audit.batch` 跨重启复放 | 通过 | 首次与重启后复放均返回 `audit_seq=7647`；审计记录和 request 索引各仅 1 行 |
| UDS 性能/稳定性 | 通过 | 空载 P99 `0.277 ms`、4KB P99 `0.463 ms`、1MB P99 `43.419 ms`、吞吐 `23.0 MB/s`、2000 次长连接零错误 |
| strict 统一入口（hermetic venv） | 正确阻断外部项 | unit/integration/E2E/Smoke/性能/短稳/SBOM/CVE=0/release 全通过；输出 `BNSEC_VERIFY_ALL_STRICT_FAIL gates=doctor,runtime_production` |
| wheel 正式 UDS 资产 | 通过 | `WHEEL_PRODUCTION_UDS_PASS files=4`，包含 server、handler、client 及 service 生命周期实现 |

P1-05 的**仓库级故障恢复实现可以关闭**：磁盘满、运行中只读、启动只读、连接
rollback 后恢复写入、哈希链完整、未决 Confirm 在关闭时拒绝并唤醒、旧 request id
重启后不可复用，均已有自动化断言和 worker 证据。Security 生产 unit/UDS 已关闭；
正式 Runtime 跨 UID 与生产运营项仍不能关闭，尚需：

1. 在只读根文件系统、真实磁盘配额/独立分区和 systemd restart policy 下重复同等演练；
2. 由正式 Runtime 的不同 UID 和 `SupplementaryGroups=bianbu-security` 对现有生产 UDS 做正反向调用；
3. 保存生产故障告警、恢复时间和数据完整性原始日志，作为 TR6/ADCP 关闭证据。

PA 大载荷产品链路已完成：大于 4KB 的 DLP 文本默认经 `dlp.scan`，大于 1KB 的完整
治理载荷默认经 `audit.batch`，小载荷使用 `dlp.policy` 中央策略；中央策略不可达且无
缓存时 fail-closed BLOCK。该链路已由 `DLP-04` 在 worker 验证，不再属于 P1-05 代码缺口。

冻结发布环境 `/var/tmp/bnsec-release-venv-hermetic.WuUZU2` 已关闭仓库级供应链与性能门禁。
由于该 venv 位于 `/var/tmp`，其解释器路径在 bwrap 沙箱内不可见；性能基准现默认使用
目标系统 `/usr/bin/python3` 同时测量裸启动和沙箱启动，并允许通过
`BIANBU_PERF_SANDBOX_PYTHON` 显式覆盖。回归测试验证默认值与覆盖值，worker strict
实测 sandbox P99 **43.586 ms**、相对裸启动开销 P99 **7.859 ms**，输出 `PERF_PASS`；
同一轮输出 `SBOM_PASS`、`CVE_SCAN_PASS vulnerabilities=0`、`RELEASE_GATE_PASS`。

#### 5.6.4 生产安装、Gunicorn 与切换后回滚实测（本轮新增）

在 worker `10.0.90.243` 上以真实 systemd 形态安装，不启用仓库内参考 Runtime。冻结
环境使用 `/var/tmp/bnsec-release-venv-hermetic.WuUZU2`，并在
`PYTHONNOUSERSITE=1` 下验证所有运行依赖均来自 venv/系统受控路径；旧
`/var/tmp/bnsec-release-venv-20260814` 曾从 `~/.local` 借用 Flask/LangGraph，不能再作为
商用 hermetic 证据。

| 验证项 | 结果 | 证据/结论 |
|------|------|-----------|
| 生产身份 | 通过 | `bianbu-securityd.service` 与 `bianbu-security-webui.service` 均为 `User/Group=bianbu-security`；代码使用 `/usr/lib/bianbu-securityd/venv/bin/python` |
| 生产 WebUI server | 通过 | systemd `ExecStart=-m webui.production`；Gunicorn master/worker 可见，单 worker + gthread 32 线程，日志无 Werkzeug development server 警告 |
| WebUI 权限 | 通过 | 未认证 API=401、管理员读取=200、viewer 修改=403；生产 token/secret 不写入仓库或报告 |
| WebUI WebSocket | 通过 | Gunicorn + simple-websocket 完成真实 Engine.IO WebSocket upgrade/open 握手 |
| 正式 UDS | 通过 | `/run/bianbu/securityd.sock` 为 socket，权限 `0660`、group=`bianbu-security`；重启 WebUI 前后 inode 不变 |
| 代码签名跨命名空间 | 通过 | `VerifyCodeDigest` 由调用方读取临时包并计算规范摘要，securityd 只验证摘要/签名与信任根；`/tmp` 内签名 Hook 在 `PrivateTmp/ProtectHome` 生产 unit 下验证通过，key id 可追溯 |
| 安装预检 | 通过 | `SBOM_PASS`、`RUNTIME_VENV_PASS`、`INSTALL_ASSETS_PASS`、`CODESIGN_TRUST_ROOT_PASS`、D-Bus/HTTP 健康检查全通过 |
| D-Bus 契约 | 通过 | `DBUS_CONTRACT_PASS methods=28 policy=identical`；XML、service、client 和 data/deploy policy 一致 |
| strict 仓库门禁 | 条件通过 | `534 unit + 14 integration + 3 E2E` 全通过，E2E `skipped=0`；性能、短稳、SBOM、CVE=0、release gate 全绿；仅 `doctor,runtime_production` 因范围外 Runtime/网络集成缺失而阻断 |
| testkit | 通过 | 生产 Security/UDS/WebUI 形态下 `35/35`，0 failed、0 error |
| PA 全量回归 | 基线一致 | 关闭安全与启用安全均为 `848 passed / 73 failed`，失败集合 `novel=0`、`baseline_only=0`；SDK 单测已与宿主机生产签名策略隔离 |
| 成功升级 | 通过 | WebUI 升级前停止，SQLite `1->1 (noop)`，代码/venv/unit 原子切换后 Security、UDS、WebUI 健康检查通过 |
| 切换前错误 | 通过 | 注入错误 unit 后由 `verify_install_assets.py` 在切换前拒绝，线上代码、unit、能力库、Token 库哈希均不变 |
| 切换后故障回滚 | 通过 | 注入仅在 WebUI 启动时报错的候选版本；安装器在 HTTP 健康检查失败后自动恢复上一版代码和 unit，能力库/Token 库逻辑哈希一致，Security/WebUI 恢复 active，401/200 鉴权恢复 |

故障版本保留在 `/usr/lib/bianbu-securityd.failed.2980459.13926`，原始故障注入目录为
`/var/tmp/bnsec-postswitch-fault.NCYyix`，用于本轮审计复核。它们不是发布物，后续清理前
应先归档安装日志。数据库迁移已改为目标 schema 相同则真正 no-op，避免重复安装仅刷新
`migrated_at` 而制造无业务意义的数据库漂移。

该证据可关闭“Security/WebUI 是否能在 worker 生产形态安装、升级和自动回滚”的技术
问题，但不能替代正式 Runtime 发布、组织级签名 CA、24/72 小时耐久和第三方渗透报告。

#### 5.6.5 历史发布与性能基线

代码签名、安装器与 WebUI 安全收口后的独立目录为 `/home/bianbu/bnsec-final-current9`，未修改既有生产部署。
`tests/unit` 为 **462 passed**、`tests/integration` 为 **12 passed**，安装器专项包含在单测中；D-Bus/安装资产/Smoke 通过，性能门禁判权 P99 **3.149 ms**、bwrap P99
**46.787 ms**（相对裸启动开销 P99 **11.084 ms**），10 秒稳定性为 **19232 ops** 且审计链完整。UDS 4KB P99 **0.359 ms**、连续吞吐 **29.4 MB/s**、2000 次长连接零错误。wheel 为 **218324 字节**。隔离发布 venv `/tmp/bnsec-release-venv19` 中严格 SBOM/CVE 门禁均通过：`SBOM_PASS`、`CVE_SCAN_PASS vulnerabilities=0`、`RELEASE_GATE_PASS`；系统解释器旧 `cryptography==46.0.5` 仅保留为非严格门禁警告，不计作发布环境。生产
Runtime 探针返回 rc=2，因 worker 未安装/注册正式 Runtime，保持 fail-closed。

本次在同一隔离目录完成增量复验：`INSTALL_ASSETS_PASS`、`DBUS_CONTRACT_PASS methods=27 policy=identical`、
`tests/unit` **462 passed**、`tests/integration` **12 passed**、WebUI 授权专项 **4 passed**；外部 E2E **3 skipped**。
`tests/smoke_test.sh` 全链路通过。worker 已安装 `pkcheck`，polkit policy XML 可解析；但 `bianbu-securityd.service`
尚未安装，桌面 seat/polkit 真实授权日志仍需目标镜像验收。`runtime_production_probe.py` 明确返回
`RUNTIME_PRODUCTION_BLOCKED`：`bianbu-agent-runtimed.service` inactive 且 `io.bianbu.Runtime` 未注册。

以下为 LangGraph broker 阶段的**历史证据**。独立目录为 `/home/bianbu/bnsec-final-current6`，未修改既有生产部署。
该目录包含本评审新增的跨进程 Unix broker、WebUI resume API/UI、pending 生命周期绑定、可选 broker token 和负向测试。
当时复验结果：**453 单测、12 集成、3 项外部 E2E 跳过、D-Bus/安装资产/Smoke 通过、10 秒稳定性
20095 ops、SBOM_PASS、pip-audit 0**；wheel 为 `217417` 字节。统一 `testkit_verify_all.sh` 输出
`BNSEC_VERIFY_ALL_PASS repo_gates=passed external_runtime_gate=pending_or_pass`。生产 Runtime 探针仍因
worker 未安装/注册 `bianbu-agent-runtimed.service` 和 `io.bianbu.Runtime` 而正确阻断。

以下保留 final38/final-current6/final-current7/final-current8 的历史基线作为可追溯记录；WebUI 安全收口后的最终交付口径以上述 final-current9 复验为准。

本轮将当前提交同步至 K3 worker `10.0.90.243` 的独立目录
`/home/bianbu/bnsec-delivery-final38`，未修改既有部署。环境为 `riscv64`、Linux
`6.18.3-generic`、Python `3.14.4`、bubblewrap `0.11.1`。

| 验证项 | 命令/范围 | 结果 | 说明 |
|------|-----------|------|------|
| D-Bus 契约校验 | `python3 tests/verify_dbus_contract.py` | 通过 | `DBUS_CONTRACT_PASS methods=27 policy=identical` |
| 单元测试 | `python3 -m pytest tests/unit -q` | 通过 | `453 passed`（LangGraph broker/token/API 负向用例已计入） |
| 集成测试 | `python3 -m pytest tests/integration -q` | 通过 | `12 passed in 3.52s`，含 Token Runtime 与 Runtime systemd 门禁 |
| E2E 测试 | `python3 -m pytest tests/e2e -q` | 条件通过 | `3 skipped`，测试明确要求真实外部服务 |
| Smoke 全链路 | `bash tests/smoke_test.sh` | 通过 | bwrap、D-Bus、Confirm、Hermes Plugin 全部通过 |
| 发布资产校验 | `python3 deploy/verify_install_assets.py` | 通过 | XML/policy/unit/install/rollback/lockfile/SBOM/Runtime probe 齐全且可解析 |
| SBOM 生成 | 隔离 venv `generate_sbom.py --strict` | 通过 | `SBOM_PASS`，`cryptography==50.0.0` 与 lockfile 一致；系统 Python 旧版本会 fail-closed |
| wheel 构建 | `python3 -m pip wheel . --no-deps` | 通过 | `bianbu_securityd-1.0.0-py3-none-any.whl`，217417 字节；含 Runtime service、XML/policy、WebUI/LangGraph broker 代码、生产探针等资产 |
| 数据库迁移/回滚门禁 | `migrate_db.py`、installer dry-run、rollback dry-run | 通过 | 事务迁移幂等、未来 schema 拒绝；无 previous 版本时 rollback 正确拒绝且不改动 |
| 发布清单 | `generate_release_manifest.py` | 通过 | 189 个文件生成并复核 SHA-256 清单 |
| 稳定性烟测 | `stability_smoke.py --seconds 10` | 通过 | 19104 次判权/审计，链完整；不替代 24/72 小时测试 |
| CVE 扫描 | 隔离发布 venv `pip-audit` | 通过 | lockfile 依赖漏洞数 `0`；当前系统 Python 仍未安装扫描器，按 fail-closed 处理 |
| 网络隔离探针 | systemd transient unit + `IPAddressDeny/Allow` | 通过 | 白名单 `archive.bianbu.xyz` 成功；非白名单 `example.com` 超时阻断；`systemctl show` 确认属性 |
| Runtime 生产探针 | `python3 deploy/runtime_production_probe.py --json` | 正确阻断 | `RUNTIME_PRODUCTION_BLOCKED`；worker 未启用 `bianbu-agent-runtimed.service`，`io.bianbu.Runtime` 未注册 |
| 严格发布门禁（隔离发布 venv） | `deploy/release_gate.py --strict --scanner <pip-audit>` | 通过 | `SBOM_PASS`、CVE `0`；系统 Python 的版本不匹配仍正确 fail-closed |
| 统一验证入口 | `bash tests/testkit_verify_all.sh` | 通过（外部门禁待部署） | `BNSEC_VERIFY_ALL_PASS repo_gates=passed external_runtime_gate=pending_or_pass` |

新增集成证据 `tests/integration/token_runtime_e2e.py` 在私有真实 D-Bus 上验证
`MeterTokensV2 → TokenExceededV2 → Runtime consumer PAUSED → model/tool 调用拒绝`，并覆盖重复
事件幂等、Runtime guard 重启恢复和 V2 session trust（同 session 放行、跨 session 重新确认）。
这证明 SDK/消费组件契约闭环；正式 `bianbu-agent-runtimed` 进程接入仍需在其仓库或系统镜像执行同等验收。

worker 上的 systemd 网络探针证明 K3 支持按 unit 的白名单和阻断，但正式 Agent Runtime
unit 尚未创建并登记，`network_policy.enforcement_status()` 仍不能作为生产网络强制证据。
cgroup 控制器存在；普通 `bianbu` 用户不能在用户 slice 外创建专属 cgroup，但 Runtime
systemd transient unit 已在 worker 真实验证 MemoryMax/CPUQuota/TasksMax/IOWeight、
进程 ControlGroup 归属及 MemoryMax OOM-kill 传播。正式生产应继续由 runtimed 创建 unit；
P1-01/P1-02 的仓库级验证已完成，生产镜像身份矩阵仍需验收。

#### 5.6.6 Security 责任域证据门禁与耐久执行器（V1.7 当前权威证据）

本轮新增 `.ci/run_tests.sh` 和 `deploy/security_release_gate.py`，完整执行
`verify_all.sh --strict`，但以独立字段判定 Security 责任域。工具不会降低全产品 strict；
只在所有 Security 自有 marker、doctor、供应链和测试均通过时，允许把范围外
`doctor,runtime_production` 记录为外部集成状态。

| 项 | worker 结果 | 判定 |
|----|-------------|------|
| 默认全量 | `548 passed / 3 skipped` | 通过 |
| strict | `534 unit + 14 integration + 3 E2E`，`skipped=0` | Security 仓库项通过 |
| Security 证据包 | `/var/tmp/bnsec-security-release-13c4206` | `SECURITY_RELEASE_GATE_PASS`、`security_scope_status=passed` |
| 全产品集成字段 | `product_status=blocked_external` | 仅表示范围外 Runtime 缺失，不计入本次完成度 |
| 生产耐久预演 | 6 秒、120 次、error=0、P99=6.981ms、RSS +1.805MB | 通过；运行中 `pending_checks` 正确 |

证据包包含 unit/integration/E2E JUnit、doctor JSON、SBOM、CVE、源码 manifest、strict
原始日志和所有产物 SHA-256。新增的 24/72 小时执行器持续验证真实 D-Bus、生产 UDS、
WebUI health、SSE、两项 systemd 服务、RSS、判权 P99 和审计链；`setsid` 启动器可脱离
SSH 持续运行。运行初期尚未达到样本门限时，样本不足及暂态 P99 与审计检查点进入
`pending_checks`；达到最小样本数后仍超标的 P99 才进入 `failures`。正式 24/72 小时
报告仍待最终提交后长跑生成。

#### 5.6.7 签名式最终商用验收门禁（V1.8 新增）

仓库新增 `deploy/commercial_acceptance_gate.py`，用于在 72 小时任务完成后对组织级
证据做最后一次 fail-closed 验收。该工具不生成或模拟外部证据，而是要求：

| 证据域 | 强制校验 |
|--------|----------|
| Security 发布包 | `security_scope_status=passed`、commit 一致、工作树非 dirty |
| 72 小时耐久 | 24h/72h 里程碑、0 error、无 pending/failure、P99≤10ms、RSS≤64MB、审计/SSE/systemd 稳定 |
| 组织 CA | production、根指纹、安装/轮换/吊销/恢复全部通过、附件哈希一致 |
| 桌面授权 | 真实 seat/session，allow/deny/expired/replay 全部通过、日志哈希一致 |
| 第三方渗透 | 覆盖 securityd/WebUI/D-Bus/UDS，严重和高危为 0，未接受遗留为 0 |
| 发布审批 | commit/tag/变更单一致、至少两名不同审批人、所有证据 SHA-256 一致 |
| 组织签名 | approval JSON 的 Ed25519 分离签名由受信且未吊销的审批公钥验证 |

最终报告同时绑定 `report.samples.jsonl` 的大小和 SHA-256；验收门禁逐行检查 iteration
连续、`ok=true`、行数等于 iterations/latency_samples。Security release summary 所列
8 类原始产物也会重新验大小/哈希；24h/72h 两份 milestone JSON 也必须实际存在、
内容状态为 milestone 且审计链通过。通过后，技术原始证据、samples、milestone、外部
附件、审批原文/签名及实际验签公钥全部复制到同一归档目录。

工具和四份示例 JSON 已进入 wheel/安装资产，专项 `6 passed`，覆盖完整签收、短耐久、
高危渗透问题、单人审批、篡改签名和吊销审批密钥。正式证据未提供时输出
`COMMERCIAL_ACCEPTANCE_FAIL`，因此该新增能力不会把内部测试伪装为正式商用批准。

## 6. 优化建议

### 6.1 架构优化

| 优化项 | 现状问题 | 建议 |
|--------|----------|------|
| 身份模型 | 旧接口允许调用方传入 agent_id | V2/服务端使用可信 caller context；正式 Runtime 启动链仍需接入验收 |
| D-Bus API | 旧接口 session、run、caller 信息不足 | V2 方法统一接收 `a{sv} context`，保持旧接口兼容；已实现 |
| 管理面 | WebUI、CLI、D-Bus 权限边界分散 | 引入统一 Policy/Authorizer，管理操作全部经同一授权路径 |
| 网络控制 | 依赖 iptables，K3 上不可用 | 抽象 `EgressEnforcer`，提供 nftables/eBPF/proxy 后端和能力探测 |
| 资源控制 | sandbox 自己尝试创建 cgroup | 将 cgroup 所有权收敛到 runtimed/systemd，securityd 只负责策略和审计 |
| Hook 错误策略 | 统一异常放行会削弱高风险控制 | L1/L2 可降级，L3/L4 fail-closed；所有降级发 SecurityAlert |
| 审计 | 本地 SQLite 哈希链可被整体删除 | 增加远端锚定、轮换归档和可信时间源 |

### 6.2 工程质量优化

1. 使用包发现机制替代 `pyproject.toml` 的手工 `packages` 列表，确保 `securityd.dlp`、`securityd.langgraph`、WebUI 静态文件和 D-Bus 资产进入安装包。
2. 增加 lockfile、最小 venv 创建脚本和 CI，保证开发机可复现运行 pytest。
3. 统一测试基线：单元、集成、E2E、worker、外部 personal-agent 回归分别计数，禁止在摘要中混用。
4. 将 worker 验证脚本纳入仓库，保存平台、内核、Python、依赖和时间戳。
5. 增加 `make verify` 或单一 `testkit/scripts/verify-all.sh` 入口，输出 JUnit/JSON 报告。
6. 对所有 D-Bus 方法自动比对 Python service、introspection XML、client SDK 和文档签名。
7. 增加数据库 schema version、迁移脚本和回滚检查。

### 6.3 安全运营优化

- 增加安全事件等级、告警去重、速率限制和管理员确认；
- 审计中记录 caller UID、session_id、run_id、policy version、decision source；
- WebUI 管理变更必须记录 old/new 值和操作人；
- 增加默认安全模板，禁止首次部署出现“能力全撤销后无提示”的不可用状态；
- 提供 `doctor` 检查 D-Bus policy、bwrap、seccomp、cgroup、网络后端、代码签名、公钥、WebUI 认证和磁盘空间；
- 安全公告和 CVE 处理纳入版本发布流程。

## 7. IPD 收口计划

### 7.1 P0：发布阻断项

| 编号 | 工作项 | 完成条件 | 建议责任域 |
|------|--------|----------|------------|
| P0-01 | 正式 24/72 小时耐久 | 24h/72h 报告生成，最终 `status=passed`、`failures=[]` | Security/QA |
| P0-02 | 最终提交证据包 | **已关闭**：实现基线 `f956d809…` 的 JUnit、doctor、SBOM、CVE、manifest、原始日志和 SHA-256 已在 clean1 目录归档 | Security/Release |
| P0-03 | 正式版本与审批 | tag、变更单、证据包、耐久报告和审批记录指向同一基线 | Release/QA |
| P0-04 | D-Bus policy 与发布资产 | **已关闭**：`methods=28 policy=identical`，安装/升级/回滚和 wheel 资产均通过 | Security/Release |
| P0-05 | Token 超限 Security 职责 | **已关闭**：V2 context、输入 fail-closed、通知、审计和当前计量拒绝已在无 Runtime 的 worker 验证；Securityd 不暂停或停止 Runtime | Security |
| P0-06 | WebUI/UDS 生产部署 | **已关闭**：认证、CSRF、角色、Gunicorn、专用身份、生产 UDS、401/200/403 和故障回滚均通过 | Security/Frontend |

### 7.2 P1：能力完整性

| 编号 | 工作项 | 完成条件 |
|------|--------|----------|
| P1-01 | 组织级签名 CA | 正式 CA、密钥托管、轮换、吊销和灾备恢复记录齐全 |
| P1-02 | 桌面 seat/polkit | 真实桌面会话完成允许、拒绝、过期和重放验证 |
| P1-03 | session trust V2 | `*V2` 接口传递 context；同 session 第二次不确认，跨 session 必须重新确认 |
| P1-04 | 代码签名供应链 | 仓库侧 enforce、吊销、防回滚和验证根闭环已完成；组织级运营见 P1-01 |
| P1-05 | 故障恢复 | **仓库级已关闭**：D-Bus/UDS/SQLite/service restart、SQLITE_FULL/只读、审计和 Confirm 重启均通过 |
| P1-06 | 安全测试 | 性能/DLP/短稳已通过；第三方渗透须严重/高危为 0，其他项关闭或正式接受 |

### 7.3 P2：体验和长期维护

- 独立 LangGraph WebUI resume 的调用方生产接入（范围外移交，不计入本次完成度）；
- Provider host 白名单和远端数据出境策略统一；
- Skill instructions 纳入 DLP 的正式主链路；
- 多 Agent 租户隔离；
- 审计检索、指标和长期归档；
- 策略模板、doctor 和桌面 polkit 集成。

### 7.4 剩余工作实施方案

剩余工作按“先冻结基线、再关闭发布阻断、再补齐强制能力、最后做发布验证”的顺序执行。不得在 P0 安全边界未闭合前继续扩展 P2 功能。

#### 7.4.0 2026-08-14 当前执行结论与下一步

仓库内还能完成的代码项已经基本收口：默认全量、strict 仓库测试和 testkit `35/35`
已有 worker 证据；PA 正式 UDS、中央 DLP 策略、完整审计、
SQLITE_FULL/只读恢复、Confirm 重启、生产 Gunicorn、成功升级和切换后故障回滚均有
worker 证据。当前本次交付内的剩余工作已从“继续补 Security 功能”转为“冻结范围、
归档证据、补齐组织级发布凭据和长期验证”。正式 Runtime 是范围外接口接收方，不是
本次 Security 交付的前置条件，也不纳入本次开发和提交。执行顺序如下：

| 顺序 | 剩余工作 | 当前状态 | 下一动作 | 完成证据 |
|------|----------|----------|----------|----------|
| 1 | Security 交付范围冻结 | **已完成**：范围外 Runtime 仓和候选测试成绩已排除 | 文档、提交和 worker 部署均只保留 Securityd/PA/testkit 范围；已增加“不控制 Runtime”回归断言 | 主仓 diff 无范围外文件；worker 无候选 Runtime unit；专项 `19 passed` |
| 2 | Token P0-05 Security 侧关闭 | **已完成**：无 Runtime 时真实超限通知通过 | 归档 `SECURITY_TOKEN_NOTIFY_ONLY_PASS`、事件字段和审计；保持生产探针 fail-closed | `within=false`、字段完整 `TokenExceededV2`、securityd active、Runtime unit not found |
| 3 | Runtime 生产身份、暂停和系统总线 | **范围外移交，不计入本次剩余工作** | 由 Runtime 责任方依据验收清单实现；Security 项目不修改、不安装范围外候选仓 | 外部自行提供正式发布物和真实暂停/恢复日志 |
| 4 | Security/WebUI 生产安装 | **已完成**：专用身份、Gunicorn、polkit、生产 env、验证信任根、正式 UDS、鉴权、成功升级和切换后自动回滚均通过 | 归档本轮日志；正式发版时替换为组织级 CA，并复跑同一安装/回滚脚本 | 当前 worker doctor 中 WebUI/Security/polkit/trust root/UDS 均绿；故障回滚哈希与健康检查通过 |
| 5 | 冻结发布环境 | **仓库级已完成**：真正 hermetic 的 `/var/tmp/bnsec-release-venv-hermetic.WuUZU2` 在禁用 user site 下通过 unit、SBOM、CVE=0、release 和性能门禁 | 将锁定依赖、扫描器版本、wheel manifest 与原始报告纳入正式发布流水线/镜像；旧非 hermetic venv 不得复用 | 正式 CI/镜像可复现相同 `SBOM_PASS`、`CVE_SCAN_PASS vulnerabilities=0`、`RELEASE_GATE_PASS`、`PERF_PASS` |
| 6 | Security 24/72 小时与外部安全评估 | 执行器、v4 短周期预演和最终提交证据已通过 | 清理范围外重启风暴后用 `f956d809…` 启动 72h；归档 24h/72h 报告并完成第三方渗透 | `status=passed`、`failures=[]`、严重/高危渗透问题为 0 |

关键判定：Runtime 生产身份、真实暂停和产品 E2E 不能通过技术手段在 Security 仓内
“补出来”，也不能用范围外候选仓刷绿。strict 对 `doctor,runtime_production` 保持红色
是正确的全产品集成诊断；它不阻断 Security 责任域签收。本次交付只对 Security 范围内
的代码、测试和证据负责。

#### 阶段 0：基线冻结与任务拆分（1–2 个工作日）

| 步骤 | 具体动作 | 输出物 | 完成标准 |
|------|----------|--------|----------|
| 0-1 | 固定评审版本、分支和提交范围 | Release baseline tag、变更清单 | 代码、文档、测试使用同一 commit/tag |
| 0-2 | 统一 Security 需求状态 | 更新 PRD/SRS/SRS-Table 状态字段 | 已实现、部分实现、受限、待开发四类无冲突 |
| 0-3 | 拆分测试基线 | unit/integration/e2e/worker/PA 回归五类报告 | 每类独立计数，记录平台、Python、依赖和时间 |
| 0-4 | 固化测试入口 | `deploy/verify_all.sh [--strict]`、JSON/JUnit 报告 | 非 strict 仓库验证通过；strict 对 doctor、E2E skip、供应链、正式 Runtime 全量累计并 fail-closed |
| 0-5 | 建立风险台账 | P0/P1/P2 backlog、负责人、截止日期 | 每项有唯一编号、验收标准和关闭证据 |

#### 阶段 1：P0 安全边界（建议优先完成）

##### P0-01/P0-02：调用者身份与管理授权

实现顺序：

1. 在 `securityd/service.py` 获取 D-Bus sender、UID、PID 等调用上下文；
2. 在 `securityd/models.py` 增加 `CallerContext`；
3. 在 `engine.py` 增加调用者校验入口；
4. 建立 `agent_id → uid/pid/cgroup/session` 运行时绑定表；
5. 将 `RegisterCapabilities`、`SetCapabilityGranted`、`RevokePermission`、`InstallPackage`、`SetTokenBudget`、`SetNetworkPolicy` 划为管理操作；
6. 对 `RespondConfirm` 绑定受信 UI、用户 session 和一次性 request_id；
7. 同步更新 `deploy/io.bianbu.Security.conf`、client SDK、WebUI 和测试替身。

当前状态（2026-08-14）：步骤 1–7 的仓库实现已完成；PA Runtime 已在启动阶段用
自身 D-Bus sender 调用 `BindAgent`，testkit 直接判权使用独立测试 Agent；管理员读取
管理数据和显式重绑均有服务端授权/审计。剩余关闭条件仅指正式
`bianbu-agent-runtimed.service`、`io.bianbu.Runtime` 和 root/
`bianbu-security`/`bianbu-admin`/普通用户四类生产身份矩阵，不能用 PA 适配层替代。

验收用例：

| 用例 | 预期 |
|------|------|
| Agent A 冒充 Agent B 调 `CheckPermission` | 拒绝并审计 |
| 普通 Agent 调 `SetCapabilityGranted(granted=1)` | D-Bus AccessDenied |
| 非受信进程调 `RespondConfirm` | 拒绝 |
| 重复提交同一 request_id | 第二次拒绝 |
| PID 退出后复用 | 不能继承旧 Agent 身份 |

##### P0-03：WebUI 认证与终端隔离

实现顺序：

1. 默认监听 localhost；
2. 增加认证中间件、角色和 session cookie 安全属性；
3. 增加 CSRF token 和管理操作审计；
4. 将普通 shell 改为默认关闭，或仅允许安全管理员；
5. 为 Hermes chat、bwrap shell、普通 shell 分别建立权限；
6. 增加未认证、越权、CSRF、PTY 访问测试。

验收指标：

- 未认证管理请求 100% 返回 401/403；
- 非管理员创建 PTY 成功率 0%；
- CSRF 请求改变能力/策略成功率 0%；
- 每次管理变更均记录操作者、时间、目标、旧值和新值。

##### P0-04：D-Bus policy 与发布资产统一

实现顺序：

1. 以 `deploy/io.bianbu.Security.conf` 为生产唯一来源；
2. 删除或标记 `data/` 中容易被误装的旧 policy；
3. 增加 XML、service.py、client SDK、policy 的方法集合一致性检查；
4. 验证 root、`bianbu-security`、`bianbu-admin`、普通用户四类身份；
5. 将 policy 校验加入 CI 和发布脚本。

##### P0-05：Token 超限事件契约与 Runtime/agent 消费

此项不要求 securityd 直接停止 Agent。职责固定如下：

> 用户任务清单中所称“P0-4：Token 超限后的真实暂停”，在本评审编号中对应
> P0-05 的 Runtime 消费环节。其 Security 侧通知责任已完成；真实暂停属于范围外
> Runtime/agent 功能。

```text
securityd MeterTokens
  → 超限判定
  → 审计 token_meter/exceed
  → TokenExceeded + SecurityAlert
  → 当前请求返回 within_limit=false
  → Agent Runtime/agent 消费事件
  → Agent/Run 进入 PAUSED 或 TERMINATED
  → 后续模型调用/工具调度被拒绝
```

实现任务与状态：

1. 固化当前 `TokenExceeded(agent_id, scope, used, limit)` 兼容字段；（已完成）
2. 固化 `TokenExceededV2` 的非空 `session_id/run_id`，并拒绝负值、`used <= limit`、非法 scope/on_exceed；（已完成并在 worker 验证）
3. 为 Runtime/agent 增加事件订阅和幂等处理；（范围外 Runtime/agent 责任）
4. Runtime/agent 将事件映射到 Agent/Run 状态机；（范围外 Runtime/agent 责任）
5. 在模型调用和工具调度入口增加配额超限状态检查；（范围外 Runtime/agent 责任）
6. 增加事件丢失、重复、securityd 重启和消费方重启恢复测试；（Security 侧事件与审计已测，消费方恢复由范围外 Runtime/agent 验收）
7. 由 Runtime/agent 负责用户提示和暂停/终止动作，securityd 只提供事件、审计和当前调用拒绝；（职责已固定，正式 Runtime 接入待验收）

当前仓库已提供 `client/runtime_token_guard.py` 作为 Runtime/agent 的嵌入式消费实现：
事件按 agent/session/run 去重，状态持久化到 SQLite，Runtime 重启后仍保持
PAUSED/TERMINATED；`assert_can_call()` 对模型和工具入口统一拒绝。该模块不依赖
`io.bianbu.Runtime.Pause`，也不停止任何服务。

2026-08-14 已在 worker 的真实系统总线上执行 Security-only 验证：正式 Runtime unit
不存在、`io.bianbu.Runtime` 未注册时，`MeterTokensV2(tokens=2)` 对 conversation 上限 1
返回 `within=false/remaining=0`，并发出字段完整的 `TokenExceededV2`，结果为
`SECURITY_TOKEN_NOTIFY_ONLY_PASS`。该证据关闭 Securityd 的超限判定、审计、当前计量
拒绝和通知职责。真实 PAUSED/TERMINATED 与后续模型/工具门禁由范围外 Runtime/agent
负责，不进入本次交付完成度。

验收标准：

- 超限事件产生率 100%，审计记录率 100%；
- Runtime/agent 收到事件后状态在 1 秒内变为 PAUSED/TERMINATED；
- 状态切换后新的模型调用和工具调度拒绝率 100%；
- 重复事件不重复创建状态或告警；
- securityd 不依赖 `io.bianbu.Runtime.Pause` 才能完成自身超限判定。

##### P0-06：发布包与干净环境验证

实现顺序：

1. 修正 `pyproject.toml` 的包发现和资源包含；
2. 添加依赖 lockfile 和最小安装脚本；
3. 在干净 venv 构建 wheel；
4. 安装后验证 `securityd.dlp`、`securityd.langgraph`、client、CLI、WebUI；
5. 验证 D-Bus XML、systemd unit、policy、静态资源和默认目录；
6. 执行安装、启动、冒烟、卸载和重复安装。

#### 阶段 2：P1 安全能力完整性

| 工作项 | 推荐实现 | 必须补的测试 |
|--------|----------|--------------|
| 网络强制 | 抽象 `EgressEnforcer`，实现 netfilter/eBPF/proxy/deny 后端探测 | 白名单域名、非白名单域名、直连 IP、DNS、IPv6、后端不可用 |
| cgroup 强制 | runtimed/systemd 创建 slice，securityd 生成和审计策略；sandbox 支持四类 v2 控制器写入 | MemoryMax、CPUQuota、TasksMax、IOWeight、OOM、越权移动 cgroup |
| session trust V2 | `CheckPermissionV2/RequestConfirmV2` 增加 `a{sv} context` | 同 session 不重复确认、跨 session 重确认、撤销清缓存 |
| 代码签名供应链 | installer 全路径验签，生产 enforce，独立信任根、吊销（含全量吊销 fail-closed）和防回滚 | 未签名、篡改、未知签名者、吊销、回滚；设备公钥轮换与真实升级/回滚演练待补 |
| 故障恢复 | D-Bus/UDS/SQLite/服务状态恢复方案 | 断线、重启、WAL 损坏、磁盘满、未决确认、事件重放 |
| DLP 加固 | 混淆归一化、流式跨 chunk 状态、超时和熔断 | Unicode、Base64、JSON 嵌套、零宽字符、长文本和异常输入 |

#### 阶段 3：发布验证与 TR6 复审

完成 P0/P1 后，按以下顺序执行发布验证：

1. 开发机 unit 测试；
2. 会话总线 integration/e2e；
3. K3 worker 真机测试；
4. bianbu-agent 全量回归；
5. 负向安全测试和权限渗透测试；
6. 24/72 小时稳定性测试；
7. 干净环境安装、升级、回滚；
8. SBOM、CVE、许可证和发布包检查；
9. 更新需求追溯矩阵和遗留风险台账；
10. 召开 TR6/ADCP 评审，决定 GA、试点或继续整改。

### 7.5 依赖关系与并行策略

```text
基线冻结
   │
   ├── P0-01 身份绑定 ──┬── P0-02 管理/Confirm 授权
   │                    └── P0-04 D-Bus policy
   ├── P0-03 WebUI 认证/终端隔离
   ├── P0-05 Token 事件契约（Security 已关闭）
   └── P0-06 发布包
             │
             ▼
      P1 网络 / cgroup / session V2 /
      代码签名 / 故障恢复 / DLP 加固
             │
             ▼
      发布验证 → TR6/ADCP 复审
```

Security 功能代码、仓库验证和最终提交证据已经收口。本次交付下一步是完成
24/72 小时耐久、正式发布 CA/流水线和第三方渗透；Runtime 实现由范围外责任域按清单
接收，桌面 seat 由 Desktop/Release 协同提供运营证据。

### 7.6 每项工作的完成定义（DoD）

任何剩余工作只有同时满足以下条件，才可从 backlog 标记为完成：

1. 需求、设计、API、代码和测试编号一致；
2. 有正向、负向和异常路径测试；
3. 测试记录平台、版本、依赖、命令和原始结果；
4. 关键安全项有 worker 或目标系统实测证据；
5. 失败时的 fail-closed/降级行为已明确；
6. 无未评审的安全回归；
7. 变更已进入发布分支并可在干净环境重现。

### 7.7 建议里程碑

| 里程碑 | 目标 | 退出条件 |
|--------|------|----------|
| R0 基线冻结 | 统一文档、测试和发布范围 | 单一 baseline tag，风险台账建立 |
| R1 P0 安全收口 | 最终证据包、24/72 小时、版本审批 | P0-01~06 全部关闭并有证据 |
| R2 P1 运营收口 | 组织 CA、桌面 seat、session、签名、恢复、渗透 | P1-01~06 全部关闭或完成正式风险接受 |
| R3 发布候选 | 全量验证和交付物冻结 | 安装/升级/回滚、长期稳定性、安全测试通过 |
| R4 TR6/ADCP | 正式 IPD 评审 | 评审结论为 GA、试点或继续整改 |

## 8. TR6/ADCP 准入标准

进入正式发布候选前，必须满足：

### 功能

- Security P0 需求 100% 有实现和测试；
- 受限需求已明确产品边界、替代方案和适用平台；
- Token 超限事件、确认、审计、DLP、沙箱形成跨模块端到端闭环；停止动作由 Agent Runtime/agent 执行，不由 securityd 直接停止服务。

### 安全

- 未授权能力调用拦截率 100%；
- 未授权管理调用拦截率 100%；
- L3/L4 未确认执行率 0%；
- WebUI 未认证管理/终端访问率 0%；
- 伪造 Agent 身份判权成功率 0%；
- 审计篡改和回滚均可检测。

### 性能

- CheckPermission P99 ≤ 10 ms；
- UDS 小载荷 P99 ≤ 1 ms，大载荷吞吐 ≥ 10 MB/s；
- 沙箱附加冷启动 ≤ 200 ms；
- 关键 DLP 路径在目标数据规模下无超时和事件循环阻塞。

### 可靠性

- 24/72 小时稳定性测试无 P0/P1 故障；
- D-Bus、UDS、SQLite、网络后端故障均有明确 fail-closed 或降级行为；
- 升级、回滚、数据库迁移成功率 100%。

### 交付

- 可复现安装包、依赖锁、SBOM、CVE 扫描和许可证清单齐全；
- PRD/SRS/API/实现/测试追溯矩阵冻结；
- 所有遗留风险有负责人、截止日期和发布决策记录。

## 9. 最终评审意见

## 9.1 Worker 实机验证记录（2026-08-13）

本轮最终源码已在 worker `10.0.90.243` 的独立目录
`/home/bianbu/bnsec-delivery-final38` 验证，未修改原有部署目录。环境为
riscv64、Linux `6.18.3-generic`、Python `3.14.4`、bubblewrap `0.11.1`。

| 验证项 | 命令/范围 | 结果 | 说明 |
|--------|-----------|------|------|
| D-Bus 契约 | `python3 tests/verify_dbus_contract.py` | 通过 | `DBUS_CONTRACT_PASS methods=27 policy=identical`（worker `final38`） |
| 单元测试 | `python3 -m pytest tests/unit -q` | 通过 | `453 passed`（worker `bnsec-final-current6`） |
| 集成测试 | `python3 -m pytest tests/integration -q` | 通过 | `12 passed in 3.52s`，含 Token Runtime、参考 Runtime 服务和 systemd Runtime 门禁 |
| E2E 测试 | `python3 -m pytest tests/e2e -q` | 有条件通过 | `3 skipped`，测试明确要求真实外部服务 |
| Smoke 全链路 | `bash tests/smoke_test.sh` | 通过 | bwrap、D-Bus、Confirm、Hermes Plugin 全部通过 |
| 发布包 | `python3 -m pip wheel . --no-deps` | 通过 | final-current6 wheel 217417 字节；含 Runtime service、XML/policy、WebUI/LangGraph broker、生产探针及发布资产 |
| SBOM/依赖锁 | `generate_sbom.py` + `requirements-lock.txt` | 通过 | `cryptography==50.0.0`，7 个锁定依赖版本/许可证完整 |
| CVE 扫描 | `pip-audit --format json` | 通过 | 24 个依赖解析，漏洞数 `0`；曾发现并修复 cryptography 46.0.5 漏洞后复扫 |
| 干净环境导入 | wheel 安装后导入 client/DLP/LangGraph/WebUI | 通过 | `PACKAGE_IMPORT_PASS`（WebUI extras 已安装） |
| 网络强制状态 | `network_policy.enforcement_status(agent_id)` | 受控通过 | Runtime unit 创建并读取 `systemctl show` 后登记 `mode=systemd,enforced=True`；未登记时严格保持 artifact-only |
| systemd 网络隔离探针 | Runtime transient unit + `IPAddressDeny/Allow` | 通过 | 白名单 `archive.bianbu.xyz`（10.0.50.55）允许；非白名单阻断；属性真实复核 |
| DLP 基准 | `python3 tests/integration/pii_benchmark.py` | 通过 | 召回 99.75%，误报 0.75%，平均 0.131 ms/条 |
| UDS 基准 | `python3 tests/integration/uds_benchmark.py` | 通过 | 4KB P99 0.359 ms，连续吞吐 29.4 MB/s，2000 次零错误 |
| 稳定性烟测 | `python3 tests/integration/stability_smoke.py --seconds 10` | 通过 | 19232 次判权/审计，链完整；不替代 24/72 小时测试 |
| Runtime bridge | `RuntimeSecurityBridge` 单测 | 通过 | 完整 agent/session/run context；V2 事件订阅、模型和工具门禁统一阻断 |
| WebUI 角色与终端隔离 | `tests/unit/test_webui_roles.py` | 通过 | viewer 只读；写 API/终端要求 admin token + CSRF |
| Strict doctor 身份矩阵 | `bncli --json doctor --strict` | 正确 fail-closed | 配置身份矩阵后仍因网络强制/生产信任根缺失失败 |

本次证据将 P0 核心调用链、身份边界、确认、Token 计量、V2 事件、Runtime
资源/网络强制、发布包、SBOM 和 CVE=0 验证推进到 worker 实机通过。E2E 的 3 项跳过仍不能计入
完整系统级验收，须在正式 Runtime、GUI 和生产系统总线服务可部署后补测。

本轮新增并已在 worker `final38` 通过的补强：`BindAgentV2/CheckPermissionV2/RequestConfirmV2`
携带 session/run context；Runtime TokenExceeded guard 的事件幂等、重启恢复和
后续调用门禁；cgroup v2 的 MemoryMax/CPUQuota/TasksMax/IOWeight 写入路径；
`bncli doctor` 发布前环境自检。worker 的 systemd transient unit 已真实复核
MemoryMax/CPUQuota/TasksMax/IOWeight、ControlGroup 归属及 MemoryMax OOM-kill；生产
仍必须由正式 runtimed/systemd 身份创建 unit 并完成身份矩阵验收。

本轮进一步交付 `client/runtime_security_consumer.py`、
`deploy/bianbu-agent-runtimed.service` 和 Runtime 接入约定文档。消费者运行在
Runtime/agent 进程内，校验完整 `TokenExceededV2` 事件、策略版本和
agent/session/run 上下文，持久化幂等状态，并通过回调交由 Runtime 自身 FSM 执行
PAUSED/TERMINATED；Securityd 不调用 Runtime 的 Pause/Stop。worker `final38` 的
跨进程 `tests/integration/token_runtime_e2e.py` 已通过 `TOKEN_RUNTIME_E2E_PASS`，参考 Runtime 服务 E2E 已通过 `RUNTIME_SERVICE_E2E_PASS`。
该交付解决了仓库侧适配缺口，但不代表 worker 上已有正式 Runtime 二进制或生产
systemd unit；这两项仍须由 Runtime 仓库/系统镜像提供真实证据。

当前代码还包括 Runtime systemd unit 编译器（资源 + 网络属性 + 实际属性复核）、代码签名吊销
清单与数字版本防回滚、DLP Unicode/Base64/流式扫描、`bncli doctor`、wheel
 data-files（D-Bus XML/policy/unit/deploy）和安装脚本资源复制。安装器现默认只管理 Security，
通过 `--enable-runtime` 才安装仓库参考 Runtime，避免 Security 越权接管外部 Runtime。
这些关闭了实现缺口，
但不替代正式部署环境中的生产签名信任根、特权 Runtime 身份矩阵、真实升级/回滚和 24/72 小时稳定性证据。

补充集成证据（worker `bnsec-final-current6`，`12 passed`，单测 `453 passed`）：`tests/integration/token_runtime_e2e.py` 和 `runtime_service_e2e.py` 在私有真实 D-Bus 上验证
`MeterTokens → TokenExceeded → Runtime guard PAUSED → model/tool 调用拒绝`，并覆盖
重复事件幂等与 Runtime guard 重启恢复；同一测试还验证 V2 session trust 在同
session 为 ALLOW、跨 session 恢复 CONFIRM。该测试证明 SDK/消费组件契约闭环，
正式 `bianbu-agent-runtimed` 进程接入仍需在其仓库或系统镜像执行同等验收。

正式 Runtime 接入的逐项验收要求已固化在
[`docs/review/Runtime-Production-Integration-Checklist.md`](Runtime-Production-Integration-Checklist.md)。
worker 当前没有 `bianbu-agent-runtimed.service`，因此 strict doctor 的身份矩阵和网络
强制仍按 fail-closed 处理，不能据此关闭 P0/P1。

本项目已经不是“只有设计没有实现”的安全方案，`bianbu-securityd` 和 Agent 集成已经具备较强的工程原型价值。当前真正的风险集中在产品化边界，而不是基础功能数量：

- 正式 Runtime 是否接入并持续提供真实调用者绑定上下文；
- 生产管理面是否可安全暴露；
- 网络和资源限制是否真正由内核/运行时强制；
- 签名、安装、升级和审计是否形成可信供应链；
- 测试、文档和发布物是否可复现。

因此，该历史阶段当时建议项目状态表述为：

> **Bianbu Security 核心功能已完成并进入系统级验证收口；仍有正式 Runtime 接入（含 LangGraph broker 目标系统验收）、生产管理面配置、网络/cgroup 强制、供应链和发布质量等 P0/P1 项，暂不通过 GA/可商用发布评审。**

该历史结论由下述 V1.8 当前结论取代。

## 10. V1.8 最终评审结论（历史）

§9 保留的是早期 worker 阶段记录，其中的 453/462 等计数和“外部 E2E 跳过”结论仅供
追溯，已被本轮 `548 passed / 3 skipped`、strict `534 unit + 14 integration + 3 E2E`
（0 skip）及 §5.6.6 的证据替代。

当前正式结论为：

1. **Security 仓库侧 86/86 功能已完成**，默认全量、strict 仓库项、testkit、PA 回归、
   生产安装、升级、故障回滚和 Security 发布证据门禁均已通过；
2. **Token 超限 Security 职责已完成**：超限判定、当前计量拒绝、审计和
   `TokenExceededV2` 通知不依赖 Runtime；Securityd 不暂停 Runtime、不停止服务；
3. `/data/workspace2026-new/work0618/bianbu-next-agentos-dev-cc` 和正式 Runtime 实现明确
   不在本次交付范围，其生产探针状态只用于全产品集成提示，不计入 Security 完成度；
4. 本次剩余工作只有发布/运营收口：24/72 小时耐久、组织级 CA、
   桌面 seat/polkit、第三方渗透及正式 tag/审批归档；
5. 在上述运营证据完成前，状态为 **Security 商用候选/TR6 候选**；完成后由
   Release/质量负责人执行 ADCP/正式商用签收。

## 11. V1.9 生产复验结论（当前有效，2026-08-17）

本节取代 §10 的“当前有效”状态。详细原始指标见
[`BNAgent-Security-Acceptance-Revalidation-2026-08-17.md`](BNAgent-Security-Acceptance-Revalidation-2026-08-17.md)。

### 11.1 新增实现与验证

本轮针对生产 P99 完成了不放宽安全语义的路径优化：D-Bus sender UID/PID
按连接生命周期缓存，每次仍重读 `/proc` executable/cgroup；单请求复用 binding；
审计链尾只在同步 `commit` 成功后推进；审计写入改为调用线程同步事务、锁串行化，
并保留存储失败回滚、关闭排空和 fail-closed。systemd 调度参数为 `Nice=-10`、
`CPUWeight=1000`、`IOWeight=1000`；不使用实时调度。安装器同时修复了成功升级后已运行 WebUI
必须恢复的问题。

| 验证项 | 2026-08-17 结果 | 判定 |
|--------|------------------|------|
| 审计/故障恢复专项 | `27 passed` | 通过 |
| 默认全量 | `557 passed / 3 skipped` | 通过 |
| strict | `543 unit + 14 integration + 3 E2E`，0 skip | 通过 |
| PA 真实端到端 | testkit `35/35` | 通过 |
| Token Runtime 消费链 | `TOKEN_RUNTIME_E2E_PASS` | V2 上下文、PAUSED、model/tool 拒绝、幂等和恢复通过 |
| strict 性能 | 100 样本，P99 `3.594 ms` | 通过 |
| 短稳 | 10s，40552 ops，chain=true | 通过；不替代 72h |
| 供应链 | SBOM、CVE=0、release gate | 通过 |
| Security 正式证据 | 实现提交 `f956d809…` | 167/167 个跟踪文件及 8 个附件哈希一致，`security_scope_status=passed` |

### 11.2 长时和生产性能判定

原 72 小时任务运行约 64.6 小时，46502 次操作无错，审计链完整，但
24h P99 为 `10.400123 ms`，累计 P99 为 `10.438273 ms`。由于已无法在剩余时间内
数学上恢复到 10 ms 内，任务已停止并保留为失败证据。

优化后 v1/v2/v3 三轮 600s/120 样本生产预演的 P99 依次为 `10.113535 ms`、
`11.488231 ms`和 `12.121011 ms`，均不达标。v4 为 `9.276006 ms`，0 error、
RSS 增长 `52.746094 MB`，审计链、服务重启和 SSE 门槛全部通过。当前无长跑进程。

验收期间 worker 上范围外 `hermes-agent.service` 约每 10.5 秒失败重启，
`NRestarts` 累计约 47400；v3 四个超限样本中三个与其启动/失败在同一秒。
本项目未修改或停止该服务，也不把它纳入实现依赖。
为避免 `systemctl is-system-running=running` 掩盖此类风暴，v2 启动器和最终门禁新增
`systemd_transient_units` 检查；当前实际拒绝输出为
`COMMERCIAL_SOAK_START_FAIL systemd_transient_units=hermes-agent.service`。

### 11.3 当前 IPD 判定

1. Security 仓库侧 86/86 功能完成，自动化、PA 真实接入、安装和 Security
   发布门禁达到商用候选标准；
2. 生产间隔采样 `CheckPermission P99≤10 ms` 已由 v4 达到；72 小时长期可靠性
   **仍未达到**；
3. 实现基线 `f956d809…` 的正式 Security 证据包已生成，8 个附件哈希一致；
4. 必须先由 worker/相关服务所有者清理循环失败 unit，再启动新 72 小时任务；
5. 组织级 CA 四项演练、真实桌面 seat/polkit 四路径、第三方渗透、双人审批、
   正式 tag/变更单和组织 Ed25519 签名仍为外部必需证据，不能内部伪造；
6. 当前 IPD 结论为 **Security 商用候选，长期可靠性未达标，不通过无条件
   GA/最终商用签收**。
