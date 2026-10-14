# Bianbu Agent Runtime × Security 安全功能与架构梳理（开发状态矩阵）

| 项 | 内容 |
|---|---|
| 文档编号 | BN-SEC-CCT-001 |
| 版本 | 1.0 |
| 日期 | 2026-09-11 |
| 状态 | 已完成梳理（基于两仓源码 + Worker 实机核对） |
| 代码基线 | Runtime `bianbu-agent-runtime` commit `5d41abe0`（包 0.1.27）；Security `bianbu-agent-security` commit `05921e6`（包 0.1.28） |
| 实机 | Worker `10.0.90.243`，SpacemiT K3 riscv64，Linux 6.18.3，Python 3.14.4，bubblewrap 0.11.1，systemd 259 |
| 配套文档 | [02 测试交付方案与用例](02-e2e-delivery-test-plan-and-cases.md) · [03 端到端验收报告](03-e2e-acceptance-report-20260911.md) |

## 1. 两仓分工与安全架构

### 1.1 职责边界

```
bianbu-agent-runtime（../bianbu-agent-runtime，Python 包 bianbu_agent）
  控制面 Control：HTTP 9899、Agent/Session/Run 编排、Worker 监督、lease 申请、能力目录、审批(HITL)
  执行面 Worker：LangGraph 引擎、工具执行、8 个 security hook（插件 bianbu.security）、Token 计量回调
        │  D-Bus io.bianbu.Security / io.bianbu.Security.Runtime（控制面）
        │  UDS /run/bianbu/securityd.sock（Worker 数据面：判权、DLP、Token、审计）
        ▼
bianbu-agent-security（impl/bianbu-securityd，独立用户 bianbu-security）
  securityd：能力字典与判权、YOLO 模式、Confirm 门禁、DLP/PII、Token 配额、审计哈希链、
            Runtime lease（PrepareStart/CommitStart/Abort/Revoke）、seccomp 策略/审计、网络策略/学习、
            manifest 与代码签名、caller binding、Key Vault
  配置台 WebUI（gunicorn，127.0.0.1:8788 实装 / 8787 文档默认）
  bianbu-syscall-observer（root，bpftrace kprobe audit_seccomp → /run/bianbu-syscall-audit）
  testkit/（36+1 项端到端测试系统）
```

设计权威：`docs/Bianbu-Security-Runtime-商用设计方案.md`（BN-SEC-RUNTIME-001）；能力映射 `docs/BNAgent-Security-Capability-Mapping.md`；Runtime 侧排障与硬约束 `../bianbu-agent-runtime/docs/ai-runtime-security-troubleshooting.md`。

### 1.2 一次工具调用的安全链路（实机核对，normal 模式）

| 序 | 环节 | 所在仓/文件 | securityd 审计留痕（`audit_record.op_type`） |
|---|---|---|---|
| 1 | Control 创建 Session/Run，Worker 已由 lease 启动（`PrepareStart → systemd-run scope → CommitStart`） | Runtime `security/execution_runtime.py` | `runtime_prepare_start` / `runtime_commit_start` / `runtime.worker_hello` |
| 2 | `before_run` hook 装载 Agent DLP 策略 | 插件 `hooks/security.before_run` | `hook:agent_startup` |
| 3 | `after_context`/`before_model` 扫描输入 PII；L3/L4 强制脱敏；BLOCK 时置 `deny_run` 并在 before_model 抛错 | 插件 `hooks/security.after_context`、`security.before_model` | `hook:input`、`hook:pre_model_call` |
| 4 | Token 配额预检（LangChain 之外）：超限 → `pause_and_notify` 走 HITL，或 `deny` 直接拒绝 | Runtime `engines/langgraph/engine.py:_token_budget_preflight` | `quota_checked` / `quota_approval_requested` / `quota_denied` |
| 5 | after_model 时序 HITL 预判：工具名→能力→`CheckPermissionV2`，DENY 直接抛，CONFIRM 弹审批 | Runtime `security/security_middleware.py` | `check_permission` |
| 6 | `before_tool` hook：`resolve_capability` → securityd `pre_tool_call` 干预点（`sec_capability@10 → dlp_pre_tool@50 → audit@90`），未映射工具按权威 `unmapped_policy()`（默认 confirm） | 插件 `hooks/security.before_tool`、`lib/mapping.py` | `check_permission`、`hook:pre_tool_call` |
| 7 | 工具执行；`after_tool` 对返回值脱敏 | 插件 `hooks/security.after_tool` | `<tool>`（如 `read_file executed ok`）、`hook:post_tool_call` |
| 8 | 模型返回后 `token_meter`/`token_metered`；`after_run` 还原占位符、水印、清 PII 表 | Runtime `engine.py:on_llm_end`；插件 `security.after_run` | `token_meter`、`token_metered`、`hook:agent_shutdown` |
| 9 | 出错走 `on_error`，仅审计不判权 | 插件 `security.on_error` | `error:-` |

实机证据（审计 seq 403–405，2026-09-11）：`check_permission file.read:/etc/hostname → decision=ALLOW;mode=yolo` → `hook:pre_tool_call sec_capability@3.7=ALLOW,dlp_pre_tool@0.2=ALLOW` → `read_file executed ok`，证明工具调用确实经过 securityd 判权。

### 1.3 身份模型（三个命名空间，混用即静默失效）

| 身份 | 值（实机） | 用途 |
|---|---|---|
| Runtime 安全身份 | `com.bianbu.runtime` | Control 的 caller binding、Runtime lease 的 `agent_id`、Worker UDS 的 `_worker_security_agent_id` |
| 逻辑 Agent ID | `com.bianbu.c6f40f30a6e5`（BibitEdgeAssistant） | 能力/DLP/Token/YOLO/审计的主键；Session `agent_id` |
| Worker 实例/租约 | `BIANBU_WORKER_INSTANCE_ID=<agent>-<hex>`、`BIANBU_WORKER_LEASE_ID` | UDS 数据面 lease 校验（PID/cgroup/instance/lease 四元组） |

## 2. Runtime 侧安全功能状态矩阵

状态定义：**已完成** = 代码完整 + 有回归测试 + 实机可观测；**部分** = 代码在但存在缺口/无专测/依赖条件；**未开始** = 无实现或显式拒绝。

| # | 功能域 | 实现位置（Runtime） | 状态 | 依据 / 缺口 | 相关测试 |
|---|---|---|---|---|---|
| R1 | Lease 三段式 Prepare/Commit/Abort/Revoke | `security/security_runtime.py:236,341,353,357`；`execution_runtime.py:1828-2032` | 已完成 | 6 字段完备校验、mode 一致性、commit 前 abort / 后 revoke；实机 lease DB 有 `committed/running` 记录 | `tests/runtime/test_security_runtime.py`(8)、`test_execution_runtime.py`(79) |
| R2 | Caller binding / Worker 身份不可伪造 | `server/runtime.py:442-453`；`security_runtime.py:163,210` | 已完成 | 受管 Worker 禁用改 PID 的 helper；身份只由 supervisor 注入环境变量；实机伪造 D-Bus/UDS 全部被拒（见报告 RT-04） | `test_security_runtime.py`、`test_security_bridge_discovery.py` |
| R3 | 固定 entrypoint / 签名 manifest | `execution_runtime.py:1778-1801`；`debian/generate-security-manifest.py` | 已完成（开发自签） | 生产命令不匹配即拒；当前包为 `DEVELOPMENT-SELF-SIGNED` 标记 | `test_manifest_generator.py`(7)、`test_manifest_registrar.py`(9) |
| R4 | 策略/镜像 digest 校验 | 无 | 未开始 | lease 协议刻意 digest-free（`test_prepare_start_uses_digest_free_security_contract`） | — |
| R5 | 沙箱后端 host-process | `execution_runtime.py:1041-1145` | 已完成 | systemd transient scope + `MemoryMax=2G`/`TasksMax=256`，Seccomp=2、NoNewPrivs=1、CapEff=0（实机） | `test_execution_runtime.py` |
| R6 | 沙箱后端 bwrap | `execution_runtime.py:1147-1461`；`security_sandbox.py` | 已完成（实机未启用） | Worker 配置 `requested_mode: host`，bwrap 仅 testkit SBX-01~05 单元级验证 | 同上；`security_sandbox.py` 无专测 |
| R7 | 沙箱后端 OCI / 控制面 sandbox | `execution_runtime.py:1501`（仅注册两后端）；`server/runtime.py:433-441` | 未开始 | 商用方案 P5；控制面 sandbox 启动期显式拒绝 | `test_service.py:105` |
| R8 | seccomp 加载 + 内核审计 LOG | `execution_runtime.py:1368-1380`；`seccomp_audit.py` | 部分 | 仅 x86_64/riscv64；实机 Worker `Seccomp_filters: 2` | `test_seccomp_audit.py`(2) |
| R9 | syscall 审计采集器 | `syscall_collector.py`；`scripts/syscall-{auditd,ebpf}-collector.py` | 已完成（可选组件） | 未配置即安全 no-op；V2 身份绑定上报 | `test_syscall_collector.py`(4) 等 |
| R10 | 网络策略 whitelist/deny_all/allow_all | `execution_runtime.py:550-583` | 已完成 | 域名解析为 `IPAddressAllow`，解析为空即拒启；实机 `allow_all`，`enforcement.mode=systemd enforced=true` | `test_execution_runtime.py` |
| R11 | 网络策略 learning | `execution_runtime.py:1863-1985`；`network_learning_*.py`；`debian/bianbu-agent-network-learning.service` | 已完成 | LD_PRELOAD + root collector + strace 回退 + degraded 上报 | `test_network_learning_*.py`(29) |
| R12 | 工具→能力映射 | 插件 `lib/mapping.py:227` | 已完成 | MCP 按 server 边界、24 条内置表、关键字推断、shell 元字符落 `<shell>` | `test_security_tool_mapping.py`(8) |
| R13 | 未映射工具处置（原 DEFAULT_ALLOW） | `lib/mapping.py:37-72`；`hook.py:83-105`；`security_middleware.py:260-273` | 部分 | 默认 confirm 已生效；残留：`DEFAULT_ALLOW` 常量仍导出、docstring 旧语义、`BIANBU_SECURITY_UNMAPPED=allow` 可一键恢复全放行、`capability==""` 无条件放行 | 无 unmapped=deny/confirm 分支直接测试 |
| R14 | 8 个 security hook | 插件 `hooks/*` | 部分 | 全部实现；`on_error` 明确不脱敏；`after_context` 的 BLOCK 需 `before_model` 补刀 | 仅 before_tool 有 2 条测试，其余 7 个无测试 |
| R15 | HITL / CONFIRM 审批 | `security_middleware.py:178,331,474-560`；`api/sessions.py` approvals | 已完成 | DENY 直接抛防 echo 绕过；批准写 `GrantSessionTrustV2` | `test_security_middleware.py`(14) |
| R16 | YOLO 模式 | `security_middleware.py:216,317,505`；`hook.py:59,91,164,177`；`engine.py:394,607`；`agent_registration.py:17` | 已完成 | 6 处生效点，权威状态在 securityd，无环境变量旁路，计量不豁免 | `test_security_api.py`、`test_security_middleware.py` |
| R17 | Token 配额（preflight + 计量） | `engines/langgraph/engine.py:379-460,580-640` | 部分 | 预检/HITL/deny 全部实机验证；缺口在 securityd `conv_used` 永不重置（见 §3 S7） | `test_token_budget_preflight.py`(6) |
| R18 | DLP 输入/模型/工具/输出 + Hybrid UDS | 插件 4 hook；`lib/uds_transport.py` | 部分 | 本地扫描与中央策略生效；**Worker UDS 数据面被 securityd 拒绝**（`_worker_security_agent_id` 未随 UDS 请求发送，见报告缺陷 D-1） | `test_security_api.py`；hook 级无测试 |
| R19 | Skill 文本 DLP | `security_skill_dlp.py`；`engines/default.py:126,146` | 已完成 | securityd 不可达 fail-closed | `test_security_skill_dlp.py`(4) |
| R20 | 能力注册 / replace-sync / catalog | `agent_registration.py`；`server/runtime.py:1085-1121`；`api/security.py` | 已完成 | `security_pending` 状态；生产态失败即致命 | `test_agent_registration.py`(6) 等 |
| R21 | `security_denied` 错误面 | `security_errors.py:39-45,158-224`；`runs/manager.py:988-1012` | 已完成 | 4 种 code、`degraded` 区分 | `test_security_error_surface.py`(19) |
| R22 | fail-closed / 降级分档 | `security_runtime.py:195-202`；插件 `lib/bridge.py:49-58,226-243` | 部分 | 生产强制 `required`；`BIANBU_SECURITY_FAIL_OPEN=1` 是无条件逃生门且生产不拦 | `test_security_runtime.py:140` |
| R23 | 代码签名门禁 | `security_codesign.py` | 部分 | 默认 fail-open，需 `BIANBU_SECURITY_CODESIGN_REQUIRE_DAEMON=1` | 无专测 |
| R24 | Provider base_url 白名单 | `security_provider_policy.py` | 已完成 | store 写事务内校验 | `test_provider_host_policy.py`(15) |
| R25 | 控制面不执行插件 / 协议校验 / RPC token | `runtime_process/control.py`、`protocol.py`、`worker_rpc.py:284` | 已完成 | 严格 schema、4MB 上限、常时比较 | `test_runtime_protocol.py`、`test_worker_rpc.py` |
| R26 | 系统单元与 polkit 加固 | `debian/bianbu-agent-runtime@.service`、`.polkit` | 已完成 | `Requires=bianbu-securityd`、`NoNewPrivileges`、polkit 只放行 scope | `debian/tests/*.sh` |
| R27 | egress broker / 出境代理 | 仅 `lib/mcp_transport.py:egress_info` 标记 | 未开始 | 只做 DLP 提档标记 | — |
| R28 | 安全 HTTP 面（6 REST + `/security-api/invoke` 25 op） | `api/security.py` | 已完成 | 错误信封 `unavailable/incompatible`；实机验证 | `test_security_api.py`(19)、`test_security_syscall_api.py`(8) |
| R29 | Runtime 状态接口反映 Worker 实况 | `api/runtime status` | 部分 | 实机 `/api/v1/runtime/status` 在 Worker 运行中仍返回 `instance_id/pid/backend=null, sandboxed=false, seccomp={}`；securityd `GetSecurityExecutionStatus.worker.state=unknown` | — |

Runtime 安全相关测试函数合计约 252 个（29 个文件），本次实机定向回归 185 项全部通过。

## 3. Security（securityd）侧功能状态矩阵

| # | 功能域 | 实现位置（securityd） | 对外接口 | 状态 | 依据 / 缺口 | 测试 |
|---|---|---|---|---|---|---|
| S1 | 能力字典与四表一致性 | `securityd/capabilities.py` | — | 已完成 | testkit CAP-01 实机 PASS | `test_scope.py`(18) |
| S2 | Capability Registry / 三态判权 / scope 最长前缀 | `capability_registry.py`、`engine.py` | `CheckPermission(V2)`、`Register/SyncAgentCapabilities`、`SetCapabilityGranted`、`RevokePermission`；UDS `permission.check` | 已完成 | PERM-01~04、CAP-02/03/04、SCOPE-01、MCP-01 实机 PASS | `test_capability_registry.py`(14) |
| S3 | Caller binding（D-Bus sender / UDS SO_PEERCRED / lease 四元组） | `caller_identity.py`、`service.py:238-374`、`uds_handlers.py:37-73`、`runtime/engine.py:authorize_worker` | `BindAgent(V2)`、`ResetAgentBinding`；UDS `worker.identity` | 已完成 | 实机伪造全部拒绝并审计 `caller_identity deny` | `test_caller_binding.py`(14) |
| S4 | Confirm 门禁 / HITL 恢复 | `confirm.py`、`langgraph/resume_registry.py` | `RequestConfirm(V2)`、`RespondConfirm`、信号 | 已完成 | PERM-03 L3/L4 禁 `trusted` | `test_confirm_recovery.py` 等 |
| S5 | YOLO / 安全模式 | `engine.py:143-159,238-242,254,329,359`；`capability_registry._ensure_initial_security_mode_locked` | `Get/SetAgentSecurityMode`；UDS `security.mode` | 已完成（产品决策变更） | **新注册 Agent 默认 yolo**（commit `3f3deb1`，`updated_by=initial-agent-default`）；yolo 下判权/confirm/token 旁路但均审计 `mode=yolo`；DLP/沙箱/绑定/审计不旁路 | `test_agent_security_mode*.py`(16)；testkit YOLO-01（已按新默认更新） |
| S6 | DLP / PII 8 类 + 4 动作 + 中央策略 | `dlp/pii_scanner.py`、`dlp/policy_store.py`、`dlp/handlers.py` | `Set/DeleteDLPPolicy`；UDS `dlp.scan`/`dlp.policy`；WebUI 5 端点 | 已完成 | DLP-01~03、EGRESS-01、SKILL-01 实机 PASS；中央 BLOCK 在 normal 模式真实拦截 run（`hook:input BLOCK` → `on_error`） | 6 个测试文件 174 项 |
| S7 | Token 配额 | `token_meter.py`、`engine.py:327-370` | `MeterTokens(V2)`、`Get/SetTokenBudget`、信号 `TokenExceeded(V2)`；UDS `token.meter`/`token.budget` | 部分 | 计量/超限/HITL/deny 均实机可观测；**`conv_used` 为 securityd 进程内累计计数，`reset_conversation()` 无任何调用方**，默认 100000 在数次 run 后即被越过，normal 模式下每个 run 都先卡 quota HITL；yolo 下 `GetTokenBudget` 把上限报成 0 掩盖了该现象 | `test_token_meter.py`(7) |
| S8 | Runtime lease 控制面 | `runtime/policy.py`、`runtime/lease.py`、`runtime/engine.py`、`service.py:106-223` | `PrepareStart`、`GetSandboxPolicy`、`CommitStart`、`AbortStart`、`RevokeAgent`、`GetRuntimeState`、`ListRuntimeInstances` | 已完成（生产 systemd 实机已跑通） | 实机 `runtime-leases.db` 有 committed lease + running instance，`attestation_json` 含 pid/unit/cgroup；伪造 lease 的 Commit/Abort 被拒；**缺口**：Worker 停止后实例记录不收敛（3 条 DEAD PID 仍 `running`，报告 D-9） | `test_runtime_policy.py`(17)、`test_runtime_lease.py`(6)、`test_runtime_engine.py`(5) |
| S9 | Manifest / 代码签名 | `manifest.py`、`code_signing.py` | `VerifyManifest`、`VerifyCodePackage`、`VerifyCodeDigest`、`InstallPackage` | 部分（demo 包关闭） | 实机 `BIANBU_SECURITY_CODESIGN=off`（`DEB_DEMO=1` drop-in），生产签名校验未验证 | `test_code_signing.py`(32) 等 |
| S10 | Sandbox 策略 / seccomp cBPF | `sandbox.py`、`seccomp_builder.py` | `BuildSandboxPolicy` | 已完成 | 12 条 mandatory denylist（riscv64 号表正确，如 `finit_module=273`） | `test_seccomp_builder.py`(5) |
| S11 | Syscall 策略版本化 | `syscall_policy.py` | `Get/SetGlobal/SetAgent/ResetAgentSyscallPolicy`、`GetSyscallCatalog` | 部分 | 实机：未知名/错误架构拒绝且不落库；追加后 `policy_version` 递增、`pending_restart=true`；**缺口**：host-process 后端不消费版本化策略，重启后 `applied_policy_version` 仍为 0（报告 D-10） | `test_syscall_policy.py`(3) |
| S12 | Syscall 审计链 + 内核观测器 | `syscall_audit.py`、`kernel_syscall_audit.py`、`deploy/syscall-kernel-observer.py`、`bianbu-syscall-observer.service` | `RecordSyscallInterception(V2)`、`GetSyscallAuditEvents/Status`、`GetSecurityExecutionStatus` | 部分（MVP） | 实机 `status=active backend=ebpf-seccomp coverage=deny-only events=0`；两条单测原先依赖宿主无观测器，已加隔离后 41/41 通过 | `test_syscall_audit.py`(7)、`test_kernel_syscall_audit.py`(7) |
| S13 | 网络策略 | `network_policy.py`、`capability_registry.network_policy` | `Set/GetNetworkPolicy` | 部分 | 实机 `enforcement.mode=systemd enforced=true`；非法 mode 拒绝；**缺口**：对运行中系统级 scope 的热应用被 polkit 拒绝（`systemctl set-property` 需交互授权），securityd 正确回滚（报告 D-6） | `test_network_policy.py`(19) |
| S14 | 网络学习采集 | `network_learning.py` | 5 个 `*NetworkLearning*` 方法 | 已完成 | 实机 `state=inactive`（当前 allow_all 不采集） | `test_network_learning.py` 等 |
| S15 | 审计哈希链（按月分段） | `audit_chain.py` | `AuditLog`、`ExportAudit`、`VerifyAuditChain`；UDS `audit.log`/`audit.batch` | 已完成 | 实机 `202609.db` 464→600+ 条，链校验连续；WebUI `intact:true` | `test_audit_chain.py`(13) 等 |
| S16 | 干预点框架（8 切面） | `interceptor.py` | — | 已完成 | HOOK-01~04 实机 PASS；已知风险：handler 异常 = 放行、无 handler 超时 | `test_interceptor.py`(14) |
| S17 | UDS 数据面（13 op） | `uds_protocol.py`、`uds_server.py`、`uds_handlers.py` | `/run/bianbu/securityd.sock` | 已完成 | 4 字节长度前缀 + JSON，`_request_id` 幂等，SO_PEERCRED | `test_uds.py`(39) |
| S18 | WebUI 配置台 | `webui/app.py`、`production.py` | 36 路由 + SocketIO | 部分（demo 无鉴权） | 实机 `/api/auth → auth_disabled:true`（unit `BIANBU_WEBUI_DEMO=1` 覆盖 `webui.env` 的 `AUTH=1`）；监听 8788 与文档 8787 不一致，8787 被 agentforce 旧进程占用 | `test_webui_*.py`(19) |
| S19 | 发布证据 / 商用门禁 / 耐久 | `deploy/security_release_gate.py`、`commercial_soak.py`、`commercial_acceptance_gate.py` | `.ci/run_tests.sh` | 部分 | 正式 24/72h 报告缺失；组织级证据未提供 | 26 项单测 |
| S20 | 数据重置命令 | `deploy/clear-security-data.py` | `bianbu-agentic-security-reset` | 已完成（0.1.28 新增） | — | `test_clear_security_data.py`(22) |
| S21 | Key Vault | `key_vault.py` | — | 已完成（软件方案） | 无 TEE | — |

securityd 测试合计约 688 个 `def test_`（unit 651 / integration 15 / e2e 3 / 根 19）。

## 4. 未交付 / 范围外 / BLOCKED 清单（两仓合并）

| # | 项目 | 定性 | 来源 |
|---|---|---|---|
| 1 | OCI 后端（crun）/ 容器 | 未开始，商用方案 P5 | 商用设计方案 §3.2/§7.4/§12 |
| 2 | 控制面 sandbox | 未开始，启动期显式拒绝 | Runtime `server/runtime.py:433-441` |
| 3 | 完整 egress broker | 未开始，仅 DLP 提档标记 | 测试与验收报告 `:152` |
| 4 | 策略/镜像 digest 校验 | 未开始（协议 digest-free） | Runtime `test_security_runtime.py:69,124` |
| 5 | 真实 eBPF 完整采集（非 bpftrace MVP） | BLOCKED / N/A | `docs/review/syscall-audit-mvp-full-solution.md` |
| 6 | 生产签名包 `DEB_DEMO=0` 的签名校验与 WebUI 鉴权 | BLOCKED（本次包为 demo） | `debian/rules:13-14,85-93` |
| 7 | 正式 24/72h 耐久、组织级商用证据 | 未关闭 | `docs/BNAgent-Security-VerifyBacklog.md` S-V01/S-V03 |
| 8 | REL-01 升级/回滚长稳 | BLOCKED | 20260911 交付报告 |
| 9 | Token 超限后真实暂停/终止（Runtime 责任） | 已由 Runtime `TokenBudgetApprovalRequired`/`TokenBudgetExceeded` 实现并实机验证；securityd 侧「范围外」定性可关闭 | VerifyBacklog §4 |
| 10 | bwrap 后端在生产 Worker 的启用 | 实机配置 `requested_mode: host`，bwrap 仅单元级验证 | Worker `~/.bianbu-agent/config.yaml` |
| 11 | WebUI 生产授权闭环（token + seat/polkit + TLS） | P0 未闭环 | `docs/DELIVERY-CHECKLIST.md:290` |

## 5. 本次梳理修正的三个历史判断

| 历史结论（20260911 交付报告） | 实机核对结果 | 修正 |
|---|---|---|
| HOOK-03 P0：工具调用落 `DEFAULT_ALLOW` 绕过判权 | 审计 seq 403 有 `check_permission file.read:/etc/hostname`；testkit 读的是 `syscall-events.db`（`sorted(glob("*.db"))[-1]`），并非无判权 | **测试缺陷**，非产品缺陷；testkit 已修 |
| DLP-04 P0：中央 BLOCK 未阻断 | Agent 处于产品默认 `yolo`，hook 对 BLOCK 只审计不拦截；normal 下 run 确被拦截（`on_error: prompt 含受限敏感信息（phone），已拒绝调用`）；真正缺陷是 Worker UDS 数据面被 lease 校验拒绝 | 降级为 **P1 缺陷 D-1**（UDS 请求缺 `_worker_security_agent_id`） |
| YOLO-01 P1：新 Agent 默认 yolo、恢复异常 | securityd `3f3deb1` 有意把新 Agent 默认置 yolo；「恢复失败」是测试在 yolo 基线上比较 DENY | **产品决策未同步测试**；testkit 已按新语义更新 |
