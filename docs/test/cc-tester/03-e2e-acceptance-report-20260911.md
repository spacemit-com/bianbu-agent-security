# Bianbu Agent Runtime × Security 端到端验收测试报告（2026-09-11，cc-tester）

| 项 | 内容 |
|---|---|
| 文档编号 | BN-SEC-CCT-003 |
| 版本 | 1.0 |
| 测试日期 | 2026-09-11 18:04（部署）— 19:35（验收结束），Asia/Shanghai |
| 执行方式 | Claude Code 自动执行 + 实机采证，全部在 Worker 完成 |
| Worker | `10.0.90.243`，SpacemiT K3 riscv64，Linux 6.18.3-generic，Python 3.14.4，bubblewrap 0.11.1，systemd 259 |
| 被测包 | `bianbu-agent-runtime 0.1.27`（commit `5d41abe0`）、`bianbu-agent-securityd 0.1.28`（commit `fbeff50` 构建；测试资产按本仓 `05921e6`+本轮修订） |
| 部署形态 | 正式 DEB + systemd：`bianbu-securityd.service`（bianbu-security）、`bianbu-agent-runtime@bianbu.service`（production/required）、`bianbu-security-webui.service`（8788，demo 无鉴权）、`bianbu-syscall-observer.service`；Worker `host-process` 后端 |
| 方案 | [02 测试交付方案与用例](02-e2e-delivery-test-plan-and-cases.md) |
| 证据 | Worker `/var/tmp/bnsec-cc-tester-20260911/`；仓内副本 `evidence/` |
| **总体结论** | **核心安全闭环（判权、拒绝透传、HITL 确认、DLP 阻断、Token 配额、seccomp、身份绑定、审计链、fail-closed）在正式安装布局下真实生效；有 10 项缺陷（3 项 P1：中央 DLP UDS 数据面、Token 会话计数不重置、网络策略热更新被 polkit 拒绝；其余 P2/P3），可作为带缺陷清单的条件交付；不满足无缺陷准出。** |

## 1. 结果总览

| 层 | 项目 | 结果 |
|---|---|---|
| L1 Runtime 定向回归（9 文件） | 185 用例 | **185 passed** |
| L1 securityd 定向回归（5 文件） | 41 用例 | 首轮 39 passed / 2 failed（测试未隔离宿主内核观测器）→ 修正后 **41 passed** |
| L2 testkit 全量（run2，修订后） | 37 项 | **35 passed / 2 failed**（DLP-04 UDS 数据面、ERR-01 因模型未调用工具） |
| L2 testkit 复跑（run3，ERR-01 改 L4 后） | 7 项 | **6 passed / 1 failed**（仅 DLP-04） |
| L3 手工探针 | P0-01、P0-03、RT-04、SC-01、CAP-02-CONFIRM(reject/approve)、API-01、API-02、NET-01 | 6 PASS、NET-01 FAIL、API-02 部分 |
| L4 故障注入 | P0-06 securityd 停止/恢复 | 见 §5 |

对比 2026-09-11 上午的交付报告（30/36，3 个 P0）：原判定的 HOOK-03 / DLP-04 / ERR-01 三个 P0 均被证实为**测试侧问题**（读错审计库、未考虑 yolo 默认、L2 拒绝按设计不终止 run、模型不调用工具），产品侧并不存在"未经判权绕过"。详见 [01 §5](01-security-feature-inventory-and-status.md#5-本次梳理修正的三个历史判断)。

## 2. 逐项结果矩阵

状态：PASS / FAIL / BLOCKED / N/A / PARTIAL。证据列为 `evidence/` 下相对路径或 Worker 路径。

### 2.1 连通、生命周期、身份

| ID | 测试点 | 结果 | 实际观测 | 证据 |
|---|---|---|---|---|
| P0-01 | 服务/总线/UDS/HTTP 连通与版本 | PASS | 6 个 unit active；`io.bianbu.Security` 52 方法 + `io.bianbu.Security.Runtime` 7 方法（PrepareStart/GetSandboxPolicy/CommitStart/AbortStart/RevokeAgent/GetRuntimeState/ListRuntimeInstances）；UDS `srw-rw---- bianbu-security`；WebUI 8788（8787 被 agentforce 旧进程占用） | `probes/p0-01-connectivity.txt` |
| CONN-01/02/03 | PA HTTP、占名、25 关键方法 | PASS | — | `testkit/run2-report.json` |
| HOOK-02 / P0-02 | 最小正常 run | PASS | `run/completed`，审计 `hook:agent_startup → input → pre_model_call → token_metered → agent_shutdown` | run2 |
| P0-03 | Worker 进程/沙箱证明 | PASS（host 后端） | Worker PID 2665040 在 `system.slice/bianbu-agent-com.bianbu.runtime-1e51ed5791c1.scope`，`Seccomp=2 Seccomp_filters=2 NoNewPrivs=1 CapEff=0`，`MemoryMax=2G TasksMax=256`；与 `runtime_instance.attestation_json`（pid/unit/cgroup/backend=host-process）一致；`BIANBU_SANDBOX_ACTIVE=0`、mnt namespace 独立、pid/net namespace 与宿主相同 | `probes/p0-03-sandbox-attestation.txt` |
| RT-01 | Prepare/Commit/Abort | PASS（间接） | lease DB：3 条 `committed` lease + `running` instance；审计 `runtime_prepare_start → runtime_commit_start → runtime.worker_hello`；P0-06 恢复后新 lease/instance（§5） | `runtime-leases.db`、审计 |
| RT-03 | manifest / entrypoint | PASS（开发自签） | Worker 命令与 lease `policy_json.entrypoint` 完全一致；manifest 为 `DEVELOPMENT-SELF-SIGNED` | 同上 |
| RT-04 | caller binding / 伪造 | PASS | D-Bus 冒充逻辑 Agent、冒充 `com.bianbu.runtime`、`MeterTokens` → `caller 无权代表 agent`；伪造 lease `CommitStart/AbortStart` → `lease 不存在`；UDS 带真实 instance/lease 但 PID 不符 → `Worker 未通过已提交 Runtime lease 身份校验`；不带 lease → `UDS caller 无权代表 agent`；审计 `caller_identity deny` ×5 | `probes/rt-04-caller-binding.txt` |
| RT-05 | Runtime 重启回收 | PARTIAL | P0-06 中 Runtime 随 securityd 停止后重启，旧 scope 消失、新 instance 生成（§5）；生产 soak 未做 | `faults/p0-06-*.txt` |

### 2.2 能力判权、YOLO、HITL

| ID | 测试点 | 结果 | 实际观测 | 证据 |
|---|---|---|---|---|
| PERM-01~04 | 注册/三态/L3L4 禁 trusted/撤销 | PASS | — | run2 |
| CAP-01 / SCOPE-01 / CAP-03 / CAP-04 | 四表一致、命令 scope、最高风险推断、未映射 confirm | PASS | `system.execute:<shell>` 哨兵在 SC-01 真实 run 中出现（复合命令落 L4） | run2、`probes/manual-probes-1-sc01.log` |
| HOOK-01 | 8 hook 加载 | PASS | — | run2 |
| HOOK-03 | normal 下真实 `read_file` 判权 | **PASS** | `check_permission file.read:/etc/hostname → allow`（seq 835/836）早于 `read_file executed`（seq 838）；无 yolo 旁路 | run2/run3 |
| HOOK-04 / MCP-01 / CAP-02 | MCP 判权与 server 边界 | PASS | — | run2 |
| ERR-01 | L4 DENY 透传 | **PASS**（run3） | `check_permission system.execute:echo → deny`；`terminal` 零执行；run `failed`，`error.code=security_denied`，message `[bianbu-security] 权限被拒绝：terminal 需能力 system.execute（scope=echo）…`，details `{tool:terminal, capability:system.execute, scope:echo, decision:BLOCK, degraded:false}`。注：details `risk_level=L3` 而能力注册为 L4（缺陷 D-7） | `testkit/run3-report.json` |
| CAP-02-CONFIRM | L4 confirm=always → 审批 | **PASS** | `check_permission system.execute:echo → confirm` → 事件 `approval/requested{approval_id, actions[terminal echo …]}` → 会话列表 `pending_interaction=approval, waiting=true` → `POST approvals` 200；重复 409 `session_control_conflict`；**reject**：`approval/resolved decision=reject`，`tool/call.completed status=error`，无 `terminal executed`；**approve**：`hook:pre_tool_call CONFIRM` → `terminal executed ok` 恰一次 | `probes/cap-02-confirm-reject.txt`、`probes/manual-probes-2-confirm-net.log` |
| YOLO-01 | 默认 yolo / 切换 / 恢复 | **PASS**（按新默认） | 新 Agent `{mode:yolo, updated_by:initial-agent-default}`；normal 下 DENY=2；yolo 下已撤销与未知能力均 ALLOW 且审计 `decision=ALLOW;mode=yolo`；`security_mode_change` 含 agent/old/new/actor/timestamp；切回 normal DENY 恢复 | run2/run3 |

### 2.3 DLP、Token

| ID | 测试点 | 结果 | 实际观测 | 证据 |
|---|---|---|---|---|
| DLP-01/02/03 | 8 类 PII、防误报、双信号 | PASS | — | run2 |
| SKILL-01 / EGRESS-01 | Skill DLP、出境提档 | PASS | `Skill 'leaky' 的文本含受限敏感信息（phone），已拒绝载入 system prompt` | run2 |
| DLP-04 阻断 | normal + 中央 `phone=block` | **PASS** | `hook:input BLOCK dlp_input@34.7=BLOCK` → `hook:pre_model_call BLOCK` → `on_error [bianbu-security] prompt 含受限敏感信息（phone），已拒绝调用`；run `failed` | run2/run3 |
| DLP-04 UDS 数据面 | >4KB 走 `dlp.scan`、>1KB 走 `audit.batch` | **FAIL → 缺陷 D-1** | securityd journal 每次 run 出现 `handler dlp.scan/dlp.policy/audit.batch 异常 … PermissionDenied: Worker 未通过已提交 Runtime lease 身份校验`；无 `uds_dlp_scan`；PA 回退本地扫描 + 本地策略库（fail-safe 仍阻断） | run3、securityd journal 19:11:58 / 19:17:15 / 19:30:30 |
| TOKEN-01/02 | 配额读写、真实计量 | PASS | `day_used 450765 → 469304`（+18539） | run2 |
| TOKEN-03 | normal + `deny` 超限 | **PASS** | run `failed`，`TOKEN_BUDGET_EXCEEDED … action=deny; used=518208; limit=1`；审计 `quota_denied`；无 `token_metered`；配额恢复 | run2/run3 |
| TOK-HITL | normal + `pause_and_notify` 超限 | 观测到 | run1：`quota_approval_requested` → 60s → `quota_approval_timeout`，run `failed TOKEN_BUDGET_APPROVAL_TIMEOUT`（approval_id `token-budget-<run>-…`） | `testkit/run1-report.json` HOOK-03/ERR-01 |
| TOK 语义 | `conv_used` 归属 | **缺陷 D-2** | `conv_used` 从 18:04 securityd 启动起累计（225k → 518k），`reset_conversation()` 无调用方；normal 模式默认 100000 上限被永久越过 | `api-01-contracts.txt`、run 日志 |

### 2.4 沙箱、seccomp、网络、审计

| ID | 测试点 | 结果 | 实际观测 | 证据 |
|---|---|---|---|---|
| SBX-01~05 | bwrap 隔离（单元级） | PASS | 非生产 Worker 证据（生产 Worker 为 host 后端） | run2 |
| SC-01 | Worker 内 deny syscall | **PASS（阻断）** | 真实 run 经 `terminal` 子进程：`finit_module -1 1 Operation not permitted`、`getpid 2718172`、`Seccomp 2`；审计 `check_permission system.execute:<shell> → ALLOW;mode=yolo → terminal executed ok` | `probes/sc-01-seccomp-deny.txt` |
| SC-03 | 拦截事件采集 | **FAIL → 缺陷 D-3** | 阻断发生后 `GetSyscallAuditEvents=[]`、`events=0`、`/run/bianbu-syscall-audit/events.jsonl` 0 行；状态仍报 `active/deny-only` | 同上 |
| SC-02 | 策略版本 / mandatory / 非法输入 | PASS | 追加 `bpf` → `policy_version 1, pending_restart`；`UnknownSyscall: not_a_syscall`、`UnsupportedArch: sparc` 拒绝不落库；reset 后 version 2 | `probes/api-01-contracts.txt` |
| SC-04 | collector 状态判定单测 | PASS（修正后） | 两条单测加 `kernel_observer_status` 隔离后 41/41 | `pytest/security-targeted-rerun.log` |
| NET-01 | `deny_all`/`learning` 热应用 | **FAIL → 缺陷 D-6** | D-Bus 直调与 Runtime `network-policy.update.v1` 均返回 `PermissionDenied: Command ['systemctl','set-property','--runtime','bianbu-agent-…scope','IPAddressDeny=any'] returned non-zero exit status 1`；根因：以 `bianbu-security` 执行 set-property 需交互式 polkit 授权（`60-bianbu-agent-runtime.rules` 只放行 Runtime 所有者的 start/stop 等 verb）；securityd 正确回滚注册表到 `allow_all`（无半应用状态） | `probes/net-01-network-policy.txt`、`probes/manual-probes-2-confirm-net.log` |
| NET-02 | learning 采集 | N/A | 因 NET-01 无法切换到 learning，未验证 | — |
| AUDIT-01/02/03 | 写入、哈希链、导出 | **PASS** | 主链库 `/var/log/bianbu/audit/202609.db`，40 条链校验 0 断链；WebUI `/api/audit intact:true` | run2/run3、`api-02-webui-status.txt` |

### 2.5 接口契约与状态展示

| ID | 测试点 | 结果 | 实际观测 | 证据 |
|---|---|---|---|---|
| API-01 | 非法输入契约 | PASS | 非法网络 mode/`on_exceed`/DLP action/pii_type → `ValueError` 明确拒绝；未知能力 grant → `false`；`/security-api/invoke` 未知 op → `{ok:false, error.code:incompatible, retryable:false}`；5xx 降为 `unavailable` | `probes/api-01-contracts.txt`、`api-02-webui-status.txt` |
| API-01 | 未知 Agent | PARTIAL → 缺陷 D-8 | `GetAgentInfo(com.bianbu.does.not.exist)` 返回带默认 token_budget 的正常 JSON，而非错误 | `api-01-contracts.txt` |
| API-02 | WebUI / Runtime 状态 | PARTIAL → 缺陷 D-4/D-5 | WebUI 8788 `/api/health securityd:connected`、security-execution-status/security-mode/syscall-policy/network/dlp matrix/audit 均可读；但 `/api/auth → auth_disabled:true`（demo）；`worker.state=unknown`；Runtime `/api/v1/runtime/status` 在 Worker 运行时 `instance_id/pid/backend=null, sandboxed=false, seccomp={}, audit={}` | `probes/api-02-webui-status.txt` |
| SIG-01 / CODE-01 | 签名校验 | PASS（测试密钥）/ BLOCKED（生产） | CODE-01 用测试密钥通过；实装 `BIANBU_SECURITY_CODESIGN=off`（`DEB_DEMO=1`），生产签名未验 | run2、unit Environment |
| REL-01 / OCI / egress broker | — | BLOCKED / N/A | 未交付项，未用模拟替代 | [01 §4] |

## 3. 缺陷清单（含根因与建议）

| # | 严重度 | 缺陷 | 根因（实机核对） | 影响 | 建议修复位置 |
|---|---|---|---|---|---|
| D-1 | **P1** | Worker 大载荷 DLP / 完整审计走不到 securityd UDS 数据面，回退本地 | 插件 `bianbu.security/lib/uds_transport.py:34-38` 的 `SecurityUdsTransport` 只随请求附带 `_worker_instance_id/_worker_lease_id`，**未附带 `_worker_security_agent_id`**；securityd `uds_handlers._require_agent` 用逻辑 Agent `com.bianbu.c6f40f30a6e5` 调 `authorize_worker`，而 lease 归属 `com.bianbu.runtime` → `Worker 未通过已提交 Runtime lease 身份校验`。对照 securityd 客户端 `_worker_uds_call` 有附带该字段且成功（`uds_dlp_scan` 46 条来自 Skill DLP 路径） | 中央策略只能经本地策略库回退读取；`audit.batch` 完整载荷丢失；>4KB 扫描在 Runtime 进程内完成 | Runtime 插件 `uds_transport.py`：在 `_worker_identity` 中加入 `"_worker_security_agent_id": os.environ.get("BIANBU_WORKER_SECURITY_AGENT_ID","")`；加 hook 级测试断言 `uds_dlp_scan` 审计 |
| D-2 | **P1** | `conv_used` 按 securityd 进程生命周期累计，永不按会话重置 | `token_meter.TokenMeter._Counter.conv_used` 内存累加；`reset_conversation()` 无任何调用方（两仓 grep）；`MeterTokensV2` 的 session/run 上下文未用于分桶 | normal 模式 Agent 数次 run 后必触发 quota HITL（60s 超时失败）；yolo 下 `GetTokenBudget` 报 0 掩盖问题 | securityd：按 `session_id` 分桶或在 `runtime.worker_hello`/新 session 调 `reset_conversation`；Runtime 预检用 `MeterTokensV2` 上下文 |
| D-3 | P2 | seccomp 拦截未进入 syscall 审计链 | 内核观测器 `bpftrace kprobe:audit_seccomp` 处于 active，但 host-process Worker 的 ERRNO 拦截未产生事件（`events.jsonl` 0 行）；状态仍宣称 `active/deny-only` | 只能证明"阻断"，不能证明"审计采集"；状态页可能误导 | 确认 Runtime `seccomp_audit.enable_filter_logging` 对 host 后端是否生效、`audit_seccomp` 是否覆盖 `SECCOMP_RET_ERRNO`；无事件时状态应降为 `degraded` |
| D-4 | P2 | Runtime `/api/v1/runtime/status` 与 securityd `GetSecurityExecutionStatus.worker.state` 不反映运行中的 Worker | 前者 `instance_id/pid/backend=null`；后者 `unknown` | 运维无法从状态接口确认沙箱/seccomp 实况 | Runtime 状态聚合读取 `AgentWorkerPool` 实例；securityd 用 lease DB 推导 worker.state |
| D-5 | P2（交付配置） | demo 包关闭 WebUI 鉴权与代码签名 | unit `BIANBU_WEBUI_DEMO=1/AUTH=0` 覆盖 `webui.env` 的 `AUTH=1`；`BIANBU_SECURITY_CODESIGN=off` | 8788 本机无鉴权可管理安全策略；签名验收 BLOCKED | 生产用 `DEB_DEMO=0` 构建；端口契约统一为 8787 或文档改 8788；清理 agentforce 旧进程 |
| D-6 | **P1** | 网络策略（deny_all/whitelist/learning）无法热应用到系统级 Worker scope | securityd 以 `bianbu-security` 执行 `systemctl set-property --runtime <scope> IPAddressDeny=…`，polkit `60-bianbu-agent-runtime.rules` 只放行 Runtime 所有者的 start/stop/kill 等 verb，`set-property` 落入默认 `auth_admin`；Runtime `network-policy.update.v1` 同样经 securityd 调用 | 管理员无法在运行期收紧网络；securityd 正确回滚，无半应用状态（fail-closed） | 增加 polkit 规则允许 `bianbu-security` 对 `bianbu-agent-*.scope` 执行 set-property，或让 securityd 把 apply 委托给 Runtime（Runtime 已有 polkit 授权）；bwrap 后端走 `restart_required` 路径 |
| D-7 | P3 | `security_denied.details.risk_level=L3`，能力注册为 L4 | 中间件拒绝路径的风险等级来自本地映射而非 securityd 返回 | 提示文案与审计等级不一致 | `security_middleware.py` 使用 `CheckPermissionV2` 返回/能力目录的 `risk_level` |
| D-8 | P3 | `GetAgentInfo` 未知 Agent 返回默认值而非错误 | `manifest:null` 但 `token_budget` 填默认 | 调用方难以区分"未注册"与"已注册未配置" | 返回 `AgentNotFound` 或 `registered:false` 字段 |
| T-1 | 测试缺陷（已修） | testkit 审计库选择、yolo 前提、L2 拒绝语义、模型不调用工具 | 见 [02 §5] | 上午报告 3 个假 P0 | 已修并复跑 |
| T-2 | 测试缺陷（已修） | `test_syscall_audit.py` 两条单测依赖宿主无内核观测器 | 未 monkeypatch `kernel_observer_status` | 在装有 observer 的机器上失败 | 已加隔离 |

## 4. 已验证通过的安全语义清单

1. **判权先于执行**：normal 模式 `check_permission` 审计 seq 恒小于工具执行 seq（HOOK-03）。
2. **DENY 真实阻断并透传**：L4 能力 DENY → 工具零执行 → run `failed` + `security_denied` + 可定位 details（ERR-01）。
3. **CONFIRM 真实挂起**：审批前不执行；reject 不执行；approve 恰执行一次；重复决策 409（CAP-02-CONFIRM）。
4. **YOLO 只旁路判权/配额且逐次审计 `mode=yolo`**，DLP、caller binding、审计不旁路；管理面切换即时生效可恢复（YOLO-01、SC-01 审计）。
5. **DLP 中央 BLOCK 在 normal 下终止 run**，L3/L4 强制脱敏、Skill 文本不外发（DLP-04 阻断步、SKILL-01）。
6. **Token 配额三分支**：within → 计量；`deny` → 模型调用前拒绝；`pause_and_notify` → HITL 超时失败（TOKEN-02/03、TOK-HITL）。
7. **seccomp 12 条 mandatory denylist 在 Worker 及其子进程生效**（`finit_module → EPERM`，`Seccomp=2`）。
8. **身份不可伪造**：D-Bus sender、UDS SO_PEERCRED、lease 四元组、伪造 Commit/Abort 全部拒绝并审计。
9. **审计哈希链连续、按月分段、WebUI `intact:true`**。
10. **非法输入不落库**：syscall 名/架构、网络 mode、`on_exceed`、DLP action/pii 全部明确拒绝；网络策略应用失败自动回滚。

## 5. 故障注入：P0-06 securityd 不可达

执行 `evidence/faults/p0-06-securityd-down.sh`（19:31:58–19:32:35），结果 **PASS（fail-closed by construction），附带 2 个新发现**。

| 步骤 | 观测 |
|---|---|
| 停止前 | 三服务 active；Worker PID 2665040，instance `…60da742702894898be101e51ed5791c1` |
| `systemctl stop bianbu-securityd` | Runtime unit 因 `Requires=bianbu-securityd.service` 同步停止（journal `Stopping bianbu-agent-runtime@bianbu …Finished server process`），WebUI 同步停止；三者 `inactive` |
| 停机期间 | `curl :9899` 连接拒绝（http=000）；`/run/bianbu/securityd.sock` 不存在；总线名无占用；WebUI 8788 连接拒绝；审计 `runtime.worker_stop control runtime close`（seq 891） |
| 启动三服务 | 25s 后全部 active（含 syscall-observer）；`GET /api/v1/agents` 200 |
| 新 Worker | PID 2725611，instance `…2c7f160ea8f04fc8986c22b38484c063`（**与旧不同**），新 scope `bianbu-agent-com.bianbu.runtime-22b38484c063.scope`，`Seccomp=2 NoNewPrivs=1`；审计 `runtime_prepare_start → runtime_commit_start → runtime.worker_spawn pid=2725611;backend=host-process`（seq 898–900） |
| 恢复后 smoke | 新 session run `completed`，回复"好"（`evidence/faults/p0-06-post-recovery.txt`） |
| 旧身份不复用 | lease DB 新增第 4 条 `committed` lease；旧 lease 未被复用 |

新发现：

| # | 严重度 | 现象 | 说明 |
|---|---|---|---|
| D-9 | P2 | `runtime_instance` 表中 3 条历史实例（PID 2665040/2663960/2389566 均已不存在）仍为 `state=running`、`audit_ended_ns=0` | Worker 正常停止（`runtime.worker_stop`）或 Runtime 重启后 securityd 侧实例记录未收敛为 stopped/revoked；`authorize_worker` 靠 PID/cgroup 匹配所以不构成越权，但 `ListRuntimeInstances`/状态页会长期显示幽灵实例，孤儿回收证据不成立（对应方案 RT-02/RT-05） |
| D-10 | P2 | 重启后 `seccomp.policy_version=2, applied_policy_version=0, pending_restart=true` 仍未清零 | `mark_applied` 只在 `build_sandbox_policy`（bwrap 路径）调用；host-process 后端的 Worker 不消费版本化 syscall 策略，`agent_additions` 在 host 模式下不会生效，状态页 `pending_restart` 永远为 true |

## 6. 状态恢复核对

验收结束时核对：Agent `com.bianbu.c6f40f30a6e5` 模式 `yolo`（初始）、Token 配额 100000/500000/`pause_and_notify`（初始默认）、网络策略 `allow_all`、`system.execute/network.access granted=1`、临时 testkit Agent 已注销、DLP 临时策略已删除；syscall 策略 `agent_additions=[]`，`policy_version` 由 0 → 2 且 `pending_restart=true`（SC-02 探针副作用；P0-06 重启 Worker 后**并未**清零，见 §5 D-10）。

## 7. 未覆盖与后续建议

| 项 | 说明 |
|---|---|
| bwrap 后端生产 Worker | 当前部署 `requested_mode: host`；建议在 Worker 上切 `sandbox` 复跑 P0-03、SC-01、NET-01（bwrap 走 `restart_required` 路径） |
| NET-02 learning 采集 | 阻塞于 D-6 |
| 生产签名包 | 需 `DEB_DEMO=0` 构建后复验 CODE-01/SIG-01 与 WebUI 鉴权 |
| RES-01/02 并发与资源限制、REL-01 长稳 | 未执行 |
| Runtime 插件 8 hook 单元测试 | 目前仅 before_tool 有 2 条；建议补齐（含 D-1 回归断言） |
