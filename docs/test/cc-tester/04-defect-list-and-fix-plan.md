# cc-tester 缺陷梳理与修复方案

| 项 | 内容 |
|---|---|
| 文档编号 | BN-SEC-CCT-004 |
| 版本 | 1.0 |
| 日期 | 2026-09-11 |
| 来源 | [03 端到端验收报告](03-e2e-acceptance-report-20260911.md) §3、§5 |
| 修复分支 | 两仓同名 `fix/cc-tester-defects`，worktree 位于 `../worktree/bianbu-agent-security-cc-tester-fix` 与 `../worktree/bianbu-agent-runtime-cc-tester-fix` |
| 验证基线 | Worker `10.0.90.243`，方案见 [02](02-e2e-delivery-test-plan-and-cases.md) §7 |

分级原则：**必须解决** = 安全语义与设计声明不一致，或让核心功能在正式布局下不可用；**其它问题** = 状态/展示/一致性缺陷，不影响阻断与授权正确性。每项给出：现象、根因（代码位置）、影响、修复方案、验证方式。

## 一、必须解决

### M-1（D-1，P1）Worker UDS 数据面请求缺少 Runtime 安全身份，被 securityd 拒绝

| 项 | 内容 |
|---|---|
| 现象 | 每次真实 run，securityd journal 出现 `handler dlp.scan / dlp.policy / audit.batch 异常 … PermissionDenied: Worker 未通过已提交 Runtime lease 身份校验`；审计无 `uds_dlp_scan`、无 `uds_audit_batch hook_payload:input`。testkit DLP-04 后三步 FAIL |
| 根因 | Runtime 插件 `.bianbu-agent/plugins/bianbu.security/lib/uds_transport.py:34-38` 的 `SecurityUdsTransport._worker_identity` 只包含 `_worker_instance_id`、`_worker_lease_id`。securityd `uds_handlers._require_agent`（`uds_handlers.py:37-62`）用 `_worker_security_agent_id or agent_id` 调 `runtime_engine.authorize_worker`；缺省时用逻辑 Agent `com.bianbu.c6f40f30a6e5` 查 lease，而 lease 归属 `com.bianbu.runtime`，匹配失败。对照 securityd 自带客户端 `client/bianbu_security_client.py:_worker_uds_call` 会附带 `_worker_security_agent_id`（来自 `BIANBU_WORKER_SECURITY_AGENT_ID`），因此 Skill DLP 路径的 46 条 `uds_dlp_scan` 成功 |
| 影响 | 中央 DLP 策略只能经 `HybridDLPPolicyStore` 缓存/本地库回退读取；>4KB 文本在 Worker 进程内扫描；>1KB 完整治理载荷不进 securityd 审计链（ARCH-01 承诺失效）。fail-safe 仍阻断，但"中央策略权威 + 完整审计"两条设计目标未达 |
| 修复（Runtime 仓） | `lib/uds_transport.py`：`_worker_identity` 增加 `"_worker_security_agent_id": os.environ.get("BIANBU_WORKER_SECURITY_AGENT_ID", "")`；同时把 `worker_identity` 构造抽成与 `bianbu_security_client._worker_uds_call` 相同的三元组，避免再次分叉。可选：securityd `_require_agent` 在缺 `_worker_security_agent_id` 时记一条 `caller_identity` 审计说明缺字段，便于定位 |
| 验证 | testkit `DLP-04` 五步全 PASS；securityd journal 无 `PermissionDenied`；新增 Runtime 单测 `tests/runtime/test_security_uds_transport.py`：断言 managed 环境下请求含三个身份字段 |

### M-2（D-2，P1）Token 会话计数 `conv_used` 永不重置，normal 模式下必触发配额审批

| 项 | 内容 |
|---|---|
| 现象 | `GetTokenBudget.conv_used` 自 securityd 启动起单调累计（225k → 518k），默认 `limit_per_conversation=100000` 被永久越过；normal 模式下每个 run 在模型调用前进入 `quota_approval_requested`，60s 超时后 `TOKEN_BUDGET_APPROVAL_TIMEOUT`。yolo 下 `GetTokenBudget` 把上限报 0，掩盖问题 |
| 根因 | securityd `token_meter.py:_Counter.conv_used` 为进程内按 Agent 累加的计数器；`reset_conversation()`（`token_meter.py:165`）在两仓均无调用方。`MeterTokensV2`（`service.py:736`）虽然强制 `session_id/run_id`，但 `engine.meter_tokens` 不按 session 分桶。Runtime `_token_budget_preflight`（`engine.py:379-460`）读取的是这个跨会话累计值 |
| 影响 | "单次对话配额"语义不存在；normal 模式 Agent 在生产上不可用（每次 run 卡审批） |
| 修复（Security 仓为主） | 1) `TokenMeter` 计数器改为 `(agent_id, session_id)` 分桶：`meter(agent_id, tokens, scope, session_id="")` 与 `get_budget(agent_id, session_id="")`；无 session 时沿用旧行为（兼容 `MeterTokens` v1）。2) `engine.meter_tokens_v2` 透传 `session_id`；`GetTokenBudget` 增加可选 `context`（新增 `GetTokenBudgetV2(agent_id, context)`），Runtime 预检改用 V2 传 `session_id`。3) 会话桶 LRU/TTL 回收（如 24h 或上限 1000 个）。4) `GetTokenBudget` 在 yolo 下保留真实 `limit_*` 并新增 `effective_unlimited: true` 字段，而不是把上限改写为 0 |
| 修复（Runtime 仓） | `_token_budget_preflight` 改用 `get_token_budget_v2(agent_id, {"session_id", "run_id"})`，client 缺方法时回退 v1；同步 `client/bianbu_security_client.py` 新增封装 |
| 验证 | 新增 securityd 单测：两个 session 各自计数、互不影响、超限只影响本 session；testkit `TOKEN-03` 保持 PASS，新增 `TOKEN-04`：normal 下连续两次 run 不触发 `quota_approval_requested`；testkit `enforcing_mode` 的临时抬高配额可在修复后移除 |

### M-3（D-6，P1）网络策略热应用被 polkit 拒绝，deny_all / whitelist / learning 在运行期不可用

| 项 | 内容 |
|---|---|
| 现象 | D-Bus `SetNetworkPolicy(agent, [], deny_all)` 与 Runtime `network-policy.update.v1` 均返回 `PermissionDenied: Command ['systemctl','set-property','--runtime','bianbu-agent-…scope','IPAddressDeny=any'] returned non-zero exit status 1`；切 `learning` 同样失败。securityd 正确回滚注册表到 `allow_all` |
| 根因 | securityd 以 `bianbu-security` 用户执行 `client/runtime_launcher.py:139 update_runtime_network → systemctl set-property --runtime <scope>`（`scope=system`）。polkit 动作 `org.freedesktop.systemd1.manage-unit-files`/`manage-units` 需 `auth_admin`；Runtime 仓 `debian/bianbu-agent-runtime.polkit`（安装为 `60-bianbu-agent-runtime.rules`）只放行 **Runtime 所有者进程** 对 `bianbu-agent-*.scope` 的 `start/stop/kill/restart/reload/reset-failed`，未覆盖 `set-property`，也未覆盖 `bianbu-security` 用户。手工以 `bianbu-security` 执行同命令得到 `Access denied … requires interactive authentication` |
| 影响 | 管理员无法在运行期收紧网络（deny_all/白名单），学习模式无法开启，NET-02 无法验证；仅新 Worker 启动时能带上策略 |
| 修复方案（推荐 A） | **Security 仓** 新增 polkit 规则 `debian/io.bianbu.securityd.rules`（安装到 `/usr/share/polkit-1/rules.d/61-bianbu-securityd.rules`）：`action.id == "org.freedesktop.systemd1.manage-units"` 且 `subject.user == "bianbu-security"` 且 `subject.system_unit == "bianbu-securityd.service"` 且 `unit` 匹配 `^bianbu-agent-[A-Za-z0-9_.-]+\.scope$` 且 `verb == "set-property"` → `YES`；其它 NOT_HANDLED。`debian/rules` 安装该文件；`tests/unit/test_install_flow.py` 加断言 |
| 备选 B | securityd 不直接改 unit，而是把 apply 委托 Runtime：`SetNetworkPolicy` 只落库并发 D-Bus 信号 `NetworkPolicyChanged(agent_id, version)`，Runtime `ExecutionCoordinator.apply_network_policy` 用自身 polkit 授权执行 `set-property` 并回报 `ReportNetworkApply`。改动面大，建议二期 |
| 验证 | 手工探针 NET-01：`deny_all` 后 `systemctl show <scope> -p IPAddressDeny` 为 `any`，Worker 内 `curl` 失败；恢复 `allow_all` 后 smoke 通过；`learning` 可开启且 `GetNetworkLearningStatus.state=active`（打通 NET-02）。testkit 新增 `NET-01` 自动化项（含 finally 恢复） |

### M-4（D-9，P2 → 提级为必须）Worker 停止后 securityd 侧 lease 实例不收敛，幽灵 `running`

| 项 | 内容 |
|---|---|
| 现象 | `runtime_instance` 中 3 条历史实例（PID 2665040/2663960/2389566 均已不存在）仍 `state=running, audit_ended_ns=0`；P0-06 重启后新增第 4 条，旧的未收敛。`ListRuntimeInstances` 与 `GetSecurityExecutionStatus` 会长期展示幽灵实例 |
| 根因 | Runtime `ExecutionCoordinator.stop`（`execution_runtime.py:2033`）只停 backend/collector、写 `runtime.worker_stop` 审计，**不通知 securityd**；只有 `revoke()`（`:2088`）才调 `revoke_agent`，且 `RevokeAgent` 按 Agent 整体撤销所有 lease，粒度过粗，正常停止不能用。securityd `runtime/lease.py` 只有 `failed`（`:192`）与 `revoked`（`:204`）两种收敛路径，无"正常停止"状态，也无启动期 PID 存活校验 |
| 影响 | 孤儿回收（RT-02/RT-05）证据不成立；`authorize_worker` 靠 PID/cgroup 精确匹配所以暂不构成越权，但 `syscall` 事件按 cgroup 归属时可能匹配到幽灵实例；状态面误导运维 |
| 修复（Security 仓） | 1) `io.bianbu.Security.Runtime` 新增 `StopInstance(lease_id, instance_id, reason) → b`：校验 caller 为 Runtime 身份且 lease/instance 匹配，置 `runtime_instance.state='stopped'`、`audit_ended_ns=now`，lease 置 `stopped`；审计 `runtime_instance_stop`。2) securityd 启动时 `LaunchLeaseStore.reap_dead()`：对 `state='running'` 且 `/proc/<pid>` 不存在或 cgroup 不匹配的实例置 `state='lost'` 并审计。3) client 新增 `stop_runtime_instance()` |
| 修复（Runtime 仓） | `ExecutionCoordinator.stop` 在 backend 停止后调用 `security_client.stop_instance(lease_id, instance_id, reason)`（客户端无该方法时降级为记录 warning，不阻塞停止）；`_start_prepared` 的 Commit 后失败路径保持 `revoke_agent` |
| 验证 | 停止 Worker 后 `ListRuntimeInstances` 无 `running` 幽灵；securityd 重启后 DEAD PID 实例变 `lost`；testkit CONN-03 方法数断言 +1；新增 securityd 单测 `test_runtime_lease.py::test_stop_instance_and_reap` |

## 二、其它问题

### O-1（D-3，P2）seccomp 拦截未进入 syscall 审计链，状态却报 `active`

| 项 | 内容 |
|---|---|
| 现象 | Worker 内 `finit_module → EPERM` 后 `GetSyscallAuditEvents=[]`、`events=0`、`/run/bianbu-syscall-audit/events.jsonl` 0 行；`GetSyscallAuditStatus` 仍 `status=active coverage=deny-only` |
| 根因 | Runtime 只在 bwrap 路径注入 `BIANBU_SECCOMP_AUDIT_FILTER`（`execution_runtime.py:1291`），且 `kernel_seccomp_log=decision.effective_mode == "sandbox"`（`:1952`）；host-process 后端的 seccomp 过滤器不带 `SECCOMP_FILTER_FLAG_LOG`，内核 `audit_seccomp` 不会为 `RET_ERRNO` 产生记录，观测器无事件。securityd `SyscallAuditStore.status()` 只看观测器心跳，不看是否有 host 实例未开启日志 |
| 修复 | Runtime：host-process 后端也调用 `seccomp_audit.enable_filter_logging`（`_launch_systemd` 传入 seccomp 文件时同样设置 LOG flag），`kernel_seccomp_log` 改为按后端能力判断；securityd：`status()` 返回 `coverage` 时区分 `deny-only(all)` / `deny-only(sandbox-only)`，存在未开启日志的 running host 实例时降为 `degraded` 并给 reason |
| 验证 | SC-01 探针复跑后 `GetSyscallAuditEvents` 出现 `finit_module` 事件，含 instance/lease/cgroup；哈希链校验 true |

### O-2（D-4，P2）Runtime 状态接口与 securityd 执行状态均不反映运行中的 Worker

| 项 | 内容 |
|---|---|
| 现象 | `/api/v1/runtime/status` 在 Worker 运行时返回 `instance_id/pid/effective_mode/backend=null, sandboxed=false, seccomp={}, audit={}`；securityd `GetSecurityExecutionStatus.worker.state=unknown` |
| 根因 | Runtime `server/runtime.py:1125 runtime_status()` 的 Worker 字段写死 `None/False`（`:1137`），未从 `AgentWorkerPool` 取当前实例；securityd `get_security_execution_status` 未查 lease DB 的 running 实例 |
| 修复 | Runtime：从 `AgentWorkerPool` 读取当前 `ExecutionRecord`（instance_id、pid、effective_mode、backend、sandboxed、seccomp profile digest/policy_version）填充；securityd：`worker.state` 由 `leases.active_instances(agent)` 推导（running/stopped/lost），附 instance_id/pid/backend |
| 验证 | API-02 探针：两处状态与 `/proc/<pid>` 与 lease DB 一致；Runtime 单测 `test_service.py` 补断言 |

### O-3（D-10，P2）host-process 后端不消费版本化 syscall 策略，`pending_restart` 永远为 true

| 项 | 内容 |
|---|---|
| 现象 | `SetAgentSyscallPolicy` 后 `policy_version=2, applied_policy_version=0, pending_restart=true`，Worker 重启后仍不清零 |
| 根因 | `syscall_policy.mark_applied` 只在 `engine.build_sandbox_policy`（`engine.py:377`，bwrap 路径）调用；host-process Worker 的 seccomp 来自 `PrepareStart` 策略 `seccomp_profile.path`，该路径生成时未 `mark_applied`，`agent_additions` 也未编进 host 过滤器 |
| 修复 | securityd `runtime/engine.prepare_start` 生成 `seccomp_profile` 时统一走 `seccomp_builder.build_policy_file(agent, arch, snapshot.effective)` 并 `mark_applied(agent, arch, version)`；返回 `policy_version` 给 Runtime 写入 attestation。这样 host/bwrap 两后端的追加 denylist 与版本状态一致 |
| 验证 | SC-02：追加 `bpf` → 重启 Worker → `applied_policy_version==policy_version, pending_restart=false`；Worker 内 `syscall(bpf)` 返回 EPERM |

### O-4（D-5，交付配置）demo 包关闭 WebUI 鉴权与代码签名；端口契约不一致

| 项 | 内容 |
|---|---|
| 现象 | unit drop-in `BIANBU_WEBUI_DEMO=1 / AUTH=0` 覆盖 `/etc/bianbu/webui.env` 的 `AUTH=1`；`BIANBU_SECURITY_CODESIGN=off`；WebUI 实际 8788 而文档/testkit 默认 8787，且 8787 被 agentforce 旧进程占用 |
| 修复 | 不改代码语义，改交付：CI 增加 `DEB_DEMO=0` 产品包构建产物；`testkit/engine.py` 默认 `BNSEC_SECURITY_WEBUI_BASE` 改为读 `/etc/bianbu/webui.env` 的 `BIANBU_WEBUI_PORT`；`docs/test/*` 与 `testkit/README.md` 端口说明改为"以 webui.env 为准"；Worker 清理 8787 旧进程属运维项 |
| 验证 | `DEB_DEMO=0` 包上 `/api/auth` 未带 token 返回 401；CODE-01 用生产密钥验证 |

### O-5（D-7，P3）`security_denied.details.risk_level` 写死 L3

| 项 | 内容 |
|---|---|
| 现象 | `system.execute` 注册为 L4，拒绝 details 报 `risk_level=L3` |
| 根因 | Runtime `security_middleware.py:152 _SecurityPolicyDenied.__init__` 写死 `self.risk_level = "L3"` |
| 修复 | `securityd_requires_confirm` 已有能力名，查 `capability_catalog`/`GetCapabilities` 缓存取 `risk_level` 传入；取不到再回退 L3 |
| 验证 | ERR-01 增加断言 `details.risk_level == "L4"` |

### O-6（D-8，P3）`GetAgentInfo` 对未注册 Agent 返回默认配置而非错误

| 项 | 内容 |
|---|---|
| 根因 | `engine.get_agent_info`（`engine.py:318`）无注册校验，`token_budget` 用默认值填充 |
| 修复 | 增加 `registered: bool` 字段；`manifest is None and capabilities == []` 时 `registered=false` 且 `token_budget=null`；WebUI 与 Runtime `agents.get.v1` 据此展示"未注册" |
| 验证 | API-01 探针；`test_webui_api.py` 补用例 |

### O-7（R13 残留，P3）未映射工具处置的历史尾巴

| 项 | 内容 |
|---|---|
| 现象 | Runtime 插件 `lib/mapping.py:72` 仍导出已弃用 `DEFAULT_ALLOW`；`:234` docstring 写"交调用方按 DEFAULT_ALLOW 处理"；`BIANBU_SECURITY_UNMAPPED=allow` 可一键恢复全放行且生产模式不拦 |
| 修复 | 删除 `DEFAULT_ALLOW` 导出与 docstring 旧语义；`BIANBU_RUNTIME_MODE=production` 下忽略 `BIANBU_SECURITY_UNMAPPED=allow` 并告警（与 `BIANBU_SECURITY=0` 同等处理）；补 unmapped=confirm/deny 分支单测 |
| 验证 | CAP-04 保持 PASS；新增单测 |

### O-8（测试资产）testkit 与单测的后续整理

| 项 | 内容 |
|---|---|
| 内容 | M-2 修复后移除 `Ctx.enforcing_mode(lift_budget=True)` 的配额抬高逻辑；把手工探针 SC-01 / CAP-02-CONFIRM / NET-01 / P0-06 收编为 testkit 正式项（SC-01、CONFIRM-01、NET-01、FAULT-01），`CONN-03` 方法数随 `StopInstance`/`GetTokenBudgetV2` 更新；testkit README 补充 yolo 默认与 normal 前提 |

## 三、修复顺序与工作量

| 序 | 项 | 仓 | 预估 | 依赖 |
|---|---|---|---|---|
| 1 | M-1 UDS 身份字段 | Runtime（插件 1 行 + 单测） | 0.5 天 | — |
| 2 | M-3 polkit 规则 | Security（debian + 单测） | 0.5 天 | Worker 上需重装包或手工放规则复验 |
| 3 | M-2 会话级 Token 计数 | Security（meter/engine/service/client）+ Runtime 预检 | 2 天 | 两仓协议新增 `GetTokenBudgetV2` |
| 4 | M-4 StopInstance + reap | Security（Runtime 接口/lease/client）+ Runtime stop 路径 | 2 天 | 两仓协议新增 |
| 5 | O-3 版本化策略统一 | Security | 1 天 | 与 O-1 一起验 SC-01/SC-02 |
| 6 | O-1 host 后端 seccomp LOG + 状态降级 | Runtime + Security | 1 天 | — |
| 7 | O-2 状态接口 | Runtime + Security | 1 天 | M-4 提供 stopped/lost 状态 |
| 8 | O-5 / O-6 / O-7 | 各 0.5 天 | — |
| 9 | O-4 交付配置 + O-8 测试收编 | Security | 1 天 | 全部修复后复跑 [02] 全量 |

按 AGENTS.md：Runtime 仓（`../personal-agent` / `bianbu-agent-runtime`）只本地 commit，不 push；Security 仓修完后走 `bianbu/<版本>` tag 发布流程，且不自动提高 Runtime 对 securityd 的最低依赖版本（新增 D-Bus 方法在 Runtime 侧做 `hasattr` 降级）。
