# cc-tester 缺陷修复与复验报告（2026-09-11）

| 项 | 内容 |
|---|---|
| 文档编号 | BN-SEC-CCT-005 |
| 版本 | 1.0 |
| 修复分支 | 第一批（D-1~D-10）已合入两仓 main（Security `06a9431`，Runtime `faeaf93b`）；第二批 R-1/R-2 在 Security `c08a97a`+`f7c7da1`、Runtime `ebaf0df8`，未合并 |
| worktree | `../worktree/bianbu-agent-security-cc-tester-fix`、`../worktree/bianbu-agent-runtime-cc-tester-fix` |
| 复验环境 | Worker `10.0.90.243`，两轮原生构建 + `dpkg -i` 覆盖安装 + systemd 重启 |
| 复验包 | `bianbu-agent-securityd_0.1.28_riscv64.deb` `aeb7934b…e00f`；`bianbu-agent-runtime_0.1.27_riscv64.deb` `717195a1…2de3`（版本号未变，源码为修复分支 HEAD） |
| 依据 | [04 缺陷梳理与修复方案](04-defect-list-and-fix-plan.md) |
| **结论** | **4 项必须解决（M-1~M-4）与 8 项其它问题（O-1~O-8）中除交付配置项 O-4 的生产包构建外全部修复并实机验证；testkit 37/37 通过；无新增回归。** |

## 1. 复验结果总览

| 层 | 修复前（[03]） | 修复后 round 2 | 证据 |
|---|---|---|---|
| Runtime 定向回归（13 文件） | 185 | **224 passed** | `evidence/fix-round/runtime-targeted.log` |
| securityd 定向回归（11 文件） | 41 | **170 passed** | `evidence/fix-round/security-targeted.log` |
| securityd 全量 unit（本地） | 707 passed / 24 failed（环境：flask、dbus ABI） | 721 passed / 23 failed（同一组环境失败，少 1 是新增用例） | 本地 |
| testkit 全量 | 35/37 | **37/37 passed** | `evidence/fix-round/testkit-run2-report.json` |
| 手工探针 | NET-01 FAIL、SC-03 FAIL、API-02 PARTIAL | 全部 PASS | `evidence/fix-round/round2.log`、`round1-*.log` |

## 2. 逐项缺陷闭合

| 缺陷 | 修复位置 | 实机验证（round 1 / round 2） | 状态 |
|---|---|---|---|
| **M-1 / D-1** UDS 缺 `_worker_security_agent_id` | Runtime `plugins/bianbu.security/lib/uds_transport.py`：`managed_worker_identity()` 三元身份 | 安装后 securityd journal `handler dlp/audit 异常` = 0；审计新增 `uds_dlp_scan` 25 条、`uds_audit_batch` 2 条；testkit DLP-04 五步全 PASS | 闭合 |
| **M-2 / D-2** `conv_used` 永不重置 | securityd `token_meter` 按 `(agent, session)` 分桶 + LRU；D-Bus `GetTokenBudgetV2`；UDS `token.meter/budget` 读 `session_id`；Runtime 预检用 v2 回退 v1 | normal 模式连续两次 run `completed`、0 次配额审批；`GetTokenBudgetV2(session)` 返回 `conv_used=0`；TOKEN-03 同会话两次 run 第二次 `TOKEN_BUDGET_EXCEEDED` + `quota_denied` | 闭合 |
| **M-3 / D-6** 网络策略 polkit 拒绝 | securityd 新增 `deploy/io.bianbu.securityd.rules` → `/usr/share/polkit-1/rules.d/61-bianbu-securityd.rules` | `SetNetworkPolicy deny_all → true`，scope `IPAddressDeny=::/0 0.0.0.0/0`；恢复 `allow_all` 后清空 | 闭合 |
| **M-4 / D-9** lease 实例不收敛 | securityd `StopInstance` D-Bus 方法 + `reap_dead()` 启动收敛；Runtime `ExecutionCoordinator.stop` 调用 `stop_instance` | 重启后 journal `4 个 running 实例的进程已不存在，已标记 lost`；lease DB 仅 1 条 running；round 2 再收敛 1 条 | 闭合 |
| **O-1 / D-3** seccomp 拦截不进审计链 | Runtime host 后端注入 `BIANBU_SECCOMP_AUDIT_FILTER`，Worker 装载策略过滤器 + LOG；attestation 声明 `kernel_seccomp_log`；securityd `status()` 对未开日志实例降 `degraded` | Worker `Seccomp_filters: 3`；`finit_module → EPERM` 后 `GetSyscallAuditEvents` 有事件（seq 2，含 instance/lease/policy_version）；状态 `active/deny-only/chain_valid`；round 1 attestation 缺字段时正确报 `degraded(logged-instances-only)` | 闭合 |
| **O-2 / D-4** 状态接口不反映 Worker | securityd `worker` 由 lease DB 推导 | `worker.state=running` 含 instance/lease/pid/cgroup/backend | 闭合（Runtime `/api/v1/runtime/status` 侧沿用原 `worker_supervisor` 快照，未改） |
| **O-3 / D-10** host 不消费版本化策略 | securityd `build_seccomp_profile()`，`policy.py` host 分支调用；过滤器按 `worker_agent_id` 生成/标记 | round 1 仍 `applied=0`（按 lease 主体标记）→ round 2 `policy_version=2, applied_policy_version=2, pending_restart=false` | 闭合 |
| **O-5 / D-7** `risk_level` 写死 L3 | Runtime `_SecurityPolicyDenied` 取能力登记 | 单测覆盖；testkit ERR-01 PASS | 闭合（实机 details 未单独核对 L4） |
| **O-6 / D-8** 未注册 Agent 返回默认值 | securityd `get_agent_info` 增加 `registered` | `GetAgentInfo(com.bianbu.does.not.exist)` → `registered:false, token_budget:null, network:null` | 闭合 |
| **O-7** `DEFAULT_ALLOW` 残留 | 删除导出；生产模式忽略 `BIANBU_SECURITY_UNMAPPED=allow`（两侧） | testkit CAP-04 新增一致性断言 PASS | 闭合 |
| **O-4 / D-5** demo 包配置 | testkit WebUI 端口自动读 `webui.env` | 测试侧闭合；`DEB_DEMO=0` 生产包未构建 | 部分（交付配置项，非代码） |
| **O-8** 测试资产收编 | testkit `run_prompt` 支持会话复用、CONN-03 +1、HOOK-04/CAP-04 适配 | 37/37 | 闭合（手工探针 SC-01/CONFIRM/NET-01/P0-06 仍为脚本，未收编为 testkit 项） |

## 3. 两轮迭代记录

**Round 1**（23:12）：安装首批修复包。D-1/D-2/D-4/D-6/D-8/D-9 立即闭合；发现三处尾巴：
- D-10 `applied_policy_version` 仍 0：过滤器按 lease 主体 `com.bianbu.runtime` 标记，管理员按逻辑 Agent 查询。
- `GetSyscallAuditEvents(逻辑 Agent)` 为空：事件 `agent_id` 为 lease 主体。
- testkit HOOK-04/CAP-04 `ImportError: DEFAULT_ALLOW`；TOKEN-03 因会话级语义首个 run 用量为 0 不再触发 deny。

**Round 2**（23:23）：按 `worker_agent_id` 生成/标记过滤器；审计 query 同时匹配 `worker_agent_id`；testkit 适配。全部通过。

## 4. 协议变更与兼容性

| 变更 | 兼容处理 |
|---|---|
| D-Bus 新增 `io.bianbu.Security.GetTokenBudgetV2(s, a{sv})` | Runtime 用 `getattr` 探测，旧 daemon 回退 `GetTokenBudget` |
| D-Bus 新增 `io.bianbu.Security.Runtime.StopInstance(sss)` | Runtime 调用失败仅 warning，不阻塞停止 |
| UDS `token.meter` / `token.budget` 可选 `session_id` | 空值保留旧 agent 级语义 |
| `GetAgentInfo` 新增 `registered`，未注册时 `token_budget/network=null` | WebUI 读取处需容忍 null（未改 WebUI） |
| `GetSyscallAuditStatus` 新增可选 `unlogged_instances` | 仅在降级时出现 |
| attestation 新增 `kernel_seccomp_log` | securityd 缺字段视为未开日志 |
| 新 polkit 规则文件 | 仅在 DEB 安装时生效；源码启动的开发态 securityd 不受影响 |

按 AGENTS.md 约定：未提高 Runtime 对 `bianbu-agent-securityd` 的最低依赖版本；Runtime 仓只本地 commit。

## 5. 未完成与后续

| 项 | 说明 |
|---|---|
| `DEB_DEMO=0` 生产包复验签名与 WebUI 鉴权 | 需另行构建 |
| Runtime `/api/v1/runtime/status` Worker 字段 | 仍来自 `worker_supervisor.status_snapshot()`；实机该接口在 Worker 运行时的表现未重新核对 |
| WebUI 对 `token_budget=null` 的展示 | 未改前端 |
| 手工探针收编为 testkit 正式项 | 未做 |
| securityd 全量 unit 中 23 项本地失败 | 均为本机缺 flask / dbus-python ABI 的既有环境问题，与 main 一致 |
| 两仓合并与发布 | 待评审：Security 走 `bianbu/<版本>` tag；Runtime 仅本地 |

## 6. 第二批：R-1 / R-2 干预点 handler 异常与超时（round 3，2026-09-12 01:02）

| 项 | 修复 | 验证 | 状态 |
|---|---|---|---|
| R-1 handler 异常 = 放行 | securityd `interceptor.py`：异常按 `on_error`（block/confirm/allow）处置，默认 confirm；`sec_capability` 与 8 个 `dlp_*` 注册为 block，`audit` 为 allow；BLOCK 带 `reason=handler_error`、`failed_handler`、`handler_errors`；生产模式忽略 `BIANBU_HOOK_ON_ERROR=allow` | 单测 10 条（`test_interceptor.py`）；securityd 全量 unit 730 passed（23 项环境失败与 main 相同） | 闭合（代码级） |
| R-2 handler 无超时 | 单 handler 超时默认 12s（`BIANBU_HOOK_HANDLER_TIMEOUT`，0 关闭），线程池限时执行，超时视同故障并在 trace 标 `TIMEOUT` | 同上（超时 0.2s 用例实测 <0.9s 返回） | 闭合（代码级） |
| Runtime 侧 | `before_tool` 把 `handler_error/handler_timeout` 的 BLOCK 与 `denied` 同等硬拒绝，不进"不可达降级" | `test_security_tool_mapping.py` +2；Runtime 定向 370 passed | 闭合 |
| 实机回归 | 重装 round-3 包（securityd `64e4a197…27a7`，runtime 0.1.29 `e291458c…cf11`）后 testkit 全量 **36/37**，唯一失败 TOKEN-03 为测试假设（上限 1 时首个 run 两轮模型调用即在 run 内被拒，产品行为正确）；修正断言后 TOKEN-03/TOKEN-02/HOOK-03 复跑 3/3 | `evidence/fix-round/round3.log`、`testkit-run3-report.json`、`testkit-run3b-report.json` | 无回归 |

实机无法注入 handler 崩溃/挂死（`BIANBU_HOOK_*` 不在 Worker unit 的环境 allowlist），故障路径由单测覆盖；hook 审计 trace 格式未变（`dlp_input@0.7=ALLOW`），故障时新增 `ERROR:`/`TIMEOUT:` 标记。

注意：round 3 结束时 Agent 网络策略为 `learning`，非本轮脚本所设（另一会话验收遗留），未改动。
