# Bianbu Agent Runtime × Security 端到端交付测试方案与测试用例

| 项 | 内容 |
|---|---|
| 文档编号 | BN-SEC-CCT-002 |
| 版本 | 1.0 |
| 日期 | 2026-09-11 |
| 状态 | 已按本方案执行一轮，结果见 [03 验收报告](03-e2e-acceptance-report-20260911.md) |
| 测试对象 | `bianbu-agent-runtime`（0.1.27，commit `5d41abe0`）+ `bianbu-agent-securityd`（0.1.28，commit `05921e6`） |
| 目标环境 | Worker `10.0.90.243`（K3 riscv64，正式 DEB 安装 + systemd） |
| 上游 | [01 功能与架构梳理](01-security-feature-inventory-and-status.md)；`docs/test/agent-runtime-security-delivery-test-plan.md`（BN-SEC-RUNTIME-TEST-001，本方案在其基础上修正测试入口、身份与 YOLO 前提并细化用例） |

## 1. 目标与原则

验证"Agent 从注册、lease 启动、运行、判权、DLP、配额到停止"的安全闭环在**正式安装布局**下真实生效。四条原则：

1. **断言落在外部可观测事实**：securityd 审计差分（`audit_record.seq`）、真实下游行为（工具是否执行、文件/网络是否变化）、HTTP/D-Bus/UDS 返回，不只看函数返回值。
2. **强制类用例必须在 normal 模式运行**。securityd 0.1.27+ 新 Agent 默认 `yolo`（判权/Confirm/Token 旁路仅审计）；测试临时切 normal，`finally` 恢复。
3. **测试侧缺陷与产品缺陷分开记**。2026-09-11 首轮 3 个"P0"实为测试读错审计库 / 未考虑 yolo，本方案已内置修正。
4. **BLOCKED/N/A 不写成 PASS**：demo 包（`DEB_DEMO=1`）关闭签名校验与 WebUI 鉴权、bwrap 未在生产 Worker 启用、OCI/egress broker 未交付，这些只能记为阻塞或不适用。

## 2. 环境契约（执行前必须核对）

| 项 | 实际值（2026-09-11） | 核对命令 |
|---|---|---|
| Runtime HTTP | `http://127.0.0.1:9899`（unit `bianbu-agent-runtime@bianbu.service`，User=bianbu，`BIANBU_RUNTIME_MODE=production`，`BIANBU_RUNTIME_SECURITY=required`） | `systemctl show bianbu-agent-runtime@bianbu.service -p Environment` |
| securityd | D-Bus system bus `io.bianbu.Security`（User=bianbu-security，PID 见 `busctl status`）；UDS `/run/bianbu/securityd.sock`（`srw-rw---- bianbu-security:bianbu-security`） | `busctl status io.bianbu.Security`；`stat /run/bianbu/securityd.sock` |
| Security WebUI | **`http://127.0.0.1:8788`**（`/etc/bianbu/webui.env` 覆盖 unit 默认 8787；8787 被 `/opt/bianbu-agentforce/server.py` 旧进程占用） | `ss -ltnp \| grep -E ':(8787\|8788)'` |
| WebUI 鉴权 | demo drop-in `BIANBU_WEBUI_DEMO=1` → `/api/auth` 返回 `auth_disabled:true` | `curl -s http://127.0.0.1:8788/api/auth -d '{}'` |
| 测试 Agent | 逻辑 Agent `com.bianbu.c6f40f30a6e5`（BibitEdgeAssistant，模型 minimax/MiniMax-M3）；Runtime 安全身份 `com.bianbu.runtime`；testkit 临时 Agent `<agent>.testkit*` | `curl -s :9899/api/v1/agents`；`busctl call ... ListAgents` |
| Worker 后端 | `host-process`（`config.yaml` `runtime.control.execution.requested_mode: host`），systemd scope `bianbu-agent-com.bianbu.runtime-*.scope`，`Seccomp=2`，`NoNewPrivs=1`，`CapEff=0` | `pgrep -f "role agent-worker"`；`/proc/<pid>/status` |
| 审计库 | 主链 `/var/log/bianbu/audit/YYYYMM.db`（表 `audit_record`）；`syscall-events.db`、`network-learning.db` 为独立库 | `sqlite3 ... .tables` |
| 内核观测器 | `bianbu-syscall-observer.service` active，spool `/run/bianbu-syscall-audit/status.json` | `systemctl is-active bianbu-syscall-observer` |
| 测试执行 Python | testkit 用系统 `python3`（3.14，含 `dbus`）；pytest 用 Runtime 构建 venv `debian/.bianbu-agent-build/venv`（含 `pytest-asyncio`） | — |
| 源码副本 | `/var/tmp/bnsec-delivery-20260911/{runtime,security}`（与被测 DEB 同源） | `git -C ... rev-parse HEAD` |

testkit 环境变量（正式布局下**必须显式**）：

```bash
export PA_ROOT=/var/tmp/bnsec-delivery-20260911/runtime
export BIANBU_SECURITYD_HOME=/usr/lib/bianbu-securityd
export PA_AGENT_ID=com.bianbu.c6f40f30a6e5 BIANBU_PA_AGENT_ID=com.bianbu.c6f40f30a6e5
export BNSEC_SECURITY_WEBUI_BASE=http://127.0.0.1:8788
export BNSEC_OUT=/var/tmp/bnsec-cc-tester-<date>/testkit/runN
cd /var/tmp/bnsec-delivery-20260911/security && python3 testkit/runner.py   # 不要跑 engine.py
```

## 3. 测试分层与入口

| 层 | 内容 | 入口 | 通过门槛 |
|---|---|---|---|
| L1 单元/契约回归 | Runtime 安全定向 9 个文件；securityd Runtime/syscall 定向 5 个文件 | `run-regressions.sh`（见 §7.1） | 全部 passed |
| L2 真实服务端到端（testkit） | 37 项：connectivity 3 / permission 12 / hook 5 / dlp 6 / token 3 / sandbox 5 / audit 3 | `python3 testkit/runner.py` | 见 §5 每项门槛 |
| L3 手工探针（真实 Worker） | P0-01 连通、P0-03 沙箱证明、RT-04 身份伪造、SC-01 seccomp deny、CAP-02 CONFIRM 审批、NET-01 deny_all、API-01/02 契约、P0-06 fail-closed | `probes/*.txt`、`cc_probes.py`（§7.2） | 见 §6 |
| L4 故障注入 | securityd 停止/恢复、collector 状态、伪造 lease | §6.8 | 高危一律拒绝，状态明确 |

## 4. 用例总览（ID → 层 → 优先级 → 门槛）

| ID | 层 | P | 测试点 | 通过门槛 |
|---|---|---|---|---|
| P0-01 | L3 | P0 | 服务/总线/UDS/HTTP 连通与版本 | 三服务 active，`io.bianbu.Security` 52 方法 + Runtime 接口 7 方法，UDS 权限正确 |
| CONN-01~03 | L2 | P0 | PA HTTP、securityd 占名、25 关键方法 | PASS |
| P0-02 / HOOK-02 | L2 | P0 | 最小正常 run | `run/completed`，审计含 `hook:agent_startup/input/pre_model_call/agent_shutdown` |
| P0-03 | L3 | P0 | Worker 沙箱/进程证明 | PID/cgroup/scope/Seccomp/NoNewPrivs/CapEff 与 lease `attestation_json` 一致 |
| PERM-01~04 | L2 | P0 | 注册、三态、L3/L4 禁 trusted、撤销 | PASS |
| HOOK-01 | L2 | P0 | 8 hook 加载启用 | PASS |
| HOOK-03 | L2 | P0 | normal 下真实工具调用 → securityd `check_permission allow` 且早于工具执行 | PASS（审计 seq 顺序） |
| HOOK-04 / MCP-01 / CAP-02~04 | L2 | P0/P1 | MCP 判权、fail-closed、server 边界、最高风险推断、未映射 confirm | PASS |
| ERR-01 | L2 | P0 | normal 下 L4 能力 DENY → run `failed` + `security_denied` + details(tool/capability/degraded=false)，工具零执行 | PASS |
| CAP-02-CONFIRM | L3 | P0 | normal 下 L4 `confirm=always` → `approval/requested` → reject 不执行 / approve 执行一次 / 重复决策 409 | 见 §6.5 |
| YOLO-01 | L2 | P1 | 新 Agent 默认 yolo（产品默认）→ 切 normal DENY → yolo 全放行并审计 `mode=yolo` → 切回 normal 恢复 DENY | PASS |
| DLP-01~03 / SKILL-01 / EGRESS-01 | L2 | P0/P1 | 8 类 PII、防误报、双信号、Skill DLP、出境提档 | PASS |
| DLP-04 | L2 | P0 | normal 下中央 BLOCK 阻断真实 run；>4KB 走 UDS `dlp.scan`；>1KB 走 `audit.batch` | 阻断 PASS；UDS 数据面两步为**缺陷 D-1** |
| TOKEN-01/02 | L2 | P1 | 配额可读写；真实 LLM 后 `day_used` 增长 | PASS |
| TOKEN-03 | L2 | P1 | normal + `on_exceed=deny` + 上限 1 → run `failed` `TOKEN_BUDGET_EXCEEDED`，`quota_denied` 审计，无 `token_metered` | PASS |
| TOK-HITL | L2 附带 | P1 | normal + `pause_and_notify` 超限 → `quota_approval_requested` → 60s 超时 `TOKEN_BUDGET_APPROVAL_TIMEOUT` | 观察到即记录（run1 证据） |
| SBX-01~05 | L2 | P1 | bwrap 隔离单元级 | PASS（非生产 Worker 证据） |
| AUDIT-01~03 | L2 | P0 | 审计写入、哈希链连续、导出 | PASS |
| CAP-01 / SCOPE-01 / CODE-01 | L2 | P0/P1 | 四表一致、命令 scope、安装期签名 | PASS（CODE-01 用测试密钥，demo 包生产签名 N/A） |
| RT-04 | L3 | P0 | D-Bus/UDS 伪造 Agent、Runtime 身份、lease、Commit/Abort | 全部拒绝并审计 `caller_identity deny` |
| SC-01 | L3 | P0 | Worker 内 `finit_module(273)` → `-1 EPERM`；`getpid` 正常；子进程 `Seccomp=2` | 阻断 PASS；采集到事件才可记"审计通过" |
| SC-02 | L3 | P1 | 策略版本、mandatory 不可删、未知名/错误架构拒绝、`pending_restart` | PASS |
| SC-03/04 | L3 | P1 | 审计状态 `active/degraded/unavailable`、collector 单测隔离 | 见报告 |
| NET-01 | L3 | P1 | `deny_all` 热应用到 scope（IPAddressDeny）→ 出网失败；恢复 `allow_all` 后 smoke 通过 | 见 §6.6 |
| API-01 | L3 | P0 | 非法 syscall 名/架构/网络模式/on_exceed/DLP action、未知 Agent、`/security-api/invoke` 未知 op | 拒绝且错误可解释，不落库 |
| API-02 | L3 | P1 | WebUI 8788 与 Runtime 状态接口反映 worker/seccomp/audit 实况 | 见报告缺陷 D-4 |
| P0-06 | L4 | P0 | 停止 securityd → Runtime 随之停止（`Requires=`）/新启动拒绝；恢复后新 lease、smoke 通过 | 见 §6.8 |
| SIG-01 / REL-01 / OCI / egress broker | — | — | demo 包、长稳、未交付项 | BLOCKED / N/A |

## 5. testkit 用例详细说明（含本次修订）

testkit 代码：`testkit/engine.py`、`testkit/tests_all.py`。本次修订点：

| 修订 | 文件:位置 | 原因 |
|---|---|---|
| `audit_chain_db()`：只取 `YYYYMM.db`，回退到含 `audit_record` 的库 | `engine.py` | 原 `sorted(glob("*.db"))[-1]` 在正式目录命中 `syscall-events.db`，AUDIT-01/02、HOOK-03、DLP-04 全误判 |
| `Ctx.enforcing_mode(agent, lift_budget=True)`：临时切 normal 并抬高 Token 配额，退出恢复 | `engine.py` | 新 Agent 默认 yolo；normal 下 `conv_used` 累计越过默认 100000 会让每个 run 先卡 quota HITL |
| YOLO-01 断言改为"初始 yolo(initial-agent-default) → 管理员切 normal → DENY → yolo 放行 → 恢复 DENY" | `tests_all.py` | 与 securityd `3f3deb1` 产品默认一致 |
| HOOK-03 在 normal 下运行，新增"判权 allow 非旁路"、"判权 seq 早于工具执行 seq" | `tests_all.py` | 证明判权先于执行 |
| DLP-04 在 normal 下运行 | `tests_all.py` | yolo 下 hook 对 BLOCK 只审计 |
| ERR-01 改用 `terminal→system.execute`（L4），新增"模型确实发起工具调用"、"判权 deny"、"工具零执行" | `tests_all.py` | L2 的 SecurityDenied 按设计不终止 run；远端模型常不调用 `web_search` |
| 新增 TOKEN-03（deny 分支真实 run） | `tests_all.py` | 原只有配额读写与计量，缺"超限真实拒绝"证据 |
| 单测 `test_syscall_audit.py` 两条 monkeypatch `kernel_observer_status` | `impl/bianbu-securityd/tests/test_syscall_audit.py` | 宿主有活跃内核观测器时被提升为 active，测试未隔离 |

### 5.1 HOOK-03（决定性用例）

前置：normal 模式（guard 自动），`file.read` granted=1 confirm=trusted。
步骤：记录 `seq0` → 真实 run "只调用 read_file 读取 /etc/hostname" → 等待终态 → 审计差分。
断言：`run completed`；存在 `check_permission file.read:/etc/hostname → allow`（agent 为被测 Agent）；`check_permission.seq < read_file executed.seq`。
失败含义：无 check_permission = hook 未调 securityd；结果非 allow = 走了旁路。

### 5.2 ERR-01（安全拒绝透传）

前置：normal；`system.execute` granted=-1（finally 恢复 granted=1）。
步骤：run "只调用 terminal 执行 echo BNSEC-ERR01"。
断言：审计有 `check_permission system.execute:* → deny`；无 `terminal` 执行审计；run `failed`；`error.code == security_denied`；message 含能力名与 `[bianbu-security]`；details.tool=`terminal`、details.capability=`system.execute`、details.degraded=false。
说明：L1/L2 能力的 DENY 按设计以 ToolMessage 交回模型，run 可 completed，此时应看审计而非 run 终态。

### 5.3 DLP-04（中央策略 + UDS 数据面）

前置：normal；经 WebUI 8788 把 `phone` 设为 `block`（finally 恢复原显式策略或删除）；等待 6s 让 PA 策略缓存过期。
步骤：run 含 `"普通文本"*1100 + 手机号`（>4KB）。
断言：run `failed`（阻断）；审计有 `uds_dlp_scan` 且 target 长度 >4096；有 `uds_audit_batch hook_payload:input` 且 result >1KB。
当前结果：阻断 PASS，后两项 FAIL → 缺陷 D-1（见报告）。

### 5.4 TOKEN-03（配额 deny 真实拒绝）

前置：`enforcing_mode(lift_budget=False)`；读取 normal 下真实配额；`SetTokenBudget(agent, 1, day, "deny")`；finally 恢复。
断言：run `failed`；`error.code == TOKEN_BUDGET_EXCEEDED`（message 含 used/limit）；审计 `quota_denied`；无 `token_metered`（模型未被调用）；恢复后 `GetTokenBudget` 回原值。

### 5.5 YOLO-01

断言链：`GetAgentSecurityMode` 初始 `{mode: yolo, updated_by: initial-agent-default}` → `SetAgentSecurityMode normal` → `CheckPermission(file.read granted=-1)=2` → 切 yolo 返回 `old_mode=normal,mode=yolo` → 已撤销与未知能力均 `0` → 两条审计 `decision=ALLOW;mode=yolo` → `security_mode_change` 含 agent/old/new/actor/timestamp → 切回 normal 后 `=2` → 注销。

其余 30 项沿用 `testkit/README.md` 的定义，不再赘述。

## 6. 手工探针用例（真实 Worker）

### 6.1 P0-01 连通性与版本

采集 `uname -a`、`dpkg -l`、`python3/bwrap/systemd/dbus --version`、六个 unit `is-active`、端口、UDS 权限、`busctl status io.bianbu.Security`、两接口方法清单。证据 `probes/p0-01-connectivity.txt`。

### 6.2 P0-03 Worker 沙箱/进程证明

对 `pgrep -f "role agent-worker"` 的 PID 采集 `/proc/<pid>/cgroup`、`status`（Seccomp/NoNewPrivs/CapEff/CapBnd）、`ns/*`、环境中的 `BIANBU_WORKER_*`；`systemctl show <scope> -p ControlGroup,MemoryMax,TasksMax,IPAddressDeny,IPAddressAllow`；与 `runtime-leases.db.runtime_instance.attestation_json` 比对 pid/unit/cgroup。host 后端只能作为开发/当前部署结果，不替代 bwrap 生产证据。

### 6.3 RT-04 身份伪造

| 攻击面 | 操作 | 预期 |
|---|---|---|
| D-Bus | 普通 shell 进程 `CheckPermission`/`MeterTokens` 冒充逻辑 Agent、冒充 `com.bianbu.runtime` | `caller 无权代表 agent`，审计 `caller_identity deny` |
| D-Bus Runtime | `CommitStart`/`AbortStart` 伪造 lease | `lease 不存在` |
| UDS | 自建连接带真实 `_worker_instance_id/_worker_lease_id` 但 PID 不匹配 | `Worker 未通过已提交 Runtime lease 身份校验` |
| UDS | 不带 lease 直接以逻辑 Agent 调 `permission.check/dlp.scan/token.meter` | `UDS caller 无权代表 agent` |

### 6.4 SC-01 seccomp deny

yolo 下经真实 run 让 Worker 用 `terminal` 执行 `python3 -c 'syscall(273 finit_module)…; syscall(172 getpid); 读取 /proc/self/status Seccomp'`。预期输出 `finit_module -1 1 Operation not permitted`、`getpid <pid>`、`Seccomp 2`。随后查 `GetSyscallAuditEvents`、`GetSyscallAuditStatus`、`/run/bianbu-syscall-audit/events.jsonl`。仅 EPERM 不能宣称"审计采集通过"。

### 6.5 CAP-02-CONFIRM 审批闭环

normal 下 `system.execute`（L4 confirm=always granted=1）：run "terminal 执行 echo BNSEC-CONFIRM" → 事件流出现 `approval/requested`（含 approval_id）→ `GET /api/v1/sessions` 该 session `pending_interaction=approval` → `POST /api/v1/sessions/{sid}/approvals/{aid} {decision}`：
- reject：工具不执行（无 `terminal` 审计），run 终态非阻塞；
- approve：工具执行一次（一条 `terminal` 审计），审计含 `check_permission … confirm` 与 session trust；
- 同一 approval 重复 POST → 409。

### 6.6 NET-01 deny_all 热应用

`SetNetworkPolicy(agent, [], deny_all)` → `GetNetworkPolicy.apply.effective/restart_required` → `systemctl show <scope> -p IPAddressDeny` → run "terminal 执行 curl 10.0.50.55" 预期失败/超时（远端模型不可达时 run 本身失败亦为强制生效证据）→ finally 恢复 `allow_all` → smoke run `completed`。

### 6.7 API-01 / API-02 契约

D-Bus：未知 syscall 名 → `UnknownSyscall`；错误架构 → `UnsupportedArch`；非法网络 mode → `ValueError`；非法 `on_exceed`/DLP action/pii_type → `ValueError`；未知能力 `SetCapabilityGranted` → `false`。HTTP：`/security-api/invoke` 未知 op → `{ok:false,error.code:incompatible}`。WebUI 8788：`/api/health`、`/api/agents`、`/api/agents/<aid>/security-execution-status|security-mode|syscall-policy|network`、`/api/dlp/matrix`、`/api/audit`。Runtime `/api/v1/runtime/status` 应反映 Worker instance/pid/backend/seccomp。

### 6.8 P0-06 securityd 不可达（fail-closed）

前置：所有其它用例完成，无进行中的 run。
步骤：`sudo systemctl stop bianbu-securityd` → 观察 `bianbu-agent-runtime@bianbu` 状态（`Requires=` 传导）、`curl :9899` 结果、UDS 是否消失、`busctl` 无占名 → `sudo systemctl start bianbu-securityd bianbu-agent-runtime@bianbu bianbu-security-webui` → 等待 → 三服务 active、新 Worker 新 lease（instance_id 变化）、`pending_restart` 清零、smoke run `completed`。
预期：securityd 停止期间不存在可服务的 Runtime/Worker（fail-closed by construction）；恢复后旧 lease 不复用。

## 7. 执行脚本与产物

### 7.1 回归

```bash
# Worker: /var/tmp/bnsec-cc-tester-20260911/pytest/run-regressions.sh
V=/var/tmp/bnsec-delivery-20260911/runtime/debian/.bianbu-agent-build/venv
cd /var/tmp/bnsec-delivery-20260911/runtime && $V/bin/python -m pytest -q \
  tests/runtime/test_security_runtime.py tests/runtime/test_execution_runtime.py tests/runtime/test_service.py \
  tests/runtime/test_security_api.py tests/runtime/test_security_skill_dlp.py tests/runtime/test_security_syscall_api.py \
  tests/runtime/test_syscall_collector.py tests/runtime/test_seccomp_audit.py tests/runtime/test_syscall_auditd_collector.py
cd /var/tmp/bnsec-delivery-20260911/security && PYTHONPATH=impl/bianbu-securityd $V/bin/python -m pytest -q \
  impl/bianbu-securityd/tests/unit/test_runtime_policy.py impl/bianbu-securityd/tests/unit/test_runtime_lease.py \
  impl/bianbu-securityd/tests/unit/test_runtime_engine.py impl/bianbu-securityd/tests/test_syscall_audit.py \
  impl/bianbu-securityd/tests/test_syscall_policy.py
```

### 7.2 手工探针

`probes/cc_probes.py`（本目录 `evidence/` 附副本）顺序执行 SC-01 → CAP-02-CONFIRM(reject/approve) → NET-01，所有状态变更 `finally` 恢复；输出 `probes/manual-probes.log`。

### 7.3 证据目录

```
/var/tmp/bnsec-cc-tester-20260911/
  pytest/     runtime-targeted.{log,xml}  security-targeted{,-rerun}.{log,xml}  status.txt
  testkit/    run1/ run2/ run3/ (events.jsonl, report.json)  run*.log
  probes/     p0-01-connectivity.txt  p0-03-sandbox-attestation.txt  rt-04-caller-binding.txt
              api-01-contracts.txt  api-02-webui-status.txt  sc-01-*.txt  manual-probes.log  p0-06-*.txt
```

仓内副本：`docs/test/cc-tester/evidence/`。

## 8. 准出标准

**必须 PASS**：P0-01、CONN-*、HOOK-02、P0-03、PERM-*、HOOK-01/03/04、ERR-01、CAP-02-CONFIRM、DLP-01~03、DLP-04 的阻断步骤、AUDIT-*、CAP-01、SCOPE-01、RT-04、SC-01 阻断、API-01、P0-06。
**允许带条件交付**：DLP-04 UDS 数据面（D-1）、`conv_used` 不重置（D-2）、Runtime 状态接口不反映 Worker（D-4）、demo 包鉴权/签名关闭（D-5）在列出负责人与关闭版本后可带缺陷交付。
**禁止交付**：任一 fail-open（yolo 之外的 ALLOW 旁路）、caller/lease 冒充成功、审计链断裂、DLP 原文外发、把 BLOCKED/N/A 记成 PASS。
