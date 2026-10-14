# Runtime → Security 清理后端到端交付验收报告

| 项目 | 结果 |
|---|---|
| Worker | `10.0.90.243`，riscv64，Linux 6.18.3-generic |
| Runtime 源码 | `main`，本地 HEAD `faeaf93`，基于远端最新 `87d6174d` rebase |
| Security 源码 | `main`，HEAD `06a9431` |
| Runtime DEB | `bianbu-agent-runtime 0.1.29` |
| Security DEB | `bianbu-agent-securityd 0.1.28` |
| 清理命令 | `bianbu-agentic-security-reset --yes` |
| 证据目录 | `/var/tmp/bnsec-build-20260912/evidence/` |

## 1. 清理和安装前置

安装前在 Worker 执行了 `--dry-run` 预览和 `--yes` 正式清理。已清理 Security capabilities、Token、DLP、lease、审计、sandbox、syscall/network collector 状态及运行 socket。按命令设计保留 `/home/bianbu/.bianbu-agent` 用户配置和聊天历史，未使用不可逆的 Runtime 用户数据删除选项。

## 2. 构建与安装

两份包均在 Worker 原生 riscv64 构建成功：

- Runtime：`/var/tmp/bnsec-build-20260912/bianbu-agent-runtime_0.1.29_riscv64.deb`
- Security：`/var/tmp/bnsec-build-20260912/bianbu-agent-securityd_0.1.28_riscv64.deb`

SHA-256：

- Runtime `e9dce3df87c3113450ab86491a19902341692f163e8415ae873e629b9424f3c4`
- Security `3dfa5b2deb6441d6b5777e035a439ebe96cb287e14e17ede726c126880b11cd8`

安装后重启成功：`bianbu-securityd.service`、`bianbu-agent-runtime@bianbu.service`、`bianbu-security-webui.service` 均为 `active`。Runtime 监听 `0.0.0.0:9899`，WebUI 监听 `127.0.0.1:8788`。

## 3. 测试结果

| 测试集 | 结果 | 证据 |
|---|---:|---|
| testkit 完整端到端 | **37 passed / 0 failed / 0 error** | `/var/tmp/bnsec-build-20260912/evidence/testkit2/report.json` |
| Runtime 定向回归 | **189 passed** | `/var/tmp/bnsec-build-20260912/evidence/runtime-targeted.log` |
| Security 定向回归 | **48 passed** | `/var/tmp/bnsec-build-20260912/evidence/security-targeted.log` |
| 安装/服务验证 | **通过** | `/var/tmp/bnsec-build-20260912/evidence/install-verification.txt` |

testkit 使用清理后的全新 Security 状态、正确 Agent 身份、正式安装路径和 WebUI `8788` 端口执行。

## 4. 验收结论

本轮清理后从最新源码构建、安装并完成 Runtime→Security 真实 Worker 端到端验收，全部自动化测试通过，可判定本轮验收 **PASS**。

生产发布仍需单独使用生产签名 manifest 和 `DEB_DEMO=0` 包验证；本轮构建默认仍生成 development self-signed manifest，Security 包为 demo 配置，因此不替代生产签名/认证验收。

## 5. 复现入口

```bash
cd /var/tmp/bnsec-build-20260912/security
PA_ROOT=/var/tmp/bnsec-build-20260912/runtime \\
BIANBU_SECURITYD_HOME=/usr/lib/bianbu-securityd \\
PA_AGENT_ID=com.bianbu.c6f40f30a6e5 \\
BIANBU_PA_AGENT_ID=com.bianbu.c6f40f30a6e5 \\
BNSEC_SECURITY_WEBUI_BASE=http://127.0.0.1:8788 \\
BNSEC_OUT=/var/tmp/bnsec-build-20260912/evidence/testkit-replay \\
python3 testkit/runner.py
```

## 6. 系统调用黑名单与拦截审计专项验收

| 项目 | 条件/步骤 | 实际结果 | 判定 |
|---|---|---|---|
| 黑名单策略 | `GetSyscallPolicy(com.bianbu.c6f40f30a6e5, riscv64)`，核对 mandatory 包含 `finit_module` | effective 黑名单包含 `finit_module`，`policy_version=0`，`pending_restart=false` | PASS |
| 黑名单阻断 | 真实 Runtime Run 调用 terminal，在 Worker 中执行 syscall 273（`finit_module`） | 返回 `-1`、errno=1、`Operation not permitted` | PASS |
| 普通 syscall | 同一进程执行 syscall 172（`getpid`） | 返回有效 PID `2943842` | PASS |
| Seccomp 生效 | 读取 Worker `/proc/self/status` | `Seccomp: 2` | PASS |
| 拦截事件审计 | Run 后调用 `GetSyscallAuditEvents(agent, instance, 10, 0)`，同时检查 spool | 返回 1 条 deny 事件；spool `events.jsonl` 1 行 | PASS |
| 审计身份 | 检查事件字段 | `worker_agent_id`、`instance_id`、`lease_id`、PID、cgroup、arch、syscall、number、backend、policy_version 均存在 | PASS |
| 哈希链 | 检查 `prev_hash/hash` 和 `GetSyscallAuditStatus` | 首条 `prev_hash=GENESIS`，`chain_valid=true`，`events=1` | PASS |

复现证据：`/var/tmp/bnsec-build-20260912/evidence/sc01-current/run.log`。关键事件：`finit_module` syscall 编号 273，PID `2943842`，backend `ebpf-seccomp`，事件序号 `1`，哈希 `9bdb8b97b05c89c8b79cce73a3e9f09eb85330020553fb6eba21580447513150`。

专项结论：当前最新安装包在 Worker 上已同时证明**系统调用黑名单真实阻断**和**拦截事件进入 Security syscall 审计链**，本专项 PASS。此前报告中“阻断成功但审计事件为 0”的结论属于旧版本/旧探针结果，不能用于评价本次清理后的最新安装验收。

## 7. 网络策略 learning 模式观测专项验收

| 项目 | 条件与步骤 | 实际结果 | 判定 |
|---|---|---|---|
| learning 策略应用 | `GetNetworkPolicy`；检查 active instance 与 apply 状态 | `mode=learning`、`version=4`、`effective=true`、`active_instances=1`、`failed_instances=0` | PASS |
| collector 状态 | `GetNetworkLearningStatus` | `state=active`、`reported_instances=1`、无降级原因 | PASS |
| 真实网络观测触发 | Runtime Session 调用 terminal，执行 `curl https://example.com` 及 `curl http://127.0.0.1:1` | 真实产生 HTTPS 200 和本地连接失败，Run completed | PASS（触发条件） |
| 观测记录查询 | `GetNetworkLearningEvents(agent, 100, 0)`；读取 `network_learning_event` | 返回 `events=[] total=0`，SQLite 表无记录 | **FAIL** |
| 记录字段完整性 | 期望 domain/IP/port/result/count/last_seen | 无事件，无法验证字段 | BLOCKED（依赖上一项） |

复现证据：Worker `/var/tmp/bnsec-learning-acceptance/before.json`、`after.json`、`run-events.json`；本轮策略状态显示 learning active，但事件表仍为空。

失败原因分析：策略应用层报告 active/effective，Runtime 真实网络请求也确实发生，但 collector 没有把连接事件写入 `network_learning_event`，或事件未按当前 lease/cgroup 关联到测试 Agent。需要进一步检查 LD_PRELOAD/collector 进程是否注入到当前 host Worker、采集 socket/权限、collector 日志及事件落库路径。当前不能把 `state=active` 当作“已有观测记录”。

复现时注意：Runtime 事件接口 `max_messages` 上限为 50；使用 100 会返回 HTTP 422（测试脚本参数错误），应使用 `?max_messages=50`。

## 8. Learning 观测未通过的根因调查

本轮确认不是策略枚举或数据库查询问题：`GetNetworkPolicy` 返回 `learning`、`effective=true`，但 `network_learning_collector` 仅有旧 registration（PID `2935907`、instance `...ac8e1f0b...`），没有当前真实 Run 的事件。对同一 Agent 重新调用 D-Bus `SetNetworkPolicy(..., learning)` 后，策略版本从 4 增至 5，但 collector registration 的 PID/instance/更新时间不变，说明只更新 Security 策略不会让 Runtime 为当前 Worker 重新注册/注入采集器。

服务端 collector 本身为 active（`network-learning-ebpf-collector.py`，socket `/run/bianbu/network-learning/collector.sock`），但当前 Run 的进程未产生 `network_learning_event`。结合 Runtime 代码，实际采集依赖 `apply_network_learning_policy()` 对当前 host Worker 启动 per-instance collector/LD_PRELOAD；该通知路径由 Runtime security API 的 `network-policy.update.v1` 触发，直接 D-Bus 改策略不会触发 Runtime 同步。因此本轮前置状态来自旧 registration，报告为 active 属于陈旧状态。

**结论：** learning 功能当前表现为“策略应用 PASS、当前实例观测 FAIL”。需要通过 Runtime 的正式 `network-policy.update.v1` 管理路径切换策略，或在 Worker 重启/重新创建实例后验证 registration 更新；本次不修改代码。测试结束已将策略恢复为 `allow_all`。

### Learning 根因复核更新

进一步核对后修正前述“旧 registration”判断：PID `2935907` 确实是当前 Runtime Worker，非陈旧进程。真正差异在于该 Worker 启动时未加载 `libbianbu-network-learning.so`（`/proc/2935907/maps` 无 preload），因此虽向 privileged collector 注册并显示 `active`，不会产生连接事件。Runtime 重启后，正式 `network-policy.update.v1` 重新应用 learning，collector registration 更新为当前 Worker PID `2962900`，并可在 `/proc/2962900/maps` 确认 preload 已加载；旧 registration 被标记 `inactive/unregistered`。这说明功能依赖“策略切换/Worker 启动时的 Runtime 注入”，仅直接 D-Bus 改 Security 策略不会重新注入当前进程。

本次未完成重启后真实网络请求的最终事件落库复核（探针第二次请求错误使用了带 body 的 GET，Runtime 返回 HTTP 405，属于测试脚本错误）。因此当前证据已证明注入链恢复，但不能把重启后的观测记录写成 PASS；需要用正确的 GET 事件查询和真实 Run 再补一轮。

## 9. Learning 模式问题解决过程与下次标准验收流程

### 9.1 本次问题现象

首次在 learning 下执行真实网络请求时，策略接口返回 `mode=learning`、`effective=true`、collector `state=active`，但 `GetNetworkLearningEvents` 和 `network_learning_event` 均为空。此时 Worker 进程 PID `2935907` 仍在运行，但 `/proc/2935907/maps` 没有 `libbianbu-network-learning.so`，说明当前 Worker 启动时没有注入观测 preload。collector 的“active”只代表 registration/服务存活，不代表当前进程已能产生事件。

### 9.2 根因

Runtime 的学习采集分为两段：Runtime 为每个 host Worker 注入 `LD_PRELOAD=/usr/lib/bianbu-agent-runtime/libbianbu-network-learning.so` 并向 privileged collector 注册 instance、lease、PID、cgroup；preload 捕获 DNS/connect 事件，经 `/run/bianbu/network-learning/collector.sock` 回传 Runtime，再由 Runtime 以 lease 身份写入 Security。直接调用 Security D-Bus 切换 learning 只更新策略，不保证当前 Worker 重新注入 preload。

### 9.3 已验证的解决过程

1. 检查策略、collector、事件表和 Worker maps。
2. 确认当前 PID/instance 存活，排除旧实例误判。
3. 重启 `bianbu-agent-runtime@bianbu.service`，让 Worker 重新启动。
4. 通过 Runtime `network-policy.update.v1` 设置 learning，触发 `apply_network_learning_policy`。
5. 确认新 Worker maps 出现 preload，registration 更新到新 PID/instance。
6. 真实执行 `curl --noproxy "*" -I --max-time 5 https://example.com`。
7. 查询 `GetNetworkLearningEvents`，确认 `dns_query/connect` 事件已落库，含 domain、remote_ip、remote_port、outcome、backend、policy_version、instance_id、lease_id、pid。
8. 恢复 `allow_all`，清理测试状态。

### 9.4 下次必须按此流程验收

| 步骤 | 操作 | 必须满足 |
|---|---|---|
| 1 | 读取策略和 learning status | 记录原策略；状态可解释 |
| 2 | 用 Runtime `/security-api/invoke` 调 `network-policy.update.v1` | `ok=true`、`apply.effective=true`，记录 runtime_learning |
| 3 | 检查 Worker `/proc/<pid>/maps` | 必须出现 `libbianbu-network-learning.so` |
| 4 | 记录事件基线 | 查询 API 和 SQLite 最大序号 |
| 5 | 真实触发网络 | terminal 执行 HTTPS 成功和失败连接 |
| 6 | 查询事件 | 至少一条当前 instance/lease 的 dns_query/connect，domain/IP/port/result/count/last_seen 可读 |
| 7 | 核对身份 | PID/instance/lease 与 Runtime 当前值一致；不能只看 active |
| 8 | 单独故障用例 | 停 collector 后应 degraded/unavailable，恢复后重新注册 |
| 9 | 恢复环境 | 恢复原策略，确认无测试 registration/策略残留 |

PASS 必须同时满足策略有效、preload 已加载、真实请求产生事件、事件落库且身份字段完整。仅 `state=active` 或 `effective=true` 不足以判 PASS。

### 9.5 测试工具注意事项

Runtime events 接口 `max_messages` 最大值为 50；使用 100 返回 HTTP 422。GET 查询不得携带 JSON body，否则返回 HTTP 405。

### 9.6 重启后最终复核结果

按上述流程重启 Runtime、通过 Runtime 正式 `network-policy.update.v1` 重新应用 learning 后，当前 Worker `2962900` 的 `/proc/2962900/maps` 已包含 preload。真实 Run `learning-recheck-1789145603325350360` 执行 `curl https://example.com` 返回 HTTP 200；随后查询得到 12 条 learning 事件，SQLite `network_learning_event` 共 47 条。事件包含 `dns_query example.com`、`connect remote_port=443`，并带当前 instance、lease、PID、backend=preload、policy_version=7。策略随后恢复 `allow_all`。

因此，本次 learning 功能最终验收 **PASS**。此前“事件为空”的结果仅适用于未注入 preload 的旧 Worker 状态；下次必须先检查 preload 和当前 registration，再判定观测是否失败。

## 10. Learning 模式 MVP 交付方案

### 10.1 用户可见行为

配置中心通过 Runtime 的 `network-policy.update.v1` 保存策略。选择 `learning` 后，接口返回 `runtime_learning.restart_required=true`，页面立即提示：**“策略已保存，重启 Agent 后生效”**。页面不宣称已运行 Agent 已经开始采集；用户重启 Agent 后，Worker 启动流程加载 learning preload 并注册 collector。

### 10.2 状态与接口契约

| 状态 | 含义 | 验收要求 |
|---|---|---|
| `restart_required` | 策略已保存，等待 Agent 重启加载 | 保存响应必须包含 `restart_required=true` |
| `active` | 重启后 preload 与 collector 均已就绪 | maps、registration、status 三者一致 |
| `degraded` | collector 不可用或身份不匹配 | 页面显示不可用原因，不得伪报 active |

`network-policy.update.v1` 是唯一保存入口；直接调用 Security D-Bus 仅用于底层策略操作，不作为 learning 生效验收入口。MVP 不实现已运行 Worker 的动态 preload 注入，也不承诺无需重启即可观测。

### 10.3 MVP 验收门槛

1. 保存 learning 策略后看到重启提示。
2. 重启 Agent，确认 `/proc/<pid>/maps` 含 `libbianbu-network-learning.so`。
3. 确认 collector registration 指向当前 PID、instance、lease。
4. 通过真实 DNS/connect 请求产生事件，并在 API 与 SQLite 落库中看到当前身份字段、目标和结果。
5. collector 停止时状态必须变为 `degraded/unavailable`，恢复并重启后可重新变为 `active`。
