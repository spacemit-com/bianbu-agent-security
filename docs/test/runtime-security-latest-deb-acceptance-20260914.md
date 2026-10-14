# 最新 Runtime / Security DEB 安装验收（2026-09-14）

> 本文保留首次验收结果。后续修复与回归见 [三类问题修复记录](runtime-security-regression-fixes-20260914.md)，请结合最新记录判断当前状态。

| 项目 | 内容 |
|---|---|
| 文档编号 | BN-SEC-RT-DEB-20260914 |
| 版本 | 1.0 |
| 来源 | 用户要求在 243 worker 构建最新 DEB、安装并验证 Runtime 基本功能及 Security 功能 |
| 状态 | 构建、安装及验收完成；核心功能通过，错误提示与全量回归存在未通过项 |
| 平台 | `10.0.90.243`，SpacemiT K3，riscv64 |
| Runtime 源码 | `0f5f59a7`，`main`，含 Memory TTL 续期修复 |
| Security 源码 | `e72938d`，`main` |
| 已安装 DEB | Runtime `0.1.44`；Security `0.1.29` |
| Worker 构建及证据根目录 | `/var/tmp/runtime-security-acceptance.voyPUJ` |

本轮完成最新代码的原生构建、安装与功能验收。37 项 testkit、163 项 Runtime 回归、系统调用拒绝审计及 learning 观测/故障恢复通过；网络拒绝时的错误解释和 Security 全量 pytest 尚未通过，不能宣称完整发布门禁全绿。

## 构建与安装

两个仓库 fetch 后核对远端 main，Runtime 本地 fast-forward 至 `0f5f59a7`。以 git archive 将两个确定版本传入 worker 新目录，分别执行 `dpkg-buildpackage -us -uc -b`，均退出 0，保留原生编译、打包检查与构建日志。

安装前调用 Security 仓 `impl/bianbu-securityd/deploy/clear-security-data.sh`（安装命令名 `bianbu-agentic-security-reset`）的 `--dry-run` 和 `--yes`。清理 Security 数据、审计、lease 和 collector 状态，保留 `/home/bianbu/.bianbu-agent` 配置、Agent 数据和聊天历史。随后 `dpkg -i` 安装两份包。

| 产物 | SHA-256 |
|---|---|
| `bianbu-agent-runtime_0.1.44_riscv64.deb` | `7978c3f3cdd6944d15a21b9cf6d3aa4d7411dfefca3b809e5d471702eb1db7a0` |
| `bianbu-agent-securityd_0.1.29_riscv64.deb` | `0a4cbc72a373ad34eb29c4377304fcee75117b0c17bf91481eedc0b8d68d1f56` |

本轮按仓库默认构建 development/demo 包：Security 关闭生产签名强制校验，Runtime 使用开发自签 manifest。因此功能验收不能替代生产信任链、认证和商用发布门禁。

## 已验证结果

| 验证范围 | 结果 | 证据（相对于 evidence/） |
|---|---|---|
| 原生构建与包安装 | 两份包均成功 | `runtime-build.log`、`security-build.log`、`install.log` |
| 包完整性 | `dpkg --audit`、`dpkg -V` 均无输出 | `dpkg-audit.txt`、`dpkg-verify.txt` |
| Security 安装冒烟 | PASS | `security-package-smoke.log` |
| Runtime 控制面、Agent、页面 | `AGENT_READY`；Agent API 和两端页面 HTTP 200 | `agents.json`、`learning-workers.json` |
| 会话持久化 | 重启后原会话历史仍可读取，含原用户消息与结果 | `history-after-restart.json` |
| Memory 注册 | 新 Worker 返回 `memory_registration.state=active`，有效期为注册时间加 24 小时 | `learning-workers.json` |
| Runtime 定向回归 | 163 passed | `runtime-pytest-with-test-deps.log` |
| 测试引擎回归 | 7 passed | `testkit-engine-tests.log` |
| 完整 testkit | **37 passed / 0 failed / 0 error**，115.8 秒 | `testkit-final/report.json` |
| 系统调用黑名单与拦截审计 | PASS，见专项说明 | `syscall-events.json`、`syscall-after.json`、`syscall-status.json` |
| learning 保存、重启、观测 | PASS，真实 HTTPS 200、DNS 和失败连接可查询 | `learning-save.json`、`learning-preload.txt`、`learning-after.json` |
| learning collector 故障恢复 | PASS，degraded → active，恢复后 11 条新增或更新记录 | `learning-collector-stopped.json`、`learning-collector-recovered.json`、`learning-recovery-verification.json` |
| Agent 创建/修改/删除 | HTTP 201 / 200 / 204；临时 Agent 已删除 | `temporary-agent-create.json`、`temporary-agent-update.json`、`temporary-agent-delete.json` |
| deny_all / 白名单拒绝 | 重启后访问被阻断；**结构化错误提示 FAIL** | `plain-agent-deny_all-run.json`、`plain-agent-whitelist-run.json` |
| Security 全量 pytest | **788 passed / 5 failed / 3 skipped**，未全绿 | `security-pytest.log` |

Runtime 生产虚拟环境不包含 pytest-asyncio，直接在其中跑异步单测首先得到 78 failed / 85 passed（异步测试缺插件）。改用已有测试虚拟环境加载本轮源码后，163 项全部通过。真实端到端始终访问本轮 DEB 安装后启动的服务。

## testkit 适配与失败复核

原始完整 testkit 为 30 passed / 7 error：六项仍从旧 `.bianbu-agent/plugins/bianbu.security` 导入模块，另一个 ERR-01 在 Runtime 通用审批阶段等待至超时。它们不能作为产品拒绝失效的结论。

本轮仅修正测试系统与文档，未修改 Security 或 Runtime 产品实现：

1. 支持 `BNSEC_SECURITY_PLUGIN_ROOT`，本轮明确指向 DEB 安装的 `/usr/share/bianbu-agent-runtime/plugins/bianbu.security`，源码默认路径改为 `resources/plugins/bianbu.security`。
2. Skill DLP fake adapter 注入路径对齐 `bianbu_agent.security.security_runtime`。
3. `Ctx.run_prompt` 默认不自动审批；HOOK-03 和 ERR-01 显式批准当前 Run 的指定无害工具探针，去重且不处理其他 Run。新增 4 个断言验证默认关闭、工具隔离、Run 隔离和去重。
4. ERR-01 仍要求 securityd DENY、零工具执行、结构化错误与审计记录。实测通用审批后，Security 撤销策略仍然阻断工具，不能把批准通用审批等同于绕过 Security。

修正入口后，7 项插件/Skill 定向测试全部通过，ERR-01 单项通过。完整重测结果以 `testkit-final/report.json` 为准，不混用不同轮次的通过数。

## 系统调用专项

真实 Runtime Run `7a3a974a-69fe-4ff6-8262-d028fdc7be06` 调用 terminal 执行工作区固定 Python 探针，工具退出码为 0。`getpid` 返回 `992925`；`finit_module`（riscv64 syscall 273）返回 `-1`、errno=1；`Seccomp: 2`。

Security 返回同一 PID 的拒绝事件：`action=deny`、`backend=ebpf-seccomp`、`worker_agent_id=com.bianbu.c6f40f30a6e5`、当前 instance 和 lease、`policy_version=0`、`prev_hash=GENESIS`。状态接口 `events=1`、`chain_valid=true`。

前两次探针分别因模型改写长命令、工具沙箱不可见 `/var/tmp` 脚本而无效。最终改为工作区固定脚本并同时检查工具 exit_code 与实际审计事件；不以 Run completed 代替执行成功。

## 网络 learning 专项

通过 `/security-api/invoke` 的 `network-policy.update.v1` 保存 learning，响应 `runtime_learning.restart_required=true`。重启 Runtime 后 Worker PID `993917`，instance 为 `com.bianbu.c6f40f30a6e5-a1df9904f18542c3ae38b171570518d7`，maps 中存在 preload。

真实工具请求得到 `HTTPS 200`、`example.com` DNS 解析结果，以及 `127.0.0.1:1` 连接失败 errno 111。事件接口记录 `dns_query` 与 `connect`，含 domain/IP/port/outcome/errno/count/last_seen、backend=preload、policy_version=2、当前 instance/lease/PID。

停止 collector 后首次状态查询即为 degraded；恢复服务后第二次查询为 active。随后再次真实发起请求，比较 event_id 和 last_seen，确认 11 条新增或更新记录，并包含 DNS、成功 443 连接和失败端口 1 连接。已恢复原 `allow_all` 策略。

## 网络拒绝和错误提示补测

临时创建只选择 `bianbu.security` 插件、保留权限声明与同一模型的普通 Agent，以隔离默认 Bibit Agent 的端侧 hook。创建 HTTP 201、修改 HTTP 200，allow_all 下真实模型请求 completed。

保存 deny_all 后，接口返回 `effective=false`、`restart_required=true`；此时旧 Worker 仍可完成请求，属于尚未重启的旧策略，不作为阻断失败。按提示重启 Runtime 后，同一测试 Agent 的请求 failed、无模型用量，错误为 `run_failed / Connection error.`。

**阻断行为已观察到，结构化网络策略错误提示未通过**：期望 `network_policy_blocked` 和可操作的策略说明，实际为通用连接错误。保留 `plain-agent-deny_all-run.json` 与 `agent-crud-network-restarted.log`。排查入口为 Runtime `runs/manager.py::_agent_network_policy`、`classify_run_exception` 的模型地址和策略上下文；本轮未将推测写成已确认根因，也未修改产品实现。

白名单仅包含 `example.com`，重启后策略接口返回 `effective=true`、`enforced=true`，未包含模型域名。真实请求 failed，无模型用量；错误为 `run_failed / model response timed out after 120s`。`plain-agent-whitelist-run.json` 与 `whitelist-active-policy.json` 保留证据。因此 deny_all 和 whitelist 的结构化错误提示均未通过。

默认 Bibit Agent 的另一次 deny_all 探针停留在 `bibit-intent.before_run`，90 秒内未返回终态（`network-modes.log`）。策略恢复后该 Run 已不再可取消（HTTP 409）；该测试超时不作为错误提示通过证据。测试退出均使用 finally 恢复策略；普通临时 Agent 删除响应为 HTTP 204。

## 全量 Security 测试的未通过项

| 项目 | 证据与影响 |
|---|---|
| 两项 UDS / 重启集成测试 | 测试用 `next(glob('*.db'))` 选到非主审计链库，报 `no such table: audit_request/audit_record`；主审计与 syscall 独立库并存，选择方式错误。未改此测试，保留失败。 |
| 两项无 dbus 客户端测试 | `client/bianbu_security_client.py` 顶层 `import dbus`，被用例的 NoDbus 拦截器拒绝。当前 worker 安装环境含 dbus，实际端到端通过；无 dbus 环境兼容性仍未通过。 |
| WebUI placeholder 测试 | 脚本优先读取运行中 WebUI 的 token，未走测试提供的临时 env 文件，因此未按用例预期拒绝 placeholder。测试未隔离已有服务；报告不披露 token。 |

这 5 项失败未被删除或计为通过；3 项 skip 同样不构成覆盖证据。本轮不宣称 Security 全量发布门禁通过。Memory 真实运行超过 25 小时的长稳验证也未完成，163 项定向回归使用模拟时间验证跨 TTL 行为。

## 完整 testkit 复现命令

```bash
cd /var/tmp/runtime-security-acceptance.voyPUJ/security
PA_ROOT=/var/tmp/runtime-security-acceptance.voyPUJ/runtime \
BIANBU_SECURITYD_HOME=/usr/lib/bianbu-securityd \
BNSEC_SECURITY_PLUGIN_ROOT=/usr/share/bianbu-agent-runtime/plugins/bianbu.security \
PA_AGENT_ID=com.bianbu.c6f40f30a6e5 \
BIANBU_PA_AGENT_ID=com.bianbu.c6f40f30a6e5 \
BNSEC_OUT=/var/tmp/runtime-security-acceptance.voyPUJ/evidence/testkit-replay \
python3 testkit/runner.py
```

重放使用本轮修正的 testkit。不得用产品代码临时放行或旧进程的状态替代上述证据。

## 最终环境与交付结论

最终真实对话 Run `f71305a3-682c-4704-b121-952d61d670d2` 为 completed。最终 Worker PID `1019132`，状态 running、Memory 注册 active；Agent 列表仅保留原有系统 Agent。临时 Agent 删除 HTTP 204，两个工作区探针已移入构建证据目录并从工作区删除。

`bianbu-securityd`、`bianbu-syscall-observer`、`bianbu-agent-network-learning`、`bianbu-agent-runtime@bianbu`、`bianbu-security-webui` 均 active。原网络策略 `allow_all`、原模式 `yolo` 已恢复；syscall 审计链仍有效。

**构建、安装与本轮测试任务已完成；核心功能验收通过，但不判定全量发布门禁通过。** 后续需处理 deny_all/whitelist 的结构化错误提示、默认 Bibit hook 在断网时的终态等待，以及上述 5 项 Security 全量测试失败。Memory 25 小时实时时长验收仍属于后续长稳工作。

本轮验收后续修复已分别提交到 Security 与 Runtime 仓库；未执行 push。测试补丁保存在 Worker `evidence/testkit-adaptation.patch`，可与最初构建源码区分。
