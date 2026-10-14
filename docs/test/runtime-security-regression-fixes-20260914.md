# Runtime / Security 三类验收问题修复记录

| 项目 | 内容 |
|---|---|
| 文档编号 | BN-SEC-RT-FIX-20260914 |
| 版本 | 1.0 |
| 日期 | 2026-09-14 |
| 来源 | 最新 DEB 验收遗留问题；用户要求修复且不影响现有功能 |
| 状态 | 修复已安装，真实网络及核心功能回归进行中 |
| 平台 | 243 worker，SpacemiT K3，riscv64 |
| 源码基线 | Runtime `0f5f59a7`；Security `e72938d`，加本轮未提交修复 |
| 修复包 | Runtime `0.1.44`；Security `0.1.29`，保持原版本号及依赖下限 |
| Worker 证据目录 | `/var/tmp/runtime-security-acceptance.voyPUJ/evidence` |

本记录接续 [首次验收报告](runtime-security-latest-deb-acceptance-20260914.md)。首次结果
`788 passed / 5 failed / 3 skipped` 是历史事实，不覆盖或改写其原始日志。

## 1. 网络拒绝返回通用错误

### 原因

1. `runs/manager.py::_agent_network_policy` 在处理异常时调用 Security 的
   `get_network_policy`。该客户端方法使用管理面 D-Bus；受管 Worker 采用 lease 绑定的
   UDS，沙箱不能依赖这条 D-Bus 查询。查询异常被诊断逻辑捕获后返回 `None`，错误分类
   缺少策略证据，只能返回 `run_failed`。
2. 即使查询可用，管理面返回的是当前保存的配置，不保证与旧 Worker 已采用的策略一致。
   保存后尚未重启时，直接拿新配置解释旧进程的错误可能误报。
3. `security_errors.py` 只识别连接错误，没有识别 Runtime 明确抛出的
   `model response timed out after 120s`。白名单过滤导致等待超时时，仍返回通用错误。
4. 默认 Bibit hook 把 HTTP 连接和读取等待统一设为 110 秒。禁止网络时，连接本地
   `127.0.0.1:8765` 也可能被丢弃，建立连接就消耗整个执行等待预算，表现为 hook 长时间无终态。

### 修复及兼容性边界

| 位置 | 修改 | 保留的行为 |
|---|---|---|
| Runtime `security/execution_runtime.py::_safe_env` | 从本次批准的启动策略生成 `BIANBU_WORKER_NETWORK_POLICY`，仅携带 Agent ID、mode、domains；覆盖请求提供的同名值 | 诊断快照不授予网络权限，不修改 cgroup、namespace 或白名单执行逻辑 |
| Runtime `runs/manager.py::_agent_network_policy` | 受管 Worker 读取自己的启动快照，校验 Agent ID；缺失、损坏或身份不符时返回未知 | 不读取尚未生效的新配置；不绕过 lease 身份；不新增 Security 协议依赖 |
| Runtime `security/security_errors.py` | 增加明确的模型响应超时识别 | 普通工具超时仍为 `run_failed`；无策略证据不声称被拦截；allow_all/learning/白名单已允许时为 `provider_connection_failed` |
| Bibit `scripts/before_run.py` | 建立连接最多等待 5 秒，读取仍为 110 秒 | 只有连接失败可交给 Runtime 兜底；请求已提交但结果不确定时仍禁止重复执行，并尝试取消 |

本修复没有加入“看到 deny_all 就预先结束整个 Run”的分支，端侧 hook、模型、工具仍按原
流程执行。保存策略继续提示重启 Agent，重启前旧 Worker 的行为保持不变。

### 回归断言

- 从真实启动策略生成快照，调用方不能用同名环境变量把 whitelist 伪装成 allow_all。
- 受管 Worker 不调用管理面策略查询；错误快照、其他 Agent 快照和缺失快照返回未知。
- deny_all 和缺少模型域名的 whitelist：明确的模型连接/超时错误返回 `network_policy_blocked`。
- allow_all、learning、白名单已包含模型域名：不能返回策略拦截错误。
- 普通工具超时、缺少策略证据：保留通用错误语义。
- Bibit 连接等待 ≤5 秒，读取预算仍为 110 秒；读超时/取消不重复交给云端执行。

新增用例先在旧源码运行，出现 8 项预期失败；实施修复后该组 131 项全部通过。

## 2. Security 五项失败

| 原失败 | 真正原因 | 修复 | 验证 |
|---|---|---|---|
| UDS 服务端到端 `audit_request` 表不存在 | `next(glob('*.db'))` 选到独立的 syscall 数据库 | 仅选择 `YYYYMM.db` 主审计链库 | 原集成断言继续执行并通过 |
| 重启拒绝未决 Confirm 的 `audit_record` 表不存在 | 同样选错审计数据库 | 同上 | 拒绝、审计及旧确认 ID 不可复用的断言通过 |
| 无 D-Bus Worker 客户端，允许分支 | 客户端顶层无条件 `import dbus` | 将导入移动到实际使用 D-Bus 类型或代理的调用路径 | 独立进程禁止导入 dbus，真实 UDS 返回配额成功 |
| 无 D-Bus Worker 客户端，拒绝分支 | 同上 | 同上 | 真实 UDS 的 `lease denied` 继续抛出，不降级、不伪造成功 |
| WebUI placeholder 测试 | 脚本优先读取运行中服务 token，测试没有隔离进程和系统配置 | 测试使用受控 `pgrep`、临时系统配置路径 | placeholder 被拒绝；生产脚本的 token 读取优先级不变 |

这些修改不改变权限引擎、DLP、审计存储格式或 Worker 的身份校验。D-Bus 管理面仍使用
真实 `dbus` 类型，依赖缺失时仍报错，不使用假类型或静默放行。

## 3. 三项跳过的专用 E2E

`test_hermes_confirm_all_paths`、`test_e2e_full_flow`、`test_hermes_plugin_all_paths`
原本通过 `BIANBU_E2E=1` 显式启用。默认跳过是执行入口的条件，不是功能通过证据。

本轮按 `deploy/verify_all.sh --strict` 的隔离方式，使用独立 `dbus-run-session`、
临时 `BIANBU_SEC_ROOT` 和专用 `BIANBU_SEC_UDS` 实际执行：**3 passed / 0 skipped**。
它们使用本仓测试驱动，不依赖 worker 上的外部 Hermes 项目。常规测试保留默认保护；
完整验收命令已写入 [testkit/README.md](../../testkit/README.md)。

## 4. 扩大 Runtime 回归发现的旧测试问题

扩大到 `tests/runtime` 后，`test_token_metering_default_uses_security_namespace`
失败。用修复前完整源码在同一 worker、同一解释器和同一测试集合对照：

| 源码/测试 | 结果 |
|---|---|
| 原基线 `0f5f59a7` | 412 passed / 1 failed |
| 本轮修复，未调整旧测试 | 426 passed / 同一项 failed |
| 调整旧测试后 | 428 passed / 0 failed |

根因是测试仍模拟 `security_client_module`，而当前 Token 回调使用
`security_client_available`，包括已安装客户端/helper 路径。改为模拟实际可用性入口，
并独立断言回调的计量身份是 `com.bianbu.agent`，不误用本地 manifest ID。
这里只修正测试，没有修改 Token 计量或 Memory TTL 实现。

## 5. 实际安装与回归流程

两份源码在 worker 原生执行 `dpkg-buildpackage -us -uc -b`，然后用 `dpkg -i` 覆盖安装。
上一轮首次安装已按要求执行 Security reset；本轮修复升级保留原运行数据，使用包的正常
升级流程重建必要的进程绑定。安装后 `dpkg --audit`、两包 `dpkg -V` 均无输出，五个服务 active。

后续同类验收按以下顺序，不能仅看策略保存响应或 Run completed：

1. 用临时普通 Agent、同一模型及 Security 插件验证 allow_all 真实请求 completed。
2. 保存 deny_all，断言 `restart_required=true`；未重启的旧 Worker 仍能完成请求。
3. 重启 Agent，确认新 PID/instance；真实模型请求失败并返回 `network_policy_blocked`，
   details 包含实际模型域名、deny_all 和处置动作。
4. 白名单仅保留 `example.com`，重启后实际模型请求失败；即使由 120 秒模型超时触发，
   仍返回 `network_policy_blocked`。再把实际模型域名加入白名单并重启，请求须 completed。
5. 默认 Bibit Agent 在 deny_all 重启后应返回明确网络错误；恢复原策略、重启后会话 completed。
   单独核对 BeforeRun 事件耗时，不能把模型自身的 120 秒预算当成 hook 卡住。
6. syscall 探针同时验证 getpid 成功、finit_module 返回 EPERM、工具 exit_code=0，
   并查询同一 PID 的新拒绝审计事件和 `chain_valid=true`。
7. learning 保存并重启，核对当前 Worker preload；真实 DNS、HTTPS 200、失败连接均有
   当前 instance/lease 的观测记录。停止 collector 得到 degraded，恢复 active 后产生新记录。
8. 跑完整 testkit；恢复原策略和模式、删除临时 Agent/探针，核对 Memory 注册 active、
   原会话可读及五个服务 active。

## 6. 验证证据

| 项目 | 结果 | evidence/ 下的文件 |
|---|---|---|
| 原五个失败涉及的测试组 | 16 passed | `fix-security-targeted.log` |
| Security 单元/集成全集 | 793 passed，1 条 GLib 弃用提示 | `fix-security-full.log` |
| 专用 E2E | 3 passed，0 skipped | `fix-e2e.log`、`fix-e2e.xml` |
| Runtime 新增失败复现 | 8 failed / 123 passed | `fix-runtime-red.log` |
| Runtime 修复定向组 | 131 passed | `fix-runtime-green.log` |
| Runtime 修复前对照 | 412 passed / 1 个旧测试失败 | `fix-runtime-baseline.log` |
| Runtime 扩大回归最终结果 | 428 passed | `fix-runtime-regression-final.log` |
| DEB 构建和安装 | 两包成功 | `fix-runtime-build.log`、`fix-security-build.log`、`fix-install.log` |
| 真实网络策略验收 | 7 个场景均符合预期 | `fix-network-acceptance.log`、`fix-acceptance/` |

### 真实网络结果

| 场景 | 结果 | 总耗时（含 Worker 启动等开销） |
|---|---|---|
| 普通 Agent allow_all | completed | 24.86 秒 |
| 保存 deny_all，未重启 | completed，保持旧策略 | 6.99 秒 |
| deny_all 重启后 | network_policy_blocked | 25.30 秒 |
| 白名单缺少模型域名 | network_policy_blocked | 144.76 秒，包含原有 120 秒模型超时预算 |
| 白名单加入 api.minimaxi.com 后重启 | completed | 24.87 秒 |
| 默认 Bibit deny_all 重启后 | network_policy_blocked | 37.12 秒 |
| 默认 Bibit 恢复 allow_all 后重启 | completed | 51.80 秒 |

Bibit 拒绝探针 Run 为 `9ca7fbb7-370b-4b6a-8912-c600f0d18089`：BeforeRun 返回
`status=completed`、`reason=edge_error`、`route=cloud`；hook 自报执行耗时约 7.27 秒，
事件 invoked→result 间隔约 10.16 秒（含进程调度等开销）。随后模型连接失败正确分类。
网络错误中模型域名均为 `api.minimaxi.com`。临时 Agent 删除响应 HTTP 204。

两包 SHA-256：

- Runtime：`7d0a0fff3518e8c400a533eb242e41cb67d1c9d7a1f18cc6c5b7c0afba6b9bc8`
- Security：`b4030bebb4c18757a51a26484de6713aa9e41acb5ebe411c84dec0437dca94e0`

本轮仍是 development/demo 包功能验收，不替代生产签名与商用发布门禁，也不声称完成
Memory 超过 25 小时的实时时长验证。
