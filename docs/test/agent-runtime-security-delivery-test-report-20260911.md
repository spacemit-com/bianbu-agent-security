# bianbu-agent-runtime + bianbu-agent-security 交付测试报告

| 项目 | 结果 |
|---|---|
| 测试日期 | 2026-09-11 |
| Worker | `10.0.90.243`，riscv64，Linux 6.18.3-generic |
| Runtime 源码 | 远端 `main`，commit `5d41abe0` |
| Security 源码 | 当前远端工作版本，commit `fbeff50` |
| Runtime 包 | `bianbu-agent-runtime 0.1.27` |
| Security 包 | `bianbu-agent-securityd 0.1.28` |
| 证据目录 | `/var/tmp/bnsec-delivery-20260911/evidence/` |
| 总体结论 | **原三个 P0 定性撤回；复核 5/6 通过，DLP UDS 数据面仍未通过，见 §7** |

## 1. 构建与部署

两份 riscv64 DEB 均在 Worker 原生构建成功：

- `bianbu-agent-runtime_0.1.27_riscv64.deb`
- `bianbu-agent-securityd_0.1.28_riscv64.deb`

SHA-256：

- Runtime `00cb9395dca3ef15dca64bfc115b0d6e5336510c168ca2b33d2c5a0d73379bf0`
- Security `263766e3c42d0678304f89a212ad1fecb587687ad59f1f9709ea8f6f63d27f9a`

安装和重启成功，以下服务均为 `active`：

- `bianbu-securityd.service`
- `bianbu-agent-runtime@bianbu.service`
- `bianbu-security-webui.service`

Runtime HTTP 监听 `9899`，Security WebUI 实际监听 `8788`；另有旧进程占用 `8787`。

## 2. 测试结果

### Runtime 定向回归

补齐 Worker 测试环境的 `pytest-asyncio` 后，方案列出的 Runtime 定向测试结果为：

**185 passed，0 failed。**

原始日志：`/var/tmp/bnsec-delivery-20260911/evidence/runtime-targeted-rerun.log`

### Security 定向回归

结果：**39 passed，2 failed**。

失败项：

1. `test_installed_auditctl_does_not_imply_active_observer`
2. `test_observer_heartbeat_must_be_fresh_and_process_alive`

现象：测试通过 monkeypatch 设置无 collector/当前进程 heartbeat 时，`SyscallAuditStore.status()` 仍返回 `active`。根因是当前实现无条件将 `kernel_observer_status()` 的非空结果加入 active；需要进一步核对 kernel observer 的测试隔离契约。

原始日志：`/var/tmp/bnsec-delivery-20260911/evidence/security-targeted.log`

### testkit 真实端到端

使用正式安装路径、端口 `8788`、已注册 Agent ID `com.bianbu.c6f40f30a6e5` 重跑：

**36 项：30 通过、5 失败、1 错误。**

报告：`/var/tmp/bnsec-delivery-20260911/evidence/testkit-current/report.json`

## 3. 评审复核后的缺陷结论

原报告把测试失败直接归因为三个产品 P0，证据不足，现撤回 HOOK-03、DLP-04、ERR-01 的 P0 定性。原始 30/36 统计保留为历史运行结果，不代表当前复核结论。

| 用例 | 复核结论 | 原因 |
|---|---|---|
| HOOK-03 | PASS，撤回“DEFAULT_ALLOW 绕过” | 旧 testkit 读错数据库，把查询失败转换为空审计；实际存在先判权后执行 |
| ERR-01 | PASS，撤回“security_denied 未透传” | 原用例未建立 normal 前提，且 L2 web_search 不保证触发终止 Run 的拒绝路径；本轮用 L4 terminal 验证 |
| DLP-04 | BLOCK 断言 PASS，完整用例仍 FAIL | normal 下真实 Run 被阻断；UDS 数据面身份校验失败，扫描/完整审计断言仍未满足，按独立 P1 问题保留 |
| YOLO-01 | PASS | 新注册 Agent 默认 yolo 是当前实现契约；显式 normal 后 DENY 生效，切回 normal 仍恢复 DENY |
| AUDIT-01 / AUDIT-02 | PASS | 正确读取月分段主审计库后，记录和哈希链验证通过 |

## 4. 通过与阻塞边界

本轮仅复核上述 6 项：5 PASS、1 FAIL，不能合并成全量重新验收通过。DLP-04 的剩余失败不等价于 BLOCK 失效。原报告基于三个 P0 给出的发布判断撤回；整体准出仍需完整计划证据和剩余问题评估。

## 5. 复现入口

```bash
# Worker 上查看完整证据
ls -R /var/tmp/bnsec-delivery-20260911/evidence

# 重新执行 Runtime 定向回归
cd /var/tmp/bnsec-delivery-20260911/runtime
.venv/bin/python -m pytest -q tests/runtime/...

# 重新执行 testkit（正式安装布局）
cd /var/tmp/bnsec-delivery-20260911/security
PA_ROOT=/var/tmp/bnsec-delivery-20260911/runtime \
BIANBU_SECURITYD_HOME=/usr/lib/bianbu-securityd \
PA_AGENT_ID=com.bianbu.c6f40f30a6e5 \
BIANBU_PA_AGENT_ID=com.bianbu.c6f40f30a6e5 \
BNSEC_SECURITY_WEBUI_BASE=http://127.0.0.1:8788 \
python3 testkit/runner.py
```


## 6. 逐项端到端验收矩阵

统一前置条件：Worker `10.0.90.243` 在线；`bianbu-securityd`、Runtime、WebUI 已启动；使用临时 Agent 和合成数据；记录 HTTP、D-Bus、UDS、审计及下游调用证据。每项通过条件是“接口结果正确且真实下游行为与安全策略一致”。

| ID | 功能 | 测试条件 | 测试步骤 | 结果 |
|---|---|---|---|---|
| CONN-01 | Runtime HTTP 连通 | Runtime 已启动 | 请求 `/api/v1/agents`、runtime status | PASS |
| CONN-02 | Security D-Bus 总线 | securityd 已启动 | 查询 `io.bianbu.Security` 总线名 | PASS |
| CONN-03 | D-Bus 接口完整性 | Security 服务已注册 | introspect 并核对 25 个关键方法 | PASS |
| PERM-01 | Agent/能力注册 | 使用临时 Agent | 注册 Agent、读取能力目录和授权 | PASS |
| PERM-02 | ALLOW/CONFIRM/DENY | 分别配置三种授权状态 | 发起同一能力判权并观察真实调用 | PASS |
| PERM-03 | 高风险确认约束 | L3/L4 能力 | 设置 `confirm=trusted` 并请求判权 | PASS |
| PERM-04 | 撤销能力 | 已授权能力 | 撤销后再次判权并调用 | PASS |
| YOLO-01 | YOLO 模式 | 新建临时 Agent | 检查默认模式、切换 YOLO、判权、恢复 normal | 历史 FAIL；复核 PASS（默认 yolo 合约） |
| HOOK-01 | 八个安全 Hook | Runtime 插件已加载 | 检查 Hook catalog 和启用状态 | PASS |
| HOOK-02 | 普通对话链路 | 无工具、无敏感数据 | 创建 session，执行短对话，轮询终态 | PASS |
| HOOK-03 | 工具判权链路 | 工具映射和审计可读 | 执行工具，比较调用前后 Security 审计及下游次数 | 历史 FAIL；复核 PASS（判权先于执行） |
| HOOK-04 | MCP 判权 | 未授权 MCP server/tool | 调用 MCP 并检查 server 级判权和审计 | PASS |
| DLP-01 | 八类 PII 扫描 | 使用合成 name/email/phone 等数据 | 分别扫描并核对实体类型 | PASS |
| DLP-02 | PII 校验与误报防护 | 合法/非法身份证和银行卡样本 | 扫描样本并比较命中结果 | PASS |
| DLP-03 | 双信号泄露检测 | 构造逐字泄露 payload | 经输入、模型、工具、输出路径检查 | PASS |
| DLP-04 | 正式 UDS DLP | 中央策略设为 block，payload >4KB | 真实 Run 发送 payload，检查下游、UDS 审计和终态 | 复核：BLOCK PASS；UDS 审计仍 FAIL |
| TOKEN-01 | Token 配额读写 | 临时 Agent 有 token 配额 | 写入并读取 session/day limit 和策略 | PASS |
| TOKEN-02 | Token 实际计量 | 可用模型配置 | 执行真实 LLM Run，比较 usage、持久化用量和审计 | PASS |
| SBX-01 | bwrap 基础隔离 | bwrap 可用 | 启动 sandbox Worker，检查 backend 和隔离标志 | PASS |
| SBX-02 | PID namespace | sandbox Worker | 读取 Worker 内外 PID 和 namespace inode | PASS |
| SBX-03 | 无网络隔离 | `net=false` | 在 sandbox 内尝试 DNS/网络连接 | PASS |
| SBX-04 | 工具参数返回序列化 | 使用无害工具 | 执行工具并核对参数、返回值和边界 | PASS |
| SBX-05 | 网络开启模式 | `net=true` | 在 sandbox 内解析测试域名 | PASS |
| AUDIT-01 | 普通审计写入 | Security 审计库可读 | 执行注册、判权、Run 并查询新增事件 | 历史 FAIL；正确选库后 PASS |
| AUDIT-02 | 审计哈希链 | 已产生审计记录 | 查询 `audit_record` 并校验 prev/hash 链 | 历史 ERROR；正确选库后 PASS |
| AUDIT-03 | 审计导出 | 有可导出的审计数据 | 调用 ExportAudit，核对导出文件 | PASS |
| CAP-01 | 能力目录一致性 | Runtime/Security 映射可读 | 逐项检查映射能力是否存在于权威字典 | PASS |
| MCP-01 | 未授权 MCP fail-closed | 使用不存在/未授权 server | 发起调用并检查待授权记录、下游调用数 | PASS |
| CAP-02 | MCP server 边界判权 | server 已配置、tool 名可变 | 使用同名/异名 tool 比较 server 级判权 | PASS |
| CAP-03 | 高风险关键字推断 | 构造多能力命中请求 | 检查最终选择是否为最高风险能力 | PASS |
| CAP-04 | 未映射工具确认 | 使用未登记工具 | 判权并在未确认前检查下游调用 | PASS |
| CODE-01 | 安装期签名校验 | 有效包及篡改包 | 分别安装/加载并比较签名校验结果 | PASS（本次包为 demo 配置，生产签名仍需另验） |
| SCOPE-01 | 命令 scope 规范化 | 设置允许路径和复合命令 | 测试正常路径、`..`、软链接和 shell 元字符 | PASS |
| EGRESS-01 | 远端 MCP 出境提档 | 模拟远端 server | 调用并检查确认升级、审计和下游状态 | PASS |
| SKILL-01 | Skill DLP | Skill 含合成敏感信息 | 加载 Skill，检查 prompt 和下游 payload | PASS |
| ERR-01 | 安全错误透传 | 配置拒绝能力 | 发起真实 Run，检查终态、错误码、能力名和前端消息 | 历史 FAIL；normal/L4 场景复核 PASS |

## 7. 评审意见独立复核（2026-09-11）

使用当前仓库 `4d436fd` 中已有的 testkit 修订副本，在同一 Worker 实测；本次未修改 Runtime、Security 或 testkit 实现，未重装服务。本轮测试与最初源码/进程状态可能有时间差，因此也核对了旧 testkit 源码和已有 cc-tester 原始证据，不能仅由本轮 PASS 推断最初部署的全部行为。

**审计库误选已经证实。** 旧 `Ctx.audit_seq()`、`audit_since()` 使用 `sorted(glob("*.db"))[-1]`；在包含 `202609.db`、`network-learning.db`、`syscall-events.db` 的目录中选中后者。后者没有 `audit_record`，异常被转为 `-1` / `[]`。因此“无审计增量”不是“未判权”的证据。新 testkit 优先读取月分段主链库。

**模式前置条件已经证实。** `capability_registry.py` 初始化为 `yolo`，来源 `initial-agent-default`。拒绝场景需显式切 normal；testkit 的 `enforcing_mode()` 会临时切换模式、抬高 Token 配额避免配额阻断干扰，并恢复原模式及配额。本轮不验证 Token 配额限制。旧 YOLO 用例的“normal 保留原 DENY”实际上没有先切 normal；不能据此声称恢复 normal 后 DENY 不生效。

| 复测项 | 可核对事实 | 结果 |
|---|---|---|
| HOOK-03 | `file.read:/etc/hostname` 的 allow 判权 seq=958/959，`read_file` 执行 seq=961 | PASS，判权早于执行 |
| ERR-01 | normal 下撤销 `system.execute`，实际判权 deny，无 terminal 执行审计，Run failed；error.code=`security_denied`，details.tool=`terminal`、capability=`system.execute`、degraded=false | PASS |
| DLP-04：中央 BLOCK | 临时中央 phone=block，发送 >4KB 合成输入，normal 下 Run failed | 阻断断言 PASS |
| DLP-04：UDS 数据面 | 无 `uds_dlp_scan` 和完整输入 `audit.batch` 记录；journal 中 dlp.scan/dlp.policy/audit.batch 被拒：`Worker 未通过已提交 Runtime lease 身份校验` | 用例整体 FAIL，独立身份/传输问题 |
| AUDIT-01/02 | 正确主链数据库可读，审计增量及哈希链断言通过 | PASS |
| YOLO-01 | 默认 yolo，normal DENY=2，yolo ALLOW=0，再切 normal DENY=2 | PASS |

这里严格依据 `steps[].ok` 和原始事件判断。部分 `detail` 是无论断言成功或失败都会填入的预设错误文案，不能把其中“绕过”“可能仍在读本地库”等文字当作实测根因。

### 复核命令与恢复条件

在 Worker 上执行（本次已部署脚本到 `/var/tmp/bnsec-review-p0/testkit`）：

```bash
cd /var/tmp/bnsec-review-p0
PA_ROOT=/var/tmp/bnsec-delivery-20260911/runtime \
BIANBU_SECURITYD_HOME=/usr/lib/bianbu-securityd \
PA_AGENT_ID=com.bianbu.c6f40f30a6e5 \
BIANBU_PA_AGENT_ID=com.bianbu.c6f40f30a6e5 \
BNSEC_SECURITY_WEBUI_BASE=http://127.0.0.1:8788 \
BNSEC_OUT=/var/tmp/bnsec-review-p0/result \
python3 testkit/runner.py HOOK-03 DLP-04 ERR-01 AUDIT-01 AUDIT-02 YOLO-01
```

前置：服务已启动，WebUI 管理凭据可从现有配置读取且不输出；Agent 存在、无并行策略修改。用例会临时修改模式、Token 上限、DLP phone 策略和 system.execute 授权；应在专用测试环境执行。ERR-01 现有清理代码对原先已存在的能力恢复 granted=1，因此执行前必须确认原授权为 1，不能在任意拒绝策略环境中直接运行。模式/配额恢复日志保存在报告中。

步骤：HOOK-03 请求 read_file 并比较审计 seq；DLP-04 通过管理面设置中央 block、等待缓存 6 秒、发送合成载荷并恢复策略；ERR-01 撤销 system.execute 后请求 terminal 执行无害 `echo BNSEC-ERR01`，核验拒绝事件而不是仅凭 Run 终态猜测。旧 web_search 用例的 L2 工具拒绝可能作为工具消息交给模型继续处理；不得要求所有 DENY 都导致整个 Run failed。

原始复测证据：[report.json](evidence/p0-review/report.json)、[Security UDS 日志](evidence/p0-review/securityd-uds.log)。Worker 原件位于 `/var/tmp/bnsec-review-p0/result/report.json`。

已有交叉证据：[cc-tester 第三轮报告](cc-tester/evidence/testkit/run3-report.json) 同样记录 HOOK-03、ERR-01 通过及 DLP BLOCK 生效、UDS 数据面未通过。残余问题详见 [M-1 分析](cc-tester/04-defect-list-and-fix-plan.md)。

## 8. 修订结论

用户评审意见关于旧报告的三个 P0 误判成立。撤回“未授权执行”“DENY 错误透传失效”“中央 BLOCK 不生效”的结论；保留 DLP-04 的 UDS 身份校验/完整审计缺口，不将其写成全项通过。本轮只修订报告并补充复测证据，未直接修复产品代码。
