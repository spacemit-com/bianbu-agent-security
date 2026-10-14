# Bianbu Security 阶段验收总结

| 项 | 内容 |
|----|------|
| 文档编号 | BN-SEC-ACCEPT-001 |
| 版本 | V1.3 |
| 验收日期 | 2026-08-14（阶段验收）；2026-08-17（复验） |
| 验收对象 | Bianbu Security 子系统及配套 Personal Agent 安全接入 |
| 验收范围 | `impl/bianbu-securityd/`、`testkit/`、Personal Agent 安全 Hook 与接入链路 |
| 验收阶段 | 仓库功能与工程交付阶段验收 |
| 验收结论 | 仓库侧功能、自动化验证和 Security 工程交付达到商用候选标准；尚未达到最终商用签收标准 |

> 本文主体保留 2026-08-14 的阶段验收记录。2026-08-17 复验已确认原长跑因
> `permission_p99` 失败并停止，当前没有 24/72 小时任务在运行。当前有效证据、
> 失败分析和剩余工作见
> [`BNAgent-Security-Acceptance-Revalidation-2026-08-17.md`](BNAgent-Security-Acceptance-Revalidation-2026-08-17.md)。

## 1. 范围与责任边界

本次验收覆盖 securityd 判权、DLP、审计、沙箱、Token 计量、管理面、生产安装资产，
以及 Personal Agent 的安全 Hook 和端到端接入。

以下内容不属于本次交付范围：

- `/data/workspace2026-new/work0618/bianbu-next-agentos-dev-cc`；
- 正式 `bianbu-agent-runtimed` 的实现、安装、暂停、终止和生命周期管理；
- Bianbu Next 的 AI HAL、Memory、Skill、Calendar 等其他子系统。

Token 超限后的职责边界已经冻结：Securityd 校验计量、拒绝当前超限调用、写审计并
发送 `TokenExceededV2`；Securityd 不调用 Runtime 暂停/停止接口，也不通过停止服务
实现暂停。Runtime/agent 收到事件后的状态切换属于外部责任域。

## 2. 已完成功能

| 功能域 | 已完成内容 | 阶段判定 |
|--------|------------|----------|
| Capability 判权 | ALLOW/CONFIRM/DENY、撤销、风险分级、caller 绑定、未注册 fail-closed、未映射工具默认确认 | 达标 |
| Personal Agent 接入 | 8 个安全 Hook、MCP 两层判权、动态 HITL、错误原因透传、中央 DLP、Token 上报 | 达标 |
| Token 治理 | 预算读写、真实调用计量、超限拒绝、审计和 `TokenExceededV2` 通知 | 达标 |
| DLP | 8 类 PII、校验和降误报、逐字泄露、流式扫描、大载荷 UDS、远端出境提档 | 达标 |
| 审计 | 哈希链、导出、验证、批量审计、跨重启和存储故障恢复 | 达标 |
| 沙箱 | bwrap、namespace、网络隔离、capability/seccomp、资源限制、参数和返回值序列化门禁 | 达标 |
| D-Bus 与 UDS | 正式 D-Bus 契约、系统总线 policy、生产 UDS、调用身份与目录权限 | 达标 |
| WebUI | Bearer 鉴权、Gunicorn、SSE、回环监听、专用身份、管理授权与终端开关 | 达标 |
| LangGraph | ToolNode 判权、异步 HITL、interrupt/resume broker、重放和跨 agent 隔离 | 达标 |
| 工程交付 | systemd、安装、升级、迁移、故障回滚、依赖锁、SBOM、CVE、发布证据门禁 | 达标 |
| 最终验收工具 | 72 小时报告、CA、桌面、渗透、双人审批和 Ed25519 签名的 fail-closed 校验 | 工具达标，正式输入证据待提供 |

按当前 SRS/实现追溯口径，仓库侧需求为 **86/86 已实现**。

## 3. 验证证据

| 验证项 | 最新结果（2026-08-17） | 判定 |
|--------|----------------|------|
| securityd 默认全量 | `557 passed / 3 skipped` | 通过；3 条为默认模式外部 E2E |
| Token Runtime 消费链 | `TOKEN_RUNTIME_E2E_PASS` | 通过；通知、PAUSED、后续 model/tool 拒绝、幂等和重启恢复 |
| securityd strict | `543 unit + 14 integration + 3 E2E`，`skipped=0` | 通过 |
| PA + securityd 端到端 | testkit `35/35` | 通过 |
| PA 全量回归 | `848 passed / 73 failed`；安全开/关失败集合一致 | 无新增回归 |
| 安装流专项 | `15 passed` | 通过 |
| 长跑执行器专项 | `11 passed` | 通过 |
| 最终商用验收器专项 | `9 passed` | 通过 |
| Security 发布证据门禁 | `security_scope_status=passed` | 通过 |
| 供应链 | hermetic venv、SBOM、许可证、CVE 扫描 0 漏洞 | 通过 |
| 安装/升级/回滚 | 干净安装、成功升级、切换后故障自动回滚 | 通过 |

2026-08-14 已提交代码证据基线为
`c01dc2b4b9ad823a67c13e5ef2135515e71ebdaa`：

- 发布证据目录：`/var/tmp/bnsec-security-release-c01dc2b`；
- 发布门禁：`SECURITY_RELEASE_GATE_PASS`；
- 8 类原始证据的文件大小和 SHA-256 已重新计算并与 summary 一致；
- wheel：`/var/tmp/bnsec-wheel-c01dc2b/bianbu_securityd-1.0.0-py3-none-any.whl`；
- wheel SHA-256：`99a88aff66c58187175df6ab5bddcdac2fc4eec0b2240d5eba2b76a957829063`。

2026-08-17 最终 Security 实现基线为
`f956d809f9d7454f496bc538e45524ee2e19996f`，正式证据目录为
`/var/tmp/bnsec-security-release-f956d809f9d7454f496bc538e45524ee2e19996f-clean1`。结果为
`SECURITY_RELEASE_GATE_PASS`、`security_scope_status=passed`、
`product_status=blocked_external`；summary SHA-256 为
`a62f521528c287a9df7c38e93d0e4e2e8222f52bf6e9f8198bbbe0c5fa53074e`。
167/167 个 Git 跟踪文件与该提交一致，8 个原始附件的大小和 SHA-256 已逐项复核一致。

全产品字段 `product_status=blocked_external` 只表示 worker 缺少范围外正式 Runtime，
不表示 Security 责任域验证失败，也不得通过部署参考 Runtime 将其伪造为通过。

## 4. 分层达标结论

| 标准层级 | 结论 | 说明 |
|----------|------|------|
| 功能实现标准 | **达到** | 86/86 条仓库侧需求已有实现 |
| 自动化测试标准 | **达到** | 默认、strict、真实 E2E、PA 接入和安装流均有通过证据 |
| Security 工程交付标准 | **达到** | 生产身份、正式 UDS、安装回滚、供应链和发布证据门禁均已关闭 |
| 长期可靠性标准 | **未达到** | 原任务运行约 64.6h 后因 P99 超标停止，无通过的 72h 报告 |
| 最终商用签收标准 | **未达到** | 长期报告及组织级运营、渗透和审批证据尚未齐全 |

因此，当前可以将项目定义为 **Security 商用候选**，不能定义为“已完成最终商用验收”
或“无条件 GA”。

## 5. PA 验证边界

Personal Agent 已参与 testkit `35/35` 真实端到端测试，覆盖工具调用、securityd 判权、
MCP、DLP、Token 上报和安全错误透传。

原 v1 商用 soak 执行器不是 PA 长跑。2026-08-17 已实现 v2 执行器，直接访问
Securityd D-Bus、生产 UDS、WebUI health/SSE、systemd 和审计链，并每 6 小时真实
调用 PA 完成 run、`bianbu.memory/memory`、Token 计量和 `mcp.*` 判权审计。因此：

- 当前没有新的正式 72 小时 v2 报告，不能声称“PA + Security 连续运行 72 小时”已
  达标；
- 最终门禁只接受 v2 报告，至少 12 次 PA canary 必须全部成功；
- worker 当前虽报告 systemd `running`，但 `hermes-agent.service` 为
  `activating/auto-restart`；正式 launcher 已增加 transient service fail-closed 检查并
  拒绝启动，待范围外重启风暴由其所有者清理后再启动。

## 6. 最终签收前置条件

| 待完成项 | 完成标准 |
|----------|----------|
| 24/72 小时 Security 耐久 | 24h/72h 里程碑存在，最终 `status=passed`、`failures=[]`；P99≤10ms、RSS≤64MB、0 error、服务/SSE/审计链稳定 |
| PA + Security 长期稳定性 | v2 真实 PA canary 至少 12 次全部成功；每次有 Token 用量、`mcp.*` 判权审计和原始样本 |
| 组织级 CA | 正式 CA 安装、轮换、吊销、恢复演练及附件哈希齐全 |
| 真实桌面授权 | 真实 seat/session 完成 allow、deny、expired、replay 验证并留存日志 |
| 第三方渗透 | 覆盖 securityd、WebUI、D-Bus、UDS；严重和高危遗留为 0 |
| 发布审批 | 正式 tag、变更单、至少两名不同审批人、证据 SHA-256 和组织 Ed25519 签名一致 |

上述证据齐全后，使用 `deploy/commercial_acceptance_gate.py` 执行最终机器签收。只有
输出 `COMMERCIAL_ACCEPTANCE_PASS`，方可由 Release/质量负责人批准最终商用发布。

## 7. 验收意见

> 截至 **2026-08-17**，Bianbu Security 的仓库侧功能、自动化验证、生产安装和
> Security 发布证据达到阶段验收标准，v4 生产预演也达到 `P99≤10 ms`。原长跑
> 未通过且尚无新的 72 小时报告；组织级 CA、真实桌面、第三方渗透和正式审批证据未完成，
> 本次不作最终商用签收结论。
