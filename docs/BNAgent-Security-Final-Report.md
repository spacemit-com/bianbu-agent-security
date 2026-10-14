# Bianbu Security 完成与商用交付报告

| 项 | 内容 |
|----|------|
| 文档编号 | BN-SEC-FINAL-001 |
| 版本 | V1.3 |
| 日期 | 2026-08-17 |
| 覆盖范围 | `impl/bianbu-securityd/`、`testkit/`、配套 personal-agent 安全接入及交付文档 |
| 代码状态 | Security 仓库侧需求已完成 |
| 验证状态 | worker 全量、strict 仓库项、真实安装/升级/回滚和 Security 发布证据门禁已通过 |
| 商用状态 | 商用候选；正式签收仍需 24/72 小时耐久和组织级运营证据 |

> **范围声明：** `/data/workspace2026-new/work0618/bianbu-next-agentos-dev-cc`
> 及正式 Agent Runtime 的实现不在本次交付范围。本报告不修改、不部署、不测试该仓，
> 也不把其完成度计入 Bianbu Security 的完成度。

2026-08-17 生产复验的原始指标、失败分析与剩余工作见
[`review/BNAgent-Security-Acceptance-Revalidation-2026-08-17.md`](review/BNAgent-Security-Acceptance-Revalidation-2026-08-17.md)。

## 1. 执行结论

Bianbu Security 已完成 Capability 判权、确认、Token 计量、DLP、审计、沙箱、UDS、
WebUI、LangGraph/Personal Agent 接入、生产安装和发布证据生成等仓库侧工作。当前可作出
以下分层结论：

| 判定口径 | 结论 | 依据 |
|----------|------|------|
| 功能开发 | **完成** | 86/86 条仓库侧需求已有实现 |
| 仓库验证 | **通过** | worker 默认全量 `551 passed / 3 skipped` |
| strict 仓库项 | **通过** | `537 unit + 14 integration + 3 E2E`，E2E `skipped=0` |
| 端到端业务验证 | **通过** | testkit `35/35`；PA 安全开/关失败集合一致，无新增回归 |
| Security 发布证据门禁 | **通过** | `security_scope_status=passed`，原始日志、JUnit、SBOM、CVE、源码 manifest 和哈希已归档 |
| 长期可靠性 | **未达到** | 原长跑约 64.6h 后因 P99 超标停止；v4 预演已达标，但尚无新的 72h 通过报告 |
| 无条件商用签收 | **暂不宣称** | 仍缺正式 24/72 小时、组织级 CA/密钥运营、桌面 seat 授权和第三方渗透证据 |

全产品 strict 在 worker 缺少正式 Runtime 时仍会输出
`BNSEC_VERIFY_ALL_STRICT_FAIL gates=doctor,runtime_production`。这是全产品集成诊断的
fail-closed 行为，不表示本次 Security 责任域失败，也不得用范围外候选 Runtime 刷绿。

## 2. 交付范围与责任边界

### 2.1 本次交付

| 交付域 | 主要内容 |
|--------|----------|
| securityd | D-Bus 服务、可信 caller 绑定、Capability、Confirm、Token、审计、DLP、沙箱策略、网络策略、Key Vault |
| 数据面 | `/run/bianbu/securityd.sock` 生产 UDS、大文本 DLP 和批量审计 |
| 管理面 | Python client、bncli、认证 WebUI、Gunicorn、SSE、Web Terminal、polkit |
| Agent 接入 | Personal Agent 8 个 Hook、MCP 两层判权、中央 DLP、动态 HITL、Token 上报、LangGraph broker |
| 工程交付 | systemd/D-Bus policy、安装/升级/回滚、依赖锁、SBOM/CVE、release gate、24/72 小时耐久执行器、签名式最终商用验收门禁 |
| 验证 | 单元、集成、真实 E2E、testkit、PA 回归、worker 生产形态验证 |

### 2.2 明确不在本次交付

| 项 | 处理原则 |
|----|----------|
| `bianbu-next-agentos-dev-cc` | 不修改、不部署、不引用其测试成绩作为本项目证据 |
| 正式 `bianbu-agent-runtimed` | 由 Runtime 项目实现暂停、终止、生命周期、模型/工具后续门禁 |
| Bianbu Next 其他子系统 | AI HAL、Memory、Skill、Calendar 等不计入 Security 完成度 |

Securityd 对 Token 超限的职责已经冻结为：校验计量、拒绝当前超限调用、写审计并发送
`TokenExceededV2`。Securityd 不调用 `Runtime.Pause/Stop/Terminate`，也不通过停止
服务实现“暂停”；真实状态切换由收到通知的 Runtime/agent 自行完成。

## 3. 功能完成度

| 需求域 | 状态 | 完成内容 |
|--------|------|----------|
| SEC | 完成 | Manifest、Capability、Confirm、Token、调用者身份、网络策略、Key Vault、审计 |
| SBX | 完成 | bwrap、seccomp、文件/namespace/capability 隔离、资源策略和 fail-closed |
| SEC-HOOK | 完成 | 8 个干预点、优先级、短路、决策合并、透明审计 |
| DLP | 完成 | PII、输入/模型/工具/输出、逐字泄露、远端 MCP 出境提升、中央策略 |
| ARCH | 完成 | D-Bus 控制面 + UDS 数据面，PA 生产选路已验证 |
| INT-LG | 完成 | ToolNode、动态 HITL、Token、跨进程 resume broker、WebUI 恢复入口 |
| MGT | 完成 | SDK、CLI、认证 WebUI、实时事件、生产 Gunicorn 和专用服务身份 |
| Release | 完成 | 安装、成功升级、切换后故障回滚、锁文件、SBOM、CVE、证据归档 |

仓库侧需求总计 **86/86 已实现**。LangGraph broker 的正式调用方接入属于调用方产品
验收，不改变本仓实现完成状态。

## 4. 当前验证基线

### 4.1 自动化与端到端

| 测试 | worker 结果 | 判定 |
|------|-------------|------|
| securityd 默认全量 | `551 passed / 3 skipped` | 通过；3 条为默认模式下的外部 E2E，strict 会真实执行 |
| securityd strict | `537 unit + 14 integration + 3 E2E`，`skipped=0` | 仓库项通过 |
| testkit | `35/35` | 真实 PA + 真实 securityd 业务闭环通过 |
| PA 回归 | `848 passed / 73 failed` | 73 条为 worker 环境基线；安全开/关失败集合一致 |
| 耐久执行器单测 | `9 passed` | 运行初期延后检查和输出目录处理通过 |
| 最终验收门禁单测 | `6 passed` | 完整签名包通过；短耐久、高危漏洞、单人审批、坏签名、吊销密钥均拒绝 |

### 4.2 生产形态证据

| 项 | 结果 |
|----|------|
| securityd / WebUI systemd | 专用身份运行，服务 active |
| WebUI | Gunicorn、回环监听、Bearer token、401/200/403 路径验证通过 |
| UDS | 默认 `/run/bianbu/securityd.sock`，PA 产品选路和权限验证通过 |
| D-Bus policy / polkit | 私有总线与 worker 生产安装验证通过 |
| 安装/升级/回滚 | 干净安装、成功升级、切换后健康失败自动回滚通过 |
| 供应链 | hermetic venv、依赖锁、SBOM、许可证、CVE 扫描 0 漏洞通过 |
| 故障恢复 | D-Bus/UDS/SQLite/service restart、SQLITE_FULL/只读、Confirm 重启和审计链通过 |

### 4.3 性能与短稳

| 指标 | 实测 | 标准 |
|------|------|------|
| CheckPermission strict P99 | 3.594ms（100 样本） | ≤10ms，通过 |
| DLP | 召回 99.75%，误报 0.75% | 达标 |
| UDS 吞吐 | 29.4MB/s | 达标 |
| bwrap 冷启动 | P99 46.787ms；相对裸启动约 +11.084ms | ≤200ms |
| 短稳 | 40552 次、0 错误、审计链完整 | 通过 |
| 生产间隔采样 | v4 600s/120 样本，P99 9.276ms、0 error、RSS 增长 52.746MB | ≤10ms，通过 |

## 5. 发布证据门禁

正式入口：

```bash
cd /home/bianbu/impl/bianbu-securityd
BNSEC_RELEASE_COMMIT=REPLACE_WITH_COMMIT
BNSEC_PYTHON=/var/tmp/bnsec-release-venv-hermetic.WuUZU2/bin/python \
BNSEC_CVE_SCANNER=/var/tmp/bnsec-release-venv-hermetic.WuUZU2/bin/pip-audit \
BNSEC_SOURCE_REVISION="$BNSEC_RELEASE_COMMIT" \
BNSEC_EVIDENCE_DIR="/var/tmp/bnsec-security-release-$BNSEC_RELEASE_COMMIT" \
BNSEC_STABILITY_SECONDS=10 \
BNSEC_PERF_SAMPLES=100 \
bash .ci/run_tests.sh
```

验收要求：

- 输出 `SECURITY_RELEASE_GATE_PASS`；
- `security-release-summary.json` 中 `security_scope_status=passed`；
- 所有要求的 pass marker 齐全；
- 不允许出现 Security 自有 doctor 或 strict 门禁失败；
- 证据包包含 JUnit、doctor、SBOM、CVE、源码 manifest、原始日志及 SHA-256；
- Runtime 缺失只允许记录为 `product_status=blocked_external`，不得改写为 Security 失败或伪造通过。

正式实现基线为 `f956d809f9d7454f496bc538e45524ee2e19996f`，证据位于
`/var/tmp/bnsec-security-release-f956d809f9d7454f496bc538e45524ee2e19996f-clean1`。结果为
`SECURITY_RELEASE_GATE_PASS`、`security_scope_status=passed`、
`product_status=blocked_external`；summary SHA-256 为
`a62f521528c287a9df7c38e93d0e4e2e8222f52bf6e9f8198bbbe0c5fa53074e`。
167/167 个 Git 跟踪文件与该提交逐文件哈希一致，8 个附件的大小和 SHA-256 已逐项复核一致。

## 6. 剩余工作及完成方式

剩余工作只列本次 Security 交付仍需收口的发布/运营证据，不再把范围外 Runtime 开发
列为本项目任务。

| 优先级 | 工作 | 当前状态 | 完成标准 |
|--------|------|----------|----------|
| P0 | worker 验收环境清理 | 范围外 `hermes-agent` 约每 10.5s 失败重启 | 验收窗口无循环失败 unit，对应 `NRestarts` 不再增长 |
| P0 | 正式 24/72 小时耐久 | 执行器完成，当前无任务运行 | 24h 与 72h 报告均生成；最终 `status=passed`、`failures=[]` |
| P0 | 正式版本/tag 与审批 | 待 Release 流程 | tag、变更单、证据包和审批记录关联同一 commit |
| P1 | 组织级签名 CA | worker 仅有验证根 | 正式 CA、密钥托管、轮换、吊销及恢复演练有记录 |
| P1 | 桌面 seat/polkit 验收 | 服务端授权已完成 | 真实桌面会话完成允许/拒绝/过期/重放测试并留日志 |
| P1 | 第三方渗透 | 尚无外部报告 | 高危/严重问题为 0，其余问题有关闭或风险接受记录 |

生产 P99 复验和最终实现提交证据包已在 2026-08-17 关闭：v4 达到
`P99=9.276006 ms`，正式证据绑定 `f956d809…` 且 8 个附件哈希一致。

上述四类外部/运营证据的机器验收入口已经实现为
`deploy/commercial_acceptance_gate.py`。门禁要求审批 JSON 的证据 SHA-256 与实际文件
一致、至少两名不同审批人，并由组织受信且未吊销的 Ed25519 公钥验证通过。缺少任何
报告、附件、哈希或签名时均 fail-closed；通过后归档发布 JUnit/doctor/SBOM/CVE/
manifest/strict 日志、72 小时原始 samples、外部附件和实际验签公钥。

### 6.1 启动正式耐久任务

```bash
cd /home/bianbu/impl/bianbu-securityd
BNSEC_RELEASE_COMMIT=REPLACE_WITH_COMMIT
SOAK_PYTHON=python3 bash deploy/start_commercial_soak.sh start "$BNSEC_RELEASE_COMMIT"
bash deploy/start_commercial_soak.sh status
```

脚本默认运行 72 小时并在 24/72 小时生成里程碑。运行初期
`insufficient_latency_samples`、样本不足时的 `permission_p99`、`audit_chain` 应显示
在 `pending_checks`；样本达到门限后仍超标的 P99 才进入 `failures`。最终必须同时满足：

- 两项 systemd 服务持续 active，非计划重启为 0；
- D-Bus、生产 UDS、WebUI health 全程无操作错误；
- SSE 有连接和消息，重连=0、errors=[]；
- 判权样本数≥100、P99≤10ms；
- securityd RSS 增长≤64MB；
- 审计链验证通过；
- `report.samples.jsonl` 行数等于 iterations/latency_samples，大小和 SHA-256 与最终报告一致。
- 24h 和 72h 两份 milestone JSON 实际存在，内容状态为 `milestone`、审计链通过，
  并且文件大小和 SHA-256 与最终报告一致。

### 6.2 发布签收顺序

1. 已冻结实现基线 `f956d809…`，完成 worker 回归并生成 Security 证据包；
2. 由 worker 所有者先清理范围外循环失败 unit，固定验收窗口；
3. 启动 72 小时任务，24 小时检查里程碑但不中断；
4. 72 小时结果通过后，执行组织 CA、桌面 seat 和渗透证据复核；
5. Release 负责人将 tag、manifest、SBOM/CVE、JUnit、耐久报告和审批记录关联归档。

## 7. 外部接口移交项（不计入本次剩余工作）

Runtime/agent 责任方可依据 `review/Runtime-Production-Integration-Checklist.md` 验收：

- 订阅 `TokenExceededV2` 并校验 agent/session/run/policy_version；
- 将合法超限事件映射为自身 PAUSED/TERMINATED 状态；
- 在模型和工具入口执行后续门禁；
- 处理重复事件、重启恢复和用户提示；
- 提供正式 unit、UID/cgroup 和生产总线证据。

这些是系统集成输入，不是 Security 项目的未完成代码，也不影响本报告的 86/86 完成度。

## 8. 最终判定

> **Bianbu Security 仓库侧功能、测试、生产安装和可归档发布证据门禁已经完成。当前
> 交付状态为“Security 商用候选”；完成 24/72 小时耐久及组织级发布运营证据后，可由
> Release/质量负责人执行正式商用签收。范围外 Agent Runtime 项目不得计入本次完成度，
> 也不得作为拖延或伪造 Security 交付结论的依据。**
