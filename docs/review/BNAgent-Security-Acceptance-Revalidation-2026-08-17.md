# Bianbu Security 阶段验收复验报告

| 项 | 内容 |
|----|------|
| 文档编号 | BN-SEC-ACCEPT-002 |
| 版本 | V1.3 |
| 验收日期 | 2026-08-17 |
| 验收对象 | Bianbu Security 子系统、testkit 及 Personal Agent 安全接入 |
| 实测平台 | worker `10.0.90.243`，SpacemiT K3 riscv64 |
| 生产预演标识 | `p99-candidate-v4` |
| 上一轮实现基线 | `f956d809f9d7454f496bc538e45524ee2e19996f` |
| 本轮实现基线 | v2 改动随本次提交冻结 |
| 验收结论 | 功能、自动化、Security 发布门禁达标；PA-inclusive 600 秒预演的 P99 和 72 小时及组织级证据未达标 |

## 1. 结论摘要

截至 **2026-08-17**，Bianbu Security 仍可定义为 **Security 商用候选**，
但不能定义为“长期可靠性已验收”或“最终商用签收完成”。

本轮已确认：

- securityd 默认全量 **557 passed / 3 skipped**；
- strict 候选门禁 **543 unit + 14 integration + 3 E2E passed**，E2E `skipped=0`；
- Personal Agent 参与的 testkit 真实端到端验证 **35/35**；
- Security 发布门禁输出 `SECURITY_RELEASE_GATE_PASS`，
  `security_scope_status=passed`；
- 范围外正式 Runtime 缺失仅记为 `product_status=blocked_external`；
- Security-only 生产 10 分钟预演 v4 曾通过：120 样本、P99 `9.276006 ms`、0 error；
- 新 v2 PA-inclusive 预演真实完成 PA run、Token 和 MCP 判权审计，但 600 秒 P99 为
  `12.159528 ms`，不能作为长期通过证据；
- 当前没有 24/72 小时长跑进程，也不应在 worker 外部重启风暴未清理前启动新的
  正式 72 小时任务。

## 2. 范围与固定边界

本次验收范围为 `impl/bianbu-securityd/`、`testkit/` 和配套 Personal Agent
安全 Hook/接入。以下不在本次交付范围：

- `/data/workspace2026-new/work0618/bianbu-next-agentos-dev-cc`；
- 正式 `bianbu-agent-runtimed` 的实现、安装和生命周期管理；
- worker 上 `hermes-agent` 的修复或复用。

Token 超限边界保持不变：Securityd 只拒绝当前超限调用、写审计并发送
`TokenExceededV2`；暂停/终止 agent 或服务属于 Runtime/agent 责任域。

## 3. 当前有效验证证据

| 验证项 | 结果 | 判定 |
|--------|------|------|
| 审计/故障恢复专项 | `27 passed` | 通过 |
| securityd 默认全量 | `557 passed / 3 skipped` | 通过；3 条外部 E2E 由 strict 真实执行 |
| Token Runtime 消费链 | `TOKEN_RUNTIME_E2E_PASS` | 通过；V2 上下文、PAUSED、model/tool 拒绝、幂等和恢复 |
| strict unit | `543 passed` | 通过 |
| strict integration | `14 passed` | 通过 |
| strict E2E | `3 passed`，`skipped=0` | 通过 |
| PA + securityd 端到端 | testkit `35/35` | 通过；PA 进程和 9899 端口真实参与 |
| strict 判权性能 | `P99=3.594 ms`，`max=5.988 ms` | 通过 `P99≤10 ms` |
| 10 秒稳定性 | `40552 ops`，`chain=True` | 通过；不替代长时测试 |
| 沙箱性能 | P99 `47.323 ms`，overhead P99 `12.167 ms` | 通过 `≤200 ms` |
| 供应链 | `SBOM_PASS`、`CVE_SCAN_PASS vulnerabilities=0` | 通过 |
| Security 责任域门禁 | 实现提交 `f956d809…` 的正式证据包 | `security_scope_status=passed` |
| 全产品状态 | `blocked_external` | 只因 `doctor,runtime_production`，不伪造 Runtime 通过 |

正式证据目录为
`/var/tmp/bnsec-security-release-f956d809f9d7454f496bc538e45524ee2e19996f-clean1`。
该目录在只含目标提交文件的独立 worker 目录中生成；release manifest 的 167 个
Git 跟踪文件与提交逐文件 SHA-256 一致，缺失数和不一致数均为 0，另有 5 个门禁运行时
生成的构建元数据文件。summary SHA-256 为
`a62f521528c287a9df7c38e93d0e4e2e8222f52bf6e9f8198bbbe0c5fa53074e`。

| 正式发布附件 | 大小（字节） | SHA-256 |
|--------------|-------------:|--------|
| `cve-report.json` | 4980 | `c469a5f1c04e78efd8e82d70dd2c697e784cb8d4677ff8720931b65b42cbf4b5` |
| `doctor.json` | 3895 | `4b651fc713918474f55619016bbba250f1d37edde3a26b62ef54bf03010e6352` |
| `e2e.xml` | 560 | `77addd26405830166dd2500064987663be5eaea1baf0381fa135236b50cf7103` |
| `integration.xml` | 1915 | `6361c5bd447f0e467674014bb4563790519461857b5941cc66310014467b4c34` |
| `release-manifest.json` | 28311 | `c65db8c413f56a07dfe2caefc9096fb1afefa6b1a574235f2066da01f5e87738` |
| `sbom.json` | 2684 | `0a1b34de6dcb1949a26696925477708bd672e58ef1899c5f4cfe41f084b098c4` |
| `unit.xml` | 60105 | `1b140db11d4fc4172f259a0571419175bac0be7cce83a6912fbca9a1a56c48f5` |
| `verify-all.log` | 34706 | `2633dcced606caff2fe989985e5f90aaf1fd83b3b71b0e5cd8a727c7e986eccf` |

testkit 首轮出现 `34/35`：真实模型在历史记忆已有多份重复项时，未按用例目标
直接调用 memory，而是自主选择未授权的 `execute_code`，Securityd 正确 fail-closed。
单项立即复跑为 1/1 通过。用例改为唯一 marker，并明确只允许直接调用
`bianbu.memory/memory` 一次后，完整复跑为 35/35。安全断言没有放宽。

## 4. 长时与生产 P99 实测

### 4.1 原 72 小时任务

原任务运行约 64.6 小时后停止。累计 46502 次、0 错误、审计链完整，但
`P99=10.438273 ms`，24 小时里程碑也为 `P99=10.400123 ms`，均超过 10 ms。
累计样本已数学上不可能恢复到门槛内，因此按计划停止并保留证据。

| 字段 | 结果 |
|------|------|
| 证据目录 | `/var/tmp/bnsec-commercial-soak/c01dc2b4b9ad823a67c13e5ef2135515-20260814T101901Z` |
| 状态 | `interrupted` |
| 运行时间 | `232530.01 s` |
| 迭代/错误 | `46502 / 0` |
| P99 | `10.438273 ms` |
| RSS 增长 | `50.33203125 MB` |
| 审计链 | `true` |
| 失败项 | `permission_p99` |

该任务不能作为正式长期签收证据。

### 4.2 优化后生产预演

| 预演 | 样本 | P99 | 超 10 ms | 其他门槛 | 结论 |
|------|------|-----|----------|----------|------|
| v1 | 120 | `10.113535 ms` | 2 | 0 error、chain/services/SSE 通过 | 失败 |
| v2 | 120 | `11.488231 ms` | 3 | 0 error、chain/services/SSE 通过 | 失败 |
| v3 | 120 | `12.121011 ms` | 4 | 0 error、chain/services/SSE 通过 | 失败 |
| v4 | 120 | `9.276006 ms` | 1 | 0 error、chain/services/SSE 通过 | **通过** |

v3 证据位于 `/var/tmp/bnsec-commercial-preflight-p99-v3`，最大值为
`33.446048 ms`，RSS 增长 `53.359375 MB`，两份里程碑齐全。唯一失败项为
`permission_p99`，不得改写为“通过”。

v4 证据位于 `/var/tmp/bnsec-commercial-preflight-p99-v4`。最终状态为
`passed`，平均值 `7.087326 ms`、P99 `9.276006 ms`、最大值 `10.024025 ms`；
120 个请求全部成功，RSS 增长 `52.746094 MB`，服务零重启、审计链完整，300/600 秒
里程碑齐全。门禁约束的是 P99，并不要求每个单样本都小于 10 ms。

| v4 证据 | SHA-256 |
|---------|--------|
| `report.json` | `39fee5988504dacd1c21a03e9f3b6f0f3274bb3e6d6f67c3daef6ae494737b59` |
| `report.samples.jsonl` | `979dd2ceb8e9ec214fbeecd3b4976aa7baefd913d8913907071e95e878d419ef` |
| `report.milestone-300s.json` | `e8379102002946013f76c82e039d33187738258dc4ef7d4808ca3d75ee780819` |
| `report.milestone-600s.json` | `8f4de8e1c106cf972f8f672212da886e7cfc788d1441f12a13090d7aff2ed52d` |

### 4.3 PA-inclusive v2 预演

2026-08-17 在清理双 securityd 实例后，使用 v2 执行器做了两次 PA-inclusive 预演：

| 时长 | Security 样本 | PA canary | Token 计量 | MCP 判权审计 | P99 | 结论 |
|------|---------------:|----------:|-----------:|-------------:|----:|------|
| 180 s | 36（预演） | 3/3 | 3/3 | 3/3 | `24.809 ms` | P99 不达标 |
| 600 s | 120 | 2/2 | 2/2 | 2/2 | `12.159528 ms` | P99 不达标 |

600 秒预演期间 PA token 总量 `182400`，securityd RSS 增长 `0.078 MB`，审计链完整、
服务未重启。P99 超限样本与 worker 范围外 `hermes-agent` 权限错误重启窗口重合；本项目
未停止、修改或复用该服务。该结果证明 v2 采集链路真实有效，但不替代正式 72 小时报告。

### 4.4 根因与对照

原始路径为：

```text
CheckPermissionV2
→ D-Bus sender UID/PID
→ /proc executable/cgroup
→ binding/capability SQLite
→ 审计哈希 + SQLite 同步 commit
```

已实施且不放宽安全语义的优化包括：

- 只缓存 D-Bus 连接生命周期内不变的 sender UID/PID；
- 每次仍重读 `/proc` executable/cgroup，防止同 PID `execve` 身份绕过；
- 单请求复用 binding，不缓存可被重绑的权限结果；
- 审计启动全链校验后缓存已提交链尾，仍每笔同步 `commit`；
- 审计从请求/写线程双向调度改为调用线程同步事务，以锁串行化；
- systemd 候选调度参数进一步收紧为 `Nice=-10`、`CPUWeight=1000`、
  `IOWeight=1000`；不使用实时调度，不独占 CPU/I/O。

同一 worker 的审计 A/B 结果：

| 路径 | 样本 | 平均 | P99 | >10 ms | 链 |
|------|------|------|-----|--------|----|
| 原写线程 | 60 | `6.581 ms` | `83.072 ms` | 1 | 完整 |
| 调用线程同步事务 | 60 | `5.080 ms` | `8.288 ms` | 0 | 完整 |

这证明内部调度优化有效；v4 进一步证明完整 D-Bus 路径已在 600 秒预演中达到
P99 门槛。复验期间，范围外 `hermes-agent.service` 约每 10.5 秒因权限错误失败重启，
`NRestarts` 累计约 47400。v3 四个超限样本中，三个与该服务启动/失败在同一秒。
按项目边界，本轮未停止、修改或复用 `hermes-agent`。

## 5. 分层达标判定

| 标准层级 | 结论 | 依据 |
|----------|------|------|
| 仓库功能 | **达到** | 86/86 功能已实现 |
| 默认/strict 自动化 | **达到** | 557/3 skip，strict 发布入口通过，E2E 0 skip |
| PA 真实接入 | **达到** | testkit 35/35；PA 真实 run/工具调用参与 |
| Security 工程交付 | **达到** | 原子升级、安装自检、供应链和候选发布门禁通过 |
| strict 短测 P99 | **达到** | 100 样本 P99 3.594 ms |
| 生产间隔采样 P99 | **达到预演门槛** | v4 600 秒/120 样本 P99 `9.276006 ms` |
| 长期可靠性 | **未达到** | 原长跑失败后停止，无新的 72h 通过报告 |
| 最终商用签收 | **未达到** | 长时、组织 CA、真实桌面、第三方渗透和审批证据不齐 |

## 6. 剩余工作与完成顺序

| 顺序 | 工作 | 责任 | 可测量完成标准 |
|------|------|------|------------------|
| 1 | 清理 worker 范围外重启风暴 | worker/相关服务所有者 | 验收窗口内无循环失败 unit；对应 `NRestarts` 不再增长 |
| 2 | 重跑生产预演 | Security 测试 | **已完成**；600 s/120 样本，`P99=9.276006 ms`、0 error、RSS 增长≤64 MB、chain/services/SSE 通过 |
| 3 | 冻结最终 Security commit | Security 交付 | **已完成**；实现基线 `f956d809f9d7454f496bc538e45524ee2e19996f`，worker 167 个跟踪文件 SHA-256 一致 |
| 4 | 生成最终提交证据包 | Security 交付 | **已完成**；`SECURITY_RELEASE_GATE_PASS`、`security_scope_status=passed`，8 个附件哈希一致 |
| 5 | 启动新 72 小时任务 | Security 测试 | 24h/72h 里程碑齐全，最终 `status=passed`、`failures=[]` |
| 6 | 补齐组织级证据 | Release/Desktop/安全 | 正式 CA 四项演练、seat 四路径、第三方渗透高危/ 严重为 0 |
| 7 | 最终机器签收 | Release/质量 | 双人审批、tag/变更单、附件哈希和组织 Ed25519 签名一致，输出 `COMMERCIAL_ACCEPTANCE_PASS` |

第 2 步已经完成。由于范围外循环失败 unit 尚未由其所有者清理，当前仍不启动新的
正式 72 小时任务，避免共享 worker 抖动污染长期证据。

## 7. PA 参与说明

PA 已参与 testkit 35 项的真实端到端测试，覆盖工具调用、Hook、MCP、
securityd 判权、DLP、Token 上报和错误透传。

v2 商用 soak 执行器每 6 小时连续调用真实 PA，验证 run、`bianbu.memory/memory`、
Token 计量和 `mcp.*` 判权审计；启动前和运行中还校验 transient systemd service 为空。
当前尚无正式 72 小时 v2 报告，不能将预演写成长期通过。

## 8. 验收意见

> **2026-08-17 复验意见：** Security 仓库功能、PA 真实接入、生产安装资产、
> strict 仓库门禁、供应链及 600 秒生产间隔采样 P99 已达到商用候选标准。72 小时长期
> 可靠性未达标；外部重启风暴、组织级 CA、真实桌面、第三方渗透和正式审批证据
> 仍需按第 6 节收口。本次不作最终商用签收。
