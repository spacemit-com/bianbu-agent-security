# Bianbu Security 验证收口清单

| 项 | 内容 |
|----|------|
| 文档编号 | BN-SEC-VERIFY-001 |
| 版本 | V1.3 |
| 日期 | 2026-08-17 |
| 用途 | 记录当前仍需取得的 Security 发布证据和范围外接口移交项 |
| 状态 | 仓库验证和最终提交证据已完成；2 项 Security 发布/运营证据待收口，Runtime 仅作范围外移交 |

> `/data/workspace2026-new/work0618/bianbu-next-agentos-dev-cc` 与正式 Agent Runtime
> 不在本次交付范围，不修改、不部署、不把其测试成绩计入本项目完成度。

## 1. 当前基线

| 验证项 | 当前结果 | 状态 |
|--------|----------|------|
| securityd 默认全量 | `551 passed / 3 skipped` | 通过 |
| securityd strict 仓库项 | `537 unit + 14 integration + 3 E2E`，`skipped=0` | 通过 |
| testkit | `35/35` | 通过 |
| PA 回归 | `848 passed / 73 failed`，安全开/关失败集合一致 | 无新增回归 |
| 安装/升级/回滚 | 干净安装、成功升级、切换后故障回滚 | 通过 |
| 发布证据门禁 | 实现提交 `f956d809…`，`security_scope_status=passed` | **通过，正式证据已生成** |
| 生产耐久预演 | v4 600s/120 次，error=0，P99=9.276ms，RSS +52.746MB | **通过** |

默认模式的 3 条 skip 是外部 E2E；strict 已在独立 D-Bus 和隔离数据根中真实执行，
因此不能再把它们写成“未验证”。

## 2. 已关闭验证项

| 编号 | 验证项 | 关闭证据 |
|------|--------|----------|
| V-01 | Python/依赖兼容与 worker 全量回归 | 当前 worker 全量 `551 passed / 3 skipped` |
| V-02 | D-Bus 部署与 policy | systemd、系统总线、policy、专用身份和管理授权已验证 |
| V-03 | strict D-Bus 延迟 | 最终证据 100 样本 P99 3.594ms；v4 生产间隔采样 P99 9.276ms |
| V-04 | 沙箱冷启动 | bwrap P99 46.787ms，低于 200ms |
| V-05 | CheckPermission 短测性能 | strict P99 3.594ms；不替代生产间隔采样和 72h |
| V-06 | SQLite/WAL/故障恢复 | WAL、并发、SQLITE_FULL、只读和重启恢复已覆盖 |
| V-07 | 服务端口与生产 WebUI | Gunicorn、回环监听、鉴权和 health 已通过 |
| V-08 | MCP 子进程沙箱 | 真实 MCP initialize/list/write 已通过 |
| V-09 | `mode=tool` | 可出进程工具和不可出进程降级均有断言 |
| V-10 | LangGraph resume 仓库实现 | broker、轮询、一次性 resume、拒绝/重放/跨 agent 单测完成 |
| V-11 | 逐字泄露语料语义 | 由调用方提供场景参考 corpus，检测引擎已验证 |
| V-12 | WebUI 认证 | Bearer token、401/200/403 和生产 env 已验证 |
| V-13 | 正式 UDS | `/run/bianbu/securityd.sock`、权限、PA 选路和大载荷已验证 |
| V-14 | 供应链 | hermetic venv、锁文件、SBOM、许可证、CVE=0 已验证 |
| V-15 | 安装与回滚 | 安装、成功升级、切换后故障自动回滚已验证 |

## 3. 本次 Security 交付待关闭项

### S-V01：正式 24/72 小时耐久

| 项 | 要求 |
|----|------|
| 入口 | `deploy/start_commercial_soak.sh` |
| 运行时间 | 默认 72 小时，24/72 小时里程碑 |
| 覆盖 | 真实 D-Bus、生产 UDS、WebUI health、SSE、systemd、RSS、P99、审计链 |
| 当前状态 | 原长跑约 64.6h 后因 P99 超标停止；v4 预演通过；当前无长跑进程 |
| 完成标准 | 24h/72h 报告存在；最终 `status=passed`、`failures=[]` |

最终报告必须包含 `samples_file/samples_size/samples_sha256`；原始 JSONL 每行 iteration
连续、`ok=true`，行数必须同时等于报告的 iterations 和 latency_samples。生产预演
已证明报告哈希、文件实际哈希和行数一致；双里程碑预演已证明两个 milestone
JSON 会在结束时间跨过检查点时由最终收尾逻辑补写并完成哈希绑定。

运行初期样本不足、此时尚不稳定的 P99 和审计链尚未到检查点时必须出现在
`pending_checks`，不能误报为 `failures`；达到最小样本数后仍超标的 P99 才是真故障。
600s/120 样本预演已达到 `P99≤10ms`。启动前仍必须由服务所有者清理 worker 上
循环失败的范围外 unit，固定无重启风暴的验收窗口。启动命令：

```bash
cd /home/bianbu/impl/bianbu-securityd
BNSEC_RELEASE_COMMIT=REPLACE_WITH_COMMIT
SOAK_PYTHON=python3 bash deploy/start_commercial_soak.sh start "$BNSEC_RELEASE_COMMIT"
bash deploy/start_commercial_soak.sh status
```

### S-V02：最终提交证据包

| 项 | 要求 |
|----|------|
| 入口 | `.ci/run_tests.sh` |
| 输入 | 最终 commit、hermetic Python、固定 CVE scanner |
| 输出 | strict 日志、unit/integration/E2E JUnit、doctor、SBOM、CVE、源码 manifest、SHA-256 |
| 状态 | **已完成**；实现基线 `f956d809f9d7454f496bc538e45524ee2e19996f` |
| 证据 | `/var/tmp/bnsec-security-release-f956d809f9d7454f496bc538e45524ee2e19996f-clean1`；summary SHA-256 `a62f521528c287a9df7c38e93d0e4e2e8222f52bf6e9f8198bbbe0c5fa53074e` |
| 完成标准 | 已输出 `SECURITY_RELEASE_GATE_PASS` 且 `security_scope_status=passed`；167/167 个跟踪文件及 8 个附件哈希复核一致 |

worker 没有正式 Runtime 时允许汇总为 `product_status=blocked_external`。该字段仅表达
全产品集成状态，不是本次 Security 验证失败。

### S-V03：组织级商用运营证据

| 子项 | 完成标准 |
|------|----------|
| 正式签名 CA | 正式根、公私钥托管、轮换、吊销和灾备恢复记录齐全 |
| 桌面 seat/polkit | 真实桌面会话的允许、拒绝、过期和重放日志齐全 |
| 第三方渗透 | 严重/高危为 0；其他发现有关闭证据或正式风险接受 |
| Release 归档 | tag、变更单、证据包、耐久报告、审批记录指向同一基线 |

仓库已提供 `deploy/commercial_acceptance_gate.py` 和四份示例 JSON。最终关闭 S-V03
必须运行该门禁并输出 `COMMERCIAL_ACCEPTANCE_PASS`；它会验证：

- 72 小时报告及 24/72 小时里程碑、性能、RSS、审计、SSE 和服务重启；
- CA 安装、轮换、吊销、恢复四项生产演练；
- 真实桌面 seat/session 的 allow、deny、expired、replay；
- 第三方范围包含 securityd、WebUI、D-Bus、UDS，严重/高危为 0；
- 所有附件 SHA-256、双人审批、release commit/tag 和组织 Ed25519 分离签名。
- Security 发布包的 JUnit/doctor/SBOM/CVE/manifest/strict 日志和 72 小时原始 samples
  均重新验哈希并复制进最终归档。

当前门禁实现和 6 项负向/正向单测已经通过；外部团队尚未提供正式证据，因此 S-V03
仍保持待关闭，不能用示例 JSON 或自签数据刷绿。

## 4. 范围外接口移交（不计入本次待办）

| 移交项 | 接收方 | Security 已提供 |
|--------|--------|-----------------|
| Token 超限后真实暂停/终止 | Runtime/agent | `TokenExceededV2`、当前计量拒绝、审计、consumer/guard 参考契约 |
| 模型/工具后续门禁 | Runtime/agent | 事件字段、幂等与恢复语义、集成验收用例 |
| Runtime 身份/网络/cgroup | Runtime/系统镜像 | production probe、systemd 模板、验收清单 |
| LangGraph broker 生产注册 | graph 所有者进程 | broker 协议、WebUI API 和仓库级测试 |

详细接口验收见 `review/Runtime-Production-Integration-Checklist.md`。这些项可以影响完整
Bianbu Next 产品集成状态，但不得降低本次 Bianbu Security 完成率。

## 5. 收口顺序

1. 已冻结实现提交、完成 worker 回归并生成正式 Security 发布证据包；
2. 清理范围外循环失败 unit，固定验收窗口；
3. 启动 72 小时耐久，24 小时只检查里程碑，不停止任务；
4. 72 小时通过后归档报告和 samples；
5. 补齐组织级 CA、桌面 seat、渗透和审批证据；
6. Release/质量负责人按同一 commit/tag 签收。

## 6. 记录原则

- 只记录真实执行结果，不把单测或参考实现写成生产证据；
- 不通过降低 strict、安装参考 Runtime 或引用范围外仓测试来“刷绿”；
- Security 与全产品集成状态分栏记录；
- 每份报告必须包含 commit、时间、平台、命令、退出码和原始产物路径；
- 24/72 小时任务中断、服务重启或故障注入必须注明原因和时间窗口。
