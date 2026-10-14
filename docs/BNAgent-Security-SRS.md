# AgentOS Security 软件需求规格说明书（SRS）

| 项 | 内容 |
|----|------|
| 文档编号 | BN-SEC-SRS-001 |
| 版本 | V1.0 |
| 来源 | PRD V0.9 §5.1/§5.3.7/§8（SEC/SBX）+ BN-SEC-SOL-001（方案）+ `impl/bianbu-securityd` 实现 + worker 10.0.90.243 实测 |
| 日期 | 2026-07-22 |
| 状态 | 已评审基线（状态字段反映真实实现进度） |
| 关联 | BN-SEC-DEV-001（开发指南）/ BN-SEC-API-001（接口）/ BN-SEC-HERMES-001（接入）/ BN-SEC-APPROVAL-001（审批） |

---

## 0. 文档说明

### 0.1 字段定义

| 字段 | 含义 |
|------|------|
| **编号** | 需求唯一主键，格式 `FR-<域>-<序号>` / `NFR-<域>-<序号>`，追溯用 |
| **规格项** | 需求名称（短语） |
| **规格描述** | 可验证的行为描述，含验收判据 |
| **依赖模块** | 实现该需求的代码模块 / 外部依赖 |
| **优先级** | P0 必须（无则不可用）/ P1 重要 / P2 增强 |
| **工作量** | 人天估算（P·D），仅供排期参考，非实际投入 |
| **负责人** | 角色分组（见 0.3），非具体个人 |
| **状态** | 见 0.2 |
| **备注** | 约束、已知边界、验证证据 |

### 0.2 状态图例

| 状态 | 含义 |
|------|------|
| ✅ 已验证 | 已实现且经 worker 实机测试通过（有测试用例/实测记录） |
| 🟢 已实现 | 代码完成、本地通过，未在 worker 做专项实测 |
| 🟡 部分实现 | 主路径可用，存在明确的已知边界（见备注） |
| ⬜ 待开发 | 需求已定义，尚未实现 |
| 🚫 受限 | 因目标环境能力缺失无法完整落地（见备注），需硬件/系统条件 |

### 0.3 负责人分组

| 分组 | 职责范围 |
|------|---------|
| **B-安全组** | securityd 核心（判权/确认/审计/配额/密钥） |
| **B-沙箱组** | seccomp / bwrap / cgroup / 网络策略 |
| **D-DLP组** | DLP/PII 检测、策略、干预点 handler |
| **E-集成组** | D-Bus 契约、客户端 SDK、CLI、部署 |
| **F-接入组** | hermes 插件、LangGraph 包装、工具映射、审批仲裁 |
| **G-前端组** | WebUI 管理台 |
| **QA** | 测试用例、实机验证 |

### 0.4 优先级与工作量汇总

| 优先级 | 条数 | 工作量合计（P·D） |
|--------|------|------------------|
| P0 | 51 | 156 |
| P1 | 25 | 81 |
| P2 | 4 | 8 |
| **合计** | **80** | **245** |

---

## 1. Manifest 校验与 Agent 安装（FR-SEC-01）

| 字段 | 内容 |
|------|------|
| **编号** | FR-SEC-01-01 |
| **规格项** | Manifest 解析 |
| **规格描述** | 解析 Agent 包内 `manifest.toml`：`[agent]`（id/version/name/signature）、`[permissions]`（每能力的 domain/risk_level/confirm/scope）、`[permissions.network].allowed_domains`、`[permissions.token_budget]`。字段缺失或类型非法时返回 `valid=false` + 具体 reason，不抛异常。**验收**：给定含 5 条权限的合法包，解析出 5 条 Permission 且字段一一对应 |
| **依赖模块** | `securityd/manifest.py`、`models.py`、Python `tomllib` |
| **优先级** | P0 |
| **工作量** | 3 |
| **负责人** | B-安全组 |
| **状态** | ✅ 已验证 |
| **备注** | 测试 `tests/unit/test_manifest.py::test_valid_manifest` |

| 字段 | 内容 |
|------|------|
| **编号** | FR-SEC-01-02 |
| **规格项** | ed25519 签名验证 |
| **规格描述** | 用包内 `pubkey.hex` 验证 `manifest.toml.sig` 对 manifest 正文的 ed25519 签名。签名负载 = manifest 去掉 `signature` 行的规范化内容（避免自指涉）。签名不符、缺 sig/pubkey、占位签名（`xxxx`/`PLACEHOLDER`）均判 `valid=false`。**验收**：篡改 manifest 任一字符后验签必失败 |
| **依赖模块** | `securityd/manifest.py`、`cryptography`（回退 `pynacl`） |
| **优先级** | P0 |
| **工作量** | 2 |
| **负责人** | B-安全组 |
| **状态** | ✅ 已验证 |
| **备注** | 测试 `test_no_signature` / `test_tampered_manifest_bad_signature`；worker 无 pynacl，走 cryptography |

| 字段 | 内容 |
|------|------|
| **编号** | FR-SEC-01-03 |
| **规格项** | 危险能力约束校验 |
| **规格描述** | 校验 `risk_level ∈ {L3,L4} ⟹ confirm ≠ trusted`（危险能力禁止永久放行）。违反时拒绝注册并返回明确错误。**验收**：注册 L3+trusted 的能力必被拒 |
| **依赖模块** | `securityd/models.py::Permission.validate` |
| **优先级** | P0 |
| **工作量** | 1 |
| **负责人** | B-安全组 |
| **状态** | ✅ 已验证 |
| **备注** | 测试 `test_l3_trusted_rejected` |

| 字段 | 内容 |
|------|------|
| **编号** | FR-SEC-01-04 |
| **规格项** | 完整安装流程 |
| **规格描述** | `InstallPackage` 一次完成：验签 → 注册能力（granted=1）→ 记 `agent_manifest`（含 manifest 原文供网络策略解析）→ 按 manifest 设 token 预算 → 写审计。返回 `{ok, reason, agent_id, count}`。**验收**：安装后 `GetCapabilities` 可查到全部声明能力，`ListAgents` 含该 agent |
| **依赖模块** | `securityd/engine.py::install_package_info`、`capability_registry.py`、`token_meter.py` |
| **优先级** | P0 |
| **工作量** | 2 |
| **负责人** | B-安全组 |
| **状态** | ✅ 已验证 |
| **备注** | worker 实测 `bncli install` + WebUI `/api/install` 均通 |

---

## 2. 能力注册表与判权（FR-SEC-02）

| 字段 | 内容 |
|------|------|
| **编号** | FR-SEC-02-01 |
| **规格项** | 能力持久化存储 |
| **规格描述** | 能力以 `(agent_id, capability, scope)` 三元组为主键存 SQLite（WAL 模式）：字段含 domain(execute/resource/data/system)、risk_level(L1-L4)、confirm(always/once_per_session/trusted)、granted(1 已授权/0 待授权/-1 已撤销)。重复注册同三元组时覆盖更新（ON CONFLICT）。**验收**：进程重启后能力清单不丢失 |
| **依赖模块** | `securityd/capability_registry.py`、SQLite3 |
| **优先级** | P0 |
| **工作量** | 3 |
| **负责人** | B-安全组 |
| **状态** | ✅ 已验证 |
| **备注** | 主键含 scope → 同能力不同目录可分别授权（设计如此，非重复数据） |

| 字段 | 内容 |
|------|------|
| **编号** | FR-SEC-02-02 |
| **规格项** | CheckPermission 三态判权 |
| **规格描述** | 按序判定并返回 **0=ALLOW / 1=CONFIRM / 2=DENY**：①无能力行或 `granted≠1` → DENY；②`risk_level=L4` → CONFIRM（恒需确认）；③`confirm=trusted` → ALLOW；④`once_per_session` → 会话已信任则 ALLOW，否则 CONFIRM；⑤`always` → CONFIRM。**验收**：五条分支各有用例覆盖，判决与表格一致 |
| **依赖模块** | `securityd/capability_registry.py::check_permission` |
| **优先级** | P0 |
| **工作量** | 3 |
| **负责人** | B-安全组 |
| **状态** | ✅ 已验证 |
| **备注** | 测试 `test_capability_registry.py` 6 用例；判权 P99 ≤ 10ms（NFR-P-01） |

| 字段 | 内容 |
|------|------|
| **编号** | FR-SEC-02-03 |
| **规格项** | scope 最长前缀匹配 |
| **规格描述** | 文件类能力按目录粒度判权：请求 scope 与声明 scope 做最长前缀匹配，取最长命中行；请求 scope 越出所有声明范围（如声明 `~/Documents` 却访问 `/etc/passwd`）→ 无匹配 → DENY。无 scope 请求取 scope 为空的行。**验收**：越界路径访问必被拒 |
| **依赖模块** | `securityd/capability_registry.py::_best_match_row` |
| **优先级** | P0 |
| **工作量** | 2 |
| **负责人** | B-安全组 |
| **状态** | ✅ 已验证 |
| **备注** | 测试 `test_scope_escape_denied`；天然防目录越界 |

| 字段 | 内容 |
|------|------|
| **编号** | FR-SEC-02-04 |
| **规格项** | 授权态变更（授权/撤销） |
| **规格描述** | 支持单条能力改 granted（1/0/-1）与按 capability 批量撤销。撤销时同步清理该能力的 `session_trust` 缓存（防撤销后仍被会话信任放行）。**验收**：撤销后立即 DENY，且会话内不再放行 |
| **依赖模块** | `capability_registry.py::set_granted` / `revoke_permission` |
| **优先级** | P0 |
| **工作量** | 2 |
| **负责人** | B-安全组 |
| **状态** | ✅ 已验证 |
| **备注** | worker 实测 WebUI 撤销→hermes 立即 DENY（hermes_config_demo 4/4） |

---

## 3. 确认门禁（FR-SEC-03）

| 字段 | 内容 |
|------|------|
| **编号** | FR-SEC-03-01 |
| **规格项** | 确认门禁基础流程 |
| **规格描述** | CONFIRM 判决时发 `ConfirmRequest` 信号（含 request_id）并阻塞等待响应；前端经 `RespondConfirm(request_id, approved)` 回传唤醒。超时（默认 30s，`BIANBU_CONFIRM_TIMEOUT` 可调）视为**拒绝**。**验收**：批准→放行、拒绝→拦截、超时→拦截 三路径均正确 |
| **依赖模块** | `securityd/confirm.py`、`service.py`（异步 async_callbacks） |
| **优先级** | P0 |
| **工作量** | 4 |
| **负责人** | B-安全组 |
| **状态** | ✅ 已验证 |
| **备注** | 先注册等待再发信号（避免信号先到丢弃的竞态）；RequestConfirm 异步化避免阻塞 GLib 主循环致死锁 |

| 字段 | 内容 |
|------|------|
| **编号** | FR-SEC-03-02 |
| **规格项** | L4 二次确认 |
| **规格描述** | risk_level=L4 的能力需**连续两次**确认才放行，第二次提示带 `[二次确认]` 标记；任一次拒绝即整体拒绝。L4 不写入 session_trust（每次都问）。**验收**：L4 触发两次确认请求，首肯次否→最终拒绝 |
| **依赖模块** | `securityd/confirm.py::request` |
| **优先级** | P0 |
| **工作量** | 2 |
| **负责人** | B-安全组 |
| **状态** | ✅ 已验证 |
| **备注** | worker 实测 hermes_confirm_demo 4/4，含首肯次否用例 |

| 字段 | 内容 |
|------|------|
| **编号** | FR-SEC-03-03 |
| **规格项** | 会话内信任缓存（once_per_session） |
| **规格描述** | confirm=once_per_session 的能力经批准后写 `session_trust(session_id, agent_id, capability)`，同会话内后续调用直接 ALLOW 不再询问；撤销能力时清除。**验收**：同会话第二次调用不再弹确认 |
| **依赖模块** | `capability_registry.py::grant_session_trust` |
| **优先级** | P1 |
| **工作量** | 2 |
| **负责人** | B-安全组 |
| **状态** | 🟡 部分实现 |
| **备注** | 已提供 CheckPermissionV2/RequestConfirmV2，context=a{sv} 传递 session_id/run_id；旧接口保持兼容，未传 session 时仍按每次确认处理 |

| 字段 | 内容 |
|------|------|
| **编号** | FR-SEC-03-04 |
| **规格项** | 确认 UI 后端可插拔 |
| **规格描述** | 确认 UI 支持多后端并存：①WebUI 确认门禁 Tab（订阅信号+RespondConfirm）②hermes 原生 TUI 弹窗 ③自动策略（无人值守测试）。谁先响应谁生效。**验收**：WebUI 与 CLI 两条响应路径独立可用 |
| **依赖模块** | `confirm.py`（signal_emit/ui_callback 注入）、`webui`、`hermes_plugin/cli_confirm.py` |
| **优先级** | P1 |
| **工作量** | 3 |
| **负责人** | B-安全组/G-前端组 |
| **状态** | ✅ 已验证 |
| **备注** | confirm.py docstring 预留该扩展点；两路径均有实测 |

---

## 4. Token 配额计量（FR-SEC-04）

| 字段 | 内容 |
|------|------|
| **编号** | FR-SEC-04-01 |
| **规格项** | Token 双维度计量 |
| **规格描述** | 按 conv（单次对话）与 day（单日）双维度累计 token 用量；`MeterTokens(agent,tokens,scope)` 返回 `(within_limit, remaining)`。默认上限 conv=100000 / day=500000，可按 Agent 配置。**验收**：累计超限时 within_limit=False 且 remaining=0 |
| **依赖模块** | `securityd/token_meter.py` |
| **优先级** | P0 |
| **工作量** | 3 |
| **负责人** | B-安全组 |
| **状态** | ✅ 已验证 |
| **备注** | 测试 test_token_meter.py 4 用例（conv 超限/day 超限/重置/持久化） |

| 字段 | 内容 |
|------|------|
| **编号** | FR-SEC-04-02 |
| **规格项** | 单日配额 00:00 重置 |
| **规格描述** | day 维度计数按**本地时区**每日 00:00 归零；当日累计持久化到 `token_budget_state`，进程重启后恢复当日已用量（不清零）。**验收**：跨日后 day_used 归零，同日重启后累计值保留 |
| **依赖模块** | `token_meter.py`（today_fn 可注入便于测试） |
| **优先级** | P0 |
| **工作量** | 2 |
| **负责人** | B-安全组 |
| **状态** | ✅ 已验证 |
| **备注** | 测试 test_day_reset / test_persistence_restore |

| 字段 | 内容 |
|------|------|
| **编号** | FR-SEC-04-03 |
| **规格项** | 超限动作与告警 |
| **规格描述** | 超限时按 `on_exceed` 策略处理（默认 `pause_and_notify`）：写审计 `token_meter/exceed` + 发 `TokenExceeded` 信号 + 发 `SecurityAlert`，由 Agent Runtime/agent 消费事件并负责将 Agent/Run 切换为暂停或终止状态；securityd 不直接停止 Agent 服务。**验收**：超限事件可被订阅方收到，且 Runtime/agent 收到后阻止后续模型调用并完成状态切换 |
| **依赖模块** | `engine.py::meter_tokens`、`service.py`（TokenExceeded 信号） |
| **优先级** | P1 |
| **工作量** | 2 |
| **负责人** | B-安全组 |
| **状态** | 🟢 已实现 |
| **备注** | securityd 当前信号（`agent_id/scope/used/limit`）、审计和当前请求超限返回已实现；Runtime/agent 侧事件消费、状态切换和后续调用阻断属于跨模块联调项，暂停动作不由 securityd 实现 |

| 字段 | 内容 |
|------|------|
| **编号** | FR-SEC-04-04 |
| **规格项** | 配额查询与设置 |
| **规格描述** | 提供只读查询 `GetTokenBudget`（返回上限+当前 conv/day 已用）与设置 `SetTokenBudget(conv, day, on_exceed)`，供 WebUI 管理。**验收**：WebUI 改上限后查询即反映新值 |
| **依赖模块** | `token_meter.py::get_budget/set_budget`、`service.py`、`webui` |
| **优先级** | P1 |
| **工作量** | 2 |
| **负责人** | B-安全组/G-前端组 |
| **状态** | ✅ 已验证 |
| **备注** | worker 实测 WebUI GET 1000/5000 → POST 2000/9000 → 复查已变 |

---

## 5. 系统调用拦截（FR-SEC-05）

| 字段 | 内容 |
|------|------|
| **编号** | FR-SEC-05-01 |
| **规格项** | seccomp BPF 生成 |
| **规格描述** | 纯 Python 生成 seccomp cBPF 程序（不依赖 libseccomp 绑定），黑名单命中返回 EPERM、其余放行、arch 不符则 KILL。黑名单含 reboot/swapon/swapoff/kexec_load/kexec_file_load/init_module/finit_module/delete_module/mount/umount2/pivot_root/perf_event_open。**验收**：生成的 BPF 字节数为 8 的整数倍且可被 bwrap 加载 |
| **依赖模块** | `securityd/seccomp_builder.py` |
| **优先级** | P0 |
| **工作量** | 4 |
| **负责人** | B-沙箱组 |
| **状态** | ✅ 已验证 |
| **备注** | 测试 test_seccomp_builder.py 5 用例 |

| 字段 | 内容 |
|------|------|
| **编号** | FR-SEC-05-02 |
| **规格项** | 多架构支持 |
| **规格描述** | 按 `platform.machine()` 适配 x86_64（AUDIT_ARCH 0xC000003E）与 riscv64（0xC00000F3）两套 syscall 号表；不支持的 arch 抛明确错误。**验收**：两 arch 各自生成的 BPF 含正确的 syscall 号 |
| **依赖模块** | `seccomp_builder.py`（_SYSCALLS_X86_64 / _SYSCALLS_RISCV64） |
| **优先级** | P0 |
| **工作量** | 2 |
| **负责人** | B-沙箱组 |
| **状态** | ✅ 已验证 |
| **备注** | worker(riscv64) 与开发机(x86_64) 均实测通过 |

| 字段 | 内容 |
|------|------|
| **编号** | FR-SEC-05-03 |
| **规格项** | 系统调用真实拦截 |
| **规格描述** | 沙箱内进程调用黑名单 syscall 必被内核拦截返回 EPERM；且 seccomp 随 fork-exec **被子进程继承**（子进程同样受限，无法逃逸）。**验收**：沙箱内 reboot() 得 EPERM（exit 99）；沙箱内 spawn 的子进程调 reboot 同样 EPERM |
| **依赖模块** | `securityd/sandbox.py`（--seccomp fd）、Linux kernel seccomp |
| **优先级** | P0 |
| **工作量** | 3 |
| **负责人** | B-沙箱组 |
| **状态** | ✅ 已验证 |
| **备注** | worker 实测 test_hermes_sandbox.py：父进程 spawn 子进程 reboot 被拦 rc=99 |

---

## 6. 审计日志（FR-SEC-06）

| 字段 | 内容 |
|------|------|
| **编号** | FR-SEC-06-01 |
| **规格项** | 防篡改哈希链 |
| **规格描述** | 每条审计记录含 `seq/ts/agent_id/op_type/target/result/prev_hash/hash`，其中 `hash = SHA256(seq‖ts‖agent_id‖op_type‖target‖result‖prev_hash)`，首条 prev_hash=`GENESIS`，前后串成链。**验收**：篡改任一字段后校验必失败并可定位 |
| **依赖模块** | `securityd/audit_chain.py` |
| **优先级** | P0 |
| **工作量** | 4 |
| **负责人** | B-安全组 |
| **状态** | ✅ 已验证 |
| **备注** | 测试 test_audit_chain.py 4 用例（链完整/篡改检出/CSV/哈希公式） |

| 字段 | 内容 |
|------|------|
| **编号** | FR-SEC-06-02 |
| **规格项** | 并发安全写入 |
| **规格描述** | 所有审计写入经**单写线程**串行化（队列 + 后台线程），防并发破链。写入返回 seq。**验收**：并发 10 线程写入后链校验仍完整 |
| **依赖模块** | `audit_chain.py`（queue + 单写线程） |
| **优先级** | P0 |
| **工作量** | 2 |
| **负责人** | B-安全组 |
| **状态** | ✅ 已验证 |
| **备注** | 设计上排除并发破链；实测 13 条交错记录校验通过 |

| 字段 | 内容 |
|------|------|
| **编号** | FR-SEC-06-03 |
| **规格项** | 导出与离线验证 |
| **规格描述** | `ExportAudit(filter_json, fmt)` 支持按 agent_id 过滤导出 json/csv（含 chain_anchor 锚点）；`VerifyAuditChain(path)` 可离线校验导出文件。**验收**：导出文件经 verify 返回 true，篡改后返回 false |
| **依赖模块** | `audit_chain.py::export/verify_export` |
| **优先级** | P0 |
| **工作量** | 3 |
| **负责人** | B-安全组 |
| **状态** | ✅ 已验证 |
| **备注** | **关键修复**：哈希链是全局单链，按 agent 过滤的子集 prev_hash 天然不相邻 → 子集只做逐条自洽校验（篡改仍可检出），全量校验才要求 prev 链首尾相连 |

| 字段 | 内容 |
|------|------|
| **编号** | FR-SEC-06-04 |
| **规格项** | 按月分段与轮转 |
| **规格描述** | 审计库按月分段（`audit/YYYYMM.db`），单段超 64MB 触发轮转，段尾哈希记入 `audit_segment_meta` 保证跨段可追溯。**验收**：跨月后新建段文件且旧段可独立校验 |
| **依赖模块** | `audit_chain.py`、`config.AUDIT_SEGMENT_MAX_BYTES` |
| **优先级** | P2 |
| **工作量** | 2 |
| **负责人** | B-安全组 |
| **状态** | 🟢 已实现 |
| **备注** | 按月分段已实现；跨月轮转未做长周期实测 |

| 字段 | 内容 |
|------|------|
| **编号** | FR-SEC-06-05 |
| **规格项** | Fail-Closed 审计 |
| **规格描述** | 审计写入失败时**阻断相关操作**并发 `SecurityAlert`，绝不静默放行（不可抵赖性优先于可用性）。**验收**：模拟写盘失败时操作被拒 |
| **依赖模块** | `engine.py::audit_log`、`errors.AuditFailure` |
| **优先级** | P0 |
| **工作量** | 1 |
| **负责人** | B-安全组 |
| **状态** | 🟢 已实现 |
| **备注** | 异常路径已实现，未做磁盘满/只读的破坏性实测 |

---

## 7. 网络访问控制（FR-SEC-07）

| 字段 | 内容 |
|------|------|
| **编号** | FR-SEC-07-01 |
| **规格项** | 域名白名单规则生成 |
| **规格描述** | 按 manifest `allowed_domains` 解析域名→IP，生成 iptables 规则文本：逐 IP `-A OUTPUT -d <ip> -j ACCEPT` + 放行 DNS + 默认 `-A OUTPUT -j DROP`（whitelist 模式）；learning 模式仅 LOG 不 DROP。产物落 `<RUN>/sandbox/<agent>/netfilter.rules`。**验收**：规则文件含声明域名的 ACCEPT 与默认 DROP |
| **依赖模块** | `securityd/network_policy.py` |
| **优先级** | P1 |
| **工作量** | 3 |
| **负责人** | B-沙箱组 |
| **状态** | ✅ 已验证 |
| **备注** | worker 实测生成 285B 规则文件 |

| 字段 | 内容 |
|------|------|
| **编号** | FR-SEC-07-02 |
| **规格项** | 规则实下发 |
| **规格描述** | 在具备 iptables/nft 且有权限的环境把规则实际下发到内核，实现出站流量强制管控。**验收**：沙箱内访问非白名单域名被丢弃 |
| **依赖模块** | `network_policy.py::apply_rules`、iptables/nftables |
| **优先级** | P1 |
| **工作量** | 3 |
| **负责人** | B-沙箱组 |
| **状态** | 🚫 受限 |
| **备注** | **环境受限**：worker（K3）无 iptables/nft → 仅生成规则产物，无法在该机强制。当前联网模式为共享宿主网络（全通或全断 `--no-net`）。域名级强制需具备 netfilter 的目标环境 |

| 字段 | 内容 |
|------|------|
| **编号** | FR-SEC-07-03 |
| **规格项** | 网络策略查询 |
| **规格描述** | `GetNetworkPolicy(agent)` 返回当前 `{mode, domains, rules_path, exists}`，供 WebUI 展示与编辑。**验收**：WebUI 可读取并回显已配域名 |
| **依赖模块** | `network_policy.py::read_rules`、`webui` |
| **优先级** | P2 |
| **工作量** | 1 |
| **负责人** | B-沙箱组/G-前端组 |
| **状态** | ✅ 已验证 |
| **备注** | worker 实测 WebUI 白名单编辑保存成功 |

---

## 8. 沙箱隔离（FR-SBX-01~08）

| 字段 | 内容 |
|------|------|
| **编号** | FR-SBX-01 |
| **规格项** | 文件系统隔离 |
| **规格描述** | 用 bubblewrap 重构最小根视图：`--ro-bind /usr` + 按需只读依赖；Agent 私有可写目录绑到 `/home/agent`；`/tmp` 为 tmpfs。**验收**：沙箱内根目录条目数显著少于宿主，看不到无关路径 |
| **依赖模块** | `securityd/sandbox.py::build_bwrap_argv`、bubblewrap |
| **优先级** | P0 |
| **工作量** | 4 |
| **负责人** | B-沙箱组 |
| **状态** | ✅ 已验证 |
| **备注** | **设计变更**：原设计 overlayfs 因非特权不可加载（需 CAP_SYS_ADMIN）→ 改 bind-mount + bwrap；worker 沙箱演示探针实测根条目 10 vs 宿主 19 |

| 字段 | 内容 |
|------|------|
| **编号** | FR-SBX-02 |
| **规格项** | 强制屏蔽敏感路径 |
| **规格描述** | `/etc/shadow`、`/etc/gshadow`、`/etc/sudoers`、`/root`、`/etc/ssh` 等以 `--ro-bind /dev/null` 覆盖，Agent 读到空内容。**验收**：沙箱内读 /etc/shadow 得 0 字节 |
| **依赖模块** | `sandbox.py::MANDATORY_DENY_PATHS` |
| **优先级** | P0 |
| **工作量** | 1 |
| **负责人** | B-沙箱组 |
| **状态** | ✅ 已验证 |
| **备注** | worker 探针实测：沙箱 0 字节 vs 宿主 1250 字节 |

| 字段 | 内容 |
|------|------|
| **编号** | FR-SBX-03 |
| **规格项** | Capability 全裁剪 |
| **规格描述** | 沙箱进程 `--cap-drop ALL`：CapEff 与 **CapBnd（边界集）** 均为 0，即使提权也拿不到任何 capability。**验收**：/proc/self/status 的 CapBnd 全 0 |
| **依赖模块** | `sandbox.py`（--cap-drop ALL） |
| **优先级** | P0 |
| **工作量** | 1 |
| **负责人** | B-沙箱组 |
| **状态** | ✅ 已验证 |
| **备注** | worker 探针：沙箱 CapBnd=0000000000000000 vs 宿主 000001ffffffffff |

| 字段 | 内容 |
|------|------|
| **编号** | FR-SBX-04 |
| **规格项** | 命名空间隔离 |
| **规格描述** | 启用 `--unshare-user/pid/ipc/uts`（可选 net）：PID/IPC/UTS/User 命名空间隔离，沙箱内看不到宿主进程。**验收**：沙箱内进程数远少于宿主；uid 映射为独立身份 |
| **依赖模块** | `sandbox.py` |
| **优先级** | P0 |
| **工作量** | 2 |
| **负责人** | B-沙箱组 |
| **状态** | ✅ 已验证 |
| **备注** | worker 探针：沙箱 4 进程 vs 宿主 443；身份 agent vs 宿主 bianbu（含 sudo 组） |

| 字段 | 内容 |
|------|------|
| **编号** | FR-SBX-05 |
| **规格项** | cgroup v2 资源限额 |
| **规格描述** | 为每 Agent 建 cgroup v2 slice 设 MemoryMax（默认 2G）/CPUQuota（默认 100%）/IOWeight（默认 100），超内存触发 OOM 保护。**验收**：限额写入 cgroup 且生效 |
| **依赖模块** | `sandbox.py::setup_cgroup`、cgroup v2 |
| **优先级** | P1 |
| **工作量** | 3 |
| **负责人** | B-沙箱组 |
| **状态** | 🟡 部分实现 |
| **备注** | **已知边界**：写 /sys/fs/cgroup 需特权，普通用户降级跳过（不阻断启动）；生产由 runtimed 以特权保证。沙箱内不暴露 cgroupfs 防 Agent 自改 |

| 字段 | 内容 |
|------|------|
| **编号** | FR-SBX-06 |
| **规格项** | 沙箱启动性能 |
| **规格描述** | 沙箱创建不使 Agent 冷启动增加超过 200ms。**验收**：策略生成+bwrap 启动耗时实测 ≤200ms |
| **依赖模块** | `sandbox.py`、`seccomp_builder.py` |
| **优先级** | P1 |
| **工作量** | 2 |
| **负责人** | B-沙箱组/QA |
| **状态** | ✅ 已验证 |
| **备注** | worker `performance_benchmark.py --check`：bwrap P99 49.045ms、相对裸启动开销 P99 11.071ms ≤200ms |

| 字段 | 内容 |
|------|------|
| **编号** | FR-SBX-07 |
| **规格项** | Fail-Closed 启动 |
| **规格描述** | 沙箱任一要素失败（bwrap 不可用、声明 seccomp 但文件缺失）→ **拒绝启动 Agent**，绝不降级为无沙箱裸跑。**验收**：seccomp 文件缺失时 launch 返回 ok=False 且不执行 |
| **依赖模块** | `sandbox.py::launch` |
| **优先级** | P0 |
| **工作量** | 1 |
| **负责人** | B-沙箱组 |
| **状态** | ✅ 已验证 |
| **备注** | 测试 test_fail_closed_missing_seccomp |

| 字段 | 内容 |
|------|------|
| **编号** | FR-SBX-08 |
| **规格项** | 整进程沙箱启动器 |
| **规格描述** | 提供 `hermes_sandbox_launch.py` 把**整个 Agent 进程**放进沙箱（而非逐工具），seccomp/cap-drop/文件视图随 fork-exec 被其 spawn 的每个子进程继承。**验收**：沙箱内父进程 spawn 的子进程执行 reboot 被 EPERM 拦截 |
| **依赖模块** | `hermes_plugin/hermes_sandbox_launch.py` |
| **优先级** | P0 |
| **工作量** | 4 |
| **负责人** | B-沙箱组/F-接入组 |
| **状态** | ✅ 已验证 |
| **备注** | worker 实测 rc=99（EPERM）；含 merged-usr/DNS/CA/passwd/tty 五项真机适配 |

---

## 9. 密钥库（FR-SEC-08）

| 字段 | 内容 |
|------|------|
| **编号** | FR-SEC-08-01 |
| **规格项** | 软件密钥库 |
| **规格描述** | 无 TEE 环境下以加密文件保管 Agent secret：32 字节随机 master.key（0600）经 SHA-256 派生 Fernet 密钥，加密各 Agent 的 `<agent_id>.vault`（JSON 整体加密）。明文不落盘。**验收**：直接查看 .vault 只见密文，get_secret 可正确解出原值 |
| **依赖模块** | `securityd/key_vault.py`、`cryptography.Fernet` |
| **优先级** | P1 |
| **工作量** | 3 |
| **负责人** | B-安全组 |
| **状态** | 🟢 已实现 |
| **备注** | **环境约束**：worker K3 无 /dev/tee → 采用软件方案（对应 TBD-17）。master.key 明文存盘靠文件权限保护，与真 TEE「密钥永不出安全世界」有本质差距，属已知降级 |

| 字段 | 内容 |
|------|------|
| **编号** | FR-SEC-08-02 |
| **规格项** | 密钥访问门控 |
| **规格描述** | `get_secret` 前经 CheckPermission 校验 `secret.read` 能力，普通 Agent 不能直读 vault 文件。**验收**：未声明 secret.read 的 Agent 读取被拒 |
| **依赖模块** | `securityd/engine.py::get_secret` |
| **优先级** | P1 |
| **工作量** | 1 |
| **负责人** | B-安全组 |
| **状态** | 🟢 已实现 |
| **备注** | 门控逻辑已实现；未做专项渗透验证 |

---

## 10. hermes 接入（FR-INT）

| 字段 | 内容 |
|------|------|
| **编号** | FR-INT-01 |
| **规格项** | hermes 插件接入 |
| **规格描述** | 以标准 hermes 插件（plugin.yaml + register(manager)）接入，注册 `pre_tool_call`（判权+确认，可拦截）/ `post_tool_call`（审计）/ `on_session_end` 钩子。**零 hermes 源码改动**，仅用其公开插件 API。**验收**：hermes 启动自动加载插件，每次工具调用触发判权 |
| **依赖模块** | `hermes_plugin/bianbu_security/`、hermes plugin API |
| **优先级** | P0 |
| **工作量** | 4 |
| **负责人** | F-接入组 |
| **状态** | ✅ 已验证 |
| **备注** | worker 实测插件加载 + 钩子与判权次数 10:10 对齐；符合 AGENTS.md「不复用 hermes 代码」 |

| 字段 | 内容 |
|------|------|
| **编号** | FR-INT-02 |
| **规格项** | 工具→能力映射 |
| **规格描述** | 把 hermes 工具名+参数归一化为 (capability, scope)：覆盖 hermes **全部 47 个工具（19 toolset）**—— 46 个显式映射到 13 类能力，clarify（纯交互）默认放行；scope 从参数就地提取（write_file 的 path、terminal 的 command、browser 的 url）。未映射工具按 DEFAULT_ALLOW 放行，避免误伤 hermes 大量只读内部工具。**验收**：resolve 对各类工具返回正确能力名与 scope |
| **依赖模块** | `hermes_plugin/bianbu_security/mapping.py` |
| **优先级** | P0 |
| **工作量** | 3 |
| **负责人** | F-接入组 |
| **状态** | ✅ 已验证 |
| **备注** | 零臆想校验：映射表内工具全部真实存在于 hermes（曾清除 5 个不存在的臆想工具名） |

| 字段 | 内容 |
|------|------|
| **编号** | FR-INT-03 |
| **规格项** | 上游真拦截 |
| **规格描述** | hermes 的 `invoke_hook` 返回 `List[Any]`（各插件返回值汇总），需**遍历**找到任一 `{"action":"block"}` 即短路、不执行工具。**验收**：DENY 的工具真正不执行，返回体含 `blocked_by=bianbu-security` |
| **依赖模块** | hermes `model_tools.py` 补丁（deploy/hermes-hook-block-patch.sh） |
| **优先级** | P0 |
| **工作量** | 2 |
| **负责人** | F-接入组 |
| **状态** | ✅ 已验证 |
| **备注** | **关键修正**：首版误用 isinstance(dict) 判断致拦截失效（实测漏过率 terminal 46%）；改为遍历 list 后 worker 实测 5/5 高风险工具全部拦截 |

| 字段 | 内容 |
|------|------|
| **编号** | FR-INT-04 |
| **规格项** | 审批仲裁开关 |
| **规格描述** | 以 `BIANBU_SEC_APPROVAL_MODE` 三态仲裁 securityd 门禁与 hermes 自带 approval，**仅对 CONFIRM 判决生效**（ALLOW/DENY 不受影响）：`securityd`（默认，关 hermes approval，WebUI 点批准）/ `hermes`（交回 hermes TUI 弹框）/ `both`（叠加双确认）。**验收**：三态 × DENY/ALLOW/CONFIRM 组合行为符合定义 |
| **依赖模块** | `hermes_plugin/bianbu_security/__init__.py` |
| **优先级** | P0 |
| **工作量** | 3 |
| **负责人** | F-接入组 |
| **状态** | ✅ 已验证 |
| **备注** | 单测 test_approval_mode.py 9 项全通过 |

| 字段 | 内容 |
|------|------|
| **编号** | FR-INT-05 |
| **规格项** | CLI 交互审批 |
| **规格描述** | 交互式 CLI（hermes chat）下 CONFIRM 主动调用 hermes 已注册的审批回调（`terminal_tool._approval_callback`），弹出原生 [Allow once/session/permanent/Deny] TUI 弹框，按返回值放行/拦截并审计 `confirm_hermes_tui:<choice>`。**验收**：真机 hermes chat 弹框且选择生效 |
| **依赖模块** | `hermes_plugin/bianbu_security/cli_confirm.py` |
| **优先级** | P1 |
| **工作量** | 4 |
| **负责人** | F-接入组 |
| **状态** | ✅ 已验证 |
| **备注** | **走过两条弯路**：①插件裸 input() 在 prompt_toolkit 全屏 App 下挂死（hermes 源码注释「input() hangs」）②被动 return None 仅在命中 hermes 危险正则时才弹框。最终借用其审批回调，真机验证通过 |

| 字段 | 内容 |
|------|------|
| **编号** | FR-INT-06 |
| **规格项** | 整进程沙箱启动器 |
| **规格描述** | hermes 无「逐工具进沙箱」的插件缝隙（pre_tool_call 只能拦截不能改写命令；_create_environment 硬编码无注册点），故用 bwrap 包裹**整个 hermes 进程**启动，seccomp/cap-drop/文件视图随 fork-exec 被其 spawn 的每个工具子进程继承。**验收**：沙箱内 hermes 的子进程执行 reboot 被 EPERM 拦截 |
| **依赖模块** | `hermes_plugin/hermes_sandbox_launch.py` |
| **优先级** | P1 |
| **工作量** | 5 |
| **负责人** | B-沙箱组/F-接入组 |
| **状态** | ✅ 已验证 |
| **备注** | worker 实测子进程继承 seccomp（rc=99）；真实 /usr/bin/hermes chat 可在沙箱内进入交互界面 |

| 字段 | 内容 |
|------|------|
| **编号** | FR-INT-07 |
| **规格项** | 沙箱运行环境适配 |
| **规格描述** | 沙箱内运行真实 hermes 需补齐宿主资源：可写绑定 `~/.hermes`（配置/凭据/会话）并设 HOME；合成最小 /etc/passwd+group（消除 userns 下 id 解析错误）；联网模式绑 DNS 文件（resolv.conf 解析符号链接真实目标 / hosts / nsswitch）+ TLS CA 目录；交互模式继承 tty 不捕获 IO。**验收**：沙箱内 hermes 能读配置、解析域名、HTTPS 调模型 API、TUI 正常交互 |
| **依赖模块** | `hermes_sandbox_launch.py`、`securityd/sandbox.py`（rw_binds/ro_binds_map/home_dir） |
| **优先级** | P1 |
| **工作量** | 4 |
| **负责人** | B-沙箱组 |
| **状态** | ✅ 已验证 |
| **备注** | worker 实测：沙箱内 curl HTTPS 到模型 API 返回 301；hermes chat 进入 agent 循环。**已知边界**：写到 HOME 根目录的文件落在沙箱 tmpfs，退出即丢；仅绑定目录持久化 |

| 字段 | 内容 |
|------|------|
| **编号** | FR-INT-08 |
| **规格项** | 交互沙箱作业控制 |
| **规格描述** | 交互模式省略 bwrap `--new-session`（它 setsid 但不设控制终端，致 bash -i 的 tcsetpgrp 失败、报「无法设定终端进程组/无任务控制」）；交互沙箱由 pty 提供专属伪终端，TIOCSTI 注入面已受控。批处理模式仍保留 --new-session 取最强隔离。**验收**：沙箱内 bash -i 无作业控制警告且可正常执行 |
| **依赖模块** | `securityd/sandbox.py::build_bwrap_argv(interactive=)` |
| **优先级** | P2 |
| **工作量** | 1 |
| **负责人** | B-沙箱组 |
| **状态** | ✅ 已验证 |
| **备注** | worker 实测警告消失；批处理沙箱测试 4 passed 隔离未变 |

---

## 11. 管理接口与工具（FR-MGT）

| 字段 | 内容 |
|------|------|
| **编号** | FR-MGT-01 |
| **规格项** | D-Bus 对外接口 |
| **规格描述** | 经系统总线（测试可用会话总线）暴露 `io.bianbu.Security`：26 个方法 + 4 个信号 （SecurityAlert / ConfirmRequest / ConfirmResponse / TokenExceeded），错误经 `io.bianbu.Error.*` 域返回。提供 introspection XML 契约文件。**验收**：busctl introspect 可见全部业务方法，契约与 XML 一致 |
| **依赖模块** | `securityd/service.py`、`data/io.bianbu.Security.xml`、dbus-python + PyGObject |
| **优先级** | P0 |
| **工作量** | 5 |
| **负责人** | E-集成组 |
| **状态** | ✅ 已验证 |
| **备注** | worker 实测 introspect 26 个业务方法齐全（另有 D-Bus 标准 Ping/GetMachineId/Introspect 需过滤） |

| 字段 | 内容 |
|------|------|
| **编号** | FR-MGT-02 |
| **规格项** | Python 客户端 SDK |
| **规格描述** | 提供 `bianbu_security_client` 封装全部 D-Bus 方法为 Python 函数，返回值转原生类型；`BIANBU_SEC_SESSION=1` 走会话总线便于测试。**验收**：每个 D-Bus 方法有对应可用封装 |
| **依赖模块** | `client/bianbu_security_client.py` |
| **优先级** | P0 |
| **工作量** | 3 |
| **负责人** | E-集成组 |
| **状态** | ✅ 已验证 |
| **备注** | 20 个封装函数；hermes 插件与 WebUI 均经此调用 |

| 字段 | 内容 |
|------|------|
| **编号** | FR-MGT-03 |
| **规格项** | 命令行工具 bncli |
| **规格描述** | 提供 `install` / `capability list|revoke` / `audit export|verify` 子命令，本地直调 SecurityEngine（不经 D-Bus，便于离线运维）；自举 sys.path 无需手设 PYTHONPATH。**验收**：非 root 用户可直接运行全部子命令 |
| **依赖模块** | `cli/bncli.py` |
| **优先级** | P1 |
| **工作量** | 2 |
| **负责人** | E-集成组 |
| **状态** | ✅ 已验证 |
| **备注** | worker 实测 install/list/revoke/export/verify 全通 |

| 字段 | 内容 |
|------|------|
| **编号** | FR-MGT-04 |
| **规格项** | WebUI 管理台 |
| **规格描述** | 提供浏览器管理界面（8 个功能页）：Agent 列表与安装、能力管理（含增删改+判权测试）、沙箱演示、审计日志、配额与网络、确认门禁、安全告警、Web 终端。全部操作经 D-Bus，不直连数据库。**验收**：各页核心操作均可用且落库生效 |
| **依赖模块** | `webui/app.py`（Flask + SocketIO）、`webui/static/` |
| **优先级** | P1 |
| **工作量** | 8 |
| **负责人** | G-前端组 |
| **状态** | ✅ 已验证 |
| **备注** | worker 实测四大功能全通；默认监听 0.0.0.0:8787 |

| 字段 | 内容 |
|------|------|
| **编号** | FR-MGT-05 |
| **规格项** | 能力灵活配置（WebUI 增删改） |
| **规格描述** | WebUI 支持新增/编辑单条能力（capability/domain/risk_level/confirm/scope/granted）并即时生效；提供工具→能力映射参考表避免填错能力名。**验收**：WebUI 改配置后 hermes 判权结果随之改变（DENY↔CONFIRM↔ALLOW） |
| **依赖模块** | `webui/app.py`（capabilities/add、/api/mapping）、`static/app.js` |
| **优先级** | P1 |
| **工作量** | 3 |
| **负责人** | G-前端组/B-安全组 |
| **状态** | ✅ 已验证 |
| **备注** | worker 实测 hermes_config_demo 4/4：配置变更即时改变判权 |

| 字段 | 内容 |
|------|------|
| **编号** | FR-MGT-06 |
| **规格项** | 实时信号推送 |
| **规格描述** | WebUI 经 SSE（`/api/events`）实时推送 SecurityAlert / ConfirmRequest / TokenExceeded；确认门禁页可直接批准/拒绝（RespondConfirm）。**验收**：CONFIRM 触发时页面即时出现待批项 |
| **依赖模块** | `webui/app.py`（SSE + 信号桥接） |
| **优先级** | P1 |
| **工作量** | 3 |
| **负责人** | G-前端组 |
| **状态** | 🟢 已实现 |
| **备注** | SSE 通道与 RespondConfirm 已实现并可用；长连接稳定性未做长跑测试 |

| 字段 | 内容 |
|------|------|
| **编号** | FR-MGT-07 |
| **规格项** | Web 终端 |
| **规格描述** | WebUI 内嵌终端（xterm.js + SocketIO + PTY），支持三模式：hermes chat（沙箱内）/ bwrap 沙箱 shell / 普通 shell，供演示与排障。**验收**：三模式均可交互，沙箱模式内隔离生效 |
| **依赖模块** | `webui/app.py`（pty.fork + SocketIO）、xterm.js |
| **优先级** | P2 |
| **工作量** | 4 |
| **负责人** | G-前端组 |
| **状态** | ✅ 已验证 |
| **备注** | worker 实测三模式可用；沙箱模式验证隔离（id/shadow/进程数） |

---

## 12. 非功能需求（NFR）

| 字段 | 内容 |
|------|------|
| **编号** | NFR-S-01 |
| **规格项** | 权限越权拦截率 |
| **规格描述** | 未授权能力的调用拦截率 **100%**，无绕过路径。**验收**：渗透测试中所有未授权能力调用均被拒 |
| **依赖模块** | `capability_registry.py`、`hermes_plugin` |
| **优先级** | P0 |
| **工作量** | — |
| **负责人** | QA |
| **状态** | ✅ 已验证 |
| **备注** | worker 实测 hermes 自测 5/5 高风险工具全 DENY（process/execute_code/terminal/write_file/patch） |

| 字段 | 内容 |
|------|------|
| **编号** | NFR-S-02 |
| **规格项** | 敏感操作确认率 |
| **规格描述** | L3/L4 及 confirm≠trusted 的能力**必经确认**才执行，无确认即拒绝（含超时）。**验收**：功能测试中确认率 100%，无未确认放行 |
| **依赖模块** | `confirm.py`、`hermes_plugin` |
| **优先级** | P0 |
| **工作量** | — |
| **负责人** | QA |
| **状态** | ✅ 已验证 |
| **备注** | confirm demo 4/4 + cli confirm demo 3/3 |

| 字段 | 内容 |
|------|------|
| **编号** | NFR-S-03 |
| **规格项** | 审计完整性 |
| **规格描述** | 审计链 **100% 可离线验证**，任何篡改可被检出并定位到具体记录。**验收**：合规审查中导出链校验通过，人为篡改必被发现 |
| **依赖模块** | `audit_chain.py` |
| **优先级** | P0 |
| **工作量** | — |
| **负责人** | QA |
| **状态** | ✅ 已验证 |
| **备注** | 篡改检测用例通过；按 agent 过滤导出的子集校验语义已修正 |

| 字段 | 内容 |
|------|------|
| **编号** | NFR-S-04 |
| **规格项** | 沙箱不降级（Fail-Closed） |
| **规格描述** | 沙箱创建失败时**100% 拒绝启动** Agent，绝不降级为无沙箱运行。**验收**：bwrap 缺失/seccomp 文件缺失时启动被拒 |
| **依赖模块** | `sandbox.py::launch` |
| **优先级** | P0 |
| **工作量** | — |
| **负责人** | QA |
| **状态** | ✅ 已验证 |
| **备注** | 测试 test_fail_closed_missing_seccomp |

| 字段 | 内容 |
|------|------|
| **编号** | NFR-P-01 |
| **规格项** | 判权延迟 |
| **规格描述** | CheckPermission **P99 ≤ 10ms**（本地 SQLite 查询 + 内存判定）。**验收**：压测 1000 次判权，P99 不超 10ms |
| **依赖模块** | `capability_registry.py`（SQLite WAL + 索引） |
| **优先级** | P0 |
| **工作量** | — |
| **负责人** | QA |
| **状态** | ✅ 已验证 |
| **备注** | worker `performance_benchmark.py --check`：100 次判权样本 P99 4.884ms ≤10ms |

| 字段 | 内容 |
|------|------|
| **编号** | NFR-P-02 |
| **规格项** | 沙箱启动开销 |
| **规格描述** | 沙箱创建不使 Agent 冷启动增加超过 **200ms**。**验收**：对比裸启动与沙箱启动耗时差 ≤200ms |
| **依赖模块** | `sandbox.py`、bubblewrap |
| **优先级** | P1 |
| **工作量** | — |
| **负责人** | QA |
| **状态** | ✅ 已验证 |
| **备注** | worker `performance_benchmark.py --check`：40 次 bwrap 样本 P99 49.045ms、相对裸启动开销 P99 11.071ms ≤200ms |

| 字段 | 内容 |
|------|------|
| **编号** | NFR-R-01 |
| **规格项** | 非 root 可运行 |
| **规格描述** | 普通用户可运行完整功能（数据根自动回退 XDG 目录 `~/.local/share/bianbu-securityd`）；root 运行时用系统路径。**验收**：非 root 用户下全部单测与冒烟通过 |
| **依赖模块** | `config.py`（四级路径优先级） |
| **优先级** | P1 |
| **工作量** | 2 |
| **负责人** | E-集成组 |
| **状态** | ✅ 已验证 |
| **备注** | worker 以 bianbu 普通用户运行全部测试通过 |

| 字段 | 内容 |
|------|------|
| **编号** | NFR-R-02 |
| **规格项** | 跨架构支持 |
| **规格描述** | 支持 x86_64 与 riscv64 双架构：seccomp 按 arch 生成对应 syscall 号表；bwrap 适配 merged-usr 布局。**验收**：两种架构下 seccomp 拦截均生效 |
| **依赖模块** | `seccomp_builder.py`、`sandbox.py` |
| **优先级** | P0 |
| **工作量** | 3 |
| **负责人** | B-沙箱组 |
| **状态** | ✅ 已验证 |
| **备注** | worker（riscv64）实测拦截生效；x86_64 开发机单测通过 |

| 字段 | 内容 |
|------|------|
| **编号** | NFR-M-01 |
| **规格项** | 测试覆盖 |
| **规格描述** | 提供单元/集成/端到端三层测试与冒烟脚本，核心判权与审计路径必须有用例覆盖。**验收**：worker 上 unit+integration ≥40 通过，冒烟脚本全阶段 PASS |
| **依赖模块** | `tests/`（unit/integration/e2e + smoke_test.sh） |
| **优先级** | P0 |
| **工作量** | 6 |
| **负责人** | QA |
| **状态** | ✅ 已验证 |
| **备注** | worker 实测 40 passed + e2e 3 passed + smoke 6 阶段 ALL PASS |

---

## 13. 需求追溯矩阵

### 13.1 PRD → SRS 正向追溯

| PRD 编号 | PRD 名称 | SRS 功能需求 | 覆盖状态 |
|----------|----------|-------------|---------|
| SEC-01 | Agent 安全模型 / Manifest | FR-SEC-01-01..04, FR-SEC-02-01..04 | ✅ 全覆盖 |
| SEC-02 | 权限与确认机制 | FR-SEC-02-01..04, FR-SEC-03-01..04 | ✅ 全覆盖 |
| SEC-03 | 审计日志 | FR-SEC-06-01..05 | ✅ 全覆盖 |
| SEC-04 | 资源配额 | FR-SEC-04-01..04, FR-SEC-07-01..02 | ✅ 全覆盖 |
| SEC-05 | 系统调用过滤 | FR-SEC-05-01..04 | ✅ 全覆盖 |
| SEC-06 | 密钥保险库 | FR-SEC-08-01..02 | ✅ 全覆盖（软件方案，TBD-17） |
| SEC-07 | 网络策略执行 | FR-SEC-07-01..02 | 🟡 规则可配置，worker 无 netfilter 不可强制执行 |
| SBX-01 | 沙箱创建 | FR-SBX-01 | ✅ 全覆盖 |
| SBX-02 | 文件系统隔离 | FR-SBX-02 | ✅ 全覆盖 |
| SBX-03 | 系统调用白名单 | FR-SBX-03, FR-SEC-05-01..04 | ✅ 全覆盖 |
| SBX-04 | 资源限制（cgroup） | FR-SBX-04 | 🟡 非 root 降级（systemd transient）|
| SBX-05 | 沙箱内 seccomp 继承 | FR-SBX-05 | ✅ worker 验证子进程 rc=99 |
| SBX-06 | 隔离级别可配置 | FR-SBX-06 | ✅ SandboxSpec 域字段 |
| SBX-07 | 批处理模式 | FR-SBX-07 | ✅ `--batch / launch(interactive=False)` |
| SBX-08 | Fail-Closed | FR-SBX-08, NFR-S-04 | ✅ 全覆盖 |
| INT-01 | hermes 插件集成 | FR-INT-01..08 | ✅ 全覆盖 |

### 13.2 SRS → PRD 反向追溯

| SRS 域 | 需求编号 | 映射 PRD | 说明 |
|--------|---------|---------|------|
| Manifest | FR-SEC-01-01..04 | SEC-01 | Manifest 解析、签名、数据库存储、元数据查询 |
| Capability | FR-SEC-02-01..04 | SEC-01/SEC-02 | 能力注册、判权算法、授权持久化、Agent 列举 |
| Confirm | FR-SEC-03-01..04 | SEC-02 | CONFIRM 流程、超时、会话缓存、主动 TUI 回调 |
| Token | FR-SEC-04-01..04 | SEC-04 | Token 预算管理 |
| Syscall | FR-SEC-05-01..04 | SEC-05/SBX-03 | cBPF 生成、双架构、可扩展 |
| Audit | FR-SEC-06-01..05 | SEC-03 | 哈希链、增量写入、分月分片、导出验证 |
| Network | FR-SEC-07-01..02 | SEC-04/SEC-07 | 策略存储 + iptables（受限于 netfilter） |
| Sandbox | FR-SBX-01..08 | SBX-01..08 | bwrap 全进程沙箱，含 cgroup/seccomp |
| Key vault | FR-SEC-08-01..02 | SEC-06 | 软件 Fernet；TBD-17 |
| hermes 集成 | FR-INT-01..08 | INT-01 | 插件 hook、映射、沙箱 launcher、approval |
| 管理接口 | FR-MGT-01..07 | SEC-01..07 | D-Bus API、SDK、bncli、WebUI |
| 非功能 | NFR-S/P/R/M | SEC-01..07/SBX | 拦截率/审计完整性/延迟/覆盖率 |

---

## 14. TBD 追踪

| TBD 编号 | 内容 | 关联需求 | 解决路径 |
|---------|------|---------|---------|
| TBD-01 | Manifest 签名算法最终选型（ed25519 vs ECDSA P-256） | FR-SEC-01-02 | 已暂定 ed25519；若目标平台无 libsodium 改 ECDSA P-256 |
| TBD-15 | 本地 AI HAL 性能 baseline | —（AI Runtime 域） | 参考 AGENTS.md IME2+TCM/RVV 分层 |
| TBD-17 | 密钥保险库硬件方案（TEE/TPM） | FR-SEC-08-01..02, NFR-S | worker K3 无 `/dev/tee`；待硬件支持后替换 Fernet |
| TBD-NET | netfilter 网络策略强制执行 | FR-SEC-07-02, NFR-S | worker 无 iptables；部署到支持 netfilter 的平台后落地 |
| TBD-PERF | P99 判权延迟压测、沙箱冷启基准 | NFR-P-01, NFR-P-02 | 已由 `tests/integration/performance_benchmark.py` 实现；worker P99 判权 4.884ms、bwrap 49.045ms、相对裸启动开销 11.071ms |

---

*文档结束 — BN-SEC-SRS-001 v1.0*

---

## 15. 干预点框架（SEC-HOOK）

| 字段 | 内容 |
|------|------|
| **编号** | SEC-HOOK-01 |
| **规格项** | 干预点注册机制 |
| **规格描述** | 提供 `InterceptorRegistry`，支持按干预点 × 优先级注册 handler（数字越小越优先，内置槽：10=SEC/Capability、50=DLP、90=Audit）；handler 签名统一 `fn(context) -> Decision`。**验收**：注册 3 个 handler 到 `pre_tool_call` 后按优先级顺序执行；单测覆盖注册/注销/优先级排序 |
| **依赖模块** | `securityd/interceptor.py`（新建） |
| **优先级** | P0 |
| **工作量** | 3 |
| **负责人** | B-安全组 |
| **状态** | ✅ 已验证 |
| **备注** | worker unit 覆盖 8 个切面、注册/注销和优先级排序 |

| 字段 | 内容 |
|------|------|
| **编号** | SEC-HOOK-02 |
| **规格项** | 短路与决策合并 |
| **规格描述** | 执行 handler 链时：遇 BLOCK/DENY 立即短路返回；多个 MODIFY 依次作用（新输出作为下一个 handler 的输入）；CONFIRM 优先级高于 ALLOW；DOWNGRADE 仅 `pre_model_call` 有效。**验收**：单测验证 handler_a(MODIFY) + handler_b(MODIFY) 结果为两次变换叠加；handler_a(ALLOW) + handler_b(BLOCK) 返回 BLOCK |
| **依赖模块** | `securityd/interceptor.py::InterceptorRegistry.invoke` |
| **优先级** | P0 |
| **工作量** | 2 |
| **负责人** | B-安全组 |
| **状态** | ✅ 已验证 |
| **备注** | worker unit 覆盖 BLOCK 短路、MODIFY 链式传递和 CONFIRM 合并 |

| 字段 | 内容 |
|------|------|
| **编号** | SEC-HOOK-03 |
| **规格项** | hermes 插件挂载 |
| **规格描述** | 在 hermes plugin 的 `register()` 中调用 `InterceptorRegistry.setup_hooks(manager)`，自动在 hermes 原生 hook（pre_tool_call/post_tool_call/on_session_end）中插入干预点调用；兼容已有 SEC capability 判权代码。**验收**：hermes 启动后 `pre_tool_call` 依次触发 SEC → DLP → Audit 三层 handler |
| **依赖模块** | `hermes_plugin/bianbu_security/__init__.py`、`securityd/interceptor.py` |
| **优先级** | P0 |
| **工作量** | 3 |
| **负责人** | F-接入组 |
| **状态** | ✅ 已验证 |
| **备注** | worker Hermes plugin/smoke 覆盖 pre_tool_call 判权、DLP 和审计 handler 链 |

| 字段 | 内容 |
|------|------|
| **编号** | SEC-HOOK-04 |
| **规格项** | LangGraph Checkpoint 挂载 |
| **规格描述** | 为 LangGraph 提供 `BianbuInterceptorNode`，在 graph 的关键位置（human node 前/后、tool node 前/后、output 前）调用干预点；支持 `interrupt()` 与 CONFIRM 联动。**验收**：LangGraph graph 执行时各干预点正确触发；CONFIRM 可通过 `interrupt()` 暂停 graph |
| **依赖模块** | `securityd/langgraph/tool_node.py`、`langgraph.types.interrupt` |
| **优先级** | P0 |
| **工作量** | 4 |
| **负责人** | F-接入组 |
| **状态** | ✅ 仓库已实现，生产 Runtime 部署验收待完成 |
| **备注** | worker LangGraph broker/负向测试通过；正式 Runtime 镜像仍需 E2E |

| 字段 | 内容 |
|------|------|
| **编号** | SEC-HOOK-05 |
| **规格项** | 干预点审计透明 |
| **规格描述** | 每个干预点调用（无论结果）写入审计链：hook_point、handler_name、decision、latency_us；WebUI 审计页支持按 hook_point 过滤查看。**验收**：审计日志可查 pre_tool_call 点有哪些 handler 执行了多久；P99 延迟 ≤ 10 ms（不含 handler 自身耗时） |
| **依赖模块** | `securityd/audit_chain.py`、`securityd/interceptor.py`、WebUI |
| **优先级** | P1 |
| **工作量** | 3 |
| **负责人** | B-安全组 |
| **状态** | ✅ 已验证 |
| **备注** | worker hook_audit_e2e 与 WebUI hook_point 过滤通过；trace 记录 handler/decision/latency |

---

## 16. LangGraph Agent 接入（INT-LG）

| 字段 | 内容 |
|------|------|
| **编号** | INT-LG-01 |
| **规格项** | LangGraph ToolNode 包装层 |
| **规格描述** | 提供 `BianbuSecurityToolNode`，继承 `langgraph.prebuilt.ToolNode`，在 `_run_tool` 前调用 `CheckPermission`；ALLOW 直接执行，DENY 返回 `{"error": "blocked_by=bianbu-security", "tool": <name>}`，CONFIRM 阻塞等待用户决策。**验收**：工具调用经 CheckPermission 判权；DENY 工具不执行，返回结构化错误；ALLOW 工具正常返回 |
| **依赖模块** | `langgraph.prebuilt.ToolNode`、`bianbu_security_client.py`、`io.bianbu.Security` D-Bus |
| **优先级** | P0 |
| **工作量** | 5 |
| **负责人** | F-接入组 |
| **状态** | ✅ 仓库已实现，生产 Runtime 部署验收待完成 |
| **备注** | 已实现于 `securityd/langgraph/tool_node.py`；与 hermes plugin hook 不同，LangGraph 是代码层包装（显式替换 ToolNode） |

| 字段 | 内容 |
|------|------|
| **编号** | INT-LG-02 |
| **规格项** | LangGraph 工具→能力映射 |
| **规格描述** | 为 LangGraph 常用内置工具（TavilySearch、PythonREPL、ShellTool、FileSystemTool、RequestsTool 等）及自定义工具建立 capability 映射表；支持通过工具名前缀批量匹配。**验收**：任意 LangGraph 工具调用均能找到对应 capability，无漏判；自定义工具默认映射到 `system.execute`（L3） |
| **依赖模块** | `langgraph_mapping.py`（新建）、`mapping.py` 公共逻辑复用 |
| **优先级** | P0 |
| **工作量** | 3 |
| **负责人** | F-接入组 |
| **状态** | ✅ 仓库已实现 |
| **备注** | 复用 hermes mapping 的 resolve 逻辑，工具名→能力表独立维护 |

| 字段 | 内容 |
|------|------|
| **编号** | INT-LG-03 |
| **规格项** | Agent 身份注册 |
| **规格描述** | LangGraph Agent 启动时以 `agent_id`（可取 graph name + pid）调用 `InstallPackage` 完成身份注册；支持通过环境变量 `BIANBU_AGENT_ID` 覆盖；无 manifest 时使用内置默认能力集。**验收**：Agent 启动后 `capability list` 可见该 agent；能力配置在 WebUI 可见可改 |
| **依赖模块** | `bianbu_security_client.py::install`、manifest 模板 |
| **优先级** | P0 |
| **工作量** | 3 |
| **负责人** | F-接入组 |
| **状态** | ✅ 仓库已实现，生产 Runtime 部署验收待完成 |
| **备注** | 默认能力集：file.read(L1)、network.access(L2)、system.execute(L3,DENY) |

| 字段 | 内容 |
|------|------|
| **编号** | INT-LG-04-A |
| **规格项** | LangGraph CONFIRM 决策联动 |
| **规格描述** | BianbuSecurityToolNode 包装层在 pre_tool_call 拿到 CONFIRM 决策后，调用 `interrupt(type="confirm", tool_name=..., capability=...)`，暂停 graph 执行并等待外部输入；用户批准后通过 LangGraph Command API `graph.update_state(..., as_node="__interrupt__", values={"approved":True})` 继续。**验收**：LangGraph graph 执行到 CONFIRM 工具时暂停；外部调 `update_state` 后继续执行；选 Deny 后 graph 继续但工具被跳过 |
| **依赖模块** | `langgraph.types.interrupt`、`langgraph.pregel.Pregel.update_state`、`bianbu_security_client::check_permission` |
| **优先级** | P0 |
| **工作量** | 3 |
| **负责人** | F-接入组 |
| **状态** | ✅ 仓库已实现，生产 Runtime 部署验收待完成 |
| **备注** | interrupt 是 graph 内部控制流暂停点；pending 经 Unix broker 交给 WebUI，最终由 graph 所在进程调用 update_state，不直接调 D-Bus RequestConfirm |

| 字段 | 内容 |
|------|------|
| **编号** | INT-LG-04-B |
| **规格项** | WebUI 确认门禁对 LangGraph 生效 |
| **规格描述** | WebUI 确认门禁 Tab 展示 LangGraph graph 触发的 CONFIRM 请求（通过轮询 LangGraph interrupt 状态或 D-Bus SecurityAlert 信号）；点批准/拒绝后调 LangGraph Command API `update_state(..., values={"approved": True/False})`，唤醒 graph 继续执行。**验收**：LangGraph 触发 CONFIRM 后 WebUI 实时出现待批项；点批准后 graph 继续、工具执行；点拒绝后 graph 继续、工具被跳过 |
| **依赖模块** | WebUI `/api/confirm`（需改造支持 LangGraph graph_id）、LangGraph Command API、SocketIO 推送 |
| **优先级** | P0 |
| **工作量** | 2 |
| **负责人** | G-前端组 |
| **状态** | ✅ 仓库已实现，生产 Runtime 部署验收待完成 |
| **备注** | 与 hermes 同步路径区别：hermes=同步阻塞（RequestConfirm），LangGraph=异步暂停+唤醒；WebUI 通过 Unix broker 转交真实 graph 进程，不持有或伪造 graph |

| 字段 | 内容 |
|------|------|
| **编号** | INT-LG-05 |
| **规格项** | 审计全链路记录 |
| **规格描述** | 每次工具调用（无论 ALLOW / DENY / CONFIRM）均通过 `AuditLog` 写入审计链；记录字段：agent_id、tool_name、capability、scope、decision、graph_run_id（LangGraph run id，便于与 graph trace 关联）。**验收**：审计日志可导出并含 graph_run_id；完整性校验通过 |
| **依赖模块** | `audit_chain.py`、`bianbu_security_client.py::audit_log` |
| **优先级** | P0 |
| **工作量** | 3 |
| **负责人** | B-安全组 |
| **状态** | ✅ 仓库已实现 |
| **备注** | graph_run_id 从 LangGraph RunnableConfig.run_id 获取 |

| 字段 | 内容 |
|------|------|
| **编号** | INT-LG-06 |
| **规格项** | Token 配额计量 |
| **规格描述** | LangGraph Agent 每次 LLM 调用后通过 `BaseCallbackHandler.on_llm_end` 获取 token 用量，经 `MeterTokens` 上报；超限时向 LangGraph graph 抛出 `TokenBudgetExceededError` 中断执行。**验收**：达 conv 上限时 graph 中断并记审计；达 day 上限时后续 graph run 被拒绝；次日 00:00 重置 |
| **依赖模块** | `token_meter.py`、`langchain_core.callbacks.BaseCallbackHandler` |
| **优先级** | P1 |
| **工作量** | 4 |
| **负责人** | B-安全组 |
| **状态** | ✅ 仓库已实现 |
| **备注** | 需 LangGraph graph 挂载 callback：`graph.with_config(callbacks=[BianbuTokenCallback()])` |

| 字段 | 内容 |
|------|------|
| **编号** | INT-LG-07 |
| **规格项** | 沙箱内启动 LangGraph Agent |
| **规格描述** | 提供 `langgraph_sandbox_launch.py`，在 bwrap 沙箱内启动 LangGraph Agent 进程；绑定必要的 Python 环境、模型配置、证书；支持批处理（`--batch`）和交互（`--interactive`）两种模式。**验收**：LangGraph Agent 在沙箱内正常运行；文件/进程/syscall 隔离生效；批处理模式输出可捕获 |
| **依赖模块** | `sandbox.py`、`hermes_sandbox_launch.py`（参考实现）、bubblewrap |
| **优先级** | P1 |
| **工作量** | 5 |
| **负责人** | B-沙箱组 |
| **状态** | ✅ 仓库已实现，目标镜像隔离验收待完成 |
| **备注** | 复用 hermes 沙箱启动器框架，绑定路径差异：LangGraph 需 Python venv + 模型配置目录 |

| 字段 | 内容 |
|------|------|
| **编号** | INT-LG-08 |
| **规格项** | WebUI 能力配置对 LangGraph 生效 |
| **规格描述** | WebUI 修改 LangGraph Agent 能力配置后，下次工具调用立即应用新规则（SQLite WAL，无需重启）；WebUI 能力管理页展示 LangGraph agent 的工具映射参考。**验收**：改 DENY→ALLOW 后 LangGraph 工具可执行；改回 DENY 立即被拦截 |
| **依赖模块** | `capability_registry.py`、WebUI `/api/capabilities`、`langgraph_mapping.py` |
| **优先级** | P1 |
| **工作量** | 2 |
| **负责人** | G-前端组 |
| **状态** | ✅ 仓库已实现 |
| **备注** | 与 hermes 共享同一能力管理页，agent 列表显示 hermes + LangGraph 两类 |

---

## 17. DLP / PII 数据防泄漏（DLP）

| 字段 | 内容 |
|------|------|
| **编号** | DLP-01 |
| **规格项** | PII 检测引擎 |
| **规格描述** | 提供 `PIIScanner`，支持正则 + NER 双引擎检测 8 类基线 PII（姓名、手机号、身份证号、邮箱、银行卡号、家庭住址、医疗记录、生物特征）；返回命中位置、类型、置信度；支持脱敏（替换为 `[PII-手机号]`）和完整保留两种输出模式。**验收**：基准测试集（每类 ≥200 条）PII 召回率 ≥95%、误报率 ≤3% |
| **依赖模块** | `dlp/pii_scanner.py`（新建）、可选 spaCy/transformers NER |
| **优先级** | P0 |
| **工作量** | 8 |
| **负责人** | D-DLP组 |
| **状态** | ✅ 已验证 |
| **备注** | worker `pii_benchmark.py`：每类 200 条正样本、400 条负样本，召回/误报门禁通过 |

| 字段 | 内容 |
|------|------|
| **编号** | DLP-02 |
| **规格项** | 启动策略加载（agent_startup 干预点） |
| **规格描述** | Agent 启动时读取 manifest 中 `[dlp]` 节（pii_types 白名单、on_detect 策略 allow/mask/block/audit_only），写入 DLP 策略缓存；无 `[dlp]` 节时使用系统默认策略（mask + audit）；作为 handler 注册到 `agent_startup` (pri=50)。**验收**：启动后 `dlp policy show <agent_id>` 可查策略；策略变更无需重启生效 |
| **依赖模块** | `securityd/dlp/policy_store.py`、`securityd/dlp/handlers.py`、SQLite |
| **优先级** | P0 |
| **工作量** | 3 |
| **负责人** | D-DLP组 |
| **状态** | ✅ 已验证 |
| **备注** | worker dlp_e2e/unit 覆盖 manifest 加载、默认策略和实时更新 |

| 字段 | 内容 |
|------|------|
| **编号** | DLP-03 |
| **规格项** | 用户输入过滤（input 干预点） |
| **规格描述** | 注册到 `input` (pri=50)：用户输入经 PIIScanner 扫描；按策略执行 mask（返回 MODIFY + 脱敏文本）/ block（返回 BLOCK）/ audit_only（返回 ALLOW + 记审计）；脱敏映射表存 session 内存供后续还原。**验收**：block 策略下含 PII 的输入被拒并提示用户；mask 策略下脱敏值进入 Agent，原值不出 session |
| **依赖模块** | `securityd/dlp/handlers.py::input_handler`、`pii_scanner.py`、`InterceptorRegistry` |
| **优先级** | P0 |
| **工作量** | 4 |
| **负责人** | D-DLP组 |
| **状态** | ✅ 已验证 |
| **备注** | worker dlp_e2e/unit 覆盖 mask/block/audit_only 和 session 映射隔离 |

| 字段 | 内容 |
|------|------|
| **编号** | DLP-04 |
| **规格项** | 云端调用 PII 阻断（pre_model_call 干预点） |
| **规格描述** | 注册到 `pre_model_call` (pri=50)：云端调用（通过 endpoint 判断非 localhost）前扫描完整 prompt；含 L3/L4 PII 时：策略=block 则返回 DOWNGRADE（提示改用本地推理）或 BLOCK；策略=mask 则返回 MODIFY + 脱敏 prompt。**验收**：云端调用含身份证号时被拒；mask 策略下脱敏后送云端，返回结果还原 PII |
| **依赖模块** | `securityd/dlp/handlers.py::pre_model_handler`、`pii_scanner.py`、`InterceptorRegistry` |
| **优先级** | P0 |
| **工作量** | 5 |
| **负责人** | D-DLP组 |
| **状态** | ✅ 已验证 |
| **备注** | worker dlp_e2e 覆盖本地和云端路径；云端高敏未将原文送出 |

| 字段 | 内容 |
|------|------|
| **编号** | DLP-05 |
| **规格项** | 模型输出 PII 检测（post_model_call 干预点） |
| **规格描述** | 注册到 `post_model_call` (pri=50)：扫描 LLM 输出是否含 PII + 训练数据泄露模式（连续 ≥20 个 token 与已知数据集高度重合）；含 PII 时按策略 mask/block/audit；训练泄露始终 block + 触发 SecurityAlert。**验收**：模型输出含手机号时被脱敏；输出训练集原文（如 WikiText 段落）时被拦截 |
| **依赖模块** | `securityd/dlp/handlers.py::post_model_handler`、`pii_scanner.py`、泄露检测 |
| **优先级** | P0 |
| **工作量** | 4 |
| **负责人** | D-DLP组 |
| **状态** | ✅ 已验证 |
| **备注** | worker unit 覆盖 PII 输出处理和参考语料逐字泄露阻断 |

| 字段 | 内容 |
|------|------|
| **编号** | DLP-06 |
| **规格项** | 工具调用 PII 提升（pre_tool_call 干预点） |
| **规格描述** | 注册到 `pre_tool_call` (pri=50)：扫描工具参数（file path / command / url 等）是否含 PII；含 PII 时自动提升决策：原 ALLOW → CONFIRM，原 CONFIRM 保持；与 SEC capability 判权联动。**验收**：write_file(path="/tmp/张三-身份证.txt") 从 ALLOW 提升为 CONFIRM；原本就 CONFIRM 的工具不重复确认 |
| **依赖模块** | `securityd/dlp/handlers.py::pre_tool_handler`、`pii_scanner.py`、`InterceptorRegistry` |
| **优先级** | P0 |
| **工作量** | 4 |
| **负责人** | D-DLP组 |
| **状态** | ✅ 已验证 |
| **备注** | worker unit/integration 覆盖 ALLOW→CONFIRM、BLOCK 和远端出境升级 |

| 字段 | 内容 |
|------|------|
| **编号** | DLP-07 |
| **规格项** | 工具返回值脱敏（post_tool_call 干预点） |
| **规格描述** | 注册到 `post_tool_call` (pri=50)：扫描工具返回值（文件内容 / 命令输出 / API 响应）是否含 PII；含 PII 时按策略脱敏后才注入上下文，防多轮传播。**验收**：read_file 返回含手机号的文本时，后续对话中 Agent 看到的是脱敏值 `[PII-手机号-001]` |
| **依赖模块** | `securityd/dlp/handlers.py::post_tool_handler`、`pii_scanner.py`、`InterceptorRegistry` |
| **优先级** | P1 |
| **工作量** | 3 |
| **负责人** | D-DLP组 |
| **状态** | ✅ 已验证 |
| **备注** | worker unit 覆盖工具返回值脱敏、阻断和 session 映射；大载荷走 UDS 基准 |

| 字段 | 内容 |
|------|------|
| **编号** | DLP-08 |
| **规格项** | 最终输出审查（output 干预点） |
| **规格描述** | 注册到 `output` (pri=50)：Agent 最终输出（返回用户前）经 PIIScanner 最后一道审查；含 PII 且策略=block 时返回 BLOCK；mask 策略下还原脱敏值为原值（仅限本 session 创建的映射）；可选水印溯源（嵌入隐形 UUID 便于泄露追踪）。**验收**：output 含未授权 PII 时被拦截；mask 策略下还原映射表中的 PII |
| **依赖模块** | `securityd/dlp/handlers.py::output_handler`、`pii_scanner.py` |
| **优先级** | P1 |
| **工作量** | 4 |
| **负责人** | D-DLP组 |
| **状态** | ✅ 已验证 |
| **备注** | worker unit 覆盖输出复扫、session 还原和零宽水印提取 |

| 字段 | 内容 |
|------|------|
| **编号** | DLP-09 |
| **规格项** | Session 清零（agent_shutdown 干预点） |
| **规格描述** | 注册到 `agent_shutdown` (pri=50)：session 结束时清零脱敏映射表与策略缓存（调用 `explicit_bzero` 或 `memset` 覆写）；记录 DLP 统计（本 session 触发次数、类型分布）到审计链。**验收**：session 结束后 映射表内存被覆写（gdb 验证全零）；审计可查 DLP 统计 |
| **依赖模块** | `securityd/dlp/handlers.py::shutdown_handler`、`DLPSessionStore` |
| **优先级** | P1 |
| **工作量** | 2 |
| **负责人** | D-DLP组 |
| **状态** | ✅ 已验证 |
| **备注** | worker unit 覆盖 session 映射清理；Python 字符串无法保证原地 explicit_bzero，作为平台边界 |

| 字段 | 内容 |
|------|------|
| **编号** | DLP-10 |
| **规格项** | WebUI DLP 配置页 |
| **规格描述** | WebUI 新增 DLP 策略配置 Tab：Agent × PII 类型矩阵（8×N 表格），每格下拉选 allow/mask/block/audit_only；触发统计卡片（本日各类型 PII 检出次数、拦截/脱敏/放行分布）；支持导出 DLP 审计子集。**验收**：改策略后下次扫描立即生效；统计卡片实时刷新 |
| **依赖模块** | `webui/app.py`（`/api/dlp/*`）、`securityd/dlp/policy_store.py` |
| **优先级** | P1 |
| **工作量** | 5 |
| **负责人** | G-前端组 |
| **状态** | ✅ 已验证 |
| **备注** | worker unit 覆盖策略矩阵、统计聚合和实时生效 |

---

## 18. 传输通道架构（ARCH）

| 字段 | 内容 |
|------|------|
| **编号** | ARCH-01 |
| **规格项** | D-Bus / UDS 传输通道分工 |
| **规格描述** | 明确两条通道职责：**D-Bus**（控制面，≤4 KB，P99 ≤ 10 ms）—— CheckPermission、能力变更、MeterTokens、信号广播（SecurityAlert/ConfirmRequest/TokenExceeded）、polkit 管控；**UDS**（数据面）—— PII 扫描被扫描内容、审计载荷全文、工具返回值、流式 token、`SO_PEERCRED` uid 校验。拆分点：DLP **策略查询**走 D-Bus，**被扫描内容**走 UDS；审计**元数据**走 D-Bus，**载荷全文**走 UDS。**验收**：>4 KB 的工具返回值经 UDS 传输；CheckPermission 保持 D-Bus（P99 ≤ 10 ms）；UDS **小载荷（≤4 KB）P99 ≤ 1 ms**、**大载荷吞吐 ≥ 10 MB/s**（延迟随载荷线性增长，不设统一延迟上限） |
| **依赖模块** | `securityd/uds_server.py`（新建）、`service.py`（D-Bus 层）、Unix domain socket `/run/bianbu/securityd.sock` |
| **优先级** | P0 |
| **工作量** | 5 |
| **负责人** | B-安全组 |
| **状态** | ✅ 已验证 |
| **备注** | worker `uds_benchmark.py` 覆盖小载荷 P99、4KB 边界、大载荷吞吐和长连接 |

---

## 19. PRD 追溯矩阵

本节建立 PRD 产品需求与 SRS 软件需求的双向追溯关系，确保每条 PRD 需求有对应 SRS 实现规格，每条 SRS 规格可追溯到 PRD 源头。

### 19.1 PRD → SRS 映射

| PRD 编号 | PRD 功能名称 | SRS 编号 | SRS 规格项 |
|----------|-------------|---------|-----------|
| **SEC-01** | 权限框架 | FR-SEC-02-01~04 | 能力注册表、判权、scope 匹配、授权态变更 |
| **SEC-02** | 能力注册表 | FR-SEC-01-01~04 | Manifest 解析、签名验证、约束校验、完整安装 |
| **SEC-03** | 确认门禁 | FR-SEC-03-01~04 | 确认基础流程、L4 二次确认、会话信任、UI 可插拔 |
| **SEC-04** | 配额计量 | FR-SEC-04-01~04 | 双维度计量、超限行为、会话/天级重置、审计完整 |
| **SEC-05** | 系统调用拦截 | FR-SEC-05-01~04 | seccomp BPF 生成、syscall 表、架构适配、拦截验证 |
| **SEC-06** | 审计日志 | FR-SEC-06-01~05 | SHA-256 哈希链、线程串行、导出/验证、按 agent 过滤 |
| **SEC-07** | 网络访问控制 | FR-SEC-07-01~02 | 域名白名单、DNS 拦截（部分实现） |
| **SBX-01** | 文件系统隔离 | FR-SBX-01~03 | tmpfs 根、私有可写目录、宿主只读绑定 |
| **SBX-02** | Cgroup 资源限制 | FR-SBX-04 | CPU/内存/进程数上限（非 root 降级） |
| **SBX-03** | 网络隔离 | FR-SBX-05 | 共享宿主网络（无独立 netns） |
| **SBX-04** | Seccomp 白名单 | FR-SEC-05-* | 同 SEC-05（syscall 拦截） |
| **SBX-05** | Capability 裁剪 | FR-SBX-02 | --cap-drop ALL，按需加白 |
| **SBX-06** | 性能开销测量 | FR-SBX-06 | 启动延迟与 syscall 开销基准 |
| **SBX-07** | Fail-Closed 保证 | FR-SBX-07 | 启动失败拒绝降级 |
| **SBX-08** | 沙箱 Level 2 | FR-SBX-08 | merged-usr 适配、交互作业控制 |
| **INT-SEC-01** | hermes plugin hook | FR-INT-01 | plugin.yaml + register(manager) |
| **INT-SEC-02** | 工具→能力映射 | FR-INT-02 | 47 工具覆盖、零臆想校验 |
| **INT-SEC-03** | 上游真拦截 | FR-INT-03 | List 遍历找 block，短路 |
| **INT-SEC-04** | WebUI 审批 | FR-INT-04 | RequestConfirm / RespondConfirm |
| **INT-SEC-05** | CLI 审批 | FR-INT-05 | 主动调 hermes TUI 回调 |
| **INT-SEC-06** | 整进程沙箱 | FR-INT-06 | bwrap 包裹 hermes 进程 |
| **INT-SEC-07** | 沙箱环境适配 | FR-INT-07 | ~/.hermes 绑定、DNS/CA、passwd/group |
| **INT-SEC-08** | 交互作业控制 | FR-INT-08 | 省略 --new-session，继承 tty |
| **INT-LG-01** | LangGraph ToolNode 包装 | INT-LG-01 | BianbuSecurityToolNode 判权 |
| **INT-LG-02** | LangGraph 工具映射 | INT-LG-02 | TavilySearch / ShellTool / FileSystemTool 等 |
| **INT-LG-03** | LangGraph Agent 注册 | INT-LG-03 | InstallPackage + 默认能力集 |
| **INT-LG-04** | LangGraph HITL | INT-LG-04-A/B | interrupt() 暂停 + WebUI Command API 唤醒 |
| **INT-LG-05** | LangGraph 审计 | INT-LG-05 | graph_run_id 关联 |
| **INT-LG-06** | LangGraph Token 配额 | INT-LG-06 | BaseCallbackHandler on_llm_end |
| **INT-LG-07** | LangGraph 沙箱启动 | INT-LG-07 | langgraph_sandbox_launch.py |
| **INT-LG-08** | LangGraph 配置生效 | INT-LG-08 | WebUI 能力管理实时应用 |
| **SEC-HOOK-01** | 干预点注册机制 | SEC-HOOK-01 | InterceptorRegistry |
| **SEC-HOOK-02** | 短路与决策合并 | SEC-HOOK-02 | BLOCK 短路、MODIFY 链式、CONFIRM 优先 |
| **SEC-HOOK-03** | hermes 挂载 | SEC-HOOK-03 | setup_hooks(manager) |
| **SEC-HOOK-04** | LangGraph 挂载 | SEC-HOOK-04 | BianbuInterceptorNode |
| **SEC-HOOK-05** | 干预点审计 | SEC-HOOK-05 | hook_point / handler / latency 记录 |
| **DLP-01** | PII 检测引擎 | DLP-01 | 正则 + NER，8 类基线 PII，召回 ≥95% |
| **DLP-02** | agent_startup 策略加载 | DLP-02 | manifest [dlp] 节 → policy_store |
| **DLP-03** | input 过滤 | DLP-03 | mask / block / audit_only，脱敏映射表 |
| **DLP-04** | pre_model_call 云端阻断 | DLP-04 | L3/L4 PII 阻断或 DOWNGRADE 本地 |
| **DLP-05** | post_model_call 输出检测 | DLP-05 | PII + 训练泄露模式（n-gram overlap） |
| **DLP-06** | pre_tool_call PII 提升 | DLP-06 | 含 PII 参数：ALLOW → CONFIRM |
| **DLP-07** | post_tool_call 返回值脱敏 | DLP-07 | 工具返回脱敏后注入上下文 |
| **DLP-08** | output 最终审查 | DLP-08 | 还原映射表 + 可选水印 |
| **DLP-09** | agent_shutdown 清零 | DLP-09 | 映射表 explicit_bzero + 统计审计 |
| **DLP-10** | WebUI DLP 配置页 | DLP-10 | Agent × PII 类型矩阵 |
| **ARCH-01** | D-Bus / UDS 分工 | ARCH-01 | 控制面 D-Bus、数据面 UDS，性能指标 |
| **MGT-01** | D-Bus 对外接口 | FR-MGT-01 | 21 方法 + 4 信号 |
| **MGT-02** | Python 客户端 SDK | FR-MGT-02 | bianbu_security_client 封装 |
| **MGT-03** | 命令行工具 bncli | FR-MGT-03 | install / capability / audit 子命令 |
| **MGT-04** | WebUI 管理台 | FR-MGT-04 | 8 功能页 |
| **MGT-05** | WebUI 能力配置 | FR-MGT-05 | 增删改即时生效 |
| **MGT-06** | 实时信号推送 | FR-MGT-06 | SSE + SocketIO |
| **MGT-07** | Web 终端 | FR-MGT-07 | xterm.js + pty，3 模式 |
| **— 新增 —** | 密钥库 | FR-SEC-08-01~02 | Fernet 软件密钥库、访问门控 |

### 19.2 SRS 覆盖统计

| PRD 章节 | PRD 需求数 | SRS 覆盖需求数 | 覆盖率 |
|---------|-----------|--------------|-------|
| 一、安全核心（SEC） | 7 | 22 | 314% |
| 二、轻量沙箱（SBX） | 8 | 8 | 100% |
| 三、干预点框架（SEC-HOOK） | 5 | 5 | 100% |
| 四、hermes 接入（INT-SEC） | 8 | 8 | 100% |
| 五、LangGraph 接入（INT-LG） | 8 | 9 | 112% |
| 六、DLP/PII（DLP） | 10 | 10 | 100% |
| 七、传输通道（ARCH） | 1 | 1 | 100% |
| 八、管理与可观测性（MGT） | 5 | 7 | 140% |
| **合计** | **52** | **70** | **134%** |

**说明**：覆盖率 >100% 表示 SRS 将 PRD 单条需求拆分为多条可测试的细粒度规格（如 SEC-01 权限框架在 SRS 拆为 FR-SEC-02-01~04 四条）。剩余 10 条 SRS 需求为非功能需求（NFR-*，性能/可靠性/可维护性指标）。
