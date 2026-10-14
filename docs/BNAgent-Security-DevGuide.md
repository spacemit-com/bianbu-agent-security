# AgentSecurityD 安全系统开发文档（Developer Guide）

| 项 | 内容 |
|----|------|
| 文档编号 | BN-SEC-DEV-001 |
| 版本 | V1.0 |
| 来源 | BN-SEC-SOL-001（方案）+ BN-SEC-HERMES-001（接入）+ `impl/bianbu-securityd` 实现 + worker 10.0.90.243 实测 |
| 日期 | 2026-07-15 |
| 状态 | 与实现同步 |
| 目标读者 | 新加入的开发者 —— 读完这份即可读懂整个项目并开始开发 |

> 本文是 AgentSecurityD 的**单点入口开发文档**：从需求、总体架构，到每个子系统的内部结构、
> 数据模型、接口契约、业务时序、详细逻辑、配置项、测试与部署，一份读懂全项目。
> 代码位置 `impl/bianbu-securityd/`；所有行为均在 worker（SpacemiT K3 / riscv64）实测。
> 姊妹文档：方案见 `BNAgent-Security-solution.md`，hermes 接入见 `BNAgent-Hermes-Integration.md`。

---

## 目录

1. [需求与目标](#1-需求与目标)
2. [总体架构](#2-总体架构)
3. [代码结构与模块地图](#3-代码结构与模块地图)
4. [数据模型（DDL 与内存结构）](#4-数据模型)
5. [D-Bus 接口契约](#5-d-bus-接口契约)
6. [子系统详细设计](#6-子系统详细设计)
7. [关键业务时序](#7-关键业务时序)
8. [配置项总表](#8-配置项总表)
9. [错误处理与安全默认](#9-错误处理与安全默认)
10. [测试体系](#10-测试体系)
11. [部署与运行](#11-部署与运行)
12. [术语表与追溯](#12-术语表与追溯)

---

## 1. 需求与目标

### 1.1 定位

AgentSecurityD（进程名 `bianbu-securityd`，D-Bus 接口 `io.bianbu.Security`）是 Bianbu Next
Agent OS 的**信任根**与安全管理器：以 Capability（能力）为核心，保证每个 Agent 的行为
**可授权、可审计、可追溯、可隔离**。核心原则——Agent 的每个受控动作都必须
**先问 securityd、后执行、再记账**。

### 1.2 功能需求（对齐 PRD SEC-01~07 / SBX-01~08）

| 编号 | 需求 | 落地模块 |
|------|------|---------|
| FR-SEC-01 | Manifest 校验：ed25519 验签 + 权限声明解析 | manifest.py |
| FR-SEC-02 | 能力注册表：声明/授权持久化，可查/可撤销 | capability_registry.py |
| FR-SEC-03 | 敏感操作确认门禁：always/once_per_session，L4 二次确认 | confirm.py |
| FR-SEC-04 | Token 配额：单次/单日上限，超限暂停 | token_meter.py |
| FR-SEC-05 | 系统调用拦截：seccomp-bpf 黑名单 | seccomp_builder.py |
| FR-SEC-06 | 审计日志：防篡改哈希链，导出+离线验证 | audit_chain.py |
| FR-SEC-07 | 网络白名单：默认 DROP，仅放行声明域名 | network_policy.py |
| FR-SBX-01~07 | 沙箱：bwrap 文件视图/cgroup/seccomp/cap-drop/Fail-Closed | sandbox.py |
| FR-AI-21 | 密钥库：无 TEE 软件方案 | key_vault.py |

### 1.3 可测量目标（NFR）

| 目标 | 指标 |
|------|------|
| 权限越权拦截率 | 100%（NFR-S-01） |
| 敏感操作确认率 | 100%，无确认不执行（NFR-S-02） |
| 审计完整性 | 哈希链 100% 可离线验证，篡改可定位（NFR-S-03） |
| 沙箱不降级 | 创建失败 100% 拒绝启动（FR-SBX-07） |
| 权限判定延迟 | CheckPermission P99 ≤ 10ms |

### 1.4 边界（不做什么）

- 不做 Agent 生命周期（归 agent-runtimed）、不做模型推理（归 aihald）。
- securityd 只**产策略**（seccomp/netfilter），实际 execve 由 runtimed / 启动器执行。
- 不复用 hermes/agentforce 代码（AGENTS.md），仅作环境参考。

---

## 2. 总体架构

### 2.1 分层视图

```
┌──────────────────────────────────────────────────────────────────┐
│  调用方：hermes-agent / bianbu-sdk / bncli / BiBit GUI / 第三方Agent │
└───────────────────────────────┬──────────────────────────────────┘
                                │ D-Bus  io.bianbu.Security（系统总线）
┌───────────────────────────────▼──────────────────────────────────┐
│                    service.py（D-Bus 服务层：26 方法 + 4 信号）      │
├───────────────────────────────────────────────────────────────────┤
│                    engine.py（SecurityEngine：业务编排）            │
│  ┌──────────────┬──────────────┬──────────────┬─────────────────┐  │
│  │ manifest     │ capability_  │ confirm      │ token_meter     │  │
│  │ (验签)       │ registry     │ (确认门禁)   │ (配额)          │  │
│  ├──────────────┼──────────────┼──────────────┼─────────────────┤  │
│  │ seccomp_     │ network_     │ audit_chain  │ key_vault       │  │
│  │ builder      │ policy       │ (哈希链)     │ (密钥库)        │  │
│  └──────────────┴──────────────┴──────────────┴─────────────────┘  │
├───────────────────────────────────────────────────────────────────┤
│  持久化：SQLite（capabilities.db / token_budget.db / audit/*.db）   │
│          + 加密文件（keys/）+ 运行时策略（/run 下 seccomp/nft）      │
└───────────────────────────────┬──────────────────────────────────┘
                                │ BuildSandboxPolicy → seccomp/nft 产物
┌───────────────────────────────▼──────────────────────────────────┐
│  sandbox.py（bwrap 编排）/ hermes_sandbox_launch（整进程沙箱）      │
│  seccomp + cap-drop + 文件视图 + cgroup + 网络                     │
└───────────────────────────────────────────────────────────────────┘
```

### 2.2 关键设计决策（ADR 摘要）

| 决策 | 理由 |
|------|------|
| D-Bus 作为 IPC | Linux 原生、标准化、天然可审计；与其他 bianbu 服务统一 |
| 权限两维模型（域 × L1-L4）+ 三级信任 | 单一模型消解多套分类矛盾 |
| 审计防篡改用 SHA-256 哈希链（非区块链） | 轻量、可离线验证 |
| 沙箱用 bubblewrap（非手动 chroot/overlayfs） | 非特权可用；worker overlayfs 需 CAP_SYS_ADMIN 不可用；bwrap 已实测 |
| seccomp 纯 Python 生成 cBPF | 无 libseccomp 绑定依赖；x86_64/riscv64 双 arch |
| 无 TEE → 软件密钥库（Fernet 加密文件） | K3 无 /dev/tee；门控读取 |
| engine 与 service 分离 | 业务逻辑可被 CLI/测试直调，不强依赖 D-Bus |

### 2.3 语言与运行环境

- **Python 3.11+**（worker 用系统 3.14 / 开发机 3.12）。依赖：`cryptography`（ed25519+Fernet）、
  `dbus-python`+`PyGObject`（D-Bus 服务）、`bubblewrap`（沙箱）。
- **非 root 友好**：`BIANBU_SEC_ROOT` 或 XDG 回退，普通用户即可跑（见 §8）。
- **arch 感知**：seccomp 与 bwrap 均按 `platform.machine()` 适配（riscv64 无 /lib64、merged-usr）。

---

## 3. 代码结构与模块地图

```
impl/bianbu-securityd/
├── securityd/                核心包（业务逻辑，不依赖 hermes）
│   ├── config.py             路径/默认值/seccomp 黑名单（四级路径优先级）
│   ├── models.py             Domain/RiskLevel/Confirm/Decision/Permission/Manifest
│   ├── errors.py             io.bianbu.Error.* 异常类型
│   ├── manifest.py           FR-SEC-01 验签+解析
│   ├── capability_registry.py FR-SEC-02/03 SQLite + CheckPermission + session_trust
│   ├── confirm.py            FR-SEC-03 确认门禁（异步、L4 二次、超时、可插 UI）
│   ├── audit_chain.py        FR-SEC-06 哈希链（单写线程+导出+验证+分段）
│   ├── token_meter.py        FR-SEC-04 conv/day 计数+00:00 重置+持久化
│   ├── seccomp_builder.py    FR-SEC-05 纯 Python cBPF（x86_64/riscv64）
│   ├── network_policy.py     FR-SEC-07 域名→iptables 规则产物
│   ├── key_vault.py          FR-AI-21 Fernet 加密文件密钥库
│   ├── sandbox.py            FR-SBX bwrap 编排（SandboxSpec/launch/cleanup）
│   ├── engine.py             SecurityEngine：组合全部模块的业务门面
│   └── service.py            D-Bus 服务层（io.bianbu.Security）
├── client/
│   └── bianbu_security_client.py  D-Bus 客户端封装（hermes/第三方调用）
├── cli/bncli.py              命令行：install/capability/audit（本地直调 engine）
├── hermes_plugin/            hermes 接入（见 BN-SEC-HERMES-001）
│   ├── bianbu_security/       插件（plugin.yaml + __init__.py + mapping.py）
│   └── hermes_sandbox_launch.py  整进程 bwrap 启动器
├── data/                     io.bianbu.Security.xml / systemd unit / dbus policy
└── tests/                    unit / integration / e2e / fixtures + smoke_test.sh
```

**依赖方向**：`service` → `engine` → 各子模块 → `config`/`models`/`errors`。
子模块之间几乎不横向依赖，`engine` 是唯一编排点，便于单测与替换。

---

## 4. 数据模型

### 4.1 共享类型（models.py）

```python
Domain      = execute | resource | data | system        # 权限域
RiskLevel   = L1 | L2 | L3 | L4                          # 风险等级
Confirm     = always | once_per_session | trusted        # 确认策略
Decision    = ALLOW(0) | CONFIRM(1) | DENY(2)            # 判权结果
Permission  = {capability, domain, risk_level, confirm, scope?, granted}
Manifest    = {agent_id, version, name, signature, permissions[], allowed_domains[], token_*}
```
约束（`Permission.validate()`）：`risk_level ∈ {L3,L4} ⟹ confirm ≠ trusted`（危险能力禁止永久放行）。

### 4.2 Capability Registry（capabilities.db，SQLite WAL）

```sql
CREATE TABLE capability (
  agent_id   TEXT, capability TEXT,
  domain     TEXT CHECK(domain IN('execute','resource','data','system')),
  risk_level TEXT CHECK(risk_level IN('L1','L2','L3','L4')),
  confirm    TEXT CHECK(confirm IN('always','once_per_session','trusted')),
  scope      TEXT DEFAULT '',
  granted    INTEGER DEFAULT 0,          -- 0=待授权 1=已授权 -1=已撤销
  PRIMARY KEY(agent_id, capability, scope));

CREATE TABLE session_trust (               -- once_per_session 的会话内缓存
  session_id TEXT, agent_id TEXT, capability TEXT, granted_at TEXT,
  PRIMARY KEY(session_id, agent_id, capability));

CREATE TABLE agent_manifest (              -- 安装记录（含 manifest 原文供网络策略解析）
  agent_id TEXT PRIMARY KEY, version TEXT, name TEXT, signature TEXT,
  manifest_raw TEXT DEFAULT '', installed_at TEXT, status TEXT DEFAULT 'active');
```

### 4.3 Token Budget（token_budget.db）

```sql
CREATE TABLE token_budget_config (
  agent_id TEXT PRIMARY KEY, unit TEXT DEFAULT 'token',
  limit_per_conversation INTEGER DEFAULT 100000,
  limit_per_day INTEGER DEFAULT 500000, on_exceed TEXT DEFAULT 'pause_and_notify');
CREATE TABLE token_budget_state (          -- 当日累计（跨重启恢复）；conv 计数在内存
  agent_id TEXT, date_epoch TEXT, day_used INTEGER DEFAULT 0,
  PRIMARY KEY(agent_id, date_epoch));
```

### 4.4 Audit Chain（audit/YYYYMM.db，按月分段）

```sql
CREATE TABLE audit_record (
  seq INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, agent_id TEXT,
  op_type TEXT, target TEXT, result TEXT,
  prev_hash TEXT, hash TEXT);
-- hash = SHA256(seq‖ts‖agent_id‖op_type‖target‖result‖prev_hash)，首条 prev_hash="GENESIS"
```
哈希链是**全局单链**（所有 agent 交错）。整链校验（verify_live）要求 prev 首尾相连；
按 agent_id 过滤导出的子集只做逐条自洽校验（每条 hash 用自身 prev_hash 重算，篡改仍可检出）。

### 4.5 Key Vault（keys/）

- `master.key`：32 字节随机主密钥（0600），SHA-256 派生 Fernet 密钥。
- `<agent_id>.vault`：该 agent 的 secret（JSON 经 Fernet 加密整体落盘，0600）。
- 明文不落盘；普通 Agent 经 CheckPermission（`secret.read`）门控访问。

### 4.6 运行时策略产物（/run 下，tmpfs）

```
<RUN>/sandbox/<agent_id>/seccomp.bpf      # BuildSandboxPolicy 生成，供 bwrap --seccomp
<RUN>/sandbox/<agent_id>/netfilter.rules  # 网络白名单规则文本
```

---

## 5. D-Bus 接口契约

接口 `io.bianbu.Security`，对象路径 `/io/bianbu/Security`。签名记法：s=string, i=int32,
x=int64, b=bool, a=array, {}=dict, v=variant。机器可读定义见 `data/io.bianbu.Security.xml`。

### 5.1 方法（26）

| 方法 | in → out | 说明 | FR |
|------|----------|------|----|
| VerifyManifest | s(pkg) → b,s,aa{sv} | 验签+解析权限 | SEC-01 |
| RegisterCapabilities | s,aa{sv} → b | 写入注册表 | SEC-02 |
| BindAgent | s → b | Runtime 建立 caller/Agent 绑定 | SEC-02 |
| BindAgentV2 | s,a{sv} → b | 带 session/run 的 caller 绑定 | SEC-02 |
| CheckPermission | s,s,s → i | 0/1/2 判权 | SEC-02/03 |
| CheckPermissionV2 | s,s,s,a{sv} → i | 带 session trust 上下文判权 | SEC-02/03 |
| RequestConfirm | s,s,s → b | 确认门禁（异步，L4 二次） | SEC-03 |
| RequestConfirmV2 | s,s,s,a{sv} → b | 带 session/run 的确认门禁 | SEC-03 |
| RespondConfirm | s,b → b | GUI 回传用户决定，唤醒 RequestConfirm | SEC-03 |
| RevokePermission | s,s → b | 撤销授权 | SEC-02 |
| BuildSandboxPolicy | s → s,s | 生成 seccomp+netfilter | SBX-03/04/05 |
| MeterTokens | s,x,s → b,x | 计量+超限判定 | SEC-04 |
| AuditLog | s,s,s,s → x | 写审计链，返回 seq | SEC-06 |
| ExportAudit | s,s → s | 导出（json/csv） | SEC-06 |
| VerifyAuditChain | s → b | 离线验证完整性 | SEC-06 |
| SetNetworkPolicy | s,as,s → b | 白名单/学习模式 | SEC-07 |
| GetCapabilities | s → aa{sv} | 查询已注册能力 | SEC-02 |
| SuspendAgent | s,s → b | 管理面兼容操作/告警记录；超限事件由 Agent Runtime/agent 消费并负责暂停或终止 | SEC-04 |

### 5.2 信号（4）

| 信号 | 载荷 | 触发 |
|------|------|------|
| SecurityAlert | s,s,s (agent_id,type,detail) | 越权/异常/审计失败 |
| ConfirmRequest | s,s,s,s (…,request_id) | RequestConfirm 触发，通知 UI |
| ConfirmResponse | s,b (request_id,approved) | RespondConfirm 后广播 |
| TokenExceeded | s,s,x,x (agent_id,scope,used,limit) | token 超限 |

### 5.3 错误码域 `io.bianbu.Error.*`

`PermissionDenied` / `ConfirmRequired` / `QuotaExceeded` / `InvalidManifest` /
`AuditFailure`（Fail-Closed） / `SandboxBuildFailed` / `NotFound` / `InvalidArgument` / `Internal`。

### 5.4 客户端封装（client/bianbu_security_client.py）

每个方法一个同义 Python 函数（`verify_manifest`/`check_permission`/`request_confirm`/
`respond_confirm`/`meter_tokens`/`audit_log`/`export_audit`/`verify_audit_chain`/
`build_sandbox_policy`/`set_network_policy`/`get_capabilities`）。`BIANBU_SEC_SESSION=1`
走会话总线（测试），否则系统总线（生产）。

---

## 6. 子系统详细设计

每个子系统按「职责 / 关键逻辑 / 要点」说明。所有子系统被 `engine.SecurityEngine` 组合调用。

### 6.1 Manifest Verifier（manifest.py，FR-SEC-01）

- **职责**：校验 Agent 包，解析权限声明。包结构：`<pkg>/manifest.toml` + `manifest.toml.sig`（ed25519 hex）+ `pubkey.hex`。
- **关键逻辑**：
  1. 解析 TOML `[agent]`（id/version/name/signature）+ `[permissions]`（每能力 domain/risk_level/confirm/scope）+ `[permissions.network]` + `[permissions.token_budget]`。
  2. 逐能力 `Permission.validate()`（L3/L4≠trusted）。
  3. 验签：签名负载 = manifest.toml 去掉 signature 行的规范化内容（避免自指涉）；ed25519 校验，优先 `cryptography` 回退 `pynacl`。
- **要点**：签名/占位符（`xxxx`/`PLACEHOLDER`）视为无签名拒绝；缺 manifest/pubkey 均返回明确 reason。

### 6.2 Capability Registry（capability_registry.py，FR-SEC-02/03）

- **职责**：能力持久化 + `CheckPermission` 判权 + 会话信任。
- **CheckPermission 算法**：
```
row = best_match_scope(agent_id, cap, scope)      # 文件类做最长前缀匹配
if not row or row.granted != 1: return DENY
if row.risk_level == 'L4':      return CONFIRM     # L4 恒二次确认
match row.confirm:
  'trusted':          return ALLOW
  'once_per_session': return ALLOW if session_trust.has else CONFIRM
  'always':           return CONFIRM
```
- **best_match_scope**：请求 scope 若越出所有声明 scope（如声明 `~/Documents` 却访问 `/etc/passwd`）→ 无匹配行 → DENY，天然防目录越界。
- **要点**：SQLite WAL + RLock 并发安全；`revoke` 置 granted=-1 并清 session_trust。

### 6.3 Confirm Gatekeeper（confirm.py，FR-SEC-03）

- **职责**：CONFIRM 时向用户/GUI 请求确认，L4 二次确认，超时默认拒绝。
- **关键逻辑**（`request` → `_ask`）：
  1. 先注册等待 Event，**再**发 `ConfirmRequest` 信号（避免"信号先到、respond 被丢弃"竞态）。
  2. 阻塞等 `respond(request_id, approved)`（GUI 经 D-Bus `RespondConfirm` 回传）或超时（默认 30s）。
  3. L4：首肯后再走一次二次确认；任一道拒绝即整体 False。
- **可插 UI**：`set_ui_callback` 支持单进程内嵌 UI；无 UI 时走信号+respond 回路。
- **要点**：D-Bus 层 `RequestConfirm` 用 async_callbacks + 后台线程，避免阻塞 GLib 主循环导致 `RespondConfirm` 无法派发的死锁。

### 6.4 Audit Chain Engine（audit_chain.py，FR-SEC-06）

- **职责**：防篡改哈希链，导出 + 离线验证 + 按月分段。
- **关键逻辑**：
  - **单写线程**：所有 `log()` 经内存队列串行化，防并发破 prev_hash 链；写失败回传异常 → 上层 Fail-Closed。
  - **导出**：按 filter（agent_id/from/to）查询，JSON/CSV + 末尾 `chain_anchor`（链尾 hash）。
  - **验证**：`_verify_rows(contiguous)` —— 全量校验要求 prev 相连（防删除/重排）；过滤子集只逐条自洽（防字段篡改）。
- **要点**：`op_type` 枚举含 check_permission/confirm/token_meter/build_sandbox_policy/install/revoke 等；result 含 allow/deny/confirm_approved/confirm_denied/exceed 等。

### 6.5 Token Meter（token_meter.py，FR-SEC-04）

- **职责**：conv/day 双维度 token 计量，超限判定，00:00 重置，持久化恢复。
- **关键逻辑**：内存计数器 `{agent_id → (conv_used, day_used, day_epoch)}`；`meter()` 原子累加，`day_epoch != today` 时 day_used 归零（本地时区重置）；`conv_used > limit_conv` 或 `day_used > limit_day` → `within_limit=False` + `exceeded_scope`；day_used 落 `token_budget_state` 供重启恢复。
- **要点**：`today_fn` 可注入便于测试重置；conv 计数会话结束 `reset_conversation`。

### 6.6 Syscall Filter Builder（seccomp_builder.py，FR-SEC-05/SBX-04）

- **职责**：纯 Python 生成 seccomp cBPF（无 libseccomp 依赖），供 bwrap `--seccomp <fd>`。
- **关键逻辑**：手写 `struct sock_filter` 序列——校验 arch（x86_64=0xC000003E / riscv64=0xC00000F3）→ 逐条 JEQ 比对黑名单 syscall 号 → 命中返回 `SECCOMP_RET_ERRNO|EPERM`，其余 ALLOW，arch 不符 KILL。
- **黑名单**：reboot/swapon/swapoff/kexec*/init_module/finit_module/delete_module/mount/umount2/pivot_root/perf_event_open。
- **要点**：x86_64/riscv64 各有 syscall 号表；seccomp 随 fork-exec **被子进程继承**（整进程沙箱兜底的基础）。

### 6.7 Network Policy（network_policy.py，FR-SEC-07/SBX-03）

- **职责**：声明域名 → iptables 白名单规则文本（默认 DROP）+ 可选实下发。
- **关键逻辑**：DNS 解析域名→IP，生成 `-A OUTPUT -d <ip> -j ACCEPT` + 默认 DROP + LOG；写 `netfilter.rules`。`apply_rules` 在有 iptables 且权限时实下发，否则降级（worker 无 iptables → 仅产物）。
- **要点**：learning 模式仅 LOG 不 DROP；SEC-07 强制需目标环境有 netfilter。

### 6.8 Key Vault（key_vault.py，FR-AI-21）

- **职责**：无 TEE 的软件密钥库。master.key 派生 Fernet 加密各 agent 的 `.vault`。
- **要点**：明文不落盘；读取经 engine `get_secret` 的 CheckPermission(`secret.read`) 门控；TEE 为未来硬件增强。

### 6.9 Sandbox（sandbox.py，FR-SBX-01~07）

- **职责**：bwrap 参数构造 + cgroup + 启动 + Fail-Closed。生产归 agent-runtimed，此处提供可复用/直测实现。
- **SandboxSpec**：agent_binary / rw_dir / seccomp_path / ro_binds / ro_binds_map / rw_binds / home_dir / unshare_net / memory_max / cpu_quota。
- **关键逻辑（build_bwrap_argv）**：`--unshare-user/pid/ipc/uts`(+可选 net) + `--cap-drop ALL` + `--die-with-parent` + merged-usr 感知的 `_base_fs_args`（/bin、/lib 为符号链接时用 `--symlink` 重建）+ tmpfs/dev/proc + mandatory deny paths（`/etc/shadow` 等 ro-bind /dev/null）+ `--seccomp <fd>`。
- **launch**：`interactive=True` 继承 tty（供 TUI）；否则捕获输出带 timeout。Fail-Closed：声明 seccomp 却缺文件 → 拒绝启动。
- **要点**：worker overlayfs 不可用 → 纯 bind-mount；开发模式 cgroup 无权限时降级，设置 `BIANBU_SECURITY_REQUIRE_CGROUP=1` 时强制拒绝启动（生产由 runtimed/systemd 提供权限）。网络规则文件存在不代表内核已强制，查询 `enforcement` 字段确认后端。

### 6.10 SecurityEngine（engine.py）与 Service（service.py）

- **engine**：组合全部子模块的业务门面，每个 D-Bus 方法对应一个 engine 方法；统一在此写审计（Fail-Closed）+ 发 SecurityAlert。`install_package` = verify + register + record_manifest + set_budget。
- **service**：dbus-python + GLib 主循环导出接口，把 D-Bus 调用转发给 engine，并接线信号发射器（alert_emit/confirm_emit）。`main(--session|--system)` 选总线。

---

## 7. 关键业务时序

### 7.1 安装 Agent（VerifyManifest → RegisterCapabilities）

```
调用方          service         engine          manifest      registry      audit
  │ install pkg   │               │               │             │            │
  ├──────────────►│ VerifyManifest│               │             │            │
  │               ├──────────────►│ verify_manifest              │            │
  │               │               ├──────────────►│ 解析+验签    │            │
  │               │               │◄──────────────┤ (valid,perms)│            │
  │◄──────────────┤ (valid,perms) │               │             │            │
  │ 用户确认权限   │               │               │             │            │
  ├──────────────►│ RegisterCaps  │               │             │            │
  │               ├──────────────►│ register_capabilities ──────►│ 写 granted=1│
  │               │               ├─ record_manifest ───────────►│            │
  │               │               ├─ set_budget                  │            │
  │               │               ├─ audit_log(install) ─────────────────────►│
  │◄──────────────┤ ok=true       │               │             │            │
```

### 7.2 运行时判权 + 确认门禁（CheckPermission → RequestConfirm）

```
Agent/插件      service        engine/registry     confirm         GUI
  │ CheckPermission(cap,scope)   │                  │              │
  ├───────────────►│────────────►│ check_permission │              │
  │                │             │ (算法 §6.2)      │              │
  │◄───────────────┤ decision    │                  │              │
  │  ALLOW→执行  DENY→阻断  CONFIRM↓                 │              │
  │ RequestConfirm(cap,detail)   │                  │              │
  ├───────────────►│────────────►│ request_confirm ►│ 注册等待     │
  │                │             │                  ├─ emit ConfirmRequest ─►│
  │                │             │                  │              │ 用户操作 │
  │                │             │                  │◄─ RespondConfirm ──────┤
  │                │             │  L4? 二次确认再来一轮            │
  │◄───────────────┤ approved    │◄─ 写 session_trust(once) + audit │
  │  approved→执行 / 否→阻断      │                  │              │
```

### 7.3 Agent 启动与沙箱（BuildSandboxPolicy → bwrap，≤200ms）

```
runtimed/启动器      securityd            sandbox/bwrap        kernel
  │ BuildSandboxPolicy │                    │                   │
  ├───────────────────►│ seccomp_builder    │                   │
  │                    ├─ 生成 seccomp.bpf   │                   │
  │                    ├─ network_policy 生成 netfilter.rules     │
  │◄───────────────────┤ (seccomp_path, rules)                   │
  │  [并行] cgroup 设限 │                    │                   │
  │  下发 netfilter（有 iptables 时）        │                   │
  │  open(seccomp_path)→fd                   │                   │
  ├─────────────────────────────────────────►│ execve bwrap     │
  │                    │                    ├─ unshare+cap-drop ►│
  │                    │                    ├─ --seccomp fd ────►│ 加载 BPF
  │                    │                    ├─ execve agent     │
  │  任一步失败 → 回滚 + SecurityAlert + 拒绝启动（Fail-Closed）  │
```

### 7.4 Token 超限 → 暂停

```
Agent → MeterTokens(tokens) → engine.meter_tokens → token_meter.meter
  conv_used/day_used += tokens
  超限 → within_limit=False → audit_log(exceed) + SecurityAlert + TokenExceeded 信号
       → Agent Runtime/agent 消费事件并暂停或终止 Agent
```

### 7.5 审计导出与验证

```
ExportAudit(filter,fmt) → 查 audit_record → 写 export（+chain_anchor）
VerifyAuditChain(path)  → 逐条重算 hash 比对 → 篡改任一字段则 intact=false
```

---

## 8. 配置项总表

### 8.1 路径优先级（config.py）

1. `BIANBU_SEC_ROOT` —— 隔离根（测试/沙箱），所有路径收敛其下（最高优先）。
2. 单项 env `BIANBU_ETC` / `BIANBU_RUN` / `BIANBU_LOG`。
3. **root（euid==0）** → 系统路径 `/etc/bianbu`、`/run/bianbu`、`/var/log/bianbu`（生产 daemon）。
4. **非 root** → `$XDG_DATA_HOME/bianbu-securityd`（默认 `~/.local/share/bianbu-securityd`）。

### 8.2 参数

| 参数 | 默认 | 说明 |
|------|------|------|
| DEFAULT_LIMIT_PER_CONVERSATION | 100000 | 单次对话 token 上限 |
| DEFAULT_LIMIT_PER_DAY | 500000 | 单日 token 上限（00:00 重置） |
| CONFIRM_TIMEOUT_SEC | 30 | 确认门禁超时（`BIANBU_CONFIRM_TIMEOUT`） |
| AUDIT_SEGMENT_MAX_BYTES | 64MB | 审计按大小分段 |
| SECCOMP_DENYLIST | reboot/mount/… | 危险 syscall 黑名单 |
| DEFAULT_MEMORY_MAX / CPU_QUOTA / IO_WEIGHT | 2G / 100% / 100 | cgroup 默认 |

### 8.3 接入层环境变量（hermes 插件/启动器）

| 变量 | 默认 | 作用 |
|------|------|------|
| BIANBU_HERMES_AGENT_ID | com.hermes.agent | 会话对应 Agent id |
| BIANBU_SEC_APPROVAL_MODE | securityd | 审批仲裁三态 |
| BIANBU_SECURITY_FAIL_OPEN | 0 | securityd 不可达：0 拦 / 1 放行 |
| BIANBU_SEC_SESSION | 未设 | 1=会话总线（测试） |
| BIANBU_SECURITYD_HOME | — | 实现根，供插件/启动器 import |
| HERMES_YOLO_MODE | — | 启动器按 approval 模式自动注入 |

---

## 9. 错误处理与安全默认

- **Fail-Closed**：审计写失败 → 阻断相关操作 + SecurityAlert；沙箱创建失败 → 拒绝启动，绝不降级为无沙箱运行（FR-SBX-07）；securityd 不可达（插件侧）→ 默认拦截（可配 FAIL_OPEN）。
- **最小权限**：cap-drop ALL 按需 add；seccomp 命中黑名单 EPERM；网络默认 DROP。
- **权限最小可见**：沙箱只 bind /usr + 显式声明目录；mandatory deny paths 覆盖 /etc/shadow 等。
- **日志脱敏**：审计不落 token/密钥明文；secret 仅经 Key Vault 门控读取。
- **并发**：Registry SQLite WAL + RLock；审计单写线程串行；Token 计量原子。

---

## 10. 测试体系

| 层 | 目录/文件 | 覆盖 | 依赖 |
|----|----------|------|------|
| 单元 | `tests/unit/` | manifest/registry/audit/token/seccomp/approval_mode（纯逻辑） | 无 |
| 集成 | `tests/integration/test_sandbox_manager.py` | bwrap seccomp 拦截/deny-path/cap-drop/fail-closed | bwrap+userns |
| 集成 | `tests/integration/test_dbus_security.py` | 真实 D-Bus 全链路（私有 session bus 自启 securityd） | dbus+gi |
| 集成 | `hermes_plugin_demo.py` / `hermes_confirm_demo.py` | 插件判权/审计 + 确认门禁全路径（详细日志） | dbus |
| e2e | `tests/e2e/` | hermes 接入端到端（BIANBU_E2E=1） | dbus |
| 冒烟 | `tests/smoke_test.sh` | 6 阶段：bwrap/fixtures/D-Bus/确认/插件/沙箱 | 全 |

```bash
export PYTHONPATH=$PWD:$PWD/client:$PWD/hermes_plugin BIANBU_SECURITYD_HOME=$PWD
python3 tests/fixtures/make_fixtures.py
python3 -m pytest tests/unit tests/integration -q       # worker: 40 passed
BIANBU_E2E=1 BIANBU_SEC_SESSION=1 dbus-run-session -- python3 -m pytest tests/e2e -q
bash tests/smoke_test.sh                                 # 6 阶段 ALL PASS
```
> 本地 x86_64 若 AppArmor 限制非特权 userns，3 个 bwrap 沙箱用例自动 skip，须在 worker 跑全。
> 详细手动验证见 `impl/bianbu-securityd/VERIFY.md`。

---

## 11. 部署与运行

### 11.1 生产（系统总线，root）

```bash
# 安装 D-Bus 策略与 systemd 单元
install data/io.bianbu.Security.conf /etc/dbus-1/system.d/
install data/bianbu-securityd.service /etc/systemd/system/
systemctl enable --now bianbu-securityd     # 信任根，最先启动
```
启动顺序：securityd → aihald → agent-runtimed → 其余服务 → GUI/BiBit。

### 11.2 开发/测试（会话总线，非 root）

```bash
export PYTHONPATH=$PWD:$PWD/client BIANBU_SEC_ROOT=/tmp/bnsec
python3 -m securityd.service --session      # 会话总线
python3 cli/bncli.py install tests/fixtures/test-security-agent
python3 cli/bncli.py capability list com.bianbu.test-security-agent
```

### 11.3 worker 部署（10.0.90.243）

见 `VERIFY.md` §1；paramiko/sshpass 传包，venv `--system-site-packages` 装 pytest。
merged-usr + 无 iptables/nft + 无 TEE 的适配已在实现中处理。

---

## 12. 术语表与追溯

### 12.1 术语

| 术语 | 含义 |
|------|------|
| Capability | Agent 声明的能力（如 file.write），判权最小单位 |
| 权限域 Domain | execute/resource/data/system，能力语义分组 |
| 风险等级 L1-L4 | 决定确认强度；L4 恒二次确认 |
| 三级信任 | always / once_per_session / trusted |
| 哈希链 | SHA-256 prev_hash 串联的防篡改审计 |
| merged-usr | /bin、/lib 为 /usr 下的符号链接（worker K3） |
| Fail-Closed | 失败时拒绝而非放行 |

### 12.2 文档链

- 方案：`BNAgent-Security-solution.md`（BN-SEC-SOL-001）
- hermes 接入：`BNAgent-Hermes-Integration.md`（BN-SEC-HERMES-001）
- 本文：开发指南（BN-SEC-DEV-001）
- 手动验证：`impl/bianbu-securityd/VERIFY.md`
- 上游需求：PRD §5.1/§8、SRS FR-SEC/SBX、HLD §3.1、API §2、LLD §1/§11

### 12.3 实现状态

- 已实现并 worker 实测：SEC-01/02/03/05/06 + SBX 沙箱 + Key Vault + hermes 接入（插件+进程沙箱+审批开关）。
- 待接/边界：SEC-04 Token 经 hermes 钩子接入（post_llm_call 无触发点）；SEC-07 白名单强制需 netfilter 环境；once_per_session 跨 D-Bus 缓存复用（需 session_id 入参）。

---
*BN-SEC-DEV-001 V1.0 · 基于 impl/bianbu-securityd 实现 + worker 10.0.90.243 实测。内容由 AI 辅助生成。*
