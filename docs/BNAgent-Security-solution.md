# BNAgent-Security-solution — Bianbu Next AgentOS 安全子系统设计方案

| 项目 | 内容 |
|------|------|
| 文档编号 | BN-SEC-SOL-001 |
| 版本 | V0.1-draft |
| 来源 PRD | Bianbu_Next_PRD_V0.9 §5.1 §5.3.7 §8 |
| 来源 SRS | BN-SRS-001 §3.1（FR-SEC-*/FR-SBX-*） |
| 来源 HLD | BN-HLD-001 §3.1 §3.3 §4 §9 |
| 来源 API | BN-API-001 §2 |
| 来源 LLD | BN-LLD-001 §1 §3 §8 §11 |
| 日期 | 2026-07-14 |
| 状态 | 草稿 |

---

## 目录

1. [概述](#1-概述)
2. [总体方案](#2-总体方案)
3. [详细架构设计](#3-详细架构设计)
4. [数据模型](#4-数据模型)
5. [D-Bus API 契约](#5-d-bus-api-契约)
6. [业务流程](#6-业务流程)
7. [hermes Agent 对接设计](#7-hermes-agent-对接设计)
8. [测试用例](#8-测试用例)
9. [开发任务清单](#9-开发任务清单)

---

## 1 概述

### 1.1 背景与目标

Bianbu Next 是面向 RISC-V + AI 的 Agent 原生 OS 底座。Agent 安全子系统（`bianbu-securityd`）是整个平台的信任根，负责：

- **可授权**：每个 Agent 的能力由 Manifest 声明，用户显式授权后才能执行；
- **可审计**：所有受控操作写入防篡改哈希链日志，可导出、可离线验证；
- **可追溯**：操作链路从权限校验到结果记账全程留痕；
- **可隔离**：每个 Agent 运行在 bubblewrap（bwrap）+ seccomp-bpf + cgroup v2 沙箱中，故障爆炸半径受控。

目标：构建"敢用、能用、管得住"的 Agent 安全底座，并通过对接 hermes agent 完成端到端功能验证。

### 1.2 设计依据

| 文档 | 章节 | 关键内容 |
|------|------|----------|
| PRD V0.9 | §5.1 | SEC-01~07 功能需求、权限两维模型、token_budget 规格 |
| PRD V0.9 | §5.3.7 | SBX-01~07 轻量沙箱需求 |
| PRD V0.9 | §8 | 多 Agent 隔离层次模型（Level 1~4） |
| SRS BN-001 | §3.1 | FR-SEC-*/FR-SBX-* 带验收标准的功能需求 |
| HLD BN-001 | §3.1/§9 | securityd 组件设计 + worker 机器校准（无 TEE，bwrap 沙箱方案已在 K3 验证） |
| API BN-001 | §2 | io.bianbu.Security D-Bus 接口完整定义 |
| LLD BN-001 | §1/§11 | Capability Registry SQLite、Audit Chain、seccomp 策略、Token Meter 实现 |

### 1.3 范围与边界

**本方案覆盖：**
- `bianbu-securityd` 服务全部六个子模块；
- Phase 1 进程级沙箱（Level 1：**bwrap** + seccomp-bpf + cgroup v2 + cap drop + netfilter，已在 worker K3 验证）；
- hermes agent 对接适配器（D-Bus 调用封装 + 测试 Agent）；
- 完整测试用例与自动化脚本框架。

**本方案不覆盖（Phase 2+ 或超出范围）：**
- Level 2 命名空间隔离（FR-SBX-08，[TBD-9]）；
- TEE 密钥存储（[TBD-17]，当前 K3 无 TEE，降级为软件方案）；
- GUI 权限管理面板（FR-SET-15~19，属于前端工作项）；
- bianbu-agentforce / hermes-agent 的代码复用（仅作环境参考）。

---

## 2 总体方案

### 2.1 设计原则

| 原则 | 说明 |
|------|------|
| **安全内生** | 安全不是旁路，权限校验/沙箱/审计贯穿每条调用链 |
| **最小权限** | seccomp 白名单优先；cgroup、netfilter 默认拒绝 |
| **Fail-Closed** | 沙箱创建失败 → 拒绝启动；审计写入失败 → 阻断相关操作 |
| **可测量验收** | 所有验收标准以百分比/延迟/token 数量等可量化指标表达 |
| **轻量可落地** | Phase 1 无需 KVM/容器，纯 Linux 原生原语，冷启动 ≤ 200 ms |

### 2.2 技术选型

| 需求域 | 选型 | 理由 |
|--------|------|------|
| 文件系统隔离 | **bubblewrap (bwrap)**：非特权沙箱，内置 namespace + bind-mount + mandatory deny paths | 已在 worker K3 验证；无需 root/CAP_SYS_ADMIN；overlayfs 不可用亦无影响 |
| 系统调用过滤 | **seccomp-bpf**（libseccomp 生成 BPF） | worker 已确认 seccomp=yes |
| 资源配额 | **cgroup v2** | worker 已确认 cgroup2=yes |
| 网络隔离 | **netfilter/iptables 白名单，默认 DROP** | 无需 NET namespace（Phase 2 增强） |
| 权限持久化 | **SQLite WAL 模式** | 轻量，无外部依赖，嵌入式可用 |
| 审计防篡改 | **SHA-256 哈希链**（非区块链） | 轻量，可离线验证，满足 NFR-S-03 |
| 密钥存储 | **gnome-keyring**（用户级）/ **age 加密文件**（服务级）| K3 无 TEE；securityd 代理读取 |
| 沙箱入口 | **bubblewrap (bwrap) + seccomp-bpf + mandatory deny paths** | 用户已在 worker 验证 |
| IPC | **D-Bus 系统总线，`io.bianbu.Security`** | 与其他 Bianbu 服务统一 |

### 2.3 总体架构

```
┌──────────────────────────────────────────────────────────────────────────┐
│                         调用方层（Caller Layer）                          │
│  hermes-agent   bianbu-sdk   CLI (bncli)   BiBit GUI   其他第三方 Agent   │
└────────────────────────────┬─────────────────────────────────────────────┘
                             │ D-Bus  io.bianbu.Security
┌────────────────────────────▼─────────────────────────────────────────────┐
│                    bianbu-securityd（信任根守护进程）                      │
│  ┌─────────────────┐  ┌──────────────────┐  ┌────────────────────────┐  │
│  │ Capability      │  │ Confirm          │  │ Audit Chain Engine     │  │
│  │ Registry        │  │ Gatekeeper       │  │（SHA-256 哈希链）       │  │
│  │ (SQLite WAL)    │  │（弹窗门禁）        │  │ FR-SEC-06             │  │
│  │ FR-SEC-01/02    │  │ FR-SEC-03        │  └────────────────────────┘  │
│  └─────────────────┘  └──────────────────┘                              │
│  ┌─────────────────┐  ┌──────────────────┐  ┌────────────────────────┐  │
│  │ Syscall Filter  │  │ Network Policy   │  │ Token Budget Meter     │  │
│  │ Builder         │  │（netfilter 白名单）│  │（内存计数器）           │  │
│  │（libseccomp BPF）│  │ FR-SEC-07        │  │ FR-SEC-04             │  │
│  │ FR-SEC-05/SBX-04│  │ SBX-03           │  └────────────────────────┘  │
│  └─────────────────┘  └──────────────────┘                              │
│  ┌─────────────────────────────────────────────────────────────────────┐ │
│  │ Key Vault（gnome-keyring / age 加密文件 + root-only 权限）            │ │
│  │ FR-AI-21  [TBD-17 已解：软件方案]                                    │ │
│  └─────────────────────────────────────────────────────────────────────┘ │
└────────────────────────────┬─────────────────────────────────────────────┘
                             │  BuildSandboxPolicy（seccomp_path, netfilter_rules）
┌────────────────────────────▼─────────────────────────────────────────────┐
│               bianbu-agent-runtimed（沙箱管理器）                         │
│        bwrap + cgroup v2 + cap drop + seccomp-bpf + netfilter             │
│   FR-SBX-01~07    冷启动 ≤ 200ms                                         │
└──────────────────────────────────────────────────────────────────────────┘
                             │
                ┌────────────▼────────────┐
                │    Agent 沙箱进程        │
                │  ~/.local/share/         │
                │  bianbu-agents/<id>/     │
                └─────────────────────────┘
```

### 2.4 服务启动顺序

```
securityd（信任根，最先启动）
  → aihald
  → agent-runtimed
  → memoryd / skilld / intentd / calendard / indexerd
  → GUI / BiBit
```

---

## 3 详细架构设计

### 3.1 Capability Registry（能力注册表）

**职责**：权限声明/授权持久化，实现两维模型（域 × 风险等级 L1-L4）+ 三级信任策略。

**权限两维模型：**

| 权限域（Domain） | 说明 | 示例能力标识 |
|-----------------|------|-------------|
| `execute` | 代表用户执行操作 | `mail.send`、`file.write`、`payment.create` |
| `resource` | 消耗 token / API 费用 | `llm.cloud_call`、`api.purchase` |
| `data` | 读取用户数据 | `contacts.read`、`docs.read`、`location.read` |
| `system` | 修改系统配置 | `network.config`、`package.install` |

| 风险等级 | 定义 | 典型能力 | 默认确认策略 |
|---------|------|---------|------------|
| L1 只读 | 读取非敏感系统信息 | `proc.list`、`fs.read`（非敏感目录） | `trusted`（安装时一次授权） |
| L2 用户数据 | 访问用户私有数据 | `docs.read`、`contacts.read`、`fs.write` | `once_per_session` |
| L3 系统修改 | 修改系统配置/安装软件 | `network.config`、`package.install` | `always` |
| L4 危险操作 | 不可逆/高破坏性 | `system.shutdown`、`disk.format`、`payment.create` | `always` + 二次确认 |

**约束**：L3/L4 不允许配置为 `trusted`；L4 无论策略如何均强制二次确认。

**三级信任策略：**

| 策略值 | 语义 |
|--------|------|
| `always` | 每次执行弹窗确认 |
| `once_per_session` | 会话内首次确认，之后免确认；会话结束失效 |
| `trusted` | 永久信任，直到用户在 SET-03 撤销（仅 L1/L2 可用） |

### 3.2 Confirm Gatekeeper（确认门禁）

**职责**：拦截 L3/L4 或 `confirm=always` 的操作，向用户弹窗；L4 强制二次确认。

**门禁流转逻辑：**

```
CheckPermission 返回 CONFIRM(1)
  → RequestConfirm(agent_id, capability, detail)
      → 弹窗（通知中心 / D-Bus activation）
      → 用户操作：
          approve  → ALLOW，写 session_cache（once_per_session），AuditLog
          deny     → DENY，AuditLog
      → L4：approve 后再次弹窗二次确认
```

### 3.3 Syscall Filter Builder（系统调用过滤器构造器）

**职责**：为每个 Agent 生成 seccomp-bpf 策略文件，由 agent-runtimed 在 execve 前加载。

**黑名单（默认拒绝的危险系统调用）：**

```
reboot, swapon, swapoff, kexec_load, kexec_file_load,
init_module, finit_module, delete_module,
mount, umount2, pivot_root,
ptrace（非调试场景）,
perf_event_open,
io_uring_setup（可选受限）
```

**生成方式**：libseccomp API → BPF 字节码 → 写入 `/run/bianbu/sandbox/<agent_id>/seccomp.bpf`。

### 3.4 Audit Chain Engine（审计哈希链引擎）

**职责**：将 Agent 所有受控操作写入防篡改哈希链，支持导出与离线验证。

**记录结构：**

```
record = {
  seq:       INT,        # 递增序列号
  ts:        RFC3339,    # 时间戳
  agent_id:  TEXT,
  op_type:   TEXT,       # check_permission / exec_tool / audit_log / token_meter 等
  target:    TEXT,       # 操作目标（文件路径 / 域名 / 能力名）
  result:    TEXT,       # allow / deny / confirm / exceed
  prev_hash: SHA256,     # 前一条记录的哈希
  hash:      SHA256(seq ‖ ts ‖ agent_id ‖ op_type ‖ target ‖ result ‖ prev_hash)
}
```

**写入保证**：单一写线程序列化，防止并发破链；写入失败 → Fail-Closed，阻断相关操作并触发 SecurityAlert。

**存储**：`/var/log/bianbu/audit/<YYYYMM>.db`（SQLite），按月分段；段间以段尾哈希链接。

### 3.5 Network Policy（网络白名单）

**职责**：将 Agent Manifest 中声明的域名编译为 netfilter 规则，默认 DROP 未声明流量。

**规则下发流程：**
```
BuildSandboxPolicy → 解析 Manifest 域名列表
  → DNS 解析为 IP 集合
  → iptables -I OUTPUT -d <IP> -j ACCEPT（白名单）
  → iptables -A OUTPUT -j DROP（默认拒绝）
  → 规则写入 /run/bianbu/sandbox/<agent_id>/netfilter.rules
```

**学习模式（SET-18）**：观察期内记录实际出站域名，生成建议白名单。

### 3.6 Token Budget Meter（Token 配额计量器）

**职责**：按 token_budget 规格计量 Agent token 用量，超限执行 pause_and_notify：securityd 返回超限结果、写审计并发出事件；Agent Runtime/agent 消费事件后负责暂停或终止 Agent。securityd 不直接停止 Agent 服务。

**内存模型：**
```
per_agent_counter = {
  agent_id → {
    conv_used:  INT,   # 本次对话累计 token（含 prompt+completion）
    day_used:   INT,   # 当日累计 token
    day_epoch:  DATE   # 重置日期（本地时区，00:00 重置）
  }
}
```

**超限处理**：`conv_used > limit_per_conversation` 或 `day_used > limit_per_day` → securityd 写审计并发送 `TokenExceeded`/`SecurityAlert` → Agent Runtime/agent 消费事件并暂停或终止 Agent → 通知用户；当前 `MeterTokens` 请求返回 `within_limit=false`，阻止本次继续消耗。

### 3.7 Sandbox Manager（沙箱管理器）

**位置**：bianbu-agent-runtimed（非 securityd），通过 `BuildSandboxPolicy` 获取策略后自行编排。

**选型说明**：Phase 1 采用 **bubblewrap (bwrap)** 作为沙箱入口，而非手动 `chroot + mount --bind + clone(ns)`。原因：①bwrap 非特权即可创建文件视图与 namespace，规避 K3 上 overlayfs 需 CAP_SYS_ADMIN 的限制；②`--ro-bind /dev/null <path>` 直接实现 mandatory deny paths；③`--seccomp <fd>`、`--cap-drop all`、`--die-with-parent` 将 seccomp 加载、能力裁剪、生命周期绑定收敛到单次 exec，减少手动实现的出错面；④Flatpak 生产验证，方案已在 worker K3 实测通过。cgroup v2 与 netfilter 白名单仍由 runtimed 在 host-ns 侧配置（bwrap 不管理这两者）。

**Phase 1 沙箱构成（bwrap 方案，已在 worker K3 验证）：**

| 隔离维度 | 实现方式 | 备注 |
|---------|---------|------|
| 文件系统隔离 | **bwrap**（`--ro-bind`/`--bind`/`--tmpfs`/`--dev`/`--proc`）+ mandatory deny paths | 非特权可用，无需 root/CAP_SYS_ADMIN；overlayfs 不可用亦无影响 |
| 进程/IPC/UTS 隔离 | bwrap `--unshare-pid --unshare-ipc --unshare-uts` | bwrap 内置 namespace unshare |
| 网络隔离 | bwrap `--unshare-net` + netfilter 白名单（veth 或 host-ns 代理） | 与 SEC-07 同源策略 |
| 资源配额 | cgroup v2（CPUQuota=100%，MemoryMax=2GB，IOWeight=100） | K3 cgroup2 已确认可用；bwrap 不管理 cgroup，外部设置 |
| 系统调用过滤 | bwrap `--seccomp <fd>`（libseccomp 生成 BPF，通过 fd 传入） | K3 seccomp 已确认可用；比 prctl 后置加载更安全 |
| 能力裁剪 | bwrap `--cap-drop all` + 按需 `--cap-add` | 最小权限，默认全部 drop |
| 父子生命周期 | bwrap `--die-with-parent` | 父进程（runtimed）退出，沙箱自动清理 |

**bwrap 调用示例：**

```bash
# securityd.BuildSandboxPolicy 生成 seccomp BPF → fd
exec 9< /run/bianbu/sandbox/<agent_id>/seccomp.bpf

bwrap \
  --ro-bind /usr        /usr          \
  --ro-bind /lib        /lib          \
  --ro-bind /lib64      /lib64        \
  --ro-bind /etc/ld.so.cache /etc/ld.so.cache \
  --bind    ~/.local/share/bianbu-agents/<id>/rw  /home/agent \
  --tmpfs   /tmp                       \
  --dev     /dev                       \
  --proc    /proc                      \
  --ro-bind /dev/null   /etc/shadow    \  # mandatory deny path
  --ro-bind /dev/null   /etc/sudoers   \  # mandatory deny path
  --unshare-pid                         \
  --unshare-ipc                         \
  --unshare-uts                         \
  --unshare-net                         \  # Phase 1：网络白名单由 netfilter 在 host-ns 控制
  --new-session                         \
  --die-with-parent                     \
  --cap-drop all                        \
  --seccomp 9                           \
  -- <agent_binary> [args]

exec 9>&-
```

**冷启动关键路径（目标 ≤ 200 ms）：**

```
Start(agent_id):
  1. securityd.BuildSandboxPolicy → seccomp_path, netfilter_rules    [可并行预取]
     生成 seccomp BPF 文件，打开为 fd
  2. 应用 cgroup v2（bwrap 启动前，将 bwrap 进程加入对应 slice）：
     /sys/fs/cgroup/bianbu-<id>/: CPUQuota / MemoryMax / IOWeight
  3. 下发 netfilter 白名单（host-ns iptables，覆盖 Agent 出站流量）
  4. 构造 bwrap 参数：
     --ro-bind 只读依赖  --bind Agent私有读写目录
     --tmpfs /tmp  --dev /dev  --proc /proc
     mandatory deny paths（/etc/shadow 等）
     --unshare-pid/ipc/uts/net
     --die-with-parent  --cap-drop all  --seccomp <fd>
  5. execve bwrap → 沙箱内 execve <agent_binary>
  6. 注入 SDK runtime → on_start → FSM=RUNNING → AuditLog
  ✗ 任一步失败：回滚 cgroup/iptables，拒绝启动，触发 SecurityAlert（Fail-Closed）
```

---

---

## 4 数据模型

### 4.1 Capability Registry（SQLite）

```sql
-- /etc/bianbu/capabilities.db  (WAL 模式)
CREATE TABLE capability (
  agent_id   TEXT NOT NULL,
  capability TEXT NOT NULL,    -- e.g. "file.write", "mail.send"
  domain     TEXT NOT NULL CHECK(domain IN ('execute','resource','data','system')),
  risk_level TEXT NOT NULL CHECK(risk_level IN ('L1','L2','L3','L4')),
  confirm    TEXT NOT NULL CHECK(confirm IN ('always','once_per_session','trusted')),
  scope      TEXT,             -- 可选，文件类能力的目录粒度，e.g. "~/Documents"
  granted    INTEGER NOT NULL DEFAULT 0,  -- 0=待授权, 1=已授权, -1=已撤销
  PRIMARY KEY (agent_id, capability, scope)
);
-- 约束：risk_level IN ('L3','L4') → confirm != 'trusted'
-- 由 securityd 应用层强制，不写 CHECK 避免 SQLite 跨列限制

CREATE TABLE session_trust (
  session_id TEXT NOT NULL,
  agent_id   TEXT NOT NULL,
  capability TEXT NOT NULL,
  granted_at TEXT NOT NULL,    -- RFC3339
  PRIMARY KEY (session_id, agent_id, capability)
);

CREATE TABLE agent_manifest (
  agent_id    TEXT PRIMARY KEY,
  version     TEXT NOT NULL,
  name        TEXT NOT NULL,
  signature   TEXT NOT NULL,   -- "ed25519:xxxx"
  manifest_raw TEXT NOT NULL,  -- 原始 TOML
  installed_at TEXT NOT NULL,
  status      TEXT NOT NULL CHECK(status IN ('active','suspended','revoked'))
);
```

### 4.2 Token Budget 持久化

```sql
-- /etc/bianbu/token_budget.db
CREATE TABLE token_budget_config (
  agent_id              TEXT PRIMARY KEY,
  unit                  TEXT NOT NULL DEFAULT 'token',
  limit_per_conversation INTEGER NOT NULL DEFAULT 100000,
  limit_per_day         INTEGER NOT NULL DEFAULT 500000,
  on_exceed             TEXT NOT NULL DEFAULT 'pause_and_notify'
);

CREATE TABLE token_budget_state (
  agent_id   TEXT NOT NULL,
  date_epoch TEXT NOT NULL,    -- YYYY-MM-DD 本地时区
  day_used   INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (agent_id, date_epoch)
);
-- conv_used 保存在内存，会话结束写回（或写审计日志）
```

### 4.3 Audit Chain 记录（SQLite）

```sql
-- /var/log/bianbu/audit/YYYYMM.db
CREATE TABLE audit_record (
  seq        INTEGER PRIMARY KEY AUTOINCREMENT,
  ts         TEXT NOT NULL,           -- RFC3339 with ms
  agent_id   TEXT NOT NULL,
  op_type    TEXT NOT NULL,           -- check_permission / exec_tool / token_meter /
                                       -- sandbox_start / sandbox_fail / network_block 等
  target     TEXT NOT NULL,           -- 操作目标（文件路径/域名/能力名）
  result     TEXT NOT NULL,           -- allow / deny / confirm_pending / confirm_approved /
                                       -- confirm_denied / exceed / tampering_detected 等
  prev_hash  TEXT NOT NULL,           -- 前一条记录的 SHA-256（首条为 "GENESIS"）
  hash       TEXT NOT NULL            -- SHA-256(seq||ts||agent_id||op_type||target||result||prev_hash)
);

CREATE TABLE audit_segment_meta (
  month        TEXT PRIMARY KEY,       -- YYYYMM
  tail_hash    TEXT NOT NULL,          -- 本月最后一条记录的 hash
  next_segment TEXT                    -- 下月 YYYYMM（链接段）
);
```

### 4.4 Manifest 格式（TOML）

```toml
[agent]
id        = "com.bianbu.test-security-agent"
version   = "1.0.0"
name      = "Security Test Agent"
signature = "ed25519:xxxx"

[permissions]
# 执行权（L3，always 确认）
execute_mail_send   = { domain = "execute", risk_level = "L3", confirm = "always" }
# 执行权（L2，会话内信任）
execute_file_write  = { domain = "execute", risk_level = "L2", confirm = "once_per_session",
                         scope = "~/Documents/test" }
# 数据访问（L2）
read_documents      = { domain = "data",    risk_level = "L2", confirm = "once_per_session",
                         scope = "~/Documents" }
# 系统只读（L1，永久信任）
read_proc_list      = { domain = "data",    risk_level = "L1", confirm = "trusted" }
# 危险操作（L4，always + 二次确认）
payment_create      = { domain = "execute", risk_level = "L4", confirm = "always" }

[permissions.token_budget]
unit                    = "token"
limit_per_conversation  = 100000
limit_per_day           = 500000
on_exceed               = "pause_and_notify"

[permissions.network]
allowed_domains = ["api.bianbu.io", "models.bianbu.io"]
```

### 4.5 Permission 通用数据结构（D-Bus 传输格式）

```jsonc
// aa{sv} 中每个元素
{
  "capability":  "file.write",              // string
  "domain":      "execute",                 // execute|resource|data|system
  "risk_level":  "L2",                      // L1|L2|L3|L4
  "confirm":     "once_per_session",        // always|once_per_session|trusted
  "scope":       "~/Documents/test"         // 可选
}
// 约束：risk_level ∈ {L3,L4} → confirm ≠ "trusted"；L4 强制二次确认
```

---

## 5 D-Bus API 契约

接口名：`io.bianbu.Security`
对象路径：`/io/bianbu/Security`
所属服务：`bianbu-securityd`

### 5.1 方法列表

| 方法 | 入参 | 返回 | 说明 | FR |
|------|------|------|------|-----|
| `VerifyManifest` | `s agent_pkg_path` | `(b valid, s reason, aa{sv} perms)` | 校验 ed25519 签名，解析权限声明 | FR-SEC-01 |
| `RegisterCapabilities` | `s agent_id, aa{sv} perms` | `b ok` | 写入 Capability Registry | FR-SEC-02 |
| `CheckPermission` | `s agent_id, s capability, s scope` | `i decision` | 0=允许, 1=需确认, 2=拒绝 | FR-SEC-02/03 |
| `RequestConfirm` | `s agent_id, s capability, s detail` | `b approved` | 触发门禁弹窗（异步等待用户操作，L4 二次确认） | FR-SEC-03 |
| `RespondConfirm` | `s request_id, b approved` | `b ok` | GUI/确认前端回传用户决定，唤醒等待中的 RequestConfirm | FR-SEC-03 |
| `RevokePermission` | `s agent_id, s capability` | `b ok` | 撤销权限（L3/L4 二次确认） | FR-SEC-02 |
| `BuildSandboxPolicy` | `s agent_id` | `(s seccomp_path, s netfilter_rules)` | 生成 seccomp BPF + netfilter 策略 | FR-SBX-03/04/05 |
| `MeterTokens` | `s agent_id, x tokens, s scope` | `(b within_limit, x remaining)` | 计量 + 超限判定；scope=conv/day | FR-SEC-04 |
| `AuditLog` | `s agent_id, s op_type, s target, s result` | `x seq` | 写审计链，返回记录序列号 | FR-SEC-06 |
| `ExportAudit` | `s filter_json, s format` | `s export_path` | 导出审计日志（JSON/CSV + 哈希链锚） | FR-SEC-06 |
| `VerifyAuditChain` | `s export_path` | `b intact` | 重算哈希链，验证完整性 | FR-SEC-06 |
| `SetNetworkPolicy` | `s agent_id, as domains, s mode` | `b ok` | 下发白名单；mode=whitelist/learning | FR-SEC-07 |
| `GetCapabilities` | `s agent_id` | `aa{sv} perms` | 查询 Agent 已注册权限（CLI/GUI 用） | FR-SEC-02 |
| `SuspendAgent` | `s agent_id, s reason` | `b ok` | 管理面兼容操作/告警记录；不由 securityd 直接停止 Agent，运行时停止动作由 Agent Runtime/agent 执行 | FR-SEC-04 |

### 5.2 错误码

| 错误名 | 含义 |
|--------|------|
| `io.bianbu.Error.PermissionDenied` | Capability 校验未通过（decision=2） |
| `io.bianbu.Error.ConfirmRequired` | 需用户确认（decision=1，门禁待响应） |
| `io.bianbu.Error.QuotaExceeded` | token / 资源超限 |
| `io.bianbu.Error.InvalidManifest` | Manifest 签名无效或格式错误 |
| `io.bianbu.Error.AuditFailure` | 审计写入失败（Fail-Closed） |
| `io.bianbu.Error.SandboxBuildFailed` | 沙箱策略生成失败 |

### 5.3 信号

| 信号名 | 参数 | 触发条件 |
|--------|------|---------|
| `SecurityAlert` | `s agent_id, s type, s detail` | 权限越界/异常高频/未知域名/审计失败 |
| `ConfirmRequest` | `s agent_id, s capability, s detail, s request_id` | RequestConfirm 触发，通知 UI 弹窗 |
| `ConfirmResponse` | `s request_id, b approved` | UI 弹窗用户操作完成 |
| `TokenExceeded` | `s agent_id, s scope, x used, x limit` | token 超限 → 联动 agent-runtimed |

---

## 6 业务流程

### 6.1 Agent 安装与权限声明（FR-SEC-01）

```
开发者/用户
  │  提交 agent.pkg（含 manifest.toml + ed25519 签名）
  ▼
bianbu-sdk / bncli install <pkg>
  │  调用 io.bianbu.Security.VerifyManifest(pkg_path)
  ▼
securityd → Manifest 校验：
  1. 检查 manifest.toml 存在
  2. 验证 ed25519 签名（公钥来自证书链或开发者证书）
  3. 解析 [permissions] 块，验证 domain/risk_level/confirm 合法性
  4. 检查约束：L3/L4 → confirm ≠ trusted
  ✗ 任一失败 → 返回 (valid=false, reason=<具体原因>) → 拒绝安装
  ✓ 全部通过 → 返回 (valid=true, perms=[...])

sdk/cli → 展示权限列表，请求用户确认
  │  用户确认
  ▼
io.bianbu.Security.RegisterCapabilities(agent_id, perms)
  → 写入 capabilities.db（granted=1）
  → AuditLog(agent_id, "install", pkg_path, "success")

安装完成，Agent 可启动
```

**验收标准（FR-SEC-01）**：无 manifest 或签名无效的包被拒绝，返回明确错误原因；三级策略均可按语义正确触发确认流程。

---

### 6.2 Agent 启动与沙箱创建（FR-SBX-01~07，目标 ≤ 200 ms）

```
bncli start <agent_id>  /  BiBit GUI 启动  /  hermes-agent 触发
  │
  ▼
bianbu-agent-runtimed.Start(agent_id)
  │  [并行]
  ├─► io.bianbu.Security.BuildSandboxPolicy(agent_id)
  │     → 读取 capabilities.db 中该 Agent 的网络域名声明
  │     → 生成 seccomp BPF → /run/bianbu/sandbox/<id>/seccomp.bpf
  │     → 生成 netfilter rules → /run/bianbu/sandbox/<id>/netfilter.rules
  │     → 返回 (seccomp_path, netfilter_rules)
  │
  ├─► 应用 cgroup v2（bwrap 启动前完成）
  │     /sys/fs/cgroup/bianbu-<id>/: CPUQuota=100% MemoryMax=2GB IOWeight=100
  │
  ├─► 下发 netfilter 白名单（host-ns，覆盖 Agent 出站流量）
  │     iptables -I OUTPUT（白名单域名 IP）
  │     iptables -A OUTPUT -j DROP（默认拒绝）
  │
  ├─► 打开 seccomp BPF fd
  │     fd = open(seccomp_path, O_RDONLY)
  │
  └─► execve bwrap \
         --ro-bind /usr /usr --ro-bind /lib /lib --ro-bind /lib64 /lib64 \
         --bind   ~/.local/share/bianbu-agents/<id>/rw  /home/agent \
         --tmpfs  /tmp  --dev /dev  --proc /proc \
         --ro-bind /dev/null /etc/shadow \     # mandatory deny
         --ro-bind /dev/null /etc/sudoers \    # mandatory deny
         --unshare-pid --unshare-ipc --unshare-uts --unshare-net \
         --new-session --die-with-parent \
         --cap-drop all \
         --seccomp <fd> \
         -- <agent_binary>

  Agent 进程进入沙箱，注入 SDK runtime
  → on_start 回调
  → FSM = RUNNING
  → io.bianbu.Security.AuditLog(agent_id, "sandbox_start", <root>, "success")

✗ 任一步失败：
  回滚已建资源（终止 bwrap 进程、cgroup 清理、iptables 规则删除；bwrap 私有挂载随进程退出自动释放）
  FSM = FAILED
  io.bianbu.Security.AuditLog(agent_id, "sandbox_start", <root>, "fail:<reason>")
  发送 SecurityAlert(agent_id, "sandbox_create_failed", <reason>)
  拒绝启动，严禁降级为无沙箱运行（FR-SBX-07 Fail-Closed）
```

**验收标准（FR-SBX-06）**：沙箱创建不使冷启动超 200 ms；（FR-SBX-07）失败时 Agent 不启动并记审计。

---

### 6.3 运行时权限校验（FR-SEC-02/03）

```
Agent SDK / Skill 执行工具调用
  │  io.bianbu.Security.CheckPermission(agent_id, capability, scope)
  ▼
securityd → CheckPermission 算法：
  row = lookup(agent_id, capability, best_match_scope(scope))
  if not row or row.granted != 1: return DENY(2)
  if row.risk_level == 'L4':      return CONFIRM(1)  ← 强制二次确认
  match row.confirm:
    'trusted':          return ALLOW(0)
    'once_per_session': 
      if session_cache.has(agent_id, capability): return ALLOW(0)
      else:                                        return CONFIRM(1)
    'always':           return CONFIRM(1)

ALLOW(0) → 继续执行 → AuditLog(... result="allow")
DENY(2)  → 返回 PermissionDenied → AuditLog(... result="deny")
CONFIRM(1) → 进入 6.4 确认门禁流程
```

---

### 6.4 敏感操作确认门禁（FR-SEC-03）

```
CheckPermission 返回 CONFIRM(1)
  │
  ▼
io.bianbu.Security.RequestConfirm(agent_id, capability, detail)
  → 发送信号 ConfirmRequest(agent_id, capability, detail, request_id)
  → UI（通知中心 / GUI 弹窗）展示："Agent [name] 请求执行 [capability]：[detail]"
     选项：[允许] [拒绝] [本次会话信任（仅 L2/L3）]

用户操作：
  允许 →
    if risk_level == L4:
      再次弹窗："【高危操作】确认执行 [capability]？此操作不可逆。" [确认] [取消]
    if 最终确认：
      session_cache.add(agent_id, capability)  // once_per_session 时
      AuditLog(... result="confirm_approved")
      返回 approved=true
  拒绝 →
    AuditLog(... result="confirm_denied")
    返回 approved=false → Agent 操作被阻断

超时（30s 无响应）：
  AuditLog(... result="confirm_timeout")
  返回 approved=false
```

**验收标准（FR-SEC-03）**：未确认时操作被阻断；L4 强制二次确认；超时默认拒绝。

---

### 6.5 Token 配额计量与超限（FR-SEC-04）

```
Agent 每次 LLM 调用完成后：
  │  io.bianbu.Security.MeterTokens(agent_id, token_count, scope="conv")
  ▼
securityd → Token Meter：
  counter = get_or_init(agent_id)
  if counter.day_epoch != today:
    counter.day_used = 0; counter.day_epoch = today  ← 次日 00:00 重置
  counter.conv_used += token_count
  counter.day_used  += token_count

  if counter.conv_used > limit_per_conversation:
    AuditLog(agent_id, "token_meter", "conv", "exceed")
    发送 TokenExceeded(agent_id, "conv", conv_used, limit_per_conversation)
    发送 SecurityAlert(agent_id, "token_exceed", "token_conv_exceed")
    Agent Runtime/agent 消费事件并暂停或终止 Agent
    通知用户（UI 弹窗："Agent [name] 已超出单次对话 token 上限"）
    返回 (within_limit=false, remaining=0)

  if counter.day_used > limit_per_day:
    AuditLog(agent_id, "token_meter", "day", "exceed")
    发送 TokenExceeded(agent_id, "day", day_used, limit_per_day)
    发送 SecurityAlert(agent_id, "token_exceed", "token_day_exceed")
    Agent Runtime/agent 消费事件并暂停或终止 Agent
    通知用户
    返回 (within_limit=false, remaining=0)

  返回 (within_limit=true, remaining=limit - used)
```

**待确认（TBD-2/3）**：①token 计量是否含 prompt+completion 双向；②本地推理是否计入预算池。当前实现按双向计量、本地推理不计入预算池。

---

### 6.6 审计日志写入与导出（FR-SEC-06）

```
写入（任意服务调用）：
  io.bianbu.Security.AuditLog(agent_id, op_type, target, result)
  → 审计专用串行写线程（防并发破链）：
      prev = 查询最后一条记录的 hash（首条 prev_hash="GENESIS"）
      seq  = 自增
      hash = SHA256(seq||ts||agent_id||op_type||target||result||prev_hash)
      INSERT INTO audit_record VALUES(...)
  写入失败 → Fail-Closed：阻断调用方操作 + SecurityAlert

导出：
  bncli audit export --agent <id> --from 2026-07-01 --format json
  → io.bianbu.Security.ExportAudit(filter_json, "json")
  → 读取 audit_record，序列化为 JSON，末尾附 chain_anchor（最后一条 hash）
  → 返回 export_path

完整性验证：
  bncli audit verify <export_path>
  → io.bianbu.Security.VerifyAuditChain(export_path)
  → 逐条重算 hash，对比 prev_hash 链；任何不匹配定位篡改位置
  → 返回 intact=true/false
```

---

### 6.7 网络白名单下发（FR-SEC-07）

```
Agent 启动时（BuildSandboxPolicy 中触发）：
  读取 capabilities.db 中 network.allowed_domains
  → DNS 解析域名 → IP 集合
  → 生成 iptables 规则批次
  → 原子下发（先删旧规则，再写新规则）
  → AuditLog(agent_id, "network_policy", domains, "applied")

运行时动态更新：
  io.bianbu.Security.SetNetworkPolicy(agent_id, domains, "whitelist")
  → 更新 capabilities.db 中网络声明
  → 重新下发 iptables 规则

拦截未授权流量：
  iptables DROP → 内核记录 → securityd 监听 netfilter LOG target
  → AuditLog(agent_id, "network_block", blocked_ip, "deny")
  → SecurityAlert(agent_id, "unauthorized_network", blocked_ip)
```


---

## 7 hermes Agent 对接设计

### 7.1 对接目标

通过 hermes agent 作为外部调用方，验证 `bianbu-securityd` 的全部核心功能：
1. 权限声明 + 安装校验（FR-SEC-01/02）
2. 运行时权限检查 + 确认门禁（FR-SEC-02/03）
3. Token 配额计量（FR-SEC-04）
4. 系统调用拦截（FR-SEC-05，沙箱启动验证）
5. 审计日志写入、导出、验证（FR-SEC-06）
6. 网络白名单策略（FR-SEC-07）

### 7.2 对接方案

hermes agent 通过 **D-Bus 系统总线**调用 `io.bianbu.Security` 接口。对接方式分两层：

```
hermes-agent（Python / TypeScript 进程）
  │
  │  层 A：D-Bus 直调（验证接口语义）
  │  使用 python-dbus / dbus-python 直接调用
  │  io.bianbu.Security 各方法
  │
  │  层 B：SDK 封装调用（验证 SDK 集成）
  │  使用 bianbu-sdk 的 @tool(permission=...) 装饰器
  │  SDK 内部调用 CheckPermission → RequestConfirm
  │
  └──► bianbu-securityd（D-Bus service on system bus）
```

**hermes agent 的角色定位**：测试驱动方，不复用 hermes 内部实现；hermes agent 发起工具调用请求，bianbu-securityd 执行安全策略，hermes agent 观察响应结果与审计记录。

### 7.3 hermes 对接适配器（ACP Adapter）

为 hermes agent 提供安全服务调用封装，文件路径：
`tools/hermes-security-adapter/bianbu_security_client.py`

```python
"""
bianbu_security_client.py
hermes agent 调用 bianbu-securityd 的 D-Bus 客户端封装。
"""
import dbus
import json
from dataclasses import dataclass
from typing import Optional, List

SECURITY_BUS_NAME  = "io.bianbu.Security"
SECURITY_OBJ_PATH  = "/io/bianbu/Security"
SECURITY_INTERFACE = "io.bianbu.Security"


def _get_proxy():
    bus = dbus.SystemBus()
    return bus.get_object(SECURITY_BUS_NAME, SECURITY_OBJ_PATH)


def verify_manifest(agent_pkg_path: str) -> dict:
    """VerifyManifest: 校验 Agent 包签名与权限声明。"""
    proxy = _get_proxy()
    valid, reason, perms = proxy.VerifyManifest(
        agent_pkg_path, dbus_interface=SECURITY_INTERFACE)
    return {"valid": bool(valid), "reason": str(reason), "permissions": list(perms)}


def register_capabilities(agent_id: str, perms: list) -> bool:
    """RegisterCapabilities: 写入能力注册表。"""
    proxy = _get_proxy()
    return bool(proxy.RegisterCapabilities(agent_id, perms,
                                            dbus_interface=SECURITY_INTERFACE))


def check_permission(agent_id: str, capability: str, scope: str = "") -> int:
    """CheckPermission: 0=允许, 1=需确认, 2=拒绝。"""
    proxy = _get_proxy()
    return int(proxy.CheckPermission(agent_id, capability, scope,
                                      dbus_interface=SECURITY_INTERFACE))


def request_confirm(agent_id: str, capability: str, detail: str) -> bool:
    """RequestConfirm: 触发确认门禁弹窗，同步等待用户操作。"""
    proxy = _get_proxy()
    return bool(proxy.RequestConfirm(agent_id, capability, detail,
                                      dbus_interface=SECURITY_INTERFACE))


def meter_tokens(agent_id: str, tokens: int, scope: str = "conv") -> dict:
    """MeterTokens: 计量 token，返回是否在限额内及剩余量。"""
    proxy = _get_proxy()
    within, remaining = proxy.MeterTokens(agent_id, dbus.Int64(tokens), scope,
                                           dbus_interface=SECURITY_INTERFACE)
    return {"within_limit": bool(within), "remaining": int(remaining)}


def audit_log(agent_id: str, op_type: str, target: str, result: str) -> int:
    """AuditLog: 写审计链，返回序列号。"""
    proxy = _get_proxy()
    return int(proxy.AuditLog(agent_id, op_type, target, result,
                               dbus_interface=SECURITY_INTERFACE))


def export_audit(filter_json: str, fmt: str = "json") -> str:
    """ExportAudit: 导出审计日志，返回文件路径。"""
    proxy = _get_proxy()
    return str(proxy.ExportAudit(filter_json, fmt,
                                  dbus_interface=SECURITY_INTERFACE))


def verify_audit_chain(export_path: str) -> bool:
    """VerifyAuditChain: 验证审计日志完整性。"""
    proxy = _get_proxy()
    return bool(proxy.VerifyAuditChain(export_path,
                                        dbus_interface=SECURITY_INTERFACE))


def build_sandbox_policy(agent_id: str) -> dict:
    """BuildSandboxPolicy: 生成沙箱策略（seccomp BPF + netfilter），
    返回 seccomp_path 供 agent-runtimed 以 bwrap --seccomp <fd> 加载。"""
    proxy = _get_proxy()
    seccomp_path, netfilter_rules = proxy.BuildSandboxPolicy(
        agent_id, dbus_interface=SECURITY_INTERFACE)
    return {"seccomp_path": str(seccomp_path), "netfilter_rules": str(netfilter_rules)}


def set_network_policy(agent_id: str, domains: list, mode: str = "whitelist") -> bool:
    """SetNetworkPolicy: 下发网络白名单策略。"""
    proxy = _get_proxy()
    return bool(proxy.SetNetworkPolicy(agent_id, domains, mode,
                                        dbus_interface=SECURITY_INTERFACE))
```

### 7.4 测试用 Agent Manifest

测试 Agent 包含覆盖 L1~L4 所有风险等级的权限声明，路径：
`tests/fixtures/test-security-agent/manifest.toml`

```toml
[agent]
id        = "com.bianbu.test-security-agent"
version   = "1.0.0"
name      = "Hermes Security Test Agent"
signature = "ed25519:TEST_SIGNATURE_PLACEHOLDER"

[permissions]
# L1 只读（trusted，安装后不再确认）
read_proc_list   = { domain = "data",    risk_level = "L1", confirm = "trusted" }
# L2 文件写（会话内信任）
file_write_docs  = { domain = "execute", risk_level = "L2", confirm = "once_per_session",
                      scope = "~/Documents/bianbu-test" }
# L2 联系人读（会话内信任）
contacts_read    = { domain = "data",    risk_level = "L2", confirm = "once_per_session" }
# L3 系统修改（每次确认）
network_config   = { domain = "system",  risk_level = "L3", confirm = "always" }
# L4 危险操作（每次 + 二次确认）
payment_create   = { domain = "execute", risk_level = "L4", confirm = "always" }
# 网络声明
[permissions.network]
allowed_domains  = ["test.bianbu.local"]
# Token 预算（设置较小值方便测试超限）
[permissions.token_budget]
unit                   = "token"
limit_per_conversation = 1000
limit_per_day          = 5000
on_exceed              = "pause_and_notify"
```

### 7.5 hermes Agent 对接测试流程

```
hermes-agent 启动
  │
  ├─ 步骤 1：安装测试 Agent
  │   verify_manifest("tests/fixtures/test-security-agent.pkg")
  │   → 期望：valid=true，解析出 5 条权限
  │   register_capabilities(agent_id, perms)
  │   → 期望：ok=true，capabilities.db 中有 5 条记录
  │
  ├─ 步骤 2：验证 L1 权限（trusted，直接放行）
  │   check_permission(agent_id, "read_proc_list")
  │   → 期望：返回 0（ALLOW），无弹窗
  │
  ├─ 步骤 3：验证 L2 权限（once_per_session）
  │   check_permission(agent_id, "file_write_docs", "~/Documents/bianbu-test")
  │   → 期望：首次返回 1（CONFIRM）
  │   request_confirm(agent_id, "file_write_docs", "写入测试文件")
  │   → 用户批准 → 返回 true
  │   check_permission(agent_id, "file_write_docs", ...)  ← 再次调用
  │   → 期望：返回 0（session_cache 命中，不再弹窗）
  │
  ├─ 步骤 4：验证 L3 权限（always）
  │   check_permission(agent_id, "network_config")
  │   → 期望：返回 1（CONFIRM）
  │   request_confirm(agent_id, "network_config", "修改 DNS 配置")
  │   → 用户拒绝 → 返回 false
  │   → 期望：操作被阻断，审计记录 result="confirm_denied"
  │
  ├─ 步骤 5：验证 L4 权限（always + 二次确认）
  │   check_permission(agent_id, "payment_create")
  │   → 期望：返回 1（强制 CONFIRM）
  │   request_confirm(agent_id, "payment_create", "支付 100 元")
  │   → 弹窗 1：用户确认 → 弹窗 2（二次确认）→ 用户再次确认
  │   → 返回 true
  │
  ├─ 步骤 6：验证 Token 超限事件通知
  │   meter_tokens(agent_id, 600, "conv")   → within=true, remaining=400
  │   meter_tokens(agent_id, 500, "conv")   → within=false（超过 1000 上限）
  │   → 期望：TokenExceeded/SecurityAlert 信号触发，Agent Runtime/agent 消费事件后暂停或终止 Agent，审计记录 result="exceed"
  │
  ├─ 步骤 7：验证 bwrap 沙箱系统调用拦截
  │   启动沙箱进程（build_sandbox_policy 生成 seccomp fd + agent-runtimed 用 bwrap --seccomp 启动）
  │   在沙箱内执行 reboot 系统调用
  │   → 期望：EPERM（seccomp 拦截），宿主机不受影响，审计记录 sandbox syscall blocked
  │
  ├─ 步骤 8：验证网络白名单
  │   set_network_policy(agent_id, ["test.bianbu.local"], "whitelist")
  │   在沙箱内访问 test.bianbu.local → 期望：放行
  │   在沙箱内访问 evil.example.com  → 期望：DROP，SecurityAlert 触发
  │
  └─ 步骤 9：审计日志导出与验证
      export_audit('{"agent_id":"com.bianbu.test-security-agent"}', "json")
      → 期望：export_path 文件存在，含步骤 2~8 全部操作记录
      verify_audit_chain(export_path)
      → 期望：intact=true，哈希链完整
      手动篡改 export 文件中一条记录
      verify_audit_chain(export_path)
      → 期望：intact=false，定位篡改位置
```


---

## 8 测试用例

### 8.1 测试覆盖矩阵

| 测试类别 | 覆盖需求 | 文件路径 |
|---------|---------|---------|
| 单元测试：Capability Registry | FR-SEC-01/02 | `tests/unit/test_capability_registry.py` |
| 单元测试：CheckPermission 算法 | FR-SEC-02/03 | `tests/unit/test_check_permission.py` |
| 单元测试：Audit Chain | FR-SEC-06 | `tests/unit/test_audit_chain.py` |
| 单元测试：Token Meter | FR-SEC-04 | `tests/unit/test_token_meter.py` |
| 单元测试：seccomp 策略生成 | FR-SEC-05/SBX-04 | `tests/unit/test_seccomp_builder.py` |
| 集成测试：D-Bus 接口 | 全部方法 | `tests/integration/test_dbus_security.py` |
| 集成测试：沙箱创建 | FR-SBX-01~07 | `tests/integration/test_sandbox_manager.py` |
| 安全测试：越权拦截 | NFR-S-01 | `tests/security/test_permission_bypass.py` |
| 安全测试：审计防篡改 | NFR-S-03 | `tests/security/test_audit_tamper.py` |
| 安全测试：沙箱逃逸 | FR-SBX-07 | `tests/security/test_sandbox_escape.py` |
| hermes E2E 测试 | 全功能 | `tests/e2e/test_hermes_integration.py` |
| 性能测试：冷启动 | FR-SBX-06 | `tests/perf/test_cold_start.py` |

---

### 8.2 单元测试用例

#### TC-UNIT-01：Manifest 校验——有效包

| 字段 | 内容 |
|------|------|
| 编号 | TC-UNIT-01 |
| 需求 | FR-SEC-01 |
| 前置条件 | securityd 进程运行；测试 Agent 包含有效 ed25519 签名 |
| 操作步骤 | 调用 `VerifyManifest("tests/fixtures/valid-agent.pkg")` |
| 期望结果 | `valid=true`，解析出 5 条权限记录，reason="" |
| 验收标准 | 100% 通过 |

#### TC-UNIT-02：Manifest 校验——无签名包

| 字段 | 内容 |
|------|------|
| 编号 | TC-UNIT-02 |
| 需求 | FR-SEC-01 |
| 前置条件 | 测试包缺少 signature 字段 |
| 操作步骤 | 调用 `VerifyManifest("tests/fixtures/no-sig-agent.pkg")` |
| 期望结果 | `valid=false`，reason 含 "missing signature" |
| 验收标准 | 拒绝安装，返回明确错误原因 |

#### TC-UNIT-03：Manifest 校验——无 manifest 包

| 字段 | 内容 |
|------|------|
| 编号 | TC-UNIT-03 |
| 需求 | FR-SEC-01 |
| 操作步骤 | 调用 `VerifyManifest("tests/fixtures/no-manifest.pkg")` |
| 期望结果 | `valid=false`，reason 含 "manifest.toml not found" |
| 验收标准 | 拒绝安装 |

#### TC-UNIT-04：CheckPermission——L1 trusted 直接放行

| 字段 | 内容 |
|------|------|
| 编号 | TC-UNIT-04 |
| 需求 | FR-SEC-02/03 |
| 前置条件 | agent_id 已注册 `read_proc_list`(L1, trusted, granted=1) |
| 操作步骤 | `CheckPermission(agent_id, "read_proc_list", "")` |
| 期望结果 | 返回 0（ALLOW），不触发弹窗 |

#### TC-UNIT-05：CheckPermission——L2 once_per_session 首次返回 CONFIRM

| 字段 | 内容 |
|------|------|
| 编号 | TC-UNIT-05 |
| 需求 | FR-SEC-02/03 |
| 前置条件 | agent_id 已注册 `file_write_docs`(L2, once_per_session)，session_cache 为空 |
| 操作步骤 | `CheckPermission(agent_id, "file_write_docs", "~/Documents/bianbu-test")` |
| 期望结果 | 返回 1（CONFIRM） |

#### TC-UNIT-06：CheckPermission——L2 once_per_session 会话内二次调用 ALLOW

| 字段 | 内容 |
|------|------|
| 编号 | TC-UNIT-06 |
| 需求 | FR-SEC-03 |
| 前置条件 | 会话内已确认 `file_write_docs`，session_cache 有记录 |
| 操作步骤 | 再次 `CheckPermission(agent_id, "file_write_docs", "~/Documents/bianbu-test")` |
| 期望结果 | 返回 0（ALLOW），不再触发弹窗 |

#### TC-UNIT-07：CheckPermission——L4 强制 CONFIRM

| 字段 | 内容 |
|------|------|
| 编号 | TC-UNIT-07 |
| 需求 | FR-SEC-03（L4 约束） |
| 前置条件 | agent_id 已注册 `payment_create`(L4, always) |
| 操作步骤 | `CheckPermission(agent_id, "payment_create", "")` |
| 期望结果 | 返回 1（CONFIRM），即使曾经确认过也不走 session_cache |

#### TC-UNIT-08：CheckPermission——未注册能力返回 DENY

| 字段 | 内容 |
|------|------|
| 编号 | TC-UNIT-08 |
| 需求 | FR-SEC-02 |
| 操作步骤 | `CheckPermission(agent_id, "system.shutdown", "")` |
| 期望结果 | 返回 2（DENY），写审计记录 result="deny" |

#### TC-UNIT-09：L3/L4 不允许 trusted 策略——注册时拒绝

| 字段 | 内容 |
|------|------|
| 编号 | TC-UNIT-09 |
| 需求 | FR-SEC-01（权限模型约束） |
| 操作步骤 | 尝试注册 `(risk_level=L3, confirm=trusted)` 的权限 |
| 期望结果 | RegisterCapabilities 返回 ok=false，错误说明约束违反 |

#### TC-UNIT-10：Token Meter——单次对话超限

| 字段 | 内容 |
|------|------|
| 编号 | TC-UNIT-10 |
| 需求 | FR-SEC-04 |
| 前置条件 | agent token_budget.limit_per_conversation=1000 |
| 操作步骤 | `MeterTokens(agent_id, 600, "conv")`；再 `MeterTokens(agent_id, 500, "conv")` |
| 期望结果 | 第二次返回 within=false, remaining=0；TokenExceeded 信号触发 |
| 验收标准 | 立即返回超限+发事件+记审计；Agent Runtime/agent 消费事件后暂停或终止 |

#### TC-UNIT-11：Token Meter——次日 00:00 重置

| 字段 | 内容 |
|------|------|
| 编号 | TC-UNIT-11 |
| 需求 | FR-SEC-04 |
| 操作步骤 | 设置 day_epoch 为昨日，`MeterTokens(agent_id, 1, "conv")` |
| 期望结果 | day_used 从 0 开始累计，day_epoch 更新为今日 |

#### TC-UNIT-12：Audit Chain——哈希链完整性

| 字段 | 内容 |
|------|------|
| 编号 | TC-UNIT-12 |
| 需求 | FR-SEC-06（NFR-S-03） |
| 操作步骤 | 写入 10 条审计记录，调用 VerifyAuditChain |
| 期望结果 | intact=true，每条 hash = SHA256(期望字段拼接) |

#### TC-UNIT-13：Audit Chain——篡改检测

| 字段 | 内容 |
|------|------|
| 编号 | TC-UNIT-13 |
| 需求 | FR-SEC-06（NFR-S-03） |
| 操作步骤 | 写入 10 条，直接修改第 5 条的 result 字段，再验证 |
| 期望结果 | intact=false，定位到第 5 条 |
| 验收标准 | 篡改 100% 可检出 |

---

### 8.3 集成测试用例

#### TC-INT-01：D-Bus 服务注册与可达性

| 字段 | 内容 |
|------|------|
| 编号 | TC-INT-01 |
| 前置条件 | bianbu-securityd 以 systemd 服务启动 |
| 操作步骤 | `busctl --system introspect io.bianbu.Security /io/bianbu/Security` |
| 期望结果 | 输出包含全部 14 个方法名和 4 个信号名 |

#### TC-INT-02：完整安装→启动→运行→审计全链路

| 字段 | 内容 |
|------|------|
| 编号 | TC-INT-02 |
| 需求 | FR-SEC-01~06, FR-SBX-01~07 |
| 操作步骤 | VerifyManifest → RegisterCapabilities → BuildSandboxPolicy → （agent-runtimed）Start → CheckPermission(L2) → RequestConfirm → MeterTokens → AuditLog → ExportAudit → VerifyAuditChain |
| 期望结果 | 每步返回值符合预期，最终 VerifyAuditChain=true，审计记录完整包含全部操作 |

#### TC-INT-03：沙箱创建——bwrap 文件隔离与 mandatory deny path

| 字段 | 内容 |
|------|------|
| 编号 | TC-INT-03 |
| 需求 | FR-SBX-01 |
| 操作步骤 | 用 bwrap 启动沙箱进程，在沙箱内：①读取宿主 `~/Documents/other`（未 bind 目录）；②读取 mandatory deny path `/etc/shadow`（已 `--ro-bind /dev/null` 覆盖） |
| 期望结果 | ①路径不可见（ENOENT）；②读到空内容（/dev/null），无法获取宿主 shadow |
| 验收标准 | 越界访问 100% 被拦截；deny path 100% 被覆盖 |

#### TC-INT-04：cgroup v2 内存超限 OOM

| 字段 | 内容 |
|------|------|
| 编号 | TC-INT-04 |
| 需求 | FR-SBX-02（联动 FR-RTE-13） |
| 操作步骤 | 将 MemoryMax 设为 64MB，在沙箱内分配 80MB 内存 |
| 期望结果 | OOM killer 触发，Agent 进程被终止，宿主系统不受影响 |

#### TC-INT-05：网络白名单——未授权流量被阻断

| 字段 | 内容 |
|------|------|
| 编号 | TC-INT-05 |
| 需求 | FR-SEC-07 / FR-SBX-03 |
| 操作步骤 | Agent 声明只允许 `test.bianbu.local`；在沙箱内 curl `https://evil.example.com` |
| 期望结果 | 连接失败（iptables DROP），SecurityAlert 信号触发，审计记录 result="deny" |
| 验收标准 | 未授权流量 100% 被阻断 |

#### TC-INT-06：seccomp——黑名单系统调用拦截

| 字段 | 内容 |
|------|------|
| 编号 | TC-INT-06 |
| 需求 | FR-SEC-05 / FR-SBX-04 |
| 操作步骤 | 在沙箱进程内调用 `syscall(SYS_reboot, ...)` |
| 期望结果 | 返回 EPERM（seccomp kill 或 ERRNO action），宿主机不重启 |
| 验收标准 | 恶意系统调用 100% 被拒绝 |

#### TC-INT-07：capability drop——CAP_SYS_ADMIN 不可用

| 字段 | 内容 |
|------|------|
| 编号 | TC-INT-07 |
| 需求 | FR-SBX-05 |
| 操作步骤 | 在沙箱内读取 `/proc/self/status`，查看 CapEff 位图 |
| 期望结果 | CAP_SYS_ADMIN（bit 21）= 0 |

#### TC-INT-08：沙箱创建失败——Fail-Closed

| 字段 | 内容 |
|------|------|
| 编号 | TC-INT-08 |
| 需求 | FR-SBX-07 |
| 操作步骤 | 人为使 seccomp 策略文件不可读，触发 BuildSandboxPolicy 失败，调用 agent-runtimed.Start |
| 期望结果 | Agent 未启动，FSM=FAILED，审计记录 sandbox_start result="fail"，SecurityAlert 触发 |
| 验收标准 | 严禁降级为无沙箱运行 |

#### TC-INT-09：冷启动延迟 ≤ 200ms

| 字段 | 内容 |
|------|------|
| 编号 | TC-INT-09 |
| 需求 | FR-SBX-06（联动 FR-RTE-02） |
| 操作步骤 | 连续启动测试 Agent 10 次，记录每次 Start 到 FSM=RUNNING 耗时 |
| 期望结果 | P95 ≤ 200ms，P99 ≤ 250ms |
| 测试平台 | worker K3（SpacemiT 10.0.90.243） |

---

### 8.4 安全测试用例

#### TC-SEC-01：权限越界——拦截率 100%（NFR-S-01）

| 字段 | 内容 |
|------|------|
| 编号 | TC-SEC-01 |
| 需求 | NFR-S-01 |
| 操作步骤 | 注册 Agent 声明 5 种权限；尝试调用未注册的 20 种能力（包括所有系统调用拦截、越界文件访问、未授权网络访问） |
| 期望结果 | 20/20 全部被拒绝或阻断，审计记录均含 result="deny" 或等价 |
| 验收标准 | 权限越权拦截率 = 100% |

#### TC-SEC-02：敏感操作未经确认不执行（NFR-S-02）

| 字段 | 内容 |
|------|------|
| 编号 | TC-SEC-02 |
| 需求 | NFR-S-02 |
| 操作步骤 | 对 L3/L4/always 的能力，模拟用户拒绝确认弹窗 |
| 期望结果 | 操作 100% 被阻断，审计记录 result="confirm_denied" |
| 验收标准 | 敏感操作确认率 = 100%（未确认不执行） |

#### TC-SEC-03：审计日志不可绕过写入

| 字段 | 内容 |
|------|------|
| 编号 | TC-SEC-03 |
| 需求 | FR-SEC-06 |
| 操作步骤 | 通过 D-Bus 调用 CheckPermission(允许)，然后直接查询 audit_record 表 |
| 期望结果 | 每次 CheckPermission 均有对应审计记录，无遗漏 |

#### TC-SEC-04：密钥不可被普通 Agent 读取

| 字段 | 内容 |
|------|------|
| 编号 | TC-SEC-04 |
| 需求 | FR-AI-21（[TBD-17] 软件方案） |
| 操作步骤 | 以普通 Agent 权限尝试读取 `/etc/bianbu/keys/` 或调用 gnome-keyring（非 securityd 代理路径） |
| 期望结果 | 访问被拒绝（EPERM / PermissionDenied） |

---

### 8.5 hermes Agent 端到端测试用例

#### TC-E2E-01：hermes agent 完整安全功能覆盖

| 字段 | 内容 |
|------|------|
| 编号 | TC-E2E-01 |
| 需求 | FR-SEC-01~07，FR-SBX-01~07 |
| 前置条件 | worker K3（10.0.90.243）上：bianbu-securityd 运行，hermes-agent 已部署，bianbu_security_client.py 可达 D-Bus |
| 操作步骤 | 执行 7.5 节全部 9 个步骤（安装 → L1 → L2 → L3 拒绝 → L4 → Token 超限 → seccomp → 网络 → 审计） |
| 期望结果 | 每步结果与 7.5 节期望一致 |
| 验收标准 | 全部 9 步 PASS，审计日志哈希链 intact=true |

#### TC-E2E-02：hermes agent 触发 SecurityAlert 信号

| 字段 | 内容 |
|------|------|
| 编号 | TC-E2E-02 |
| 需求 | FR-SET-19 |
| 操作步骤 | hermes agent 订阅 `SecurityAlert` 信号；沙箱内触发 3 种告警（越界文件访问/未知域名/syscall 拒绝） |
| 期望结果 | hermes agent 收到 3 次 SecurityAlert 信号，含正确 agent_id/type/detail |

#### TC-E2E-03：hermes agent 导出审计日志并离线验证

| 字段 | 内容 |
|------|------|
| 编号 | TC-E2E-03 |
| 需求 | FR-SEC-06（SET-16） |
| 操作步骤 | 执行 TC-E2E-01 后，export_audit，scp 到开发机，verify_audit_chain（离线）|
| 期望结果 | 离线环境下 VerifyAuditChain=true，CSV 含所有预期字段 |

---

### 8.6 回归测试快速验证脚本

```bash
#!/bin/bash
# tests/smoke_test.sh
# 在 worker 机执行：sshpass -p 'bianbu' ssh -o StrictHostKeyChecking=no bianbu@10.0.90.243 'bash /home/bianbu/bianbu-agentos/tests/smoke_test.sh'

set -e
AGENT_ID="com.bianbu.test-security-agent"

echo "[0/6] 检查 bwrap 非特权沙箱可用..."
bwrap --ro-bind /usr /usr --tmpfs /tmp --unshare-all --die-with-parent -- /bin/true
echo "  PASS: bwrap 可用"

echo "[1/6] 检查 securityd D-Bus 服务是否运行..."
busctl --system status io.bianbu.Security | grep -q "ActiveState=active"
echo "  PASS: securityd 运行中"

echo "[2/6] 验证 Manifest（有效包）..."
python3 -c "
from bianbu_security_client import verify_manifest
r = verify_manifest('/home/bianbu/bianbu-agentos/tests/fixtures/test-security-agent.pkg')
assert r['valid'] == True, f'FAIL: {r}'
print('  PASS: Manifest 校验通过')
"

echo "[3/6] 注册能力..."
python3 -c "
from bianbu_security_client import register_capabilities
perms = [{'capability':'read_proc_list','domain':'data','risk_level':'L1','confirm':'trusted'}]
assert register_capabilities('$AGENT_ID', perms) == True
print('  PASS: 能力注册成功')
"

echo "[4/6] 权限校验 L1 ALLOW..."
python3 -c "
from bianbu_security_client import check_permission
assert check_permission('$AGENT_ID', 'read_proc_list') == 0
print('  PASS: L1 trusted ALLOW')
"

echo "[5/6] Token 计量..."
python3 -c "
from bianbu_security_client import meter_tokens
r = meter_tokens('$AGENT_ID', 100, 'conv')
assert r['within_limit'] == True
print('  PASS: Token 计量正常')
"

echo "[6/6] 审计日志写入与验证..."
python3 -c "
from bianbu_security_client import audit_log, export_audit, verify_audit_chain
seq = audit_log('$AGENT_ID', 'smoke_test', 'smoke', 'allow')
assert seq > 0
path = export_audit('{\"agent_id\":\"$AGENT_ID\"}', 'json')
assert verify_audit_chain(path) == True
print('  PASS: 审计链完整')
"

echo "=== Smoke Test ALL PASS ==="
```


---

## 9 开发任务清单

> 说明：按模块分组，标注需求编号与依赖关系。不含人力时间估算，由 AI Coding 工具自行推进。

### 9.1 基础设施与 D-Bus 框架

| 编号 | 任务 | 需求映射 | 依赖 | 输出产物 |
|------|------|---------|------|---------|
| INF-01 | 创建 bianbu-securityd systemd 服务单元文件，配置启动顺序（最先启动） | HLD §5 | — | `bianbu-securityd.service` |
| INF-02 | 搭建 D-Bus 服务框架（GDBus / sd-bus），注册 `io.bianbu.Security` 接口 | API §2 | INF-01 | D-Bus 服务骨架 |
| INF-03 | 定义 D-Bus 接口描述文件（XML introspection）：14 方法 + 4 信号 | API §2 | INF-02 | `io.bianbu.Security.xml` |
| INF-04 | 编写 D-Bus polkit 策略文件，限定调用方身份 | HLD §8.4 | INF-02 | `io.bianbu.security.policy` |
| INF-05 | 初始化 SQLite WAL 模式数据库（capabilities.db、token_budget.db） | LLD §1.1 | — | DB 初始化脚本 + schema |
| INF-06 | 创建审计数据库（audit/YYYYMM.db），分段机制，段间哈希链接 | LLD §1.2 | INF-05 | 审计 DB + 轮转逻辑 |
| INF-07 | 统一错误码实现（PermissionDenied / ConfirmRequired / QuotaExceeded 等） | API §1 | INF-02 | 错误码枚举 + D-Bus 映射 |
| INF-08 | 创建 `/run/bianbu/sandbox/` 运行时目录结构与权限设置 | LLD §3.2 | INF-01 | 目录初始化脚本 |

### 9.2 Capability Registry 模块

| 编号 | 任务 | 需求映射 | 依赖 | 输出产物 |
|------|------|---------|------|---------|
| CAP-01 | 实现 `VerifyManifest`：ed25519 签名验证 + TOML 解析 + 约束校验（L3/L4 不允许 trusted） | FR-SEC-01 | INF-05 | verify_manifest.c/rs |
| CAP-02 | 实现 `RegisterCapabilities`：权限写入 SQLite，防重复，覆盖更新 | FR-SEC-02 | INF-05 | register_caps.c/rs |
| CAP-03 | 实现 `CheckPermission`：lookup + best_match_scope + L4 强制逻辑 | FR-SEC-02/03 | CAP-02 | check_permission.c/rs |
| CAP-04 | 实现 session_trust 表：会话级缓存（once_per_session），会话结束清理 | FR-SEC-03 | CAP-03 | session_cache.c/rs |
| CAP-05 | 实现 `RevokePermission`：撤销授权，L3/L4 二次确认 | FR-SEC-02 | CAP-02 | revoke_permission.c/rs |
| CAP-06 | 实现 `GetCapabilities`：按 agent_id 查询已注册权限列表（CLI/GUI 用） | FR-SEC-02 | CAP-02 | get_capabilities.c/rs |
| CAP-07 | 实现 CLI 工具 `bncli capability`：查询/撤销/列表子命令 | FR-SEC-02 | CAP-06 | bncli capability 子命令 |

### 9.3 Confirm Gatekeeper 模块

| 编号 | 任务 | 需求映射 | 依赖 | 输出产物 |
|------|------|---------|------|---------|
| CFM-01 | 实现 `RequestConfirm`（异步，不阻塞主循环）：发 `ConfirmRequest` 信号，等 `RespondConfirm` 回传（或超时 30s）；GUI 经 `RespondConfirm` 回传后广播 `ConfirmResponse` 信号 | FR-SEC-03 | INF-02, CAP-03 | confirm_gatekeeper.c/rs |
| CFM-02 | 实现 L4 二次确认逻辑：首次确认通过后再发信号，等待二次 | FR-SEC-03（L4 约束） | CFM-01 | 集成至 CFM-01 |
| CFM-03 | 实现超时机制：30s 无响应自动返回 denied，写审计记录 | FR-SEC-03 | CFM-01 | 超时逻辑 |
| CFM-04 | 实现通知中心集成（D-Bus 激活 UI 弹窗进程） | FR-SEC-03 | CFM-01 | 通知适配器 |

### 9.4 Audit Chain Engine 模块

| 编号 | 任务 | 需求映射 | 依赖 | 输出产物 |
|------|------|---------|------|---------|
| AUD-01 | 实现 `AuditLog`：专用串行写线程 + 内存队列 + SHA-256 哈希链计算 | FR-SEC-06 | INF-06 | audit_chain.c/rs |
| AUD-02 | 实现 Fail-Closed 策略：写入失败阻断调用方操作 + SecurityAlert 信号 | FR-SEC-06（NFR-S-03） | AUD-01 | Fail-Closed 逻辑 |
| AUD-03 | 实现 `ExportAudit`：JSON/CSV 导出，末尾附哈希锚 | FR-SEC-06（SET-16） | AUD-01 | export_audit.c/rs |
| AUD-04 | 实现 `VerifyAuditChain`：逐条重算哈希，定位篡改位置 | FR-SEC-06（NFR-S-03） | AUD-03 | verify_chain.c/rs |
| AUD-05 | 实现按月分段轮转：新月创建新 DB，段间以 audit_segment_meta 链接 | FR-SEC-06 | AUD-01 | 轮转逻辑 |
| AUD-06 | 实现 CLI 工具 `bncli audit`：查看/导出/验证子命令 | SET-15/16 | AUD-03, AUD-04 | bncli audit 子命令 |

### 9.5 Syscall Filter Builder 模块

| 编号 | 任务 | 需求映射 | 依赖 | 输出产物 |
|------|------|---------|------|---------|
| SCM-01 | 实现 seccomp 黑名单策略生成（libseccomp）：包含 reboot/swapon/kexec/init_module 等 | FR-SEC-05/SBX-04 | INF-08 | seccomp_builder.c/rs |
| SCM-02 | 将 seccomp BPF 写入 `/run/bianbu/sandbox/<id>/seccomp.bpf` | FR-SBX-04 | SCM-01 | 集成至 BuildSandboxPolicy |
| SCM-03 | 支持按 Agent 能力声明动态调整黑名单（高风险 Agent 更严格的黑名单） | FR-SBX-04 | CAP-02, SCM-01 | 动态策略逻辑 |

### 9.6 Network Policy 模块

| 编号 | 任务 | 需求映射 | 依赖 | 输出产物 |
|------|------|---------|------|---------|
| NET-01 | 实现 `SetNetworkPolicy`：域名 DNS 解析 → iptables 白名单规则生成与下发 | FR-SEC-07/SBX-03 | INF-08 | network_policy.c/rs |
| NET-02 | 实现默认 DROP 策略：新 Agent 沙箱启动时先 DROP 全部流量，再放行白名单 | FR-SBX-03 | NET-01 | 集成至 BuildSandboxPolicy |
| NET-03 | 实现拦截记录：监听 netfilter LOG target，触发 AuditLog + SecurityAlert | FR-SEC-07（SET-19） | NET-01, AUD-01 | 网络拦截监听器 |
| NET-04 | 实现学习模式：观察期自动收集实际出站域名，生成建议白名单 | SET-18 | NET-01 | 学习模式逻辑 |
| NET-05 | 实现 Agent 停止时清理 iptables 规则 | FR-SBX-03 | NET-01 | 规则清理逻辑 |

### 9.7 Token Budget Meter 模块

| 编号 | 任务 | 需求映射 | 依赖 | 输出产物 |
|------|------|---------|------|---------|
| TOK-01 | 实现 `MeterTokens`：in-memory 原子计数器，conv/day 双维度 | FR-SEC-04 | INF-05 | token_meter.c/rs |
| TOK-02 | 实现次日 00:00 重置逻辑（本地时区 day_epoch） | FR-SEC-04 | TOK-01 | 重置逻辑 |
| TOK-03 | 实现超限触发：发送 `TokenExceeded`/`SecurityAlert`，由 Agent Runtime/agent 消费并执行暂停或终止 | FR-SEC-04 | TOK-01, INF-02 | securityd 事件触发；运行时动作由 Agent Runtime/agent 负责 |
| TOK-04 | 实现 day_used 持久化（token_budget_state 表），服务重启后恢复 | FR-SEC-04 | TOK-01, INF-05 | 持久化逻辑 |

### 9.8 Sandbox Manager 模块（bianbu-agent-runtimed 侧）

| 编号 | 任务 | 需求映射 | 依赖 | 输出产物 |
|------|------|---------|------|---------|
| SBX-01 | 实现 `BuildSandboxPolicy` 方法（securityd 侧）：聚合 seccomp + netfilter 策略，写入 /run | FR-SBX-03/04/05 | SCM-02, NET-02 | build_sandbox_policy.c/rs |
| SBX-02 | 实现 bwrap 参数构造器：按 Agent 声明生成 `--ro-bind`/`--bind`/`--tmpfs`/`--dev`/`--proc` + mandatory deny paths | FR-SBX-01 | INF-08 | bwrap_args_builder.c/rs |
| SBX-03 | 实现 cgroup v2 编排：创建 slice，bwrap 启动前加入，设置 CPUQuota/MemoryMax/IOWeight | FR-SBX-02 | INF-08 | sandbox_cgroup.c/rs |
| SBX-04 | 实现 bwrap 启动：拼装 `--unshare-*` + `--cap-drop all` + `--seccomp <fd>` + `--die-with-parent`，execve bwrap | FR-SBX-04/05 | SCM-02, SBX-02 | sandbox_exec.c/rs |
| SBX-05 | 实现 Fail-Closed：任一步失败回滚资源（终止 bwrap/cgroup/iptables），拒绝启动，触发 SecurityAlert + AuditLog | FR-SBX-07 | AUD-01, SBX-02~04 | fail_closed.c/rs |
| SBX-06 | 实现沙箱停止与资源清理：终止 bwrap 进程、cgroup 删除、iptables 规则清理（bwrap 挂载随进程自动释放） | FR-SBX-01~03 | SBX-02~04, NET-05 | sandbox_cleanup.c/rs |
| SBX-07 | 性能优化：BuildSandboxPolicy 并行预取、seccomp fd 预打开、bwrap 参数最小化，目标 P95 ≤ 200ms | FR-SBX-06 | SBX-01~06 | 性能调优 |
| SBX-08 | 验证 worker K3 上 bwrap 版本与非特权可用性（`bwrap --version`，`unprivileged_userns_clone`），文档化最小依赖 | FR-SBX-01 | — | bwrap 环境校验脚本 |

### 9.9 Key Vault 模块（软件方案）

| 编号 | 任务 | 需求映射 | 依赖 | 输出产物 |
|------|------|---------|------|---------|
| KV-01 | 实现用户级密钥存储：gnome-keyring 读写封装（服务通过 D-Bus 代理，Agent 不可直读） | FR-AI-21/[TBD-17] | INF-01 | key_vault_user.c/rs |
| KV-02 | 实现服务级密钥存储：age/libsodium 加密文件，文件 root-only 权限，securityd 代理读取 | FR-AI-21/[TBD-17] | INF-01 | key_vault_service.c/rs |
| KV-03 | 普通 Agent 经 CheckPermission 门控访问密钥，不可直读文件 | FR-AI-21 | CAP-03, KV-01/02 | 门控逻辑 |

### 9.10 hermes Agent 对接适配器

| 编号 | 任务 | 需求映射 | 依赖 | 输出产物 |
|------|------|---------|------|---------|
| HMA-01 | 编写 `bianbu_security_client.py`（见 7.3 节） | 7.3 | INF-02 | `tools/hermes-security-adapter/bianbu_security_client.py` |
| HMA-02 | 创建测试 Agent Manifest（见 7.4 节），生成有效 ed25519 签名 | 7.4 | CAP-01 | `tests/fixtures/test-security-agent.pkg` |
| HMA-03 | 创建无签名 / 无 manifest 负面测试 fixture | TC-UNIT-02/03 | CAP-01 | 测试 fixture |
| HMA-04 | 编写 hermes agent 测试驱动脚本（覆盖 7.5 节 9 步骤） | TC-E2E-01 | HMA-01/02, 全部核心模块 | `tests/e2e/test_hermes_integration.py` |
| HMA-05 | 编写 SecurityAlert 信号订阅测试（TC-E2E-02） | TC-E2E-02 | HMA-01 | `tests/e2e/test_security_alert.py` |
| HMA-06 | 编写审计离线验证测试（TC-E2E-03） | TC-E2E-03 | AUD-03, HMA-01 | `tests/e2e/test_audit_offline.py` |
| HMA-07 | 编写 smoke 测试脚本（见 8.6 节）并在 worker 机验证可执行 | 快速回归 | 全部 | `tests/smoke_test.sh` |

### 9.11 测试自动化框架

| 编号 | 任务 | 依赖 | 输出产物 |
|------|------|------|---------|
| TST-01 | 配置 pytest 框架（单元 + 集成），fixture：securityd mock + 真实 D-Bus | — | `tests/conftest.py` |
| TST-02 | 实现单元测试（TC-UNIT-01~13，见 8.2 节） | 各核心模块 | `tests/unit/` |
| TST-03 | 实现集成测试（TC-INT-01~09，见 8.3 节） | 各核心模块 | `tests/integration/` |
| TST-04 | 实现安全测试（TC-SEC-01~04，见 8.4 节） | 全部核心模块 | `tests/security/` |
| TST-05 | 实现性能测试：冷启动 10 次采样，输出 P50/P95/P99（TC-INT-09） | SBX-07 | `tests/perf/test_cold_start.py` |
| TST-06 | 配置 CI 流水线：在 worker 机（10.0.90.243）上运行全套测试，smoke → unit → int → e2e | TST-01~05 | `.ci/run_tests.sh` |

### 9.12 任务依赖关系摘要

```
基础层:  INF-01~08（D-Bus + DB 框架）
   ↓
核心层:  CAP-01~07 → CFM-01~04
         AUD-01~06
         SCM-01~03
         NET-01~05
         TOK-01~04
         KV-01~03
   ↓
沙箱层:  SBX-01~07（依赖 SCM + NET + AUD）
   ↓
对接层:  HMA-01~07（依赖全部核心模块）
   ↓
测试层:  TST-01~06
```

### 9.13 Phase 2 预留任务（当前不纳入）

| 编号 | 任务 | 需求映射 |
|------|------|---------|
| P2-01 | Level 2 命名空间隔离：PID/NET/MNT/UTS/IPC ns（[TBD-9]） | FR-SBX-08 |
| P2-02 | TEE 密钥存储：待 K3 TEE 可用后替换 KV-01/02 软件方案（[TBD-17]） | FR-AI-21 |
| P2-03 | token_budget 计量口径确认后实现调整（[TBD-2/3]） | FR-SEC-04 |
| P2-04 | Level 3 容器级隔离（Docker，P2） | PRD §8.1 |

---

## 附录 A：需求追溯矩阵

| 需求编号 | 方案章节 | D-Bus 方法 | 任务编号 | 测试用例 |
|---------|---------|-----------|---------|---------|
| FR-SEC-01 | §3.1, §6.1 | VerifyManifest | CAP-01 | TC-UNIT-01~03 |
| FR-SEC-02 | §3.1, §6.3 | RegisterCapabilities, CheckPermission, GetCapabilities, RevokePermission | CAP-02~07 | TC-UNIT-04~09, TC-INT-02 |
| FR-SEC-03 | §3.2, §6.4 | CheckPermission, RequestConfirm | CAP-03, CFM-01~04 | TC-UNIT-05~07, TC-E2E-01 步骤 3~5 |
| FR-SEC-04 | §3.6, §6.5 | MeterTokens, TokenExceeded/SecurityAlert | TOK-01~04 | TC-UNIT-10~11；补充 securityd→Agent Runtime/agent 事件消费 E2E |
| FR-SEC-05 | §3.3, §6.7 | BuildSandboxPolicy（seccomp） | SCM-01~03 | TC-INT-06, TC-E2E-01 步骤 7 |
| FR-SEC-06 | §3.4, §6.6 | AuditLog, ExportAudit, VerifyAuditChain | AUD-01~06 | TC-UNIT-12~13, TC-INT-02, TC-E2E-03 |
| FR-SEC-07 | §3.5, §6.7 | SetNetworkPolicy, BuildSandboxPolicy（netfilter） | NET-01~05 | TC-INT-05, TC-E2E-01 步骤 8 |
| FR-SBX-01 | §3.7 | BuildSandboxPolicy | SBX-02 | TC-INT-03 |
| FR-SBX-02 | §3.7 | — | SBX-03 | TC-INT-04 |
| FR-SBX-03 | §3.5, §3.7 | SetNetworkPolicy | NET-02, SBX-01 | TC-INT-05 |
| FR-SBX-04 | §3.3, §3.7 | BuildSandboxPolicy | SCM-02, SBX-04 | TC-INT-06 |
| FR-SBX-05 | §3.7 | — | SBX-04 | TC-INT-07 |
| FR-SBX-06 | §3.7 | — | SBX-07 | TC-INT-09 |
| FR-SBX-07 | §3.7, §6.2 | — | SBX-05 | TC-INT-08 |
| NFR-S-01 | §8.4 | — | 全部 CAP/SCM/NET/SBX | TC-SEC-01 |
| NFR-S-02 | §8.4 | RequestConfirm | CFM-01~04 | TC-SEC-02 |
| NFR-S-03 | §3.4 | AuditLog, VerifyAuditChain | AUD-01~04 | TC-UNIT-12~13, TC-SEC-03 |

---

## 附录 B：worker 机部署说明

**目标机器**：SpacemiT K3，`10.0.90.243`，用户 `bianbu`，工作路径 `/home/bianbu/bianbu-agentos`

```bash
# 非交互式连接（sshpass 已在 AGENTS.md 说明）
sshpass -p 'bianbu' ssh -o StrictHostKeyChecking=no bianbu@10.0.90.243 \
  'cd /home/bianbu/bianbu-agentos && bash tests/smoke_test.sh'

# 传送文件
sshpass -p 'bianbu' scp -o StrictHostKeyChecking=no \
  tools/hermes-security-adapter/bianbu_security_client.py \
  bianbu@10.0.90.243:/home/bianbu/bianbu-agentos/tools/

# 已确认可用的内核特性（worker K3）
# cgroup2=yes, seccomp=yes, gnome-keyring=running
# bwrap：已在 K3 验证可用（非特权沙箱），作为 Phase 1 文件/namespace 隔离主方案
# overlayfs：需 root/CAP_SYS_ADMIN → 不作为方案，bwrap 已覆盖文件隔离需求
# TEE：无 /dev/tee* → 软件 Key Vault（gnome-keyring + age 加密文件）

# 验证 bwrap 可用性
bwrap --version
bwrap --ro-bind /usr /usr --tmpfs /tmp --unshare-all --die-with-parent -- /bin/true && echo "bwrap OK"
```
