# Bianbu Next 概要设计说明书（HLD）

| 项 | 内容 |
|----|------|
| 文档编号 | BN-HLD-001 |
| 版本 | V1.0 |
| 来源 | 基于 PRD V0.9 + SRS（BN-SRS-001） |
| 日期 | 2026-07-07 |
| 状态 | 待评审 |

---

## 1. 引言

### 1.1 目的
定义 Bianbu Next 的系统级架构：组件划分、进程/服务拓扑、数据流、通信机制、部署视图与关键设计决策，作为 API 定义与详细设计的输入。

### 1.2 设计原则
- **底座而非应用**：以系统常驻服务 + 内核安全机制 + 用户态 SDK/CLI + GUI 面板存在。
- **层间契约化**：六层仅经 D-Bus 服务接口与 AI HAL 契约交互，禁止跨层直接依赖实现。
- **本地优先**：P0 能力离线可用，云端为授权增强。
- **安全内生**：安全不是旁路，权限校验/沙箱/审计贯穿调用链（SRS FR-SEC/SBX 全程）。
- **RISC-V 软硬协同**：AI 推理经 HAL 收敛硬件差异，便于 K3/K5/K7 演进。

---

## 2. 系统总体架构

### 2.1 分层架构（对应 PRD 六层）
```
┌─────────────────────────────────────────────────────────┐
│ L6 AI 应用生态层   Agent Hub / 签名 / 更新 / 仪表盘 (ECO)   │
├─────────────────────────────────────────────────────────┤
│ L5 自然交互与应用框架  Intent/ASR/TTS/DCO/OCR/VEC/SKL/APP  │
│         + 跨层能力  Memory(MEM) · Calendar(CAL)           │
├─────────────────────────────────────────────────────────┤
│ L4 开发者工具链    SDK / CLI / bench / doctor              │
├─────────────────────────────────────────────────────────┤
│ L3 高性能运行时    Lifecycle / Sandbox(SBX) / Ckpt / Monitor│
├─────────────────────────────────────────────────────────┤
│ L2 AI 能力与调度   AI HAL / 模型管理 / 并行推理 / 端云 / KV │
├─────────────────────────────────────────────────────────┤
│ L1 内生安全与审计  Capability / seccomp / 审计链 / 网络策略 │
├─────────────────────────────────────────────────────────┤
│ HW  RISC-V K3/K5/K7 · AI 核 · 统一内存 · TEE · PMU         │
└─────────────────────────────────────────────────────────┘
   贯穿：D-Bus 系统总线 · 可观测/审计 · 权限校验
```

### 2.1.1 架构范式：借鉴 Android System Services + Binder IPC
Bianbu Next **借鉴 Android 的 System Services + Binder IPC 模式**，将系统能力沉淀为一组常驻「系统服务」，客户端（Apps/Agents/BiBit/CLI/SDK）通过统一 IPC 总线按接口访问，服务之下经 HAL 屏蔽硬件差异。区别在于：Android 用 Binder，Bianbu Next 采用 **D-Bus 作为 IPC 总线**（Linux 原生、标准化、可审计），并在服务层内生安全与审计。

```
┌────────────────────────────────────────────────────────────────┐
│                     Clients (Apps, Agents, BiBit)               │
│                                                                  │
│   ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐        │
│   │ CLI Tool │  │  SDK     │  │ BiBit UI │  │  Agent   │        │
│   └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘        │
│        │             │             │             │              │
│        └─────────────┴──────┬──────┴─────────────┘              │
│                             ▼                                    │
│                    ┌─────────────────────┐                      │
│                    │   DBus System Bus   │  ← 类比 Android Binder│
│                    └─────────────────────┘                      │
│                             │                                    │
│   ┌─────────────┬───────────┼───────────┬─────────────┐         │
│   ▼             ▼           ▼           ▼             ▼         │
│ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐    │
│ │io.bianbu│ │io.bianbu│ │io.bianbu│ │io.bianbu│ │io.bianbu│    │ System
│ │.AIHal   │ │.Runtime │ │.Security│ │.Skill   │ │.Memory  │    │ Services
│ └─────────┘ └─────────┘ └─────────┘ └─────────┘ └─────────┘    │ (类比 Android
│       │           │           │           │             │       │  System Services)
│       └───────────┴───────────┴───────────┴─────────────┘       │
│                             ▼                                    │
│                ┌──────────────────────────┐                     │
│                │  HAL (Hardware Abstraction)│                    │
│                │   ├─ AI HAL               │                     │
│                │   ├─ Security HAL         │                     │
│                │   └─ IO HAL               │                     │
│                └──────────────────────────┘                     │
│                             ▼                                    │
│                ┌──────────────────────────┐                     │
│                │  Linux Kernel（主线 + K3 驱动）│                │
│                └──────────────────────────┘                     │
│                             ▼                                    │
│                ┌──────────────────────────┐                     │
│                │  RISC-V K3/K5/K7 硬件      │                    │
│                │  CPU + AI 核 + 统一内存    │                     │
│                └──────────────────────────┘                     │
└────────────────────────────────────────────────────────────────┘
```

**与 Android 的对应关系**：

| Android 概念 | Bianbu Next 对应 | 说明 |
|--------------|------------------|------|
| System Services（ActivityManager/PackageManager…） | `io.bianbu.*` 系统服务（AIHal/Runtime/Security/Skill/Memory…） | 系统能力常驻服务化，客户端按接口调用 |
| Binder IPC | **D-Bus System Bus** | IPC 总线；D-Bus 为 Linux 原生、标准化、天然可审计 |
| ServiceManager（服务发现） | D-Bus 名称注册（`io.bianbu.*` 命名空间） | 客户端按 well-known name 寻址服务 |
| HAL（hardware/interfaces） | AI HAL / Security HAL / IO HAL | 屏蔽 K3 硬件差异（推理后端、密钥、IO） |
| Permission + AppOps | Capability Registry + Confirm Gatekeeper（securityd） | 权限模型内生于服务层 |
| SELinux/沙箱 | seccomp-bpf + cgroup + 沙箱（SBX） | 内核级隔离 |
| Zygote/进程模型 | bianbu-agent-runtimed 沙箱进程 | Agent 作为受隔离执行单元 |

**设计取舍**：相比 Android 自研 Binder，选用 D-Bus 免去内核态驱动依赖、贴合 LXQt/systemd 生态、便于审计与调试（ADR-01）；高频/大吞吐路径（如推理 token 流）在 D-Bus 之外走共享内存/UNIX socket 旁路，规避 D-Bus 序列化开销。

### 2.2 进程/服务拓扑
每个 L1–L3 能力域落为一个 systemd 管理的常驻 D-Bus 系统服务（daemon），彼此经 D-Bus 通信；L4/L5 多为用户态库/进程；Agent 运行在各自沙箱进程中。

| 服务进程 | 类型 | 关键职责 | 提供接口 |
|----------|------|----------|----------|
| `bianbu-agent-runtimed` | system daemon | Agent 生命周期、沙箱编排、checkpoint、资源监控 | io.bianbu.Runtime |
| `bianbu-aihald` | system daemon | 模型加载/缓存/推理/嵌入、并行调度、端云决策、KV 管理 | io.bianbu.AIHal |
| `bianbu-securityd` | system daemon | 权限校验、确认门禁、审计哈希链、网络白名单 | io.bianbu.Security |
| `bianbu-memoryd` | system daemon | 记忆读写/语义检索/隔离/淘汰 | io.bianbu.Memory |
| `bianbu-skilld` | system/user daemon | Skill 注册/发现/调用、MCP 网关 | io.bianbu.Skill |
| `bianbu-intentd` | user daemon | 意图分类/槽位/多轮上下文 | io.bianbu.Intent |
| `bianbu-calendard` | user daemon | 日历读写/提醒 | io.bianbu.Calendar |
| `bianbu-indexerd` | user daemon | 全盘 inotify 监视、向量索引构建/检索、知了 | (内部, 经 Skill/Intent 暴露) |
| Agent 进程 | sandboxed | 承载单个 Agent | 经 SDK 调用上述服务 |
| BiBit | 首方应用 | 交互入口（独立产品） | 消费全部底座接口 |

### 2.3 关键跨层数据流

**语音指令端到端（对应 SRS FR-ASR-04 ≤1.5s）**
```
麦克风 → intentd(ASR: Whisper.cpp) → intentd(意图分类 0.5B) 
      → securityd(权限校验) → skilld(Skill 路由/MCP)
      → aihald(推理 llama.cpp, 端云决策) 
      → agent-runtimed(在沙箱内执行工具/操控)
      → securityd(审计记账) → TTS(Piper) → 用户
```
关键路径预算分解（目标值，[TBD-15] baseline 锁定）：ASR ≤500ms + 意图 ≤200ms + 推理首 token ≤200ms + 工具执行 + TTS，串行总和须压到 ≤1.5s，靠模型常驻缓存与流式输出达成。

**Agent 启动（对应 FR-RTE-02 ≤200ms）**
```
CLI/GUI → agent-runtimed.Start(agent_id)
  → securityd 加载 Capability + 生成 seccomp/netfilter 策略
  → agent-runtimed 创建沙箱(chroot+overlayfs+cgroup+ns+cap drop)
  → 注入 SDK runtime, 触发 on_start
  → 状态机 → RUNNING, 审计记录
```

### 2.4 通信机制
- **同步调用**：D-Bus method call（权限校验、模型加载、Skill 调用）。
- **流式**：推理 token 流经 D-Bus signal 或专用 fd/pipe（大吞吐走共享内存/UNIX socket，避免 D-Bus 负载）。
- **事件**：状态变更、资源告警、安全告警经 D-Bus signal 广播给 GUI/审计。
- **Agent 间 IPC**（FR-RTE-15）：经 agent-runtimed 中转的受控消息总线，按 Capability 授权可达。

---

## 3. 组件分解（按层）

### 3.1 L1 安全审计（bianbu-securityd）
| 子组件 | 职责 | 关联 FR |
|--------|------|---------|
| Capability Registry | 权限声明/授权持久化，两维模型(域×L1-L4)+三级信任 | FR-SEC-01/02 |
| Confirm Gatekeeper | 敏感操作弹窗门禁（always/once_per_session/trusted） | FR-SEC-03 |
| Syscall Filter Builder | 生成 seccomp-bpf 策略（黑名单+能力裁剪） | FR-SEC-05/SBX-04/05 |
| Audit Chain Engine | 防篡改哈希链（prev_hash 链接），导出+校验 | FR-SEC-06 |
| Network Policy | netfilter 白名单编译与下发，学习模式 | FR-SEC-07/SBX-03/SET-18 |
| Token Budget Meter | 用量计量与超限暂停触发 | FR-SEC-04 |

### 3.2 L2 AI 能力与调度（bianbu-aihald）
| 子组件 | 职责 | 关联 FR |
|--------|------|---------|
| AI HAL | 统一推理接口，后端插件（llama.cpp/ONNX/vLLM/Ollama 兼容） | FR-AI-09~13 |
| Model Manager | 注册/发现、单实例共享加载、缓存、热切换、卸载 | FR-AI-01~04 |
| Parallel Scheduler | 多模型并发、动态批处理、推理队列、抢占 | FR-AI-05~08 |
| Endpoint Decision | 本地置信度评估、隐私检测、云端透明路由 | FR-AI-18~20 |
| KV Cache Manager | 池化、LRU、跨会话复用 | FR-AI-22~24 |
| Task-Aware Scheduler（预研） | 任务分类与算力分配、统一内存优化 | FR-AI-14~17 |
| Key Vault | TEE 密钥存储 | FR-AI-21 |

### 3.3 L3 运行时（bianbu-agent-runtimed）
| 子组件 | 职责 | 关联 FR |
|--------|------|---------|
| Lifecycle FSM | 状态机与 Start/Pause/Resume/Stop/Terminate | FR-RTE-01~06 |
| Sandbox Manager | chroot+overlayfs+cgroup v2+ns+cap drop 编排 | FR-SBX-01~08 |
| Checkpoint/Restore | 自动/手动快照、崩溃恢复、存储保留策略 | FR-RTE-07~11 |
| Resource Monitor | CPU/内存/IO 实时统计、超限暂停、历史导出 | FR-RTE-12~14 |
| Agent IPC Bus | 受控 Agent 间消息 | FR-RTE-15 |

### 3.4 L4 工具链（用户态）
SDK（Python 首发，C++ 远期）、CLI（bianbu-agent/bianbu-skill）、bench、doctor。经 D-Bus 客户端封装访问 L1–L3。

### 3.5 L5 交互框架 + 跨层
| 子组件 | 进程 | 关联 FR |
|--------|------|---------|
| Intent Engine | intentd | FR-INT-01~04 |
| Speech（ASR/TTS） | intentd | FR-ASR-01~04 |
| Doc2MD / OCR | 库/服务（MinerU/PaddleOCR） | FR-DCO/OCR |
| Vector Indexer / 知了 | indexerd | FR-VEC-01~08 |
| Skill Registry + MCP Gateway | skilld | FR-SKL-01~09 |
| App Control（DBus/AT-SPI/键盘/视觉） | 库 + skilld | FR-APP-01~05 |
| Memory Service | memoryd | FR-MEM-01~08 |
| Calendar Service | calendard | FR-CAL-01~05 |

### 3.6 L6 生态（云端 + 客户端）
Agent Hub 后端（托管/审核/签名验证/下载）、开发者后台、度量仪表盘（匿名遥测）、客户端安装器。P2。

---

## 4. 关键设计决策（ADR 摘要）

| 编号 | 决策 | 理由 | 备选/权衡 |
|------|------|------|-----------|
| ADR-01 | IPC 用 D-Bus，大吞吐流走共享内存/UNIX socket | 标准化、LXQt 原生、可审计；D-Bus 不适合高频 token 流 | gRPC（重）、纯 socket（缺发现） |
| ADR-02 | 沙箱 Phase1 用 chroot+cgroup+seccomp（无守护容器） | 轻量、冷启动 ≤200ms、无 dockerd 依赖 | 直接上容器（开销大，违反 NFR-P-01） |
| ADR-03 | AI 统一 HAL + 后端插件 | 引擎可切换不改上层，适配 RISC-V 演进 | 直接绑定 llama.cpp（锁死） |
| ADR-04 | 权限两维模型（域×L1-L4）单一实现 | 消解 PRD 多套分类矛盾 | 维持多套（不一致） |
| ADR-05 | 记忆=LanceDB(向量)+KV(元数据)双存储 | 复用 VEC 层，语义+精确兼得 | 纯向量（精确查弱）[TBD-5] |
| ADR-06 | 审计防篡改用哈希链（非区块链） | 轻量、可离线验证、满足 NFR-S-03 | 区块链（过重） |
| ADR-07 | 端云默认本地，云端授权+隐私检测门控 | 满足 CO-05/NFR-Q-04 | 默认云端（隐私风险） |
| ADR-08 | 模型单实例共享 + KV 复用 | 满足 FR-AI-02/07 内存与延迟 | 每 Agent 独占（内存爆炸） |

---

## 5. 部署与运行视图

### 5.1 软件包与目录
```
/usr/lib/bianbu/                 服务二进制与后端插件
/usr/lib/bianbu/models/          系统内置模型
~/.local/share/bianbu-agents/<id>/   Agent 私有目录（沙箱根）
        ├─ memory/               记忆存储 [TBD-6]
        ├─ ckpt/ (→ /var/lib/bianbu/checkpoints/)
        └─ rootfs overlay
/var/lib/bianbu/checkpoints/     全局 checkpoint
/var/log/bianbu/audit/           审计哈希链
/etc/bianbu/                     系统策略、白名单、端云配置
```

### 5.2 服务启动顺序（systemd 依赖）
```
securityd（信任根，最先）→ aihald → agent-runtimed → memoryd/skilld/intentd/calendard/indexerd → GUI/BiBit
```

### 5.3 可观测性
统一 trace_id 贯穿：intent→schedule→infer→exec→audit。资源监控与推理计量经 signal 推送 GUI；审计链独立持久化。

---

## 6. 安全架构映射

| 隔离级别 | 阶段 | 组件 | SRS |
|----------|------|------|-----|
| Level 1 进程沙箱 | Phase1 P0 | Sandbox Manager（chroot/overlayfs/cgroup/seccomp/netfilter/cap drop） | FR-SBX-01~07 |
| Level 2 命名空间 | Phase2 P1 | + PID/NET/MNT/UTS/IPC ns | FR-SBX-08 [TBD-9] |
| Level 3 容器 | P2 | Docker（可选） | 8.1 |
| Level 4 VM | P3 远期 | Firecracker/kata | 8.1 |

调用链安全门：每次 Skill/工具调用 → securityd 校验 Capability → 命中敏感则 Confirm Gatekeeper → 执行 → Audit Chain 记账。

---

## 7. 与外部系统集成
- **MCP Gateway**（skilld）：双向——对外暴露 Bianbu Skill 为 MCP 工具；对内允许调用外部 MCP 工具。
- **进迭时空社区 AI**：aihald 端云路由目标 + memoryd 备份 + 知了知识库来源，HTTPS+令牌，令牌存 Key Vault。
- **硬件**：AI HAL 经 K3 AI 核驱动；Key Vault 经 TEE [TBD-17]；bench 经 PMU。

---

## 8. 风险与设计约束回应
- RISC-V 成熟度 [TBD-14]：HAL 后端插件化隔离风险，M1 spike。
- 性能 baseline [TBD-15]：关键路径预算已在 2.3 分解，靠常驻缓存+流式达标。
- 选型待定 [TBD-16]：ADR 以接口收敛，选型变更不影响上层。

---

## 9. 实机校准（worker 10.0.90.243，2026-07-07）【V1.1 新增】

登录 worker 采集真实环境后，对 HLD 关键假设做校准。**结论：架构方向成立（现有实现印证了可行性），全栈自研、不复用现有实现，并修正三处硬约束。**

### 9.1 实测环境事实
| 维度 | 实测值 | 对设计的影响 |
|------|--------|--------------|
| 主机/SoC | `bianbu-spacemitk3deb1`，SpacemiT **A100（8×2.0GHz）+ X100（8×2.4GHz）** 16 核 riscv64 | 确认 K3 目标平台，CO-01 成立 |
| ISA | `rv64imafdcv...zve64d zvfh zvfhmin zvbb zvkned...`（**含 RVV 向量 + fp16 向量 + 向量密码**） | RVV/CPU 作回退层；本地推理主加速为 **IME+TCM**（定制 ggml-spacemit / spacemit-ep），本地推理**可行** |
| 内存 | 31Gi（≈32GB 统一内存），无 swap | 满足 4-8GB 本地模型 CO-07 |
| OS | **Bianbu 4.0.1**（VERSION_CODENAME=resolute），内核 6.18.3 riscv64 | 与"首版 Bianbu 4.x"一致 |
| AI 加速 | **IME+TCM**（A100=IME2+TCM，X100=IME1）为矩阵加速主通路；`/dev/ai_dma`、`/dev/aidma_list`；GPU=Imagination PowerVR（pvrsrvkm/img rgx） | **无独立 NPU**；本地 AI 经 IME/TCM（定制 llama.cpp+ggml-spacemit / onnxruntime+spacemit-ep），回退 RVV/CPU |
| TEE | **无** `/dev/tee*`、`/dev/optee*` | **[TBD-17] 落地：当前硬件无 TEE**，Key Vault 须降级为软件加密+文件权限方案 |
| 沙箱内核 | cgroup2=yes、seccomp=yes、**overlay 模块存在但无权限加载**、userns=n/a | seccomp/cgroup 可用；**overlayfs 需 root/CAP 或改用 bind-mount 方案**（修正 SBX-01） |
| 存储 | 根 `/dev/sda3` 117G（用 66%） | 充足 |
| 已装推理栈 | llama.cpp/ollama/onnx/torch/lancedb/whisper **均未安装**；cmake/clang 缺 | 本地推理栈需从零构建，M1 前必须 spike |
| Python | 系统 3.12；Hermes 自带 3.11 venv | SDK 目标 Python 版本需对齐 |

### 9.2 关键发现：已存在运行中的 Agent 平台
worker 上已部署并 `active (running)` 两个服务，是 Bianbu Agent 能力的**现有实现**。**注意：本项目不复用 agentforce/hermes-agent（见 AGENTS.md 复用边界）**，下表仅作**概念对照与方向印证**，说明目标能力已被验证可行，本设计据 PRD/SRS 自研，不桥接、不移植其代码或运行时：

| 现有资产 | 形态 | 概念对照（**仅参考，不复用**） |
|----------|------|----------------|
| `bianbu-agentforce.service` | `/opt/bianbu-agentforce/server.py`（FastAPI）+ 数字员工平台 | 印证 L5/L6 应用层与 BiBit 类入口方向 |
| `bianbu-agentforce-webui.service` | Node 服务 + vanilla-JS/React(JDUI) | 印证 GUI/WebUI 管理面板（SET-*）方向 |
| `hermes-agent`（`/usr/lib/hermes-agent`） | Python agent runtime，含 toolsets/skills/memory/cron/ACP/MCP | 概念对照 L3 运行时+L5 工具/技能；**不复用，自研** |
| ACP adapter（`acp_adapter/`） | Agent Client Protocol 适配（session/tools/permissions/auth/events） | 参考调用契约概念，本项目用自定义 SDK/Skill 契约 |
| toolsets（file/terminal/code_execution/browser/tts/cronjob/skill_manager/send_message/homeassistant） | Python 工具集 | 参考能力清单，对照 FR-APP/SKL/ASR，自研实现 |
| budget_config / website_policy | 预算与网络策略 | 参考策略概念，对照 FR-SEC-04/07，自研实现 |

**模型侧现实**：Hermes venv 仅含 `openai/anthropic/mcp/fastapi/pydantic`，支持 OpenAI/Anthropic/MiniMax/Kimi/OpenRouter/**Spacemit Engine** —— 当前是**云 LLM API 优先**，与 PRD"本地优先"相反（见 9.4 冲突）。

### 9.3 ADR 校准
| ADR | 原决策 | 校准后 |
|-----|--------|--------|
| ADR-01 IPC=D-Bus | 全 D-Bus | **修正**：L1–L3 系统服务走 D-Bus；对 Agent/WebUI **自研** HTTP/SSE + MCP 接入层（双通道）。参考了现有实现的接入形态，但不复用其代码 |
| ADR-02 沙箱 chroot+overlayfs | overlayfs 隔离 | **修正**：overlayfs 当前无法非特权加载 → Phase1 改用 **bind-mount + 只读挂载 + cgroup + seccomp**；overlayfs 作为可选增强（需内核/权限支持），见 LLD 3.2 |
| ADR-03 AI HAL 插件 | llama.cpp/ONNX/vLLM | **保留并强化**：本地 LLM=**定制 llama.cpp+ggml-spacemit**（IME/TCM），视觉/OCR=**onnxruntime+spacemit-ep**，另有 `CloudBackend`；回退 RVV/CPU（见 AGENTS.md 运行平台基线） |
| ADR-07 端云默认本地 | 本地优先 | **保留为目标**，现实差距：worker 无本地模型。M1 须用**定制 toolchain** 编 ggml-spacemit + 跑 GGUF 小模型以兑现本地优先 |
| ADR-06 Key Vault=TEE | TEE 存密钥 | **修正**：无 TEE → 软件方案（用户 keyring/加密文件 + 权限隔离），TEE 作为未来硬件增强 |

### 9.4 需求可行性冲突（转 SRS 核验）
1. **本地优先 vs 云端现状**：CO-05/NFR-P-05/P-10 要求本地推理，但 worker 无本地栈、现有平台云优先 → 需求成立但**未实现**，M1 关键路径。
2. **NPU 假设**：PRD 多处假设"AI 核/NPU"，实测为 RVV+AI-DMA+PowerVR，无独立 NPU → 性能预算 [TBD-15] 须在此硬件上重测。
3. **TEE 依赖**：FR-AI-21 依赖 TEE，硬件缺失 → 降级实现。

### 9.5 校准后服务拓扑（全部自研，不复用 agentforce/hermes）
```
应用层:  BiBit（自研首方应用）+ 自研 WebUI 管理面板（SET-*）
接入层:  自研 HTTP/SSE + MCP 接入 + SDK（Agent/WebUI 接入）
运行时:  bianbu-agent-runtimed（自研）承载 Agent + Skill/工具/cron
系统服务(自研, D-Bus): securityd / aihald / bianbu-agent-runtimed / memoryd / skilld / intentd / calendard / indexerd
硬件:    RVV + /dev/ai_dma + PowerVR，无 NPU/TEE
```
即：**全栈按 PRD/SRS 自研**——下层 D-Bus 系统服务提供安全/沙箱/本地推理/记忆，上层自研接入层与应用。worker 上的 agentforce/hermes 仅用于印证方向与校准硬件，**不作为实现来源**（见 AGENTS.md 复用边界）。

---
*BN-HLD-001 V1.1 · 输入 PRD V0.9 + BN-SRS-001 + worker 10.0.90.243 实测（2026-07-07）。内容由 AI 辅助生成。*
