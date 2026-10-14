# Bianbu Next 软件需求规格说明书（SRS）

| 项 | 内容 |
|----|------|
| 文档编号 | BN-SRS-001 |
| 版本 | V1.0 |
| 来源 | 基于 docs/Bianbu_Next_PRD_V0.9.md 需求分析 |
| 日期 | 2026-07-07 |
| 状态 | 待评审 |
| 评审维度 | 完整性 / 可测试性 / 无歧义性 / 一致性 / 可实现性 |

> 本 SRS 是 PRD V0.9 的工程化重述：将产品语言转为可实现、可验证的需求条目，补充接口需求、数据需求、约束与可追溯性。PRD 中标注的 `【待确认】` 项在本文件以 **[TBD-n]** 编号透传，不阻塞主体需求成立。

---

## 1. 引言

### 1.1 目的
本文件为 Bianbu Next（面向 RISC-V + AI 的 Agent 原生 OS 底座）定义完整软件需求，作为概要设计、API 定义、详细设计与测试的基线。读者对象：架构师、各层开发、测试、项目管理。

### 1.2 范围
覆盖 PRD V0.9 六层架构全部功能域：内生安全与审计（SEC/SBX）、AI 能力与调度（AI）、高性能运行时（RTE）、开发者工具链（SDK/CLI/BENCH/DOC）、自然交互（INT/ASR/DCO/OCR/VEC/SKL/APP）、AI 应用生态（ECO），以及跨层能力记忆服务（MEM）、日历联动（CAL）、系统设置（SET）。BiBit 作为首方应用仅覆盖其对底座的接口依赖，独立 PRD/SRS 另行编制。

### 1.3 定义与缩略语
沿用 PRD 12.1 术语表。补充本文件约定：
- **FR**：Functional Requirement 功能需求
- **NFR**：Non-Functional Requirement 非功能需求
- **IR**：Interface Requirement 接口需求
- **DR**：Data Requirement 数据需求
- **CO**：Constraint 约束
- **[TBD-n]**：待确认项，对应 PRD 12.2 编号

### 1.4 参考文件
- docs/Bianbu_Next_PRD_V0.9.md / Bianbu_Next_PRD_V0.9.html
- Bianbu_Next_PRD_V0.7_Review.md
- MCP 协议规范、D-Bus 规范、cgroup v2 / seccomp-bpf 内核文档

### 1.5 需求标识规范
需求 ID 形如 `FR-<域>-<序号>`，与 PRD 功能编号保持映射（见第 9 章可追溯性矩阵）。每条需求含：描述、优先级（P0/P1/P2）、验收标准、来源、依赖。

---

## 2. 总体描述

### 2.1 产品视角
Bianbu Next 是操作系统底座，非独立应用。它以一组系统级常驻服务（D-Bus 服务）+ 内核安全机制（seccomp/cgroup/namespace）+ 用户态 SDK/CLI + GUI 配置面板的形态存在，向上为 Agent/Skill/BiBit 提供运行时、AI 推理、安全、记忆、交互能力。

### 2.2 系统上下文
```
外部实体            与系统的交互
─────────           ─────────────────────────────
Agent 开发者    →   SDK/CLI 构建、打包、发布 Agent/Skill
终端用户        →   经 BiBit / GUI 面板使用与授权
安全审计员      →   审计日志查看、权限策略配置
进迭时空社区 AI →   云端模型路由、知识库、账号备份
RISC-V K3 硬件  →   AI 核推理、统一内存、TEE、PMU
第三方应用      →   通过 Skill/MCP 暴露能力为 Tool
```

### 2.3 用户角色
| 角色 | 关注点 | 主要用例 |
|------|--------|----------|
| Agent 开发者 | 开发效率、调试、发布 | SDK 编码、CLI 构建、bench/doctor、发布 Hub |
| 终端用户 | 好用、可控、隐私 | 语音/文本交互、授权确认、模型/Skill 管理 |
| 安全审计员 | 可追溯、可管控 | 审计日志、权限策略、网络白名单、告警 |
| 系统管理员 | 稳定、资源 | Agent 启停、资源监控、模型清理 |

### 2.4 总体约束（Constraints）
| ID | 约束 |
|----|------|
| CO-01 | 目标硬件为进迭时空 RISC-V K3/K5/K7；软件须在 RISC-V 上编译运行，[TBD-14] 依赖成熟度须验证 |
| CO-02 | 保持 Linux 主线兼容，AI 能力经 HAL 接入，不做内核侵入式改造 |
| CO-03 | 桌面基座为 LXQt（Wayland 优先，X11 兼容） |
| CO-04 | IPC 统一采用 D-Bus |
| CO-05 | 本地优先：P0 交互能力须离线可用，云端为可选增强且需用户授权 |
| CO-06 | 开源开放，选型优先开源组件 |
| CO-07 | 模型本地部署以 4-8GB 内存占用为主要约束（对话主模型） |

### 2.5 假设与依赖
- 假设 K3 提供 AI 核驱动、统一内存、可选 TEE、PMU 功耗接口。
- 依赖开源组件在 RISC-V 的可用性（llama.cpp/ONNX/Whisper.cpp/Piper/MinerU/PaddleOCR/BGE/LanceDB），见 [TBD-14]。

---

## 3. 功能需求（FR）

优先级沿用 PRD。验收标准均为可测量判据。「来源」列给出 PRD 对应编号以便追溯。

### 3.1 内生安全与审计（SEC / SBX）

| ID | 需求描述 | 优先级 | 验收标准 | 来源 |
|----|----------|--------|----------|------|
| FR-SEC-01 | 系统应校验 Agent 包 manifest 的存在与 ed25519 签名，解析权限声明（域+风险等级 L1–L4+确认策略） | P0 | 无 manifest 或签名无效的包被拒绝安装并给出原因；权限声明被正确解析入 Capability Registry | SEC-01 |
| FR-SEC-02 | 系统应提供能力注册表，记录每个 Agent 的声明能力与用户授权状态，支持 CLI 查询/修改与 GUI 展示 | P0 | CLI 可读写 Agent 权限；SET-03 面板可见并可撤销 | SEC-02 |
| FR-SEC-03 | 系统应在 Agent 执行敏感操作（L3/L4 或标记 confirm=always）前弹窗确认，支持 always/once_per_session | P0 | 未确认时操作被阻断；L4 强制二次确认 | SEC-03 |
| FR-SEC-04 | 系统应按 token_budget（单次≤10万、单日≤50万，单位 token）计量，超限由 securityd 执行 pause_and_notify 事件通知 | P1 | securityd 判定超限、发事件并记审计；Agent Runtime/agent 消费事件后暂停或终止；达单日上限后同样处理且次日本地 00:00 重置。[TBD-2][TBD-3] 计量口径 | SEC-04 |
| FR-SEC-05 | 系统应以 seccomp-bpf 拦截危险系统调用（reboot/swapon/kexec/init_module 等） | P0 | 黑名单调用被拒绝，恶意 Agent 无法关机/重启/加载内核模块 | SEC-05 |
| FR-SEC-06 | 系统应记录 Agent 全部受控操作到防篡改哈希链审计日志，支持查看与导出 | P0 | 日志可导出（JSON/CSV含哈希链），离线可验证完整性，篡改可检出 | SEC-06 |
| FR-SEC-07 | 系统应按声明域名实施网络白名单，默认 DROP | P1 | 未声明域名的出站请求被阻断并记审计 | SEC-07 |
| FR-SBX-01 | 系统应以 chroot+overlayfs 将 Agent 文件视图限制在其私有目录+声明只读挂载 | P0 | 访问声明范围外路径 100% 被拦截 | SBX-01 |
| FR-SBX-02 | 系统应以 cgroup v2 施加资源配额（默认 CPUQuota=100%,MemoryMax=2GB,IOWeight=100，可覆盖） | P0 | 内存超 MemoryMax 触发 OOM 保护（联动 FR-RTE-13） | SBX-02 |
| FR-SBX-03 | 沙箱应经 netfilter 实施网络白名单（与 FR-SEC-07 同源策略） | P0 | 未声明域名请求被阻断 | SBX-03 |
| FR-SBX-04 | 沙箱应加载 seccomp-bpf 过滤器（与 FR-SEC-05 同源黑名单） | P0 | 黑名单调用被拒且不影响宿主 | SBX-04 |
| FR-SBX-05 | 沙箱启动应执行 capability drop，去除非必要 Linux capabilities | P0 | 进程不持有 CAP_SYS_ADMIN 等危险能力 | SBX-05 |
| FR-SBX-06 | 沙箱环境应随 Agent 冷启动创建且不成为性能瓶颈 | P0 | 沙箱创建使冷启动总耗时仍 ≤200ms（联动 FR-RTE-02） | SBX-06 |
| FR-SBX-07 | 沙箱创建失败时系统应拒绝启动 Agent 并告警，严禁降级为无沙箱运行 | P0 | 失败时 Agent 不启动并记审计 | SBX-07 |
| FR-SBX-08 | （Phase 2）系统应支持 Level 2 命名空间隔离（PID/NET/MNT/UTS/IPC ns） | P1 | 各 ns 隔离生效。[TBD-9] 是否本阶段纳入 | 8.2.2 |

### 3.2 AI 能力与调度（AI）

| ID | 需求描述 | 优先级 | 验收标准 | 来源 |
|----|----------|--------|----------|------|
| FR-AI-01 | 系统应提供模型注册表，Agent 仅用模型名即可解析到具体模型 | P0 | 仅凭模型名调用成功，无需路径 | AI-01 |
| FR-AI-02 | 系统应对同一模型做单实例共享加载与内存缓存 | P0 | 第二次调用同模型延迟降低 ≥80% | AI-02 |
| FR-AI-03 | 系统应支持运行时模型热切换并释放原模型资源 | P1 | 目标 ≤2s，M1 baseline 后锁定 [TBD-15] | AI-03 |
| FR-AI-04 | 系统应支持模型卸载并释放 AI 核/内存资源 | P0 | 卸载后内存可见释放 | AI-04 |
| FR-AI-05 | 系统应支持多模型并发推理调度（按优先级/资源） | P1 | 3 模型并发延迟增加 ≤30% | AI-05 |
| FR-AI-06 | 系统应对同模型请求做动态批处理合并 | P1 | 高并发吞吐提升 ≥2x | AI-06 |
| FR-AI-07 | 系统应对同 Agent 连续调用复用 KV cache | P1 | 连续对话 token 生成延迟减少 ≥40% | AI-07 |
| FR-AI-08 | 系统应提供推理队列与高优先级抢占 | P1 | 抢占切换延迟 ≤100ms | AI-08 |
| FR-AI-09 | 系统应提供统一推理接口（AI HAL），后端引擎可切换而不改调用方代码 | P0 | 切换 llama.cpp/ONNX/vLLM 无需改 Agent 代码 | AI-09 |
| FR-AI-10 | AI HAL 应适配 llama.cpp 主引擎，支持 GGUF，利用 K3 AI 核 | P0 | 首 token ≤200ms（7B，目标值+baseline 锁定 [TBD-15]） | AI-10 |
| FR-AI-11 | AI HAL 应适配 ONNX Runtime 对接 K3 AI 核驱动 | P1 | ONNX 推理正确率 100% | AI-11 |
| FR-AI-12 | AI HAL 应（P2）适配 vLLM 高吞吐批处理 | P2 | 批处理吞吐 ≥50 tokens/s/请求 | AI-12 |
| FR-AI-13 | 系统应（P2）提供 Ollama API 兼容层 | P2 | 现有 Ollama 命令可运行 | AI-13 |
| FR-AI-14 | （预研）调度器应识别任务类型并分类 | P2 | 分类准确率 ≥95%（[TBD-11] 与 INT-01 口径） | AI-14 |
| FR-AI-15 | （预研）调度器应按任务类型分配算力 | P2 | 能效比相对纯 CPU 提升 ≥2x | AI-15 |
| FR-AI-16 | （预研）调度器应负载感知动态调度 | P2 | 高负载延迟增加 ≤50% | AI-16 |
| FR-AI-17 | （预研）应利用 K3 统一内存使 KV cache 不离开 AI 核内存区 | P2 | KV cache 访问延迟 ≤10ms | AI-17 |
| FR-AI-18 | 端云决策引擎应评估本地模型置信度以决定是否上云 | P1 | 置信度预测准确率 ≥85% | AI-18 |
| FR-AI-19 | 端云决策引擎应检测隐私敏感任务并强制本地执行 | P1 | 隐私检测准确率 ≥99% | AI-19 |
| FR-AI-20 | 系统应在本地不足时透明路由到云端（需预先授权） | P0 | 云端切换用户无感知 ≤1s | AI-20 |
| FR-AI-21 | 云端 API 密钥应经 K3 安全存储（TEE），普通 Agent 不可读 | P1 | 密钥不可被普通 Agent 读取 [TBD-17] | AI-21 |
| FR-AI-22 | 系统应池化管理 KV cache 内存分配/释放 | P1 | 内存碎片率 ≤10% | AI-22 |
| FR-AI-23 | KV cache 应支持 LRU 淘汰 | P1 | 淘汰决策延迟 ≤1ms | AI-23 |
| FR-AI-24 | 系统应（P2）支持相似 prefix 跨会话 cache 复用 | P2 | token 生成延迟减少 ≥30% | AI-24 |

### 3.3 高性能运行时（RTE）

| ID | 需求描述 | 优先级 | 验收标准 | 来源 |
|----|----------|--------|----------|------|
| FR-RTE-01 | 系统应实现 Agent 状态机（INSTALLED/RUNNING/PAUSED/STOPPED/TERMINATED）并对外可见 | P0 | 状态转换正确率 100%，非法转换被拒 | RTE-01 |
| FR-RTE-02 | 系统应支持 Agent 启动并分配隔离环境 | P0 | 冷启动 ≤200ms（含沙箱） | RTE-02 |
| FR-RTE-03 | 系统应支持暂停，可选保存内存快照 | P0 | Pause 响应 ≤100ms | RTE-03 |
| FR-RTE-04 | 系统应支持从暂停恢复 | P0 | Resume ≤100ms | RTE-04 |
| FR-RTE-05 | 系统应支持停止并释放资源 | P0 | Stop 响应 ≤200ms | RTE-05 |
| FR-RTE-06 | 系统应支持彻底终止并清理全部数据 | P0 | 清理完整性 100% | RTE-06 |
| FR-RTE-07 | 系统应周期性自动 Checkpoint | P1 | 保存 ≤500ms | RTE-07 |
| FR-RTE-08 | 系统应支持 CLI 手动 Checkpoint | P1 | 手动触发正确 | RTE-08 |
| FR-RTE-09 | 系统应支持从指定 checkpoint 恢复 | P1 | 恢复 ≤2s（含模型加载） | RTE-09 |
| FR-RTE-10 | 系统应在 Agent 崩溃后自动从最近存档恢复 | P1 | 崩溃恢复成功率 ≥95% | RTE-10 |
| FR-RTE-11 | 系统应管理 checkpoint 存储，默认保留最近 10 个 | P1 | 保留策略生效 | RTE-11 |
| FR-RTE-12 | 系统应实时统计每 Agent 的 CPU/内存 | P1 | 更新频率 ≤1s | RTE-12 |
| FR-RTE-13 | 系统应在 Agent 内存超 2GB 时自动暂停并通知 | P1 | 超限触发暂停+通知 | RTE-13 |
| FR-RTE-14 | 系统应（P2）导出运行历史资源数据（JSON/CSV） | P2 | 导出完整可用 | RTE-14 |
| FR-RTE-15 | 系统应提供 Agent 间通信总线（IPC） | P0 | Agent 间消息按权限可达/受限 | 4.2 L3 |

#### 3.3.1 Agent 循环引擎（LOOP，内建于运行时）
> 来源：HLD（BN-HLD-002）§11 Loop Engine。Loop Engine 内建于 Agent Runtime Executor，为平台级闭环机制（Agent 本质是循环体，闭环/反思/恢复须由平台保证而非各 Agent 自造）。补全 HLD→SRS 断链。PRD 建议增补 `LOOP` 编号前缀。

| ID | 需求描述 | 优先级 | 验收标准 | 来源 |
|----|----------|--------|----------|------|
| FR-LOOP-01 | 系统应实现 Agent 循环状态机 Plan→Execute→Observe→Reflect→Evaluate→(Retry/Replan)→Finish | P0 | 状态转换正确率 100%，非法转换被拒 | HLD §11.1 |
| FR-LOOP-02 | 循环每步应产生可观测事件并可触发可选 Checkpoint | P0 | 每步发 LoopStep 事件；关键节点 Checkpoint 生效（联动 FR-RTE-07） | HLD §11 |
| FR-LOOP-03 | 系统应支持多种终止条件：目标达成/超最大步数/超 token_budget/超时/用户取消/不可恢复错误 | P0 | 任一条件命中即终止并给出终止原因码 | HLD §11.2 |
| FR-LOOP-04 | 循环命中 L3/L4 敏感操作时应暂停等待用户确认（HITL） | P0 | 未确认不执行；确认后继续；拒绝则结束（联动 FR-SEC-03） | HLD §11.2 |
| FR-LOOP-05 | 系统应提供循环护栏：重复动作防抖、Reflect 偏离阈值触发 Replan、budget 成本护栏 | P1 | 重复动作被检测；偏离超阈触发 Replan；超预算终止（联动 FR-SEC-04） | HLD §11.2 |
| FR-LOOP-06 | 循环应在崩溃后从最近 Checkpoint 恢复并继续 | P1 | 恢复后从断点续跑，成功率 ≥95%（联动 FR-RTE-10） | HLD §11.2 |
| FR-LOOP-07 | （扩展）系统应支持不同 Workflow 策略的循环形态（单轮/多 Agent/DAG）及可插自定义评估器 | P2 | 可注册自定义 Evaluate/Reflect | HLD §11 扩展点 |

#### 3.3.2 工作区与 Harness（WS，内建于运行时）
> 来源：HLD（BN-HLD-002）§10 Harness & Workspace。runtimed 的 Workspace Manager + Sandbox Manager。补全 HLD→SRS 断链。PRD 建议增补 `WS` 编号前缀。

| ID | 需求描述 | 优先级 | 验收标准 | 来源 |
|----|----------|--------|----------|------|
| FR-WS-01 | 系统应为每个 Agent 提供独立 Workspace，以 bind-mount 限定文件视图 | P0 | 越界访问被拦截（复用 FR-SBX-01 判据） | HLD §10.1 |
| FR-WS-02 | 系统应支持修改前 Snapshot 与一键 Rollback，且与进程 Checkpoint 一致快照 | P1 | 回滚后文件+进程状态一致还原 | HLD §10.2 |
| FR-WS-03 | 系统应经 inotify 监听 Workspace 变更并增量更新索引 | P1 | 变更 10min 内入索引（联动 FR-VEC-07） | HLD §10.2 |
| FR-WS-04 | 系统应将 Agent 产物落 `artifacts/` 并可导出/预览 | P1 | 产物可经 WebUI 列出/导出 | HLD §10.2 |
| FR-WS-05 | Workspace 内代码执行应受 cgroup 限额与网络白名单约束 | P0 | 执行受限额；越白名单请求被阻断（联动 FR-SBX-02/03） | HLD §10.2 |
| FR-WS-06 | （扩展）系统应为代码类 Agent 提供 Code Graph 符号/依赖图 | P2 | 可查询符号与依赖影响面 | HLD §10.2 |
| FR-WS-07 | （Phase）overlayfs 写时复制增强 / 容器化强隔离作为可选项 | P2 | 具备条件时可启用，默认 bind-mount | HLD §10 扩展点 |

### 3.4 开发者工具链（SDK / CLI / BENCH / DOC）

| ID | 需求描述 | 优先级 | 验收标准 | 来源 |
|----|----------|--------|----------|------|
| FR-SDK-01 | 提供 Agent 基类，继承即得生命周期回调 | P1 | 继承基类即可定义可运行 Agent | SDK-01 |
| FR-SDK-02 | 提供 `@tool` 装饰器将函数注册为 Skill | P1 | 函数自动注册到 Skill Registry | SDK-02 |
| FR-SDK-03 | 提供权限声明 API，声明自动并入 manifest | P1 | 声明合并正确，与 5.1.3 模型一致 | SDK-03 |
| FR-SDK-04 | 提供记忆服务客户端（读写跨会话记忆） | P1 | 记忆读写 API 符合 MEM 契约 | SDK-04 |
| FR-SDK-05 | 封装系统能力（DBus）调用 | P1 | SDK 调用与原生 DBus 等效 | SDK-05 |
| FR-SDK-06 | 提供分级日志，自动关联 agent_id | P1 | 日志可在管理器按 Agent 查看 | SDK-06 |
| FR-SDK-07 | 提供 Python SDK 包 `bianbu-agent-sdk` | P1 | PyPI 可安装，示例可运行 | SDK-07 |
| FR-SDK-08 | （P2）提供 C++ SDK | P2 | 示例编译运行通过 | SDK-08 |
| FR-SDK-09 | `@tool(skill_package=True)` 一键生成 skill 包骨架 | P1 | 生成项目符合 Skill 包规范 | SDK-09 |
| FR-CLI-01..07 | 提供 init/build/install/run/logs/status/uninstall 命令 | P1 | 各命令按 5.4.3 验收；run 支持热重载，logs 支持 --follow | CLI-01~07 |
| FR-BENCH-01..06 | 提供延迟/吞吐/内存/功耗/多模型对比/报告导出 | P1(功耗P2) | 输出 ns 精度延迟、0.1 tokens/s、RSS/PSS、对比表、JSON/HTML | BENCH-01~06 |
| FR-DOC-01..04 | 提供环境/依赖/性能/权限诊断 | P1 | 输出检查清单与修复命令 | DOC-01~04 |

### 3.5 自然交互与应用框架（INT/ASR/DCO/OCR/VEC/SKL/APP）

| ID | 需求描述 | 优先级 | 验收标准 | 来源 |
|----|----------|--------|----------|------|
| FR-INT-01 | 意图分类应支持 16 类意图（清单见 PRD 5.5.2.1） | P1 | 标注集（每类≥50，共≥800）top-1 ≥90% [TBD-10] | INT-01 |
| FR-INT-02 | 应从输入提取槽位（文件名/路径/应用/时间段） | P1 | 槽位准确率 ≥85% | INT-02 |
| FR-INT-03 | 应支持多轮上下文指代解析 | P1 | 指代正确率 ≥80% | INT-03 |
| FR-INT-04 | 意图解析应可纯本地运行（Qwen2-0.5B 微调） | P1 | 延迟 ≤200ms | INT-04 |
| FR-ASR-01 | 应支持 Super+B 唤醒，可选唤醒词 | P1 | 按键唤醒立即响应 | ASR-01 |
| FR-ASR-02 | 应用 Whisper.cpp 做 ASR | P1 | 安静环境识别率 ≥95% | ASR-02 |
| FR-ASR-03 | 应用 Piper 做 TTS | P1 | MOS≥4.0（≥20人×≥30句） | ASR-03 |
| FR-ASR-04 | 语音指令端到端延迟 | P0 | ≤1.5s（目标值+baseline 锁定 [TBD-15]） | ASR-04 |
| FR-DCO-01 | 多格式文档转结构化 Markdown | P1 | 主流格式成功率 ≥95% | DCO-NV-01 |
| FR-DCO-02 | 用 MinerU2.5-Pro 解析 | P1 | OmniDocBench 子集(≥100)结构 F1≥0.90 | DCO-NV-02 |
| FR-DCO-03 | 送模型前自动转 MD 省 token | P1 | token 节省 ≥30% | DCO-NV-03 |
| FR-DCO-04 | （P2）批量转换 API | P2 | 并发数可配置 | DCO-NV-04 |
| FR-OCR-01 | 图像文字识别 | P1 | 中英混合识别率 ≥90% | OCR-01 |
| FR-OCR-02 | （P2）截图快速 OCR | P2 | 2s 内返回 | OCR-02 |
| FR-OCR-03 | 控件文字识别（操控 fallback） | P1 | 准确率 ≥85% | OCR-03 |
| FR-VEC-01 | 对指定目录建向量索引（仅检索用） | P1 | 支持增量更新 | VEC-01 |
| FR-VEC-02 | 自然语言语义搜索文件内容 | P1 | 检索延迟 ≤2s | VEC-02 |
| FR-VEC-03 | 文件管理器集成语义搜索入口 | P1 | 入口可见，结果可打开 | VEC-03 |
| FR-VEC-04 | 本地嵌入模型（BGE-small/nomic） | P1 | 嵌入延迟 ≤100ms | VEC-04 |
| FR-VEC-05 | LanceDB 向量库，支持百万级 | P1 | 插入 ≥1000 条/秒 | VEC-05 |
| FR-VEC-06 | 可选本地知识库「知了」 | P1 | ≥200 QA 对准确率 ≥80% | VEC-06 |
| FR-VEC-07 | inotify 全盘监视增量索引 | P1 | 新增文件 10 分钟内被索引 | VEC-07 |
| FR-VEC-08 | 搜索结果预览+相关性评分 | P1 | 片段高亮关键词 | VEC-08 |
| FR-SKL-01..04 | Skill 注册/发现/调用/MCP 集成 | P1 | 发现 ≤50ms；调用成功率 ≥99%；MCP Client 可访问 | SKL-01~04 |
| FR-SKL-05 | `.skill` 包格式（skill.toml+entry.py+permissions.json） | P1 | 合规包可解析安装 | SKL-05 |
| FR-SKL-06 | Skill 生命周期（装/更/卸/semver） | P1 | 各操作后状态正确 | SKL-06 |
| FR-SKL-07 | Skill 权限分级 L1–L4（统一 5.1.3） | P1 | 各级触发对应确认，L4 二次确认 | SKL-07 |
| FR-SKL-08 | Skill 沙箱执行（复用 SBX） | P1 | Skill 无法越权访问 | SKL-08 |
| FR-SKL-09 | Skill CLI（list/install/call/uninstall） | P1 | 命令执行正确，格式规范 | SKL-09 |
| FR-APP-01 | 应用操控优先 DBus 接口 | P1 | 受支持应用操控成功率 ≥95% | APP-01 |
| FR-APP-02 | AT-SPI 读取控件树并操作 | P1 | 标准桌面应用可操控 | APP-02 |
| FR-APP-03 | 快捷键模拟（ydotool/xdotool） | P1 | Wayland/X11 均可用 | APP-03 |
| FR-APP-04 | 视觉定位+OCR 兜底 | P1 | 识别准确率 ≥80% | APP-04 |
| FR-APP-05 | 四级 Fallback 链（3s 超时返回失败） | P1 | Fallback 逻辑正确 | APP-05 |

### 3.6 记忆服务（MEM）

| ID | 需求描述 | 优先级 | 验收标准 | 来源 |
|----|----------|--------|----------|------|
| FR-MEM-01 | 写入键值/文本记忆，自动关联 agent_id+时间戳 | P1 | 写入后可读回，字段完整 | MEM-01 |
| FR-MEM-02 | 按 key 精确读取 | P1 | 命中返回正确值，未命中返回空不报错 | MEM-02 |
| FR-MEM-03 | 文本记忆语义检索 top-k（复用 BGE） | P1 | 检索 ≤100ms；top-5 命中率 ≥80% | MEM-03 |
| FR-MEM-04 | 按 Agent 命名空间隔离 | P1 | 跨 Agent 访问 100% 拦截 | MEM-04 |
| FR-MEM-05 | 容量上限+LRU 淘汰 | P1 | 超限淘汰最久未访问，写入成功 [TBD-4] | MEM-05 |
| FR-MEM-06 | （P2）TTL 过期清理 | P2 | 到期不再被检索 | MEM-06 |
| FR-MEM-07 | （P2）云端备份/恢复（登录社区账号） | P2 | 新设备可恢复；未登录不可见 | MEM-07 |
| FR-MEM-08 | 记忆清理（按 Agent/卸载时） | P1 | 清理后不可检索，空间释放 | MEM-08 |

### 3.7 日历联动（CAL）

| ID | 需求描述 | 优先级 | 验收标准 | 来源 |
|----|----------|--------|----------|------|
| FR-CAL-01 | 接入本地日历后端读取日程 | P1 | 读取既有日程，标题/起止/地点完整 [TBD-8] | CAL-01 |
| FR-CAL-02 | 经确认创建日程 | P1 | 创建日程在日历应用可见 | CAL-02 |
| FR-CAL-03 | 自然语言日程查询 | P1 | 时间范围解析正确，返回匹配 | CAL-03 |
| FR-CAL-04 | 到点系统通知提醒，可选 TTS | P1 | 设定时间 ±30s 内触发 | CAL-04 |
| FR-CAL-05 | 日历读/写权限（L2，写需确认） | P1 | 未授权读写被拒并提示 | CAL-05 |

### 3.8 系统设置（SET）与生态（ECO）

| ID | 需求描述 | 优先级 | 验收标准 | 来源 |
|----|----------|--------|----------|------|
| FR-SET-01..05 | Agent 管理器：状态总览/启停/权限查改/详情/卸载 | P1 | 见 PRD 7.2 量化验收；[TBD-12] 余项定稿 | SET-01~05 |
| FR-SET-06..10 | AI 模型管理：列表/下载导入/切换/端云配置/卸载清理 | P1 | 见 PRD 7.3；热切换 ≤2s | SET-06~10 |
| FR-SET-11..14 | Skill 管理：列表/启停/权限查看/装卸 | P1 | 见 PRD 7.4；L3/L4 红色标记 | SET-11~14 |
| FR-SET-15..19 | 安全审计：日志查看/导出/策略/白名单/告警 | P1 | 见 PRD 7.5；导出含哈希链校验码 | SET-15~19 |
| FR-ECO-01..06 | Agent Hub/签名/更新/依赖/后台/仪表盘 | P2 | 见 PRD 5.6.2；遥测可关闭 | ECO-01~06 |

---

## 4. 非功能需求（NFR）

### 4.1 性能
| ID | 指标 | 目标 | 优先级 |
|----|------|------|--------|
| NFR-P-01 | Agent 冷启动（无模型） | ≤200ms | P0 |
| NFR-P-02 | Agent 空闲内存（不含模型） | ≤50MB/Agent | P0 |
| NFR-P-03 | BiBit 空闲内存增量 | ≤400MB | P0（[TBD] 移交 BiBit SRS） |
| NFR-P-04 | CPU 空闲占用 | ≤5% 单核 | P0 |
| NFR-P-05 | 语音端到端 | ≤1.5s（目标值+baseline 锁定 [TBD-15]） | P0 |
| NFR-P-06 | 语义搜索 | ≤2s | P1 |
| NFR-P-07 | 文档转 MD（10页 PDF） | ≤3s | P1 |
| NFR-P-08 | ASR（1s 语音） | ≤500ms | P1 |
| NFR-P-09 | 记忆检索 | ≤100ms | P1 |
| NFR-P-10 | 首 token（7B GGUF） | ≤200ms（目标值+baseline 锁定 [TBD-15]） | P0 |

### 4.2 可靠性
| ID | 指标 | 目标 |
|----|------|------|
| NFR-R-01 | Agent 运行时可用性 | 99.9% |
| NFR-R-02 | 长时运行（7天） | 无泄漏/无崩溃 |
| NFR-R-03 | 崩溃恢复成功率 | ≥95% |

### 4.3 安全
| ID | 指标 | 目标 |
|----|------|------|
| NFR-S-01 | 权限越权拦截率 | 100% |
| NFR-S-02 | 敏感操作确认率 | 100% |
| NFR-S-03 | 审计日志完整性 | 100%（哈希链可验证） |

### 4.4 其他质量属性
| ID | 属性 | 需求 |
|----|------|------|
| NFR-Q-01 | 可移植性 | 全栈须在 RISC-V K3 编译运行（[TBD-14]） |
| NFR-Q-02 | 可维护性 | 六层解耦，层间仅经 DBus/HAL 契约交互 |
| NFR-Q-03 | 可观测性 | 全链路轨迹追踪，审计+资源+推理计量可查 |
| NFR-Q-04 | 隐私合规 | 敏感数据强制本地；遥测默认可关闭（[TBD] 个保法合规细则） |
| NFR-Q-05 | 兼容性 | Wayland 优先，X11 兼容；MCP 行业标准兼容 |
| NFR-Q-06 | 国际化/无障碍 | 中英文；GUI 满足基本 a11y（待细化） |

---

## 5. 接口需求（IR）

### 5.1 D-Bus 系统服务（详见 API 文档）
| 服务名 | 职责 | 对应需求 |
|--------|------|----------|
| `io.bianbu.Runtime` | Agent 生命周期与 checkpoint | FR-RTE-* |
| `io.bianbu.AIHal` | 模型加载/推理/嵌入 | FR-AI-* |
| `io.bianbu.Security` | 权限校验/审计/网络策略 | FR-SEC-*/SBX-* |
| `io.bianbu.Memory` | 记忆读写/检索 | FR-MEM-* |
| `io.bianbu.Skill` | Skill 注册/发现/调用 | FR-SKL-* |
| `io.bianbu.Calendar` | 日历读写/提醒 | FR-CAL-* |
| `io.bianbu.Intent` | 意图解析/槽位 | FR-INT-* |

### 5.2 外部接口
- MCP 协议：对外暴露 Bianbu Skill 为 MCP 工具，兼容 MCP Client。
- 云端：进迭时空社区 AI 服务（模型路由、知识库、账号备份），HTTPS + 授权令牌。
- 硬件：K3 AI 核驱动、统一内存、TEE、PMU 功耗接口。

### 5.3 用户接口
- CLI：`bianbu-agent`、`bianbu-skill` 命令族。
- GUI：系统设置 Agent OS 配置面板（SET-01~19）。
- 语音/文本：经 BiBit（独立产品）作为首方入口。

---

## 6. 数据需求（DR）

| ID | 数据实体 | 存储 | 关键字段 | 需求 |
|----|----------|------|----------|------|
| DR-01 | Agent Manifest / Capability | Capability Registry | id,version,signature,permissions[domain,risk_level,confirm,scope] | FR-SEC-01/02 |
| DR-02 | 审计日志 | 哈希链日志存储 | ts,agent_id,op_type,target,result,prev_hash,hash | FR-SEC-06 |
| DR-03 | Checkpoint | `/var/lib/bianbu/checkpoints/` | agent_id,ckpt_id,ts,state_blob | FR-RTE-07~11 |
| DR-04 | 记忆条目 | LanceDB(向量)+KV[TBD-5] | agent_id,key,text,vector,ttl,ts | FR-MEM-* |
| DR-05 | 模型注册表 | 本地元数据库 | name,version,path,format,size,status | FR-AI-01 |
| DR-06 | 文件向量索引 | LanceDB | path,chunk,vector,mtime | FR-VEC-* |
| DR-07 | Skill 包 | `.skill` 目录 | skill.toml,entry,permissions.json | FR-SKL-05 |
| DR-08 | 资源计量 | 时序统计 | agent_id,cpu,mem,io,ts | FR-RTE-12 |
| DR-09 | Agent 私有目录 | `~/.local/share/bianbu-agents/<id>/` | 沙箱根 + memory/ + ckpt | FR-SBX-01 |

存储路径与 KV 选型见 [TBD-5][TBD-6]。

---

## 7. 待确认事项（TBD 透传）

沿用 PRD 12.2 的 19 项，编号 [TBD-1..19] 与之一致。不阻塞需求成立，但影响以下：
- 阻塞可实现性最终确认：[TBD-14] RISC-V 成熟度、[TBD-15] 性能 baseline、[TBD-16] 选型截止、[TBD-17] TEE。
- 阻塞数据/接口细化：[TBD-4][TBD-5][TBD-6] 记忆存储、[TBD-8] 日历后端。
- 阻塞测试集构建：[TBD-10][TBD-11] 意图语料与口径、[TBD-12] SET 验收定稿。

---

## 8. 假设、风险与优先级基线

| 风险 | 影响 | 缓解 |
|------|------|------|
| RISC-V 组件不可用/需大量移植 | 阻断 AI 层交付 | M1 前置做 [TBD-14] 成熟度验证与 spike |
| 激进性能指标不达标 | P0 验收失败 | 两段式：目标值→baseline 锁定 |
| AI 工程仅 2 人 | 第二层进度风险 | [TBD-13] 评估配比/外部支持 |
| 选型全待定 | 设计返工 | [TBD-16] 设决策截止日 |

优先级基线：**Phase1 P0**（SEC/SBX/RTE/AI HAL+llama.cpp/AI-20）→ **Phase2 P1**（MEM/VEC/CAL/SDK/CLI/交互）→ **Phase3 P1/P2**（ECO/异构调度/优化）。

---

## 9. 需求可追溯性矩阵（RTM 摘要）

| PRD 编号段 | SRS FR 段 | 下游（HLD 组件） |
|------------|-----------|------------------|
| SEC-01~07 / SBX | FR-SEC-01~07 / FR-SBX-01~08 | 安全审计服务、沙箱管理器 |
| AI-01~24 | FR-AI-01~24 | AI HAL、模型管理器、调度器、端云引擎、KV 管理器 |
| RTE-01~14 | FR-RTE-01~15 | 运行时服务、Checkpoint 管理器、资源监控 |
| SDK/CLI/BENCH/DOC | FR-SDK/CLI/BENCH/DOC | 开发者工具链 |
| INT/ASR/DCO/OCR/VEC/SKL/APP | FR-INT.../APP | 交互框架、Skill Registry、检索引擎、操控引擎 |
| MEM/CAL | FR-MEM/CAL | 记忆服务、日历服务 |
| SET/ECO | FR-SET/ECO | 配置面板、生态后端 |

（完整逐条 RTM 在详细设计阶段维护为独立表。）

---

## 10. 五维评审自检

| 维度 | 结论 | 说明 |
|------|------|------|
| 完整性 | ✅ | 覆盖 PRD V0.9 全部功能域 + NFR/IR/DR/约束；MEM/CAL/SBX 已成条目 |
| 可测试性 | ✅ | 每条 FR 含可测量验收；主观项已量化（MOS/F1/QA 集） |
| 无歧义性 | ✅ | 权限模型两维统一、token 单位明确、意图清单枚举 |
| 一致性 | ✅ | FR 与 PRD 编号双向可追溯；SBX 与 SEC/RTE 同源策略；延迟指标对齐 NFR |
| 可实现性 | ⚠️ | 主体可实现；最大剩余风险为 [TBD-14] RISC-V 成熟度与 [TBD-15] 性能 baseline，须 M1 前 spike 验证 |

---

## 11. 需求可行性核验（worker 10.0.90.243 实测，2026-07-07）【V1.1 新增】

登录真实 K3 worker 后逐项核验需求是否 OK。**总体结论：需求整体成立且合理，无需删改功能条目；但 5 项需求的"实现前提"须调整，2 项性能指标须在本硬件重新 baseline。**

### 11.1 判定汇总
| 需求域 | 判定 | 依据 |
|--------|------|------|
| FR-SEC-01~07（安全审计） | ✅ OK | seccomp/cgroup2 内核可用；自研实现（现有 website_policy/budget_config 仅作概念参考，不复用） |
| FR-SBX-01（文件隔离） | ⚠️ 调整实现 | overlayfs 非特权不可加载 → 改 bind-mount 方案（LLD 11.1），需求不变 |
| FR-SBX-02~07 | ✅ OK | cgroup v2 / seccomp / cap drop 均可用 |
| FR-AI-09~13（AI HAL） | ✅ OK（前提） | RVV+fp16 向量齐备，llama.cpp 理论可行；**须 M1 编译验证** |
| FR-AI-10（首 token ≤200ms） | ⚠️ 重定 baseline | 无 NPU，靠 A100/X100+RVV，200ms 需实测，勿沿用 NPU 假设 |
| FR-AI-21（TEE 密钥） | ⚠️ 降级实现 | 无 /dev/tee → 软件 keyring/加密文件（LLD 11.3），需求保留 |
| FR-AI-18~20（端云决策） | ✅ OK | 多云 provider 可行性已被现有平台印证；自研端云引擎，本地侧待补 |
| FR-RTE-*（运行时） | ✅ OK | 方向经 hermes-agent 印证可行；本项目自研运行时，不桥接 |
| FR-ASR-04（语音 ≤1.5s） | ⚠️ 重定 baseline | Whisper/Piper 未装，须在 RVV 实测链路 |
| FR-MEM-*（记忆） | ✅ OK | 分层记忆方向经 hermes 印证；自研 memoryd，LanceDB RVV 待验 |
| FR-VEC-*（检索） | ✅ OK（前提） | 依赖 BGE/LanceDB 在 RVV 可用性，待验 |
| FR-SKL/APP（技能/操控） | ✅ OK | hermes toolsets 印证能力清单可行；自研 skilld 与操控链，不复用 |
| FR-CAL-*（日历） | ✅ OK | LXQt 环境，后端选型 [TBD-8] 仍待定 |
| FR-INT-*（意图） | ✅ OK（前提） | 依赖 Qwen2-0.5B 本地推理，随 AI HAL 落地 |
| NFR 性能 P0 项 | ⚠️ | NFR-P-05/P-10 须在本硬件 baseline 后锁定 |

### 11.2 需求是否"OK"的结论
- **功能需求**：**OK**。全部 FR 在目标硬件上语义成立，且 worker 已有 hermes-agent/agentforce **印证了 Agent OS 方向的可实现性**——但本项目**不复用**其实现（见 AGENTS.md 复用边界），交互/工具/记忆/技能等均按 PRD/SRS 自研，现有平台仅作概念参考。
- **非功能需求**：**基本 OK，2 项待实测**。安全/可靠性需求成立；性能类 NFR-P-05（语音≤1.5s）、NFR-P-10（首 token≤200ms）**不能在纸面确认**，必须在此 SoC（无 NPU、RVV+AI-DMA）实测后锁定，当前维持"目标值+baseline 锁定"两段式。
- **约束**：CO-01（RISC-V K3）✅ 实测确认；CO-05（本地优先）**方向成立但当前未实现**——worker 现状是云优先、无本地推理栈，M1 必须补齐本地 llama.cpp(RVV) 才能兑现该约束。

### 11.3 阻断项与前置动作（M1 前必做）
1. **[TBD-14] 本地推理验证**：在 worker 编译 llama.cpp(RISCV_VECTOR)，跑 GGUF 7B/0.5B，确认可运行——这是 CO-05/多数 P0 的共同前提。
2. **[TBD-15] 性能 baseline**：实测首 token、语音端到端、热切换，回填 NFR/AI-03/AI-10/ASR-04。
3. **SpacemiT AI 加速 SDK**：明确 `/dev/ai_dma` 的编程接口（厂商 SDK），决定 SpacemitEngineBackend 可行性。
4. **TEE 缺失确认**：[TBD-17] 定稿为软件密钥方案。

### 11.4 五维复评（实机后）
| 维度 | 结论 | 变化 |
|------|------|------|
| 完整性 | ✅ | 不变，功能域完整 |
| 可测试性 | ✅ | 不变，验收可量化 |
| 无歧义性 | ✅ | 不变 |
| 一致性 | ✅ | 不变 |
| 可实现性 | ⚠️→可控 | 由"纸面存疑"变为"路径清晰、前提明确"：硬件确认、方向经现有平台印证（不复用），剩余风险收敛为 4 个 M1 前置动作 |

---
*BN-SRS-001 V1.1 · 基于 PRD V0.9 + worker 10.0.90.243 实测校准（2026-07-07）。功能需求核验为 OK，2 项性能 NFR 待实机 baseline。内容由 AI 辅助生成。*


