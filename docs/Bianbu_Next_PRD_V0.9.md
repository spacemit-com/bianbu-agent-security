# Bianbu Next 产品需求文档 V0.9

## 文档说明

- **对外统一名称**：Bianbu（不再区分 LXQt/GNOME，LXQt 为默认桌面，GNOME 版本已正式退出，不对外释放）
- **内部项目代号**：Bianbu Next（面向 Agent 能力的系统底座，Bianbu 升级项目）
- **版本号继承**：现有 Bianbu 版本体系（如 Bianbu 4.0.1 等）
- **系统助手名称**：BiBit（发音 /ˈbɪbɪt/，融合 "bit" 极客感与 "bib" 萌趣）

### V0.9 变更说明（相对 V0.7）

- 统一**权限模型**为「权限域 × 风险等级 L1–L4 + 三级信任策略」，废弃并存的多套分类与 L0（见 5.1.3）
- 明确 **token_budget** 单位与口径，修复 SEC-04 与 Manifest 冲突（见 5.1.5）
- 新增**记忆服务 MEM-01~08**（见 5.7）、**日历联动 CAL-01~05**（见 5.8）、**轻量沙箱 SBX-01~07**（见 5.3.7）三处规格空洞补齐
- 补充**意图类型清单**（16 类，见 5.5.2.1），使 INT-01 可验收
- 激进性能指标（首 token、语音端到端、热切换）改为「目标值 + baseline 锁定」两段式（见第 10 章）
- 统一**里程碑**为单一权威表，消解甘特图与交付表矛盾（见第 11 章）
- 标注 `【待确认】` 项，须由负责人回填后定稿（见 12.2）

> 图例：`【待确认】` = 需负责人回填的决策项；`【V0.9】` = 本版新增或修订。

## 目录

1. 摘要
2. 背景与战略定位
3. 产品定位与范围
4. 核心能力总览
5. 各层能力详细设计
6. 原生系统 AI 助理 BiBit
7. 系统设置 Agent OS 配置
8. 安全设计专题
9. 技术选型汇总
10. 非功能性需求
11. 里程碑与交付计划
12. 附录（含待确认事项汇总）

---

## 1. 摘要

**Bianbu Next** 是进迭时空面向 AI Agent 时代的原生操作系统底座——为 Agent 最想运行的底层操作系统。

**核心定位**：面向 RISC-V + AI 架构的 Agent 原生 OS 底座，为 Agent 提供运行时、安全、记忆、调度、可观测、开发工具全栈能力。

**核心特点**：

- **芯片级 AI 原生**：端侧 AI 能力 + 统一内存，本地运行多种模态模型，端云协同
- **RISC-V 开源生态**：从 Kernel 到应用全栈自研，开源开放，深度定制
- **系统级 Agent 运行时**：不是在 OS 之上叠加 AI 能力，而是将 Agent 作为第一类执行单元
- **原生 Agent 应用 BiBit**：系统级智能助手，用户入口及 Agent 能力试炼场

Bianbu Next 不仅是未来 K3/K5/K7 的原生配套系统，也是未来 Agent Computer 与 Agent Robot 的应用场景底座。随着端侧 AI 能力从 60TOPS（K3）向更高算力演进，Bianbu Next 将持续为各种 Agent 提供安全、高效、可观测的原生运行环境。

---

## 2. 背景与战略定位

### 2.1 行业趋势

2026 年，科技产业正从"大模型参数竞赛"转向"智能体如何融入计算系统每一层"。Agent OS 成为定义 AI 时代竞争格局的核心制高点。当前市场呈现三种 Agent OS 形态探索路径：

- **云平台基础设施层**（如阿里云 Agentic OS / ANOLISA）：定位为 Agent 提供高效、安全运行底座的云操作系统
- **现有 OS 深度集成**（如微软 Windows + MXC、苹果 iOS 27 + Siri AI、Android + Gemini Intelligence）：将 Agent 能力内化为操作系统原生功能
- **学术探索与前瞻架构**（如 Stanford AgenticOS、Agent libOS）：以前瞻性架构研究为主，探索以 Agent 为中心的操作系统新范式

从 Windows Agent Runtime 到华为 HarmonyOS 7，从苹果 Siri 进化到谷歌 Gemini Intelligence，全球巨头已形成共识——下一代操作系统的核心是"智能体生态"而非"应用生态"。

> `【待确认】` 2.1/2.2 引用的前瞻性竞品信息（iOS 27、Android 17、HarmonyOS 7、盘古 6.0、MAI 7/Maia 200/MXC 等）与"IDC 预测 2860 万→22.16 亿"统计均无出处，建议标注来源或加"待核实"。

### 2.2 四大 OS 厂商 Agent OS 对比

| 厂商 | 定位 | Agent 应用层 | 中间层 | 模型层 | 硬件层 | 安全/隐私 |
|------|------|--------------|--------|--------|--------|-----------|
| **Windows** | 企业 Agent 优先 · Copilot 超级应用 | Copilot 超级应用 · Scout · OpenClaw | MXC 策略驱动沙箱层（内核级强制执行·内置安全护栏） | MAI 7 自研栈 · Microsoft IQ | Surface RTX Spark · Maia 200 | 隔离 · 身份 · 可容错性 |
| **Apple iOS/macOS** | 隐私优先 · 统一芯片 · Siri AI | Siri AI · System Orchestrator | 语义引擎 + App Intents（原子化技能包·系统统一路由） | AFM 3（2 锁频 + 3 云端）· PCC | Neural Engine · A/M 系列 · 12GB+ DRAM | PCC 隐私计算（无状态·可验证透明·无特权访问） |
| **HarmonyOS** | 内核级 AI 原生 · 鸿蒙智能体 | 小艺 Claw · 第三方 Agent 生态 | 鸿蒙智能体框架 2.0（"意图即服务"·复杂任务成功率 90%+） | 盘古大模型 6.0（嵌入内核·百亿参数·端侧本地·断网可用） | 麒麟芯片 · NPU↑ 全场景分布式设备 | 星盾安全架构（AI 反诈·6 大能力） |
| **Android 17** | 开放生态 Agent 化 · Gemini | Gemini Intelligence · Generative UI | Android MCP + AppFunctions（标准化协议·应用能力暴露为"工具"） | Gemini（系统级集成） | 多芯片兼容 · 5-8 亿 · 大屏设备 | 显性用户控制 · 数据保护 · 透明 |

> Agent OS 之争的底层逻辑，是"谁来定义用户与数字世界交互的默认入口"。
> 搜索时代，用户寻找信息；App 时代，用户调用功能；Agent 时代，用户委托任务。

**Bianbu Next 的差异化**：

- 不同于 Windows 的企业优先：Bianbu 面向个人开发者与垂直市场，开源开放
- 不同于 macOS 的封闭生态：Bianbu 基于 RISC-V 开源架构，软硬件协同但生态开放
- 不同于 HarmonyOS 的内核耦合：Bianbu 保持 Linux 主线兼容，AI 能力通过 HAL 层接入而非内核侵入
- 不同于 Android 的多芯片兼容：Bianbu 深度绑定自研 RISC-V AI 芯片，软硬件深度协同优化

### 2.3 进迭时空的战略支点

- **芯片优势**：RISC-V AI CPU K3（最高 60TOPS AI 核 + 32GB LPDDR5 统一内存），下一代 K5/K7 本地 AI 能力逐步加强，能够在本地运行 30B/70B 模型。Bianbu Next 不仅适用于 K3，也是 K5/K7 原生的 Agent OS
- **系统基础**：Bianbu（基于 LXQt 的轻量桌面）高度自研和定义，从启动、Kernel 到系统、应用，深度开发且开源
- **市场窗口**：IDC 预测，活跃 Agent 的数量将从 2025 年的约 2860 万增长至 2030 年的 22.16 亿
- **核心定位**：不做 Agent 应用本身，而是提供 Agent 最想运行的底层操作系统

### 2.4 产品愿景

让每一个 Agent 在 Bianbu 上获得原生般的运行体验——安全、高效、持久、可观测、会记忆。同时，让 Bianbu + 进迭时空 RISC-V 芯片成为开发者构建 Agent 应用的首选平台，让系统助手 BiBit 成为用户及开发者使用的智能伙伴。

---

## 3. 产品定位与范围

### 3.1 产品名称

- 对外统一名称：**Bianbu**（不再区分 LXQt/GNOME，GNOME 版本已正式退出）
- 内部（项目）代号：**Bianbu Next**（面向 Agent 能力的系统底座升级项目）
- 版本号继承：现有 Bianbu 版本体系（如 Bianbu 4.0.1 → Bianbu 4.2 等）

### 3.2 定位

- 面向 RISC-V + AI 架构的 Agent 原生操作系统底座
- 为 Agent 提供运行时、安全、记忆、调度、可观测、开发工具全栈能力
- 通过系统助手 BiBit 作为首方应用，验证并展示底座能力。BiBit 作为独立产品已拆分单独 PRD

### 3.3 范围界定

**包含（本 PRD 覆盖）**：

- Agent 运行时与生命周期管理 `P0`
- Agent 级安全权限模型与审计 `P0`
- 多 Agent 隔离与沙箱 `P0`
- 设备级持久记忆服务 `P1`
- AI 能力层：向量模型、OCR、ASR、TTS、文档转 Markdown、LLM 模型管理与并行推理调度 `P0` `P1`
- 全盘文件向量检索 `P1`（仅文件检索与识别，不作为知识库）
- 本地知识库"知了"（用户可选建立）`P1`
- 日历联动与日程提醒 `P1`
- 异构 AI 调度框架（预研）
- 可观测性与轨迹追踪 `P1`
- 开发者 SDK 与 CLI 工具链 `P1`
- Skill 开发与扩展框架 `P1`
- 系统助手 BiBit 作为首方应用的技术接口与底座支撑
- UI 组件标准化（主题、控件库）
- 桌面环境视觉效果

### 3.4 版本说明

版本号继承现有 Bianbu 版本体系，第一个 Bianbu Next 版本预计是 Bianbu 4.x。

---

## 4. 核心能力总览

### 4.1 用户故事

用户角色：开发者构建 Agent、用户通过 BiBit 完成日常任务、安全审计员管控第三方 Agent。

**一天的工作流**：

- 🌅 **上午**：晨间启动（开机唤醒 BiBit，"今天有哪些待办？"）→ 代码审查（Agent 自动 Review PR，本地模型推理发现 3 处问题）→ 自动修复（一键应用并跑通测试）→ 构建部署（CI/CD 全流程托管）→ 完成 5 个 PR 审查、3 个 Bug 修复、1 次成功部署
- ☀️ **下午**：技术调研（问 Agent "RISC-V 向量扩展？"）→ 知识库检索（『知了』本地搜索，找到 15 篇文档）→ 文档撰写（Agent 辅助写 PRD 初稿）→ 安装新 Skill（从市场装飞书连接器）→ 完成 1 份调研、1 份 PRD 初稿、2 个新 Skill
- 🌙 **晚间**：语音交互（"帮我总结下今天的"）→ 日报生成（Whisper 语音识别，汇总全天）→ 安全审计（查看审计日志，所有操作合规）→ 明日规划（Agent 建议明天安排）→ 收工

> 💡 核心价值：AI Agent 贯穿全工作流 · 本地推理不依赖云端 · 语音/文本/文档多模态交互 · 安全审计全程可追溯

### 4.2 Bianbu Next 六层结构

| 层 | 名称（优先级） | 关键能力 |
|----|----------------|----------|
| 🔵 第六层 | AI 应用生态层（P2） | Agent Hub（Agent 商店）、ed25519 签名认证、开发者激励计划、生态质量仪表盘、BiBit 助手、第三方 App 接入、Web UI 管理面板 |
| 💬 第五层 | 自然交互与应用框架（P1） | 意图解析引擎（端云协同）、Skill Registry（MCP）、语音 ASR（Whisper.cpp）、语音 TTS（Piper）、OCR（MinerU2.5）、文档转 MD、文件向量检索（LanceDB+BGE）、BiBit 助手、本地知识库/会议助理、日历联动、应用内操控（DBus/AT-SPI/OCR） |
| 🛠️ 第四层 | 开发者工具链层（P1） | Bianbu Agent SDK（Python/C++）、CLI 套件、bench、doctor、API 文档与示例、Vibe Coding IDE、调试/Profiling |
| ⚙️ 第三层 | 高性能运行时层（P0） | 生命周期管理、轻量沙箱（cgroup v2 + ns + seccomp）、多 Agent 隔离、Checkpoint/Restore、资源监控、OOM 保护、Agent 通信总线（IPC） |
| 🧠 第二层 | AI 能力与异构调度层（P0/P1） | 模型生命周期、并行推理管理、AI HAL（llama.cpp/VLLM/ONNX）、Task-Aware Scheduler、端云决策引擎、KV Cache Manager、量化/压缩/蒸馏管线 |
| 🔒 第一层 | 内生安全与审计层（P0） | Agent 权限模型（Capability Registry）、系统调用拦截（seccomp-bpf）、审计日志（防篡改哈希链）、敏感操作确认、TEE 集成（预研）、Manifest 验证、多用户隔离 |
| ⚙️ 硬件层 | RISC-V K3/K5/K7 / 统一内存 | — |

### 4.3 功能框架总览

- **第一层 内生安全与审计 P0**：SEC-01 权限声明框架 / SEC-02 能力注册表 / SEC-03 敏感操作确认门禁 / SEC-04 资源配额控制 / SEC-05 系统调用拦截层 / SEC-06 审计日志引擎 / SEC-07 网络白名单
- **第二层 AI 能力与调度管理 P0/P1**：AI-01~04 模型生命周期 / AI-05~08 并行推理 / AI-09~13 推理引擎 HAL / AI-14~17 任务感知调度 / AI-18~21 端云决策 / AI-22~24 KV Cache Manager
- **第三层 高性能运行时 P0**：RTE-01~06 生命周期 / RTE-07~11 Checkpoint/Restore / RTE-12~14 资源监控 / **SBX-01~07 轻量沙箱【V0.9】**
- **第四层 开发者工具链 P1**：SDK-01~09 / CLI-01~07 / BENCH-01~06 / DOC-01~04
- **第五层 自然交互与应用框架 P1**：INT-01~04 意图解析 / ASR-01~04 语音 / DCO-NV-01~04 文档转 MD / OCR-01~03 / VEC-01~08 文件检索与知了 / SKL-01~09 Skill / APP-01~05 应用内操控
- **记忆与日历【V0.9】**：MEM-01~08 记忆服务 / CAL-01~05 日历联动
- **第六层 AI 应用生态层 P2**：ECO-01~06 Agent Hub / 签名 / 更新 / 依赖 / 后台 / 仪表盘

### 4.4 Agent 交互数据流总览

```
用户输入层（语音 Whisper ASR / 文本指令 / 文档图片）
   → 意图解析层 L4（意图解析引擎端云协同 → Skill Registry MCP 路由）
   → AI 调度层 L2（Task-Aware Scheduler → 模型生命周期 → 并行推理 llama.cpp/VLLM/ONNX）
   → 运行时层 L3（Agent 生命周期 → 轻量沙箱 cgroup+ns+seccomp → 资源监控 & OOM）
   → 工具执行层（本地工具 CLI/DBus/AT-SPI / Skill 执行 / 知识库检索『知了』LanceDB+BGE）
   → 输出层（操作结果 → TTS 语音 Piper / 文本 UI 响应）

安全审计 L1 贯穿全链路：权限模型校验（Capability Registry）→ seccomp-bpf 过滤 → 审计日志哈希链
```

---

## 5. 各层能力详细设计

### 5.1 第一层：内生安全与审计层

#### 5.1.1 核心目标

构建 Agent 运行的信任根。确保每个 Agent 的行为可授权、可审计、可追溯，敏感操作必须经过用户确认。借鉴 Windows MXC 的策略驱动沙箱理念，结合 RISC-V 芯片安全特性，打造"敢用、能用、管得住"的 Agent 安全底座。

**用户故事**：小徐安装了一个来自社区市场的第三方 Agent，系统自动扫描其 Manifest 签名和权限声明，发现该 Agent 申请了网络访问权限但实际功能不需要联网。安全层弹出确认对话框："该 Agent 请求网络权限，是否允许？"小徐选择"仅限本地"，Agent 在受限沙箱中运行。所有操作被记录到防篡改审计日志中。

#### 5.1.2 功能细项

| 编号 | 功能项 | 需求描述 | 优先级 | 验收标准 |
|------|--------|----------|--------|----------|
| SEC-01 | Agent 权限声明框架 | 开发者发布 Agent 时声明所需权限（域 + 风险等级），支持 always/once_per_session/trusted 三级策略（见 5.1.3） | P0 | 安装无 manifest 的包被拒绝并提示；三级策略均可按 5.1.3 语义正确触发确认流程 |
| SEC-02 | 能力注册表 | 用户可在 Agent 管理器中查看/撤销权限；开发者可通过 CLI 查询和调整 | P0 | CLI 可查询和修改 Agent 权限；UI 可见 |
| SEC-03 | 敏感操作确认门禁 | Agent 执行敏感操作（发邮件、删除文件、支付）时弹窗确认，支持"每次确认"或"本次会话内信任" | P0 | 敏感操作需确认后才执行 |
| SEC-04 | 资源配额控制 | 按 token_budget 规格（5.1.5）限制用量：单次 ≤10 万、单日 ≤50 万 token，超限由 securityd 发出 pause_and_notify 事件 | P1 | securityd 判定超限、发事件并记审计；Agent Runtime/agent 消费事件后暂停或终止；达 limit_per_day 后同样处理，次日 00:00 重置 |
| SEC-05 | 系统调用拦截层 | 底层拦截危险操作（关机、重启、加载内核模块），即使 Agent 代码有 bug 或被恶意利用也无法执行 | P0 | 恶意 Agent 无法执行关机/重启等操作 |
| SEC-06 | 审计日志引擎 | 记录 Agent 所有操作（读文件、连网站、调模型），写入防篡改日志，支持查看和导出 | P0 | 审计日志可导出、可验证完整性，用户可查看 |
| SEC-07 | 网络白名单 | Agent 只能访问声明的网站，其他网络请求被拦截 | P1 | 网络策略生效，未授权流量被阻断 |

#### 5.1.3 统一权限模型【V0.9 统一】

V0.9 将此前并存的多套权限分类统一为**单一两维模型**：一维为「权限域」（能力的语义分组），一维为「风险等级 L1–L4」（决定确认强度）。**废弃 L0**，SEC / SKL / SDK 全部引用本模型。

**① 权限域（Capability Domain）**

| 域 | 说明 | 示例能力标识 |
|----|------|--------------|
| `execute` 执行权 | 代表用户执行操作 | mail.send、file.write、payment.create |
| `resource` 资源消耗权 | 消耗 token / API 费用 | llm.cloud_call、api.purchase |
| `data` 数据访问权 | 读取用户数据 | contacts.read、docs.read、location.read |
| `system` 系统修改权 | 修改系统配置 | network.config、package.install |

**② 风险等级（Risk Level）与默认确认策略**——跨 SEC/SKL/SDK 的唯一分级标准：

| 等级 | 定义 | 典型能力 | 默认确认策略 |
|------|------|----------|--------------|
| L1 只读 | 读取非敏感系统信息 | system.info、proc.list、fs.read（非敏感目录） | 安装时一次授权，运行期不再确认 |
| L2 用户数据 | 访问用户私有数据 | docs.read、contacts.read、calendar.read、fs.write | once_per_session（会话内信任） |
| L3 系统修改 | 修改系统配置/安装软件 | network.config、package.install | always（每次确认） |
| L4 危险操作 | 不可逆/高破坏性 | system.shutdown、disk.format、net.monitor、payment.create | always + 二次确认 |

`fs.read` 的等级取决于目标目录：访问声明的只读目录为 L1，访问用户私有目录（如 `~/Documents`）为 L2，以实际访问路径判定，由 SEC-02 能力注册表按目录粒度记录。

**③ 三级信任策略定义**（补齐 SEC-01 验收口径）

| 策略值 | 语义 |
|--------|------|
| `always` | 每次执行该能力都弹窗确认 |
| `once_per_session` | 会话内首次确认，之后本会话免确认；会话结束失效 |
| `trusted` | 永久信任，直到用户在 SET-03 中撤销 |

**约束**：L3/L4 能力不允许配置为 `trusted`（防止危险能力被永久放行）；L4 无论策略如何均强制二次确认。

#### 5.1.4 Manifest 示例

```toml
[agent]
id = "com.bianbu.bibit"
version = "1.0.0"
name = "BiBit Assistant"
signature = "ed25519:xxxx"

[permissions]
# 执行权
execute_file_write = {action = "write", confirm = "once_per_session"}
execute_mail_send = {confirm = "always"}
# 资源权（token 预算，单位：token 个）
[permissions.token_budget]
unit = "token"
limit_per_conversation = 100000   # 单次对话上限，默认 10 万
limit_per_day = 500000            # 单日上限，默认 50 万
on_exceed = "pause_and_notify"    # 超限：securityd 发事件；Agent Runtime/agent 暂停或终止并通知
# 数据访问
read_documents = {allow = true, scope = "~/Documents", risk_level = "L2"}
read_contacts = {allow = false}
# 系统修改
modify_network = {allow = false}
```

安装时，`manifest.toml` 的 `[permissions]` 简写将被展开为规范化结构写入 Capability Registry，每条含 `capability / domain / risk_level / confirm / scope` 五字段，与 5.5.8.1 的 `permissions.json` 共用同一 schema。

#### 5.1.5 token_budget 规格【V0.9 明确】

统一 SEC-04、5.1.3、Manifest 三处口径，替换 V0.7 中无单位的 `limit = 0.5`：

| 字段 | 含义 | 默认值 |
|------|------|--------|
| unit | 计量单位，固定为 token（个） | token |
| limit_per_conversation | 单次对话 token 上限 | 100000（10 万） |
| limit_per_day | 单日 token 上限，本地时区 00:00 重置 | 500000（50 万） |
| on_exceed | 超限行为 | pause_and_notify（暂停并通知，记审计） |

> `【待确认】` ①计量是否含 prompt+completion 双向计数（建议双向）；②本地推理是否计入预算池（建议不计入）。

### 5.2 第二层：AI 能力与调度管理层

#### 5.2.1 核心目标

统一管理 CPU、AI 核等异构算力，为上层 Agent 提供标准化的模型推理接口，并实现任务感知的智能调度，最大化能效比（Intelligence per Watt）。

**用户场景**：小徐对 BiBit 说"帮我总结这篇文档"。BiBit 调用本地 7B 模型进行摘要生成——模型已在内存中缓存，首 token 延迟仅 200ms。同时，另一个 Agent 也在调用 0.5B 意图分类模型，两个模型并行运行。当本地 7B 模型置信度不足时，端云决策引擎自动透明切换到云端大模型（已授权），用户全程无感知。

#### 5.2.2 模块一：模型生命周期管理

| 编号 | 功能项 | 需求描述 | 优先级 | 验收标准 |
|------|--------|----------|--------|----------|
| AI-01 | 模型注册与发现 | 开发者仅用模型名（如 "qwen2.5-7b"）即可调用，系统自动管理注册表 | P0 | Agent 无需指定模型路径，仅需模型名即可调用 |
| AI-02 | 模型加载与缓存 | 多 Agent 共用同一模型时只加载一份到内存共享，第二次调用"秒开" | P0 | 第二次调用同模型时延迟降低 ≥80% |
| AI-03 | 模型热切换 | Agent 运行时动态切换模型（如 30B → A3B → 2B），原模型释放资源 | P1 | 目标值 ≤2s，M1 完成 K3 baseline 后锁定为验收值 |
| AI-04 | 模型卸载 | 模型不再使用时释放 AI 核资源 | P0 | 内存释放确认可用 |

#### 5.2.3 模块二：模型并行推理管理

| 编号 | 功能项 | 需求描述 | 优先级 | 验收标准 |
|------|--------|----------|--------|----------|
| AI-05 | 多模型并发调度 | 多个 AI 模型并行运行，系统根据优先级和资源情况智能调度 | P1 | 3 个模型并发时延迟增加 ≤30% |
| AI-06 | 批次合并（Dynamic Batching） | 将多个同模型推理请求合并为批次，提升 AI 核吞吐 | P1 | 高并发场景下吞吐提升 ≥2x |
| AI-07 | 连续调用优化 | 同一 Agent 多次调用同模型时复用 KV cache | P1 | 连续对话 token 生成延迟减少 ≥40% |
| AI-08 | 推理队列管理 | 高优先级 Agent 可抢占推理资源；支持任务排队 | P1 | 抢占切换延迟 ≤100ms |

#### 5.2.4 模块三：推理引擎 HAL（硬件抽象层）

| 编号 | 功能项 | 需求描述 | 优先级 | 验收标准 |
|------|--------|----------|--------|----------|
| AI-09 | 统一推理接口 | 一套 API 调用不同 AI 推理引擎（llama.cpp、ONNX Runtime、vLLM），切换引擎不改代码 | P0 | Agent 无需修改代码即可切换后端引擎 |
| AI-10 | llama.cpp 适配（主引擎） | 支持 GGUF 格式模型加载，利用 RISC-V AI 核优化 | P0 | 首 token 延迟 ≤200ms（7B 模型，目标值+baseline 锁定） |
| AI-11 | ONNX Runtime 适配 | 支持 ONNX 模型在 AI 核上推理，对接 K3 AI 核驱动 | P1 | ONNX 模型推理正确率 100% |
| AI-12 | vLLM 适配（高吞吐场景） | 支持 vLLM 的高吞吐批处理推理，vLLM 现已支持 RISC-V 架构 CPU 推理 | P2 | 批处理吞吐 ≥50 tokens/s/请求 |
| AI-13 | Ollama 兼容层 | 兼容 Ollama API，让现有 Ollama 用户无缝迁移 | P2 | 现有 Ollama 命令可在 Bianbu 上运行 |

#### 5.2.5 模块四：任务感知调度器（预研）

| 编号 | 功能项 | 需求描述 | 优先级 | 验收标准 |
|------|--------|----------|--------|----------|
| AI-14 | 任务特征识别 | 识别任务类型：意图解析（0.5B~2B）/ 文本生成（7-14B）/ Embedding / 工具调用 | P2 | 分类准确率 ≥95% |
| AI-15 | 计算资源分配 | 意图解析 → CPU 及 AI 能力分配；Embedding → AI 算力；工具调用 → CPU | P2 | 能效比相对于纯 CPU 提升 ≥2x |
| AI-16 | 负载感知调度 | 根据当前 CPU/AI 核负载动态调度任务，避免资源竞争 | P2 | 高负载时延迟增加 ≤50% |
| AI-17 | 统一内存优化 | 利用 K3 统一内存架构，Agent 状态（KV cache）不离开 AI 核内存区域 | P2 | KV cache 访问延迟 ≤10ms |

#### 5.2.6 模块五：端云决策引擎

| 编号 | 功能项 | 需求描述 | 优先级 | 验收标准 |
|------|--------|----------|--------|----------|
| AI-18 | 本地能力评估 | 评估本地模型能否答好问题，能则本地处理，不确定再考虑云端 | P1 | 置信度预测准确率 ≥85% |
| AI-19 | 隐私检测 | 检测任务是否涉及敏感数据（文档、联系人等），强制本地执行 | P1 | 隐私检测准确率 ≥99% |
| AI-20 | 云端路由 | 本地模型答不好时自动、透明切换到云端大模型（用户需提前授权），接入进迭时空社区 AI 服务 | P0 | 云端切换用户无感知 ≤1s |
| AI-21 | API 密钥安全存储 | 云端 API 密钥通过 K3 安全存储（TEE） | P1 | 密钥不可被普通 Agent 读取。`【待确认】` TEE 可用性 |

#### 5.2.7 模块六：KV Cache Manager

| 编号 | 功能项 | 需求描述 | 优先级 | 验收标准 |
|------|--------|----------|--------|----------|
| AI-22 | KV cache 池化 | 统一管理推理 KV cache 的内存分配与释放 | P1 | 内存碎片率 ≤10% |
| AI-23 | LRU 淘汰策略 | 内存不足时自动淘汰不活跃的 cache | P1 | 淘汰决策延迟 ≤1ms |
| AI-24 | 跨会话复用 | 相似 prefix 的对话复用 cache（如系统 prompt） | P2 | Token 生成延迟减少 ≥30% |

#### 5.2.8 DBus 接口

服务名：`io.bianbu.AIHal`

| DBus 方法 | 参数 | 返回值 | 说明 |
|-----------|------|--------|------|
| Generate | prompt, model_name, params | text | 生成文本 |
| Embed | text, model_name | vector | 文本向量化 |
| LoadModel | model_name, model_path | status | 加载模型到内存 |
| UnloadModel | model_name | status | 卸载模型 |
| GetStatus | - | status | 查询 AI HAL 状态 |

#### 5.2.9 模型推理数据流

`请求接入`（Agent/Skill 调用 → 模型类型识别 → 隐私等级判定）→ `调度决策`（本地优先 → 云端 fallback → 批处理/优先级）→ `推理执行`（AI HAL → llama.cpp/ONNX → KV Cache 复用）→ `结果治理`（流式返回 → 审计记录 → 资源计量）。并行优化点：同模型请求合批、KV Cache 复用、任务感知调度、端云策略动态切换。

#### 5.2.10 技术选型汇总

| 组件 | 选型 | 确认状态 | 说明 |
|------|------|----------|------|
| 主推理引擎 | llama.cpp / ONNX Runtime | 待选型 | GGUF/ONNX 格式，适配 RISC-V 优化路线 |
| 高吞吐批处理 | vLLM | 待选型 | P2 方向验证 RISC-V CPU 推理与批处理能力 |
| 兼容层 | Ollama | 待选型 | 面向开发者体验和模型迁移兼容 |
| 模型格式 | GGUF（量化）/ ONNX | 待选型 | 覆盖本地 LLM 与传统推理模型 |
| KV Cache | 自定义管理器 | 待选型 | 内存池 + LRU 淘汰，服务长上下文与多 Agent 并发 |

### 5.3 第三层：高性能运行时层

#### 5.3.1 核心目标

为 Agent 提供轻量、隔离、可恢复的执行环境，支持长时运行（数天至数周），具备状态快照与恢复能力。

**用户场景**：小徐的 BiBit 已连续运行 3 天，中间经历一次系统更新。更新前系统自动创建 Checkpoint 快照；更新后 BiBit 从快照恢复，对话记忆完整保留。另一个 Agent 因内存泄漏持续占用资源，当内存超过 2GB 上限时系统自动暂停并通知小徐。

#### 5.3.2 模块一：生命周期管理

| 编号 | 功能项 | 需求描述 | 优先级 | 验收标准 |
|------|--------|----------|--------|----------|
| RTE-01 | Agent 状态机 | 安装 → 运行 → 暂停 → 停止 → 卸载，用户可在管理器中查看状态 | P0 | 状态转换正确率 100% |
| RTE-02 | Agent 启动（Start） | 点击"启动"后 200ms 内运行，自动分配隔离环境 | P0 | 冷启动 ≤200ms |
| RTE-03 | Agent 暂停（Pause） | 暂停运行，可选保存内存快照 | P0 | Pause 响应 ≤100ms |
| RTE-04 | Agent 恢复（Resume） | 从暂停状态恢复 | P0 | Resume ≤100ms |
| RTE-05 | Agent 停止（Stop） | 停止并释放资源 | P0 | Stop 响应 ≤200ms |
| RTE-06 | Agent 终止（Terminate） | 彻底终止，清理所有数据 | P0 | 清理完整性 100% |

#### 5.3.3 模块二：Checkpoint / Restore 机制

| 编号 | 功能项 | 需求描述 | 优先级 | 验收标准 |
|------|--------|----------|--------|----------|
| RTE-07 | 自动 Checkpoint | 系统定期给 Agent"存档"，意外重启后从最近存档恢复 | P1 | Checkpoint 保存 ≤500ms |
| RTE-08 | 手动 Checkpoint | CLI 手动创建快照：`bianbu-agent checkpoint <agent-id>` | P1 | 手动触发执行正确 |
| RTE-09 | 从快照恢复 | 从指定 checkpoint 恢复 Agent 运行 | P1 | 恢复时间 ≤2s（含模型加载） |
| RTE-10 | 崩溃自动恢复 | Agent 崩溃后自动从最近存档恢复，用户可能无感知 | P1 | 崩溃恢复成功率 ≥95% |
| RTE-11 | Checkpoint 存储管理 | 存储于 `/var/lib/bianbu/checkpoints/`，支持清理策略，保留最近 10 个 | P1 | 保留最近 10 个 checkpoint |

#### 5.3.4 模块三：资源监控

| 编号 | 功能项 | 需求描述 | 优先级 | 验收标准 |
|------|--------|----------|--------|----------|
| RTE-12 | CPU/内存实时统计 | Agent 管理器中实时查看每个 Agent 的 CPU 和内存占用 | P1 | 数据更新频率 ≤1s |
| RTE-13 | 资源超限处理 | Agent 占用内存超过 2GB 时自动暂停并通知用户 | P1 | 超限时触发暂停并通知用户 |
| RTE-14 | 历史统计导出 | 支持导出 Agent 运行历史资源数据（JSON/CSV） | P2 | 导出数据完整可用 |

#### 5.3.5 Agent 生命周期状态流转图

```
[*] → INSTALLED（安装完成）
INSTALLED → RUNNING（Start）
RUNNING → PAUSED（Pause） → RUNNING（Resume）
RUNNING → STOPPED（Stop） → RUNNING（Start）
PAUSED → STOPPED（Stop）
RUNNING / PAUSED / STOPPED → TERMINATED（Terminate）
TERMINATED → [*]（清理所有数据）
```

#### 5.3.6 DBus 接口

服务名：`io.bianbu.Runtime`

| 方法 | 参数 | 返回值 | 说明 |
|------|------|--------|------|
| Start | agent_id | status | 启动 Agent |
| Pause | agent_id | status | 暂停，可选保存快照 |
| Resume | agent_id | status | 恢复运行 |
| Stop | agent_id | status | 停止（不保存） |
| Terminate | agent_id | status | 彻底终止 |
| Restore | agent_id, checkpoint_id | status | 从快照恢复 |
| List | - | list of AgentStatus | 列出所有 Agent |

#### 5.3.7 模块四：轻量沙箱 SBX【V0.9 补齐】

V0.7 将「轻量沙箱」列为第三层 P0 能力但无编号需求项。V0.9 补齐为可验收编号需求，与第 8.2.1 节 Level 1 配置对应，是 SEC-05/07 与 RTE 在运行时的落地载体。

| 编号 | 功能项 | 需求描述 | 优先级 | 验收标准 |
|------|--------|----------|--------|----------|
| SBX-01 | 文件系统隔离 | chroot + overlayfs 限制 Agent 于 `~/.local/share/bianbu-agents/<agent-id>/` + 声明的只读挂载 | P0 | 访问声明范围外路径 100% 被拦截 |
| SBX-02 | 资源配额（cgroup v2） | 默认 CPUQuota=100%、MemoryMax=2GB、IOWeight=100，可按 Agent 覆盖 | P0 | 内存超 MemoryMax 触发 OOM 保护（对齐 RTE-13） |
| SBX-03 | 网络隔离 | netfilter 白名单，默认 DROP，仅放行声明域名（对齐 SEC-07） | P0 | 未声明域名请求被阻断 |
| SBX-04 | 系统调用过滤 | seccomp-bpf 默认黑名单：reboot/swapon/kexec/init_module 等（对齐 SEC-05） | P0 | 黑名单调用被拒绝且不影响宿主 |
| SBX-05 | 能力裁剪 | 启动时 capability drop，去除非必要 Linux capabilities | P0 | 进程不持有 CAP_SYS_ADMIN 等危险能力 |
| SBX-06 | 沙箱创建性能 | 沙箱随 Agent 冷启动创建 | P0 | 沙箱创建不使冷启动超 200ms（对齐 RTE-02） |
| SBX-07 | 创建失败降级 | 沙箱创建失败时 Agent 拒绝启动并告警，绝不降级为无沙箱运行 | P0 | 失败时 Agent 不启动，记审计 |

> Level 2 命名空间隔离（第 8.2.2）为 Phase 2 增强，预留编号 SBX-08~12。`【待确认】` 是否本阶段纳入（建议 Phase 2）。

### 5.4 第四层：开发者工具链层

#### 5.4.1 核心目标

降低开发者构建、调试、部署 Agent 的门槛，提供从创建到发布的完整工具链。让"Hello World Agent 从零到运行 < 10 分钟"。

#### 5.4.2 模块一：Bianbu Agent SDK

| 编号 | 功能项 | 需求描述 | 优先级 | 验收标准 |
|------|--------|----------|--------|----------|
| SDK-01 | Agent 基类 | 继承 Python 类即可创建 Agent，生命周期回调自动处理 | P1 | 继承基类即可定义 Agent |
| SDK-02 | 工具装饰器 | `@tool` 装饰器将函数自动变成 Agent 可调用的"技能" | P1 | 函数自动转换为工具并在 Skill Registry 注册 |
| SDK-03 | 权限声明 API | 提供权限声明接口，代码中声明 Agent 所需权限 | P1 | 权限声明自动合并到 manifest |
| SDK-04 | 记忆服务客户端 | 提供记忆服务客户端封装，Agent 可读写跨会话持久记忆 | P1 | 记忆读写 API 符合预期 |
| SDK-05 | 系统能力调用 | 封装系统能力 API 调用（DBus），Agent 可通过 SDK 调用文件、应用等系统功能 | P1 | SDK 调用与原生 DBus 调用等效 |
| SDK-06 | 日志记录 | 提供分级日志（DEBUG/INFO/WARN/ERROR），自动关联 agent_id | P1 | 日志可关联到 Agent 管理器查看 |
| SDK-07 | Python SDK | 优先提供 Python SDK 包 `bianbu-agent-sdk` | P1 | PyPI 可安装，示例代码可运行 |
| SDK-08 | C++ SDK（远期） | 提供 C++ SDK，用于高性能 Agent 开发 | P2 | 示例编译运行通过 |
| SDK-09 | Tool 接口扩展 | `@tool` 装饰器增加 `skill_package` 参数，自动生成 skill.toml；提供 `bianbu_agent_sdk.skill` 子模块用于 Skill 包构建、验证和打包 | P1 | 开发者可用 `@tool(skill_package=True)` 一键生成符合 Skill 包格式规范的项目 |

#### 5.4.3 模块二：CLI 工具

| 编号 | 功能项 | 需求描述 | 优先级 | 验收标准 |
|------|--------|----------|--------|----------|
| CLI-01 | `bianbu-agent init` | 一条命令创建完整 Agent 项目，自带代码模板、权限声明文件和 README | P1 | 生成的项目可立即运行 |
| CLI-02 | `bianbu-agent build` | 打包 Agent 为 `.bianbu-agent` 格式 | P1 | 打包文件可被 install 安装 |
| CLI-03 | `bianbu-agent install` | 安装 Agent 包到系统 | P1 | 安装后 Agent 显示在管理器中 |
| CLI-04 | `bianbu-agent run` | 开发者修改代码后直接运行测试，无需反复打包安装 | P1 | 开发迭代无需反复安装 |
| CLI-05 | `bianbu-agent logs` | 查看 Agent 运行日志，支持 `--follow` 实时跟踪 | P1 | 日志可查、可筛选 |
| CLI-06 | `bianbu-agent status` | 查看 Agent 运行状态 | P1 | 状态与 DBus 一致 |
| CLI-07 | `bianbu-agent uninstall` | 卸载 Agent | P1 | 清理所有相关文件 |

#### 5.4.4 模块三：性能基准工具 bench

| 编号 | 功能项 | 需求描述 | 优先级 | 验收标准 |
|------|--------|----------|--------|----------|
| BENCH-01 | 延迟测量 | 测量 Agent 响应速度——从用户说话到 AI 开始回答需多久 | P1 | 输出 ns 级精度 |
| BENCH-02 | 吞吐测量 | 测量 tokens/s 吞吐 | P1 | 精确到 0.1 tokens/s |
| BENCH-03 | 内存测量 | 测量模型 / Agent 运行时内存占用 | P1 | 输出 RSS/PSS |
| BENCH-04 | 功耗测量（需硬件支持） | 测量推理功耗，计算 tokens/J | P2 | 与 K3 PMU 对接 |
| BENCH-05 | 多模型对比 | 支持对比不同模型 / 量化配置的性能 | P1 | 输出对比表格 |
| BENCH-06 | 报告导出 | 支持导出 JSON/HTML 格式报告 | P1 | 导出文件可读 |

#### 5.4.5 模块四：诊断工具 doctor

| 编号 | 功能项 | 需求描述 | 优先级 | 验收标准 |
|------|--------|----------|--------|----------|
| DOC-01 | 环境检查 | 运行 `bianbu-agent doctor` 自动检查 AI 核驱动、推理引擎、模型等是否安装正确，发现问题直接给出修复命令 | P1 | 输出检查清单和修复建议 |
| DOC-02 | 依赖诊断 | 检查 Agent 的依赖是否满足 | P1 | 依赖缺失时给出安装命令 |
| DOC-03 | 性能诊断 | 分析 Agent 运行慢的原因（CPU/AI 核瓶颈/IO） | P1 | 输出诊断报告 |
| DOC-04 | 权限诊断 | 检查 Agent 权限配置是否有冲突 | P1 | 提示缺失权限 |

#### 5.4.6 开发者工作流

`① bianbu-agent init`（生成项目模板：agent.py + manifest.toml + README）→ `② bianbu-agent run`（开发模式热重载 + logs --follow 实时调试）→ `③ bianbu-agent bench`（性能基准，对比模型配置）→ `④ bianbu-agent doctor`（环境诊断：依赖+权限+驱动）→ `⑤ bianbu-agent build`（打包 .bianbu-agent）→ `⑥ bianbu-agent install`（安装+权限确认弹窗）→ `⑦ 发布到 Agent Hub`（签名认证 → 上架 → 用户安装）。

#### 5.4.7 SDK 使用示例

```python
import os
from bianbu_agent_sdk import Agent, tool, memory, permission

class MyAgent(Agent):
    def __init__(self):
        super().__init__()
        self.register_tool(self.search_files)

    @tool(permission="read_documents", confirm="once_per_session")
    def search_files(self, query: str) -> list:
        # 调用系统记忆服务的语义检索
        return memory.retrieve(query)

    @tool(permission="execute_file_write")
    def save_note(self, content: str) -> bool:
        note_path = os.path.expanduser("~/notes/agent_note.txt")
        with open(note_path, "a") as f:
            f.write(content)
        return True

    def on_start(self):
        self.logger.info("MyAgent started")

    def on_stop(self):
        self.logger.info("MyAgent stopped")
```

### 5.5 第五层：自然交互与应用框架

#### 5.5.1 核心目标

为用户提供自然语言/语音交互入口，将传统 GUI 应用抽象为可被 Agent 调用的"技能模块"（Skill）。借鉴华为"意图即服务"的交互范式和 Android AppFunctions 的应用能力暴露机制，同时提供全盘文件向量检索和本地知识库"知了"。

**用户场景**：小徐按下 `Super+B` 唤醒 BiBit，说："把桌面上那个 PDF 转成 Markdown，然后找一下里面提到的 Agent 调度相关内容"。BiBit 调用 MinerU2.5-Pro 将 PDF 转为 Markdown，在转换后的内容中向量检索"Agent 调度"相关段落，返回匹配结果并高亮关键词。

#### 5.5.2 模块一：意图解析引擎

| 编号 | 功能项 | 需求描述 | 优先级 | 验收标准 |
|------|--------|----------|--------|----------|
| INT-01 | 意图分类 | 支持 16 类意图类型（清单见 5.5.2.1） | P1 | 在标注测试集（每类 ≥50 条，共 ≥800 条）上 top-1 准确率 ≥90% |
| INT-02 | 槽位提取 | 从用户输入中提取关键参数（文件名、路径、应用名、时间段等） | P1 | 槽位提取准确率 ≥85% |
| INT-03 | 多轮对话上下文 | 理解上下文指代（如"打开第一个"指搜索结果中的第一个文件） | P1 | 上下文指代正确率 ≥80% |
| INT-04 | 本地模型意图解析 | 使用 Qwen2-0.5B 微调的分类器，纯本地运行 | P1 | 延迟 ≤200ms |

#### 5.5.2.1 意图类型清单【V0.9 补齐】

V0.7 中 INT-01 仅称「15+ 意图」未列举，导致不可验收。V0.9 给出 16 类基线清单（可扩展）：

| # | 意图类型 | 示例 | 目标模型/模块 |
|---|----------|------|---------------|
| 1 | 系统控制 | "调高音量" | 意图分类 0.5B |
| 2 | 应用启动 | "打开 Firefox" | 0.5B |
| 3 | 应用内操控 | "在浏览器搜索 RISC-V" | 0.5B + APP 层 |
| 4 | 文件语义搜索 | "找上月的调度文档" | 0.5B + VEC |
| 5 | 文件操作 | "把文件移到 Downloads" | 0.5B |
| 6 | 文档转换 | "把 PDF 转成 Markdown" | DCO |
| 7 | OCR 识别 | "识别这张截图的文字" | OCR |
| 8 | 文本生成/摘要 | "总结这篇文档" | 7B |
| 9 | 代码辅助 | "帮我改这个 bug" | Coder-7B |
| 10 | 知识库问答 | "知了里关于 X 的说明" | VEC + LLM |
| 11 | 日程查询 | "我明天有什么安排" | CAL |
| 12 | 日程创建 | "明天 3 点提醒我开会" | CAL |
| 13 | 记忆读写 | "记住我喜欢深色主题" | MEM |
| 14 | 语音交互控制 | "开始/停止听写" | ASR |
| 15 | 设置/配置 | "切换默认模型" | SET |
| 16 | 闲聊/兜底 | 无法归类的自然语言 | 7B |

> `【待确认】` 意图标注语料由谁提供；AI-14（≥95%）与 INT-01（≥90%）准确率口径关系需明确。

#### 5.5.3 模块二：语音交互

| 编号 | 功能项 | 需求描述 | 优先级 | 验收标准 |
|------|--------|----------|--------|----------|
| ASR-01 | 语音唤醒 | 按 `Super+B` 唤出 BiBit 开始说话；高级用户可开启语音唤醒词"Hello BiBit" | P1 | 按键唤醒立即响应 |
| ASR-02 | 语音识别（ASR） | 使用 Whisper.cpp（tiny 模型），将语音转为文本 | P1 | 安静环境下识别率 ≥95% |
| ASR-03 | 语音合成（TTS） | 使用 Piper TTS，合成中文/英文语音反馈 | P1 | MOS 主观评测：≥20 名评测者、≥30 条中英句子，平均 MOS ≥4.0/5.0 |
| ASR-04 | 语音指令端到端延迟 | 从语音结束到反馈显示 | P0 | ≤1.5s（目标值+baseline 锁定） |

#### 5.5.4 模块三：文档转 Markdown

| 编号 | 功能项 | 需求描述 | 优先级 | 验收标准 |
|------|--------|----------|--------|----------|
| DCO-NV-01 | 多格式文档转换 | PDF、Word、PPT 等转为结构化 Markdown，转换成功率 95% 以上 | P1 | 主流格式转换成功率 ≥95% |
| DCO-NV-02 | 文档解析引擎 | 使用 MinerU2.5-Pro（1.2B 参数），OmniDocBench 上达 95.69 分 | P1 | 在 OmniDocBench 子集（≥100 文档）上结构还原 F1 ≥0.90；标题/表格/列表还原正确率 ≥90% |
| DCO-NV-03 | 文档预转换 | 文档发送给大模型前自动转换为 Markdown，节省 Token | P1 | Token 节省 ≥30% |
| DCO-NV-04 | 批量转换 API | 提供批量转换接口，用于知识库构建 | P2 | 批量转换并发数可配置 |

#### 5.5.5 模块四：OCR 识别

| 编号 | 功能项 | 需求描述 | 优先级 | 验收标准 |
|------|--------|----------|--------|----------|
| OCR-01 | 图像文字识别 | 从截图/图片中提取文字 | P1 | 中英文混合识别率 ≥90% |
| OCR-02 | 截图快速 OCR | 用户截图后可调用 OCR 提取文字 | P2 | 触发后结果在 2s 内返回 |
| OCR-03 | 应用内控件的文字识别 | 用于应用内操控 fallback 方案，识别按钮文字 | P1 | 准确率 ≥85% |

#### 5.5.6 模块五：全盘文件向量检索与本地知识库「知了」

| 编号 | 功能项 | 需求描述 | 优先级 | 验收标准 |
|------|--------|----------|--------|----------|
| VEC-01 | 向量化索引构建 | 对用户指定目录建立向量索引，仅用于文件检索，不作为知识库 | P1 | 支持增量更新 |
| VEC-02 | 自然语言语义搜索 | 用户直接说"找一下上个月关于 Agent 调度的文档"，系统理解语义搜索文件内容 | P1 | 检索延迟 ≤2s |
| VEC-03 | 文件管理器集成 | 文件管理器提供语义搜索入口，直接搜索文件内容 | P1 | 搜索入口可见，结果可打开 |
| VEC-04 | 本地嵌入模型 | 使用 BGE-small 或 nomic-embed-text，纯本地运行 | P1 | 嵌入延迟 ≤100ms |
| VEC-05 | 向量数据库 | 使用 LanceDB（轻量、嵌入式），支持百万级向量 | P1 | 插入 ≥1000 条/秒 |
| VEC-06 | 本地知识库"知了"（可选） | 用户可将重要文档加入本地知识库，对话时优先使用本地向量检索，可无缝切换至云端模型 | P1 | 在 ≥200 QA 对基准集上人工判定答案正确率 ≥80% |
| VEC-07 | 全盘文件监视 | inotify 监听文件变化，自动增量更新索引 | P1 | 新增文件 10 分钟内被索引 |
| VEC-08 | 搜索结果预览 | 搜索结果显示文件预览片段和相关性评分 | P1 | 预览片段高亮关键词 |

#### 5.5.7 模块六：Skill Registry

| 编号 | 功能项 | 需求描述 | 优先级 | 验收标准 |
|------|--------|----------|--------|----------|
| SKL-01 | Skill 注册 | 应用开发者将应用功能注册为"技能"（如浏览器注册"打开网页"、"搜索"技能） | P1 | 注册后 Agent 可发现 |
| SKL-02 | Skill 发现 | Agent 可查询 Registry 获取可用 Skill 列表 | P1 | 查询延迟 ≤50ms |
| SKL-03 | Skill 调用 | 标准化调用接口，支持参数传递和结果返回 | P1 | 调用成功率 ≥99% |
| SKL-04 | MCP 协议集成 | 系统兼容行业标准 MCP 协议，外部 AI Agent 工具也能调用 Bianbu 上的应用能力 | P1 | MCP Client 可访问 Bianbu Skill |

#### 5.5.8 模块七：Skill 开发与扩展框架

| 编号 | 功能项 | 需求描述 | 优先级 | 验收标准 |
|------|--------|----------|--------|----------|
| SKL-05 | Skill 包格式规范 | 定义 `.skill` 标准包格式：skill.toml（元数据、入口、权限、依赖）、entry.py（Skill 入口，含 `@tool` 装饰器函数）、permissions.json（四级权限声明） | P1 | 符合规范的 .skill 包可被系统解析和安装 |
| SKL-06 | Skill 生命周期管理 | 安装（含依赖检查和权限确认）、更新（含版本兼容检查）、卸载（含清理注册表引用）、版本管理（semver） | P1 | Skill 安装/更新/卸载后状态正确 |
| SKL-07 | Skill 权限分级 | 四级权限：L1 只读、L2 用户数据、L3 系统修改、L4 危险操作（统一引用 5.1.3） | P1 | 不同等级触发不同确认流程；L4 需二次确认 |
| SKL-08 | Skill 沙箱执行 | 复用 SEC 层沙箱能力（L1~2 隔离），结合 RTE 运行时管理，每个 Skill 在独立进程空间运行 | P1 | Skill 无法访问其权限声明之外的系统资源 |
| SKL-09 | Skill CLI | `bianbu-skill list`、`bianbu-skill install <path>`、`bianbu-skill call <skill-id>.<function> [args]`、`bianbu-skill uninstall <skill-id>` | P1 | CLI 命令执行正确，返回格式规范 |

#### 5.5.8.1 Skill 包规范详解

SKL-05 定义了 `.skill` 标准包格式，由四个核心文件组成：

| 组成部分 | 说明 | 示例 |
|----------|------|------|
| Skill 描述文件（skill.toml） | 声明 Skill 名称、描述、意图触发词、参数定义、权限需求、版本号 | `name="file-search" trigger=["找文件","搜索文件"] permissions=["fs.read"]` |
| 入口脚本（entry.py） | Skill 的执行逻辑，接收解析后的参数，返回结果。支持 Python/Shell | `def execute(params): ...` |
| 权限声明（permissions.json） | 声明该 Skill 需要的系统权限，安装时按 L1–L4 权限模型（5.1.3）分级确认 | 每条含 capability/domain/risk_level/confirm/scope |
| Skill 清单（可选） | 知识库文档、示例对话、测试用例 | `docs/usage.md, tests/test_search.py` |

skill.toml 示例：

```toml
name = "file-search"
description = "全盘语义文件检索"
trigger = ["找文件", "搜索文件", "find files"]
params = [{name = "query", type = "string", required = true}]
permissions = ["fs.read"]
version = "1.0.0"
```

#### 5.5.8.2 Tool 接口分类规范

| Tool 类型 | 说明 | 注册方式 | 示例 |
|-----------|------|----------|------|
| 系统 Tool | Agent OS 提供的原子系统能力，通过 DBus/REST API 暴露 | Agent OS 内置注册 | fs.read, fs.write, proc.list, net.config, hw.control |
| 应用 Tool | 第三方应用通过 Tool SDK 注册的能力接口 | `@tool` 装饰器注册，安装时声明到 Capability Registry | browser.navigate, editor.open, terminal.exec, mail.send |
| AI Tool | AI 模型能力封装为 Tool，通过 AI HAL 统一调度 | AI HAL 内置注册，按模型名调用 | llm.generate, embedding.create, asr.transcribe, tts.speak |
| 社区 Tool | 进迭时空社区开发者贡献的扩展 Tool，通过 Skill 包分发 | 社区 Skill 包内声明，注册到 Tool Registry | riscv.compile, k3.benchmark, ros2.publish |

#### 5.5.8.3 Skill 市场基础设施

| 市场能力 | 说明 | 对应 Agent OS 功能项 |
|----------|------|----------------------|
| Skill 托管与分发 | 集成在进迭时空社区平台，开发者可发布 .skill 包 | ECO-01 Agent Hub |
| Skill 安全审核 | 自动安全扫描 + 人工审核后上架 | ECO-02 签名认证 + SEC-06 审计日志 |
| Skill 评分与推荐 | 用户可评分评论，优质 Skill 获官方推荐 | ECO-05 开发者后台 |
| Skill 版本管理 | 遵循 semver，支持回滚、自动更新通知 | SKL-06 + ECO-03 |
| 开发者激励 | 优质 Skill 开发者获社区积分/荣誉称号 | ECO-05 + ECO-06 |

> `【待确认】` 原 V0.7 此处引用的 `BIT-42` 编号在本 PRD 不存在，疑似误引 BiBit PRD，建议删除或改引 ECO-05。

#### 5.5.9 模块八：应用内部操控

| 编号 | 功能项 | 需求描述 | 优先级 | 验收标准 |
|------|--------|----------|--------|----------|
| APP-01 | DBus 接口优先 | 用户说"打开 Firefox 搜索 RISC-V"时，优先通过应用标准接口（DBus）操控 | P1 | 受支持应用的操控成功率 ≥95% |
| APP-02 | AT-SPI 辅助功能 | GTK/Qt 应用通过辅助功能接口读取控件树并模拟操作 | P1 | 标准桌面应用可操控 |
| APP-03 | 快捷键模拟 | 使用 ydotool（Wayland 原生）模拟快捷键；X11 兼容 xdotool | P1 | 常见快捷键在 Wayland 和 X11 下均可用 |
| APP-04 | 视觉定位 + OCR | 截图识别按钮位置，模拟鼠标点击（fallback） | P1 | 识别准确率 ≥80% |
| APP-05 | 多级 Fallback 链 | 标准接口 → 辅助功能 → 快捷键 → 视觉识别，四级保障 | P1 | Fallback 逻辑正确 |

#### 5.5.10 应用操控 Fallback 链流程

`Level 1 DBus 接口` → 失败则 `Level 2 AT-SPI 辅助功能` → 失败则 `Level 3 快捷键模拟（ydotool/xdotool）` → 失败则 `Level 4 视觉定位+OCR（截图→识别→点击）` → 仍失败则 `超时 3s 返回失败`。任一级成功即执行完成。

### 5.6 第六层：AI 应用生态层

#### 5.6.1 核心目标

构建 Agent 的分发、安装、更新、评价体系，吸引开发者贡献 Agent，形成正循环生态。

#### 5.6.2 功能细项

| 编号 | 功能项 | 需求描述 | 优先级 | 验收标准 |
|------|--------|----------|--------|----------|
| ECO-01 | Agent Hub | 像 AppStore 一样的 Agent 应用商店，用户可浏览、一键安装、评价各种 Agent | P2 | 用户可浏览、安装、评价 Agent |
| ECO-02 | 签名认证 | 每个 Agent 包都有开发者数字签名，安装时系统自动验证 | P2 | 安装时验证签名 |
| ECO-03 | 自动更新 | Agent 有新版本时系统自动提醒更新（或静默更新） | P2 | 更新提示或静默更新 |
| ECO-04 | 依赖管理 | 安装时自动处理 Agent 依赖（模型、库等） | P2 | 依赖缺失时自动安装或提示 |
| ECO-05 | 开发者后台 | 开发者上传 Agent，查看下载量、评分 | P2 | 后台功能完整 |
| ECO-06 | 生态度量仪表盘 | 统计 Agent 使用、评分、故障率（匿名遥测，用户可选关闭） | P2 | 数据可视化展示 |

### 5.7 记忆服务 MEM【V0.9 补齐】

#### 5.7.1 核心目标

为 Agent 提供跨会话、设备级持久的记忆读写能力，支持按 Agent 隔离、语义检索、TTL 过期与容量上限。V0.7 在范围（3.3）、里程碑（M4）、SDK-04 反复引用记忆服务但无规格，V0.9 补齐。

#### 5.7.2 功能细项

| 编号 | 功能项 | 需求描述 | 优先级 | 验收标准 |
|------|--------|----------|--------|----------|
| MEM-01 | 记忆写入 | Agent 经 SDK/DBus 写入键值或文本记忆，自动关联 agent_id 与时间戳 | P1 | 写入后可读回，字段完整 |
| MEM-02 | 记忆读取（精确） | 按 key 精确读取 | P1 | 命中返回正确值，未命中返回空且不报错 |
| MEM-03 | 记忆语义检索 | 对文本记忆做向量检索返回 top-k（复用 VEC 层 BGE 嵌入） | P1 | 检索延迟 ≤100ms（对齐 NFR）；top-5 相关性人工评测命中率 ≥80% |
| MEM-04 | 按 Agent 隔离 | 各 Agent 仅访问自身命名空间，跨 Agent 需显式授权 | P1 | 跨 Agent 访问 100% 被拦截（渗透测试） |
| MEM-05 | 容量与淘汰 | 单 Agent 容量上限，超限按 LRU 淘汰 | P1 | 超限时最久未访问条目被淘汰，写入成功。`【待确认】` 默认容量（建议 256MB） |
| MEM-06 | 记忆 TTL | 写入时可设过期时间，过期自动清理 | P2 | 到期条目不再被检索到 |
| MEM-07 | 云端备份（可选） | 登录社区账号后可备份/恢复（对齐 M4） | P2 | 新设备登录可恢复；未登录时功能不可见 |
| MEM-08 | 记忆清理 | 用户可在 SET 面板按 Agent 清空；Agent 卸载时自动清理 | P1 | 清理后不可检索，磁盘空间释放 |

#### 5.7.3 DBus 接口

服务名：`io.bianbu.Memory`

| 方法 | 参数 | 返回值 | 说明 |
|------|------|--------|------|
| Store | agent_id, key, value, ttl(可选) | status | 写入记忆 |
| Get | agent_id, key | value | 精确读取 |
| Retrieve | agent_id, query, top_k | list of (text, score) | 语义检索 |
| Delete | agent_id, key | status | 删除条目 |
| Clear | agent_id | status | 清空该 Agent 记忆 |

> 存储：向量部分复用 LanceDB + BGE；`【待确认】` 键值/元数据存储选型（建议 SQLite）、存储路径规范（建议 `~/.local/share/bianbu-agents/<id>/memory/`）、是否采用 Hy-Memory 双系统（暂按单层 KV+向量）。

### 5.8 日历联动与日程提醒 CAL【V0.9 补齐】

#### 5.8.1 核心目标

让 Agent/BiBit 读取用户日程、创建提醒，并到点通过系统通知/语音提醒。V0.7 在范围与 M4 含此能力但无规格，V0.9 补齐。

#### 5.8.2 功能细项

| 编号 | 功能项 | 需求描述 | 优先级 | 验收标准 |
|------|--------|----------|--------|----------|
| CAL-01 | 日历数据接入 | 接入本地日历后端并读取日程 | P1 | 能读取既有日程，标题/起止/地点字段完整 |
| CAL-02 | 日程创建 | Agent 经确认后创建日程 | P1 | 创建的日程在日历应用中可见 |
| CAL-03 | 日程查询 | 自然语言查询经意图解析后返回 | P1 | 时间范围解析正确，返回匹配日程 |
| CAL-04 | 日程提醒 | 到点经系统通知提醒，可选 TTS 播报 | P1 | 提醒在设定时间 ±30s 内触发 |
| CAL-05 | 权限控制 | 日历读=L2，日历写=L2 且写需确认 | P1 | 未授权时读写被拒绝并提示 |

> `【待确认】` 日历后端协议（建议 CalDAV / Evolution Data Server）；LXQt 是否随系统内置日历应用。

---

## 6. 原生系统 AI 助理（BiBit）— 独立产品

BiBit 已拆分为独立 PRD，详见《BiBit — Bianbu 原生系统助理产品需求文档》。

BiBit 是运行在 Bianbu Next Agent OS 之上的第一个原生 Agent 应用，是用户和开发者与系统交互的统一入口。

**BiBit 在 Agent OS 中的角色**：

- 作为系统级智能助手，验证并展示 Agent OS 六层架构的全部能力
- 作为开发者的 AI 编程伙伴（类 Claude Code 体验），降低 Agent 开发门槛
- 作为系统的交互入口，接管人机交互（语音/文字/CLI）
- 作为社区知识的智能入口，接入进迭时空社区 AI 知识库

> `【待确认】` BiBit 边界：本 PRD 仅保留"底座接口支撑"，BiBit 特有功能/性能指标（含 NFR 中 BiBit 内存 ≤400MB 等）应移交 BiBit PRD，避免两份文档职责重叠。

---

## 7. 系统设置 Agent OS 配置

### 7.1 设计目标

为用户和系统管理员提供图形化的 Agent OS 配置中心，涵盖 Agent 生命周期管理、AI 模型管理、Skill 管理、安全与审计配置。与 CLI 工具互补——CLI 面向开发者和高级用户，GUI 面板面向日常用户和系统管理员。

> `【待确认】` SET-01~19 验收标准在 V0.7 多为"XX 功能正常"（循环定义）。V0.9 已示范量化改写（下表加粗项），其余须由 QA 与 PM 按「前置状态 → 操作 → 可观测结果」模板逐条定稿。

### 7.2 Agent 管理器

| 编号 | 功能项 | 需求描述 | 优先级 | 验收标准 |
|------|--------|----------|--------|----------|
| SET-01 | Agent 状态总览 | 列表/卡片展示所有已安装 Agent：名称、图标、状态、资源占用、运行时长 | P1 | **安装 N 个后列表恰好显示 N 条，每条含名称/状态/CPU%/内存 MB，与 DBus List 一致，刷新 ≤1s** |
| SET-02 | Agent 启停控制 | 提供启动/暂停/恢复/停止/终止按钮，支持批量操作 | P1 | **点击启动后状态 ≤200ms 变为运行中；批量 M 个执行停止全部转为已停止** |
| SET-03 | Agent 权限查看与修改 | 展示每个 Agent 的权限列表，支持撤销或调整。高风险权限撤销需二次确认 | P1 | 权限查看和修改正常；高风险权限撤销有二次确认 |
| SET-04 | Agent 详情面板 | 点击展开详情：manifest 信息、资源历史趋势、最近日志摘要、Checkpoint 列表 | P1 | Agent 详情面板显示完整信息 |
| SET-05 | Agent 卸载 | 卸载并清理所有关联数据（沙箱文件、checkpoint、日志），卸载前弹窗确认 | P1 | 卸载正常并清理关联数据；卸载前有确认弹窗 |

### 7.3 AI 模型管理

| 编号 | 功能项 | 需求描述 | 优先级 | 验收标准 |
|------|--------|----------|--------|----------|
| SET-06 | 模型列表与状态 | 展示所有已注册模型：名称、版本、大小、状态、加载进度；按类型筛选（LLM/Embedding/ASR/文档解析） | P1 | 模型列表正确显示状态和类型 |
| SET-07 | 模型下载与导入 | 内置模型商店一键下载、从本地导入 GGUF/ONNX、从 URL 下载；显示进度和速度 | P1 | 下载和导入正常，进度显示正确 |
| SET-08 | 模型切换 | 设置默认对话/Embedding/意图分类模型；支持热切换 | P1 | **切换后新推理使用新模型；运行中 Agent ≤2s 内切换（对齐 AI-03）** |
| SET-09 | 端云配置 | 配置云端 API 密钥、端云决策策略、隐私数据规则 | P1 | 端云配置正常，隐私数据规则生效 |
| SET-10 | 模型卸载与清理 | 手动卸载释放内存，按最后使用时间排序，一键清理未使用模型 | P1 | 卸载和清理正常，一键清理生效 |

### 7.4 Skill 管理

| 编号 | 功能项 | 需求描述 | 优先级 | 验收标准 |
|------|--------|----------|--------|----------|
| SET-11 | 已安装 Skill 列表 | 展示名称、版本、来源、状态、权限等级（L1-L4） | P1 | Skill 列表正确显示状态和权限等级 |
| SET-12 | Skill 启用/禁用 | 按需启用或禁用，禁用的 Skill 不被 Agent 发现调用，保留数据配置 | P1 | 启用/禁用正常，禁用后不被调用 |
| SET-13 | Skill 权限查看 | 展示每个 Skill 的权限声明（L1–L4），高风险（L3/L4）红色标记 | P1 | 权限查看正常，高风险红色标记 |
| SET-14 | Skill 安装/卸载 | 从本地 .skill 包或社区商店安装，安装时展示权限确认面板；支持卸载清理 | P1 | 安装和卸载正常，安装时展示权限确认面板 |

### 7.5 安全与审计配置

| 编号 | 功能项 | 需求描述 | 优先级 | 验收标准 |
|------|--------|----------|--------|----------|
| SET-15 | 审计日志查看 | 时间线展示所有 Agent 操作：时间、Agent、类型、目标、结果；支持筛选和全文搜索 | P1 | **执行一次敏感操作后日志 ≤1s 出现对应条目，含五字段；筛选搜索正常** |
| SET-16 | 审计日志导出 | 导出为 JSON/CSV，含哈希链完整性校验码，可离线验证未被篡改 | P1 | 导出正常，含哈希链完整性校验码 |
| SET-17 | 权限策略配置 | 默认 Agent 权限模板（最小权限）、敏感操作确认策略、高危系统调用黑名单自定义 | P1 | 权限策略配置正常，默认模板生效 |
| SET-18 | 网络白名单管理 | 全局白名单编辑、按 Agent 配置或继承、"学习模式"自动生成建议白名单 | P1 | **学习期结束后建议白名单覆盖观察期内 100% 已访问域名** |
| SET-19 | 安全事件告警 | 检测权限越界、异常高频网络、未知域名访问等，通知中心弹告警并在安全面板醒目标记 | P1 | 告警正常，可疑行为触发告警 |

---

## 8. 安全设计专题

### 8.1 多 Agent 隔离层次模型

多 Agent 安全隔离是 Agent OS 的基石。Linux 原生进程模型不针对"自动化 Agent"做安全设计，需要额外构建隔离层。

| 层级 | 名称（优先级） | 说明 |
|------|----------------|------|
| Level 4 | VM 隔离（P3/远期） | 使用 Firecracker / kata-container 创建轻量 VM。硬件边界，最强隔离，性能开销最大 |
| Level 3 | 容器级隔离（P2） | 每个 Agent 运行在独立 Docker 容器。namespace 完全隔离，中等性能开销 |
| Level 2 | 命名空间 + 资源限制（Phase 2, P1） | `cgroup v2 + mount ns + net ns + pid ns + seccomp`。进程级隔离 + 资源配额 + 网络隔离 + 文件系统隔离（PID/NET/MNT/UTS/IPC ns） |
| Level 1 | 进程级沙箱（Phase 1 基础, P0） | 独立工作目录 + seccomp 过滤 + cgroup 配额；chroot+overlayfs 文件隔离 + netfilter 网络白名单 + seccomp-bpf 系统调用 + capability drop |

### 8.2 沙箱详细配置

#### 8.2.1 Level 1：进程级沙箱（Phase 1 基础，P0）

| 隔离维度 | 实现方式 | 配置策略 |
|----------|----------|----------|
| 文件系统 | chroot + overlayfs | Agent 只看到 `~/.local/share/bianbu-agents/<agent-id>/` + 显式挂载的只读目录 |
| 资源限制 | cgroup v2 | CPUQuota=100%, MemoryMax=2GB, IOWeight=100 |
| 网络 | netfilter + iptables | 白名单模式，默认 DROP，仅允许声明域名 |
| 系统调用 | seccomp-bpf | 默认黑名单：reboot, swapon, kexec, init_module 等 |

> 对应 5.3.7 的 SBX-01~07 编号需求项。

#### 8.2.2 Level 2：命名空间隔离（Phase 2 增强，P1）

| 隔离类型 | Namespace 类型 | 隔离效果 |
|----------|----------------|----------|
| 进程隔离 | PID namespace | Agent 看不到宿主机和其他 Agent 的进程 |
| 网络隔离 | NET namespace | Agent 拥有独立网络栈，可配置 veth 对 |
| 挂载隔离 | MNT namespace | Agent 的 mount 不会影响宿主机 |
| UTS 隔离 | UTS namespace | Agent 可独立设置 hostname |
| IPC 隔离 | IPC namespace | Agent 独立 System V IPC |

---

## 9. 技术选型汇总

| 类别 | 组件 | 选型 | 确认状态 | 说明 |
|------|------|------|----------|------|
| 模型推理引擎 | 主推理 | llama.cpp、ONNX Runtime | 待选型 | GGUF/ONNX，RISC-V 优化优先 |
| 模型推理引擎 | 高吞吐 | vLLM | 待选型 | P2 验证批处理与服务化吞吐 |
| 模型推理引擎 | 兼容层 | Ollama | 待选型 | 提升开发者模型迁移体验 |
| LLM 模型 | 对话主模型 | Qwen2.5-7B-Instruct / InternLM2.5-7B | 待选型 | 以 4-8GB 本地部署为主要约束 |
| LLM 模型 | 意图分类 | Qwen2-0.5B 微调 | 待选型 | 轻量分类器，服务意图解析 |
| LLM 模型 | 代码模型 | Qwen2.5-Coder-7B | 待选型 | 面向代码调试与辅助编程 |
| 文档/语音/视觉 | 文档解析 | MinerU2.5-Pro (1.2B) | 待选型 | 文档转 Markdown 与结构化解析 |
| 文档/语音/视觉 | ASR | Whisper.cpp tiny/base，备选 medium/large | 待选型 | 本地优先，高精度场景使用备选 |
| 文档/语音/视觉 | TTS | Piper TTS | 待选型 | 轻量本地 TTS |
| 文档/语音/视觉 | 嵌入模型 | BGE-small / nomic-embed-text | 待选型 | 本地知识库与向量检索 |
| 文档/语音/视觉 | OCR + 视觉定位 | PaddleOCR | 待选型 | 应用操控 fallback 与文档视觉理解 |
| 基础设施 | 向量数据库 | LanceDB | 待选型 | 轻量嵌入式向量存储 |
| 基础设施 | IPC 总线 | DBus | 待选型 | 标准化系统通信 |
| 基础设施 | 容器/沙箱 | chroot / cgroup v2 / seccomp | 待选型 | 轻量无守护进程，满足 P0 隔离 |

> `【待确认】` 所有组件"确认状态"均为待选型。须给出每项决策截止日期与评估标准；RISC-V 可用性见 12.0 成熟度矩阵。

---

## 10. 非功能性需求

> **性能指标口径说明（V0.9）**：标注「目标值 + baseline 锁定」的激进 P0 指标（首 token ≤200ms、语音端到端 ≤1.5s、模型热切换 ≤2s）在 RISC-V + K3 上缺 baseline，采用两段式：先作为目标值，M1（推理）/M5（语音链路）完成实测 baseline 后锁定为正式验收值。`【待确认】` baseline 结果。

| 类别 | 指标 | 目标值 | 测量方法 | 优先级 |
|------|------|--------|----------|--------|
| 性能 | Agent 冷启动（无模型） | ≤200ms | `time bianbu-agent start` | P0 |
| 性能 | Agent 内存（空闲，不含模型） | ≤50MB/Agent | `smem -P agent` | P0 |
| 性能 | 系统助手 BiBit 空闲内存增量 | ≤400MB（相对 Phase1） | `free` 对比 | P0 |
| 性能 | CPU 空闲占用 | ≤5% 单核 | top 持续 10 分钟 | P0 |
| 性能 | 语音指令端到端响应（目标值+baseline 锁定） | ≤1.5s | 录制 + 打点 | P0 |
| 性能 | 语义搜索查询 | ≤2s | 向量检索 + 生成 | P1 |
| 性能 | 文档转 Markdown（10 页 PDF） | ≤3s | 计时 | P1 |
| 性能 | ASR 识别（1s 语音） | ≤500ms | 计时 | P1 |
| 性能 | 记忆检索 | ≤100ms | 计时 | P1 |
| 可靠性 | Agent 运行时可用性 | 99.9% | 故障注入测试 | P1 |
| 可靠性 | 长时运行（7 天） | 无泄漏/无崩溃 | 持续监控 | P1 |
| 可靠性 | 崩溃恢复成功率 | ≥95% | 故障注入测试 | P1 |
| 安全 | 权限越权拦截率 | 100% | 渗透测试 | P0 |
| 安全 | 敏感操作确认率 | 100% | 功能测试 | P0 |
| 安全 | 审计日志完整性 | 100%（哈希链可验证） | 合规审查 | P0 |

---

## 11. 里程碑与交付计划

### 11.1 路线图总览

> V0.9 已消解 V0.7 甘特图（M1–M10）与交付表（M1–M7）的矛盾，统一为单一 M1–M7 体系；Bianbu 4.x 正式发布锁定于 M7（2027.03）。`【待确认】` 具体日期与人力配比由 PM/PjM 最终核定。

| 阶段 | 里程碑 | 时间窗口 |
|------|--------|----------|
| Phase 1 基础能力 P0 | M1 AI HAL + llama.cpp 适配 + run CLI | 2026.08–09 |
| Phase 1 | M2 运行时 + Level1 沙箱 + 安全基础 | 2026.09–10 |
| Phase 1 | M3 BiBit 基础版 + 云端知识库接入 | 2026.10–11 |
| Phase 2 增强能力 P1 | M4 记忆 + 向量检索 + 日历联动 | 2026.11–12 |
| Phase 2 | M5 开发者 SDK/CLI/bench/doctor + 代码调试 | 2026.12–2027.01 |
| Phase 2 | M6 BiBit 正式版 + 语音 + 知了 | 2027.01–02 |
| Phase 3 生态与发布 P1/P2 | M7 Agent Hub + 签名 + 仪表盘 + Bianbu 4.x 发布 | 2027.02–03 |

### 11.2 里程碑详细交付

| 里程碑 | 时间 | 交付内容（P0 加粗） | 人力关键依赖 |
|--------|------|---------------------|--------------|
| M1: AI HAL + llama.cpp | 2026.08 | **AI HAL 接口定义**，**llama.cpp 适配 K3 AI 核**；模型注册加载；**bianbu-agent run CLI** | AI 算法、系统 |
| M2: 运行时 + 安全基础 | 2026.09 | **生命周期管理 DBus**，**Level 1 沙箱（SBX-01~07）**；**权限模型（Capability Registry）**；**审计日志** | 系统、后端 |
| M3: BiBit 基础版 | 2026.10 | **BiBit 快捷键唤醒**，**文本交互**，**系统指令执行**；云端知识库接入 | 前端、AI 算法 |
| M4: 记忆 + 检索 + 日历 | 2026.11 | 记忆服务 DBus（MEM）；**文件向量检索**；**日历联动（CAL）**；BiBit 记忆云端备份 | 后端、前端 |
| M5: 开发者工具 + 代码调试 | 2026.12 | **Python SDK**；**CLI 完整命令**；**bench / doctor**；BiBit 代码调试功能 | 开发者工具、AI 算法 |
| M6: BiBit 正式版 | 2027.01 | 语音唤醒（可选）；**本地知识库"知了"**；**多轮对话优化**；性能调优 | 前端、AI 算法 |
| M7: Agent Hub + 生态 | 2027.03 | **Agent Hub 上线**；**签名认证**；**生态度量仪表盘**；**Bianbu 4.x 正式发布** | 后端、测试 |

### 11.3 人力分工

| 角色 | 人数 | 责任人 | 主要职责 | 涉及模块 |
|------|------|--------|----------|----------|
| 产品经理 | 1 | 徐东 | 整体需求、优先级、里程碑、生态合作 | 全部 |
| 项目经理 | 1 | 吴群 | 资源协调，进度、计划、质量把控 | - |
| 系统架构 | 1 | 付强 | 六层架构设计、技术选型、跨模块接口 | 全部，重点第一~三层 |
| 后端/系统 | 3 | 段成 | Agent 运行时、安全沙箱、生命周期管理、DBus 服务 | 第三层、第一层 |
| AI 工程师 | 2 | - | 模型适配、AI HAL、模型管理、并行调度 | 第二层 |
| 前端/应用 | 2 | - | BiBit 界面、Agent 管理器 UI、系统设置面板、托盘图标 | 第五层、第十一章 |
| 开发者工具 | 1 | - | CLI、bench、doctor 工具 | 第四层 |
| 测试工程师 | 3 | 朱潇婷 | 功能/性能/安全测试、全系统验收 | 全部 |
| 技术文档 | 1 | 罗俊琳 | API 文档、开发者指南、用户手册 | 第四层、第五层 |

> `【待确认】` AI 工程师仅 2 人覆盖整个第二层（含最难的模型 RISC-V 适配）；AI/前端/开发者工具责任人为"-"未定，须评估配比。

---

## 12. 附录

### 12.0 RISC-V 依赖成熟度矩阵【V0.9 新增】【待确认】

所有 AI 组件均假设可在 RISC-V + K3 运行，此为项目最大可实现性风险。须逐项核实移植状态（可用 / 需移植 / 不可用）并给出证据后回填：

| 组件 | 用途 | RISC-V/K3 状态 | 确认人 |
|------|------|----------------|--------|
| llama.cpp | 主推理引擎 | 【待确认】 | AI 工程 |
| ONNX Runtime | 传统模型推理 | 【待确认】 | AI 工程 |
| vLLM | 高吞吐（P2） | 【待核实"已支持 RISC-V CPU"说法】 | AI 工程 |
| Whisper.cpp | ASR | 【待确认】 | AI 工程 |
| Piper | TTS | 【待确认】 | AI 工程 |
| MinerU2.5-Pro | 文档解析 | 【待确认 1.2B 能否在 K3 运行】 | AI 工程 |
| PaddleOCR | OCR | 【待确认】 | AI 工程 |
| BGE-small | 嵌入 | 【待确认】 | AI 工程 |
| LanceDB | 向量库 | 【待确认】 | 后端 |

### 12.1 术语表

| 术语 | 定义 |
|------|------|
| BiBit | 系统助手名称，Bianbu 的第一个原生 Agent |
| 知了 | 可选本地知识库组件，用户可将文档加入构建个人知识库 |
| 进迭时空社区 AI | 与 SpacemiT Studio 共享的后端知识库服务，提供产品文档、技术问答 |
| Agent | 具有自主意图、可调用系统能力、拥有记忆和生命周期的自治程序 |
| Agent 运行时 | 管理 Agent 生命周期、沙箱、调度的系统服务 |
| Checkpoint | Agent 状态的快照，用于故障恢复 |
| Skill | 可被 Agent 调用的功能单元，封装应用或系统能力 |
| Skill 包 | 符合规范格式的 .skill 可分发包，包含 skill.toml + entry.py + 权限声明 |
| AI HAL | 硬件抽象层，统一不同推理引擎接口 |
| Capability Registry | 权限注册表，记录 Agent 声明和用户授权 |
| MCP 协议 | 专为 AI Agent 设计的标准化工具调用协议 |
| GGUF | llama.cpp 原生模型格式，支持低比特量化 |
| Hy-Memory | 腾讯混元发布的 6 层记忆框架，实现 System1/System2 双系统记忆（`【待确认】` 是否采用，见 5.7.3） |
| MXC | Microsoft Execution Containers，微软的 Agent 执行沙箱 |
| PCC | Private Cloud Compute，苹果的隐私云计算架构 |
| HMAF | Harmony Mobile AI Framework，华为鸿蒙智能体框架 |
| AppFunctions | 谷歌 Android 的应用能力暴露 API |
| K3 / K5 / K7 | 进迭时空 RISC-V AI CPU 系列。K3：最高 60 TOPS AI 核 + 32GB LPDDR5 统一内存；K5/K7 为后续算力增强型号（`【待确认】` 具体规格） |
| MEM / CAL / SBX | V0.9 新增需求编号前缀：记忆服务 / 日历联动 / 轻量沙箱 |

### 12.2 待确认事项汇总【V0.9 新增】

下列事项涉及产品/技术决策，无法由文档自行推定，须由负责人回填后 V0.9 定稿：

| # | 事项 | 所在章节 | 建议默认值 | 负责人 |
|---|------|----------|-----------|--------|
| 1 | K5/K7 具体规格 | 12.1 | — | 架构 |
| 2 | token 计量是否含 prompt+completion | 5.1.5 | 双向计数 | AI 工程 |
| 3 | 本地推理是否计入 token 预算 | 5.1.5 | 不计入 | PM |
| 4 | 单 Agent 记忆容量上限 | MEM-05 | 256MB | 后端 |
| 5 | 记忆 KV 存储选型 | 5.7.3 | SQLite | 后端 |
| 6 | 记忆存储路径规范 | 5.7.3 | ~/.local/share/bianbu-agents/&lt;id&gt;/memory/ | 架构 |
| 7 | 是否采用 Hy-Memory 双系统 | 5.7.3 | 否（单层） | 架构 |
| 8 | 日历后端协议 / 是否内置日历应用 | 5.8.2 | CalDAV/EDS | 前端 |
| 9 | Level 2 命名空间是否本阶段纳入 | 5.3.7 | Phase 2 | 系统 |
| 10 | 意图标注语料由谁提供 | 5.5.2.1 | — | AI 工程/PM |
| 11 | AI-14 与 INT-01 准确率口径关系 | 5.5.2.1 | — | AI 工程 |
| 12 | SET 系列逐条量化验收定稿 | 第 7 章 | QA+PM | QA |
| 13 | 统一里程碑日期与人力配比 | 11.1 | — | PM/PjM |
| 14 | RISC-V 依赖成熟度矩阵回填 | 12.0 | — | AI 工程 |
| 15 | 激进性能指标 baseline 锁定 | 第 10 章 | — | AI 工程 |
| 16 | 各组件选型截止日期与评估标准 | 第 9 章 | — | 架构 |
| 17 | TEE 可用性与接口 | AI-21 | — | 架构 |
| 18 | BIT-42 引用处理（疑误引 BiBit PRD） | 5.5.8.3 | 删除或改引 ECO-05 | PM |
| 19 | Hy-Memory 术语去留（依 #7） | 12.1 | 依 #7 | 架构 |

---

*版本：V0.9 | 编制：Xu Dong | 注：内容由 AI 生成，请谨慎参考；含 19 项待确认事项（见 12.2），回填后定稿*









