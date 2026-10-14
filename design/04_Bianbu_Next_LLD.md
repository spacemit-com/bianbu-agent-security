# Bianbu Next 详细设计说明书（LLD）

| 项 | 内容 |
|----|------|
| 文档编号 | BN-LLD-001 |
| 版本 | V1.1（worker 实机校准） |
| 来源 | 基于 API（BN-API-001）+ HLD（BN-HLD-001 V1.1）+ SRS + worker 10.0.90.243 实测 |
| 日期 | 2026-07-07 |
| 状态 | 待评审 |

> 本文件落到可实现粒度：核心模块的内部数据结构、算法、状态机、时序、并发模型、存储布局与异常处理。聚焦 P0/关键路径模块；P2/预研模块给出接口占位。

---

## 1. bianbu-securityd 详细设计

### 1.1 Capability Registry
**存储**：SQLite `/etc/bianbu/capabilities.db`
```sql
CREATE TABLE capability (
  agent_id   TEXT NOT NULL,
  capability TEXT NOT NULL,
  domain     TEXT CHECK(domain IN('execute','resource','data','system')),
  risk_level TEXT CHECK(risk_level IN('L1','L2','L3','L4')),
  confirm    TEXT CHECK(confirm IN('always','once_per_session','trusted')),
  scope      TEXT,
  granted    INTEGER DEFAULT 0,      -- 用户授权状态
  PRIMARY KEY(agent_id, capability, scope)
);
-- 约束校验（应用层）：risk_level∈{L3,L4} ⟹ confirm≠'trusted'
```

**CheckPermission 算法**（FR-SEC-02/03）：
```
def check(agent_id, cap, scope):
    row = lookup(agent_id, cap, best_match_scope(scope))
    if not row or not row.granted: return DENY(2)
    if row.risk_level == 'L4': return CONFIRM(1)  # 强制二次确认
    match row.confirm:
      'trusted':          return ALLOW(0)
      'once_per_session': return ALLOW(0) if session_cache.has(agent_id,cap) else CONFIRM(1)
      'always':           return CONFIRM(1)
```
`best_match_scope`：对文件类能力做最长前缀匹配，据实际路径定 L1/L2（FR-SEC 目录粒度）。

### 1.2 Audit Chain Engine（FR-SEC-06）
**结构**：追加写日志，每条：
```
record = {seq, ts, agent_id, op_type, target, result, prev_hash, hash}
hash = SHA256(seq‖ts‖agent_id‖op_type‖target‖result‖prev_hash)
```
- 单写线程串行化 seq 与 prev_hash，避免并发断链。
- 导出：写 JSON/CSV + 末条 hash 作为链尾锚点。
- 校验：逐条重算 hash 并比对 prev_hash 链，任一处不符 → 定位篡改位置。
- 存储轮转：按大小/日期分段，段间用段尾 hash 链接。

### 1.3 Sandbox Policy & Token Meter
- **seccomp 策略**：默认 allowlist（白名单更安全），叠加显式黑名单（reboot/swapon/kexec/init_module/mount 等）。以 libseccomp 生成 BPF，Start 时 `seccomp_load` 于 fork 后 execve 前。
- **Token Meter**：内存计数器 `{agent_id → (conv_used, day_used, day_epoch)}`；MeterTokens 原子累加；`conv_used>limit_per_conversation` 或 `day_used>limit_per_day` → securityd 记录审计并发送 `TokenExceeded`/`SecurityAlert`，由 Agent Runtime/agent 消费事件并负责暂停或终止；securityd 不直接请求 runtimed 停止服务。day_epoch 跨本地零点重置。[TBD-2/3] 计量口径。

### 1.4 并发/异常
- 服务多线程处理 D-Bus 请求，Registry 走 SQLite WAL + 连接池；审计走单独串行线程 + 内存队列（防阻塞调用方）。
- 审计写失败 = 安全关键 → 阻断相关操作并告警（fail-closed）。

---

## 2. bianbu-aihald 详细设计

### 2.1 Model Manager
**内存结构**：
```
ModelEntry { name, path, format(GGUF/ONNX), backend, handle,
             refcount, last_used, mem_bytes, state(LOADED/CACHED/UNLOADED) }
registry: Map<name, ModelEntry>
```
- **共享加载**（FR-AI-02）：LoadModel 命中且 state≠UNLOADED → refcount++ 直接返回（秒开）；否则真加载。
- **卸载**（FR-AI-04）：refcount==0 且内存压力 → 卸载；释放 handle。
- **热切换**（FR-AI-03）：加载 to 模型就绪后原子切换 Agent 绑定，再对 from refcount--；确保切换期间无空窗。

### 2.2 AI HAL 后端插件（FR-AI-09）
```
interface InferenceBackend {
  load(path, params) -> handle
  generate(handle, prompt, params, on_token) -> result   # 流式回调
  embed(handle, text) -> vector
  unload(handle)
}
```
后端（SpacemiT 定制栈，见 §11.2 与 AGENTS.md）：`LlamaSpacemitBackend`（定制 llama.cpp+ggml-spacemit，LLM 主，IME/TCM 回退 RVV/CPU）、`OnnxSpacemitBackend`（onnxruntime+spacemit-ep，视觉/OCR/嵌入）、`CloudBackend`（端云回退）。选择由任务类别+模型 format 决定，上层不感知（ADR-03）。

### 2.3 Parallel Scheduler（FR-AI-05~08）
- **推理队列**：优先级队列 `PriorityQueue<InferRequest{priority, model, prompt, deadline}>`。
- **动态批处理**（FR-AI-06）：同 model 且时间窗（如 10ms）内的请求合批；批大小上限受内存约束。
- **抢占**（FR-AI-08）：高优先级到达时，低优先级批在当前 token 边界让出（≤100ms）。
- **KV 复用**（FR-AI-07）：同 (agent_id, model, prefix_hash) 命中则续用 KV。

### 2.4 KV Cache Manager（FR-AI-22~24）
```
KVPool { blocks: slab allocator, index: Map<prefix_hash, KVBlock>, lru: LinkedList }
```
- 池化 slab 分配降碎片（目标 ≤10%）。
- LRU：内存不足淘汰链尾（决策 ≤1ms，O(1) 摘除）。
- 跨会话复用（P2）：系统 prompt 等公共 prefix 常驻。

### 2.5 Endpoint Decision（FR-AI-18~20）
```
def route(task):
    if privacy_detect(task): return LOCAL          # FR-AI-19 强制本地(≥99%)
    conf = local_confidence(task)                  # FR-AI-18 (≥85%)
    if conf >= threshold or not cloud_authorized(): return LOCAL
    return CLOUD                                    # FR-AI-20 透明, ≤1s
```
- privacy_detect：规则（路径/联系人/关键词）+ 轻量分类器。
- 云端调用：令牌取自 Key Vault（TEE，[TBD-17]），HTTPS 流式回传。

### 2.6 时序：一次流式生成
```
Agent→aihald.Generate(prompt,model,{stream:true})
  aihald: securityd.CheckPermission(resource) → route(local/cloud)
        → Scheduler 入队 → backend.generate(on_token)
        → 逐 token 经 TokenStream signal / fd 回传
        → 结束 securityd.AuditLog + MeterTokens
```

---

## 3. bianbu-agent-runtimed 详细设计

### 3.1 Lifecycle FSM（FR-RTE-01）
```
状态: INSTALLED, RUNNING, PAUSED, STOPPED, TERMINATED
合法转换表（拒绝表外转换）:
  INSTALLED --Start--> RUNNING
  RUNNING --Pause--> PAUSED --Resume--> RUNNING
  RUNNING --Stop--> STOPPED --Start--> RUNNING
  PAUSED --Stop--> STOPPED
  {RUNNING,PAUSED,STOPPED} --Terminate--> TERMINATED --cleanup--> INSTALLED?/removed
```
每 Agent 一个 FSM 实例 + 互斥锁，防并发转换竞态。

### 3.2 Sandbox Manager（FR-SBX-01~07）—— Start 关键路径（≤200ms）
```
Start(agent_id):
 1. securityd.BuildSandboxPolicy → seccomp_path, netfilter_rules   [并行预取]
 2. 准备 overlayfs: lowerdir=agent_ro, upperdir=agent_rw, merged=root
 3. clone(NEW ns per level) / Phase1 仅 mount+chroot
 4. 应用 cgroup v2: CPUQuota/MemoryMax/IOWeight 写 cgroup.subtree
 5. 下发 netfilter 白名单（默认 DROP）
 6. execve 前: cap drop + seccomp_load
 7. 注入 SDK runtime → on_start → FSM=RUNNING → AuditLog
 失败任一步: 回滚已建资源, 拒绝启动, 告警 (FR-SBX-07 fail-closed)
```
性能：步骤1与2/3并行，overlayfs 与 cgroup 预创建模板复用以压 ≤200ms（[TBD-15] baseline）。

### 3.3 Checkpoint/Restore（FR-RTE-07~11）
- **快照内容**：进程内存（CRIU 或 SDK 序列化状态）+ 记忆引用 + 会话上下文 + 时间戳。
- **自动**：定时器周期触发（≤500ms 完成），写 `/var/lib/bianbu/checkpoints/<agent_id>/<ckpt_id>/`。
- **保留策略**：环形保留最近 10 个，超出删最旧（FR-RTE-11）。
- **崩溃恢复**（FR-RTE-10）：agent-runtimed 监控 Agent 进程退出码，异常退出 → 取最新 ckpt → Restore（成功率 ≥95%，失败降级为重启到 INSTALLED 并告警）。

### 3.4 Resource Monitor（FR-RTE-12/13）
- 每 1s 读 cgroup `memory.current`/`cpu.stat` → 更新统计 → signal 推 GUI。
- `memory.current > 2GB`（或自定义）→ 触发 Pause + `ResourceExceeded` 通知。
- 历史环形缓冲，ExportResourceHistory 导出 JSON/CSV。

---

## 4. bianbu-memoryd 详细设计（FR-MEM-*）

### 4.1 存储布局
- 向量：LanceDB 表 `mem_<agent_id>`（namespace 物理隔离，FR-MEM-04）。
- 元数据/KV：SQLite（[TBD-5]）`memory.db`：
```sql
CREATE TABLE mem(agent_id,key,text,vector_id,ttl_ms,ts,last_access,
                 PRIMARY KEY(agent_id,key));
```
- 路径：`~/.local/share/bianbu-agents/<id>/memory/`（[TBD-6]）。

### 4.2 算法
- **Store**：写 SQLite + 若为文本则 aihald.Embed → LanceDB 插入 vector_id。
- **Retrieve**（FR-MEM-03，≤100ms）：aihald.Embed(query) → LanceDB ANN top_k → 回填 text/score。
- **隔离**（FR-MEM-04）：调用者身份 vs agent_id 校验，不符 → PermissionDenied。
- **容量+LRU**（FR-MEM-05）：维护 `sum(bytes)`；超上限（[TBD-4] 默认 256MB）按 last_access 升序淘汰至阈值下。
- **TTL**（FR-MEM-06,P2）：惰性 + 定时清理 `ts+ttl_ms < now`。
- **Clear/卸载清理**（FR-MEM-08）：drop 表 + 删目录。

---

## 5. bianbu-intentd 详细设计（FR-INT/ASR）

### 5.1 意图解析流水（FR-INT-01~04，≤200ms）
```
text → 归一化 → Qwen2-0.5B 分类器 → intent∈16类 + conf
     → 槽位抽取（模板/NER 混合）→ slots
     → 若 session 有上下文: 指代消解（FR-INT-03）
```
- 16 类标签固定枚举（PRD 5.5.2.1），分类器输出 softmax top-1；conf < 阈值 → 兜底类。
- 多轮：session_id → 环形对话栈，指代（"第一个"）映射到上一结果集索引。
- 测试集：每类 ≥50 条（[TBD-10]），top-1 ≥90%。

### 5.2 语音（FR-ASR）
- ASR：Whisper.cpp tiny 常驻；VAD 切分；流式转写。
- TTS：Piper 常驻声学模型；文本分句流式合成，边合成边播。
- 端到端预算（FR-ASR-04 ≤1.5s）：VAD+ASR ≤500ms ∥ 意图 ≤200ms → 推理首 token ≤200ms（流式）→ 执行 → TTS 首句提前播，掩盖尾部延迟。

---

## 6. bianbu-skilld 详细设计（FR-SKL-*）

### 6.1 Registry
- 内存索引 `Map<trigger_term, [skill_id]>` + `Map<skill_id, SkillManifest>`；Discover 走倒排（≤50ms）。
- Invoke：解析 skill_id.function → securityd.CheckPermission → 在 Skill 沙箱进程执行 entry → 返回结果 → 审计。

### 6.2 Skill 包安装（FR-SKL-05/06）
```
Install(pkg):
  解析 skill.toml + permissions.json（schema 校验）
  依赖检查 → 收集需确认权限 → 返回 perms_to_confirm
  用户确认后: 落地 ~/.local/share/bianbu-skills/<id>/, 注册 Registry, semver 记录
```

### 6.3 MCP Gateway（FR-SKL-04）
- 对外：将 Skill manifest 映射为 MCP tool schema，起 MCP server endpoint。
- 对内：McpCall 代理到外部 MCP server，同样经权限校验与审计。

### 6.4 App Control Fallback（FR-APP-05）
```
invoke(app, action):
  try DBus 接口(APP-01, 超时) 
  except: try AT-SPI(APP-02)
  except: try 快捷键 ydotool/xdotool(APP-03)
  except: try 视觉定位+OCR(APP-04)
  全失败或总超时 3s: return FAIL
```

---

## 7. 检索引擎 bianbu-indexerd（FR-VEC-*）

- **索引构建**：目录遍历 → 分块（chunk）→ aihald.Embed(BGE) → LanceDB 插入 `{path,chunk,vector,mtime}`。
- **增量**（FR-VEC-07）：inotify 监听 create/modify/delete → 队列去抖 → 增量 upsert（新增文件 10 分钟内入索引）。
- **检索**（FR-VEC-02，≤2s）：query embed → ANN → 按 path 聚合 → 高亮片段 + score（FR-VEC-08）。
- **知了**（FR-VEC-06）：独立集合，问答时先本地检索拼上下文 → aihald 生成，可端云切换。

---

## 8. 横切关注点

### 8.1 并发模型
- 各 daemon：D-Bus 事件循环 + 工作线程池；共享状态用细粒度锁或无锁结构。
- 长任务（推理/索引/转换）异步化，经 signal/回调返回，避免阻塞总线。

### 8.2 错误与降级
| 场景 | 处理 |
|------|------|
| 模型加载失败 | 返回 Unavailable；端云可回退云端（若授权） |
| 云端不可达 | 回退本地或返回 Unavailable，不静默失败 |
| 沙箱创建失败 | fail-closed，拒绝启动（FR-SBX-07） |
| 审计写失败 | fail-closed，阻断相关操作 |
| Agent 崩溃 | checkpoint 恢复（FR-RTE-10），失败则重置+告警 |

### 8.3 可观测性
- trace_id 由入口（intent/CLI）生成，随调用链透传，各 daemon 记录 span；审计链独立。

### 8.4 安全默认
- seccomp 白名单优先；网络默认 DROP；权限最小化；密钥仅 Key Vault；日志脱敏（不落 token/密钥明文）。

---

## 9. 关键时序图（文字）

**语音→执行→审计（端到端）**
```
User→intentd: 语音
intentd→intentd: ASR+意图+槽位
intentd→securityd: CheckPermission
securityd-->intentd: allow/confirm
intentd→skilld: Invoke(skill,fn,args)
skilld→securityd: CheckPermission(工具)
skilld→aihald: Generate(prompt) [如需]
aihald-->skilld: token stream
skilld→agent-runtimed: 沙箱内执行工具/操控
agent-runtimed-->skilld: result
skilld→securityd: AuditLog
skilld→intentd: result
intentd→intentd: TTS
intentd→User: 语音/UI
```

---

## 10. 详细设计追溯与遗留

| LLD 模块 | API | SRS FR | 遗留 TBD |
|----------|-----|--------|----------|
| securityd | io.bianbu.Security | FR-SEC/SBX | TBD-2/3(计量) |
| aihald | io.bianbu.AIHal | FR-AI | TBD-14/15/16/17 |
| agent-runtimed | io.bianbu.Runtime | FR-RTE/SBX | TBD-9/15 |
| memoryd | io.bianbu.Memory | FR-MEM | TBD-4/5/6/7 |
| intentd | io.bianbu.Intent | FR-INT/ASR | TBD-10/11 |
| skilld | io.bianbu.Skill | FR-SKL/APP | TBD-18 |
| indexerd | (内部) | FR-VEC | — |
| calendard | io.bianbu.Calendar | FR-CAL | TBD-8 |

**实现顺序建议**（对齐里程碑）：M1 aihald(HAL+llama.cpp)+CLI run；M2 agent-runtimed+securityd+SBX；M3 intentd 基础+BiBit 接入；M4 memoryd+indexerd+calendard；M5 SDK/CLI/bench/doctor；M6 知了+多轮优化；M7 skilld MCP+ECO。

---

## 11. 实机校准（worker 10.0.90.243）【V1.1 新增】

依据 worker 真实软硬件（详见 HLD §9），对详细设计做落地修正与 TBD 回填。

### 11.1 沙箱管理器修正（SBX-01，因 overlayfs 不可用）
worker 上 overlay 模块存在但**非特权无法 `modprobe`**（`Operation not permitted`）。Phase1 沙箱改为：
```
Start(agent_id) 文件隔离:
  优先: 若 overlayfs 可用(root/CAP_SYS_ADMIN 或已加载) → lowerdir/upperdir/merged
  回退(默认): bind-mount 方案
     - mkdir 私有根 ~/.local/share/bianbu-agents/<id>/
     - mount --bind <agent_rw> <root>；只读依赖用 mount --bind -o ro
     - chroot/pivot_root 进入
  资源: cgroup v2 (worker 确认可用) CPUQuota/MemoryMax/IOWeight
  syscall: seccomp-bpf (worker 确认可用) + cap drop
  网络: netfilter 白名单
  ns(Phase2): PID/NET/MNT/UTS/IPC — worker userns 状态 n/a，需实测特权需求
```
性能：无 overlayfs 写时复制开销，bind-mount 更轻，利于 ≤200ms 冷启动目标（[TBD-15] 待实测）。

### 11.2 AI HAL 后端修正（SpacemiT 定制栈，无独立 NPU）
```
后端与加速通路（见 AGENTS.md 运行平台基线）:
  1. LlamaSpacemitBackend  — 定制 llama.cpp + ggml-spacemit；LLM 本地主引擎，GGUF Q4/Q8 小模型(0.5B~7B)
       加速: A100 簇=IME2+TCM，X100 簇=IME1；IME 未覆盖算子 → 回退 RVV → 回退 CPU
  2. OnnxSpacemitBackend   — onnxruntime + spacemit-ep (riscv64 IME/TCM 适配版)；视觉/OCR/嵌入主后端
  3. CloudBackend          — openai/anthropic 兼容，端云回退（授权+隐私门控）
  说明1: 编译 llama.cpp 与 onnxruntime 均需 SpacemiT 定制 toolchain 才能启用 IME/TCM，标准 riscv64-gnu 不行
  说明2: worker GPU 为 Imagination PowerVR，非 LLM 加速用途，不纳入推理后端
```
**M1 spike 必做**：用**定制 toolchain** 编 `llama.cpp+ggml-spacemit`（启用 IME2/TCM）+ 跑 GGUF 7B，实测首 token，回填 [TBD-15]；同步验证 `onnxruntime+spacemit-ep`。

### 11.3 Key Vault 修正（因无 TEE）
```
FR-AI-21 密钥存储:
  目标(硬件具备时): TEE
  worker 现实(无 /dev/tee): 软件方案
    - 用户级 secret: gnome-keyring（worker 已运行 gnome-keyring-daemon）
    - 服务级 secret: 加密文件(age/libsodium) + root-only 权限 + securityd 代理读取
  普通 Agent 经 CheckPermission 门控，不可直读密钥文件
```
[TBD-17] 回填：**当前 K3 无 TEE，采用 keyring/加密文件软方案；TEE 为未来硬件增强。**

### 11.4 能力概念对照（**仅参考 hermes，不复用**，全部自研）
> 依 AGENTS.md 复用边界：**本项目不复用 worker 上的 hermes-agent/agentforce**。下表仅将其能力清单作为**概念对照**，验证各模块可行、明确自研范围，**不桥接、不移植其代码**。

| 本设计模块 | hermes 中的同类能力（仅对照） | 自研落地动作 |
|------------|------------------------------|--------------|
| skilld / SKL | skill_manager/toolsets/optional-skills | **自研** io.bianbu.Skill 与 skill.toml 包格式 |
| App 操控 APP | browser/terminal/code_execution 工具 | **自研** FR-APP 四级 fallback 链 |
| 记忆 MEM | 分层 memory + 状态持久化 | **自研** io.bianbu.Memory：SQLite(元数据)+LanceDB(向量,RVV 待验) |
| cron/定时 | cronjob 能力 | **自研**后台任务调度 |
| 网络策略 SEC-07 | website policy 概念 | **自研** netfilter 白名单 |
| 预算 SEC-04 | budget 概念 | **自研** token_budget 计量 |
| MCP 接入 | ACP/MCP 服务概念 | **自研** MCP 网关与 SDK/Skill 调用契约 |
| TTS ASR-03 | tts 工具 | **自研** io.bianbu.Intent.Speak（集成本地 Piper） |

### 11.5 TBD 回填汇总（实机结论）
| TBD | 原状态 | 实机结论 |
|-----|--------|----------|
| TBD-14 RISC-V 成熟度 | 待验证 | 本地栈=定制 llama.cpp+ggml-spacemit / onnxruntime+spacemit-ep（IME2/TCM、IME1，回退 RVV/CPU），**须用 SpacemiT 定制 toolchain 编译验证**；worker 未预装 |
| TBD-15 性能 baseline | 待测 | 硬件为 A100+X100@2.0-2.4GHz，无 NPU，**首 token/语音端到端须在此实测**，勿沿用 NPU 假设 |
| TBD-16 选型截止 | 已定向 | LLM=定制 llama.cpp+ggml-spacemit；视觉/OCR=onnxruntime+spacemit-ep；向量库 LanceDB 需验 riscv64 可用性 |
| TBD-17 TEE | 待确认 | **无 TEE**，软件密钥方案（见 11.3） |
| TBD-5/6 记忆存储 | 待定 | 自研 SQLite(元数据)+LanceDB(向量)；路径 `~/.local/share/bianbu-agents/<id>/memory/` |

---

## 12. 实现顺序（对齐里程碑，实机校准）
- **M1**：aihald + **ggml-spacemit spike**（定制 toolchain 编 llama.cpp+ggml-spacemit，IME2/TCM，实测 GGUF 首 token 回填 [TBD-15]）+ CLI run
- **M2**：bianbu-agent-runtimed + securityd + SBX（**bind-mount 沙箱**方案）
- **M3**：intentd 基础 + 自研 BiBit 入口
- **M4**：memoryd（自研）+ indexerd + calendard
- **M5**：SDK/CLI/bench/doctor（doctor 须检测 SpacemiT 定制 toolchain、ggml-spacemit、spacemit-ep、IME/TCM 驱动、TEE 缺失并给建议）
- **M6**：知了 + 多轮优化
- **M7**：skilld MCP（自研网关）+ ECO

---
*BN-LLD-001 V1.1 · 输入 BN-API-001 + BN-HLD-001 V1.1 + BN-SRS-001 + worker 10.0.90.243 实测。内容由 AI 辅助生成；[TBD] 已按实机部分回填。*
