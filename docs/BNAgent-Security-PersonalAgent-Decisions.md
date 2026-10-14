# personal-agent × AgentOS Security 接入 — 待确认事项（架构与流程）

| 项 | 内容 |
|----|------|
| 文档编号 | BN-SEC-PA-DECISION-001 |
| 版本 | V1.0 |
| 日期 | 2026-08-11 |
| 前置 | BN-SEC-PA-ASSESS-001（评估稿，其中两处结论已由本文更正） |
| 需求边界 | A+B+C 全要；能力级判权以 securityd 为准；**可改 bianbu_agent** |
| 状态 | 12 项待确认（4 项阻塞、5 项影响设计、3 项可延后） |

---

## 0. 先说已经查实的事实（不需要你确认，供决策参考）

评估稿里两处结论是错的，已更正：

| # | 评估稿说法 | 实际（源码查实） |
|---|-----------|-----------------|
| 1 | `BEFORE_TOOL` 返回 `{"action":"deny",...}` 拦截 | **错**。契约是 `HookHandler = Callable[[RunContext], Awaitable[ContextPatch | None]]`，拦截靠 **`raise PermissionError`** |
| 2 | hook 层可改写工具参数做 DLP 脱敏 | **错**。`ContextPatch` 只有 `context_sections` / `metadata` / `direct_reply`，无参数通道 |

另外查实三条对方案影响很大的事实：

**① 全部工具都被 hook 覆盖**（原先担心内置工具漏网）

```
default_engine.py:22   build_plugin_tools(generation.tools[...], hook_runner=generation, hook_ids=agent.hooks)
  → plugin_tools.py:114 build_plugin_tools()
      → _adapt_tool()  每个工具包一层 invoke()
          → BEFORE_TOOL hook → contribution.handler() → AFTER_TOOL hook
```

内置工具、插件工具、MCP 工具**走同一条 `_adapt_tool` 路径**。A 能全覆盖，不必在主干另加内置工具拦截点。

**② `PermissionError` 是既有的权限门设计**

`plugins/host.py:319-325` 对 `BEFORE_RUN` / `BEFORE_TOOL` / `BEFORE_MODEL` 三点**专门重抛 `PermissionError`**，其他异常一律 catch + warning + continue。`plugin_tools.py::invoke()` 无 try/except，所以 `PermissionError` 直穿到 LangGraph，`contribution.handler` 不执行。

MCP 自己也用同一手法（`mcp/plugin.py:135-140`）：未授权的 server 直接 `raise PermissionError`。**这是项目既有惯例，securityd 沿用即可。**

**③ MCP 已有现成授权钩子**

```python
MCPAuthorizer = Callable[[str, str], bool | Awaitable[bool]]   # mcp/plugin.py:33
# 签名：(agent_id, mcp_id) -> bool
```

securityd 可直接接这里做**整台 server 级**判权，无需改 MCP 模块。

且 MCP 工具的 `qualified_id = f"{mcp_id}/{local_name}"`，hook context 收到的是**真 qualified_id**（不是 `encode_tool_name` 的 hash 名）—— 按 `<mcp_id>/*` 前缀映射能力天然可行。

---

## 1. 阻塞项（不定这 4 个，代码没法动）

### ① `PermissionError` 拦截后的用户体验 —— 终止 run 还是让 Agent 重试？

**背景**：`PermissionError` 会直穿到 LangGraph 的 `create_agent`。但 LangGraph 对工具异常有两种处理：包成 `ToolMessage` 交回模型（Agent 会看到错误、可能改参数重试），或直接冒泡终止整个 run。**具体行为取决于 `create_agent` 的配置，我尚未实测**（列为验证项 V1）。

这个差别对安全语义很关键：

| 行为 | 后果 | 好/坏 |
|------|------|-------|
| 包成 ToolMessage 交回模型 | Agent 看到"权限被拒"，可能换个路径再试（比如改用别的工具达到同样目的）| 体验好、但**给了 Agent 绕道空间** |
| 冒泡终止 run | 整轮对话中断，用户看到报错 | 安全硬、但**体验差**（一次越权就断整轮）|

**需要你定**：

- (a) **交回模型**（宽松）—— 允许 Agent 换路径，靠 capability 覆盖面兜住；越权尝试全部记审计
- (b) **终止 run**（严格）—— 一次越权即中断，适合高合规场景
- (c) **按 risk_level 分档** —— L1/L2 交回模型，L3/L4 终止 run（推荐；需在适配层区分两种异常类型）

> 我倾向 (c)。低风险越权让 Agent 自己调整，高风险直接断，避免 Agent 反复试探。

---

### ② DLP 脱敏改写通道 —— 改哪一层？

hook 层没有参数改写能力（事实更正 #2）。既然可改 bianbu_agent，有三个落点：

| 方案 | 落点 | 改动量 | 影响面 |
|------|------|--------|--------|
| **B1** | 扩 `ContextPatch` 加 `rewritten_arguments` 字段，`_adapt_tool` 里应用 | 小（约 30 行）| 改公共契约，所有 hook 都能改参数 —— **权力过大** |
| **B2** | `_adapt_tool::invoke()` 里直接插 securityd 脱敏调用（不经 hook 契约）| 中（约 60 行）| 与 hook 系统解耦，securityd 专属通道 |
| **B3** | 在 LangChain 中间件层做（与 HITL 中间件同层）| 中（约 80 行）| 最贴 LangGraph 原生，但要处理 message 结构 |

**需要你定**：走哪个？

> 我倾向 **B2**。B1 把"改写工具参数"开放给任意 hook，是个不小的权限扩张（任何插件都能改别的工具的参数）；B2 是 securityd 专属通道，边界清楚。

---

### ③ 判权失败时 fail-closed 还是 fail-open？

securityd 不可达时（D-Bus 挂了、securityd 没起）：

- (a) **fail-closed** —— 所有工具调用被拒。安全，但 securityd 一挂 personal-agent 全废
- (b) **fail-open** —— 放行 + 记日志。可用性优先，但安全形同虚设
- (c) **分档** —— L1/L2 fail-open，L3/L4 fail-closed

securityd 侧已有 `BIANBU_SECURITY_FAIL_OPEN` 环境变量（默认 fail-closed）。

**需要你定**：personal-agent 的默认值取哪个？

> 个人使用场景建议 (c)；多用户/合规场景建议 (a)。

---

### ④ agent_id 映射规则

securityd 的能力表主键是 `(agent_id, capability, scope)`。personal-agent 是**多 Agent** 架构（`agents/<id>/agent.yaml`，`default_agent_id: default`）。

| 方案 | 映射 | 后果 |
|------|------|------|
| (a) 一对一 | `com.bianbu.agent.<agent_id>` | 每个 Agent 独立能力配置，粒度细，但配置量随 Agent 数增长 |
| (b) 全局共用 | `com.bianbu.agent` | 一份配置管全部，简单，但**无法按 Agent 差异化授权** |
| (c) 分层 | 全局默认 + 按需覆盖单个 Agent | 兼顾（securityd 的 scope 通配已支持类似语义）|

**需要你定**：走哪个？这决定 WebUI 上要配几套能力表。

> 我倾向 (c)：默认继承全局，需要收紧的 Agent 单独配。

---

## 2. 影响设计（可先按我的建议做，但你最好过一眼）

### ⑤ 8 个 hook 点的映射与 DLP 落点

| personal-agent | securityd | 挂什么 | 备注 |
|----------------|-----------|--------|------|
| `before_run` | `agent_startup` | DLP 策略加载 | |
| `after_context` | `input` | DLP 输入过滤 | **脱敏需 B2 通道** |
| `before_model` | `pre_model_call` | DLP 云端 L3/L4 阻断 | **脱敏需 B2 通道** |
| `after_model` | `post_model_call` | DLP 输出检测 + 逐字泄露 + Token 计量 | |
| `before_tool` | `pre_tool_call` | **SEC 判权（主战场）** + DLP 参数扫描 | 拦截靠 `PermissionError` |
| `after_tool` | `post_tool_call` | DLP 返回值脱敏 + 审计 | **脱敏需 B2 通道** |
| `after_run` | `output` | DLP 最终审查 + 还原 + 水印 | |
| `on_error` | —— | 审计（personal-agent 独有）| securityd 侧无对应点，建议只记审计 |

**需要你确认**：`on_error` 只记审计够不够？还是也要参与判权（比如错误信息里含 PII 要脱敏）？

---

### ⑥ MCP 判权粒度 —— 两层能力如何配合

MCP 有两个可判权的层次：

```
层 1：整台 server        MCPAuthorizer(agent_id, mcp_id) -> bool     ← 现成钩子
层 2：单个工具调用       BEFORE_TOOL hook，qualified_id = <mcp_id>/<tool>
```

建议**两层都接**：

- 层 1 接 `MCPAuthorizer` → 查 securityd 能力 `mcp.<mcp_id>`（整台 server 授权）
- 层 2 在 `before_tool` 按 `<mcp_id>/*` 前缀映射到具体能力 + DLP 扫参数

**需要你定**：MCP 工具的能力映射方式

- (a) **每台 server 在 WebUI 显式配置**能力（准确，需人工维护）
- (b) 关键字推断（自动，但第三方工具名不可控，`search_files` 可能被推成 `network.access` 而实际是文件操作）
- (c) (a) 为主 + (b) 兜底未配置的

> 我倾向 (c)：显式配置优先，未配置的用关键字推断并在 WebUI 标黄提示"推断值，建议人工确认"。

---

### ⑦ 动态 HITL 的审批 UI 走哪条路

现状：`langgraph/engine.py:205` 的 `interrupt_on` 由**静态** `tool.metadata["requires_approval"]` 决定。securityd 的 CONFIRM 是**动态**判定。

改造后 securityd 判 CONFIRM 时，审批弹窗走哪里？

- (a) 复用 personal-agent 原生 HITL（`HumanInTheLoopMiddleware` 的 approve/reject）—— 用户在它自己的 WebUI 上批
- (b) 走 securityd 的 D-Bus `RequestConfirm` → bianbu-security WebUI 确认门禁 Tab 批
- (c) 两者都支持，可配置

**需要你定**：走哪个？

> 我倾向 (a)。用户已经在 personal-agent 的 WebUI 里对话，弹窗出现在同一界面才连贯；securityd 的 WebUI 更适合管理员配策略而非日常审批。

---

### ⑧ 沙箱化范围（C）—— 包整个服务还是只包子进程

| 方案 | 范围 | 得到 | 风险 |
|------|------|------|------|
| **C1** | bwrap 包整个 FastAPI 服务进程 | 文件隔离 + syscall 拦截 + cap 裁剪，MCP 子进程自动继承 | FastAPI 要对外绑 `0.0.0.0:9899`；SQLite WAL 在沙箱内行为待实测；`npx` 起 MCP 需 node + 网络 |
| **C2** | 只沙箱化 MCP stdio 子进程 | 隔离最危险的部分（第三方代码）| 主服务与插件仍无隔离（插件是进程内可信代码）|
| **C3** | C1 + C2 双层 | 最严 | 复杂度最高 |

**需要你定**：C 的范围？

> 建议分两步：**先 C2**（风险最高、隔离收益最直接、不影响主服务可用性），**再评估 C1**。C1 的端口绑定和 SQLite 行为需要实测才能定，不宜一上来就做。

---

### ⑨ Token 配额的计量点

securityd 的 Token 配额（SEC-04）需要 LLM 用量数据。personal-agent 里两个可选点：

- (a) `after_model` hook —— 拿 `RunContext`，但**需确认 hook context 里有没有 token usage**（验证项 V4）
- (b) LangChain `BaseCallbackHandler.on_llm_end` —— 我在 INT-LG-06 已实现，可直接复用

**需要你定**：走哪个？

> 我倾向 (b)，INT-LG-06 的 `BianbuTokenCallback` 现成可用，且 `on_llm_end` 拿到的 usage 数据更规范。

---

## 3. 可延后（先记着，做到那步再定）

### ⑩ 审计存储位置

securityd 的审计链在自己的 `<data>/audit/`，personal-agent 有自己的 `logs/`。是否需要在 personal-agent 的 WebUI 里展示 securityd 审计？还是让用户去 bianbu-security WebUI 看？

### ⑪ 配置来源的权威性

personal-agent 的角色 `tools: ["*"]` 白名单与 securityd 的能力表，同一工具两处都能管。既然"能力级判权以 securityd 为准"，那 personal-agent 的角色白名单是否要：

- (a) 保留（两层过滤，securityd 更严）
- (b) 改为只做 UI 展示，实际判权全交 securityd
- (c) 从 securityd 反向生成角色白名单

### ⑫ 部署形态

- securityd 跑 root 系统总线，还是与 personal-agent 同用户会话总线？
- personal-agent 用 `uv` 管依赖，securityd 客户端（`dbus-python`）如何进它的虚拟环境？

---

## 4. 需要实测的技术项（我做，不需要你定，但结论可能反过来影响 ①②⑨）

| # | 项 | 为什么关键 |
|---|-----|-----------|
| **V1** | `PermissionError` 在 `create_agent` 下的真实行为 —— 包成 ToolMessage 还是终止 run | 直接决定 ① 的选项可行性 |
| **V2** | Python 3.13 兼容性（personal-agent 要求 `>=3.11,<3.14`；securityd 在 **3.14.4** 上验的） | 若有差异需回退适配 |
| **V3** | 异步边界开销 —— hook 是 `async`，securityd D-Bus 客户端同步阻塞，需 `run_in_executor` | 影响每次工具调用的延迟 |
| **V4** | `after_model` hook context 里有无 token usage | 决定 ⑨ 的选项 (a) 是否可行 |
| **V5** | SQLite WAL 在 bwrap 沙箱内的行为 | 决定 ⑧ 的 C1 可行性 |

**V1 必须先做。** hermes 接入时踩过同类坑：契约看着对、实际行为不对（误判 `invoke_hook` 返回类型），导致拦截静默失效，漏过率 terminal 46% / execute_code 43%。这次不能只读代码就下结论。

---

## 5. 修订后的架构图

```
┌─────────────────────────── personal-agent (FastAPI + LangGraph) ───────────────────────────┐
│                                                                                            │
│  create_agent(model, tools, middleware=[...])                                              │
│       │                                                                                    │
│       ├─ QueuedSteeringMiddleware                                                          │
│       ├─ HumanInTheLoopMiddleware ◄──── B：改造为 securityd 感知（动态 interrupt_on）       │
│       └─ [新增] BianbuDLPMiddleware ◄─── B2：DLP 脱敏改写通道（决策 ②）                     │
│                                                                                            │
│  每个工具经 _adapt_tool() 包装：                                                            │
│    invoke() ─→ BEFORE_TOOL hook ─→ handler() ─→ AFTER_TOOL hook                            │
│                     │                                  │                                   │
│                     ▼                                  ▼                                   │
│           ┌──────────────────── A：hook 适配层（plugins/bianbu.security/）──────────────┐   │
│           │  raise PermissionError 拦截（既有惯例）                                      │   │
│           │  run_in_executor 包裹同步 D-Bus 调用（V3）                                   │   │
│           └────────────────────────────┬──────────────────────────────────────────────┘   │
│                                        │                                                   │
│  MCPAuthorizer(agent_id, mcp_id) ──────┤ ◄──── 层 1：整台 server 判权（决策 ⑥）            │
│                                        │                                                   │
└────────────────────────────────────────┼───────────────────────────────────────────────────┘
                                         │ D-Bus io.bianbu.Security（控制面）
                                         │ UDS /run/bianbu/securityd.sock（数据面 >4KB）
                                         ▼
┌─────────────────────── bianbu-securityd（已完成 86/86 需求）──────────────────────────────┐
│  InterceptorRegistry                                                                      │
│    pri=10  sec_capability   CheckPermission → ALLOW / CONFIRM / BLOCK                      │
│    pri=50  dlp_*（8 点）    PII 检测（召回 99.75% / 误报 0.75%）                            │
│    pri=90  audit            SHA-256 哈希链，防篡改                                          │
└───────────────────────────────────────────────────────────────────────────────────────────┘
                                         │
                    C：bwrap 沙箱（决策 ⑧）—— 包服务进程 和/或 MCP 子进程
```

---

## 6. 修订后的流程（before_tool 判权，最关键一条）

```
LangGraph 决定调用工具 read_file(path="/home/user/身份证.txt")
  │
  ├─ 1. _adapt_tool::invoke() 触发 BEFORE_TOOL hook
  │      context = RunContext(run_id, session_id, agent_id, request, metadata)
  │      metadata 含 qualified_name + arguments
  │
  ├─ 2. 适配层 async handler
  │      loop.run_in_executor(None, lambda: registry.invoke(   ← V3：避免阻塞事件循环
  │          HookPoint.PRE_TOOL_CALL, agent_id,
  │          {"tool": qualified_name, "capability": cap, "scope": scope, "args": args}))
  │
  ├─ 3. securityd 干预点链（pri 顺序）
  │      ├─ sec_capability@10  → CheckPermission(agent_id, "file.read", "/home/user")
  │      │                        └─ DENY → 短路，DLP 不执行（省扫描开销）
  │      ├─ dlp_pre_tool@50    → 扫 args 里的 PII → 检出身份证 → 提升为 CONFIRM
  │      └─ audit@90           → 写审计链（op_type="hook:pre_tool_call"）
  │
  ├─ 4. 决策落地
  │      ├─ ALLOW    → handler 正常执行
  │      ├─ BLOCK    → raise PermissionError(...)   ← 行为取决于决策 ①
  │      └─ CONFIRM  → 触发审批                      ← 走哪条取决于决策 ⑦
  │                     (a) personal-agent 原生 HITL 弹窗
  │                     (b) securityd D-Bus RequestConfirm
  │
  └─ 5. 工具执行完 → AFTER_TOOL hook → DLP 返回值脱敏（需 B2 通道，决策 ②）+ 审计
```

---

## 7. 请回复这 9 个决策

阻塞项（必须先定）：

1. **①** `PermissionError` 后的行为：(a) 交回模型 / (b) 终止 run / **(c) 按 risk_level 分档** ← 建议
2. **②** DLP 脱敏通道：(B1) 扩 ContextPatch / **(B2) `_adapt_tool` 专属通道** ← 建议 / (B3) 中间件层
3. **③** fail 策略：(a) fail-closed / (b) fail-open / **(c) 分档** ← 建议
4. **④** agent_id 映射：(a) 一对一 / (b) 全局共用 / **(c) 分层** ← 建议

影响设计：

5. **⑤** `on_error` 只记审计够吗？
6. **⑥** MCP 能力映射：(a) 显式 / (b) 推断 / **(c) 显式为主+推断兜底** ← 建议
7. **⑦** 审批 UI：**(a) personal-agent 原生 HITL** ← 建议 / (b) securityd WebUI / (c) 都支持
8. **⑧** 沙箱范围：(C1) 整服务 / **(C2) 先只包 MCP 子进程** ← 建议 / (C3) 双层
9. **⑨** Token 计量点：(a) `after_model` hook / **(b) `BianbuTokenCallback`（现成）** ← 建议

⑩⑪⑫ 可延后，做到那步再定。

---

*文档结束 — BN-SEC-PA-DECISION-001 v1.0*
