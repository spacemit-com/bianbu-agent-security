# bianbu-agent × AgentOS Security 集成技术方案（可商用）

| 项 | 内容 |
|----|------|
| 文档编号 | BN-SEC-BA-TECH-001 |
| 版本 | V1.0 |
| 日期 | 2026-08-11 |
| 需求 | PRD 第八章 INT-PA-01~18（37 P·D） |
| 目标系统 | `personal-agent` / `bianbu-agent` v0.1.0（FastAPI + LangGraph + MCP，304 py 文件） |
| 接入方 | `impl/bianbu-securityd`（86/86 需求已验证，324 测试通过） |
| 前置验证 | BN-SEC-PA-PHASE0-001（P1/P2/P3 全通过） |

---

## 1. 源码 deep dive 结论

以下全部从源码读出，是方案的事实基础。

### 1.1 调用链（工具执行的完整路径）

```
api/runs.py  POST /api/v1/runs
  → run_manager.py         RunBroker 派发
    → service_runtime.py   ServiceRuntime 持有 PluginManager + AgentManager
      → default_engine.py:22   build_plugin_tools(generation.tools[...],
                                    hook_runner=generation, hook_ids=agent.hooks)
        → langgraph/plugin_tools.py:114  build_plugin_tools()
          → _adapt_tool(contribution, hook_runner, hook_ids, resolver)
              返回 StructuredTool(name=encode_tool_name(qualified_id), coroutine=invoke)
        → default_engine.py:39   build_langgraph_agent(model, checkpointer, tools, prompt)
          → langgraph/engine.py:177  create_agent(model, tools, middleware=[...])
                middleware = [QueuedSteeringMiddleware(),
                              HumanInTheLoopMiddleware(interrupt_on=...)]
      → LangGraphEngine.stream()  → graph.astream(stream_mode="messages")
```

**工具实际执行**（`plugin_tools.py:67-96`）：

```python
async def invoke(config: RunnableConfig, **arguments) -> str:
    context = _tool_context(config)                      # 从 configurable 提取 run/session/agent
    qualified_name = contribution.spec.metadata["qualified_id"] or spec.name
    if hook_runner is not None:
        await _run_hooks(hook_runner, HookPoint.BEFORE_TOOL,
                         _hook_context(context, qualified_name, arguments), hook_ids)
    result = await contribution.handler(context, dict(arguments))   # ← 真正执行
    if hook_runner is not None:
        await _run_hooks(hook_runner, HookPoint.AFTER_TOOL,
                         _hook_context(..., result_metadata=dict(result.metadata)), hook_ids)
    return result.content
```

**关键**：`_run_hooks` 的返回值被**丢弃**（`await` 后不接收）。所以 hook 无法用返回值改参数 —— 只能靠抛异常拦截。

### 1.2 三类工具走同一条路（判权可全覆盖）

| 工具类型 | 来源 | 是否经 `_adapt_tool` |
|---------|------|---------------------|
| 内置工具（`cronjob`、`evolution_undo`）| `tools/definitions.py` → catalog | ✅ |
| 插件工具 | `plugins/<id>/tools/` | ✅ |
| MCP 工具 | `mcp/plugin.py::MCPDirectoryPlugin` → `ToolContribution` | ✅ |

全部汇入 `generation.tools`，`default_engine.py:22` 统一取。**A 类判权无死角。**

### 1.3 hook 契约（实测确认）

```python
HookHandler = Callable[[RunContext], Awaitable[ContextPatch | None]]

@dataclass(frozen=True, slots=True)
class RunContext:
    run_id: str; session_id: str; agent_id: str; request: str
    metadata: Mapping[str, object]

@dataclass(frozen=True, slots=True)
class ContextPatch:
    context_sections: tuple[str, ...] = ()
    metadata: Mapping[str, object] = {}
    direct_reply: str | None = None      # 仅 BEFORE_RUN 允许
```

`_hook_context()` 填充的 `metadata`：

| 键 | 值 |
|----|-----|
| `tool` | `qualified_id`（真名，非 `encode_tool_name` 的 hash）|
| `arguments` | 工具参数 dict |
| `run_id` / `session_id` / `agent_id` / `request_id` / `thread_id` | 全部 configurable 透传 |
| `result_metadata` | 仅 AFTER_TOOL 有 |

**拦截机制**（`plugins/host.py:317-325`）：

```python
except BaseException as exc:
    if isinstance(exc, (KeyboardInterrupt, SystemExit)): raise
    if isinstance(exc, PermissionError) and point in {
        HookPoint.BEFORE_RUN, HookPoint.BEFORE_TOOL, HookPoint.BEFORE_MODEL,
    }: raise                        # ← 三个 before 点重抛
    logger.warning(...); continue   # ← 其他异常吞掉
```

`plugin_tools.py::invoke()` 无 try/except → `PermissionError` 直穿到 LangGraph。

### 1.4 hook 交付形态（已有占位实现可改造）

`.personal-agent/plugins/bianbu.security/` **已存在**，含两个占位 hook：

```
bianbu.security/
├── hooks/security.before_tool/hook.py    # 21 行，只读预设 metadata 标记
├── hooks/security.before_model/hook.py   # 16 行，同上
└── skills/security-guide/SKILL.md
```

加载契约（`hooks/loader.py:39-56`）：

- 每个 hook 一个目录，目录名 = hook id，内含单文件 `hook.py`
- `hook.py` 必须导出 `create_hook(context) -> HookContribution`
- `contribution.id` 必须等于目录名
- `context: HookLoadContext` 含 `workspace_root` / `data_root` / `owner_plugin_id` / `approved_permissions` / **`services`**（依赖注入通道）

权限枚举（`plugins/models.py:57-64`）：`run.observe` / `run.transform_context` / `tool.provide` / `tool.inspect` / `tool.decide` / `skill.provide` / `filesystem.plugin_data`

现有占位 hook 声明 `{run.observe, tool.inspect, tool.decide}` —— 判权需要的权限已齐。

### 1.5 中间件协议（P3 实测，langchain 1.3.14/1.5.3）

```python
class AgentMiddleware:
    async def awrap_tool_call(
        self, request: ToolCallRequest,
        handler: Callable[[ToolCallRequest], Awaitable[ToolMessage | Command]],
    ) -> ToolMessage | Command: ...
```

**wrapper 式** —— 可短路（不调 handler）、可重试（多次调）、可改写 request/response。

```python
@dataclass
class ToolCallRequest:
    tool_call: ToolCall          # 含 name / args / id
    tool: BaseTool | None
    state: Any
    runtime: ToolRuntime
    def override(self, **kw) -> ToolCallRequest: ...   # 官方改写方法
```

`InterruptOnConfig`（TypedDict）：

```python
{
  "allowed_decisions": list[DecisionType],
  "description": NotRequired[str | _DescriptionFactory],
  "args_schema": NotRequired[dict],
  "when": NotRequired[Callable[[ToolCallRequest], bool]],   # ← 逐次求值
}
```

`when` 是**每次工具调用都求值的 callable** → 动态 HITL 不需要重建 `interrupt_on`。

### 1.6 HITL 审批的完整往返

```
中间件判定需审批 → HumanInTheLoopMiddleware 发 interrupt
  value = {"action_requests": [{name, args, description}, ...],
           "review_configs":  [{allowed_decisions}, ...]}
  ↓
LangGraphEngine._pending_approval(config)  (engine.py:574)
  读 interrupt.value，decode_tool_name 还原真工具名
  → {"approval_id": interrupt.id, "actions": [{name, arguments, description, allowed_decisions}]}
  ↓
api/runs.py:585  event.kind == "approval_required" → SSE 推给前端
  ↓
用户在 WebUI 点批准/拒绝
  ↓
POST /api/v1/runs/{run_id}/approvals/{approval_id}   (api/runs.py:507)
  → RunBroker.resolve_approval → handle.approve(id) / handle.reject(id, reason)
  ↓
LangGraphEngine.stream(resume_decisions=[...])  (engine.py:294)
  agent_input = Command(resume={"decisions": resume_decisions})
  → graph 从 interrupt 处继续
```

**结论**：审批 UI 全链路已就绪。B 类只需让"哪些工具需审批"由 securityd 动态决定。

### 1.7 MCP 两个注入点

```python
# 层 1：整台 server 授权（现成钩子，service_runtime.py:176-184 已有默认实现）
MCPAuthorizer = Callable[[str, str], bool | Awaitable[bool]]   # (agent_id, mcp_id) -> bool
# 现默认实现：return mcp_id in agent.mcps

# 层 2：子进程启动（mcp/client.py:113-118）
parameters = StdioServerParameters(command=config.command, args=list(config.args), env=dict(config.env))
async with stdio_client(parameters) as (read, write): ...
```

MCP 工具 `qualified_id = f"{mcp_id}/{local_name}"`（`mcp/plugin.py:127`）→ 前缀映射天然可行。
`MCPServerConfig` 有 `command` / `args` / `env` → **沙箱 mode=mcp 的注入点就是这里**（用 bwrap 包 command）。

### 1.8 沙箱配置的落点

```python
@dataclass(frozen=True, slots=True)
class AgentSpec:
    id: str; name: str; description: str = ""; instructions: str = ""
    model: AgentModel | str | None = None
    tools / skills / mcps / hooks: tuple[str, ...] = ()
    metadata: Mapping[str, object] = {}      # ← 开放字段
```

`agents/file_store.py:53,68` 证实 `metadata` 双向持久化到 `agent.yaml`。
**沙箱配置放 `metadata.sandbox`，无需改 schema。**

---

## 2. 总体架构

```
┌───────────────────── bianbu-agent (FastAPI :9899) ──────────────────────┐
│                                                                          │
│  api/runs.py ── SSE ──▶ WebUI（审批弹窗，全链路已就绪 §1.6）              │
│       │                                                                  │
│  default_engine.py                                                       │
│    build_plugin_tools(generation.tools, hook_runner=generation)           │
│         │                                                                │
│         └─ _adapt_tool ─▶ invoke():                                      │
│              BEFORE_TOOL hook ─┐                                         │
│              handler()          │                                        │
│              AFTER_TOOL hook ──┤                                         │
│                                 │                                        │
│    create_agent(middleware=[                                             │
│      QueuedSteeringMiddleware,   │                                        │
│      BianbuSecurityMiddleware,  ─┼── B 类：awrap_tool_call               │
│      HumanInTheLoopMiddleware ──┘    （脱敏改写 + 风险分档 + when 动态）  │
│    ])                                                                    │
│                                 │                                        │
│  ┌──────────────────────────────▼─────────────────────────────────────┐  │
│  │ A 类：.personal-agent/plugins/bianbu.security/hooks/*/hook.py       │  │
│  │   8 个 hook → SecurityBridge → securityd InterceptorRegistry        │  │
│  │   拦截：raise SecurityDenied(PermissionError)                       │  │
│  │   异步：run_in_executor 包同步 D-Bus                                │  │
│  └──────────────────────────────┬─────────────────────────────────────┘  │
│                                 │                                        │
│  MCPAuthorizer(agent_id,mcp_id) ┤ ── A 类层 1：整台 server 授权           │
│  StdioServerParameters(command) ┤ ── C 类 mode=mcp：bwrap 包 command      │
└─────────────────────────────────┼────────────────────────────────────────┘
                                  │ D-Bus io.bianbu.Security（控制面 ≤4KB）
                                  │ UDS securityd.sock（数据面 >4KB）
                                  ▼
┌──────────── bianbu-securityd（已完成，324 测试）─────────────────────────┐
│  InterceptorRegistry  pri=10 sec_capability / 50 dlp_* / 90 audit         │
│  8 干预点 · PII 召回99.75%误报0.75% · SHA-256 哈希链 · bwrap+seccomp      │
└──────────────────────────────────────────────────────────────────────────┘
```

**三层改动边界**：

| 层 | 位置 | 改动性质 |
|----|------|---------|
| A | `.personal-agent/plugins/bianbu.security/` | **纯新增**（改造现有占位 hook） |
| B | `bianbu_agent/langgraph/{engine,plugin_tools}.py` | 主干改造（约 40 行） |
| C | `bianbu_agent/mcp/client.py`、`agents/`、新增 sandbox 模块 | 主干改造 + 新增 |

---

## 3. A 类实现 —— Hook 适配层

### 3.1 目录结构

```
.personal-agent/plugins/bianbu.security/
├── _bridge/                            # 共享桥接层（非 hook 目录，不被 loader 扫）
│   ├── __init__.py
│   ├── bridge.py                       # SecurityBridge：registry + run_in_executor
│   ├── errors.py                       # SecurityDenied
│   ├── mapping.py                      # 工具→能力（含 MCP 前缀）
│   └── agent_id.py                     # 分层映射 + 缓存
├── hooks/
│   ├── security.before_run/hook.py     # DLP 策略加载
│   ├── security.after_context/hook.py  # DLP 输入过滤
│   ├── security.before_model/hook.py   # DLP 云端 L3/L4 阻断（改造现有）
│   ├── security.after_model/hook.py    # DLP 输出 + 逐字泄露
│   ├── security.before_tool/hook.py    # SEC 判权主战场（改造现有）
│   ├── security.after_tool/hook.py     # DLP 返回值 + 审计
│   ├── security.after_run/hook.py      # DLP 最终审查 + 还原 + 水印
│   └── security.on_error/hook.py       # 只记审计
└── skills/security-guide/SKILL.md      # 保留现有
```

**注意**：`hooks/loader.py` 要求每个 hook 目录内是单文件 `hook.py`。共享代码放 `_bridge/`（在 `hooks/` 之外），hook.py 用 `sys.path` 引导导入。

### 3.2 SecurityBridge（核心桥接）

```python
# _bridge/bridge.py
class SecurityBridge:
    """单例。持有 securityd registry，把同步 D-Bus 调用桥到 async hook。"""

    def __init__(self, securityd_home: str, *, with_dlp: bool = True):
        sys.path.insert(0, securityd_home)                 # securityd 包
        sys.path.insert(0, f"{securityd_home}/client")     # client SDK
        from securityd.interceptor import global_registry
        import bianbu_security_handlers as h
        h.register_core_handlers(global_registry, with_audit=True)
        global_registry.set_audit_sink(h.make_audit_sink(client_provider=self._client))
        if with_dlp:
            from securityd.dlp.handlers import register_dlp_handlers
            register_dlp_handlers(global_registry)
        self._registry = global_registry

    async def invoke(self, hook_point, agent_id, data, **ctx):
        """async 边界：run_in_executor 包同步 D-Bus，避免阻塞事件循环。"""
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            None,
            lambda: self._registry.invoke(hook_point, agent_id, data,
                                          client_provider=self._client, **ctx))
```

### 3.3 SecurityDenied（拦截异常）

```python
# _bridge/errors.py
class SecurityDenied(PermissionError):
    """继承 PermissionError → 被 host.py 的三个 before 点重抛（§1.3）。

    携带 risk_level 供 B 类中间件做风险分档（INT-PA-06）。
    """
    def __init__(self, *, tool, capability, risk_level, reason, decision="BLOCK"):
        self.tool, self.capability = tool, capability
        self.risk_level, self.reason, self.decision = risk_level, reason, decision
        super().__init__(f"[bianbu-security] {reason}")

    @property
    def should_terminate_run(self) -> bool:
        """L3/L4 终止整轮；L1/L2 交回模型（INT-PA-06）。"""
        return self.risk_level in ("L3", "L4")
```

### 3.4 before_tool（判权主战场）

```python
# hooks/security.before_tool/hook.py
def create_hook(context):
    bridge = get_bridge(context)

    async def before_tool(run):
        tool = str(run.metadata.get("tool") or run.request)
        args = run.metadata.get("arguments") or {}
        agent_id = resolve_agent_id(run.agent_id)          # 分层映射
        resolved = resolve_capability(tool, args)
        if resolved is None:
            return None                                     # DEFAULT_ALLOW
        capability, scope = resolved

        r = await bridge.invoke(HookPoint.PRE_TOOL_CALL, agent_id,
                                {"tool": tool, "capability": capability,
                                 "scope": scope, "args": args},
                                session_id=run.session_id)

        if r.decision.value == "BLOCK":
            raise SecurityDenied(tool=tool, capability=capability,
                                 risk_level=(r.metadata or {}).get("max_risk", "L3"),
                                 reason=r.message)

        patch_meta = {"securityd": {"decision": r.decision.value,
                                    "capability": capability, "scope": scope}}
        if r.decision.value == "CONFIRM":
            # hook 层无法触发 interrupt（同步返回）→ 交 B 类中间件
            patch_meta["securityd"]["requires_approval"] = True
        if r.decision.value == "MODIFY" and r.modified_data:
            # 脱敏参数经 metadata 传给 B 类中间件应用（§1.3 metadata 是唯一通道）
            patch_meta["dlp_masked_args"] = (r.modified_data or {}).get("args")
        return ContextPatch(metadata=patch_meta)

    return HookContribution(
        plugin_id=context.owner_plugin_id, id="security.before_tool",
        point=HookPoint.BEFORE_TOOL, handler=before_tool,
        timeout_seconds=35.0,                # > securityd CONFIRM 超时 30s
        permissions=frozenset({"run.observe", "tool.inspect", "tool.decide"}))
```

**`timeout_seconds=35.0` 是必须的** —— `host.py:301` 用 `asyncio.timeout(contribution.timeout_seconds)` 包 handler，默认 5s；securityd 的 CONFIRM 门禁默认 30s 超时，若 hook 5s 就被砍，CONFIRM 永远走不完。

### 3.5 agent_id 分层映射（INT-PA-05）

```python
# _bridge/agent_id.py
GLOBAL_AGENT_ID = "com.bianbu.agent"
_cache: dict[str, str] = {}

def resolve_agent_id(agent_id: str) -> str:
    """先查 <global>.<agent_id> 有无覆盖配置，无则用全局。结果缓存。

    securityd 的 CheckPermission 是精确匹配，不做前缀回退，故在客户端探测。
    """
    if agent_id in _cache:
        return _cache[agent_id]
    specific = f"{GLOBAL_AGENT_ID}.{agent_id}"
    try:
        has_override = any(a["agent_id"] == specific for a in _client().list_agents())
        resolved = specific if has_override else GLOBAL_AGENT_ID
    except Exception:
        resolved = GLOBAL_AGENT_ID
    _cache[agent_id] = resolved
    return resolved
```

### 3.6 fail 策略分档（INT-PA-07）

```python
# _bridge/bridge.py
_HIGH_RISK = {"system.execute", "execute.code", "file.write", "communication.send"}

def degrade(capability: str, error: Exception) -> None:
    """securityd 不可达时：L1/L2 fail-open，L3/L4 fail-closed。"""
    if capability in _HIGH_RISK:
        raise SecurityDenied(tool="-", capability=capability, risk_level="L3",
                             reason=f"securityd 不可达，高危能力 fail-closed（{error}）")
    logger.warning("securityd 不可达，%s fail-open 放行：%s", capability, error)
```

### 3.7 MCP 层 1 授权（INT-PA-08）

改 `service_runtime.py:176-184` 的 `authorize_mcp`，在原逻辑后串 securityd：

```python
async def authorize_mcp(agent_id: str, mcp_id: str) -> bool:
    agent = await manager.get(agent_id)
    if mcp_id not in agent.mcps:      # 原有逻辑：Agent 未选该 server
        return False
    # 新增：securityd 能力判权（capability="mcp.<mcp_id>"）
    return await _securityd_allows_mcp(agent_id, mcp_id)
```

---

## 4. B 类实现 —— 主干改造

### 4.1 BianbuSecurityMiddleware（一个中间件解决三件事）

```python
# bianbu_agent/langgraph/security_middleware.py（新增）
class BianbuSecurityMiddleware(AgentMiddleware):
    """awrap_tool_call 是 wrapper 式（§1.5）→ 一处解决脱敏/分档/审批标记。"""

    async def awrap_tool_call(self, request, handler):
        # ① DLP 脱敏改写（INT-PA-10）—— 用官方 override，主干零侵入
        masked = self._masked_args_from_state(request)
        if masked is not None:
            request = request.override(
                tool_call={**request.tool_call, "args": masked})

        # ② 风险分档（INT-PA-06）
        try:
            return await handler(request)
        except SecurityDenied as exc:
            if exc.should_terminate_run:        # L3/L4 → 冒泡终止整轮
                raise
            return ToolMessage(                 # L1/L2 → 交回模型
                content=f"[bianbu-security] {exc.reason}",
                tool_call_id=request.tool_call.get("id", ""),
                name=request.tool_call.get("name", ""),
                status="error")
```

`request.override()` 是官方方法（§1.5），比改 `_adapt_tool` 干净 —— **`plugin_tools.py` 零改动**。

### 4.2 动态 HITL（INT-PA-12）

`engine.py:189-207` 现状：

```python
protected_names = {tool.name for tool in explicit_tools
                   if tool.metadata.get("requires_approval") is True}      # 静态
interrupt_on = {name: {"allowed_decisions": ["approve", "reject"]}
                for name in sorted(set(protected_names) & loaded_names)}
```

改为给**全部工具**挂 `when` callable：

```python
def _make_when(tool_name: str):
    def when(req: ToolCallRequest) -> bool:
        """逐次求值（§1.5）→ securityd 动态判定是否需审批。
        静态 requires_approval 保留为 OR 条件，向后兼容。"""
        return _securityd_requires_confirm(req) or tool_name in protected_names
    return when

interrupt_on = {
    name: {"allowed_decisions": ["approve", "reject"], "when": _make_when(name)}
    for name in sorted(loaded_names)
}
```

审批弹窗、SSE 推送、`resume_decisions` 全链路复用现有实现（§1.6），**改动约 15 行**。

### 4.3 Token 计量（INT-PA-13）

`RunContext` 无 token usage 字段，runtime 也无 `AFTER_MODEL` 调用点（V4 实测）→ 走 callback：

```python
# default_engine.py
model_lc = to_langchain_model(model)
if security_enabled:
    from securityd.langgraph.callbacks import BianbuTokenCallback   # INT-LG-06 现成
    model_lc = model_lc.with_config(callbacks=[BianbuTokenCallback(agent_id)])
```

---

## 5. C 类实现 —— 三种沙箱模式

### 5.1 配置（INT-PA-14）

放 `AgentSpec.metadata`（§1.8 已证实双向持久化），不改 schema：

```yaml
# agents/<id>/agent.yaml
metadata:
  sandbox:
    mode: agent            # off | agent | mcp | tool
    net: true
    rw_dirs: ["~/.bianbu-agent/workspace"]
    mcp_servers: ["acme.filesystem"]     # mode=mcp 时限定范围
    tools: ["python_repl"]               # mode=tool 时限定范围
    limits: {cpu: "100%", memory: "2G", pids: 256}
```

**`agent` 与 `mcp` 互斥** —— agent 模式下整进程已在沙箱内，MCP 子进程自动继承，再包一层会嵌套 bwrap。

### 5.2 mode=agent（INT-PA-15）

启动脚本层面包 bwrap，不改 Python 代码：

```bash
# run.sh 增 BIANBU_SANDBOX=agent 分支
exec bwrap --unshare-user --unshare-pid --unshare-ipc --unshare-uts \
  --cap-drop ALL --seccomp 3 3<"$SECCOMP_BPF" \
  --ro-bind / / --tmpfs /tmp --proc /proc --dev /dev \
  --bind "$DATA_DIR" "$DATA_DIR" \
  -- uv run bianbu-agent --config "$CONFIG"
```

**不加 `--unshare-net`**（服务要对外绑 `0.0.0.0:9899`）。V-07 已部分验证 bwrap 内绑端口宿主可达。

### 5.3 mode=mcp（INT-PA-16）

注入点 `mcp/client.py:113`（§1.7）：

```python
if config.transport == "stdio":
    command, args = config.command, list(config.args)
    spec = _sandbox_spec_for_mcp(config)          # 读 agent metadata.sandbox
    if spec is not None:
        command, args = wrap_with_bwrap(command, args, spec)   # 默认 --unshare-net
    parameters = StdioServerParameters(command=command, args=args, env=dict(config.env))
```

**已知风险**：`npx -y @modelcontextprotocol/server-filesystem` 首次运行要联网拉包，若 `--unshare-net` 会失败 → 需预装或该 server 单独允许网络（V-08）。

### 5.4 mode=tool（INT-PA-17）

内置工具是**进程内 Python 函数**，出进程需通用 runner 序列化参数与返回值：

```python
# 在 _adapt_tool::invoke() 里，判权通过后
spec = sandbox_spec_for_tool(qualified_name, context.agent_id)
if spec is None:
    result = await contribution.handler(context, effective_args)   # 原路径
else:
    result = await run_tool_sandboxed(contribution, context, effective_args, spec)
```

**适用边界**（V-09 待逐项评估）：有副作用的工具（持 DB 连接、改进程内状态、依赖宿主 fd）不适用。首版建议只支持纯函数式工具，配置了不支持的工具要明确报错而非静默降级。

---

## 6. 关键流程（before_tool 判权全链路）

```
LangGraph 决定调 read_file(path="/home/user/身份证.txt")
  │
  ├─ BianbuSecurityMiddleware.awrap_tool_call(request, handler)
  │    ① 从 state 取上轮 hook 写的 dlp_masked_args → request.override() 改参数
  │    ② try: await handler(request)
  │
  ├─ handler → StructuredTool.invoke() → plugin_tools.invoke()
  │    │
  │    ├─ BEFORE_TOOL hook（适配层）
  │    │    resolve_agent_id("default") → "com.bianbu.agent"（分层探测+缓存）
  │    │    resolve_capability("read_file") → ("file.read", "/home/user")
  │    │    run_in_executor → registry.invoke(PRE_TOOL_CALL, ...)
  │    │      ├─ sec_capability@10  CheckPermission → DENY 则短路（省 DLP 扫描）
  │    │      ├─ dlp_pre_tool@50    扫 args 检出身份证 → 提升 CONFIRM
  │    │      └─ audit@90           写哈希链（op_type="hook:pre_tool_call"）
  │    │    ├─ BLOCK   → raise SecurityDenied(risk_level=...)
  │    │    ├─ CONFIRM → ContextPatch(metadata.securityd.requires_approval=True)
  │    │    └─ MODIFY  → ContextPatch(metadata.dlp_masked_args=...)
  │    │
  │    ├─ host.py::_dispatch 聚合 → {plugin_id: {securityd:..., dlp_masked_args:...}}
  │    │    PermissionError 在 BEFORE_TOOL 被重抛（§1.3）
  │    │
  │    ├─ contribution.handler(context, args)   # 真正执行（或经沙箱 runner）
  │    └─ AFTER_TOOL hook → DLP 返回值脱敏 + 审计
  │
  └─ 中间件 catch SecurityDenied
       ├─ L3/L4 → raise（终止整轮 run）
       └─ L1/L2 → ToolMessage(status="error")（交回模型，可换路径）

CONFIRM 分支（走原生 HITL，§1.6）：
  HumanInTheLoopMiddleware 的 when callable 实时查 securityd → True
    → interrupt(action_requests=[...])
    → engine._pending_approval() → SSE "approval_required" → WebUI 弹窗
    → 用户点批准 → POST /runs/{id}/approvals/{aid}
    → stream(resume_decisions=[{type:"approve"}]) → Command(resume=...) → 继续
```

---

## 7. 需求追溯

| 需求 | 实现位置 | 状态 |
|------|---------|------|
| INT-PA-01 适配层骨架 | `plugins/bianbu.security/`（8 hook + `_bridge/`）| 待开发 |
| INT-PA-02 判权拦截 | `hooks/security.before_tool/hook.py` | 待开发 |
| INT-PA-03 异步桥接 | `_bridge/bridge.py::invoke`（run_in_executor）| 待开发 |
| INT-PA-04 工具映射 | `_bridge/mapping.py` | 待开发 |
| INT-PA-05 agent_id 分层 | `_bridge/agent_id.py` | 待开发 |
| INT-PA-06 风险分档 | `SecurityDenied.should_terminate_run` + 中间件 | 待开发 |
| INT-PA-07 fail 分档 | `_bridge/bridge.py::degrade` | 待开发 |
| INT-PA-08 MCP 两层 | `service_runtime.py::authorize_mcp` + before_tool | 待开发 |
| INT-PA-09 审计/on_error | `hooks/security.on_error/hook.py` | 待开发 |
| INT-PA-10 DLP 脱敏通道 | `security_middleware.py`（`request.override`）| 待开发 |
| INT-PA-11 DLP 全链路 | 8 个 hook 分别挂 DLP handler | 待开发 |
| INT-PA-12 动态 HITL | `engine.py` 的 `interrupt_on` 加 `when` | 待开发 |
| INT-PA-13 Token 计量 | `default_engine.py` 挂 `BianbuTokenCallback` | 待开发 |
| INT-PA-14 沙箱配置 | `AgentSpec.metadata.sandbox` | 待开发 |
| INT-PA-15 mode=agent | `run.sh` bwrap 包裹 | 待开发 |
| INT-PA-16 mode=mcp | `mcp/client.py::_open_session` | 待开发 |
| INT-PA-17 mode=tool | `plugin_tools.py` + 通用 runner | 待开发 |
| INT-PA-18 资源限额 | securityd `sandbox.py`（cgroup 已实现）| 待开发 |

---

## 8. 商用注意事项

| # | 项 | 说明 |
|---|-----|------|
| 1 | **WebUI 无认证** | bianbu-agent README 自述"服务暴露到公网前应增加认证、TLS 和访问控制"。securityd 的 WebUI 同样无认证且内嵌真实终端。**两者都只应绑内网**，公网部署必须前置反代 + 认证 |
| 2 | **`mode=tool` 适用边界** | 有副作用的工具不适用（V-09）。首版限纯函数式工具，不支持的要显式报错 |
| 3 | **`npx` MCP 需网络** | mode=mcp 默认 `--unshare-net` 会导致首次拉包失败，需预装或放行（V-08） |
| 4 | **判权缓存仅单次调用内** | WebUI 改配置后，**正在执行的 run 不受影响**，下一次工具调用才生效 |
| 5 | **`agent_id` 探测有一次 D-Bus 往返** | 首次调用后缓存；WebUI 新增 Agent 覆盖后需失效缓存 |
| 6 | **`on_error` 只记审计** | 错误信息可能含 PII，当前不脱敏（决策 ⑤）。若合规要求高需另加 |
| 7 | **Python 版本** | securityd 在 3.14.4 验的 324 测试；bianbu-agent 要求 `>=3.11,<3.14`。**V-01 必须先跑回归** |
| 8 | **lockfile 锁定 riscv64** | 私有索引的 psutil/playwright 只有 riscv64 wheel，本机 x86_64 无法完整 `uv sync` —— 集成测试须在 worker 上做 |
| 9 | **securityd 单点** | securityd 挂了按 INT-PA-07 分档降级（L1/L2 放行、L3/L4 拒绝），不会让服务全废，但高危能力不可用 |

---

## 9. 交付顺序

```
P0-A（16 P·D）INT-PA-01~09  Hook 适配层 —— 主干零改动，可独立验收
P0-B（8 P·D） INT-PA-10~13  主干改造 —— 依赖 A 的 metadata 约定
P0-C（13 P·D）INT-PA-14~18  三种沙箱 —— 独立于 A/B，可并行
```

每阶段验收标准见 PRD 第八章各条的"验收标准"列。

---

*文档结束 — BN-SEC-BA-TECH-001 v1.0*
