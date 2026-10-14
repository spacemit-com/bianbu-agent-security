# AgentOS Security — LangGraph Agent 接入详细设计与说明书

| 项 | 内容 |
|----|------|
| 文档编号 | BN-SEC-LG-001 |
| 版本 | V1.1 |
| 来源 | BN-SEC-SRS-001 §16（INT-LG-01~08）+ §15（SEC-HOOK-04）+ BN-SEC-PRD-TABLE §五 |
| 日期 | 2026-08-11 |
| 状态 | ✅ 已实现；独立 WebUI resume 已增加 Unix broker 跨进程链路，待 worker 回归 |
| 实现 | `securityd/langgraph/` |
| 测试 | `tests/unit/test_langgraph.py`（36 用例） |

---

## 1. 架构分层

```
LangGraph graph
      │
      ├─ BianbuSecurityToolNode     ← INT-LG-01（包装 ToolNode）
      │       │  pre_tool_call
      │       └─ InterceptorRegistry.invoke(PRE_TOOL_CALL)
      │               ├─ sec_capability@10   → CheckPermission（ALLOW/CONFIRM/BLOCK）
      │               ├─ dlp_pre_tool@50     → PII → CONFIRM 提升
      │               └─ audit@90            → AuditLog（含 graph_run_id）
      │
      ├─ BianbuInterceptorNode      ← SEC-HOOK-04（任意干预点插入节点）
      │       └─ InterceptorRegistry.invoke(hook_point)
      │
      └─ BianbuTokenCallback        ← INT-LG-06（on_llm_end 上报 token）
             └─ sc.meter_tokens()
```

与 hermes 接入对比：

| 维度 | hermes (INT-SEC) | LangGraph (INT-LG) |
|------|------------------|--------------------|
| 注入方式 | `manager.register_hook(pre_tool_call)` | 显式替换 `ToolNode` |
| 判权路径 | `InterceptorRegistry.invoke(PRE_TOOL_CALL)` | 同上（共享框架） |
| CONFIRM UI | 调 `terminal_tool._approval_callback` → TUI | `interrupt()` → 暂停 graph |
| Token 计量 | 未内置 | `BaseCallbackHandler.on_llm_end` |
| 沙箱启动 | `hermes_sandbox_launch.py` | `build_sandbox_argv()` 复用底层 |

---

## 2. INT-LG-01 — BianbuSecurityToolNode

替换 `langgraph.prebuilt.ToolNode`，在每次 tool call 前经干预点框架判权。

### 2.1 判权流程

```
graph.invoke(state)
  → BianbuSecurityToolNode.__call__(state)
    → 遍历 last_message.tool_calls
      → _check(tool_name, args)
          → mapping.resolve(tool_name)       # INT-LG-02
          → InterceptorRegistry.invoke(PRE_TOOL_CALL, ...)
              # sec_capability@10：CheckPermission
              # dlp_pre_tool@50：args PII → CONFIRM
          → 决策：ALLOW/CONFIRM/BLOCK
      → BLOCK  → 插入 ToolMessage(content="[bianbu-security] 已拦截")
      → CONFIRM → interrupt() 暂停 graph       # INT-LG-04-A
      → ALLOW  → 转发给 inner ToolNode 执行
```

### 2.2 部分放行

同一个 AIMessage 里有多个 tool call 时，BLOCK 的生成 ToolMessage 错误，ALLOW 的正常执行。两类结果合并后返回，graph 可继续推进。

### 2.3 fail-closed / fail-open

securityd 不可达时默认 fail-closed（返回 BLOCK）。`BIANBU_SECURITY_FAIL_OPEN=1` 改为 fail-open（返回 ALLOW，记日志）。

---

## 3. INT-LG-02 — 工具→能力映射

`securityd/langgraph/mapping.py` — 46 个显式映射 + 前缀/关键字回退。

解析顺序：
1. **精确匹配**（`read_file`→`file.read`，`terminal`→`system.execute`）
2. **前缀匹配**（`_prefix_search_` → `network.access`）
3. **关键字回退**（`tl.contains("search")`→`network.access` 等）
4. **未识别 → None**，交由 `DEFAULT_ALLOW=True` 默认放行

覆盖的工具集：TavilySearch、PythonREPL、ShellTool、FileSystemTool、RequestsTool、WikipediaQueryRun、DuckDuckGoSearch、GmailSendMessage、SlackSendMessage、GoogleCalendar 等。

---

## 4. INT-LG-03 — Agent 身份注册

```python
register_agent(agent_id="com.myapp", fail_open=True)
```

无 manifest 时使用内置默认能力集（6 条）：

| 能力 | 风险级 | 策略 |
|------|--------|------|
| `file.read` | L1 | trusted（无需确认）|
| `network.access` | L2 | once_per_session |
| `execute.code` | L3 | always（每次确认）|
| `system.execute` | L3 | always（每次确认）|
| `file.write` | L2 | once_per_session |
| `communication.send` | L3 | always |

---

## 5. INT-LG-04-A — CONFIRM 决策联动（interrupt + Command API）

```
BianbuSecurityToolNode._check() → Decision.CONFIRM
  → interrupt({"type":"bianbu_confirm", "tool_name":..., "capability":...})
  → graph 暂停，控制权交回调用方（graph.stream() 的调用者）
  → 调用方调 graph.update_state(..., as_node="__interrupt__", values={"approved":True})
  → graph 继续
```

**与 hermes 的关键区别**：
- hermes：同步阻塞（`RequestConfirm` → 等 D-Bus 信号）
- LangGraph：异步暂停（`interrupt()` → `update_state()` 唤醒），非阻塞

`langgraph_interrupt_confirm()` 封装上述逻辑，在 `BianbuSecurityToolNode._check()` 的 CONFIRM 分支内调用。

---

## 6. INT-LG-05 — 审计全链路（含 graph_run_id）

每次 `_check()` 调 `sc.audit_log(agent_id, tool_name, target, result)`。

`result` 格式：`"{decision}|run={run_id}"`，其中 `run_id = os.environ["LANGGRAPH_RUN_ID"]`（不存在时省略）。

`run_id` 与 LangGraph 的 `RunnableConfig.run_id` 关联，便于在审计日志里反查是哪次 graph.invoke 触发了某次工具调用。

---

## 7. INT-LG-06 — Token 配额计量

```python
from securityd.langgraph.callbacks import BianbuTokenCallback

cb = BianbuTokenCallback(agent_id="com.myapp")
chain = model.with_config(callbacks=[cb])
```

`on_llm_end` 解析 LLM 响应里的 token 用量（支持 `llm_output.token_usage`、`usage_metadata` 两种 LangChain 格式），调 `sc.meter_tokens(agent_id, total)`。

超限时抛 `TokenBudgetExceededError`，向 LangGraph graph 传播，中断执行。计量失败（总线不可达）被静默吞掉，不阻断 LLM 流程。

---

## 8. INT-LG-07 — 沙箱内启动 LangGraph Agent

```python
from securityd.langgraph.callbacks import build_sandbox_argv

argv = build_sandbox_argv(
    "myapp.agent",       # 模块名
    rw_dirs=["~/.myapp"],
    net=True,
)
subprocess.run(argv)
```

优先使用 `hermes_sandbox_launch.py` 作为底层引擎（已完成 merged-usr 适配、DNS/CA 绑定、passwd/group 合成）。launcher 不存在时回退到最小化 bwrap 参数。

---

## 9. INT-LG-08 — WebUI 能力配置实时生效

与 hermes 共享同一个 `capability_registry.py` SQLite 数据库（WAL 模式），WebUI 改配置写入后，下一次 `CheckPermission` 调用立即读取新值，无需重启 ToolNode 或 graph。

`setup_interceptor()` 注册了 audit sink，把每次干预点的执行轨迹写进审计链，WebUI 审计页可按 `hook:pre_tool_call` 过滤查看 LangGraph 的判权记录。

---

## 10. SEC-HOOK-04 — BianbuInterceptorNode（通用干预节点）

在 graph 任意位置插入干预点：

```python
from securityd.langgraph.tool_node import BianbuInterceptorNode
from securityd.interceptor import HookPoint

# 在 output 节点前插入 DLP 输出审查
dlp_node = BianbuInterceptorNode(HookPoint.OUTPUT, agent_id="com.myapp")
graph.add_node("dlp_output", dlp_node)
graph.add_edge("agent", "dlp_output")
graph.add_edge("dlp_output", END)
```

BLOCK 时触发 `interrupt({"type":"blocked",...})` 让外部决定是否覆盖；MODIFY 时把 modified_data 写回 messages[-1].content（可自定义 injector）。

---

## 11. setup_interceptor — 一键配置

```python
from securityd.langgraph.tool_node import setup_interceptor

node, registry = setup_interceptor(
    tools=[search, read_file, write_file],
    agent_id="com.myapp.agent",
    register=True,      # 自动注册 Agent 身份
    with_dlp=True,      # 同时启用 DLP 全链路
)
graph.add_node("tools", node)
```

完成：身份注册 + SEC capability@10 + 可选 DLP@50 + audit sink。

---

## 12. 测试覆盖

`tests/unit/test_langgraph.py` — **36 用例，worker riscv64 全通过**。

`tests/unit/test_langgraph_resume_registry.py` 额外覆盖真实 graph callback 的一次性
resume、run/agent 绑定、同 run 发布幂等、未注册 fail-closed、普通文件不可覆盖，以及
Unix socket list/resume RPC。该测试证明 broker 语义，不替代正式 Runtime 服务部署验收。

| 分组 | 覆盖 |
|------|------|
| INT-LG-02 映射（7） | 精确匹配/前缀匹配/关键字回退/unknown→None/空名/DEFAULT_ALLOW/全部显式项 |
| INT-LG-03 注册（3） | 默认能力集/env 覆盖/fail-open |
| INT-LG-01 判权（8） | ALLOW/BLOCK/CONFIRM/fail-closed/fail-open/unmapped/audit/run_id |
| SEC-HOOK-04 registry（3） | SEC DENY 覆盖/DLP 提升 CONFIRM/SEC DENY 短路 DLP |
| INT-LG-06 Token（5） | llm_output 格式/usage_metadata 格式/超限抛异常/失败不中断/零量不上报 |
| INT-LG-04-A interrupt（2） | 非 LangGraph 环境/response 解析 |
| INT-LG-07 沙箱（4） | minimal argv/no-net/rw_dirs/batch |
| SEC-HOOK-04 节点（2） | ALLOW 透传/MODIFY 更新 content |
| setup_interceptor（2） | 基础配置/with_dlp |

全量回归：**324 passed**（起始 288）

---

## 13. 已知边界

1. **interrupt() 在非 graph 上下文不可用** — 直接调用而非在 graph.invoke/stream 里会抛异常。已在测试中 try/except 处理
2. **graph_id/run_id 由 Agent/Runtime 注册并注入** — 未注册或缺 run_id 时 fail-closed，不产生可伪造 pending；审计 run_id 仍需由调用方按运行配置注入
3. **BianbuSecurityToolNode 不支持 streaming** — 仅处理 tool call 判权，不改变 LangGraph 的 streaming 行为
4. **BianbuInterceptorNode 的默认 extractor/injector 针对 HumanMessage/AIMessage** — 自定义 state schema 需传入自定义 extractor/injector
5. **INT-LG-04-B WebUI 唤醒需 graph.update_state** — WebUI 不持有 graph 实例，而是经 Unix socket broker 把请求转给 Agent/Runtime 所在进程；broker socket 默认 0600，支持部署时指定共享路径/权限
6. **INT-LG-07 在 K3 上回退到最小化 bwrap** — `hermes_sandbox_launch.py` 尚未针对 LangGraph 工作目录测试过，可能需要额外绑定

---

## 14. INT-LG-04-B 当前状态（V1.1）

当前 WebUI 的确认门禁 Tab 同时支持 D-Bus `RequestConfirm/RespondConfirm`（hermes 同步路径）和 LangGraph 异步路径：

1. Agent/Runtime 注册 `graph_id`、graph 实例、`config`、`run_id`、`agent_id`，并启动 Unix broker；
2. `BianbuSecurityToolNode` 在 CONFIRM 前发布带绑定字段的 pending，再调用 LangGraph `interrupt()`；
3. WebUI `GET /api/langgraph/interrupts` 经 broker 聚合 pending；
4. 管理员 `POST /api/langgraph/resume`，broker 在拥有 graph 的进程执行 `graph.update_state(config, values={"approved": ...}, as_node="__interrupt__")`；
5. 同一 pending 只消费一次；run/agent 不匹配、过期、未注册 graph、重复 resume 均 fail-closed。

WebUI 不提供 graph 注册接口，也不在自身进程伪造 graph。broker 协议仅允许 list/resume/ping，socket 默认 0600；多用户部署可配置 `BIANBU_LANGGRAPH_BROKER_TOKEN`、`BIANBU_LANGGRAPH_BROKER_DIR_MODE` 和 `BIANBU_LANGGRAPH_BROKER_SOCKET_MODE` 进行第二层认证。

---

*文档结束 — BN-SEC-LG-001 v1.1*
