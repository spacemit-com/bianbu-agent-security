# personal-agent 接入 AgentOS Security — 评估方案

| 项 | 内容 |
|----|------|
| 文档编号 | BN-SEC-PA-ASSESS-001 |
| 版本 | V0.1（评估稿，非设计稿） |
| 日期 | 2026-08-11 |
| 评估对象 | `/data/workspace2026-new/work0618/personal-agent`（`bianbu-agent` v0.1.0） |
| 接入方 | `impl/bianbu-securityd`（86/86 需求已验证，324 测试通过） |
| 状态 | 待决策 —— 含 4 项需拍板事项、2 项待实测 |

---

## 1. 目标系统摘要

| 维度 | 现状 |
|------|------|
| 定位 | YAML 配置驱动的个人 Agent 服务（Runtime + FastAPI Web 控制台 + CLI + 插件宿主） |
| 技术栈 | FastAPI + LangGraph（`langgraph>=1,<2`）+ langchain + MCP（`mcp>=1.27`）|
| 规模 | 304 个 Python 文件 |
| Python | `>=3.11,<3.14` |
| 依赖管理 | `uv` |
| 数据目录 | `agents/ models/ sessions/ runs/ hooks/ tools/ skills/ mcps/ plugins/ workspace/ logs/ cache/` |
| 默认服务 | `0.0.0.0:9899` |

---

## 2. 最重要的发现：hook 点几乎一一对应

`bianbu_agent/plugins/contributions.py::HookPoint` 已定义 8 个点，与 securityd 的 `HookPoint` 对应关系：

| personal-agent | securityd | 说明 |
|----------------|-----------|------|
| `before_run` | `agent_startup` | 直接对应 |
| `after_context` | `input` | 上下文组装后 ≈ 输入进 Agent 前 |
| `before_model` | `pre_model_call` | 直接对应 |
| `after_model` | `post_model_call` | 直接对应 |
| `before_tool` | `pre_tool_call` | 直接对应 —— **判权主战场** |
| `after_tool` | `post_tool_call` | 直接对应 |
| `after_run` | `output` | 直接对应 |
| `on_error` | —— | personal-agent 独有，可额外映射到审计 |

**这意味着适配层可以很薄** —— 不需要在 personal-agent 里新造干预点，只需把它的 hook 调用桥接到 securityd 的 `InterceptorRegistry`。SEC-HOOK-01/02 的注册机制、决策合并、短路语义、DLP 的 8 个 handler 全部可直接复用。

`hooks/models.py::HookManifest` 用 `id / version / description / point / entrypoint / permissions` 描述 hook，`entrypoint` 格式为 `module.path:function` —— 适配层作为一个 hook 插件安装即可，**不改主干**。

---

## 3. LangGraph 接入形态与我的实现不同（关键差异）

`bianbu_agent/langgraph/engine.py:205-224` 用的是：

```python
create_agent(
    model=model, tools=explicit_tools, system_prompt=...,
    checkpointer=checkpointer,
    middleware=[QueuedSteeringMiddleware(), HumanInTheLoopMiddleware(interrupt_on=...)],
    context_schema=AgentRunContext,
)
```

**不是裸 `ToolNode`。** 因此我在 INT-LG-01 写的 `BianbuSecurityToolNode`（继承 `langgraph.prebuilt.ToolNode`）**不能直接替换**。

好消息是它**已有完整 HITL 审批链路**：

```python
interrupt_on = {
    name: {"allowed_decisions": ["approve", "reject"]}
    for name in sorted(set(protected_names) & loaded_names)
}
```

`protected_names` 来自工具元数据 `tool.metadata["requires_approval"] is True`。

**问题**：这是**静态**配置 —— 按工具固定标记；而 securityd 的 CONFIRM 是**动态**决策（按 capability × scope × risk_level × 会话信任状态实时判定）。二者语义不对齐，是本次接入的核心难点（见 §5 方案 B）。

---

## 4. 安全能力差距

| 维度 | personal-agent 现状 | securityd 可补 |
|------|--------------------|---------------|
| 权限粒度 | 角色级工具白名单（`tools: ["*"]`）| 能力级判权（capability × scope × risk_level）|
| 审批门禁 | 静态 `requires_approval` 元数据 | 动态 CONFIRM + L4 二次确认 + 会话信任 |
| 审计 | 事件日志（`events.py`）| SHA-256 哈希链，防篡改、可离线验证 |
| DLP / PII | **空白** | 8 类 PII，召回 99.75%、误报 0.75%，8 个干预点全覆盖 |
| 进程沙箱 | **无**（文档明说"插件是宿主进程内的可信 Python 代码，不是操作系统沙箱"）| bwrap + seccomp + cap-drop |
| syscall 拦截 | **无** | cBPF 双架构（x86_64 / riscv64）|
| Token 配额 | **无** | 双维度（conv / day）+ 超限 pause_and_notify |
| 网络白名单 | **无** | 策略可配（worker K3 无 netfilter，见已知边界）|
| MCP 子进程 | 以服务用户身份启动，无隔离 | 可纳入沙箱 + 能力映射 |

README 自述的三个安全缺口，正是 securityd 的对应能力：

1. "插件是宿主进程内的可信 Python 代码，不是操作系统沙箱" → 方案 C（整进程沙箱）
2. "服务暴露到公网前应增加认证、TLS 和访问控制" → 本次不覆盖（属 Web 层）
3. "stdio MCP Server 同样会以服务用户身份启动子进程" → 方案 A 的 MCP 能力映射 + 方案 C 的沙箱继承

---

## 5. 三个接入方案

### 方案 A —— Hook 适配层（推荐起点）

新增一个 hook 插件目录，把 personal-agent 的 hook 调用桥接到 securityd 的 `InterceptorRegistry`。

```
plugins/bianbu.security/
├── plugin.toml            # 声明 8 个 hook 的 entrypoint
└── adapter.py             # 桥接层
```

桥接核心（伪代码）：

```python
async def before_tool(invocation, ctx):
    # personal-agent hook 是 async，securityd 客户端是同步阻塞 D-Bus
    # → 必须用 run_in_executor 包裹，否则阻塞事件循环
    loop = asyncio.get_running_loop()
    r = await loop.run_in_executor(None, lambda: registry.invoke(
        HookPoint.PRE_TOOL_CALL, agent_id,
        {"tool": invocation.tool_name, "capability": cap,
         "scope": scope, "args": invocation.arguments},
        client_provider=_client,
    ))
    return _to_hook_result(r)   # securityd 决策 → personal-agent 返回契约
```

| 项 | 内容 |
|----|------|
| 改动范围 | 只新增 plugin 目录，**不改主干** |
| 可得 | 能力级判权、防篡改审计、DLP 全链路（8 点）、Token 配额 |
| 不可得 | 进程沙箱隔离；CONFIRM 需降级处理（见 §7 待确认①）|
| 工作量 | 约 8 P·D（适配层 3 + 工具映射 2 + 异步处理 1 + 测试文档 2）|

### 方案 B —— 改造 HITL 中间件（解决动态 CONFIRM）

替换 `HumanInTheLoopMiddleware` 为 securityd 感知版本：工具调用前实时查判权，把 CONFIRM 的工具动态注入 `interrupt_on`，从而触发**原生审批弹窗**（用户在 WebUI 上看到 approve/reject）。

| 项 | 内容 |
|----|------|
| 改动范围 | 需改 `bianbu_agent/langgraph/engine.py` 主干 |
| 可得 | 动态确认 + 保留原生审批体验 |
| 前置 | 需确认 LangChain 中间件协议：调用时机、`interrupt_on` 能否运行时改、`create_agent` 是否支持动态注入 |
| 工作量 | 约 5 P·D（在方案 A 之上）|

### 方案 C —— 整进程沙箱

用 bwrap 包裹整个 FastAPI 服务进程。

| 项 | 内容 |
|----|------|
| 可得 | 文件隔离、syscall 拦截、cap 裁剪；**MCP 子进程自动继承沙箱限制** |
| 风险 | FastAPI 需对外绑端口（比 hermes 交互式 CLI 复杂）；SQLite WAL 在沙箱内行为需实测；MCP 经 `npx` 启动子进程需 node 运行时 + 网络 |
| 工作量 | 约 8 P·D |
| 建议 | 放在最后阶段 |

---

## 6. 推荐路线（分阶段）

| 阶段 | 内容 | 交付 | 工作量 |
|------|------|------|--------|
| **0** | 可行性验证 | Python 3.13 兼容性、异步边界开销、hook 返回契约实测 | 1 P·D |
| **1** | 最小闭环 | 只挂 `before_tool` + `sec_capability@10`。验收：改 WebUI 能力配置后 personal-agent 工具调用被拦截、审计留痕 | 3 P·D |
| **2** | DLP 全链路 | 8 个 DLP handler 挂到对应 hook 点 | 5 P·D |
| **3** | 动态 HITL | 方案 B，CONFIRM 触发原生审批弹窗 | 5 P·D |
| **4** | 整进程沙箱 | 方案 C | 8 P·D |

**阶段 1 是可行性分水岭** —— 若 `before_tool` 返回值能真正阻止工具执行（需实测，见 §8），整条路线成立。

---

## 7. 工具映射需补充

personal-agent 的工具清单与 hermes 不同，我的 `langgraph/mapping.py` 需扩充：

| 工具 | 建议 capability | 备注 |
|------|----------------|------|
| `cronjob` | `calendar.write` | 定时任务调度 |
| `evolution_undo` | `system.execute`（L3）| 自我演化回滚，风险高 |
| MCP 动态工具 | 见下 | 运行时发现，无法预先枚举 |

**MCP 工具是最麻烦的部分**：工具名由第三方 MCP Server 提供、运行时才发现、不可控。

三层回退设计：
1. 按 `mcp.<server-id>.*` 前缀匹配整台 server 的能力（推荐）
2. 关键字推断（复用 `mapping.py` 的现有逻辑）
3. 未识别按 `DEFAULT_ALLOW` 放行

**风险**：关键字推断可能误判 —— 某 MCP 的 `search_files` 会被推成 `network.access`，实际是文件操作。**建议在 WebUI 的 MCP 页面为每台 server 显式配置能力映射**，而不是依赖启发式。

---

## 8. 风险清单

### 已确认（从代码读出）

| # | 风险 | 影响 | 应对 |
|---|------|------|------|
| 1 | **CONFIRM 语义不对齐** —— hook 层同步返回，无法触发 LangGraph `interrupt()` 暂停 | 方案 A 下 CONFIRM 只能降级为拒绝 | 走方案 B，或接受降级（提示用户改角色配置）|
| 2 | **LangGraph 用 `create_agent` + 中间件，非裸 `ToolNode`** | 我的 `BianbuSecurityToolNode` 不能直接复用 | 走 hook 层（方案 A）或改中间件（方案 B）|
| 3 | **MCP 工具名第三方不可控** | 关键字推断可能误判能力 | 按 server 显式配置映射 |
| 4 | **异步边界** —— hook 是 `async`，securityd D-Bus 客户端同步阻塞 | 直接调用会阻塞事件循环 | `run_in_executor` 包裹 |

### 待实测（阶段 0）

| # | 项 | 为什么重要 |
|---|-----|-----------|
| 5 | **Python 版本兼容** —— personal-agent 要求 `>=3.11,<3.14`，我的实现在 **3.14.4** 上验证 | 若 3.13 上有语法/行为差异，需回退适配 |
| 6 | **D-Bus 部署形态** —— securityd 是否需 root、能否共用会话总线、personal-agent 服务用户能否访问系统总线 | 决定部署可行性 |

---

## 9. 需要你拍板的 4 件事

| # | 决策点 | 选项 |
|---|--------|------|
| ① | **CONFIRM 怎么处理** | (a) 降级为拒绝 + 提示改配置（不改主干，体验差）(b) 走方案 B 动态 HITL（改主干，体验好）|
| ② | **MCP 能力映射粒度** | (a) 按 server 显式配置（准确，需人工）(b) 关键字推断（自动，可能误判）|
| ③ | **部署形态** | securityd 跑 root 系统总线，还是与 personal-agent 同用户会话总线？ |
| ④ | **DLP 范围** | (a) 只 input + output 两点（个人使用够）(b) 8 点全闭环（多用户/合规场景）|

---

## 10. 诚实说明：本次评估未完成的部分

评估过程中 shell 会话在最后阶段停止响应，以下一项**没能实测确认**，是从 hook 系统的设计意图推断的：

- **`before_tool` hook 返回值的确切契约** —— 我读到 `hooks/models.py` 的 `HookManifest` 结构和 8 个 `HookPoint` 枚举值，但**没能定位到 hook 的返回值类型定义与实际调用点**（尝试 grep `HookPoint.`／`before_tool`／`HookResult` 均因 shell 无响应未返回结果）。

  §5 方案 A 里 `_to_hook_result(r)` 的具体映射，取决于这个契约。**阶段 0 必须先确认**：
  - 返回值字段名与 action 取值（是 `{"action":"deny","reason":...}` 还是别的形式）
  - 是否支持"改写参数"语义（DLP 脱敏依赖它）
  - 返回 deny 后工具是否**真的不执行**

  这一点尤其要实测 —— hermes 接入时踩过同类坑：当时误判 `invoke_hook` 返回 `dict`，实际返回 `List[Any]`，导致拦截静默失效（漏过率 terminal 46%、execute_code 43%）。**同样的错误不能再犯一次。**

本文其余内容（8 点 hook 映射、`create_agent` + `HumanInTheLoopMiddleware` 形态、`interrupt_on` 静态配置、工具清单、依赖版本）均从源码直接读出，有据可查。

---

## 11. 结论

**接入可行，成本低于预期。** 主要理由是 personal-agent 已有与 securityd 一一对应的 8 点 hook 系统，适配层可以很薄且不改主干。

建议**先做阶段 0 + 阶段 1**（共 4 P·D）：确认 hook 返回契约与 Python 兼容性，跑通"改 WebUI 能力配置 → personal-agent 工具被拦截"这一条最小闭环。这条通了再决定是否推进动态 HITL（方案 B）与整进程沙箱（方案 C）。

---

*评估稿结束 — BN-SEC-PA-ASSESS-001 v0.1*
