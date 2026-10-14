# 能力映射整改与 HITL 修复计划

| 项 | 内容 |
|----|------|
| 文档编号 | BN-SEC-REMED-001 |
| 版本 | V1.0 |
| 日期 | 2026-08-12 |
| 上游 | BN-SEC-CAPMAP-001（能力映射技术方案） |
| 范围 | §7.4 的 10 项决策全部按建议执行 + HITL 链路修复 |

---

## 0. 本次新发现：HITL 完全失效（P0，优先于其它 10 项）

用户报告"web_search 直接返回发送失败"。复现后发现的问题比表面更严重。

### 0.1 复现结果

**现象 1 — DENY 是硬失败，错误被 UI 掩盖**

```
network.access 判权 = DENY
run 终态 = failed
error = "[bianbu-security] 权限被拒绝：web_search 需能力 network.access（scope=-），未授权或已撤销"
```

securityd 的错误信息本身很清楚，但前端显示为"发送失败，请稍后再试" —— **真实原因没有传达给用户**。

能力为何是 DENY：审计显示 `01:23` 有人经 WebUI 把 5 个能力全部撤销（`granted=-1`），非 testkit 所为。

**现象 2 — CONFIRM 静默放行（真正的漏洞）**

把 `network.access` 设成 `L3 / confirm=always / granted=1`，`CheckPermission` 正确返回 CONFIRM，但：

```
run 状态: running → completed     ← 没有 awaiting_approval
content = "搜索服务连不上（SearXNG 连接错误）…"   ← 工具真的执行了
```

错误是网络层的（SearXNG 连不上），不是权限层的 —— 说明**判权说要确认，工具却直接跑了**。

两条路都不走 HITL：DENY 硬失败、CONFIRM 静默放行。

### 0.2 根因

链路本身完整，断在最后一环：

```
before_tool hook
  decision == "CONFIRM" → payload["requires_approval"] = True
  return ContextPatch(metadata={"securityd": payload})
      │
      ▼  plugin_tools.py:128
async def _run_hooks(hook_runner, point, context, hook_ids) -> None:
    await runner(point, context, hook_ids=hook_ids)     ← 返回值直接丢弃
      │
      ▼  调用点也不接收
await _run_hooks(hook_runner, HookPoint.BEFORE_TOOL, ...)
      │
      ▼  ContextPatch 从未进入 graph state
extract_security_metadata(state)
    state.get("hook_metadata") or state.get("metadata")  → 取不到 securityd
      │
      ▼
securityd_requires_confirm(request) → 永远 False
      │
      ▼
InterruptOnConfig.when → 永远不触发 interrupt → 无审批
```

我此前记录过 `_run_hooks` 丢弃 ContextPatch，但当时判定为"既有架构、非缺陷" —— **那个判断是错的**。它让 INT-PA-12 的动态 HITL 完全失效。

### 0.3 执行顺序决定了修复方案（实测）

初版方案想"把 hook 写的 metadata 传给中间件"，实测证明**这条路走不通**。

读 `langchain.agents.middleware.human_in_the_loop` 源码，`when(req)` 的调用点在 **`after_model`** 里：

```python
def after_model(...):
    ...
    req = ToolCallRequest(tool_call=tool_call, tool=None,
                          state=state, runtime=tool_runtime)
    return when(req)          # ← 模型刚产出 tool_call，工具还没执行
```

而 `before_tool` hook 在 `_adapt_tool.invoke()` 里执行 —— 那是**工具执行阶段**。时序：

```
① 模型产出 tool_call
② HITL 中间件 after_model → when(req) → 决定是否 interrupt    ← 需要判权结果
③ （若放行）工具开始执行 → _adapt_tool.invoke()
④ before_tool hook 跑，调 securityd 拿到 CONFIRM              ← 太晚了
```

hook 的 `requires_approval` 永远赶不上同一次调用的 HITL 检查。**这是顺序问题，不是数据传递问题**，靠 config/state 传值都无法解决。

### 0.4 修复方案（修正版）

让 `when` 自己直接问 securityd，不依赖 hook 的产出：

| # | 位置 | 改动 |
|---|------|------|
| F-1 | `security_middleware.py::securityd_requires_confirm` | 从「读 metadata」改为「直接调 `CheckPermission`」：从 `request.tool_call` 取工具名与参数 → `resolve_capability()` → `CheckPermission` → CONFIRM 则返回 True |
| F-2 | 同上 | 加进程内短时缓存（同一 run 内同工具同 scope 不重复问），避免每次工具调用一次 D-Bus 往返 |
| F-3 | `plugin_tools.py::_run_hooks` | 仍改为返回 ContextPatch —— `before_tool` 的 DLP 脱敏结果（`dlp_masked_args`）需要传给中间件应用，这条链路同样断着 |

F-1 的开销：`when` 是逐工具调用同步执行，一次 D-Bus 往返实测 P99 4.357ms，可接受。F-2 的缓存进一步降低。

**职责划分变化**：

| 环节 | 修复前 | 修复后 |
|------|--------|--------|
| 判权（要不要确认） | hook 判、中间件读 metadata（断） | **`when` 直接判** |
| 拦截（DENY） | hook 抛 SecurityDenied | 不变 |
| DLP 脱敏 | hook 算、中间件应用（断） | hook 算、中间件应用（F-3 修通） |
| 审计 | hook 写 | 不变 |

hook 仍然负责 DENY 拦截与审计 —— 它跑在工具执行前，能阻断。只有"要不要弹审批"这件事必须提前到 `when`。

**代价**：同一次工具调用会问 securityd 两次（`when` 一次、hook 一次）。用 F-2 的缓存消掉重复，且第二次（hook）仍需要，因为它承担审计与 DLP。

### 0.4 DENY 的错误信息透出

即便 HITL 修好，DENY 仍应是硬失败（这是正确行为）。但要让用户知道**为什么**：

- PA 的 `error.message` 已含完整原因，是前端把它替换成了"发送失败，请稍后再试"
- 需查 PA 的 WebUI/前端错误处理，让 `[bianbu-security]` 前缀的错误原样透出
- 并给出可操作提示："该能力未授权，请在 securityd 配置台（:8787）授予 `network.access`"

### 0.5 修复结果（已完成，worker 实测）

三处改动全部落地并验证：

| # | 位置 | 状态 |
|---|------|------|
| F-1 | `security_middleware.py::securityd_requires_confirm` 改为直接调 `CheckPermission` | ✅ |
| F-2 | 同上，加 `(agent, capability, scope)` 缓存 | ✅ |
| F-3 | `plugin_tools.py::_run_hooks` 返回 ContextPatch，`_adapt_tool` 应用 `dlp_masked_args` | ✅ |

**实测证据**

插桩确认 `when` 链路：

```
CALLED tool_call={'name': 'web_search', 'args': {'query': 'RISC-V 处理器架构', ...}}
  tool='web_search' resolved=('network.access', '')
  decision=1 need=True
```

run 状态与审批载荷：

```
状态序列: running → waiting
pending_actions: [{
  "type": "approval_required",
  "approval_id": "f01e7314307d5ed3980a7c730da1d317",
  "actions": [{"name": "web_search",
               "allowed_decisions": ["approve", "reject"],
               "arguments": {"query": "RISC-V 处理器架构", "limit": 5}}]
}]
```

批准与拒绝两条路径都通：

| 操作 | 状态序列 | 结果 |
|------|---------|------|
| approve | `waiting → running → waiting` | run 恢复执行；第二次 waiting 是 `confirm=always` 下重试触发的新审批，语义正确 |
| reject ×2 | `waiting → running → waiting → running → completed` | LLM 换关键词重试一次（`RISC-V` → `RISC-V architecture processor`），再次被拒后放弃并如实告知用户 |

拒绝的最终回复：

> 两次搜索都被拒绝了 —— `web_search` 工具返回了"测试拒绝"，没有返回任何搜索结果……
> 是不是当前环境对搜索有权限限制？

**不是死循环** —— agent 在连续拒绝后主动停止并向用户求证，这是期望行为。

### 0.6 遗留：DENY 的错误信息被前端掩盖

securityd 返回的错误本身很清楚：

```
[bianbu-security] 权限被拒绝：web_search 需能力 network.access（scope=-），未授权或已撤销
```

但前端显示为"发送失败，请稍后再试"。这是**前端错误处理**问题，不在本次修复范围内，需单独处理（见 §5 遗留事项）。

另：审计显示 `01:23` 有人经 WebUI 把 5 个能力全部撤销（`granted=-1`），这是 web_search 拿到 DENY 的直接原因 —— 不是代码缺陷。

---

## 1. 十项决策的执行计划

按 CAPMAP §7.4 的建议逐项执行。编号沿用原文档。

### 阶段划分

```
P0 阶段（阻断性，必须先做）
  F-1~F-3  HITL 链路修复            ← 用户报告的问题
  D-1      能力词汇表统一
  D-2      MCP 层 1 fail 策略

P1 阶段（安全性）
  D-3      MCP 推断优先级
  D-4      关键字推断取最高风险
  D-5      未知工具改 CONFIRM
  D-6      Hook 安装期签名校验

P2 阶段（增强）
  D-7      system.execute 命令级 scope
  D-8      Provider base_url 白名单
  D-9      远端 MCP 数据出境（DLP 覆盖）
  D-10     Skill 文本过 DLP
```

### D-1【P0】能力词汇表统一

**建议**：以 securityd `/api/mapping` 清单为准改映射表 + 清单写入 SRS + 加 CI 校验。

改动：

| 映射表现值 | 改为 | 影响文件 |
|-----------|------|---------|
| `system.execute` | `system.exec` | PA `lib/mapping.py`、securityd `langgraph/mapping.py`、TechSpec `_HIGH_RISK` |
| `communication.send` | `message.send` | 同上 |
| `data.access` | `data.read` | 同上 |
| `system.info` | `system.config` | securityd `langgraph/mapping.py` |

新增能力定义（清单里完全没有，需定 domain/risk_level/confirm）：

| 能力 | domain | risk_level | confirm | 理由 |
|------|--------|-----------|---------|------|
| `execute.code` | execute | L3 | always | 代码执行，能读写文件与网络 |
| `execute.model` | execute | L2 | trusted | 调 LLM，主要是成本而非安全风险 |
| `calendar.read` | data | L1 | trusted | 只读 |
| `calendar.write` | data | L2 | once_per_session | 改用户日程 |

三处配套：
1. 权威清单写入 SRS（新增一节「能力字典」），作为唯一事实来源
2. securityd 侧加 `CAPABILITY_REGISTRY` 常量（当前只有运行时数据，无声明）
3. testkit 加一项 `CAP-01`：校验映射表引用的每个能力都在权威清单内

### D-2【P0】MCP 层 1 fail 策略

**建议**：fail-closed + 首次连接时自动注册为 `granted=0`（待授权）。

改 `service_runtime.py::_securityd_allows_mcp`：

```
check_permission(agent_id, f"mcp.{mcp_id}", "")
  ALLOW/CONFIRM → 放行
  DENY:
    ├─ 能力已注册且 granted=-1  → 拦截（用户明确撤销）
    └─ 能力未注册               → 自动 RegisterCapabilities(granted=0)
                                  + 拦截 + 日志提示"请在配置台授权 mcp.<id>"
```

同时修 docstring（当前说 fail-open，与行为相反）。

### D-3【P1】MCP 推断优先级

**建议**：把关键字推断（1b）降到 `mcp.<server>`（1c）之后。

即第 ① 层顺序改为：
1. 查 securityd 是否注册 `mcp.<mcp_id>` → 命中即用
2. **返回 `("mcp.<mcp_id>", local_name)`**（原 1c 提前）
3. 关键字推断仅用于**日志提示**，不改变返回值

效果：MCP 工具的能力边界由 server 身份决定，不被工具名字面绕过。

### D-4【P1】关键字推断取最高风险

**建议**：改为「取所有命中中风险最高的」。

`securityd/langgraph/mapping.py::resolve()` 的关键字扫描改为：收集全部命中，按 risk_level 排序取最高。需要一张 `能力 → risk_level` 表（可从 D-1 的权威清单取）。

效果：`run_query` 不再被低判为 `network.access`，而是取 `system.execute`（L4）。

### D-5【P1】未知工具改 CONFIRM

**建议**：`DEFAULT_ALLOW` 语义从"放行"改为"要确认"。

`lib/mapping.py` 的 `DEFAULT_ALLOW = True` 改为三态常量：

```python
UNKNOWN_TOOL_POLICY = "confirm"   # allow | confirm | deny
```

hook 侧 `resolved is None` 分支据此：
- `allow` → 原行为
- `confirm` → 返回一个特殊能力 `unknown.tool`（L3/always），走正常判权拿 CONFIRM
- `deny` → 抛 SecurityDenied

依赖 F-1~F-3（HITL 修好才有意义）。

### D-6【P1】Hook 安装期签名校验

**建议**：复用 securityd 已有的 `VerifyManifest`，在安装期校验，不做运行期判权。

理由（重要）：运行期判权有**循环依赖** —— securityd 的判权入口本身就是 hook，用 hook 判 hook 说不通。

改动：
1. `plugins/installer.py` 安装 hook 时调 `VerifyManifest`
2. 校验失败拒绝安装（可用 `BIANBU_SECURITY_ALLOW_UNSIGNED=1` 开发期绕过）
3. 已装 hook 的 `content_digest` 变化时告警（篡改检测）

### D-7【P2】system.execute 命令级 scope

**建议**：用命令首 token（可执行名）作 scope。

`_extract_scope` 扩展：`system.exec` 从 `command` / `cmd` 参数取第一个 token。
securityd 侧匹配规则需从"路径最长前缀"扩展为"命令名精确匹配"。

### D-8【P2】Provider base_url 白名单

**建议**：PA 侧配置项列白名单，非白名单拒绝注册。

`config.yaml` 增 `security.allowed_model_hosts: [...]`，`POST /api/admin/v1/providers` 校验 `base_url` 的 host。

### D-9【P2】远端 MCP 数据出境

**建议**：靠 DLP + 层 2 判权，不追加沙箱（沙箱对远端无意义）。

确认 `dlp_pre_tool` handler 对 HTTP 传输的 MCP 工具参数同样生效（当前应该已经生效，因为它在 `before_tool` 层，不区分传输）。补一项测试验证。

### D-10【P2】Skill 文本过 DLP

**建议**：把 Skill instructions 一并交 `after_context` 的 DLP 扫描。

`after_context` hook 当前只扫用户输入。改为把 `context_sections`（含 Skill instructions）一并扫，防止 Skill 里的敏感信息进 prompt 送云端。

---

## 2. 实施顺序与依赖

```
F-1 → F-2 → F-3          HITL 链路（三处必须一起，否则中间断）
   │
   ├─→ D-5               未知工具改 CONFIRM（依赖 HITL 可用）
   │
D-1 ──┬─→ D-4            关键字取最高风险（依赖权威清单的 risk_level）
      └─→ CAP-01 测试     词汇表一致性校验

D-2（独立）
D-3（独立）
D-6（独立，需签名体系）
D-7 → 依赖 D-1（能力名改了）
D-8 / D-9 / D-10（独立）
```

**第一批交付**：F-1~F-3 + D-1 + D-2（P0 全部）
**第二批**：D-3 / D-4 / D-5 / D-6
**第三批**：D-7 ~ D-10

---

## 3. 验证方案

### 3.1 HITL 修复的验证（F-1~F-3）

必须端到端验，不能只验函数返回值 —— 这个 bug 正是"每层都对、串起来断"。

| 步骤 | 断言 |
|------|------|
| 1 | 把 `network.access` 设 `L3/always/granted=1` → `CheckPermission` = CONFIRM |
| 2 | 发 run 让 agent 调 `web_search` |
| 3 | **run 状态应停在 `awaiting_approval`（或等价的中断态）**，不是 completed |
| 4 | securityd 审计里应有 `check_permission → confirm` 记录 |
| 5 | 经 API 批准后，run 继续并完成 |
| 6 | 拒绝时，run 以明确的"用户拒绝"结束，不是超时 |

第 3 步是关键 —— 当前就是这里失败（直接 completed）。

### 3.2 词汇表一致性（D-1）

新增 testkit 项 `CAP-01`：

```python
@test("CAP-01", "映射表引用的能力都在权威清单内", "INT-PA-04", "permission")
def t_cap_vocabulary(c: Ctx):
    used = 收集 BUILTIN_MAP + CAPABILITY_MAP 引用的全部能力名
    known = securityd 的权威清单
    missing = used - known
    return [Step("无未定义能力", not missing, f"缺失 {sorted(missing)}")]
```

这项测试是防回归的关键 —— 词汇不一致这类问题应由测试兜住，不靠人工核对。

### 3.3 全量回归

每批交付后跑：
- testkit 全量（当前 24 项，D-1 后 25 项）
- bianbu-agent 全量回归（基线 799 passed / 6 failed，不得新增失败）
- securityd 全量（基线 326 passed）

---

## 4. 风险与注意

| 风险 | 说明 | 对策 |
|------|------|------|
| D-1 破坏既有部署 | 改能力名后，已注册 `system.execute` 的部署会失效 | 提供迁移脚本：读旧名 → 按映射注册新名 → 撤销旧名 |
| F-1~F-3 改动主干 | `plugin_tools.py` 是所有工具调用的公共路径 | 改动最小化；先验 config 通道可达性再定实现 |
| D-5 提高审批频率 | 未知工具都要确认，可能烦扰用户 | 提供 `once_per_session`；并鼓励把常用工具加入映射表 |
| D-6 需签名体系 | 当前没有密钥分发机制 | 开发期用 `BIANBU_SECURITY_ALLOW_UNSIGNED=1`；生产前建密钥体系 |
| 能力全被撤销的现状 | 当前 5 个能力 `granted=-1`，任何工具都不可用 | 修复后需重新授权；文档说明如何在配置台恢复 |
