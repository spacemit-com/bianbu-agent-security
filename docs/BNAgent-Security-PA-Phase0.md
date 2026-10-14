# 阶段 0 验证结论 — personal-agent 接入前置事实核验

| 项 | 内容 |
|----|------|
| 文档编号 | BN-SEC-PA-PHASE0-001 |
| 日期 | 2026-08-11 |
| 前置 | BN-SEC-PA-ASSESS-001（评估）、BN-SEC-PA-DECISION-001（决策） |
| 结论 | **P1/P2/P3 全部验证通过**，其中 P3 修正了设计文档的一处关键假设 |

---

## P1 — `SecurityDenied` 穿透 hook 分发层 ✅

`plugins/host.py` 的 `_dispatch` 对 `BEFORE_RUN` / `BEFORE_TOOL` / `BEFORE_MODEL` 三点**专门重抛 `PermissionError`**，其他异常一律 catch + warning + continue。

实测：继承 `PermissionError` 的 `SecurityDenied` 能穿过分发层；非 before 点（如 `AFTER_TOOL`）被吞掉。

**结论**：拦截靠 `raise SecurityDenied(...)`，符合项目既有惯例（MCP 自己也这么用）。

---

## P2 — `ContextPatch.metadata` 嵌套结构 ✅

聚合后是**两层**：`{plugin_id: {自己的 metadata}}`。

```python
# handler 返回
ContextPatch(metadata={"securityd": {...}, "dlp_masked_args": {...}})
# host 聚合后
ContextPatch(metadata={"bianbu.security": {"securityd": {...}, "dlp_masked_args": {...}}})
```

**结论**：B-2 提取脱敏参数的路径是 `patch.metadata["bianbu.security"]["dlp_masked_args"]`。

---

## P3 — LangChain 中间件协议 ⚠️ 修正设计假设

设计文档 §"B-3" 里我推断钩子名是 `abefore_tool_call`。**实际不是。**

### 真实协议（langchain 1.3.14 / 1.5.3）

```python
class AgentMiddleware:
    async def awrap_tool_call(
        self,
        request: ToolCallRequest,
        handler: Callable[[ToolCallRequest], Awaitable[ToolMessage | Command]],
    ) -> ToolMessage | Command: ...
```

**wrapper 式，不是 before/after 式。** 文档说明：middleware 可以

- 多次调 handler（重试）
- **不调 handler（短路）**
- 修改 request / response

`ToolCallRequest` 是 dataclass：

| 字段 | 说明 |
|------|------|
| `tool_call` | `ToolCall`（含 name / args / id）|
| `tool` | `BaseTool | None` |
| `state` | graph state |
| `runtime` | `ToolRuntime` |
| `.override(...)` | **改写 request 的官方方法** |

### 这比原设计更好 —— 三处简化

**① B-2 的 DLP 脱敏通道不必改 `_adapt_tool`**

原方案：在 `_adapt_tool::invoke()` 里插 securityd 专属通道（约 60 行，改主干）。

现方案：在中间件里 `request.override(tool_call={**tc, "args": masked_args})` 后再调 handler。**主干零改动**，脱敏通道就是中间件本身。

**② 风险分档也可落在中间件**

原方案：`handle_tool_errors` 传 callable，L3/L4 raise、L1/L2 return 字符串。

现方案：中间件里 catch `SecurityDenied` → 按 `risk_level` 决定 raise（终止 run）或 return `ToolMessage`（交回模型）。与 `handle_tool_errors` 二选一，中间件方式更集中。

**③ 动态 HITL 有原生支持，不必重建 `interrupt_on`**

`InterruptOnConfig` 是 TypedDict：

```python
{
    "allowed_decisions": list[DecisionType],
    "description":       NotRequired[str | _DescriptionFactory],
    "args_schema":       NotRequired[dict],
    "when":              NotRequired[Callable[[ToolCallRequest], bool]],   # ← 关键
}
```

**`when` 是逐次调用求值的 callable。** 所以动态判权不需要改 `engine.py` 重建 `interrupt_on`，只要：

```python
interrupt_on = {
    tool_name: {
        "allowed_decisions": ["approve", "reject"],
        "when": lambda req: _securityd_says_confirm(req),   # 实时查 securityd
    }
    for tool_name in all_tools
}
```

`engine.py` 的改动从"替换中间件"降为"把 `when` 塞进现有 `interrupt_on` 构造"，约 15 行。

### 额外发现：原生已有 `PIIMiddleware`

```python
PIIMiddleware(
    pii_type: Literal['email','credit_card','ip','mac_address','url'] | str,
    strategy: Literal['block','redact','mask','hash'] = 'redact',
    detector: Callable[[str], list[PIIMatch]] | str | None = None,
    apply_to_input / apply_to_output / apply_to_tool_results: bool,
)
```

内置类型只覆盖 email/credit_card/ip/mac/url —— **没有中文 PII**（手机号、身份证、中文姓名地址）。但 `detector` 接受 callable，可以把我们的 `PIIScanner`（召回 99.75% / 误报 0.75%）作为 detector 注入，复用原生的 `strategy` 与 `apply_to_*` 开关。

**待评估**：走原生 `PIIMiddleware` + 自定义 detector，还是自建中间件。前者省事，但 `strategy` 是全局一档，不支持我们"按 PII 类型分档处置"（DLP-02 的四级回退）。倾向自建，把 `PIIScanner` 直接接进来。

---

## 工作量修订

| 项 | 原估 | 修订 | 原因 |
|----|------|------|------|
| B-2 DLP 脱敏通道 | 2 P·D（改 `_adapt_tool`）| **1 P·D** | 改用 `request.override()`，主干零改动 |
| B-3 动态 HITL | 5 P·D（替换中间件）| **3 P·D** | `InterruptOnConfig.when` 原生支持 |
| **B 合计** | 7 P·D | **5 P·D** | |

---

## 下一步（B-1 最小闭环）

1. 建 `plugins/bianbu.security/`（plugin.toml + adapter.py）
2. 只挂 `before_tool` + `sec_capability@10`
3. 验收：改 WebUI 能力配置 → personal-agent 工具被拦截 + 审计留痕

---

*阶段 0 结束 — BN-SEC-PA-PHASE0-001*
