# AgentOS Security — 干预点框架详细设计与说明书

| 项 | 内容 |
|----|------|
| 文档编号 | BN-SEC-HOOK-001 |
| 版本 | V1.0 |
| 来源 | BN-SEC-SRS-001 §15（SEC-HOOK-01~05）+ BN-SEC-PRD-TABLE §三 |
| 日期 | 2026-08-11 |
| 状态 | SEC-HOOK-01 已实现并 worker 验证（9/9 通过） |
| 实现 | `impl/bianbu-securityd/securityd/interceptor.py` |
| 测试 | `impl/bianbu-securityd/tests/unit/test_interceptor.py` |

---

## 1. 设计目标

把散落在各处的治理逻辑（Capability 判权、DLP 脱敏、审计、配额）统一到**可插拔的干预点框架**上，实现三个目标：

1. **框架与应用分离** — 8 个干预点是稳定基础设施，治理功能是注册其上的 handler
2. **跨 Agent 框架复用** — hermes / LangGraph / 未来任何框架共用同一套 handler
3. **新增治理功能零改框架** — 内容审核、限流等新需求只需注册 handler

---

## 2. 8 个干预点

### 2.1 生命周期顺序

```
agent_startup                        Agent 启动，manifest 已加载
      ↓
   input                             用户输入进入 Agent 前
      ↓
pre_model_call                       LLM 调用前（prompt 已组装）
      ↓
post_model_call                      LLM 返回后（注入上下文前）
      ↓
pre_tool_call        ←──┐            工具参数确定后、执行前
      ↓                 │
post_tool_call          │ 多轮循环   工具执行完、返回值进上下文前
      ↓                 │
   （回到 pre_model_call）┘
      ↓
   output                            向用户返回最终答案前
      ↓
agent_shutdown                       Agent 正常/异常退出
```

### 2.2 各点契约

| 干预点 | 传入 data | 典型 handler | 可返回决策 |
|--------|----------|-------------|-----------|
| `agent_startup` | manifest dict | DLP 策略加载 | ALLOW / BLOCK |
| `input` | 用户输入字符串 | DLP 输入脱敏 | ALLOW / MODIFY / BLOCK |
| `pre_model_call` | 完整 prompt 字符串 | DLP 云端阻断 | ALLOW / MODIFY / BLOCK |
| `post_model_call` | LLM 响应字符串 | DLP 输出检测、Token 计量 | ALLOW / MODIFY / BLOCK |
| `pre_tool_call` | `{tool, args, capability}` | **Capability 判权**、DLP 参数扫描 | ALLOW / CONFIRM / BLOCK |
| `post_tool_call` | 工具返回值 | DLP 返回值脱敏、审计 | ALLOW / MODIFY / BLOCK |
| `output` | 最终输出字符串 | DLP 最终审查、水印 | ALLOW / MODIFY / BLOCK |
| `agent_shutdown` | `{exit_reason}` | Session 清零、统计审计 | ALLOW（只观察） |

---

## 3. 核心数据结构

### 3.1 HookPoint（干预点枚举）

```python
class HookPoint(str, Enum):
    AGENT_STARTUP   = "agent_startup"
    INPUT           = "input"
    PRE_MODEL_CALL  = "pre_model_call"
    POST_MODEL_CALL = "post_model_call"
    PRE_TOOL_CALL   = "pre_tool_call"
    POST_TOOL_CALL  = "post_tool_call"
    OUTPUT          = "output"
    AGENT_SHUTDOWN  = "agent_shutdown"
```

继承 `str` 便于直接作字典键与日志输出。

### 3.2 Decision（决策码）

| 决策 | 语义 | 与 CheckPermission 对应 |
|------|------|------------------------|
| `ALLOW` | 放行 | 0 |
| `CONFIRM` | 需用户确认 | 1 |
| `BLOCK` | 拒绝（DENY 同义） | 2 |
| `MODIFY` | 内容已改写，链式传给下游 | — |

### 3.3 InterceptResult（handler 返回值）

```python
@dataclass
class InterceptResult:
    decision: Decision = Decision.ALLOW
    message: str = ""                    # BLOCK 理由 / MODIFY 说明
    modified_data: Optional[Any] = None  # MODIFY 时的新数据
    metadata: dict = None                # 附加信息（PII 类型等）
```

`metadata` 在 `__post_init__` 中兜底为 `{}`，避免可变默认参数陷阱。

### 3.4 Handler 签名

```python
InterceptHandler = Callable[[str, HookPoint, Any, dict], InterceptResult]
#                            agent_id, hook_point, data, context
```

统一签名让所有治理功能可互换注册，框架不需要知道 handler 内部做什么。

---

## 4. 优先级槽位

| 优先级 | 用途 | 理由 |
|--------|------|------|
| **10** | SEC Capability 判权 | 最先执行 — 无权限直接 BLOCK，省掉后续所有开销 |
| **50** | DLP / PII | 判权通过后才需要看内容 |
| **90** | Audit 审计 | 最后执行 — 记录最终决策结果 |

数字越小越先执行，同优先级按注册顺序（`list.sort` 是稳定排序）。中间留白便于插入（如 30 = 内容审核，70 = 限流）。

---

## 5. 执行语义（SEC-HOOK-02）

### 5.1 短路规则

任一 handler 返回 `BLOCK` → **立即停止**，后续 handler 不执行，直接返回该 BLOCK 结果。

理由：拒绝是终态，继续执行浪费资源且可能产生矛盾决策。

```python
if result.decision == Decision.BLOCK:
    result.metadata["_handler_trace"] = trace
    return result
```

### 5.2 决策合并：CONFIRM > ALLOW

`CONFIRM` 不短路（后续 handler 仍执行），但会**提升最终决策**：

```python
if result.decision == Decision.CONFIRM:
    final_decision = Decision.CONFIRM
```

场景：SEC 判权 ALLOW，DLP 检出参数含手机号 → 最终 CONFIRM，让用户确认。这是 DLP-06 的核心机制。

### 5.3 链式传递：MODIFY

`MODIFY` 的 `modified_data` 作为**下游 handler 的 data**：

```python
if result.decision == Decision.MODIFY and result.modified_data is not None:
    current_data = result.modified_data
```

场景：DLP 脱敏 handler 把 `alice@example.com` 替换为 `<EMAIL_1>`，下游校验 handler 看到的已是脱敏值。多个 MODIFY 依次叠加。

### 5.4 异常隔离

handler 抛异常**不中断链**，记录后继续：

```python
except Exception as e:
    trace.append((name, 0.0, f"ERROR: {e}"))
```

理由：一个 handler 有 bug 不应让整个治理链瘫痪（fail-open 对可用性友好）。但**这是有意的权衡** — 若某 handler 是关键安全控制，其异常等于放行。生产部署需配合监控告警。

---

## 6. 审计透明（SEC-HOOK-05）

每次 `invoke` 在 `result.metadata["_handler_trace"]` 中返回执行轨迹：

```python
trace = [
    ("sec_capability", 1.23, "ALLOW"),   # (handler名, 延迟ms, 决策)
    ("dlp_pii_scan",   8.45, "CONFIRM"),
    ("audit_log",      0.51, "ALLOW"),
]
```

用途：
- 排障 — 定位是哪个 handler 拒绝的
- 性能分析 — 找出慢 handler（如 NER 模型推理）
- 审计合规 — 证明治理链完整执行

**空 hook_point 也返回 `_handler_trace: []`**，调用方无需判空（这是 worker 测试发现并修复的缺陷）。

---

## 7. API 使用示例

### 7.1 注册 handler

```python
from securityd.interceptor import (
    HookPoint, Decision, InterceptResult, global_registry
)

def sec_capability_check(agent_id, hook_point, data, context):
    """SEC 判权 handler（优先级 10）。"""
    tool = data.get("tool")
    capability = data.get("capability")
    decision_code = engine.check_permission(agent_id, capability, scope)
    if decision_code == 2:
        return InterceptResult(
            decision=Decision.BLOCK,
            message=f"capability {capability} denied",
        )
    elif decision_code == 1:
        return InterceptResult(decision=Decision.CONFIRM)
    return InterceptResult(decision=Decision.ALLOW)

global_registry.register(
    HookPoint.PRE_TOOL_CALL,
    sec_capability_check,
    name="sec_capability",
    priority=10,
)
```

### 7.2 触发干预点

```python
result = global_registry.invoke(
    HookPoint.PRE_TOOL_CALL,
    agent_id="com.hermes.agent",
    data={"tool": "terminal", "args": {...}, "capability": "system.execute"},
    session_id="sess-123",   # 进 context
)

if result.decision == Decision.BLOCK:
    return {"error": result.message, "blocked_by": "bianbu-security"}
elif result.decision == Decision.CONFIRM:
    approved = ask_user_confirm(...)
    if not approved:
        return {"error": "user denied"}

# 用可能被 MODIFY 过的数据继续
actual_args = result.modified_data or original_args
```

### 7.3 注销与查询

```python
global_registry.unregister(HookPoint.PRE_TOOL_CALL, "sec_capability")
global_registry.list_handlers(HookPoint.PRE_TOOL_CALL)
# → [(10, "sec_capability"), (50, "dlp_scan"), (90, "audit")]
```

---

## 8. 测试覆盖

`tests/unit/test_interceptor.py` — **9 个用例，worker riscv64 全通过**

| 用例 | 验证点 |
|------|--------|
| `test_register_and_list` | 注册后按优先级排序（10 在 50 前） |
| `test_unregister` | 按名注销；不存在返回 False |
| `test_invoke_allow` | 全 ALLOW；消息聚合；trace 顺序正确 |
| `test_invoke_block_shortcut` | BLOCK 短路 — 第 3 个 handler（会抛异常）未被执行，trace 长度=2 |
| `test_invoke_confirm_precedence` | CONFIRM 提升最终决策；不短路（trace 长度=3） |
| `test_invoke_modify_chain` | MODIFY 链式 — 下游看到脱敏值，最终 `modified_data` 正确 |
| `test_invoke_handler_exception` | 异常 handler 不中断链；trace 记录 ERROR |
| `test_empty_hook_point` | 空 hook_point 返回 ALLOW + 空 trace |
| `test_priority_order` | 10→50→90 三 handler 执行顺序 |

### 8.1 worker 验证记录

```
platform linux -- Python 3.14.4, pytest-9.1.1
rootdir: /home/bianbu/impl/bianbu-securityd
collected 9 items
............................................. 9 passed in 0.12s
```

同步方式：paramiko + sftp 逐文件传输 + md5 校验（worker 上 `impl/bianbu-securityd` 非 git 仓库）。

---

## 9. 已实现 / 待实现

| 需求 | 状态 | 说明 |
|------|------|------|
| **SEC-HOOK-01** 注册机制 | ✅ 已验证 | `InterceptorRegistry`，9/9 测试通过 |
| **SEC-HOOK-02** 短路与决策合并 | ✅ 已验证 | BLOCK 短路 / CONFIRM 优先 / MODIFY 链式均有用例 |
| **SEC-HOOK-03** hermes 挂载 | ✅ 已验证 | 判权改为 `sec_capability@10` handler，11/11 + 全量 66/66 |
| **SEC-HOOK-04** LangGraph 挂载 | ⬜ 待开发 | 需 `BianbuInterceptorNode` |
| **SEC-HOOK-05** 审计透明 | ✅ 已验证 | trace 落审计链 + WebUI 过滤/延迟聚合，10+10 单测 + e2e 16 项 |

---

## 9A. SEC-HOOK-03 — hermes 挂载实现

### 9A.1 分层：治理决策 vs 呈现

判权逻辑从插件内联移到 `client/bianbu_security_handlers.py`，成为框架无关 handler；
**确认 UI 留在插件**（hermes 的 prompt_toolkit TUI 是 hermes 特有的，LangGraph 用 `interrupt()`）。

| 层 | 位置 | 职责 |
|----|------|------|
| 治理决策 | `client/bianbu_security_handlers.py::sec_capability_handler` | 查 CheckPermission → ALLOW/CONFIRM/BLOCK |
| 审计 | 同上 `audit_handler` | 写审计链，恒 ALLOW（观察者） |
| hermes 呈现 | `hermes_plugin/bianbu_security/__init__.py` | `InterceptResult` → `{"action":"block"}`；CONFIRM 弹 TUI |

`sec_capability_handler` 拿到 CONFIRM 时**只返回决策，不做 UI** —— 这是能被 LangGraph 复用的前提。

### 9A.2 client_provider 注入

handler 通过 `context["client_provider"]` 取 D-Bus 客户端，未注入时才 `import bianbu_security_client`：

```python
provider = (context or {}).get("client_provider") or _client
decision = provider().check_permission(agent_id, capability, scope)
```

插件 invoke 时注入自己的 `_client` 间接层：

```python
r = reg.invoke(HookPoint.PRE_TOOL_CALL, AGENT_ID, data,
               client_provider=_client)
```

**为什么需要这层**：`tests/unit/test_approval_mode.py` 用 `monkeypatch.setattr(plugin, "_client", ...)` 注入替身。改造首版 handler 内部直接 import，绕过了该间接层，导致 6 个既有测试打到真总线而失败。注入 provider 后测试替身重新生效。

### 9A.3 回退路径

`securityd.interceptor` 不可 import 时（如仅部署了 client 目录），插件回退到直连 `check_permission`，行为与改造前完全一致：

```python
reg = _registry()          # 惰性加载，失败返回 None
if reg is not None:
    ... 走干预点框架 ...
else:
    ... 直连 CheckPermission（原逻辑）...
```

### 9A.4 可插拔验证

两个用例证明框架真的可插拔，而非只是包装：

- `test_dlp_can_escalate_allow_to_confirm` — SEC 判 ALLOW，注册一个检出手机号的 fake DLP handler 后，最终决策变 CONFIRM。这正是 DLP-06 依赖的机制
- `test_sec_deny_shortcuts_dlp` — SEC 判 DENY 时 DLP handler 未被执行（`ran == []`），证明短路省掉了后续开销

### 9A.5 worker 验证

```
tests/unit/test_hook_hermes.py  11 passed
全量回归 tests/unit + tests/integration  66 passed in 1.67s
```

---

## 9B. SEC-HOOK-05 — 审计透明实现

### 9B.1 为什么用 sink 而非链内 handler

handler 只能看到自己的返回值；**完整 trace 只在链跑完才存在**。所以 trace 落库必须由框架在链结束后触发：

```python
registry.set_audit_sink(sink)   # sink(hook_point, agent_id, decision, trace)
```

`_emit_audit` 在两处调用 —— 正常结束、以及 BLOCK 短路返回前（否则被拒的调用不会留痕，恰是最需要审计的场景）。sink 抛异常被吞掉，不阻断治理链。

框架本身不 import 审计模块，sink 由 client 层注入，保持 `interceptor.py` 零依赖。

### 9B.2 trace 编码进 result 字段

审计表 schema 固定（`seq/ts/agent_id/op_type/target/result/prev_hash/hash`），无 trace 列。**不改表结构**，把 trace 编码进 `result`：

| 字段 | 值 | 说明 |
|------|-----|------|
| `op_type` | `hook:pre_tool_call` | `hook:` 前缀便于过滤 |
| `target` | `ALLOW` / `CONFIRM` / `BLOCK` | 最终决策 |
| `result` | `sec_capability@0.4=ALLOW,dlp_stub@0.1=CONFIRM` | handler@延迟ms=决策 |

`result` 参与哈希计算，所以 trace 同样受哈希链保护——e2e 已验证加入 hook 记录后链仍 intact。

不改表的代价：延迟数据是字符串，需解析后聚合（`/api/audit/hook-points` 干这件事）。换来的是既有审计链、导出、校验逻辑全部不动。

### 9B.3 WebUI 接口

```
GET /api/audit?hook=pre_tool_call   # 只看该干预点
GET /api/audit?hook=any             # 所有 hook 记录
GET /api/audit?hook=exclude         # 排除 hook 记录（看纯业务审计）
GET /api/audit/hook-points          # 干预点计数 + handler 平均延迟排行
```

`exclude` 是必要的：hook 记录会显著增加审计量，老的业务审计视图需要能屏蔽这类噪声。

完整性校验对**导出全集**做，在过滤之前——过滤后的子集不相邻，哈希链本就无法自证（这与既有 `_verify_rows(contiguous=False)` 的处理一致）。

### 9B.4 开关

`BIANBU_SEC_HOOK_AUDIT=0` 关闭 trace 审计（默认开）。高频场景下每次工具调用多一条审计写入，需要时可关。

### 9B.5 worker 验证

单测 `tests/unit/test_hook_audit.py` 10/10、`test_hook_audit_filter.py` 10/10；全量回归 **86/86**。

端到端 `tests/integration/hook_audit_e2e.py` **16/16**（走真实 SecurityEngine + SQLite）：

```
[6] 导出审计链，验证 hook trace 落库
  ✅ hook 审计记录 ≥3 条（实得 3）
  ✅ op_type 前缀正确 — {'hook:pre_tool_call'}
  ✅ 三种决策均已记录 — ['ALLOW', 'BLOCK', 'CONFIRM']
  ✅ CONFIRM 记录含两个 handler 的 trace
     — sec_capability@0.4=ALLOW,dlp_stub@0.1=CONFIRM
[7] 完整性校验（hook 记录不破坏哈希链）
  ✅ 导出链完整性 intact
  ✅ 在线链完整性 intact
[8] 延迟聚合（模拟 WebUI /api/audit/hook-points）
  ✅ 可聚合出 sec_capability 平均延迟 — avg=0.47ms calls=3
```

实测 `sec_capability` 平均 0.47ms，距 NFR-P-01 的 P99 ≤ 10ms 有充裕余量（该 e2e 走本地 SQLite，D-Bus 路径的 P99 仍待 NFR-P-01 专项压测）。

---

## 10. 已知边界

1. **handler 异常 = 放行** — 见 §5.4，这是可用性权衡，关键控制需配监控
2. **无并发保护** — `register` / `invoke` 非线程安全。当前使用场景是启动时注册、运行时只读，暂不加锁；若未来支持运行时动态注册需补 `threading.RLock`
3. **无 handler 超时控制** — 慢 handler（如 NER 推理）会阻塞整条链，DLP 实现时需自行控制耗时
4. **hook 审计放大写入量** — 每次工具调用多一条审计记录。高频场景可用 `BIANBU_SEC_HOOK_AUDIT=0` 关闭
5. **延迟数据是字符串** — 编码在 `result` 字段中，聚合需解析。换来的是不改审计表 schema
6. **空 hook_point 不写审计** — 无 handler 时无治理动作，不产生审计噪声

---

## 11. 下一步

SEC-HOOK-01/02/03/05 已完成，剩余：

1. **ARCH-01** — UDS 数据通道（DLP 大载荷前置依赖）
2. **DLP-01** — PIIScanner，然后逐个干预点注册 handler
3. **SEC-HOOK-04** — LangGraph 挂载（`BianbuInterceptorNode`），与 INT-LG-01 一并做

---

*文档结束 — BN-SEC-HOOK-001 v1.0*
