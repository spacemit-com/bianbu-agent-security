"""单元测试 — 干预点注册与执行。"""
import pytest

from securityd.interceptor import (
    Decision,
    HookPoint,
    InterceptResult,
    InterceptorRegistry,
)


def test_register_and_list():
    """测试 handler 注册与列表。"""
    reg = InterceptorRegistry()

    def h1(aid, hp, data, ctx):
        return InterceptResult(decision=Decision.ALLOW)

    def h2(aid, hp, data, ctx):
        return InterceptResult(decision=Decision.BLOCK)

    reg.register(HookPoint.PRE_TOOL_CALL, h1, name="sec", priority=10)
    reg.register(HookPoint.PRE_TOOL_CALL, h2, name="dlp", priority=50)

    handlers = reg.list_handlers(HookPoint.PRE_TOOL_CALL)
    assert handlers == [(10, "sec"), (50, "dlp")]  # 按优先级排序


def test_unregister():
    """测试 handler 注销。"""
    reg = InterceptorRegistry()

    def h1(aid, hp, data, ctx):
        return InterceptResult(decision=Decision.ALLOW)

    reg.register(HookPoint.INPUT, h1, name="test")
    assert reg.list_handlers(HookPoint.INPUT) == [(50, "test")]

    ok = reg.unregister(HookPoint.INPUT, "test")
    assert ok
    assert reg.list_handlers(HookPoint.INPUT) == []

    ok = reg.unregister(HookPoint.INPUT, "nonexist")
    assert not ok  # 不存在返回 False


def test_invoke_allow():
    """测试全部 ALLOW 场景。"""
    reg = InterceptorRegistry()

    def h1(aid, hp, data, ctx):
        return InterceptResult(decision=Decision.ALLOW, message="h1 ok")

    def h2(aid, hp, data, ctx):
        return InterceptResult(decision=Decision.ALLOW, message="h2 ok")

    reg.register(HookPoint.PRE_MODEL_CALL, h1, name="h1", priority=10)
    reg.register(HookPoint.PRE_MODEL_CALL, h2, name="h2", priority=20)

    result = reg.invoke(HookPoint.PRE_MODEL_CALL, "test-agent", {"prompt": "hi"})
    assert result.decision == Decision.ALLOW
    assert "h1 ok" in result.message
    assert "h2 ok" in result.message
    trace = result.metadata["_handler_trace"]
    assert len(trace) == 2
    assert trace[0][0] == "h1"  # 优先级 10 先执行
    assert trace[1][0] == "h2"


def test_invoke_block_shortcut():
    """测试 BLOCK 短路（后续 handler 不执行）。"""
    reg = InterceptorRegistry()

    def h_allow(aid, hp, data, ctx):
        return InterceptResult(decision=Decision.ALLOW, message="allow")

    def h_block(aid, hp, data, ctx):
        return InterceptResult(decision=Decision.BLOCK, message="blocked by h2")

    def h_never(aid, hp, data, ctx):
        raise RuntimeError("should not reach here")

    reg.register(HookPoint.PRE_TOOL_CALL, h_allow, name="h1", priority=10)
    reg.register(HookPoint.PRE_TOOL_CALL, h_block, name="h2", priority=20)
    reg.register(HookPoint.PRE_TOOL_CALL, h_never, name="h3", priority=30)

    result = reg.invoke(HookPoint.PRE_TOOL_CALL, "agent", {"tool": "terminal"})
    assert result.decision == Decision.BLOCK
    assert result.message == "blocked by h2"
    trace = result.metadata["_handler_trace"]
    assert len(trace) == 2  # h1 + h2，h3 未执行
    assert trace[1][2] == "BLOCK"


def test_invoke_confirm_precedence():
    """测试 CONFIRM > ALLOW（决策合并）。"""
    reg = InterceptorRegistry()

    def h_allow(aid, hp, data, ctx):
        return InterceptResult(decision=Decision.ALLOW)

    def h_confirm(aid, hp, data, ctx):
        return InterceptResult(decision=Decision.CONFIRM, message="need confirm")

    def h_allow2(aid, hp, data, ctx):
        return InterceptResult(decision=Decision.ALLOW)

    reg.register(HookPoint.PRE_TOOL_CALL, h_allow, name="h1", priority=10)
    reg.register(HookPoint.PRE_TOOL_CALL, h_confirm, name="h2", priority=20)
    reg.register(HookPoint.PRE_TOOL_CALL, h_allow2, name="h3", priority=30)

    result = reg.invoke(HookPoint.PRE_TOOL_CALL, "agent", {})
    assert result.decision == Decision.CONFIRM  # CONFIRM 优先
    assert "need confirm" in result.message
    trace = result.metadata["_handler_trace"]
    assert len(trace) == 3  # 全部执行完（CONFIRM 不短路）


def test_invoke_modify_chain():
    """测试 MODIFY 链式传递（modified_data 作为下游 data）。"""
    reg = InterceptorRegistry()

    def h_mask(aid, hp, data, ctx):
        # 输入脱敏：alice@example.com → <EMAIL_1>
        masked = data.replace("alice@example.com", "<EMAIL_1>")
        return InterceptResult(
            decision=Decision.MODIFY,
            message="masked PII",
            modified_data=masked,
        )

    def h_check(aid, hp, data, ctx):
        # 检查脱敏后的数据（不应再含原始 PII）
        if "alice@example.com" in data:
            return InterceptResult(decision=Decision.BLOCK, message="PII leaked")
        return InterceptResult(decision=Decision.ALLOW, message="clean")

    reg.register(HookPoint.INPUT, h_mask, name="dlp_mask", priority=10)
    reg.register(HookPoint.INPUT, h_check, name="dlp_check", priority=20)

    result = reg.invoke(HookPoint.INPUT, "agent", "hello alice@example.com")
    # 最终决策为 MODIFY —— 数据被改写过必须体现在决策里，否则调用方
    # 只看到 ALLOW 就会继续用原始数据，脱敏白做了
    assert result.decision == Decision.MODIFY
    assert "clean" in result.message
    assert result.modified_data == "hello <EMAIL_1>"


def test_modify_decision_precedence():
    """决策优先级：CONFIRM > MODIFY > ALLOW（BLOCK 已短路）。"""
    def h_mask(aid, hp, data, ctx):
        return InterceptResult(decision=Decision.MODIFY,
                               modified_data=str(data) + "-masked")

    def h_confirm(aid, hp, data, ctx):
        return InterceptResult(decision=Decision.CONFIRM, message="need ok")

    reg = InterceptorRegistry()
    reg.register(HookPoint.PRE_TOOL_CALL, h_mask, name="mask", priority=10)
    reg.register(HookPoint.PRE_TOOL_CALL, h_confirm, name="confirm", priority=20)

    r = reg.invoke(HookPoint.PRE_TOOL_CALL, "a", "x")
    assert r.decision == Decision.CONFIRM      # CONFIRM 压过 MODIFY
    assert r.modified_data == "x-masked"       # 但改写结果仍要带出


def test_no_modify_stays_allow():
    """没有 handler 改写数据时仍是 ALLOW。"""
    def h(aid, hp, data, ctx):
        return InterceptResult(decision=Decision.ALLOW)

    reg = InterceptorRegistry()
    reg.register(HookPoint.INPUT, h, name="h", priority=10)
    r = reg.invoke(HookPoint.INPUT, "a", "unchanged")
    assert r.decision == Decision.ALLOW
    assert r.modified_data is None


def test_invoke_handler_exception_defaults_to_confirm():
    """R-1：handler 异常不再静默放行 —— 默认交给人（CONFIRM），链继续执行。"""
    reg = InterceptorRegistry()

    def h_error(aid, hp, data, ctx):
        raise ValueError("handler crash")

    def h_ok(aid, hp, data, ctx):
        return InterceptResult(decision=Decision.ALLOW, message="ok")

    reg.register(HookPoint.OUTPUT, h_error, name="buggy", priority=10)
    reg.register(HookPoint.OUTPUT, h_ok, name="stable", priority=20)

    result = reg.invoke(HookPoint.OUTPUT, "agent", "some output")
    assert result.decision == Decision.CONFIRM
    assert "ok" in result.message and "handler_error" in result.message
    trace = result.metadata["_handler_trace"]
    assert len(trace) == 2
    assert "ERROR" in trace[0][2]  # buggy handler 异常被捕获
    assert trace[1][2] == "ALLOW"
    errors = result.metadata["handler_errors"]
    assert errors[0]["handler"] == "buggy" and errors[0]["kind"] == "handler_error"
    assert errors[0]["policy"] == "confirm"


def test_audit_style_handler_exception_can_be_allowed():
    """审计型 handler 显式 on_error=allow：故障只记 trace，不改变决策。"""
    reg = InterceptorRegistry()

    def h_error(aid, hp, data, ctx):
        raise ValueError("audit sink down")

    reg.register(HookPoint.OUTPUT, h_error, name="audit", priority=90, on_error="allow")
    result = reg.invoke(HookPoint.OUTPUT, "agent", "x")
    assert result.decision == Decision.ALLOW
    assert result.metadata["handler_errors"][0]["policy"] == "allow"


def test_governance_handler_exception_blocks_fail_closed():
    """治理型 handler（判权/DLP）异常 → BLOCK 短路，reason=handler_error，写审计。"""
    reg = InterceptorRegistry()
    audited = []
    reg.set_audit_sink(lambda hp, aid, dec, trace: audited.append((dec, list(trace))))

    def h_dlp(aid, hp, data, ctx):
        raise KeyError("dlp_scanner")

    def h_never(aid, hp, data, ctx):
        raise AssertionError("must not run after BLOCK")

    reg.register(HookPoint.PRE_TOOL_CALL, h_dlp, name="dlp_pre_tool", priority=50, on_error="block")
    reg.register(HookPoint.PRE_TOOL_CALL, h_never, name="late", priority=90)
    result = reg.invoke(HookPoint.PRE_TOOL_CALL, "agent", {"tool": "t"})
    assert result.decision == Decision.BLOCK
    assert result.metadata["reason"] == "handler_error"
    assert result.metadata["failed_handler"] == "dlp_pre_tool"
    assert "fail-closed" in result.message
    assert audited and audited[0][0] == Decision.BLOCK
    assert "ERROR" in audited[0][1][0][2]


def test_handler_timeout_is_treated_as_failure():
    """R-2：handler 超过 timeout_seconds 未返回 → 视同故障，按 on_error 处置。"""
    import time as _time

    reg = InterceptorRegistry(handler_timeout=0.2)

    def h_slow(aid, hp, data, ctx):
        _time.sleep(1.0)
        return InterceptResult(decision=Decision.ALLOW)

    reg.register(HookPoint.INPUT, h_slow, name="slow_dlp", priority=50, on_error="block")
    t0 = _time.perf_counter()
    result = reg.invoke(HookPoint.INPUT, "agent", "text")
    elapsed = _time.perf_counter() - t0
    assert elapsed < 0.9, "超时后必须立即返回，不能等 handler 跑完"
    assert result.decision == Decision.BLOCK
    assert result.metadata["reason"] == "handler_timeout"
    assert "TIMEOUT" in result.metadata["_handler_trace"][0][2]


def test_handler_timeout_zero_runs_inline_without_limit():
    import threading as _threading

    reg = InterceptorRegistry(handler_timeout=0)
    seen = {}

    def h(aid, hp, data, ctx):
        seen["thread"] = _threading.current_thread().name
        return InterceptResult(decision=Decision.ALLOW)

    reg.register(HookPoint.INPUT, h, name="inline", priority=50)
    assert reg.invoke(HookPoint.INPUT, "agent", "x").decision == Decision.ALLOW
    assert seen["thread"] == _threading.current_thread().name


def test_per_handler_timeout_overrides_registry_default():
    import time as _time

    reg = InterceptorRegistry(handler_timeout=5.0)

    def h_slow(aid, hp, data, ctx):
        _time.sleep(0.5)
        return InterceptResult(decision=Decision.ALLOW)

    reg.register(HookPoint.INPUT, h_slow, name="slow", priority=50,
                 on_error="confirm", timeout_seconds=0.1)
    result = reg.invoke(HookPoint.INPUT, "agent", "x")
    assert result.decision == Decision.CONFIRM
    assert result.metadata["handler_errors"][0]["kind"] == "handler_timeout"
    assert reg.describe_handlers(HookPoint.INPUT)[0]["timeout_seconds"] == 0.1


def test_yolo_preserves_capability_handler_failure_block_and_records_it():
    reg = InterceptorRegistry()

    class _Client:
        def get_agent_security_mode(self, aid):
            return {"mode": "yolo"}

    def h_err(aid, hp, data, ctx):
        raise RuntimeError("boom")

    reg.register(HookPoint.PRE_TOOL_CALL, h_err, name="sec_capability", priority=10, on_error="block")
    result = reg.invoke(HookPoint.PRE_TOOL_CALL, "agent", {}, client_provider=lambda: _Client())
    assert result.decision == Decision.BLOCK
    assert result.metadata["failed_handler"] == "sec_capability"
    assert result.metadata["handler_errors"][0]["kind"] == "handler_error"


def test_non_result_return_value_is_a_handler_error():
    reg = InterceptorRegistry()
    reg.register(HookPoint.INPUT, lambda *a: None, name="bad_return", priority=50, on_error="block")
    result = reg.invoke(HookPoint.INPUT, "agent", "x")
    assert result.decision == Decision.BLOCK
    assert "TypeError" in result.metadata["handler_errors"][0]["error"]


def test_env_default_on_error_and_production_guard(monkeypatch):
    from securityd import interceptor as module

    monkeypatch.setenv("BIANBU_HOOK_ON_ERROR", "allow")
    monkeypatch.delenv("BIANBU_RUNTIME_MODE", raising=False)
    assert module.default_on_error() == "allow"
    monkeypatch.setenv("BIANBU_RUNTIME_MODE", "production")
    assert module.default_on_error() == "confirm"
    monkeypatch.setenv("BIANBU_HOOK_ON_ERROR", "garbage")
    assert module.default_on_error() == "confirm"
    monkeypatch.setenv("BIANBU_HOOK_HANDLER_TIMEOUT", "-3")
    assert module.default_handler_timeout() == 0.0
    monkeypatch.setenv("BIANBU_HOOK_HANDLER_TIMEOUT", "abc")
    assert module.default_handler_timeout() == module._HANDLER_TIMEOUT_DEFAULT


def test_core_and_dlp_handlers_register_fail_closed():
    """判权与 DLP handler 必须以 on_error=block 注册，审计 handler 为 allow。"""
    import sys
    from pathlib import Path

    client_dir = Path(__file__).resolve().parents[2] / "client"
    if str(client_dir) not in sys.path:
        sys.path.append(str(client_dir))
    import bianbu_security_handlers as handlers
    from securityd.dlp.handlers import register_dlp_handlers

    reg = InterceptorRegistry()
    handlers.register_core_handlers(reg, with_audit=True)
    register_dlp_handlers(reg)
    pre_tool = {row["name"]: row for row in reg.describe_handlers(HookPoint.PRE_TOOL_CALL)}
    assert pre_tool["sec_capability"]["on_error"] == "block"
    assert pre_tool["dlp_pre_tool"]["on_error"] == "block"
    post_tool = {row["name"]: row for row in reg.describe_handlers(HookPoint.POST_TOOL_CALL)}
    assert post_tool["audit"]["on_error"] == "allow"
    for hp in HookPoint:
        for row in reg.describe_handlers(hp):
            if row["name"].startswith("dlp_"):
                assert row["on_error"] == "block", row
            assert row["timeout_seconds"] > 0, row


def test_empty_hook_point():
    """测试未注册 handler 的 hook_point（直接 ALLOW）。"""
    reg = InterceptorRegistry()
    result = reg.invoke(HookPoint.AGENT_SHUTDOWN, "agent", None)
    assert result.decision == Decision.ALLOW
    assert result.metadata["_handler_trace"] == []


def test_metadata_merged_from_handlers():
    """handler 的 metadata 要合并进最终结果。

    不合并的话调用方只拿到 _handler_trace，看不到判定细节 ——
    WebUI 统计与审计都依赖这些字段。
    """
    def h1(aid, hp, data, ctx):
        return InterceptResult(decision=Decision.ALLOW,
                               metadata={"pii_types": ["phone"], "n": 1})

    def h2(aid, hp, data, ctx):
        return InterceptResult(decision=Decision.ALLOW,
                               metadata={"is_cloud": True})

    reg = InterceptorRegistry()
    reg.register(HookPoint.PRE_MODEL_CALL, h1, name="h1", priority=10)
    reg.register(HookPoint.PRE_MODEL_CALL, h2, name="h2", priority=20)

    r = reg.invoke(HookPoint.PRE_MODEL_CALL, "a", "prompt")
    assert r.metadata["pii_types"] == ["phone"]
    assert r.metadata["n"] == 1
    assert r.metadata["is_cloud"] is True
    assert "_handler_trace" in r.metadata


def test_metadata_later_handler_overrides():
    """同名键后者覆盖前者（按优先级顺序）。"""
    def h1(aid, hp, data, ctx):
        return InterceptResult(decision=Decision.ALLOW, metadata={"k": "first"})

    def h2(aid, hp, data, ctx):
        return InterceptResult(decision=Decision.ALLOW, metadata={"k": "second"})

    reg = InterceptorRegistry()
    reg.register(HookPoint.INPUT, h1, name="h1", priority=10)
    reg.register(HookPoint.INPUT, h2, name="h2", priority=20)
    assert reg.invoke(HookPoint.INPUT, "a", "x").metadata["k"] == "second"


def test_metadata_preserved_on_block_shortcut():
    """BLOCK 短路时也要带上此前 handler 的 metadata。"""
    def h_meta(aid, hp, data, ctx):
        return InterceptResult(decision=Decision.ALLOW,
                               metadata={"scanned": True})

    def h_block(aid, hp, data, ctx):
        return InterceptResult(decision=Decision.BLOCK, message="no",
                               metadata={"reason": "denied"})

    reg = InterceptorRegistry()
    reg.register(HookPoint.PRE_TOOL_CALL, h_meta, name="scan", priority=10)
    reg.register(HookPoint.PRE_TOOL_CALL, h_block, name="block", priority=20)

    r = reg.invoke(HookPoint.PRE_TOOL_CALL, "a", {})
    assert r.decision == Decision.BLOCK
    assert r.metadata["scanned"] is True   # 前一个 handler 的
    assert r.metadata["reason"] == "denied"  # BLOCK 自己的
    assert len(r.metadata["_handler_trace"]) == 2


def test_priority_order():
    """测试多 handler 按优先级顺序执行。"""
    reg = InterceptorRegistry()
    order = []

    def make_handler(name):
        def h(aid, hp, data, ctx):
            order.append(name)
            return InterceptResult(decision=Decision.ALLOW)

        return h

    reg.register(HookPoint.POST_TOOL_CALL, make_handler("audit"), "audit", 90)
    reg.register(HookPoint.POST_TOOL_CALL, make_handler("sec"), "sec", 10)
    reg.register(HookPoint.POST_TOOL_CALL, make_handler("dlp"), "dlp", 50)

    reg.invoke(HookPoint.POST_TOOL_CALL, "agent", {})
    assert order == ["sec", "dlp", "audit"]  # 10 → 50 → 90

@pytest.mark.parametrize('decision', [Decision.BLOCK, Decision.CONFIRM])
def test_yolo_does_not_override_non_capability_handlers(decision):
    from types import SimpleNamespace
    reg = InterceptorRegistry()
    reg.register(HookPoint.PRE_MODEL_CALL,
                 lambda *args: InterceptResult(decision=decision, metadata={'dlp_action': 'block'}),
                 name='dlp_pre_model')
    client = SimpleNamespace(get_agent_security_mode=lambda aid: {'mode': 'yolo'})
    result = reg.invoke(HookPoint.PRE_MODEL_CALL, 'agent', 'synthetic phone', client_provider=lambda: client)
    assert result.decision == decision


def test_yolo_does_not_ignore_fail_closed_handler_errors():
    from types import SimpleNamespace
    reg = InterceptorRegistry()
    def unavailable(*args):
        raise RuntimeError('DLP unavailable')
    reg.register(HookPoint.PRE_MODEL_CALL, unavailable, name='dlp_pre_model', on_error='block')
    client = SimpleNamespace(get_agent_security_mode=lambda aid: {'mode': 'yolo'})
    result = reg.invoke(HookPoint.PRE_MODEL_CALL, 'agent', 'text', client_provider=lambda: client)
    assert result.decision == Decision.BLOCK
    assert result.metadata['reason'] == 'handler_error'
