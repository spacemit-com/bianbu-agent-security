"""SEC-HOOK-05 — 干预点执行轨迹落审计链。"""
import sys
import types
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "client"))

from securityd.interceptor import (  # noqa: E402
    Decision,
    HookPoint,
    InterceptResult,
    InterceptorRegistry,
)


@pytest.fixture
def fake_client(monkeypatch):
    mod = types.ModuleType("bianbu_security_client")
    mod._audit = []

    def audit_log(agent_id, op_type, target, result):
        mod._audit.append((agent_id, op_type, target, result))
        return len(mod._audit)

    mod.audit_log = audit_log
    mod.check_permission = lambda *a, **k: 0
    monkeypatch.setitem(sys.modules, "bianbu_security_client", mod)
    return mod


@pytest.fixture
def handlers(fake_client):
    import bianbu_security_handlers as h

    return h


def _allow(name):
    def h(aid, hp, data, ctx):
        return InterceptResult(decision=Decision.ALLOW, message=f"{name} ok")

    return h


def test_format_hook_trace(handlers):
    """trace 编码为紧凑单行。"""
    s = handlers.format_hook_trace(
        [("sec_capability", 1.234, "ALLOW"), ("dlp", 8.5, "CONFIRM")])
    assert s == "sec_capability@1.2=ALLOW,dlp@8.5=CONFIRM"


def test_format_hook_trace_empty(handlers):
    assert handlers.format_hook_trace([]) == ""
    assert handlers.format_hook_trace(None) == ""


def test_format_hook_trace_malformed(handlers):
    """畸形条目不抛异常（审计不能因格式问题挂掉）。"""
    s = handlers.format_hook_trace(["weird", ("a", 1.0, "ALLOW")])
    assert "weird" in s and "a@1.0=ALLOW" in s


def test_sink_writes_audit_on_allow(handlers, fake_client):
    """ALLOW 链写一条审计：op_type=hook:<point>，result=trace。"""
    reg = InterceptorRegistry()
    reg.set_audit_sink(handlers.make_audit_sink("default-agent"))
    reg.register(HookPoint.PRE_TOOL_CALL, _allow("h1"), name="h1", priority=10)

    reg.invoke(HookPoint.PRE_TOOL_CALL, "com.hermes.agent", {"tool": "t"})

    assert len(fake_client._audit) == 1
    aid, op_type, target, result = fake_client._audit[0]
    assert aid == "com.hermes.agent"
    assert op_type == "hook:pre_tool_call"
    assert target == "ALLOW"
    assert result.startswith("h1@") and result.endswith("=ALLOW")


def test_sink_writes_audit_on_block(handlers, fake_client):
    """BLOCK 短路也写审计（trace 只含已执行的 handler）。"""
    reg = InterceptorRegistry()
    reg.set_audit_sink(handlers.make_audit_sink())

    def blocker(aid, hp, data, ctx):
        return InterceptResult(decision=Decision.BLOCK, message="nope")

    reg.register(HookPoint.PRE_TOOL_CALL, _allow("first"), name="first", priority=10)
    reg.register(HookPoint.PRE_TOOL_CALL, blocker, name="blocker", priority=20)
    reg.register(HookPoint.PRE_TOOL_CALL, _allow("never"), name="never", priority=30)

    reg.invoke(HookPoint.PRE_TOOL_CALL, "a", {})

    assert len(fake_client._audit) == 1
    _, op_type, target, result = fake_client._audit[0]
    assert op_type == "hook:pre_tool_call"
    assert target == "BLOCK"
    assert "first@" in result and "blocker@" in result
    assert "never" not in result  # 短路后未执行


def test_sink_uses_default_agent_id(handlers, fake_client):
    """agent_id 为空时用 sink 的默认值。"""
    reg = InterceptorRegistry()
    reg.set_audit_sink(handlers.make_audit_sink("fallback-agent"))
    reg.register(HookPoint.OUTPUT, _allow("h"), name="h", priority=10)
    reg.invoke(HookPoint.OUTPUT, "", "some output")
    assert fake_client._audit[0][0] == "fallback-agent"


def test_empty_hook_point_no_audit(handlers, fake_client):
    """无 handler 的干预点不写审计（无治理动作，避免噪声）。"""
    reg = InterceptorRegistry()
    reg.set_audit_sink(handlers.make_audit_sink())
    reg.invoke(HookPoint.AGENT_SHUTDOWN, "a", None)
    assert fake_client._audit == []


def test_sink_failure_does_not_break_chain(handlers, fake_client, monkeypatch):
    """sink 抛异常不影响治理决策。"""
    reg = InterceptorRegistry()

    def boom(*a, **kw):
        raise RuntimeError("audit backend down")

    reg.set_audit_sink(boom)
    reg.register(HookPoint.PRE_TOOL_CALL, _allow("h"), name="h", priority=10)

    r = reg.invoke(HookPoint.PRE_TOOL_CALL, "a", {})
    assert r.decision == Decision.ALLOW  # 链正常返回


def test_sink_can_be_disabled(handlers, fake_client):
    """set_audit_sink(None) 关闭审计。"""
    reg = InterceptorRegistry()
    reg.set_audit_sink(handlers.make_audit_sink())
    reg.register(HookPoint.INPUT, _allow("h"), name="h", priority=10)
    reg.invoke(HookPoint.INPUT, "a", "x")
    assert len(fake_client._audit) == 1

    reg.set_audit_sink(None)
    reg.invoke(HookPoint.INPUT, "a", "y")
    assert len(fake_client._audit) == 1  # 未新增


def test_latency_recorded_in_audit(handlers, fake_client):
    """延迟数据进审计（可离线分析慢 handler）。"""
    reg = InterceptorRegistry()
    reg.set_audit_sink(handlers.make_audit_sink())

    def slow(aid, hp, data, ctx):
        import time
        time.sleep(0.01)  # 10ms
        return InterceptResult(decision=Decision.ALLOW)

    reg.register(HookPoint.PRE_MODEL_CALL, slow, name="slow", priority=10)
    reg.invoke(HookPoint.PRE_MODEL_CALL, "a", "prompt")

    result = fake_client._audit[0][3]
    latency = float(result.split("@")[1].split("=")[0])
    assert latency >= 9.0  # 至少 ~10ms
