"""SEC-HOOK-03 — hermes 插件经干预点框架判权（行为等价 + 可插拔验证）。

用 fake client 替换 D-Bus 客户端，验证：
  1. 判权走 registry 的 pre_tool_call 点
  2. ALLOW/DENY/CONFIRM 三态与改造前行为一致
  3. 额外注册的 DLP handler 能影响最终决策（可插拔生效）
"""
import sys
import types
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "client"))
sys.path.insert(0, str(ROOT / "hermes_plugin"))

from securityd.interceptor import (  # noqa: E402
    Decision,
    HookPoint,
    InterceptResult,
    InterceptorRegistry,
)

ALLOW, CONFIRM, DENY = 0, 1, 2


@pytest.fixture
def fake_client(monkeypatch):
    """伪造 bianbu_security_client（不碰 D-Bus）。"""
    mod = types.ModuleType("bianbu_security_client")
    calls = {"check": [], "check_v2": [], "audit": [], "confirm": []}
    mod._decision = ALLOW

    def check_permission(agent_id, capability, scope):
        calls["check"].append((agent_id, capability, scope))
        if isinstance(mod._decision, Exception):
            raise mod._decision
        return mod._decision

    def audit_log(agent_id, op_type, target, result):
        calls["audit"].append((agent_id, op_type, target, result))
        return True

    def check_permission_v2(agent_id, capability, scope, context):
        calls["check_v2"].append((agent_id, capability, scope, context))
        if isinstance(mod._decision, Exception):
            raise mod._decision
        return mod._decision

    def request_confirm(agent_id, capability, detail):
        calls["confirm"].append((agent_id, capability, detail))
        return mod._confirm_result

    mod.check_permission = check_permission
    mod.check_permission_v2 = check_permission_v2
    mod.audit_log = audit_log
    mod.request_confirm = request_confirm
    mod._confirm_result = False
    mod._calls = calls
    monkeypatch.setitem(sys.modules, "bianbu_security_client", mod)
    return mod


@pytest.fixture
def handlers(fake_client):
    import bianbu_security_handlers as h

    return h


def test_sec_handler_allow(handlers, fake_client):
    """ALLOW → Decision.ALLOW。"""
    fake_client._decision = ALLOW
    r = handlers.sec_capability_handler(
        "com.hermes.agent", HookPoint.PRE_TOOL_CALL,
        {"tool": "read_file", "capability": "file.read", "scope": "/tmp"}, {})
    assert r.decision == Decision.ALLOW
    assert fake_client._calls["check"] == [("com.hermes.agent", "file.read", "/tmp")]


def test_sec_handler_deny(handlers, fake_client):
    """DENY → Decision.BLOCK，metadata 标记 reason=denied。"""
    fake_client._decision = DENY
    r = handlers.sec_capability_handler(
        "com.hermes.agent", HookPoint.PRE_TOOL_CALL,
        {"tool": "terminal", "capability": "system.execute", "scope": ""}, {})
    assert r.decision == Decision.BLOCK
    assert r.metadata["reason"] == "denied"
    assert "system.execute" in r.message


def test_sec_handler_confirm(handlers, fake_client):
    """CONFIRM → Decision.CONFIRM，不在 handler 内做 UI。"""
    fake_client._decision = CONFIRM
    r = handlers.sec_capability_handler(
        "com.hermes.agent", HookPoint.PRE_TOOL_CALL,
        {"tool": "write_file", "capability": "file.write", "scope": "/etc"}, {})
    assert r.decision == Decision.CONFIRM
    assert r.metadata["capability"] == "file.write"
    assert fake_client._calls["confirm"] == []  # handler 不触发确认


def test_sec_handler_uses_v2_session_context(handlers, fake_client):
    """有完整 Run 上下文时判权必须读取 once_per_session 信任。"""

    fake_client._decision = ALLOW
    r = handlers.sec_capability_handler(
        "com.hermes.agent",
        HookPoint.PRE_TOOL_CALL,
        {"tool": "memory_retrieve", "capability": "data.memory", "scope": ""},
        {
            "client_provider": lambda: fake_client,
            "session_id": "session-1",
            "run_id": "run-1",
        },
    )
    assert r.decision == Decision.ALLOW
    assert fake_client._calls["check"] == []
    assert fake_client._calls["check_v2"] == [
        (
            "com.hermes.agent",
            "data.memory",
            "",
            {"session_id": "session-1", "run_id": "run-1"},
        )
    ]


def test_sec_handler_fail_closed(handlers, fake_client, monkeypatch):
    """securityd 不可达 + 默认 fail-closed → BLOCK。"""
    monkeypatch.delenv("BIANBU_SECURITY_FAIL_OPEN", raising=False)
    fake_client._decision = RuntimeError("bus unreachable")
    r = handlers.sec_capability_handler(
        "a", HookPoint.PRE_TOOL_CALL,
        {"tool": "t", "capability": "system.execute", "scope": ""}, {})
    assert r.decision == Decision.BLOCK
    assert "fail-closed" in r.message
    assert r.metadata.get("reason") != "denied"  # 不可达 ≠ 明确拒绝


def test_sec_handler_fail_open(handlers, fake_client, monkeypatch):
    """securityd 不可达 + FAIL_OPEN=1 → ALLOW。"""
    monkeypatch.setenv("BIANBU_SECURITY_FAIL_OPEN", "1")
    fake_client._decision = RuntimeError("bus unreachable")
    r = handlers.sec_capability_handler(
        "a", HookPoint.PRE_TOOL_CALL,
        {"tool": "t", "capability": "system.execute", "scope": ""}, {})
    assert r.decision == Decision.ALLOW


def test_sec_handler_no_capability(handlers, fake_client):
    """capability 为空（映射表未声明）→ ALLOW，不查总线。"""
    r = handlers.sec_capability_handler(
        "a", HookPoint.PRE_TOOL_CALL, {"tool": "clarify", "capability": None}, {})
    assert r.decision == Decision.ALLOW
    assert fake_client._calls["check"] == []


def test_register_core_handlers_idempotent(handlers):
    """重复注册不产生重复 handler（幂等）。"""
    reg = InterceptorRegistry()
    handlers.register_core_handlers(reg)
    handlers.register_core_handlers(reg)
    names = [n for _, n in reg.list_handlers(HookPoint.PRE_TOOL_CALL)]
    assert names == ["sec_capability"]
    assert [n for _, n in reg.list_handlers(HookPoint.POST_TOOL_CALL)] == ["audit"]


def test_dlp_can_escalate_allow_to_confirm(handlers, fake_client):
    """可插拔验证：SEC 判 ALLOW，DLP 检出 PII → 最终 CONFIRM（DLP-06 机制）。"""
    fake_client._decision = ALLOW
    reg = InterceptorRegistry()
    handlers.register_core_handlers(reg, with_audit=False)

    def fake_dlp(agent_id, hook_point, data, ctx):
        if "13812345678" in str(data.get("args", {})):
            return InterceptResult(
                decision=Decision.CONFIRM, message="检出手机号")
        return InterceptResult(decision=Decision.ALLOW)

    reg.register(HookPoint.PRE_TOOL_CALL, fake_dlp, name="dlp", priority=50)

    r = reg.invoke(HookPoint.PRE_TOOL_CALL, "a",
                   {"tool": "send_email", "capability": "network.access",
                    "scope": "", "args": {"body": "call 13812345678"}})
    assert r.decision == Decision.CONFIRM
    assert "检出手机号" in r.message
    # 顺序：sec(10) 先于 dlp(50)
    trace = r.metadata["_handler_trace"]
    assert [t[0] for t in trace] == ["sec_capability", "dlp"]


def test_sec_deny_shortcuts_dlp(handlers, fake_client):
    """SEC 判 DENY 时短路，DLP handler 不执行（省开销）。"""
    fake_client._decision = DENY
    reg = InterceptorRegistry()
    handlers.register_core_handlers(reg, with_audit=False)

    ran = []

    def fake_dlp(agent_id, hook_point, data, ctx):
        ran.append(1)
        return InterceptResult(decision=Decision.ALLOW)

    reg.register(HookPoint.PRE_TOOL_CALL, fake_dlp, name="dlp", priority=50)

    r = reg.invoke(HookPoint.PRE_TOOL_CALL, "a",
                   {"tool": "terminal", "capability": "system.execute", "scope": ""})
    assert r.decision == Decision.BLOCK
    assert ran == []  # DLP 未执行


def test_audit_handler_records(handlers, fake_client):
    """审计 handler 写审计链，且始终 ALLOW（观察者）。"""
    r = handlers.audit_handler(
        "com.hermes.agent", HookPoint.POST_TOOL_CALL,
        {"tool": "read_file", "capability": "file.read", "scope": "/tmp"},
        {"audit_result": "executed"})
    assert r.decision == Decision.ALLOW
    assert fake_client._calls["audit"] == [
        ("com.hermes.agent", "read_file", "file.read:/tmp", "executed")]


def test_audit_failure_does_not_break(handlers, fake_client, monkeypatch):
    """审计失败不影响主流程（仍 ALLOW）。"""
    def boom(*a, **kw):
        raise RuntimeError("audit down")

    monkeypatch.setattr(fake_client, "audit_log", boom)
    r = handlers.audit_handler("a", HookPoint.POST_TOOL_CALL, {"tool": "t"}, {})
    assert r.decision == Decision.ALLOW
