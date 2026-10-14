"""INT-LG-01/02/03/04/05/06/07/08 + SEC-HOOK-04 — LangGraph 集成层单元测试。"""
from __future__ import annotations

import sys
import types
from pathlib import Path
from typing import Optional

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "client"))


@pytest.fixture
def fake_client(monkeypatch):
    mod = types.ModuleType("bianbu_security_client")
    mod._decision = 0  # ALLOW
    mod._calls = {"check": [], "audit": [], "register": []}

    def check_permission(aid, cap, scope=""):
        mod._calls["check"].append((aid, cap, scope))
        if isinstance(mod._decision, Exception):
            raise mod._decision
        return mod._decision

    def audit_log(aid, op_type, target, result):
        mod._calls["audit"].append((aid, op_type, target, result))
        return 1

    def register_capabilities(aid, caps):
        mod._calls["register"].append((aid, len(caps)))
        return True

    def install_package(path):
        return {"ok": True, "agent_id": "test", "count": 5}

    mod.check_permission = check_permission
    mod.audit_log = audit_log
    mod.register_capabilities = register_capabilities
    mod.install_package = install_package
    monkeypatch.setitem(sys.modules, "bianbu_security_client", mod)
    return mod


# ═══════════════════════════════════════════════════════════════
# INT-LG-02 — 工具映射
# ═══════════════════════════════════════════════════════════════
class TestMapping:
    def test_tool_name_is_the_policy_key(self):
        from securityd.langgraph.mapping import resolve
        assert resolve("terminal") == ("terminal", "")
        assert resolve("read_file") == ("read_file", "")
        assert resolve("write_file") == ("write_file", "")

    def test_empty_name(self):
        from securityd.langgraph.mapping import resolve
        assert resolve("") is None
        assert resolve(None) is None

    def test_unmapped_policy_defaults_to_allow(self):
        """目录/映射都没命中的工具默认放行，与目录默认值保持一致。"""
        import importlib
        import os

        from securityd import capabilities
        from securityd.langgraph import mapping

        assert capabilities.unmapped_policy() == "allow"
        assert capabilities.unmapped_decision() == 0      # ALLOW
        assert mapping.DEFAULT_ALLOW is True

        old = os.environ.get("BIANBU_SECURITY_UNMAPPED")
        try:
            os.environ["BIANBU_SECURITY_UNMAPPED"] = "ask"
            assert capabilities.unmapped_decision() == 1
            assert importlib.reload(mapping).DEFAULT_ALLOW is False
            os.environ["BIANBU_SECURITY_UNMAPPED"] = "deny"
            assert capabilities.unmapped_decision() == 2
            os.environ["BIANBU_SECURITY_UNMAPPED"] = "garbage"
            assert capabilities.unmapped_policy() == "allow"   # 非法值回落
        finally:
            if old is None:
                os.environ.pop("BIANBU_SECURITY_UNMAPPED", None)
            else:
                os.environ["BIANBU_SECURITY_UNMAPPED"] = old
            importlib.reload(mapping)


# ═══════════════════════════════════════════════════════════════
# INT-LG-03 — Agent 身份注册
# ═══════════════════════════════════════════════════════════════
class TestRegisterAgent:
    def test_register_uses_default_capabilities(self, fake_client):
        from securityd.langgraph.tool_node import register_agent
        ok = register_agent("com.test.lg", fail_open=True)
        assert ok is True
        assert any(r[0] == "com.test.lg" for r in fake_client._calls["register"])

    def test_register_env_override(self, fake_client, monkeypatch):
        monkeypatch.setenv("BIANBU_AGENT_ID", "com.env.agent")
        from securityd.langgraph import tool_node as tn
        import importlib; importlib.reload(tn)
        ok = tn.register_agent(fail_open=True)
        assert ok

    def test_register_fail_open(self, monkeypatch):
        """securityd 不可达时 fail_open=True 不抛异常。"""
        mod = types.ModuleType("bianbu_security_client")
        def bad(*a, **k): raise RuntimeError("bus down")
        mod.register_capabilities = bad
        monkeypatch.setitem(sys.modules, "bianbu_security_client", mod)
        from securityd.langgraph.tool_node import register_agent
        ok = register_agent("a", fail_open=True)
        assert ok is False


# ═══════════════════════════════════════════════════════════════
# INT-LG-01 — BianbuSecurityToolNode 判权
# ═══════════════════════════════════════════════════════════════
def _make_state(tool_name: str, args: dict | None = None):
    """构造最小化 LangGraph 消息状态。"""
    try:
        from langchain_core.messages import AIMessage
    except ImportError:
        pytest.skip("langchain_core 未安装")

    tc = {"name": tool_name, "args": args or {}, "id": f"call_{tool_name}"}
    msg = AIMessage(content="", tool_calls=[tc])
    return {"messages": [msg]}


class TestToolNode:
    def _node(self, fake_client, decision=0, registry=None):
        from securityd.langgraph.tool_node import BianbuSecurityToolNode
        fake_client._decision = decision
        return BianbuSecurityToolNode(
            [],
            agent_id="com.test",
            registry=registry,
            client_provider=lambda: fake_client,
        )

    def test_allow_calls_inner(self, fake_client):
        """ALLOW → 转发给内部 ToolNode。"""
        node = self._node(fake_client, decision=0)
        # 内部 ToolNode 对空工具会返回 error message，但这里验证判权逻辑即可
        state = _make_state("read_file")
        r = node._check("read_file", {})
        assert r["decision"] == "ALLOW"
        assert any(c[1] == "read_file" for c in fake_client._calls["check"])

    def test_deny_returns_block(self, fake_client):
        node = self._node(fake_client, decision=2)
        r = node._check("terminal", {})
        assert r["decision"] == "BLOCK"

    def test_confirm_returns_confirm(self, fake_client):
        node = self._node(fake_client, decision=1)
        r = node._check("write_file", {})
        assert r["decision"] == "CONFIRM"

    def test_fail_closed_on_bus_error(self, monkeypatch):
        monkeypatch.delenv("BIANBU_SECURITY_FAIL_OPEN", raising=False)
        mod = types.ModuleType("bianbu_security_client")
        def bad(*a, **k): raise RuntimeError("bus down")
        mod.check_permission = bad
        mod.audit_log = lambda *a, **k: 1
        monkeypatch.setitem(sys.modules, "bianbu_security_client", mod)
        from securityd.langgraph.tool_node import BianbuSecurityToolNode
        node = BianbuSecurityToolNode([], client_provider=lambda: mod)
        r = node._check("read_file", {})
        assert r["decision"] == "BLOCK"
        assert "不可达" in r["message"]

    def test_fail_open_on_bus_error(self, monkeypatch):
        monkeypatch.setenv("BIANBU_SECURITY_FAIL_OPEN", "1")
        mod = types.ModuleType("bianbu_security_client")
        def bad(*a, **k): raise RuntimeError("bus down")
        mod.check_permission = bad
        mod.audit_log = lambda *a, **k: 1
        monkeypatch.setitem(sys.modules, "bianbu_security_client", mod)
        from securityd.langgraph.tool_node import BianbuSecurityToolNode
        node = BianbuSecurityToolNode([], client_provider=lambda: mod)
        r = node._check("read_file", {})
        assert r["decision"] == "ALLOW"

    def test_ask_decision_prompts(self, fake_client):
        """securityd 返回 ask(1) → tool_node 报 CONFIRM，交用户逐次确认。"""
        node = self._node(fake_client, decision=1)
        r = node._check("totally_custom_xyz", {})
        assert r["decision"] == "CONFIRM"
        assert r["capability"] == "totally_custom_xyz"
        assert any(c[1] == "totally_custom_xyz" for c in fake_client._calls["check"])

    def test_audit_written(self, fake_client):
        node = self._node(fake_client, decision=0)
        node._check("read_file", {})
        assert fake_client._calls["audit"]

    def test_audit_contains_run_id(self, fake_client, monkeypatch):
        monkeypatch.setenv("LANGGRAPH_RUN_ID", "run-abc")
        node = self._node(fake_client)
        node._check("read_file", {})
        result_vals = [c[3] for c in fake_client._calls["audit"]]
        assert any("run=run-abc" in v for v in result_vals)


# ═══════════════════════════════════════════════════════════════
# SEC-HOOK-04 — 通过 registry 挂载（DLP 可插拔）
# ═══════════════════════════════════════════════════════════════
class TestRegistryIntegration:
    def test_registry_deny_overrides_allow(self, fake_client):
        """SEC capability DENY 时 ToolNode 报 BLOCK（优先级 10，最先执行）。"""
        from securityd.interceptor import (
            Decision, HookPoint, InterceptResult, InterceptorRegistry,
        )
        fake_client._decision = 0  # check_permission 返回 ALLOW
        reg = InterceptorRegistry()

        # 手动注册 SEC handler（通常由 setup_interceptor 完成）
        import bianbu_security_handlers as h
        h.register_core_handlers(reg, with_audit=False)
        # override: SEC 改为 DENY
        def force_deny(aid, hp, data, ctx):
            return InterceptResult(decision=Decision.BLOCK, message="sec deny")
        reg.register(HookPoint.PRE_TOOL_CALL, force_deny, name="sec_test", priority=10)
        reg.unregister(HookPoint.PRE_TOOL_CALL, "sec_capability")

        from securityd.langgraph.tool_node import BianbuSecurityToolNode
        node = BianbuSecurityToolNode([], registry=reg,
                                     client_provider=lambda: fake_client)
        r = node._check("terminal", {})
        assert r["decision"] == "BLOCK"

    def test_dlp_escalates_allow_to_confirm(self, fake_client):
        """SEC ALLOW + DLP 检出 PII → CONFIRM（DLP-06 机制在 LangGraph 下生效）。"""
        from securityd.interceptor import (
            Decision, HookPoint, InterceptResult, InterceptorRegistry,
        )
        fake_client._decision = 0
        reg = InterceptorRegistry()

        import bianbu_security_handlers as h
        h.register_core_handlers(reg, with_audit=False)

        def fake_dlp(aid, hp, data, ctx):
            args = data.get("args") if isinstance(data, dict) else {}
            if "13812345678" in str(args):
                return InterceptResult(decision=Decision.CONFIRM,
                                       message="PII in args")
            return InterceptResult(decision=Decision.ALLOW)

        reg.register(HookPoint.PRE_TOOL_CALL, fake_dlp, name="dlp", priority=50)

        from securityd.langgraph.tool_node import BianbuSecurityToolNode
        node = BianbuSecurityToolNode([], registry=reg,
                                     client_provider=lambda: fake_client)
        r = node._check("write_file", {"path": "/tmp/13812345678.txt"})
        assert r["decision"] == "CONFIRM"

    def test_sec_deny_shortcuts_dlp(self, fake_client):
        """SEC DENY 短路，DLP 不执行。"""
        from securityd.interceptor import (
            Decision, HookPoint, InterceptResult, InterceptorRegistry,
        )
        fake_client._decision = 0
        reg = InterceptorRegistry()

        def sec_deny(aid, hp, data, ctx):
            return InterceptResult(decision=Decision.BLOCK, message="deny")
        reg.register(HookPoint.PRE_TOOL_CALL, sec_deny, name="sec", priority=10)

        ran = []
        def dlp(aid, hp, data, ctx):
            ran.append(1)
            return InterceptResult(decision=Decision.ALLOW)
        reg.register(HookPoint.PRE_TOOL_CALL, dlp, name="dlp", priority=50)

        from securityd.langgraph.tool_node import BianbuSecurityToolNode
        node = BianbuSecurityToolNode([], registry=reg,
                                     client_provider=lambda: fake_client)
        r = node._check("terminal", {})
        assert r["decision"] == "BLOCK"
        assert ran == []  # DLP 未执行
