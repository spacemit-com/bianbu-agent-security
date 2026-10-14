"""Logical Agent registration and capability synchronization contract tests."""
from __future__ import annotations

import importlib
import sys
import types

import pytest


def _permission(name: str, *, policy: str = "ask"):
    from securityd.models import Permission

    return Permission.from_dict({"tool": name, "policy": policy})


def test_register_agent_is_idempotent_and_refreshes_metadata(engine):
    first = engine.register_agent("agent.demo", {"name": "Demo", "version": "1.0.0"})
    second = engine.register_agent("agent.demo", {"name": "Demo v2", "version": "2.0.0"})

    assert first == {
        "agent_id": "agent.demo", "name": "Demo", "version": "1.0.0",
        "status": "active", "framework": "",
    }
    assert second["agent_id"] == "agent.demo"
    assert second["name"] == "Demo v2"
    assert second["version"] == "2.0.0"
    assert engine.registry.get_manifest_info("agent.demo")["name"] == "Demo v2"
    assert engine.registry.list_agents() == [
        {
            "agent_id": "agent.demo", "name": "Demo v2", "version": "2.0.0",
            "status": "active", "installed_at": engine.registry.get_manifest_info("agent.demo")["installed_at"],
            "framework": "", "capability_count": 0, "allowed_count": 0,
        }
    ]


@pytest.mark.parametrize("agent_id", ["", "   ", None])
def test_register_agent_rejects_empty_id(engine, agent_id):
    with pytest.raises(ValueError, match="agent_id"):
        engine.register_agent(agent_id, {})


def test_sync_replaces_capabilities_and_is_audited(engine):
    engine.register_agent("agent.demo", {"name": "Demo"})
    engine.sync_agent_capabilities("agent.demo", [
        _permission("old_tool"),
        _permission("keep_tool", policy="allow"),
    ])
    result = engine.sync_agent_capabilities("agent.demo", [
        _permission("new_tool", policy="deny"),
    ])

    assert result == {"agent_id": "agent.demo", "count": 1, "status": "synced"}
    capabilities = engine.registry.get_capabilities("agent.demo")
    assert [(p.tool, p.policy.value) for p in capabilities] == [
        ("new_tool", "deny"),
    ]
    rows = engine.audit._conn.execute(
        "SELECT op_type,target,result FROM audit_record ORDER BY seq"
    ).fetchall()
    assert [(r[0], r[1], r[2]) for r in rows] == [
        ("register_agent", "agent.demo", "success"),
        ("sync_capabilities", "agent.demo", "count=2"),
        ("sync_capabilities", "agent.demo", "count=1"),
    ]


def test_sync_requires_prior_agent_registration(engine):
    with pytest.raises(ValueError, match="未注册|registered"):
        engine.sync_agent_capabilities("agent.unknown", [_permission("cap")])


def test_sync_rejects_malformed_capability_without_destroying_existing_rows(engine):
    engine.register_agent("agent.demo", {"name": "Demo"})
    engine.sync_agent_capabilities("agent.demo", [_permission("existing")])
    from securityd.models import Permission
    malformed = Permission("bad", "maybe")

    with pytest.raises(ValueError, match="policy"):
        engine.sync_agent_capabilities("agent.demo", [malformed])

    assert [p.tool for p in engine.registry.get_capabilities("agent.demo")] == ["existing"]
    # The failed operation must not leave an open transaction that a later
    # successful operation could accidentally commit.
    engine.sync_agent_capabilities("agent.demo", [_permission("after")])
    assert [p.tool for p in engine.registry.get_capabilities("agent.demo")] == ["after"]


@pytest.mark.parametrize("bad", [
    {"tool": "", "policy": "ask"},
    {"tool": "bad", "policy": "maybe"},
])
def test_sync_rejects_empty_or_invalid_policy_capability(engine, bad):
    engine.register_agent("agent.demo", {"name": "Demo"})
    from securityd.models import Permission

    with pytest.raises(ValueError, match="tool|policy"):
        engine.sync_agent_capabilities("agent.demo", [Permission.from_dict(bad)])


def test_unregister_agent_removes_identity_capabilities_binding_and_session_trust(engine):
    from securityd.models import CallerContext

    engine.register_agent("agent.demo", {"name": "Demo"})
    engine.sync_agent_capabilities("agent.demo", [
        _permission("session.cap"),
    ])
    engine.registry.bind_agent(
        "agent.demo", CallerContext(":1.1", 1000, 1, "/usr/bin/agent", "/agent", "s1"), "now"
    )
    engine.registry.grant_session_trust("s1", "agent.demo", "session.cap", "now")

    assert engine.unregister_agent("agent.demo") is True
    assert engine.unregister_agent("agent.demo") is False
    assert engine.registry.get_manifest_info("agent.demo") is None
    assert engine.registry.get_capabilities("agent.demo") == []
    assert engine.registry.get_binding("agent.demo") is None
    assert engine.registry._conn.execute(
        "SELECT 1 FROM session_trust WHERE agent_id='agent.demo'"
    ).fetchone() is None
    rows = engine.audit._conn.execute(
        "SELECT op_type,target,result FROM audit_record ORDER BY seq"
    ).fetchall()
    assert [(r[0], r[1], r[2]) for r in rows] == [
        ("register_agent", "agent.demo", "success"),
        ("sync_capabilities", "agent.demo", "count=1"),
        ("unregister_agent", "agent.demo", "success"),
        ("unregister_agent", "agent.demo", "notfound"),
    ]


def test_security_xml_declares_lifecycle_methods():
    from pathlib import Path

    xml = (Path(__file__).resolve().parents[2] / "data/io.bianbu.Security.xml").read_text()
    for method in ("RegisterAgent", "UnregisterAgent", "SyncAgentCapabilities"):
        assert f'<method name="{method}">' in xml


def test_client_capability_payload_preserves_values(monkeypatch):
    """Client wrapper translates Python rows to D-Bus-safe dictionaries.

    ``register_capabilities`` is the only writer left: the console reads the
    existing rows through ``get_capabilities`` and only adds what is missing,
    so an operator's tightening is never overwritten by an Agent declaration.
    """
    class _Variant(str):
        pass

    class _Dictionary(dict):
        def __init__(self, values=(), signature=None):
            super().__init__(values)

    fake_dbus = types.ModuleType("dbus")
    fake_dbus.String = _Variant
    fake_dbus.Boolean = bool
    fake_dbus.Int32 = int
    fake_dbus.Int64 = int
    fake_dbus.Double = float
    fake_dbus.Dictionary = _Dictionary
    fake_dbus.exceptions = types.SimpleNamespace(DBusException=RuntimeError)
    monkeypatch.setitem(sys.modules, "dbus", fake_dbus)
    sys.modules.pop("client.bianbu_security_client", None)
    client = importlib.import_module("client.bianbu_security_client")

    seen = {}

    class Proxy:
        def BindAgent(self, agent_id, **kwargs):
            seen["bound"] = str(agent_id)
            return True

        def RegisterCapabilities(self, agent_id, rows, **kwargs):
            seen["agent_id"] = str(agent_id)
            seen["rows"] = rows
            return True

    monkeypatch.setattr(client, "_get_proxy", lambda: Proxy())
    assert client.register_capabilities("agent.demo", [{
        "tool": "read_file", "policy": "allow",
    }]) is True
    assert seen["bound"] == "agent.demo"
    assert seen["agent_id"] == "agent.demo"
    assert len(seen["rows"]) == 1
    row = dict(seen["rows"][0])
    assert {str(k): str(v) for k, v in row.items()}["policy"] == "allow"
