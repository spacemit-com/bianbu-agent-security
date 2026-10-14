"""Control-plane contracts for per-Agent security mode."""
from __future__ import annotations

import importlib
import json
from pathlib import Path
import sys
import types

import pytest


def test_service_mode_setter_requires_admin_and_forwards_trusted_actor(sec_root):
    pytest.importorskip("dbus")
    from securityd.models import CallerContext
    from securityd.service import SecurityService

    service = object.__new__(SecurityService)
    caller = CallerContext(":1.42", 1000, 4242, "/usr/bin/admin-ui", "/admin.slice", "")
    calls = []
    service._require_admin = lambda sender: calls.append(("admin", sender)) or caller
    service.engine = types.SimpleNamespace(
        set_agent_security_mode=lambda aid, mode, actor: calls.append(
            ("set", aid, mode, actor)
        ) or {"agent_id": aid, "old_mode": "normal", "mode": mode,
              "updated_at": "now", "updated_by": actor}
    )

    result = SecurityService.SetAgentSecurityMode(
        service, "agent.demo", "yolo", sender=":1.42"
    )

    assert calls[0] == ("admin", ":1.42")
    assert calls[1] == (
        "set", "agent.demo", "yolo",
        "uid=1000;pid=4242;exe=/usr/bin/admin-ui;cgroup=/admin.slice",
    )
    assert str(result["mode"]) == "yolo"


def test_service_mode_getter_is_admin_only(sec_root):
    pytest.importorskip("dbus")
    from securityd.service import SecurityService

    service = object.__new__(SecurityService)
    calls = []
    service._require_admin = lambda sender: calls.append(sender)
    service.engine = types.SimpleNamespace(
        get_agent_security_mode=lambda aid: {
            "agent_id": aid, "mode": "normal", "updated_at": "", "updated_by": ""
        }
    )

    result = SecurityService.GetAgentSecurityMode(service, "agent.demo", sender=":1.8")

    assert calls == [":1.8"]
    assert str(result["mode"]) == "normal"


def test_client_wraps_mode_dbus_calls(monkeypatch):
    class _Dictionary(dict):
        def __init__(self, values=(), signature=None):
            super().__init__(values)

    fake_dbus = types.ModuleType("dbus")
    fake_dbus.String = str
    fake_dbus.Boolean = bool
    fake_dbus.Int32 = int
    fake_dbus.Int64 = int
    fake_dbus.Double = float
    fake_dbus.Dictionary = _Dictionary
    fake_dbus.exceptions = types.SimpleNamespace(DBusException=RuntimeError)
    monkeypatch.setitem(sys.modules, "dbus", fake_dbus)
    sys.modules.pop("client.bianbu_security_client", None)
    client = importlib.import_module("client.bianbu_security_client")
    seen = []

    class Proxy:
        def GetAgentSecurityMode(self, aid, **kwargs):
            seen.append(("get", aid))
            return {"agent_id": aid, "mode": "normal", "updated_at": "", "updated_by": ""}

        def SetAgentSecurityMode(self, aid, mode, **kwargs):
            seen.append(("set", aid, mode))
            return {"agent_id": aid, "old_mode": "normal", "mode": mode,
                    "updated_at": "now", "updated_by": "uid=0"}

    monkeypatch.setattr(client, "_get_proxy", lambda: Proxy())

    assert client.get_agent_security_mode("agent.demo")["mode"] == "normal"
    assert client.set_agent_security_mode("agent.demo", "yolo")["mode"] == "yolo"
    assert seen == [("get", "agent.demo"), ("set", "agent.demo", "yolo")]


def test_cli_agent_mode_uses_control_plane_client(monkeypatch, capsys):
    from cli import bncli

    calls = []
    fake = types.ModuleType("client.bianbu_security_client")
    fake.get_agent_security_mode = lambda aid: calls.append(("get", aid)) or {
        "agent_id": aid, "mode": "normal"
    }
    fake.set_agent_security_mode = lambda aid, mode: calls.append(("set", aid, mode)) or {
        "agent_id": aid, "old_mode": "normal", "mode": mode
    }
    monkeypatch.setitem(sys.modules, "client.bianbu_security_client", fake)

    assert bncli.main(["agent", "mode", "agent.demo", "show"]) == 0
    assert json.loads(capsys.readouterr().out)["mode"] == "normal"
    assert bncli.main(["agent", "mode", "agent.demo", "yolo"]) == 0
    assert json.loads(capsys.readouterr().out)["mode"] == "yolo"
    assert calls == [("get", "agent.demo"), ("set", "agent.demo", "yolo")]


def test_security_xml_declares_mode_methods():
    xml = (Path(__file__).resolve().parents[2] / "data/io.bianbu.Security.xml").read_text()
    assert '<method name="GetAgentSecurityMode">' in xml
    assert '<method name="SetAgentSecurityMode">' in xml


def test_worker_dlp_calls_forward_security_agent_identity(monkeypatch):
    """Managed Worker DLP calls must authorize against the lease principal."""
    fake_uds = types.ModuleType("bianbu_security_uds")
    seen = []

    class Client:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def call(self, request):
            seen.append(request)
            return {"ok": True, "effective_policy": {}}

    fake_uds.UdsClient = Client
    monkeypatch.setitem(sys.modules, "bianbu_security_uds", fake_uds)
    fake_dbus = types.ModuleType("dbus")
    fake_dbus.String = str
    fake_dbus.Boolean = bool
    fake_dbus.Int32 = int
    fake_dbus.Int64 = int
    fake_dbus.Double = float
    fake_dbus.Dictionary = dict
    monkeypatch.setitem(sys.modules, "dbus", fake_dbus)
    monkeypatch.setenv("BIANBU_WORKER_MANAGED", "1")
    monkeypatch.setenv("BIANBU_WORKER_INSTANCE_ID", "instance-1")
    monkeypatch.setenv("BIANBU_WORKER_LEASE_ID", "lease-1")
    monkeypatch.setenv("BIANBU_WORKER_SECURITY_AGENT_ID", "com.bianbu.runtime")

    sys.modules.pop("client.bianbu_security_client", None)
    client = importlib.import_module("client.bianbu_security_client")
    client.dlp_scan("agent-business", "hello")
    client.dlp_policy("agent-business")

    assert [req["_worker_security_agent_id"] for req in seen] == [
        "com.bianbu.runtime", "com.bianbu.runtime"
    ]


def test_service_permission_group_decodes_the_dbus_json_payload(sec_root):
    """D-Bus 只能传字符串，服务层必须把客户端的 JSON 还原成原始值。

    客户端在 ``set_permission_group`` 里把数组/对象编码成 JSON 交给
    ``sss`` 签名的 ``SetPermissionGroup``；服务层若直接把字符串透传给
    ``permissions.normalise``，``read``/``write`` 会被判成"需要是路径数组"，
    控制台保存权限范围必然失败。
    """
    pytest.importorskip("dbus")
    from securityd.models import CallerContext
    from securityd.service import SecurityService

    service = object.__new__(SecurityService)
    caller = CallerContext(":1.42", 1000, 4242, "/usr/bin/admin-ui", "/admin.slice", "")
    service._require_admin = lambda sender: caller
    service._audit_admin = lambda *args, **kwargs: None
    seen = []
    service.engine = types.SimpleNamespace(
        set_permission_group=lambda aid, group, value: seen.append((aid, group, value))
        or {"agent_id": aid, "group": group, "value": value}
    )

    SecurityService.SetPermissionGroup(
        service, "agent.demo", "read", json.dumps(["/opt/data"]), sender=":1.42"
    )
    SecurityService.SetPermissionGroup(
        service, "agent.demo", "custom", json.dumps({"keep": True}), sender=":1.42"
    )

    assert seen == [
        ("agent.demo", "read", ["/opt/data"]),
        ("agent.demo", "custom", {"keep": True}),
    ]


def test_service_permission_group_rejects_a_non_json_payload(sec_root):
    pytest.importorskip("dbus")
    from securityd.models import CallerContext
    from securityd.service import SecurityService

    service = object.__new__(SecurityService)
    caller = CallerContext(":1.42", 1000, 4242, "/usr/bin/admin-ui", "/admin.slice", "")
    service._require_admin = lambda sender: caller
    service.engine = types.SimpleNamespace(
        set_permission_group=lambda *args: pytest.fail("must not reach the engine")
    )

    with pytest.raises(ValueError):
        SecurityService.SetPermissionGroup(
            service, "agent.demo", "read", "not json", sender=":1.42"
        )
