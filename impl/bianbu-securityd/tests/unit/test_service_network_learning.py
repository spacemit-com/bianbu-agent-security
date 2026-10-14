from __future__ import annotations

import importlib
import json
from pathlib import Path
import sys
import time
import types
import xml.etree.ElementTree as ET

import pytest


IDENTITY = {
    "agent_id": "com.example.agent",
    "instance_id": "worker-1",
    "lease_id": "lease-1",
    "pid": 1234,
}
EVENT = {
    "event_id": "evt-1",
    "observed_at": time.time(),
    "event_type": "connect",
    "protocol": "tcp",
    "remote_ip": "203.0.113.8",
    "remote_port": 443,
    "outcome": "success",
    "errno": "",
    "backend": "strace",
    "policy_version": 4,
}


class _Runtime:
    def __init__(self, authorized=True):
        self.authorized = authorized
        self.calls = []

    def _actual_cgroup(self, pid):
        self.calls.append(("cgroup", pid))
        return "/user.slice/worker.scope"

    def authorize_worker(self, agent_id, **identity):
        self.calls.append(("authorize", agent_id, identity))
        return self.authorized

    def active_instances(self, agent_id):
        return [{"instance_id": "worker-1"}] if agent_id == IDENTITY["agent_id"] else []


class _LogicalWorkerRuntime(_Runtime):
    def worker_agent_id_for_lease(self, agent_id, instance_id, lease_id):
        assert agent_id == IDENTITY["agent_id"]
        assert instance_id == IDENTITY["instance_id"]
        assert lease_id == IDENTITY["lease_id"]
        return "agent-0fefac549b59"

    def active_instances_for_worker(self, agent_id):
        return [{"instance_id": "worker-1"}] if agent_id == "agent-0fefac549b59" else []


def test_engine_accepts_only_live_learning_worker_events(engine):
    from securityd.errors import PermissionDenied

    engine.registry.set_network_policy(IDENTITY["agent_id"], [], "learning")
    engine.runtime_engine = _Runtime()
    assert engine.record_network_learning_event(IDENTITY, EVENT) is True
    assert engine.get_network_learning_events(IDENTITY["agent_id"], 20, 0)["total"] == 1

    engine.runtime_engine = _Runtime(authorized=False)
    with pytest.raises(PermissionDenied, match="lease"):
        engine.record_network_learning_event(IDENTITY, {**EVENT, "event_id": "evt-2"})

    engine.runtime_engine = _Runtime()
    engine.registry.set_network_policy(IDENTITY["agent_id"], [], "allow_all")
    with pytest.raises(PermissionDenied, match="learning"):
        engine.record_network_learning_event(IDENTITY, {**EVENT, "event_id": "evt-3"})


def test_engine_collector_status_uses_live_learning_instances(engine):
    from securityd.errors import PermissionDenied

    engine.registry.set_network_policy(IDENTITY["agent_id"], [], "learning")
    engine.runtime_engine = _Runtime()
    assert engine.get_network_learning_status(IDENTITY["agent_id"])["state"] == "degraded"
    assert engine.report_network_learning_collector(IDENTITY, "active", "") is True
    assert engine.get_network_learning_status(IDENTITY["agent_id"])["state"] == "active"

    engine.runtime_engine = _Runtime(authorized=False)
    with pytest.raises(PermissionDenied, match="lease"):
        engine.report_network_learning_collector(IDENTITY, "degraded", "observer exited")


def test_engine_attributes_learning_events_to_logical_worker_agent(engine):
    logical_agent_id = "agent-0fefac549b59"
    engine.registry.set_network_policy(logical_agent_id, [], "learning")
    engine.runtime_engine = _LogicalWorkerRuntime()

    assert engine.record_network_learning_event(IDENTITY, EVENT) is True
    assert engine.report_network_learning_collector(IDENTITY, "active", "") is True

    assert engine.get_network_learning_events(logical_agent_id, 20, 0)["total"] == 1
    assert engine.get_network_learning_events(IDENTITY["agent_id"], 20, 0)["total"] == 0
    status = engine.get_network_learning_status(logical_agent_id)
    assert status["state"] == "active"
    assert status["active_instances"] == 1


def test_service_authenticates_runtime_writes_and_admin_reads(sec_root):
    pytest.importorskip("dbus")
    from securityd.service import SecurityService

    service = object.__new__(SecurityService)
    calls = []
    service._require_runtime = lambda sender: calls.append(("runtime", sender))
    service._require_admin = lambda sender: calls.append(("admin", sender))
    service.engine = types.SimpleNamespace(
        record_network_learning_event=lambda identity, event: calls.append(
            ("record", identity, event)) or True,
        report_network_learning_collector=lambda identity, state, reason: calls.append(
            ("report", identity, state, reason)) or True,
        get_network_learning_events=lambda aid, limit, cursor: {
            "agent_id": aid, "events": [{"remote_ip": "2001:db8::1"}],
            "total": 1, "next_cursor": None,
        },
        get_network_learning_status=lambda aid: {
            "agent_id": aid, "state": "active", "reason": "",
        },
        clear_network_learning_events=lambda aid: calls.append(("clear", aid)) or 3,
    )

    assert SecurityService.RecordNetworkLearningEvent(
        service, IDENTITY["agent_id"], IDENTITY["instance_id"],
        IDENTITY["lease_id"], IDENTITY["pid"], EVENT, sender=":1.10",
    ) is True
    assert SecurityService.ReportNetworkLearningCollector(
        service, IDENTITY["agent_id"], IDENTITY["instance_id"],
        IDENTITY["lease_id"], IDENTITY["pid"], "degraded", "observer exited",
        sender=":1.10",
    ) is True
    events = SecurityService.GetNetworkLearningEvents(
        service, IDENTITY["agent_id"], 20, 0, sender=":1.20")
    status = SecurityService.GetNetworkLearningStatus(
        service, IDENTITY["agent_id"], sender=":1.20")
    assert SecurityService.ClearNetworkLearningEvents(
        service, IDENTITY["agent_id"], sender=":1.20") is True

    assert json.loads(str(events["json"]))["events"][0]["remote_ip"] == "2001:db8::1"
    assert json.loads(str(status["json"]))["state"] == "active"
    assert calls[0] == ("runtime", ":1.10")
    assert calls[2] == ("runtime", ":1.10")
    assert calls[-1] == ("clear", IDENTITY["agent_id"])
    assert [entry for entry in calls if entry[0] == "admin"] == [
        ("admin", ":1.20"), ("admin", ":1.20"), ("admin", ":1.20"),
    ]


def test_client_round_trips_learning_contract(monkeypatch):
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
        def RecordNetworkLearningEvent(self, aid, instance, lease, pid, event, **kwargs):
            seen.append(("record", aid, instance, lease, pid, dict(event)))
            return True

        def ReportNetworkLearningCollector(self, aid, instance, lease, pid,
                                           state, reason, **kwargs):
            seen.append(("report", aid, instance, lease, pid, state, reason))
            return True

        def GetNetworkLearningEvents(self, aid, limit, cursor, **kwargs):
            seen.append(("events", aid, limit, cursor))
            return {"json": json.dumps({"agent_id": aid, "events": [EVENT],
                                         "total": 1, "next_cursor": None})}

        def GetNetworkLearningStatus(self, aid, **kwargs):
            seen.append(("status", aid))
            return {"json": json.dumps({"agent_id": aid, "state": "active"})}

        def ClearNetworkLearningEvents(self, aid, **kwargs):
            seen.append(("clear", aid))
            return True

    monkeypatch.setattr(client, "_get_proxy", lambda: Proxy())
    assert client.record_network_learning_event(**IDENTITY, event=EVENT)
    assert client.report_network_learning_collector(**IDENTITY, state="active", reason="")
    assert client.get_network_learning_events(IDENTITY["agent_id"], 20, 4)["total"] == 1
    assert client.get_network_learning_status(IDENTITY["agent_id"])["state"] == "active"
    assert client.clear_network_learning_events(IDENTITY["agent_id"])
    assert seen[0][:5] == ("record", "com.example.agent", "worker-1", "lease-1", 1234)
    assert seen[2] == ("events", "com.example.agent", 20, 4)


def test_security_xml_declares_network_learning_methods():
    xml = (Path(__file__).resolve().parents[2] / "data/io.bianbu.Security.xml").read_text()
    for name in (
        "RecordNetworkLearningEvent", "ReportNetworkLearningCollector",
        "GetNetworkLearningEvents", "GetNetworkLearningStatus",
        "ClearNetworkLearningEvents",
    ):
        assert f'<method name="{name}">' in xml


def test_system_bus_policy_allows_runtime_learning_writes_and_assets_match():
    root = Path(__file__).resolve().parents[2]
    data_policy = root / "data/io.bianbu.Security.conf"
    deploy_policy = root / "deploy/io.bianbu.Security.conf"
    def policy_semantics(path):
        return [
            (node.tag, tuple(sorted(node.attrib.items())))
            for node in ET.parse(path).iter()
        ]
    assert policy_semantics(data_policy) == policy_semantics(deploy_policy)
    tree = ET.parse(data_policy)
    runtime_policies = [
        policy for policy in tree.findall("policy")
        if policy.attrib.get("group") == "bianbu-security"
    ]
    allowed = {
        node.attrib.get("send_member")
        for policy in runtime_policies for node in policy.findall("allow")
    }
    assert "RecordNetworkLearningEvent" in allowed
    assert "ReportNetworkLearningCollector" in allowed
