from __future__ import annotations

import sqlite3

import pytest

from securityd.network_learning import NetworkLearningStore


IDENTITY = {
    "agent_id": "com.example.agent",
    "instance_id": "worker-1",
    "lease_id": "lease-1",
    "pid": 1234,
}


def _event(event_id: str, observed_at: float, **values):
    event = {
        "event_id": event_id,
        "observed_at": observed_at,
        "event_type": "connect",
        "protocol": "tcp",
        "domain": "",
        "remote_ip": "203.0.113.8",
        "remote_port": 443,
        "dns_qtype": "",
        "outcome": "success",
        "errno": "",
        "backend": "strace",
        "policy_version": 4,
    }
    event.update(values)
    return event


def test_records_normalizes_and_aggregates_dns_ipv4_ipv6_and_failures(tmp_path):
    store = NetworkLearningStore(tmp_path / "learning.db", clock=lambda: 2000.0)
    try:
        dns = _event(
            "dns-1", 1000.0, event_type="dns_query", protocol="udp",
            domain="API.Example.COM.", remote_ip="192.0.2.53", remote_port=53,
            dns_qtype="AAAA",
        )
        ipv4 = _event("v4-1", 1001.0)
        ipv6 = _event("v6-1", 1002.0, remote_ip="2001:0db8::1", remote_port=8443)
        failed = _event(
            "failed-1", 1003.0, remote_ip="198.51.100.9", remote_port=9,
            outcome="failed", errno="ECONNREFUSED",
        )
        repeated = _event("v4-2", 1004.0)

        for event in (dns, ipv4, ipv6, failed, repeated):
            assert store.record(IDENTITY, event) is True
        assert store.record(IDENTITY, repeated) is False

        result = store.query(IDENTITY["agent_id"], limit=20, cursor=0)
        assert result["total"] == 4
        assert result["next_cursor"] is None
        assert [row["event_id"] for row in result["events"]] == [
            "v4-2", "failed-1", "v6-1", "dns-1",
        ]
        assert result["events"][0] == {
            "event_id": "v4-2",
            "event_type": "connect",
            "protocol": "tcp",
            "domain": "",
            "remote_ip": "203.0.113.8",
            "remote_port": 443,
            "dns_qtype": "",
            "outcome": "success",
            "errno": "",
            "backend": "strace",
            "policy_version": 4,
            "first_seen": 1001.0,
            "last_seen": 1004.0,
            "count": 2,
            "instance_id": "worker-1",
            "lease_id": "lease-1",
            "pid": 1234,
        }
        assert result["events"][2]["remote_ip"] == "2001:db8::1"
        assert result["events"][3]["domain"] == "api.example.com"
    finally:
        store.close()


def test_query_paginates_aggregated_rows_and_clear_is_agent_scoped(tmp_path):
    store = NetworkLearningStore(tmp_path / "learning.db", clock=lambda: 2000.0)
    try:
        for index in range(3):
            assert store.record(
                IDENTITY,
                _event(f"evt-{index}", 1000.0 + index,
                       remote_ip=f"203.0.113.{index + 1}"),
            )
        other = {**IDENTITY, "agent_id": "com.example.other"}
        assert store.record(other, _event("other", 1004.0))

        first = store.query(IDENTITY["agent_id"], limit=2, cursor=0)
        assert [row["remote_ip"] for row in first["events"]] == [
            "203.0.113.3", "203.0.113.2",
        ]
        assert first["next_cursor"] == 2
        second = store.query(IDENTITY["agent_id"], limit=2, cursor=2)
        assert [row["remote_ip"] for row in second["events"]] == ["203.0.113.1"]
        assert second["next_cursor"] is None

        assert store.clear(IDENTITY["agent_id"]) == 3
        assert store.query(IDENTITY["agent_id"], limit=10, cursor=0)["events"] == []
        assert store.query(other["agent_id"], limit=10, cursor=0)["total"] == 1
    finally:
        store.close()


@pytest.mark.parametrize(
    "identity,event,error",
    [
        ({**IDENTITY, "agent_id": ""}, _event("e1", 1.0), "identity"),
        ({**IDENTITY, "pid": 0}, _event("e1", 1.0), "identity"),
        (IDENTITY, _event("", 1.0), "event_id"),
        (IDENTITY, _event("e1", 0.0), "observed_at"),
        (IDENTITY, _event("e1", 1.0, event_type="http"), "event_type"),
        (IDENTITY, _event("e1", 1.0, protocol="icmp"), "protocol"),
        (IDENTITY, _event("e1", 1.0, remote_ip="bad"), "remote_ip"),
        (IDENTITY, _event("e1", 1.0, remote_port=65536), "remote_port"),
        (IDENTITY, _event("e1", 1.0, outcome="unknown"), "outcome"),
        (IDENTITY, _event("e1", 1.0, backend=""), "backend"),
        (
            IDENTITY,
            _event("e1", 1.0, event_type="dns_query", protocol="udp",
                   domain="", remote_ip="192.0.2.53", remote_port=53,
                   dns_qtype="A"),
            "domain",
        ),
    ],
)
def test_rejects_malformed_identity_and_event(tmp_path, identity, event, error):
    store = NetworkLearningStore(tmp_path / "learning.db", clock=lambda: 2000.0)
    try:
        with pytest.raises(ValueError, match=error):
            store.record(identity, event)
    finally:
        store.close()


def test_retention_and_per_agent_raw_event_cap_are_enforced(tmp_path):
    path = tmp_path / "learning.db"
    now = 1_000_000.0
    store = NetworkLearningStore(path, clock=lambda: now)
    try:
        assert store.record(IDENTITY, _event("expired", now - 7 * 86400 - 1))
        for index in range(5001):
            assert store.record(
                IDENTITY,
                _event(f"cap-{index}", now - 5000 + index,
                       remote_port=(index % 65535) + 1),
            )
        with sqlite3.connect(path) as conn:
            assert conn.execute(
                "SELECT COUNT(*) FROM network_learning_event WHERE agent_id=?",
                (IDENTITY["agent_id"],),
            ).fetchone()[0] == 5000
            assert conn.execute(
                "SELECT COUNT(*) FROM network_learning_event WHERE event_id='expired'"
            ).fetchone()[0] == 0
            assert conn.execute(
                "SELECT COUNT(*) FROM network_learning_event WHERE event_id='cap-0'"
            ).fetchone()[0] == 0
    finally:
        store.close()


def test_collector_status_distinguishes_active_degraded_inactive_and_missing(tmp_path):
    now = [1000.0]
    store = NetworkLearningStore(tmp_path / "learning.db", clock=lambda: now[0])
    try:
        assert store.status(IDENTITY["agent_id"], ["worker-1"])["state"] == "degraded"
        assert store.report_status(IDENTITY, "active", "") is True
        assert store.status(IDENTITY["agent_id"], ["worker-1"]) == {
            "agent_id": "com.example.agent",
            "state": "active",
            "reason": "",
            "active_instances": 1,
            "reported_instances": 1,
            "updated_at": 1000.0,
        }
        now[0] = 1001.0
        assert store.report_status(IDENTITY, "degraded", "observer exited") is True
        degraded = store.status(IDENTITY["agent_id"], ["worker-1"])
        assert degraded["state"] == "degraded"
        assert degraded["reason"] == "observer exited"
        with pytest.raises(ValueError, match="state"):
            store.report_status(IDENTITY, "broken", "")
        assert store.report_status(IDENTITY, "inactive", "stopped") is True
        assert store.status(IDENTITY["agent_id"], [])["state"] == "inactive"
    finally:
        store.close()
