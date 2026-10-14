"""LaunchLease 一次性提交和过期语义测试。"""

from __future__ import annotations

import json
import time
import sqlite3

import pytest


def _policy():
    return {"sandbox_required": False}


def _shift_wall_clock(monkeypatch, seconds: float) -> None:
    """只平移 runtime.lease 看到的墙上时钟，单调时钟保持真实。"""
    import runtime.lease as lease_module

    real = lease_module.time

    class _Shifted:
        @staticmethod
        def time():
            return real.time() + seconds

        @staticmethod
        def monotonic():
            return real.monotonic()

        @staticmethod
        def monotonic_ns():
            return real.monotonic_ns()

    monkeypatch.setattr(lease_module, "time", _Shifted)


def _issue(store, agent_id="a"):
    return store.issue(agent_id=agent_id, policy=_policy(), requested_mode="host",
                       effective_mode="host", backend="host-process",
                       sandbox_required=False)


def test_lease_survives_wall_clock_step_forward(tmp_path, monkeypatch):
    """开机校时前跳 1281s 后，签发仅 1.4 秒的租约仍可提交。"""
    from runtime.lease import LaunchLeaseStore

    store = LaunchLeaseStore(tmp_path / "leases.db", ttl_seconds=30)
    try:
        lease = _issue(store)
        _shift_wall_clock(monkeypatch, 1281.5)
        committed = store.commit(lease["lease_id"], instance_id="i", pid=1,
                                 cgroup_path="/cg/a", attestation={})
        assert committed["state"] == "committed"
    finally:
        store.close()


def test_lease_expiry_follows_monotonic_deadline(tmp_path, monkeypatch):
    """墙上时钟回拨不延长租约：真实经过 TTL 后依然过期。"""
    from runtime.lease import LaunchLeaseStore, LeaseError

    store = LaunchLeaseStore(tmp_path / "leases.db", ttl_seconds=1)
    try:
        lease = _issue(store)
        _shift_wall_clock(monkeypatch, -3600)
        time.sleep(1.1)
        with pytest.raises(LeaseError):
            store.commit(lease["lease_id"], instance_id="i", pid=1,
                         cgroup_path="/cg/a", attestation={})
        assert store.get(lease["lease_id"])["state"] == "expired"
    finally:
        store.close()


def test_lease_issued_before_reboot_is_expired(tmp_path, monkeypatch):
    """上一次启动留下的 issued 租约不可提交：单调时钟跨启动没有可比性。"""
    import runtime.lease as lease_module
    from runtime.lease import LaunchLeaseStore, LeaseError

    store = LaunchLeaseStore(tmp_path / "leases.db", ttl_seconds=30)
    try:
        lease = _issue(store)
        monkeypatch.setattr(lease_module, "_boot_id", lambda: "another-boot")
        with pytest.raises(LeaseError):
            store.commit(lease["lease_id"], instance_id="i", pid=1,
                         cgroup_path="/cg/a", attestation={})
        assert store.get(lease["lease_id"])["state"] == "expired"
    finally:
        store.close()


def test_lease_without_monotonic_deadline_falls_back_to_wall_clock(tmp_path):
    """升级前签发、没有单调时钟的旧记录仍按墙上时钟 fail-closed。"""
    from runtime.lease import LaunchLeaseStore, LeaseError

    store = LaunchLeaseStore(tmp_path / "leases.db", ttl_seconds=30)
    try:
        lease = _issue(store)
        with store._lock:
            store._conn.execute(
                "UPDATE runtime_lease SET expires_monotonic=0,expires_at=? WHERE lease_id=?",
                (int(time.time()) - 1, lease["lease_id"]),
            )
            store._conn.commit()
        with pytest.raises(LeaseError):
            store.commit(lease["lease_id"], instance_id="i", pid=1,
                         cgroup_path="/cg/a", attestation={})
        assert store.get(lease["lease_id"])["state"] == "expired"
    finally:
        store.close()


def test_lease_commit_is_one_shot(tmp_path):
    from runtime.lease import LaunchLeaseStore, LeaseError

    store = LaunchLeaseStore(tmp_path / "leases.db", ttl_seconds=10)
    try:
        lease = store.issue(agent_id="a", policy=_policy(), requested_mode="host",
                            effective_mode="host", backend="host-process",
                            sandbox_required=False)
        first = store.commit(lease["lease_id"], instance_id="i1", pid=1,
                             cgroup_path="/cg/a", attestation={})
        assert first["state"] == "committed"
        with pytest.raises(LeaseError):
            store.commit(lease["lease_id"], instance_id="i2", pid=2,
                         cgroup_path="/cg/a", attestation={})
    finally:
        store.close()


def test_abort_prevents_commit_and_expiry_is_fail_closed(tmp_path):
    from runtime.lease import LaunchLeaseStore, LeaseError

    store = LaunchLeaseStore(tmp_path / "leases.db", ttl_seconds=1)
    try:
        lease = store.issue(agent_id="a", policy=_policy(), requested_mode="host",
                            effective_mode="host", backend="host-process",
                            sandbox_required=False)
        store.abort(lease["lease_id"], "backend failed")
        with pytest.raises(LeaseError):
            store.commit(lease["lease_id"], instance_id="i", pid=1,
                         cgroup_path="/cg/a", attestation={})

        expired = store.issue(agent_id="a", policy=_policy(), requested_mode="host",
                              effective_mode="host", backend="host-process",
                              sandbox_required=False)
        time.sleep(1.1)
        with pytest.raises(LeaseError):
            store.commit(expired["lease_id"], instance_id="i", pid=1,
                         cgroup_path="/cg/a", attestation={})
        assert store.get(expired["lease_id"])["state"] == "expired"
    finally:
        store.close()


def test_fail_commit_marks_lease_and_instance_terminal(tmp_path):
    from runtime.lease import LaunchLeaseStore

    store = LaunchLeaseStore(tmp_path / "leases.db", ttl_seconds=10)
    try:
        lease = store.issue(agent_id="a", policy=_policy(), requested_mode="host",
                            effective_mode="host", backend="host-process",
                            sandbox_required=False)
        store.commit(lease["lease_id"], instance_id="i", pid=1,
                     cgroup_path="/cg/a", attestation={})
        store.fail_commit(lease["lease_id"], "audit unavailable")
        assert store.get(lease["lease_id"])["state"] == "failed"
        assert store.instances("a")[0]["state"] == "failed"
    finally:
        store.close()


def test_active_instance_network_policy_update_is_recorded(tmp_path):
    from runtime.lease import LaunchLeaseStore

    store = LaunchLeaseStore(tmp_path / "leases.db", ttl_seconds=10)
    try:
        lease = store.issue(agent_id="a", policy=_policy(), requested_mode="host",
                            effective_mode="host", backend="host-process",
                            sandbox_required=False)
        store.commit(lease["lease_id"], instance_id="i", pid=1,
                     cgroup_path="/cg/a", attestation={"unit": "a.service"})
        rows = store.active_instances("a")
        assert rows[0]["instance_id"] == "i"
        assert rows[0]["network_policy_version"] == 0
        store.update_instance_network_policy(
            "i", {"mode": "whitelist", "domains": ["api.example.com"], "version": 3},
            state="applied", reason="systemd set-property",
            network_properties=["IPAddressDeny=any", "IPAddressAllow=192.0.2.1"])
        row = store.active_instances("a")[0]
        assert row["network_policy_version"] == 3
        assert row["network_apply_state"] == "applied"
        assert row["network_apply_reason"] == "systemd set-property"
        assert json.loads(row["attestation_json"])["network_properties"] == [
            "IPAddressDeny=any", "IPAddressAllow=192.0.2.1",
        ]
    finally:
        store.close()


def test_active_instances_can_be_selected_by_logical_worker_agent(tmp_path):
    from runtime.lease import LaunchLeaseStore

    store = LaunchLeaseStore(tmp_path / "leases.db", ttl_seconds=10)
    try:
        for worker_id, instance_id in (("agent-a", "i-a"), ("agent-b", "i-b")):
            lease = store.issue(
                agent_id="com.bianbu.runtime",
                policy={"worker_agent_id": worker_id},
                requested_mode="sandbox", effective_mode="sandbox",
                backend="bwrap", sandbox_required=True,
            )
            store.commit(
                lease["lease_id"], instance_id=instance_id, pid=1,
                cgroup_path="/cg/runtime", attestation={},
            )

        rows = store.active_instances_for_worker("agent-b")

        assert [row["instance_id"] for row in rows] == ["i-b"]
        assert rows[0]["agent_id"] == "com.bianbu.runtime"
    finally:
        store.close()


def test_incompatible_digest_schema_is_recreated(tmp_path):
    from runtime.lease import LaunchLeaseStore

    path = tmp_path / "leases.db"
    connection = sqlite3.connect(path)
    connection.executescript(
        "CREATE TABLE runtime_lease ("
        "lease_id TEXT PRIMARY KEY, package_digest TEXT NOT NULL);"
        "INSERT INTO runtime_lease VALUES ('old', 'sha256:old');"
        "CREATE TABLE runtime_instance (instance_id TEXT PRIMARY KEY);"
    )
    connection.close()

    store = LaunchLeaseStore(path)
    try:
        columns = {
            row[1] for row in store._conn.execute("PRAGMA table_info(runtime_lease)")
        }
        assert "package_digest" not in columns
        assert store.get("old") is None
    finally:
        store.close()


def test_stop_instance_converges_lease_and_instance_without_touching_siblings(tmp_path):
    """D-9：正常停止只收敛本实例；同 Agent 其它 running 实例不受影响。"""
    from runtime.lease import LaunchLeaseStore, LeaseError

    store = LaunchLeaseStore(tmp_path / "leases.db", ttl_seconds=10)
    try:
        a = store.issue(agent_id="a", policy=_policy(), requested_mode="host",
                        effective_mode="host", backend="host-process", sandbox_required=False)
        b = store.issue(agent_id="a", policy=_policy(), requested_mode="host",
                        effective_mode="host", backend="host-process", sandbox_required=False)
        store.commit(a["lease_id"], instance_id="i-a", pid=11, cgroup_path="/cg/a", attestation={})
        store.commit(b["lease_id"], instance_id="i-b", pid=12, cgroup_path="/cg/b", attestation={})
        with pytest.raises(LeaseError):
            store.stop_instance(b["lease_id"], "i-a", "mismatch")
        result = store.stop_instance(a["lease_id"], "i-a", "requested")
        assert result["state"] == "stopped" and result["changed"] is True
        rows = {r["instance_id"]: r for r in store.instances("a")}
        assert rows["i-a"]["state"] == "stopped" and int(rows["i-a"]["audit_ended_ns"]) > 0
        assert rows["i-b"]["state"] == "running"
        assert store.get(a["lease_id"])["state"] == "stopped"
        assert store.get(b["lease_id"])["state"] == "committed"
        # 幂等：再次 stop 不报错、不改变
        again = store.stop_instance(a["lease_id"], "i-a", "requested")
        assert again["changed"] is False and again["state"] == "stopped"
        assert [r["instance_id"] for r in store.active_instances("a")] == ["i-b"]
    finally:
        store.close()


def test_reap_dead_marks_only_gone_processes_as_lost(tmp_path):
    from runtime.lease import LaunchLeaseStore

    store = LaunchLeaseStore(tmp_path / "leases.db", ttl_seconds=10)
    try:
        for name, pid in (("i-live", 101), ("i-dead", 102)):
            lease = store.issue(agent_id="a", policy=_policy(), requested_mode="host",
                                effective_mode="host", backend="host-process", sandbox_required=False)
            store.commit(lease["lease_id"], instance_id=name, pid=pid, cgroup_path="/cg", attestation={})
        lost = store.reap_dead(lambda pid, cg: pid == 101)
        assert [r["instance_id"] for r in lost] == ["i-dead"]
        rows = {r["instance_id"]: r for r in store.instances("a")}
        assert rows["i-dead"]["state"] == "lost" and int(rows["i-dead"]["audit_ended_ns"]) > 0
        assert rows["i-live"]["state"] == "running"
        assert store.get(rows["i-dead"]["lease_id"])["state"] == "lost"
        assert store.reap_dead(lambda pid, cg: True) == []
    finally:
        store.close()
