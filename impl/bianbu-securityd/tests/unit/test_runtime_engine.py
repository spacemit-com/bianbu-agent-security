"""security.runtime 引擎的启动证明和撤销测试。"""

from __future__ import annotations

import os

import pytest


def _cgroup(pid):
    for row in open(f"/proc/{pid}/cgroup", encoding="utf-8"):
        parts = row.rstrip().split(":", 2)
        if len(parts) == 3 and parts[2]:
            if parts[0] == "0":
                return parts[2]
    return "/"


class _Registry:
    def get_manifest_info(self, _agent):
        return {"version": "1.0", "status": "active"}

    def get_allowed_domains(self, _agent):
        return []

    def get_entrypoint(self, _agent):
        return ["/usr/bin/agent"]


class _Security:
    # 沙箱与否来自声明的安全设置；验证 sandbox 的用例单独覆盖原因列表。
    boundary_reasons: list[str] = []

    def __init__(self):
        self.registry = _Registry()
        self.audit = []

    def get_capabilities(self, _agent):
        return [{"risk_level": "L1"}]

    def execution_mode_for(self, _agent):
        return {"mode": "sandbox" if self.boundary_reasons else "host",
                "reasons": list(self.boundary_reasons), "trusted": True}

    def build_sandbox_policy(self, _agent):
        return "/run/seccomp", "/run/net.rules"

    def audit_log(self, *args, **kwargs):
        self.audit.append(args)
        return len(self.audit)


def test_commit_requires_matching_backend_and_sandbox_proof(tmp_path, monkeypatch):
    monkeypatch.setenv("BIANBU_SEC_ROOT", str(tmp_path / "root"))
    import importlib
    import securityd.config as config
    import runtime.engine as runtime_engine
    importlib.reload(config)
    importlib.reload(runtime_engine)

    from runtime.engine import RuntimeEngineError, SecurityRuntimeEngine

    namespace_calls = []
    def fake_namespaces(pid):
        namespace_calls.append(pid)
        value = "target" if len(namespace_calls) % 2 == 1 else "securityd"
        return {name: f"{name}:[{value}]" for name in
                ("user", "pid", "mnt", "ipc", "uts", "net")}
    monkeypatch.setattr(SecurityRuntimeEngine, "_namespace_ids", staticmethod(fake_namespaces))

    security = _Security()
    security.boundary_reasons = ["可读范围"]
    engine = SecurityRuntimeEngine(security)
    try:
        prepared = engine.prepare_start(
            "com.example.agent", {"requested_mode": "sandbox"})
        pid = os.getpid()
        cgroup = _cgroup(pid)
        base = {"backend": prepared["backend"], "pid": pid}
        with pytest.raises(RuntimeEngineError, match="sandboxed"):
            engine.commit_start(prepared["lease_id"], "instance", pid, cgroup, base)

        base.update({"sandboxed": True, "container_id": "ctr-1",
                     "_kernel_audit": {"cgroup_id": -1, "boot_id": "forged"}})
        committed = engine.commit_start(prepared["lease_id"], "instance", pid,
                                        cgroup, base)
        assert committed["state"] == "committed"
        state = engine.state("com.example.agent")["instance"]
        assert state["pid"] == pid
        import json
        from pathlib import Path
        identity = json.loads(state["audit_identity_json"])
        assert identity["cgroup_id"] == (Path('/sys/fs/cgroup') / cgroup.lstrip('/')).stat().st_ino
        assert identity["boot_id"] == Path('/proc/sys/kernel/random/boot_id').read_text().strip()
        assert identity["started_ns"] > 0
    finally:
        engine.close()


def test_revoke_marks_live_leases_and_instances(tmp_path, monkeypatch):
    monkeypatch.setenv("BIANBU_SEC_ROOT", str(tmp_path / "root"))
    import importlib
    import securityd.config as config
    import runtime.engine as runtime_engine
    importlib.reload(config)
    importlib.reload(runtime_engine)
    from runtime.engine import SecurityRuntimeEngine

    security = _Security()
    engine = SecurityRuntimeEngine(security)
    try:
        prepared = engine.prepare_start(
            "com.example.agent", {"requested_mode": "host"})
        pid = os.getpid()
        cgroup = _cgroup(pid)
        engine.commit_start(prepared["lease_id"], "instance", pid, cgroup, {
            "backend": prepared["backend"], "pid": pid,
        })
        assert engine.revoke_agent("com.example.agent", "operator revoke")
        state = engine.state("com.example.agent")
        assert state["lease"]["state"] == "revoked"
        assert state["instance"]["state"] == "revoked"
    finally:
        engine.close()


def test_active_instances_filters_missing_and_cgroup_mismatched_processes(
    tmp_path, monkeypatch,
):
    from runtime.engine import SecurityRuntimeEngine

    monkeypatch.setattr("securityd.config.ETC_DIR", tmp_path)
    engine = SecurityRuntimeEngine(type("Security", (), {})())
    rows = [
        {"instance_id": "live", "pid": 101, "cgroup_path": "/cg/live"},
        {"instance_id": "missing", "pid": 102, "cgroup_path": "/cg/missing"},
        {"instance_id": "reused", "pid": 103, "cgroup_path": "/cg/old"},
    ]
    monkeypatch.setattr(engine.leases, "active_instances", lambda agent_id: rows)

    def actual(pid):
        if pid == 102:
            raise OSError("gone")
        return {101: "/cg/live", 103: "/cg/new"}[pid]

    monkeypatch.setattr(engine, "_actual_cgroup", actual)
    try:
        assert engine.active_instances("com.example") == [rows[0]]
    finally:
        engine.close()


def test_commit_audit_failure_does_not_leave_committed_instance(tmp_path, monkeypatch):
    monkeypatch.setenv("BIANBU_SEC_ROOT", str(tmp_path / "root"))
    import importlib
    import securityd.config as config
    import runtime.engine as runtime_engine
    importlib.reload(config)
    importlib.reload(runtime_engine)
    from runtime.engine import RuntimeEngineError, SecurityRuntimeEngine

    security = _Security()
    calls = {"count": 0}
    def fail_commit_audit(*args, **kwargs):
        calls["count"] += 1
        if calls["count"] > 1:
            raise RuntimeError("audit down")
        return calls["count"]
    security.audit_log = fail_commit_audit
    engine = SecurityRuntimeEngine(security)
    try:
        prepared = engine.prepare_start(
            "com.example.agent", {"requested_mode": "host"})
        pid = os.getpid()
        with pytest.raises(RuntimeEngineError, match="审计失败"):
            engine.commit_start(prepared["lease_id"], "instance", pid,
                                _cgroup(pid), {
                                    "backend": prepared["backend"], "pid": pid,
                                })
        state = engine.state("com.example.agent")
        assert state["lease"]["state"] == "failed"
        assert state["instance"]["state"] == "failed"
    finally:
        engine.close()


def test_authorize_worker_accepts_short_lived_child_in_committed_cgroup(tmp_path, monkeypatch):
    monkeypatch.setenv("BIANBU_SEC_ROOT", str(tmp_path / "root"))
    import importlib
    import securityd.config as config
    import runtime.engine as runtime_engine
    importlib.reload(config)
    importlib.reload(runtime_engine)
    from runtime.engine import SecurityRuntimeEngine

    security = _Security()
    engine = SecurityRuntimeEngine(security)
    try:
        prepared = engine.prepare_start("com.example.agent", {"requested_mode": "host"})
        worker_pid = os.getpid()
        cgroup = _cgroup(worker_pid)
        engine.commit_start(prepared["lease_id"], "instance", worker_pid, cgroup,
                            {"backend": prepared["backend"], "pid": worker_pid})
        child_pid = worker_pid + 100000
        monkeypatch.setattr(SecurityRuntimeEngine, "_actual_cgroup",
                            staticmethod(lambda pid: cgroup if pid == child_pid else (_ for _ in ()).throw(OSError())))
        assert engine.authorize_worker("com.example.agent", pid=child_pid,
                                      cgroup_path=cgroup, instance_id="instance",
                                      lease_id=prepared["lease_id"])
    finally:
        engine.close()


def test_engine_stop_instance_and_startup_reap_audit(tmp_path, monkeypatch):
    monkeypatch.setenv("BIANBU_SEC_ROOT", str(tmp_path / "root"))
    import importlib
    import securityd.config as config
    import runtime.engine as runtime_engine
    importlib.reload(config)
    importlib.reload(runtime_engine)
    from runtime.engine import RuntimeEngineError, SecurityRuntimeEngine

    security = _Security()
    engine = SecurityRuntimeEngine(security)
    try:
        live = engine.leases.issue(agent_id="com.example.agent", policy={"sandbox_required": False},
                                   requested_mode="host", effective_mode="host",
                                   backend="host-process", sandbox_required=False)
        dead = engine.leases.issue(agent_id="com.example.agent", policy={"sandbox_required": False},
                                   requested_mode="host", effective_mode="host",
                                   backend="host-process", sandbox_required=False)
        engine.leases.commit(live["lease_id"], instance_id="i-live", pid=os.getpid(),
                             cgroup_path=_cgroup(os.getpid()), attestation={})
        engine.leases.commit(dead["lease_id"], instance_id="i-dead", pid=2**22 - 1,
                             cgroup_path="/nonexistent", attestation={})
        lost = engine.reap_dead_instances()
        assert [r["instance_id"] for r in lost] == ["i-dead"]
        assert any(a[1] == "runtime_instance_lost" for a in security.audit)
        with pytest.raises(RuntimeEngineError):
            engine.stop_instance(dead["lease_id"], "i-live", "mismatch")
        result = engine.stop_instance(live["lease_id"], "i-live", "requested")
        assert result["state"] == "stopped"
        assert any(a[1] == "runtime_instance_stop" for a in security.audit)
        assert engine.active_instances("com.example.agent") == []
    finally:
        engine.close()


def test_sandbox_policy_survives_wall_clock_step(tmp_path, monkeypatch):
    """开机校时前跳后，issued 租约的沙箱策略仍可读取（不再被判过期）。"""
    monkeypatch.setenv("BIANBU_SEC_ROOT", str(tmp_path / "root"))
    import importlib
    import securityd.config as config
    import runtime.engine as runtime_engine
    import runtime.lease as lease_module
    importlib.reload(config)
    importlib.reload(runtime_engine)
    from runtime.engine import SecurityRuntimeEngine

    real = lease_module.time

    class _Shifted:
        @staticmethod
        def time():
            return real.time() + 1281.5

        @staticmethod
        def monotonic():
            return real.monotonic()

        @staticmethod
        def monotonic_ns():
            return real.monotonic_ns()

    monkeypatch.setattr(lease_module, "time", _Shifted)

    security = _Security()
    security.boundary_reasons = ["可读范围"]
    engine = SecurityRuntimeEngine(security)
    try:
        prepared = engine.prepare_start(
            "com.example.agent", {"requested_mode": "sandbox"})
        policy = engine.sandbox_policy(prepared["lease_id"])
        assert policy["effective_mode"] == "sandbox"
    finally:
        engine.close()
