from __future__ import annotations

import os
import sys
import threading
from collections import OrderedDict
from types import SimpleNamespace

import pytest


def _caller(uid, exe="/usr/bin/agent", cgroup="0::/agent", session="s"):
    from securityd.models import CallerContext
    return CallerContext(":1.1", uid, 123, exe, cgroup, session)


def test_binding_requires_all_available_identity_attributes(sec_root):
    from securityd.capability_registry import CapabilityRegistry
    r = CapabilityRegistry()
    r.bind_agent("com.a", _caller(1000), "now")
    assert r.caller_matches("com.a", _caller(1000))
    assert not r.caller_matches("com.a", _caller(1001))
    assert not r.caller_matches("com.a", _caller(1000, cgroup="0::/other"))
    assert r.caller_matches("com.a", _caller(1000, session="other"))
    assert not r.caller_matches("com.a", _caller(1000, session="other"), require_session=True)
    assert r.caller_matches("com.a", _caller(1000), require_session=True)
    r.close()


def test_registry_reset_binding_is_idempotent(sec_root):
    from securityd.capability_registry import CapabilityRegistry

    registry = CapabilityRegistry()
    registry.bind_agent("com.reset", _caller(1000), "now")
    assert registry.get_binding("com.reset") is not None
    assert registry.reset_binding("com.reset") is True
    assert registry.get_binding("com.reset") is None
    assert registry.reset_binding("com.reset") is False
    registry.close()


def test_caller_identity_prefers_kernel_executable_over_hidden_argv(monkeypatch):
    from securityd import caller_identity

    class _Path:
        def __init__(self, value):
            self.value = value

        def read_bytes(self):
            return b"/home/hidden/venv/bin/python3\0agent\0"

        def read_text(self):
            return "0::/user.slice/user-1000.slice"

    monkeypatch.setattr(caller_identity, "Path", _Path)
    monkeypatch.setattr(caller_identity.os, "readlink",
                        lambda path: "/usr/bin/python3.14" if path.endswith("/exe") else "")
    monkeypatch.setattr(caller_identity.os.path, "realpath",
                        lambda path: "/usr/bin/python3.14" if path.endswith("/exe") else path)

    caller = caller_identity.caller_from_process(1000, 123, sender="x")
    assert caller.executable == "/usr/bin/python3.14"


def test_service_caches_only_immutable_bus_credentials(monkeypatch, sec_root):
    """缓存 UID/PID，但每次重读 /proc 身份，避免同 PID execve 绕过绑定。"""
    from securityd import service as service_mod
    from securityd.service import SecurityService

    class Bus:
        uid_calls = 0
        pid_calls = 0

        def get_unix_user(self, sender):
            self.uid_calls += 1
            return 1000

        def call_blocking(self, *args):
            self.pid_calls += 1
            return 4321

    bus = Bus()
    proc_reads = []

    def read_process(uid, pid, *, sender, session_id="", include_groups=True):
        proc_reads.append((uid, pid, sender, session_id, include_groups))
        return _caller(uid, exe=f"/opt/agent-v{len(proc_reads)}", session=session_id)

    monkeypatch.setattr(service_mod, "caller_from_process", read_process)
    svc = SecurityService.__new__(SecurityService)
    svc.bus = bus
    svc._sender_credential_cache = OrderedDict()
    svc._sender_credential_lock = threading.Lock()

    first = svc._caller(":1.20", "session-1")
    second = svc._caller(":1.20", "session-2")
    assert bus.uid_calls == bus.pid_calls == 1
    assert len(proc_reads) == 2
    assert first.executable != second.executable
    assert proc_reads[-1][-2:] == ("session-2", False)

    svc._name_owner_changed(":1.20", ":1.20", "")
    svc._caller(":1.20", "session-3")
    assert bus.uid_calls == bus.pid_calls == 2

    svc._MAX_SENDER_CREDENTIALS = 2
    svc._caller(":1.21", "session-4")
    svc._caller(":1.22", "session-5")
    assert list(svc._sender_credential_cache) == [":1.21", ":1.22"]


def test_require_agent_reuses_loaded_binding(sec_root):
    from securityd.service import SecurityService

    caller = _caller(1000)
    binding = {"uid": 1000, "executable": caller.executable,
               "cgroup": caller.cgroup, "session_id": caller.session_id}
    loaded = []
    checked = []
    svc = SecurityService.__new__(SecurityService)
    svc._caller = lambda sender, session_id="": caller
    svc.engine = SimpleNamespace(
        registry=SimpleNamespace(
            get_binding=lambda aid: loaded.append(aid) or binding),
        caller_allowed=lambda aid, actual, *, binding=None: checked.append(
            (aid, actual, binding)) or True,
    )

    assert svc._require_agent("com.a", ":1.1") is caller
    assert loaded == ["com.a"]
    assert checked == [("com.a", caller, binding)]


def test_binding_ignores_volatile_login_session_number(sec_root):
    from securityd.capability_registry import CapabilityRegistry
    r = CapabilityRegistry()
    old = "0::/user.slice/user-1000.slice/session-1077.scope"
    new = "0::/user.slice/user-1000.slice/session-2048.scope"
    r.bind_agent("com.session", _caller(1000, cgroup=old), "now")
    assert r.caller_matches("com.session", _caller(1000, cgroup=new))
    r.close()


def test_legacy_system_python_binding_migrates_only_to_specific_venv_path(
    sec_root, tmp_path,
):
    from securityd.capability_registry import CapabilityRegistry
    venv_python = tmp_path / "pa-venv" / "bin" / "python3"
    venv_python.parent.mkdir(parents=True)
    venv_python.symlink_to(sys.executable)
    system_python = os.path.realpath(sys.executable)
    cgroup = "0::/user.slice/user-1000.slice/session-1.scope"

    r = CapabilityRegistry()
    r.bind_agent("com.legacy", _caller(1000, exe=system_python, cgroup=cgroup), "old")
    migrated = _caller(1000, exe=str(venv_python),
                       cgroup="0::/user.slice/user-1000.slice/session-2.scope")
    assert r.caller_matches("com.legacy", migrated)
    r.bind_agent("com.legacy", migrated, "new")
    assert not r.caller_matches(
        "com.legacy", _caller(1000, exe=system_python,
                               cgroup="0::/user.slice/user-1000.slice/session-3.scope"))
    r.close()


def test_management_reads_allow_admin_without_agent_impersonation(sec_root):
    from securityd.service import SecurityService

    svc = SecurityService.__new__(SecurityService)
    admin = _caller(1000, exe="/usr/bin/security-console")
    svc._caller = lambda sender: admin
    svc._is_admin = lambda caller: caller is admin
    svc._require_agent = lambda agent_id, sender: (_ for _ in ()).throw(
        AssertionError("管理员读取不应冒充 Agent"))

    assert svc._require_agent_or_admin("com.a", ":1.9") is admin


def test_runtime_identity_accepts_security_primary_group(monkeypatch, sec_root):
    from securityd import service as service_mod
    from securityd.service import SecurityService

    runtime = _caller(1000, exe="/opt/runtime/bin/python")
    svc = SecurityService.__new__(SecurityService)
    svc._caller = lambda sender: runtime
    status = "Uid:\t1000\t1000\t1000\t1000\nGid:\t1001\t1001\t1001\t1001\nGroups:\t4 24 1000\n"

    class _Path:
        def __init__(self, value):
            self.value = value

        def read_text(self):
            return status

    monkeypatch.setattr(service_mod, "Path", _Path)
    monkeypatch.setattr(
        service_mod.grp, "getgrnam",
        lambda name: SimpleNamespace(gr_gid={
            "bianbu-security": 1001,
            "bianbu-admin": 1002,
        }[name]),
    )

    assert svc._require_runtime(":1.50") is runtime


def test_admin_rebinds_stale_runtime_identity_with_audit(sec_root):
    from securityd.service import SecurityService

    svc = SecurityService.__new__(SecurityService)
    admin = _caller(1000, exe="/opt/new-runtime/bin/python")
    events = []
    svc.engine = SimpleNamespace(
        registry=SimpleNamespace(get_binding=lambda aid: {
            "uid": 1000, "executable": "/opt/old-runtime/bin/python",
            "cgroup": "0::/old.scope",
        }),
        caller_allowed=lambda aid, caller: False,
        bind_agent=lambda aid, caller: events.append(("bind", aid, caller)) or True,
    )
    svc._is_admin = lambda caller: caller is admin
    svc._audit_admin = lambda caller, operation, target: events.append(
        ("audit", operation, target))

    assert svc._bind_agent_identity("com.a", admin) is True
    assert events[0] == ("bind", "com.a", admin)
    assert events[1][0:2] == ("audit", "bind_agent")


def test_non_admin_runtime_cannot_replace_other_binding(sec_root):
    from securityd.service import AccessDenied, SecurityService

    svc = SecurityService.__new__(SecurityService)
    runtime = _caller(1000, exe="/opt/other-runtime/bin/python")
    svc.engine = SimpleNamespace(
        registry=SimpleNamespace(get_binding=lambda aid: {
            "uid": 1000, "executable": "/opt/original-runtime/bin/python",
            "cgroup": "0::/runtime.scope",
        }),
        caller_allowed=lambda aid, caller: False,
    )
    svc._is_admin = lambda caller: False

    with pytest.raises(AccessDenied):
        svc._bind_agent_identity("com.a", runtime)


def test_reset_agent_binding_is_idempotent_and_audited(sec_root):
    from securityd.service import SecurityService

    admin = _caller(0, exe="/usr/bin/dpkg")
    events = []
    registry = SimpleNamespace(
        get_binding=lambda aid: {"uid": 1000, "executable": "/old/runtime",
                                 "cgroup": "/old.scope"},
        reset_binding=lambda aid: events.append(("reset", aid)) or True,
    )
    svc = SecurityService.__new__(SecurityService)
    svc.engine = SimpleNamespace(registry=registry)
    svc._require_admin = lambda sender: admin
    svc._audit_admin = lambda caller, operation, target, result="success": events.append(
        ("audit", operation, target, result))

    assert svc.ResetAgentBinding("com.a", "package-upgrade", sender=":1.1") is True
    assert events[0] == ("reset", "com.a")
    assert events[1][0:2] == ("audit", "reset_agent_binding")


def test_reset_agent_binding_requires_admin(sec_root):
    from securityd.service import AccessDenied, SecurityService

    svc = SecurityService.__new__(SecurityService)
    svc._require_admin = lambda sender: (_ for _ in ()).throw(AccessDenied("admin"))
    with pytest.raises(AccessDenied):
        svc.ResetAgentBinding("com.a", "test", sender=":1.1")
