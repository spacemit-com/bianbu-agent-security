#!/usr/bin/env python3
"""security.runtime D-Bus lease lifecycle driver for a private session bus."""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import dbus

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT), str(ROOT / "client")]


def _cgroup(pid: int) -> str:
    rows = Path(f"/proc/{pid}/cgroup").read_text().splitlines()
    for row in rows:
        parts = row.split(":", 2)
        if len(parts) == 3 and parts[2].strip() and parts[0] == "0":
            return parts[2].strip()
    for row in rows:
        parts = row.split(":", 2)
        if len(parts) == 3 and parts[2].strip():
            return parts[2].strip()
    return "/"


def _wait(bus, proc):
    for _ in range(80):
        if proc.poll() is not None:
            raise RuntimeError(proc.stdout.read() if proc.stdout else "service exited")
        try:
            obj = bus.get_object("io.bianbu.Security", "/io/bianbu/Security/Runtime")
            obj.Introspect(dbus_interface="org.freedesktop.DBus.Introspectable")
            return obj
        except dbus.DBusException:
            time.sleep(0.1)
    raise RuntimeError("runtime object not ready")


def main() -> int:
    root = tempfile.mkdtemp(prefix="bnsec_runtime_dbus_")
    env = dict(os.environ)
    env.update({"PYTHONPATH": str(ROOT), "BIANBU_SEC_ROOT": root,
                "BIANBU_SECURITY_TEST_ADMIN": "1"})
    # The driver also writes the isolated fixture registry; keep its imports
    # on the same root as the child securityd process.
    os.environ.update({"PYTHONPATH": str(ROOT), "BIANBU_SEC_ROOT": root,
                       "BIANBU_SECURITY_TEST_ADMIN": "1"})
    proc = subprocess.Popen([sys.executable, "-m", "securityd.service", "--session"],
                            env=env, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True)
    try:
        bus = dbus.SessionBus()
        runtime = _wait(bus, proc)
        security = bus.get_object("io.bianbu.Security", "/io/bianbu/Security")
        aid = "com.bianbu.runtime-dbus-test"
        assert security.BindAgent(aid, dbus_interface="io.bianbu.Security")
        import importlib
        import securityd.config as config
        config = importlib.reload(config)
        from securityd.capability_registry import CapabilityRegistry
        registry = CapabilityRegistry(config.CAPABILITIES_DB)
        registry.record_manifest(aid, "1.0.0", "Runtime test", "test-signature",
                                 "[agent]\nid='runtime-test'\n"
                                 "[runtime]\n"
                                 "entrypoint=['/bin/true']\n", "now")
        registry.close()
        security.RegisterCapabilities(aid, [dbus.Dictionary({
            "capability": "file.read", "domain": "data", "risk_level": "L1",
            "confirm": "trusted", "granted": "1",
        }, signature="sv")], dbus_interface="io.bianbu.Security")
        # The driver itself is not sandboxed.  Request host mode; the package
        # is L1 and installed, so policy should allow it.
        context = dbus.Dictionary({"requested_mode": dbus.String("host")},
                                  signature="sv")
        prepared = dict(runtime.PrepareStart(
            aid, context, dbus_interface="io.bianbu.Security.Runtime"))
        assert str(prepared["effective_mode"]) == "host", prepared
        assert str(prepared["backend"]) == "host-process"
        lease = str(prepared["lease_id"])
        policy = dict(runtime.GetSandboxPolicy(lease,
                                               dbus_interface="io.bianbu.Security.Runtime"))
        attestation = dbus.Dictionary({
            "backend": dbus.String("host-process"),
        }, signature="sv")
        committed = dict(runtime.CommitStart(
            lease, "runtime-instance", dbus.Int64(0), "", attestation,
            dbus_interface="io.bianbu.Security.Runtime"))
        assert str(committed["state"]) == "committed"
        state = dict(runtime.GetRuntimeState(aid,
                                             dbus_interface="io.bianbu.Security.Runtime"))
        assert str(state["lease_state"]) == "committed"
        assert str(state["instance_id"]) == "runtime-instance"
        assert len(runtime.ListRuntimeInstances(aid,
                                                dbus_interface="io.bianbu.Security.Runtime")) == 1
        try:
            runtime.CommitStart(lease, "duplicate", dbus.Int64(0), "",
                                attestation, dbus_interface="io.bianbu.Security.Runtime")
        except dbus.DBusException:
            pass
        else:
            raise AssertionError("one-shot lease accepted duplicate CommitStart")
        assert bool(runtime.RevokeAgent(aid, "integration test revoke",
                                        dbus_interface="io.bianbu.Security.Runtime"))
        print("SECURITY_RUNTIME_DBUS_PASS")
        return 0
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


if __name__ == "__main__":
    raise SystemExit(main())
