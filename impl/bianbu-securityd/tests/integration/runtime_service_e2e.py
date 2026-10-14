#!/usr/bin/env python3
"""参考 Runtime 进程的真实 D-Bus 生命周期验收（无 token 配额）。"""
from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def _wait(bus, name, path, timeout=8):
    import dbus
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            obj = bus.get_object(name, path)
            obj.Introspect(dbus_interface="org.freedesktop.DBus.Introspectable")
            return obj
        except dbus.DBusException:
            time.sleep(0.1)
    return None


def main() -> int:
    os.environ["BIANBU_SEC_SESSION"] = "1"
    os.environ["BIANBU_SECURITY_TEST_ADMIN"] = "1"
    root = Path(tempfile.mkdtemp(prefix="bnsec_runtime_service_"))
    env = dict(os.environ, PYTHONPATH=str(ROOT), BIANBU_SEC_ROOT=str(root / "security"))
    sec = subprocess.Popen([sys.executable, "-m", "securityd.service", "--session"], env=env,
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    rt = subprocess.Popen([sys.executable, "-m", "runtime.runtime_service", "--session",
                           "--state-dir", str(root / "runtime")], env=env,
                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    try:
        import dbus
        bus = dbus.SessionBus()
        security = _wait(bus, "io.bianbu.Security", "/io/bianbu/Security")
        runtime = _wait(bus, "io.bianbu.Runtime", "/io/bianbu/Runtime")
        if security is None or runtime is None:
            return 1
        aid = "com.bianbu.reference-runtime"
        if not bool(runtime.Register(aid, "reference", dbus.Dictionary(
                                      {"pid": dbus.Int64(os.getpid())}, signature="sv"),
                                      dbus_interface="io.bianbu.Runtime")):
            return 2
        if str(runtime.Start(aid, dbus_interface="io.bianbu.Runtime")) != "RUNNING":
            return 3
        first = next(dict(x) for x in runtime.List(dbus_interface="io.bianbu.Runtime"))
        first_session = str(first["session_id"])
        stats = dict(runtime.GetResourceStats(aid, dbus_interface="io.bianbu.Runtime"))
        if not bool(stats.get("resource_available")) or int(stats.get("pid", 0)) != os.getpid():
            return 3
        checkpoint = str(runtime.Checkpoint(aid, dbus_interface="io.bianbu.Runtime"))
        checkpoints = runtime.ListCheckpoints(aid, dbus_interface="io.bianbu.Runtime")
        if checkpoint not in {str(dict(x).get("checkpoint_id")) for x in checkpoints}:
            return 3
        if str(runtime.Restore(aid, checkpoint, dbus_interface="io.bianbu.Runtime")) != "RESTORED":
            return 3
        if str(runtime.Pause(aid, False, dbus_interface="io.bianbu.Runtime")) != "PAUSED":
            return 3
        if str(runtime.Stop(aid, dbus_interface="io.bianbu.Runtime")) != "STOPPED":
            return 3
        if str(runtime.Start(aid, dbus_interface="io.bianbu.Runtime")) != "RUNNING":
            return 3
        second = next(dict(x) for x in runtime.List(dbus_interface="io.bianbu.Runtime"))
        if str(second["session_id"]) == first_session:
            return 3
        # 真实 Runtime 进程重启：状态持久化后必须重新绑定 Security 并恢复服务。
        rt.terminate()
        try:
            rt.wait(timeout=5)
        except subprocess.TimeoutExpired:
            rt.kill()
        rt = subprocess.Popen([sys.executable, "-m", "runtime.runtime_service", "--session",
                               "--state-dir", str(root / "runtime")], env=env,
                              stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        runtime = _wait(bus, "io.bianbu.Runtime", "/io/bianbu/Runtime")
        if runtime is None:
            return 3
        restored = next(dict(x) for x in runtime.List(dbus_interface="io.bianbu.Runtime"))
        if str(restored.get("state")) != "RUNNING":
            return 3
        rows = [dict(x) for x in runtime.List(dbus_interface="io.bianbu.Runtime")]
        row = next(x for x in rows if str(x.get("agent_id")) == aid)
        if str(row.get("state")) != "RUNNING":
            return 3
        session = str(row.get("session_id"))
        allowed = bool(runtime.CanCall(aid, session, "model",
                                       dbus_interface="io.bianbu.Runtime"))
        print("RUNTIME_SERVICE_E2E_PASS" if allowed else "RUNTIME_SERVICE_E2E_FAIL")
        return 0 if allowed else 7
    finally:
        for p in (rt, sec):
            p.terminate()
            try:
                p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                p.kill()


if __name__ == "__main__":
    raise SystemExit(main())
