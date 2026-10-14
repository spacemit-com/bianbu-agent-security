#!/usr/bin/env python3
"""正式 securityd.service 的 D-Bus 绑定 + UDS DLP/审计 + 重启复放验收。"""
from __future__ import annotations

import os
import sqlite3
import subprocess
import sys
import tempfile
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def _start(env):
    return subprocess.Popen(
        [sys.executable, "-m", "securityd.service", "--session"], env=env,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)


def _wait(bus, socket_path: Path, timeout: float = 8.0):
    import dbus
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            obj = bus.get_object("io.bianbu.Security", "/io/bianbu/Security")
            obj.Introspect(dbus_interface="org.freedesktop.DBus.Introspectable")
            if socket_path.is_socket():
                return dbus.Interface(obj, "io.bianbu.Security")
        except (dbus.DBusException, OSError):
            pass
        time.sleep(0.05)
    return None


def _stop(process):
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def main() -> int:
    import dbus

    data_root = Path(tempfile.mkdtemp(prefix="bnsec_uds_service_"))
    env = dict(os.environ, PYTHONPATH=f"{ROOT}:{ROOT / 'client'}",
               BIANBU_SEC_ROOT=str(data_root), BIANBU_SEC_SESSION="1",
               BIANBU_SECURITY_TEST_ADMIN="1")
    socket_path = data_root / "run/bianbu/securityd.sock"
    bus = dbus.SessionBus()
    process = _start(env)
    try:
        iface = _wait(bus, socket_path)
        if iface is None:
            return 1
        agent_id = "com.bianbu.uds-service-e2e"
        if not bool(iface.BindAgent(agent_id)):
            return 2

        sys.path.insert(0, str(ROOT / "client"))
        from bianbu_security_uds import UdsClient
        client = UdsClient(socket_path=socket_path, timeout=5.0)
        scan = client.call({
            "op": "dlp.scan", "agent_id": agent_id,
            "session_id": "session-e2e", "run_id": "run-e2e",
            "text": "手机号 13812345678",
        })
        if not scan.get("ok") or "13812345678" in scan.get("masked_text", ""):
            return 3
        request = {
            "op": "audit.batch", "agent_id": agent_id,
            "session_id": "session-e2e", "run_id": "run-e2e",
            "_request_id": "persistent-e2e-request",
            "entries": [{"op_type": "tool_result", "target": "weather",
                         "result": "allow", "payload": "full payload"}],
        }
        first = client.call(request)
        client.close()
        if not first.get("ok"):
            return 4
        first_seq = int(first["audit_seq"])

        _stop(process)
        process = _start(env)
        iface = _wait(bus, socket_path)
        if iface is None or not bool(iface.BindAgent(agent_id)):
            return 5
        client = UdsClient(socket_path=socket_path, timeout=5.0)
        replay = client.call(request)
        client.close()
        if int(replay.get("audit_seq", -1)) != first_seq:
            return 6

        audit_db = next((data_root / "var/log/bianbu/audit").glob("[0-9][0-9][0-9][0-9][0-9][0-9].db"))
        conn = sqlite3.connect(audit_db)
        request_rows = conn.execute(
            "SELECT COUNT(*) FROM audit_request WHERE request_id=?",
            (f"uds:{agent_id}:persistent-e2e-request",)).fetchone()[0]
        record_rows = conn.execute(
            "SELECT COUNT(*) FROM audit_record WHERE seq=?", (first_seq,)).fetchone()[0]
        conn.close()
        if request_rows != 1 or record_rows != 1:
            return 7
        print(f"UDS_SERVICE_E2E_PASS audit_seq={first_seq}")
        return 0
    finally:
        if process.poll() is None:
            _stop(process)


if __name__ == "__main__":
    raise SystemExit(main())
