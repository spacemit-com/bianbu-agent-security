#!/usr/bin/env python3
"""真实 securityd 重启时，未决 Confirm 必须拒绝、审计且旧 ID 不可复用。"""
from __future__ import annotations

import os
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def _start(env):
    return subprocess.Popen(
        [sys.executable, "-m", "securityd.service", "--session"], env=env,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)


def _stop(process):
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def _wait_iface(bus, timeout=8.0):
    import dbus

    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            obj = bus.get_object("io.bianbu.Security", "/io/bianbu/Security")
            obj.Introspect(dbus_interface="org.freedesktop.DBus.Introspectable")
            return dbus.Interface(obj, "io.bianbu.Security")
        except dbus.DBusException:
            time.sleep(0.05)
    return None


def _pump_until(context, predicate, timeout):
    deadline = time.time() + timeout
    while time.time() < deadline and not predicate():
        context.iteration(False)
        time.sleep(0.01)
    return predicate()


def main() -> int:
    import dbus
    import dbus.mainloop.glib
    from gi.repository import GLib

    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
    data_root = Path(tempfile.mkdtemp(prefix="bnsec_confirm_restart_"))
    env = dict(os.environ, PYTHONPATH=f"{ROOT}:{ROOT / 'client'}",
               BIANBU_SEC_ROOT=str(data_root), BIANBU_SEC_SESSION="1",
               BIANBU_CONFIRM_TIMEOUT="30", BIANBU_SECURITY_TEST_ADMIN="1")
    bus = dbus.SessionBus()
    context = GLib.MainContext.default()
    request_ids = []
    signal_seen = threading.Event()

    def on_confirm(_agent_id, _capability, _detail, request_id):
        request_ids.append(str(request_id))
        signal_seen.set()

    bus.add_signal_receiver(
        on_confirm, signal_name="ConfirmRequest",
        dbus_interface="io.bianbu.Security",
        path="/io/bianbu/Security")

    process = _start(env)
    try:
        iface = _wait_iface(bus)
        if iface is None or not bool(iface.BindAgent("com.test.confirm-restart")):
            return 1
        replies, errors = [], []
        iface.RequestConfirm(
            "com.test.confirm-restart", "write_file", "pending-before-restart",
            reply_handler=lambda value: replies.append(bool(value)),
            error_handler=lambda error: errors.append(str(error)))
        if not _pump_until(context, signal_seen.is_set, 5):
            return 2
        old_id = request_ids[0]

        _stop(process)
        if not _pump_until(context, lambda: bool(replies or errors), 5):
            return 3
        if any(replies):
            return 4  # 服务退出绝不能把未决请求当成批准

        process = _start(env)
        iface = _wait_iface(bus)
        if iface is None or not bool(iface.BindAgent("com.test.confirm-restart")):
            return 5
        try:
            iface.RespondConfirm(old_id, True)
            return 6
        except dbus.DBusException as exc:
            if "确认请求不存在" not in str(exc):
                return 7

        audit_db = next((data_root / "var/log/bianbu/audit").glob("[0-9][0-9][0-9][0-9][0-9][0-9].db"))
        conn = sqlite3.connect(audit_db)
        cancelled = conn.execute(
            "SELECT COUNT(*) FROM audit_record "
            "WHERE op_type='confirm_cancelled_shutdown' AND result LIKE ?",
            (f"%{old_id}%",)).fetchone()[0]
        approved = conn.execute(
            "SELECT COUNT(*) FROM audit_record "
            "WHERE op_type='confirm' AND result='confirm_approved' "
            "AND agent_id='com.test.confirm-restart'").fetchone()[0]
        conn.close()
        if cancelled != 1 or approved != 0:
            return 8
        print(f"CONFIRM_RESTART_E2E_PASS request_id={old_id}")
        return 0
    finally:
        if process.poll() is None:
            _stop(process)


if __name__ == "__main__":
    raise SystemExit(main())
