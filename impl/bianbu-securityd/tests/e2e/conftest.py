"""e2e 会话级夹具：在会话总线上启动一个 securityd 供全部 e2e 用例复用。

需 BIANBU_E2E=1，且在 dbus-run-session 内运行（保证有会话总线）。
若总线上已有 securityd（外部启动）则直接复用、不重复起。
"""
from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent


@pytest.fixture(scope="session", autouse=True)
def securityd_service():
    if os.environ.get("BIANBU_E2E") != "1":
        yield None
        return
    os.environ.setdefault("BIANBU_SEC_SESSION", "1")
    sys.path.insert(0, str(ROOT))
    sys.path.insert(0, str(ROOT / "client"))
    import dbus

    # 已在总线上则复用
    try:
        obj = dbus.SessionBus().get_object("io.bianbu.Security", "/io/bianbu/Security")
        obj.Introspect(dbus_interface="org.freedesktop.DBus.Introspectable")
        yield None
        return
    except dbus.DBusException:
        pass

    env = dict(os.environ); env["PYTHONPATH"] = str(ROOT)
    proc = subprocess.Popen(
        [sys.executable, "-m", "securityd.service", "--session"],
        env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    for _ in range(80):
        try:
            obj = dbus.SessionBus().get_object("io.bianbu.Security", "/io/bianbu/Security")
            obj.Introspect(dbus_interface="org.freedesktop.DBus.Introspectable")
            break
        except dbus.DBusException:
            time.sleep(0.1)
    try:
        yield proc
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
