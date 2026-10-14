"""TC-INT-01/02：D-Bus 服务可达性 + 全链路（私有 session bus 内自启 securityd）。

需 dbus-python + PyGObject + dbus-daemon。缺任一则 skip。
用 dbus-run-session 起私有总线，避免污染用户会话。
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent

_have_dbus = shutil.which("dbus-run-session") is not None
try:
    import dbus  # noqa: F401
    import gi  # noqa: F401
    _have_py = True
except ImportError:
    _have_py = False

pytestmark = pytest.mark.skipif(
    not (_have_dbus and _have_py),
    reason="需 dbus-run-session + dbus-python + PyGObject")


def test_dbus_service_full_flow(tmp_path):
    """在私有 session bus 内启动 securityd，跑安装→校验→计量→审计。"""
    env = dict(os.environ)
    env["BIANBU_SEC_ROOT"] = str(tmp_path / "root")
    env["PYTHONPATH"] = str(ROOT)

    # driver：在同一 session bus 内先启服务线程，再跑客户端断言
    driver = ROOT / "tests" / "integration" / "_dbus_driver.py"
    r = subprocess.run(
        ["dbus-run-session", "--", sys.executable, str(driver)],
        env=env, capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, f"stdout={r.stdout}\nstderr={r.stderr}"
    assert "DBUS_E2E_PASS" in r.stdout, r.stdout


def test_reference_runtime_service_e2e(tmp_path):
    """参考 Runtime 进程在真实私有总线上消费超限事件并阻断调用。"""
    env = dict(os.environ)
    env["PYTHONPATH"] = str(ROOT)
    driver = ROOT / "tests" / "integration" / "runtime_service_e2e.py"
    r = subprocess.run(["dbus-run-session", "--", sys.executable, str(driver)],
                       env=env, capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, f"stdout={r.stdout}\nstderr={r.stderr}"
    assert "RUNTIME_SERVICE_E2E_PASS" in r.stdout


def test_securityd_production_uds_service_e2e(tmp_path):
    """正式 securityd 进程必须同时提供 UDS，并在重启后保持审计幂等。"""
    env = dict(os.environ)
    env["PYTHONPATH"] = str(ROOT)
    driver = ROOT / "tests" / "integration" / "uds_service_e2e.py"
    r = subprocess.run(["dbus-run-session", "--", sys.executable, str(driver)],
                       env=env, capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, f"stdout={r.stdout}\nstderr={r.stderr}"
    assert "UDS_SERVICE_E2E_PASS" in r.stdout


def test_pending_confirm_is_rejected_across_securityd_restart(tmp_path):
    """未决确认在真实服务重启时必须拒绝并留审计，旧 request_id 不可复用。"""
    env = dict(os.environ)
    env["PYTHONPATH"] = str(ROOT)
    driver = ROOT / "tests" / "integration" / "confirm_restart_e2e.py"
    r = subprocess.run(["dbus-run-session", "--", sys.executable, str(driver)],
                       env=env, capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, f"stdout={r.stdout}\nstderr={r.stderr}"
    assert "CONFIRM_RESTART_E2E_PASS" in r.stdout
