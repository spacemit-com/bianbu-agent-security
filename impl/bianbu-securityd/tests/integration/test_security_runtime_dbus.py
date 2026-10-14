from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]

pytestmark = pytest.mark.skipif(
    shutil.which("dbus-run-session") is None or
    __import__("importlib.util").util.find_spec("dbus") is None,
    reason="需 dbus-run-session + dbus-python",
)


def test_security_runtime_lease_dbus_lifecycle():
    env = dict(os.environ)
    env["PYTHONPATH"] = str(ROOT)
    driver = ROOT / "tests" / "integration" / "runtime_security_dbus.py"
    result = subprocess.run(["dbus-run-session", "--", sys.executable, str(driver)],
                            env=env, capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, f"stdout={result.stdout}\nstderr={result.stderr}"
    assert "SECURITY_RUNTIME_DBUS_PASS" in result.stdout
