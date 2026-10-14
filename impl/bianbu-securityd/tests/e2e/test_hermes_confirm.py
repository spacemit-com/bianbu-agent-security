"""TC-E2E: hermes 接入·确认门禁全路径（批准/拒绝/L4 二次确认）。

驱动 hermes_confirm_demo（自起 securityd 子进程 + 模拟GUI 回传），
验证 §7.5 步骤 3/4/5 中经 RespondConfirm 打通的用户确认主路径。
需真实 D-Bus；在 dbus-run-session 内运行（设 BIANBU_E2E=1）。
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent

pytestmark = pytest.mark.skipif(
    os.environ.get("BIANBU_E2E") != "1",
    reason="需真实 D-Bus（设 BIANBU_E2E=1，在 dbus-run-session 内运行）")


def test_hermes_confirm_all_paths():
    env = dict(os.environ)
    env["PYTHONPATH"] = f"{ROOT}:{ROOT / 'client'}"
    env.setdefault("BIANBU_CONFIRM_TIMEOUT", "10")
    r = subprocess.run(
        [sys.executable, str(ROOT / "tests" / "integration" / "hermes_confirm_demo.py")],
        env=env, capture_output=True, text=True, timeout=120)
    assert "HERMES_CONFIRM_PASS" in r.stdout, r.stdout + r.stderr
