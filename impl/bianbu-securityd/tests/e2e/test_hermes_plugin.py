"""TC-E2E: hermes 插件接入（pre/post_tool_call 判权·确认·审计全路径）。

驱动 hermes_plugin_demo（模拟 hermes 钩子分发 + 模拟GUI + 真实 securityd），
验证插件把工具调用接入 securityd 的调用级管控。需真实 D-Bus（BIANBU_E2E=1）。
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


def test_hermes_plugin_all_paths():
    env = dict(os.environ)
    env["PYTHONPATH"] = f"{ROOT}:{ROOT / 'client'}:{ROOT / 'hermes_plugin'}"
    env["BIANBU_SECURITYD_HOME"] = str(ROOT)
    env.setdefault("BIANBU_CONFIRM_TIMEOUT", "10")
    r = subprocess.run(
        [sys.executable, str(ROOT / "tests" / "integration" / "hermes_plugin_demo.py")],
        env=env, capture_output=True, text=True, timeout=120)
    assert "HERMES_PLUGIN_PASS" in r.stdout, r.stdout + r.stderr
