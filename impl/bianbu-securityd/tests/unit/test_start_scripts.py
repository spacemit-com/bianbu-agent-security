"""启动脚本的发布前置检查回归。"""

from __future__ import annotations

import os
import subprocess

import pytest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[4]
_TESTKIT_ROOT = Path(
    os.environ.get("BNSEC_TESTKIT", "")
).expanduser() if os.environ.get("BNSEC_TESTKIT", "").strip() else None
if _TESTKIT_ROOT is None:
    # The source checkout keeps testkit beside ``impl``; the Worker deployment
    # installs the same tree at its persistent runtime path.  Prefer the
    # checkout for local tests and use the deployed path when the checkout is
    # not present (the test file is copied independently to the Worker).
    _source_root = ROOT / "testkit"
    _deployed_root = Path("/home/bianbu/bnsec-testkit")
    _TESTKIT_ROOT = _source_root if _source_root.is_dir() else _deployed_root
SCRIPT = _TESTKIT_ROOT / "scripts" / "start-bianbu-agent.sh"
WEBUI_SCRIPT = _TESTKIT_ROOT / "scripts" / "start-securityd-webui.sh"



@pytest.fixture
def isolated_webui_script(tmp_path, monkeypatch):
    """Keep token tests independent of the installed WebUI and its secrets."""
    script = tmp_path / "start-securityd-webui.sh"
    script.write_text(WEBUI_SCRIPT.read_text().replace(
        "/etc/bianbu/webui.env", str(tmp_path / "system-webui.env")))
    commands = tmp_path / "bin"
    commands.mkdir()
    pgrep = commands / "pgrep"
    pgrep.write_text("#!/bin/sh\nexit 1\n")
    pgrep.chmod(0o755)
    monkeypatch.setenv("PATH", f"{commands}:{os.environ['PATH']}")
    monkeypatch.setitem(globals(), "WEBUI_SCRIPT", script)


def test_bianbu_agent_script_requires_memory_sdk_by_default(tmp_path: Path) -> None:
    ba_home = tmp_path / "personal-agent"
    (ba_home / ".bianbu-agent").mkdir(parents=True)
    (ba_home / ".bianbu-agent" / "config.yaml").write_text("agents: {}\n", encoding="utf-8")
    fake_uv = tmp_path / "uv"
    fake_uv.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    fake_uv.chmod(0o755)
    env = {
        **os.environ,
        "BA_HOME": str(ba_home),
        "BA_CONFIG": ".bianbu-agent/config.yaml",
        "BA_UV": str(fake_uv),
        "BA_LOG_DIR": str(tmp_path / "logs"),
        "BIANBU_SECURITY": "0",
        "BA_UV_NO_SYNC": "0",
    }
    result = subprocess.run(
        ["bash", str(SCRIPT), "--foreground"],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 1
    assert "未找到 Agent Memory SDK" in result.stderr


def test_bianbu_agent_script_waits_for_slow_bwrap_start(tmp_path: Path) -> None:
    ba_home = tmp_path / "personal-agent"
    (ba_home / ".bianbu-agent").mkdir(parents=True)
    (ba_home / ".bianbu-agent" / "config.yaml").write_text("agents: {}\n", encoding="utf-8")
    (ba_home / "run.sh").write_text(
        "#!/usr/bin/env bash\n"
        "sleep 7\n"
        "exit 0\n",
        encoding="utf-8",
    )
    (ba_home / "run.sh").chmod(0o755)
    fake_uv = tmp_path / "uv"
    fake_uv.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    fake_uv.chmod(0o755)
    env = {
        **os.environ,
        "BA_HOME": str(ba_home),
        "BA_CONFIG": ".bianbu-agent/config.yaml",
        "BA_UV": str(fake_uv),
        "BA_LOG_DIR": str(tmp_path / "logs"),
        "BIANBU_SECURITY": "0",
        "BA_UV_NO_SYNC": "1",
    }
    result = subprocess.run(
        ["bash", str(SCRIPT), "--foreground"],
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=20,
    )
    assert result.returncode == 0
    assert "未在 60s 内就绪" not in result.stderr


def test_securityd_webui_get_token_prefers_current_environment(tmp_path: Path, isolated_webui_script) -> None:
    env_file = tmp_path / "webui.env"
    env_file.write_text("BIANBU_WEBUI_TOKEN=file-token\n", encoding="utf-8")
    result = subprocess.run(
        ["bash", str(WEBUI_SCRIPT), "--get-token"],
        env={
            **os.environ,
            "BIANBU_WEBUI_TOKEN": "environment-token",
            "BIANBU_WEBUI_DEMO": "0",
            "BIANBU_SECURITY_WEBUI_ENV_FILE": str(env_file),
            "SECURITYD_HOME": str(tmp_path),
        },
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0
    assert result.stdout.strip() == "BIANBU_WEBUI_TOKEN=environment-token"


def test_securityd_webui_get_token_reads_env_file_without_sourcing(tmp_path: Path, isolated_webui_script) -> None:
    marker = tmp_path / "must-not-exist"
    env_file = tmp_path / "webui.env"
    env_file.write_text(
        f"touch {marker}\n"
        "BIANBU_WEBUI_TOKEN='file-token-123456789012345678901234'\n",
        encoding="utf-8",
    )
    env = {
        **os.environ,
        "BIANBU_SECURITY_WEBUI_ENV_FILE": str(env_file),
        "SECURITYD_HOME": str(tmp_path),
        "BIANBU_WEBUI_DEMO": "0",
    }
    env.pop("BIANBU_WEBUI_TOKEN", None)
    result = subprocess.run(
        ["bash", str(WEBUI_SCRIPT), "--get-token"],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0
    assert result.stdout.strip() == (
        "BIANBU_WEBUI_TOKEN=file-token-123456789012345678901234"
    )
    assert not marker.exists()


def test_securityd_webui_get_token_rejects_placeholder(tmp_path: Path, isolated_webui_script) -> None:
    env_file = tmp_path / "webui.env"
    env_file.write_text(
        "BIANBU_WEBUI_TOKEN=REPLACE_WITH_RANDOM_VALUE\n", encoding="utf-8"
    )
    env = {
        **os.environ,
        "BIANBU_SECURITY_WEBUI_ENV_FILE": str(env_file),
        "SECURITYD_HOME": str(tmp_path),
        "BIANBU_WEBUI_DEMO": "0",
    }
    env.pop("BIANBU_WEBUI_TOKEN", None)
    result = subprocess.run(
        ["bash", str(WEBUI_SCRIPT), "--get-token"],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 1
    assert "未找到 BIANBU_WEBUI_TOKEN" in result.stderr


def test_webui_start_scripts_accept_demo_auth_bypass() -> None:
    for name in ("run.sh", "run-system-bus.sh"):
        text = (ROOT / "impl/bianbu-securityd/webui" / name).read_text()
        assert "BIANBU_WEBUI_DEMO" in text
        assert "BIANBU_WEBUI_AUTH=0 或 BIANBU_WEBUI_DEMO=1" in text
        assert '"${BIANBU_WEBUI_DEMO:-0}" != "1"' in text


def test_testkit_get_token_reports_demo_mode_without_secret(tmp_path: Path, isolated_webui_script) -> None:
    result = subprocess.run(
        ["bash", str(WEBUI_SCRIPT), "--get-token"],
        env={**os.environ, "SECURITYD_HOME": str(tmp_path),
             "BIANBU_WEBUI_DEMO": "1", "BIANBU_SECURITY_WEBUI_ENV_FILE": str(tmp_path / "missing")},
        capture_output=True, text=True, check=False,
    )
    assert result.returncode == 0
    assert "不需要 token" in result.stdout


def test_get_token_prefers_running_process_over_demo_default(tmp_path: Path) -> None:
    source = WEBUI_SCRIPT.read_text()
    # Keep this a source-level regression assertion: process inspection must
    # precede the demo shortcut, otherwise a product process token is hidden.
    assert source.index("for pid in $(webui_pids)") < source.index(
        'BIANBU_WEBUI_AUTH=0（开发/demo 模式；不需要 token）')


def test_testkit_webui_launchers_default_to_demo_mode() -> None:
    for name in ("start-sec-webui.sh", "start-securityd-webui.sh"):
        text = (ROOT / "testkit/scripts" / name).read_text()
        assert '"${BIANBU_WEBUI_DEMO:=1}"' in text
        assert "export BIANBU_WEBUI_DEMO" in text
