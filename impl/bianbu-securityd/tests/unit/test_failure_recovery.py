from __future__ import annotations

import os


def test_migration_corrupt_sqlite_fails_closed(tmp_path):
    import subprocess
    from pathlib import Path
    root = Path(__file__).resolve().parents[2]
    db = tmp_path / "corrupt.db"
    db.write_bytes(b"not sqlite")
    cp = subprocess.run(["python3", str(root / "deploy/migrate_db.py"), str(db)],
                        capture_output=True, text=True)
    assert cp.returncode == 1
    assert "DB_MIGRATE_FAIL" in cp.stdout


def test_audit_readonly_filesystem_startup_fails_closed(tmp_path):
    """真实 chmod 只读目录/DB；root 测试进程降权到 nobody 后再启动引擎。"""
    import pwd
    import subprocess
    import sys
    from pathlib import Path
    from securityd.audit_chain import AuditChainEngine

    root = Path(__file__).resolve().parents[2]
    db_dir = tmp_path / "readonly-audit"
    db_dir.mkdir()
    db = db_dir / "audit.db"
    engine = AuditChainEngine(db)
    engine.log("com.test", "seed", "target", "ok")
    engine.close()

    # nobody 需要能穿越 pytest 的临时父目录，但不能在目标目录创建 WAL/SHM。
    tmp_path.chmod(0o755)
    db.chmod(0o444)
    db_dir.chmod(0o555)
    code = (
        "from securityd.audit_chain import AuditChainEngine\n"
        "from securityd.errors import AuditFailure\n"
        f"path={str(db)!r}\n"
        "try:\n"
        "    engine=AuditChainEngine(path)\n"
        "except AuditFailure as exc:\n"
        "    print('READONLY_AUDIT_FAIL_CLOSED', exc)\n"
        "else:\n"
        "    engine.close()\n"
        "    raise SystemExit('readonly audit unexpectedly opened writable')\n"
    )
    preexec = None
    if os.geteuid() == 0:
        nobody = pwd.getpwnam("nobody")

        def drop_privileges():
            os.setgroups([])
            os.setgid(nobody.pw_gid)
            os.setuid(nobody.pw_uid)

        preexec = drop_privileges
    try:
        cp = subprocess.run(
            [sys.executable, "-c", code], cwd=root,
            env={**os.environ, "PYTHONPATH": str(root)},
            preexec_fn=preexec, capture_output=True, text=True, timeout=20)
        assert cp.returncode == 0, cp.stdout + cp.stderr
        assert "READONLY_AUDIT_FAIL_CLOSED" in cp.stdout
    finally:
        db_dir.chmod(0o755)
        db.chmod(0o644)


def test_release_gate_reports_missing_scanner_without_false_pass(tmp_path):
    import subprocess
    from pathlib import Path
    root = Path(__file__).resolve().parents[2]
    report = tmp_path / "cve.json"
    cp = subprocess.run(["python3", str(root / "deploy/dependency_audit.py"),
                         "--scanner", "definitely-not-installed", "--strict",
                         "--output", str(report)], capture_output=True, text=True)
    assert cp.returncode == 1
    assert "scanner_missing" in cp.stdout


def test_rollback_dry_run_is_non_destructive(tmp_path):
    import os
    import subprocess
    from pathlib import Path
    root = Path(__file__).resolve().parents[2]
    lib = tmp_path / "lib"
    prev = tmp_path / "previous"
    lib.mkdir(); prev.mkdir()
    (lib / "version").write_text("new")
    (prev / "version").write_text("old")
    env = {**os.environ, "BIANBU_SECURITY_LIB_DIR": str(lib),
           "BIANBU_SECURITY_BACKUP_DIR": str(prev)}
    cp = subprocess.run(["bash", str(root / "deploy/rollback.sh"), "--dry-run"],
                        env=env, capture_output=True, text=True)
    assert cp.returncode == 0
    assert (lib / "version").read_text() == "new"
    assert (prev / "version").read_text() == "old"


def test_strict_doctor_requires_runtime_identity_matrix(monkeypatch, tmp_path):
    import importlib
    monkeypatch.setenv("BIANBU_SEC_ROOT", str(tmp_path))
    monkeypatch.setenv("BIANBU_SECURITY_CODESIGN", "enforce")
    monkeypatch.setenv("BIANBU_WEBUI_TOKEN", "test-token")
    monkeypatch.delenv("BIANBU_SECURITY_RUNTIME_UNIT", raising=False)
    monkeypatch.delenv("BIANBU_SECURITY_RUNTIME_UID", raising=False)
    monkeypatch.delenv("BIANBU_SECURITY_RUNTIME_CGROUP", raising=False)
    import securityd.config as config
    import securityd.doctor as doctor
    importlib.reload(config); importlib.reload(doctor)
    result = doctor.run(strict=True)
    assert result["ok"] is False
    assert any(x["name"] == "runtime_identity_matrix" for x in result["errors"])


def test_runtime_identity_accepts_systemd_username_for_expected_uid(monkeypatch):
    import types
    from securityd import doctor

    monkeypatch.setenv("BIANBU_SECURITY_RUNTIME_UNIT", "bianbu-agent-runtimed.service")
    monkeypatch.setenv("BIANBU_SECURITY_RUNTIME_UID", "994")
    monkeypatch.setenv("BIANBU_SECURITY_RUNTIME_CGROUP",
                       "/system.slice/bianbu-agent-runtimed.service")
    monkeypatch.setattr(doctor.pwd, "getpwnam",
                        lambda name: types.SimpleNamespace(pw_uid=994))
    monkeypatch.setattr(doctor.subprocess, "run", lambda *args, **kwargs: types.SimpleNamespace(
        stdout=("User=bianbu-runtime\n"
                "ControlGroup=/system.slice/bianbu-agent-runtimed.service\n"
                "ActiveState=active\nMainPID=123\n")))
    check = doctor._runtime_identity_check()
    assert check.ok is True


def test_runtime_identity_treats_empty_systemd_user_as_root(monkeypatch):
    import types
    from securityd import doctor

    monkeypatch.setenv("BIANBU_SECURITY_RUNTIME_UNIT", "root-runtime.service")
    monkeypatch.setenv("BIANBU_SECURITY_RUNTIME_UID", "0")
    monkeypatch.setenv("BIANBU_SECURITY_RUNTIME_CGROUP",
                       "/system.slice/root-runtime.service")
    monkeypatch.setattr(doctor.subprocess, "run", lambda *args, **kwargs: types.SimpleNamespace(
        stdout=("User=\nControlGroup=/system.slice/root-runtime.service\n"
                "ActiveState=active\nMainPID=123\n")))
    assert doctor._runtime_identity_check().ok is True


def test_strict_verify_all_pins_production_security_paths():
    from pathlib import Path

    text = (Path(__file__).resolve().parents[2] / "deploy" / "verify_all.sh").read_text()
    for expected in ("BIANBU_ETC=/etc/bianbu", "BIANBU_RUN=/run/bianbu",
                     "BIANBU_LOG=/var/log/bianbu",
                     "BIANBU_AGENTS_HOME=/var/lib/bianbu/agents",
                     "BIANBU_SEC_UDS=/run/bianbu/securityd.sock"):
        assert expected in text


def test_install_assets_includes_webui_launchers():
    import subprocess
    from pathlib import Path
    root = Path(__file__).resolve().parents[2]
    cp = subprocess.run(["python3", str(root / "deploy/verify_install_assets.py")],
                        capture_output=True, text=True)
    assert cp.returncode == 0, cp.stdout + cp.stderr


def test_strict_webui_doctor_accepts_hardened_loopback_env(monkeypatch, tmp_path):
    from securityd.doctor import _webui_checks

    env_file = tmp_path / "webui.env"
    env_file.write_text(
        "BIANBU_WEBUI_AUTH=1\n"
        f"BIANBU_WEBUI_TOKEN={'a' * 40}\n"
        f"BIANBU_WEBUI_SECRET={'b' * 40}\n"
        f"BIANBU_WEBUI_VIEWER_TOKEN={'c' * 40}\n"
        "BIANBU_WEBUI_HOST=127.0.0.1\n"
        "BIANBU_WEBUI_ENABLE_SHELL=0\n"
        "BIANBU_WEBUI_ALLOW_INSECURE_REMOTE=0\n",
        encoding="utf-8",
    )
    env_file.chmod(0o640)
    monkeypatch.setenv("BIANBU_SECURITY_WEBUI_ENV_FILE", str(env_file))
    monkeypatch.setenv("BIANBU_SECURITY_WEBUI_ENV_OWNER_UID", str(os.getuid()))
    for name in (
        "BIANBU_WEBUI_AUTH", "BIANBU_WEBUI_TOKEN", "BIANBU_WEBUI_SECRET",
        "BIANBU_WEBUI_VIEWER_TOKEN", "BIANBU_WEBUI_HOST",
        "BIANBU_WEBUI_TLS_CERT", "BIANBU_WEBUI_TLS_KEY",
        "BIANBU_WEBUI_TRUST_PROXY", "BIANBU_WEBUI_ALLOW_INSECURE_REMOTE",
        "BIANBU_WEBUI_ENABLE_SHELL",
    ):
        monkeypatch.delenv(name, raising=False)

    checks = {item.name: item for item in _webui_checks(strict=True)}
    assert all(item.ok for item in checks.values()), checks


def test_strict_webui_doctor_rejects_placeholder_remote_and_shell(monkeypatch, tmp_path):
    from securityd.doctor import _webui_checks

    env_file = tmp_path / "webui.env"
    env_file.write_text(
        "BIANBU_WEBUI_AUTH=1\n"
        "BIANBU_WEBUI_TOKEN=REPLACE_WITH_至少32字节随机值\n"
        f"BIANBU_WEBUI_SECRET={'b' * 40}\n"
        "BIANBU_WEBUI_HOST=0.0.0.0\n"
        "BIANBU_WEBUI_TRUST_PROXY=1\n"
        "BIANBU_WEBUI_ENABLE_SHELL=1\n",
        encoding="utf-8",
    )
    env_file.chmod(0o640)
    monkeypatch.setenv("BIANBU_SECURITY_WEBUI_ENV_FILE", str(env_file))
    monkeypatch.setenv("BIANBU_SECURITY_WEBUI_ENV_OWNER_UID", str(os.getuid()))
    for name in list(os.environ):
        if name.startswith("BIANBU_WEBUI_"):
            monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("BIANBU_SECURITY_WEBUI_ENV_FILE", str(env_file))
    monkeypatch.setenv("BIANBU_SECURITY_WEBUI_ENV_OWNER_UID", str(os.getuid()))

    checks = {item.name: item for item in _webui_checks(strict=True)}
    assert checks["webui_auth"].ok is False
    assert checks["webui_transport"].ok is False
    assert checks["webui_shell_disabled"].ok is False


def test_strict_webui_doctor_rejects_reused_session_secret(monkeypatch, tmp_path):
    from securityd.doctor import _webui_checks

    token = "a" * 40
    env_file = tmp_path / "webui.env"
    env_file.write_text(
        "BIANBU_WEBUI_AUTH=1\n"
        f"BIANBU_WEBUI_TOKEN={token}\n"
        f"BIANBU_WEBUI_SECRET={token}\n"
        "BIANBU_WEBUI_HOST=127.0.0.1\n",
        encoding="utf-8",
    )
    env_file.chmod(0o640)
    monkeypatch.setenv("BIANBU_SECURITY_WEBUI_ENV_FILE", str(env_file))
    monkeypatch.setenv("BIANBU_SECURITY_WEBUI_ENV_OWNER_UID", str(os.getuid()))
    for name in list(os.environ):
        if name.startswith("BIANBU_WEBUI_"):
            monkeypatch.delenv(name, raising=False)

    checks = {item.name: item for item in _webui_checks(strict=True)}
    assert checks["webui_session_secret"].ok is False


def test_polkit_doctor_validates_required_actions(monkeypatch):
    from pathlib import Path
    from securityd.doctor import _polkit_policy_check

    root = Path(__file__).resolve().parents[2]
    monkeypatch.setenv(
        "BIANBU_SECURITY_POLKIT_POLICY",
        str(root / "deploy/io.bianbu.security.policy"),
    )
    assert _polkit_policy_check(strict=True).ok is True


def test_strict_doctor_validates_production_uds_socket(monkeypatch, tmp_path):
    import os
    import socket
    from securityd.doctor import _uds_dataplane_check

    path = tmp_path / "securityd.sock"
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.bind(str(path))
    path.chmod(0o660)
    try:
        monkeypatch.setenv("BIANBU_SECURITY_UDS_SOCKET", str(path))
        monkeypatch.setenv("BIANBU_SECURITY_UDS_GID", str(os.getgid()))
        assert _uds_dataplane_check(strict=True).ok is True
        path.chmod(0o600)
        assert _uds_dataplane_check(strict=True).ok is False
        path.chmod(0o666)
        assert _uds_dataplane_check(strict=True).ok is False
    finally:
        sock.close()


def test_verify_all_exposes_real_strict_commercial_gate():
    import subprocess
    from pathlib import Path

    root = Path(__file__).resolve().parents[2]
    script = root / "deploy/verify_all.sh"
    wrapper = root / "tests/testkit_verify_all.sh"
    cp = subprocess.run(["bash", "-n", str(script)], capture_output=True, text=True)
    assert cp.returncode == 0, cp.stderr
    cp = subprocess.run(["bash", "-n", str(wrapper)], capture_output=True, text=True)
    assert cp.returncode == 0, cp.stderr
    assert "../deploy/verify_all.sh" in wrapper.read_text()
    text = script.read_text()
    for marker in ("doctor", "--strict", "STRICT_E2E_FAIL",
                   "dbus-run-session", "BIANBU_E2E=1", "BIANBU_SEC_ROOT",
                   "PYTHONNOUSERSITE=1", "BIANBU_SECURITY_CODESIGN_KEYS",
                   "release_gate.py", "RUNTIME_PRODUCTION_REQUIRED",
                   "BNSEC_VERIFY_ALL_STRICT_FAIL",
                   "BNSEC_VERIFY_ALL_STRICT_PASS"):
        assert marker in text
