from __future__ import annotations


def test_install_manifest_records_version_and_rejects_lower_candidate(engine, fixtures_dir, tmp_path):
    import shutil
    from securityd import code_signing
    src = fixtures_dir / "test-security-agent"
    ok, reason = engine.install_package(str(src))
    assert ok, reason
    info = engine.registry.get_manifest_info("com.bianbu.test-security-agent")
    assert info["version"] == "1.0.0"
    assert not code_signing.prevents_rollback(info["version"], "0.9.0")


def test_offline_install_assets_verifier():
    import subprocess
    from pathlib import Path
    root = Path(__file__).resolve().parents[2]
    cp = subprocess.run(["python3", str(root / "deploy/verify_install_assets.py")],
                        capture_output=True, text=True, check=False)
    assert cp.returncode == 0, cp.stdout + cp.stderr
    assert "INSTALL_ASSETS_PASS" in cp.stdout


def test_production_codesign_configuration_is_pinned():
    from pathlib import Path

    root = Path(__file__).resolve().parents[2]
    unit = (root / "deploy/bianbu-securityd.service").read_text()
    assert "Environment=BIANBU_SECURITY_CODESIGN=enforce" in unit
    assert "Environment=BIANBU_SECURITY_CODESIGN_KEYS=/etc/bianbu/codesign-keys" in unit
    assert "ExecStart=/usr/lib/bianbu-securityd/venv/bin/python" in unit
    assert "Environment=PYTHONNOUSERSITE=1" in unit
    for marker in ("Nice=-10", "CPUWeight=1000", "IOWeight=1000"):
        assert marker in unit
    assert not (root / "data/bianbu-securityd.service").exists()


def test_production_units_pin_shared_security_paths_without_runtime_chown():
    from pathlib import Path

    root = Path(__file__).resolve().parents[2]
    security = (root / "deploy/bianbu-securityd.service").read_text()
    webui = (root / "deploy/bianbu-security-webui.service").read_text()
    runtime = (root / "deploy/bianbu-agent-runtimed.service").read_text()
    for marker in ("BIANBU_ETC=/etc/bianbu", "BIANBU_RUN=/run/bianbu",
                   "BIANBU_LOG=/var/log/bianbu",
                   "BIANBU_SEC_UDS=/run/bianbu/securityd.sock",
                   "BIANBU_AGENTS_HOME=/var/lib/bianbu/agents"):
        assert marker in security
    assert "ReadWritePaths=/etc/bianbu /run/bianbu /var/log/bianbu /var/lib/bianbu/agents" in security
    assert "StateDirectory=bianbu/agents" in security
    assert "BIANBU_ETC=/etc/bianbu" in webui
    assert "BIANBU_SEC_UDS=/run/bianbu/securityd.sock" in webui
    assert "ReadWritePaths=/etc/bianbu /run/bianbu /var/log/bianbu" in webui
    assert "RuntimeDirectory=bianbu" not in webui
    assert "-m webui.production" in webui
    assert "webui/app.py" not in webui
    assert "SupplementaryGroups=bianbu-security" in runtime
    assert "BIANBU_SEC_UDS=/run/bianbu/securityd.sock" in runtime
    assert "RuntimeDirectory=bianbu\n" not in runtime
    assert "RuntimeDirectory=bianbu-runtime" in runtime


def test_security_runtime_directory_is_group_writable_for_uds_recovery():
    from pathlib import Path

    root = Path(__file__).resolve().parents[2]
    package_root = root.parents[1]
    tmpfiles = (root / "deploy/bianbu-securityd.tmpfiles").read_text()
    postinst = (package_root / "debian/postinst").read_text()
    assert "d /run/bianbu 0770 bianbu-security bianbu-security -" in tmpfiles
    assert "chmod 0770 /run/bianbu" in postinst


def test_installer_dry_run_does_not_take_ownership_of_external_runtime():
    import subprocess
    from pathlib import Path

    root = Path(__file__).resolve().parents[2]
    cp = subprocess.run(["bash", str(root / "deploy/install.sh"), "--dry-run"],
                        capture_output=True, text=True, check=False)
    assert cp.returncode == 0, cp.stdout + cp.stderr
    assert "/etc/bianbu/codesign-keys" in cp.stdout
    assert "/etc/bianbu/keys" in cp.stdout
    assert "bianbu-agent-runtimed.service" not in cp.stdout


def test_installer_can_explicitly_enable_reference_runtime():
    import subprocess
    from pathlib import Path

    root = Path(__file__).resolve().parents[2]
    cp = subprocess.run(["bash", str(root / "deploy/install.sh"), "--dry-run",
                         "--enable-runtime"], capture_output=True, text=True,
                        check=False)
    assert cp.returncode == 0, cp.stdout + cp.stderr
    assert "bianbu-agent-runtimed.service" in cp.stdout


def test_installer_exposes_explicit_codesign_trust_root():
    import subprocess
    from pathlib import Path

    root = Path(__file__).resolve().parents[2]
    cp = subprocess.run(["bash", str(root / "deploy/install.sh"), "--dry-run",
                         "--codesign-key", "/secure/release.pub"],
                        capture_output=True, text=True, check=False)
    assert cp.returncode == 0, cp.stdout + cp.stderr
    assert "/secure/release.pub" in cp.stdout
    assert "/etc/bianbu/codesign-keys/release.pub" in cp.stdout


def test_demo_deb_disables_codesign_without_removing_product_policy():
    from pathlib import Path

    root = Path(__file__).resolve().parents[4]
    control = (root / "debian/control").read_text()
    assert "Package: bianbu-agent-securityd-keys" not in control
    rules = (root / "debian/rules").read_text()
    assert "CODESIGN_KEY_FILE" not in rules
    assert "bianbu-securityd-demo.conf" in rules
    drop_in = (root / "debian/bianbu-securityd-demo.conf").read_text()
    assert "Environment=BIANBU_SECURITY_CODESIGN=off" in drop_in
    product_unit = (root / "impl/bianbu-securityd/deploy/bianbu-securityd.service").read_text()
    assert "Environment=BIANBU_SECURITY_CODESIGN=enforce" in product_unit


def test_demo_deb_disables_webui_auth_without_removing_product_policy():
    from pathlib import Path

    root = Path(__file__).resolve().parents[4]
    rules = (root / "debian/rules").read_text()
    assert "bianbu-security-webui-demo.conf" in rules
    assert "DEB_DEMO ?= 1" in rules
    assert '"$(DEB_DEMO)" = 1' in rules
    assert "DEB_DEMO=0" in (root / "debian/README.Debian").read_text()
    drop_in = (root / "debian/bianbu-security-webui-demo.conf").read_text()
    assert "Environment=BIANBU_WEBUI_DEMO=1" in drop_in
    assert "Environment=BIANBU_WEBUI_AUTH=0" in drop_in
    assert "UnsetEnvironment=BIANBU_WEBUI_TOKEN BIANBU_WEBUI_VIEWER_TOKEN" in drop_in
    product_unit = (root / "impl/bianbu-securityd/deploy/bianbu-security-webui.service").read_text()
    assert "EnvironmentFile=-/etc/bianbu/webui.env" in product_unit
    assert "BIANBU_WEBUI_DEMO" not in product_unit


def test_demo_deb_starts_without_a_release_trust_key():
    from pathlib import Path

    root = Path(__file__).resolve().parents[4]
    postinst = (root / "debian/postinst").read_text()
    assert "key_ready" not in postinst
    assert "no code-signing public key found" not in postinst
    assert "development/demo delivery" in postinst
    assert "systemctl unmask bianbu-securityd.service" in postinst
    assert "systemctl mask bianbu-securityd.service" not in postinst
    assert "systemctl enable bianbu-securityd.service" in postinst
    assert "systemctl start bianbu-securityd.service" in postinst


def test_installer_accepts_frozen_runtime_venv():
    import subprocess
    from pathlib import Path

    root = Path(__file__).resolve().parents[2]
    cp = subprocess.run(["bash", str(root / "deploy/install.sh"), "--dry-run",
                         "--runtime-venv", "/release/bnsec-venv"],
                        capture_output=True, text=True, check=False)
    assert cp.returncode == 0, cp.stdout + cp.stderr
    assert "/release/bnsec-venv" in cp.stdout
    assert ".staging." in cp.stdout and "/venv" in cp.stdout
    assert "generate_sbom.py --strict" in (root / "deploy/install.sh").read_text()
    assert "PYTHONNOUSERSITE=1" in (root / "deploy/install.sh").read_text()


def test_installer_webui_dry_run_does_not_require_target_secrets():
    import subprocess
    from pathlib import Path

    root = Path(__file__).resolve().parents[2]
    cp = subprocess.run(["bash", str(root / "deploy/install.sh"), "--dry-run",
                         "--enable-webui"], capture_output=True, text=True, check=False)
    assert cp.returncode == 0, cp.stdout + cp.stderr
    assert "bianbu-security-webui.service" in cp.stdout


def test_production_webui_uses_one_gthread_worker(monkeypatch):
    from webui import production

    monkeypatch.setenv("BIANBU_WEBUI_AUTH", "0")
    monkeypatch.setenv("BIANBU_WEBUI_HOST", "127.0.0.1")
    monkeypatch.setenv("BIANBU_WEBUI_PORT", "9876")
    monkeypatch.setenv("BIANBU_WEBUI_THREADS", "24")
    options = production.build_options()
    assert options["bind"] == "127.0.0.1:9876"
    assert options["workers"] == 1
    assert options["worker_class"] == "gthread"
    assert options["threads"] == 24
    assert options["control_socket_disable"] is True


def test_installer_restores_matching_units_and_database_ownership():
    from pathlib import Path

    root = Path(__file__).resolve().parents[2]
    text = (root / "deploy/install.sh").read_text()
    assert "SYSTEMD_UNIT_PREVIOUS" in text
    assert 'cp -a "$SYSTEMD_UNIT_PREVIOUS" "$SYSTEMD_UNIT"' in text
    assert "! -name webui.env" in text
    assert 'chown -R "$SVC_USER:$SVC_GROUP" /var/log/bianbu/audit' in text
    assert "WEBUI_WAS_ACTIVE" in text
    assert "systemctl stop bianbu-security-webui.service" in text
    assert 'if [ "$WEBUI_WAS_ACTIVE" = 1 ]; then systemctl start bianbu-security-webui.service' in text
    start_block = text.split('echo "== 7. 启动"', 1)[1].split(
        'if [ "$DRY" = 0 ]; then', 1)[0]
    assert 'elif [ "$WEBUI_WAS_ACTIVE" = 1 ]; then' in start_block
    assert "systemctl start bianbu-security-webui.service" in start_block
    assert "Security 身份与正式 UDS 权限正确" in text
    assert "WebUI 由专用身份运行且 HTTP 就绪" in text


def test_uninstall_default_does_not_stop_external_runtime():
    import subprocess
    from pathlib import Path

    root = Path(__file__).resolve().parents[2]
    cp = subprocess.run(["bash", str(root / "deploy/install.sh"), "--dry-run",
                         "--uninstall"], capture_output=True, text=True,
                        check=False)
    assert cp.returncode == 0, cp.stdout + cp.stderr
    assert "bianbu-agent-runtimed.service" not in cp.stdout


def test_database_migration_is_idempotent_and_backup_safe(tmp_path):
    import sqlite3
    from pathlib import Path
    import subprocess
    root = Path(__file__).resolve().parents[2]
    db = tmp_path / "capabilities.db"
    conn = sqlite3.connect(db)
    conn.execute("CREATE TABLE sample (id INTEGER PRIMARY KEY)")
    conn.execute("INSERT INTO sample VALUES (1)")
    conn.commit(); conn.close()
    script = root / "deploy/migrate_db.py"
    first = subprocess.run(["python3", str(script), str(db)], capture_output=True, text=True)
    conn = sqlite3.connect(db)
    first_migrated_at = conn.execute(
        "SELECT value FROM schema_meta WHERE key='migrated_at'"
    ).fetchone()[0]
    conn.close()
    second = subprocess.run(["python3", str(script), str(db)], capture_output=True, text=True)
    assert first.returncode == second.returncode == 0
    conn = sqlite3.connect(db)
    assert conn.execute("SELECT value FROM schema_meta WHERE key='schema_version'").fetchone()[0] == "1"
    assert conn.execute("SELECT value FROM schema_meta WHERE key='migrated_at'").fetchone()[0] == first_migrated_at
    assert conn.execute("SELECT id FROM sample").fetchone()[0] == 1
    conn.close()
    assert (tmp_path / "capabilities.db.pre-migrate").exists()


def test_release_gate_assets_script():
    import subprocess
    from pathlib import Path
    root = Path(__file__).resolve().parents[2]
    cp = subprocess.run(["python3", str(root / "deploy/release_gate.py"),
                         "--output", str(root / "release-test-sbom.json")],
                        capture_output=True, text=True, check=False)
    try:
        assert cp.returncode == 0, cp.stdout + cp.stderr
        assert "RELEASE_GATE_PASS" in cp.stdout
    finally:
        (root / "release-test-sbom.json").unlink(missing_ok=True)


def test_database_migration_rejects_future_schema_and_keeps_backup(tmp_path):
    import sqlite3
    import subprocess
    from pathlib import Path
    root = Path(__file__).resolve().parents[2]
    db = tmp_path / "future.db"
    conn = sqlite3.connect(db)
    conn.execute("CREATE TABLE schema_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
    conn.execute("INSERT INTO schema_meta VALUES ('schema_version','99')")
    conn.commit(); conn.close()
    cp = subprocess.run(["python3", str(root / "deploy/migrate_db.py"), str(db)],
                        capture_output=True, text=True)
    assert cp.returncode == 1
    assert "future_schema=99" in cp.stdout
    conn = sqlite3.connect(db)
    assert conn.execute("SELECT value FROM schema_meta WHERE key='schema_version'").fetchone()[0] == "99"
    conn.close()


def test_package_installs_securityd_polkit_rule_for_scope_set_property():
    """D-6：securityd 需对 Runtime Worker scope 执行 systemctl set-property 热应用网络策略。

    没有这条 polkit 规则，bianbu-security 用户的 set-property 会落入 auth_admin，
    SetNetworkPolicy 对运行中 Worker 一律 PermissionDenied 并回滚。
    """
    from pathlib import Path

    root = Path(__file__).resolve().parents[2]
    rules = (root.parents[1] / "debian/rules").read_text()
    assert "deploy/io.bianbu.securityd.rules" in rules
    assert "usr/share/polkit-1/rules.d/61-bianbu-securityd.rules" in rules
    text = (root / "deploy/io.bianbu.securityd.rules").read_text()
    assert 'action.id !== "org.freedesktop.systemd1.manage-units"' in text
    assert 'subject.user !== "bianbu-security"' in text
    assert 'subject.system_unit !== "bianbu-securityd.service"' in text
    assert "subject.no_new_privileges" in text
    assert 'verb === "set-property"' in text
    # 只放行 Worker scope，绝不放行 service 单元
    assert r"\.scope$" in text
    assert "service$" not in text.replace("bianbu-securityd.service", "")
