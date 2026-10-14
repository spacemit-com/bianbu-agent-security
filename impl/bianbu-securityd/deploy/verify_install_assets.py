#!/usr/bin/env python3
"""已安装目录的离线发布资产校验。

不依赖 pytest、D-Bus 或网络；installer 在切换 staging 目录前执行，
确保 XML、policy、systemd unit、安装/回滚脚本齐全且 XML 可解析。
"""
from __future__ import annotations

import json
import sys
import xml.etree.ElementTree as ET
from pathlib import Path


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    required = [
        root / "data/io.bianbu.Security.xml",
        root / "data/io.bianbu.Security.conf",
        root / "data/io.bianbu.Runtime.xml",
        root / "deploy/io.bianbu.Security.conf",
        root / "deploy/io.bianbu.Runtime.conf",
        root / "deploy/io.bianbu.Runtime.service",
        root / "deploy/bianbu-securityd.service",
        root / "deploy/bianbu-security-webui.service",
        root / "deploy/webui.env.example",
        root / "deploy/io.bianbu.security.policy",
        root / "deploy/bianbu-agent-runtimed.service",
        root / "deploy/agent-runtimed-security-integration.md",
        root / "deploy/runtime_production_probe.py",
        root / "deploy/verify_all.sh",
        root / "deploy/install.sh",
        root / "deploy/rollback.sh",
        root / "deploy/generate_sbom.py",
        root / "deploy/migrate_db.py",
        root / "deploy/release_gate.py",
        root / "deploy/security_release_gate.py",
        root / "deploy/commercial_acceptance_gate.py",
        root / "deploy/commercial-ca-evidence.example.json",
        root / "deploy/commercial-desktop-evidence.example.json",
        root / "deploy/commercial-pentest-evidence.example.json",
        root / "deploy/commercial-release-approval.example.json",
        root / "deploy/commercial_soak.py",
        root / "deploy/start_commercial_soak.sh",
        root / "deploy/dependency_audit.py",
        root / "deploy/generate_release_manifest.py",
        root / "webui/README.md",
        root / "webui/run.sh",
        root / "webui/run-system-bus.sh",
        root / "webui/re-run.sh",
        root / "webui/production.py",
        root / "securityd/uds_handlers.py",
        root / "securityd/uds_server.py",
        root / "client/bianbu_security_uds.py",
        root / "requirements-lock.txt",
        root / "THIRD_PARTY_LICENSES.md",
    ]
    missing = [str(p.relative_to(root)) for p in required if not p.is_file()]
    if missing:
        print("INSTALL_ASSETS_FAIL missing=" + ",".join(missing), file=sys.stderr)
        return 1
    try:
        if (root / "data/bianbu-securityd.service").exists():
            raise ValueError("legacy root systemd unit must be removed; deploy/ is canonical")
        ET.parse(root / "data/io.bianbu.Security.xml")
        ET.parse(root / "data/io.bianbu.Runtime.xml")
        ET.parse(root / "data/io.bianbu.Security.conf")
        ET.parse(root / "deploy/io.bianbu.Security.conf")
        ET.parse(root / "deploy/io.bianbu.Runtime.conf")
        ET.parse(root / "deploy/io.bianbu.security.policy")
        # systemd unit 不是 XML；以关键安全约束做离线门禁，防止发布包漏掉
        # Runtime 接入模板或把 unit 装成无隔离的普通进程。
        unit = (root / "deploy/bianbu-agent-runtimed.service").read_text()
        for marker in ("ExecStart=/usr/lib/bianbu-securityd/venv/bin/python",
                       "User=bianbu-runtime", "Group=bianbu-runtime",
                       "SupplementaryGroups=bianbu-security", "NoNewPrivileges=yes",
                       "ProtectSystem=strict", "ReadWritePaths=/var/lib/bianbu/runtime",
                       "Environment=PYTHONNOUSERSITE=1"):
            if marker not in unit:
                raise ValueError(f"Runtime unit missing {marker}")
        if "-m runtime.runtime_service" not in unit:
            raise ValueError("Runtime unit must launch the packaged runtime service")
        if not (root / "runtime/runtime_service.py").is_file():
            raise ValueError("runtime/runtime_service.py missing")
        webui_unit = (root / "deploy/bianbu-security-webui.service").read_text()
        for marker in ("ExecStart=/usr/lib/bianbu-securityd/venv/bin/python",
                       "EnvironmentFile=-/etc/bianbu/webui.env",
                       "User=bianbu-security", "SupplementaryGroups=bianbu-admin",
                       "NoNewPrivileges=yes", "ProtectSystem=strict",
                       "Environment=PYTHONNOUSERSITE=1",
                       "ReadWritePaths=/etc/bianbu /run/bianbu /var/log/bianbu",
                       "ReadOnlyPaths=/run/bianbu"):
            if marker not in webui_unit:
                raise ValueError(f"WebUI unit missing {marker}")
        if "-m webui.production" not in webui_unit:
            raise ValueError("WebUI unit must use the Gunicorn production launcher")
        if "RuntimeDirectory=bianbu" in webui_unit:
            raise ValueError("WebUI unit must not own Security shared /run/bianbu")
        if "Requires=dbus.service bianbu-securityd.service" in webui_unit:
            raise ValueError("WebUI must remain available while securityd is restarting")
        if "Restart=always" not in webui_unit or "RestartSec=2s" not in webui_unit:
            raise ValueError("WebUI unit must restart after unexpected exit")
        webui_env = (root / "deploy/webui.env.example").read_text()
        for marker in ("BIANBU_WEBUI_AUTH=0",
                       "BIANBU_WEBUI_SECRET=", "BIANBU_WEBUI_HOST=0.0.0.0",
                       "BIANBU_WEBUI_ENABLE_SHELL=0",
                       "BIANBU_WEBUI_ALLOW_INSECURE_REMOTE=0"):
            if marker not in webui_env:
                raise ValueError(f"WebUI env example missing {marker}")
        # Demo authentication bypass is package-only.  The product unit and
        # environment template must not silently contain the bypass flag.
        if "BIANBU_WEBUI_DEMO" in webui_unit or "BIANBU_WEBUI_DEMO" in webui_env:
            raise ValueError("WebUI product assets must not enable demo auth bypass")
        webui_runner = (root / "webui/run-system-bus.sh").read_text()
        if 'HOST="${HOST:-0.0.0.0}"' not in webui_runner:
            raise ValueError("system-bus WebUI runner must default to all interfaces")
        security_unit = (root / "deploy/bianbu-securityd.service").read_text()
        for marker in ("ExecStart=/usr/lib/bianbu-securityd/venv/bin/python",
                       "Environment=BIANBU_SECURITY_CODESIGN=enforce",
                       "Environment=PYTHONNOUSERSITE=1",
                       "Nice=-10", "CPUWeight=1000", "IOWeight=1000",
                       "ProtectSystem=full",
                       "Environment=BIANBU_SECURITY_CODESIGN_KEYS=/etc/bianbu/codesign-keys",
                       "Environment=BIANBU_ETC=/etc/bianbu",
                       "Environment=BIANBU_RUN=/run/bianbu",
                       "Environment=BIANBU_LOG=/var/log/bianbu",
                       "Environment=BIANBU_SEC_UDS=/run/bianbu/securityd.sock",
                       "Environment=BIANBU_AGENTS_HOME=/var/lib/bianbu/agents",
                       "ReadWritePaths=/etc/bianbu /run/bianbu /var/log/bianbu /var/lib/bianbu/agents",
                       "StateDirectory=bianbu/agents"):
            if marker not in security_unit:
                raise ValueError(f"Security unit missing {marker}")
        if "ProtectSystem=strict" in security_unit or "RuntimeDirectory=bianbu" in security_unit:
            raise ValueError("Security unit must keep /run/bianbu host-shared")
        tmpfiles = root / "deploy/bianbu-securityd.tmpfiles"
        if not tmpfiles.is_file() or "/run/bianbu/sandbox" not in tmpfiles.read_text():
            raise ValueError("Security tmpfiles policy missing shared sandbox tree")
        service = (root / "securityd/service.py").read_text()
        for marker in ("build_security_uds_server", "uds_server.start()",
                       "uds_server.stop()"):
            if marker not in service:
                raise ValueError(f"Security service missing production UDS lifecycle: {marker}")
        runtime_unit = (root / "deploy/bianbu-agent-runtimed.service").read_text()
        if "RuntimeDirectory=bianbu\n" in runtime_unit:
            raise ValueError("Runtime unit must not take ownership of Security shared /run/bianbu")
        for marker in ("SupplementaryGroups=bianbu-security",
                       "Environment=BIANBU_SEC_UDS=/run/bianbu/securityd.sock"):
            if marker not in runtime_unit:
                raise ValueError(f"Runtime unit missing production UDS access: {marker}")
        installer = (root / "deploy/install.sh").read_text()
        if "--enable-runtime" not in installer:
            raise ValueError("installer must expose explicit --enable-runtime reference path")
        for marker in ("--codesign-key", "CODESIGN_TRUST_ROOT_PASS",
                       "代码签名信任根未就绪", "--runtime-venv",
                       "RUNTIME_VENV_PASS", "generate_sbom.py --strict",
                       "SYSTEMD_UNIT_PREVIOUS", "! -name webui.env",
                       "WEBUI_WAS_ACTIVE", "Security 身份与正式 UDS 权限正确",
                       "WebUI 由专用身份运行且 HTTP 就绪"):
            if marker not in installer:
                raise ValueError(f"installer missing code-signing preflight: {marker}")
        for marker in ("BIANBU_WEBUI_SECRET", "BIANBU_WEBUI_ENABLE_SHELL=1",
                       "受信反向代理模式要求 WebUI 自身只监听回环地址"):
            if marker not in installer:
                raise ValueError(f"installer missing WebUI production gate: {marker}")
        verify_all = (root / "deploy/verify_all.sh").read_text()
        for marker in ("--strict", "STRICT_E2E_FAIL", "dbus-run-session",
                       "BIANBU_E2E=1", "BIANBU_SEC_ROOT",
                       "PYTHONNOUSERSITE=1", "BIANBU_SECURITY_CODESIGN_KEYS",
                       "RUNTIME_PRODUCTION_REQUIRED",
                       "BNSEC_VERIFY_ALL_STRICT_FAIL",
                       "BNSEC_VERIFY_ALL_STRICT_PASS"):
            if marker not in verify_all:
                raise ValueError(f"verify-all missing strict gate: {marker}")
        security_release = (root / "deploy/security_release_gate.py").read_text()
        for marker in ("ALLOWED_PRODUCT_GATES", "ALLOWED_DOCTOR_ERRORS",
                       "REQUIRED_PASS_MARKERS", "SECURITY_RELEASE_GATE_PASS",
                       "security-release-summary.json"):
            if marker not in security_release:
                raise ValueError(f"security release gate missing marker: {marker}")
        commercial_acceptance = (root / "deploy/commercial_acceptance_gate.py").read_text()
        for marker in ("COMMERCIAL_ACCEPTANCE_PASS", "MIN_SOAK_SECONDS",
                       "REQUIRED_PENTEST_SCOPE", "approval:four_eyes_missing",
                       "REQUIRED_SECURITY_EVIDENCE", "soak:samples_count_mismatch",
                       "soak:milestone_evidence_missing", "Ed25519PublicKey",
                       "commercial-acceptance-summary.json"):
            if marker not in commercial_acceptance:
                raise ValueError(f"commercial acceptance gate missing marker: {marker}")
        for name in ("commercial-ca-evidence.example.json",
                     "commercial-desktop-evidence.example.json",
                     "commercial-pentest-evidence.example.json",
                     "commercial-release-approval.example.json"):
            data = json.loads((root / "deploy" / name).read_text())
            if not isinstance(data, dict) or "format" not in data:
                raise ValueError(f"commercial evidence template invalid: {name}")
        commercial_soak = (root / "deploy/commercial_soak.py").read_text()
        for marker in ("24/72", "CheckPermissionV2", "COMMERCIAL_SOAK_PASS",
                       "security-commercial-soak-v2", "samples_sha256", "SSEMonitor",
                       "PACanaryMonitor", "pa_canary"):
            if marker not in commercial_soak:
                raise ValueError(f"commercial soak missing marker: {marker}")
        soak_launcher = (root / "deploy/start_commercial_soak.sh").read_text()
        for marker in ("setsid", "current.pid", "SOAK_MILESTONE_SECONDS",
                       "COMMERCIAL_SOAK_STARTED", "SOAK_PA_INTERVAL_SECONDS",
                       "SOAK_MIN_PA_RUNS"):
            if marker not in soak_launcher:
                raise ValueError(f"commercial soak launcher missing marker: {marker}")
        # Security 默认不能强制接管/启动外部 Runtime；参考 Runtime 只能由显式选项启用。
        default_block = installer.split("ENABLE_RUNTIME=0", 1)[1].split(
            "if [ \"$ENABLE_RUNTIME\" = 1 ]", 1)[0]
        if "enable --now bianbu-agent-runtimed.service" in default_block:
            raise ValueError("installer default path must not start Runtime")
        if "enable --now bianbu-security-webui.service" in default_block:
            raise ValueError("installer default path must not start WebUI")
    except (ET.ParseError, ValueError) as exc:
        print(f"INSTALL_ASSETS_FAIL xml={exc}", file=sys.stderr)
        return 1
    print("INSTALL_ASSETS_PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
