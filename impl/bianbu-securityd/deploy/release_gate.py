#!/usr/bin/env python3
"""离线发布门禁：资产、SBOM、wheel 元数据和许可证状态一次性校验。"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--strict", action="store_true")
    ap.add_argument("--output", default="sbom.json")
    ap.add_argument("--scanner", default="pip-audit",
                    help="CVE 扫描器名称或绝对路径（strict 时使用）")
    args = ap.parse_args(argv)
    root = Path(__file__).resolve().parents[1]
    checks = [root / "deploy/verify_install_assets.py", root / "deploy/generate_sbom.py",
              root / "deploy/migrate_db.py", root / "deploy/rollback.sh",
              root / "deploy/dependency_audit.py", root / "deploy/generate_release_manifest.py",
              root / "deploy/security_release_gate.py",
              root / "deploy/commercial_acceptance_gate.py",
              root / "deploy/commercial_soak.py",
              root / "deploy/start_commercial_soak.sh",
              root / "requirements-lock.txt", root / "THIRD_PARTY_LICENSES.md"]
    missing = [str(p.relative_to(root)) for p in checks if not p.exists()]
    if missing:
        print("RELEASE_GATE_FAIL missing=" + ",".join(missing))
        return 1
    for script in (root / "deploy/verify_install_assets.py",):
        cp = subprocess.run([sys.executable, str(script)], cwd=root, text=True)
        if cp.returncode:
            return cp.returncode
    sbom_cmd = [sys.executable, str(root / "deploy/generate_sbom.py")]
    if args.strict:
        sbom_cmd.append("--strict")
    sbom_cmd.extend(["--output", args.output])
    cp = subprocess.run(sbom_cmd,
                        cwd=root, text=True)
    if cp.returncode and args.strict:
        return cp.returncode
    if cp.returncode:
        print("RELEASE_GATE_WARNING dependency metadata differs from lockfile")
    data = json.loads(Path(args.output).read_text())
    if args.strict and (data.get("missing_packages") or data.get("license_unknown")):
        print("RELEASE_GATE_FAIL dependency metadata incomplete")
        return 1
    if args.strict:
        cve = subprocess.run([sys.executable, str(root / "deploy/dependency_audit.py"),
                              "--lock", str(root / "requirements-lock.txt"),
                              "--output", str(Path(args.output).with_name("cve-report.json")),
                              "--scanner", args.scanner,
                              "--strict"], cwd=root, text=True)
        if cve.returncode:
            return cve.returncode
    print("RELEASE_GATE_PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
