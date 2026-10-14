#!/usr/bin/env python3
"""依赖 CVE/许可证发布检查。

该脚本不把“没有扫描器”误报成安全通过。生产门禁使用 ``--strict``，要求
调用 pip-audit（或通过 ``--scanner`` 指定等价工具）并保存原始 JSON 报告。
"""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
from pathlib import Path


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--lock", default="requirements-lock.txt")
    ap.add_argument("--output", default="cve-report.json")
    ap.add_argument("--scanner", default="pip-audit")
    ap.add_argument("--strict", action="store_true")
    args = ap.parse_args(argv)
    scanner = shutil.which(args.scanner)
    if not scanner:
        msg = {"status": "not_run", "reason": f"scanner_missing:{args.scanner}"}
        Path(args.output).write_text(json.dumps(msg, indent=2) + "\n")
        print("CVE_SCAN_NOT_RUN scanner_missing=" + args.scanner)
        return 1 if args.strict else 0
    cp = subprocess.run([scanner, "-r", args.lock, "--format", "json"],
                        capture_output=True, text=True, check=False)
    raw = cp.stdout.strip() or "{}"
    try:
        report = json.loads(raw)
    except json.JSONDecodeError:
        report = {"raw": raw, "stderr": cp.stderr}
    Path(args.output).write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    vulns = report.get("vulnerabilities") or []
    if not vulns and isinstance(report.get("dependencies"), list):
        vulns = [v for dep in report["dependencies"]
                 for v in (dep.get("vulns") or [])]
    if cp.returncode != 0 or vulns:
        print(f"CVE_SCAN_FAIL vulnerabilities={len(vulns)} rc={cp.returncode}")
        return 1
    print("CVE_SCAN_PASS vulnerabilities=0")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
