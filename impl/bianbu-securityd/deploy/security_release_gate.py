#!/usr/bin/env python3
"""生成 Security 责任域的商用发布证据包。

全产品 ``verify_all.sh --strict`` 在正式 Runtime 缺失时必须保持失败。本工具不会
降低该门禁，而是严格确认：所有 Security 自有门禁已经通过，失败项只能是明确列出的
Runtime/系统集成外部依赖；随后归档原始日志、JUnit、SBOM、CVE 与源码清单。
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
ALLOWED_PRODUCT_GATES = {"doctor", "runtime_production"}
ALLOWED_DOCTOR_ERRORS = {"network_enforcement", "runtime_identity_matrix"}
REQUIRED_PASS_MARKERS = {
    "DBUS_CONTRACT_PASS",
    "INSTALL_ASSETS_PASS",
    "STRICT_E2E_PASS skipped=0",
    "PERF_PASS",
    "STABILITY_PASS",
    "SBOM_PASS",
    "CVE_SCAN_PASS vulnerabilities=0",
    "RELEASE_GATE_PASS",
}


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _strict_failure_gates(log: str) -> set[str] | None:
    matches = re.findall(r"BNSEC_VERIFY_ALL_STRICT_FAIL gates=([^\s]+)", log)
    if not matches:
        return None
    return {x for x in matches[-1].split(",") if x}


def evaluate_strict_result(returncode: int, log: str,
                           doctor: dict[str, Any] | None) -> dict[str, Any]:
    """判定 Security 自有门禁是否通过，不把外部 Runtime 缺失伪装成全产品通过。"""
    missing_markers = sorted(marker for marker in REQUIRED_PASS_MARKERS if marker not in log)
    if missing_markers:
        return {"ok": False, "reason": "missing_pass_markers",
                "missing_markers": missing_markers}

    if returncode == 0:
        if "BNSEC_VERIFY_ALL_STRICT_PASS" not in log:
            return {"ok": False, "reason": "strict_pass_marker_missing"}
        return {"ok": True, "product_status": "passed", "external_gates": []}

    if returncode != 1:
        return {"ok": False, "reason": "unexpected_strict_returncode",
                "returncode": returncode}

    gates = _strict_failure_gates(log)
    if not gates:
        return {"ok": False, "reason": "strict_failure_marker_missing"}
    unexpected_gates = sorted(gates - ALLOWED_PRODUCT_GATES)
    if unexpected_gates:
        return {"ok": False, "reason": "security_gate_failed",
                "unexpected_gates": unexpected_gates, "gates": sorted(gates)}

    if "doctor" in gates:
        if not isinstance(doctor, dict):
            return {"ok": False, "reason": "doctor_report_missing"}
        errors = doctor.get("errors")
        if not isinstance(errors, list) or not errors:
            return {"ok": False, "reason": "doctor_errors_missing"}
        names = {str(item.get("name", "")) for item in errors if isinstance(item, dict)}
        unexpected_doctor = sorted(names - ALLOWED_DOCTOR_ERRORS)
        if unexpected_doctor:
            return {"ok": False, "reason": "security_doctor_failed",
                    "unexpected_doctor_errors": unexpected_doctor,
                    "doctor_errors": sorted(names)}

    return {"ok": True, "product_status": "blocked_external",
            "external_gates": sorted(gates)}


def _source_revision(explicit: str) -> tuple[str, bool | None]:
    cp = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT,
                        capture_output=True, text=True, check=False)
    if cp.returncode:
        return explicit.strip(), None
    dirty = subprocess.run(["git", "status", "--porcelain"], cwd=ROOT,
                           capture_output=True, text=True, check=False)
    return explicit.strip() or cp.stdout.strip(), bool(dirty.stdout.strip())


def _evidence_files(output_dir: Path) -> list[dict[str, Any]]:
    rows = []
    for path in sorted(p for p in output_dir.iterdir()
                       if p.is_file() and p.name != "security-release-summary.json"):
        rows.append({"name": path.name, "size": path.stat().st_size,
                     "sha256": _sha256(path)})
    return rows


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--output-dir", required=True)
    ap.add_argument("--python", default=sys.executable)
    ap.add_argument("--scanner", default="pip-audit")
    ap.add_argument("--source-revision", default=os.environ.get(
        "BIANBU_SOURCE_REVISION", ""))
    ap.add_argument("--stability-seconds", type=float, default=10.0)
    ap.add_argument("--perf-samples", type=int, default=100)
    ap.add_argument("--timeout-seconds", type=float, default=3600.0)
    ap.add_argument("--allow-dirty", action="store_true")
    args = ap.parse_args(argv)

    output_dir = Path(args.output_dir).resolve()
    if output_dir.exists() and any(output_dir.iterdir()):
        print(f"SECURITY_RELEASE_GATE_FAIL output_dir_not_empty={output_dir}")
        return 2
    output_dir.mkdir(parents=True, exist_ok=True)

    revision, dirty = _source_revision(args.source_revision)
    if not revision:
        print("SECURITY_RELEASE_GATE_FAIL source_revision_required")
        return 2
    if dirty and not args.allow_dirty:
        print("SECURITY_RELEASE_GATE_FAIL source_tree_dirty")
        return 2

    doctor_path = output_dir / "doctor.json"
    unit_xml = output_dir / "unit.xml"
    integration_xml = output_dir / "integration.xml"
    e2e_xml = output_dir / "e2e.xml"
    sbom_path = output_dir / "sbom.json"
    verify_log = output_dir / "verify-all.log"
    started = datetime.now(timezone.utc)
    env = dict(os.environ)
    env.update({
        "PYTHON": args.python,
        "CVE_SCANNER": args.scanner,
        "STABILITY_SECONDS": str(args.stability_seconds),
        "PERF_SAMPLES": str(args.perf_samples),
        "DOCTOR_JSON": str(doctor_path),
        "JUNIT_UNIT": str(unit_xml),
        "JUNIT_INT": str(integration_xml),
        "JUNIT_E2E": str(e2e_xml),
        "SBOM_JSON": str(sbom_path),
    })
    command = ["bash", str(ROOT / "deploy/verify_all.sh"), "--strict"]
    try:
        cp = subprocess.run(command, cwd=ROOT, env=env, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True, check=False,
                            timeout=args.timeout_seconds)
        log = cp.stdout
        returncode = cp.returncode
    except subprocess.TimeoutExpired as exc:
        log = (exc.stdout or "") + "\nSECURITY_RELEASE_GATE_TIMEOUT\n"
        returncode = 124
    verify_log.write_text(log)

    doctor = None
    if doctor_path.is_file():
        try:
            doctor = json.loads(doctor_path.read_text())
        except json.JSONDecodeError:
            doctor = None
    evaluation = evaluate_strict_result(returncode, log, doctor)

    manifest_path = output_dir / "release-manifest.json"
    manifest_result = None
    if evaluation.get("ok"):
        manifest_cp = subprocess.run([
            args.python, str(ROOT / "deploy/generate_release_manifest.py"),
            "--root", str(ROOT), "--output", str(manifest_path),
        ], cwd=ROOT, capture_output=True, text=True, check=False)
        manifest_result = {"returncode": manifest_cp.returncode,
                           "stdout": manifest_cp.stdout.strip(),
                           "stderr": manifest_cp.stderr.strip()}
        if manifest_cp.returncode:
            evaluation = {"ok": False, "reason": "release_manifest_failed",
                          "details": manifest_result}

    finished = datetime.now(timezone.utc)
    summary = {
        "format": "bianbu-security-release-evidence-v1",
        "security_scope_status": "passed" if evaluation.get("ok") else "failed",
        "product_status": evaluation.get("product_status", "failed"),
        "source_revision": revision,
        "source_dirty": dirty,
        "started_at": started.isoformat(),
        "finished_at": finished.isoformat(),
        "duration_seconds": round((finished - started).total_seconds(), 3),
        "platform": platform.platform(),
        "python": args.python,
        "verify_command": command,
        "strict_returncode": returncode,
        "evaluation": evaluation,
        "manifest": manifest_result,
        "evidence": _evidence_files(output_dir),
    }
    summary_path = output_dir / "security-release-summary.json"
    summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n")

    if not evaluation.get("ok"):
        print("SECURITY_RELEASE_GATE_FAIL reason=" + str(evaluation.get("reason")))
        return 1
    external = ",".join(evaluation.get("external_gates", [])) or "none"
    print(f"SECURITY_RELEASE_GATE_PASS product_status={evaluation['product_status']} "
          f"external_gates={external} evidence={output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
