#!/usr/bin/env python3
"""Bianbu Security 最终商用验收门禁。

该门禁只在 Security/WebUI/PA 72 小时耐久和组织级外部证据齐全后执行。它不会生成 CA、桌面授权或
渗透报告，而是 fail-closed 校验这些证据的附件哈希、版本一致性、双人审批和组织
Ed25519 签名，避免用内部单测或自述文档冒充正式商用签收。
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

FORMAT = "bianbu-security-commercial-acceptance-v1"
REQUIRED_PENTEST_SCOPE = {"securityd", "webui", "dbus", "uds"}
REQUIRED_CA_TESTS = {"install", "rotation", "revocation", "recovery"}
REQUIRED_DESKTOP_CASES = {"allow", "deny", "expired", "replay"}
REQUIRED_SECURITY_EVIDENCE = {
    "unit.xml", "integration.xml", "e2e.xml", "doctor.json", "sbom.json",
    "cve-report.json", "release-manifest.json", "verify-all.log",
}
MIN_SOAK_SECONDS = 72 * 3600
MIN_PA_CANARY_RUNS = 12
MILESTONES = (24 * 3600, 72 * 3600)
HEX64 = re.compile(r"^[0-9a-f]{64}$")
PLACEHOLDER_MARKERS = ("replace", "tbd", "draft", "example")


def _real_string(value: Any) -> bool:
    return (isinstance(value, str) and bool(value.strip())
            and not any(marker in value.casefold() for marker in PLACEHOLDER_MARKERS))


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _load_json(path: Path, errors: list[str], label: str) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        errors.append(f"{label}:invalid_json:{exc}")
        return {}
    if not isinstance(data, dict):
        errors.append(f"{label}:not_object")
        return {}
    return data


def _parse_time(value: Any, errors: list[str], label: str) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        errors.append(f"{label}:issued_at_missing")
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        errors.append(f"{label}:issued_at_invalid")
        return None
    if parsed.tzinfo is None:
        errors.append(f"{label}:issued_at_timezone_missing")
        return None
    return parsed.astimezone(timezone.utc)


def _validate_age(data: dict[str, Any], *, label: str, max_age_days: int,
                  now: datetime, errors: list[str]) -> None:
    issued = _parse_time(data.get("issued_at"), errors, label)
    if issued is None:
        return
    if issued > now + timedelta(minutes=5):
        errors.append(f"{label}:issued_at_in_future")
    if now - issued > timedelta(days=max_age_days):
        errors.append(f"{label}:evidence_expired")


def _validate_artifacts(data: dict[str, Any], *, source: Path, label: str,
                        errors: list[str]) -> list[dict[str, Any]]:
    artifacts = data.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        errors.append(f"{label}:artifacts_missing")
        return []
    verified = []
    for index, item in enumerate(artifacts):
        item_label = f"{label}:artifact[{index}]"
        if not isinstance(item, dict):
            errors.append(f"{item_label}:not_object")
            continue
        raw_path, expected = item.get("path"), item.get("sha256")
        if not isinstance(raw_path, str) or not raw_path:
            errors.append(f"{item_label}:path_missing")
            continue
        if not isinstance(expected, str) or not HEX64.fullmatch(expected.lower()):
            errors.append(f"{item_label}:sha256_invalid")
            continue
        path = Path(raw_path)
        if not path.is_absolute():
            path = source.parent / path
        try:
            actual = _sha256(path.resolve())
        except OSError:
            errors.append(f"{item_label}:file_missing")
            continue
        if actual != expected.lower():
            errors.append(f"{item_label}:sha256_mismatch")
            continue
        verified.append({"path": str(path.resolve()), "sha256": actual})
    return verified


def _validate_common(data: dict[str, Any], *, expected_format: str,
                     source: Path, label: str, max_age_days: int,
                     now: datetime, errors: list[str]) -> list[dict[str, Any]]:
    if data.get("format") != expected_format:
        errors.append(f"{label}:format_invalid")
    if data.get("status") != "passed":
        errors.append(f"{label}:status_not_passed")
    if data.get("environment") != "production":
        errors.append(f"{label}:environment_not_production")
    issuer = data.get("issuer")
    if not _real_string(issuer):
        errors.append(f"{label}:issuer_invalid")
    _validate_age(data, label=label, max_age_days=max_age_days, now=now,
                  errors=errors)
    return _validate_artifacts(data, source=source, label=label, errors=errors)


def _validate_security_summary(data: dict[str, Any], revision: str, source: Path,
                               errors: list[str]) -> list[dict[str, Any]]:
    if data.get("format") != "bianbu-security-release-evidence-v1":
        errors.append("security_summary:format_invalid")
    if data.get("security_scope_status") != "passed":
        errors.append("security_summary:scope_not_passed")
    if data.get("source_revision") != revision:
        errors.append("security_summary:revision_mismatch")
    if data.get("source_dirty") is True:
        errors.append("security_summary:source_dirty")
    evaluation = data.get("evaluation")
    if not isinstance(evaluation, dict) or evaluation.get("ok") is not True:
        errors.append("security_summary:evaluation_not_ok")
    evidence = data.get("evidence")
    if not isinstance(evidence, list):
        errors.append("security_summary:evidence_missing")
        return []
    verified = []
    names = set()
    for index, item in enumerate(evidence):
        label = f"security_summary:evidence[{index}]"
        if not isinstance(item, dict):
            errors.append(f"{label}:not_object")
            continue
        name, expected, size = item.get("name"), item.get("sha256"), item.get("size")
        if (not isinstance(name, str) or not name or Path(name).name != name
                or name in names):
            errors.append(f"{label}:name_invalid")
            continue
        names.add(name)
        if not isinstance(expected, str) or not HEX64.fullmatch(expected.lower()):
            errors.append(f"{label}:sha256_invalid")
            continue
        path = source.parent / name
        try:
            actual, actual_size = _sha256(path), path.stat().st_size
        except OSError:
            errors.append(f"{label}:file_missing")
            continue
        if actual != expected.lower():
            errors.append(f"{label}:sha256_mismatch")
            continue
        if not isinstance(size, int) or size != actual_size:
            errors.append(f"{label}:size_mismatch")
            continue
        verified.append({"path": str(path.resolve()), "sha256": actual})
    missing = sorted(REQUIRED_SECURITY_EVIDENCE - names)
    if missing:
        errors.append("security_summary:required_evidence_missing:" + ",".join(missing))
    return verified


def _milestone_present(values: Any, target: float) -> bool:
    return isinstance(values, list) and any(
        isinstance(v, (int, float)) and abs(float(v) - target) < 1.0
        for v in values)


def _validate_pa_canary(data: Any, *, label: str, min_runs: int,
                        errors: list[str]) -> None:
    if not isinstance(data, dict) or data.get("enabled") is not True:
        errors.append(f"{label}:missing")
        return
    runs, passed, failed = (data.get("runs"), data.get("passed"), data.get("failed"))
    if (not isinstance(runs, int) or not isinstance(passed, int)
            or not isinstance(failed, int) or runs != passed + failed):
        errors.append(f"{label}:counts_invalid")
        return
    if passed < min_runs:
        errors.append(f"{label}:insufficient_runs")
    if failed != 0 or data.get("errors"):
        errors.append(f"{label}:errors_present")
    if data.get("permission_audited_runs") != passed:
        errors.append(f"{label}:permission_audit_incomplete")
    samples = data.get("samples")
    if not isinstance(samples, list) or len(samples) != passed:
        errors.append(f"{label}:samples_invalid")
        return
    run_ids: set[str] = set()
    session_ids: set[str] = set()
    for index, sample in enumerate(samples):
        if not isinstance(sample, dict):
            errors.append(f"{label}:sample_invalid:{index}")
            continue
        run_id = str(sample.get("run_id") or "")
        session_id = str(sample.get("session_id") or "")
        if (not run_id or run_id in run_ids or not session_id
                or session_id in session_ids
                or sample.get("status") != "completed"
                or not isinstance(sample.get("permission_audits"), int)
                or sample.get("permission_audits", 0) < 1):
            errors.append(f"{label}:sample_invalid:{index}")
        run_ids.add(run_id)
        session_ids.add(session_id)


def _validate_soak(data: dict[str, Any], revision: str, source: Path,
                   errors: list[str]) -> tuple[list[dict[str, Any]],
                                               list[dict[str, Any]]]:
    if data.get("format") != "bianbu-security-commercial-soak-v2":
        errors.append("soak:format_invalid")
    if data.get("status") != "passed":
        errors.append("soak:status_not_passed")
    if data.get("source_revision") != revision:
        errors.append("soak:revision_mismatch")
    target = data.get("target_seconds")
    elapsed = data.get("elapsed_seconds")
    if not isinstance(target, (int, float)) or target < MIN_SOAK_SECONDS:
        errors.append("soak:target_too_short")
    if not isinstance(elapsed, (int, float)) or elapsed < MIN_SOAK_SECONDS:
        errors.append("soak:elapsed_too_short")
    for milestone in MILESTONES:
        if not _milestone_present(data.get("completed_milestones"), milestone):
            errors.append(f"soak:milestone_missing:{milestone}")
    if data.get("error_count") != 0 or data.get("errors"):
        errors.append("soak:operation_errors")
    if data.get("failures"):
        errors.append("soak:failures_present")
    if data.get("pending_checks"):
        errors.append("soak:pending_checks_present")
    if data.get("audit_chain_ok") is not True:
        errors.append("soak:audit_chain_failed")
    if (data.get("initial_system_state") != "running"
            or data.get("system_state") != "running"):
        errors.append("soak:system_degraded")
    if (data.get("initial_systemd_transient_units")
            or data.get("systemd_transient_units")):
        errors.append("soak:systemd_transient_units")
    samples, p99, rss = (data.get("latency_samples"),
                         data.get("permission_p99_ms"), data.get("rss_growth_mb"))
    if not isinstance(samples, int) or samples < 100:
        errors.append("soak:insufficient_samples")
    if not isinstance(p99, (int, float)) or p99 > 10.0:
        errors.append("soak:p99_exceeded")
    if not isinstance(rss, (int, float)) or rss > 64.0:
        errors.append("soak:rss_exceeded")
    services, initial = data.get("services"), data.get("initial_services")
    if not isinstance(services, dict) or not isinstance(initial, dict):
        errors.append("soak:services_missing")
    else:
        for unit in ("bianbu-securityd.service", "bianbu-security-webui.service"):
            current, original = services.get(unit), initial.get(unit)
            if not isinstance(current, dict) or current.get("ActiveState") != "active":
                errors.append(f"soak:service_inactive:{unit}")
                continue
            if not isinstance(original, dict) or current.get("NRestarts") != original.get("NRestarts"):
                errors.append(f"soak:service_restarted:{unit}")
    sse = data.get("sse")
    if (not isinstance(sse, dict) or sse.get("connections", 0) < 1
            or sse.get("messages", 0) < 1 or sse.get("reconnects") != 0
            or sse.get("errors")):
        errors.append("soak:sse_unstable")
    _validate_pa_canary(
        data.get("pa_canary"), label="soak:pa_canary",
        min_runs=MIN_PA_CANARY_RUNS,
        errors=errors)
    name, expected, size = (data.get("samples_file"), data.get("samples_sha256"),
                            data.get("samples_size"))
    sample_artifacts: list[dict[str, Any]] = []
    if (not isinstance(name, str) or not name or Path(name).name != name
            or not isinstance(expected, str) or not HEX64.fullmatch(expected.lower())
            or not isinstance(size, int) or size < 1):
        errors.append("soak:samples_metadata_invalid")
    else:
        path = source.parent / name
        try:
            actual, actual_size = _sha256(path), path.stat().st_size
        except OSError:
            errors.append("soak:samples_missing")
        else:
            if actual != expected.lower() or actual_size != size:
                errors.append("soak:samples_integrity_failed")
            else:
                rows = 0
                try:
                    with path.open() as fh:
                        for rows, line in enumerate(fh, start=1):
                            item = json.loads(line)
                            if (not isinstance(item, dict)
                                    or item.get("iteration") != rows - 1
                                    or item.get("ok") is not True):
                                errors.append(f"soak:samples_row_invalid:{rows}")
                                break
                except (OSError, json.JSONDecodeError):
                    errors.append(f"soak:samples_row_invalid:{rows + 1}")
                if (rows != data.get("iterations")
                        or rows != data.get("latency_samples")):
                    errors.append("soak:samples_count_mismatch")
                sample_artifacts.append(
                    {"path": str(path.resolve()), "sha256": actual})
    milestone_artifacts: list[dict[str, Any]] = []
    evidence = data.get("milestone_evidence")
    if not isinstance(evidence, list):
        errors.append("soak:milestone_evidence_missing")
        return sample_artifacts, milestone_artifacts
    by_seconds = {item.get("seconds"): item for item in evidence
                  if isinstance(item, dict)}
    for milestone in MILESTONES:
        item = by_seconds.get(milestone)
        label = f"soak:milestone_evidence:{milestone}"
        if not isinstance(item, dict):
            errors.append(f"{label}:missing")
            continue
        file_name, digest, file_size = (item.get("file"), item.get("sha256"),
                                        item.get("size"))
        if (not isinstance(file_name, str) or Path(file_name).name != file_name
                or not isinstance(digest, str) or not HEX64.fullmatch(digest.lower())
                or not isinstance(file_size, int) or file_size < 1):
            errors.append(f"{label}:metadata_invalid")
            continue
        path = source.parent / file_name
        try:
            actual, actual_size = _sha256(path), path.stat().st_size
            milestone_report = json.loads(path.read_text())
        except (OSError, json.JSONDecodeError):
            errors.append(f"{label}:file_invalid")
            continue
        if actual != digest.lower() or actual_size != file_size:
            errors.append(f"{label}:integrity_failed")
            continue
        if (not isinstance(milestone_report, dict)
                or milestone_report.get("format") != "bianbu-security-commercial-soak-v2"
                or milestone_report.get("source_revision") != revision
                or milestone_report.get("status") != "milestone"
                or milestone_report.get("audit_chain_ok") is not True
                or milestone_report.get("initial_system_state") != "running"
                or milestone_report.get("system_state") != "running"
                or milestone_report.get("initial_systemd_transient_units")
                or milestone_report.get("systemd_transient_units")
                or milestone_report.get("failures")
                or not _milestone_present(
                    milestone_report.get("completed_milestones"), milestone)):
            errors.append(f"{label}:content_invalid")
            continue
        milestone_pa = milestone_report.get("pa_canary")
        required_pa = (milestone_pa.get("required_runs")
                       if isinstance(milestone_pa, dict) else 1)
        if not isinstance(required_pa, int) or required_pa < 1:
            errors.append(f"{label}:pa_required_invalid")
            continue
        before_pa_errors = len(errors)
        _validate_pa_canary(
            milestone_pa, label=f"{label}:pa_canary",
            min_runs=required_pa, errors=errors)
        if len(errors) != before_pa_errors:
            continue
        milestone_artifacts.append(
            {"path": str(path.resolve()), "sha256": actual})
    return sample_artifacts, milestone_artifacts


def _validate_ca(data: dict[str, Any], errors: list[str]) -> None:
    fingerprint = data.get("root_fingerprint_sha256")
    if not isinstance(fingerprint, str) or not HEX64.fullmatch(fingerprint.lower()):
        errors.append("ca:root_fingerprint_invalid")
    tests = data.get("tests")
    if not isinstance(tests, dict):
        errors.append("ca:tests_missing")
        return
    for name in REQUIRED_CA_TESTS:
        if tests.get(name) is not True:
            errors.append(f"ca:test_not_passed:{name}")


def _validate_desktop(data: dict[str, Any], errors: list[str]) -> None:
    for key in ("seat", "session_id"):
        if not _real_string(data.get(key)):
            errors.append(f"desktop:{key}_invalid")
    cases = data.get("cases")
    if not isinstance(cases, dict):
        errors.append("desktop:cases_missing")
        return
    for name in REQUIRED_DESKTOP_CASES:
        if cases.get(name) is not True:
            errors.append(f"desktop:case_not_passed:{name}")


def _validate_pentest(data: dict[str, Any], errors: list[str]) -> None:
    scope = data.get("scope")
    if not isinstance(scope, list) or not REQUIRED_PENTEST_SCOPE.issubset(
            {str(x).lower() for x in scope}):
        errors.append("pentest:scope_incomplete")
    findings = data.get("open_findings")
    if not isinstance(findings, dict):
        errors.append("pentest:findings_missing")
        return
    for severity in ("critical", "high"):
        if findings.get(severity) != 0:
            errors.append(f"pentest:open_{severity}")
    if data.get("unresolved_unaccepted") != 0:
        errors.append("pentest:unresolved_unaccepted")


def _load_public_keys(
        keys_dir: Path, errors: list[str]) -> list[tuple[str, Ed25519PublicKey, bytes]]:
    revoked_path = keys_dir / "revoked.list"
    try:
        revoked = {line.strip() for line in revoked_path.read_text().splitlines()
                   if line.strip() and not line.lstrip().startswith("#")}
    except OSError:
        revoked = set()
    keys = []
    for path in sorted(keys_dir.glob("*.pub")):
        if path.name in revoked:
            continue
        try:
            raw = bytes.fromhex(path.read_text().strip())
            if len(raw) != 32:
                raise ValueError
            keys.append((path.name, Ed25519PublicKey.from_public_bytes(raw), raw))
        except (OSError, ValueError):
            errors.append(f"approval:key_invalid:{path.name}")
    if not keys:
        errors.append("approval:no_usable_keys")
    return keys


def _verify_approval_signature(approval_path: Path, signature_path: Path,
                               keys_dir: Path,
                               errors: list[str]) -> tuple[str, str]:
    try:
        signature = bytes.fromhex(signature_path.read_text().strip())
    except (OSError, ValueError):
        errors.append("approval:signature_invalid")
        return "", ""
    if len(signature) != 64:
        errors.append("approval:signature_invalid")
        return "", ""
    try:
        payload = approval_path.read_bytes()
    except OSError:
        errors.append("approval:payload_missing")
        return "", ""
    keys = _load_public_keys(keys_dir, errors)
    for key_id, key, raw in keys:
        try:
            key.verify(signature, payload)
            return key_id, raw.hex()
        except InvalidSignature:
            continue
    if keys:
        errors.append("approval:signature_untrusted")
    return "", ""


def _validate_approval(data: dict[str, Any], *, revision: str,
                       evidence_paths: dict[str, Path], errors: list[str]) -> None:
    if data.get("format") != "bianbu-security-release-approval-v1":
        errors.append("approval:format_invalid")
    if data.get("approved") is not True:
        errors.append("approval:not_approved")
    if data.get("source_revision") != revision:
        errors.append("approval:revision_mismatch")
    tag = data.get("release_tag")
    if not _real_string(tag) or len(tag.strip()) < 3:
        errors.append("approval:release_tag_invalid")
    if not _real_string(data.get("change_request")):
        errors.append("approval:change_request_invalid")
    approvers = data.get("approvers")
    normalized_approvers = ({str(x).strip().casefold() for x in approvers
                             if _real_string(x)}
                            if isinstance(approvers, list) else set())
    if len(normalized_approvers) < 2:
        errors.append("approval:four_eyes_missing")
    if isinstance(approvers, list) and any(not _real_string(x) for x in approvers):
        errors.append("approval:approver_invalid")
    expected_hashes = data.get("evidence_sha256")
    if not isinstance(expected_hashes, dict):
        errors.append("approval:evidence_hashes_missing")
        return
    for label, path in evidence_paths.items():
        expected = expected_hashes.get(label)
        actual = _sha256(path)
        if expected != actual:
            errors.append(f"approval:evidence_hash_mismatch:{label}")


def evaluate(*, revision: str, security_summary_path: Path, soak_path: Path,
             ca_path: Path, desktop_path: Path, pentest_path: Path,
             approval_path: Path, signature_path: Path, keys_dir: Path,
             max_age_days: int, now: datetime | None = None) -> dict[str, Any]:
    errors: list[str] = []
    now = now or datetime.now(timezone.utc)
    paths = {
        "security_summary": security_summary_path,
        "soak_report": soak_path,
        "ca_evidence": ca_path,
        "desktop_evidence": desktop_path,
        "pentest_evidence": pentest_path,
    }
    security = _load_json(security_summary_path, errors, "security_summary")
    soak = _load_json(soak_path, errors, "soak")
    ca = _load_json(ca_path, errors, "ca")
    desktop = _load_json(desktop_path, errors, "desktop")
    pentest = _load_json(pentest_path, errors, "pentest")
    approval = _load_json(approval_path, errors, "approval")
    security_artifacts = _validate_security_summary(
        security, revision, security_summary_path, errors)
    soak_samples, soak_milestones = _validate_soak(
        soak, revision, soak_path, errors)
    verified_artifacts = {
        "security_release": security_artifacts,
        "soak_samples": soak_samples,
        "soak_milestones": soak_milestones,
        "ca": _validate_common(
            ca, expected_format="bianbu-security-ca-evidence-v1", source=ca_path,
            label="ca", max_age_days=max_age_days, now=now, errors=errors),
        "desktop": _validate_common(
            desktop, expected_format="bianbu-security-desktop-evidence-v1",
            source=desktop_path, label="desktop", max_age_days=max_age_days,
            now=now, errors=errors),
        "pentest": _validate_common(
            pentest, expected_format="bianbu-security-pentest-evidence-v1",
            source=pentest_path, label="pentest", max_age_days=max_age_days,
            now=now, errors=errors),
    }
    _validate_ca(ca, errors)
    _validate_desktop(desktop, errors)
    _validate_pentest(pentest, errors)
    _validate_age(approval, label="approval", max_age_days=max_age_days,
                  now=now, errors=errors)
    _validate_approval(approval, revision=revision, evidence_paths=paths, errors=errors)
    signer, signer_public_key = _verify_approval_signature(
        approval_path, signature_path, keys_dir, errors)
    return {
        "format": FORMAT,
        "status": "passed" if not errors else "failed",
        "source_revision": revision,
        "evaluated_at": now.isoformat(),
        "signer_key_id": signer,
        "signer_public_key": signer_public_key,
        "errors": errors,
        "evidence_sha256": {label: _sha256(path) for label, path in paths.items()},
        "approval_sha256": _sha256(approval_path),
        "approval_signature_sha256": _sha256(signature_path),
        "verified_artifacts": verified_artifacts,
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--source-revision", required=True)
    ap.add_argument("--security-summary", required=True)
    ap.add_argument("--soak-report", required=True)
    ap.add_argument("--ca-evidence", required=True)
    ap.add_argument("--desktop-evidence", required=True)
    ap.add_argument("--pentest-evidence", required=True)
    ap.add_argument("--approval", required=True)
    ap.add_argument("--approval-signature", required=True)
    ap.add_argument("--approval-keys-dir", required=True)
    ap.add_argument("--output-dir", required=True)
    ap.add_argument("--max-evidence-age-days", type=int, default=180)
    args = ap.parse_args(argv)
    if args.max_evidence_age_days <= 0:
        ap.error("max evidence age must be positive")
    output = Path(args.output_dir).resolve()
    if output.exists() and any(output.iterdir()):
        print(f"COMMERCIAL_ACCEPTANCE_FAIL output_dir_not_empty={output}")
        return 2
    output.mkdir(parents=True, exist_ok=True)
    inputs = {
        "security-summary.json": Path(args.security_summary).resolve(),
        "soak-report.json": Path(args.soak_report).resolve(),
        "ca-evidence.json": Path(args.ca_evidence).resolve(),
        "desktop-evidence.json": Path(args.desktop_evidence).resolve(),
        "pentest-evidence.json": Path(args.pentest_evidence).resolve(),
        "release-approval.json": Path(args.approval).resolve(),
        "release-approval.sig": Path(args.approval_signature).resolve(),
    }
    try:
        result = evaluate(
            revision=args.source_revision,
            security_summary_path=inputs["security-summary.json"],
            soak_path=inputs["soak-report.json"], ca_path=inputs["ca-evidence.json"],
            desktop_path=inputs["desktop-evidence.json"],
            pentest_path=inputs["pentest-evidence.json"],
            approval_path=inputs["release-approval.json"],
            signature_path=inputs["release-approval.sig"],
            keys_dir=Path(args.approval_keys_dir).resolve(),
            max_age_days=args.max_evidence_age_days)
    except OSError as exc:
        result = {"format": FORMAT, "status": "failed",
                  "source_revision": args.source_revision,
                  "evaluated_at": datetime.now(timezone.utc).isoformat(),
                  "errors": [f"input_error:{exc}"]}
    if result["status"] != "passed":
        summary = output / "commercial-acceptance-summary.json"
        summary.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n")
        print("COMMERCIAL_ACCEPTANCE_FAIL errors=" + ",".join(result["errors"]))
        return 1
    for name, path in inputs.items():
        target = output / name
        shutil.copy2(path, target)
        expected = (result["evidence_sha256"].get(name.removesuffix(".json").replace(
            "-", "_")) if name.endswith(".json") else None)
        if name == "release-approval.json":
            expected = result["approval_sha256"]
        elif name == "release-approval.sig":
            expected = result["approval_signature_sha256"]
        if expected and _sha256(target) != expected:
            result["status"] = "failed"
            result["errors"].append(f"archive:source_changed:{name}")
    archived_artifacts: dict[str, list[dict[str, str]]] = {}
    for label, items in result["verified_artifacts"].items():
        destination = output / "artifacts" / label
        destination.mkdir(parents=True, exist_ok=True)
        archived_artifacts[label] = []
        for index, item in enumerate(items):
            source = Path(item["path"])
            target = destination / f"{index:02d}-{source.name}"
            shutil.copy2(source, target)
            if _sha256(target) != item["sha256"]:
                result["status"] = "failed"
                result["errors"].append(
                    f"archive:artifact_changed:{label}:{index}")
            archived_artifacts[label].append({
                "path": str(target.relative_to(output)), "sha256": item["sha256"]})
    signer_target = output / "approval-signer.pub"
    signer_target.write_text(result.pop("signer_public_key") + "\n")
    result["signer_public_key_sha256"] = _sha256(signer_target)
    revoked = Path(args.approval_keys_dir).resolve() / "revoked.list"
    if revoked.is_file():
        shutil.copy2(revoked, output / "approval-revoked.list")
        result["approval_revoked_list_sha256"] = _sha256(
            output / "approval-revoked.list")
    result["archived_artifacts"] = archived_artifacts
    summary = output / "commercial-acceptance-summary.json"
    summary.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n")
    if result["status"] != "passed":
        print("COMMERCIAL_ACCEPTANCE_FAIL errors=" + ",".join(result["errors"]))
        return 1
    print(f"COMMERCIAL_ACCEPTANCE_PASS revision={args.source_revision} "
          f"signer={result['signer_key_id']} evidence={output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
