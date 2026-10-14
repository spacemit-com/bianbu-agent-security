from __future__ import annotations

import hashlib
import importlib.util
import json
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def _module():
    path = Path(__file__).resolve().parents[2] / "deploy/commercial_acceptance_gate.py"
    spec = importlib.util.spec_from_file_location("bnsec_commercial_acceptance", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write(path: Path, data: dict) -> Path:
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n")
    return path


def _bundle(tmp_path: Path, revision: str = "abc123") -> dict[str, Path | str]:
    now = datetime.now(timezone.utc).isoformat()
    logs = {}
    for name in ("ca", "desktop", "pentest"):
        log = tmp_path / f"{name}.log"
        log.write_text(f"{name} evidence\n")
        logs[name] = log
    security_artifacts = []
    for name in ("unit.xml", "integration.xml", "e2e.xml", "doctor.json",
                 "sbom.json", "cve-report.json", "release-manifest.json",
                 "verify-all.log"):
        artifact = tmp_path / name
        artifact.write_text(f"{name} evidence\n")
        security_artifacts.append({
            "name": name, "size": artifact.stat().st_size, "sha256": _sha(artifact)})
    security = _write(tmp_path / "security.json", {
        "format": "bianbu-security-release-evidence-v1",
        "security_scope_status": "passed", "source_revision": revision,
        "source_dirty": None, "evaluation": {"ok": True},
        "evidence": security_artifacts,
    })
    samples = tmp_path / "soak.samples.jsonl"
    samples.write_text("".join(
        json.dumps({"iteration": index, "ok": True}) + "\n" for index in range(100)))
    pa_samples = [{
        "at": now,
        "run_id": f"run-{index}",
        "session_id": f"session-{index}",
        "status": "completed",
        "duration_seconds": 10.0,
        "total_tokens": 20,
        "token_accounted": True,
        "permission_audits": 1,
    } for index in range(12)]
    milestone_evidence = []
    for milestone in (86400, 259200):
        pa_count = 4 if milestone == 86400 else 12
        milestone_path = tmp_path / f"soak.milestone-{milestone}s.json"
        _write(milestone_path, {
            "format": "bianbu-security-commercial-soak-v2",
            "status": "milestone", "source_revision": revision,
            "audit_chain_ok": True, "failures": [],
            "initial_system_state": "running", "system_state": "running",
            "initial_systemd_transient_units": [], "systemd_transient_units": [],
            "completed_milestones": [x for x in (86400, 259200) if x <= milestone],
            "pa_canary": {
                "enabled": True, "required_runs": pa_count,
                "runs": pa_count, "passed": pa_count, "failed": 0,
                "total_tokens": pa_count * 20,
                "token_accounted_runs": pa_count,
                "permission_audited_runs": pa_count,
                "samples": pa_samples[:pa_count], "errors": [],
            },
        })
        milestone_evidence.append({
            "seconds": milestone, "file": milestone_path.name,
            "size": milestone_path.stat().st_size, "sha256": _sha(milestone_path),
        })
    soak = _write(tmp_path / "soak.json", {
        "format": "bianbu-security-commercial-soak-v2", "status": "passed",
        "source_revision": revision, "target_seconds": 259200,
        "elapsed_seconds": 259220, "completed_milestones": [86400.0, 259200.0],
        "error_count": 0, "errors": [], "failures": [], "pending_checks": [],
        "audit_chain_ok": True, "latency_samples": 100, "iterations": 100,
        "initial_system_state": "running", "system_state": "running",
        "initial_systemd_transient_units": [], "systemd_transient_units": [],
        "permission_p99_ms": 4.2, "rss_growth_mb": 3.0,
        "samples_file": samples.name, "samples_size": samples.stat().st_size,
        "samples_sha256": _sha(samples),
        "milestone_evidence": milestone_evidence,
        "initial_services": {
            "bianbu-securityd.service": {"NRestarts": "0"},
            "bianbu-security-webui.service": {"NRestarts": "0"},
        },
        "services": {
            "bianbu-securityd.service": {"ActiveState": "active", "NRestarts": "0"},
            "bianbu-security-webui.service": {"ActiveState": "active", "NRestarts": "0"},
        },
        "sse": {"connections": 1, "messages": 12, "reconnects": 0, "errors": []},
        "pa_canary": {
            "enabled": True, "required_runs": 12,
            "runs": 12, "passed": 12, "failed": 0,
            "total_tokens": 240, "token_accounted_runs": 12,
            "permission_audited_runs": 12,
            "samples": pa_samples, "errors": [],
        },
    })
    ca = _write(tmp_path / "ca.json", {
        "format": "bianbu-security-ca-evidence-v1", "status": "passed",
        "environment": "production", "issued_at": now, "issuer": "PKI team",
        "root_fingerprint_sha256": "a" * 64,
        "tests": {name: True for name in ("install", "rotation", "revocation", "recovery")},
        "artifacts": [{"path": logs["ca"].name, "sha256": _sha(logs["ca"])}],
    })
    desktop = _write(tmp_path / "desktop.json", {
        "format": "bianbu-security-desktop-evidence-v1", "status": "passed",
        "environment": "production", "issued_at": now, "issuer": "Desktop QA",
        "seat": "seat0", "session_id": "42",
        "cases": {name: True for name in ("allow", "deny", "expired", "replay")},
        "artifacts": [{"path": logs["desktop"].name,
                       "sha256": _sha(logs["desktop"])}],
    })
    pentest = _write(tmp_path / "pentest.json", {
        "format": "bianbu-security-pentest-evidence-v1", "status": "passed",
        "environment": "production", "issued_at": now, "issuer": "External Lab",
        "scope": ["securityd", "webui", "dbus", "uds"],
        "open_findings": {"critical": 0, "high": 0, "medium": 1, "low": 2},
        "unresolved_unaccepted": 0,
        "artifacts": [{"path": logs["pentest"].name,
                       "sha256": _sha(logs["pentest"])}],
    })
    evidence = {
        "security_summary": security, "soak_report": soak, "ca_evidence": ca,
        "desktop_evidence": desktop, "pentest_evidence": pentest,
    }
    approval = _write(tmp_path / "approval.json", {
        "format": "bianbu-security-release-approval-v1", "approved": True,
        "source_revision": revision, "release_tag": "v1.0.0",
        "change_request": "CR-2026-001", "approvers": ["security-lead", "qa-lead"],
        "issued_at": now,
        "evidence_sha256": {name: _sha(path) for name, path in evidence.items()},
    })
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    keys = tmp_path / "approval-keys"
    keys.mkdir()
    (keys / "release.pub").write_text(public.hex() + "\n")
    signature = tmp_path / "approval.sig"
    signature.write_text(private.sign(approval.read_bytes()).hex() + "\n")
    return {"revision": revision, "security": security, "soak": soak, "ca": ca,
            "desktop": desktop, "pentest": pentest, "approval": approval,
            "signature": signature, "keys": keys}


def _evaluate(module, bundle):
    return module.evaluate(
        revision=bundle["revision"], security_summary_path=bundle["security"],
        soak_path=bundle["soak"], ca_path=bundle["ca"],
        desktop_path=bundle["desktop"], pentest_path=bundle["pentest"],
        approval_path=bundle["approval"], signature_path=bundle["signature"],
        keys_dir=bundle["keys"], max_age_days=180)


def test_commercial_acceptance_passes_complete_signed_bundle(tmp_path):
    result = _evaluate(_module(), _bundle(tmp_path))
    assert result["status"] == "passed"
    assert result["signer_key_id"] == "release.pub"
    assert result["errors"] == []


def test_commercial_acceptance_cli_archives_exact_evidence(tmp_path):
    module, bundle = _module(), _bundle(tmp_path)
    output = tmp_path / "acceptance"
    rc = module.main([
        "--source-revision", bundle["revision"],
        "--security-summary", str(bundle["security"]),
        "--soak-report", str(bundle["soak"]),
        "--ca-evidence", str(bundle["ca"]),
        "--desktop-evidence", str(bundle["desktop"]),
        "--pentest-evidence", str(bundle["pentest"]),
        "--approval", str(bundle["approval"]),
        "--approval-signature", str(bundle["signature"]),
        "--approval-keys-dir", str(bundle["keys"]),
        "--output-dir", str(output),
    ])
    assert rc == 0
    summary = json.loads((output / "commercial-acceptance-summary.json").read_text())
    assert summary["status"] == "passed"
    assert _sha(output / "soak-report.json") == _sha(bundle["soak"])
    assert _sha(output / "approval-signer.pub") == summary["signer_public_key_sha256"]
    assert (output / summary["archived_artifacts"]["pentest"][0]["path"]).is_file()
    assert len(summary["archived_artifacts"]["security_release"]) == 8
    assert len(summary["archived_artifacts"]["soak_samples"]) == 1
    assert len(summary["archived_artifacts"]["soak_milestones"]) == 2


def test_commercial_acceptance_rejects_short_soak(tmp_path):
    module, bundle = _module(), _bundle(tmp_path)
    data = json.loads(bundle["soak"].read_text())
    data["status"], data["target_seconds"] = "running", 3600
    _write(bundle["soak"], data)
    result = _evaluate(module, bundle)
    assert "soak:status_not_passed" in result["errors"]
    assert "soak:target_too_short" in result["errors"]
    assert "approval:evidence_hash_mismatch:soak_report" in result["errors"]


def test_commercial_acceptance_rejects_security_only_soak(tmp_path):
    module, bundle = _module(), _bundle(tmp_path)
    data = json.loads(bundle["soak"].read_text())
    data.pop("pa_canary")
    _write(bundle["soak"], data)
    result = _evaluate(module, bundle)
    assert "soak:pa_canary:missing" in result["errors"]
    assert "approval:evidence_hash_mismatch:soak_report" in result["errors"]


def test_commercial_acceptance_rejects_degraded_system_soak(tmp_path):
    module, bundle = _module(), _bundle(tmp_path)
    data = json.loads(bundle["soak"].read_text())
    data["system_state"] = "degraded"
    _write(bundle["soak"], data)
    result = _evaluate(module, bundle)
    assert "soak:system_degraded" in result["errors"]
    assert "approval:evidence_hash_mismatch:soak_report" in result["errors"]


def test_commercial_acceptance_rejects_transient_systemd_soak(tmp_path):
    module, bundle = _module(), _bundle(tmp_path)
    data = json.loads(bundle["soak"].read_text())
    data["systemd_transient_units"] = ["hermes-agent.service"]
    _write(bundle["soak"], data)
    result = _evaluate(module, bundle)
    assert "soak:systemd_transient_units" in result["errors"]
    assert "approval:evidence_hash_mismatch:soak_report" in result["errors"]


def test_commercial_acceptance_rejects_high_pentest_finding(tmp_path):
    module, bundle = _module(), _bundle(tmp_path)
    data = json.loads(bundle["pentest"].read_text())
    data["open_findings"]["high"] = 1
    _write(bundle["pentest"], data)
    result = _evaluate(module, bundle)
    assert "pentest:open_high" in result["errors"]


def test_commercial_acceptance_rejects_single_approver_and_bad_signature(tmp_path):
    module, bundle = _module(), _bundle(tmp_path)
    data = json.loads(bundle["approval"].read_text())
    data["approvers"] = ["security-lead", "REPLACE_WITH_QA_APPROVER"]
    _write(bundle["approval"], data)
    result = _evaluate(module, bundle)
    assert "approval:four_eyes_missing" in result["errors"]
    assert "approval:approver_invalid" in result["errors"]
    assert "approval:signature_untrusted" in result["errors"]


def test_commercial_acceptance_rejects_revoked_approval_key(tmp_path):
    module, bundle = _module(), _bundle(tmp_path)
    (bundle["keys"] / "revoked.list").write_text("release.pub\n")
    result = _evaluate(module, bundle)
    assert "approval:no_usable_keys" in result["errors"]
    assert result["status"] == "failed"
