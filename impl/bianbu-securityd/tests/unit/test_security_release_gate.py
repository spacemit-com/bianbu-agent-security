from __future__ import annotations

import importlib.util
from pathlib import Path
import subprocess


def _module():
    path = Path(__file__).resolve().parents[2] / "deploy/security_release_gate.py"
    spec = importlib.util.spec_from_file_location("bnsec_security_release_gate", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _pass_log(tail: str) -> str:
    module = _module()
    return "\n".join(sorted(module.REQUIRED_PASS_MARKERS) + [tail])


def test_full_product_strict_pass_is_security_release_pass():
    module = _module()
    result = module.evaluate_strict_result(
        0, _pass_log("BNSEC_VERIFY_ALL_STRICT_PASS repo_gates=passed"), {"errors": []})
    assert result == {"ok": True, "product_status": "passed", "external_gates": []}


def test_only_runtime_external_gates_may_remain():
    module = _module()
    doctor = {"errors": [
        {"name": "network_enforcement"}, {"name": "runtime_identity_matrix"},
    ]}
    result = module.evaluate_strict_result(
        1, _pass_log("BNSEC_VERIFY_ALL_STRICT_FAIL gates=doctor,runtime_production"),
        doctor)
    assert result["ok"] is True
    assert result["product_status"] == "blocked_external"
    assert result["external_gates"] == ["doctor", "runtime_production"]


def test_unexpected_repository_gate_never_gets_waived():
    module = _module()
    result = module.evaluate_strict_result(
        1, _pass_log("BNSEC_VERIFY_ALL_STRICT_FAIL gates=unit,runtime_production"),
        {"errors": []})
    assert result["ok"] is False
    assert result["reason"] == "security_gate_failed"


def test_non_runtime_doctor_error_never_gets_waived():
    module = _module()
    result = module.evaluate_strict_result(
        1, _pass_log("BNSEC_VERIFY_ALL_STRICT_FAIL gates=doctor,runtime_production"),
        {"errors": [{"name": "webui_auth"}]})
    assert result["ok"] is False
    assert result["reason"] == "security_doctor_failed"


def test_required_evidence_marker_cannot_be_omitted():
    module = _module()
    log = _pass_log("BNSEC_VERIFY_ALL_STRICT_FAIL gates=runtime_production")
    log = log.replace("CVE_SCAN_PASS vulnerabilities=0", "")
    result = module.evaluate_strict_result(1, log, {"errors": []})
    assert result["ok"] is False
    assert result["reason"] == "missing_pass_markers"


def test_ci_entry_runs_security_release_gate():
    root = Path(__file__).resolve().parents[2]
    script = root / ".ci/run_tests.sh"
    cp = subprocess.run(["bash", "-n", str(script)], capture_output=True, text=True)
    assert cp.returncode == 0, cp.stderr
    text = script.read_text()
    assert "security_release_gate.py" in text
    assert "BNSEC_SOURCE_REVISION" in text
    assert "BNSEC_EVIDENCE_DIR" in text
