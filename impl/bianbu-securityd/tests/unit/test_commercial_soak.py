from __future__ import annotations

import importlib.util
from datetime import date
from pathlib import Path
import subprocess

import pytest


def _module():
    path = Path(__file__).resolve().parents[2] / "deploy/commercial_soak.py"
    spec = importlib.util.spec_from_file_location("bnsec_commercial_soak", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_percentile_uses_nearest_rank():
    module = _module()
    values = [float(x) for x in range(1, 101)]
    assert module._percentile(values, 0.99) == 99.0


def test_env_parser_does_not_require_shell_evaluation(tmp_path):
    module = _module()
    env = tmp_path / "webui.env"
    env.write_text("# comment\nBIANBU_WEBUI_TOKEN='secret value'\nEMPTY=\n")
    assert module._parse_env_file(env) == {
        "BIANBU_WEBUI_TOKEN": "secret value", "EMPTY": ""}


def test_commercial_soak_prepares_new_output_directory(tmp_path):
    module = _module()
    output = tmp_path / "new" / "run" / "report.json"
    samples = module._prepare_output(output)
    assert output.parent.is_dir()
    assert samples == output.parent / "report.samples.jsonl"

    samples.write_text("reserved")
    with pytest.raises(FileExistsError):
        module._prepare_output(output)


def test_commercial_evaluation_accepts_healthy_security_scope():
    module = _module()
    report = {
        "error_count": 0,
        "latency_samples": 100,
        "permission_p99_ms": 3.0,
        "rss_growth_mb": 2.0,
        "audit_chain_ok": True,
        "services": {
            "bianbu-securityd.service": {"ActiveState": "active"},
            "bianbu-security-webui.service": {"ActiveState": "active"},
        },
        "initial_system_state": "running", "system_state": "running",
        "initial_systemd_transient_units": [], "systemd_transient_units": [],
        "sse": {"alive": True, "connections": 1, "messages": 2,
                "reconnects": 0, "errors": []},
        "pa_canary": {
            "enabled": True, "required_runs": 1, "passed": 1, "failed": 0,
            "errors": [],
            "permission_audited_runs": 1,
        },
    }
    assert module._evaluate(report, max_p99_ms=10, max_rss_growth_mb=64) == []


def test_commercial_evaluation_reports_every_failed_dimension():
    module = _module()
    report = {
        "error_count": 1,
        "latency_samples": 100,
        "permission_p99_ms": 11.0,
        "rss_growth_mb": 65.0,
        "audit_chain_ok": False,
        "services": {"bianbu-securityd.service": {"ActiveState": "failed"}},
        "initial_system_state": "degraded", "system_state": "degraded",
        "initial_systemd_transient_units": ["hermes-agent.service"],
        "systemd_transient_units": ["hermes-agent.service"],
        "sse": {"alive": False, "connections": 1, "messages": 1,
                "reconnects": 1, "errors": ["closed"]},
        "pa_canary": {
            "enabled": True, "required_runs": 1, "passed": 0, "failed": 1,
            "errors": [{"error": "PA unavailable"}],
            "permission_audited_runs": 0,
        },
    }
    failures = module._evaluate(report, max_p99_ms=10, max_rss_growth_mb=64)
    assert set(failures) == {
        "operation_errors", "permission_p99", "rss_growth", "audit_chain",
        "service:bianbu-securityd.service", "sse_stability",
        "pa_canary_samples", "pa_canary_errors", "system_degraded",
        "systemd_transient_units",
    }


def test_commercial_evaluation_requires_enough_latency_samples():
    module = _module()
    report = {
        "error_count": 0, "latency_samples": 2,
        "permission_p99_ms": 3.0, "rss_growth_mb": 1.0,
        "audit_chain_ok": True,
        "services": {"security": {"ActiveState": "active"}},
        "initial_system_state": "running", "system_state": "running",
        "initial_systemd_transient_units": [], "systemd_transient_units": [],
        "sse": {"connections": 1, "messages": 1, "reconnects": 0, "errors": []},
        "pa_canary": {
            "enabled": True, "required_runs": 1, "passed": 1, "failed": 0,
            "errors": [],
            "permission_audited_runs": 1,
        },
    }
    assert module._evaluate(
        report, max_p99_ms=10, max_rss_growth_mb=64,
        min_latency_samples=100) == ["insufficient_latency_samples"]


def test_commercial_evaluation_rejects_missing_pa_canary():
    module = _module()
    report = {
        "error_count": 0, "latency_samples": 100,
        "permission_p99_ms": 3.0, "rss_growth_mb": 1.0,
        "audit_chain_ok": True,
        "services": {"security": {"ActiveState": "active"}},
        "initial_system_state": "running", "system_state": "running",
        "sse": {"connections": 1, "messages": 1, "reconnects": 0, "errors": []},
    }
    assert module._evaluate(
        report, max_p99_ms=10, max_rss_growth_mb=64) == ["pa_canary_missing"]


def test_running_report_marks_deferred_checks_pending():
    module = _module()
    failures, pending = module._split_pending(
        "running", ["insufficient_latency_samples", "permission_p99",
                    "audit_chain", "operation_errors"])
    assert failures == ["operation_errors"]
    assert pending == ["insufficient_latency_samples", "permission_p99", "audit_chain"]
    assert module._split_pending("running", ["permission_p99"]) == (
        ["permission_p99"], [])
    assert module._split_pending("running", ["pa_canary_samples"]) == (
        [], ["pa_canary_samples"])


def test_commercial_soak_pins_production_uds_by_default():
    path = Path(__file__).resolve().parents[2] / "deploy/commercial_soak.py"
    text = path.read_text()
    assert 'default="/run/bianbu/securityd.sock"' in text
    assert "UdsClient(args.uds_socket" in text
    assert 'report["samples_sha256"] = _sha256(samples_path)' in text
    assert 'report["milestone_evidence"] = []' in text
    assert '"format": "bianbu-security-commercial-soak-v2"' in text
    assert "PACanaryMonitor" in text


def test_commercial_soak_launcher_detaches_and_tracks_pid():
    root = Path(__file__).resolve().parents[2]
    script = root / "deploy/start_commercial_soak.sh"
    cp = subprocess.run(["bash", "-n", str(script)], capture_output=True, text=True)
    assert cp.returncode == 0, cp.stderr
    text = script.read_text()
    for marker in ("setsid", "</dev/null", "current.pid", "current-run",
                   "SOAK_MILESTONE_SECONDS", "commercial_soak.py",
                   "pending_checks", "SOAK_PA_INTERVAL_SECONDS",
                   "SOAK_MIN_PA_RUNS", "is-system-running",
                   "systemd_transient_units"):
        assert marker in text
