#!/usr/bin/env python3
"""生产 Security/WebUI/Personal Agent 24/72 小时耐久验证。

默认运行 72 小时，并在 24/72 小时生成里程碑报告。脚本持续验证真实系统总线判权、
审计、UDS、WebUI 健康、SSE 长连接、systemd 服务状态与 RSS；同时周期性驱动真实 PA
完成模型、MCP 工具和判权审计闭环。报告采用原子写入，进程被中断时仍
保留最近进度。该脚本不测试范围外 Runtime。
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import signal
import statistics
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def _percentile(values: list[float], percentile: float) -> float:
    if not values:
        return float("inf")
    ordered = sorted(values)
    rank = max(0, min(len(ordered) - 1,
                      int(len(ordered) * percentile + 0.999999) - 1))
    return ordered[rank]


def _parse_env_file(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.is_file():
        return values
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip().strip('"').strip("'")
    return values


def _systemd_state(unit: str) -> dict[str, str]:
    cp = subprocess.run([
        "systemctl", "show", unit,
        "--property=ActiveState,NRestarts,MainPID,MemoryCurrent",
    ], capture_output=True, text=True, check=False, timeout=10)
    values = {"_returncode": str(cp.returncode)}
    for line in cp.stdout.splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            values[key] = value
    return values


def _system_state() -> str:
    cp = subprocess.run(
        ["systemctl", "is-system-running"], capture_output=True, text=True,
        check=False, timeout=10)
    return cp.stdout.strip() or "unknown"


def _systemd_transient_units() -> list[str]:
    cp = subprocess.run(
        ["systemctl", "list-units", "--type=service",
         "--state=activating,failed", "--no-legend", "--plain", "--no-pager"],
        capture_output=True, text=True, check=False, timeout=10)
    return sorted({line.split()[0] for line in cp.stdout.splitlines()
                   if line.split()})


def _atomic_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(path.name + ".tmp")
    temp.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n")
    os.replace(temp, path)


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _prepare_output(output: Path) -> Path:
    """创建报告目录并返回同目录的原始样本路径。"""
    output.parent.mkdir(parents=True, exist_ok=True)
    samples = output.with_name(output.stem + ".samples.jsonl")
    if output.exists() or samples.exists():
        raise FileExistsError(output)
    return samples


class SSEMonitor:
    def __init__(self, url: str, token: str):
        self.url = url
        self.token = token
        self.stop_event = threading.Event()
        self.thread = threading.Thread(target=self._run, name="bnsec-sse-soak", daemon=True)
        self.connections = 0
        self.reconnects = 0
        self.messages = 0
        self.last_message_at = ""
        self.errors: list[str] = []
        self._response = None
        self._response_lock = threading.Lock()

    def start(self) -> None:
        self.thread.start()

    def stop(self) -> None:
        self.stop_event.set()
        with self._response_lock:
            if self._response is not None:
                self._response.close()
        self.thread.join(timeout=45)

    def _run(self) -> None:
        while not self.stop_event.is_set():
            request = urllib.request.Request(
                self.url, headers={"Authorization": f"Bearer {self.token}"})
            try:
                with urllib.request.urlopen(request, timeout=40) as response:
                    with self._response_lock:
                        self._response = response
                    self.connections += 1
                    if self.connections > 1:
                        self.reconnects += 1
                    for raw in response:
                        if self.stop_event.is_set():
                            return
                        line = raw.decode("utf-8", errors="replace").strip()
                        if line.startswith("data:") or line.startswith(":"):
                            self.messages += 1
                            self.last_message_at = datetime.now(timezone.utc).isoformat()
                with self._response_lock:
                    self._response = None
                if not self.stop_event.is_set():
                    self.errors.append("SSE stream closed")
            except Exception as exc:  # noqa: BLE001
                with self._response_lock:
                    self._response = None
                if not self.stop_event.is_set():
                    self.errors.append(repr(exc))
            self.stop_event.wait(2.0)

    def snapshot(self) -> dict[str, Any]:
        return {
            "connections": self.connections,
            "reconnects": self.reconnects,
            "messages": self.messages,
            "last_message_at": self.last_message_at,
            "errors": self.errors[-20:],
            "alive": self.thread.is_alive(),
        }


def _http_json(method: str, url: str, body: dict[str, Any] | None = None,
               timeout: float = 30.0) -> dict[str, Any]:
    payload = json.dumps(body).encode() if body is not None else None
    request = urllib.request.Request(
        url, data=payload, headers={"Content-Type": "application/json"},
        method=method)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read().decode("utf-8")
            if response.status < 200 or response.status >= 300:
                raise RuntimeError(f"PA HTTP {response.status}: {raw[:200]}")
            value = json.loads(raw) if raw else {}
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"PA HTTP {exc.code}: {raw[:200]}") from exc
    if not isinstance(value, dict):
        raise RuntimeError("PA response is not an object")
    return value


def _agent_audit_records(sec, agent_id: str, *, from_ts: str = "") -> list[dict[str, Any]]:
    audit_filter = {"agent_id": agent_id}
    if from_ts:
        audit_filter["from"] = from_ts
    path = Path(str(sec.ExportAudit(json.dumps(audit_filter), "json")))
    value = json.loads(path.read_text())
    rows = value.get("records")
    if not isinstance(rows, list):
        raise RuntimeError("PA audit export has no records")
    return [row for row in rows if isinstance(row, dict)]


class PACanaryMonitor:
    """周期性执行真实 PA 模型/工具调用，并核验判权审计。"""

    def __init__(self, *, url: str, agent_id: str, security_agent_id: str,
                 interval_seconds: float, run_timeout_seconds: float,
                 min_runs: int):
        self.url = url.rstrip("/")
        self.agent_id = agent_id
        self.security_agent_id = security_agent_id
        self.interval_seconds = interval_seconds
        self.run_timeout_seconds = run_timeout_seconds
        self.min_runs = min_runs
        self.stop_event = threading.Event()
        self.thread = threading.Thread(
            target=self._run, name="bnsec-pa-soak", daemon=True)
        self._lock = threading.Lock()
        self._samples: list[dict[str, Any]] = []
        self._errors: list[dict[str, Any]] = []

    def start(self) -> None:
        self.thread.start()

    def stop(self) -> None:
        self.stop_event.set()
        self.thread.join(timeout=max(45.0, self.run_timeout_seconds + 10.0))
        if self.thread.is_alive():
            with self._lock:
                self._errors.append({
                    "at": datetime.now(timezone.utc).isoformat(),
                    "error": "PA canary thread did not stop",
                })

    def _run_once(self) -> dict[str, Any] | None:
        import dbus

        bus = dbus.SystemBus()
        proxy = bus.get_object("io.bianbu.Security", "/io/bianbu/Security")
        sec = dbus.Interface(proxy, "io.bianbu.Security")
        audit_from = datetime.now(timezone.utc).isoformat(timespec="milliseconds")

        marker = f"BNSEC-PA-SOAK-{uuid.uuid4().hex}"
        session_id = f"bnsec-soak-{uuid.uuid4().hex}"
        started = time.monotonic()
        created = _http_json("POST", self.url + "/api/v1/runs", {
            "session_id": session_id,
            "idempotency_key": uuid.uuid4().hex,
            "agent_id": self.agent_id,
            "prompt": (
                "请只直接调用名为 bianbu.memory/memory 的工具一次，把"
                f"「商用耐久探针 {marker}」新增到长期记忆后简短确认。"
                "不要查询、清理或去重历史记忆，不要调用其他工具。"
            ),
        })
        run_id = str((created.get("data") or {}).get("id") or "")
        if not run_id:
            raise RuntimeError("PA create run returned no id")
        deadline = time.monotonic() + self.run_timeout_seconds
        result: dict[str, Any] = {}
        while time.monotonic() < deadline:
            if self.stop_event.is_set():
                return None
            value = _http_json(
                "GET", self.url + f"/api/v1/runs/{run_id}", timeout=30)
            result = value.get("data") or {}
            if result.get("status") in {"completed", "failed", "cancelled"}:
                break
            self.stop_event.wait(3.0)
        if result.get("status") != "completed":
            raise RuntimeError(
                f"PA run {run_id} ended as {result.get('status')}: "
                f"{str(result.get('error'))[:300]}")

        # 判权审计写入是同步的，但给负载较高的 worker 留一点调度窗口。
        self.stop_event.wait(2.0)
        if self.stop_event.is_set():
            return None
        after_rows = _agent_audit_records(
            sec, self.security_agent_id, from_ts=audit_from)
        permission_rows = [
            row for row in after_rows
            if row.get("op_type") == "check_permission"
            and "mcp." in str(row.get("target", ""))
        ]
        if not permission_rows:
            raise RuntimeError(f"PA run {run_id} has no MCP permission audit")
        return {
            "at": datetime.now(timezone.utc).isoformat(),
            "run_id": run_id,
            "session_id": session_id,
            "status": "completed",
            "duration_seconds": round(time.monotonic() - started, 3),
            "permission_audits": len(permission_rows),
        }

    def _run(self) -> None:
        next_run = time.monotonic()
        while not self.stop_event.is_set():
            if self.stop_event.wait(max(0.0, next_run - time.monotonic())):
                return
            try:
                sample = self._run_once()
                if sample is None:
                    return
                with self._lock:
                    self._samples.append(sample)
            except Exception as exc:  # noqa: BLE001
                if self.stop_event.is_set():
                    return
                with self._lock:
                    self._errors.append({
                        "at": datetime.now(timezone.utc).isoformat(),
                        "error": repr(exc),
                    })
            next_run += self.interval_seconds
            if next_run <= time.monotonic():
                next_run = time.monotonic() + self.interval_seconds

    def snapshot(self, *, elapsed_seconds: float) -> dict[str, Any]:
        with self._lock:
            samples = list(self._samples)
            errors = list(self._errors)
        required = min(
            self.min_runs,
            max(1, int(max(0.0, elapsed_seconds) / self.interval_seconds)),
        )
        return {
            "enabled": True,
            "url": self.url,
            "agent_id": self.agent_id,
            "security_agent_id": self.security_agent_id,
            "interval_seconds": self.interval_seconds,
            "min_runs": self.min_runs,
            "required_runs": required,
            "runs": len(samples) + len(errors),
            "passed": len(samples),
            "failed": len(errors),
            "permission_audited_runs": sum(
                int(x["permission_audits"]) > 0 for x in samples),
            "samples": samples,
            "errors": errors[-20:],
            "alive": self.thread.is_alive(),
        }


def _evaluate(report: dict[str, Any], *, max_p99_ms: float,
              max_rss_growth_mb: float, min_latency_samples: int = 1) -> list[str]:
    failures = []
    if report.get("error_count", 0):
        failures.append("operation_errors")
    if report.get("latency_samples", 0) < min_latency_samples:
        failures.append("insufficient_latency_samples")
    p99 = report.get("permission_p99_ms")
    if isinstance(p99, (int, float)) and p99 > max_p99_ms:
        failures.append("permission_p99")
    rss_growth = report.get("rss_growth_mb")
    if not isinstance(rss_growth, (int, float)) or rss_growth > max_rss_growth_mb:
        failures.append("rss_growth")
    if report.get("audit_chain_ok") is not True:
        failures.append("audit_chain")
    for unit, state in report.get("services", {}).items():
        if state.get("ActiveState") != "active":
            failures.append(f"service:{unit}")
    if (report.get("initial_system_state") != "running"
            or report.get("system_state") != "running"):
        failures.append("system_degraded")
    if (report.get("initial_systemd_transient_units")
            or report.get("systemd_transient_units")):
        failures.append("systemd_transient_units")
    sse = report.get("sse", {})
    if (sse.get("connections", 0) < 1 or sse.get("messages", 0) < 1
            or sse.get("reconnects", 0) or sse.get("errors")):
        failures.append("sse_stability")
    pa = report.get("pa_canary")
    if not isinstance(pa, dict) or pa.get("enabled") is not True:
        failures.append("pa_canary_missing")
    else:
        passed = pa.get("passed") if isinstance(pa.get("passed"), int) else 0
        required = (pa.get("required_runs")
                    if isinstance(pa.get("required_runs"), int) else 1)
        permission_runs = (pa.get("permission_audited_runs")
                           if isinstance(pa.get("permission_audited_runs"), int) else 0)
        if passed < required:
            failures.append("pa_canary_samples")
        if pa.get("failed") or pa.get("errors"):
            failures.append("pa_canary_errors")
        if permission_runs < passed:
            failures.append("pa_permission_audit")
    return failures


def _split_pending(status: str, failures: list[str]) -> tuple[list[str], list[str]]:
    """运行中尚未到采样/审计检查点的项目是 pending，不应误报成实时故障。"""
    if status != "running":
        return failures, []
    pending_names = {"insufficient_latency_samples", "audit_chain", "pa_canary_samples"}
    if "insufficient_latency_samples" in failures:
        pending_names.add("permission_p99")
    return ([item for item in failures if item not in pending_names],
            [item for item in failures if item in pending_names])


def _http_health(url: str, token: str) -> None:
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
    with urllib.request.urlopen(req, timeout=10) as response:
        body = json.loads(response.read().decode("utf-8"))
        if response.status != 200 or body.get("ok") is not True:
            raise RuntimeError(f"WebUI health failed: status={response.status} body={body}")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--seconds", type=float, default=72 * 3600)
    ap.add_argument("--interval-seconds", type=float, default=5.0)
    ap.add_argument("--milestone-seconds", default=f"{24 * 3600},{72 * 3600}")
    ap.add_argument("--output", required=True)
    ap.add_argument("--source-revision", required=True)
    ap.add_argument("--webui-url", default="http://127.0.0.1:8787")
    ap.add_argument("--webui-env", default="/etc/bianbu/webui.env")
    ap.add_argument("--uds-socket", default="/run/bianbu/securityd.sock")
    ap.add_argument("--max-permission-p99-ms", type=float, default=10.0)
    ap.add_argument("--max-rss-growth-mb", type=float, default=64.0)
    ap.add_argument("--min-latency-samples", type=int, default=100)
    ap.add_argument("--pa-url", default="http://127.0.0.1:9899")
    ap.add_argument("--pa-agent-id", default="personal-agent-default")
    ap.add_argument("--pa-security-agent-id", default="com.bianbu.agent")
    ap.add_argument("--pa-interval-seconds", type=float, default=6 * 3600)
    ap.add_argument("--pa-run-timeout-seconds", type=float, default=300.0)
    ap.add_argument("--min-pa-runs", type=int, default=12)
    args = ap.parse_args(argv)
    if (args.seconds <= 0 or args.interval_seconds <= 0
            or args.pa_interval_seconds <= 0 or args.pa_run_timeout_seconds <= 0
            or args.min_pa_runs <= 0):
        ap.error("duration and interval must be positive")

    env = _parse_env_file(Path(args.webui_env))
    token = env.get("BIANBU_WEBUI_TOKEN", "")
    if not token:
        print("COMMERCIAL_SOAK_FAIL webui_token_missing")
        return 2

    import dbus
    from client.bianbu_security_uds import UdsClient

    output = Path(args.output).resolve()
    try:
        samples_path = _prepare_output(output)
    except FileExistsError:
        print("COMMERCIAL_SOAK_FAIL output_already_exists")
        return 2
    except OSError as exc:
        print(f"COMMERCIAL_SOAK_FAIL output_unavailable={exc}")
        return 2
    milestones = sorted({float(x) for x in args.milestone_seconds.split(",")
                         if x.strip() and 0 < float(x) <= args.seconds})
    aid = f"com.bianbu.commercial-soak-{os.getpid()}"
    context = dbus.Dictionary({
        "session_id": dbus.String("commercial-soak"),
        "run_id": dbus.String(f"soak-{int(time.time())}"),
    }, signature="sv")
    bus = dbus.SystemBus()
    proxy = bus.get_object("io.bianbu.Security", "/io/bianbu/Security")
    sec = dbus.Interface(proxy, "io.bianbu.Security")
    if not bool(sec.BindAgentV2(aid, context)):
        raise RuntimeError("BindAgentV2 failed")
    permission = dbus.Dictionary({
        "tool": dbus.String("read_file"),
        "policy": dbus.String("allow"),
    }, signature="sv")
    if not bool(sec.RegisterCapabilities(aid, [permission])):
        raise RuntimeError("RegisterCapabilities failed")

    health_url = args.webui_url.rstrip("/") + "/api/health"
    sse = SSEMonitor(args.webui_url.rstrip("/") + "/api/events", token)
    sse.start()
    pa_canary = PACanaryMonitor(
        url=args.pa_url, agent_id=args.pa_agent_id,
        security_agent_id=args.pa_security_agent_id,
        interval_seconds=args.pa_interval_seconds,
        run_timeout_seconds=args.pa_run_timeout_seconds,
        min_runs=args.min_pa_runs)
    pa_canary.start()
    uds = UdsClient(args.uds_socket, timeout=10)
    stop_requested = False

    def _stop(_signum, _frame):
        nonlocal stop_requested
        stop_requested = True

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)

    started_wall = datetime.now(timezone.utc)
    started = time.monotonic()
    permission_latencies: list[float] = []
    errors: list[dict[str, Any]] = []
    iterations = 0
    completed_milestones: list[float] = []
    initial_services = {
        unit: _systemd_state(unit)
        for unit in ("bianbu-securityd.service", "bianbu-security-webui.service")
    }
    initial_system_state = _system_state()
    initial_systemd_transient_units = _systemd_transient_units()
    initial_rss = int(initial_services["bianbu-securityd.service"].get(
        "MemoryCurrent", "0") or 0)

    def build_report(status: str, audit_chain_ok: bool | None = None) -> dict[str, Any]:
        elapsed = time.monotonic() - started
        services = {
            unit: _systemd_state(unit)
            for unit in ("bianbu-securityd.service", "bianbu-security-webui.service")
        }
        current_rss = int(services["bianbu-securityd.service"].get(
            "MemoryCurrent", "0") or 0)
        report = {
            "format": "bianbu-security-commercial-soak-v2",
            "status": status,
            "source_revision": args.source_revision,
            "agent_id": aid,
            "started_at": started_wall.isoformat(),
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "target_seconds": args.seconds,
            "elapsed_seconds": round(elapsed, 3),
            "interval_seconds": args.interval_seconds,
            "iterations": iterations,
            "error_count": len(errors),
            "errors": errors[-100:],
            "permission_avg_ms": (statistics.mean(permission_latencies)
                                  if permission_latencies else None),
            "latency_samples": len(permission_latencies),
            "permission_p99_ms": (_percentile(permission_latencies, 0.99)
                                  if permission_latencies else None),
            "permission_max_ms": (max(permission_latencies)
                                  if permission_latencies else None),
            "initial_rss_bytes": initial_rss,
            "current_rss_bytes": current_rss,
            "rss_growth_mb": max(0, current_rss - initial_rss) / (1024 * 1024),
            "initial_services": initial_services,
            "services": services,
            "initial_system_state": initial_system_state,
            "system_state": _system_state(),
            "initial_systemd_transient_units": initial_systemd_transient_units,
            "systemd_transient_units": _systemd_transient_units(),
            "sse": sse.snapshot(),
            "pa_canary": pa_canary.snapshot(elapsed_seconds=elapsed),
            "audit_chain_ok": audit_chain_ok,
            "completed_milestones": completed_milestones,
        }
        evaluated = _evaluate(
            report, max_p99_ms=args.max_permission_p99_ms,
            max_rss_growth_mb=args.max_rss_growth_mb,
            min_latency_samples=args.min_latency_samples)
        report["failures"], report["pending_checks"] = _split_pending(
            status, evaluated)
        return report

    try:
        with samples_path.open("a", buffering=1) as sample_log:
            while not stop_requested and time.monotonic() - started < args.seconds:
                cycle_started = time.monotonic()
                row: dict[str, Any] = {
                    "at": datetime.now(timezone.utc).isoformat(),
                    "iteration": iterations,
                }
                try:
                    t0 = time.perf_counter_ns()
                    decision = int(sec.CheckPermissionV2(
                        aid, "health.read", "", context))
                    latency = (time.perf_counter_ns() - t0) / 1e6
                    permission_latencies.append(latency)
                    if decision != 0:
                        raise RuntimeError(f"unexpected permission decision={decision}")
                    if not bool(uds.ping()):
                        raise RuntimeError("UDS ping failed")
                    _http_health(health_url, token)
                    if iterations % 12 == 0:
                        sec.AuditLog(aid, "commercial_soak", str(iterations), "ok")
                    row.update({"ok": True, "permission_ms": round(latency, 6)})
                except Exception as exc:  # noqa: BLE001
                    item = {"at": row["at"], "iteration": iterations,
                            "error": repr(exc)}
                    errors.append(item)
                    row.update({"ok": False, "error": repr(exc)})
                    uds.close()
                sample_log.write(json.dumps(row, ensure_ascii=False) + "\n")
                iterations += 1

                elapsed = time.monotonic() - started
                for milestone in milestones:
                    if elapsed >= milestone and milestone not in completed_milestones:
                        try:
                            export_path = str(sec.ExportAudit("{}", "json"))
                            chain_ok = bool(sec.VerifyAuditChain(export_path))
                        except Exception as exc:  # noqa: BLE001
                            errors.append({"at": datetime.now(timezone.utc).isoformat(),
                                           "iteration": iterations,
                                           "error": f"milestone audit: {exc!r}"})
                            chain_ok = False
                        completed_milestones.append(milestone)
                        milestone_report = build_report("milestone", chain_ok)
                        _atomic_json(output.with_name(
                            f"{output.stem}.milestone-{int(milestone)}s{output.suffix}"),
                            milestone_report)
                _atomic_json(output, build_report("running"))
                remaining = args.interval_seconds - (time.monotonic() - cycle_started)
                if remaining > 0:
                    time.sleep(remaining)
    finally:
        uds.close()
        sse.stop()
        pa_canary.stop()

    try:
        export_path = str(sec.ExportAudit("{}", "json"))
        chain_ok = bool(sec.VerifyAuditChain(export_path))
    except Exception as exc:  # noqa: BLE001
        errors.append({"at": datetime.now(timezone.utc).isoformat(),
                       "iteration": iterations,
                       "error": f"final audit: {exc!r}"})
        chain_ok = False
    # 结束时间可能刚好跨过一个 milestone，循环体来不及再执行一次；在最终
    # 收尾阶段补写所有已经达到的检查点，但不为被主动中断的任务伪造报告。
    if not stop_requested:
        elapsed_final = time.monotonic() - started
        for milestone in milestones:
            if elapsed_final >= milestone and milestone not in completed_milestones:
                completed_milestones.append(milestone)
                milestone_report = build_report("milestone", chain_ok)
                _atomic_json(output.with_name(
                    f"{output.stem}.milestone-{int(milestone)}s{output.suffix}"),
                    milestone_report)
    final_status = "interrupted" if stop_requested else "completed"
    report = build_report(final_status, chain_ok)
    report["samples_file"] = samples_path.name
    report["samples_size"] = samples_path.stat().st_size
    report["samples_sha256"] = _sha256(samples_path)
    report["milestone_evidence"] = []
    for milestone in completed_milestones:
        milestone_path = output.with_name(
            f"{output.stem}.milestone-{int(milestone)}s{output.suffix}")
        if milestone_path.is_file():
            report["milestone_evidence"].append({
                "seconds": milestone,
                "file": milestone_path.name,
                "size": milestone_path.stat().st_size,
                "sha256": _sha256(milestone_path),
            })
    report["failures"] = _evaluate(
        report, max_p99_ms=args.max_permission_p99_ms,
        max_rss_growth_mb=args.max_rss_growth_mb,
        min_latency_samples=args.min_latency_samples)
    report["status"] = "passed" if not report["failures"] and not stop_requested else (
        "interrupted" if stop_requested else "failed")
    _atomic_json(output, report)
    if report["status"] != "passed":
        print("COMMERCIAL_SOAK_FAIL failures=" + ",".join(report["failures"]))
        return 1
    print(f"COMMERCIAL_SOAK_PASS seconds={args.seconds:g} iterations={iterations} "
          f"p99_ms={report['permission_p99_ms']:.3f} "
          f"pa_runs={report['pa_canary']['passed']} report={output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
