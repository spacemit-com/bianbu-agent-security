#!/usr/bin/env bash
# 生产 24/72 小时耐久任务启停器。后台进程完全脱离 SSH 通道，报告持续原子落盘。
set -euo pipefail
umask 077

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
STATE_DIR="${SOAK_STATE_DIR:-/var/tmp/bnsec-commercial-soak}"
PID_FILE="$STATE_DIR/current.pid"
RUN_FILE="$STATE_DIR/current-run"
PYTHON="${SOAK_PYTHON:-python3}"

is_running() {
  [ -f "$PID_FILE" ] || return 1
  local pid
  pid="$(cat "$PID_FILE" 2>/dev/null || true)"
  [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null || return 1
  tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null | grep -Fq "$ROOT/deploy/commercial_soak.py"
}

status() {
  if ! is_running; then
    echo "COMMERCIAL_SOAK_NOT_RUNNING"
    return 1
  fi
  local pid run_dir
  pid="$(cat "$PID_FILE")"
  run_dir="$(cat "$RUN_FILE")"
  echo "COMMERCIAL_SOAK_RUNNING pid=$pid run_dir=$run_dir"
  if [ -f "$run_dir/report.json" ]; then
    "$PYTHON" - "$run_dir/report.json" <<'PY'
import json, sys
r = json.load(open(sys.argv[1]))
keys = ("status", "elapsed_seconds", "target_seconds", "iterations",
        "error_count", "permission_p99_ms", "rss_growth_mb", "failures",
        "pending_checks", "pa_canary")
print(json.dumps({k: r.get(k) for k in keys}, ensure_ascii=False))
PY
  fi
}

case "${1:-status}" in
  start)
    revision="${2:-${BNSEC_SOURCE_REVISION:-}}"
    if [ -z "$revision" ]; then
      echo "用法: $0 start <source-revision>" >&2
      exit 2
    fi
    system_state="$(systemctl is-system-running 2>/dev/null || true)"
    if [ "$system_state" != running ]; then
      echo "COMMERCIAL_SOAK_START_FAIL system_state=${system_state:-unknown}" >&2
      exit 1
    fi
    transient_units="$(systemctl list-units --type=service \
      --state=activating,failed --no-legend --plain --no-pager 2>/dev/null \
      | awk '{print $1}' | paste -sd, -)"
    if [ -n "$transient_units" ]; then
      echo "COMMERCIAL_SOAK_START_FAIL systemd_transient_units=$transient_units" >&2
      exit 1
    fi
    mkdir -p "$STATE_DIR"
    if is_running; then
      status
      exit 2
    fi
    safe_revision="$(printf '%s' "$revision" | tr -cd 'A-Za-z0-9._-' | cut -c1-32)"
    [ -n "$safe_revision" ] || { echo "invalid source revision" >&2; exit 2; }
    run_dir="$STATE_DIR/${safe_revision}-$(date -u +%Y%m%dT%H%M%SZ)"
    mkdir -p "$run_dir"
    printf '%s\n' "$run_dir" > "$RUN_FILE"
    setsid "$PYTHON" "$ROOT/deploy/commercial_soak.py" \
      --seconds "${SOAK_SECONDS:-259200}" \
      --interval-seconds "${SOAK_INTERVAL_SECONDS:-5}" \
      --milestone-seconds "${SOAK_MILESTONE_SECONDS:-86400,259200}" \
      --pa-url "${SOAK_PA_URL:-http://127.0.0.1:9899}" \
      --pa-agent-id "${SOAK_PA_AGENT_ID:-personal-agent-default}" \
      --pa-security-agent-id "${SOAK_PA_SECURITY_AGENT_ID:-com.bianbu.agent}" \
      --pa-interval-seconds "${SOAK_PA_INTERVAL_SECONDS:-21600}" \
      --pa-run-timeout-seconds "${SOAK_PA_RUN_TIMEOUT_SECONDS:-300}" \
      --min-pa-runs "${SOAK_MIN_PA_RUNS:-12}" \
      --output "$run_dir/report.json" \
      --source-revision "$revision" \
      >"$run_dir/runner.log" 2>&1 </dev/null &
    pid=$!
    printf '%s\n' "$pid" > "$PID_FILE"
    sleep 1
    if ! is_running; then
      echo "COMMERCIAL_SOAK_START_FAIL log=$run_dir/runner.log" >&2
      tail -n 40 "$run_dir/runner.log" >&2 || true
      exit 1
    fi
    echo "COMMERCIAL_SOAK_STARTED pid=$pid run_dir=$run_dir"
    ;;
  status)
    status
    ;;
  stop)
    if ! is_running; then
      echo "COMMERCIAL_SOAK_NOT_RUNNING"
      exit 0
    fi
    pid="$(cat "$PID_FILE")"
    run_dir="$(cat "$RUN_FILE")"
    kill -TERM "$pid"
    for _ in $(seq 1 30); do
      kill -0 "$pid" 2>/dev/null || break
      sleep 1
    done
    if kill -0 "$pid" 2>/dev/null; then
      echo "COMMERCIAL_SOAK_STOP_TIMEOUT pid=$pid" >&2
      exit 1
    fi
    echo "COMMERCIAL_SOAK_STOPPED run_dir=$run_dir"
    ;;
  *)
    echo "用法: $0 {start <source-revision>|status|stop}" >&2
    exit 2
    ;;
esac
