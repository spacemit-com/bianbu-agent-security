#!/usr/bin/env bash
# 发布前统一验证入口：契约、安装资产、单元/集成/E2E、性能、稳定性、Smoke 和供应链门禁。
set -euo pipefail

STRICT=0
case "${1:-}" in
  --strict) STRICT=1 ;;
  "") ;;
  *) echo "用法: $0 [--strict]" >&2; exit 2 ;;
esac
if [ "$STRICT" = 1 ]; then
  # 商用门禁禁止从调用用户的 ~/.local 补依赖；否则 venv 复制到 systemd 后会缺包。
  export PYTHONNOUSERSITE=1
fi

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
PYTHON="${PYTHON:-python3}"
cd "$ROOT"

STRICT_FAILURES=()
run_gate() {
  local name="$1"
  shift
  if [ "$STRICT" = 0 ]; then
    "$@"
    return
  fi
  set +e
  "$@"
  local rc=$?
  set -e
  if [ "$rc" -ne 0 ]; then
    echo "STRICT_GATE_FAIL name=$name rc=$rc" >&2
    STRICT_FAILURES+=("$name")
  fi
}

DOCTOR_ARGS=(--json doctor)
if [ "$STRICT" = 1 ]; then
  DOCTOR_ARGS+=(--strict)
fi
UNIT_XML="${JUNIT_UNIT:-/tmp/bnsec-unit.xml}"
INT_XML="${JUNIT_INT:-/tmp/bnsec-integration.xml}"
E2E_XML="${JUNIT_E2E:-/tmp/bnsec-e2e.xml}"

run_gate dbus_contract "$PYTHON" tests/verify_dbus_contract.py
run_gate install_assets "$PYTHON" deploy/verify_install_assets.py
DOCTOR_OUTPUT="${DOCTOR_JSON:-/tmp/bnsec-doctor.json}"
if [ "$STRICT" = 1 ]; then
  set +e
  env \
    BIANBU_ETC=/etc/bianbu \
    BIANBU_RUN=/run/bianbu \
    BIANBU_LOG=/var/log/bianbu \
    BIANBU_AGENTS_HOME=/var/lib/bianbu/agents \
    BIANBU_SEC_UDS=/run/bianbu/securityd.sock \
    BIANBU_SECURITY_CODESIGN="${BIANBU_SECURITY_CODESIGN:-enforce}" \
    BIANBU_SECURITY_CODESIGN_KEYS="${BIANBU_SECURITY_CODESIGN_KEYS:-/etc/bianbu/codesign-keys}" \
    "$PYTHON" -m cli.bncli "${DOCTOR_ARGS[@]}" > "$DOCTOR_OUTPUT"
  DOCTOR_RC=$?
  set -e
  if [ "$DOCTOR_RC" -ne 0 ]; then
    cat "$DOCTOR_OUTPUT" >&2
    echo "STRICT_GATE_FAIL name=doctor rc=$DOCTOR_RC" >&2
    STRICT_FAILURES+=(doctor)
  fi
else
  "$PYTHON" -m cli.bncli "${DOCTOR_ARGS[@]}" > "$DOCTOR_OUTPUT"
fi
run_gate unit "$PYTHON" -m pytest tests/unit -q --junitxml="$UNIT_XML"
run_gate integration "$PYTHON" -m pytest tests/integration -q --junitxml="$INT_XML"
if [ "$STRICT" = 1 ]; then
  # strict 必须真实执行 E2E，不能依靠 pytest skip 后再统计。使用独立 D-Bus 与
  # 隔离数据根，避免开发中的 securityd/UDS socket 污染发布门禁。
  E2E_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/bnsec-e2e.XXXXXX")"
  trap 'rm -rf "$E2E_ROOT"' EXIT
  run_gate e2e dbus-run-session -- env \
    BIANBU_E2E=1 \
    BIANBU_SEC_ROOT="$E2E_ROOT" \
    BIANBU_SEC_UDS="$E2E_ROOT/run/bianbu/securityd.sock" \
    PYTHONPATH="$ROOT:$ROOT/client${PYTHONPATH:+:$PYTHONPATH}" \
    "$PYTHON" -m pytest tests/e2e -q --junitxml="$E2E_XML"
  set +e
  "$PYTHON" - "$E2E_XML" <<'PY'
import sys
import xml.etree.ElementTree as ET

root = ET.parse(sys.argv[1]).getroot()
suites = [root] if root.tag == "testsuite" else list(root.findall("testsuite"))
skipped = sum(int(s.attrib.get("skipped", "0")) for s in suites)
if skipped:
    print(f"STRICT_E2E_FAIL skipped={skipped}", file=sys.stderr)
    raise SystemExit(1)
print("STRICT_E2E_PASS skipped=0")
PY
  E2E_STRICT_RC=$?
  set -e
  if [ "$E2E_STRICT_RC" -ne 0 ]; then
    echo "STRICT_GATE_FAIL name=e2e_no_skips rc=$E2E_STRICT_RC" >&2
    STRICT_FAILURES+=(e2e_no_skips)
  fi
else
  run_gate e2e "$PYTHON" -m pytest tests/e2e -q --junitxml="$E2E_XML"
fi
run_gate smoke bash tests/smoke_test.sh
run_gate pii_benchmark "$PYTHON" tests/integration/pii_benchmark.py
run_gate uds_benchmark "$PYTHON" tests/integration/uds_benchmark.py
run_gate performance "$PYTHON" tests/integration/performance_benchmark.py --samples "${PERF_SAMPLES:-100}" --check
run_gate stability "$PYTHON" tests/integration/stability_smoke.py --seconds "${STABILITY_SECONDS:-10}"
RELEASE_ARGS=(--output "${SBOM_JSON:-/tmp/bnsec-sbom.json}")
if [ "$STRICT" = 1 ]; then
  RELEASE_ARGS+=(--strict --scanner "${CVE_SCANNER:-pip-audit}")
fi
run_gate release "$PYTHON" deploy/release_gate.py "${RELEASE_ARGS[@]}"
set +e
PROBE_OUT="$($PYTHON deploy/runtime_production_probe.py --json 2>&1)"
PROBE_RC=$?
set -e
printf '%s\n' "$PROBE_OUT"
if [ "$PROBE_RC" -eq 0 ]; then
  echo "RUNTIME_PRODUCTION_PASS"
elif [ "$PROBE_RC" -eq 2 ]; then
  if [ "$STRICT" = 1 ]; then
    echo "RUNTIME_PRODUCTION_REQUIRED" >&2
    STRICT_FAILURES+=(runtime_production)
  else
    echo "RUNTIME_PRODUCTION_GATE_PENDING"
  fi
else
  if [ "$STRICT" = 1 ]; then
    echo "RUNTIME_PRODUCTION_PROBE_ERROR rc=$PROBE_RC" >&2
    STRICT_FAILURES+=(runtime_probe)
  else
    echo "RUNTIME_PRODUCTION_PROBE_ERROR rc=$PROBE_RC" >&2
    exit "$PROBE_RC"
  fi
fi
if [ "$STRICT" = 1 ]; then
  if [ "${#STRICT_FAILURES[@]}" -ne 0 ]; then
    printf 'BNSEC_VERIFY_ALL_STRICT_FAIL gates=%s\n' "$(IFS=,; echo "${STRICT_FAILURES[*]}")" >&2
    exit 1
  fi
  echo "BNSEC_VERIFY_ALL_STRICT_PASS repo_gates=passed external_runtime_gate=passed"
else
  echo "BNSEC_VERIFY_ALL_PASS repo_gates=passed external_runtime_gate=pending_or_pass"
fi
