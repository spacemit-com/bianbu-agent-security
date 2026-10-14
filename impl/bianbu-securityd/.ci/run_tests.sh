#!/usr/bin/env bash
# Worker/发布流水线入口：生成可归档的 Security 责任域商用证据包。
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
PYTHON="${BNSEC_PYTHON:-python3}"
SCANNER="${BNSEC_CVE_SCANNER:-pip-audit}"
REVISION="${BNSEC_SOURCE_REVISION:-}"
if [ -z "$REVISION" ] && git -C "$ROOT" rev-parse HEAD >/dev/null 2>&1; then
  REVISION="$(git -C "$ROOT" rev-parse HEAD)"
fi
if [ -z "$REVISION" ]; then
  echo "BNSEC_CI_FAIL BNSEC_SOURCE_REVISION is required outside a git checkout" >&2
  exit 2
fi

SAFE_REVISION="$(printf '%s' "$REVISION" | tr -cd 'A-Za-z0-9._-' | cut -c1-32)"
if [ -z "$SAFE_REVISION" ]; then
  echo "BNSEC_CI_FAIL invalid source revision" >&2
  exit 2
fi
EVIDENCE_DIR="${BNSEC_EVIDENCE_DIR:-${TMPDIR:-/tmp}/bnsec-security-release-$SAFE_REVISION}"

exec "$PYTHON" "$ROOT/deploy/security_release_gate.py" \
  --output-dir "$EVIDENCE_DIR" \
  --python "$PYTHON" \
  --scanner "$SCANNER" \
  --source-revision "$REVISION" \
  --stability-seconds "${BNSEC_STABILITY_SECONDS:-10}" \
  --perf-samples "${BNSEC_PERF_SAMPLES:-100}"
