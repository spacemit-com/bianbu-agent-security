#!/usr/bin/env bash
# 重置 Security 自有运行状态；默认只预览。
set -euo pipefail
script_dir="$(cd -- "$(dirname -- "$(readlink -f -- "${BASH_SOURCE[0]}")")" && pwd)"
helper="${script_dir}/clear-security-data.py"
if [[ ! -f "$helper" ]]; then
  helper=/usr/lib/bianbu-securityd/deploy/clear-security-data.py
fi
exec /usr/bin/python3 "$helper" "$@"
