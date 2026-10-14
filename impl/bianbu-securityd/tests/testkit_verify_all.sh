#!/usr/bin/env bash
# 向后兼容入口；正式发布门禁位于 deploy/verify_all.sh，并会进入安装资产。
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec bash "$HERE/../deploy/verify_all.sh" "$@"
