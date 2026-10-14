#!/usr/bin/env bash
# 按依赖顺序起三个服务：securityd → personal-agent → WebUI。
#
# 顺序不能颠倒：PA 启动时会连 securityd，securityd 没起 PA 会把安全层
# 降级（低危 fail-open），跑出来的测试结果不可信。
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

echo "═══ 1/3 securityd ═══"
./start-securityd.sh || exit 1
echo
echo "═══ 2/3 personal-agent ═══"
./start-pa.sh || exit 1
echo
echo "═══ 3/3 测试 WebUI ═══"
./start-webui.sh || exit 1
echo
echo "═══ 体检 ═══"
./status.sh
