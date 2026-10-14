#!/usr/bin/env bash
# 命令行跑测试。不带参数跑全量，带参数只跑指定项。
#
#   ./run-tests.sh                      全量 24 项
#   ./run-tests.sh HOOK-03 TOKEN-02     只跑两个决定性测试
#
# 退出码：全通过 0 / 有失败 1 / 传错测试 ID 2
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
# shellcheck source=env.sh
source ./env.sh

if [ ! -f "$BNSEC_TESTKIT/runner.py" ]; then
  echo "找不到 $BNSEC_TESTKIT/runner.py，先跑 ./deploy.sh" >&2
  exit 1
fi

# 前置检查：两个服务缺任一就没必要跑（会得到一堆 ServiceUnknown/Connection refused）
fail=0
if ! bnsec_secd_owned >/dev/null; then
  echo "✗ securityd 未占名 —— 先跑 ./start-securityd.sh" >&2
  fail=1
fi
if [ "$(curl -s -m 5 -o /dev/null -w '%{http_code}' "$PA_BASE/" 2>/dev/null)" != "200" ]; then
  echo "✗ personal-agent 不可达（$PA_BASE）—— 先跑 ./start-pa.sh" >&2
  fail=1
fi
[ "$fail" = 1 ] && exit 1

cd "$BNSEC_TESTKIT"
exec python3 runner.py "$@"
