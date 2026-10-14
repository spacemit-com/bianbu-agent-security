#!/usr/bin/env bash
# 三服务体检 + 上轮测试结果摘要。
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
# shellcheck source=env.sh
source ./env.sh

rc=0

echo "── securityd"
if owned=$(bnsec_secd_owned); then
  echo "   ✓ 已占名（$owned 总线）"
else
  echo "   ✗ 未占名"; rc=1
fi

echo "── personal-agent"
code=$(curl -s -m 5 -o /dev/null -w '%{http_code}' "$PA_BASE/" 2>/dev/null)
if [ "$code" = "200" ]; then
  echo "   ✓ HTTP 200（$PA_BASE）"
else
  echo "   ✗ HTTP ${code:-000}（$PA_BASE）"; rc=1
fi

echo "── 测试 WebUI"
code=$(curl -s -m 5 -o /dev/null -w '%{http_code}' "http://127.0.0.1:$BNSEC_WEB_PORT/" 2>/dev/null)
if [ "$code" = "200" ]; then
  echo "   ✓ HTTP 200（端口 $BNSEC_WEB_PORT）"
else
  echo "   ✗ HTTP ${code:-000}（端口 $BNSEC_WEB_PORT）"; rc=1
fi

echo "── securityd 配置台"
code=$(curl -s -m 5 -o /dev/null -w '%{http_code}' \
       "http://127.0.0.1:${BNSEC_SEC_WEB_PORT:-8787}/api/health" 2>/dev/null)
if [ "$code" = "200" ]; then
  echo "   ✓ HTTP 200（端口 ${BNSEC_SEC_WEB_PORT:-8787}）"
else
  echo "   · 未运行（端口 ${BNSEC_SEC_WEB_PORT:-8787}）—— 非必需，./start-sec-webui.sh 可起"
fi

echo "── testkit 安装"
if [ -f "$BNSEC_TESTKIT/runner.py" ]; then
  echo "   ✓ $BNSEC_TESTKIT"
else
  echo "   ✗ 未部署到 $BNSEC_TESTKIT"; rc=1
fi

echo "── 上轮测试结果"
if [ -f "$BNSEC_OUT/report.json" ]; then
  python3 - "$BNSEC_OUT/report.json" <<'PY'
import json, sys, time
r = json.load(open(sys.argv[1]))
s = r["summary"]
age = int(time.time() - s.get("finished_at", 0))
unit = f"{age}s 前" if age < 3600 else f"{age // 3600}h{age % 3600 // 60}m 前"
print(f"   总计 {s['total']} | 通过 {s['passed']} | 失败 {s['failed']} "
      f"| 错误 {s['error']} | {unit}")
bad = [t for t in r["results"] if t["status"] not in ("passed", "skipped")]
for t in bad:
    print(f"     [{t['status'].upper()}] {t['id']} {t['title']}")
PY
else
  echo "   （尚无 $BNSEC_OUT/report.json）"
fi

exit $rc
