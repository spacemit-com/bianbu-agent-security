#!/usr/bin/env bash
# 启动测试监视 WebUI。
#
# ⚠️ 无认证，绑 0.0.0.0。测试会真实调 LLM（耗 token）、真实注册授予能力、
# 真实往审计库写记录。只在可信内网用，演示完 ./stop-all.sh。
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
# shellcheck source=env.sh
source ./env.sh

if [ ! -f "$BNSEC_TESTKIT/webui.py" ]; then
  echo "找不到 $BNSEC_TESTKIT/webui.py" >&2
  echo "先部署：./deploy.sh  （或设 BNSEC_TESTKIT 指向正确位置）" >&2
  exit 1
fi

echo "停止旧的 WebUI…"
pkill -f 'python3 .*webui\.py' 2>/dev/null || true
sleep 1

runner="$BNSEC_LOG_DIR/_run_webui.sh"
cat >"$runner" <<EOF
#!/usr/bin/env bash
cd '$BNSEC_TESTKIT' || exit 1
export PATH=/usr/local/bin:/usr/bin:/bin
export BIANBU_SECURITYD_HOME='$BIANBU_SECURITYD_HOME'
export BIANBU_PA_AGENT_ID='$BIANBU_PA_AGENT_ID'
export PA_AGENT_ID='$PA_AGENT_ID'
export PA_BASE='$PA_BASE'
export BNSEC_OUT='$BNSEC_OUT'
export BNSEC_WEB_PORT='$BNSEC_WEB_PORT'
export DBUS_SESSION_BUS_ADDRESS='$DBUS_SESSION_BUS_ADDRESS'
exec python3 webui.py
EOF
chmod +x "$runner"

bnsec_spawn "$runner" "$BNSEC_LOG_DIR/webui.log"

if bnsec_wait_http "http://127.0.0.1:$BNSEC_WEB_PORT/" "WebUI" 15; then
  ip=$(hostname -I 2>/dev/null | awk '{print $1}')
  echo
  echo "  监视页面：http://${ip:-127.0.0.1}:$BNSEC_WEB_PORT"
  echo "  ⚠️  无认证，仅限内网"
else
  tail -15 "$BNSEC_LOG_DIR/webui.log" >&2
  exit 1
fi
