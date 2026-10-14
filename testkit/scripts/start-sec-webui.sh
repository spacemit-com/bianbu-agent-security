#!/usr/bin/env bash
# 启动 securityd 自带的配置台 WebUI（默认 8787）。
#
# 注意与 testkit 的 WebUI（9700）是两个不同的东西：
#   9700  测试监视台 —— 跑 24 项测试、看报告（本仓 testkit/webui.py）
#   8787  securityd 配置台 —— 管能力/配额/DLP策略/审计/沙箱（securityd 自带）
#
# 走 run-system-bus.sh 而非 run.sh：后者写死会话总线，若 securityd 已在系统
# 总线占名会去启第二个实例，两个 securityd 各写一份数据。
#
# ⚠️ 开发/demo 模式可通过 BIANBU_WEBUI_DEMO=1 关闭鉴权；产品模式要求管理员
#    token。无论哪种模式，内置 Web Terminal（可开 shell），绑 0.0.0.0 等同对外
#    暴露远程终端。只在可信内网用，用完 ./stop-all.sh --sec-webui。
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
# shellcheck source=env.sh
source ./env.sh

: "${BNSEC_SEC_WEB_PORT:=8787}"
# testkit is a development/demo entry point.  Keep the WebUI usable without
# provisioning a production token; product systemd units do not inherit this.
: "${BIANBU_WEBUI_DEMO:=1}"
export BIANBU_WEBUI_DEMO
WEBUI_DIR="$BIANBU_SECURITYD_HOME/webui"
LAUNCHER="$WEBUI_DIR/run-system-bus.sh"

if [ ! -f "$LAUNCHER" ]; then
  echo "✗ 找不到 $LAUNCHER" >&2
  echo "  从仓库同步：scp impl/bianbu-securityd/webui/run-system-bus.sh \\" >&2
  echo "                  bianbu@<worker>:$WEBUI_DIR/" >&2
  exit 1
fi

if ! bus=$(bnsec_secd_owned); then
  echo "✗ securityd 未占名 —— 先跑 ./start-securityd.sh" >&2
  exit 1
fi

echo "停止旧的 securityd WebUI…"
pkill -f 'webui/app\.py' 2>/dev/null || true
sleep 1

runner="$BNSEC_LOG_DIR/_run_secwebui.sh"
if [ "$bus" = "session" ]; then
  # securityd 在会话总线上，用它自带的 run.sh
  cat >"$runner" <<EOF
#!/usr/bin/env bash
export PATH=/usr/local/bin:/usr/bin:/bin
export DBUS_SESSION_BUS_ADDRESS='$DBUS_SESSION_BUS_ADDRESS'
cd '$WEBUI_DIR' || exit 1
PORT='$BNSEC_SEC_WEB_PORT' exec bash ./run.sh
EOF
else
  cat >"$runner" <<EOF
#!/usr/bin/env bash
export PATH=/usr/local/bin:/usr/bin:/bin
cd '$WEBUI_DIR' || exit 1
PORT='$BNSEC_SEC_WEB_PORT' exec ./run-system-bus.sh
EOF
fi
chmod +x "$runner"

echo "启动 securityd WebUI（$bus 总线）…"
bnsec_spawn "$runner" "$BNSEC_LOG_DIR/sec-webui.log"

if bnsec_wait_http "http://127.0.0.1:$BNSEC_SEC_WEB_PORT/" "securityd WebUI" 15; then
  ip=$(hostname -I 2>/dev/null | awk '{print $1}')
  echo
  echo "  配置台：http://${ip:-127.0.0.1}:$BNSEC_SEC_WEB_PORT"
  echo "  ⚠️  开发/demo 可无鉴权；内置 Web Terminal，仅限可信内网"
else
  tail -15 "$BNSEC_LOG_DIR/sec-webui.log" >&2
  exit 1
fi
