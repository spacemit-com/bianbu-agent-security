#!/usr/bin/env bash
# 启动 personal-agent（带安全接入的全部环境变量）。PA 正式启动前必须提供
# Agent Memory SDK；开发验证可显式设置 PA_UV_NO_SYNC=1。
# 安全模式统一通过 PA run.sh 进入 bwrap；不要直接 uv run serve。
#
# BIANBU_PA_AGENT_ID 很关键：它是 securityd 侧的能力注册主键，与
# bianbu-agent 本地的 agent.id（personal-agent-default）不是同一命名空间。
# 用错会把 Token 用量记到未注册的 agent 上，配额永不触发。
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
# shellcheck source=env.sh
source ./env.sh

if [ ! -d "$BNSEC_PA_HOME/../bianbu-agent-memory/sdk/python" ] && [ "${PA_UV_NO_SYNC:-0}" != "1" ]; then
  echo "✗ 未找到 Agent Memory SDK：$BNSEC_PA_HOME/../bianbu-agent-memory/sdk/python" >&2
  echo "  请先部署 SDK；仅开发验证可显式设置 PA_UV_NO_SYNC=1" >&2
  exit 1
fi

echo "停止旧的 PA 进程…"
pkill -9 -f 'bianbu-agent.*serve' 2>/dev/null || true
sleep 2

runner="$BNSEC_LOG_DIR/_run_pa.sh"
cat >"$runner" <<EOF
#!/usr/bin/env bash
cd '$BNSEC_PA_HOME' || exit 1
export PATH="\$(dirname '$BNSEC_UV'):/usr/local/bin:/usr/bin:/bin"
export BIANBU_SECURITY=1
export BIANBU_SECURITYD_HOME='$BIANBU_SECURITYD_HOME'
export BIANBU_SEC_UDS='$BIANBU_SEC_UDS'
export BIANBU_PA_AGENT_ID='$BIANBU_PA_AGENT_ID'
export BIANBU_PA_DLP=1
export BIANBU_PA_TOKEN_METER=1
export DBUS_SESSION_BUS_ADDRESS='$DBUS_SESSION_BUS_ADDRESS'
export BIANBU_SANDBOX='${BIANBU_SANDBOX:-agent}'
export BIANBU_AGENT_CONFIG='.bianbu-agent/config.yaml'
export UV_NO_SYNC='${PA_UV_NO_SYNC:-0}'
exec '$BNSEC_PA_HOME/run.sh' serve
EOF
chmod +x "$runner"

echo "启动 PA…"
bnsec_spawn "$runner" "$BNSEC_LOG_DIR/pa.log"

if ! bnsec_wait_http "$PA_BASE/" "personal-agent" 30; then
  echo "日志尾部：" >&2
  tail -20 "$BNSEC_LOG_DIR/pa.log" | tr -d '\000' >&2
  exit 1
fi
