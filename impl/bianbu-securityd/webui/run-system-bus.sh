#!/usr/bin/env bash
# securityd WebUI 启动脚本 —— 系统总线版。
#
# 与 run.sh 的区别：run.sh 写死 BIANBU_SEC_SESSION=1（会话总线），若 securityd
# 已在**系统总线**上占名，run.sh 会因 `busctl --user status` 查不到而去启动
# 第二个实例，两个 securityd 各写一份数据。
#
# 本脚本不设 BIANBU_SEC_SESSION，客户端据此走系统总线
# （client/bianbu_security_client.py:17），并先确认已有 securityd 占名。
#
# 用法：
#   ./run-system-bus.sh              默认 127.0.0.1:8787
#   PORT=9001 ./run-system-bus.sh
#   HOST=0.0.0.0 ./run-system-bus.sh 显式对外监听（必须配置 TLS）
#
# 生产要求 BIANBU_WEBUI_TOKEN；开发/demo 可设置 BIANBU_WEBUI_DEMO=1；
# 可选 BIANBU_WEBUI_VIEWER_TOKEN 提供只读访问。
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$HERE")"

PORT="${PORT:-8787}"
HOST="${HOST:-0.0.0.0}"

# 挑一个装了 flask_socketio 的解释器
if [ -z "${PYTHON:-}" ]; then
  for cand in /usr/bin/python3 python3; do
    if command -v "$cand" >/dev/null 2>&1 \
       && "$cand" -c "import flask_socketio" >/dev/null 2>&1; then
      PYTHON="$cand"; break
    fi
  done
fi
PYTHON="${PYTHON:-python3}"
if ! "$PYTHON" -c "import flask_socketio" >/dev/null 2>&1; then
  echo "✗ $PYTHON 缺 flask_socketio。装：$PYTHON -m pip install flask flask-socketio" >&2
  exit 1
fi

export PYTHONPATH="$ROOT:$ROOT/client"
# 关键：不设 BIANBU_SEC_SESSION，让客户端走系统总线
unset BIANBU_SEC_SESSION || true
# 数据根用默认的用户级目录，勿覆盖
unset BIANBU_SEC_ROOT || true

# 确认 securityd 已在系统总线占名（本脚本不负责启动它）
if ! busctl --system list 2>/dev/null | grep -q io.bianbu.Security; then
  echo "✗ securityd 未在系统总线上占名。" >&2
  if busctl --user list 2>/dev/null | grep -q io.bianbu.Security; then
    echo "  检测到它在**会话总线**上 —— 那就用 run.sh（会话总线版）。" >&2
  else
    echo "  先启动：cd $ROOT && python3 -m securityd.service" >&2
    echo "  或用 testkit 的脚本：bnsec-testkit/scripts/start-securityd.sh" >&2
  fi
  exit 1
fi
echo "[webui] securityd 就绪（系统总线）"

if [ "$HOST" = "0.0.0.0" ]; then
  MYIP="$(hostname -I 2>/dev/null | awk '{print $1}')"
  echo "⚠️  ================================================================"
  echo "⚠️   WebUI 监听 0.0.0.0:$PORT —— 同网络任何主机均可访问！"
  echo "⚠️   对外监听：必须配置管理员 BIANBU_WEBUI_TOKEN，并建议使用 TLS 反向代理。"
  echo "⚠️   Web Terminal 仅管理员 token 可用；viewer token 仅可读。"
  echo "⚠️  ================================================================"
  echo "[webui] 跨主机访问： http://${MYIP:-<本机IP>}:$PORT"
fi
if [ -z "${BIANBU_WEBUI_TOKEN:-}" ] \
   && [ "${BIANBU_WEBUI_AUTH:-0}" != "0" ] \
   && [ "${BIANBU_WEBUI_DEMO:-0}" != "1" ]; then
  echo "✗ 生产系统总线 WebUI 必须设置 BIANBU_WEBUI_TOKEN；开发临时测试可显式 BIANBU_WEBUI_AUTH=0 或 BIANBU_WEBUI_DEMO=1" >&2
  exit 1
fi
if [ "${BIANBU_WEBUI_DEMO:-0}" != "1" ] \
   && [ -n "${BIANBU_WEBUI_VIEWER_TOKEN:-}" ] \
   && [ "${BIANBU_WEBUI_VIEWER_TOKEN}" = "${BIANBU_WEBUI_TOKEN:-}" ]; then
  echo "✗ viewer token 必须与管理员 token 不同" >&2
  exit 1
fi
if [ "$HOST" != "127.0.0.1" ] && [ "$HOST" != "::1" ] && [ "$HOST" != "localhost" ] \
   && [ -z "${BIANBU_WEBUI_TLS_CERT:-}" ] \
   && [ "${BIANBU_WEBUI_TRUST_PROXY:-0}" != "1" ] \
   && [ "${BIANBU_WEBUI_ALLOW_INSECURE_REMOTE:-0}" != "1" ]; then
  echo "✗ 非回环 WebUI 必须设置 BIANBU_WEBUI_TLS_CERT/BIANBU_WEBUI_TLS_KEY" >&2
  exit 1
fi
if { [ -n "${BIANBU_WEBUI_TLS_CERT:-}" ] && [ -z "${BIANBU_WEBUI_TLS_KEY:-}" ]; } || \
   { [ -z "${BIANBU_WEBUI_TLS_CERT:-}" ] && [ -n "${BIANBU_WEBUI_TLS_KEY:-}" ]; }; then
  echo "✗ TLS 证书与私钥必须同时配置" >&2
  exit 1
fi
echo "[webui] 本机访问：   http://127.0.0.1:$PORT"

exec "$PYTHON" "$HERE/app.py" --host "$HOST" --port "$PORT"
