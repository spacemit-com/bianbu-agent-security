#!/bin/bash
# bianbu-security WebUI 启动脚本。
# 起 securityd（会话总线，若未运行）+ Flask WebUI。无需 root。
#
# 用法: bash webui/run.sh              # 默认 127.0.0.1:8787（本机访问），会话总线
#       PORT=9000 bash webui/run.sh
#       LOCAL=1 bash webui/run.sh      # 仅本机 127.0.0.1:8787
#       HOST=127.0.0.1 bash webui/run.sh # 同上（显式指定绑定地址）
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(dirname "$HERE")"
# 优先用已装 flask_socketio 的 venv python；允许 PYTHON 环境变量覆盖
if [ -z "${PYTHON:-}" ]; then
  for candidate in /tmp/bnv/bin/python3 /tmp/bnvenv2/bin/python3 python3; do
    if command -v "$candidate" >/dev/null 2>&1 && \
       "$candidate" -c "import flask_socketio" 2>/dev/null; then
      PYTHON="$candidate"; break
    fi
  done
  PYTHON="${PYTHON:-python3}"
fi
PY="$PYTHON"
PORT="${PORT:-8787}"
# 默认监听 0.0.0.0；可通过 HOST 指定监听地址，并配置
# BIANBU_WEBUI_TOKEN（开发/demo 可由 BIANBU_WEBUI_DEMO=1 关闭认证）。
if [ "${LOCAL:-0}" = "1" ] && [ -z "${HOST:-}" ]; then
  HOST="127.0.0.1"
fi
HOST="${HOST:-0.0.0.0}"

export PYTHONPATH="$ROOT:$ROOT/client"
export BIANBU_SEC_SESSION=1
# 数据根：默认用户级 ~/.local/share/bianbu-securityd（与 hermes 插件一致，勿设 BIANBU_SEC_ROOT）
unset BIANBU_SEC_ROOT || true

# 1) 确保 securityd 在会话总线上运行
if ! busctl --user status io.bianbu.Security >/dev/null 2>&1; then
  echo "[webui] securityd 未运行，后台启动…"
  nohup "$PY" -m securityd.service --session > "$HOME/securityd-webui.log" 2>&1 &
  sleep 2
fi
busctl --user status io.bianbu.Security >/dev/null 2>&1 \
  && echo "[webui] securityd 就绪" \
  || { echo "[webui] securityd 启动失败，见 ~/securityd-webui.log" >&2; exit 1; }

# 2) 起 Flask WebUI
if [ "$HOST" = "0.0.0.0" ]; then
  # 探测本机对外 IP，方便直接给出访问地址
  MYIP="$(hostname -I 2>/dev/null | awk '{print $1}')"
  echo "⚠️  ================================================================"
  echo "⚠️   WebUI 正监听 0.0.0.0:$PORT —— 同网络任何主机均可访问！"
  echo "⚠️   非回环监听必须配置 BIANBU_WEBUI_TLS_CERT/KEY；请同时配置 token 与网络 ACL。"
  echo "⚠️  ================================================================"
  echo "[webui] 跨主机访问： http://${MYIP:-<本机IP>}:$PORT"
fi
if [ -z "${BIANBU_WEBUI_TOKEN:-}" ] \
   && [ "${BIANBU_WEBUI_AUTH:-0}" != "0" ] \
   && [ "${BIANBU_WEBUI_DEMO:-0}" != "1" ]; then
  echo "错误：生产 WebUI 必须设置 BIANBU_WEBUI_TOKEN；开发临时测试可设置 BIANBU_WEBUI_AUTH=0 或 BIANBU_WEBUI_DEMO=1" >&2
  exit 1
fi
if [ "${BIANBU_WEBUI_DEMO:-0}" != "1" ] \
   && [ -n "${BIANBU_WEBUI_VIEWER_TOKEN:-}" ] \
   && [ "${BIANBU_WEBUI_VIEWER_TOKEN}" = "${BIANBU_WEBUI_TOKEN:-}" ]; then
  echo "错误：BIANBU_WEBUI_VIEWER_TOKEN 必须与管理员 token 不同" >&2
  exit 1
fi
if [ "$HOST" != "127.0.0.1" ] && [ "$HOST" != "::1" ] && [ "$HOST" != "localhost" ] \
   && [ -z "${BIANBU_WEBUI_TLS_CERT:-}" ] \
   && [ "${BIANBU_WEBUI_TRUST_PROXY:-0}" != "1" ] \
   && [ "${BIANBU_WEBUI_ALLOW_INSECURE_REMOTE:-0}" != "1" ]; then
  echo "错误：非回环 WebUI 必须设置 BIANBU_WEBUI_TLS_CERT/BIANBU_WEBUI_TLS_KEY" >&2
  exit 1
fi
if [ -n "${BIANBU_WEBUI_TLS_CERT:-}" ] && [ -z "${BIANBU_WEBUI_TLS_KEY:-}" ] || \
   [ -z "${BIANBU_WEBUI_TLS_CERT:-}" ] && [ -n "${BIANBU_WEBUI_TLS_KEY:-}" ]; then
  echo "错误：BIANBU_WEBUI_TLS_CERT 与 BIANBU_WEBUI_TLS_KEY 必须同时配置" >&2
  exit 1
fi
echo "[webui] 本机访问：   http://127.0.0.1:$PORT"
exec "$PY" "$HERE/app.py" --host "$HOST" --port "$PORT"
