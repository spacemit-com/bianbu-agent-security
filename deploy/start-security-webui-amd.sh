#!/usr/bin/env bash
# x86/Ubuntu/AMD 开发机一键启动 bianbu-securityd + Security WebUI。
# 不依赖 run.sh；使用系统 Python 3.12（兼容 dbus-python CPython 3.12 ABI），
# 并通过用户 systemd 保持进程脱离当前终端。
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SECURITYD_HOME="${BIANBU_SECURITYD_HOME:-$ROOT/impl/bianbu-securityd}"
PYTHON="${PYTHON:-/usr/bin/python3.12}"
HOST="${SECURITY_WEBUI_HOST:-0.0.0.0}"
PORT="${SECURITY_WEBUI_PORT:-8787}"
BUS="${DBUS_SESSION_BUS_ADDRESS:-unix:path=/run/user/$(id -u)/bus}"
UNIT_PREFIX="bianbu-security-dev"
STATE_DIR="${XDG_RUNTIME_DIR:-/tmp}/bianbu-security-dev"
mkdir -p "$STATE_DIR"
PYTHONPATH_VALUE="$SECURITYD_HOME:$SECURITYD_HOME/client:$SECURITYD_HOME/.venv/lib/python3.14/site-packages:/usr/lib/python3/dist-packages"

die() { echo "错误：$*" >&2; exit 1; }
command -v systemd-run >/dev/null || die "缺少 systemd-run --user"
[ -x "$PYTHON" ] || die "找不到兼容 Python：$PYTHON"
[ -f "$SECURITYD_HOME/webui/app.py" ] || die "找不到 Security WebUI：$SECURITYD_HOME/webui/app.py"

status() {
  systemctl --user --no-pager --plain --full status "${UNIT_PREFIX}-securityd.service" "${UNIT_PREFIX}-webui.service" 2>/dev/null || true
  echo "监听："
  ss -ltnp 2>/dev/null | grep -E ":${PORT}\b" || true
}

stop() {
  systemctl --user stop "${UNIT_PREFIX}-webui.service" "${UNIT_PREFIX}-securityd.service" 2>/dev/null || true
  if [ -s "$STATE_DIR/webui.pid" ]; then kill "$(cat "$STATE_DIR/webui.pid")" 2>/dev/null || true; fi
  echo "已停止开发 Security WebUI/securityd（仅停止本脚本创建的用户 unit）。"
}

case "${1:-start}" in
  --status|status) status; exit 0 ;;
  --stop|stop) stop; exit 0 ;;
  start) ;;
  *) die "用法：$0 [--status|--stop]" ;;
esac

systemctl --user is-system-running >/dev/null 2>&1 || die "用户 systemd 不可用"

# 已有可用 securityd 时复用，避免创建第二个实例；否则创建持久用户 unit。
if ! busctl --user status io.bianbu.Security >/dev/null 2>&1; then
  systemd-run --user --unit="${UNIT_PREFIX}-securityd.service" --collect \
    --property=Restart=on-failure --property=RestartSec=2 \
    --setenv=DBUS_SESSION_BUS_ADDRESS="$BUS" \
    --setenv=BIANBU_SEC_SESSION=1 --setenv=BIANBU_SECURITY_TEST_ADMIN=1 \
    --setenv=BIANBU_SECURITYD_HOME="$SECURITYD_HOME" \
    --setenv=PYTHONPATH="$PYTHONPATH_VALUE" \
    --working-directory="$SECURITYD_HOME" \
    "$PYTHON" -m securityd.service --session >/dev/null
  for _ in $(seq 1 30); do
    busctl --user status io.bianbu.Security >/dev/null 2>&1 && break
    sleep .2
  done
  busctl --user status io.bianbu.Security >/dev/null 2>&1 || die "securityd 启动失败：journalctl --user -u ${UNIT_PREFIX}-securityd.service"
else
  echo "复用已运行的 io.bianbu.Security（不会启动第二个 securityd）。"
fi

systemctl --user stop "${UNIT_PREFIX}-webui.service" 2>/dev/null || true
if ! systemd-run --user --unit="${UNIT_PREFIX}-webui.service" --collect \
  --property=Restart=on-failure --property=RestartSec=2 \
  --setenv=DBUS_SESSION_BUS_ADDRESS="$BUS" \
  --setenv=BIANBU_SEC_SESSION=1 --setenv=BIANBU_SECURITY_TEST_ADMIN=1 \
  --setenv=BIANBU_WEBUI_DEMO=1 --setenv=BIANBU_WEBUI_ALLOW_INSECURE_REMOTE=1 \
  --setenv=BIANBU_SECURITYD_HOME="$SECURITYD_HOME" \
  --setenv=PYTHONPATH="$PYTHONPATH_VALUE" \
  --working-directory="$SECURITYD_HOME" \
  "$PYTHON" webui/app.py --host "$HOST" --port "$PORT" >/dev/null; then
  :
fi
if ! systemctl --user is-active --quiet "${UNIT_PREFIX}-webui.service"; then
  nohup setsid bash -c "cd '$SECURITYD_HOME' && exec env DBUS_SESSION_BUS_ADDRESS='$BUS' BIANBU_SEC_SESSION=1 \
    BIANBU_SECURITY_TEST_ADMIN=1 BIANBU_WEBUI_DEMO=1 \
    BIANBU_WEBUI_ALLOW_INSECURE_REMOTE=1 BIANBU_SECURITYD_HOME='$SECURITYD_HOME' \
    PYTHONPATH='$PYTHONPATH_VALUE' '$PYTHON' webui/app.py --host '$HOST' --port '$PORT'" \
    >"$STATE_DIR/webui.log" 2>&1 < /dev/null &
  echo $! >"$STATE_DIR/webui.pid"
fi

for _ in $(seq 1 30); do
  code="$(curl -sS -m 1 -o /dev/null -w '%{http_code}' "http://127.0.0.1:${PORT}/" 2>/dev/null || true)"
  [ "$code" = 200 ] && break
  sleep .2
done
[ "${code:-000}" = 200 ] || { journalctl --user -u "${UNIT_PREFIX}-webui.service" -n 30 --no-pager; die "WebUI 启动失败"; }

IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
echo "Security WebUI 已启动（用户 systemd 持久运行）"
echo "本机：http://127.0.0.1:${PORT}"
echo "远程：http://${IP:-<本机IP>}:${PORT}"
echo "状态：$0 --status"
echo "停止：$0 --stop"
