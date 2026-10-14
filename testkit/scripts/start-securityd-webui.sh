#!/usr/bin/env bash
# 启动 securityd 配置台 WebUI —— 独立脚本，无外部依赖。
#
# 与 start-sec-webui.sh 的区别：那个 source env.sh，要先 deploy 整套 testkit
# 才能用。本脚本自带全部默认值，拷到目标机上直接跑。
#
# ⚠️ 安全提示：开发/demo 包由 systemd drop-in 设置 BIANBU_WEBUI_DEMO=1 关闭认证；
#    产品包启用认证时需要 BIANBU_WEBUI_TOKEN，且内置 Web Terminal
#    （管理员 token 才能使用）。绑 0.0.0.0 仍需显式 --lan，并配置 TLS；
#    要查看已配置的管理员 token，可执行 --get-token。
#
# 注意别和 testkit 的测试监视台搞混：
#   8787  securityd 配置台   —— 管能力/配额/DLP策略/审计/沙箱（securityd 自带）
#   9700  testkit 测试监视台 —— 跑测试项、看报告（testkit/webui.py）
#
# 用法
#   ./start-securityd-webui.sh              启动，仅本机可访问
#   ./start-securityd-webui.sh --lan        绑 0.0.0.0，内网可访问（危险）
#   ./start-securityd-webui.sh --status     只看状态
#   ./start-securityd-webui.sh --get-token  输出已配置的管理员认证 token
#   ./start-securityd-webui.sh --stop       停止
#   ./start-securityd-webui.sh --foreground 前台运行，便于看启动报错
#   SECD_WEB_PORT=9001 ./start-securityd-webui.sh
set -uo pipefail

# ── 可覆盖配置 ────────────────────────────────────────────
: "${SECURITYD_HOME:=/home/bianbu/impl/bianbu-securityd}"
: "${SECD_WEB_PORT:=8787}"
: "${SECD_LOG_DIR:=/var/tmp/bnsec-logs}"
: "${DBUS_SESSION_BUS_ADDRESS:=unix:path=/run/user/$(id -u)/bus}"
: "${BIANBU_SECURITY_WEBUI_ENV_FILE:=/etc/bianbu/webui.env}"
# This standalone testkit launcher is a development/demo entry point.  A
# product systemd unit uses its own environment and never inherits this flag.
: "${BIANBU_WEBUI_DEMO:=1}"
export BIANBU_WEBUI_DEMO

BUS_NAME="io.bianbu.Security"
WEBUI_DIR="$SECURITYD_HOME/webui"
LOG="$SECD_LOG_DIR/sec-webui.log"
RUNNER="$SECD_LOG_DIR/_run_secwebui.sh"

say() { printf '%s\n' "$*"; }
die() { printf '✗ %s\n' "$*" >&2; exit 1; }

secd_owned() {
  if busctl --system list 2>/dev/null | grep -q "$BUS_NAME"; then
    echo system; return 0
  fi
  if busctl --user list 2>/dev/null | grep -q "$BUS_NAME"; then
    echo session; return 0
  fi
  return 1
}

webui_pids() {
  pgrep -f 'webui/app\.py' 2>/dev/null || true
}

web_http() {
  # curl 失败时 -w 也会打印 "000"，若再叠加 fallback 的 echo 就成了 "000000"。
  # 取最后 3 位，两种路径都得到规范的三位状态码。
  local code
  code=$(curl -s -m 5 -o /dev/null -w '%{http_code}' \
    "http://127.0.0.1:${SECD_WEB_PORT}/" 2>/dev/null)
  echo "${code: -3}"
}

show_status() {
  local pids code bound
  pids="$(webui_pids)"
  code="$(web_http)"
  say "── securityd 配置台（端口 $SECD_WEB_PORT）"
  if [ -n "$pids" ]; then
    say "   进程   : PID $(echo "$pids" | tr '\n' ' ')"
  else
    say "   进程   : 未运行"
  fi
  if [ "$code" = "200" ]; then
    say "   HTTP   : ✓ 200（http://127.0.0.1:$SECD_WEB_PORT）"
    # 实际绑在哪个地址 —— 绑 0.0.0.0 时要把警告说清楚
    bound=$(ss -ltnp 2>/dev/null | grep ":$SECD_WEB_PORT " | awk '{print $4}' | head -1)
    [ -n "$bound" ] && say "   监听   : $bound"
    case "$bound" in
      0.0.0.0:*|\[::\]:*|:::*)
        say "   ⚠️  绑在所有网卡 —— 必须启用管理员 token 与 TLS，Web Terminal 仅管理员可用"
        ;;
    esac
  else
    say "   HTTP   : ✗ $code"
  fi
  say "   日志   : $LOG"
  if owned=$(secd_owned); then
    say "── securityd: ✓ 已占名（$owned 总线）"
  else
    say "── securityd: ✗ 未占名 —— 配置台会连不上，先跑 ./start-bianbu-securityd.sh"
  fi
}

get_webui_token() {
  local pid token env_file

  # 优先读取正在运行的 WebUI 进程，确保显示的是当前实际生效的 token。
  for pid in $(webui_pids); do
    [ -r "/proc/$pid/environ" ] || continue
    token=$(tr '\0' '\n' <"/proc/$pid/environ" 2>/dev/null \
      | sed -n 's/^BIANBU_WEBUI_TOKEN=//p' | tail -1)
    if [ -n "$token" ]; then
      say "BIANBU_WEBUI_TOKEN=$token"
      return 0
    fi
  done

  if [ "${BIANBU_WEBUI_DEMO:-0}" = "1" ]; then
    say "BIANBU_WEBUI_AUTH=0（开发/demo 模式；不需要 token）"
    return 0
  fi

  # 未运行时读取当前 shell 或部署环境文件。只解析 KEY=VALUE，不 source
  # 文件，避免 --get-token 执行环境文件中的任意 shell 代码。
  if [ -n "${BIANBU_WEBUI_TOKEN:-}" ]; then
    say "BIANBU_WEBUI_TOKEN=$BIANBU_WEBUI_TOKEN"
    return 0
  fi
  for env_file in "$BIANBU_SECURITY_WEBUI_ENV_FILE" /etc/bianbu/webui.env \
      "$SECURITYD_HOME/deploy/webui.env"; do
    [ -r "$env_file" ] || continue
    token=$(sed -n 's/^BIANBU_WEBUI_TOKEN=//p' "$env_file" | tail -1)
    token=${token#\"}; token=${token%\"}
    token=${token#\'}; token=${token%\'}
    [ -n "$token" ] || continue
    case "$token" in
      REPLACE_WITH_*|CHANGE_ME|changeme|*placeholder*) continue ;;
    esac
    say "BIANBU_WEBUI_TOKEN=$token"
    return 0
  done

  die "未找到 BIANBU_WEBUI_TOKEN：WebUI 未运行且当前环境/配置文件中没有有效管理员 token"
}

stop_webui() {
  local pids
  pids="$(webui_pids)"
  if [ -z "$pids" ]; then
    say "· 配置台未在运行"
    return 0
  fi
  say "停止配置台（PID: $(echo "$pids" | tr '\n' ' ')）…"
  kill $pids 2>/dev/null || true
  for _ in $(seq 1 8); do
    sleep 1
    [ -z "$(webui_pids)" ] && { say "✓ 已停止"; return 0; }
  done
  kill -9 $(webui_pids) 2>/dev/null || true
  sleep 1
  [ -z "$(webui_pids)" ] && say "✓ 已停止" || die "无法停止配置台"
}

# ── 参数 ──────────────────────────────────────────────────
FOREGROUND=0
BIND_LAN=0
case "${1:-}" in
  --status)  show_status; exit 0 ;;
  --get-token) get_webui_token; exit 0 ;;
  --stop)    stop_webui; exit 0 ;;
  --lan)     BIND_LAN=1 ;;
  --foreground|-f) FOREGROUND=1 ;;
  "")        ;;
  *)         die "未知参数 ${1}（支持 --lan / --status / --get-token / --stop / --foreground）" ;;
esac

# ── 前置检查 ──────────────────────────────────────────────
[ -d "$WEBUI_DIR" ] || die "找不到 webui 目录：$WEBUI_DIR"
[ -f "$WEBUI_DIR/app.py" ] || die "找不到 $WEBUI_DIR/app.py"
mkdir -p "$SECD_LOG_DIR" 2>/dev/null || die "无法创建日志目录：$SECD_LOG_DIR"

# 配置台是 securityd 的前端，securityd 没起就没有意义 —— 提前说清楚，
# 免得看到一堆 D-Bus 报错才反应过来
if ! bus=$(secd_owned); then
  die "securityd 未占名 —— 先跑 ./start-bianbu-securityd.sh"
fi

stop_webui

# ── 选启动器 ──────────────────────────────────────────────
# 必须按 securityd 实际所在的总线选：
# run.sh 写死 BIANBU_SEC_SESSION=1（会话总线），若 securityd 在系统总线上，
# 它会因查不到而去启动第二个 securityd 实例，两个各写一份 capabilities.db。
if [ "$bus" = "session" ]; then
  LAUNCHER="run.sh"
  [ -f "$WEBUI_DIR/run.sh" ] || die "缺 $WEBUI_DIR/run.sh"
else
  LAUNCHER="run-system-bus.sh"
  if [ ! -f "$WEBUI_DIR/run-system-bus.sh" ]; then
    say "✗ 缺 $WEBUI_DIR/run-system-bus.sh" >&2
    say "  从仓库同步：scp impl/bianbu-securityd/webui/run-system-bus.sh \\" >&2
    say "                  bianbu@<worker>:$WEBUI_DIR/" >&2
    exit 1
  fi
fi

# 默认只绑本机；绑 0.0.0.0 时必须同时配置认证、TLS 和网络 ACL。
if [ "$BIND_LAN" = "1" ]; then
  BIND_HOST="0.0.0.0"
else
  BIND_HOST="127.0.0.1"
fi

cat >"$RUNNER" <<EOF
#!/usr/bin/env bash
export PATH=/usr/local/bin:/usr/bin:/bin
cd '$WEBUI_DIR' || exit 1
EOF
if [ "$bus" = "session" ]; then
  echo "export DBUS_SESSION_BUS_ADDRESS='$DBUS_SESSION_BUS_ADDRESS'" >>"$RUNNER"
fi
cat >>"$RUNNER" <<EOF
export PORT='$SECD_WEB_PORT'
export HOST='$BIND_HOST'
exec bash './$LAUNCHER'
EOF
chmod +x "$RUNNER"

if [ "$FOREGROUND" = "1" ]; then
  say "前台启动（$bus 总线，绑 $BIND_HOST:$SECD_WEB_PORT，Ctrl-C 退出）"
  exec "$RUNNER"
fi

say "启动 securityd 配置台（$bus 总线，绑 $BIND_HOST:$SECD_WEB_PORT）…"
say "  日志 : $LOG"
setsid "$RUNNER" </dev/null >"$LOG" 2>&1 &

for i in $(seq 1 20); do
  sleep 1
  if [ "$(web_http)" = "200" ]; then
    say "✓ 配置台就绪（${i}s）"
    echo
    if [ "$BIND_LAN" = "1" ]; then
      ip=$(hostname -I 2>/dev/null | awk '{print $1}')
      say "  访问：http://${ip:-127.0.0.1}:$SECD_WEB_PORT"
      say "  ⚠️  请确认管理员 token、TLS 和网络 ACL 已配置；用完请 --stop"
    else
      say "  访问：http://127.0.0.1:$SECD_WEB_PORT （仅本机）"
      say "  远程看：ssh -L $SECD_WEB_PORT:127.0.0.1:$SECD_WEB_PORT bianbu@<worker>"
      say "  要直接对内网开放（危险）：$0 --lan"
    fi
    exit 0
  fi
  if [ -z "$(webui_pids)" ] && [ "$i" -gt 3 ]; then
    say "✗ 进程已退出" >&2
    say "日志尾部：" >&2
    tail -20 "$LOG" 2>/dev/null | tr -d '\000' >&2
    exit 1
  fi
done

say "✗ 20s 内未就绪" >&2
say "日志尾部：" >&2
tail -20 "$LOG" 2>/dev/null | tr -d '\000' >&2
exit 1
