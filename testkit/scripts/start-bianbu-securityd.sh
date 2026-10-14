#!/usr/bin/env bash
# 启动 bianbu-securityd —— 独立脚本，无外部依赖。
#
# 与 start-securityd.sh 的区别：那个 source env.sh，要先 deploy 整套 testkit
# 才能用。本脚本自带全部默认值，拷到目标机上直接跑。
#
# 用法
#   ./start-bianbu-securityd.sh              启动（已占名则跳过）
#   ./start-bianbu-securityd.sh --status     只看状态，不动进程
#   ./start-bianbu-securityd.sh --stop       停止
#   ./start-bianbu-securityd.sh --restart    强制重启（改了代码后用）
#   ./start-bianbu-securityd.sh --foreground 前台运行，便于看启动报错
#   SECD_BUS=session ./start-bianbu-securityd.sh   强制走会话总线
#
# 路径与总线可用同名环境变量覆盖：
#   SECURITYD_HOME=/opt/securityd ./start-bianbu-securityd.sh
set -uo pipefail

# ── 可覆盖配置 ────────────────────────────────────────────
: "${SECURITYD_HOME:=/home/bianbu/impl/bianbu-securityd}"
: "${SECD_LOG_DIR:=/var/tmp/bnsec-logs}"

# 总线选择：auto | system | session
#   system  生产形态。要占名需 ① 装了 D-Bus policy ② 用户在 bianbu-security 组
#   session 免 policy、免 root，但随登录会话生死，重启掉线
: "${SECD_BUS:=auto}"
: "${DBUS_SESSION_BUS_ADDRESS:=unix:path=/run/user/$(id -u)/bus}"

BUS_NAME="io.bianbu.Security"
LOG="$SECD_LOG_DIR/securityd.log"
RUNNER="$SECD_LOG_DIR/_run_securityd.sh"

say() { printf '%s\n' "$*"; }
die() { printf '✗ %s\n' "$*" >&2; exit 1; }

# 已占名？回显总线类型（system/session），未占名返回 1
secd_owned() {
  if busctl --system list 2>/dev/null | grep -q "$BUS_NAME"; then
    echo system; return 0
  fi
  if busctl --user list 2>/dev/null | grep -q "$BUS_NAME"; then
    echo session; return 0
  fi
  return 1
}

# 该走哪条总线：auto 时按"policy 已装 且 用户在组里"判断
pick_bus() {
  case "$SECD_BUS" in
    system|session) echo "$SECD_BUS"; return 0 ;;
  esac
  if [ -f /etc/dbus-1/system.d/${BUS_NAME}.conf ] \
     && id -nG 2>/dev/null | tr ' ' '\n' | grep -qx bianbu-security; then
    echo system
  else
    echo session
  fi
}

secd_pids() {
  pgrep -f 'python3 -m securityd\.service' 2>/dev/null || true
}

show_status() {
  local pids owned
  pids="$(secd_pids)"
  say "── bianbu-securityd"
  if owned=$(secd_owned); then
    say "   D-Bus  : ✓ 已占名 $BUS_NAME（$owned 总线）"
  else
    say "   D-Bus  : ✗ 未占名 —— 判权会走 fail 分档（高危拦截、低危放行）"
  fi
  if [ -n "$pids" ]; then
    say "   进程   : PID $(echo "$pids" | tr '\n' ' ')"
  else
    say "   进程   : 未运行"
  fi
  say "   源码   : $SECURITYD_HOME"
  say "   日志   : $LOG"
  # 判权真的能调通吗 —— 占名不等于服务正常
  if [ -d "$SECURITYD_HOME" ]; then
    local probe
    probe=$(cd "$SECURITYD_HOME" && \
      PYTHONPATH="$SECURITYD_HOME:$SECURITYD_HOME/client" \
      python3 -c "
import bianbu_security_client as sc
print(int(sc.check_permission('__probe__','file.read','')))
" 2>&1 | tail -1)
    case "$probe" in
      0|1|2) say "   判权探测: ✓ CheckPermission 可调（返回 $probe）" ;;
      *PermissionDenied*未绑定*|*PermissionDenied*caller*)
             say "   判权探测: ✓ CheckPermission 可调，未绑定 caller 正确 fail-closed" ;;
      *)     say "   判权探测: ✗ ${probe:0:120}" ;;
    esac
  fi
}

stop_secd() {
  local pids
  pids="$(secd_pids)"
  if [ -z "$pids" ]; then
    say "· securityd 未在运行"
    return 0
  fi
  say "停止 securityd（PID: $(echo "$pids" | tr '\n' ' ')）…"
  # 先 TERM：让它关掉 SQLite 连接、写完审计链的当前段，避免下次启动要恢复
  kill $pids 2>/dev/null || true
  for _ in $(seq 1 10); do
    sleep 1
    [ -z "$(secd_pids)" ] && { say "✓ 已停止"; return 0; }
  done
  say "· TERM 未生效，改用 KILL"
  kill -9 $(secd_pids) 2>/dev/null || true
  sleep 1
  [ -z "$(secd_pids)" ] && say "✓ 已停止" || die "无法停止 securityd"
}

hint_bus_failure() {
  say "" >&2
  say "常见原因与处置：" >&2
  say "  ① 系统总线缺 D-Bus policy" >&2
  say "     sudo cp $SECURITYD_HOME/deploy/${BUS_NAME}.conf /etc/dbus-1/system.d/" >&2
  say "     sudo systemctl reload dbus" >&2
  say "  ② 用户不在 bianbu-security 组（加组后须重新登录才生效）" >&2
  say "     sudo groupadd -f bianbu-security" >&2
  say "     sudo usermod -aG bianbu-security \$USER" >&2
  say "  ③ 先退回会话总线应急（免 policy 免 root，但随登录会话生死）" >&2
  say "     SECD_BUS=session $0" >&2
}

# ── 参数 ──────────────────────────────────────────────────
FOREGROUND=0
FORCE_RESTART=0
case "${1:-}" in
  --status)  show_status; exit 0 ;;
  --stop)    stop_secd; exit 0 ;;
  --restart) FORCE_RESTART=1 ;;
  --foreground|-f) FOREGROUND=1; FORCE_RESTART=1 ;;
  "")        ;;
  *)         die "未知参数 ${1}（支持 --status / --stop / --restart / --foreground）" ;;
esac

# ── 前置检查 ──────────────────────────────────────────────
[ -d "$SECURITYD_HOME" ] || die "SECURITYD_HOME 不存在：$SECURITYD_HOME"
[ -f "$SECURITYD_HOME/securityd/service.py" ] \
  || die "不像 securityd 源码树（缺 securityd/service.py）：$SECURITYD_HOME"
command -v python3 >/dev/null || die "找不到 python3"
mkdir -p "$SECD_LOG_DIR" 2>/dev/null || die "无法创建日志目录：$SECD_LOG_DIR"

# 已占名就别重复启动 —— 两个实例会各写一份 capabilities.db，
# 判权结果取决于哪个先占名，排查起来极难
if owned=$(secd_owned); then
  if [ "$FORCE_RESTART" = "0" ]; then
    say "securityd 已在 $owned 总线上占名，无需重启"
    say "（改了代码要生效请用 --restart）"
    exit 0
  fi
  say "已占名（$owned 总线），按 --restart 先停掉"
  stop_secd
fi

bus=$(pick_bus)

# ── 组装环境 ──────────────────────────────────────────────
# 写成脚本再 setsid 拉起，而不是直接 `nohup ... &`：在 SSH 会话里直接
# 后台化会让子进程继承 SSH 通道的 stdout/stderr，通道等不到 EOF 就一直挂住。
{
  echo '#!/usr/bin/env bash'
  echo "cd '$SECURITYD_HOME' || exit 1"
  echo "export PATH=/usr/local/bin:/usr/bin:/bin"
  echo "export PYTHONPATH='$SECURITYD_HOME:$SECURITYD_HOME/client'"
  if [ "$bus" = "session" ]; then
    echo "export DBUS_SESSION_BUS_ADDRESS='$DBUS_SESSION_BUS_ADDRESS'"
    echo "export BIANBU_SEC_SESSION=1"
    echo "exec python3 -m securityd.service --session"
  else
    echo "exec python3 -m securityd.service"
  fi
} >"$RUNNER"
chmod +x "$RUNNER"

if [ "$FOREGROUND" = "1" ]; then
  say "前台启动（$bus 总线，Ctrl-C 退出）"
  exec "$RUNNER"
fi

say "启动 securityd（$bus 总线）…"
say "  源码 : $SECURITYD_HOME"
say "  日志 : $LOG"
setsid "$RUNNER" </dev/null >"$LOG" 2>&1 &

for i in $(seq 1 20); do
  sleep 1
  if owned=$(secd_owned); then
    say "✓ 已占名（$owned 总线，${i}s）"
    echo
    show_status
    exit 0
  fi
  if [ -z "$(secd_pids)" ] && [ "$i" -gt 2 ]; then
    say "✗ 进程已退出" >&2
    say "日志尾部：" >&2
    tail -20 "$LOG" 2>/dev/null | tr -d '\000' >&2
    hint_bus_failure
    exit 1
  fi
done

say "✗ 20s 内未占名" >&2
say "日志尾部：" >&2
tail -20 "$LOG" 2>/dev/null | tr -d '\000' >&2
hint_bus_failure
exit 1
