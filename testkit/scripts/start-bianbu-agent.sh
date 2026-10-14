#!/usr/bin/env bash
# 启动 Bianbu Agent（带 bianbu-security 全套接入）—— 脚本本身无额外依赖；BA
# 正式安装仍必须提供 Agent Memory SDK。
#
# 与 testkit/scripts/start-pa.sh 的区别：那个要先 deploy testkit 才能用
# （它 source env.sh 取路径）。本脚本自带全部默认值，拷到 worker 上直接跑。
#
# 用法
#   ./start-bianbu-agent.sh              启动（已在跑则先停）
#   ./start-bianbu-agent.sh --status     只看状态，不动进程
#   ./start-bianbu-agent.sh --stop       停止
#   ./start-bianbu-agent.sh --foreground 前台运行（Ctrl-C 退出，便于看报错）
#   ./start-bianbu-agent.sh --no-security 关掉安全接入（对照基线用）
#
# 路径可用同名环境变量覆盖：
#   BA_HOME=/opt/bianbu-agent ./start-bianbu-agent.sh
#   BA_UV_NO_SYNC=1 ./start-bianbu-agent.sh  # 仅开发验证：复用现有 venv
set -uo pipefail

# ── 可覆盖配置 ────────────────────────────────────────────
: "${BA_HOME:=/home/bianbu/bianbu-agent}"           # Bianbu Agent 源码根
: "${BA_CONFIG:=.bianbu-agent/config.yaml}"           # 相对 BA_HOME；安全交付配置
: "${BA_PORT:=9899}"
: "${BA_UV:=/home/bianbu/.local/bin/uv}"
: "${SECURITYD_HOME:=/home/bianbu/impl/bianbu-securityd}"
: "${BA_LOG_DIR:=/var/tmp/bnsec-logs}"
: "${BA_UV_NO_SYNC:=0}"                         # 仅开发验证时显式设为 1

# securityd 侧的能力注册主键。**与 bianbu-agent 本地的 agent.id
# （personal-agent-default）不是同一命名空间** —— 用错会把判权与 Token
# 用量记到一个未注册的 agent 上，配额永不触发、能力查不到。
: "${BIANBU_PA_AGENT_ID:=com.bianbu.agent}"

: "${BIANBU_SECURITY:=1}"        # 0 = 关掉全部安全接入（取基线用）
: "${BIANBU_PA_DLP:=1}"
: "${BIANBU_PA_TOKEN_METER:=1}"
# 安全策略要求 sandbox 时，必须经 PA run.sh 的 bwrap 入口启动。
: "${BIANBU_SANDBOX:=agent}"
if [ -z "${BIANBU_SEC_UDS:-}" ]; then
  if [ -S /run/bianbu/securityd.sock ]; then
    BIANBU_SEC_UDS=/run/bianbu/securityd.sock
  else
    BIANBU_SEC_UDS="$HOME/.local/share/bianbu-securityd/run/bianbu/securityd.sock"
  fi
fi

BA_URL="http://127.0.0.1:${BA_PORT}"
LOG="$BA_LOG_DIR/ba.log"
RUNNER="$BA_LOG_DIR/_run_ba.sh"
READY_MARKER="$BA_LOG_DIR/.ba-${BA_PORT}.launcher-ready"

# ── 工具函数 ──────────────────────────────────────────────
say() { printf '%s\n' "$*"; }
die() { printf '✗ %s\n' "$*" >&2; exit 1; }

ba_pids() {
  # run.sh 会把相对配置路径解析成绝对路径；按 cwd 限定本 BA_HOME，
  # 避免旧版按命令行相对路径匹配不到而留下旧进程。
  for pid in $(pgrep -f 'bianbu-agent .*serve' 2>/dev/null || true); do
    [ "$(readlink "/proc/$pid/cwd" 2>/dev/null || true)" = "$(cd "$BA_HOME" && pwd)" ] \
      && echo "$pid"
  done
}

ba_launcher_pids() {
  # 在 bwrap 启动早期，宿主机可能暂时看不到 PID namespace 内的
  # bianbu-agent；保留外层 bwrap 进程作为启动中的存活证据。
  pgrep -f "bwrap .*${BA_HOME}.*bianbu-agent.*serve" 2>/dev/null || true
}

ba_http() {
  # curl 失败时 -w 也会打印 "000"，若再叠加 fallback 的 echo 就成了 "000000"。
  # 取最后 3 位，两种路径都得到规范的三位状态码。
  local code
  code=$(curl -s -m 5 -o /dev/null -w '%{http_code}' "$BA_URL/" 2>/dev/null)
  echo "${code: -3}"
}

show_status() {
  local pids code
  pids="$(ba_pids)"
  code="$(ba_http)"
  say "── bianbu-agent"
  if [ -n "$pids" ]; then
    say "   进程 PID: $(echo "$pids" | tr '\n' ' ')"
  else
    say "   进程   : 未运行"
  fi
  if [ "$code" = "200" ]; then
    say "   HTTP   : ✓ 200（$BA_URL）"
  else
    say "   HTTP   : ✗ $code（$BA_URL）"
  fi
  say "   日志   : $LOG"
  say "── securityd"
  if busctl --system list 2>/dev/null | grep -q io.bianbu.Security; then
    say "   ✓ 已占名（system 总线）"
  elif busctl --user list 2>/dev/null | grep -q io.bianbu.Security; then
    say "   ✓ 已占名（session 总线）"
  else
    say "   ✗ 未占名 —— 判权会走 fail 分档（高危拦截、低危放行）"
  fi
  say "   安全接入: BIANBU_SECURITY=$BIANBU_SECURITY  agent_id=$BIANBU_PA_AGENT_ID"
}

stop_ba() {
  local pids
  pids="$(ba_pids)"
  if [ -z "$pids" ]; then
    say "· Bianbu Agent 未在运行"
    return 0
  fi
  say "停止 Bianbu Agent（PID: $(echo "$pids" | tr '\n' ' ')）…"
  # 先 TERM 让它清理 checkpointer / 释放端口，不行再 KILL
  kill $pids 2>/dev/null || true
  for _ in $(seq 1 10); do
    sleep 1
    [ -z "$(ba_pids)" ] && { say "✓ 已停止"; return 0; }
  done
  say "· TERM 未生效，改用 KILL"
  kill -9 $(ba_pids) 2>/dev/null || true
  sleep 1
  [ -z "$(ba_pids)" ] && say "✓ 已停止" || die "无法停止 PA"
}

# ── 参数 ──────────────────────────────────────────────────
FOREGROUND=0
case "${1:-}" in
  --status)  show_status; exit 0 ;;
  --stop)    stop_ba; exit 0 ;;
  --foreground|-f) FOREGROUND=1 ;;
  --no-security)   BIANBU_SECURITY=0 ;;
  "")        ;;
  *)         die "未知参数 ${1}（支持 --status / --stop / --foreground / --no-security）" ;;
esac

if [ "$BIANBU_SECURITY" = "0" ]; then
  BIANBU_SANDBOX=off
fi

# ── 前置检查 ──────────────────────────────────────────────
[ -d "$BA_HOME" ]                || die "BA_HOME 不存在：$BA_HOME"
[ -f "$BA_HOME/$BA_CONFIG" ]     || die "配置不存在：$BA_HOME/$BA_CONFIG"
[ -x "$BA_UV" ]                  || die "uv 不可执行：$BA_UV（用 BA_UV=... 指定）"
if [ ! -d "$BA_HOME/../bianbu-agent-memory/sdk/python" ]; then
  if [ "$BA_UV_NO_SYNC" = "1" ]; then
    say "⚠ 未找到 Agent Memory SDK：开发态 BA_UV_NO_SYNC=1，复用现有 venv"
  else
    die "未找到 Agent Memory SDK：$BA_HOME/../bianbu-agent-memory/sdk/python；请先部署 SDK，或仅开发验证时显式设置 BA_UV_NO_SYNC=1"
  fi
fi
if [ "$BIANBU_SECURITY" = "1" ] && [ ! -d "$SECURITYD_HOME" ]; then
  say "⚠ securityd 源码树不存在：$SECURITYD_HOME"
  say "  判权桥接会不可用，PA 仍可启动但安全接入形同关闭"
fi
mkdir -p "$BA_LOG_DIR" 2>/dev/null || die "无法创建日志目录：$BA_LOG_DIR"
rm -f "$READY_MARKER"

stop_ba

# ── 组装环境 ──────────────────────────────────────────────
# 写成脚本再 setsid 拉起，而不是直接 `nohup ... &`：
# 在 SSH 会话里直接后台化会让子进程继承 SSH 通道的 stdout/stderr，
# 通道等不到 EOF 就一直挂着，远端调用方（ssh / paramiko）卡到超时。踩过多次。
cat >"$RUNNER" <<EOF
#!/usr/bin/env bash
cd '$BA_HOME' || exit 1
# uv 所在目录必须在 PATH 里：部分测试会 subprocess 调 uv，
# 非交互 shell 默认不带 ~/.local/bin
export PATH="\$(dirname '$BA_UV'):/usr/local/bin:/usr/bin:/bin"
export BIANBU_SECURITY='$BIANBU_SECURITY'
export BIANBU_SECURITYD_HOME='$SECURITYD_HOME'
export BIANBU_SEC_UDS='$BIANBU_SEC_UDS'
export BIANBU_PA_AGENT_ID='$BIANBU_PA_AGENT_ID'
export BIANBU_PA_DLP='$BIANBU_PA_DLP'
export BIANBU_PA_TOKEN_METER='$BIANBU_PA_TOKEN_METER'
export BIANBU_SANDBOX='$BIANBU_SANDBOX'
export BIANBU_AGENT_CONFIG='$BA_CONFIG'
export UV_NO_SYNC='$BA_UV_NO_SYNC'
touch '$READY_MARKER'
exec '$BA_HOME/run.sh' serve
EOF
chmod +x "$RUNNER"

if [ "$FOREGROUND" = "1" ]; then
  say "前台启动（Ctrl-C 退出）：$BA_HOME"
  exec "$RUNNER"
fi

say "启动 PA…"
say "  源码 : $BA_HOME"
say "  配置 : $BA_CONFIG"
say "  日志 : $LOG"
# bwrap 使用 --die-with-parent；强制 setsid fork，避免 SSH/启动脚本退出时
# 把 PA 一并回收。Runner 被 reparent 到 init 后才可作为后台服务持续运行。
setsid --fork "$RUNNER" </dev/null >"$LOG" 2>&1 &

for i in $(seq 1 30); do
  sleep 2
  if [ "$(ba_http)" = "200" ]; then
    say "✓ Bianbu Agent 就绪（${i} 次探测，$BA_URL）"
    echo
    show_status
    exit 0
  fi
  # bwrap/uv 在 RISC-V worker 上首次启动可能超过 6 秒；只有启动器进程
  # 已退出且没有 PA 子进程时才提前判定失败，不能把“尚未出现内层 PID”误报成失败。
  if [ "$i" -gt 5 ] && [ -f "$READY_MARKER" ] \
      && [ -z "$(ba_pids)" ] \
      && [ -z "$(ba_launcher_pids)" ]; then
    say "✗ 进程已退出" >&2
    say "日志尾部：" >&2
    tail -30 "$LOG" 2>/dev/null | tr -d '\000' >&2
    exit 1
  fi
done

say "✗ 未在 60s 内就绪" >&2
say "日志尾部：" >&2
tail -30 "$LOG" 2>/dev/null | tr -d '\000' >&2
exit 1
