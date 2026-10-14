#!/bin/bash
# re-run.sh — 检测已运行的 WebUI 进程，按需 kill 后重启。
# 用法: bash webui/re-run.sh [port]
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
PORT="${1:-${PORT:-8787}}"

# ── 查找已存在的 WebUI 进程 ─────────────────────────────
PIDS=$(pgrep -f "webui/app\.py" 2>/dev/null || true)

if [ -n "$PIDS" ]; then
  echo "⚠️  检测到 WebUI 正在运行（PID: $PIDS）"

  # 显示当前进程信息
  for pid in $PIDS; do
    cmd=$(ps -p "$pid" -o args= 2>/dev/null || echo "(已退出)")
    echo "   [$pid] $cmd"
  done

  echo ""
  printf "是否终止上述进程并重新启动？[y/N] "
  read -r ans </dev/tty

  case "$ans" in
    [yY]|[yY][eE][sS])
      echo "  正在终止旧进程…"
      for pid in $PIDS; do
        kill "$pid" 2>/dev/null && echo "  killed $pid" || echo "  $pid 已不存在"
      done
      sleep 1
      # 确认端口已释放
      if lsof -ti :"$PORT" >/dev/null 2>&1; then
        echo "  端口 $PORT 仍占用，强制 kill…"
        lsof -ti :"$PORT" | xargs kill -9 2>/dev/null || true
        sleep 1
      fi
      ;;
    *)
      echo "已取消。"
      exit 0
      ;;
  esac
else
  # 检查端口是否被其他进程占用
  if lsof -ti :"$PORT" >/dev/null 2>&1; then
    PORT_PIDS=$(lsof -ti :"$PORT")
    echo "⚠️  端口 $PORT 被占用（PID: $PORT_PIDS）"
    printf "是否终止并继续？[y/N] "
    read -r ans </dev/tty
    case "$ans" in
      [yY]|[yY][eE][sS])
        echo "$PORT_PIDS" | xargs kill 2>/dev/null || true
        sleep 1
        ;;
      *) echo "已取消。"; exit 0 ;;
    esac
  else
    echo "✓ 未发现正在运行的 WebUI，直接启动。"
  fi
fi

# ── 启动 ────────────────────────────────────────────────
exec "$HERE/run.sh"
