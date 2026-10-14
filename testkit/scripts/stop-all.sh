#!/usr/bin/env bash
# 停掉测试相关服务。
#
# 两个 WebUI 是不同的东西，进程匹配必须区分开：
#   9700 测试监视台     $BNSEC_TESTKIT/webui.py
#   8787 securityd 配置台  $BIANBU_SECURITYD_HOME/webui/app.py
# 用 'python3 .*webui\.py' 这种宽模式会同时命中两个（踩过：想停配置台却停了测试台）。
#
#   ./stop-all.sh              停两个 WebUI + 测试进程 + PA（securityd 保留）
#   ./stop-all.sh --secd       连 securityd 一起停
#   ./stop-all.sh --webui      只停测试监视台(9700)
#   ./stop-all.sh --sec-webui  只停 securityd 配置台(8787)
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
# shellcheck source=env.sh
source ./env.sh

want_secd=0
only=""
for a in "$@"; do
  case "$a" in
    --secd)      want_secd=1 ;;
    --webui)     only=webui ;;
    --sec-webui) only=sec-webui ;;
    -h|--help)   sed -n '2,15p' "$0"; exit 0 ;;
    *) echo "未知参数：$a（-h 看用法）" >&2; exit 2 ;;
  esac
done

stop() {
  local pat="$1" label="$2"
  if pgrep -f "$pat" >/dev/null 2>&1; then
    pkill -f "$pat" 2>/dev/null || true
    sleep 1
    pgrep -f "$pat" >/dev/null 2>&1 && pkill -9 -f "$pat" 2>/dev/null || true
    echo "  ✓ 已停 $label"
  else
    echo "  · $label 未在运行"
  fi
}

# 按 cwd 精确停某个 webui。
#
# 不能靠 cmdline 匹配：start-webui.sh 会先 cd 再 `exec python3 webui.py`，
# cmdline 里只有相对路径（实测 "python3 webui.py"），按绝对路径 pgrep 匹配不到；
# 而放宽成 'webui.*\.py' 又会同时命中另一个 WebUI（想停配置台却停了测试台）。
# cwd 是两者唯一稳定可区分的特征。
stop_by_cwd() {
  local want_cwd="$1" name_pat="$2" label="$3" found=0 p cwd
  for p in $(pgrep -f "$name_pat" 2>/dev/null); do
    cwd=$(readlink "/proc/$p/cwd" 2>/dev/null) || continue
    [ "$cwd" = "$want_cwd" ] || continue
    kill "$p" 2>/dev/null || true
    found=1
  done
  if [ "$found" = 1 ]; then
    sleep 1
    for p in $(pgrep -f "$name_pat" 2>/dev/null); do
      cwd=$(readlink "/proc/$p/cwd" 2>/dev/null) || continue
      [ "$cwd" = "$want_cwd" ] && kill -9 "$p" 2>/dev/null || true
    done
    echo "  ✓ 已停 $label"
  else
    echo "  · $label 未在运行"
  fi
}

stop_test_webui() {
  stop_by_cwd "$BNSEC_TESTKIT" 'webui\.py' '测试监视台(9700)'
}
stop_sec_webui() {
  stop_by_cwd "$BIANBU_SECURITYD_HOME/webui" 'app\.py' 'securityd 配置台(8787)'
}

case "$only" in
  webui)     stop_test_webui; exit 0 ;;
  sec-webui) stop_sec_webui;  exit 0 ;;
esac

stop_test_webui
stop_sec_webui
stop 'runner\.py' '测试进程'
stop 'bianbu-agent.*serve' 'personal-agent'

if [ "$want_secd" = 1 ]; then
  stop 'securityd\.service' 'securityd'
else
  echo "  · securityd 保留（要停加 --secd）"
fi
