#!/usr/bin/env bash
# 把 testkit 装到持久位置（默认 /home/bianbu/bnsec-testkit）。
#
# 为什么需要这一步：先前把脚本与 testkit 放在 /tmp，而 worker 的 /tmp 是
# tmpfs（重启即失），systemd-tmpfiles 还配了 `q /tmp ... 10d` 清理 10 天前
# 的文件。装到 $HOME 下才能长期用。
#
# 在仓库的 testkit/ 目录里直接跑：
#   ./scripts/deploy.sh                     装到默认位置
#   BNSEC_TESTKIT=/opt/bnsec ./scripts/deploy.sh   装到别处
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="$(cd "$HERE/.." && pwd)"     # testkit/ 根
cd "$HERE"
# shellcheck source=env.sh
source ./env.sh

echo "源目录: $SRC"
echo "目标:   $BNSEC_TESTKIT"

for f in engine.py tests_all.py runner.py webui.py; do
  if [ ! -f "$SRC/$f" ]; then
    echo "✗ 源目录缺 $f，确认在仓库 testkit/ 下运行本脚本" >&2
    exit 1
  fi
done

mkdir -p "$BNSEC_TESTKIT/scripts"
install -m 0644 "$SRC"/engine.py "$SRC"/tests_all.py "$SRC"/runner.py \
                "$SRC"/webui.py "$BNSEC_TESTKIT/"
for f in "$SRC"/*.md; do
  [ -f "$f" ] && install -m 0644 "$f" "$BNSEC_TESTKIT/"
done
install -m 0755 "$HERE"/*.sh "$BNSEC_TESTKIT/scripts/"

# 语法自检 —— 装完就发现问题，别等跑测试时才炸
if ! (cd "$BNSEC_TESTKIT" && python3 -m py_compile engine.py tests_all.py runner.py webui.py); then
  echo "✗ 语法检查失败" >&2
  exit 1
fi
rm -rf "$BNSEC_TESTKIT/__pycache__"

echo
echo "✓ 已部署"
echo "  代码:   $BNSEC_TESTKIT/"
echo "  脚本:   $BNSEC_TESTKIT/scripts/"
echo "  产物:   $BNSEC_OUT/"
echo "  日志:   $BNSEC_LOG_DIR/"
echo
echo "接着跑："
echo "  cd $BNSEC_TESTKIT/scripts"
echo "  ./start-all.sh      # 起三个服务"
echo "  ./run-tests.sh      # 或从 WebUI 点「开始测试」"
