#!/usr/bin/env bash
# 启动 bianbu-securityd。总线由 BNSEC_BUS 决定（auto/system/session）。
#
# 系统总线要占名，前提是：
#   ① /etc/dbus-1/system.d/io.bianbu.Security.conf 已装
#   ② 当前用户在 bianbu-security 组（且已重新登录让组生效）
# 二者缺一就会 AccessDenied，此时用 BNSEC_BUS=session 退回会话总线。
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
# shellcheck source=env.sh
source ./env.sh

if owned=$(bnsec_secd_owned); then
  echo "securityd 已在 $owned 总线上占名，无需重启"
  exit 0
fi

bus=$(bnsec_pick_bus)
echo "启动 securityd（$bus 总线）…"

runner="$BNSEC_LOG_DIR/_run_securityd.sh"
{
  echo '#!/usr/bin/env bash'
  echo "cd '$BIANBU_SECURITYD_HOME' || exit 1"
  echo "export PYTHONPATH='$BIANBU_SECURITYD_HOME:$BIANBU_SECURITYD_HOME/client'"
  if [ "$bus" = "session" ]; then
    echo "export DBUS_SESSION_BUS_ADDRESS='$DBUS_SESSION_BUS_ADDRESS'"
    echo "export BIANBU_SEC_SESSION=1"
    echo "exec python3 -m securityd.service --session"
  else
    echo "exec python3 -m securityd.service"
  fi
} >"$runner"
chmod +x "$runner"

bnsec_spawn "$runner" "$BNSEC_LOG_DIR/securityd.log"

for i in $(seq 1 15); do
  sleep 1
  if owned=$(bnsec_secd_owned); then
    echo "  ✓ 已占名（$owned 总线，${i}s）"
    exit 0
  fi
done

echo "  ✗ 未占名，日志尾部：" >&2
tail -12 "$BNSEC_LOG_DIR/securityd.log" >&2
echo >&2
echo "常见原因：系统总线缺 D-Bus policy 或用户不在 bianbu-security 组。" >&2
echo "  补 policy：sudo cp $BIANBU_SECURITYD_HOME/deploy/io.bianbu.Security.conf /etc/dbus-1/system.d/" >&2
echo "  建组：     sudo groupadd -f bianbu-security && sudo usermod -aG bianbu-security \$USER（需重新登录）" >&2
echo "  或退回会话总线：BNSEC_BUS=session $0" >&2
exit 1
