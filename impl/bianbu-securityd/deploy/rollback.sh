#!/usr/bin/env bash
# 回滚到最近一次原子安装保留的 /usr/lib/bianbu-securityd.previous。
# 支持 --dry-run；真实回滚采用失败可恢复切换，旧版本启动失败时恢复原版本。
set -euo pipefail
LIB_DIR="${BIANBU_SECURITY_LIB_DIR:-/usr/lib/bianbu-securityd}"
BACKUP_DIR="${BIANBU_SECURITY_BACKUP_DIR:-${LIB_DIR}.previous}"
SYSTEMD_UNIT="${BIANBU_SECURITY_SYSTEMD_UNIT:-bianbu-securityd.service}"
DRY=0
for arg in "$@"; do
  case "$arg" in
    --dry-run) DRY=1 ;;
    *) echo "未知参数：$arg" >&2; exit 2 ;;
  esac
done
if [ "$(id -u)" != 0 ]; then
  [ "$DRY" = 1 ] || { echo "需要 root" >&2; exit 1; }
fi
if [ ! -d "$BACKUP_DIR" ]; then
  echo "没有可回滚版本：$BACKUP_DIR" >&2
  exit 1
fi
if [ "$DRY" = 1 ]; then
  echo "ROLLBACK_DRY_RUN current=$LIB_DIR previous=$BACKUP_DIR"
  exit 0
fi
FAILED_DIR=${LIB_DIR}.failed.$$.${RANDOM}
systemctl stop "$SYSTEMD_UNIT" || true
mv "$LIB_DIR" "$FAILED_DIR"
mv "$BACKUP_DIR" "$LIB_DIR"
if systemctl daemon-reload && systemctl start "$SYSTEMD_UNIT"; then
  rm -rf "$FAILED_DIR"
  echo "ROLLBACK_PASS"
else
  echo "回滚版本启动失败，恢复原版本" >&2
  systemctl stop "$SYSTEMD_UNIT" || true
  mv "$LIB_DIR" "$BACKUP_DIR"
  mv "$FAILED_DIR" "$LIB_DIR"
  systemctl daemon-reload || true
  systemctl start "$SYSTEMD_UNIT" || true
  exit 1
fi
