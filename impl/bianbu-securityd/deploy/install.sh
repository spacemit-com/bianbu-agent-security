#!/usr/bin/env bash
# bianbu-securityd 系统部署脚本（需 root）
#
# V-02 实测：会话总线免 policy 可占名，系统总线必须有 /etc/dbus-1/system.d/
# 下的 policy 才能 RequestName。本脚本装齐 policy + 激活文件 + systemd unit。
#
# 用法：
#   sudo ./install.sh                    装齐并启动 Security（默认不接管 Runtime）
#   sudo ./install.sh --codesign-key /secure/release.pub
#   sudo ./install.sh --runtime-venv /release/bnsec-venv
#   sudo ./install.sh --enable-runtime   显式启用仓库内参考 Runtime（仅测试/参考部署）
#   sudo ./install.sh --enable-webui     显式启用本机认证 WebUI（需先配置 env）
#   sudo ./install.sh --dry-run          只打印要做什么
#   sudo ./install.sh --uninstall        卸载 Security，不停止外部 Runtime

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC_ROOT="$(cd "$HERE/.." && pwd)"

LIB_DIR=/usr/lib/bianbu-securityd
CLEAR_TOOL=/usr/bin/bianbu-security-clear-data
DBUS_POLICY=/etc/dbus-1/system.d/io.bianbu.Security.conf
DBUS_ACTIVATION=/usr/share/dbus-1/system-services/io.bianbu.Security.service
POLKIT_POLICY=/usr/share/polkit-1/actions/io.bianbu.security.policy
RUNTIME_DBUS_ACTIVATION=/usr/share/dbus-1/system-services/io.bianbu.Runtime.service
RUNTIME_DBUS_POLICY=/etc/dbus-1/system.d/io.bianbu.Runtime.conf
SYSTEMD_UNIT=/etc/systemd/system/bianbu-securityd.service
RUNTIME_SYSTEMD_UNIT=/etc/systemd/system/bianbu-agent-runtimed.service
WEBUI_SYSTEMD_UNIT=/etc/systemd/system/bianbu-security-webui.service
SYSTEMD_UNIT_PREVIOUS=${SYSTEMD_UNIT}.previous
WEBUI_SYSTEMD_UNIT_PREVIOUS=${WEBUI_SYSTEMD_UNIT}.previous
RUNTIME_SYSTEMD_UNIT_PREVIOUS=${RUNTIME_SYSTEMD_UNIT}.previous
SVC_USER=bianbu-security
SVC_GROUP=bianbu-security
ADMIN_GROUP=bianbu-admin
RUNTIME_USER=bianbu-runtime
RUNTIME_GROUP=bianbu-runtime

DRY=0
UNINSTALL=0
ENABLE_RUNTIME=0
ENABLE_WEBUI=0
CODE_SIGN_KEY=
RUNTIME_VENV=
while [ "$#" -gt 0 ]; do
  case "$1" in
    --dry-run) DRY=1 ;;
    --uninstall) UNINSTALL=1 ;;
    --enable-runtime) ENABLE_RUNTIME=1 ;;
    --enable-webui) ENABLE_WEBUI=1 ;;
    --codesign-key)
      [ "$#" -ge 2 ] || { echo "--codesign-key 缺少公钥路径" >&2; exit 2; }
      CODE_SIGN_KEY="$2"
      shift
      ;;
    --runtime-venv)
      [ "$#" -ge 2 ] || { echo "--runtime-venv 缺少冻结 venv 路径" >&2; exit 2; }
      RUNTIME_VENV="$2"
      shift
      ;;
    *) echo "未知参数：$1" >&2; exit 2 ;;
  esac
  shift
done

run() {
  if [ "$DRY" = 1 ]; then printf '  [dry-run] %s\n' "$*"; else "$@"; fi
}

restore_previous() {
  if [ "$SWITCHED" = 1 ] && [ -d "$BACKUP_DIR" ] && [ -d "$LIB_DIR" ]; then
    FAILED_DIR="${LIB_DIR}.failed.$$.${RANDOM}"
    mv "$LIB_DIR" "$FAILED_DIR"
    mv "$BACKUP_DIR" "$LIB_DIR"
    [ -f "$SYSTEMD_UNIT_PREVIOUS" ] && cp -a "$SYSTEMD_UNIT_PREVIOUS" "$SYSTEMD_UNIT"
    [ -f "$WEBUI_SYSTEMD_UNIT_PREVIOUS" ] && cp -a "$WEBUI_SYSTEMD_UNIT_PREVIOUS" "$WEBUI_SYSTEMD_UNIT"
    [ -f "$RUNTIME_SYSTEMD_UNIT_PREVIOUS" ] && cp -a "$RUNTIME_SYSTEMD_UNIT_PREVIOUS" "$RUNTIME_SYSTEMD_UNIT"
    systemctl daemon-reload || true
    systemctl start bianbu-securityd.service || true
    if [ "$WEBUI_WAS_ACTIVE" = 1 ]; then
      systemctl start bianbu-security-webui.service || true
    fi
    echo "已恢复上一版本，失败版本保留在 $FAILED_DIR" >&2
    SWITCHED=0
  fi
}

need_root() {
  if [ "$DRY" = 0 ] && [ "$(id -u)" != 0 ]; then
    echo "需要 root：sudo $0 $*" >&2; exit 1
  fi
}

if [ "$UNINSTALL" = 1 ]; then
  need_root
  echo "== 卸载 bianbu-securityd"
  run systemctl disable --now bianbu-securityd.service || true
  # Runtime 由外部 Runtime 包/系统镜像拥有；Security 卸载不得停止或删除
  # 它的 unit、D-Bus policy 或 activation 文件。
  run rm -f "$SYSTEMD_UNIT" "$DBUS_POLICY" "$DBUS_ACTIVATION"
  run rm -f "$CLEAR_TOOL"
  run rm -f "$POLKIT_POLICY"
  if [ "$ENABLE_RUNTIME" = 1 ]; then
    run systemctl disable --now bianbu-agent-runtimed.service || true
    run rm -f "$RUNTIME_SYSTEMD_UNIT" "$RUNTIME_DBUS_ACTIVATION" "$RUNTIME_DBUS_POLICY"
  fi
  if [ "$ENABLE_WEBUI" = 1 ] || [ -f "$WEBUI_SYSTEMD_UNIT" ]; then
    run systemctl disable --now bianbu-security-webui.service || true
    run rm -f "$WEBUI_SYSTEMD_UNIT"
  fi
  run systemctl daemon-reload
  # 重载 dbus 配置，让 policy 移除生效（不重启 dbus，避免打断在线会话）
  run systemctl reload dbus.service || true
  echo "   代码目录 $LIB_DIR 与数据目录 /etc/bianbu /var/log/bianbu 保留"
  echo "   （审计链与密钥不自动删除，需要时手工清理）"
  exit 0
fi

need_root

echo "== 1. 建服务用户与管理组"
if ! getent group "$SVC_GROUP" >/dev/null; then
  run groupadd --system "$SVC_GROUP"
fi
if ! getent group "$ADMIN_GROUP" >/dev/null; then
  run groupadd --system "$ADMIN_GROUP"
fi
if ! getent passwd "$SVC_USER" >/dev/null; then
  run useradd --system --gid "$SVC_GROUP" --groups "$ADMIN_GROUP" \
      --home-dir "$LIB_DIR" --shell /usr/sbin/nologin \
      --comment "Bianbu Security Daemon" "$SVC_USER"
fi
if [ "$ENABLE_RUNTIME" = 1 ]; then
  if ! getent group "$RUNTIME_GROUP" >/dev/null; then
    run groupadd --system "$RUNTIME_GROUP"
  fi
  if ! getent passwd "$RUNTIME_USER" >/dev/null; then
    run useradd --system --gid "$RUNTIME_GROUP" --groups "$SVC_GROUP" \
        --home-dir /var/lib/bianbu/runtime --shell /usr/sbin/nologin \
        --comment "Bianbu Agent Runtime" "$RUNTIME_USER"
  fi
fi

echo "== 2. 装代码到 $LIB_DIR"
STAGE_DIR="${LIB_DIR}.staging.$$"
BACKUP_DIR="${LIB_DIR}.previous"
SWITCHED=0
OLD_STOPPED=0
WEBUI_WAS_ACTIVE=0
if [ "$DRY" = 0 ]; then
  trap 'rc=$?; if [ "$rc" -ne 0 ]; then if [ "$SWITCHED" = 1 ]; then restore_previous || true; elif [ "$OLD_STOPPED" = 1 ]; then systemctl start bianbu-securityd.service || true; if [ "$WEBUI_WAS_ACTIVE" = 1 ]; then systemctl start bianbu-security-webui.service || true; fi; fi; fi; rm -rf "$STAGE_DIR"; exit "$rc"' EXIT
fi
run install -d -m 0755 "$STAGE_DIR"
for d in securityd client cli webui hermes_plugin runtime; do
  [ -d "$SRC_ROOT/$d" ] || continue
  run cp -a "$SRC_ROOT/$d" "$STAGE_DIR/"
done
# D-Bus 契约和部署资产独立安装，避免仅复制 Python 包时遗漏 policy/XML。
run install -d -m 0755 "$STAGE_DIR/data" "$STAGE_DIR/deploy"
run cp -a "$SRC_ROOT/data/." "$STAGE_DIR/data/"
run cp -a "$SRC_ROOT/deploy/." "$STAGE_DIR/deploy/"
if [ -f "$SRC_ROOT/requirements-lock.txt" ]; then
  run cp -a "$SRC_ROOT/requirements-lock.txt" "$STAGE_DIR/requirements-lock.txt"
fi
if [ -f "$SRC_ROOT/THIRD_PARTY_LICENSES.md" ]; then
  run cp -a "$SRC_ROOT/THIRD_PARTY_LICENSES.md" "$STAGE_DIR/THIRD_PARTY_LICENSES.md"
fi
run chown -R root:root "$STAGE_DIR"
run find "$STAGE_DIR" -type d -exec chmod 0755 {} +
run find "$STAGE_DIR" -type f -exec chmod 0644 {} +
run find "$STAGE_DIR/deploy" -type f -name '*.sh' -exec chmod 0755 {} +
run install -m 0755 "$SRC_ROOT/deploy/clear-security-data.sh" "$CLEAR_TOOL"
if [ -n "$RUNTIME_VENV" ]; then
  if [ "$DRY" = 0 ]; then
    [ -x "$RUNTIME_VENV/bin/python" ] || {
      echo "冻结运行环境缺少可执行解释器：$RUNTIME_VENV/bin/python" >&2; exit 1;
    }
  fi
  run cp -a "$RUNTIME_VENV" "$STAGE_DIR/venv"
else
  run /usr/bin/python3 -m venv --system-site-packages "$STAGE_DIR/venv"
fi
run chown -R root:root "$STAGE_DIR/venv"
if [ "$DRY" = 0 ]; then
  # 发布运行环境必须与 lockfile 完全一致，并包含 systemd 服务实际使用的模块。
  PYTHONNOUSERSITE=1 PYTHONPATH="$STAGE_DIR:$STAGE_DIR/client" \
    "$STAGE_DIR/venv/bin/python" -c \
    'import site; assert not site.ENABLE_USER_SITE; import cryptography, dbus, gi; import flask, flask_socketio, gunicorn, simple_websocket, langgraph'
  (cd "$STAGE_DIR" && PYTHONNOUSERSITE=1 PYTHONPATH="$STAGE_DIR:$STAGE_DIR/client" \
    "$STAGE_DIR/venv/bin/python" deploy/generate_sbom.py --strict \
      --output "$STAGE_DIR/install-sbom.json")
  echo "RUNTIME_VENV_PASS python=$STAGE_DIR/venv/bin/python"
  # 先做离线发布资产校验，再一次性切换目录；失败时保留 previous 可回滚。
  (cd "$STAGE_DIR" && "$STAGE_DIR/venv/bin/python" deploy/verify_install_assets.py)
  # 升级迁移前停止旧进程，避免 SQLite WAL 锁竞争；后续 enable --now 负责恢复。
  if systemctl is-active --quiet bianbu-security-webui.service; then
    WEBUI_WAS_ACTIVE=1
    systemctl stop bianbu-security-webui.service || true
  fi
  systemctl stop bianbu-securityd.service || true
  OLD_STOPPED=1
  for db in /etc/bianbu/capabilities.db; do
    [ -e "$db" ] && (cd "$STAGE_DIR" && "$STAGE_DIR/venv/bin/python" deploy/migrate_db.py "$db")
  done
  for db in /var/log/bianbu/audit/*.db; do
    [ -e "$db" ] && (cd "$STAGE_DIR" && "$STAGE_DIR/venv/bin/python" deploy/migrate_db.py "$db")
  done
  run rm -rf "$BACKUP_DIR"
  if [ -e "$LIB_DIR" ]; then run mv "$LIB_DIR" "$BACKUP_DIR"; fi
  run mv "$STAGE_DIR" "$LIB_DIR"
  SWITCHED=1
fi

echo "== 3. 建数据目录"
# ETC_DIR 含能力注册表与密钥 → 只有服务用户可读写，其他用户不可见
run install -d -m 0750 -o "$SVC_USER" -g "$SVC_GROUP" /etc/bianbu
run install -d -m 0700 -o "$SVC_USER" -g "$SVC_GROUP" /etc/bianbu/keys
run chown "$SVC_USER:$SVC_GROUP" /etc/bianbu /etc/bianbu/keys
run chmod 0750 /etc/bianbu
run chmod 0700 /etc/bianbu/keys
# 代码签名信任根与运行期密钥分离：信任根由发布/设备管理员维护，
# securityd 只读；不得把开发者私钥放入此目录。
run install -d -m 0750 -o root -g "$SVC_GROUP" /etc/bianbu/codesign-keys
run touch /etc/bianbu/codesign-keys/revoked.list
run chown root:"$SVC_GROUP" /etc/bianbu/codesign-keys/revoked.list
run chmod 0640 /etc/bianbu/codesign-keys/revoked.list
if [ -n "$CODE_SIGN_KEY" ]; then
  if [ "$DRY" = 0 ]; then
    [ -f "$CODE_SIGN_KEY" ] || { echo "代码签名公钥不存在：$CODE_SIGN_KEY" >&2; exit 1; }
    CODE_SIGN_VALUE="$(tr -d '\r\n' < "$CODE_SIGN_KEY")"
    if ! printf '%s' "$CODE_SIGN_VALUE" | grep -Eq '^[0-9a-fA-F]{64}$'; then
      echo "代码签名公钥必须是 32 字节 Ed25519 公钥的 64 位 hex" >&2
      exit 1
    fi
  fi
  CODE_SIGN_NAME="$(basename "$CODE_SIGN_KEY")"
  case "$CODE_SIGN_NAME" in
    *.pub) ;;
    *) CODE_SIGN_NAME="${CODE_SIGN_NAME}.pub" ;;
  esac
  run install -m 0640 -o root -g "$SVC_GROUP" \
      "$CODE_SIGN_KEY" "/etc/bianbu/codesign-keys/$CODE_SIGN_NAME"
fi
if [ "$DRY" = 0 ]; then
  if ! BIANBU_SECURITY_CODESIGN=enforce \
       BIANBU_SECURITY_CODESIGN_KEYS=/etc/bianbu/codesign-keys \
       BIANBU_SEC_ROOT=/var/empty/bianbu-security-preflight \
       PYTHONNOUSERSITE=1 \
       PYTHONPATH="$LIB_DIR" "$LIB_DIR/venv/bin/python" - <<'PY'
from securityd.code_signing import enforce_ready
ok, reason = enforce_ready()
if not ok:
    raise SystemExit(f"代码签名信任根未就绪：{reason}")
print("CODESIGN_TRUST_ROOT_PASS")
PY
  then
    exit 1
  fi
fi
run install -d -m 0750 -o "$SVC_USER" -g "$SVC_GROUP" /var/log/bianbu
run install -d -m 0750 -o "$SVC_USER" -g "$SVC_GROUP" /var/log/bianbu/audit
run install -d -m 0750 -o "$SVC_USER" -g "$SVC_GROUP" /run/bianbu
run chown "$SVC_USER:$SVC_GROUP" /var/log/bianbu /var/log/bianbu/audit /run/bianbu
run chmod 0750 /var/log/bianbu /var/log/bianbu/audit /run/bianbu
if [ "$DRY" = 0 ]; then
  # SQLite 的 WAL/SHM 与迁移备份由 root 创建后必须交还服务用户；WebUI env 和
  # 代码签名信任根仍保持 root 管理。
  find /etc/bianbu -maxdepth 1 -type f ! -name webui.env \
    -exec chown "$SVC_USER:$SVC_GROUP" {} +
  chown -R "$SVC_USER:$SVC_GROUP" /var/log/bianbu/audit
fi

echo "== 4. 装 D-Bus policy（系统总线占名的前提）"
run install -m 0644 "$HERE/io.bianbu.Security.conf" "$DBUS_POLICY"
run install -d -m 0755 /usr/share/polkit-1/actions
run install -m 0644 "$HERE/io.bianbu.security.policy" "$POLKIT_POLICY"
if [ "$ENABLE_RUNTIME" = 1 ]; then
  run install -m 0644 "$HERE/io.bianbu.Runtime.conf" "$RUNTIME_DBUS_POLICY"
fi

echo "== 5. 装 D-Bus 按需激活文件"
run install -d -m 0755 /usr/share/dbus-1/system-services
run install -m 0644 "$HERE/io.bianbu.Security.service" "$DBUS_ACTIVATION"
if [ "$ENABLE_RUNTIME" = 1 ]; then
  run install -m 0644 "$HERE/io.bianbu.Runtime.service" "$RUNTIME_DBUS_ACTIVATION"
fi

echo "== 6. 装 systemd unit"
if [ "$DRY" = 0 ]; then
  [ -f "$SYSTEMD_UNIT" ] && cp -a "$SYSTEMD_UNIT" "$SYSTEMD_UNIT_PREVIOUS"
  if [ "$ENABLE_RUNTIME" = 1 ] && [ -f "$RUNTIME_SYSTEMD_UNIT" ]; then
    cp -a "$RUNTIME_SYSTEMD_UNIT" "$RUNTIME_SYSTEMD_UNIT_PREVIOUS"
  fi
  if [ "$ENABLE_WEBUI" = 1 ] && [ -f "$WEBUI_SYSTEMD_UNIT" ]; then
    cp -a "$WEBUI_SYSTEMD_UNIT" "$WEBUI_SYSTEMD_UNIT_PREVIOUS"
  fi
fi
run install -m 0644 "$HERE/bianbu-securityd.service" "$SYSTEMD_UNIT"
if [ "$ENABLE_RUNTIME" = 1 ]; then
  # 仅显式 --enable-runtime 时安装仓库内参考 Runtime；正式产品应由
  # Runtime 自身包提供同名 unit，并在独立验收后启用。
  run install -m 0644 "$HERE/bianbu-agent-runtimed.service" "$RUNTIME_SYSTEMD_UNIT"
fi
if [ "$ENABLE_WEBUI" = 1 ]; then
  if [ "$DRY" = 0 ]; then
  if [ ! -s /etc/bianbu/webui.env ]; then
    echo "启用 WebUI 前必须创建非空 /etc/bianbu/webui.env" >&2
    exit 1
  fi
  WEBUI_TOKEN_VALUE="$(sed -n 's/^BIANBU_WEBUI_TOKEN=//p' /etc/bianbu/webui.env | tail -1)"
  WEBUI_SECRET_VALUE="$(sed -n 's/^BIANBU_WEBUI_SECRET=//p' /etc/bianbu/webui.env | tail -1)"
  WEBUI_VIEWER_VALUE="$(sed -n 's/^BIANBU_WEBUI_VIEWER_TOKEN=//p' /etc/bianbu/webui.env | tail -1)"
  case "$WEBUI_TOKEN_VALUE" in
    *REPLACE_WITH*|*CHANGE_ME*|*changeme*|*placeholder*) WEBUI_TOKEN_VALUE= ;;
  esac
  case "$WEBUI_SECRET_VALUE" in
    *REPLACE_WITH*|*CHANGE_ME*|*changeme*|*placeholder*) WEBUI_SECRET_VALUE= ;;
  esac
  case "$WEBUI_VIEWER_VALUE" in
    *REPLACE_WITH*|*CHANGE_ME*|*changeme*|*placeholder*) WEBUI_VIEWER_VALUE=invalid-placeholder ;;
  esac
  WEBUI_AUTH_VALUE="$(sed -n 's/^BIANBU_WEBUI_AUTH=//p' /etc/bianbu/webui.env | tail -1)"
  if [ "$WEBUI_AUTH_VALUE" = "1" ] && [ "${#WEBUI_TOKEN_VALUE}" -lt 32 ]; then
    echo "启用 WebUI 前必须在 /etc/bianbu/webui.env 配置至少 32 字节的非占位 BIANBU_WEBUI_TOKEN" >&2
    exit 1
  fi
  if [ "$WEBUI_AUTH_VALUE" = "1" ] && { [ "${#WEBUI_SECRET_VALUE}" -lt 32 ] || [ "$WEBUI_SECRET_VALUE" = "$WEBUI_TOKEN_VALUE" ]; }; then
    echo "生产 WebUI 必须配置至少 32 字节且不同于 token 的 BIANBU_WEBUI_SECRET" >&2
    exit 1
  fi
  if [ -n "$WEBUI_VIEWER_VALUE" ] && { [ "$WEBUI_VIEWER_VALUE" = invalid-placeholder ] || \
       [ "${#WEBUI_VIEWER_VALUE}" -lt 32 ] || \
       [ "$WEBUI_VIEWER_VALUE" = "$WEBUI_TOKEN_VALUE" ]; }; then
    echo "BIANBU_WEBUI_VIEWER_TOKEN 必须至少 32 字节且不同于管理员 token" >&2
    exit 1
  fi
  if [ "$WEBUI_AUTH_VALUE" = "1" ] && grep -q '^BIANBU_WEBUI_ALLOW_INSECURE_REMOTE=1$' /etc/bianbu/webui.env; then
    echo "认证 WebUI 禁止 BIANBU_WEBUI_ALLOW_INSECURE_REMOTE=1" >&2
    exit 1
  fi
  WEBUI_HOST_VALUE="$(sed -n 's/^BIANBU_WEBUI_HOST=//p' /etc/bianbu/webui.env | tail -1)"
  WEBUI_TLS_CERT_VALUE="$(sed -n 's/^BIANBU_WEBUI_TLS_CERT=//p' /etc/bianbu/webui.env | tail -1)"
  WEBUI_TLS_KEY_VALUE="$(sed -n 's/^BIANBU_WEBUI_TLS_KEY=//p' /etc/bianbu/webui.env | tail -1)"
  if { [ -n "$WEBUI_TLS_CERT_VALUE" ] && [ -z "$WEBUI_TLS_KEY_VALUE" ]; } || \
     { [ -z "$WEBUI_TLS_CERT_VALUE" ] && [ -n "$WEBUI_TLS_KEY_VALUE" ]; }; then
    echo "BIANBU_WEBUI_TLS_CERT 与 BIANBU_WEBUI_TLS_KEY 必须同时配置" >&2
    exit 1
  fi
  if [ -n "$WEBUI_TLS_CERT_VALUE" ] && { [ ! -f "$WEBUI_TLS_CERT_VALUE" ] || \
       [ ! -f "$WEBUI_TLS_KEY_VALUE" ]; }; then
    echo "WebUI TLS 证书或私钥文件不存在" >&2
    exit 1
  fi
  if [ -n "$WEBUI_HOST_VALUE" ] && case "$WEBUI_HOST_VALUE" in
       127.0.0.1|::1|localhost) false ;;
       *) true ;;
     esac; then
    if grep -q '^BIANBU_WEBUI_TRUST_PROXY=1$' /etc/bianbu/webui.env; then
      echo "受信反向代理模式要求 WebUI 自身只监听回环地址" >&2
      exit 1
    fi
    if [ -z "$WEBUI_TLS_CERT_VALUE" ]; then
      echo "非回环 WebUI 必须配置 TLS 证书和私钥" >&2
      exit 1
    fi
  fi
  if grep -q '^BIANBU_WEBUI_ENABLE_SHELL=1$' /etc/bianbu/webui.env; then
    echo "商用 WebUI 配置必须关闭普通 shell" >&2
    exit 1
  fi
  run chown root:"$SVC_GROUP" /etc/bianbu/webui.env
  run chmod 0640 /etc/bianbu/webui.env
  fi
  run install -m 0644 "$HERE/bianbu-security-webui.service" "$WEBUI_SYSTEMD_UNIT"
fi
run systemctl daemon-reload
# reload 而非 restart：重启 dbus 会打断所有在线会话
run systemctl reload dbus.service || run systemctl restart dbus.service

echo "== 7. 启动"
run systemctl enable --now bianbu-securityd.service
if [ "$ENABLE_RUNTIME" = 1 ]; then
  run systemctl enable --now bianbu-agent-runtimed.service
fi
if [ "$ENABLE_WEBUI" = 1 ]; then
  run systemctl enable --now bianbu-security-webui.service
elif [ "$WEBUI_WAS_ACTIVE" = 1 ]; then
  # 升级前已运行的 WebUI 必须在成功切换后恢复；--enable-webui 只控制
  # 首次安装/显式启用，不能让普通 Security 升级静默停止既有管理面。
  run systemctl start bianbu-security-webui.service
fi

if [ "$DRY" = 0 ]; then
  echo "== 8. 自检"
  sleep 1.5
  if busctl --system list 2>/dev/null | grep -q io.bianbu.Security; then
    echo "   ✅ io.bianbu.Security 已在系统总线上"
  else
    echo "   ❌ 未占名，看日志：journalctl -u bianbu-securityd -n 40" >&2
    restore_previous
    exit 1
  fi
  if [ "$ENABLE_RUNTIME" = 1 ]; then
    if busctl --system list 2>/dev/null | grep -q io.bianbu.Runtime; then
      echo "   ✅ io.bianbu.Runtime 已在系统总线上"
    else
      echo "   ❌ Runtime 未占名，看日志：journalctl -u bianbu-agent-runtimed -n 40" >&2
      restore_previous
      exit 1
    fi
  else
    echo "   ℹ️  未启用 Runtime：由外部 Runtime 包负责安装、启动和自检"
  fi
  if busctl --system introspect io.bianbu.Security /io/bianbu/Security \
       2>/dev/null | grep -q CheckPermission; then
    echo "   ✅ CheckPermission 可见"
  else
    echo "   ⚠️  占名成功但接口 introspect 失败" >&2
    restore_previous
    exit 1
  fi
  SEC_USER="$(systemctl show bianbu-securityd.service --property=User --value)"
  if [ "$SEC_USER" != "$SVC_USER" ]; then
    echo "   ❌ Security unit 身份错误：User=$SEC_USER，期望 $SVC_USER" >&2
    restore_previous
    exit 1
  fi
  if [ ! -S /run/bianbu/securityd.sock ] || \
     [ "$(stat -c '%a' /run/bianbu/securityd.sock)" != 660 ] || \
     [ "$(stat -c '%G' /run/bianbu/securityd.sock)" != "$SVC_GROUP" ]; then
    echo "   ❌ 正式 UDS 必须是 /run/bianbu/securityd.sock 0660:$SVC_GROUP" >&2
    restore_previous
    exit 1
  fi
  echo "   ✅ Security 身份与正式 UDS 权限正确"
  if [ "$ENABLE_WEBUI" = 1 ]; then
    WEBUI_READY=0
    for _ in $(seq 1 20); do
      if systemctl is-active --quiet bianbu-security-webui.service && \
         "$LIB_DIR/venv/bin/python" -c \
           'import urllib.request; assert urllib.request.urlopen("http://127.0.0.1:8787/", timeout=2).status == 200' \
           >/dev/null 2>&1; then
        WEBUI_READY=1
        break
      fi
      sleep 0.5
    done
    WEBUI_USER="$(systemctl show bianbu-security-webui.service --property=User --value)"
    if [ "$WEBUI_READY" != 1 ] || [ "$WEBUI_USER" != "$SVC_USER" ]; then
      echo "   ❌ WebUI unit/HTTP 自检失败：User=$WEBUI_USER" >&2
      restore_previous
      exit 1
    fi
    echo "   ✅ WebUI 由专用身份运行且 HTTP 就绪"
  fi
fi

cat <<'NOTE'

装好了。要点：

- 需要调用管理类方法（SetCapabilityPolicy / RevokePermission / SuspendAgent /
  InstallPackage / SetNetworkPolicy）的用户，必须加入
  bianbu-admin 组：`sudo usermod -aG bianbu-admin <user>`（重登生效）。
  判权类方法（CheckPermission 等）对所有本地用户开放，无需额外授权。

- bianbu-agent 侧不要设 BIANBU_SEC_SESSION=1，否则会去连会话总线而非系统总线。

- 生产 systemd 服务默认 `BIANBU_SECURITY_CODESIGN=enforce`，设备发布前必须把
  受信 `.pub` 公钥安装到 `/etc/bianbu/codesign-keys/`；推荐安装时使用
  `--codesign-key /secure/release.pub`。安装器会拒绝无可用公钥、非法 hex 或全部吊销
  的信任根。公钥轮换通过替换/新增公钥，吊销通过 `revoked.list`，私钥不得下发到设备。

- 商用安装应把已按 `requirements-lock.txt` 冻结并通过 strict SBOM/CVE 门禁的 venv
  通过 `--runtime-venv /release/bnsec-venv` 传入。安装器会把它原子纳入版本目录，
  unit 只使用 `/usr/lib/bianbu-securityd/venv/bin/python`，不依赖漂移的系统 Python。

- 本脚本默认不安装/启动/停止 `bianbu-agent-runtimed`；正式 Runtime 由其自身包
  管理。仅在测试参考部署时显式使用 `--enable-runtime`。

- 验证：
    busctl --system introspect io.bianbu.Security /io/bianbu/Security
    journalctl -u bianbu-securityd -f
NOTE
