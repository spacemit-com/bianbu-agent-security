#!/usr/bin/env bash
# 测试环境的公共配置。被 scripts/ 下其它脚本 source。
#
# 所有路径都可用同名环境变量覆盖，便于换机器/换部署位置：
#   BNSEC_TESTKIT=/opt/bnsec-testkit ./start-webui.sh
#
# 不要在这里放密码或密钥。

# ── 安装位置 ───────────────────────────────────────────────
# testkit 自身（engine.py / runner.py / webui.py / tests_all.py 所在目录）
: "${BNSEC_TESTKIT:=/home/bianbu/bnsec-testkit}"
# securityd 源码根
: "${BIANBU_SECURITYD_HOME:=/home/bianbu/impl/bianbu-securityd}"
# personal-agent 源码根
: "${BNSEC_PA_HOME:=/home/bianbu/bianbu-agent}"
# uv 可执行文件（PA 用它启动）
: "${BNSEC_UV:=/home/bianbu/.local/bin/uv}"
# Memory SDK 缺失时仅允许显式开发态复用已有 venv；商用部署保持 0。
: "${PA_UV_NO_SYNC:=0}"

# ── 运行时输出 ─────────────────────────────────────────────
# 测试产物目录（events.jsonl / report.json / runner.log）
: "${BNSEC_OUT:=/var/tmp/bnsec-testrun}"
# 服务日志目录
: "${BNSEC_LOG_DIR:=/var/tmp/bnsec-logs}"

# ── 服务参数 ───────────────────────────────────────────────
: "${BNSEC_WEB_PORT:=9700}"        # testkit 测试监视台
: "${BNSEC_SEC_WEB_PORT:=8787}"    # securityd 自带配置台
: "${PA_BASE:=http://127.0.0.1:9899}"
: "${PA_AGENT_ID:=bianbu-agent-default}"
: "${BIANBU_PA_AGENT_ID:=${PA_AGENT_ID}}"
# 安全启用时默认从 PA 的 run.sh+bwrap 入口启动；设 off 可验证 host 策略。
: "${BIANBU_SANDBOX:=agent}"

# 正式 systemd 数据面/审计库存在时优先使用；开发启动脚本仍回退用户目录。
if [ -z "${BIANBU_SEC_UDS:-}" ]; then
  if [ -S /run/bianbu/securityd.sock ]; then
    BIANBU_SEC_UDS=/run/bianbu/securityd.sock
  else
    BIANBU_SEC_UDS="$HOME/.local/share/bianbu-securityd/run/bianbu/securityd.sock"
  fi
fi
if [ -z "${BNSEC_AUDIT_DB:-}" ]; then
  if [ -d /var/log/bianbu/audit ] && [ -r /var/log/bianbu/audit ]; then
    BNSEC_AUDIT_DB=/var/log/bianbu/audit
  else
    BNSEC_AUDIT_DB="$HOME/.local/share/bianbu-securityd/var/log/bianbu/audit"
  fi
fi

# ── securityd 总线选择 ────────────────────────────────────
# auto   自动探测（装了 system.d policy 且用户在 bianbu-security 组 → 系统总线）
# system 强制系统总线
# session 强制会话总线（免 policy、免 root，但随登录会话生死）
: "${BNSEC_BUS:=auto}"

# 会话总线地址（BNSEC_BUS=session 时用）
: "${DBUS_SESSION_BUS_ADDRESS:=unix:path=/run/user/$(id -u)/bus}"

export BNSEC_TESTKIT BIANBU_SECURITYD_HOME BNSEC_PA_HOME BNSEC_UV PA_UV_NO_SYNC
export BNSEC_OUT BNSEC_LOG_DIR BNSEC_WEB_PORT BNSEC_SEC_WEB_PORT PA_BASE
export BIANBU_PA_AGENT_ID PA_AGENT_ID BIANBU_SANDBOX BNSEC_BUS DBUS_SESSION_BUS_ADDRESS
export BIANBU_SEC_UDS BNSEC_AUDIT_DB

mkdir -p "$BNSEC_OUT" "$BNSEC_LOG_DIR" 2>/dev/null || true

# ── 公共函数 ───────────────────────────────────────────────

# 判定 securityd 该走哪条总线；回显 "system" 或 "session"
bnsec_pick_bus() {
  case "$BNSEC_BUS" in
    system|session) echo "$BNSEC_BUS"; return 0 ;;
  esac
  # auto：有 policy 且在组里就用系统总线
  if [ -f /etc/dbus-1/system.d/io.bianbu.Security.conf ] \
     && id -nG 2>/dev/null | tr ' ' '\n' | grep -qx bianbu-security; then
    echo system
  else
    echo session
  fi
}

# securityd 是否已占名（两条总线都查）；成功回显总线类型
bnsec_secd_owned() {
  if busctl --system list 2>/dev/null | grep -q io.bianbu.Security; then
    echo system; return 0
  fi
  if busctl --user list 2>/dev/null | grep -q io.bianbu.Security; then
    echo session; return 0
  fi
  return 1
}

# 后台启动一个脚本，脱离 SSH 会话。
#
# 必须用 setsid + </dev/null：直接在 SSH 命令里 `nohup ... &` 会让子进程
# 继承 SSH 通道的 stdout/stderr，通道等不到 EOF 就一直挂着，远端调用方
# （paramiko / ssh）会卡到超时。踩过多次。
bnsec_spawn() {
  local script="$1" logfile="$2"
  setsid --fork "$script" </dev/null >"$logfile" 2>&1 &
  echo "已启动 $(basename "$script") → $logfile"
}

# 等某个 HTTP 端点返回 200
bnsec_wait_http() {
  local url="$1" label="$2" tries="${3:-30}" i
  for ((i = 1; i <= tries; i++)); do
    if [ "$(curl -s -m 5 -o /dev/null -w '%{http_code}' "$url" 2>/dev/null)" = "200" ]; then
      echo "  ✓ $label 就绪（${i}次探测）"
      return 0
    fi
    sleep 2
  done
  echo "  ✗ $label 未在 $((tries * 2))s 内就绪" >&2
  return 1
}
