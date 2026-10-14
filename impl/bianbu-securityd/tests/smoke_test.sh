#!/bin/bash
# smoke_test.sh — securityd 快速回归（8.6 节），详细可追踪日志版。
# 在 worker 机执行：ssh bianbu@10.0.90.243 'bash <repo>/tests/smoke_test.sh'
# 起私有会话总线 + 子进程 securityd，逐项验证并打印【调用/输入/期望/实际/判定】。无需 root。
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(dirname "$HERE")"
PY="${PYTHON:-python3}"
export PYTHONPATH="$ROOT:$ROOT/client"
export BIANBU_SEC_ROOT="${BIANBU_SEC_ROOT:-/tmp/bnsec_smoke}"
rm -rf "$BIANBU_SEC_ROOT"

# 颜色（仅 tty）
if [ -t 1 ]; then B=$'\033[1m'; G=$'\033[32m'; R=$'\033[31m'; C=$'\033[36m'; D=$'\033[2m'; N=$'\033[0m';
else B=; G=; R=; C=; D=; N=; fi
hr(){ printf '%s\n' "${C}────────────────────────────────────────────────────────────────────${N}"; }
pass(){ printf '  └ %s✔ PASS%s\n' "$G" "$N"; }
fail(){ printf '  └ %s✘ FAIL: %s%s\n' "$R" "$1" "$N" >&2; exit 1; }

printf '%s\n' "${B}╔══════════════════════════════════════════════════════════════════╗${N}"
printf '%s\n' "${B}║   bianbu-securityd 冒烟测试 — 环境自检 + 全链路（详细日志）       ║${N}"
printf '%s\n' "${B}╚══════════════════════════════════════════════════════════════════╝${N}"
printf '%s主机%s : %s\n' "$D" "$N" "$(uname -n) / $(uname -m) / $(uname -r)"
printf '%s解释器%s: %s (%s)\n' "$D" "$N" "$($PY --version 2>&1)" "$PY"
printf '%sbwrap%s: %s\n' "$D" "$N" "$(bwrap --version 2>/dev/null || echo 未安装)"
printf '%s数据根%s: %s\n' "$D" "$N" "$BIANBU_SEC_ROOT"

hr; printf '%s阶段 1/3 ▸ bwrap 非特权沙箱可用性%s\n' "$C" "$N"
printf '%s  说明：securityd 用 bwrap 隔离运行 Agent，先确认非特权 userns 可用%s\n' "$D" "$N"; hr
# merged-usr 感知：/bin、/lib 可能是符号链接，用 --symlink 重建，exec /usr/bin/true
BWRAP_BASE=(--unshare-user --ro-bind /usr /usr --dev /dev --proc /proc --tmpfs /tmp --die-with-parent)
for top in /bin /lib /lib64 /sbin; do
  if [ -L "$top" ]; then BWRAP_BASE+=(--symlink "$(readlink "$top")" "$top");
  elif [ -d "$top" ]; then BWRAP_BASE+=(--ro-bind "$top" "$top"); fi
done
printf '  ├ 调用: bwrap --unshare-user ... -- /usr/bin/true\n'
printf '  ├ 期望: 退出码 0（能创建用户命名空间并执行）\n'
if bwrap "${BWRAP_BASE[@]}" -- /usr/bin/true; then
  printf '  ├ 实际: 退出码 0\n'; pass
else
  fail "bwrap 非特权沙箱不可用（检查 userns / AppArmor）"
fi

hr; printf '%s阶段 2/3 ▸ 生成测试 Agent 包（fixtures）%s\n' "$C" "$N"
printf '%s  说明：生成带真实 ed25519 签名的 manifest 包，供验签与判权用%s\n' "$D" "$N"; hr
printf '  ├ 调用: python tests/fixtures/make_fixtures.py\n'
printf '  ├ 期望: 生成 manifest.toml / .sig / pubkey.hex\n'
"$PY" "$ROOT/tests/fixtures/make_fixtures.py" >/dev/null
FX="$ROOT/tests/fixtures/test-security-agent"
if [ -f "$FX/manifest.toml" ] && [ -f "$FX/manifest.toml.sig" ] && [ -f "$FX/pubkey.hex" ]; then
  printf '  ├ 实际: %s\n' "$(cd "$FX" && echo *)"; pass
else
  fail "fixtures 生成不完整"
fi

hr; printf '%s阶段 3/6 ▸ 私有 session bus 内跑全链路（8 步全链路）%s\n' "$C" "$N"
printf '%s  说明：起 securityd 子进程，经 D-Bus 逐项验证 —— 详见下方每步日志%s\n' "$D" "$N"; hr
dbus-run-session -- "$PY" "$ROOT/tests/integration/_dbus_driver.py"

hr; printf '%s阶段 4/6 ▸ hermes 接入·确认门禁全路径（批准/拒绝/L4 二次确认）%s\n' "$C" "$N"
printf '%s  说明：模拟GUI 订阅 ConfirmRequest 经 RespondConfirm 回传，验证用户确认主路径%s\n' "$D" "$N"; hr
dbus-run-session -- "$PY" "$ROOT/tests/integration/hermes_confirm_demo.py"

hr; printf '%s阶段 5/6 ▸ hermes 插件·调用级管控（pre/post_tool_call）%s\n' "$C" "$N"
printf '%s  说明：模拟 hermes 钩子分发 → 插件经 securityd 判权/确认/审计（放行/拦截）%s\n' "$D" "$N"; hr
BIANBU_SECURITYD_HOME="$ROOT" PYTHONPATH="$ROOT:$ROOT/client:$ROOT/hermes_plugin" \
  dbus-run-session -- "$PY" "$ROOT/tests/integration/hermes_plugin_demo.py"

hr; printf '%s阶段 6/6 ▸ hermes 进程级 bwrap 沙箱（seccomp 继承）%s\n' "$C" "$N"
printf '%s  说明：沙箱内启动模拟 hermes，其 spawn 的工具子进程危险 syscall 被拦截%s\n' "$D" "$N"; hr
BIANBU_SECURITYD_HOME="$ROOT" PYTHONPATH="$ROOT:$ROOT/client:$ROOT/hermes_plugin" \
  "$PY" -m pytest "$ROOT/tests/integration/test_hermes_sandbox.py" -q 2>&1 | tail -3

printf '\n%s\n' "${B}${G}════════════ SMOKE TEST ALL PASS ════════════${N}"
