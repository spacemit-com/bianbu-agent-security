"""CLI 确认路由演示 —— CONFIRM 按 APPROVAL_MODE 交回 hermes TUI / 走 WebUI 信号。

真机源码实证：hermes chat 是 prompt_toolkit 全屏 App，插件裸 input() 会挂死，
故交互式 CLI 下 CONFIRM 应交回 hermes 原生 approval（mode=hermes），由其 TUI 弹
[o/s/a/d]。本演示验证插件的路由逻辑（不依赖真 TUI）：
  · mode=hermes：CONFIRM → 交回 hermes（pre_tool_call 返回 None 放行给 hermes approval）
  · mode=securityd + 交互式 CLI + 无 WebUI 响应：CONFIRM → 超时拦截，且提示改用 mode=hermes
  · DENY 在任何 mode 都硬拦

全通过打印 CLI_CONFIRM_PASS。
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "client"))
sys.path.insert(0, str(ROOT / "hermes_plugin"))

from tests.integration import _dbus_driver as L

AID = "com.hermes.cli-route"


def _register(sc):
    import dbus
    from bianbu_security_client import _get_proxy, SECURITY_INTERFACE
    p = _get_proxy()
    for cap, dom, risk, cf, granted in [
        ("system.exec", "execute", "L4", "always", 1),      # 已授权 → CONFIRM
        ("mail.send",   "execute", "L3", "always", -1)]:    # 未授权 → DENY
        dperm = dbus.Dictionary({"capability": cap, "domain": dom, "risk_level": risk,
                                 "confirm": cf, "scope": ""}, signature="sv")
        p.RegisterCapabilities(AID, [dperm], dbus_interface=SECURITY_INTERFACE)
        if granted != 1:
            sc.set_capability_policy(AID, cap, "allow" if granted == 1 else "deny")


def run_cases(sc) -> int:
    import importlib
    T = "3"
    os.environ["BIANBU_HERMES_AGENT_ID"] = AID
    os.environ["HERMES_INTERACTIVE"] = "1"  # 模拟交互式 CLI

    # CASE 1：mode=hermes → CONFIRM 交回 hermes（放行给 hermes approval）
    L.section(1, T, "mode=hermes：CONFIRM 交回 hermes TUI（pre_tool_call 放行）",
              "交互式 CLI 下唯一可行：securityd 判 CONFIRM 后交回 hermes 原生 [o/s/a/d]")
    os.environ["BIANBU_SEC_APPROVAL_MODE"] = "hermes"
    import bianbu_security as plugin
    importlib.reload(plugin)
    block = plugin.pre_tool_call("terminal", {"command": "echo hi"})
    L.check("pre_tool_call(terminal) mode=hermes", "system.exec=CONFIRM",
            "None（交回 hermes 放行）", f"{block}", block is None)

    # CASE 2：mode=securityd + 交互式 CLI + 无 WebUI → 超时拦截 + 提示
    L.section(2, T, "mode=securityd + 交互CLI + 无WebUI响应 → 拦截并提示改 mode=hermes",
              "securityd 信号路径无终端响应者，超时拦截；message 含改 mode=hermes 提示")
    os.environ["BIANBU_SEC_APPROVAL_MODE"] = "securityd"
    importlib.reload(plugin)
    # 强制 is_cli_interactive=True（测试进程无真 TTY，patch 掉 isatty 判断）
    import bianbu_security.cli_confirm as cc
    cc.is_cli_interactive = lambda: True
    block = plugin.pre_tool_call("terminal", {"command": "echo hi"})
    ok = (block is not None and "APPROVAL_MODE=hermes" in block.get("message", ""))
    L.check("pre_tool_call(terminal) mode=securityd 无WebUI", "超时无响应",
            "block + 提示改 mode=hermes", f"{'block' if block else 'None'}: "
            f"{(block or {}).get('message','')[:50]}", ok)

    # CASE 3：DENY 任何 mode 都硬拦（terminal→system.exec，但先撤销授权制造 DENY）
    L.section(3, T, "DENY 硬拦（撤销 system.exec 后 terminal 被拒）",
              "撤销 system.exec 授权 → CheckPermission=DENY，直接 block，与 mode 无关")
    sc.set_capability_policy(AID, "terminal", "deny")
    block = plugin.pre_tool_call("terminal", {"command": "echo hi"})
    L.check("pre_tool_call(terminal) 撤销后", "system.exec granted=-1",
            "block（DENY）", f"{'block' if block else 'None'}", block is not None)
    return 0


def main() -> int:
    os.environ["BIANBU_SEC_SESSION"] = "1"
    print(L.bold("\n╔══════════════════════════════════════════════════════════════════╗"))
    print(L.bold("║  CLI 确认路由演示 —— CONFIRM 按 mode 交回 hermes TUI / WebUI 信号  ║"))
    print(L.bold("╚══════════════════════════════════════════════════════════════════╝"))

    import dbus
    proc = None
    try:
        obj = dbus.SessionBus().get_object("io.bianbu.Security", "/io/bianbu/Security")
        obj.Introspect(dbus_interface="org.freedesktop.DBus.Introspectable")
    except dbus.DBusException:
        env = dict(os.environ); env["PYTHONPATH"] = str(ROOT)
        proc = subprocess.Popen([sys.executable, "-m", "securityd.service", "--session"],
                                env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        if L.wait_ready(proc) is None:
            print(L.red("securityd 未就绪")); return 1
    try:
        import bianbu_security_client as sc
        _register(sc)
        run_cases(sc)
        print()
        return L._summary("CLI_CONFIRM_PASS")
    finally:
        if proc is not None:
            proc.terminate()
            try: proc.wait(timeout=5)
            except subprocess.TimeoutExpired: proc.kill()


if __name__ == "__main__":
    sys.exit(main())
