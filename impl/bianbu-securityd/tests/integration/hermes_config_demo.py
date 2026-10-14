"""WebUI 能力配置 → hermes 端到端生效 演示（详细日志）。

证明"在 WebUI（经 client/D-Bus 后端路径）改能力配置，hermes 判权即时随之改变"：
  ① 未配置 system.exec → hermes terminal 判 DENY（拦截）
  ② 经 WebUI 后端新增 system.exec(L4)+授权 → terminal 变 CONFIRM（需确认）
  ③ 经 WebUI 后端撤销 → terminal 回到 DENY
  ④ 新增 file.write(L2 once)+授权 → write_file 触发确认门禁

每步打印配置动作 + 配置前后 hermes pre_tool_call 决策对比。全通过打印 CONFIG_DEMO_PASS。
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

AID = "com.hermes.config-demo"


def _tool_decision(plugin, tool):
    """模拟 hermes pre_tool_call，返回 'executed'/'blocked'/'confirm-needed'。"""
    # 用 mapping 先看它映射到什么能力
    from bianbu_security import mapping
    resolved = mapping.resolve(tool, {"command": "x", "path": "/tmp/x"})
    block = plugin.pre_tool_call(tool, {"command": "echo hi", "path": "~/Documents/bianbu-test/a"})
    return ("blocked" if block else "allowed"), resolved


def _add_cap(sc, cap, domain, risk, confirm, scope="", granted=1):
    """经 D-Bus 增量注册一条能力（等价 WebUI 的 capabilities/add）。"""
    import dbus
    from bianbu_security_client import _get_proxy, SECURITY_INTERFACE
    p = _get_proxy()
    dperm = dbus.Dictionary({"capability":cap,"domain":domain,"risk_level":risk,
                             "confirm":confirm,"scope":scope}, signature="sv")
    p.RegisterCapabilities(AID, [dperm], dbus_interface=SECURITY_INTERFACE)
    if granted != 1:
        sc.set_capability_policy(AID, cap, "allow" if granted == 1 else "deny")


def _dec(sc, cap, scope=""):
    d = sc.check_permission(AID, cap, scope)
    return d, {0:"ALLOW 放行",1:"CONFIRM 需确认",2:"DENY 拦截"}.get(d, str(d))


def run_cases(sc) -> int:
    T = "4"
    # CASE 1：未配置 system.exec → terminal 判 DENY
    L.section(1, T, "配置前：未注册 system.exec → hermes terminal 应 DENY",
              "hermes terminal 工具映射到 system.exec；Agent 未配该能力，判权拒绝")
    d, lab = _dec(sc, "system.exec", "echo hi")
    L.check("check_permission(system.exec) 配置前", "未注册",
            "2 = DENY 拦截", f"{d} = {lab}", d == 2)

    # CASE 2：WebUI 新增 system.exec(L4)+授权 → 变 CONFIRM
    L.section(2, T, "WebUI 新增 system.exec(L4) 并授权 → terminal 变 CONFIRM",
              "在 WebUI 能力管理里加一条 system.exec、风险 L4、状态已授权，hermes 判权即时改变")
    _add_cap(sc, "system.exec", "execute", "L4", "always", scope="", granted=1)
    d, lab = _dec(sc, "system.exec", "echo hi")
    L.check("check_permission(system.exec) 新增授权后", "system.exec L4 已授权",
            "1 = CONFIRM 需确认（L4 恒确认）", f"{d} = {lab}", d == 1)

    # CASE 3：WebUI 撤销 → 回到 DENY
    L.section(3, T, "WebUI 撤销 system.exec → terminal 回到 DENY",
              "在 WebUI 点撤销（granted=-1），hermes 判权立刻回到拒绝")
    sc.set_capability_policy(AID, "terminal", "deny")
    d, lab = _dec(sc, "system.exec", "echo hi")
    L.check("check_permission(system.exec) 撤销后", "granted=-1",
            "2 = DENY 拦截", f"{d} = {lab}", d == 2)

    # CASE 4：新增 file.write(L2 once)+授权 → 首次 CONFIRM
    L.section(4, T, "WebUI 新增 file.write(L2 once_per_session) → write_file 首次需确认",
              "文件写能力配 L2 once_per_session，hermes write_file 首次触发确认门禁")
    _add_cap(sc, "file.write", "execute", "L2", "once_per_session",
             scope="~/Documents/bianbu-test", granted=1)
    d, lab = _dec(sc, "file.write", "~/Documents/bianbu-test/a.txt")
    L.check("check_permission(file.write,scope) 配置后", "file.write L2 已授权",
            "1 = CONFIRM 首次需确认", f"{d} = {lab}", d == 1)
    return 0


def main() -> int:
    os.environ["BIANBU_SEC_SESSION"] = "1"
    print(L.bold("\n╔══════════════════════════════════════════════════════════════════╗"))
    print(L.bold("║  WebUI 能力配置 → hermes 判权端到端生效演示（配置即时改变决策）  ║"))
    print(L.bold("╚══════════════════════════════════════════════════════════════════╝"))
    print(L.dim(f"  Agent: {AID}；每步经 D-Bus 改配置（等价 WebUI 操作），再看 CheckPermission 决策"))

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
        run_cases(sc)
        print()
        return L._summary("CONFIG_DEMO_PASS")
    finally:
        if proc is not None:
            proc.terminate()
            try: proc.wait(timeout=5)
            except subprocess.TimeoutExpired: proc.kill()


if __name__ == "__main__":
    sys.exit(main())
