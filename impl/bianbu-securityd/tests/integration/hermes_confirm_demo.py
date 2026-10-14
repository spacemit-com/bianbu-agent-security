"""hermes 接入演示 —— ask 确认门禁路径（批准/拒绝）详细日志版。

模拟真实部署形态：
  · securityd 子进程跑在（私有）会话总线上；
  · 一个"模拟 GUI"后台线程订阅 ConfirmRequest 信号，按预设策略经
    RespondConfirm 回传用户决定 —— 这正是生产里通知中心/GUI 的角色；
  · 本进程扮演 hermes agent，用 bianbu_security_client 发起工具调用。

覆盖 D-Bus 直调下无法自动完成的"用户批准/拒绝"主路径。
全部通过打印 HERMES_CONFIRM_PASS。
"""
from __future__ import annotations

import os
import subprocess
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "client"))

from tests.integration import _dbus_driver as L  # 复用日志助手（section/check/field/...）


class MockGUI:
    """后台线程：订阅 ConfirmRequest，按 policy 决定并 RespondConfirm 回传。

    policy: capability -> list[bool]，按到达顺序弹出（先批准后拒绝等）。
    """

    def __init__(self, policy: dict[str, list[bool]]):
        self.policy = {k: list(v) for k, v in policy.items()}
        self.seen: list[tuple[str, str]] = []  # (capability, detail) 到达记录
        self._loop = None
        self._thread = None
        self._bus = None
        self._ready = threading.Event()

    def _on_confirm_request(self, agent_id, capability, detail, request_id):
        cap = str(capability)
        self.seen.append((cap, str(detail)))
        decisions = self.policy.get(cap, [])
        approved = decisions.pop(0) if decisions else False
        verb = L.green("批准") if approved else L.red("拒绝")
        print(f"    {L.dim('· 模拟GUI 收到 ConfirmRequest')}: {cap} «{detail}» → {verb}")
        # 关键：用 GUI 自己的私有连接回传，绝不复用主线程正阻塞着的共享连接
        # （两线程共用一条 dbus 连接做 call_blocking 会串消息、报 recipient disconnected）。
        obj = self._bus.get_object("io.bianbu.Security", "/io/bianbu/Security")
        obj.RespondConfirm(str(request_id), bool(approved),
                           dbus_interface="io.bianbu.Security")

    def start(self):
        import dbus
        import dbus.mainloop.glib
        from gi.repository import GLib

        loop_factory = dbus.mainloop.glib.DBusGMainLoop()

        def _run():
            # 私有连接并显式挂主循环（共享连接可能已被客户端无主循环地缓存）
            self._bus = dbus.SessionBus(private=True, mainloop=loop_factory)
            self._bus.add_signal_receiver(
                self._on_confirm_request, signal_name="ConfirmRequest",
                dbus_interface="io.bianbu.Security")
            self._loop = GLib.MainLoop()
            self._ready.set()
            self._loop.run()

        self._thread = threading.Thread(target=_run, daemon=True)
        self._thread.start()
        self._ready.wait(timeout=5)
        time.sleep(0.3)  # 让信号接收器完成注册

    def stop(self):
        if self._loop:
            self._loop.quit()


def run_steps(sc, gui: MockGUI, aid: str) -> int:
    # 单一持久 GUI（一条连接、一个循环），决定按能力名排队，顺序消费——契合真实
    # 部署形态；也避免"每步新建连接"的重复开销。

    # 步骤 A：ask 策略 —— 用户批准 → 放行
    L.section("A", "3", "ask 确认·批准路径（write_file）",
              "write_file=ask 触发确认，模拟 GUI 批准 → RequestConfirm 返回 True，审计记 approved")
    n0 = len(gui.seen)
    approved = sc.request_confirm(aid, "write_file", "写入 ~/Documents/bianbu-test/a.txt")
    L.check("sc.request_confirm(aid,'write_file',...)", "模拟GUI 批准",
            "approved=True（放行），收到 1 次确认",
            f"approved={approved} 确认 {len(gui.seen) - n0} 次",
            approved is True and len(gui.seen) - n0 == 1)

    # 步骤 B：ask 策略 —— 用户拒绝 → 阻断
    L.section("B", "3", "ask 确认·拒绝路径（terminal）",
              "terminal=ask，模拟 GUI 拒绝 → RequestConfirm 返回 False，操作被阻断")
    n0 = len(gui.seen)
    denied = sc.request_confirm(aid, "terminal", "执行 rm -rf /")
    L.check("sc.request_confirm(aid,'terminal',...)", "模拟GUI 拒绝",
            "approved=False（阻断），收到 1 次确认",
            f"approved={denied} 确认 {len(gui.seen) - n0} 次",
            denied is False and len(gui.seen) - n0 == 1)

    # 步骤 C：未声明工具 —— 未映射默认 ask
    L.section("C", "3", "未映射工具·默认 ask（unknown.tool）",
              "目录与声明都没命中的工具按 ask 处置：仍需一次用户确认")
    n0 = len(gui.seen)
    unmapped_ok = sc.request_confirm(aid, "unknown.tool", "调用未声明工具")
    L.check("sc.request_confirm(aid,'unknown.tool',...)", "未映射工具 + 模拟GUI 批准",
            "approved=True，收到 1 次确认",
            f"approved={unmapped_ok} 确认 {len(gui.seen) - n0} 次",
            unmapped_ok is True and len(gui.seen) - n0 == 1)
    return 0


def main() -> int:
    os.environ["BIANBU_SEC_SESSION"] = "1"
    aid = "com.bianbu.test-security-agent"
    fixtures = ROOT / "tests" / "fixtures" / "test-security-agent"

    print(L.bold("\n╔══════════════════════════════════════════════════════════════════╗"))
    print(L.bold("║   hermes 接入演示 —— ask 确认门禁全路径（批准/拒绝/未映射）      ║"))
    print(L.bold("╚══════════════════════════════════════════════════════════════════╝"))
    print(L.dim("  形态：securityd 子进程 + 模拟GUI 订阅 ConfirmRequest 经 RespondConfirm 回传"))

    from tests.fixtures import make_fixtures
    make_fixtures.main()

    # 复用已在总线上的 securityd（如 conftest/外部已启动）；否则自起子进程（独立运行）
    import dbus
    proc = None
    try:
        obj = dbus.SessionBus().get_object("io.bianbu.Security", "/io/bianbu/Security")
        obj.Introspect(dbus_interface="org.freedesktop.DBus.Introspectable")
        print(L.dim("  复用总线上已有的 securityd"))
    except dbus.DBusException:
        env = dict(os.environ); env["PYTHONPATH"] = str(ROOT)
        proc = subprocess.Popen(
            [sys.executable, "-m", "securityd.service", "--session"],
            env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        obj = L.wait_ready(proc)
        if obj is None:
            return 1
    try:
        import bianbu_security_client as sc
        # 前置：安装 + 注册（否则判权/确认无声明可依）
        r = sc.verify_manifest(str(fixtures))
        sc.register_capabilities(aid, r["permissions"])
        print(L.dim(f"  前置：已安装 {aid}，注册 {len(r['permissions'])} 条能力"))
        # 决定按到达顺序消费：write_file 批；terminal 拒；unknown.tool 批
        gui = MockGUI({
            "write_file": [True],
            "terminal": [False],
            "unknown.tool": [True],
        })
        gui.start()
        try:
            run_steps(sc, gui, aid)
        finally:
            gui.stop()
        print()
        return L._summary("HERMES_CONFIRM_PASS")
    finally:
        if proc is not None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()


if __name__ == "__main__":
    sys.exit(main())
