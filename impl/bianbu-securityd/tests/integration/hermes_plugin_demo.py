"""hermes 插件接入演示（详细日志）——模拟 hermes 的钩子分发，验证插件行为。

不依赖安装 hermes：本脚本扮演 hermes 的工具执行循环，按 hermes 的钩子契约调用
插件的 pre_tool_call / post_tool_call，对接真实 securityd（子进程/会话总线）。

验证：
  · 未映射工具（think 等）→ 按策略处置（可配 allow）
  · 声明为 allow 的工具（read_file）→ 放行
  · 声明为 deny 的工具（terminal）→ DENY，pre_tool_call 返回 block
  · 声明为 ask 的工具（write_file）→ 模拟GUI 批准则放行、拒绝则 block
  · 每次调用后 post_tool_call 写审计，末尾导出+验证链
全通过打印 HERMES_PLUGIN_PASS。
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
from tests.integration.hermes_confirm_demo import MockGUI


def _simulate_tool(plugin, tool_name, args):
    """模拟 hermes 工具执行循环：pre_tool_call 决定放行/拦截，放行则"执行"+post。"""
    block = plugin.pre_tool_call(tool_name, args)
    if block is not None:
        return ("blocked", block.get("message", ""))
    # 放行 → 模拟执行 → 观察者钩子
    plugin.post_tool_call(tool_name, args, result="ok")
    return ("executed", "")


def run_steps(plugin, gui, aid) -> int:
    import bianbu_security_client as sc
    T = "5"

    # 步骤 1：未映射工具 → 按策略处置（默认 ask；显式设 allow 可放行内部只读工具）
    import os
    os.environ["BIANBU_SECURITY_UNMAPPED"] = "allow"
    L.section(1, T, "未映射工具按策略放行（think）",
              "未映射工具默认 ask 交用户确认；"
              "设 BIANBU_SECURITY_UNMAPPED=allow 可恢复「默认放行只记审计」")
    st, msg = _simulate_tool(plugin, "think", {"thought": "hi"})
    L.check("pre_tool_call('think',...)", "未在目录 + unmapped=allow",
            "executed（放行）", f"{st} {msg}", st == "executed")
    os.environ.pop("BIANBU_SECURITY_UNMAPPED", None)

    # 步骤 2：allow 策略（read_file）→ 放行
    L.section(2, T, "allow 策略放行（read_file）",
              "已声明 read_file=allow，判权 ALLOW，工具直接执行")
    st, msg = _simulate_tool(plugin, "read_file", {"path": "/tmp/x"})
    L.check("pre_tool_call('read_file',path=/tmp/x)", "read_file = allow",
            "executed（ALLOW）", f"{st}", st == "executed")

    # 步骤 3：deny 策略（terminal）→ DENY 拦截
    L.section(3, T, "deny 策略拦截（terminal）",
              "Agent 声明 terminal=deny，判权 DENY，pre_tool_call 返回 block")
    st, msg = _simulate_tool(plugin, "terminal", {"command": "rm -rf /"})
    L.check("pre_tool_call('terminal',...)", "terminal = deny",
            "blocked（DENY）", f"{st}: {msg[:40]}", st == "blocked")

    # 步骤 4：ask 策略（write_file）+ GUI 批准 → 放行
    L.section(4, T, "确认门禁·批准放行（write_file，ask）",
              "write_file=ask 触发确认；模拟 GUI 批准 → 放行")
    st, msg = _simulate_tool(plugin, "write_file",
                             {"path": "~/Documents/bianbu-test/a.txt", "content": "x"})
    L.check("pre_tool_call('write_file',...)", "write_file = ask + GUI 批准",
            "executed（确认通过）", f"{st} {msg[:30]}", st == "executed")

    # 步骤 5：ask 策略 + GUI 拒绝 → 拦截
    L.section(5, T, "确认门禁·拒绝拦截（write_file）",
              "同上策略，模拟GUI 拒绝 → pre_tool_call 返回 block")
    st, msg = _simulate_tool(plugin, "write_file",
                             {"path": "~/Documents/bianbu-test/b.txt", "content": "y"})
    L.check("pre_tool_call('write_file',...)", "write_file = ask + GUI 拒绝",
            "blocked（未确认）", f"{st}: {msg[:36]}", st == "blocked")

    # 审计链导出 + 验证
    L.section("审计", T, "审计链导出与验证（ExportAudit→Verify）",
              "上面每步 post_tool_call/deny 均写入哈希链，导出后离线验证完整")
    path = sc.export_audit('{"agent_id":"%s"}' % aid, "json")
    intact = sc.verify_audit_chain(path)
    L.check("sc.verify_audit_chain(export)", f"export={Path(path).name}",
            "True（链完整）", f"{intact}", intact is True)
    return 0


def main() -> int:
    os.environ["BIANBU_SEC_SESSION"] = "1"
    aid = "com.hermes.agent"
    os.environ["BIANBU_HERMES_AGENT_ID"] = aid

    print(L.bold("\n╔══════════════════════════════════════════════════════════════════╗"))
    print(L.bold("║   hermes 插件接入演示 —— pre/post_tool_call 钩子对接 securityd    ║"))
    print(L.bold("╚══════════════════════════════════════════════════════════════════╝"))
    print(L.dim("  形态：模拟 hermes 工具循环调用插件钩子 → 插件经 D-Bus 判权/审计"))

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
            return 1
    try:
        import bianbu_security_client as sc
        # 注册与 hermes 工具目录一致的工具名：read_file=allow、write_file=ask、terminal=deny
        perms = [
            {"tool": "read_file", "policy": "allow"},
            {"tool": "write_file", "policy": "ask"},
            {"tool": "terminal", "policy": "deny"},
        ]
        sc.register_capabilities(aid, perms)
        print(L.dim(f"  前置：{aid} 注册 read_file=allow + write_file=ask + terminal=deny"))

        gui = MockGUI({"write_file": [True, False]})  # 步骤4 批准、步骤5 拒绝
        gui.start()
        import bianbu_security as plugin
        try:
            run_steps(plugin, gui, aid)
        finally:
            gui.stop()
        print()
        return L._summary("HERMES_PLUGIN_PASS")
    finally:
        if proc is not None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()


if __name__ == "__main__":
    sys.exit(main())
