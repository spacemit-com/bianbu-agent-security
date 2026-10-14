"""securityd 冒烟全链路 driver —— 详细可追踪日志版。

在当前（私有）session bus 内以子进程启动 securityd，再以 D-Bus 客户端逐项验证。
每步打印【功能说明 / 调用代码 / 输入 / 期望 / 实际 / 判定】，任何人都能看懂运行结果。
全部通过才打印 DBUS_E2E_PASS（供 pytest / smoke_test.sh 断言）。镜像真实部署形态。
"""
from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path
import dbus

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "client"))

# ——— 日志助手（tty 才上色，pytest 捕获时自动降级为纯文本）———
_PASS = 0
_FAIL = 0
_TTY = sys.stdout.isatty()


def _c(code: str, s: str) -> str:
    return f"\033[{code}m{s}\033[0m" if _TTY else s


def green(s): return _c("32", s)
def red(s): return _c("31", s)
def cyan(s): return _c("36", s)
def dim(s): return _c("2", s)
def bold(s): return _c("1", s)


def _dec(d: int) -> str:
    return {0: "ALLOW 放行", 1: "CONFIRM 需确认", 2: "DENY 拒绝"}.get(d, "未知")


def section(n: int, total: int, title: str, desc: str) -> None:
    line = "━" * 68
    print("\n" + cyan(line))
    print(cyan(f"步骤 {n}/{total} ▸ {title}"))
    print(dim(f"  说明：{desc}"))
    print(cyan(line))


def field(label: str, value: str) -> None:
    print(f"  ├ {label:<4}: {value}")


def check(code: str, inp: str, expect: str, actual: str, ok: bool) -> None:
    """打印一次断言的完整轨迹并累计计数。"""
    global _PASS, _FAIL
    field("调用", code)
    if inp:
        field("输入", inp)
    field("期望", expect)
    field("实际", actual)
    if ok:
        _PASS += 1
        print(f"  └ {green('✔ PASS')}")
    else:
        _FAIL += 1
        print(f"  └ {red('✘ FAIL')}")


def wait_ready(proc, timeout_s: float = 8.0):
    """轮询等待 securityd 在总线上就绪，返回对象代理。"""
    import dbus
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        if proc.poll() is not None:
            print(red("  服务进程提前退出：\n") + (proc.stdout.read() or ""))
            return None
        try:
            obj = dbus.SessionBus().get_object("io.bianbu.Security", "/io/bianbu/Security")
            obj.Introspect(dbus_interface="org.freedesktop.DBus.Introspectable")
            return obj
        except dbus.DBusException:
            time.sleep(0.1)
    return None


TOTAL = 8


def main() -> int:
    # 本地开发机未必存在生产 bianbu-admin 组；driver 通过显式测试标记
    # 允许管理调用，生产系统总线仍由 policy + service 层强制授权。
    os.environ.setdefault("BIANBU_SECURITY_TEST_ADMIN", "1")
    os.environ["BIANBU_SEC_SESSION"] = "1"
    aid = "com.bianbu.test-security-agent"
    fixtures = ROOT / "tests" / "fixtures" / "test-security-agent"

    print(bold("\n╔══════════════════════════════════════════════════════════════════╗"))
    print(bold("║   bianbu-securityd 全链路冒烟测试（详细追踪日志）                 ║"))
    print(bold("╚══════════════════════════════════════════════════════════════════╝"))
    print(dim(f"  Agent 包：{fixtures}"))
    print(dim(f"  数据根  ：{os.environ.get('BIANBU_SEC_ROOT', '<default>')}"))

    from tests.fixtures import make_fixtures
    make_fixtures.main()

    # 步骤 0：启动守护进程
    section(0, TOTAL, "启动 securityd 守护进程",
            "以子进程在会话总线上拉起服务，模拟真实部署，等待其在 D-Bus 就绪")
    env = dict(os.environ); env["PYTHONPATH"] = str(ROOT)
    proc = subprocess.Popen(
        [sys.executable, "-m", "securityd.service", "--session"],
        env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    obj = wait_ready(proc)
    check("securityd.service --session（子进程）", "会话总线",
          "服务在 io.bianbu.Security 上就绪", "已就绪" if obj else "未就绪/超时",
          obj is not None)
    if obj is None:
        _summary(); proc.terminate(); return 1

    try:
        import bianbu_security_client as sc

        # 步骤 1：接口自省——业务方法齐全
        section(1, TOTAL, "D-Bus 接口自省（Introspect）",
                "确认对外契约完整：io.bianbu.Security 暴露全部业务方法")
        xml = obj.Introspect(dbus_interface="org.freedesktop.DBus.Introspectable")
        methods = ["VerifyManifest", "VerifyCodePackage", "VerifyCodeDigest", "RegisterCapabilities", "BindAgent",
                   "BindAgentV2", "CheckPermission", "CheckPermissionV2",
                   "ResetAgentBinding",
                   "GrantSessionTrustV2",
                   "RequestConfirm", "RespondConfirm", "RevokePermission",
                   "RequestConfirmV2",
                   "BuildSandboxPolicy", "AuditLog", "ExportAudit",
                   "QueryAudit", "VerifyAuditChain", "SetNetworkPolicy", "GetCapabilities", "SuspendAgent",
                   "InstallPackage", "ListAgents", "SetCapabilityPolicy",
                   "GetNetworkPolicy", "GetAgentInfo", "GetAgentSecurityMode", "SetAgentSecurityMode"]
        n = len(methods)
        missing = [m for m in methods if f'name="{m}"' not in xml]
        check("obj.Introspect()", "统计 <method> 节点",
              f"{n} 个业务方法全部存在", f"存在 {n - len(missing)}/{n}，缺失={missing or '无'}",
              not missing)

        # 步骤 2：Manifest 验签
        section(2, TOTAL, "Manifest 验签（VerifyManifest）",
                "ed25519 校验 Agent 包签名与权限声明，防止被篡改的包被安装")
        r = sc.verify_manifest(str(fixtures))
        check("sc.verify_manifest(pkg)", f"pkg={fixtures.name}",
              "valid=True，解析出 5 条权限声明",
              f"valid={r['valid']} perms={len(r['permissions'])} reason='{r['reason']}'",
              r["valid"] and len(r["permissions"]) == 5)

        # 步骤 3：能力注册
        section(3, TOTAL, "能力注册（RegisterCapabilities）",
            "把校验通过的权限写入 SQLite 能力库，作为后续判权依据")
        # 生产由 Runtime/admin 在启动阶段先建立可信 caller 绑定；测试显式走同一接口。
        bound = bool(obj.BindAgent(aid, dbus_interface="io.bianbu.Security"))
        check("obj.BindAgent(aid)", f"agent={aid}", "绑定成功", f"ok={bound}", bound)
        bound_v2 = bool(obj.BindAgentV2(
            aid, dbus.Dictionary({"session_id": dbus.String("session-v2"),
                                   "run_id": dbus.String("run-v2")}, signature="sv"),
            dbus_interface="io.bianbu.Security"))
        check("obj.BindAgentV2(aid, context)", f"agent={aid}",
              "V2 session/run 上下文绑定成功", f"ok={bound_v2}", bound_v2)
        ok = sc.register_capabilities(aid, r["permissions"])
        check("sc.register_capabilities(aid, perms)", f"agent={aid}，5 条权限",
              "ok=True", f"ok={ok}", ok is True)

        # 步骤 4：权限判定三态
        section(4, TOTAL, "工具策略判定（CheckPermission）",
                "按工具策略返回 ALLOW/ASK/DENY —— 安全子系统的核心决策")
        d1 = sc.check_permission(aid, "read_file")
        check("check_permission(aid,'read_file')", "声明 allow 的只读工具",
              "0 = ALLOW（直接放行）", f"{d1} = {_dec(d1)}", d1 == 0)
        d2 = sc.check_permission(aid, "process")
        check("check_permission(aid,'process')", "声明 deny 的有副作用工具",
              "2 = DENY（明确拒绝）", f"{d2} = {_dec(d2)}", d2 == 2)
        d_v2 = int(obj.CheckPermissionV2(
            aid, "write_file", "~/Documents/bianbu-test/a.txt",
            dbus.Dictionary({"session_id": dbus.String("session-v2"),
                             "run_id": dbus.String("run-v2")}, signature="sv"),
            dbus_interface="io.bianbu.Security"))
        check("obj.CheckPermissionV2(..., context)", "声明 ask 的写入工具 + session-v2/run-v2",
              "1 = ASK（首次需用户确认）", f"{d_v2} = {_dec(d_v2)}", d_v2 == 1)
        d3 = sc.check_permission(aid, "unknown.tool")
        check("check_permission(aid,'unknown.tool')", "未声明工具",
              "1 = ASK（未映射默认交用户确认）", f"{d3} = {_dec(d3)}", d3 == 1)

        # 步骤 5：沙箱策略编译
        section(5, TOTAL, "沙箱策略编译（BuildSandboxPolicy）",
                "生成 seccomp BPF 与 netfilter 白名单，供 bwrap 隔离运行 Agent")
        pol = sc.build_sandbox_policy(aid)
        sp = Path(pol["seccomp_path"])
        size = sp.stat().st_size if sp.exists() else 0
        check("sc.build_sandbox_policy(aid)", f"agent={aid}",
              "seccomp.bpf 存在且非空",
              f"seccomp={sp.name}({size}B) netfilter={Path(pol['netfilter_rules']).name}",
              sp.exists() and size > 0)

        # 步骤 6：审计写入 + 导出 + 哈希链验证
        section(6, TOTAL, "审计链完整性（AuditLog→Export→Verify）",
                "所有操作写入 SHA-256 哈希链，导出后可离线验证（不可抵赖）")
        seq = sc.audit_log(aid, "smoke_marker", "target-A", "allow")
        field("写入", f"AuditLog(...) 返回 seq={seq}")
        import json
        page = sc.query_audit(json.dumps({"agent_id": aid, "limit": 1}))
        check("sc.query_audit(limit=1)", f"agent={aid}",
              "返回最新记录及快照游标", str(page),
              len(page["records"]) == 1 and page["records"][0]["seq"] == seq
              and page["snapshot_seq"] >= seq and isinstance(page["has_more"], bool))
        path = sc.export_audit('{"agent_id":"%s"}' % aid, "json")
        field("导出", Path(path).name)
        intact = sc.verify_audit_chain(path)
        check("sc.verify_audit_chain(export)", f"export={Path(path).name}",
              "True = 哈希链完整未被篡改", f"{intact}", intact is True)

        # 步骤 7：能力清单查询
        section(7, TOTAL, "能力清单查询（GetCapabilities）",
                "供管理端/GUI 展示某 Agent 已授予的全部能力")
        caps = sc.get_capabilities(aid)
        names = ", ".join(sorted(c.get("capability", "?") for c in caps))
        check("sc.get_capabilities(aid)", f"agent={aid}",
              "返回 5 条能力", f"{len(caps)} 条：{names}", len(caps) == 5)

        print()
        return _summary()
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


def _summary(sentinel: str = "DBUS_E2E_PASS") -> int:
    total = _PASS + _FAIL
    line = "═" * 68
    print(bold(line))
    if _FAIL == 0:
        print(bold(green(f"  结果：全部通过  {_PASS}/{total}  ✔")))
        print(bold(green(f"  {sentinel}")))  # 供 smoke_test.sh / pytest 断言
        print(bold(line))
        return 0
    print(bold(red(f"  结果：{_FAIL} 项失败  通过 {_PASS}/{total}  ✘")))
    print(bold(line))
    return 1


if __name__ == "__main__":
    sys.exit(main())
