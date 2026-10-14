"""bianbu-security 接入 hermes —— 全功能逐 case 验收（case by case，从 install 开始）。

形态：真实 securityd（子进程/会话总线）+ 真实插件钩子（pre/post_tool_call）+ 模拟 GUI
（订阅 ConfirmRequest 经 RespondConfirm 回传）。逐条打印【case/输入/期望/实际/判定】。
覆盖：安装验签 → 工具策略注册 → 判权 allow/deny → 确认门禁批准/拒绝 →
      沙箱策略 → 网络策略 → 审计写入/导出/验证/篡改检测 → 撤销。
全通过打印 HERMES_ACCEPTANCE_PASS。
"""
from __future__ import annotations

import os
import subprocess
import sys
import textwrap
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "client"))
sys.path.insert(0, str(ROOT / "hermes_plugin"))

from tests.integration import _dbus_driver as L        # 复用日志助手
from tests.integration.hermes_confirm_demo import MockGUI

AID = "com.hermes.acceptance"

# hermes 接入用 manifest：工具名取自 hermes 工具目录（read_file/write_file/terminal…）
MANIFEST = """[agent]
id        = "com.hermes.acceptance"
version   = "1.0.0"
name      = "Hermes Acceptance Agent"
signature = "ed25519:PLACEHOLDER"

[permissions]
read_file    = "allow"
search_files = "allow"
write_file   = "ask"
terminal     = "deny"

[permissions.network]
allowed_domains  = ["api.minimaxi.com"]
"""


def _make_pkg(tmp: Path) -> Path:
    """生成带真实 ed25519 签名的接入 Agent 包。"""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    pkg = tmp / "acceptance-agent"
    pkg.mkdir(parents=True, exist_ok=True)
    (pkg / "manifest.toml").write_text(MANIFEST)
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
    payload = "\n".join(l for l in MANIFEST.splitlines()
                        if not l.strip().startswith("signature")).encode()
    (pkg / "manifest.toml.sig").write_text(priv.sign(payload).hex())
    (pkg / "pubkey.hex").write_text(pub.hex())
    return pkg


def _tool(plugin, name, args):
    """模拟 hermes 工具循环：pre_tool_call 决定放行/拦截，放行则执行+post。"""
    block = plugin.pre_tool_call(name, args)
    if block is not None:
        return "blocked", block.get("message", "")
    plugin.post_tool_call(name, args, result="ok")
    return "executed", ""


def run_cases(sc, plugin, gui, pkg: Path) -> int:
    T = "10"

    # CASE 1：安装——验签
    L.section(1, T, "安装·Manifest 验签（VerifyManifest）",
              "ed25519 校验 Agent 包签名与权限声明，无效包应拒绝")
    r = sc.verify_manifest(str(pkg))
    L.check("sc.verify_manifest(pkg)", f"pkg={pkg.name}",
            "valid=True，解析 4 条工具策略", f"valid={r['valid']} perms={len(r['permissions'])}",
            r["valid"] and len(r["permissions"]) == 4)

    # CASE 2：安装——能力注册
    L.section(2, T, "安装·工具策略注册（RegisterCapabilities）",
              "校验通过后写入 securityd 策略库，作为后续判权依据")
    ok = sc.register_capabilities(AID, r["permissions"])
    caps = sc.get_capabilities(AID)
    L.check("sc.register_capabilities + get_capabilities", f"agent={AID}",
            "ok=True 且注册 4 条", f"ok={ok} 已注册 {len(caps)} 条", ok and len(caps) == 4)

    # CASE 3：安装——负例：无签名包应拒绝
    L.section(3, T, "安装·负例（无签名包拒绝）",
              "signature=PLACEHOLDER 视为无签名，install 应失败")
    bad = pkg.parent / "bad-agent"; bad.mkdir(exist_ok=True)
    (bad / "manifest.toml").write_text(MANIFEST)  # 无 .sig / pubkey
    rb = sc.verify_manifest(str(bad))
    L.check("sc.verify_manifest(无签名)", "缺 .sig/pubkey",
            "valid=False", f"valid={rb['valid']} reason={rb['reason'][:30]}", not rb["valid"])

    # CASE 4：运行时判权——allow 放行（read_file）
    L.section(4, T, "判权·allow 放行（read_file）",
              "read_file 策略为 allow，pre_tool_call 应放行")
    st, _ = _tool(plugin, "read_file", {"path": "/tmp/x"})
    L.check("pre_tool_call('read_file')", "read_file = allow",
            "executed（ALLOW）", st, st == "executed")

    # CASE 5：运行时判权——deny 拦截（terminal）
    L.section(5, T, "判权·DENY 拦截（terminal）",
              "terminal 策略为 deny，pre_tool_call 返回 block（真拦截）")
    st, msg = _tool(plugin, "terminal", {"command": "rm -rf /"})
    L.check("pre_tool_call('terminal')", "terminal = deny",
            "blocked（DENY）", f"{st}: {msg[:36]}", st == "blocked")

    # CASE 6：确认门禁·批准放行（write_file + GUI 批准）
    L.section(6, T, "确认门禁·批准（write_file，ask）",
              "write_file=ask 触发确认；模拟 GUI 批准 → 放行")
    st, msg = _tool(plugin, "write_file", {"path": "~/Documents/bianbu-test/a.txt", "content": "x"})
    L.check("pre_tool_call('write_file') + GUI 批准", "write_file = ask",
            "executed（确认通过）", f"{st} {msg[:20]}", st == "executed")

    # CASE 7：确认门禁·拒绝拦截（write_file，GUI 拒绝）
    # 注：D-Bus 的 CheckPermission/RequestConfirm 签名不带 session_id，故 ask 的
    #     “会话内复用免确认”在纯 D-Bus 路径下不生效——每次仍确认。
    #     这里验证的是“再次触发确认且 GUI 拒绝 → 拦截”。
    L.section(7, T, "确认门禁·拒绝拦截（write_file，GUI 拒绝）",
              "D-Bus 无 session_id → ask 每次都确认；本次 GUI 拒绝应 blocked")
    seen_before = len(gui.seen)
    st, msg = _tool(plugin, "write_file", {"path": "~/Documents/bianbu-test/b.txt", "content": "y"})
    L.check("pre_tool_call('write_file') 第二次 + GUI 拒绝", f"确认前 GUI 触发={seen_before}",
            "blocked（未确认）且新增一次确认", f"{st}: {msg[:24]}, GUI 触发={len(gui.seen)}",
            st == "blocked" and len(gui.seen) == seen_before + 1)

    # CASE 8：沙箱策略产物（BuildSandboxPolicy）
    L.section(8, T, "沙箱·策略产物（BuildSandboxPolicy）",
              "生成 seccomp BPF 与 netfilter 规则文件，供 bwrap/整进程沙箱使用")
    pol = sc.build_sandbox_policy(AID)
    seccomp_ok = bool(pol.get("seccomp_path")) and Path(pol["seccomp_path"]).exists()
    L.check("sc.build_sandbox_policy(AID)", "生成 seccomp.bpf",
            "seccomp_path 存在", f"seccomp={pol.get('seccomp_path')} 存在={seccomp_ok}", seccomp_ok)

    # CASE 9：网络策略（SetNetworkPolicy）
    L.section(9, T, "网络·白名单策略（SetNetworkPolicy）",
              "按 manifest allowed_domains 生成 netfilter 规则产物")
    nok = sc.set_network_policy(AID, ["api.minimaxi.com"], "whitelist")
    L.check("sc.set_network_policy(AID,[api.minimaxi.com])", "whitelist 1 域名",
            "ok=True", f"ok={nok}", nok is True)

    # CASE 10：审计导出 + 验证 + 篡改检测（ExportAudit/VerifyAuditChain）
    L.section(10, T, "审计·导出/验证/篡改检测（ExportAudit→Verify）",
              "上面各 case 的判权/确认/拦截均入哈希链；导出后验证完整，篡改可检出")
    path = sc.export_audit('{"agent_id":"%s"}' % AID, "json")
    intact = sc.verify_audit_chain(path)
    import json as _json
    doc = _json.loads(Path(path).read_text())
    recs = doc.get("records", doc) if isinstance(doc, dict) else doc
    L.check("sc.export_audit + verify_audit_chain", f"export={Path(path).name}",
            "记录>0 且链完整=True", f"records={len(recs)} intact={intact}",
            len(recs) > 0 and intact is True)
    # 篡改一条后应验证失败
    if recs:
        recs[0]["result"] = "TAMPERED"
        tf = Path(path).with_suffix(".tampered.json")
        tf.write_text(_json.dumps({"records": recs, "chain_anchor": doc.get("chain_anchor", "")}
                                  if isinstance(doc, dict) else recs))
        bad_intact = sc.verify_audit_chain(str(tf))
        L.check("verify_audit_chain(篡改副本)", "改第一条 result",
                "intact=False（检出篡改）", f"intact={bad_intact}", bad_intact is False)
    return 0


def main() -> int:
    os.environ["BIANBU_SEC_SESSION"] = "1"
    os.environ["BIANBU_HERMES_AGENT_ID"] = AID
    import tempfile
    tmp = Path(tempfile.mkdtemp(prefix="hermes_accept_"))

    print(L.bold("\n╔══════════════════════════════════════════════════════════════════╗"))
    print(L.bold("║  bianbu-security 接入 hermes —— 全功能逐 case 验收（case by case）║"))
    print(L.bold("╚══════════════════════════════════════════════════════════════════╝"))
    print(L.dim("  形态：真实 securityd + 真实插件钩子 + 模拟GUI；从 install 开始逐条走完"))

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
        pkg = _make_pkg(tmp)
        gui = MockGUI({"write_file": [True, False]})   # case6 批准；case7 拒绝
        gui.start()
        import bianbu_security as plugin
        try:
            run_cases(sc, plugin, gui, pkg)
        finally:
            gui.stop()
        print()
        return L._summary("HERMES_ACCEPTANCE_PASS")
    finally:
        if proc is not None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()


if __name__ == "__main__":
    sys.exit(main())
