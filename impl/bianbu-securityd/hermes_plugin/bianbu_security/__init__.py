"""bianbu-security — hermes 插件：把工具调用接入 bianbu-securityd。

接线（均用 hermes 公开插件 API，不改 hermes 内部）：
  · pre_tool_call  → CheckPermission；DENY 或 CONFIRM 未获批 → {"action":"block"}
  · post_tool_call → AuditLog（观察者，记账）
  · on_session_end → 清理会话信任（当前由 securityd 内部管理，占位）
  · CLI: securityd-install <pkg> / securityd-audit-export <agent_id>

环境变量：
  BIANBU_HERMES_AGENT_ID   本 hermes 会话对应的 securityd Agent id（默认 com.hermes.agent）
  BIANBU_SEC_SESSION=1      客户端走会话总线（测试）；否则系统总线（生产）
  BIANBU_SECURITY_FAIL_OPEN 1=securityd 不可达时放行（默认 0=fail-closed 拦截）
"""
from __future__ import annotations

import logging
import os
import sys
from pathlib import Path

logger = logging.getLogger("bianbu-security")

# 让插件能 import 到 client 封装（仓库 client/ 目录）。软链部署时按实际路径调整，
# 或设 BIANBU_SECURITYD_HOME 指向 impl/bianbu-securityd。
_HOME = os.environ.get("BIANBU_SECURITYD_HOME")
if _HOME:
    sys.path.insert(0, str(Path(_HOME) / "client"))
    sys.path.insert(0, str(_HOME))  # 供 import securityd.interceptor（干预点框架）

AGENT_ID = os.environ.get("BIANBU_HERMES_AGENT_ID", "com.hermes.agent")
FAIL_OPEN = os.environ.get("BIANBU_SECURITY_FAIL_OPEN") == "1"

# —— 审批仲裁开关（用户可控）——
# BIANBU_SEC_APPROVAL_MODE：
#   "securityd"（默认，推荐）：securityd 确认门禁为准，自动关闭 hermes 自带 approval，
#                              避免双重确认；
#   "both"：securityd 判权/确认 + hermes approval 叠加（更严，双确认）；
#   "hermes"：仅用 hermes approval，securityd 的 CONFIRM 降级为放行（只判权 DENY + 审计）。
APPROVAL_MODE = os.environ.get("BIANBU_SEC_APPROVAL_MODE", "securityd").strip().lower()

# 决策码（与 securityd 一致）：0=ALLOW 1=CONFIRM 2=DENY
ALLOW, CONFIRM, DENY = 0, 1, 2


def _client():
    import bianbu_security_client as sc
    return sc


def _disable_hermes_approval() -> str:
    """按开关关闭 hermes 自带 approval。返回状态说明（供日志）。

    首选进程级 HERMES_YOLO_MODE（须在 hermes 导入前设，见启动器/文档）；
    运行时兜底调用 approval.enable_session_yolo（对当前 session 生效）。
    """
    if APPROVAL_MODE != "securityd":
        return f"保留 hermes approval（mode={APPROVAL_MODE}）"
    frozen = os.environ.get("HERMES_YOLO_MODE", "")
    if frozen and frozen not in ("0", "false", "False", ""):
        return "hermes approval 已由 HERMES_YOLO_MODE 进程级关闭"
    # 运行时兜底：对所有已知 session 开启 yolo（hermes approval 短路为 approved）
    try:
        from tools import approval as _ap  # hermes 模块（运行于 hermes 进程内时可用）
        key = _ap.get_current_session_key(default="") if hasattr(_ap, "get_current_session_key") else ""
        if key:
            _ap.enable_session_yolo(key)
            return f"hermes approval 已对 session={key} 运行时关闭"
        return ("未能自动关闭 hermes approval：请在启动 hermes 前设 HERMES_YOLO_MODE=1"
                "（securityd 门禁仍为准）")
    except Exception as e:  # noqa: BLE001 — 非 hermes 进程内/接口不符
        return f"hermes approval 关闭跳过（{e}）；建议设 HERMES_YOLO_MODE=1"


def _fail(action_reason: str):
    """securityd 不可达时的策略：fail-closed 拦截，或 fail-open 放行。"""
    if FAIL_OPEN:
        logger.warning("securityd 不可达，FAIL_OPEN 放行：%s", action_reason)
        return None
    return {"action": "block",
            "message": f"bianbu-securityd 不可达，已 fail-closed 拦截（{action_reason}）"}


def _registry():
    """干预点框架 registry（惰性加载：securityd 包不可 import 时回退 None）。"""
    global _REGISTRY, _HOOKS_READY
    if _HOOKS_READY:
        return _REGISTRY
    _HOOKS_READY = True
    try:
        from securityd.interceptor import global_registry
        import bianbu_security_handlers as h

        h.register_core_handlers(global_registry, with_audit=False)
        # SEC-HOOK-05：干预点执行轨迹落审计链（BIANBU_SEC_HOOK_AUDIT=0 可关）
        if os.environ.get("BIANBU_SEC_HOOK_AUDIT", "1") != "0":
            global_registry.set_audit_sink(
                h.make_audit_sink(AGENT_ID, client_provider=_client))
        _REGISTRY = global_registry
        logger.info("干预点框架已挂载（pre_tool_call: sec_capability@10）")
    except Exception as e:  # noqa: BLE001 — 框架不可用时走直连判权
        logger.debug("干预点框架不可用，回退直连判权：%s", e)
        _REGISTRY = None
    return _REGISTRY


_REGISTRY = None
_HOOKS_READY = False


def pre_tool_call(tool_name: str, args: dict, **kwargs):
    """判权 + 确认门禁。返回 {"action":"block","message":...} 阻止工具，None 放行。

    判权经干预点框架（pre_tool_call 点，sec_capability@10 + 后续 DLP@50 等）；
    CONFIRM 的确认 UI 仍由本插件按 APPROVAL_MODE 处理（hermes 特有的 TUI 呈现）。
    """
    from . import mapping
    yolo = False
    try:
        mode = _client().get_agent_security_mode(AGENT_ID)
        yolo = isinstance(mode, dict) and str(mode.get("mode", "")).lower() == "yolo"
    except Exception:
        pass
    resolved = mapping.resolve(tool_name, args or {})

    # 未映射工具：工具名不在 hermes 工具目录中。原来按 DEFAULT_ALLOW 直接放行，
    # 等于"名字不含关键字的新工具全部免判权"，且配置台上看不到痕迹。现按统一
    # 策略处置（unmapped_policy，默认 ask）—— 交用户逐次确认。
    try:
        from securityd.capabilities import is_known as _is_known
        unmapped = not _is_known(tool_name, "hermes")
    except Exception:  # noqa: BLE001 — 无 securityd 时退回旧判定
        unmapped = resolved is None
    if unmapped:
        from securityd.capabilities import (
            UNMAPPED_TOOL, unmapped_decision, unmapped_policy,
        )
        code = unmapped_decision()
        _safe_audit(tool_name, f"{UNMAPPED_TOOL}:", f"unmapped:{unmapped_policy()}")
        if code == 0:
            return None
        if code == 2 and not yolo:
            return {"action": "block",
                    "message": f"工具 {tool_name} 未在安全策略目录中声明"}
        capability, scope = tool_name, ""
    else:
        capability, scope = resolved

    if unmapped:
        # 未映射 + confirm 策略：不必判权（能力未注册必然 DENY），
        # 直接落到下方确认门禁交用户定。
        pass
    elif (reg := _registry()) is not None:
        from securityd.interceptor import Decision, HookPoint

        r = reg.invoke(
            HookPoint.PRE_TOOL_CALL,
            AGENT_ID,
            {"tool": tool_name, "capability": capability, "scope": scope,
             "args": args or {}},
            session_id=kwargs.get("session_id", ""),
            # 注入本模块的 _client 间接层：测试可 monkeypatch plugin._client 生效
            client_provider=_client,
        )
        if r.decision == Decision.BLOCK and not yolo:
            # fail-closed 拦截也走这里；DENY 才记审计（不可达无需重复记）
            if (r.metadata or {}).get("reason") == "denied":
                _safe_audit(tool_name, f"{capability}:{scope}", "deny")
            return {"action": "block", "message": r.message}
        if r.decision != Decision.CONFIRM or yolo:
            return None
        # CONFIRM → 落到下方确认门禁逻辑
    else:
        # 回退：框架不可用时直连 CheckPermission（行为与改造前一致）
        try:
            sc = _client()
            decision = sc.check_permission(AGENT_ID, capability, scope)
        except Exception as e:  # noqa: BLE001 — 总线不可达
            return _fail(f"CheckPermission {capability}: {e}")

        if decision == ALLOW:
            return None
        if decision == DENY and not yolo:
            _safe_audit(tool_name, f"{capability}:{scope}", "deny")
            return {"action": "block",
                    "message": f"权限被拒绝：工具 {tool_name} 的策略为 deny"}
    if yolo:
        _safe_audit(tool_name, f"{capability}:{scope}", "allow;mode=yolo")
        return None

    # CONFIRM：确认走哪条路纯按 APPROVAL_MODE 决定（真机源码实证的取舍）：
    #   · mode=hermes：交回 hermes 原生 approval，在其 prompt_toolkit TUI 里弹
    #     [o/s/a/d]。这是**交互式 CLI（hermes chat）下唯一可行**的确认方式——插件
    #     裸 input() 会挂死（hermes 源码注释 "input() hangs"），且拿不到 hermes 的
    #     cli 对象无法复用其 TUI 审批。mode=hermes 不关 hermes approval，故其 TUI 生效。
    #   · mode=securityd/both：走 securityd 信号路径，由 WebUI 确认门禁 Tab 经
    #     RespondConfirm 回传（已验证；交互式 CLI 下无终端响应者，须保持 WebUI 在线）。
    detail = f"{tool_name}"
    from . import cli_confirm

    # 优先：交互式 CLI 下主动调 hermes 已注册的 TUI 审批回调，弹出原生
    # [Allow once/session/always/Deny] 弹窗（走 cli._app prompt_toolkit，不挂死）。
    # 这样 bianbu 判定"需确认"的任何能力都能弹框，不受 hermes 危险正则范围限制。
    if APPROVAL_MODE != "securityd" or cli_confirm.is_cli_interactive():
        choice = cli_confirm.hermes_tui_approve(
            command=detail,
            description=f"bianbu-security: {AGENT_ID} 需确认工具 {tool_name}")
        if choice is not None:  # 成功弹框并拿到用户决定
            approved = choice != "deny"
            _safe_audit(tool_name, f"{capability}:{scope}",
                        f"confirm_hermes_tui:{choice}")
            if approved:
                return None
            return {"action": "block",
                    "message": f"用户拒绝：工具 {tool_name}（hermes TUI 选择 Deny）"}
        # 拿不到 hermes 回调（非 CLI/未注册）→ 若 mode=hermes 放行交回 hermes 自身流程
        if APPROVAL_MODE == "hermes":
            _safe_audit(tool_name, f"{capability}:{scope}", "confirm_delegated_to_hermes")
            return None

    # 回退：securityd 信号路径，等 WebUI/GUI 经 RespondConfirm 回传（无响应者则超时→拦截）
    try:
        approved = _client().request_confirm(AGENT_ID, capability, detail)
    except Exception as e:  # noqa: BLE001
        return _fail(f"RequestConfirm {capability}: {e}")
    if approved:
        return None
    hint = ("；交互式 CLI 无 TUI 审批回调可用，请设 BIANBU_SEC_APPROVAL_MODE=hermes "
            "或保持 WebUI 确认门禁在线") if cli_confirm.is_cli_interactive() else ""
    return {"action": "block",
            "message": f"用户未确认：工具 {tool_name} 的确认被拒绝/超时{hint}"}


def _safe_audit(op_type: str, target: str, result: str) -> None:
    try:
        _client().audit_log(AGENT_ID, op_type, target, result)
    except Exception as e:  # noqa: BLE001 — 审计失败不应影响 hermes 主流程
        logger.debug("AuditLog 失败：%s", e)


def post_tool_call(tool_name: str, args: dict = None, result=None, **kwargs):
    """观察者：把工具执行写入审计链。"""
    from . import mapping
    resolved = mapping.resolve(tool_name, args or {})
    target = f"{resolved[0]}:{resolved[1]}" if resolved else tool_name
    _safe_audit(tool_name, target, "executed")


def on_session_end(**kwargs):
    """会话结束占位：securityd 侧会话信任由其自身管理，这里仅记一条审计。"""
    _safe_audit("session", "hermes", "session_end")


# ————————————————————————————————————————————————————————————————
# hermes 插件入口：discover_and_load 会调用本模块的 register(manager)
# ————————————————————————————————————————————————————————————————
def _cmd_install(args) -> int:
    """securityd-install <pkg_path>：验签 + 注册 Agent 能力（安装准备）。"""
    sc = _client()
    pkg = args[0] if args else ""
    r = sc.verify_manifest(pkg)
    if not r["valid"]:
        print(f"install 失败：{r['reason']}")
        return 1
    ok = sc.register_capabilities(AGENT_ID, r["permissions"])
    print(f"install {'成功' if ok else '失败'}：{AGENT_ID} 注册 {len(r['permissions'])} 条能力")
    return 0 if ok else 1


def _cmd_audit_export(args) -> int:
    """securityd-audit-export <agent_id?>：导出审计链并验证完整性。"""
    sc = _client()
    aid = args[0] if args else AGENT_ID
    path = sc.export_audit('{"agent_id":"%s"}' % aid, "json")
    intact = sc.verify_audit_chain(path)
    print(f"导出：{path}\n完整性：{'intact' if intact else 'TAMPERED'}")
    return 0 if intact else 1


def register(manager):
    """hermes 插件注册入口。"""
    manager.register_hook("pre_tool_call", pre_tool_call)
    manager.register_hook("post_tool_call", post_tool_call)
    manager.register_hook("on_session_end", on_session_end)
    # CLI 命令（若该 hermes 版本支持 register_cli_command）
    reg_cli = getattr(manager, "register_cli_command", None)
    if callable(reg_cli):
        try:
            reg_cli("securityd-install", _cmd_install,
                    help="验签+注册 Agent 包到 bianbu-securityd")
            reg_cli("securityd-audit-export", _cmd_audit_export,
                    help="导出并校验 securityd 审计链")
        except Exception as e:  # noqa: BLE001 — CLI 注册失败不影响钩子
            logger.debug("register_cli_command 跳过：%s", e)
    # 按开关仲裁与 hermes 自带 approval 的关系
    approval_status = _disable_hermes_approval()
    # 注：CLI 终端确认不在此启动（此时 HERMES_INTERACTIVE 尚未设、hermes 无 gi）——
    # 改在 pre_tool_call 的 CONFIRM 分支按 cli_confirm.is_cli_interactive() 即时决定。
    logger.info("bianbu-security 插件已注册（agent_id=%s, fail_open=%s, approval_mode=%s）：%s",
                AGENT_ID, FAIL_OPEN, APPROVAL_MODE, approval_status)
    # 会话开始时也尝试关一次（拿到 session_key 的时机更准）
    reg_hook = getattr(manager, "register_hook", None)
    if callable(reg_hook):
        try:
            reg_hook("on_session_start", lambda **kw: _disable_hermes_approval() and None)
        except Exception:  # noqa: BLE001
            pass
