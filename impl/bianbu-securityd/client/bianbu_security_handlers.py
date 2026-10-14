"""客户端侧可复用干预点 handler（框架无关）。

hermes 插件、LangGraph 包装层共用这些 handler，只在"如何呈现确认 UI"上各自适配。

handler 只做治理决策（ALLOW / CONFIRM / BLOCK），不碰任何框架特有的返回格式；
把 InterceptResult 翻译成 hermes 的 {"action":"block"} 或 LangGraph 的 error dict
是各适配层的职责。
"""
from __future__ import annotations

import logging
import os

from securityd.interceptor import Decision, HookPoint, InterceptResult

logger = logging.getLogger("bianbu-security.handlers")

# 决策码（与 securityd 一致）：0=ALLOW 1=CONFIRM 2=DENY
ALLOW, CONFIRM, DENY = 0, 1, 2

# 优先级槽位
PRI_SEC_CAPABILITY = 10
PRI_DLP = 50
PRI_AUDIT = 90


def _client():
    import bianbu_security_client as sc

    return sc


def _fail_open() -> bool:
    return os.environ.get("BIANBU_SECURITY_FAIL_OPEN") == "1"


# ————————————————————————————————————————————————————————————————
# SEC Capability 判权 handler（pri=10）
# ————————————————————————————————————————————————————————————————
def sec_capability_handler(
    agent_id: str, hook_point: HookPoint, data, context: dict
) -> InterceptResult:
    """判权 handler：查 CheckPermission，返回 ALLOW / CONFIRM / BLOCK。

    期望 data 形如 {"tool": str, "capability": str, "scope": str}。
    capability 为 None 表示映射表未声明该工具 —— 交由调用方的 DEFAULT_ALLOW 策略决定，
    此处按"未声明即放行"处理（与既有 mapping.DEFAULT_ALLOW 行为一致，由适配层前置判断）。

    客户端来源：context["client_provider"]（适配层注入，便于测试替身）优先，
    否则 import bianbu_security_client。context 同时携带 session_id/run_id 时
    使用 CheckPermissionV2，以便 once_per_session 信任在 HITL 恢复后生效。

    securityd 不可达时按 BIANBU_SECURITY_FAIL_OPEN 决定放行或拦截（默认 fail-closed）。
    """
    capability = (data or {}).get("capability")
    if not capability:
        return InterceptResult(decision=Decision.ALLOW)

    scope = (data or {}).get("scope") or ""
    tool_name = (data or {}).get("tool", "?")
    provider = (context or {}).get("client_provider") or _client

    try:
        client = provider()
        # LangGraph HITL 的审批恢复由 PA 负责，once_per_session 信任必须
        # 使用同一 session_id 才能在恢复后的下一次 before_tool 判权中生效。
        # 旧版 handler 一律调用无上下文的 CheckPermission，securityd 无法
        # 查 session_trust，于是同一 Run 每次 memory_retrieve 都重复 CONFIRM。
        session_id = str((context or {}).get("session_id") or "").strip()
        run_id = str((context or {}).get("run_id") or "").strip()
        check_v2 = getattr(client, "check_permission_v2", None)
        if session_id and run_id and callable(check_v2):
            decision = check_v2(
                agent_id,
                capability,
                scope,
                {"session_id": session_id, "run_id": run_id},
            )
        else:
            decision = client.check_permission(agent_id, capability, scope)
    except Exception as e:  # noqa: BLE001 — 总线不可达
        if _fail_open():
            logger.warning("securityd 不可达，FAIL_OPEN 放行：CheckPermission %s: %s",
                           capability, e)
            return InterceptResult(
                decision=Decision.ALLOW,
                message=f"securityd 不可达，fail-open 放行（{e}）",
            )
        return InterceptResult(
            decision=Decision.BLOCK,
            message=f"bianbu-securityd 不可达，已 fail-closed 拦截"
                    f"（CheckPermission {capability}: {e}）",
        )

    if decision == ALLOW:
        return InterceptResult(decision=Decision.ALLOW)

    if decision == DENY:
        return InterceptResult(
            decision=Decision.BLOCK,
            message=f"权限被拒绝：{tool_name} 需能力 {capability}"
                    f"（scope={scope or '-'}），未授权或已撤销",
            metadata={"capability": capability, "scope": scope, "reason": "denied"},
        )

    # CONFIRM：仅返回决策，确认 UI 由适配层负责
    return InterceptResult(
        decision=Decision.CONFIRM,
        message=f"{tool_name}({capability}) scope={scope or '-'}",
        metadata={"capability": capability, "scope": scope},
    )


# ————————————————————————————————————————————————————————————————
# 审计 handler（pri=90）
# ————————————————————————————————————————————————————————————————
def audit_handler(
    agent_id: str, hook_point: HookPoint, data, context: dict
) -> InterceptResult:
    """审计 handler：把干预点事件写入审计链。审计失败不影响主流程。"""
    d = data or {}
    tool_name = d.get("tool", str(hook_point.value))
    capability = d.get("capability")
    scope = d.get("scope") or ""
    target = f"{capability}:{scope}" if capability else tool_name
    result = (context or {}).get("audit_result", hook_point.value)
    provider = (context or {}).get("client_provider") or _client

    try:
        provider().audit_log(agent_id, tool_name, target, result)
    except Exception as e:  # noqa: BLE001 — 审计失败不阻断
        logger.debug("AuditLog 失败：%s", e)

    return InterceptResult(decision=Decision.ALLOW)


# ————————————————————————————————————————————————————————————————
# 注册辅助
# ————————————————————————————————————————————————————————————————
# ————————————————————————————————————————————————————————————————
# 干预点审计 sink（SEC-HOOK-05）
# ————————————————————————————————————————————————————————————————
def format_hook_trace(trace: list) -> str:
    """把 trace 编码为紧凑单行：handler@延迟ms=决策，逗号分隔。

    形如 "sec_capability@1.2=ALLOW,dlp@8.5=CONFIRM"
    审计表 schema 固定（无 trace 列）且 result 参与哈希计算，故编码进 result 字段，
    不改表结构、不破坏既有哈希链。
    """
    parts = []
    for item in trace or []:
        try:
            name, latency_ms, decision = item
            parts.append(f"{name}@{latency_ms:.1f}={decision}")
        except (ValueError, TypeError):
            parts.append(str(item))
    return ",".join(parts)


def make_audit_sink(agent_id_default: str = "", client_provider=None):
    """构造审计 sink，注册到 registry.set_audit_sink()。

    每条 handler 链执行完写一条审计记录：
      op_type = "hook:<hook_point>"
      target  = "<决策>"
      result  = "handler@延迟=决策,..."（trace 编码）

    延迟数据落在 result 里可离线分析慢 handler；op_type 前缀 "hook:" 便于
    WebUI 按干预点过滤（见 filter 用法：op_type LIKE 'hook:%'）。
    """
    provider = client_provider or _client

    def sink(hook_point, agent_id, decision, trace) -> None:
        aid = agent_id or agent_id_default
        hp = getattr(hook_point, "value", str(hook_point))
        dec = getattr(decision, "value", str(decision))
        try:
            provider().audit_log(
                aid, f"hook:{hp}", dec, format_hook_trace(trace))
        except Exception as e:  # noqa: BLE001 — 审计失败不阻断
            logger.debug("hook trace 审计失败：%s", e)

    return sink


def register_core_handlers(registry, with_audit: bool = True) -> None:
    """把 SEC 判权 + 审计注册到 registry（幂等：重复调用先注销同名）。"""
    registry.unregister(HookPoint.PRE_TOOL_CALL, "sec_capability")
    registry.register(
        HookPoint.PRE_TOOL_CALL,
        sec_capability_handler,
        name="sec_capability",
        priority=PRI_SEC_CAPABILITY,
        # 判权 handler 自身异常/超时 = 无法证明有权限 → fail-closed（R-1/R-2）
        on_error="block",
    )
    if with_audit:
        registry.unregister(HookPoint.POST_TOOL_CALL, "audit")
        registry.register(
            HookPoint.POST_TOOL_CALL,
            audit_handler,
            name="audit",
            priority=PRI_AUDIT,
            # 纯审计 handler 不做治理决策，其故障不应改变工具调用结果
            on_error="allow",
        )
