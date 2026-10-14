"""INT-LG-01 — BianbuSecurityToolNode：包装 ToolNode，pre_tool_call 经干预点框架判权。
INT-LG-03 — Agent 身份注册（InstallPackage + 默认能力集）。
INT-LG-05 — 审计全链路记录（含 graph_run_id）。
INT-LG-08 — WebUI 能力配置对 LangGraph 生效（SQLite WAL，无需重启）。
SEC-HOOK-04 — LangGraph 干预点挂载（BianbuInterceptorNode）。
"""
from __future__ import annotations

import logging
import os
import sys
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger("bianbu-security.langgraph")

# ─── 路径引导（client/ 目录可能不在 sys.path）──────────────────────
_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parent.parent          # impl/bianbu-securityd/
_CLIENT = _ROOT / "client"
for _p in (str(_ROOT), str(_CLIENT)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

AGENT_ID_ENV = "BIANBU_AGENT_ID"

__all__ = [
    "BianbuSecurityToolNode",
    "BianbuInterceptorNode",
    "register_agent",
    "setup_interceptor",
]


# ─── 懒加载 LangGraph（无 LangGraph 时优雅降级）────────────────────
def _check_langgraph():
    try:
        from langgraph.prebuilt import ToolNode  # noqa: F401
        return True
    except ImportError:
        return False


# ─── 客户端懒加载 ────────────────────────────────────────────────
def _client():
    import bianbu_security_client as sc
    return sc


def _fail_open() -> bool:
    return os.environ.get("BIANBU_SECURITY_FAIL_OPEN") == "1"


# ────────────────────────────────────────────────────────────────
# INT-LG-03 — Agent 身份注册
# ────────────────────────────────────────────────────────────────
_DEFAULT_MANIFEST_TOOLS = [
    # 默认工具策略集：LangGraph Agent 常用工具的基础权限。
    {"tool": "read_file",      "policy": "allow"},
    {"tool": "search_files",   "policy": "allow"},
    {"tool": "write_file",     "policy": "ask"},
    {"tool": "patch",          "policy": "ask"},
    {"tool": "terminal",       "policy": "ask"},
    {"tool": "execute_code",   "policy": "ask"},
    {"tool": "web_search",     "policy": "allow"},
    {"tool": "web_extract",    "policy": "allow"},
]


def register_agent(
    agent_id: Optional[str] = None,
    manifest_path: Optional[str] = None,
    fail_open: bool = False,
) -> bool:
    """INT-LG-03：LangGraph Agent 启动时注册身份到 bianbu-securityd。

    agent_id 可由 BIANBU_AGENT_ID 环境变量覆盖。
    无 manifest 时使用内置默认能力集。
    """
    aid = agent_id or os.environ.get(AGENT_ID_ENV) or "com.langgraph.agent"
    try:
        sc = _client()
        if manifest_path:
            result = sc.install_package(manifest_path)
            ok = result.get("ok", False)
        else:
            # 无 manifest → 直接注册默认能力集
            ok = sc.register_capabilities(aid, _DEFAULT_MANIFEST_TOOLS)
        if ok:
            logger.info("LangGraph Agent 已注册：%s", aid)
        else:
            logger.warning("LangGraph Agent 注册失败：%s", aid)
        return ok
    except Exception as e:  # noqa: BLE001
        if fail_open:
            logger.warning("注册失败（fail-open）：%s", e)
            return False
        raise


# ────────────────────────────────────────────────────────────────
# INT-LG-01 — BianbuSecurityToolNode（SEC-HOOK-04 同步完成）
# ────────────────────────────────────────────────────────────────
class BianbuSecurityToolNode:
    """包装 LangGraph ToolNode，在 _run_tool 前经干预点框架判权。

    用法：
        from securityd.langgraph.tool_node import BianbuSecurityToolNode
        tools = [search_tool, read_file_tool, ...]
        node = BianbuSecurityToolNode(tools, agent_id="com.myapp.agent")
        graph.add_node("tools", node)

    SEC-HOOK-04 通过 registry.invoke(PRE_TOOL_CALL, ...) 挂载：
    这样 DLP handler（pri=50）也会在同一调用链里执行，
    与 hermes 共享同一套治理逻辑。
    """

    def __init__(
        self,
        tools,
        agent_id: Optional[str] = None,
        registry=None,
        client_provider=None,
    ):
        if not _check_langgraph():
            raise ImportError(
                "langgraph 未安装。请 pip install langgraph 后再使用 "
                "BianbuSecurityToolNode。")

        from langgraph.prebuilt import ToolNode
        self._inner = ToolNode(tools)
        self._agent_id = (agent_id or os.environ.get(AGENT_ID_ENV)
                          or "com.langgraph.agent")
        self._registry = registry
        self._client_provider = client_provider or _client
        self._tools_by_name = {
            getattr(t, "name", getattr(t, "__name__", str(t))): t
            for t in (tools if isinstance(tools, list) else [tools])
        }

    # ── LangGraph 节点调用协议：__call__(state) ──────────────────
    def __call__(self, state) -> dict:
        """LangGraph 节点入口。处理 state["messages"] 里的 tool_call。"""
        from langchain_core.messages import AIMessage, ToolMessage

        messages = state.get("messages", [])
        if not messages:
            return state

        last = messages[-1]
        if not (isinstance(last, AIMessage) and getattr(last, "tool_calls", None)):
            return self._inner(state)  # 没有 tool call → 直接转发

        blocked = []
        confirmed_ids = set()

        for tc in last.tool_calls:
            tool_name = tc.get("name", "") if isinstance(tc, dict) else tc.name
            tool_args = tc.get("args", {}) if isinstance(tc, dict) else tc.args
            tool_call_id = (tc.get("id", "") if isinstance(tc, dict)
                            else getattr(tc, "id", ""))

            verdict = self._check(tool_name, tool_args)

            if verdict["decision"] == "BLOCK":
                blocked.append(ToolMessage(
                    content=f"[bianbu-security] 工具 {tool_name} 已被拦截：{verdict['message']}",
                    tool_call_id=tool_call_id,
                    name=tool_name,
                ))
            elif verdict["decision"] == "CONFIRM":
                # CONFIRM → 注册 pending 后触发 interrupt()。graph_id/run_id
                # 由 LangGraph Runtime 注入环境变量，WebUI 通过 broker 唤醒
                # 真正拥有 graph 实例的 Agent 进程。
                from .callbacks import langgraph_interrupt_confirm
                decision = langgraph_interrupt_confirm(
                    tool_name, verdict.get("capability", ""), self._agent_id,
                    verdict["message"], graph_id=os.environ.get("LANGGRAPH_GRAPH_ID"),
                    run_id=os.environ.get("LANGGRAPH_RUN_ID"),
                )
                if decision and str(decision).lower() in ("yes", "true", "allow", "1"):
                    confirmed_ids.add(tool_call_id)
                else:
                    blocked.append(ToolMessage(
                        content=f"[bianbu-security] 用户拒绝：{tool_name}",
                        tool_call_id=tool_call_id,
                        name=tool_name,
                    ))
            else:  # ALLOW
                confirmed_ids.add(tool_call_id)

        if not blocked:
            # 全部放行 → 交给原始 ToolNode 执行
            return self._inner(state)

        # 部分拦截：先执行放行的，再附上拦截消息
        if confirmed_ids:
            import copy
            allowed_calls = [
                tc for tc in last.tool_calls
                if (tc.get("id", "") if isinstance(tc, dict) else tc.id)
                in confirmed_ids
            ]
            patched = copy.copy(last)
            patched.tool_calls = allowed_calls
            allowed_result = self._inner({"messages": messages[:-1] + [patched]})
            result_messages = allowed_result.get("messages", [])
        else:
            result_messages = []

        return {"messages": result_messages + blocked}

    def _check(self, tool_name: str, args: dict) -> dict:
        """调 InterceptorRegistry.invoke(PRE_TOOL_CALL) 或直接 CheckPermission。"""
        # 判权维度就是工具名本身：securityd 按该 Agent 的工具策略返回
        # allow / ask / deny；未在目录中声明的工具由 securityd 按
        # unmapped 默认策略处置（默认 ask）。
        capability, scope = tool_name, ""

        # 经干预点框架（含 DLP@50 等）
        if self._registry is not None:
            from securityd.interceptor import Decision, HookPoint

            r = self._registry.invoke(
                HookPoint.PRE_TOOL_CALL,
                self._agent_id,
                {"tool": tool_name, "capability": capability,
                 "scope": scope, "args": args},
                client_provider=self._client_provider,
            )
            self._audit(tool_name, capability, scope,
                        f"registry:{r.decision.value}")
            return {
                "decision": r.decision.value,
                "message": r.message,
                "capability": capability,
                "metadata": r.metadata,
            }

        # 回退：直接 CheckPermission
        try:
            sc = self._client_provider()
            code = sc.check_permission(self._agent_id, capability, scope)
            CODES = {0: "ALLOW", 1: "CONFIRM", 2: "BLOCK"}
            decision = CODES.get(code, "BLOCK")
            self._audit(tool_name, capability, scope, decision.lower())
            return {
                "decision": decision,
                "message": f"工具 {capability}",
                "capability": capability,
            }
        except Exception as e:  # noqa: BLE001
            if _fail_open():
                logger.warning("securityd 不可达（fail-open）：%s", e)
                return {"decision": "ALLOW", "message": ""}
            return {"decision": "BLOCK",
                    "message": f"bianbu-securityd 不可达：{e}"}

    def _audit(self, tool: str, cap: str, scope: str, result: str) -> None:
        """INT-LG-05：写审计链，附 graph_run_id。"""
        try:
            run_id = os.environ.get("LANGGRAPH_RUN_ID", "")
            target = f"{cap}:{scope}" if cap else tool
            if run_id:
                result = f"{result}|run={run_id}"
            self._client_provider().audit_log(self._agent_id, tool, target, result)
        except Exception:  # noqa: BLE001
            pass


# ────────────────────────────────────────────────────────────────
# SEC-HOOK-04 — BianbuInterceptorNode（通用干预节点）
# ────────────────────────────────────────────────────────────────
class BianbuInterceptorNode:
    """在 LangGraph graph 任意位置插入干预点调用。

    SEC-HOOK-04：通过在 graph 的 human node 前/后、tool node 前/后、
    output 前增加此节点，实现干预点覆盖。

    用法：
        from securityd.langgraph.tool_node import BianbuInterceptorNode
        from securityd.interceptor import HookPoint

        # 在 graph 里 output 节点前插入审查
        checker = BianbuInterceptorNode(HookPoint.OUTPUT, agent_id="com.app")
        graph.add_node("dlp_output_check", checker)
        graph.add_edge("agent", "dlp_output_check")
        graph.add_edge("dlp_output_check", END)
    """

    def __init__(
        self,
        hook_point,
        agent_id: Optional[str] = None,
        registry=None,
        data_extractor=None,
        data_injector=None,
    ):
        """
        hook_point:      HookPoint 枚举值
        registry:        InterceptorRegistry（传 None 时用 global_registry）
        data_extractor:  state → data，从 graph state 提取干预数据
                         默认取 state["messages"][-1].content
        data_injector:   (state, modified_data) → new_state，把 MODIFY 结果写回 state
                         默认替换 messages[-1].content
        """
        self.hook_point = hook_point
        self._agent_id = (agent_id or os.environ.get(AGENT_ID_ENV)
                          or "com.langgraph.agent")
        self._registry = registry
        self._extract = data_extractor or _default_extract
        self._inject = data_injector or _default_inject

    def __call__(self, state) -> dict:
        from securityd.interceptor import Decision, global_registry

        reg = self._registry or global_registry
        data = self._extract(state)

        r = reg.invoke(self.hook_point, self._agent_id, data,
                       client_provider=_client)

        yolo = False
        try:
            mode = self._client_provider().get_agent_security_mode(self._agent_id)
            yolo = isinstance(mode, dict) and str(mode.get("mode", "")).lower() == "yolo"
        except Exception:
            pass
        if r.decision == Decision.BLOCK and yolo:
            return state
        if r.decision == Decision.BLOCK:
            from langgraph.types import interrupt
            result = interrupt({
                "type": "blocked",
                "hook_point": self.hook_point.value,
                "message": r.message,
            })
            if result and str(result).lower() in ("override", "allow"):
                return state  # 管理员覆盖
            return self._inject(state, f"[内容已阻止：{r.message}]")

        if r.decision == Decision.MODIFY and r.modified_data is not None:
            return self._inject(state, r.modified_data)

        return state


def _default_extract(state) -> Any:
    """默认：取 messages 最后一条的 content。"""
    msgs = state.get("messages", [])
    if not msgs:
        return ""
    last = msgs[-1]
    return getattr(last, "content", str(last))


def _default_inject(state, data) -> dict:
    """默认：替换 messages 最后一条的 content。"""
    import copy
    msgs = list(state.get("messages", []))
    if not msgs:
        return state
    patched = copy.copy(msgs[-1])
    patched.content = data if isinstance(data, str) else str(data)
    return {**state, "messages": msgs[:-1] + [patched]}


# ────────────────────────────────────────────────────────────────
# setup_interceptor：INT-LG-01~08 一键配置
# ────────────────────────────────────────────────────────────────
def setup_interceptor(
    tools=None,
    agent_id: Optional[str] = None,
    register: bool = True,
    with_dlp: bool = False,
    registry=None,
    client_provider=None,
):
    """为 LangGraph Agent 挂载完整的 bianbu-security 治理。

    返回：
      (BianbuSecurityToolNode, registry) — 替换原始 ToolNode；registry 可继续注册 handler
    """
    from securityd.interceptor import global_registry

    reg = registry or global_registry

    # 注册 SEC capability handler（pri=10）
    import bianbu_security_handlers as h
    h.register_core_handlers(reg, with_audit=True)
    reg.set_audit_sink(h.make_audit_sink(agent_id, client_provider=client_provider or _client))

    # 可选：注册 DLP handler（pri=50）
    if with_dlp:
        from securityd.dlp.handlers import register_dlp_handlers
        register_dlp_handlers(reg)

    # INT-LG-03：身份注册
    if register:
        try:
            register_agent(agent_id, fail_open=True)
        except Exception as e:  # noqa: BLE001
            logger.debug("身份注册失败：%s", e)

    # INT-LG-01：包装 ToolNode
    node = BianbuSecurityToolNode(
        tools or [],
        agent_id=agent_id,
        registry=reg,
        client_provider=client_provider or _client,
    )

    return node, reg
