"""INT-LG-04-A — LangGraph CONFIRM 决策联动（interrupt + Command API）
INT-LG-04-B — WebUI 确认门禁对 LangGraph 生效（LangGraph graph_id + SocketIO 推送）
INT-LG-07   — 沙箱内启动 LangGraph Agent（参考 hermes_sandbox_launch.py）
"""
from __future__ import annotations

import logging
import os
import sys
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger("bianbu-security.langgraph")

_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parent.parent
_CLIENT = _ROOT / "client"
for _p in (str(_ROOT), str(_CLIENT)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

__all__ = [
    "langgraph_interrupt_confirm",
    "build_sandbox_argv",
]


# ────────────────────────────────────────────────────────────────
# INT-LG-04-A — interrupt() 封装（在 BianbuSecurityToolNode 内使用）
# ────────────────────────────────────────────────────────────────
def langgraph_interrupt_confirm(
    tool_name: str,
    capability: str,
    agent_id: str,
    message: str = "",
    allow_permanent: bool = True,
    graph_id: str | None = None,
    run_id: str | None = None,
) -> bool:
    """INT-LG-04-A：在 pre_tool_call 阶段触发 LangGraph interrupt()。

    暂停 graph 执行，把确认请求推给外部（WebUI 或人类节点）；
    等 graph.update_state(..., values={"approved": True/False}) 唤醒后返回决策。

    返回 True = 用户批准，False = 用户拒绝。
    """
    try:
        from langgraph.types import interrupt
    except ImportError:
        # 非 LangGraph 环境（如单测）默认放行
        return True

    graph_id = graph_id or os.environ.get("LANGGRAPH_GRAPH_ID", "")
    run_id = run_id or os.environ.get("LANGGRAPH_RUN_ID", "")
    published = False
    if graph_id:
        from .resume_registry import registry
        registry.publish({
            "graph_id": graph_id, "run_id": run_id, "agent_id": agent_id,
            "tool_name": tool_name, "capability": capability,
            "message": message or f"工具 {tool_name} 需能力 {capability}，请确认",
            "allow_permanent": allow_permanent,
        })
        published = True

    try:
        response = interrupt({
            "type": "bianbu_confirm",
            "tool_name": tool_name,
            "capability": capability,
            "agent_id": agent_id,
            "message": message or f"工具 {tool_name} 需能力 {capability}，请确认",
            "allow_permanent": allow_permanent,
        })
    except Exception as exc:
        # LangGraph 的正常暂停可能以 GraphInterrupt/GraphBubbleUp 异常
        # 离开节点；此时必须保留 pending，等待远端 resume。其它异常才
        # 清理 pending，避免非 graph 上下文留下幽灵请求。
        name = type(exc).__name__
        module = type(exc).__module__
        if not (name in {"GraphInterrupt", "GraphBubbleUp"}
                or module.startswith("langgraph.")):
            if published:
                registry.discard_pending(graph_id, run_id=run_id)
        raise

    if published:
        registry.discard_pending(graph_id, run_id=run_id)

    if response is None:
        return False

    if isinstance(response, dict):
        return bool(response.get("approved", False))

    return str(response).lower() in ("yes", "true", "allow", "1", "approved")


# ────────────────────────────────────────────────────────────────
# INT-LG-07 — 沙箱内启动 LangGraph Agent
# ────────────────────────────────────────────────────────────────
def build_sandbox_argv(
    agent_module: str,
    agent_args: list[str] | None = None,
    rw_dirs: list[str] | None = None,
    hermes_config: str | None = None,
    net: bool = True,
    batch: bool = False,
    quiet: bool = False,
) -> list[str]:
    """构造 bwrap 沙箱启动 LangGraph Agent 的命令行参数列表。

    参考 hermes_sandbox_launch.py 的沙箱参数构造，添加 LangGraph 专属需求：
    - Python venv 路径（若有）
    - LangGraph/langchain 包路径
    - agent_module 的工作目录

    用法：
        argv = build_sandbox_argv("myapp.agent:run", rw_dirs=["~/.myapp"])
        import subprocess; subprocess.run(argv)
    """
    from pathlib import Path as _Path
    _root = _Path(__file__).resolve().parent.parent.parent  # impl/bianbu-securityd/

    # 找 hermes_sandbox_launch.py 作为底层引擎
    launcher = _root / "hermes_plugin" / "hermes_sandbox_launch.py"
    if not launcher.exists():
        # 回退：直接拼 bwrap
        return _minimal_bwrap_argv(agent_module, agent_args or [], rw_dirs or [], net)

    argv = [sys.executable, str(launcher),
            "--agent", f"langgraph:{agent_module}"]
    for d in (rw_dirs or []):
        argv += ["--rw-dir", d]
    if hermes_config:
        argv += ["--hermes-config", hermes_config]
    if not net:
        argv.append("--no-net")
    if batch:
        argv.append("--batch")
    if quiet:
        argv.append("--quiet")
    if agent_args:
        argv.append("--")
        argv.extend(agent_args)
    return argv


def _minimal_bwrap_argv(
    agent_module: str,
    agent_args: list[str],
    rw_dirs: list[str],
    net: bool,
) -> list[str]:
    """最小化 bwrap 启动，无完整 merged-usr 处理（仅回退用）。"""
    import shutil
    bwrap = shutil.which("bwrap") or "bwrap"
    argv = [bwrap,
            "--unshare-user", "--unshare-pid", "--unshare-ipc", "--unshare-uts",
            "--cap-drop", "ALL",
            "--ro-bind", "/", "/",
            "--tmpfs", "/tmp",
            "--proc", "/proc",
            "--dev", "/dev",
            "--bind", str(Path.home()), str(Path.home()),
            ]
    for d in rw_dirs:
        expanded = os.path.expanduser(d)
        argv += ["--bind", expanded, expanded]
    if not net:
        argv.append("--unshare-net")
    argv += [sys.executable, "-m", agent_module] + agent_args
    return argv
