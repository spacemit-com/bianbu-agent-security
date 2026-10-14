"""CLI 运行形态探测 —— 决定 CONFIRM 的确认走哪条路。

真机源码实证（worker hermes）：
  · hermes chat 是 prompt_toolkit 全屏 App，接管 stdin。插件裸 input() 会挂死
    （hermes 自身源码注释 hermes_cli/skills_hub.py:1128 "input() hangs"），且插件
    拿不到 hermes 的 cli 对象，无法复用其 TUI 审批（cli._app / cli._approval_state）。
  · 因此交互式 CLI 下不能由插件自己弹终端确认；应把 CONFIRM 交回 hermes 原生 approval
    （在它自己的 TUI 里弹 [o/s/a/d]），或改用非交互模式 + WebUI 响应。

本模块只提供形态探测，供 pre_tool_call 决策；不再做终端 input()。
"""
from __future__ import annotations

import os
import sys


def hermes_tui_approve(command: str, description: str):
    """调用 hermes 已注册的 TUI 审批回调，弹出原生
    [Allow once / session / always / Deny] 弹窗（走 cli._app prompt_toolkit）。

    返回 "once"/"session"/"always"/"deny"；拿不到回调（非 CLI 会话 / 未注册）返回 None。
    这样 bianbu 判定"需确认"的任何能力都能借 hermes TUI 弹框，不受其危险正则范围限制。
    """
    try:
        from tools import terminal_tool
    except Exception:  # noqa: BLE001 — 非 hermes 进程内
        return None
    cb = getattr(terminal_tool, "_approval_callback", None)
    if not callable(cb):
        return None
    try:
        # hermes 的 approval_callback(command, description, allow_permanent=True)
        return cb(command, description, allow_permanent=True)
    except TypeError:
        try:
            return cb(command, description)
        except Exception:  # noqa: BLE001
            return None
    except Exception:  # noqa: BLE001
        return None


def is_cli_interactive() -> bool:
    """是否处于 hermes 交互式 CLI（prompt_toolkit TUI）。

    True 时插件不应自行终端确认，应把 CONFIRM 交回 hermes 原生 approval。
    可用 BIANBU_SEC_CLI_CONFIRM=0 强制视为非交互（回退 securityd 信号路径）。
    """
    if os.environ.get("BIANBU_SEC_CLI_CONFIRM") == "0":
        return False
    if os.environ.get("HERMES_GATEWAY_SESSION"):
        return False
    if not os.environ.get("HERMES_INTERACTIVE"):
        return False
    try:
        return sys.stdin.isatty()
    except Exception:  # noqa: BLE001
        return False
