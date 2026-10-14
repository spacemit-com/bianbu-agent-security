"""Securityd 与 Agent Runtime 的职责边界回归测试。"""

from __future__ import annotations

import ast
import inspect
import textwrap
from types import SimpleNamespace


def test_security_service_notifies_but_never_controls_runtime():
    """Token 超限只能通知 Runtime/agent，不能由 securityd 控制其生命周期。"""
    from securityd.service import SecurityService

    tree = ast.parse(textwrap.dedent(inspect.getsource(SecurityService)))
    forbidden_members = {"Pause", "Stop", "Terminate"}
    forbidden_literals = {"io.bianbu.Runtime", *forbidden_members}

    called_members = {
        node.func.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
    }
    string_literals = {
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant) and isinstance(node.value, str)
    }

    assert called_members.isdisjoint(forbidden_members)
    assert string_literals.isdisjoint(forbidden_literals)
