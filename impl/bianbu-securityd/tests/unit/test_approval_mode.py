"""审批仲裁开关 BIANBU_SEC_APPROVAL_MODE 的三态行为（纯逻辑，不需 D-Bus/hermes）。

用一个假的 client 替身注入 check_permission/request_confirm，验证 pre_tool_call：
  - securityd（默认）：CONFIRM → 走 securityd.request_confirm（阻塞门禁）
  - hermes：CONFIRM → 降级放行（交回 hermes approval），不调 request_confirm
  - both：同 securityd（叠加语义由不关 hermes approval 实现）
DENY 三态一致拦截；ALLOW 一致放行。
"""
from __future__ import annotations

import importlib
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent


class _FakeClient:
    def __init__(self, decision, approved=True):
        self._decision = decision
        self._approved = approved
        self.confirm_called = False

    def check_permission(self, aid, cap, scope=""):
        return self._decision

    def request_confirm(self, aid, cap, detail, timeout=60.0):
        self.confirm_called = True
        return self._approved

    def audit_log(self, *a, **k):
        return 1


def _load_plugin(monkeypatch, mode: str, fake: _FakeClient):
    monkeypatch.setenv("BIANBU_SEC_APPROVAL_MODE", mode)
    sys.path.insert(0, str(ROOT / "hermes_plugin"))
    import bianbu_security as plugin
    importlib.reload(plugin)
    monkeypatch.setattr(plugin, "_client", lambda: fake)
    return plugin


@pytest.mark.parametrize("mode", ["securityd", "both", "hermes"])
def test_deny_always_blocks(monkeypatch, mode):
    fake = _FakeClient(decision=2)  # DENY
    plugin = _load_plugin(monkeypatch, mode, fake)
    r = plugin.pre_tool_call("terminal", {"command": "x"})
    assert r is not None and r["action"] == "block"


@pytest.mark.parametrize("mode", ["securityd", "both", "hermes"])
def test_allow_always_passes(monkeypatch, mode):
    fake = _FakeClient(decision=0)  # ALLOW
    plugin = _load_plugin(monkeypatch, mode, fake)
    assert plugin.pre_tool_call("read_file", {"path": "/tmp/x"}) is None


def test_confirm_securityd_uses_gate(monkeypatch):
    fake = _FakeClient(decision=1, approved=True)  # CONFIRM → securityd 门禁批准
    plugin = _load_plugin(monkeypatch, "securityd", fake)
    r = plugin.pre_tool_call("write_file", {"path": "~/Documents/bianbu-test/a"})
    assert r is None and fake.confirm_called is True


def test_confirm_securityd_denied_blocks(monkeypatch):
    fake = _FakeClient(decision=1, approved=False)  # CONFIRM → 门禁拒绝
    plugin = _load_plugin(monkeypatch, "securityd", fake)
    r = plugin.pre_tool_call("write_file", {"path": "~/Documents/bianbu-test/a"})
    assert r is not None and r["action"] == "block" and fake.confirm_called is True


def test_confirm_hermes_mode_delegates(monkeypatch):
    fake = _FakeClient(decision=1)  # CONFIRM
    plugin = _load_plugin(monkeypatch, "hermes", fake)
    r = plugin.pre_tool_call("write_file", {"path": "~/Documents/bianbu-test/a"})
    # hermes 模式：不调 securityd 门禁，放行交回 hermes approval
    assert r is None and fake.confirm_called is False
