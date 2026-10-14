"""WebUI 新增后端接口单测（阶段1）：list_agents / set_capability_policy /
get_network_policy / get_agent_info / 安全权限设置。

均走 SecurityEngine（本地直调，不经 D-Bus），用隔离 BIANBU_SEC_ROOT。
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT))

from securityd.models import Permission  # noqa: E402


@pytest.fixture()
def engine(tmp_path, monkeypatch):
    monkeypatch.setenv("BIANBU_SEC_ROOT", str(tmp_path))
    # 重新载入 config 以生效新根
    import importlib
    import securityd.config as cfg
    importlib.reload(cfg)
    import securityd.engine as eng_mod
    importlib.reload(eng_mod)
    e = eng_mod.SecurityEngine()
    yield e
    e.close()


def _perm(tool, policy="ask"):
    return Permission.from_dict({"tool": tool, "policy": policy})


def test_list_agents_empty(engine):
    assert engine.list_agents() == []


def test_list_agents_after_register(engine):
    engine.register_capabilities("com.a", [_perm("read_file", "allow")])
    engine.register_capabilities("com.b", [_perm("write_file", "ask")])
    agents = {a["agent_id"] for a in engine.list_agents()}
    assert agents == {"com.a", "com.b"}


def test_set_capability_policy(engine):
    engine.register_capabilities("com.a", [_perm("write_file", "ask")])
    assert engine.set_capability_policy("com.a", "write_file", "deny")
    caps = {c["tool"]: c["policy"] for c in engine.get_capabilities("com.a")}
    assert caps["write_file"] == "deny"
    assert engine.set_capability_policy("com.a", "write_file", "allow")
    caps = {c["tool"]: c["policy"] for c in engine.get_capabilities("com.a")}
    assert caps["write_file"] == "allow"


def test_get_network_policy(engine):
    engine.register_capabilities("com.a", [_perm("read_file", "allow")])
    engine.set_network_policy("com.a", ["api.example.com"], "whitelist")
    pol = engine.get_network_policy("com.a")
    assert pol["mode"] in ("whitelist", "learning")
    assert pol.get("rules_path")  # 规则文件已生成
    assert "enforcement" in pol
    assert "enforced" in pol["enforcement"]


def test_get_agent_info(engine):
    engine.register_capabilities("com.a", [_perm("read_file", "allow")])
    info = engine.get_agent_info("com.a")
    assert info["agent_id"] == "com.a"
    assert len(info["capabilities"]) >= 1
    assert "permissions" in info and "network" in info
