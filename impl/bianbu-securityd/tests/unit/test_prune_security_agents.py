import importlib.util
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "deploy/prune-security-agents.py"


def load():
    spec = importlib.util.spec_from_file_location("prune_security_agents", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_plan_matches_ids_not_names_and_preserves_services():
    mod = load()
    experts = mod.expert_ids({"data": [{"id": "com.bianbu.current"}]})
    rows = [{"agent_id": aid, "name": "BibitEdgeAssistant"} for aid in
            ("com.bianbu.current", "com.bianbu.old", "com.bianbu.runtime",
             "com.bianbu.runtime.development", "com.bianbu.agent")]
    assert mod.stale_ids(rows, experts, set()) == ["com.bianbu.old"]


@pytest.mark.parametrize("payload", [{}, {"data": []}, {"data": [{}]},
                                      {"data": [{"id": ""}]}, {"data": None}])
def test_invalid_or_empty_inventory_fails_closed(payload):
    with pytest.raises(ValueError):
        load().expert_ids(payload)


def test_missing_security_registration_stops_cleanup():
    with pytest.raises(ValueError, match="未注册"):
        load().stale_ids([], {"com.bianbu.current"}, set())


@pytest.mark.parametrize("apply", [False, True])
def test_cleanup_backs_up_and_only_unregisters_stale_rows(tmp_path, monkeypatch, apply):
    import sqlite3
    import sys
    from types import SimpleNamespace
    module = load()
    db = tmp_path / "capabilities.db"
    rows = [{"agent_id": aid} for aid in ("com.bianbu.current", "com.bianbu.old")]
    with sqlite3.connect(db) as conn:
        conn.execute("CREATE TABLE agent_manifest(agent_id TEXT)")
        conn.executemany("INSERT INTO agent_manifest VALUES (?)", [(r["agent_id"],) for r in rows])
    deleted = []
    def unregister(aid):
        assert list(tmp_path.glob("security-agent-prune-*/capabilities.db"))
        deleted.append(aid)
        rows[:] = [r for r in rows if r["agent_id"] != aid]
        return True
    monkeypatch.setattr(module, "load_client", lambda: SimpleNamespace(
        list_agents=lambda: list(rows), unregister_agent=unregister))
    monkeypatch.setattr(module, "fetch_experts", lambda url: {"com.bianbu.current"})
    monkeypatch.setattr(module.os, "geteuid", lambda: 0)
    monkeypatch.setattr(sys, "argv", [str(SCRIPT), "--database", str(db)] + (["--yes"] if apply else []))
    assert module.main() == 0
    assert deleted == (["com.bianbu.old"] if apply else [])
