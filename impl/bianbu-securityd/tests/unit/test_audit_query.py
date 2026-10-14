"""Bounded browsing must not export, verify, or block the audit writer."""
import json
import sqlite3
import threading
from types import SimpleNamespace

import pytest


@pytest.fixture
def audit(tmp_path):
    from securityd.audit_chain import AuditChainEngine
    engine = AuditChainEngine(tmp_path / "audit.db")
    yield engine
    engine.close()


def test_pages_are_complete_and_stable_while_appending(audit):
    expected = [audit.log("a", "op", str(i), "allow") for i in range(205)]
    first = audit.query('{"agent_id":"a"}')
    assert len(first["records"]) == 100
    assert first["snapshot_seq"] == 205
    assert first["next_cursor"] == 106
    audit.log("a", "op", "new", "allow")
    records = list(first["records"])
    page = first
    while page["has_more"]:
        page = audit.query(json.dumps({"agent_id": "a", "cursor": page["next_cursor"],
                                       "snapshot_seq": first["snapshot_seq"]}))
        records.extend(page["records"])
    assert [r["seq"] for r in records] == expected[::-1]
    assert page["next_cursor"] is None
    previous = audit.query(json.dumps({"agent_id": "a", "snapshot_seq": 205}))
    assert previous == first
    assert audit.query('{"agent_id":"a"}')["records"][0]["seq"] == 206
    assert "hash" not in records[0]  # list DTO excludes full-chain metadata
    assert audit.verify_live()


@pytest.mark.parametrize("kind,expected", [("all", [4, 3, 1]), ("hook", [3]), ("deny", [4, 3])])
def test_filters_are_applied_before_limit(audit, kind, expected):
    audit.log("a", "op", "1", "allow")
    audit.log("other", "hook:before_tool", "2", "DENY")
    audit.log("a", "hook:before_tool", "3", "DENY")
    audit.log("a", "op", "4", "decision=deny")
    query = {"agent_id": "a", "filter": kind, "limit": 1}
    actual = []
    while True:
        page = audit.query(json.dumps(query))
        actual.extend(row["seq"] for row in page["records"])
        if not page["has_more"]:
            break
        query.update(cursor=page["next_cursor"], snapshot_seq=page["snapshot_seq"])
    assert actual == expected
    assert audit.query(json.dumps({**query, "from": "9999"}))["records"] == []
    assert audit.query(json.dumps({**query, "to": "0000"}))["records"] == []


@pytest.mark.parametrize("query", [[], {"limit": 0}, {"limit": 201}, {"limit": True},
                                  {"cursor": -1}, {"cursor": "1"}, {"cursor": 2**63},
                                  {"snapshot_seq": -1}, {"filter": "invalid"}, {"agent_id": 42}])
def test_invalid_queries_are_rejected(audit, query):
    with pytest.raises(ValueError):
        audit.query(json.dumps(query))


def test_empty_snapshot_stays_empty_after_append(audit):
    assert audit.query('{}') == {"records": [], "snapshot_seq": 0, "has_more": False, "next_cursor": None}
    audit.log("a", "op", "new", "allow")
    assert audit.query('{"snapshot_seq":0}')["records"] == []


def test_reader_uses_independent_connection_without_export_or_verify(audit, monkeypatch):
    audit.log("a", "op", "target", "allow")
    def forbidden(*args, **kwargs):
        raise AssertionError("list browsing must not export or verify")
    monkeypatch.setattr(audit, "export", forbidden)
    monkeypatch.setattr(audit, "verify_live", forbidden)
    pages = []
    # The writer lock is held by another thread from the reader's perspective.
    with audit._conn_lock:
        thread = threading.Thread(target=lambda: pages.append(audit.query('{}')))
        thread.start()
        thread.join(timeout=2)
        finished = not thread.is_alive()
    thread.join(timeout=2)
    assert finished
    assert pages[0]["records"][0]["target"] == "target"


@pytest.mark.parametrize("kind,index,predicate", [
    ("all", "audit_agent_seq", "1=1"),
    ("hook", "audit_hook_agent_seq", "substr(op_type, 1, 5) = 'hook:'"),
    ("deny", "audit_deny_agent_seq", "instr(lower(result), 'deny') > 0"),
])
def test_queries_use_indexes(audit, kind, index, predicate):
    plan = audit._conn.execute(
        "EXPLAIN QUERY PLAN SELECT seq,ts,agent_id,op_type,target,result FROM audit_record "
        f"WHERE seq <= ? AND agent_id = ? AND {predicate} ORDER BY seq DESC LIMIT ?",
        (899, "a", 101)).fetchall()
    text = str([tuple(row) for row in plan])
    assert "SEARCH" in text and index in text
    assert "TEMP B-TREE" not in text


def test_deep_page_has_bounded_sqlite_work(audit, monkeypatch):
    # Query-only synthetic rows: no chain verification is involved in browsing.
    audit._conn.executemany(
        "INSERT INTO audit_record VALUES (?, '2026', 'a', 'op', '', 'allow', '', '')",
        ((seq,) for seq in range(1, 10001)))
    audit._conn.commit()
    connect = sqlite3.connect
    steps = 0

    def bounded_connect(*args, **kwargs):
        conn = connect(*args, **kwargs)
        def progress():
            nonlocal steps
            steps += 100
            return int(steps > 5000)
        conn.set_progress_handler(progress, 100)
        return conn

    monkeypatch.setattr(sqlite3, "connect", bounded_connect)
    page = audit.query('{"agent_id":"a","cursor":1000,"snapshot_seq":10000}')
    assert [r["seq"] for r in page["records"]] == list(range(999, 899, -1))


def test_existing_database_adds_indexes_without_changing_chain(audit):
    from securityd.audit_chain import AuditChainEngine
    audit.log("a", "hook:before_tool", "target", "DENY")
    original = tuple(audit._conn.execute("SELECT * FROM audit_record").fetchone())
    for name in ("audit_agent_seq", "audit_hook_agent_seq", "audit_deny_agent_seq"):
        audit._conn.execute(f"DROP INDEX {name}")
    other = AuditChainEngine(audit.db_path)
    try:
        assert other.verify_live()
        assert tuple(other._conn.execute("SELECT * FROM audit_record").fetchone()) == original
        assert len(other.query('{"filter":"deny"}')["records"]) == 1
        assert len(other._conn.execute("PRAGMA index_list(audit_record)").fetchall()) == 3
    finally:
        other.close()


def test_dbus_query_requires_admin_before_reading(audit):
    pytest.importorskip("dbus")
    from securityd.service import SecurityService
    service = object.__new__(SecurityService)
    service.engine = SimpleNamespace(query_audit=audit.query)
    callers = []
    service._require_admin = lambda sender: callers.append(sender)
    assert json.loads(service.QueryAudit('{}', sender=":1.7"))["records"] == []
    assert callers == [":1.7"]
    def denied(sender):
        raise PermissionError("admin required")
    service._require_admin = denied
    with pytest.raises(PermissionError):
        service.QueryAudit('{}', sender=":1.8")


def test_client_query_round_trip(monkeypatch):
    import importlib.util
    from pathlib import Path
    path = Path(__file__).resolve().parents[2] / "client" / "bianbu_security_client.py"
    spec = importlib.util.spec_from_file_location("audit_test_client", path)
    client = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(client)
    calls = []
    page = {"records": [], "snapshot_seq": 12, "has_more": False, "next_cursor": None}
    def query(value, **kwargs):
        calls.append((json.loads(value), kwargs))
        return json.dumps(page)
    monkeypatch.setattr(client, "_get_proxy", lambda: SimpleNamespace(QueryAudit=query))
    assert client.query_audit('{"limit":100}') == page
    assert calls == [({"limit": 100}, {"dbus_interface": client.SECURITY_INTERFACE})]
