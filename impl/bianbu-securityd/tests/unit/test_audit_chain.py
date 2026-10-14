"""TC-UNIT-12~13：审计哈希链完整性 + 篡改检测。"""
from __future__ import annotations

import json
import threading
import time

import pytest


def test_chain_integrity(sec_root):  # TC-UNIT-12
    from securityd.audit_chain import AuditChainEngine
    au = AuditChainEngine()
    for i in range(10):
        au.log("com.test", "check_permission", f"cap{i}", "allow")
    assert au.verify_live() is True
    path = au.export('{"agent_id":"com.test"}', "json")
    assert AuditChainEngine.verify_export(path) is True
    au.close()


def test_tamper_detected(sec_root):  # TC-UNIT-13
    from securityd.audit_chain import AuditChainEngine
    au = AuditChainEngine()
    for i in range(10):
        au.log("com.test", "op", f"t{i}", "allow")
    path = au.export("{}", "json")
    data = json.loads(open(path).read())
    data["records"][4]["result"] = "deny"  # 篡改第 5 条
    json.dump(data, open(path, "w"))
    assert AuditChainEngine.verify_export(path) is False
    au.close()


def test_csv_export_verify(sec_root):
    from securityd.audit_chain import AuditChainEngine
    au = AuditChainEngine()
    for i in range(5):
        au.log("com.test", "op", f"t{i}", "allow")
    cpath = au.export("{}", "csv")
    assert AuditChainEngine.verify_export(cpath) is True
    au.close()


def test_hash_formula(sec_root):
    from securityd.audit_chain import compute_hash
    import hashlib
    h = compute_hash(1, "2026-07-14T00:00:00.000+00:00", "a", "op", "t", "allow", "GENESIS")
    payload = "‖".join(["1", "2026-07-14T00:00:00.000+00:00", "a", "op", "t", "allow", "GENESIS"])
    assert h == hashlib.sha256(payload.encode()).hexdigest()


def test_chain_recovers_after_engine_restart(sec_root):
    """WAL 数据库重开后继续接链，不能回到 genesis 或丢失记录。"""
    from securityd.audit_chain import AuditChainEngine
    from securityd import config
    path = config.AUDIT_DIR / "restart.db"
    au = AuditChainEngine(path)
    au.log("com.test", "before_restart", "x", "allow")
    assert au.verify_live()
    au.close()
    au2 = AuditChainEngine(path)
    seq = au2.log("com.test", "after_restart", "y", "allow")
    assert seq == 2 and au2.verify_live()
    au2.close()


def test_concurrent_engine_instances_allocate_unique_contiguous_sequences(tmp_path):
    """多个 securityd 实例共享审计库时，seq 分配必须由 SQLite 串行化。"""
    from securityd.audit_chain import AuditChainEngine

    path = tmp_path / "concurrent.db"
    engines = [AuditChainEngine(path), AuditChainEngine(path)]
    results: list[int] = []
    errors: list[Exception] = []
    lock = threading.Lock()

    def invoke(engine: AuditChainEngine, index: int) -> None:
        try:
            seq = engine.log("com.test", "concurrent", str(index), "allow")
            with lock:
                results.append(seq)
        except Exception as exc:  # pragma: no cover - failure shown by assertions
            with lock:
                errors.append(exc)

    threads = [threading.Thread(target=invoke, args=(engines[i % 2], i))
               for i in range(20)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=5)

    assert errors == []
    assert sorted(results) == list(range(1, 21))
    verifier = AuditChainEngine(path)
    assert verifier.verify_live() is True
    verifier.close()
    for engine in engines:
        engine.close()


def test_corrupt_audit_database_fails_closed_on_start(tmp_path):
    from securityd.audit_chain import AuditChainEngine
    from securityd.errors import AuditFailure

    path = tmp_path / "corrupt.db"
    path.write_bytes(b"not-a-sqlite-database")
    with pytest.raises(AuditFailure, match="启动校验失败"):
        AuditChainEngine(path)


def test_tampered_live_chain_fails_closed_on_restart(tmp_path):
    import sqlite3
    from securityd.audit_chain import AuditChainEngine
    from securityd.errors import AuditFailure

    path = tmp_path / "tampered.db"
    au = AuditChainEngine(path)
    au.log("com.test", "op", "target", "allow")
    au.close()
    conn = sqlite3.connect(path)
    conn.execute("UPDATE audit_record SET result='deny' WHERE seq=1")
    conn.commit()
    conn.close()

    with pytest.raises(AuditFailure, match="hash chain mismatch"):
        AuditChainEngine(path)


def test_close_drains_all_accepted_audit_requests(tmp_path):
    from securityd.audit_chain import AuditChainEngine
    from securityd.errors import AuditFailure

    path = tmp_path / "drain.db"
    au = AuditChainEngine(path)
    original_write = au._write_record
    release = threading.Event()
    entered = threading.Condition()
    entered_count = 0

    def blocked_write(*args, **kwargs):
        nonlocal entered_count
        with entered:
            entered_count += 1
            entered.notify_all()
        assert release.wait(timeout=2)
        return original_write(*args, **kwargs)

    au._write_record = blocked_write
    results = []
    errors = []

    def invoke(i):
        try:
            results.append(au.log("com.test", "queued", str(i), "allow"))
        except Exception as exc:  # pragma: no cover - 失败时供断言展示
            errors.append(exc)

    writers = []
    for i in range(20):
        writer = threading.Thread(target=invoke, args=(i,))
        writer.start()
        writers.append(writer)
    deadline = time.monotonic() + 2
    with entered:
        while entered_count < 20 and time.monotonic() < deadline:
            entered.wait(deadline - time.monotonic())
    assert entered_count == 20

    close_errors = []

    def close_engine():
        try:
            au.close()
        except Exception as exc:  # pragma: no cover - 失败时供断言展示
            close_errors.append(exc)

    closer = threading.Thread(target=close_engine)
    closer.start()
    time.sleep(0.05)
    assert closer.is_alive()
    release.set()
    for writer in writers:
        writer.join(timeout=2)
    closer.join(timeout=2)

    assert not closer.is_alive()
    assert close_errors == []
    assert errors == []
    assert sorted(results) == list(range(1, 21))
    with pytest.raises(AuditFailure, match="已关闭"):
        au.log("com.test", "late", "x", "deny")
    reopened = AuditChainEngine(path)
    assert reopened._next_seq() == 21
    assert reopened.verify_live() is True
    reopened.close()


def test_audit_request_id_is_idempotent_across_restart(tmp_path):
    from securityd.audit_chain import AuditChainEngine
    from securityd.errors import AuditFailure

    path = tmp_path / "idempotent.db"
    au = AuditChainEngine(path)
    first = au.log("com.test", "batch", "count=1", "payload",
                   request_id="request-1")
    second = au.log("com.test", "batch", "count=1", "payload",
                    request_id="request-1")
    assert first == second == 1
    with pytest.raises(AuditFailure, match="不同载荷"):
        au.log("com.test", "batch", "count=1", "changed",
               request_id="request-1")
    au.close()

    reopened = AuditChainEngine(path)
    assert reopened.log("com.test", "batch", "count=1", "payload",
                        request_id="request-1") == 1
    assert reopened._next_seq() == 2
    reopened.close()


def test_tampered_audit_request_index_fails_closed(tmp_path):
    import sqlite3
    from securityd.audit_chain import AuditChainEngine
    from securityd.errors import AuditFailure

    path = tmp_path / "request-index.db"
    au = AuditChainEngine(path)
    au.log("com.test", "batch", "count=1", "payload", request_id="request-1")
    au.close()
    conn = sqlite3.connect(path)
    conn.execute("UPDATE audit_request SET fingerprint='tampered'")
    conn.commit()
    conn.close()
    with pytest.raises(AuditFailure, match="request fingerprint mismatch"):
        AuditChainEngine(path)


def test_sqlite_full_fails_closed_and_connection_recovers(tmp_path):
    """用 SQLite max_page_count 注入真实 SQLITE_FULL，不靠 mock commit。"""
    from securityd.audit_chain import AuditChainEngine
    from securityd.errors import AuditFailure

    path = tmp_path / "full.db"
    au = AuditChainEngine(path)
    with au._conn_lock:
        pages = int(au._conn.execute("PRAGMA page_count").fetchone()[0])
        au._conn.execute(f"PRAGMA max_page_count={pages}")
    with pytest.raises(AuditFailure, match="database or disk is full"):
        au.log("com.test", "large", "payload", "x" * (2 * 1024 * 1024))
    # 放开上限后必须能继续写，证明失败事务已 rollback，连接未中毒。
    with au._conn_lock:
        au._conn.execute("PRAGMA max_page_count=1073741823")
    assert au.log("com.test", "recovered", "payload", "ok") == 1
    assert au.verify_live() is True
    au.close()


def test_readonly_connection_fails_closed_and_recovers(tmp_path):
    """query_only 注入运行中只读故障，验证请求不被当成已审计成功。"""
    from securityd.audit_chain import AuditChainEngine
    from securityd.errors import AuditFailure

    au = AuditChainEngine(tmp_path / "readonly.db")
    with au._conn_lock:
        au._conn.execute("PRAGMA query_only=ON")
    with pytest.raises(AuditFailure, match="readonly"):
        au.log("com.test", "write", "target", "deny")
    with au._conn_lock:
        au._conn.execute("PRAGMA query_only=OFF")
    assert au.log("com.test", "recovered", "target", "ok") == 1
    assert au.verify_live() is True
    au.close()
