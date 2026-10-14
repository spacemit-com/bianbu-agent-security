"""Audit Chain Engine（FR-SEC-06 / AUD-01~05）。

SHA-256 哈希链 + 同步事务串行化 + 导出 + 离线验证 + 按月分段。
对齐设计 §3.4 / §4.3 / §6.6。
"""
from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

from . import config
from .errors import AuditFailure

_SCHEMA = """
CREATE TABLE IF NOT EXISTS audit_record (
  seq       INTEGER PRIMARY KEY AUTOINCREMENT,
  ts        TEXT NOT NULL,
  agent_id  TEXT NOT NULL,
  op_type   TEXT NOT NULL,
  target    TEXT NOT NULL,
  result    TEXT NOT NULL,
  prev_hash TEXT NOT NULL,
  hash      TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_request (
  request_id  TEXT PRIMARY KEY,
  fingerprint TEXT NOT NULL,
  seq         INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS audit_agent_seq ON audit_record(agent_id, seq);
CREATE INDEX IF NOT EXISTS audit_hook_agent_seq ON audit_record(agent_id, seq)
  WHERE substr(op_type, 1, 5) = 'hook:';
CREATE INDEX IF NOT EXISTS audit_deny_agent_seq ON audit_record(agent_id, seq)
  WHERE instr(lower(result), 'deny') > 0;
"""

# 审计按月分片（YYYYMM.db）；"最近活动"回溯历史分片时的上限。
_ACTIVITY_SHARD_LIMIT = 6
_ACTIVITY_SHARD_NAME = re.compile(r"^\d{6}\.db$")


def compute_hash(seq: int, ts: str, agent_id: str, op_type: str,
                 target: str, result: str, prev_hash: str) -> str:
    """记录哈希：SHA256(seq‖ts‖agent_id‖op_type‖target‖result‖prev_hash)。"""
    payload = "‖".join([str(seq), ts, agent_id, op_type, target, result, prev_hash])
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def compute_request_fingerprint(agent_id: str, op_type: str,
                                target: str, result: str) -> str:
    payload = "\0".join([agent_id, op_type, target, result])
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class AuditChainEngine:
    """调用线程同步提交，用锁序列化审计写入，防并发破链。"""

    def __init__(self, db_path: Path | None = None):
        if db_path is None:
            config.AUDIT_DIR.mkdir(parents=True, exist_ok=True)
            month = datetime.now().strftime("%Y%m")
            db_path = config.AUDIT_DIR / f"{month}.db"
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn_lock = threading.RLock()
        self._state_cond = threading.Condition()
        self._active_writes = 0
        self._accepting = True
        self._closed = False
        try:
            self._conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
            self._conn.row_factory = sqlite3.Row
            self._conn.execute("PRAGMA journal_mode=WAL")
            # Multiple development securityd instances may share one audit
            # segment.  Wait briefly for the writer holding SQLite's RESERVED
            # lock instead of racing on an in-memory seq counter.
            self._conn.execute("PRAGMA busy_timeout=5000")
            self._conn.executescript(_SCHEMA)
            self._conn.commit()
            self._last_seq_value, self._last_hash_value = self._validate_storage()
        except (OSError, sqlite3.Error, ValueError) as exc:
            conn = getattr(self, "_conn", None)
            if conn is not None:
                try:
                    conn.close()
                except sqlite3.Error:
                    pass
            raise AuditFailure(f"审计数据库启动校验失败: {exc}") from exc

    def _validate_storage(self) -> tuple[int, str]:
        """启动时同时校验 SQLite 物理完整性和审计哈希链。"""
        with self._conn_lock:
            row = self._conn.execute("PRAGMA quick_check").fetchone()
            quick = str(row[0]) if row else "missing"
            if quick.lower() != "ok":
                raise ValueError(f"sqlite quick_check={quick}")
            rows = [dict(r) for r in self._conn.execute(
                "SELECT * FROM audit_record ORDER BY seq ASC").fetchall()]
            request_rows = self._conn.execute(
                """SELECT q.request_id,q.fingerprint,q.seq,
                          r.agent_id,r.op_type,r.target,r.result
                   FROM audit_request q LEFT JOIN audit_record r ON r.seq=q.seq""").fetchall()
        if not self._verify_rows(rows, contiguous=True):
            raise ValueError("audit hash chain mismatch")
        for row in request_rows:
            if row["agent_id"] is None:
                raise ValueError(f"audit request references missing seq={row['seq']}")
            expected = compute_request_fingerprint(
                row["agent_id"], row["op_type"], row["target"], row["result"])
            if expected != row["fingerprint"]:
                raise ValueError(f"audit request fingerprint mismatch: {row['request_id']}")
        if not rows:
            return 0, config.GENESIS_HASH
        return int(rows[-1]["seq"]), str(rows[-1]["hash"])

    def _last_hash(self) -> str:
        return self._last_hash_value

    def _write_record(self, agent_id: str, op_type: str, target: str,
                      result: str, request_id: str, timeout: float) -> int:
        """持锁完成单条事务；commit 成功前不推进内存链尾。"""
        acquired = self._conn_lock.acquire(timeout=max(0.0, float(timeout)))
        if not acquired:
            raise AuditFailure("审计写入超时")
        try:
            fingerprint = compute_request_fingerprint(
                agent_id, op_type, target, result)
            if request_id:
                existing = self._conn.execute(
                    "SELECT fingerprint,seq FROM audit_request WHERE request_id=?",
                    (request_id,),
                ).fetchone()
                if existing is not None:
                    if existing["fingerprint"] != fingerprint:
                        raise ValueError("audit request_id 已被不同载荷使用")
                    return int(existing["seq"])
            # _last_seq_value only serializes threads in one process.  The
            # development launcher can have multiple securityd instances
            # sharing the same SQLite file, so reserve the chain tail in a
            # database transaction as well.
            self._conn.execute("BEGIN IMMEDIATE")
            tail = self._conn.execute(
                "SELECT seq,hash FROM audit_record ORDER BY seq DESC LIMIT 1"
            ).fetchone()
            seq = int(tail["seq"]) + 1 if tail is not None else 1
            ts = datetime.now(timezone.utc).isoformat(timespec="milliseconds")
            prev = str(tail["hash"]) if tail is not None else config.GENESIS_HASH
            h = compute_hash(seq, ts, agent_id, op_type, target, result, prev)
            self._conn.execute(
                """INSERT INTO audit_record(seq,ts,agent_id,op_type,target,result,prev_hash,hash)
                   VALUES(?,?,?,?,?,?,?,?)""",
                (seq, ts, agent_id, op_type, target, result, prev, h),
            )
            if request_id:
                self._conn.execute(
                    "INSERT INTO audit_request(request_id,fingerprint,seq) VALUES(?,?,?)",
                    (request_id, fingerprint, seq),
                )
            self._conn.commit()
            self._last_seq_value = seq
            self._last_hash_value = h
            return seq
        except Exception:
            try:
                self._conn.rollback()
            except sqlite3.Error:
                pass
            raise
        finally:
            self._conn_lock.release()

    def _next_seq(self) -> int:
        return self._last_seq_value + 1

    def log(self, agent_id: str, op_type: str, target: str, result: str,
            timeout: float = 5.0, request_id: str = "") -> int:
        """写审计记录，返回 seq。写失败抛 AuditFailure（Fail-Closed 由调用方处理）。"""
        request_id = str(request_id or "")
        if len(request_id) > 256:
            raise AuditFailure("审计 request_id 超过 256 字符")
        with self._state_cond:
            if not self._accepting:
                raise AuditFailure("审计引擎已关闭，拒绝未记录操作")
            self._active_writes += 1
        try:
            return self._write_record(
                agent_id, op_type, target, result, request_id, timeout)
        except AuditFailure:
            raise
        except Exception as exc:  # noqa: BLE001 — 审计失败必须转为 Fail-Closed
            raise AuditFailure(f"审计写入失败: {exc}") from exc
        finally:
            with self._state_cond:
                self._active_writes -= 1
                if self._active_writes == 0:
                    self._state_cond.notify_all()

    def query(self, query_json: str) -> dict:
        """Read a bounded newest-first page without exporting or verifying the chain.

        cursor is an exclusive seq upper bound; snapshot_seq freezes the first
        page's high-water mark so appends do not shift subsequent/previous pages.
        The read-only connection never takes the audit writer's Python lock.
        """
        query = json.loads(query_json)
        if not isinstance(query, dict):
            raise ValueError("audit query must be an object")

        def integer(name, default, maximum):
            value = query.get(name, default)
            if type(value) is not int or not 0 <= value <= maximum:
                raise ValueError(f"invalid audit {name}")
            return value

        limit = integer("limit", 100, 200)
        if not limit:
            raise ValueError("audit limit must be positive")
        cursor = integer("cursor", 0, 2**63 - 1)
        snapshot = query.get("snapshot_seq")
        if snapshot is not None:
            snapshot = integer("snapshot_seq", 0, 2**63 - 1)
        kind = query.get("filter", "all")
        if kind not in ("all", "hook", "deny"):
            raise ValueError("invalid audit filter")
        clauses = ["seq <= ?"]
        params = []
        for name, column, operator in (("agent_id", "agent_id", "="),
                                       ("from", "ts", ">="), ("to", "ts", "<=")):
            value = query.get(name, "")
            if not isinstance(value, str):
                raise ValueError(f"invalid audit {name}")
            if value:
                clauses.append(f"{column} {operator} ?")
                params.append(value)
        if kind == "hook":
            clauses.append("substr(op_type, 1, 5) = 'hook:'")
        elif kind == "deny":
            clauses.append("instr(lower(result), 'deny') > 0")
        conn = sqlite3.connect(self.db_path.resolve().as_uri() + "?mode=ro", uri=True,
                               timeout=1.0)
        try:
            conn.row_factory = sqlite3.Row
            conn.execute("BEGIN")
            if snapshot is None:
                snapshot = conn.execute("SELECT coalesce(max(seq), 0) FROM audit_record").fetchone()[0]
            # One bound lets SQLite seek directly to the page. With both
            # seq <= snapshot and seq < cursor it may seek to snapshot and
            # scan all intervening entries before applying cursor.
            upper = min(snapshot, cursor - 1) if cursor else snapshot
            sql = ("SELECT seq,ts,agent_id,op_type,target,result FROM audit_record WHERE "
                   + " AND ".join(clauses) + " ORDER BY seq DESC LIMIT ?")
            rows = [dict(row) for row in conn.execute(sql, [upper, *params, limit + 1])]
        finally:
            conn.close()
        has_more = len(rows) > limit
        records = rows[:limit]
        return {"records": records, "snapshot_seq": snapshot, "has_more": has_more,
                "next_cursor": records[-1]["seq"] if has_more else None}

    def activity_index(self, agent_ids) -> dict[str, str]:
        """返回每个 Agent 最近一条审计记录的时间戳。

        WebUI 的「最近活动」用它表示"该 Agent 最近一次产生安全动作"。
        审计按月分片，所以从当前分片起向历史分片回溯，最多读
        ``_ACTIVITY_SHARD_LIMIT`` 个分片，某个 Agent 命中后不再回看更早的分片。
        只读连接不与写入方争锁；任一分片读取失败都跳过该分片，由调用方
        降级到绑定/安装时间等其它活动证据。
        """
        pending = [aid for aid in dict.fromkeys(
            str(agent_id or "").strip() for agent_id in agent_ids) if aid]
        found: dict[str, str] = {}
        if not pending:
            return found
        for path in self._activity_shards()[:_ACTIVITY_SHARD_LIMIT]:
            if not pending:
                break
            try:
                conn = sqlite3.connect(path.resolve().as_uri() + "?mode=ro",
                                       uri=True, timeout=1.0)
            except (OSError, sqlite3.Error):
                continue
            try:
                conn.row_factory = sqlite3.Row
                for agent_id in list(pending):
                    row = conn.execute(
                        "SELECT ts FROM audit_record WHERE agent_id=?"
                        " ORDER BY seq DESC LIMIT 1", (agent_id,)).fetchone()
                    if row is not None and row["ts"]:
                        found[agent_id] = str(row["ts"])
                        pending.remove(agent_id)
            except sqlite3.Error:
                continue
            finally:
                conn.close()
        return found

    def _activity_shards(self) -> list[Path]:
        """审计分片文件列表，当前写入的分片排在最前。"""
        shards = [self.db_path]
        try:
            candidates = sorted(
                (path for path in self.db_path.parent.iterdir()
                 if path.is_file() and _ACTIVITY_SHARD_NAME.match(path.name)),
                key=lambda path: path.name, reverse=True)
        except OSError:
            return shards
        shards.extend(path for path in candidates if path != self.db_path)
        return shards

    # —— 导出（AUD-03）——
    def export(self, filter_json: str, fmt: str = "json") -> str:
        try:
            filt = json.loads(filter_json) if filter_json else {}
        except json.JSONDecodeError:
            filt = {}
        sql = "SELECT * FROM audit_record WHERE 1=1"
        params: list = []
        if filt.get("agent_id"):
            sql += " AND agent_id=?"
            params.append(filt["agent_id"])
        if filt.get("from"):
            sql += " AND ts>=?"
            params.append(filt["from"])
        if filt.get("to"):
            sql += " AND ts<=?"
            params.append(filt["to"])
        sql += " ORDER BY seq ASC"
        with self._conn_lock:
            rows = [dict(r) for r in self._conn.execute(sql, params).fetchall()]

        ts = int(time.time())
        out_dir = config.AUDIT_DIR / "exports"
        out_dir.mkdir(parents=True, exist_ok=True)
        anchor = rows[-1]["hash"] if rows else config.GENESIS_HASH

        if fmt == "csv":
            path = out_dir / f"audit_export_{ts}.csv"
            import csv
            with path.open("w", newline="") as f:
                w = csv.writer(f)
                w.writerow(["seq", "ts", "agent_id", "op_type", "target", "result", "prev_hash", "hash"])
                for r in rows:
                    w.writerow([r[k] for k in ("seq", "ts", "agent_id", "op_type", "target", "result", "prev_hash", "hash")])
                w.writerow(["#chain_anchor", anchor])
        else:
            path = out_dir / f"audit_export_{ts}.json"
            path.write_text(json.dumps({"records": rows, "chain_anchor": anchor}, ensure_ascii=False, indent=2))
        return str(path)

    # —— 验证（AUD-04）——
    @staticmethod
    def verify_export(export_path: str) -> bool:
        """离线验证导出文件哈希链完整性。任一处不符返回 False。"""
        p = Path(export_path)
        if not p.exists():
            return False
        if p.suffix == ".csv":
            import csv
            with p.open() as f:
                rows = [r for r in csv.DictReader(f) if r.get("seq") and not str(r["seq"]).startswith("#")]
        else:
            data = json.loads(p.read_text())
            rows = data.get("records", [])
        return AuditChainEngine._verify_rows(rows)

    @staticmethod
    def _verify_rows(rows: list[dict], contiguous: bool = False) -> bool:
        """校验记录哈希链。

        - 每条 hash 必须等于 compute_hash(该条字段, 该条 prev_hash)：防单条内容篡改。
        - contiguous=True（全量/连续链，如 verify_live）：额外要求 prev_hash 首尾相连，
          首条须接 GENESIS，防删除/重排/截断。
        - contiguous=False（按 agent_id 等过滤导出的子集）：链是全局单链，过滤后
          prev_hash 天然不相邻，只做逐条自洽校验（篡改任一字段仍可检出）。
        """
        prev = config.GENESIS_HASH
        for r in rows:
            seq = int(r["seq"])
            expect = compute_hash(seq, r["ts"], r["agent_id"], r["op_type"],
                                  r["target"], r["result"], r["prev_hash"])
            if expect != r["hash"]:
                return False
            if contiguous and r["prev_hash"] != prev:
                return False
            prev = r["hash"]
        return True

    def verify_live(self) -> bool:
        with self._conn_lock:
            rows = [dict(r) for r in self._conn.execute(
                "SELECT * FROM audit_record ORDER BY seq ASC").fetchall()]
        return self._verify_rows(rows, contiguous=True)

    def close(self) -> None:
        deadline = time.monotonic() + 2.0
        with self._state_cond:
            if self._closed:
                return
            self._accepting = False
            while self._active_writes:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise AuditFailure(
                        "审计同步写入关闭超时，拒绝在未排空状态退出")
                self._state_cond.wait(remaining)
            self._closed = True
        with self._conn_lock:
            self._conn.close()
