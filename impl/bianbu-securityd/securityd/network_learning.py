"""Durable network observations produced by Runtime learning collectors."""
from __future__ import annotations

import ipaddress
import math
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping

from . import config


_SCHEMA = """
CREATE TABLE IF NOT EXISTS network_learning_event (
  event_id TEXT PRIMARY KEY,
  observed_at REAL NOT NULL,
  agent_id TEXT NOT NULL,
  instance_id TEXT NOT NULL,
  lease_id TEXT NOT NULL,
  pid INTEGER NOT NULL,
  event_type TEXT NOT NULL,
  protocol TEXT NOT NULL,
  domain TEXT NOT NULL DEFAULT '',
  remote_ip TEXT NOT NULL DEFAULT '',
  remote_port INTEGER NOT NULL DEFAULT 0,
  dns_qtype TEXT NOT NULL DEFAULT '',
  outcome TEXT NOT NULL,
  errno TEXT NOT NULL DEFAULT '',
  backend TEXT NOT NULL,
  policy_version INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_network_learning_agent_time
  ON network_learning_event(agent_id, observed_at DESC);
CREATE TABLE IF NOT EXISTS network_learning_collector (
  agent_id TEXT NOT NULL,
  instance_id TEXT NOT NULL,
  lease_id TEXT NOT NULL,
  pid INTEGER NOT NULL,
  state TEXT NOT NULL,
  reason TEXT NOT NULL DEFAULT '',
  updated_at REAL NOT NULL,
  PRIMARY KEY(agent_id, instance_id)
);
"""

_GROUP_COLUMNS = (
    "agent_id", "event_type", "protocol", "domain", "remote_ip",
    "remote_port", "dns_qtype", "outcome",
)


class NetworkLearningStore:
    """Validate, retain and aggregate per-Agent learning observations."""

    def __init__(self, db_path: str | Path | None = None, *,
                 clock: Callable[[], float] = time.time,
                 retention_seconds: int = 7 * 86400,
                 max_events_per_agent: int = 5000):
        config.ensure_dirs()
        self.db_path = Path(db_path or (config.AUDIT_DIR / "network-learning.db"))
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._clock = clock
        self._retention_seconds = max(1, int(retention_seconds))
        self._max_events_per_agent = max(1, int(max_events_per_agent))
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    @staticmethod
    def _identity(identity: Mapping[str, Any]) -> dict[str, Any]:
        value = {
            "agent_id": str(identity.get("agent_id", "")).strip(),
            "instance_id": str(identity.get("instance_id", "")).strip(),
            "lease_id": str(identity.get("lease_id", "")).strip(),
            "pid": int(identity.get("pid", 0) or 0),
        }
        if (not value["agent_id"] or not value["instance_id"] or
                not value["lease_id"] or value["pid"] <= 0):
            raise ValueError("invalid network learning identity")
        return value

    @staticmethod
    def _event(event: Mapping[str, Any]) -> dict[str, Any]:
        event_id = str(event.get("event_id", "")).strip()
        if not event_id or len(event_id) > 255:
            raise ValueError("invalid event_id")
        try:
            observed_at = float(event.get("observed_at", 0))
        except (TypeError, ValueError) as exc:
            raise ValueError("invalid observed_at") from exc
        if not math.isfinite(observed_at) or observed_at <= 0:
            raise ValueError("invalid observed_at")
        event_type = str(event.get("event_type", "")).strip().lower()
        if event_type not in {"dns_query", "connect"}:
            raise ValueError("invalid event_type")
        protocol = str(event.get("protocol", "")).strip().lower()
        if protocol not in {"tcp", "udp"}:
            raise ValueError("invalid protocol")
        outcome = str(event.get("outcome", "")).strip().lower()
        if outcome not in {"success", "failed"}:
            raise ValueError("invalid outcome")
        backend = str(event.get("backend", "")).strip()
        if not backend or len(backend) > 64:
            raise ValueError("invalid backend")
        try:
            port = int(event.get("remote_port", 0) or 0)
            policy_version = int(event.get("policy_version", 0) or 0)
        except (TypeError, ValueError) as exc:
            raise ValueError("invalid remote_port or policy_version") from exc
        if port < 0 or port > 65535 or (event_type == "connect" and port == 0):
            raise ValueError("invalid remote_port")
        if policy_version < 0:
            raise ValueError("invalid policy_version")

        raw_ip = str(event.get("remote_ip", "")).strip()
        if event_type == "connect" and not raw_ip:
            raise ValueError("invalid remote_ip")
        try:
            remote_ip = str(ipaddress.ip_address(raw_ip)) if raw_ip else ""
        except ValueError as exc:
            raise ValueError("invalid remote_ip") from exc

        domain = str(event.get("domain", "")).strip().lower().rstrip(".")
        dns_qtype = str(event.get("dns_qtype", "")).strip().upper()
        if event_type == "dns_query":
            if not domain or len(domain) > 253 or any(c.isspace() for c in domain):
                raise ValueError("invalid domain")
            if not dns_qtype or len(dns_qtype) > 16:
                raise ValueError("invalid dns_qtype")
        else:
            domain = ""
            dns_qtype = ""

        return {
            "event_id": event_id,
            "observed_at": observed_at,
            "event_type": event_type,
            "protocol": protocol,
            "domain": domain,
            "remote_ip": remote_ip,
            "remote_port": port,
            "dns_qtype": dns_qtype,
            "outcome": outcome,
            "errno": str(event.get("errno", "")).strip()[:128],
            "backend": backend,
            "policy_version": policy_version,
        }

    def record(self, identity: Mapping[str, Any], event: Mapping[str, Any]) -> bool:
        owner = self._identity(identity)
        value = self._event(event)
        columns = (
            "event_id", "observed_at", "agent_id", "instance_id", "lease_id",
            "pid", "event_type", "protocol", "domain", "remote_ip",
            "remote_port", "dns_qtype", "outcome", "errno", "backend",
            "policy_version",
        )
        row = {**owner, **value}
        with self._lock, self._conn:
            cursor = self._conn.execute(
                f"INSERT OR IGNORE INTO network_learning_event ({','.join(columns)}) "
                f"VALUES ({','.join('?' for _ in columns)})",
                tuple(row[column] for column in columns),
            )
            self._prune(owner["agent_id"])
            return cursor.rowcount == 1

    def _prune(self, agent_id: str) -> None:
        cutoff = float(self._clock()) - self._retention_seconds
        self._conn.execute(
            "DELETE FROM network_learning_event WHERE observed_at<?", (cutoff,))
        self._conn.execute(
            """DELETE FROM network_learning_event
               WHERE agent_id=? AND rowid NOT IN (
                 SELECT rowid FROM network_learning_event WHERE agent_id=?
                 ORDER BY observed_at DESC, rowid DESC LIMIT ?
               )""",
            (agent_id, agent_id, self._max_events_per_agent),
        )

    def query(self, agent_id: str, *, limit: int = 100,
              cursor: int = 0) -> dict[str, Any]:
        aid = str(agent_id).strip()
        if not aid:
            raise ValueError("agent_id must not be empty")
        selected_limit = int(limit)
        selected_cursor = int(cursor)
        if selected_limit < 1 or selected_limit > 200:
            raise ValueError("limit must be between 1 and 200")
        if selected_cursor < 0:
            raise ValueError("cursor must be non-negative")
        partition = ",".join(_GROUP_COLUMNS)
        with self._lock:
            total = int(self._conn.execute(
                f"SELECT COUNT(*) FROM (SELECT 1 FROM network_learning_event "
                f"WHERE agent_id=? GROUP BY {partition})", (aid,),
            ).fetchone()[0])
            rows = self._conn.execute(
                f"""WITH ranked AS (
                       SELECT *,
                         MIN(observed_at) OVER (PARTITION BY {partition}) AS first_seen,
                         MAX(observed_at) OVER (PARTITION BY {partition}) AS last_seen,
                         COUNT(*) OVER (PARTITION BY {partition}) AS aggregate_count,
                         ROW_NUMBER() OVER (
                           PARTITION BY {partition}
                           ORDER BY observed_at DESC, rowid DESC
                         ) AS aggregate_rank
                       FROM network_learning_event WHERE agent_id=?
                     )
                     SELECT * FROM ranked WHERE aggregate_rank=1
                     ORDER BY last_seen DESC, event_id DESC LIMIT ? OFFSET ?""",
                (aid, selected_limit, selected_cursor),
            ).fetchall()
        events = []
        for source in rows:
            events.append({
                "event_id": str(source["event_id"]),
                "event_type": str(source["event_type"]),
                "protocol": str(source["protocol"]),
                "domain": str(source["domain"]),
                "remote_ip": str(source["remote_ip"]),
                "remote_port": int(source["remote_port"]),
                "dns_qtype": str(source["dns_qtype"]),
                "outcome": str(source["outcome"]),
                "errno": str(source["errno"]),
                "backend": str(source["backend"]),
                "policy_version": int(source["policy_version"]),
                "first_seen": float(source["first_seen"]),
                "last_seen": float(source["last_seen"]),
                "count": int(source["aggregate_count"]),
                "instance_id": str(source["instance_id"]),
                "lease_id": str(source["lease_id"]),
                "pid": int(source["pid"]),
            })
        consumed = selected_cursor + len(events)
        return {
            "agent_id": aid,
            "events": events,
            "total": total,
            "next_cursor": consumed if consumed < total else None,
        }

    def clear(self, agent_id: str) -> int:
        aid = str(agent_id).strip()
        if not aid:
            raise ValueError("agent_id must not be empty")
        with self._lock, self._conn:
            cursor = self._conn.execute(
                "DELETE FROM network_learning_event WHERE agent_id=?", (aid,))
            return int(cursor.rowcount)

    def report_status(self, identity: Mapping[str, Any], state: str,
                      reason: str = "") -> bool:
        owner = self._identity(identity)
        selected_state = str(state).strip().lower()
        if selected_state not in {"active", "degraded", "inactive"}:
            raise ValueError("invalid collector state")
        with self._lock, self._conn:
            self._conn.execute(
                """INSERT INTO network_learning_collector
                   (agent_id,instance_id,lease_id,pid,state,reason,updated_at)
                   VALUES(?,?,?,?,?,?,?)
                   ON CONFLICT(agent_id,instance_id) DO UPDATE SET
                     lease_id=excluded.lease_id,pid=excluded.pid,state=excluded.state,
                     reason=excluded.reason,updated_at=excluded.updated_at""",
                (owner["agent_id"], owner["instance_id"], owner["lease_id"],
                 owner["pid"], selected_state, str(reason).strip()[:1024],
                 float(self._clock())),
            )
        return True

    def status(self, agent_id: str,
               active_instance_ids: Iterable[str] | None = None) -> dict[str, Any]:
        aid = str(agent_id).strip()
        if not aid:
            raise ValueError("agent_id must not be empty")
        active = ({str(value) for value in active_instance_ids}
                  if active_instance_ids is not None else None)
        with self._lock:
            rows = [dict(row) for row in self._conn.execute(
                "SELECT * FROM network_learning_collector WHERE agent_id=?",
                (aid,),
            ).fetchall()]
        if active is None:
            active = {str(row["instance_id"]) for row in rows
                      if str(row["state"]) != "inactive"}
        if not active:
            return {"agent_id": aid, "state": "inactive", "reason": "",
                    "active_instances": 0, "reported_instances": 0,
                    "updated_at": max((float(row["updated_at"]) for row in rows),
                                      default=0.0)}
        selected = [row for row in rows if str(row["instance_id"]) in active]
        by_instance = {str(row["instance_id"]): row for row in selected}
        missing = active - by_instance.keys()
        degraded = [row for row in selected if str(row["state"]) != "active"]
        if missing:
            state = "degraded"
            reason = "采集器未报告状态"
        elif degraded:
            state = "degraded"
            reason = str(degraded[0]["reason"] or "采集器未处于 active 状态")
        else:
            state = "active"
            reason = ""
        return {
            "agent_id": aid,
            "state": state,
            "reason": reason,
            "active_instances": len(active),
            "reported_instances": len(selected),
            "updated_at": max((float(row["updated_at"]) for row in selected),
                              default=0.0),
        }

    def close(self) -> None:
        with self._lock:
            self._conn.close()


__all__ = ["NetworkLearningStore"]
