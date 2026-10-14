"""一次性启动租约持久化存储。"""
from __future__ import annotations

import json
import sqlite3
import threading
import time
import uuid
from pathlib import Path
from typing import Any


class LeaseError(RuntimeError):
    """租约不存在、过期或状态错误。"""


_SCHEMA = """
CREATE TABLE IF NOT EXISTS runtime_lease (
  lease_id TEXT PRIMARY KEY,
  agent_id TEXT NOT NULL,
  policy_json TEXT NOT NULL,
  requested_mode TEXT NOT NULL,
  effective_mode TEXT NOT NULL,
  backend TEXT NOT NULL,
  sandbox_required INTEGER NOT NULL,
  issued_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  boot_id TEXT NOT NULL DEFAULT '',
  expires_monotonic REAL NOT NULL DEFAULT 0,
  state TEXT NOT NULL,
  instance_id TEXT NOT NULL DEFAULT '',
  reason TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS runtime_instance (
  instance_id TEXT PRIMARY KEY,
  lease_id TEXT NOT NULL,
  agent_id TEXT NOT NULL,
  pid INTEGER NOT NULL,
  cgroup_path TEXT NOT NULL,
  attestation_json TEXT NOT NULL,
  started_at INTEGER NOT NULL,
  state TEXT NOT NULL,
  network_policy_version INTEGER NOT NULL DEFAULT 0,
  network_policy_json TEXT NOT NULL DEFAULT '{}',
  network_apply_state TEXT NOT NULL DEFAULT 'initial',
  network_apply_reason TEXT NOT NULL DEFAULT ''
);
"""

_LEASE_COLUMNS = {
    "lease_id", "agent_id", "policy_json", "requested_mode",
    "effective_mode", "backend", "sandbox_required", "issued_at",
    "expires_at", "state", "instance_id", "reason",
    "boot_id", "expires_monotonic",
}


_BOOT_ID_PATH = Path("/proc/sys/kernel/random/boot_id")


def _boot_id() -> str:
    """本次启动的唯一标识；读不到时返回空串。"""
    try:
        return _BOOT_ID_PATH.read_text(encoding="utf-8").strip()
    except OSError:
        return ""


def _row_get(row: Any, key: str, default: Any = None) -> Any:
    """从 sqlite3.Row 或普通映射里取一列，缺列时给默认值。"""
    try:
        return row[key]
    except (KeyError, IndexError, TypeError):
        return default


class LaunchLeaseStore:
    def __init__(self, path: str | Path, *, ttl_seconds: int = 30):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.ttl_seconds = max(1, int(ttl_seconds))
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(str(self.path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        existing = {
            str(row[1]) for row in self._conn.execute("PRAGMA table_info(runtime_lease)")
        }
        self._conn.executescript(_SCHEMA)
        required = {"lease_id", "agent_id", "policy_json", "requested_mode", "effective_mode", "backend", "sandbox_required", "issued_at", "expires_at", "state", "instance_id", "reason"}
        if existing and not required.issubset(existing):
            self._conn.execute("DROP TABLE IF EXISTS runtime_lease")
            self._conn.executescript(_SCHEMA)
        # Forward-compatible migration: 过期判定改用单调时钟后新增两列，
        # 既有 issued 租约不能在升级时被丢掉。
        lease_cols = {
            str(row[1]) for row in self._conn.execute("PRAGMA table_info(runtime_lease)")
        }
        for name, ddl in {
            "boot_id": "TEXT NOT NULL DEFAULT ''",
            "expires_monotonic": "REAL NOT NULL DEFAULT 0",
        }.items():
            if name not in lease_cols:
                self._conn.execute(f"ALTER TABLE runtime_lease ADD COLUMN {name} {ddl}")
        # Forward-compatible migration: never destroy active leases.
        instance_cols = {str(row[1]) for row in self._conn.execute("PRAGMA table_info(runtime_instance)")}
        for name, ddl in {
            "audit_identity_json": "TEXT NOT NULL DEFAULT '{}'",
            "audit_ended_ns": "INTEGER NOT NULL DEFAULT 0",
            "network_policy_version": "INTEGER NOT NULL DEFAULT 0",
            "network_policy_json": "TEXT NOT NULL DEFAULT '{}'",
            "network_apply_state": "TEXT NOT NULL DEFAULT 'initial'",
            "network_apply_reason": "TEXT NOT NULL DEFAULT ''",
        }.items():
            if name not in instance_cols:
                self._conn.execute(f"ALTER TABLE runtime_instance ADD COLUMN {name} {ddl}")
        self._conn.commit()

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def issue(self, *, agent_id: str, policy: dict[str, Any],
              requested_mode: str, effective_mode: str,
              backend: str, sandbox_required: bool, reason: str = "") -> dict[str, Any]:
        now = int(time.time())
        lease_id = uuid.uuid4().hex
        expires = now + self.ttl_seconds
        # 过期以单调时钟为准：墙上时钟会被 NTP 校时前跳，冷启动实测跳变
        # 1281s，用它比较会把只过了 1.4 秒的租约判成过期。expires_at 仍按
        # 墙上时钟记录，只用于展示与回退判定。
        expires_monotonic = time.monotonic() + self.ttl_seconds
        with self._lock:
            self._conn.execute(
                """INSERT INTO runtime_lease
                (lease_id,agent_id,policy_json,
                 requested_mode,effective_mode,backend,sandbox_required,issued_at,expires_at,
                 boot_id,expires_monotonic,state,reason)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (lease_id, agent_id, json.dumps(policy, ensure_ascii=False,
                 sort_keys=True, separators=(",", ":")), requested_mode, effective_mode,
                 backend, int(sandbox_required), now, expires,
                 _boot_id(), expires_monotonic, "issued", reason),
            )
            self._conn.commit()
        return {"lease_id": lease_id, "expires_at": expires}

    def get(self, lease_id: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM runtime_lease WHERE lease_id=?", (str(lease_id),)
            ).fetchone()
        if row is None:
            return None
        value = dict(row)
        value["policy"] = json.loads(value.pop("policy_json"))
        value["sandbox_required"] = bool(value["sandbox_required"])
        return value

    def is_expired(self, row: Any) -> bool:
        """租约是否已过期。

        过期判定优先使用签发时记录的单调时钟截止点：墙上时钟前跳（NTP 首次
        校时、手工改时间）不会让仍然只有几秒的租约被判死。记录来自上一次启动
        （``boot_id`` 不同）时单调时钟没有可比性，直接按过期处理——请求这张
        租约的 Runtime 进程已经随重启消失。升级前签发、没有单调时钟的旧记录
        退回墙上时钟判定，保持 fail-closed。
        """
        expires_monotonic = float(_row_get(row, "expires_monotonic", 0) or 0)
        if expires_monotonic > 0:
            if str(_row_get(row, "boot_id", "") or "") != _boot_id():
                return True
            return time.monotonic() >= expires_monotonic
        return int(_row_get(row, "expires_at", 0) or 0) <= int(time.time())

    def _require_issued(self, lease_id: str) -> dict[str, Any]:
        row = self.get(lease_id)
        if row is None:
            raise LeaseError("lease 不存在")
        if row["state"] != "issued":
            raise LeaseError(f"lease 状态不可用：{row['state']}")
        if self.is_expired(row):
            self._set_state(lease_id, "expired", "lease expired")
            raise LeaseError("lease 已过期")
        return row

    def _set_state(self, lease_id: str, state: str, reason: str = "", instance_id: str = "") -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE runtime_lease SET state=?,reason=?,instance_id=COALESCE(NULLIF(?,''),instance_id) WHERE lease_id=?",
                (state, reason, instance_id, str(lease_id)),
            )
            self._conn.commit()

    def commit(self, lease_id: str, *, instance_id: str, pid: int,
               cgroup_path: str, attestation: dict[str, Any],
               audit_identity: dict[str, Any] | None = None) -> dict[str, Any]:
        row = self._require_issued(lease_id)
        now = int(time.time())
        monotonic_now = time.monotonic()
        with self._lock:
            # Consume the lease atomically.  Two concurrent Commit requests
            # must not both pass a preceding read/check and create two live
            # instances for a one-shot authorization.
            # 过期条件与 ``is_expired`` 保持一致：同一次启动内用单调时钟
            # 截止点，跨启动或旧记录退回墙上时钟。
            cur = self._conn.execute(
                """UPDATE runtime_lease
                   SET state='committed',instance_id=?
                   WHERE lease_id=? AND state='issued'
                     AND CASE WHEN expires_monotonic>0 AND boot_id=?
                              THEN expires_monotonic>?
                              ELSE expires_at>? END""",
                (instance_id, lease_id, _boot_id(), monotonic_now, now),
            )
            if cur.rowcount != 1:
                latest = self.get(lease_id)
                raise LeaseError(
                    f"lease 不可提交：{latest['state'] if latest else 'missing'}")
            self._conn.execute(
                """INSERT INTO runtime_instance
                (instance_id,lease_id,agent_id,pid,cgroup_path,attestation_json,started_at,state,audit_identity_json)
                VALUES(?,?,?,?,?,?,?,?,?)""",
                (instance_id, lease_id, row["agent_id"], int(pid), str(cgroup_path),
                 json.dumps(attestation, ensure_ascii=False, sort_keys=True), now, "running",
                 json.dumps(audit_identity or {}, sort_keys=True)),
            )
            self._conn.commit()
        return {"lease_id": lease_id, "instance_id": instance_id,
                "agent_id": row["agent_id"], "state": "committed"}

    def abort(self, lease_id: str, reason: str) -> None:
        row = self.get(lease_id)
        if row is None:
            raise LeaseError("lease 不存在")
        if row["state"] == "committed":
            raise LeaseError("已提交的 lease 不能 Abort")
        self._set_state(lease_id, "aborted", reason)

    def fail_commit(self, lease_id: str, reason: str) -> None:
        """Mark a consumed lease failed after a CommitStart side-effect fails."""
        row = self.get(lease_id)
        if row is None:
            raise LeaseError("lease 不存在")
        if row["state"] != "committed":
            raise LeaseError(f"lease 状态不可回滚：{row['state']}")
        with self._lock:
            self._conn.execute(
                "UPDATE runtime_lease SET state='failed',reason=? WHERE lease_id=?",
                (str(reason)[:1024], str(lease_id)),
            )
            self._conn.execute(
                "UPDATE runtime_instance SET state='failed' WHERE lease_id=? AND state='running'",
                (str(lease_id),),
            )
            self._conn.commit()

    def stop_instance(self, lease_id: str, instance_id: str, reason: str) -> dict[str, Any]:
        """Runtime 正常停止 Worker 后收敛 lease/instance 状态。

        原先只有 ``fail_commit``（failed）与 ``revoke_agent``（revoked，按 Agent
        整体撤销）两条收敛路径；正常 stop 不能用 Agent 级撤销（会误伤刚提交的
        新 Worker），于是历史实例永远停留在 ``running``（缺陷 D-9）。
        """
        with self._lock:
            row = self._conn.execute(
                "SELECT lease_id, agent_id, state FROM runtime_instance WHERE instance_id=?",
                (str(instance_id),),
            ).fetchone()
            if row is None:
                raise LeaseError("instance 不存在")
            if str(row["lease_id"]) != str(lease_id):
                raise LeaseError("lease 与 Worker 实例不匹配")
            if str(row["state"]) != "running":
                return {"lease_id": str(lease_id), "instance_id": str(instance_id),
                        "agent_id": str(row["agent_id"]), "state": str(row["state"]),
                        "changed": False}
            ended = time.monotonic_ns()
            self._conn.execute(
                "UPDATE runtime_instance SET state='stopped',audit_ended_ns=? "
                "WHERE instance_id=? AND state='running'",
                (ended, str(instance_id)),
            )
            self._conn.execute(
                "UPDATE runtime_lease SET state='stopped',reason=? "
                "WHERE lease_id=? AND state='committed'",
                (str(reason)[:1024], str(lease_id)),
            )
            self._conn.commit()
        return {"lease_id": str(lease_id), "instance_id": str(instance_id),
                "agent_id": str(row["agent_id"]), "state": "stopped", "changed": True}

    def reap_dead(self, is_alive) -> list[dict[str, Any]]:
        """启动/巡检时把进程已消失的 running 实例标记为 lost。

        ``is_alive(pid, cgroup_path) -> bool`` 由调用方注入（读取 /proc），
        便于测试。返回被标记的实例列表。
        """
        with self._lock:
            rows = self._conn.execute(
                "SELECT instance_id, lease_id, agent_id, pid, cgroup_path "
                "FROM runtime_instance WHERE state='running'").fetchall()
            lost = []
            ended = time.monotonic_ns()
            for row in rows:
                try:
                    alive = bool(is_alive(int(row["pid"] or 0), str(row["cgroup_path"] or "")))
                except Exception:
                    alive = False
                if alive:
                    continue
                self._conn.execute(
                    "UPDATE runtime_instance SET state='lost',audit_ended_ns=? WHERE instance_id=?",
                    (ended, str(row["instance_id"])))
                self._conn.execute(
                    "UPDATE runtime_lease SET state='lost',reason='worker process gone' "
                    "WHERE lease_id=? AND state='committed'",
                    (str(row["lease_id"]),))
                lost.append(dict(row))
            if lost:
                self._conn.commit()
        return lost

    def revoke_agent(self, agent_id: str, reason: str) -> int:
        with self._lock:
            cur = self._conn.execute(
                "UPDATE runtime_lease SET state='revoked',reason=? WHERE agent_id=? AND state IN ('issued','committed')",
                (reason, agent_id),
            )
            self._conn.execute(
                "UPDATE runtime_instance SET state='revoked',audit_ended_ns=? WHERE agent_id=? AND state='running'",
                (time.monotonic_ns(), agent_id),
            )
            self._conn.commit()
            return int(cur.rowcount)

    def state(self, agent_id: str) -> dict[str, Any]:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM runtime_lease WHERE agent_id=? ORDER BY issued_at DESC LIMIT 1",
                (agent_id,),
            ).fetchone()
            inst = self._conn.execute(
                "SELECT * FROM runtime_instance WHERE agent_id=? ORDER BY started_at DESC LIMIT 1",
                (agent_id,),
            ).fetchone()
        return {"lease": dict(row) if row else None,
                "instance": dict(inst) if inst else None}

    def syscall_audit_instances(self) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM runtime_instance WHERE state IN ('running','revoked') ORDER BY started_at DESC").fetchall()
        return [dict(row) for row in rows]

    def instances(self, agent_id: str) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM runtime_instance WHERE agent_id=? ORDER BY started_at DESC",
                (agent_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    def active_instances(self, agent_id: str) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT i.*, l.backend FROM runtime_instance i JOIN runtime_lease l ON l.lease_id=i.lease_id "
                "WHERE i.agent_id=? AND i.state='running' ORDER BY i.started_at DESC", (agent_id,)
            ).fetchall()
        return [dict(row) for row in rows]

    def active_instances_for_worker(self, worker_agent_id: str) -> list[dict[str, Any]]:
        selected = str(worker_agent_id).strip()
        with self._lock:
            rows = self._conn.execute(
                "SELECT i.*, l.backend, l.policy_json AS lease_policy_json "
                "FROM runtime_instance i JOIN runtime_lease l ON l.lease_id=i.lease_id "
                "WHERE i.state='running' ORDER BY i.started_at DESC"
            ).fetchall()
        result = []
        for row in rows:
            value = dict(row)
            try:
                policy = json.loads(str(value.pop("lease_policy_json", "{}")))
            except (TypeError, ValueError):
                policy = {}
            if str(policy.get("worker_agent_id", "")).strip() == selected:
                value["lease_network_policy"] = policy.get("network", {})
                result.append(value)
        return result

    def update_instance_network_policy(
        self, instance_id: str, policy: dict[str, Any], *, state: str,
        reason: str = "", network_properties: list[str] | None = None,
    ) -> None:
        with self._lock:
            row = self._conn.execute(
                "SELECT attestation_json FROM runtime_instance "
                "WHERE instance_id=? AND state='running'",
                (str(instance_id),),
            ).fetchone()
            if row is None:
                return
            try:
                attestation = json.loads(str(row["attestation_json"] or "{}"))
            except (TypeError, ValueError):
                attestation = {}
            if network_properties is not None:
                attestation["network_properties"] = [
                    str(value) for value in network_properties
                ]
            self._conn.execute(
                "UPDATE runtime_instance SET network_policy_version=?,"
                "network_policy_json=?,network_apply_state=?,network_apply_reason=?,"
                "attestation_json=? WHERE instance_id=? AND state='running'",
                (int(policy.get("version", 0)), json.dumps(policy, ensure_ascii=False, sort_keys=True),
                 str(state), str(reason)[:1024],
                 json.dumps(attestation, ensure_ascii=False, sort_keys=True),
                 str(instance_id)))
            self._conn.commit()


__all__ = ["LaunchLeaseStore", "LeaseError"]
