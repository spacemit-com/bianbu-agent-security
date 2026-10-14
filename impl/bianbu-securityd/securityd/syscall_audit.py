"""Independent syscall interception audit chain with runtime identity."""
from __future__ import annotations
import hashlib, json, sqlite3, shutil, time, threading
from .kernel_syscall_audit import kernel_observer_status
from datetime import datetime, timezone
from pathlib import Path
from . import config

COLLECTOR_STATUS_DIR = Path("/run/bianbu/syscall-audit")

class SyscallAuditStore:
    def __init__(self, db_path: Path | None = None):
        self._lock = threading.RLock()
        config.ensure_dirs()
        self.db_path = Path(db_path or (config.AUDIT_DIR / "syscall-events.db"))
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("CREATE TABLE IF NOT EXISTS syscall_event (seq INTEGER PRIMARY KEY, ts TEXT, event_id TEXT NOT NULL DEFAULT '', agent_id TEXT, worker_agent_id TEXT NOT NULL DEFAULT '', instance_id TEXT NOT NULL DEFAULT '', lease_id TEXT NOT NULL DEFAULT '', pid INTEGER, cgroup_id INTEGER NOT NULL DEFAULT 0, arch TEXT, syscall TEXT, number INTEGER, action TEXT, backend TEXT, policy_version INTEGER, prev_hash TEXT, hash TEXT)")
        existing = {str(r[1]) for r in self.conn.execute("PRAGMA table_info(syscall_event)")}
        for name, typ in (("event_id", "TEXT NOT NULL DEFAULT ''"), ("worker_agent_id", "TEXT NOT NULL DEFAULT ''"), ("instance_id", "TEXT NOT NULL DEFAULT ''"), ("lease_id", "TEXT NOT NULL DEFAULT ''"), ("cgroup_id", "INTEGER NOT NULL DEFAULT 0")):
            if name not in existing:
                self.conn.execute(f"ALTER TABLE syscall_event ADD COLUMN {name} {typ}")
        self.conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_syscall_event_event_id ON syscall_event(event_id) WHERE event_id <> ''")
        self.conn.commit()

    def record(self, agent_id, pid, arch, syscall, number, backend, policy_version,
               *, worker_agent_id="", instance_id="", lease_id="", cgroup_id=0, event_id=""):
        with self._lock:
            if not str(agent_id).strip() or int(pid) <= 0:
                raise ValueError("invalid syscall audit identity")
            event_id = str(event_id or "")
            if event_id:
                old = self.conn.execute("SELECT seq,hash,backend FROM syscall_event WHERE event_id=?", (event_id,)).fetchone()
                if old:
                    return {"seq": int(old[0]), "hash": str(old[1]), "backend": str(old[2]), "duplicate": True}
            row = self.conn.execute("SELECT seq,hash FROM syscall_event ORDER BY seq DESC LIMIT 1").fetchone()
            seq = int(row[0]) + 1 if row else 1
            prev = str(row[1]) if row else "GENESIS"
            ts = datetime.now(timezone.utc).isoformat(timespec="milliseconds")
            display_agent = str(worker_agent_id or agent_id)
            values = (seq, ts, event_id, str(agent_id), display_agent, str(instance_id), str(lease_id), int(pid), int(cgroup_id), str(arch), str(syscall), int(number), "deny", str(backend), int(policy_version), prev)
            payload_values = (seq, ts, event_id, str(agent_id), str(instance_id), str(lease_id), int(pid), int(cgroup_id), str(arch), str(syscall), int(number), "deny", str(backend), int(policy_version), prev)
            payload = "|".join(map(str, payload_values))
            digest = hashlib.sha256(payload.encode()).hexdigest()
            self.conn.execute("INSERT INTO syscall_event (seq,ts,event_id,agent_id,worker_agent_id,instance_id,lease_id,pid,cgroup_id,arch,syscall,number,action,backend,policy_version,prev_hash,hash) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", values + (digest,))
            self.conn.commit()
            return {"seq": seq, "hash": digest, "backend": str(backend), "duplicate": False}

    def query(self, *, agent_id="", instance_id="", limit=100, cursor=0):
        clauses, args = [], []
        # agent_id 是经 lease 认证的安全主体（如 com.bianbu.runtime），
        # worker_agent_id 是用户面的逻辑 Agent；两者任一匹配都返回。
        if agent_id: clauses.append("(agent_id=? OR worker_agent_id=?)"); args.extend([str(agent_id)] * 2)
        if instance_id: clauses.append("instance_id=?"); args.append(str(instance_id))
        if cursor: clauses.append("seq<?"); args.append(int(cursor))
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        rows = self.conn.execute(f"SELECT * FROM syscall_event{where} ORDER BY seq DESC LIMIT ?", (*args, max(1, min(int(limit), 1000)))).fetchall()
        return [dict(r) for r in rows]

    def latest_seen(self, agent_ids) -> dict[str, str]:
        """返回每个 Agent 最近一条系统调用拦截事件的时间戳。

        `agent_id` 是经 lease 认证的安全主体，`worker_agent_id` 是用户面的
        逻辑 Agent；两者任一匹配都算该 Agent 的活动。
        """
        found: dict[str, str] = {}
        ids = [aid for aid in dict.fromkeys(
            str(agent_id or "").strip() for agent_id in agent_ids) if aid]
        if not ids:
            return found
        with self._lock:
            for agent_id in ids:
                row = self.conn.execute(
                    "SELECT ts FROM syscall_event WHERE agent_id=? OR worker_agent_id=?"
                    " ORDER BY seq DESC LIMIT 1", (agent_id, agent_id)).fetchone()
                if row is not None and row["ts"]:
                    found[agent_id] = str(row["ts"])
        return found

    def verify(self):
        prev = "GENESIS"
        for row in self.conn.execute("SELECT * FROM syscall_event ORDER BY seq"):
            # Keep the original chain payload stable for backwards compatibility;
            # worker_agent_id is a display/lookup alias, while agent_id remains
            # the authenticated lease identity.
            payload = "|".join(map(str, tuple(row[k] for k in ("seq","ts","event_id","agent_id","instance_id","lease_id","pid","cgroup_id","arch","syscall","number","action","backend","policy_version")) + (prev,)))
            if row["prev_hash"] != prev or row["hash"] != hashlib.sha256(payload.encode()).hexdigest(): return False
            prev = row["hash"]
        return True

    def status(self, running_instances=None):
        """采集状态；`running_instances` 为 lease DB 中 running 实例的 attestation 列表。

        内核观测器只能看到带 SECCOMP_FILTER_FLAG_LOG 的过滤器；若有运行中实例未
        声明 kernel_seccomp_log，则阻断仍生效但拦截事件不会入链，状态必须降为
        degraded 并说明原因，而不是继续宣称 active（验收缺陷 D-3）。
        """
        observers = []
        for path in COLLECTOR_STATUS_DIR.glob("*.json"):
            try:
                row = json.loads(path.read_text())
                age = time.time() - float(row["updated_at"])
                pid = int(row["pid"])
                if 0 <= age <= 10 and pid > 0 and Path(f"/proc/{pid}").exists():
                    observers.append(row)
            except (OSError, ValueError, KeyError, TypeError):
                continue
        active = [row for row in observers if row.get("status") == "active"]
        kernel = kernel_observer_status()
        if kernel:
            active.append(kernel)
        count = int(self.conn.execute("SELECT COUNT(*) FROM syscall_event").fetchone()[0])
        unlogged = []
        for row in list(running_instances or []):
            try:
                att = json.loads(str(row.get("attestation_json") or "{}"))
            except (TypeError, ValueError):
                att = {}
            if str(att.get("kernel_seccomp_log", "")).lower() not in {"true", "1"}:
                unlogged.append(str(row.get("instance_id", "")))
        if kernel and unlogged:
            return {"status": "degraded", "backend": "ebpf-seccomp",
                    "coverage": "deny-only(logged-instances-only)", "events": count,
                    "chain_valid": self.verify(), "collectors": len(active),
                    "unlogged_instances": unlogged,
                    "reason": (f"{len(unlogged)} running instance(s) load seccomp without "
                               "SECCOMP_FILTER_FLAG_LOG; their denials are enforced but not audited")}
        return {"status": "active" if kernel else ("degraded" if active else "unavailable"),
                "backend": "ebpf-seccomp" if kernel else ("auditd-seccomp" if active else "none"),
                "coverage": "deny-only" if kernel else ("live-process-only" if active else "none"), "events": count,
                "chain_valid": self.verify(), "collectors": len(active),
                "reason": "" if kernel else ("Kernel observer unavailable; exited children may be missed" if active else "No live syscall collector with a ready kernel audit source")}

    def close(self): self.conn.close()
