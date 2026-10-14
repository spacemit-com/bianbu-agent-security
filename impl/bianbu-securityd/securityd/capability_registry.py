"""Capability Registry（FR-SEC-01/02/03 / CAP-02~06）。

SQLite WAL 持久化 + CheckPermission 算法 + best_match_scope + session_trust。
对齐设计 §3.1 / §4.1 / §6.3。
"""
from __future__ import annotations

import json
import os
import re
import sqlite3
import threading
import tomllib
from collections.abc import Mapping
from pathlib import Path

from . import config
from .capabilities import unmapped_policy
from .models import Decision, Permission, Policy, policy_value

_SCHEMA = """
CREATE TABLE IF NOT EXISTS capability (
  agent_id   TEXT NOT NULL,
  tool       TEXT NOT NULL,
  policy     TEXT NOT NULL CHECK(policy IN ('allow','ask','deny')),
  framework  TEXT NOT NULL DEFAULT '',
  PRIMARY KEY (agent_id, tool)
);
CREATE TABLE IF NOT EXISTS session_trust (
  session_id TEXT NOT NULL,
  agent_id   TEXT NOT NULL,
  tool       TEXT NOT NULL,
  granted_at TEXT NOT NULL,
  PRIMARY KEY (session_id, agent_id, tool)
);
CREATE TABLE IF NOT EXISTS agent_manifest (
  agent_id     TEXT PRIMARY KEY,
  version      TEXT NOT NULL,
  name         TEXT NOT NULL,
  signature    TEXT NOT NULL,
  manifest_raw TEXT NOT NULL DEFAULT '',
  installed_at TEXT NOT NULL,
  status       TEXT NOT NULL DEFAULT 'active',
  framework    TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS agent_binding (
  agent_id TEXT PRIMARY KEY,
  uid INTEGER NOT NULL,
  executable TEXT NOT NULL DEFAULT '',
  cgroup TEXT NOT NULL DEFAULT '',
  session_id TEXT NOT NULL DEFAULT '',
  bound_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS agent_security_mode (
  agent_id TEXT PRIMARY KEY,
  mode TEXT NOT NULL CHECK(mode IN ('normal','yolo')),
  updated_at TEXT NOT NULL,
  updated_by TEXT NOT NULL,
  FOREIGN KEY (agent_id) REFERENCES agent_manifest(agent_id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS network_policy (
  agent_id TEXT PRIMARY KEY,
  mode TEXT NOT NULL CHECK(mode IN ('whitelist','deny_all','allow_all','learning')),
  domains_json TEXT NOT NULL DEFAULT '[]',
  version INTEGER NOT NULL DEFAULT 0,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (agent_id) REFERENCES agent_manifest(agent_id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS permission_settings (
  agent_id      TEXT NOT NULL,
  group_name    TEXT NOT NULL CHECK(group_name IN ('read','write')),
  value_json    TEXT NOT NULL DEFAULT '{"include":[],"exclude":[]}',
  updated_at    TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (agent_id, group_name),
  FOREIGN KEY (agent_id) REFERENCES agent_manifest(agent_id) ON DELETE CASCADE
);
"""


# 既有部署在升级后需要补上的列。新增列时同步登记在这里，
# 让老的 SQLite 库也能平滑升级，而不是在首次读写时报 no such column。
_ADDED_COLUMNS: dict[str, tuple[tuple[str, str], ...]] = {
    "agent_manifest": (
        ("framework", "TEXT NOT NULL DEFAULT ''"),
    ),
}


_VOLATILE_SESSION_SCOPE = re.compile(r"/session-\d+\.scope$")
_LEGACY_SYSTEM_EXE_DIRS = frozenset({"/bin", "/usr/bin", "/usr/local/bin"})
_INITIAL_NETWORK_POLICY_MODE = "allow_all"


def _stable_cgroup(value: str) -> str:
    """去掉 SSH/login session 编号，保留 systemd 服务/cgroup 归属。"""
    return "\n".join(
        _VOLATILE_SESSION_SCOPE.sub("", line.strip())
        for line in str(value or "").splitlines()
        if line.strip()
    )


def _normalise_stored_range(value: object) -> dict:
    """Coerce a stored range into ``{include, exclude}``.

    Older databases stored a bare path list under ``permission_settings``; a
    row in that shape is read as ``include`` so an upgrade does not silently
    drop an operator's declared scope.
    """
    if isinstance(value, Mapping):
        include = value.get("include")
        exclude = value.get("exclude")
    elif isinstance(value, list):
        include, exclude = value, []
    else:
        include, exclude = [], []
    return {
        "include": [str(p) for p in (include or []) if str(p).strip()],
        "exclude": [str(p) for p in (exclude or []) if str(p).strip()],
    }


def _executable_matches(expected: str, actual: str) -> bool:
    """精确匹配新身份，并兼容旧版 /proc/exe → venv argv[0] 迁移一次。"""
    expected = str(expected or "")
    actual = str(actual or "")
    if expected == actual:
        return True
    if not expected or not actual or not os.path.isabs(actual):
        return False
    # A newly created binding may retain a concrete venv path while the
    # caller's argv path is a symlink to that same venv interpreter.  Permit
    # this one-way resolution only when the *actual path* is not a system
    # interpreter path; once the binding has migrated, a system Python must
    # not match it by realpath.
    if str(Path(expected).parent) not in _LEGACY_SYSTEM_EXE_DIRS:
        if str(Path(actual).parent) in _LEGACY_SYSTEM_EXE_DIRS:
            return False
        try:
            return os.path.realpath(actual) == expected
        except OSError:
            return False
    # 旧记录是解析后的系统解释器路径；只允许它迁移到指向同一解释器的
    # 绝对 venv argv[0]。新记录保存 venv 路径后不会反向放宽到系统 Python。
    if str(Path(actual).parent) in _LEGACY_SYSTEM_EXE_DIRS:
        return False
    try:
        return os.path.realpath(actual) == expected
    except OSError:
        return False


class CapabilityRegistry:
    def __init__(self, db_path: Path | None = None):
        self.db_path = Path(db_path) if db_path else config.CAPABILITIES_DB
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.executescript(_SCHEMA)
        self._migrate_added_columns()
        self._migrate_network_policy_modes()
        self._migrate_tool_schema()
        self._conn.commit()

    def _migrate_added_columns(self) -> None:
        """给既有表补上后来新增的列。

        ``CREATE TABLE IF NOT EXISTS`` 只保证表存在，不会给已经建好的旧表
        补列；从既有部署升级时缺列会在第一次读写时抛
        ``no such column``。这里按表逐列检查，缺什么补什么，并保留
        ``NOT NULL DEFAULT``，因此旧行会落到与全新库一致的默认值。
        旧数据本身可丢弃，这里只为避免升级路径直接报错。
        """
        for table, columns in _ADDED_COLUMNS.items():
            row = self._conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
                (table,),
            ).fetchone()
            if row is None:
                continue
            existing = {
                str(r["name"])
                for r in self._conn.execute(f"PRAGMA table_info({table})")
            }
            for name, clause in columns:
                if name in existing:
                    continue
                self._conn.execute(
                    f"ALTER TABLE {table} ADD COLUMN {name} {clause}"
                )

    def _migrate_tool_schema(self) -> None:
        """把旧的 domain/risk_level/scope 能力表重建为三态工具策略表。

        ``CREATE TABLE IF NOT EXISTS`` 不会改动已存在的旧表，因此从既有部署
        升级时 ``capability``/``session_trust`` 仍保留 ``capability`` 列，
        后续 ``INSERT ... tool`` 会抛 ``no column named tool``。历史策略维度
        已废弃，直接重建为空表即可（旧声明由 Runtime 重新下发）。
        """
        stale = False
        for table in ("capability", "session_trust"):
            row = self._conn.execute(
                "SELECT sql FROM sqlite_master WHERE type='table' AND name=?",
                (table,),
            ).fetchone()
            if row is not None and "tool" not in str(row["sql"] or ""):
                stale = True
        if stale:
            self._conn.executescript(
                "DROP TABLE IF EXISTS capability;"
                "DROP TABLE IF EXISTS session_trust;"
            )
            self._conn.executescript(_SCHEMA)

    def _migrate_network_policy_modes(self) -> None:
        row = self._conn.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='network_policy'"
        ).fetchone()
        if row is None or "'allow_all'" in str(row["sql"] or ""):
            return
        self._conn.executescript(
            "ALTER TABLE network_policy RENAME TO network_policy_legacy;"
            "CREATE TABLE network_policy ("
            "agent_id TEXT PRIMARY KEY, "
            "mode TEXT NOT NULL CHECK(mode IN ('whitelist','deny_all','allow_all','learning')), "
            "domains_json TEXT NOT NULL DEFAULT '[]', "
            "version INTEGER NOT NULL DEFAULT 0, "
            "updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, "
            "FOREIGN KEY (agent_id) REFERENCES agent_manifest(agent_id) ON DELETE CASCADE);"
            "INSERT INTO network_policy(agent_id,mode,domains_json,version,updated_at) "
            "SELECT agent_id,mode,domains_json,version,updated_at FROM network_policy_legacy;"
            "DROP TABLE network_policy_legacy;"
        )

    def _ensure_initial_network_policy_locked(self, agent_id: str) -> None:
        """Materialize the safe connectivity default without replacing user policy."""
        self._conn.execute(
            "INSERT OR IGNORE INTO network_policy(agent_id,mode,domains_json,version) "
            "VALUES(?,?,?,1)",
            (str(agent_id), _INITIAL_NETWORK_POLICY_MODE, "[]"),
        )

    def _ensure_initial_security_mode_locked(self, agent_id: str) -> None:
        """New Agents start in YOLO; existing operator choices are retained."""
        self._conn.execute(
            "INSERT OR IGNORE INTO agent_security_mode(agent_id,mode,updated_at,updated_by) "
            "VALUES(?,?,datetime('now'),?)",
            (str(agent_id), "yolo", "initial-agent-default"),
        )

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def register_agent(self, agent_id: str, name: str = "", version: str = "1.0.0",
                       framework: str = "") -> dict:
        """Register or refresh a logical Agent without a signed package."""
        if agent_id is None:
            raise ValueError("agent_id must not be empty")
        agent_id = str(agent_id).strip()
        if not agent_id:
            raise ValueError("agent_id must not be empty")
        fw = str(framework or "").strip().lower()
        if fw not in ("", "runtime", "hermes"):
            raise ValueError("framework must be runtime or hermes")
        with self._lock:
            self._conn.execute(
                """INSERT INTO agent_manifest(agent_id,version,name,signature,installed_at,status,framework)
                   VALUES(?,?,?,?,datetime('now'),'active',?)
                   ON CONFLICT(agent_id) DO UPDATE SET version=excluded.version,
                     name=excluded.name,status='active',
                     framework=CASE WHEN excluded.framework='' THEN agent_manifest.framework
                                    ELSE excluded.framework END""",
                (agent_id, str(version or "1.0.0"), str(name or agent_id), "", fw),
            )
            self._ensure_initial_network_policy_locked(agent_id)
            self._ensure_initial_security_mode_locked(agent_id)
            self._conn.commit()
        return {"agent_id": agent_id, "name": str(name or agent_id),
                "version": str(version or "1.0.0"), "status": "active",
                "framework": fw}

    def get_framework(self, agent_id: str) -> str:
        """该 Agent 对接的框架（runtime / hermes）；未知返回空串。"""
        with self._lock:
            row = self._conn.execute(
                "SELECT framework FROM agent_manifest WHERE agent_id=?",
                (str(agent_id),),
            ).fetchone()
        return str(row["framework"] or "") if row is not None else ""

    def unregister_agent(self, agent_id: str) -> bool:
        with self._lock:
            self._conn.execute("DELETE FROM agent_security_mode WHERE agent_id=?", (str(agent_id),))
            cur = self._conn.execute("DELETE FROM agent_manifest WHERE agent_id=?", (str(agent_id),))
            self._conn.execute("DELETE FROM capability WHERE agent_id=?", (str(agent_id),))
            self._conn.execute("DELETE FROM agent_binding WHERE agent_id=?", (str(agent_id),))
            self._conn.execute("DELETE FROM session_trust WHERE agent_id=?", (str(agent_id),))
            self._conn.commit()
            return cur.rowcount > 0

    def get_security_mode(self, agent_id: str, *, require_registered: bool = True) -> dict:
        """Return the persisted per-Agent permission mode; absent rows are normal."""
        aid = str(agent_id or "").strip()
        if not aid:
            raise ValueError("agent_id must not be empty")
        with self._lock:
            manifest = self._conn.execute(
                "SELECT 1 FROM agent_manifest WHERE agent_id=? AND status='active'", (aid,)
            ).fetchone()
            if require_registered and manifest is None:
                raise ValueError(f"agent {aid} 未注册")
            row = self._conn.execute(
                "SELECT mode,updated_at,updated_by FROM agent_security_mode WHERE agent_id=?",
                (aid,),
            ).fetchone()
        if row is None or manifest is None:
            return {"agent_id": aid, "mode": "normal", "updated_at": "", "updated_by": ""}
        return {"agent_id": aid, **dict(row)}

    def set_security_mode(self, agent_id: str, mode: str, actor: str, ts: str) -> dict:
        aid = str(agent_id or "").strip()
        value = str(mode) if mode is not None else ""
        if value not in {"normal", "yolo"}:
            raise ValueError("mode must be normal or yolo")
        with self._lock:
            registered = self._conn.execute(
                "SELECT 1 FROM agent_manifest WHERE agent_id=? AND status='active'", (aid,)
            ).fetchone()
            if registered is None:
                raise ValueError(f"agent {aid} 未注册")
            old = self._conn.execute(
                "SELECT mode FROM agent_security_mode WHERE agent_id=?", (aid,)
            ).fetchone()
            old_mode = str(old["mode"]) if old else "normal"
            self._conn.execute(
                """INSERT INTO agent_security_mode(agent_id,mode,updated_at,updated_by)
                   VALUES(?,?,?,?)
                   ON CONFLICT(agent_id) DO UPDATE SET mode=excluded.mode,
                     updated_at=excluded.updated_at,updated_by=excluded.updated_by""",
                (aid, value, str(ts), str(actor)),
            )
            self._conn.commit()
        return {"agent_id": aid, "old_mode": old_mode, "mode": value,
                "updated_at": str(ts), "updated_by": str(actor)}

    def sync_capabilities(self, agent_id: str, perms: list[Permission]) -> bool:
        # Validate the complete replacement set before deleting anything.  A
        # malformed capability must leave the previous effective policy intact
        # so a transient bad update cannot silently turn an Agent into one with
        # no permissions (or partially apply a replacement).
        aid = str(agent_id).strip()
        if not aid:
            raise ValueError("agent_id must not be empty")
        for p in perms:
            p.validate()
        with self._lock:
            registered = self._conn.execute(
                "SELECT 1 FROM agent_manifest WHERE agent_id=? AND status='active'", (aid,)
            ).fetchone()
            if registered is None:
                raise ValueError(f"agent {aid} 未注册")
            try:
                self._conn.execute("DELETE FROM capability WHERE agent_id=?", (aid,))
                for p in perms:
                    self._conn.execute(
                        "INSERT INTO capability(agent_id,tool,policy,framework) VALUES(?,?,?,?)",
                        (aid, p.tool, policy_value(p.policy), p.framework),
                    )
                self._conn.commit()
            except Exception:
                self._conn.rollback()
                raise
        return True

    # —— 注册 / 撤销（CAP-02/05）——
    def register_capabilities(self, agent_id: str, perms: list[Permission],
                              granted: int | None = None,
                              *, preserve_existing_granted: bool = False) -> bool:
        """写入能力，覆盖更新。约束校验 L3/L4≠trusted。

        每条工具策略按自己的 policy 写入；``granted`` 仅为兼容旧调用方保留，
        新模型下策略本身就是 allow/ask/deny 三态，不再有独立的"授权态"。
        """
        with self._lock:
            for p in perms:
                p.validate()
            for p in perms:
                self._conn.execute(
                    """INSERT INTO capability(agent_id,tool,policy,framework)
                       VALUES(?,?,?,?)
                       ON CONFLICT(agent_id,tool) DO UPDATE SET
                         policy=CASE WHEN ? THEN capability.policy
                                     ELSE excluded.policy END,
                         framework=excluded.framework""",
                    (agent_id, p.tool, policy_value(p.policy), p.framework,
                     1 if preserve_existing_granted else 0),
                )
            self._conn.commit()
        return True

    def revoke_permission(self, agent_id: str, capability: str) -> bool:
        """把工具策略置为 deny，并清理 session_trust（FR-SEC-02/SET-03）。"""
        with self._lock:
            cur = self._conn.execute(
                "UPDATE capability SET policy='deny' WHERE agent_id=? AND tool=?",
                (agent_id, capability),
            )
            self._conn.execute(
                "DELETE FROM session_trust WHERE agent_id=? AND tool=?",
                (agent_id, capability),
            )
            self._conn.commit()
            return cur.rowcount > 0

    def get_capabilities(self, agent_id: str) -> list[Permission]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM capability WHERE agent_id=?", (agent_id,)
            ).fetchall()
        out = []
        for r in rows:
            p = Permission.from_dict({
                "tool": r["tool"], "policy": r["policy"],
                "framework": r["framework"],
            })
            out.append(p)
        return out

    # —— WebUI 支撑：列 agent / 单条授权 / manifest 详情 ——
    def list_agents(self) -> list[dict]:
        """列出所有已知 agent（capability ∪ agent_manifest），带 manifest 元信息与能力计数。"""
        with self._lock:
            rows = self._conn.execute(
                """SELECT ids.agent_id AS agent_id,
                          m.name AS name, m.version AS version, m.status AS status,
                          m.installed_at AS installed_at, m.framework AS framework,
                          (SELECT COUNT(*) FROM capability c WHERE c.agent_id=ids.agent_id) AS capability_count,
                          (SELECT COUNT(*) FROM capability c WHERE c.agent_id=ids.agent_id AND c.policy='allow') AS allowed_count
                   FROM (SELECT DISTINCT agent_id FROM capability
                         UNION SELECT agent_id FROM agent_manifest) ids
                   LEFT JOIN agent_manifest m ON m.agent_id = ids.agent_id
                   ORDER BY ids.agent_id"""
            ).fetchall()
        return [dict(r) for r in rows]

    def set_policy(self, agent_id: str, capability: str, policy: str) -> bool:
        """单条工具策略更新；非 allow 时清 session_trust。"""
        value = Policy(str(policy)).value
        with self._lock:
            cur = self._conn.execute(
                "UPDATE capability SET policy=? WHERE agent_id=? AND tool=?",
                (value, agent_id, capability),
            )
            if value != Policy.ALLOW.value:
                self._conn.execute(
                    "DELETE FROM session_trust WHERE agent_id=? AND tool=?",
                    (agent_id, capability),
                )
            self._conn.commit()
            return cur.rowcount > 0

    def get_manifest_info(self, agent_id: str) -> dict | None:
        with self._lock:
            r = self._conn.execute(
                """SELECT agent_id, version, name, signature, installed_at, status, framework
                   FROM agent_manifest WHERE agent_id=?""", (agent_id,)
            ).fetchone()
        return dict(r) if r else None

    # —— 工具策略查询 ——
    def _policy_row(self, agent_id: str, tool: str):
        """取该 Agent 对某工具的策略行；未声明时返回 None。"""
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM capability WHERE agent_id=? AND tool=?",
                (agent_id, tool),
            ).fetchone()

    # —— CheckPermission 算法（FR-SEC-02/03）：allow / ask / deny ——
    def check_permission(self, agent_id: str, capability: str, scope: str = "",
                         session_id: str = "") -> Decision:
        row = self._policy_row(agent_id, capability)
        # 未登记的工具走目录的未映射兜底策略（默认 allow），与 capabilities
        # 模块保持一致；已登记的行仍以落库的 policy 为准。
        policy = (
            Policy(str(row["policy"])) if row is not None
            else Policy(unmapped_policy())
        )
        if policy == Policy.ALLOW:
            return Decision.ALLOW
        if policy == Policy.DENY:
            return Decision.DENY
        # ask：本会话已批准过则放行
        if session_id and self._session_has(session_id, agent_id, capability):
            return Decision.ALLOW
        return Decision.ASK

    # —— session_trust（once_per_session，CAP-04）——
    def _session_has(self, session_id: str, agent_id: str, capability: str) -> bool:
        with self._lock:
            r = self._conn.execute(
                "SELECT 1 FROM session_trust WHERE session_id=? AND agent_id=? AND tool=?",
                (session_id, agent_id, capability),
            ).fetchone()
        return r is not None

    def grant_session_trust(self, session_id: str, agent_id: str, capability: str, ts: str) -> None:
        with self._lock:
            self._conn.execute(
                """INSERT OR REPLACE INTO session_trust(session_id,agent_id,tool,granted_at)
                   VALUES(?,?,?,?)""",
                (session_id, agent_id, capability, ts),
            )
            self._conn.commit()

    def clear_session(self, session_id: str) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM session_trust WHERE session_id=?", (session_id,))
            self._conn.commit()

    # —— manifest 记录 ——
    def record_manifest(self, agent_id: str, version: str, name: str,
                        signature: str, raw: str, ts: str,
                        framework: str = "") -> None:
        """记下签名包信息；``framework`` 为空时保留既有值。

        The framework scopes the console tool catalog, so a manifest that
        declares it must win, while an older package that does not must not
        wipe the value a caller already registered.
        """
        fw = str(framework or "").strip().lower()
        with self._lock:
            self._conn.execute(
                """INSERT INTO agent_manifest(agent_id,version,name,signature,manifest_raw,installed_at,status,framework)
                   VALUES(?,?,?,?,?,?, 'active', ?)
                   ON CONFLICT(agent_id) DO UPDATE SET
                     version=excluded.version, name=excluded.name,
                     signature=excluded.signature, manifest_raw=excluded.manifest_raw,
                     installed_at=excluded.installed_at, status='active',
                     framework=CASE WHEN excluded.framework='' THEN agent_manifest.framework
                                    ELSE excluded.framework END""",
                (agent_id, version, name, signature, raw, ts, fw),
            )
            self._ensure_initial_network_policy_locked(agent_id)
            self._ensure_initial_security_mode_locked(agent_id)
            self._conn.commit()

    # —— caller/Agent 可信绑定（P0-01）——
    def bind_agent(self, agent_id: str, caller, ts: str) -> None:
        """登记安装/启动实例的稳定身份属性；PID 不作为持久身份。"""
        with self._lock:
            self._conn.execute(
                """INSERT INTO agent_binding(agent_id,uid,executable,cgroup,session_id,bound_at)
                   VALUES(?,?,?,?,?,?)
                   ON CONFLICT(agent_id) DO UPDATE SET
                     uid=excluded.uid, executable=excluded.executable,
                     cgroup=excluded.cgroup, session_id=excluded.session_id,
                     bound_at=excluded.bound_at""",
                (agent_id, int(caller.uid), caller.executable or "",
                 _stable_cgroup(caller.cgroup), caller.session_id or "", ts),
            )
            self._conn.commit()

    def get_binding(self, agent_id: str) -> dict | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM agent_binding WHERE agent_id=?", (agent_id,)
            ).fetchone()
        return dict(row) if row else None

    def binding_times(self, agent_ids) -> dict[str, str]:
        """返回一批 Agent 最近一次 caller 绑定的时间戳。

        绑定在 Runtime 启动/注册 Agent 时续租，是"该 Agent 最近被拉起"的
        直接证据；WebUI 的最近活动字段会把它和其他活动证据合并取最新值。
        """
        ids = [str(agent_id) for agent_id in agent_ids if str(agent_id or "").strip()]
        if not ids:
            return {}
        placeholders = ",".join("?" * len(ids))
        with self._lock:
            rows = self._conn.execute(
                f"SELECT agent_id, bound_at FROM agent_binding WHERE agent_id IN ({placeholders})",
                ids,
            ).fetchall()
        return {str(r["agent_id"]): str(r["bound_at"]) for r in rows if r["bound_at"]}

    def reset_binding(self, agent_id: str) -> bool:
        """Remove the persisted caller binding for an explicit admin operation.

        Binding rows are deliberately not removed automatically when a process
        exits: a stale row protects the Agent identity across restarts.  Package
        upgrades therefore call this method only after stopping the old Runtime
        and record the operation in the Security audit chain.
        """
        with self._lock:
            cur = self._conn.execute(
                "DELETE FROM agent_binding WHERE agent_id=?", (str(agent_id),)
            )
            self._conn.commit()
            return cur.rowcount > 0

    def caller_matches(self, agent_id: str, caller, *, require_session: bool = False) -> bool:
        """验证 UID + executable/cgroup 绑定。

        V1 接口没有 session context，因此只验证稳定 caller 身份；V2 接口
        传入 `require_session=True` 时再校验绑定的 session_id。绑定中已有
        的 executable/cgroup 若本次无法解析也必须拒绝，不能用空值绕过。
        """
        return self.caller_matches_binding(
            self.get_binding(agent_id), caller, require_session=require_session)

    @staticmethod
    def caller_matches_binding(binding: dict | None, caller, *,
                               require_session: bool = False) -> bool:
        """校验已读取的 binding，供同一次请求避免重复 SQLite 查询。"""
        if caller is None:
            return False
        if getattr(caller, "is_root", False):
            return True
        if binding is None:
            return False
        if int(binding["uid"]) != int(caller.uid):
            return False
        # 安装时某属性可能不可用；可用属性必须匹配，避免空值放行。
        expected_exe = str(binding["executable"] or "")
        actual_exe = str(getattr(caller, "executable", "") or "")
        if expected_exe and not _executable_matches(expected_exe, actual_exe):
            return False
        expected_cgroup = _stable_cgroup(binding["cgroup"])
        actual_cgroup = _stable_cgroup(getattr(caller, "cgroup", ""))
        if expected_cgroup and expected_cgroup != actual_cgroup:
            return False
        if require_session:
            expected = str(binding["session_id"] or "")
            actual = str(getattr(caller, "session_id", "") or "")
            if expected != actual:
                return False
        return True

    def get_allowed_domains(self, agent_id: str) -> list[str]:
        """从 manifest_raw 解析网络白名单（供 BuildSandboxPolicy）。"""
        with self._lock:
            r = self._conn.execute(
                "SELECT manifest_raw FROM agent_manifest WHERE agent_id=?", (agent_id,)
            ).fetchone()
        if not r or not r["manifest_raw"]:
            return []

        import tomllib
        try:
            data = tomllib.loads(r["manifest_raw"])
            return list(data.get("permissions", {}).get("network", {}).get("allowed_domains", []))
        except Exception:
            return []

    def get_network_policy(self, agent_id: str) -> dict | None:
        import json
        with self._lock:
            row = self._conn.execute(
                "SELECT mode, domains_json, version FROM network_policy WHERE agent_id=?",
                (str(agent_id),)).fetchone()
        if not row:
            return None
        try:
            domains = json.loads(row["domains_json"])
        except (TypeError, ValueError):
            domains = []
        return {"agent_id": str(agent_id), "mode": row["mode"],
                "domains": list(domains) if isinstance(domains, list) else [],
                "version": int(row["version"])}

    def set_network_policy(self, agent_id: str, domains: list[str], mode: str = "deny_all") -> dict:
        import json
        mode = str(mode).strip().lower()
        if mode not in {"whitelist", "deny_all", "allow_all", "learning"}:
            raise ValueError(f"unsupported network policy mode: {mode}")
        values = []
        for value in (domains if mode == "whitelist" else []):
            domain = str(value).strip().lower().rstrip(".")
            if domain and domain not in values:
                values.append(domain)
        with self._lock:
            # Network policy can be configured from the standalone WebUI before
            # the first manifest refresh.  Create the minimal registry identity
            # so the foreign-key invariant is preserved without an orphan row.
            self._conn.execute(
                "INSERT OR IGNORE INTO agent_manifest(agent_id,version,name,signature,installed_at,status) "
                "VALUES(?,?,?,? ,datetime('now'),'active')",
                (str(agent_id), "1.0.0", str(agent_id), ""))
            row = self._conn.execute("SELECT version FROM network_policy WHERE agent_id=?", (str(agent_id),)).fetchone()
            version = int(row["version"]) + 1 if row else 1
            self._conn.execute(
                "INSERT INTO network_policy(agent_id,mode,domains_json,version,updated_at) VALUES(?,?,?,?,CURRENT_TIMESTAMP) "
                "ON CONFLICT(agent_id) DO UPDATE SET mode=excluded.mode,domains_json=excluded.domains_json,version=excluded.version,updated_at=CURRENT_TIMESTAMP",
                (str(agent_id), mode, json.dumps(values), version))
            self._conn.commit()
        return {"agent_id": str(agent_id), "mode": mode, "domains": values, "version": version}

    def delete_network_policy(self, agent_id: str) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM network_policy WHERE agent_id=?", (str(agent_id),))
            self._conn.commit()

    def restore_network_policy(self, agent_id: str, policy: dict) -> None:
        import json
        with self._lock:
            self._conn.execute("UPDATE network_policy SET mode=?, domains_json=?, version=? WHERE agent_id=?",
                (policy["mode"], json.dumps(policy["domains"]), policy["version"], str(agent_id)))
            self._conn.commit()

    # —— 安全权限设置（可读/可写范围，各自「包含 + 排除」）——
    def get_permission_settings(self, agent_id: str) -> dict:
        """返回该 Agent 的 {group: {include, exclude}}；缺项回退到空范围。"""
        from . import permissions as permissions_mod

        with self._lock:
            rows = self._conn.execute(
                "SELECT group_name, value_json FROM permission_settings WHERE agent_id=?",
                (str(agent_id),),
            ).fetchall()
        stored = {str(r["group_name"]): str(r["value_json"]) for r in rows}
        out: dict = {}
        for name in permissions_mod.GROUPS:
            raw = stored.get(name)
            value = None
            if raw is not None:
                try:
                    value = json.loads(raw)
                except (TypeError, ValueError):
                    value = None
            out[name] = _normalise_stored_range(value)
        return out

    def set_permission_group(self, agent_id: str, group: str, value: object) -> object:
        """写入一个安全权限组；值已由 permissions.normalise 校验。"""
        import json
        from . import permissions as permissions_mod

        name = permissions_mod.group_name(group)
        normalised = permissions_mod.normalise(value, group=name)
        with self._lock:
            # 允许在 manifest 首次刷新前配置：先建最小身份，避免外键悬空。
            self._conn.execute(
                "INSERT OR IGNORE INTO agent_manifest(agent_id,version,name,signature,installed_at,status) "
                "VALUES(?,?,?,?,datetime('now'),'active')",
                (str(agent_id), "1.0.0", str(agent_id), ""))
            self._conn.execute(
                "INSERT INTO permission_settings(agent_id,group_name,value_json,updated_at) VALUES(?,?,?,CURRENT_TIMESTAMP) "
                "ON CONFLICT(agent_id,group_name) DO UPDATE SET value_json=excluded.value_json,updated_at=CURRENT_TIMESTAMP",
                (str(agent_id), name, json.dumps(normalised, ensure_ascii=False, sort_keys=True)))
            self._conn.commit()
        return normalised

    def get_entrypoint(self, agent_id: str) -> list[str]:
        """读取已安装 manifest 的固定 Runtime entrypoint。

        仅供 security.runtime 内部策略编译使用；不把 manifest 原文暴露给
        WebUI/D-Bus 普通查询接口。
        """
        with self._lock:
            row = self._conn.execute(
                "SELECT manifest_raw FROM agent_manifest WHERE agent_id=?", (agent_id,)
            ).fetchone()
        if not row or not row["manifest_raw"]:
            return []
        try:
            data = tomllib.loads(str(row["manifest_raw"]))
            runtime = data.get("runtime", {})
            values = runtime.get("entrypoint", []) if isinstance(runtime, dict) else []
            if isinstance(values, list) and values and all(str(item).strip() for item in values):
                return [str(item) for item in values]
        except (tomllib.TOMLDecodeError, TypeError, ValueError):
            pass
        return []

    def get_runtime_binding(self, agent_id: str) -> dict[str, object] | None:
        """Return the non-secret signed Runtime binding for a registered Agent.

        This is consumed by the trusted PA package preflight.  It deliberately
        exposes only values already covered by the signed manifest; capability
        rows, signatures, and raw manifest text remain behind the admin API.
        """
        info = self.get_manifest_info(agent_id)
        if info is None or str(info.get("status", "")) != "active":
            return None
        entrypoint = self.get_entrypoint(agent_id)
        if not entrypoint:
            return None
        return {
            "agent_id": str(agent_id),
            "version": str(info.get("version", "")),
            "status": str(info.get("status", "")),
            "entrypoint": tuple(entrypoint),
        }
