"""DLP 策略存储（DLP-02）。

按 (agent_id, pii_type) 存处置动作；查询时逐级回退：
    精确匹配 → agent 的 "*" 默认 → 全局 "*" 默认 → 系统兜底

动作与能力策略同构：allow 放行 / ask 确认 / deny 拒绝，另加 mask 脱敏。
不再按风险级别区分兜底 —— 默认统一走 ``DEFAULT_ACTION``；
需要更细的处置时由运维逐类型显式配置。
"""
from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from collections.abc import Iterator
from enum import Enum
from pathlib import Path
from typing import Optional

from .. import config
from .pii_scanner import PIIType

__all__ = ["DLPAction", "DLPPolicyStore", "WILDCARD", "DEFAULT_ACTION"]

WILDCARD = "*"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS dlp_policy (
  agent_id  TEXT NOT NULL,
  pii_type  TEXT NOT NULL,
  action    TEXT NOT NULL,
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY (agent_id, pii_type)
);
"""


class DLPAction(str, Enum):
    """处置动作（与能力策略同构，另加脱敏）。"""

    ALLOW = "allow"  # 放行
    ASK = "ask"      # 需人工确认
    DENY = "deny"    # 拒绝
    MASK = "mask"    # 脱敏后继续


# 系统兜底动作：未显式配置的类型统一按此处置。
DEFAULT_ACTION = DLPAction.MASK


class DLPPolicyStore:
    """DLP 策略读写；每次操作独立事务并确定关闭连接，不依赖 GC。"""

    def __init__(self, db_path: Path | None = None):
        if db_path is None:
            config.ETC_DIR.mkdir(parents=True, exist_ok=True)
            db_path = config.ETC_DIR / "dlp_policy.db"
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as c:
            c.execute("PRAGMA journal_mode=WAL")
            c.executescript(_SCHEMA)

    @contextmanager
    def _conn(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(str(self.db_path), timeout=10.0)
        try:
            conn.row_factory = sqlite3.Row
            # Connection 的上下文只提交/回滚事务，不负责 close。
            with conn:
                yield conn
        finally:
            conn.close()

    def close(self) -> None:
        """兼容既有调用方；连接已在各操作退出时释放。"""

    # —— 写 ——
    def set_policy(self, agent_id: str, pii_type: PIIType | str,
                   action: DLPAction | str) -> None:
        """设置策略。pii_type 可为 WILDCARD 表示该 agent 的默认。"""
        pt = pii_type.value if isinstance(pii_type, PIIType) else str(pii_type)
        act = action.value if isinstance(action, DLPAction) else str(action)
        if act not in {a.value for a in DLPAction}:
            raise ValueError(f"非法 action：{act}")
        with self._conn() as c:
            c.execute(
                "INSERT INTO dlp_policy(agent_id,pii_type,action,updated_at) "
                "VALUES(?,?,?,datetime('now')) "
                "ON CONFLICT(agent_id,pii_type) DO UPDATE SET "
                "action=excluded.action, updated_at=excluded.updated_at",
                (agent_id, pt, act))

    def set_from_manifest(self, agent_id: str, dlp_section: dict) -> int:
        """从 manifest 的 [dlp] 节导入（DLP-02）。

        形如：
            [dlp]
            default = "mask"
            id_card = "deny"
            name = "allow"
        返回写入条数。未识别的 PII 类型名跳过（不让 manifest 拼错拖垮启动）。
        """
        if not dlp_section:
            return 0
        valid_types = {t.value for t in PIIType}
        n = 0
        for key, val in dlp_section.items():
            k = str(key).strip().lower()
            target = WILDCARD if k in ("default", "*") else k
            if target != WILDCARD and target not in valid_types:
                continue
            try:
                self.set_policy(agent_id, target, str(val).strip().lower())
                n += 1
            except ValueError:
                continue  # 非法 action 跳过
        return n

    def delete_policy(self, agent_id: str,
                      pii_type: PIIType | str | None = None) -> int:
        """删策略。pii_type=None 删该 agent 全部。"""
        with self._conn() as c:
            if pii_type is None:
                cur = c.execute("DELETE FROM dlp_policy WHERE agent_id=?",
                                (agent_id,))
            else:
                pt = pii_type.value if isinstance(pii_type, PIIType) else str(pii_type)
                cur = c.execute(
                    "DELETE FROM dlp_policy WHERE agent_id=? AND pii_type=?",
                    (agent_id, pt))
            return cur.rowcount

    # —— 读 ——
    def get_action(self, agent_id: str, pii_type: PIIType) -> DLPAction:
        """查处置动作，四级回退。"""
        pt = pii_type.value
        with self._conn() as c:
            rows = c.execute(
                "SELECT agent_id, pii_type, action FROM dlp_policy "
                "WHERE (agent_id=? OR agent_id=?) AND (pii_type=? OR pii_type=?)",
                (agent_id, WILDCARD, pt, WILDCARD)).fetchall()
        if rows:
            index = {(r["agent_id"], r["pii_type"]): r["action"] for r in rows}
            for key in ((agent_id, pt), (agent_id, WILDCARD),
                        (WILDCARD, pt), (WILDCARD, WILDCARD)):
                if key in index:
                    return DLPAction(index[key])
        return DEFAULT_ACTION

    def list_policies(self, agent_id: str | None = None) -> list[dict]:
        sql = "SELECT agent_id, pii_type, action, updated_at FROM dlp_policy"
        args: tuple = ()
        if agent_id:
            sql += " WHERE agent_id=?"
            args = (agent_id,)
        sql += " ORDER BY agent_id, pii_type"
        with self._conn() as c:
            return [dict(r) for r in c.execute(sql, args).fetchall()]

    def effective_matrix(self, agent_id: str) -> dict[str, str]:
        """该 agent 对全部 8 类 PII 的生效动作（WebUI 矩阵用）。"""
        return {t.value: self.get_action(agent_id, t).value for t in PIIType}

    def enabled_types(self, agent_id: str) -> set[PIIType]:
        """需要检测的类型（action=allow 的可跳过扫描，省开销）。"""
        return {t for t in PIIType
                if self.get_action(agent_id, t) != DLPAction.ALLOW}

    def actions(self) -> list[str]:
        """全部可用处置动作（WebUI 下拉用）。"""
        return [a.value for a in DLPAction]
