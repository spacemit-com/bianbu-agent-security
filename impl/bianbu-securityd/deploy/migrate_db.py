#!/usr/bin/env python3
"""安全数据库迁移门禁。

迁移只在临时/目标数据根内执行，采用 SQLite 事务和同目录备份；重复执行
幂等。当前版本给已有数据库补充 schema_meta，未改变业务表语义，便于后续
版本扩展时拒绝未知版本而不是静默使用错误 schema。
"""
from __future__ import annotations

import argparse
import shutil
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

SCHEMA_VERSION = 1


def migrate(path: Path, *, backup: bool = True) -> tuple[bool, str]:
    path = Path(path)
    if not path.exists():
        return True, "absent"
    backup_path = path.with_suffix(path.suffix + ".pre-migrate")
    conn = None
    try:
        conn = sqlite3.connect(str(path))
        # 把 WAL 合并到主库后再备份，避免只复制 .db 丢失尚未 checkpoint 的记录。
        conn.execute("PRAGMA wal_checkpoint(FULL)")
        if backup and not backup_path.exists():
            shutil.copy2(path, backup_path)
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("BEGIN IMMEDIATE")
        conn.execute("CREATE TABLE IF NOT EXISTS schema_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
        row = conn.execute("SELECT value FROM schema_meta WHERE key='schema_version'").fetchone()
        current = int(row[0]) if row else 0
        if current > SCHEMA_VERSION:
            conn.rollback()
            conn.close()
            return False, f"future_schema={current}"
        if current == SCHEMA_VERSION:
            # 已是目标 schema 时保持字节级业务状态不变。重复安装不应仅因
            # migrated_at 刷新就制造数据库漂移，尤其会干扰失败升级回滚核验。
            conn.commit()
            conn.close()
            return True, f"{current}->{SCHEMA_VERSION} (noop)"
        conn.execute("INSERT OR REPLACE INTO schema_meta(key,value) VALUES('schema_version',?)",
                     (str(SCHEMA_VERSION),))
        conn.execute("INSERT OR REPLACE INTO schema_meta(key,value) VALUES('migrated_at',?)",
                     (datetime.now(timezone.utc).isoformat(),))
        conn.commit()
        conn.close()
        return True, f"{current}->{SCHEMA_VERSION}"
    except (OSError, sqlite3.DatabaseError, ValueError) as exc:
        try:
            conn.rollback()
            conn.close()
        except Exception:
            pass
        if backup and backup_path.exists():
            shutil.copy2(backup_path, path)
        return False, str(exc)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("paths", nargs="+", type=Path)
    ap.add_argument("--no-backup", action="store_true")
    args = ap.parse_args(argv)
    ok = True
    for path in args.paths:
        good, detail = migrate(path, backup=not args.no_backup)
        print(f"DB_MIGRATE_{'PASS' if good else 'FAIL'} {path} {detail}")
        ok &= good
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
