"""Versioned syscall denylist policy owned by securityd.

出厂默认不限制：没有任何强制基线，只有管理员显式追加的条目才会生效。
"""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from . import config, seccomp_builder

class SyscallPolicyError(ValueError):
    pass

_ARCHES = frozenset(seccomp_builder._ARCH_TABLE)
_DESCRIPTIONS = {
    "reboot": "重启或关闭系统", "swapon": "启用交换分区", "swapoff": "停用交换分区",
    "kexec_load": "加载新的内核", "kexec_file_load": "从文件加载内核",
    "init_module": "加载内核模块", "finit_module": "从文件加载内核模块",
    "delete_module": "卸载内核模块", "mount": "挂载文件系统",
    "umount2": "卸载文件系统", "pivot_root": "切换根文件系统",
    "perf_event_open": "创建性能监控事件", "openat2": "受限文件打开接口",
    "ptrace": "调试或控制其他进程", "bpf": "加载内核 eBPF 程序", "userfaultfd": "创建用户态缺页处理器",
}
_CATALOG = {arch: dict(table) for arch, (_audit, table) in seccomp_builder._ARCH_TABLE.items()}
# Keep a known-but-unsupported-on-x86 example explicit for useful errors.
_CATALOG["riscv64"].setdefault("openat2", 437)

def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")

class SyscallPolicyStore:
    def __init__(self, db_path: Path | None = None):
        config.ensure_dirs()
        self.db_path = Path(db_path or (config.ETC_DIR / "syscall_policy.db"))
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA busy_timeout=5000")
        self.conn.execute("""CREATE TABLE IF NOT EXISTS syscall_policy (
          scope TEXT NOT NULL, agent_id TEXT NOT NULL DEFAULT '', arch TEXT NOT NULL,
          additions_json TEXT NOT NULL, policy_version INTEGER NOT NULL,
          updated_by TEXT NOT NULL, updated_at TEXT NOT NULL,
          PRIMARY KEY(scope,agent_id,arch))""")
        self.conn.execute("CREATE TABLE IF NOT EXISTS syscall_policy_meta (k TEXT PRIMARY KEY,v TEXT NOT NULL)")
        self.conn.commit()

    def close(self):
        self.conn.close()

    def catalog(self, arch: str) -> dict:
        self._arch(arch)
        return {"arch": arch, "syscalls": [
            {"name": n, "number": int(v),
             "description": _DESCRIPTIONS.get(n, "危险系统调用")}
            for n, v in sorted(_CATALOG[arch].items())
        ]}

    def _arch(self, arch: str):
        if arch not in _ARCHES:
            raise SyscallPolicyError(f"UnsupportedArch: {arch}")

    def _validate(self, arch: str, names):
        self._arch(arch)
        out = []
        for name in names:
            n = str(name).strip()
            if n not in _DESCRIPTIONS:
                raise SyscallPolicyError(f"UnknownSyscall: {n}")
            if n not in _CATALOG[arch]:
                raise SyscallPolicyError(f"SyscallNotApplicable: {n} on {arch}")
            if n not in out:
                out.append(n)
        return sorted(out)

    def _next_version(self):
        row = self.conn.execute("SELECT v FROM syscall_policy_meta WHERE k='version'").fetchone()
        v = int(row[0]) + 1 if row else 1
        self.conn.execute("INSERT OR REPLACE INTO syscall_policy_meta(k,v) VALUES('version',?)", (str(v),))
        return v

    def _set(self, scope, agent_id, arch, additions, updated_by="admin"):
        additions = self._validate(arch, additions)
        version = self._next_version()
        self.conn.execute("INSERT OR REPLACE INTO syscall_policy VALUES(?,?,?,?,?,?,?)",
                          (scope, agent_id if scope == "agent" else "", arch,
                           json.dumps(additions), version, str(updated_by), _now()))
        self.conn.commit()
        return self.get(agent_id, arch)

    def set_global(self, arch, additions, updated_by="admin"):
        return self._set("global", "", arch, additions, updated_by)

    def set_agent(self, agent_id, arch, additions, updated_by="admin"):
        if not str(agent_id).strip():
            raise SyscallPolicyError("InvalidAgent: empty agent_id")
        return self._set("agent", str(agent_id), arch, additions, updated_by)

    def reset_agent(self, agent_id, arch, updated_by="admin"):
        self._arch(arch)
        version = self._next_version()
        self.conn.execute("INSERT OR REPLACE INTO syscall_policy VALUES(?,?,?,?,?,?,?)",
                          ("agent", str(agent_id), arch, "[]", version, str(updated_by), _now()))
        self.conn.commit()
        return self.get(agent_id, arch)

    def mark_applied(self, agent_id, arch, version):
        self.conn.execute("INSERT OR REPLACE INTO syscall_policy_meta(k,v) VALUES(?,?)",
                          (f"applied:{agent_id}:{arch}", str(int(version))))
        self.conn.commit()

    def get(self, agent_id, arch) -> dict:
        self._arch(arch)
        def additions(scope, aid=""):
            row = self.conn.execute("SELECT additions_json,policy_version FROM syscall_policy WHERE scope=? AND agent_id=? AND arch=?",
                                    (scope, aid, arch)).fetchone()
            return (json.loads(row[0]) if row else [], int(row[1]) if row else 0)
        global_add, gv = additions("global")
        agent_add, av = additions("agent", str(agent_id))
        version = max(gv, av, int((self.conn.execute("SELECT v FROM syscall_policy_meta WHERE k='version'").fetchone() or [0])[0]))
        ar = self.conn.execute("SELECT v FROM syscall_policy_meta WHERE k=?", (f"applied:{agent_id}:{arch}",)).fetchone()
        applied = int(ar[0]) if ar else 0
        # 没有强制基线：没配置就是空，不会装载任何 seccomp 过滤器。
        effective: list[str] = []
        for n in global_add + agent_add:
            if n not in effective: effective.append(n)
        return {"arch": arch, "global_additions": global_add,
                "agent_additions": agent_add, "effective": effective,
                "policy_version": version, "applied_policy_version": applied,
                "pending_restart": version != applied}
