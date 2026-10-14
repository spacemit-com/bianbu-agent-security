"""从受信内核进程信息构造调用者身份，供 D-Bus 与 UDS 共用。"""
from __future__ import annotations

import os
from pathlib import Path

from .models import CallerContext


def caller_from_process(uid: int, pid: int, *, sender: str,
                        session_id: str = "", include_groups: bool = True) -> CallerContext:
    """读取内核进程身份；任何字段解析失败都保持空值而非伪造。"""
    executable = ""
    cgroup = ""
    groups: tuple[int, ...] = ()
    # /proc/<pid>/exe is the kernel-resolved executable identity and remains
    # readable under securityd's ProtectHome=yes view.  Prefer it over argv[0]:
    # argv[0] may be a venv path hidden by ProtectHome, causing an otherwise
    # valid PA UDS caller to fail executable binding.
    try:
        executable = os.path.realpath(f"/proc/{pid}/exe")
    except (OSError, UnicodeDecodeError):
        try:
            argv0 = Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0", 1)[0].decode()
            executable = os.path.normpath(argv0) if os.path.isabs(argv0) else ""
        except (OSError, UnicodeDecodeError):
            pass
    try:
        cgroup = Path(f"/proc/{pid}/cgroup").read_text().strip()
    except OSError:
        pass
    if include_groups:
        try:
            status = Path(f"/proc/{pid}/status").read_text()
            groups_line = status.split("Groups:", 1)[1].splitlines()[0]
            groups = tuple(int(value) for value in groups_line.split())
        except (OSError, IndexError, ValueError):
            pass
    return CallerContext(sender=str(sender), uid=int(uid), pid=int(pid),
                         executable=executable, cgroup=cgroup,
                         session_id=str(session_id), groups=groups)


__all__ = ["caller_from_process"]
