"""Phase 3：整进程 bwrap 沙箱 —— hermes 进程及其 spawn 的工具子进程均受 seccomp 限制。

证明"bwrap 集成到 hermes"的进程级方案：用 hermes_sandbox_launch 在沙箱内启动一个
"模拟 hermes"父进程，它 spawn 一个"工具"子进程执行 reboot → 被 seccomp EPERM 拦截。
需 bwrap + 非特权 userns（本地 AppArmor 受限时 skip；worker K3 可跑）。
"""
from __future__ import annotations

import shutil
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(shutil.which("bwrap") is None, reason="bwrap 不可用")

ROOT = Path(__file__).resolve().parent.parent.parent


def _base_python() -> str:
    cand = getattr(sys, "_base_executable", sys.executable)
    if cand and cand.startswith("/usr"):
        return cand
    for c in ("/usr/bin/python3", "/usr/bin/python"):
        if Path(c).exists():
            return c
    return sys.executable


def _userns_ok() -> bool:
    from securityd.sandbox import _base_fs_args
    try:
        argv = ["bwrap", "--unshare-user", *_base_fs_args(),
                "--dev", "/dev", "--proc", "/proc", "--", "/usr/bin/true"]
        return subprocess.run(argv, capture_output=True, timeout=10).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


needs_userns = pytest.mark.skipif(not _userns_ok(), reason="非特权 userns 受限（AppArmor?）")


@needs_userns
def test_process_sandbox_blocks_child_syscall(sec_root, tmp_path):
    """整进程沙箱：hermes 父进程 spawn 的工具子进程 reboot 被拦截（seccomp 继承）。"""
    from hermes_plugin import hermes_sandbox_launch as launcher

    # 脚本须放进沙箱可见的 rw 目录（launcher 把 rw_dir 绑到 /home/agent）
    rw = tmp_path / "rw"; rw.mkdir()
    mock_hermes = rw / "mock_hermes.py"
    mock_hermes.write_text(textwrap.dedent(f"""
        import subprocess, sys
        # 模拟 hermes 的 terminal/code_execution 工具 spawn 子进程
        r = subprocess.run([{_base_python()!r}, "-c",
            "import ctypes,sys;l=ctypes.CDLL(None,use_errno=True);"
            "l.reboot(0xfee1dead);sys.exit(99 if ctypes.get_errno()==1 else 0)"])
        sys.exit(r.returncode)
    """))

    rc = launcher.main([
        "--agent", "com.hermes.test", "--rw-dir", str(rw),
        "--", _base_python(), "/home/agent/mock_hermes.py",
    ])
    # 子进程 reboot 被 seccomp EPERM → 子 exit 99 → 父透传 99 → 沙箱 rc 99
    assert rc == 99, f"工具子进程的 reboot 未被进程沙箱拦截: rc={rc}"
