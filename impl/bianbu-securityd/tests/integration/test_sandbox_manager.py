"""集成测试：bwrap 沙箱 + seccomp + cap-drop（TC-INT-03/06/07/08）。

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

def _base_python() -> str:
    """沙箱内可用的解释器：优先 /usr 下的真实解释器（venv 包装器不可见）。"""
    cand = getattr(sys, "_base_executable", sys.executable)
    if cand and cand.startswith("/usr"):
        return cand
    for c in ("/usr/bin/python3", "/usr/bin/python"):
        if Path(c).exists():
            return c
    return sys.executable



def _userns_ok() -> bool:
    """探测非特权 userns 是否可用（merged-usr 感知）。"""
    from securityd.sandbox import _base_fs_args
    try:
        argv = ["bwrap", "--unshare-user", *_base_fs_args(),
                "--dev", "/dev", "--proc", "/proc", "--", "/usr/bin/true"]
        r = subprocess.run(argv, capture_output=True, timeout=10)
        return r.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


needs_userns = pytest.mark.skipif(not _userns_ok(), reason="非特权 userns 受限（AppArmor?）")


@needs_userns
def test_seccomp_blocks_reboot(sec_root, tmp_path):  # TC-INT-06
    from securityd import seccomp_builder
    from securityd.sandbox import SandboxSpec, launch, setup_cgroup
    seccomp = seccomp_builder.build_policy_file("com.test")
    prog = tmp_path / "try.py"
    prog.write_text(textwrap.dedent("""
        import ctypes, sys
        libc = ctypes.CDLL(None, use_errno=True)
        libc.reboot(0xfee1dead)
        sys.exit(99 if ctypes.get_errno() == 1 else 0)
    """))
    rw = tmp_path / "rw"; rw.mkdir()
    spec = SandboxSpec(
        agent_id="com.test",
        agent_binary=[_base_python(), "/prog/try.py"],
        rw_dir=rw, seccomp_path=seccomp, unshare_net=False,
        ro_binds=[str(tmp_path)],
    )
    # 把脚本挂进去
    spec.ro_binds = [str(prog.parent)]
    spec.agent_binary = [_base_python(), str(prog)]
    res = launch(spec, wait=True, timeout=20)
    # reboot 被 seccomp EPERM → 脚本 exit 99
    assert res.returncode == 99, f"reboot 未被拦截: rc={res.returncode} out={res.output}"


@needs_userns
def test_mandatory_deny_path_shadow(sec_root, tmp_path):  # TC-INT-03
    from securityd.sandbox import SandboxSpec, launch, setup_cgroup
    prog = tmp_path / "readshadow.py"
    prog.write_text(textwrap.dedent("""
        import sys
        try:
            data = open("/etc/shadow").read()
            # /dev/null 覆盖 → 读到空
            sys.exit(0 if data == "" else 7)
        except Exception:
            sys.exit(0)
    """))
    rw = tmp_path / "rw"; rw.mkdir()
    spec = SandboxSpec(
        agent_id="com.test", agent_binary=[_base_python(), str(prog)],
        rw_dir=rw, unshare_net=False, ro_binds=[str(prog.parent)],
    )
    res = launch(spec, wait=True, timeout=20)
    assert res.returncode == 0, f"shadow deny path 失效: rc={res.returncode} out={res.output}"


@needs_userns
def test_cap_drop_sys_admin(sec_root, tmp_path):  # TC-INT-07
    from securityd.sandbox import SandboxSpec, launch
    prog = tmp_path / "readcap.py"
    prog.write_text(textwrap.dedent("""
        import sys
        capeff = 0
        for line in open("/proc/self/status"):
            if line.startswith("CapEff:"):
                capeff = int(line.split()[1], 16)
        # CAP_SYS_ADMIN = bit 21
        sys.exit(0 if not (capeff & (1 << 21)) else 8)
    """))
    rw = tmp_path / "rw"; rw.mkdir()
    spec = SandboxSpec(
        agent_id="com.test", agent_binary=[_base_python(), str(prog)],
        rw_dir=rw, unshare_net=False, ro_binds=[str(prog.parent)],
    )
    res = launch(spec, wait=True, timeout=20)
    assert res.returncode == 0, f"CAP_SYS_ADMIN 未被 drop: rc={res.returncode} out={res.output}"


def test_fail_closed_missing_seccomp(sec_root, tmp_path):  # TC-INT-08
    """声明 seccomp 但文件缺失 → 拒绝启动（Fail-Closed），不 skip（纯逻辑）。"""
    from securityd.sandbox import SandboxSpec, launch
    rw = tmp_path / "rw"; rw.mkdir()
    spec = SandboxSpec(
        agent_id="com.test", agent_binary=["/bin/true"],
        rw_dir=rw, seccomp_path=str(tmp_path / "nonexistent.bpf"),
    )
    res = launch(spec, wait=True, timeout=10)
    assert res.ok is False
    assert "seccomp" in res.reason


def test_fail_closed_required_cgroup(sec_root, tmp_path, monkeypatch):
    """生产标记要求 cgroup 强制时，无法设置资源限制不得启动。"""
    monkeypatch.setenv("BIANBU_SECURITY_REQUIRE_CGROUP", "1")
    from securityd.sandbox import SandboxSpec, launch, setup_cgroup
    rw = tmp_path / "rw"; rw.mkdir()
    spec = SandboxSpec(agent_id="com.cgroup", agent_binary=["/bin/true"], rw_dir=rw)
    res = launch(spec, wait=True, timeout=10)
    # 若内核允许设置，必须成功；否则生产路径明确拒绝启动。
    cg = setup_cgroup("com.cgroup.probe", "64M", "100%", require=True)
    if cg is None:
        assert not res.ok and "cgroup" in res.reason
    else:
        assert res.ok


def test_cgroup_writes_all_resource_controls(tmp_path, monkeypatch):
    """在模拟 cgroup v2 根目录验证 Memory/CPU/Tasks/IO 四类控制器写入。"""
    from securityd.sandbox import setup_cgroup
    root = tmp_path / "cg"; root.mkdir()
    (root / "cgroup.controllers").write_text("cpu io memory pids")
    child = root / "bianbu-com.test_unsafe"; child.mkdir()
    for name in ("memory.max", "cpu.max", "pids.max", "io.weight", "cgroup.procs"):
        (child / name).write_text("")
    monkeypatch.setenv("BIANBU_SECURITY_CGROUP_ROOT", str(root))
    monkeypatch.setenv("BIANBU_SECURITY_CGROUP_PARENT", str(root))
    cg = setup_cgroup("com.test/unsafe", "64M", "25%", tasks_max=32,
                      io_weight=200, require=True)
    assert cg is not None
    assert (cg / "memory.max").read_text() == str(64 * 1024 * 1024)
    assert (cg / "cpu.max").read_text() == "25000 100000"
    assert (cg / "pids.max").read_text() == "32"
    assert (cg / "io.weight").read_text() == "200"
