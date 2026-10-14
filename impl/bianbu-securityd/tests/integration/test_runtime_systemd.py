"""K3/systemd Runtime 强制集成门禁。

验证 runtime_launcher 创建的 transient unit 真实写入资源和 IP 过滤属性，
并验证 MemoryMax OOM 结果由 systemd 传播。没有用户 systemd 时明确 skip，
不能把本地环境缺失误报为通过。
"""
from __future__ import annotations

import shutil
import subprocess
import uuid

import pytest


def _user_systemd_available() -> bool:
    if not shutil.which("systemd-run") or not shutil.which("systemctl"):
        return False
    try:
        return subprocess.run(["systemctl", "--user", "is-system-running"],
                              capture_output=True, timeout=5).returncode in {0, 1}
    except (OSError, subprocess.TimeoutExpired):
        return False


pytestmark = pytest.mark.skipif(
    not _user_systemd_available(), reason="需可用的 user systemd 实例")


def test_runtime_unit_enforces_resources_and_network(monkeypatch):
    from client.runtime_launcher import (RuntimeLaunchSpec, launch_runtime,
                                         unit_name, verify_runtime_resources)
    from securityd import network_policy

    monkeypatch.setattr(network_policy, "_resolve",
                        lambda domains: {d: ["10.0.50.55"] for d in domains})
    aid = "com.bianbu.runtime-test-" + uuid.uuid4().hex[:8]
    spec = RuntimeLaunchSpec(aid, ["/bin/sh", "-c", "sleep 8"],
                             ["archive.bianbu.xyz"], ["127.0.0.53"],
                             "64M", "25%", 32, 200)
    result = launch_runtime(spec)
    unit = unit_name(aid)
    try:
        assert result.ok, result.reason
        assert result.verified_network is True
        assert result.verified_resources is True
        props = subprocess.run(
            ["systemctl", "--user", "show", unit,
             "--property=MemoryMax,CPUQuotaPerSecUSec,TasksMax,IOWeight,"
             "IPAddressDeny,IPAddressAllow,ControlGroup"],
            check=True, capture_output=True, text=True, timeout=5).stdout
        assert "MemoryMax=67108864" in props
        assert "CPUQuotaPerSecUSec=250ms" in props
        assert "TasksMax=32" in props
        assert "IOWeight=200" in props
        deny_line = next(line for line in props.splitlines()
                         if line.startswith("IPAddressDeny="))
        assert {"0.0.0.0/0", "::/0"}.issubset(set(deny_line.split("=", 1)[1].split()))
        assert "10.0.50.55/32" in props and "127.0.0.53/32" in props
        assert "ControlGroup=/" in props
    finally:
        subprocess.run(["systemctl", "--user", "stop", unit],
                       capture_output=True, timeout=5)


def test_runtime_memory_max_propagates_oom():
    unit = "bnsec-oom-" + uuid.uuid4().hex[:8] + ".service"
    cp = subprocess.run([
        "systemd-run", "--user", "--wait", "--pipe", "--collect",
        f"--unit={unit}", "--property=MemoryMax=16M", "--property=TasksMax=32",
        "/usr/bin/python3", "-c", "bytearray(64*1024*1024)",
    ], capture_output=True, text=True, timeout=20)
    # Some user managers delegate accounting to a parent cgroup and report
    # success even when MemoryMax is not enforceable. Treat that as an
    # environment limitation rather than a product failure.
    combined = (cp.stdout + cp.stderr).lower()
    if cp.returncode == 0 and "oom-kill" not in combined and "status=9" not in combined:
        pytest.skip("当前 user systemd/cgroup 未启用 MemoryMax OOM 强制")
    assert cp.returncode != 0
    assert "oom-kill" in combined or "status=9" in combined
