"""seccomp BPF 生成（SCM-01）：结构与 arch 覆盖。"""
from __future__ import annotations

import pytest

from securityd import seccomp_builder as sb


def test_bpf_x86_64_nonempty():
    bpf = sb.generate_bpf("x86_64")
    assert len(bpf) % 8 == 0  # 每条 sock_filter 8 字节
    assert len(bpf) == 8 * 6  # arch 装载 + 校验 + ALLOW/DENY/KILL


def test_bpf_riscv64_nonempty():
    bpf = sb.generate_bpf("riscv64")
    assert len(bpf) % 8 == 0
    assert len(bpf) > 0


def test_unsupported_arch():
    with pytest.raises(ValueError):
        sb.generate_bpf("mips")


def test_denylist_syscalls_present():
    # x86_64 reboot=169 / mount=165 应出现在某条 JEQ 的 k 字段
    import struct
    bpf = sb.generate_bpf("x86_64", ["reboot", "mount"])
    ks = [struct.unpack("=HBBI", bpf[i:i+8])[3] for i in range(0, len(bpf), 8)]
    assert 169 in ks  # reboot
    assert 165 in ks  # mount


def test_build_policy_file(sec_root):
    path = sb.build_policy_file("com.test", arch="x86_64", denylist=["reboot"])
    import os
    assert os.path.exists(path)
    assert os.path.getsize(path) > 0


def test_build_policy_file_skips_empty_denylist(sec_root):
    """默认不限制：没有要拒绝的系统调用时不生成过滤器文件。"""
    assert sb.build_policy_file("com.test", arch="x86_64", denylist=[]) == ""
