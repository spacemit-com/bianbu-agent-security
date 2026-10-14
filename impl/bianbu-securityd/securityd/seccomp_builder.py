"""Syscall Filter Builder（FR-SEC-05 / SBX-04 / SCM-01~03）。

纯 Python 生成 seccomp cBPF 程序（无需 libseccomp 绑定），产出 struct sock_filter
数组字节，供 bwrap `--seccomp <fd>` 加载。denylist 命中返回 EPERM，其余放行。

支持 arch：x86_64（本地）、riscv64（worker K3）。对齐设计 §3.3 / §6.2。
"""
from __future__ import annotations

import platform
import struct
from pathlib import Path

from . import config

# —— AUDIT_ARCH 常量 ——
AUDIT_ARCH_X86_64 = 0xC000003E
AUDIT_ARCH_RISCV64 = 0xC00000F3

# —— seccomp 返回动作 ——
SECCOMP_RET_ALLOW = 0x7FFF0000
SECCOMP_RET_ERRNO = 0x00050000
SECCOMP_RET_KILL_PROCESS = 0x80000000
EPERM = 1

# —— BPF 指令码 ——
BPF_LD_W_ABS = 0x20  # BPF_LD|BPF_W|BPF_ABS
BPF_JEQ_K = 0x15     # BPF_JMP|BPF_JEQ|BPF_K
BPF_RET_K = 0x06     # BPF_RET|BPF_K

# seccomp_data 偏移
OFF_NR = 0
OFF_ARCH = 4

# —— 危险系统调用号（denylist），按 arch ——
# x86_64: arch/x86/entry/syscalls/syscall_64.tbl
_SYSCALLS_X86_64 = {
    "reboot": 169, "swapon": 167, "swapoff": 168,
    "kexec_load": 246, "kexec_file_load": 320,
    "init_module": 175, "finit_module": 313, "delete_module": 176,
    "mount": 165, "umount2": 166, "pivot_root": 155,
    "perf_event_open": 298,
    "ptrace": 101, "bpf": 321, "userfaultfd": 323,
}
# riscv64: include/uapi/asm-generic/unistd.h（通用号，arm64/riscv 共用）
_SYSCALLS_RISCV64 = {
    "reboot": 142, "swapon": 224, "swapoff": 225,
    "kexec_load": 104, "kexec_file_load": 294,
    "init_module": 105, "finit_module": 273, "delete_module": 106,
    "mount": 40, "umount2": 39, "pivot_root": 41,
    "perf_event_open": 241,
    "ptrace": 117, "bpf": 280, "userfaultfd": 282,
}

_ARCH_TABLE = {
    "x86_64": (AUDIT_ARCH_X86_64, _SYSCALLS_X86_64),
    "riscv64": (AUDIT_ARCH_RISCV64, _SYSCALLS_RISCV64),
}


def _insn(code: int, jt: int, jf: int, k: int) -> bytes:
    """struct sock_filter { u16 code; u8 jt; u8 jf; u32 k; }（native endian）。"""
    return struct.pack("=HBBI", code, jt & 0xFF, jf & 0xFF, k & 0xFFFFFFFF)


def generate_bpf(arch: str | None = None, denylist: list[str] | None = None) -> bytes:
    """生成 seccomp BPF 程序字节。

    结构：
      0  LD  arch
      1  JEQ arch_val -> 相等继续(jt=0)，否则跳 KILL(jf)
      2  LD  nr
      3..2+n  JEQ syscall[k] -> 命中跳 DENY(jt)，否则继续(jf=0)
      3+n RET ALLOW
      4+n RET ERRNO|EPERM   (DENY)
      5+n RET KILL_PROCESS  (arch 不符)
    """
    arch = arch or platform.machine()
    if arch not in _ARCH_TABLE:
        raise ValueError(f"seccomp: 不支持的 arch {arch}（仅 x86_64/riscv64）")
    arch_val, table = _ARCH_TABLE[arch]
    names = denylist if denylist is not None else config.SECCOMP_DENYLIST
    nrs = [table[n] for n in names if n in table]
    n = len(nrs)

    idx_deny = 4 + n
    idx_kill = 5 + n
    prog = bytearray()
    # 0: load arch
    prog += _insn(BPF_LD_W_ABS, 0, 0, OFF_ARCH)
    # 1: JEQ arch_val: 相等 fall-through(jt=0)，否则跳 KILL
    prog += _insn(BPF_JEQ_K, 0, idx_kill - 2, arch_val)
    # 2: load nr
    prog += _insn(BPF_LD_W_ABS, 0, 0, OFF_NR)
    # 3..: JEQ 每个 denied syscall
    for i, nr in enumerate(nrs):
        j = 3 + i
        jt = idx_deny - (j + 1)  # 命中跳 DENY
        prog += _insn(BPF_JEQ_K, jt, 0, nr)
    # 3+n: ALLOW
    prog += _insn(BPF_RET_K, 0, 0, SECCOMP_RET_ALLOW)
    # 4+n: DENY -> EPERM
    prog += _insn(BPF_RET_K, 0, 0, SECCOMP_RET_ERRNO | EPERM)
    # 5+n: KILL（arch 不符）
    prog += _insn(BPF_RET_K, 0, 0, SECCOMP_RET_KILL_PROCESS)
    return bytes(prog)


def build_policy_file(agent_id: str, arch: str | None = None,
                      denylist: list[str] | None = None) -> str:
    """生成 seccomp BPF 并写入 /run/bianbu/sandbox/<agent_id>/seccomp.bpf，返回路径。

    没有需要拒绝的系统调用时返回空串：调用方据此跳过 ``--seccomp``，既不装载
    一个什么都放行的过滤器，也不会把「有 seccomp 审计」写进 attestation。
    """
    names = list(config.SECCOMP_DENYLIST if denylist is None else denylist)
    if not names:
        return ""
    out_dir = config.SANDBOX_RUN_DIR / agent_id
    out_dir.mkdir(parents=True, exist_ok=True)
    # Runtime launches the Worker through a per-user systemd unit.  The unit
    # runs as the Runtime user (usually ``bianbu``), while securityd itself
    # owns this tree as ``bianbu-security``.  The BPF program is policy data,
    # not a credential; make only the policy directory/file traversable and
    # readable so bwrap can open it before installing the filter.  The UDS and
    # other securityd runtime files keep their separate restrictive modes.
    try:
        config.SANDBOX_RUN_DIR.chmod(0o755)
        out_dir.chmod(0o755)
    except OSError:
        pass
    bpf = generate_bpf(arch, denylist)
    path = out_dir / "seccomp.bpf"
    path.write_bytes(bpf)
    try:
        path.chmod(0o644)
    except OSError:
        pass
    return str(path)
