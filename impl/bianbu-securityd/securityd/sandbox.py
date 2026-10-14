"""Sandbox Manager（FR-SBX-01~07 / SBX-01~08）。

bwrap 参数构造 + cgroup v2 编排 + 启动 + Fail-Closed。arch 感知（riscv64 无 /lib64）。
对齐设计 §3.7 / §6.2。生产中归 bianbu-agent-runtimed；此处提供可被其复用/直测的实现。
"""
from __future__ import annotations

import os
import platform
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from . import config

# mandatory deny paths：以 /dev/null 覆盖，Agent 读到空
MANDATORY_DENY_PATHS = [
    "/etc/shadow", "/etc/gshadow", "/etc/sudoers",
    "/root", "/etc/ssh",
]


@dataclass
class SandboxSpec:
    agent_id: str
    agent_binary: list[str]                 # 例如 ["/bin/sh","-c","..."]
    rw_dir: Path                            # Agent 私有读写目录
    seccomp_path: str | None = None         # seccomp BPF 文件
    ro_binds: list[str] = field(default_factory=list)   # 额外只读依赖（原路径映射）
    ro_binds_map: list[tuple[str, str]] = field(default_factory=list)  # 只读绑定 (host, sandbox)
    rw_binds: list[tuple[str, str]] = field(default_factory=list)  # 额外可写绑定 (host, sandbox)
    unshare_net: bool = True
    home_dir: str = "/home/agent"           # 沙箱内 HOME（默认私有目录）
    memory_max: str = config.DEFAULT_MEMORY_MAX
    cpu_quota: str = config.DEFAULT_CPU_QUOTA
    tasks_max: int | str = config.DEFAULT_TASKS_MAX
    io_weight: int = config.DEFAULT_IO_WEIGHT


def _base_fs_args() -> list[str]:
    """基础只读文件系统参数，兼容 merged-usr（/bin、/lib 为符号链接）。

    - 始终 --ro-bind /usr /usr
    - 顶层若为符号链接（merged-usr）→ 用 --symlink 重建；若为真实目录 → --ro-bind
    - /etc/ld.so.cache 单独 bind（存在时）
    """
    args: list[str] = ["--ro-bind", "/usr", "/usr"]
    for top in ("/bin", "/lib", "/lib64", "/sbin"):
        p = Path(top)
        if p.is_symlink():
            target = os.readlink(top)  # e.g. "usr/bin"
            args += ["--symlink", target, top]
        elif p.is_dir():
            args += ["--ro-bind", top, top]
    if Path("/etc/ld.so.cache").exists():
        args += ["--ro-bind", "/etc/ld.so.cache", "/etc/ld.so.cache"]
    return args


def build_bwrap_argv(spec: SandboxSpec, seccomp_fd: int | None = None,
                     interactive: bool = False) -> list[str]:
    """构造 bwrap 命令行（SBX-02/04）。seccomp 经 fd 传入（--seccomp <fd>）。

    interactive=True：省略 --new-session。--new-session 会 setsid() 建新会话但不设
    控制终端，导致交互式作业控制 shell（bash -i）启动时 tcsetpgrp() 失败、报
    "无法设定终端进程组 / 无任务控制"。交互式沙箱由 pty.fork() 提供专属伪终端，
    TIOCSTI 注入面已受控，故安全地省略该项以恢复作业控制。批处理模式仍保留
    --new-session 以获得最强隔离。
    """
    argv = ["bwrap", "--unshare-user", "--unshare-pid", "--unshare-ipc", "--unshare-uts"]
    if spec.unshare_net:
        argv.append("--unshare-net")
    if not interactive:
        argv.append("--new-session")
    argv += ["--die-with-parent", "--cap-drop", "ALL"]

    argv += _base_fs_args()
    # 先建虚拟文件系统，再挂调用方 bind，使 ro_bind 能覆盖在 tmpfs 之上不被清空
    argv += ["--tmpfs", "/tmp", "--dev", "/dev", "--proc", "/proc"]
    for b in spec.ro_binds:
        if Path(b).exists():
            argv += ["--ro-bind", b, b]
    for host, sbx in spec.ro_binds_map:
        if Path(host).exists():
            argv += ["--ro-bind", host, sbx]
    # Agent 私有读写目录挂到 /home/agent
    argv += ["--bind", str(spec.rw_dir), "/home/agent"]
    # 额外可写绑定（如 hermes 的 ~/.hermes 配置/会话目录）
    for host, sbx in spec.rw_binds:
        if Path(host).exists():
            argv += ["--bind", host, sbx]
    argv += ["--chdir", spec.home_dir]
    # mandatory deny paths
    for p in MANDATORY_DENY_PATHS:
        if Path(p).exists():
            argv += ["--ro-bind", "/dev/null", p]
    argv += ["--setenv", "HOME", spec.home_dir, "--setenv", "BIANBU_AGENT_ID", spec.agent_id]
    if seccomp_fd is not None:
        argv += ["--seccomp", str(seccomp_fd)]
    argv += ["--"] + spec.agent_binary
    return argv


def setup_cgroup(agent_id: str, memory_max: str, cpu_quota: str,
                 tasks_max: int | str = config.DEFAULT_TASKS_MAX,
                 io_weight: int = config.DEFAULT_IO_WEIGHT,
                 *, require: bool = False) -> Path | None:
    """创建 cgroup v2 slice 并设限（SBX-03）。

    `require=True` 用于生产强制路径：内核控制器不存在或当前进程无权设置
    限制时返回 None，由调用方 fail-closed；默认 False 保留开发/测试可用性。
    """
    base = Path(os.environ.get("BIANBU_SECURITY_CGROUP_ROOT", "/sys/fs/cgroup"))
    if not (base / "cgroup.controllers").exists():
        return None
    # systemd/runtimed 可把服务专属 cgroup 根目录传入；securityd 不在
    # 用户 slice 根目录直接创建节点，避免普通用户越权和路径污染。
    parent = Path(os.environ.get("BIANBU_SECURITY_CGROUP_PARENT", str(base)))
    if not parent.exists():
        return None
    safe_id = "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in agent_id)
    cg = parent / f"bianbu-{safe_id}"
    try:
        cg.mkdir(exist_ok=True)
        # MemoryMax
        mem_bytes = _parse_size(memory_max)
        (cg / "memory.max").write_text(str(mem_bytes))
        # CPU 配额采用 cgroup v2 cpu.max：`quota period`，100%=period。
        period = 100000
        quota = "max"
        value = str(cpu_quota).strip().rstrip("%")
        if value and value != "max":
            quota = str(max(1, int(float(value) * period / 100)))
        if (cg / "cpu.max").exists():
            (cg / "cpu.max").write_text(f"{quota} {period}")
        if (cg / "pids.max").exists():
            value = str(tasks_max).strip()
            if value != "max":
                value = str(max(1, int(value)))
            (cg / "pids.max").write_text(value)
        if (cg / "io.weight").exists():
            (cg / "io.weight").write_text(str(max(1, min(10000, int(io_weight)))))
        return cg
    except (PermissionError, OSError, ValueError):
        return None


def _parse_size(s: str) -> int:
    s = s.strip().upper()
    mult = {"K": 1024, "M": 1024**2, "G": 1024**3}
    if s and s[-1] in mult:
        return int(float(s[:-1]) * mult[s[-1]])
    return int(s)


@dataclass
class LaunchResult:
    ok: bool
    pid: int = 0
    returncode: int | None = None
    output: str = ""
    reason: str = ""


def launch(spec: SandboxSpec, wait: bool = True, timeout: int = 30,
           interactive: bool = False) -> LaunchResult:
    """启动沙箱进程（Fail-Closed：任一步失败拒绝启动，SBX-05）。

    interactive=True：不捕获 IO，直接继承父进程 tty（stdin/stdout/stderr），
    用于交互式 TUI（如 hermes chat）；此时 output 不收集，timeout 被忽略。
    """
    if not shutil.which("bwrap"):
        return LaunchResult(False, reason="bwrap not available")
    if not spec.rw_dir.exists():
        spec.rw_dir.mkdir(parents=True, exist_ok=True)

    # 生产要求 cgroup 强制时 fail-closed；开发默认允许无特权降级。
    require_cgroup = os.environ.get("BIANBU_SECURITY_REQUIRE_CGROUP") == "1"
    cgroup_path = setup_cgroup(spec.agent_id, spec.memory_max, spec.cpu_quota,
                               spec.tasks_max, spec.io_weight,
                               require=require_cgroup)
    if require_cgroup and cgroup_path is None:
        return LaunchResult(False, reason="cgroup v2 resource enforcement unavailable")

    seccomp_fd = None
    fobj = None
    try:
        if spec.seccomp_path:
            if not Path(spec.seccomp_path).exists():
                # Fail-Closed：声明了 seccomp 却缺文件 → 拒绝
                return LaunchResult(False, reason=f"seccomp policy missing: {spec.seccomp_path}")
            fobj = open(spec.seccomp_path, "rb")
            seccomp_fd = fobj.fileno()

        argv = build_bwrap_argv(spec, seccomp_fd, interactive=interactive)
        # interactive：继承父进程 tty，不捕获 IO（供 TUI）；否则捕获输出
        popen_io = {} if interactive else dict(
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        try:
            proc = subprocess.Popen(
                argv,
                pass_fds=([seccomp_fd] if seccomp_fd is not None else ()),
                **popen_io,
            )
        except OSError as e:
            return LaunchResult(False, reason=f"bwrap spawn failed: {e}")

        # cgroup 限额只有把实际沙箱进程加入目标 cgroup 才生效。生产权限不足时
        # fail-closed；开发模式保留可运行降级但通过返回原因可审计。
        if cgroup_path is not None:
            try:
                (cgroup_path / "cgroup.procs").write_text(str(proc.pid))
            except (OSError, PermissionError) as e:
                if require_cgroup:
                    proc.kill()
                    proc.wait()
                    return LaunchResult(False, pid=proc.pid,
                                        reason=f"cgroup attach failed: {e}")

        if not wait:
            return LaunchResult(True, pid=proc.pid)

        if interactive:
            # 交互会话：阻塞直到用户退出，不设 timeout、不收集 output
            proc.wait()
            return LaunchResult(proc.returncode == 0, pid=proc.pid,
                                returncode=proc.returncode,
                                reason="" if proc.returncode == 0 else f"exit {proc.returncode}")
        try:
            out, _ = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            out, _ = proc.communicate()
            return LaunchResult(False, pid=proc.pid, output=out, reason="timeout")
        return LaunchResult(proc.returncode == 0, pid=proc.pid,
                            returncode=proc.returncode, output=out or "",
                            reason="" if proc.returncode == 0 else f"exit {proc.returncode}")
    finally:
        if fobj:
            fobj.close()


def cleanup(agent_id: str) -> None:
    """清理沙箱运行时资源（SBX-06）。bwrap 私有挂载随进程退出自动释放。"""
    cg = Path("/sys/fs/cgroup") / f"bianbu-{agent_id}"
    if cg.exists():
        try:
            cg.rmdir()
        except OSError:
            pass
    run_dir = config.SANDBOX_RUN_DIR / agent_id
    if run_dir.exists():
        shutil.rmtree(run_dir, ignore_errors=True)
