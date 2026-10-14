"""集中配置：路径与默认值（对齐设计 §4/§9 与 LLD §3.1 g 配置项）。

路径优先级：
  1) BIANBU_SEC_ROOT —— 显式指定的隔离根（测试/沙箱），所有路径收敛其下；
  2) 单项 env（BIANBU_ETC/RUN/LOG）覆盖；
  3) root（euid==0，生产 daemon）→ 系统路径 /etc/bianbu、/run/bianbu、/var/log/bianbu；
  4) 非 root（CLI/开发）→ 自动回退到用户级 XDG 目录（无需 root，不再 PermissionError）。
"""
from __future__ import annotations

import os
from pathlib import Path


def _is_root() -> bool:
    try:
        return os.geteuid() == 0
    except AttributeError:  # 非 POSIX
        return False


def _user_base() -> Path:
    """非 root 的用户级根：$XDG_DATA_HOME/bianbu-securityd 或 ~/.local/share/…。"""
    xdg = os.environ.get("XDG_DATA_HOME")
    base = Path(xdg) if xdg else (Path.home() / ".local/share")
    return base / "bianbu-securityd"


def _root(env: str, default: str) -> Path:
    base = os.environ.get("BIANBU_SEC_ROOT")
    if base:
        # 隔离模式：所有路径收敛到一个可写根目录下
        return Path(base) / default.lstrip("/")
    if os.environ.get(env):
        return Path(os.environ[env])
    if _is_root():
        return Path(default)
    # 非 root 自动回退用户级目录（把 /etc、/run、/var/log 映射到用户根下）
    return _user_base() / default.lstrip("/")


# —— 存储路径 ——
ETC_DIR = _root("BIANBU_ETC", "/etc/bianbu")
RUN_DIR = _root("BIANBU_RUN", "/run/bianbu")
LOG_DIR = _root("BIANBU_LOG", "/var/log/bianbu")

CAPABILITIES_DB = ETC_DIR / "capabilities.db"
AUDIT_DIR = LOG_DIR / "audit"
SANDBOX_RUN_DIR = RUN_DIR / "sandbox"
KEYS_DIR = ETC_DIR / "keys"

# Agent 私有目录根（沙箱根）
AGENTS_HOME = Path(
    os.environ.get(
        "BIANBU_AGENTS_HOME",
        str(Path.home() / ".local/share/bianbu-agents"),
    )
)

# —— Confirm 门禁 ——
CONFIRM_TIMEOUT_SEC = int(os.environ.get("BIANBU_CONFIRM_TIMEOUT", "30"))

# —— 审计 ——
AUDIT_SEGMENT_MAX_BYTES = 64 * 1024 * 1024  # 64MB 分段轮转
GENESIS_HASH = "GENESIS"

# —— D-Bus ——
BUS_NAME = "io.bianbu.Security"
OBJECT_PATH = "/io/bianbu/Security"
INTERFACE = "io.bianbu.Security"
# Security Runtime is exposed by the same securityd bus name, but on a
# separate object/interface.  It is deliberately not ``io.bianbu.Runtime``:
# that name belongs to the reference lifecycle service and is not the PA
# integration boundary.
RUNTIME_OBJECT_PATH = "/io/bianbu/Security/Runtime"
RUNTIME_INTERFACE = "io.bianbu.Security.Runtime"
# 事件契约版本。Runtime 以此值记录审计/状态迁移，升级时保持向后兼容。
SECURITY_POLICY_VERSION = os.environ.get("BIANBU_SECURITY_POLICY_VERSION", "1.0")

# —— UDS 数据面（ARCH-01）——
# 控制面走 D-Bus（≤4KB，判权/配置/信号）；数据面走 UDS（大载荷 PII 扫描、审计全文）
UDS_SOCKET_PATH = Path(
    os.environ.get("BIANBU_SEC_UDS", str(RUN_DIR / "securityd.sock")))
UDS_DBUS_THRESHOLD = int(os.environ.get("BIANBU_SEC_UDS_THRESHOLD", str(4 * 1024)))
UDS_MAX_PAYLOAD = int(os.environ.get("BIANBU_SEC_UDS_MAX", str(64 * 1024 * 1024)))
UDS_SOCKET_MODE = 0o660  # 同组可访问；再叠加 SO_PEERCRED uid 校验
UDS_RECV_TIMEOUT_SEC = float(os.environ.get("BIANBU_SEC_UDS_TIMEOUT", "10"))

# —— seccomp 黑名单（危险系统调用，FR-SEC-05/SBX-04）——
# 出厂默认不限制：只有管理员在「系统调用黑名单」里为该 Agent（或全局）追加过
# 条目时，才会生成并装载 seccomp 过滤器。没有强制基线，避免默认 Agent 平白
# 多一层内核过滤。
SECCOMP_DENYLIST: list[str] = []

# —— 沙箱资源默认值（cgroup v2，FR-SBX-02）——
DEFAULT_CPU_QUOTA = "100%"
DEFAULT_MEMORY_MAX = "2G"
DEFAULT_IO_WEIGHT = 100
DEFAULT_TASKS_MAX = 256


def ensure_dirs() -> None:
    """创建全部运行时目录（幂等）。"""
    for d in (ETC_DIR, RUN_DIR, LOG_DIR, AUDIT_DIR, SANDBOX_RUN_DIR, KEYS_DIR, AGENTS_HOME):
        d.mkdir(parents=True, exist_ok=True)
    try:
        KEYS_DIR.chmod(0o700)
    except PermissionError:
        pass
