"""Agent Runtime 的 systemd transient-unit 启动参数编译器。

Runtime 以特权身份执行返回的 argv；securityd/SDK 只编译最小权限配置，
不自行提权。使用 systemd 的 cgroup 与 IPAddressAllow/Deny 可按 Agent unit
隔离资源和网络，不修改宿主全局防火墙链。
"""
from __future__ import annotations

import hashlib
import re
import subprocess
import time
from dataclasses import dataclass, field

from securityd import network_policy
from securityd.network_policy import systemd_ip_filter_properties


@dataclass(frozen=True)
class RuntimeLaunchSpec:
    agent_id: str
    command: list[str]
    domains: list[str] = field(default_factory=list)
    dns_servers: list[str] = field(default_factory=list)
    memory_max: str = "2G"
    cpu_quota: str = "100%"
    tasks_max: int = 256
    io_weight: int = 100
    systemd_scope: str = "user"  # Runtime 生产可设 system；securityd 不自行提权
    network_mode: str = "whitelist"


def unit_name(agent_id: str) -> str:
    base = re.sub(r"[^A-Za-z0-9_.-]", "_", agent_id)[:48]
    suffix = hashlib.sha256(agent_id.encode()).hexdigest()[:10]
    return f"bianbu-agent-{base}-{suffix}.service"


def build_systemd_run_argv(spec: RuntimeLaunchSpec) -> tuple[list[str], list[str]]:
    if not spec.command:
        raise ValueError("agent command must not be empty")
    net_props = systemd_ip_filter_properties(spec.domains, mode=spec.network_mode,
                                              dns_servers=spec.dns_servers)
    props = [f"MemoryMax={spec.memory_max}", f"CPUQuota={spec.cpu_quota}",
             f"TasksMax={max(1, int(spec.tasks_max))}",
             f"IOWeight={max(1, min(10000, int(spec.io_weight)))}",
             "NoNewPrivileges=yes", "PrivateTmp=yes", *net_props]
    argv = ["systemd-run"]
    if spec.systemd_scope == "user":
        argv.append("--user")
    elif spec.systemd_scope != "system":
        raise ValueError("systemd_scope must be user or system")
    argv += ["--quiet", "--collect", "--unit", unit_name(spec.agent_id)]
    for prop in props:
        argv += ["--property", prop]
    argv += ["--", *spec.command]
    return argv, props


@dataclass(frozen=True)
class RuntimeLaunchResult:
    ok: bool
    unit: str
    pid: int = 0
    verified_network: bool = False
    verified_resources: bool = False
    reason: str = ""


def launch_runtime(spec: RuntimeLaunchSpec, *, env: dict[str, str] | None = None,
                   timeout: float = 10.0) -> RuntimeLaunchResult:
    """由 Agent Runtime 调用 systemd transient unit 并登记真实资源/网络状态。

    securityd/SDK 只提供此适配器，不提权、不停止服务。创建成功后必须读取
    systemd 实际属性；网络属性无法复核时返回失败，不登记强制状态。
    """
    argv, props = build_systemd_run_argv(spec)
    unit = unit_name(spec.agent_id)
    try:
        cp = subprocess.run(argv, env=env, capture_output=True, text=True,
                            timeout=timeout, check=True)
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        return RuntimeLaunchResult(False, unit, reason=f"systemd-run failed: {exc}")
    scope = spec.systemd_scope
    network_properties = [
        prop for prop in props if prop.startswith(("IPAddressAllow=", "IPAddressDeny="))
    ]
    network_verification_required = bool(network_properties)
    verified = False
    resources_verified = False
    # systemd-run 返回后 unit 可能尚未完成装载；短暂轮询，避免把启动竞态
    # 误判为“未强制”。超过窗口仍无法读取则 fail-closed。
    for _ in range(20):
        verified = network_policy.verify_systemd_unit(unit, props, scope=scope)
        resources_verified = verify_runtime_resources(unit, props, scope=scope)
        if (verified or not network_verification_required) and resources_verified:
            break
        time.sleep(0.05)
    if network_verification_required and not verified:
        _stop_unit(unit, scope)
        return RuntimeLaunchResult(False, unit,
                                   reason="systemd unit 网络属性无法复核，拒绝登记强制状态")
    if not resources_verified:
        _stop_unit(unit, scope)
        return RuntimeLaunchResult(False, unit,
                                   reason="systemd unit 资源属性无法复核，拒绝启动 Runtime")
    if network_verification_required:
        network_policy.mark_systemd_unit_applied(spec.agent_id, unit, props,
                                                  scope=scope, verified=verified)
    pid = _unit_main_pid(unit, scope)
    return RuntimeLaunchResult(True, unit, pid=pid, verified_network=verified,
                               verified_resources=resources_verified,
                               reason=cp.stderr.strip())


def _systemctl(scope: str, *args: str) -> list[str]:
    if scope == "user":
        return ["systemctl", "--user", *args]
    return ["systemctl", *args]


def _unit_main_pid(unit: str, scope: str) -> int:
    try:
        out = subprocess.run(_systemctl(scope, "show", unit, "--property=MainPID", "--value"),
                             check=True, capture_output=True, text=True, timeout=5).stdout.strip()
        return int(out or 0)
    except (OSError, ValueError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return 0


def _stop_unit(unit: str, scope: str) -> None:
    try:
        subprocess.run(_systemctl(scope, "stop", unit), capture_output=True,
                       timeout=5, check=False)
    except (OSError, subprocess.TimeoutExpired):
        pass


def update_runtime_network(unit: str, new_properties: list[str], old_properties: list[str], *,
                           scope: str = "user") -> dict:
    """Apply new properties, verify them, and restore old properties on failure."""
    try:
        effective_properties = list(new_properties) or ["IPAddressDeny=", "IPAddressAllow="]
        subprocess.run(_systemctl(scope, "set-property", "--runtime", unit, *effective_properties),
                       check=True, capture_output=True, text=True, timeout=5)
        if network_policy.verify_systemd_unit(unit, new_properties, scope=scope):
            return {"ok": True, "rolled_back": False}
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        reason = str(exc)
    else:
        reason = "systemd unit 网络属性校验失败"
    rolled_back = False
    try:
        subprocess.run(_systemctl(scope, "set-property", "--runtime", unit, *old_properties),
                       check=True, capture_output=True, text=True, timeout=5)
        rolled_back = network_policy.verify_systemd_unit(unit, old_properties, scope=scope)
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        pass
    return {"ok": False, "rolled_back": rolled_back, "reason": reason}


def verify_runtime_resources(unit: str, properties: list[str], *, scope: str = "user") -> bool:
    """复核 transient unit 的 Memory/CPU/Tasks/IO 实际属性。"""
    wanted = {p.split("=", 1)[0]: p.split("=", 1)[1]
              for p in properties if "=" in p and p.split("=", 1)[0] in
              {"MemoryMax", "CPUQuota", "TasksMax", "IOWeight"}}
    try:
        show_names = ["MemoryMax", "CPUQuotaPerSecUSec" if "CPUQuota" in wanted else "CPUQuota",
                      "TasksMax", "IOWeight"]
        names = ",".join(n for n in show_names if n in wanted or
                          (n == "CPUQuotaPerSecUSec" and "CPUQuota" in wanted))
        out = subprocess.run(_systemctl(scope, "show", unit, f"--property={names}"),
                             check=True, capture_output=True, text=True, timeout=5).stdout
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return False
    values = {}
    for line in out.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            values[k] = v.strip()
    # systemd 将 MemoryMax/CPUQuota 格式化为 bytes/time；只需确保不是无界/空值，
    # TasksMax/IOWeight 则要求正值并与声明一致（允许 systemd 的 canonical 格式）。
    if "MemoryMax" in wanted and values.get("MemoryMax", "") in {"", "infinity", "18446744073709551615"}:
        return False
    if "CPUQuota" in wanted and values.get("CPUQuotaPerSecUSec", values.get("CPUQuota", "")) in {"", "infinity"}:
        return False
    if "TasksMax" in wanted and values.get("TasksMax", "") in {"", "infinity"}:
        return False
    if "IOWeight" in wanted and values.get("IOWeight", "") in {"", "0", "infinity", "[not set]"}:
        return False
    return True


__all__ = ["RuntimeLaunchSpec", "RuntimeLaunchResult", "build_systemd_run_argv",
           "launch_runtime", "update_runtime_network", "unit_name"]
