"""Security Runtime 执行策略模型与模式裁决。

策略只描述安全边界和执行后端，不创建或停止 Agent 进程；实际进程控制由
PA ``bianbu-agent-runtime`` 完成。Agent 只提交标识信息，最终模式由 securityd
根据自己保存的 per-Agent execution_mode 裁决——执行模式是安全边界，不随
Agent 声明来回漂移。
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from collections.abc import Mapping
from typing import Any

from securityd import config, network_policy
from securityd.models import Policy

VALID_MODES = frozenset({"auto", "sandbox", "host"})
_AGENT_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@+-]{0,254}$")


class RuntimePolicyError(ValueError):
    """执行模式或策略参数非法。"""


def _text(value: object, field: str, *, max_len: int = 4096) -> str:
    result = str(value or "").strip()
    if not result:
        raise RuntimePolicyError(f"{field} 必须是非空字符串")
    if len(result) > max_len:
        raise RuntimePolicyError(f"{field} 超过 {max_len} 字符")
    return result


def _runtime_path(value: object, field: str, *, max_len: int = 4096) -> Path:
    """Validate a Runtime path without resolving it through securityd's view.

    ``bianbu-securityd`` runs with ``ProtectHome=yes``.  A user Runtime's
    ``~/.bianbu-agent`` and socket directory are therefore intentionally not
    visible in the daemon's mount namespace.  Calling ``Path.exists()`` or
    ``Path.is_file()`` here would reject every legitimate Worker even though
    the Runtime process can validate and mount the path itself.  Keep the
    securityd-side checks lexical and deterministic; the trusted Runtime
    backend performs the kernel/filesystem existence check immediately before
    spawning the Worker.
    """
    raw = _text(value, field, max_len=max_len)
    path = Path(raw).expanduser()
    if not path.is_absolute():
        raise RuntimePolicyError(f"{field} 必须是绝对路径")
    if ".." in path.parts:
        raise RuntimePolicyError(f"{field} 不得包含父目录片段")
    # ``normpath`` is lexical and does not require visibility of the target.
    normalized = Path(os.path.normpath(str(path)))
    if not normalized.is_absolute() or ".." in normalized.parts:
        raise RuntimePolicyError(f"{field} 路径非法")
    return normalized


@dataclass(frozen=True)
class ExecutionDecision:
    agent_id: str
    requested_mode: str
    effective_mode: str
    backend: str
    sandbox_required: bool
    reason: str
    policy: dict[str, Any]

    @property
    def policy_json(self) -> str:
        return json.dumps(self.policy, ensure_ascii=False, sort_keys=True,
                          separators=(",", ":"))


def _same_or_below(candidate: object, path: object) -> bool:
    """``candidate`` 是否等于 ``path`` 或位于其下（词法比较）。"""
    base = PurePosixPath(str(path))
    target = PurePosixPath(str(candidate))
    return target == base or base in target.parents


def _declared_boundary(engine, agent_id: str, *, trusted: bool) -> dict:
    """用 securityd 自己的判定推导 host / sandbox。

    优先问引擎（它同时能看到网络与 syscall 存储）；引擎没提供时退回策略本身
    能看到的能力风险，宁可保守地选沙箱。
    """
    getter = getattr(engine, "execution_mode_for", None)
    if callable(getter):
        try:
            value = getter(agent_id)
        except (TypeError, ValueError):
            value = None
        if isinstance(value, Mapping):
            mode = str(value.get("mode", "sandbox")).strip().lower()
            reasons = [str(item) for item in (value.get("reasons") or [])]
            if mode not in {"host", "sandbox"}:
                mode = "sandbox"
            return {"mode": mode, "reasons": reasons}
    return {"mode": "sandbox" if not trusted else "host", "reasons": []}


def build_execution_policy(engine, agent_id: str, requested_mode: str = "auto",
                           request: dict[str, Any] | None = None) -> ExecutionDecision:
    aid = _text(agent_id, "agent_id", max_len=255)
    if not _AGENT_ID.fullmatch(aid):
        raise RuntimePolicyError("agent_id 含非法字符")
    # ``requested_mode`` is retained only so the legacy D-Bus signature keeps
    # working; it is deliberately ignored. Whether this Agent needs a sandbox
    # follows from the security settings it declares, so a caller cannot widen
    # its own boundary by asking for ``host``.
    supplied = str(requested_mode or "auto").strip().lower()
    if supplied not in VALID_MODES:
        raise RuntimePolicyError(
            f"requested_mode 非法：{supplied!r}（可选 auto、sandbox、host）")
    requested = "auto"
    request = dict(request or {})
    worker_agent_id = str(request.get("worker_agent_id", "")).strip() or aid
    if not _AGENT_ID.fullmatch(worker_agent_id):
        raise RuntimePolicyError("worker_agent_id 含非法字符")

    permissions = engine.get_capabilities(aid)
    # A tool that is denied or must be confirmed is high-consequence by
    # construction: force the sandbox so a mis-answer cannot escape it.
    high_risk = any(str(p.get("policy")) in {Policy.DENY.value, Policy.ASK.value}
                    for p in permissions)
    manifest = engine.registry.get_manifest_info(aid)
    # Only an installed/active manifest with a fixed entrypoint is a trust
    # anchor. The caller cannot provide or replace the command.
    manifest_trusted = bool(manifest and str(manifest.get("status", "active")) == "active")
    entrypoint: list[str] = []
    try:
        getter = getattr(engine.registry, "get_entrypoint", None)
        candidate = getter(aid) if callable(getter) else []
        if isinstance(candidate, list) and candidate and all(str(item).strip() for item in candidate):
            entrypoint = [str(item) for item in candidate]
    except (TypeError, ValueError):
        entrypoint = []
    trusted_runtime = manifest_trusted and bool(entrypoint)
    # 沙箱与否来自「声明了什么安全设置」，不是人指定的开关。
    boundary = _declared_boundary(engine, aid, trusted=trusted_runtime)
    requested = "sandbox" if boundary["mode"] == "sandbox" else "host"
    reason_detail = "、".join(boundary["reasons"])

    if requested == "sandbox" and reason_detail:
        effective = "sandbox"
        reason = f"已声明 {reason_detail}，需要沙箱落实"
    elif requested == "sandbox":
        effective = "sandbox"
        reason = "缺少可信 manifest 或固定启动程序，策略要求 sandbox"
    elif trusted_runtime and not high_risk:
        effective = "host"
        reason = "未声明额外安全设置，使用 host"
    else:
        effective = "sandbox"
        reason = "存在 ask/deny 工具策略，误答不得逃出沙箱"

    sandbox_required = effective == "sandbox"
    backend = "bwrap" if sandbox_required else "host-process"
    seccomp_path = ""
    netfilter_rules = ""
    # Entrypoint 是已登记 Agent manifest 的一部分，不能由 PrepareStart
    # 调用方动态传入。旧 manifest 没有 [runtime].entrypoint 时返回空值，
    # 由 PA Runtime 的开发态协调器拒绝生产启动，避免退化成任意命令执行。
    getter = getattr(engine, "_effective_network_policy", None)
    if getter is None:
        getter = getattr(engine.registry, "get_network_policy", lambda _aid: None)
    configured = getter(worker_agent_id)
    if configured:
        network_mode = str(configured.get("mode", "allow_all"))
        allowed_domains = list(configured.get("domains", []))
        network_version = int(configured.get("version", 0))
    else:
        # Agents created before network_policy was persisted have no row.
        # Match the registration default instead of silently making a legacy
        # Agent offline during Runtime startup.
        network_mode = "allow_all"
        allowed_domains = []
        network_version = 0
    syscall_policy_version = 0
    # syscall denylist 追加项由管理员按逻辑 Agent（worker_agent_id）配置，
    # 过滤器与 applied 版本也必须按逻辑 Agent 生成/标记；按 lease 主体
    # （com.bianbu.runtime）标记会让逻辑 Agent 的 pending_restart 永远为 true。
    if sandbox_required:
        seccomp_path, netfilter_rules = engine.build_sandbox_policy(worker_agent_id)
        getter = getattr(engine, "get_syscall_policy", None)
        if callable(getter):
            import platform
            snapshot = getter(worker_agent_id, platform.machine())
            syscall_policy_version = int(snapshot["applied_policy_version"])
    else:
        # host-process Worker 同样消费版本化 syscall denylist（mandatory 基线 +
        # 管理员追加项），并把 policy_version 标记为已应用。修复前 host 后端
        # 没有 seccomp_profile，SetAgentSyscallPolicy 后 pending_restart 永远为
        # true，追加项对 host Worker 不生效（验收缺陷 D-10）。engine 无
        # build_seccomp_profile（旧引擎/测试桩）时保持无 profile 的旧行为。
        builder = getattr(engine, "build_seccomp_profile", None)
        if callable(builder):
            seccomp_path, syscall_policy_version = builder(worker_agent_id)
    worker_data_root = str(request.get("worker_data_root", "")).strip()
    if worker_data_root:
        data_root = _runtime_path(worker_data_root, "worker_data_root")
    else:
        data_root = None
    worker_socket_root = str(request.get("worker_socket_root", "")).strip()
    if worker_socket_root:
        socket_root = _runtime_path(worker_socket_root, "worker_socket_root")
    else:
        socket_root = None
    worker_config_path = str(request.get("worker_config_path", "")).strip()
    config_path = (_runtime_path(worker_config_path, "worker_config_path")
                   if worker_config_path else None)
    if config_path is not None:
        if data_root is not None and not config_path.is_relative_to(data_root):
            raise RuntimePolicyError("worker_config_path 必须位于 worker_data_root 内")
    security_uds = str(request.get("security_uds", "")).strip()
    security_uds_path = (_runtime_path(security_uds, "security_uds")
                         if security_uds else None)
    securityd_home = str(request.get("securityd_home", "")).strip()
    securityd_home_path = (_runtime_path(securityd_home, "securityd_home")
                           if securityd_home else None)
    data_root = data_root or (config.AGENTS_HOME / aid).resolve()
    data_target = "/home/agent"
    socket_target = "/run/bianbu-agent/instances"
    # Agent package/configuration bytes are an integrity boundary: bind the
    # complete data root read-only and overlay only runtime state directories.
    # The control plane owns sessions/runs metadata, so those roots are not
    # writable in the Worker namespace.
    readonly_bind_mounts = [
        {"host": str(data_root), "target": data_target},
    ]
    writable_mounts = [
        {"host": str(data_root / "workspace"),
         "target": f"{data_target}/workspace"},
        {"host": str(data_root / "sessions" / "checkpoints"),
         "target": f"{data_target}/sessions/checkpoints"},
        {"host": str(data_root / "runtime" / "worker"),
         "target": f"{data_target}/runtime/worker"},
        {"host": str(data_root / "logs" / "provider-capture"),
         "target": f"{data_target}/logs/provider-capture"},
    ]
    if socket_root is not None:
        writable_mounts.append({"host": str(socket_root), "target": socket_target})
    # 安全权限设置：管理员声明的可读范围与可写范围，编译成逐路径的
    # 只读绑定和读写绑定。securityd 带 ProtectHome，看不到用户 Runtime 的目录，
    # 因此这里只做词法校验，存在性由可信的 Runtime 后端在挂载前复核（不存在
    # 即 fail-closed 拒绝启动）。路径必须绝对、无父目录片段、去重。
    empty_range = {"include": [], "exclude": []}
    permission_settings = {"read": dict(empty_range), "write": dict(empty_range)}
    settings_getter = getattr(engine, "get_permission_settings", None)
    if callable(settings_getter):
        try:
            permission_settings = dict(settings_getter(aid) or {})
        except (TypeError, ValueError):
            permission_settings = {"read": dict(empty_range), "write": dict(empty_range)}

    def _range(group: str) -> tuple[list[str], list[str]]:
        value = permission_settings.get(group) or {}
        if isinstance(value, dict):
            include = [str(p) for p in (value.get("include") or []) if str(p).strip()]
            exclude = [str(p) for p in (value.get("exclude") or []) if str(p).strip()]
            return include, exclude
        # Legacy row: a bare path list means "include everything here".
        return [str(p) for p in (value or []) if str(p).strip()], []

    declared_read, read_exclude = _range("read")
    declared_write, write_exclude = _range("write")
    for path in declared_read:
        readonly_bind_mounts.append({"host": path, "target": path})
    for path in declared_write:
        writable_mounts.append({"host": path, "target": path})
    # Exclusions are final-boundary overrides, applied after the includes so a
    # nested "allow the parent, deny one child" declaration wins regardless of
    # ordering. Read exclusions hide the path completely; write exclusions
    # keep it readable but not writable (a read-only rebind).
    read_only_overrides = list(read_exclude)
    inaccessible_overrides = list(read_exclude)
    for path in write_exclude:
        read_only_overrides.append(path)
    # A path denied for reading must not be re-opened for writing.
    writable_mounts = [
        item for item in writable_mounts
        if not any(_same_or_below(item["host"], path) for path in inaccessible_overrides)
    ]
    if security_uds_path is not None:
        readonly_bind_mounts.append({"host": str(security_uds_path),
                                     "target": "/run/bianbu/securityd.sock"})
    if securityd_home_path is not None:
        readonly_bind_mounts.append({"host": str(securityd_home_path),
                                     "target": "/opt/bianbu-securityd"})
    config_target = data_target
    if config_path is not None and data_root is not None:
        config_target = f"{data_target}/{config_path.relative_to(data_root).as_posix()}"
        # The signed manifest stores the canonical Worker argv (the path that
        # exists inside bwrap). Host mode must instead execute the exact
        # installed host config; never pass the namespace-only path to a host
        # process. Accept the legacy host-path form too for old manifests.
        entrypoint = [
            (str(config_path) if effective == "host" and item == config_target
             else config_target if item == str(config_path) else item)
            for item in entrypoint
        ]
    policy: dict[str, Any] = {
        "version": 1,
        "agent_id": aid,
        "worker_agent_id": worker_agent_id,
        "requested_mode": requested,
        "effective_mode": effective,
        "backend": backend,
        "sandbox_required": sandbox_required,
        "manifest_version": str((manifest or {}).get("version", "")),
        "entrypoint": entrypoint,
        "readonly_mounts": ["/usr", "/etc"],
        "readonly_bind_mounts": readonly_bind_mounts,
        "writable_mounts": writable_mounts,
        "permissions": {
            "read": {"include": declared_read, "exclude": read_exclude},
            "write": {"include": declared_write, "exclude": write_exclude},
        },
        "read_only_overrides": read_only_overrides,
        "inaccessible_overrides": inaccessible_overrides,
        "worker_config_path": config_target,
        "worker_socket_root": socket_target,
        "deny_paths": ["/etc/shadow", "/etc/sudoers", "/root", "/etc/ssh"],
        "namespaces": (["user", "pid", "mnt", "ipc", "uts", "net"]
                        if sandbox_required else []),
        "capabilities": [],
        "seccomp_profile": {"path": seccomp_path, "policy_version": syscall_policy_version} if seccomp_path else None,
        "network": {
            "mode": network_mode,
            "domains": allowed_domains,
            # Keep lease metadata aligned with the effective enforcement:
            # allow_all/learning produce no default-deny network filter,
            # whereas whitelist/deny_all reject undeclared egress.
            "default": "allow" if network_mode in {"allow_all", "learning"} else "drop",
            **({"observe": True} if configured and configured.get("observe") else {}),
            "rules_path": netfilter_rules,
            "version": network_version,
        },
        "resources": {
            "memory_max": config.DEFAULT_MEMORY_MAX,
            "cpu_quota": config.DEFAULT_CPU_QUOTA,
            "tasks_max": config.DEFAULT_TASKS_MAX,
            "io_weight": config.DEFAULT_IO_WEIGHT,
        },
        "environment_allowlist": [
            "BIANBU_AGENT_ID", "BIANBU_PA_AGENT_ID",
            "BIANBU_RUNTIME_ENDPOINT", "BIANBU_SECURITY_ENDPOINT",
            "BIANBU_SEC_UDS", "BIANBU_SECURITY_CLIENT_DIR",
            "BIANBU_SEC_ROOT",
            "BIANBU_SECURITYD_HOME", "BIANBU_RUNTIME_MODE",
            "BIANBU_RUNTIME_SECURITY", "BIANBU_SECURITY",
            # Supervisor-issued Worker identity. These are non-secret lease
            # coordinates used for Hello/attestation and cannot be supplied
            # from an HTTP request; the Runtime backend injects them after the
            # policy has been selected.
            "BIANBU_RUNTIME_ROLE", "BIANBU_WORKER_INSTANCE_ID",
            "BIANBU_WORKER_SOCKET", "BIANBU_WORKER_AGENT_ID",
            "BIANBU_WORKER_SECURITY_AGENT_ID",
            "BIANBU_WORKER_SOCKET_TARGET", "BIANBU_WORKER_CONFIG_PATH",
            "BIANBU_WORKER_CWD_TARGET",
            "BIANBU_RUNTIME_DATA_DIR", "BIANBU_WORKER_LEASE_ID",
            "BIANBU_WORKER_EFFECTIVE_MODE", "BIANBU_WORKER_BACKEND",
            "BIANBU_WORKER_RPC_TOKEN",
            "BIANBU_CONTAINER_ID", "BIANBU_SANDBOX_ACTIVE",
        ],
        "host_constraints": {
            "resource_cgroup_required": True,
            "port_proxy_required": True,
            "egress_enforcement": "security-broker-or-ebpf",
            # Host mode uses systemd's private mount namespace plus
            # ProtectSystem/ProtectHome/ReadWritePaths as the file boundary.
            # Landlock remains an optional hardening layer on kernels that
            # expose it, but a plain unrestricted Popen is never acceptable.
            "file_boundary_required": True,
            "landlock_required": False,
            "seccomp_required": False,
            "system_dbus_allowed": False,
            "working_directory": str(data_root) if data_root is not None else "",
            "sandbox_working_directory": data_target,
        },
        "policy_reason": reason,
    }
    return ExecutionDecision(aid, requested, effective, backend,
                             sandbox_required, reason, policy)


__all__ = ["ExecutionDecision", "RuntimePolicyError", "VALID_MODES",
           "build_execution_policy"]
