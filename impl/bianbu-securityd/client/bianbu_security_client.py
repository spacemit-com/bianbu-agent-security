"""bianbu_security_client.py — hermes agent / 第三方调用 bianbu-securityd 的 D-Bus 客户端封装。

对齐设计 §7.3。支持系统总线（生产）或会话总线（测试，BIANBU_SEC_SESSION=1）。
"""
from __future__ import annotations

import os

# D-Bus is a control-plane dependency; managed Workers use only lease-bound UDS.

SECURITY_BUS_NAME = "io.bianbu.Security"
SECURITY_OBJ_PATH = "/io/bianbu/Security"
SECURITY_INTERFACE = "io.bianbu.Security"
RUNTIME_OBJECT_PATH = "/io/bianbu/Security/Runtime"
RUNTIME_INTERFACE = "io.bianbu.Security.Runtime"


def _get_proxy():
    import dbus

    bus = dbus.SessionBus() if os.environ.get("BIANBU_SEC_SESSION") == "1" else dbus.SystemBus()
    return bus.get_object(SECURITY_BUS_NAME, SECURITY_OBJ_PATH)


def _get_runtime_proxy():
    import dbus

    bus = dbus.SessionBus() if os.environ.get("BIANBU_SEC_SESSION") == "1" else dbus.SystemBus()
    return bus.get_object(SECURITY_BUS_NAME, RUNTIME_OBJECT_PATH)


def _sv(values: dict | None) -> dbus.Dictionary:
    import dbus

    return dbus.Dictionary({str(k): dbus.String(str(v)) for k, v in (values or {}).items()},
                            signature="sv")


def _runtime_dict(value) -> dict:
    import dbus

    return {str(k): (bool(v) if isinstance(v, dbus.Boolean) else
                     int(v) if isinstance(v, (dbus.Int64, dbus.Int32, int)) and
                     not isinstance(v, bool) else str(v))
            for k, v in dict(value).items()}


def _worker_uds_enabled() -> bool:
    """Whether this process is a supervised Worker using the lease-bound UDS."""
    return os.environ.get("BIANBU_WORKER_MANAGED", "") == "1"


def _worker_uds_call(op: str, **payload) -> dict:
    """Call the restricted UDS data plane with supervisor-issued identity.

    A managed Worker must never fall back to a process-level D-Bus binding:
    its PID is intentionally different from the control plane.  Missing lease
    coordinates are therefore a hard error, not an optional compatibility path.
    """
    required = ("BIANBU_WORKER_INSTANCE_ID", "BIANBU_WORKER_LEASE_ID")
    missing = [name for name in required if not os.environ.get(name, "").strip()]
    if missing:
        raise RuntimeError(f"managed Worker missing identity: {', '.join(missing)}")
    from bianbu_security_uds import UdsClient
    request = dict(payload)
    request.update({
        "_worker_instance_id": os.environ["BIANBU_WORKER_INSTANCE_ID"],
        "_worker_lease_id": os.environ["BIANBU_WORKER_LEASE_ID"],
        "_worker_security_agent_id": os.environ.get(
            "BIANBU_WORKER_SECURITY_AGENT_ID", ""),
    })
    with UdsClient() as client:
        response = client.call({"op": op, **request})
    if response.get("ok") is not True:
        raise RuntimeError(str(response.get("error") or f"securityd UDS {op} failed"))
    return dict(response)


def prepare_runtime_start(agent_id: str, requested_mode: str = "auto",
                          **request) -> dict:
    """Ask security.runtime for a one-shot execution lease and policy."""
    proxy = _get_runtime_proxy()
    payload = {"requested_mode": requested_mode, **request}
    return _runtime_dict(proxy.PrepareStart(
        str(agent_id), _sv(payload), dbus_interface=RUNTIME_INTERFACE))


def get_runtime_sandbox_policy(lease_id: str) -> dict:
    return _runtime_dict(_get_runtime_proxy().GetSandboxPolicy(
        str(lease_id), dbus_interface=RUNTIME_INTERFACE))


def commit_runtime_start(lease_id: str, instance_id: str, pid: int,
                         cgroup_path: str, attestation: dict | None = None) -> dict:
    import dbus

    return _runtime_dict(_get_runtime_proxy().CommitStart(
        str(lease_id), str(instance_id), dbus.Int64(int(pid)), str(cgroup_path),
        _sv(attestation), dbus_interface=RUNTIME_INTERFACE))


def abort_runtime_start(lease_id: str, reason: str) -> bool:
    return bool(_get_runtime_proxy().AbortStart(str(lease_id), str(reason),
                                                dbus_interface=RUNTIME_INTERFACE))


def stop_runtime_instance(lease_id: str, instance_id: str, reason: str) -> dict:
    """Runtime 正常停止 Worker 后收敛该 lease/instance（不撤销整个 Agent）。"""
    return _runtime_dict(_get_runtime_proxy().StopInstance(
        str(lease_id), str(instance_id), str(reason), dbus_interface=RUNTIME_INTERFACE))


def revoke_runtime_agent(agent_id: str, reason: str) -> bool:
    return bool(_get_runtime_proxy().RevokeAgent(str(agent_id), str(reason),
                                                 dbus_interface=RUNTIME_INTERFACE))

def register_agent(agent_id: str, metadata: dict | None = None) -> dict:
    return _runtime_dict(_get_proxy().RegisterAgent(str(agent_id), _sv(metadata), dbus_interface=SECURITY_INTERFACE))

def unregister_agent(agent_id: str) -> bool:
    return bool(_get_proxy().UnregisterAgent(str(agent_id), dbus_interface=SECURITY_INTERFACE))

def get_capabilities(agent_id: str) -> list[dict]:
    """已登记的工具策略行；控制台据此只补缺失项，不覆盖已收紧的策略。"""
    if _worker_uds_enabled():
        return list(_worker_uds_call("capabilities.list", agent_id=str(agent_id)).get("capabilities", []))
    proxy = _get_proxy()
    return [dict(p) for p in proxy.GetCapabilities(agent_id, dbus_interface=SECURITY_INTERFACE)]


def get_runtime_state(agent_id: str) -> dict:
    return _runtime_dict(_get_runtime_proxy().GetRuntimeState(
        str(agent_id), dbus_interface=RUNTIME_INTERFACE))


def list_runtime_instances(agent_id: str) -> list[dict]:
    return [_runtime_dict(row) for row in _get_runtime_proxy().ListRuntimeInstances(
        str(agent_id), dbus_interface=RUNTIME_INTERFACE)]


def verify_manifest(agent_pkg_path: str) -> dict:
    proxy = _get_proxy()
    valid, reason, perms = proxy.VerifyManifest(agent_pkg_path, dbus_interface=SECURITY_INTERFACE)
    return {"valid": bool(valid), "reason": str(reason),
            "permissions": [dict(p) for p in perms]}


def verify_code_package(pkg_path: str, kind: str = "hook") -> dict:
    """D-6：代码包（hook / tool / skill 目录）安装期签名校验。

    返回 {allowed, signed, valid, digest, policy, reason, key_id}。
    allowed=False 时调用方应拒绝安装，reason 可直接展示给用户。
    """
    proxy = _get_proxy()
    if __package__:
        from .bianbu_security_codesign import describe_code_package
    else:
        from bianbu_security_codesign import describe_code_package
    digest, signature = describe_code_package(pkg_path)
    d = proxy.VerifyCodeDigest(digest, signature, kind,
                               dbus_interface=SECURITY_INTERFACE)
    out = {k: (bool(v) if isinstance(v, bool) else str(v)) for k, v in dict(d).items()}
    for k in ("allowed", "signed", "valid"):
        # D-Bus 侧已是 Boolean，但走 str 化的旧代理时会拿到 "True"/"False"
        if isinstance(out.get(k), str):
            out[k] = out[k].lower() in ("true", "1")
    return out


def register_capabilities(agent_id: str, perms: list) -> bool:
    proxy = _get_proxy()
    # Runtime 启动阶段先建立 caller 绑定；管理员配置端若已绑定则幂等。
    proxy.BindAgent(agent_id, dbus_interface=SECURITY_INTERFACE)
    import dbus

    dperms = [dbus.Dictionary({k: dbus.String(str(v)) for k, v in p.items()}, signature="sv")
              for p in perms]
    return bool(proxy.RegisterCapabilities(agent_id, dperms, dbus_interface=SECURITY_INTERFACE))


def bind_agent(agent_id: str) -> bool:
    if _worker_uds_enabled():
        # Worker identity is established by the committed Runtime lease, not
        # by replacing the control-plane agent_binding row.
        result = _worker_uds_call("worker.identity", agent_id=str(agent_id))
        return bool(result.get("authorized"))
    proxy = _get_proxy()
    return bool(proxy.BindAgent(agent_id, dbus_interface=SECURITY_INTERFACE))


def bind_agent_v2(agent_id: str, context: dict | None = None) -> bool:
    if _worker_uds_enabled():
        result = _worker_uds_call("worker.identity", agent_id=str(agent_id),
                                  session_id=str((context or {}).get("session_id", "")),
                                  run_id=str((context or {}).get("run_id", "")))
        return bool(result.get("authorized"))
    proxy = _get_proxy()
    import dbus

    dctx = dbus.Dictionary({str(k): dbus.String(str(v))
                            for k, v in (context or {}).items()}, signature="sv")
    return bool(proxy.BindAgentV2(agent_id, dctx, dbus_interface=SECURITY_INTERFACE))


def reset_agent_binding(agent_id: str, reason: str = "") -> bool:
    """Clear a stale persisted caller binding (admin/root only)."""
    proxy = _get_proxy()
    return bool(proxy.ResetAgentBinding(str(agent_id), str(reason),
                                        dbus_interface=SECURITY_INTERFACE))


def check_permission(agent_id: str, capability: str, scope: str = "") -> int:
    if _worker_uds_enabled():
        return int(_worker_uds_call("permission.check", agent_id=str(agent_id),
                                    capability=str(capability), scope=str(scope)).get("decision", 2))
    proxy = _get_proxy()
    return int(proxy.CheckPermission(agent_id, capability, scope, dbus_interface=SECURITY_INTERFACE))


def check_permission_v2(agent_id: str, capability: str, scope: str = "",
                        context: dict | None = None) -> int:
    if _worker_uds_enabled():
        ctx = dict(context or {})
        return int(_worker_uds_call(
            "permission.check", agent_id=str(agent_id), capability=str(capability),
            scope=str(scope), session_id=str(ctx.get("session_id", "")),
            run_id=str(ctx.get("run_id", ""))).get("decision", 2))
    proxy = _get_proxy()
    import dbus

    dctx = dbus.Dictionary({str(k): dbus.String(str(v))
                            for k, v in (context or {}).items()}, signature="sv")
    return int(proxy.CheckPermissionV2(agent_id, capability, scope, dctx,
                                      dbus_interface=SECURITY_INTERFACE))


def grant_session_trust_v2(agent_id: str, capability: str, scope: str = "",
                           context: dict | None = None) -> bool:
    """记录 PA 已完成 HITL 批准的 once_per_session 信任。"""
    if _worker_uds_enabled():
        ctx = dict(context or {})
        return bool(_worker_uds_call(
            "session.trust", agent_id=str(agent_id), capability=str(capability),
            scope=str(scope), session_id=str(ctx.get("session_id", "")),
            run_id=str(ctx.get("run_id", ""))).get("accepted"))
    proxy = _get_proxy()
    import dbus

    dctx = dbus.Dictionary({str(k): dbus.String(str(v))
                            for k, v in (context or {}).items()}, signature="sv")
    return bool(proxy.GrantSessionTrustV2(agent_id, capability, scope, dctx,
                                          dbus_interface=SECURITY_INTERFACE))


def request_confirm(agent_id: str, capability: str, detail: str, timeout: float = 60.0) -> bool:
    if _worker_uds_enabled():
        return bool(_worker_uds_call("confirm.request", agent_id=str(agent_id),
                                     capability=str(capability), detail=str(detail)).get("approved"))
    proxy = _get_proxy()
    # 异步方法：客户端同步等待，超时应 > securityd 侧确认超时（默认 30s）
    return bool(proxy.RequestConfirm(agent_id, capability, detail,
                                     dbus_interface=SECURITY_INTERFACE, timeout=timeout))


def request_confirm_v2(agent_id: str, capability: str, detail: str,
                       context: dict | None = None, timeout: float = 60.0) -> bool:
    if _worker_uds_enabled():
        ctx = dict(context or {})
        return bool(_worker_uds_call(
            "confirm.request", agent_id=str(agent_id), capability=str(capability),
            detail=str(detail), session_id=str(ctx.get("session_id", "")),
            run_id=str(ctx.get("run_id", ""))).get("approved"))
    proxy = _get_proxy()
    import dbus

    dctx = dbus.Dictionary({str(k): dbus.String(str(v))
                            for k, v in (context or {}).items()}, signature="sv")
    return bool(proxy.RequestConfirmV2(agent_id, capability, detail, dctx,
                                       dbus_interface=SECURITY_INTERFACE, timeout=timeout))


def respond_confirm(request_id: str, approved: bool) -> bool:
    """确认前端（GUI/测试驱动）回传用户决定。"""
    proxy = _get_proxy()
    return bool(proxy.RespondConfirm(request_id, approved, dbus_interface=SECURITY_INTERFACE))


def revoke_permission(agent_id: str, capability: str) -> bool:
    proxy = _get_proxy()
    return bool(proxy.RevokePermission(agent_id, capability, dbus_interface=SECURITY_INTERFACE))


def audit_log(agent_id: str, op_type: str, target: str, result: str) -> int:
    if _worker_uds_enabled():
        return int(_worker_uds_call(
            "audit.log", agent_id=str(agent_id), op_type=str(op_type),
            target=str(target), result=str(result)).get("audit_seq", 0))
    proxy = _get_proxy()
    return int(proxy.AuditLog(agent_id, op_type, target, result, dbus_interface=SECURITY_INTERFACE))


def query_audit(query_json: str) -> dict:
    """Query a bounded audit page; requires QueryAudit on the daemon."""
    import json
    proxy = _get_proxy()
    return json.loads(str(proxy.QueryAudit(query_json, dbus_interface=SECURITY_INTERFACE)))


def export_audit(filter_json: str, fmt: str = "json") -> str:
    proxy = _get_proxy()
    return str(proxy.ExportAudit(filter_json, fmt, dbus_interface=SECURITY_INTERFACE))


def verify_audit_chain(export_path: str) -> bool:
    proxy = _get_proxy()
    return bool(proxy.VerifyAuditChain(export_path, dbus_interface=SECURITY_INTERFACE))


def build_sandbox_policy(agent_id: str) -> dict:
    proxy = _get_proxy()
    seccomp_path, netfilter_rules = proxy.BuildSandboxPolicy(agent_id, dbus_interface=SECURITY_INTERFACE)
    return {"seccomp_path": str(seccomp_path), "netfilter_rules": str(netfilter_rules)}

def _policy_result(value) -> dict:
    import json
    raw = dict(value).get("policy_json", "{}")
    return json.loads(str(raw))

def get_syscall_catalog(arch: str) -> dict:
    import json
    value = _get_proxy().GetSyscallCatalog(str(arch), dbus_interface=SECURITY_INTERFACE)
    return json.loads(str(dict(value).get("catalog_json", "{}")))

def get_syscall_policy(agent_id: str, arch: str) -> dict:
    return _policy_result(_get_proxy().GetSyscallPolicy(str(agent_id), str(arch), dbus_interface=SECURITY_INTERFACE))

def set_global_syscall_policy(arch: str, additions: list[str]) -> dict:
    return _policy_result(_get_proxy().SetGlobalSyscallPolicy(str(arch), additions, dbus_interface=SECURITY_INTERFACE))

def set_agent_syscall_policy(agent_id: str, arch: str, additions: list[str]) -> dict:
    return _policy_result(_get_proxy().SetAgentSyscallPolicy(str(agent_id), str(arch), additions, dbus_interface=SECURITY_INTERFACE))

def reset_agent_syscall_policy(agent_id: str, arch: str) -> dict:
    return _policy_result(_get_proxy().ResetAgentSyscallPolicy(str(agent_id), str(arch), dbus_interface=SECURITY_INTERFACE))

def get_security_execution_status(agent_id: str) -> dict:
    import json
    value = _get_proxy().GetSecurityExecutionStatus(str(agent_id), dbus_interface=SECURITY_INTERFACE)
    return json.loads(str(dict(value).get("status_json", "{}")))

def record_syscall_interception(agent_id: str, pid: int, arch: str, syscall: str,
                                number: int, backend: str, policy_version: int) -> dict:
    value = _get_proxy().RecordSyscallInterception(str(agent_id), int(pid), str(arch),
        str(syscall), int(number), str(backend), int(policy_version), dbus_interface=SECURITY_INTERFACE)
    return _runtime_dict(value)

def record_syscall_interception_v2(agent_id: str, instance_id: str, lease_id: str,
                                   pid: int, cgroup_id: int, arch: str, syscall: str,
                                   number: int, backend: str, policy_version: int,
                                   event_id: str = "", worker_agent_id: str = "") -> dict:
    value = _get_proxy().RecordSyscallInterceptionV2(
        str(agent_id), str(instance_id), str(lease_id), int(pid), int(cgroup_id),
        str(arch), str(syscall), int(number), str(backend), int(policy_version),
        str(event_id), str(worker_agent_id), dbus_interface=SECURITY_INTERFACE)
    return _runtime_dict(value)

def get_syscall_audit_events(agent_id: str = "", instance_id: str = "",
                             limit: int = 100, cursor: int = 0) -> list[dict]:
    """Query independent syscall interception audit events."""
    import json
    value = _get_proxy().GetSyscallAuditEvents(
        str(agent_id), str(instance_id), int(limit), int(cursor),
        dbus_interface=SECURITY_INTERFACE)
    return json.loads(str(dict(value).get("events_json", "[]")))

def get_syscall_audit_status() -> dict:
    """Return collector/chain status for independent syscall audit."""
    import json
    value = _get_proxy().GetSyscallAuditStatus(dbus_interface=SECURITY_INTERFACE)
    return json.loads(str(dict(value).get("status_json", "{}")))


def record_network_learning_event(agent_id: str, instance_id: str, lease_id: str,
                                  pid: int, event: dict) -> bool:
    import dbus

    return bool(_get_proxy().RecordNetworkLearningEvent(
        str(agent_id), str(instance_id), str(lease_id), dbus.Int64(int(pid)),
        _sv(event), dbus_interface=SECURITY_INTERFACE))


def report_network_learning_collector(agent_id: str, instance_id: str,
                                      lease_id: str, pid: int, state: str,
                                      reason: str = "") -> bool:
    import dbus

    return bool(_get_proxy().ReportNetworkLearningCollector(
        str(agent_id), str(instance_id), str(lease_id), dbus.Int64(int(pid)),
        str(state), str(reason), dbus_interface=SECURITY_INTERFACE))


def get_network_learning_events(agent_id: str, limit: int = 100,
                                cursor: int = 0) -> dict:
    import json
    value = _get_proxy().GetNetworkLearningEvents(
        str(agent_id), int(limit), int(cursor), dbus_interface=SECURITY_INTERFACE)
    return json.loads(str(dict(value).get("json", "{}")))


def get_network_learning_status(agent_id: str) -> dict:
    import json
    value = _get_proxy().GetNetworkLearningStatus(
        str(agent_id), dbus_interface=SECURITY_INTERFACE)
    return json.loads(str(dict(value).get("json", "{}")))


def clear_network_learning_events(agent_id: str) -> bool:
    return bool(_get_proxy().ClearNetworkLearningEvents(
        str(agent_id), dbus_interface=SECURITY_INTERFACE))


def dlp_scan(agent_id: str, text: str) -> dict:
    """Scan text through the versioned Security data-plane client."""
    from bianbu_security_uds import UdsClient

    request = {"op": "dlp.scan", "agent_id": str(agent_id), "text": str(text)}
    if _worker_uds_enabled():
        request.update({"_worker_instance_id": os.environ.get("BIANBU_WORKER_INSTANCE_ID", ""),
                        "_worker_lease_id": os.environ.get("BIANBU_WORKER_LEASE_ID", ""),
                        "_worker_security_agent_id": os.environ.get(
                            "BIANBU_WORKER_SECURITY_AGENT_ID", "")})
    with UdsClient() as client:
        response = client.call(request)
    if response.get("ok") is not True:
        raise RuntimeError(str(response.get("error") or "securityd DLP scan failed"))
    return dict(response)


def dlp_policy(agent_id: str) -> dict[str, str]:
    """Read the effective central DLP policy for one bound Agent."""
    from bianbu_security_uds import UdsClient

    request = {"op": "dlp.policy", "agent_id": str(agent_id)}
    if _worker_uds_enabled():
        request.update({"_worker_instance_id": os.environ.get("BIANBU_WORKER_INSTANCE_ID", ""),
                        "_worker_lease_id": os.environ.get("BIANBU_WORKER_LEASE_ID", ""),
                        "_worker_security_agent_id": os.environ.get(
                            "BIANBU_WORKER_SECURITY_AGENT_ID", "")})
    with UdsClient() as client:
        response = client.call(request)
    if response.get("ok") is not True:
        raise RuntimeError(str(response.get("error") or "securityd DLP policy failed"))
    return {str(k): str(v) for k, v in (response.get("effective_policy") or {}).items()}


def set_dlp_policy(agent_id: str, pii_type: str, action: str) -> bool:
    """Set one central DLP policy row through the admin D-Bus API."""
    proxy = _get_proxy()
    return bool(proxy.SetDLPPolicy(str(agent_id), str(pii_type), str(action),
                                   dbus_interface=SECURITY_INTERFACE))


def delete_dlp_policy(agent_id: str, pii_type: str) -> bool:
    """Delete one central DLP policy row through the admin D-Bus API."""
    proxy = _get_proxy()
    return bool(proxy.DeleteDLPPolicy(str(agent_id), str(pii_type),
                                      dbus_interface=SECURITY_INTERFACE))


def set_network_policy(agent_id: str, domains: list, mode: str = "whitelist") -> bool:
    proxy = _get_proxy()
    return bool(proxy.SetNetworkPolicy(agent_id, domains, mode, dbus_interface=SECURITY_INTERFACE))


def get_permission_settings(agent_id: str) -> dict:
    """读取安全权限设置：{read:[...], write:[...], custom:{...}}。"""
    import json
    if _worker_uds_enabled():
        result = _worker_uds_call("permissions.settings", agent_id=str(agent_id))
        return {str(k): v for k, v in result.items() if str(k) != "ok"}
    proxy = _get_proxy()
    d = dict(proxy.GetPermissionSettings(agent_id, dbus_interface=SECURITY_INTERFACE))
    return {str(k): json.loads(str(v or "null")) for k, v in d.items()}


def get_security_permissions(agent_id: str) -> dict:
    """读取五组安全权限设置（可读/可写/网络/系统调用/自定义）。"""
    import json
    proxy = _get_proxy()
    d = dict(proxy.GetSecurityPermissions(agent_id, dbus_interface=SECURITY_INTERFACE))
    return json.loads(str(d.get("json", "{}")))


def set_permission_group(agent_id: str, group: str, value) -> dict:
    """写入一个安全权限组（read/write 传路径列表，custom 传对象）。"""
    import json
    proxy = _get_proxy()
    d = dict(proxy.SetPermissionGroup(
        agent_id, str(group), json.dumps(value, ensure_ascii=False),
        dbus_interface=SECURITY_INTERFACE))
    return {"agent_id": str(d.get("agent_id", "")),
            "group": str(d.get("group", "")),
            "value": json.loads(str(d.get("value", "null")))}


def install_package(pkg_path: str) -> dict:
    proxy = _get_proxy()
    r = proxy.InstallPackage(pkg_path, dbus_interface=SECURITY_INTERFACE)
    return {"ok": bool(r["ok"]), "reason": str(r["reason"]),
            "agent_id": str(r["agent_id"]), "count": int(r["count"])}


# —— WebUI 支撑 ——
def list_agents() -> list:
    proxy = _get_proxy()
    return [dict(a) for a in proxy.ListAgents(dbus_interface=SECURITY_INTERFACE)]


def set_capability_policy(agent_id: str, capability: str, policy: str) -> bool:
    proxy = _get_proxy()
    return bool(proxy.SetCapabilityPolicy(agent_id, capability, str(policy),
                                          dbus_interface=SECURITY_INTERFACE))


def get_agent_security_mode(agent_id: str) -> dict:
    if _worker_uds_enabled():
        result = _worker_uds_call("security.mode", agent_id=str(agent_id))
        return {str(k): v for k, v in result.items() if str(k) != "ok"}
    proxy = _get_proxy()
    return _runtime_dict(proxy.GetAgentSecurityMode(
        str(agent_id), dbus_interface=SECURITY_INTERFACE))


def set_agent_security_mode(agent_id: str, mode: str) -> dict:
    proxy = _get_proxy()
    return _runtime_dict(proxy.SetAgentSecurityMode(
        str(agent_id), str(mode), dbus_interface=SECURITY_INTERFACE))


def get_agent_info(agent_id: str) -> dict:
    import json
    proxy = _get_proxy()
    d = dict(proxy.GetAgentInfo(agent_id, dbus_interface=SECURITY_INTERFACE))
    return json.loads(str(d.get("json", "{}")))


def get_network_policy(agent_id: str) -> dict:
    import json
    proxy = _get_proxy()
    d = dict(proxy.GetNetworkPolicy(agent_id, dbus_interface=SECURITY_INTERFACE))
    return json.loads(str(d.get("json", "{}")))


def suspend_agent(agent_id: str, reason: str = "") -> bool:
    """Suspend an Agent through the control-plane API."""
    proxy = _get_proxy()
    return bool(proxy.SuspendAgent(str(agent_id), str(reason),
                                   dbus_interface=SECURITY_INTERFACE))


def _security_package_dirs() -> list[str]:
    """``securityd`` 包的候选目录，按优先级排列。

    客户端发布在 ``<root>/client``，``securityd`` 是它的兄弟目录
    ``<root>/securityd``；``<root>`` 本身不一定在调用者的 ``sys.path`` 上
    （Runtime 只把客户端目录加进去），所以这里按客户端自身位置推导。
    """
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return [root]


def capability_catalog(framework: str = "") -> list[dict]:
    """Return securityd's authoritative capability dictionary.

    The catalog is immutable policy metadata and is intentionally read from
    the installed securityd package rather than duplicated in Runtime/UI.
    Deployments that ship only the thin client may return an empty catalog;
    callers should continue to expose capabilities already configured on an
    Agent in that case. ``framework`` scopes the listing to runtime or hermes
    tools; empty lists every known tool.
    """
    import sys

    for path in _security_package_dirs():
        if os.path.isdir(os.path.join(path, "securityd")) and path not in sys.path:
            sys.path.append(path)
    try:
        from securityd.capabilities import catalog
    except ImportError:
        return []
    rows = []
    for spec in sorted(catalog(str(framework)), key=lambda value: (value.framework, value.name)):
        rows.append({
            "tool": str(spec.name),
            "framework": str(spec.framework),
            "default_policy": str(spec.default_policy),
            "summary": str(getattr(spec, "summary", "")),
        })
    return rows
