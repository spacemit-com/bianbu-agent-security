"""D-Bus 服务层（INF-02/03，io.bianbu.Security）。

用 dbus-python + GLib 主循环导出接口。系统总线（生产）或会话总线（测试）。
42 方法 + 5 信号，映射到 SecurityEngine。
"""
from __future__ import annotations

from collections import OrderedDict
import grp
import sys
import threading
import os
import shutil
import signal
import subprocess
from pathlib import Path

import dbus
import dbus.service
import dbus.mainloop.glib
from gi.repository import GLib

from . import config
from .caller_identity import caller_from_process
from .engine import SecurityEngine
from .errors import SecurityError
from .models import CallerContext, Permission
from .uds_handlers import build_security_uds_server
from runtime.engine import RuntimeEngineError, SecurityRuntimeEngine


class AccessDenied(dbus.DBusException):
    _dbus_error_name = "io.bianbu.Error.PermissionDenied"


def _caller_from_sender(bus, sender: str, session_id: str = "") -> CallerContext:
    """通过 bus-daemon credentials 解析 sender；不信任 D-Bus 参数中的 agent_id。"""
    uid, pid = _sender_credentials(bus, sender)
    return caller_from_process(
        uid, pid, sender=str(sender), session_id=session_id, include_groups=False)


def _sender_credentials(bus, sender: str) -> tuple[int, int]:
    """读取 D-Bus 连接建立时由内核固定的 UID/PID。"""
    uid = int(bus.get_unix_user(sender))
    # get_peer_unix_process_id() 只适用于直接 peer connection；这里 sender
    # 是总线上的 unique name，必须通过 org.freedesktop.DBus 凭据 API 查询。
    pid = int(bus.call_blocking(
        "org.freedesktop.DBus", "/org/freedesktop/DBus",
        "org.freedesktop.DBus", "GetConnectionUnixProcessID", "s", (sender,)))
    return uid, pid


def _process_group_ids(pid: int) -> set[int]:
    """Return both primary and supplementary kernel group identities."""
    status = Path(f"/proc/{int(pid)}/status").read_text()
    primary_line = status.split("Gid:", 1)[1].splitlines()[0]
    supplementary_line = status.split("Groups:", 1)[1].splitlines()[0]
    primary = int(primary_line.split()[0])
    return {primary, *(int(value) for value in supplementary_line.split())}


def _perms_from_dbus(perms) -> list[Permission]:
    out = []
    for entry in perms:
        d = {str(k): str(v) for k, v in entry.items()}
        out.append(Permission.from_dict(d))
    return out


def _dbus_scalar(value):
    """Convert a runtime result to a D-Bus ``variant``-compatible scalar."""
    if isinstance(value, bool):
        return dbus.Boolean(value)
    if isinstance(value, int):
        return dbus.Int64(value)
    if isinstance(value, float):
        return dbus.Double(value)
    return dbus.String(str(value))


def _dbus_result(values: dict) -> dbus.Dictionary:
    """Encode runtime control-plane responses without nested D-Bus types."""
    return dbus.Dictionary(
        {str(key): _dbus_scalar(value) for key, value in values.items()},
        signature="sv",
    )


def _plain_dict(values) -> dict:
    """Copy a D-Bus a{sv} into ordinary Python values for runtime validation."""
    try:
        return {str(key): value for key, value in dict(values or {}).items()}
    except (AttributeError, TypeError, ValueError) as exc:
        raise AccessDenied("runtime 参数必须是 a{sv} 字典") from exc


class SecurityRuntimeService(dbus.service.Object):
    """受限的 ``io.bianbu.Security.Runtime`` 控制面。

    The object lives in securityd and only decides/attests launches.  It never
    forks, execs or stops PA processes; those operations remain in the PA
    ``bianbu-agent-runtime`` backend.
    """

    def __init__(self, bus, security_service: "SecurityService"):
        super().__init__(bus, config.RUNTIME_OBJECT_PATH)
        self.security_service = security_service
        self.engine = SecurityRuntimeEngine(security_service.engine)
        try:
            lost = self.engine.reap_dead_instances()
        except Exception:  # noqa: BLE001 - startup reap must never block the service
            lost = []
        if lost:
            import logging
            logging.getLogger("securityd").warning(
                "runtime: %d 个 running 实例的进程已不存在，已标记 lost", len(lost))

    def close(self) -> None:
        self.engine.close()

    def _runtime(self, sender: str):
        return self.security_service._require_runtime(sender)

    def _agent(self, agent_id: str, sender: str):
        self._runtime(sender)
        return self.security_service._require_agent(str(agent_id), sender)

    def _lease_agent(self, lease_id: str) -> str:
        row = self.engine.leases.get(str(lease_id))
        if row is None:
            raise RuntimeEngineError("lease 不存在")
        return str(row["agent_id"])

    @dbus.service.method(config.RUNTIME_INTERFACE, in_signature="sa{sv}",
                         out_signature="a{sv}", sender_keyword="sender")
    def PrepareStart(self, agent_id, request, sender=None):
        self._agent(str(agent_id), sender)
        result = self.engine.prepare_start(str(agent_id), _plain_dict(request))
        return _dbus_result(result)

    @dbus.service.method(config.RUNTIME_INTERFACE, in_signature="s",
                         out_signature="a{sv}", sender_keyword="sender")
    def GetSandboxPolicy(self, lease_id, sender=None):
        agent_id = self._lease_agent(str(lease_id))
        self._agent(agent_id, sender)
        policy = self.engine.sandbox_policy(str(lease_id))
        import json
        return _dbus_result({
            "policy_json": json.dumps(policy, ensure_ascii=False,
                                       sort_keys=True, separators=(",", ":")),
            "effective_mode": str(policy.get("effective_mode", "")),
            "backend": str(policy.get("backend", "")),
        })

    @dbus.service.method(config.RUNTIME_INTERFACE, in_signature="ssxsa{sv}",
                         out_signature="a{sv}", sender_keyword="sender")
    def CommitStart(self, lease_id, instance_id, pid, cgroup_path, attestation,
                    sender=None):
        agent_id = self._lease_agent(str(lease_id))
        caller = self._agent(agent_id, sender)
        # A PA process inside a PID namespace cannot know its host PID.  A
        # zero PID/empty cgroup therefore means "the D-Bus Runtime sender";
        # both values are resolved from kernel-backed sender credentials here.
        effective_pid = int(pid)
        effective_cgroup = str(cgroup_path).strip()
        if effective_cgroup.startswith("0::"):
            effective_cgroup = effective_cgroup[3:]
        if effective_pid <= 0:
            effective_pid = int(caller.pid)
        if not effective_cgroup:
            effective_cgroup = str(caller.cgroup)
        proof = _plain_dict(attestation)
        if int(proof.get("pid", 0) or 0) <= 0:
            proof["pid"] = effective_pid
        result = self.engine.commit_start(
            str(lease_id), str(instance_id), effective_pid, effective_cgroup,
            proof)
        return _dbus_result(result)

    @dbus.service.method(config.RUNTIME_INTERFACE, in_signature="ss",
                         out_signature="b", sender_keyword="sender")
    def AbortStart(self, lease_id, reason, sender=None):
        agent_id = self._lease_agent(str(lease_id))
        self._agent(agent_id, sender)
        return dbus.Boolean(self.engine.abort_start(str(lease_id), str(reason)))

    @dbus.service.method(config.RUNTIME_INTERFACE, in_signature="sss",
                         out_signature="a{sv}", sender_keyword="sender")
    def StopInstance(self, lease_id, instance_id, reason, sender=None):
        """Runtime 正常停止 Worker 后收敛该实例，不影响同 Agent 的其它 lease。"""
        agent_id = self._lease_agent(str(lease_id))
        self._agent(agent_id, sender)
        return _dbus_result(self.engine.stop_instance(
            str(lease_id), str(instance_id), str(reason)))

    @dbus.service.method(config.RUNTIME_INTERFACE, in_signature="ss",
                         out_signature="b", sender_keyword="sender")
    def RevokeAgent(self, agent_id, reason, sender=None):
        self._agent(str(agent_id), sender)
        return dbus.Boolean(self.engine.revoke_agent(str(agent_id), str(reason)))

    @dbus.service.method(config.RUNTIME_INTERFACE, in_signature="s",
                         out_signature="a{sv}", sender_keyword="sender")
    def GetRuntimeState(self, agent_id, sender=None):
        self._agent(str(agent_id), sender)
        state = self.engine.state(str(agent_id))
        lease = state.get("lease") or {}
        instance = state.get("instance") or {}
        return _dbus_result({
            "agent_id": str(agent_id),
            "lease_id": str(lease.get("lease_id", "")),
            "lease_state": str(lease.get("state", "")),
            "instance_id": str(lease.get("instance_id", "") or instance.get("instance_id", "")),
            "pid": int(instance.get("pid", 0) or 0),
            "cgroup_path": str(instance.get("cgroup_path", "")),
            "effective_mode": str(lease.get("effective_mode", "")),
            "backend": str(lease.get("backend", "")),
            "instance_state": str(instance.get("state", "")),
        })

    @dbus.service.method(config.RUNTIME_INTERFACE, in_signature="s",
                         out_signature="aa{sv}", sender_keyword="sender")
    def ListRuntimeInstances(self, agent_id, sender=None):
        self._agent(str(agent_id), sender)
        rows = []
        for row in self.engine.instances(str(agent_id)):
            rows.append(_dbus_result({
                "instance_id": str(row.get("instance_id", "")),
                "lease_id": str(row.get("lease_id", "")),
                "agent_id": str(row.get("agent_id", "")),
                "pid": int(row.get("pid", 0) or 0),
                "cgroup_path": str(row.get("cgroup_path", "")),
                "started_at": int(row.get("started_at", 0) or 0),
                "state": str(row.get("state", "")),
            }))
        return rows


class SecurityService(dbus.service.Object):
    _MAX_SENDER_CREDENTIALS = 1024

    def __init__(self, bus, engine: SecurityEngine):
        super().__init__(bus, config.OBJECT_PATH)
        self.bus = bus
        self.engine = engine
        self._sender_credential_cache: "OrderedDict[str, tuple[int, int]]" = OrderedDict()
        self._sender_credential_lock = threading.Lock()
        bus.add_signal_receiver(
            self._name_owner_changed,
            signal_name="NameOwnerChanged",
            dbus_interface="org.freedesktop.DBus",
        )

    def _caller(self, sender: str, session_id: str = "") -> CallerContext:
        sender = str(sender)
        with self._sender_credential_lock:
            credentials = self._sender_credential_cache.get(sender)
            if credentials is not None:
                self._sender_credential_cache.move_to_end(sender)
        if credentials is None:
            resolved = _sender_credentials(self.bus, sender)
            with self._sender_credential_lock:
                credentials = self._sender_credential_cache.setdefault(sender, resolved)
                self._sender_credential_cache.move_to_end(sender)
                while len(self._sender_credential_cache) > self._MAX_SENDER_CREDENTIALS:
                    self._sender_credential_cache.popitem(last=False)
        # executable/cgroup/groups 可能在同一 PID execve 后变化，绝不能缓存；
        # 每次请求仍从 /proc 重读并参与绑定校验。
        return caller_from_process(
            credentials[0], credentials[1], sender=sender, session_id=session_id,
            include_groups=False)

    def _name_owner_changed(self, name, _old_owner, new_owner) -> None:
        name = str(name)
        if not name.startswith(":") or str(new_owner):
            return
        with self._sender_credential_lock:
            self._sender_credential_cache.pop(name, None)

    @staticmethod
    def _context_dict(context) -> dict[str, str]:
        """解析 V2 接口的可信上下文载荷。

        上下文只补充 session/run 追踪信息，绝不替代 D-Bus sender 凭据；
        UID/PID/executable/cgroup 仍始终由服务端从 sender 解析。
        """
        if not context:
            return {}
        try:
            return {str(k): str(v) for k, v in context.items()}
        except (AttributeError, TypeError, ValueError):
            raise AccessDenied("context 必须是 a{sv} 字典")

    @staticmethod
    def _require_runtime_context(context: dict[str, str]) -> tuple[str, str]:
        session_id = str(context.get("session_id", "")).strip()
        run_id = str(context.get("run_id", "")).strip()
        if not session_id or not run_id:
            raise AccessDenied("V2 接口必须提供非空 session_id 和 run_id")
        return session_id, run_id

    def _require_agent(self, agent_id: str, sender: str, *, allow_unbound: bool = False,
                       session_id: str = ""):
        caller = self._caller(sender, session_id)
        if caller.is_root:
            return caller
        binding = self.engine.registry.get_binding(agent_id)
        if binding is None:
            if allow_unbound:
                self.engine.bind_agent(agent_id, caller)
                return caller
            raise AccessDenied(f"agent {agent_id} 未绑定可信 caller")
        # session_id 是一次运行上下文，不是稳定 caller 身份；它只参与
        # session_trust 判定，不能要求绑定表被每个新 run 覆盖。
        if not self.engine.caller_allowed(agent_id, caller, binding=binding):
            raise AccessDenied(f"caller 无权代表 agent {agent_id}")
        return caller

    def _require_agent_or_admin(self, agent_id: str, sender: str):
        """管理只读接口允许管理员查看，业务接口仍只接受绑定 Agent。"""
        caller = self._caller(sender)
        if self._is_admin(caller):
            return caller
        return self._require_agent(agent_id, sender)

    def _bind_agent_identity(self, agent_id: str, caller: CallerContext) -> bool:
        """续租或由管理员显式重绑 Agent 身份，并为覆盖操作留审计。"""
        existing = self.engine.registry.get_binding(agent_id)
        replacing = existing is not None and not self.engine.caller_allowed(
            agent_id, caller)
        if replacing and not caller.is_root and not self._is_admin(caller):
            raise AccessDenied(f"agent {agent_id} 已绑定其他 caller，拒绝覆盖绑定")
        ok = self.engine.bind_agent(agent_id, caller)
        if replacing:
            self._audit_admin(
                caller, "bind_agent",
                f"agent={agent_id};old_uid={existing.get('uid')};"
                f"old_executable={existing.get('executable')};"
                f"old_cgroup={existing.get('cgroup')}")
        return ok

    def _polkit_authorized(self, caller: CallerContext, action: str) -> bool:
        """通过 polkit 复核桌面 seat 授权；不可用时保持拒绝。"""
        pkcheck = shutil.which("pkcheck")
        if not pkcheck or caller.pid <= 0:
            return False
        try:
            cp = subprocess.run(
                [pkcheck, "--action-id", action, "--process", str(caller.pid)],
                capture_output=True, text=True, timeout=3, check=False)
            return cp.returncode == 0
        except (OSError, subprocess.TimeoutExpired):
            return False

    def _require_admin(self, sender: str, *, action: str = "io.bianbu.security.manage"):
        caller = self._caller(sender)
        if self._is_admin(caller, action=action):
            return caller
        raise AccessDenied("需要 bianbu-admin 或 root")

    def _is_admin(self, caller: CallerContext,
                  *, action: str = "io.bianbu.security.manage") -> bool:
        if caller.is_root or os.environ.get("BIANBU_SECURITY_TEST_ADMIN") == "1":
            return True
        # D-Bus policy 是第一层；服务层再检查主组与补充组，防止会话总线/
        # 错误 policy 绕过。Linux 的 Groups: 不保证重复列出主组。
        try:
            groups = _process_group_ids(caller.pid)
            import grp
            admin_gid = grp.getgrnam("bianbu-admin").gr_gid
            if admin_gid in groups:
                return True
        except (OSError, KeyError, IndexError, ValueError):
            pass
        return self._polkit_authorized(caller, action)

    def _require_runtime(self, sender: str):
        caller = self._caller(sender)
        if caller.is_root or os.environ.get("BIANBU_SECURITY_TEST_ADMIN") == "1":
            return caller
        try:
            groups = _process_group_ids(caller.pid)
            import grp
            allowed = {grp.getgrnam("bianbu-security").gr_gid,
                       grp.getgrnam("bianbu-admin").gr_gid}
            if groups & allowed:
                return caller
        except (OSError, KeyError, IndexError, ValueError):
            pass
        raise AccessDenied("需要 bianbu-security/bianbu-admin 运行时身份")

    def _audit_admin(self, caller: CallerContext, operation: str,
                     target: str, result: str = "success") -> int:
        """为管理面变更补充真实调用者身份审计。

        业务引擎记录“改了什么”，这里记录“谁改的”；两条记录都进入同一
        哈希链。UID/PID/executable/cgroup 来自 D-Bus sender 解析，不能由
        WebUI 请求体伪造。
        """
        actor = (f"uid={caller.uid};pid={caller.pid};"
                 f"exe={caller.executable or '-'};cgroup={caller.cgroup or '-'}")
        return self.engine.audit_log(
            "system", f"admin:{operation}", f"actor={actor};{target}", result)

    # —— 信号（4）——
    @dbus.service.signal(config.INTERFACE, signature="sss")
    def SecurityAlert(self, agent_id, type, detail):
        pass

    @dbus.service.signal(config.INTERFACE, signature="ssss")
    def ConfirmRequest(self, agent_id, capability, detail, request_id):
        pass

    @dbus.service.signal(config.INTERFACE, signature="sb")
    def ConfirmResponse(self, request_id, approved):
        pass

    # —— 方法（13）——
    @dbus.service.method(config.INTERFACE, in_signature="s", out_signature="bsaa{sv}", sender_keyword="sender")
    def VerifyManifest(self, agent_pkg_path, sender=None):
        valid, reason, perms, _m = self.engine.verify_manifest(str(agent_pkg_path))
        return valid, reason, [dbus.Dictionary(p, signature="sv") for p in perms]

    @dbus.service.method(config.INTERFACE, in_signature="ss", out_signature="a{sv}", sender_keyword="sender")
    def VerifyCodePackage(self, pkg_path, kind, sender=None):
        """D-6：Hook / Tool / Skill 安装期签名校验。

        返回 {allowed, signed, valid, digest, policy, reason, key_id}。
        调用方（PA 的 installer）看 allowed 决定装不装，reason 给用户看。
        """
        d = self.engine.verify_code_package(str(pkg_path), str(kind) or "hook")
        return dbus.Dictionary(
            {k: dbus.Boolean(v) if isinstance(v, bool) else dbus.String(str(v))
             for k, v in d.items()}, signature="sv")

    @dbus.service.method(config.INTERFACE, in_signature="sss", out_signature="a{sv}", sender_keyword="sender")
    def VerifyCodeDigest(self, digest, signature, kind, sender=None):
        """跨 mount namespace 的生产验签：调用方传规范摘要和分离签名。"""
        d = self.engine.verify_code_digest(str(digest), str(signature),
                                           str(kind) or "hook")
        return dbus.Dictionary(
            {k: dbus.Boolean(v) if isinstance(v, bool) else dbus.String(str(v))
             for k, v in d.items()}, signature="sv")

    @dbus.service.method(config.INTERFACE, in_signature="saa{sv}", out_signature="b", sender_keyword="sender")
    def RegisterCapabilities(self, agent_id, perms, sender=None):
        caller = self._caller(sender)
        aid = str(agent_id)
        admin_update = False
        if self.engine.registry.get_binding(aid) is not None:
            # 已运行 Agent 由自身更新声明；管理员配置台可在服务端授权后
            # 维护能力，但不会把管理员进程写成 Agent 运行绑定主体。
            if self._is_admin(caller):
                binding_caller = None
                admin_update = True
            else:
                self._require_agent(aid, sender)
                binding_caller = caller
        elif self._is_admin(caller):
            # 管理员维护声明，不成为 Agent 运行实例的绑定主体。
            binding_caller = None
            admin_update = True
        else:
            raise AccessDenied(f"agent {aid} 尚未由 Runtime 绑定 caller")
        parsed = _perms_from_dbus(perms)
        ok = self.engine.register_capabilities(aid, parsed, caller=binding_caller)
        if admin_update:
            self._audit_admin(caller, "register_capabilities",
                              f"agent={aid};capabilities={[p.capability for p in parsed]}")
        return ok

    @dbus.service.method(config.INTERFACE, in_signature="s", out_signature="b", sender_keyword="sender")
    def BindAgent(self, agent_id, sender=None):
        """由 Agent Runtime 启动阶段建立 caller→agent 绑定；不接受代理身份信息。"""
        caller = self._require_runtime(sender)
        # 绑定是信任根：已存在的 Agent 只能由同一稳定身份续租，不能由
        # 任意同 UID 进程覆盖；管理员/root 可在显式运维操作后重绑。
        return self._bind_agent_identity(str(agent_id), caller)

    @dbus.service.method(config.INTERFACE, in_signature="sa{sv}", out_signature="b",
                         sender_keyword="sender")
    def BindAgentV2(self, agent_id, context, sender=None):
        """带 session/run 上下文的启动绑定；sender 凭据仍由服务端解析。"""
        ctx = self._context_dict(context)
        self._require_runtime_context(ctx)
        caller = self._caller(sender, ctx.get("session_id", ""))
        if not self._is_admin(caller) and not caller.is_root:
            # 运行时身份与旧 BindAgent 保持一致
            self._require_runtime(sender)
        return self._bind_agent_identity(str(agent_id), caller)

    @dbus.service.method(config.INTERFACE, in_signature="ss", out_signature="b",
                         sender_keyword="sender")
    def ResetAgentBinding(self, agent_id, reason, sender=None):
        """Clear a stale Agent caller binding after an explicit admin operation.

        This is intentionally separate from BindAgent: a normal Runtime may
        only renew the same identity, while package installation/upgrade runs
        as root and must first stop the previous instance.  The caller is
        authenticated by D-Bus credentials and the admin/root policy; the
        reason is retained in the audit chain for traceability.
        """
        caller = self._require_admin(sender)
        aid = str(agent_id).strip()
        if not aid:
            raise AccessDenied("agent_id 不能为空")
        existing = self.engine.registry.get_binding(aid)
        removed = bool(self.engine.registry.reset_binding(aid))
        old = "none"
        if existing is not None:
            old = (f"uid={existing.get('uid')};"
                   f"executable={existing.get('executable')};"
                   f"cgroup={existing.get('cgroup')}")
        self._audit_admin(
            caller, "reset_agent_binding",
            f"agent={aid};removed={removed};old={old};reason={str(reason)[:1024]}",
            "success",
        )
        return removed

    @dbus.service.method(config.INTERFACE, in_signature="sss", out_signature="i", sender_keyword="sender")
    def CheckPermission(self, agent_id, capability, scope, sender=None):
        self._require_agent(str(agent_id), sender)
        return int(self.engine.check_permission(str(agent_id), str(capability), str(scope)))

    @dbus.service.method(config.INTERFACE, in_signature="sssa{sv}", out_signature="i",
                         sender_keyword="sender")
    def CheckPermissionV2(self, agent_id, capability, scope, context, sender=None):
        ctx = self._context_dict(context)
        session_id, _run_id = self._require_runtime_context(ctx)
        self._require_agent(str(agent_id), sender, session_id=session_id)
        return int(self.engine.check_permission(str(agent_id), str(capability),
                                                str(scope), session_id=session_id))

    @dbus.service.method(config.INTERFACE, in_signature="sssa{sv}",
                         out_signature="b", sender_keyword="sender")
    def GrantSessionTrustV2(self, agent_id, capability, scope, context, sender=None):
        """记录已由 PA HITL 批准的 ask 策略工具。"""
        ctx = self._context_dict(context)
        session_id, _run_id = self._require_runtime_context(ctx)
        self._require_agent(str(agent_id), sender, session_id=session_id)
        return bool(self.engine.grant_session_trust(
            str(agent_id), str(capability), str(scope), session_id))

    @dbus.service.method(config.INTERFACE, in_signature="sss", out_signature="b",
                         async_callbacks=("reply_cb", "error_cb"), sender_keyword="sender")
    def RequestConfirm(self, agent_id, capability, detail, reply_cb, error_cb, sender=None):
        caller = self._require_agent(str(agent_id), sender)
        # 异步：在后台线程阻塞等待用户确认，避免堵住 GLib 主循环
        # （否则 RespondConfirm 无法被派发，形成死锁）。
        def _worker():
            try:
                approved = self.engine.request_confirm(
                    str(agent_id), str(capability), str(detail), caller=caller)
                GLib.idle_add(lambda: reply_cb(bool(approved)) or False)
            except Exception as exc:  # noqa: BLE001
                GLib.idle_add(lambda: error_cb(exc) or False)
        threading.Thread(target=_worker, daemon=True).start()

    @dbus.service.method(config.INTERFACE, in_signature="sssa{sv}", out_signature="b",
                         async_callbacks=("reply_cb", "error_cb"), sender_keyword="sender")
    def RequestConfirmV2(self, agent_id, capability, detail, context,
                         reply_cb, error_cb, sender=None):
        ctx = self._context_dict(context)
        session_id, _run_id = self._require_runtime_context(ctx)
        caller = self._require_agent(str(agent_id), sender, session_id=session_id)
        def _worker():
            try:
                approved = self.engine.request_confirm(
                    str(agent_id), str(capability), str(detail),
                    session_id=session_id, caller=caller)
                GLib.idle_add(lambda: reply_cb(bool(approved)) or False)
            except Exception as exc:  # noqa: BLE001
                GLib.idle_add(lambda: error_cb(exc) or False)
        threading.Thread(target=_worker, daemon=True).start()

    @dbus.service.method(config.INTERFACE, in_signature="sb", out_signature="b", sender_keyword="sender")
    def RespondConfirm(self, request_id, approved, sender=None):
        """GUI/确认前端回传用户决定，唤醒等待中的 RequestConfirm。"""
        caller = self._require_admin(sender, action="io.bianbu.security.confirm")
        pending = self.engine.confirm.get_pending(str(request_id))
        if pending is None:
            raise AccessDenied("确认请求不存在、已超时或已消费")
        if pending.caller is not None and not caller.is_root and pending.caller.uid != caller.uid:
            raise AccessDenied("确认响应者与发起者 session 不匹配")
        if not self.engine.confirm.respond(str(request_id), bool(approved)):
            raise AccessDenied("确认请求已消费或不存在")
        self._audit_admin(caller, "respond_confirm",
                          f"request_id={request_id};approved={bool(approved)}")
        self.ConfirmResponse(str(request_id), bool(approved))  # 广播设计 §5 的 ConfirmResponse 信号
        return True

    @dbus.service.method(config.INTERFACE, in_signature="ss", out_signature="b", sender_keyword="sender")
    def RevokePermission(self, agent_id, capability, sender=None):
        caller = self._require_admin(sender)
        old = self.engine.registry._policy_row(str(agent_id), str(capability))
        ok = self.engine.revoke_permission(str(agent_id), str(capability))
        self._audit_admin(caller, "revoke_permission",
                          f"agent={agent_id};tool={capability};"
                          f"old_policy={old['policy'] if old else 'missing'};new_policy=deny",
                          "success" if ok else "notfound")
        return ok

    @dbus.service.method(config.INTERFACE, in_signature="s", out_signature="ss", sender_keyword="sender")
    def BuildSandboxPolicy(self, agent_id, sender=None):
        self._require_agent(str(agent_id), sender)
        return self.engine.build_sandbox_policy(str(agent_id))

    @dbus.service.method(config.INTERFACE, in_signature="s", out_signature="a{sv}", sender_keyword="sender")
    def GetSyscallCatalog(self, arch, sender=None):
        self._require_agent_or_admin("system", sender)
        return _dbus_result({"catalog_json": __import__("json").dumps(self.engine.get_syscall_catalog(str(arch)), ensure_ascii=False)})

    @dbus.service.method(config.INTERFACE, in_signature="ss", out_signature="a{sv}", sender_keyword="sender")
    def GetSyscallPolicy(self, agent_id, arch, sender=None):
        self._require_agent_or_admin(str(agent_id), sender)
        import json
        return _dbus_result({"policy_json": json.dumps(self.engine.get_syscall_policy(str(agent_id), str(arch)), ensure_ascii=False)})

    @dbus.service.method(config.INTERFACE, in_signature="sas", out_signature="a{sv}", sender_keyword="sender")
    def SetGlobalSyscallPolicy(self, arch, additions, sender=None):
        caller = self._require_admin(sender)
        return _dbus_result({"policy_json": __import__("json").dumps(self.engine.set_global_syscall_policy(str(arch), [str(x) for x in additions], str(caller.uid)), ensure_ascii=False)})

    @dbus.service.method(config.INTERFACE, in_signature="ssas", out_signature="a{sv}", sender_keyword="sender")
    def SetAgentSyscallPolicy(self, agent_id, arch, additions, sender=None):
        caller = self._require_admin(sender)
        return _dbus_result({"policy_json": __import__("json").dumps(self.engine.set_agent_syscall_policy(str(agent_id), str(arch), [str(x) for x in additions], str(caller.uid)), ensure_ascii=False)})

    @dbus.service.method(config.INTERFACE, in_signature="ss", out_signature="a{sv}", sender_keyword="sender")
    def ResetAgentSyscallPolicy(self, agent_id, arch, sender=None):
        caller = self._require_admin(sender)
        return _dbus_result({"policy_json": __import__("json").dumps(self.engine.reset_agent_syscall_policy(str(agent_id), str(arch), str(caller.uid)), ensure_ascii=False)})

    @dbus.service.method(config.INTERFACE, in_signature="s", out_signature="a{sv}", sender_keyword="sender")
    def GetSecurityExecutionStatus(self, agent_id, sender=None):
        self._require_agent_or_admin(str(agent_id), sender)
        import json
        return _dbus_result({"status_json": json.dumps(self.engine.get_security_execution_status(str(agent_id)), ensure_ascii=False)})

    @dbus.service.method(config.INTERFACE, in_signature="sissisi", out_signature="a{sv}", sender_keyword="sender")
    def RecordSyscallInterception(self, agent_id, pid, arch, syscall, number, backend, policy_version, sender=None):
        self._require_runtime(sender)
        return _dbus_result(self.engine.record_syscall_interception(
            str(agent_id), int(pid), str(arch), str(syscall), int(number),
            str(backend), int(policy_version)))

    @dbus.service.method(config.INTERFACE, in_signature="sssixssisiss", out_signature="a{sv}", sender_keyword="sender")
    def RecordSyscallInterceptionV2(self, agent_id, instance_id, lease_id, pid, cgroup_id,
                                    arch, syscall, number, backend, policy_version,
                                    event_id, worker_agent_id="", sender=None):
        self._require_runtime(sender)
        return _dbus_result(self.engine.record_syscall_interception_v2(
            str(agent_id), str(instance_id), str(lease_id), int(pid), int(cgroup_id),
            str(arch), str(syscall), int(number), str(backend), int(policy_version),
            str(event_id), worker_agent_id=str(worker_agent_id)))

    @dbus.service.method(config.INTERFACE, in_signature="ssii", out_signature="a{sv}", sender_keyword="sender")
    def GetSyscallAuditEvents(self, agent_id, instance_id, limit, cursor, sender=None):
        self._require_admin(sender)
        import json
        return _dbus_result({"events_json": json.dumps(self.engine.get_syscall_audit_events(str(agent_id), str(instance_id), int(limit), int(cursor)), ensure_ascii=False)})

    @dbus.service.method(config.INTERFACE, in_signature="", out_signature="a{sv}", sender_keyword="sender")
    def GetSyscallAuditStatus(self, sender=None):
        self._require_admin(sender)
        import json
        return _dbus_result({"status_json": json.dumps(self.engine.get_syscall_audit_status(), ensure_ascii=False)})

    @dbus.service.method(config.INTERFACE, in_signature="sssxa{sv}", out_signature="b",
                         sender_keyword="sender")
    def RecordNetworkLearningEvent(self, agent_id, instance_id, lease_id, pid,
                                   event, sender=None):
        self._require_runtime(sender)
        identity = {"agent_id": str(agent_id), "instance_id": str(instance_id),
                    "lease_id": str(lease_id), "pid": int(pid)}
        return self.engine.record_network_learning_event(identity, _plain_dict(event))

    @dbus.service.method(config.INTERFACE, in_signature="sssxss", out_signature="b",
                         sender_keyword="sender")
    def ReportNetworkLearningCollector(self, agent_id, instance_id, lease_id, pid,
                                       state, reason="", sender=None):
        self._require_runtime(sender)
        identity = {"agent_id": str(agent_id), "instance_id": str(instance_id),
                    "lease_id": str(lease_id), "pid": int(pid)}
        return self.engine.report_network_learning_collector(
            identity, str(state), str(reason))

    @dbus.service.method(config.INTERFACE, in_signature="sii", out_signature="a{sv}",
                         sender_keyword="sender")
    def GetNetworkLearningEvents(self, agent_id, limit, cursor, sender=None):
        self._require_admin(sender)
        import json
        result = self.engine.get_network_learning_events(
            str(agent_id), int(limit), int(cursor))
        return _dbus_result({"json": json.dumps(result, ensure_ascii=False)})

    @dbus.service.method(config.INTERFACE, in_signature="s", out_signature="a{sv}",
                         sender_keyword="sender")
    def GetNetworkLearningStatus(self, agent_id, sender=None):
        self._require_admin(sender)
        import json
        result = self.engine.get_network_learning_status(str(agent_id))
        return _dbus_result({"json": json.dumps(result, ensure_ascii=False)})

    @dbus.service.method(config.INTERFACE, in_signature="s", out_signature="b",
                         sender_keyword="sender")
    def ClearNetworkLearningEvents(self, agent_id, sender=None):
        self._require_admin(sender)
        return self.engine.clear_network_learning_events(str(agent_id)) >= 0

    @dbus.service.method(config.INTERFACE, in_signature="ssss", out_signature="x", sender_keyword="sender")
    def AuditLog(self, agent_id, op_type, target, result, sender=None):
        self._require_agent(str(agent_id), sender)
        return self.engine.audit_log(str(agent_id), str(op_type), str(target), str(result))

    @dbus.service.method(config.INTERFACE, in_signature="s", out_signature="s", sender_keyword="sender")
    def QueryAudit(self, query_json, sender=None):
        import json
        self._require_admin(sender)
        return json.dumps(self.engine.query_audit(str(query_json)), ensure_ascii=False)

    @dbus.service.method(config.INTERFACE, in_signature="ss", out_signature="s", sender_keyword="sender")
    def ExportAudit(self, filter_json, format, sender=None):
        self._require_admin(sender)
        return self.engine.export_audit(str(filter_json), str(format))

    @dbus.service.method(config.INTERFACE, in_signature="s", out_signature="b", sender_keyword="sender")
    def VerifyAuditChain(self, export_path, sender=None):
        self._require_admin(sender)
        return self.engine.verify_audit_chain(str(export_path))

    @dbus.service.method(config.INTERFACE, in_signature="sass", out_signature="b", sender_keyword="sender")
    def SetNetworkPolicy(self, agent_id, domains, mode, sender=None):
        caller = self._require_admin(sender)
        old = self.engine.get_network_policy(str(agent_id))
        ok = self.engine.set_network_policy(str(agent_id), [str(d) for d in domains], str(mode))
        self._audit_admin(caller, "set_network_policy",
                          f"agent={agent_id};old={old};new_domains={list(domains)};new_mode={mode}")
        return ok

    @dbus.service.method(config.INTERFACE, in_signature="s", out_signature="aa{sv}", sender_keyword="sender")
    def GetCapabilities(self, agent_id, sender=None):
        self._require_agent_or_admin(str(agent_id), sender)
        perms = self.engine.get_capabilities(str(agent_id))
        return [dbus.Dictionary({k: str(v) for k, v in p.items()}, signature="sv") for p in perms]

    @dbus.service.method(config.INTERFACE, in_signature="ss", out_signature="b", sender_keyword="sender")
    def SuspendAgent(self, agent_id, reason, sender=None):
        caller = self._require_admin(sender)
        # 兼容管理操作：securityd 只记审计并发告警，不直接停止 Agent 服务。
        # 暂停请求通过 SecurityAlert 通知 Agent Runtime/agent，由运行时负责
        # 暂停或终止。
        self.engine.audit_log(str(agent_id), "suspend", str(reason), "requested")
        self._audit_admin(caller, "suspend_agent", f"agent={agent_id};reason={reason}")
        self.SecurityAlert(str(agent_id), "suspend", str(reason))
        return True

    @dbus.service.method(config.INTERFACE, in_signature="s", out_signature="a{sv}", sender_keyword="sender")
    def InstallPackage(self, pkg_path, sender=None):
        caller = self._require_admin(sender)
        r = self.engine.install_package_info(str(pkg_path))
        self._audit_admin(caller, "install_package",
                          f"path={pkg_path};agent={r['agent_id']};count={r['count']}",
                          "success" if r["ok"] else f"deny:{r['reason']}")
        return dbus.Dictionary({
            "ok": dbus.Boolean(r["ok"]), "reason": dbus.String(r["reason"]),
            "agent_id": dbus.String(r["agent_id"]), "count": dbus.Int32(r["count"]),
        }, signature="sv")

    @dbus.service.method(config.INTERFACE, in_signature="sa{sv}", out_signature="a{sv}", sender_keyword="sender")
    def RegisterAgent(self, agent_id, metadata, sender=None):
        caller = self._require_runtime(sender)
        aid = str(agent_id).strip()
        if not aid:
            raise AccessDenied("agent_id 不能为空")
        # Check an existing stable binding before mutating metadata.  Without
        # this preflight an unauthorized caller could overwrite the manifest
        # and only then be rejected while binding, leaving a partial update.
        existing = self.engine.registry.get_binding(aid)
        if (existing is not None and not caller.is_root and
                not self._is_admin(caller) and
                not self.engine.caller_allowed(aid, caller, binding=existing)):
            raise AccessDenied(f"caller 无权代表 agent {aid}")
        result = self.engine.register_agent(aid, _plain_dict(metadata))
        self._bind_agent_identity(aid, caller)
        self._audit_admin(caller, "register_agent", f"agent={agent_id}")
        return _dbus_result(result)

    @dbus.service.method(config.INTERFACE, in_signature="s", out_signature="b", sender_keyword="sender")
    def UnregisterAgent(self, agent_id, sender=None):
        caller = self._require_runtime(sender)
        aid = str(agent_id).strip()
        if not caller.is_root and not self._is_admin(caller):
            self._require_agent(aid, sender)
        result = self.engine.unregister_agent(aid)
        self._audit_admin(caller, "unregister_agent", f"agent={agent_id}")
        return bool(result)

    @dbus.service.method(config.INTERFACE, in_signature="saa{sv}", out_signature="a{sv}", sender_keyword="sender")
    def SyncAgentCapabilities(self, agent_id, capabilities, sender=None):
        caller = self._require_runtime(sender)
        aid = str(agent_id).strip()
        if not caller.is_root and not self._is_admin(caller):
            self._require_agent(aid, sender)
        result = self.engine.sync_agent_capabilities(aid, _perms_from_dbus(capabilities))
        self._audit_admin(caller, "sync_agent_capabilities", f"agent={agent_id};count={result['count']}")
        return _dbus_result(result)

    # —— WebUI 配置支撑（6 方法）——
    @dbus.service.method(config.INTERFACE, in_signature="", out_signature="aa{sv}", sender_keyword="sender")
    def ListAgents(self, sender=None):
        # 仅返回非敏感的 Agent 清单/计数；真正的变更仍由 admin 组控制。
        # D-Bus policy 已将该只读方法列入 default 白名单，服务层保持一致。
        # 值统一转成字符串（aa{sv} 不能带 None），并丢掉空值：能力表里有、
        # manifest 里没有的 Agent 会因 LEFT JOIN 得到 NULL，字符串化后会变成
        # 字面量 "None" 显示到界面上。
        return [dbus.Dictionary({k: str(v) for k, v in a.items() if v is not None},
                               signature="sv")
                for a in self.engine.list_agents()]

    @dbus.service.method(config.INTERFACE, in_signature="sss", out_signature="b", sender_keyword="sender")
    def SetCapabilityPolicy(self, agent_id, capability, policy, sender=None):
        caller = self._require_admin(sender)
        old = self.engine.registry._policy_row(str(agent_id), str(capability))
        ok = self.engine.set_capability_policy(
            str(agent_id), str(capability), str(policy))
        self._audit_admin(caller, "set_capability_policy",
                          f"agent={agent_id};tool={capability};"
                          f"old_policy={old['policy'] if old else 'missing'};new_policy={policy}",
                          "success" if ok else "notfound")
        return ok

    @dbus.service.method(config.INTERFACE, in_signature="s", out_signature="a{sv}", sender_keyword="sender")
    def GetAgentSecurityMode(self, agent_id, sender=None):
        self._require_admin(sender)
        return _dbus_result(self.engine.get_agent_security_mode(str(agent_id)))

    @dbus.service.method(config.INTERFACE, in_signature="s", out_signature="a{sv}", sender_keyword="sender")
    def GetPermissionSettings(self, agent_id, sender=None):
        self._require_agent_or_admin(str(agent_id), sender)
        import json as _json
        settings = self.engine.get_permission_settings(str(agent_id))
        return dbus.Dictionary(
            {k: _json.dumps(v, ensure_ascii=False) for k, v in settings.items()},
            signature="sv")

    @dbus.service.method(config.INTERFACE, in_signature="sss", out_signature="a{sv}", sender_keyword="sender")
    def SetPermissionGroup(self, agent_id, group, value, sender=None):
        caller = self._require_admin(sender)
        import json as _json
        # D-Bus 只能传字符串，客户端把数组/对象编码成 JSON；这里先还原成
        # 原始值再交给 permissions.normalise 校验，否则 read/write 会收到
        # 一个字符串而被判成"需要是路径数组"。
        try:
            payload = _json.loads(str(value))
        except (TypeError, ValueError) as exc:
            raise ValueError(f"权限值不是合法 JSON：{exc}") from exc
        result = self.engine.set_permission_group(str(agent_id), str(group), payload)
        self._audit_admin(caller, "set_permission_group",
                          f"agent={agent_id};group={result['group']}")
        return dbus.Dictionary({
            "agent_id": dbus.String(result["agent_id"]),
            "group": dbus.String(result["group"]),
            "value": dbus.String(_json.dumps(result["value"], ensure_ascii=False)),
        }, signature="sv")

    @dbus.service.method(config.INTERFACE, in_signature="s", out_signature="a{sv}", sender_keyword="sender")
    def GetSecurityPermissions(self, agent_id, sender=None):
        self._require_agent_or_admin(str(agent_id), sender)
        import json as _json
        return dbus.Dictionary(
            {"json": _json.dumps(self.engine.get_security_permissions(str(agent_id)),
                                 ensure_ascii=False)},
            signature="sv")

    @dbus.service.method(config.INTERFACE, in_signature="ss", out_signature="a{sv}", sender_keyword="sender")
    def SetAgentSecurityMode(self, agent_id, mode, sender=None):
        caller = self._require_admin(sender)
        actor = (f"uid={caller.uid};pid={caller.pid};"
                 f"exe={caller.executable or '-'};cgroup={caller.cgroup or '-'}")
        return _dbus_result(self.engine.set_agent_security_mode(
            str(agent_id), str(mode), actor))

    @dbus.service.method(config.INTERFACE, in_signature="s", out_signature="a{sv}", sender_keyword="sender")
    def GetAgentInfo(self, agent_id, sender=None):
        self._require_agent_or_admin(str(agent_id), sender)
        import json as _json
        # 嵌套结构（manifest/capabilities/network）序列化为 JSON 字符串，避免 a{sv} 深层类型难题
        info = self.engine.get_agent_info(str(agent_id))
        return dbus.Dictionary({"json": _json.dumps(info, ensure_ascii=False)}, signature="sv")

    @dbus.service.method(config.INTERFACE, in_signature="s", out_signature="a{sv}", sender_keyword="sender")
    def GetNetworkPolicy(self, agent_id, sender=None):
        self._require_agent_or_admin(str(agent_id), sender)
        import json as _json
        p = self.engine.get_network_policy(str(agent_id))
        p["apply"] = self.engine.get_network_policy_apply_status(str(agent_id))
        return dbus.Dictionary({"json": _json.dumps(p, ensure_ascii=False)}, signature="sv")

    @dbus.service.method(config.INTERFACE, in_signature="sss", out_signature="b", sender_keyword="sender")
    def SetDLPPolicy(self, agent_id, pii_type, action, sender=None):
        caller = self._require_admin(sender)
        from .dlp.policy_store import DLPAction, DLPPolicyStore
        from .dlp.pii_scanner import PIIType
        aid, pt, act = str(agent_id).strip(), str(pii_type).strip(), str(action).strip().lower()
        if not aid or not pt:
            raise ValueError("agent_id 与 pii_type 必填")
        if pt not in {item.value for item in PIIType} | {"*"}:
            raise ValueError("非法 pii_type")
        DLPPolicyStore().set_policy(aid, pt, DLPAction(act))
        self._audit_admin(caller, "set_dlp_policy", f"agent={aid};pii_type={pt};action={act}")
        return True

    @dbus.service.method(config.INTERFACE, in_signature="ss", out_signature="b", sender_keyword="sender")
    def DeleteDLPPolicy(self, agent_id, pii_type, sender=None):
        caller = self._require_admin(sender)
        from .dlp.policy_store import DLPPolicyStore
        aid, pt = str(agent_id).strip(), str(pii_type).strip()
        if not aid or not pt:
            raise ValueError("agent_id 与 pii_type 必填")
        count = DLPPolicyStore().delete_policy(aid, None if pt == "*" else pt)
        self._audit_admin(caller, "delete_dlp_policy", f"agent={aid};pii_type={pt};deleted={count}")
        return bool(count)


def main(argv=None):
    argv = argv or sys.argv[1:]
    use_session = "--session" in argv
    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
    bus = dbus.SessionBus() if use_session else dbus.SystemBus()

    engine = SecurityEngine()
    # 信号发射器接线
    service = SecurityService(bus, engine)
    runtime_service = SecurityRuntimeService(bus, service)
    service.runtime_engine = runtime_service.engine
    # V2 syscall audit validation is implemented by SecurityEngine and must
    # use the same live Runtime lease engine as the D-Bus service facade.
    engine.runtime_engine = runtime_service.engine
    engine._alert_emit = lambda a, t, d: service.SecurityAlert(a, t, d)
    engine.confirm._emit = lambda rid, a, cap, det: service.ConfirmRequest(a, cap, det, rid)

    uds_server, uds_handlers = build_security_uds_server(
        engine, runtime_engine=runtime_service.engine)
    from .kernel_syscall_audit import KernelAuditReader
    kernel_audit = KernelAuditReader(engine)
    audit_timer = GLib.timeout_add(100, kernel_audit.poll)
    loop = GLib.MainLoop()

    def request_shutdown(_signum=None, _frame=None):
        loop.quit()

    for signum in (signal.SIGTERM, signal.SIGINT):
        signal.signal(signum, request_shutdown)
    try:
        uds_server.start()
        name = dbus.service.BusName(config.BUS_NAME, bus)
        print(f"bianbu-securityd started on {'session' if use_session else 'system'} bus "
              f"as {config.BUS_NAME}; uds={config.UDS_SOCKET_PATH}", flush=True)
        loop.run()
    except KeyboardInterrupt:
        pass
    finally:
        GLib.source_remove(audit_timer)
        kernel_audit.close()
        try:
            runtime_service.close()
        finally:
            try:
                uds_server.stop()
            finally:
                try:
                    uds_handlers.close()
                finally:
                    engine.close()


if __name__ == "__main__":
    main()
