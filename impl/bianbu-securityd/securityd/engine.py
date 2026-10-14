"""SecurityEngine：组合全部子模块，实现 io.bianbu.Security 方法的业务逻辑。

D-Bus 服务层（service.py）与测试/ CLI 均调用本引擎，保证行为一致。
对齐设计 §5 方法 + §6 业务流程。
"""
from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from typing import Callable, Optional

from . import config, manifest as manifest_mod, network_policy, seccomp_builder
from .audit_chain import AuditChainEngine
from .capability_registry import CapabilityRegistry
from .confirm import ConfirmGatekeeper
from .errors import AuditFailure, NotFound, PermissionDenied
from .key_vault import KeyVault
from .models import CallerContext, Decision, Permission, Policy, policy_decision
from .network_learning import NetworkLearningStore
from .syscall_policy import SyscallPolicyStore
from .syscall_audit import SyscallAuditStore


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def _normalized_ts(value: object) -> str:
    """把审计/绑定/安装时间统一成 ISO-8601（UTC、毫秒）。

    SQLite 的 ``datetime('now')`` 产出 ``YYYY-MM-DD HH:MM:SS``（UTC、无时区），
    审计链、caller 绑定和系统调用事件写 ISO-8601；展示层只认识一种格式，
    因此在这里归一。无法解析的值返回空串，由调用方忽略。
    """
    text = str(value or "").strip()
    if not text:
        return ""
    if "T" not in text:
        text = text.replace(" ", "T", 1)
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return ""
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).isoformat(timespec="milliseconds")


def _latest_ts(values) -> str:
    """返回一批时间戳里最新的一个；同格式下 ISO-8601 可直接按字典序比较。"""
    normalized = [ts for ts in (_normalized_ts(value) for value in values) if ts]
    return max(normalized) if normalized else ""


class SecurityEngine:
    def __init__(self, confirm_ui=None, alert_emit: Optional[Callable] = None,
                 confirm_emit: Optional[Callable] = None):
        config.ensure_dirs()
        self.registry = CapabilityRegistry()
        self.audit = AuditChainEngine()
        self.syscall_policy = SyscallPolicyStore()
        self.syscall_audit = SyscallAuditStore()
        self.network_learning = NetworkLearningStore()
        self.vault = KeyVault()
        self.confirm = ConfirmGatekeeper(ui_callback=confirm_ui, signal_emit=confirm_emit)
        self._alert_emit = alert_emit  # emit(agent_id, type, detail)

    # —— 审计（Fail-Closed）——
    def audit_log(self, agent_id: str, op_type: str, target: str, result: str,
                  *, request_id: str = "") -> int:
        try:
            return self.audit.log(agent_id, op_type, target, result,
                                  request_id=request_id)
        except AuditFailure:
            self._alert(agent_id, "audit_failure", f"{op_type}:{target}")
            raise

    def _alert(self, agent_id: str, atype: str, detail: str) -> None:
        if self._alert_emit:
            try:
                self._alert_emit(agent_id, atype, detail)
            except Exception:  # noqa: BLE001
                pass

    # —— FR-SEC-01 ——
    def verify_manifest(self, pkg_path: str):
        valid, reason, m = manifest_mod.verify_manifest(pkg_path)
        perms = [p.to_dict() for p in m.permissions] if m else []
        return valid, reason, perms, m

    # —— D-6 代码签名（Hook / Tool / Skill 安装期门禁）——
    def verify_code_package(self, pkg_path: str, kind: str = "hook") -> dict:
        """校验一个代码包能否安装。返回 SignatureVerdict 的字典形式。

        与 verify_manifest 分开：manifest 校验的是 Agent 包的权限声明，
        这里校验的是**任意可执行目录**的完整性 —— hook 没有 manifest.toml，
        但它是可执行代码且权力大于 tool，同样需要来源可信。
        """
        from . import code_signing

        v = code_signing.verify_code_package(pkg_path, kind=kind)
        # 装不上要留痕（运维得知道"有个包因签名被挡了"）；
        # 未签名放行也留痕，否则 enforce 前无法评估影响面。
        self.audit_log("system", "verify_code_package", f"{kind}:{pkg_path}",
                       f"{'allow' if v.allowed else 'deny'}:"
                       f"{'signed' if v.signed else 'unsigned'}:{v.policy}")
        return v.to_dict()

    def verify_code_digest(self, digest: str, signature: str,
                           kind: str = "hook") -> dict:
        """校验调用方命名空间内代码包的摘要/签名，不读取调用方路径。"""
        from . import code_signing

        v = code_signing.verify_code_digest(digest, signature, kind=kind)
        self.audit_log("system", "verify_code_digest", f"{kind}:{digest[:16]}",
                       f"{'allow' if v.allowed else 'deny'}:"
                       f"{'signed' if v.signed else 'unsigned'}:{v.policy}")
        return v.to_dict()

    # —— FR-SEC-02 安装/注册 ——
    def register_capabilities(self, agent_id: str, perms: list[Permission],
                              manifest=None, caller: CallerContext | None = None) -> bool:
        self.registry.register_capabilities(agent_id, perms)
        if manifest is not None:
            self.registry.record_manifest(
                agent_id, manifest.version, manifest.name, manifest.signature, "", _now(),
                framework=str(getattr(manifest, "framework", "") or ""))
        self.audit_log(agent_id, "register", agent_id, "success")
        if caller is not None:
            self.registry.bind_agent(agent_id, caller, _now())
        return True

    def register_agent(self, agent_id: str, metadata: dict | None = None) -> dict:
        if metadata is None:
            metadata = {}
        if not isinstance(metadata, dict):
            raise ValueError("metadata must be a dictionary")
        result = self.registry.register_agent(
            agent_id,
            metadata.get("name", ""),
            metadata.get("version", "1.0.0"),
            str(metadata.get("framework", "") or ""),
        )
        self.audit_log(str(result["agent_id"]), "register_agent",
                       str(result["agent_id"]), "success")
        return result

    def unregister_agent(self, agent_id: str) -> bool:
        aid = str(agent_id).strip()
        if not aid:
            raise ValueError("agent_id must not be empty")
        removed = self.registry.unregister_agent(aid)
        self.audit_log(aid, "unregister_agent", aid,
                       "success" if removed else "notfound")
        return removed

    def sync_agent_capabilities(self, agent_id: str, perms: list[Permission]) -> dict:
        aid = str(agent_id).strip()
        if not aid:
            raise ValueError("agent_id must not be empty")
        self.registry.sync_capabilities(aid, perms)
        self.audit_log(aid, "sync_capabilities", aid, f"count={len(perms)}")
        return {"agent_id": aid, "count": len(perms), "status": "synced"}

    def get_agent_security_mode(self, agent_id: str) -> dict:
        return self.registry.get_security_mode(agent_id)

    def set_agent_security_mode(self, agent_id: str, mode: str, actor: str) -> dict:
        """Apply effective controls while retaining saved normal policies."""
        changed_at = _now()
        old_effective = self._effective_network_policy(agent_id)
        saved_network = self.registry.get_network_policy(agent_id)
        current_mode = self.registry.get_security_mode(agent_id)["mode"]
        runtime = getattr(self, "runtime_engine", None)
        if mode != current_mode and runtime is not None:
            getter = (getattr(runtime, "active_instances_for_worker", None)
                      or getattr(runtime, "active_instances", None)
                      or getattr(runtime, "instances", None))
            if getter and any(row.get("backend") == "bwrap" for row in getter(agent_id)):
                raise PermissionDenied("bwrap network namespace requires restart")
        result = self.registry.set_security_mode(agent_id, mode, actor, changed_at)
        new_effective = self._effective_network_policy(agent_id)
        network_changed = new_effective != old_effective
        try:
            if network_changed:
                self._apply_network_policy(agent_id, new_effective, saved_network, allow_stopped=True)
            self.audit_log(
                str(result["agent_id"]), "security_mode_change",
                f"agent={result['agent_id']};old_mode={result['old_mode']};"
                f"new_mode={result['mode']};actor={actor};timestamp={changed_at}",
                "success",
            )
        except Exception:
            # An unaudited privilege transition must not remain effective.
            self.registry.set_security_mode(
                str(result["agent_id"]), str(result["old_mode"]), actor, _now())
            if network_changed:
                self._apply_network_policy(agent_id, old_effective, saved_network, allow_stopped=True)
            raise
        return result

    def install_package(self, pkg_path: str) -> tuple[bool, str]:
        """完整安装：验签 → 注册 → 记 manifest（含 raw 供网络策略）。"""
        valid, reason, _perms, m = self.verify_manifest(pkg_path)
        if not valid or m is None:
            return False, reason
        # Runtime bindings are mandatory for the PA default Agent package in
        # production.  Legacy capability-only packages remain installable for
        # the existing Security API, but cannot become a trusted Worker host
        # launch because runtime.policy requires this registered value.
        if (str(m.agent_id) == "com.bianbu.agent" and
                not m.runtime_entrypoint):
            return False, "com.bianbu.agent manifest 缺少 [runtime].entrypoint"
        old = self.registry.get_manifest_info(m.agent_id)
        if old is not None:
            from .code_signing import prevents_rollback
            if not prevents_rollback(str(old.get("version", "")), m.version):
                self.audit_log(m.agent_id, "install", pkg_path,
                               f"rollback_denied:{old.get('version')}->{m.version}")
                return False, f"版本回滚被拒绝：当前 {old.get('version')}，候选 {m.version}"
        # Package installation supplies the initial grants, but an upgrade
        # must not silently overwrite operator revocations or pending review
        # decisions for capabilities that remain present in the new manifest.
        self.registry.register_capabilities(
            m.agent_id, m.permissions, granted=1,
            preserve_existing_granted=old is not None,
        )
        from pathlib import Path
        p = Path(pkg_path)
        raw = (p / "manifest.toml" if p.is_dir() else p).read_text()
        self.registry.record_manifest(
            m.agent_id, m.version, m.name, m.signature, raw, _now(),
            framework=str(getattr(m, "framework", "") or ""))
        # A clean package install gets the signed manifest's initial policy.
        # Existing agents retain operator-configured policy across upgrades.
        if old is None:
            self.registry.set_network_policy(
                m.agent_id, m.allowed_domains, m.network_mode
            )
        self.audit_log(m.agent_id, "install", pkg_path, "success")
        return True, ""

    def bind_agent(self, agent_id: str, caller: CallerContext) -> bool:
        """显式启动绑定入口；只允许为当前 caller 建立自身绑定。"""
        if caller is None:
            return False
        self.registry.bind_agent(agent_id, caller, _now())
        self.audit_log(agent_id, "bind_caller", caller.sender, "success")
        return True

    def caller_allowed(self, agent_id: str, caller: CallerContext | None,
                       *, require_session: bool = False,
                       binding: dict | None = None) -> bool:
        if binding is None:
            ok = self.registry.caller_matches(
                agent_id, caller, require_session=require_session)
        else:
            ok = self.registry.caller_matches_binding(
                binding, caller, require_session=require_session)
        if not ok:
            self.audit_log(agent_id, "caller_identity", getattr(caller, "sender", "unknown"), "deny")
            self._alert(agent_id, "caller_identity_denied", getattr(caller, "sender", "unknown"))
        return ok

    def install_package_info(self, pkg_path: str) -> dict:
        """完整安装并返回 {ok, reason, agent_id, count} —— 供 WebUI/CLI 展示。"""
        valid, reason, _perms, m = self.verify_manifest(pkg_path)
        if not valid or m is None:
            return {"ok": False, "reason": reason, "agent_id": "", "count": 0}
        ok, r = self.install_package(pkg_path)
        return {"ok": ok, "reason": r, "agent_id": m.agent_id,
                "count": len(m.permissions)}

    # —— FR-SEC-02/03 权限校验 ——
    def check_permission(self, agent_id: str, capability: str, scope: str = "",
                         session_id: str = "") -> Decision:
        mode = self.registry.get_security_mode(
            agent_id, require_registered=False)["mode"]
        if mode == "yolo":
            d = Decision.ALLOW
            result = "decision=ALLOW;mode=yolo"
        else:
            d = self.registry.check_permission(agent_id, capability, scope, session_id)
            result = {Decision.ALLOW: "allow", Decision.ASK: "ask", Decision.DENY: "deny"}[d]
        self.audit_log(agent_id, "check_permission", f"{capability}:{scope}", result)
        if d == Decision.DENY:
            self._alert(agent_id, "permission_denied", f"{capability}:{scope}")
        return d

    # —— FR-SEC-03 确认门禁 ——
    def request_confirm(self, agent_id: str, capability: str, detail: str,
                        session_id: str = "", scope: str = "", caller=None) -> bool:
        if self.registry.get_security_mode(agent_id, require_registered=False).get("mode") == "yolo":
            self.audit_log(agent_id, "confirm", capability, "confirm_approved;mode=yolo")
            return True
        approved = self.confirm.request(agent_id, capability, detail, caller=caller)
        if approved:
            # ask 策略在本会话内记住批准结果，避免同一会话反复弹窗。
            if session_id:
                self.registry.grant_session_trust(session_id, agent_id, capability, _now())
            self.audit_log(agent_id, "ask", capability, "ask_approved")
        else:
            self.audit_log(agent_id, "ask", capability, "ask_denied")
        return approved

    def grant_session_trust(self, agent_id: str, capability: str,
                            scope: str, session_id: str) -> bool:
        """记录 PA 已完成 HITL 批准的 once_per_session 信任。

        LangGraph 的 HITL 门禁由 PA 承担，批准不会经过 RequestConfirmV2，
        因此必须由一个受 service caller 校验保护的接口补写 session_trust。
        仅允许策略为 ask 的工具写会话信任；deny 永不缓存。
        """
        row = self.registry._policy_row(agent_id, capability)
        if row is None or str(row["policy"]) != Policy.ASK.value:
            self.audit_log(agent_id, "session_trust", capability, "deny")
            return False
        self.registry.grant_session_trust(session_id, agent_id, capability, _now())
        self.audit_log(agent_id, "session_trust", capability, "grant")
        return True

    def revoke_permission(self, agent_id: str, capability: str) -> bool:
        ok = self.registry.revoke_permission(agent_id, capability)
        self.audit_log(agent_id, "revoke", capability, "success" if ok else "notfound")
        return ok

    def get_capabilities(self, agent_id: str) -> list[dict]:
        perms = self.registry.get_capabilities(agent_id)
        return [p.to_dict() for p in perms]

    # —— WebUI 支撑：列 agent / 单条工具策略 / 详情 / 网络查 ——
    def list_agents(self) -> list[dict]:
        """Agent 清单，附带 WebUI「最近活动」时间（``last_seen``）。

        Securityd 没有单独的心跳表，最近活动取三类真实活动证据中的最新时间：
        审计链（判权、Hook、管理等动作）、系统调用拦截事件、caller 绑定
        （最近一次被 Runtime 拉起）。任一路读取失败只降级该路证据。

        安装时间不是活动证据：把 manifest 的 ``installed_at`` 当成最近活动，
        会让一个装了但从没跑过的 Agent 显示成"最近活跃"，用户拿它和实际使用
        时间一对就对不上。因此没有活动证据的 Agent 返回空串，由展示层明确写成
        「暂无活动」。``installed_at`` 仍然返回，且与 ``last_seen`` 统一成
        带时区的 ISO-8601（UTC、毫秒），避免前端把无时区的裸时间按本地时间解析。
        """
        rows = self.registry.list_agents()
        last_seen = self._last_seen_index(rows)
        for row in rows:
            row["last_seen"] = last_seen.get(str(row.get("agent_id", "")), "")
            installed_at = str(row.get("installed_at") or "")
            if installed_at:
                row["installed_at"] = _normalized_ts(installed_at) or installed_at
        return rows

    def _last_seen_index(self, rows: list[dict]) -> dict[str, str]:
        """汇总清单里每个 Agent 最近一次真实活动的规范化时间戳。"""
        candidates: dict[str, list[str]] = {}
        for row in rows:
            agent_id = str(row.get("agent_id", "") or "")
            if agent_id:
                candidates[agent_id] = []
        if not candidates:
            return {}
        for collect in (self.audit.activity_index,
                        self.syscall_audit.latest_seen,
                        self.registry.binding_times):
            try:
                found = collect(list(candidates))
            except Exception:  # noqa: BLE001 — 只读展示，缺一路证据就降级
                continue
            for agent_id, ts in (found or {}).items():
                key = str(agent_id)
                if key in candidates:
                    candidates[key].append(str(ts))
        return {agent_id: latest for agent_id, values in candidates.items()
                if (latest := _latest_ts(values))}

    def set_capability_policy(self, agent_id: str, capability: str,
                              policy: str) -> bool:
        ok = self.registry.set_policy(agent_id, capability, policy)
        self.audit_log(agent_id, "set_policy", capability,
                       f"{Policy(str(policy)).value}:{'ok' if ok else 'notfound'}")
        return ok

    def get_agent_info(self, agent_id: str) -> dict:
        manifest = self.registry.get_manifest_info(agent_id)
        capabilities = self.get_capabilities(agent_id)
        registered = bool(manifest) or bool(capabilities)
        return {
            "agent_id": agent_id,
            # 未注册 Agent 原先也返回默认 network/permissions，调用方无法区分
            # "未注册" 与 "已注册未配置"（验收缺陷 D-8）。
            "registered": registered,
            "framework": self.registry.get_framework(agent_id),
            "manifest": manifest,
            "capabilities": capabilities,
            # 安全权限设置：可读范围 / 可写范围（各自 include + exclude）。
            # 网络访问范围与系统调用黑名单各自有独立查询接口，避免同一份
            # 数据在两处漂移；这里只汇总文件系统范围。
            "permissions": self.get_permission_settings(agent_id) if registered else None,
            "network": self.get_network_policy(agent_id) if registered else None,
        }

    # —— 安全权限设置（可读范围 / 可写范围，各自包含 + 排除）——
    def get_permission_settings(self, agent_id: str) -> dict:
        return self.registry.get_permission_settings(str(agent_id))

    def execution_mode_for(self, agent_id: str) -> dict:
        """这个 Agent 应该跑 host 还是 sandbox——由已声明的安全设置推导。

        不是人指定的开关：声明了可读/可写范围、受限网络或 syscall 追加项就
        需要沙箱来落实；什么都没声明就走 host。缺少可信 launch 的 Agent 一律
        进沙箱（fail-closed）。
        """
        from . import execution_mode as execution_mode_mod

        aid = str(agent_id)
        settings = self.registry.get_permission_settings(aid)
        try:
            network = self.get_network_policy(aid)
        except (TypeError, ValueError):
            network = None
        additions: object = ()
        try:
            manifest = self.registry.get_manifest_info(aid)
            entrypoint = self.registry.get_entrypoint(aid)
            trusted = bool(manifest) and str(manifest.get("status", "active")) == "active" and bool(entrypoint)
        except (TypeError, ValueError):
            trusted = False
        try:
            arch = "x86_64" if os.uname().machine in {"x86_64", "amd64"} else "riscv64"
            additions = (self.get_syscall_policy(aid, arch) or {}).get("agent_additions") or ()
        except Exception:  # noqa: BLE001 — 只读推导，缺一路就当作没声明
            additions = ()
        return execution_mode_mod.decide(
            read=settings.get("read"), write=settings.get("write"),
            network=network, syscall_additions=additions, trusted=trusted)

    def get_security_permissions(self, agent_id: str) -> dict:
        """汇总一个 Agent 的完整安全权限设置（供控制台/插件一次读取）。

        四组：可读范围 ``read``、可写范围 ``write``、网络访问范围 ``network``、
        系统调用黑名单 ``syscall``。前两组（各自的 include/exclude）由
        capability_registry 持久化；网络与 syscall 各自有权威存储，这里只
        做汇总，避免同一条策略在多处漂移。
        """
        aid = str(agent_id)
        settings = self.registry.get_permission_settings(aid)
        network = self.get_network_policy(aid) or {
            "agent_id": aid, "mode": "allow_all", "domains": [], "version": 0}
        arch = "x86_64" if os.uname().machine in {"x86_64", "amd64"} else "riscv64"
        try:
            syscall = self.get_syscall_policy(aid, arch)
        except Exception:  # noqa: BLE001 — 只读汇总，缺一路就降级
            syscall = {"arch": arch, "agent_additions": [],
                       "effective": [], "policy_version": 0,
                       "applied_policy_version": 0, "pending_restart": False}
        return {
            "agent_id": aid,
            "read": settings.get("read", {"include": [], "exclude": []}),
            "write": settings.get("write", {"include": [], "exclude": []}),
            "network": {
                "mode": str(network.get("mode", "allow_all")),
                "domains": list(network.get("domains", []) or []),
                "version": int(network.get("version", 0) or 0),
            },
            "syscall": {
                "arch": str(syscall.get("arch", arch)),
                "agent_additions": list(syscall.get("agent_additions", []) or []),
                "effective": list(syscall.get("effective", []) or []),
                "policy_version": int(syscall.get("policy_version", 0) or 0),
                "applied_policy_version": int(
                    syscall.get("applied_policy_version", 0) or 0),
                "pending_restart": bool(syscall.get("pending_restart", False)),
            },
            # 执行模式是推导出来的结论，与设置一起返回，方便控制台直接展示。
            "execution_mode": self.execution_mode_for(aid),
        }

    def set_permission_group(self, agent_id: str, group: str, value: object) -> dict:
        from . import permissions as permissions_mod

        name = permissions_mod.group_name(group)
        normalised = self.registry.set_permission_group(str(agent_id), name, value)
        try:
            summary = json.dumps(normalised, ensure_ascii=False, sort_keys=True)[:200]
        except (TypeError, ValueError):
            summary = name
        self.audit_log(str(agent_id), "set_permission_group", f"{name}:{summary}",
                       "success")
        return {"agent_id": str(agent_id), "group": name, "value": normalised}

    def _effective_network_policy(self, agent_id: str) -> dict:
        configured = self.registry.get_network_policy(agent_id) or {
            "agent_id": agent_id, "mode": "allow_all", "domains": [], "version": 0}
        if self.registry.get_security_mode(agent_id, require_registered=False).get("mode") == "yolo":
            configured = {**configured, "mode": "allow_all", "domains": [], "observe": True}
        return configured

    def get_network_policy(self, agent_id: str) -> dict:
        configured = self._effective_network_policy(agent_id)
        enforcement = network_policy.enforcement_status(agent_id)
        runtime = getattr(self, "runtime_engine", None)
        if runtime is not None and hasattr(runtime, "active_instances_for_worker"):
            status = self.get_network_policy_apply_status(agent_id)
            enforced = status["effective"] and status["active_instances"] > 0
            enforcement.update(mode="systemd" if enforced else "artifact_only",
                               enforced=enforced,
                               reason="" if enforced else "当前策略尚未在全部运行实例上验证生效")
        return {**network_policy.read_rules(agent_id), **configured,
                "enforcement": enforcement}

    def build_seccomp_profile(self, agent_id: str) -> tuple[str, int]:
        """生成并标记应用当前版本的 seccomp 过滤器，供 host-process Worker 使用。

        返回 (seccomp_path, applied_policy_version)。与 build_sandbox_policy 共用
        同一份 denylist 快照，但不生成 netfilter 规则。
        """
        arch = "x86_64" if os.uname().machine in {"x86_64", "amd64"} else "riscv64"
        snapshot = self.syscall_policy.get(agent_id, arch)
        seccomp_path = seccomp_builder.build_policy_file(agent_id, arch, snapshot["effective"])
        self.syscall_policy.mark_applied(agent_id, arch, snapshot["policy_version"])
        self.audit_log(agent_id, "build_seccomp_profile",
                       f"arch={arch};version={snapshot['policy_version']}", "success")
        return seccomp_path, int(snapshot["policy_version"])

    # —— FR-SBX-03/04/05 沙箱策略 ——
    def build_sandbox_policy(self, agent_id: str) -> tuple[str, str]:
        arch = "x86_64" if os.uname().machine in {"x86_64", "amd64"} else "riscv64"
        snapshot = self.syscall_policy.get(agent_id, arch)
        seccomp_path = seccomp_builder.build_policy_file(agent_id, arch, snapshot["effective"])
        self.syscall_policy.mark_applied(agent_id, arch, snapshot["policy_version"])
        configured = self._effective_network_policy(agent_id)
        domains = (list(configured.get("domains", [])) if configured
                   else [])
        # Keep the sandbox rule artifact consistent with get_network_policy()
        # and Runtime launch leases: missing legacy rows mean allow_all.
        mode = str(configured.get("mode", "allow_all")) if configured else "allow_all"
        rules_path = network_policy.build_rules(agent_id, domains, mode)
        self.audit_log(agent_id, "build_sandbox_policy", agent_id, "success")
        return seccomp_path, rules_path

    def get_syscall_catalog(self, arch: str) -> dict:
        return self.syscall_policy.catalog(str(arch))

    def get_syscall_policy(self, agent_id: str, arch: str) -> dict:
        return self.syscall_policy.get(str(agent_id), str(arch))

    def set_global_syscall_policy(self, arch: str, additions: list[str], actor: str = "admin") -> dict:
        result = self.syscall_policy.set_global(str(arch), additions, actor)
        self.audit_log("system", "set_global_syscall_policy", str(arch), f"success:{result['policy_version']}")
        return result

    def set_agent_syscall_policy(self, agent_id: str, arch: str, additions: list[str], actor: str = "admin") -> dict:
        result = self.syscall_policy.set_agent(str(agent_id), str(arch), additions, actor)
        self.audit_log(str(agent_id), "set_agent_syscall_policy", str(arch), f"success:{result['policy_version']}")
        return result

    def reset_agent_syscall_policy(self, agent_id: str, arch: str, actor: str = "admin") -> dict:
        result = self.syscall_policy.reset_agent(str(agent_id), str(arch), actor)
        self.audit_log(str(agent_id), "reset_agent_syscall_policy", str(arch), f"success:{result['policy_version']}")
        return result

    def _worker_execution_view(self, agent_id: str) -> dict:
        """从 lease DB 推导逻辑 Agent 的 Worker 实况（缺陷 D-4：原先固定 unknown）。"""
        runtime = getattr(self, "runtime_engine", None)
        if runtime is None:
            return {"state": "unknown", "reason": "security.runtime 未启用"}
        try:
            active = runtime.active_instances_for_worker(str(agent_id))
        except Exception as exc:  # noqa: BLE001 - status must not raise
            return {"state": "unknown", "reason": str(exc)[:200]}
        if not active:
            return {"state": "stopped", "instances": 0}
        latest = active[0]
        return {
            "state": "running",
            "instances": len(active),
            "instance_id": str(latest.get("instance_id", "")),
            "lease_id": str(latest.get("lease_id", "")),
            "pid": int(latest.get("pid", 0) or 0),
            "cgroup_path": str(latest.get("cgroup_path", "")),
            "backend": str(latest.get("backend", "")),
            "started_at": int(latest.get("started_at", 0) or 0),
        }

    def get_security_execution_status(self, agent_id: str) -> dict:
        arch = "x86_64" if os.uname().machine in {"x86_64", "amd64"} else "riscv64"
        policy = self.syscall_policy.get(str(agent_id), arch)
        return {"agent_id": str(agent_id), "control": {"state": "running"},
                "securityd": {"state": "running"},
                "worker": self._worker_execution_view(str(agent_id)),
                "seccomp": {"status": "pending_restart" if policy["pending_restart"] else "active",
                            **policy}, "audit": self.syscall_audit_status()}

    def syscall_audit_status(self) -> dict:
        runtime = getattr(self, "runtime_engine", None)
        running = []
        if runtime is not None:
            try:
                running = runtime.leases.syscall_audit_instances()
                running = [r for r in running if str(r.get("state")) == "running"]
            except Exception:  # noqa: BLE001
                running = []
        return self.syscall_audit.status(running)

    def record_syscall_interception(self, agent_id: str, pid: int, arch: str,
                                    syscall: str, number: int, backend: str,
                                    policy_version: int) -> dict:
        """Record a deny event in the independent syscall audit chain."""
        return self.syscall_audit.record(agent_id, pid, arch, syscall, number,
                                         backend, policy_version)

    def record_syscall_interception_v2(self, agent_id: str, instance_id: str,
                                       lease_id: str, pid: int, cgroup_id: int,
                                       arch: str, syscall: str, number: int,
                                       backend: str, policy_version: int,
                                       event_id: str = "", worker_agent_id: str = "") -> dict:
        """Record an event only after validating it belongs to a live lease."""
        # The privileged kernel observer is authoritative when available and
        # also covers exited children. Avoid duplicate best-effort auditd reports.
        from .kernel_syscall_audit import kernel_observer_status
        if backend == "auditd-seccomp" and kernel_observer_status():
            return {"backend": "ebpf-seccomp", "delegated": True}
        # Runtime lease validation is kernel-backed (PID/cgroup), not caller supplied.
        cgroup_path = self.runtime_engine._actual_cgroup(int(pid))
        if not self.runtime_engine.authorize_worker(
                str(agent_id), pid=int(pid), cgroup_path=cgroup_path,
                instance_id=str(instance_id), lease_id=str(lease_id)):
            raise PermissionDenied("Worker syscall event 未通过 Runtime lease 身份校验")
        return self.syscall_audit.record(agent_id, pid, arch, syscall, number,
                                         backend, policy_version,
                                         worker_agent_id=worker_agent_id, instance_id=instance_id, lease_id=lease_id,
                                         cgroup_id=cgroup_id, event_id=event_id)

    def get_syscall_audit_events(self, agent_id: str = "", instance_id: str = "",
                                 limit: int = 100, cursor: int = 0) -> list[dict]:
        return self.syscall_audit.query(agent_id=agent_id, instance_id=instance_id,
                                        limit=limit, cursor=cursor)

    def get_syscall_audit_status(self) -> dict:
        return self.syscall_audit_status()

    def _require_network_learning_worker(self, identity: dict) -> str:
        agent_id = str(identity.get("agent_id", "")).strip()
        runtime = getattr(self, "runtime_engine", None)
        if runtime is None:
            raise PermissionDenied("Network learning Runtime engine unavailable")
        try:
            cgroup_path = runtime._actual_cgroup(int(identity.get("pid", 0)))
            authorized = runtime.authorize_worker(
                agent_id,
                pid=int(identity.get("pid", 0)),
                cgroup_path=cgroup_path,
                instance_id=str(identity.get("instance_id", "")),
                lease_id=str(identity.get("lease_id", "")),
            )
        except Exception as exc:
            self.audit_log(agent_id or "unknown", "network_learning_identity",
                           str(identity.get("instance_id", "")), "deny")
            raise PermissionDenied(
                "Network learning event 未通过 Runtime lease 身份校验") from exc
        if not authorized:
            self.audit_log(agent_id or "unknown", "network_learning_identity",
                           str(identity.get("instance_id", "")), "deny")
            raise PermissionDenied(
                "Network learning event 未通过 Runtime lease 身份校验")
        resolver = getattr(runtime, "worker_agent_id_for_lease", None)
        if callable(resolver):
            return str(resolver(
                agent_id, str(identity.get("instance_id", "")),
                str(identity.get("lease_id", "")),
            )).strip()
        return agent_id

    def _network_observation_enabled(self, agent_id: str) -> bool:
        if self.registry.get_security_mode(agent_id, require_registered=False).get("mode") == "yolo":
            return True
        return (self.registry.get_network_policy(agent_id) or {}).get("mode") == "learning"

    def record_network_learning_event(self, identity: dict, event: dict) -> bool:
        agent_id = self._require_network_learning_worker(identity)
        if not self._network_observation_enabled(agent_id):
            self.audit_log(agent_id or "unknown", "network_learning_event",
                           str(event.get("event_id", "")), "deny:not_learning")
            raise PermissionDenied("Agent 当前网络策略不是 learning")
        owner = {**identity, "agent_id": agent_id}
        try:
            inserted = self.network_learning.record(owner, event)
        except (TypeError, ValueError) as exc:
            self.audit_log(agent_id or "unknown", "network_learning_event",
                           str(event.get("event_id", "")), "deny:invalid")
            raise
        return inserted

    def report_network_learning_collector(self, identity: dict, state: str,
                                          reason: str = "") -> bool:
        agent_id = self._require_network_learning_worker(identity)
        if str(state) != "inactive" and not self._network_observation_enabled(agent_id):
            raise PermissionDenied("Agent 当前网络策略不是 learning")
        owner = {**identity, "agent_id": agent_id}
        return self.network_learning.report_status(owner, state, reason)

    def get_network_learning_events(self, agent_id: str, limit: int = 100,
                                    cursor: int = 0) -> dict:
        return self.network_learning.query(str(agent_id), limit=int(limit),
                                           cursor=int(cursor))

    def get_network_learning_status(self, agent_id: str) -> dict:
        aid = str(agent_id)
        runtime = getattr(self, "runtime_engine", None)
        active = []
        if self._network_observation_enabled(aid) and runtime is not None:
            active_instances = (
                runtime.active_instances_for_worker(aid)
                if hasattr(runtime, "active_instances_for_worker")
                else runtime.active_instances(aid)
            )
            active = [str(row.get("instance_id", ""))
                      for row in active_instances
                      if str(row.get("instance_id", ""))]
        return self.network_learning.status(aid, active)

    def clear_network_learning_events(self, agent_id: str) -> int:
        count = self.network_learning.clear(str(agent_id))
        self.audit_log(str(agent_id), "network_learning_clear", str(agent_id),
                       f"deleted={count}")
        return count

    def set_network_policy(self, agent_id: str, domains: list[str], mode: str = "whitelist") -> bool:
        mode = str(mode).strip().lower()
        old = self.registry.get_network_policy(agent_id)
        self.registry.set_network_policy(agent_id, domains, mode)
        return self._apply_network_policy(agent_id, self._effective_network_policy(agent_id), old)

    def _apply_network_policy(self, agent_id: str, configured: dict, old: dict | None,
                              *, allow_stopped: bool = False) -> bool:
        domains, mode = configured["domains"], configured["mode"]
        applied_instances = []
        if not hasattr(self, "_network_apply_statuses"):
            self._network_apply_statuses = {}
        self._network_apply_status = {"requested": True, "active_instances": 0,
                                      "applied_instances": 0, "failed_instances": 0,
                                      "effective": True,
                                      "restart_required": False,
                                      "restart_required_instances": 0}
        runtime = getattr(self, "runtime_engine", None)
        if runtime is not None:
            import json
            from client.runtime_launcher import update_runtime_network
            if hasattr(runtime, "active_instances_for_worker"):
                active = runtime.active_instances_for_worker(agent_id)
            elif hasattr(runtime, "active_instances"):
                active = runtime.active_instances(agent_id)
            else:
                active = runtime.instances(agent_id)
            self._network_apply_status["active_instances"] = len(active)
            for instance in active:
                if str(instance.get("backend", "")) == "bwrap":
                    self._network_apply_status["restart_required"] = True
                    self._network_apply_status["restart_required_instances"] += 1
                    self._network_apply_status["effective"] = False
                    if hasattr(runtime, "update_instance_network_policy"):
                        runtime.update_instance_network_policy(
                            instance["instance_id"], configured,
                            state="restart_required",
                            reason="bwrap network namespace requires restart",
                        )
                    elif hasattr(runtime, "leases"):
                        runtime.leases.update_instance_network_policy(
                            instance["instance_id"], configured,
                            state="restart_required",
                            reason="bwrap network namespace requires restart",
                        )
                    continue
                try:
                    att = json.loads(instance.get("attestation_json", "{}"))
                except (TypeError, ValueError):
                    att = {}
                unit = str(att.get("unit", ""))
                old_props = list(att.get("network_properties", []))
                if not unit or "network_properties" not in att:
                    self._network_apply_status.update(failed_instances=len(active), effective=False)
                    self._network_apply_statuses[agent_id] = dict(self._network_apply_status)
                    self.registry.restore_network_policy(agent_id, old) if old else self.registry.delete_network_policy(agent_id)
                    raise PermissionDenied("运行实例缺少可验证的 systemd 网络属性")
                new_props = network_policy.systemd_ip_filter_properties(
                    configured["domains"], mode=configured["mode"])
                result = update_runtime_network(unit, new_props, old_props,
                                                scope=str(att.get("systemd_scope", "user")))
                if not result.get("ok"):
                    self._network_apply_status.update(failed_instances=1, effective=False)
                    self._network_apply_statuses[agent_id] = dict(self._network_apply_status)
                    if old:
                        self.registry.restore_network_policy(agent_id, old)
                    else:
                        self.registry.delete_network_policy(agent_id)
                    raise PermissionDenied(str(result.get("reason", "网络策略热更新失败")))
                if hasattr(runtime, "update_instance_network_policy"):
                    runtime.update_instance_network_policy(
                        instance["instance_id"], configured, state="applied",
                        network_properties=new_props,
                    )
                elif hasattr(runtime, "leases"):
                    runtime.leases.update_instance_network_policy(
                        instance["instance_id"], configured, state="applied",
                        network_properties=new_props,
                    )
                applied_instances.append(instance["instance_id"])
            self._network_apply_status["applied_instances"] = len(applied_instances)
        try:
            path = network_policy.build_rules(agent_id, configured["domains"], configured["mode"])
        except Exception:
            if old is None:
                self.registry.delete_network_policy(agent_id)
            else:
                self.registry.restore_network_policy(agent_id, old)
            raise
        if allow_stopped and not self._network_apply_status["active_instances"]:
            self._network_apply_status["effective"] = False
            self._network_apply_statuses[agent_id] = dict(self._network_apply_status)
            self.audit_log(agent_id, "network_policy", ",".join(domains), "pending_launch")
            return True
        status = network_policy.enforcement_status(agent_id)
        production = str(os.environ.get("BIANBU_RUNTIME_MODE", "development")).lower() == "production"
        fail_closed = production or os.environ.get("BIANBU_SECURITY_NET_FAIL_CLOSED") == "1"
        live_enforced = bool(applied_instances) and len(applied_instances) == self._network_apply_status["active_instances"]
        if mode in {"whitelist", "deny_all"} and not (status["enforced"] or live_enforced):
            self.audit_log(agent_id, "network_policy", ",".join(domains),
                           "artifact_only:enforcement_unavailable")
            self._alert(agent_id, "network_enforcement_unavailable", status["reason"])
            if fail_closed:
                if old is None:
                    self.registry.delete_network_policy(agent_id)
                else:
                    self.registry.restore_network_policy(agent_id, old)
                raise PermissionDenied("网络强制后端不可用，按 fail-closed 拒绝策略")
        else:
            self.audit_log(agent_id, "network_policy", ",".join(domains), "applied")
        self._network_apply_statuses[agent_id] = dict(self._network_apply_status)
        return True

    def get_network_policy_apply_status(self, agent_id: str) -> dict:
        cached = dict(getattr(self, "_network_apply_statuses", {}).get(agent_id, {
            "requested": False, "active_instances": 0, "applied_instances": 0,
            "failed_instances": 0, "effective": False,
            "restart_required": False, "restart_required_instances": 0}))
        runtime = getattr(self, "runtime_engine", None)
        if runtime is None or not hasattr(runtime, "active_instances_for_worker"):
            return cached
        import json
        saved = self.registry.get_network_policy(agent_id)
        configured = self._effective_network_policy(agent_id)
        rows = runtime.active_instances_for_worker(agent_id)
        status = {"requested": bool(saved), "active_instances": len(rows),
                  "applied_instances": 0, "failed_instances": 0, "effective": False,
                  "restart_required": False, "restart_required_instances": 0}
        for row in rows:
            state = row.get("network_apply_state", "initial")
            try:
                applied = (json.loads(row.get("network_policy_json", "{}"))
                           if state == "applied" else row.get("lease_network_policy", {}))
                att = json.loads(row.get("attestation_json", "{}"))
                matches = all(applied.get(key) == configured.get(key)
                              for key in ("version", "mode", "domains"))
                if state == "restart_required" or not matches:
                    status["restart_required_instances"] += 1
                    continue
                properties = att.get("network_properties")
                # D-Bus clients historically stringify nested values with repr;
                # also accept JSON and native lists from other transports.
                if isinstance(properties, str):
                    try:
                        properties = json.loads(properties)
                    except ValueError:
                        import ast
                        properties = ast.literal_eval(properties)
                verified = isinstance(properties, list) and all(
                    isinstance(value, str) for value in properties
                ) and network_policy.verify_systemd_unit(
                    str(att.get("unit", "")), properties,
                    scope=str(att.get("systemd_scope", "system")))
            except (TypeError, ValueError, SyntaxError):
                verified = False
            status["applied_instances" if verified else "failed_instances"] += 1
        status["restart_required"] = status["restart_required_instances"] > 0
        status["effective"] = bool(rows) and status["applied_instances"] == len(rows)
        return status

    # —— FR-SEC-06 审计导出/验证 ——
    def query_audit(self, query_json: str) -> dict:
        return self.audit.query(query_json)

    def export_audit(self, filter_json: str, fmt: str = "json") -> str:
        return self.audit.export(filter_json, fmt)

    def verify_audit_chain(self, export_path: str) -> bool:
        return AuditChainEngine.verify_export(export_path)

    # —— Key Vault ——
    def get_secret(self, agent_id: str, key: str) -> str:
        # 门控：须持 secret.read 且已授权
        if self.check_permission(agent_id, "secret.read") == Decision.DENY:
            self._alert(agent_id, "secret_denied", key)
            raise PermissionDenied(f"agent {agent_id} 无 secret.read 权限")
        return self.vault.get_secret(agent_id, key)

    def put_secret(self, agent_id: str, key: str, value: str) -> bool:
        return self.vault.put_secret(agent_id, key, value)

    def close(self) -> None:
        # 先拒绝/唤醒 Confirm，避免等待线程在服务关闭后永久悬挂或复用旧批准。
        pending = self.confirm.list_pending()
        self.confirm.close()
        for ctx in pending:
            self.audit_log(ctx.agent_id, "confirm_cancelled_shutdown",
                           ctx.capability, f"request_id={ctx.request_id}")
        self.registry.close()
        self.syscall_policy.close()
        self.syscall_audit.close()
        self.network_learning.close()
        self.audit.close()
