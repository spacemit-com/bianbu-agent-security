"""securityd 正式 UDS 数据面 handler（ARCH-01）。"""
from __future__ import annotations

import grp
import json
import logging
import os
from dataclasses import asdict

from .caller_identity import caller_from_process
from .dlp.pii_scanner import PIIScanner
from .dlp.policy_store import DLPPolicyStore
from .engine import SecurityEngine
from .errors import PermissionDenied
from .uds_server import PeerCredentials, UdsServer


class SecurityUdsHandlers:
    def __init__(self, engine: SecurityEngine, runtime_engine=None):
        self.engine = engine
        # The Runtime engine is an optional dependency to preserve the small
        # unit-test handler surface.  In the service it is supplied so a
        # supervised Worker can be authorized by its committed lease rather
        # than replacing the control-plane agent_binding row.
        self.runtime_engine = runtime_engine
        self.scanner = PIIScanner()
        self.policy = DLPPolicyStore()

    @staticmethod
    def _required_text(req: dict, key: str, *, max_chars: int | None = None) -> str:
        value = req.get(key)
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{key} 必须是非空字符串")
        if max_chars is not None and len(value) > max_chars:
            raise ValueError(f"{key} 超过 {max_chars} 字符")
        return value

    def _require_agent(self, req: dict, peer: PeerCredentials | None):
        agent_id = self._required_text(req, "agent_id", max_chars=255)
        lease_agent_id = str(req.get("_worker_security_agent_id", "")).strip()
        auth_agent_id = lease_agent_id or agent_id
        if peer is None:
            raise PermissionDenied("平台未提供 SO_PEERCRED，拒绝 Agent 数据面请求")
        caller = caller_from_process(
            peer.uid, peer.pid, sender=f"uds:{peer.pid}",
            session_id=str(req.get("session_id", "")), include_groups=False)
        worker_instance = str(req.get("_worker_instance_id", "")).strip()
        worker_lease = str(req.get("_worker_lease_id", "")).strip()
        if worker_instance or worker_lease:
            if self.runtime_engine is None:
                raise PermissionDenied("security.runtime 未启用 Worker lease 校验")
            try:
                worker_ok = self.runtime_engine.authorize_worker(
                    auth_agent_id,
                    pid=peer.pid,
                    cgroup_path=caller.cgroup,
                    instance_id=worker_instance,
                    lease_id=worker_lease,
                )
            except Exception:
                worker_ok = False
            if not worker_ok:
                raise PermissionDenied("Worker 未通过已提交 Runtime lease 身份校验")
            # Return the logical Agent ID for capability/DLP/audit operations;
            # only lease authorization uses the Runtime security identity.
            return agent_id, caller
        # Development/session-bus deployments use the explicit test-admin
        # switch for management consoles before a persistent caller binding
        # has been established. Production deployments never set this flag.
        if os.environ.get("BIANBU_SECURITY_TEST_ADMIN") == "1":
            return agent_id, caller
        if not self.engine.caller_allowed(agent_id, caller):
            raise PermissionDenied(f"UDS caller 无权代表 agent {agent_id}")
        return agent_id, caller

    @staticmethod
    def ping(req: dict, uid: int | None, peer: PeerCredentials | None = None) -> dict:
        return {"pong": True, "peer_uid": uid,
                "peer_pid": peer.pid if peer else 0}

    def dlp_scan(self, req: dict, uid: int | None,
                 peer: PeerCredentials | None = None) -> dict:
        agent_id, _caller = self._require_agent(req, peer)
        text = req.get("text")
        if not isinstance(text, str):
            raise ValueError("text 必须是字符串")
        if self.engine.registry.get_security_mode(agent_id, require_registered=False).get("mode") == "yolo":
            request_id = str(req.get("_request_id", ""))
            seq = 0
            try:
                seq = self.engine.audit_log(
                    agent_id, "uds_dlp_scan", f"bytes={len(text.encode('utf-8'))}",
                    "skipped;mode=yolo", request_id=f"uds:{agent_id}:{request_id}" if request_id else "")
            except Exception:
                logging.getLogger(__name__).exception("YOLO DLP bypass audit failed for %s", agent_id)
            return {"has_pii": False, "findings": [], "masked_text": text,
                    "effective_policy": {}, "audit_seq": seq,
                    "mode": "yolo", "scanning_enabled": False}
        result = self.scanner.scan_and_mask(text)
        findings = []
        for finding in result.findings:
            item = asdict(finding)
            # 原始 PII 已在调用者输入里；响应只返回位置/类型/风险，避免再复制一份明文。
            item.pop("value", None)
            item["pii_type"] = finding.pii_type.value
            item["action"] = self.policy.get_action(
                agent_id, finding.pii_type).value
            findings.append(item)
        request_id = str(req.get("_request_id", ""))
        seq = self.engine.audit_log(
            agent_id, "uds_dlp_scan", f"bytes={len(text.encode('utf-8'))}",
            f"findings={len(findings)}",
            request_id=f"uds:{agent_id}:{request_id}" if request_id else "")
        return {
            "has_pii": bool(findings),
            "findings": findings,
            "masked_text": result.masked_text,
            "effective_policy": self.policy.effective_matrix(agent_id),
            "audit_seq": seq,
        }

    def dlp_policy(self, req: dict, uid: int | None,
                   peer: PeerCredentials | None = None) -> dict:
        """向已绑定 Agent 返回 securityd 中央生效策略，不允许客户端写策略。"""
        agent_id, _caller = self._require_agent(req, peer)
        mode = self.engine.registry.get_security_mode(agent_id, require_registered=False)["mode"]
        return {"effective_policy": self.policy.effective_matrix(agent_id),
                "mode": mode, "scanning_enabled": mode != "yolo"}

    def audit_batch(self, req: dict, uid: int | None,
                    peer: PeerCredentials | None = None) -> dict:
        agent_id, _caller = self._require_agent(req, peer)
        request_id = self._required_text(req, "_request_id", max_chars=128)
        entries = req.get("entries")
        if not isinstance(entries, list) or not entries or len(entries) > 100:
            raise ValueError("entries 必须是 1~100 条 JSON object")
        normalized = []
        for index, entry in enumerate(entries):
            if not isinstance(entry, dict):
                raise ValueError(f"entries[{index}] 必须是 JSON object")
            op_type = entry.get("op_type")
            target = entry.get("target", "")
            result = entry.get("result", "")
            payload = entry.get("payload", "")
            if not isinstance(op_type, str) or not op_type.strip() or len(op_type) > 128:
                raise ValueError(f"entries[{index}].op_type 非法")
            if not all(isinstance(value, str) for value in (target, result, payload)):
                raise ValueError(f"entries[{index}] 的 target/result/payload 必须是字符串")
            normalized.append({"op_type": op_type, "target": target,
                               "result": result, "payload": payload})
        document = json.dumps({
            "session_id": str(req.get("session_id", "")),
            "run_id": str(req.get("run_id", "")),
            "entries": normalized,
        }, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        seq = self.engine.audit_log(
            agent_id, "uds_audit_batch", f"entries={len(normalized)}", document,
            request_id=f"uds:{agent_id}:{request_id}")
        return {"audit_seq": seq, "accepted": len(normalized)}

    def permission_check(self, req: dict, uid: int | None,
                         peer: PeerCredentials | None = None) -> dict:
        agent_id, _caller = self._require_agent(req, peer)
        capability = self._required_text(req, "capability", max_chars=255)
        scope = str(req.get("scope", ""))
        session_id = str(req.get("session_id", ""))
        decision = self.engine.check_permission(
            agent_id, capability, scope, session_id=session_id)
        return {"decision": int(decision)}

    def session_trust(self, req: dict, uid: int | None,
                      peer: PeerCredentials | None = None) -> dict:
        agent_id, _caller = self._require_agent(req, peer)
        capability = self._required_text(req, "capability", max_chars=255)
        scope = str(req.get("scope", ""))
        session_id = self._required_text(req, "session_id", max_chars=255)
        return {"accepted": bool(self.engine.grant_session_trust(
            agent_id, capability, scope, session_id))}

    def security_mode(self, req: dict, uid: int | None,
                      peer: PeerCredentials | None = None) -> dict:
        agent_id, _caller = self._require_agent(req, peer)
        return {str(k): v for k, v in self.engine.get_agent_security_mode(agent_id).items()}

    def confirm_request(self, req: dict, uid: int | None,
                        peer: PeerCredentials | None = None) -> dict:
        agent_id, caller = self._require_agent(req, peer)
        capability = self._required_text(req, "capability", max_chars=255)
        detail = self._required_text(req, "detail", max_chars=4096)
        approved = self.engine.request_confirm(
            agent_id, capability, detail,
            session_id=str(req.get("session_id", "")), caller=caller)
        return {"approved": bool(approved)}

    def audit_log(self, req: dict, uid: int | None,
                  peer: PeerCredentials | None = None) -> dict:
        agent_id, _caller = self._require_agent(req, peer)
        op_type = self._required_text(req, "op_type", max_chars=128)
        target = str(req.get("target", ""))
        result = str(req.get("result", ""))
        seq = self.engine.audit_log(agent_id, op_type, target, result,
                                    request_id=str(req.get("_request_id", "")))
        return {"audit_seq": int(seq)}

    def capabilities_list(self, req: dict, uid: int | None,
                          peer: PeerCredentials | None = None) -> dict:
        agent_id, _caller = self._require_agent(req, peer)
        return {"capabilities": self.engine.get_capabilities(agent_id)}

    def permission_settings(self, req: dict, uid: int | None,
                            peer: PeerCredentials | None = None) -> dict:
        """Worker 启动时可读：可读范围 / 可写范围 / 自定义补充项。"""
        agent_id, _caller = self._require_agent(req, peer)
        return {str(k): v for k, v in
                self.engine.get_permission_settings(agent_id).items()}

    def worker_identity(self, req: dict, uid: int | None,
                       peer: PeerCredentials | None = None) -> dict:
        """Authenticated Worker bootstrap probe.

        The response contains only kernel-derived peer coordinates.  The
        instance/lease values in the request are used solely for lookup and
        are accepted only after ``authorize_worker`` validates PID/cgroup.
        """
        agent_id, caller = self._require_agent(req, peer)
        return {"authorized": True, "agent_id": agent_id,
                "pid": int(caller.pid), "cgroup": str(caller.cgroup)}

    def register(self, server: UdsServer) -> None:
        server.register("ping", self.ping)
        server.register("dlp.policy", self.dlp_policy)
        server.register("dlp.scan", self.dlp_scan)
        server.register("audit.batch", self.audit_batch)
        server.register("permission.check", self.permission_check)
        server.register("session.trust", self.session_trust)
        server.register("security.mode", self.security_mode)
        server.register("confirm.request", self.confirm_request)
        server.register("audit.log", self.audit_log)
        server.register("capabilities.list", self.capabilities_list)
        server.register("permissions.settings", self.permission_settings)
        server.register("worker.identity", self.worker_identity)

    def close(self) -> None:
        self.policy.close()


def build_security_uds_server(engine: SecurityEngine, runtime_engine=None) -> tuple[UdsServer, SecurityUdsHandlers]:
    allowed_gids = set()
    for group_name in ("bianbu-security", "bianbu"):
        try:
            allowed_gids.add(grp.getgrnam(group_name).gr_gid)
        except KeyError:
            pass
    server = UdsServer(allowed_gids=allowed_gids)
    handlers = SecurityUdsHandlers(engine, runtime_engine=runtime_engine)
    handlers.register(server)
    return server, handlers


__all__ = ["SecurityUdsHandlers", "build_security_uds_server"]
