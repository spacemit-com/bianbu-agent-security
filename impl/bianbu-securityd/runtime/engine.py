"""security.runtime 的策略、启动租约和证明校验。"""
from __future__ import annotations

import os
import time
import uuid
from pathlib import Path
from typing import Any

from securityd import config

from .lease import LaunchLeaseStore, LeaseError
from .policy import ExecutionDecision, RuntimePolicyError, build_execution_policy


class RuntimeEngineError(RuntimeError):
    """Runtime 安全操作失败。"""


class SecurityRuntimeEngine:
    def __init__(self, security_engine):
        self.security_engine = security_engine
        ttl = int(os.environ.get("BIANBU_SECURITY_LEASE_TTL", "30"))
        self.leases = LaunchLeaseStore(config.ETC_DIR / "runtime-leases.db",
                                       ttl_seconds=ttl)

    def close(self) -> None:
        self.leases.close()

    def reap_dead_instances(self) -> list[dict[str, Any]]:
        """securityd 启动时收敛已消失 Worker 的 running 实例（缺陷 D-9）。"""
        def alive(pid: int, cgroup_path: str) -> bool:
            if pid <= 0 or not Path(f"/proc/{pid}").exists():
                return False
            try:
                actual = self._actual_cgroup(pid)
            except RuntimeEngineError:
                return False
            return self._normalise_cgroup(actual) == self._normalise_cgroup(cgroup_path)

        lost = self.leases.reap_dead(alive)
        for row in lost:
            self.security_engine.audit_log(
                str(row.get("agent_id", "")), "runtime_instance_lost",
                f"lease={row.get('lease_id')};instance={row.get('instance_id')};pid={row.get('pid')}",
                "worker process gone")
        return lost

    def stop_instance(self, lease_id: str, instance_id: str, reason: str) -> dict[str, Any]:
        try:
            result = self.leases.stop_instance(str(lease_id), str(instance_id), str(reason)[:1024])
        except LeaseError as exc:
            raise RuntimeEngineError(str(exc)) from exc
        if result.get("changed"):
            self.security_engine.audit_log(
                str(result.get("agent_id", "")), "runtime_instance_stop",
                f"lease={lease_id};instance={instance_id}", str(reason)[:1024])
        return result

    def prepare_start(self, agent_id: str, request: dict[str, Any]) -> dict[str, Any]:
        requested = str(request.get("requested_mode", "auto") or "auto")
        decision = build_execution_policy(self.security_engine, agent_id, requested,
                                          request=request)
        lease = self.leases.issue(
            agent_id=decision.agent_id, policy=decision.policy,
            requested_mode=decision.requested_mode,
            effective_mode=decision.effective_mode, backend=decision.backend,
            sandbox_required=decision.sandbox_required, reason=decision.reason)
        self.security_engine.audit_log(
            decision.agent_id, "runtime_prepare_start",
            f"lease={lease['lease_id']};mode={decision.effective_mode}",
            decision.reason)
        return {
            "lease_id": lease["lease_id"],
            "policy_json": decision.policy_json,
            "effective_mode": decision.effective_mode,
            "backend": decision.backend,
            "sandbox_required": decision.sandbox_required,
            "expires_at": lease["expires_at"],
            "reason": decision.reason,
        }

    @staticmethod
    def _actual_cgroup(pid: int) -> str:
        try:
            rows = Path(f"/proc/{int(pid)}/cgroup").read_text().splitlines()
        except OSError as exc:
            raise RuntimeEngineError("无法读取 attestation pid 的 cgroup") from exc
        # cgroup v2 unified hierarchy is ``0::<path>``.  On a hybrid host,
        # prefer it but accept the first non-empty hierarchy for compatibility.
        candidates = []
        for row in rows:
            parts = row.split(":", 2)
            if len(parts) == 3 and parts[2].strip():
                candidates.append(parts[2].strip())
                if parts[0] == "0":
                    return parts[2].strip()
        if candidates:
            return candidates[0]
        raise RuntimeEngineError("attestation pid 没有可验证的 cgroup")

    @staticmethod
    def _normalise_cgroup(value: str) -> str:
        selected = str(value).strip()
        if selected.startswith("0::"):
            selected = selected[3:]
        if selected.startswith("/sys/fs/cgroup"):
            selected = selected[len("/sys/fs/cgroup"):]
        if not selected.startswith("/"):
            selected = "/" + selected
        return selected.rstrip("/") or "/"

    @staticmethod
    def _namespace_ids(pid: int) -> dict[str, str]:
        names = ("user", "pid", "mnt", "ipc", "uts", "net")
        values: dict[str, str] = {}
        for name in names:
            try:
                values[name] = os.readlink(f"/proc/{int(pid)}/ns/{name}")
            except OSError as exc:
                raise RuntimeEngineError(f"无法读取 pid namespace：{name}") from exc
        return values

    @classmethod
    def _validate_attestation(cls, row: dict[str, Any], instance_id: str, pid: int,
                              cgroup_path: str, attestation: dict[str, Any]) -> None:
        if not instance_id or len(instance_id) > 255:
            raise RuntimeEngineError("instance_id 非法")
        if int(pid) <= 0 or not Path(f"/proc/{int(pid)}").exists():
            raise RuntimeEngineError("attestation pid 不存在")
        if not str(cgroup_path).strip():
            raise RuntimeEngineError("cgroup_path 不能为空")
        actual_cgroup = cls._actual_cgroup(pid)
        if cls._normalise_cgroup(cgroup_path) != cls._normalise_cgroup(actual_cgroup):
            raise RuntimeEngineError(
                f"cgroup_path 不匹配：声明={cgroup_path} 实际={actual_cgroup}")
        policy = row["policy"]
        if str(attestation.get("backend", "")) != str(row["backend"]):
            raise RuntimeEngineError("backend 不匹配")
        if int(attestation.get("pid", pid)) != int(pid):
            raise RuntimeEngineError("attestation pid 不匹配")
        if row["effective_mode"] == "sandbox":
            if not bool(attestation.get("sandboxed", False)):
                raise RuntimeEngineError("sandbox lease 缺少 sandboxed 证明")
            if not str(attestation.get("container_id", "")).strip():
                raise RuntimeEngineError("sandbox lease 缺少 container_id")
            # Do not trust a caller-provided boolean as proof.  The committed
            # PID must be in at least a separate user and mount namespace from
            # securityd itself.  bwrap/OCI backends satisfy this; a host
            # process claiming ``sandboxed=true`` does not.
            target_ns = cls._namespace_ids(pid)
            security_ns = cls._namespace_ids(os.getpid())
            if target_ns["user"] == security_ns["user"] and target_ns["mnt"] == security_ns["mnt"]:
                raise RuntimeEngineError("sandbox lease 的 PID 未处于隔离 namespace")
        if bool(policy.get("sandbox_required")) and row["effective_mode"] != "sandbox":
            raise RuntimeEngineError("策略要求 sandbox 但租约模式不是 sandbox")

    def commit_start(self, lease_id: str, instance_id: str, pid: int,
                     cgroup_path: str, attestation: dict[str, Any]) -> dict[str, Any]:
        row = self.leases._require_issued(lease_id)
        self._validate_attestation(row, instance_id, pid, cgroup_path, attestation)
        # Persist kernel-derived identity while the cgroup still exists. It is
        # separate from caller-supplied attestation and survives Worker exit.
        import time
        cg = Path('/sys/fs/cgroup') / self._normalise_cgroup(cgroup_path).lstrip('/')
        audit_identity = {'cgroup_id': cg.stat().st_ino,
            'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
            'started_ns': time.monotonic_ns()}
        result = self.leases.commit(lease_id, instance_id=instance_id, pid=int(pid),
                                    cgroup_path=cgroup_path, attestation=attestation,
                                    audit_identity=audit_identity)
        try:
            self.security_engine.audit_log(
                row["agent_id"], "runtime_commit_start",
                f"lease={lease_id};instance={instance_id};pid={pid}", "success")
        except Exception as exc:
            # A committed lease cannot be Abort'ed. Keep durable state
            # terminal and fail closed so PA stops the backend.
            self.leases.fail_commit(lease_id, f"commit audit failed: {exc}")
            raise RuntimeEngineError("CommitStart 审计失败，租约已标记 failed") from exc
        return result

    def abort_start(self, lease_id: str, reason: str) -> bool:
        row = self.leases.get(lease_id)
        if row is None:
            raise RuntimeEngineError("lease 不存在")
        self.leases.abort(lease_id, str(reason)[:1024])
        self.security_engine.audit_log(row["agent_id"], "runtime_abort_start",
                                       f"lease={lease_id}", str(reason)[:1024])
        return True

    def sandbox_policy(self, lease_id: str) -> dict[str, Any]:
        """Return the immutable policy attached to a live launch lease.

        A policy is never rebuilt from the current registry here.  Returning
        the lease snapshot prevents a capability/network change between
        ``PrepareStart`` and backend creation from silently changing the
        command that is about to be started.
        """
        row = self.leases.get(str(lease_id))
        if row is None:
            raise RuntimeEngineError("lease 不存在")
        if row["state"] not in {"issued", "committed"}:
            raise RuntimeEngineError(f"lease 状态不可查询：{row['state']}")
        if row["state"] == "issued" and self.leases.is_expired(row):
            # Reuse the same expiry transition as Commit.
            self.leases._require_issued(str(lease_id))
        return dict(row["policy"])

    def revoke_agent(self, agent_id: str, reason: str) -> bool:
        count = self.leases.revoke_agent(str(agent_id), str(reason)[:1024])
        self.security_engine.audit_log(str(agent_id), "runtime_revoke_agent",
                                       str(reason)[:1024], f"revoked={count}")
        return count > 0

    def state(self, agent_id: str) -> dict[str, Any]:
        return self.leases.state(str(agent_id))

    def instances(self, agent_id: str) -> list[dict[str, Any]]:
        return self.leases.instances(str(agent_id))

    def active_instances(self, agent_id: str) -> list[dict[str, Any]]:
        active = []
        for row in self.leases.active_instances(str(agent_id)):
            try:
                actual = self._actual_cgroup(int(row.get("pid", 0) or 0))
            except (OSError, RuntimeError, ValueError, TypeError):
                continue
            if self._normalise_cgroup(actual) != self._normalise_cgroup(
                str(row.get("cgroup_path", ""))
            ):
                continue
            active.append(row)
        return active

    def active_instances_for_worker(self, worker_agent_id: str) -> list[dict[str, Any]]:
        active = []
        for row in self.leases.active_instances_for_worker(str(worker_agent_id)):
            try:
                actual = self._actual_cgroup(int(row.get("pid", 0) or 0))
            except (OSError, RuntimeError, ValueError, TypeError):
                continue
            if self._normalise_cgroup(actual) != self._normalise_cgroup(
                str(row.get("cgroup_path", ""))
            ):
                continue
            active.append(row)
        return active

    def worker_agent_id_for_lease(self, agent_id: str, instance_id: str,
                                  lease_id: str) -> str:
        lease = self.leases.get(str(lease_id))
        if lease is None or str(lease.get("agent_id", "")) != str(agent_id):
            raise RuntimeEngineError("lease 与安全主体不匹配")
        if str(lease.get("instance_id", "")) != str(instance_id):
            raise RuntimeEngineError("lease 与 Worker 实例不匹配")
        return str(
            lease.get("policy", {}).get("worker_agent_id") or agent_id
        ).strip()

    def update_instance_network_policy(
        self, instance_id: str, policy: dict, *, state: str = "applied",
        reason: str = "", network_properties: list[str] | None = None,
    ):
        return self.leases.update_instance_network_policy(
            instance_id, policy, state=state, reason=reason,
            network_properties=network_properties,
        )

    def authorize_worker(self, agent_id: str, *, pid: int, cgroup_path: str,
                         instance_id: str = "", lease_id: str = "") -> bool:
        """Verify a Worker caller against a committed Runtime lease.

        The ordinary ``agent_binding`` table represents the control-plane
        process and is intentionally one-to-one.  A supervised Worker is a
        separate process, so it must be authorized by the immutable lease and
        the kernel-backed PID/cgroup recorded by ``CommitStart`` instead of
        replacing that binding.  No caller-supplied identity fields are used.
        """
        selected_pid = int(pid)
        selected_cgroup = self._normalise_cgroup(cgroup_path)
        if selected_pid <= 0 or not selected_cgroup:
            return False
        for row in self.leases.instances(str(agent_id)):
            if str(row.get("state", "")) != "running":
                continue
            if instance_id and str(row.get("instance_id", "")) != str(instance_id):
                continue
            if lease_id and str(row.get("lease_id", "")) != str(lease_id):
                continue
            recorded_pid = int(row.get("pid", 0) or 0)
            if recorded_pid != selected_pid:
                # bwrap exposes the outer launcher PID through SO_PEERCRED,
                # while CommitStart records the Worker PID observed from its
                # RPC namespace.  Terminal commands are short-lived and may
                # also be gone by the time the collector forwards an event.
                # In that case the committed cgroup is the durable identity;
                # the selected PID is still required to be in that exact
                # cgroup.  Lease, instance and cgroup checks remain mandatory.
                try:
                    recorded_cgroup = self._actual_cgroup(recorded_pid)
                except Exception:
                    recorded_cgroup = str(row.get("cgroup_path", ""))
                if self._normalise_cgroup(recorded_cgroup) != selected_cgroup:
                    continue
            if selected_cgroup != self._normalise_cgroup(str(row.get("cgroup_path", ""))):
                continue
            lease = self.leases.get(str(row.get("lease_id", "")))
            if lease is None or str(lease.get("state", "")) != "committed":
                continue
            return True
        return False


__all__ = ["SecurityRuntimeEngine", "RuntimeEngineError", "LeaseError",
           "ExecutionDecision", "RuntimePolicyError"]
