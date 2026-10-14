from __future__ import annotations

def test_syscall_audit_has_independent_chain(sec_root):
    from securityd.syscall_audit import SyscallAuditStore
    store = SyscallAuditStore()
    a = store.record("agent-a", 123, "x86_64", "mount", 165, "ebpf", 3)
    b = store.record("agent-a", 123, "x86_64", "reboot", 169, "ebpf", 3)
    assert b["seq"] == a["seq"] + 1
    assert store.verify() is True
    assert store.status()["status"] in {"active", "unavailable"}


def test_syscall_audit_does_not_share_security_audit_db(sec_root):
    from securityd.syscall_audit import SyscallAuditStore
    store = SyscallAuditStore()
    assert "syscall" in str(store.db_path)

def test_syscall_audit_records_deny_action(sec_root):
    from securityd.syscall_audit import SyscallAuditStore
    event = SyscallAuditStore().record("a", 1, "x86_64", "mount", 165, "ebpf", 1)
    assert event["seq"] == 1

def test_syscall_audit_tracks_runtime_identity_and_deduplicates(sec_root):
    from securityd.syscall_audit import SyscallAuditStore
    store = SyscallAuditStore()
    kwargs = dict(worker_agent_id="agent-123", instance_id="inst-1", lease_id="lease-1", cgroup_id=42,
                  event_id="evt-1")
    first = store.record("a", 10, "x86_64", "mount", 165, "seccomp-user-notify", 2, **kwargs)
    again = store.record("a", 10, "x86_64", "mount", 165, "seccomp-user-notify", 2, **kwargs)
    assert again["seq"] == first["seq"]
    rows = store.query(agent_id="a")
    assert rows[0]["instance_id"] == "inst-1"
    assert rows[0]["worker_agent_id"] == "agent-123"
    assert rows[0]["lease_id"] == "lease-1"
    assert rows[0]["cgroup_id"] == 42
    assert store.status()["events"] == 1


def test_installed_auditctl_does_not_imply_active_observer(sec_root, monkeypatch, tmp_path):
    import securityd.syscall_audit as module
    monkeypatch.setattr(module.shutil, 'which', lambda _: '/usr/sbin/auditctl')
    monkeypatch.setattr(module, 'COLLECTOR_STATUS_DIR', tmp_path / 'absent', raising=False)
    # 隔离宿主机真实的 root 内核观测器（bianbu-syscall-observer.service 的
    # /run/bianbu-syscall-audit/status.json）；本用例只验"装了 auditctl ≠ 有活跃采集器"。
    monkeypatch.setattr(module, 'kernel_observer_status', lambda: None)
    status = module.SyscallAuditStore().status()
    assert status['status'] == 'unavailable'
    assert status['coverage'] == 'none'


def test_observer_heartbeat_must_be_fresh_and_process_alive(sec_root, monkeypatch, tmp_path):
    import json, os, time
    import securityd.syscall_audit as module
    monkeypatch.setattr(module, 'COLLECTOR_STATUS_DIR', tmp_path, raising=False)
    # 同上：在装有活跃内核观测器的机器上不隔离会被提升为 active，掩盖 heartbeat 判定。
    monkeypatch.setattr(module, 'kernel_observer_status', lambda: None)
    path = tmp_path / 'worker.json'
    path.write_text(json.dumps({'pid': os.getpid(), 'updated_at': time.time(),
                               'status': 'active', 'backend': 'auditd-seccomp'}))
    store = module.SyscallAuditStore()
    assert store.status()['status'] == 'degraded'
    path.write_text(json.dumps({'pid': os.getpid(), 'updated_at': time.time()-60,
                               'status': 'active', 'backend': 'auditd-seccomp'}))
    assert store.status()['status'] == 'unavailable'


def test_kernel_observer_is_required_for_full_deny_coverage(sec_root, monkeypatch, tmp_path):
    import securityd.syscall_audit as module
    monkeypatch.setattr(module, 'COLLECTOR_STATUS_DIR', tmp_path)
    monkeypatch.setattr(module, 'kernel_observer_status', lambda: {'status': 'active'})
    status = module.SyscallAuditStore().status()
    assert status['status'] == 'active'
    assert status['backend'] == 'ebpf-seccomp'
    assert status['coverage'] == 'deny-only'


def test_status_degrades_when_running_instances_lack_kernel_log_flag(sec_root, monkeypatch, tmp_path):
    """D-3：有 running 实例未带 SECCOMP_FILTER_FLAG_LOG 时不得宣称 active。"""
    import json
    import securityd.syscall_audit as module
    monkeypatch.setattr(module, 'COLLECTOR_STATUS_DIR', tmp_path)
    monkeypatch.setattr(module, 'kernel_observer_status', lambda: {'status': 'active'})
    store = module.SyscallAuditStore()
    logged = {'instance_id': 'i-logged', 'state': 'running',
              'attestation_json': json.dumps({'kernel_seccomp_log': True})}
    unlogged = {'instance_id': 'i-host', 'state': 'running',
                'attestation_json': json.dumps({'backend': 'host-process'})}
    assert store.status([logged])['status'] == 'active'
    status = store.status([logged, unlogged])
    assert status['status'] == 'degraded'
    assert status['unlogged_instances'] == ['i-host']
    assert 'SECCOMP_FILTER_FLAG_LOG' in status['reason']


def test_query_matches_lease_agent_or_worker_agent(sec_root):
    from securityd.syscall_audit import SyscallAuditStore
    store = SyscallAuditStore()
    store.record("com.bianbu.runtime", 10, "riscv64", "mount", 40, "ebpf", 1,
                 worker_agent_id="com.logical.agent", instance_id="i", lease_id="l",
                 cgroup_id=1, event_id="e1")
    assert len(store.query(agent_id="com.bianbu.runtime")) == 1
    assert len(store.query(agent_id="com.logical.agent")) == 1
    assert store.query(agent_id="com.other") == []
