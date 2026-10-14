import json
from types import SimpleNamespace


def test_kernel_capture_keeps_dead_pid_and_uses_committed_cgroup(sec_root, tmp_path, monkeypatch):
    from securityd.kernel_syscall_audit import record_kernel_event
    from securityd.syscall_audit import SyscallAuditStore
    from pathlib import Path
    cg = Path('/sys/fs/cgroup/test-worker')
    original_stat = Path.stat
    monkeypatch.setattr(Path, 'stat', lambda p, *a, **k:
        SimpleNamespace(st_ino=42) if p == cg else original_stat(p, *a, **k))
    policy = {'worker_agent_id': 'worker-a', 'seccomp_profile': {'policy_version': 7}}
    row = {'state': 'running', 'agent_id': 'runtime', 'instance_id': 'instance-a',
           'lease_id': 'lease-a', 'cgroup_path': str(cg), 'started_at': 10}
    leases = SimpleNamespace(syscall_audit_instances=lambda: [row],
        get=lambda _: {'state': 'committed', 'policy': policy})
    engine = SimpleNamespace(runtime_engine=SimpleNamespace(leases=leases), syscall_audit=SyscallAuditStore())
    event = {'pid': 99999999, 'cgroup_id': cg.stat().st_ino, 'number': 273,
             'code': 0x50000, 'arch': 'riscv64', 'event_id': 'kernel-test', 'time': 20}
    assert record_kernel_event(engine, event)
    record_kernel_event(engine, event)
    rows = engine.syscall_audit.query()
    assert len(rows) == 1
    assert rows[0]['pid'] == 99999999
    assert rows[0]['worker_agent_id'] == 'worker-a'
    assert rows[0]['policy_version'] == 7
    assert rows[0]['syscall'] == 'finit_module'
    for change in ({'cgroup_id': 0}, {'code': 0x7fff0000}, {'time': 1}, {'arch': 'unknown'}):
        assert not record_kernel_event(engine, dict(event, **change))
    row['state'] = 'stopped'
    assert not record_kernel_event(engine, event)


def test_untrusted_spool_is_rejected(tmp_path):
    from securityd.kernel_syscall_audit import trusted_open
    path = tmp_path / 'events.jsonl'; path.write_text('{}\n'); path.chmod(0o666)
    import pytest
    with pytest.raises(PermissionError): trusted_open(path)


def test_concurrent_kernel_and_runtime_events_preserve_chain(sec_root):
    from concurrent.futures import ThreadPoolExecutor
    from securityd.syscall_audit import SyscallAuditStore
    store = SyscallAuditStore()
    def append(i):
        store.record('runtime', i + 1, 'riscv64', 'mount', 40, 'ebpf-seccomp', 1,
                     event_id=f'event-{i}')
    with ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(append, range(40)))
    assert len(store.query()) == 40
    assert store.verify()


def test_kernel_event_with_real_lease_store(sec_root, tmp_path, monkeypatch):
    import time
    from pathlib import Path
    from runtime.lease import LaunchLeaseStore
    from securityd.kernel_syscall_audit import record_kernel_event
    from securityd.syscall_audit import SyscallAuditStore
    leases = LaunchLeaseStore(tmp_path / 'leases.db')
    issued = leases.issue(agent_id='runtime', policy={'worker_agent_id': 'real-worker',
        'seccomp_profile': {'policy_version': 3}}, requested_mode='sandbox',
        effective_mode='sandbox', backend='bwrap', sandbox_required=True)
    leases.commit(issued['lease_id'], instance_id='real-instance', pid=321,
                  cgroup_path='/test-cgroup', attestation={})
    original_stat = Path.stat
    monkeypatch.setattr(Path, 'stat', lambda p, *a, **k:
        SimpleNamespace(st_ino=1234) if str(p) == '/sys/fs/cgroup/test-cgroup'
        else original_stat(p, *a, **k))
    engine = SimpleNamespace(runtime_engine=SimpleNamespace(leases=leases), syscall_audit=SyscallAuditStore())
    assert record_kernel_event(engine, {'pid': 9999999, 'cgroup_id': 1234,
        'number': 273, 'code': 0x50000, 'arch': 'riscv64',
        'event_id': 'real-lease-test', 'time': time.time()})
    assert engine.syscall_audit.query()[0]['worker_agent_id'] == 'real-worker'


def test_reader_waits_for_complete_lines_and_follows_rotation(tmp_path, monkeypatch):
    import securityd.kernel_syscall_audit as module
    observed = []
    monkeypatch.setattr(module, 'trusted_open', lambda p: p.open())
    monkeypatch.setattr(module, 'record_kernel_event', lambda engine, row: observed.append(row))
    log = tmp_path / 'events.jsonl'
    log.write_text('{"id":1}')
    reader = module.KernelAuditReader(None, tmp_path)
    reader.poll()
    assert not observed
    with log.open('a') as f: f.write('\n')
    reader.poll()
    assert observed == [{'id': 1}]
    log.rename(tmp_path / 'events.jsonl.1')
    log.write_text('{"id":2}\n')
    reader.poll()
    assert observed == [{'id': 1}, {'id': 2}]
    reader.close()


def test_rotation_drains_more_than_one_batch(tmp_path, monkeypatch):
    import securityd.kernel_syscall_audit as module
    observed = []
    monkeypatch.setattr(module, 'trusted_open', lambda p: p.open())
    monkeypatch.setattr(module, 'record_kernel_event', lambda engine, row: observed.append(row['id']))
    previous = tmp_path / 'events.jsonl.1'
    previous.write_text(''.join(json.dumps({'id': i}) + '\n' for i in range(9000)))
    (tmp_path / 'events.jsonl').write_text('{"id":9000}\n')
    reader = module.KernelAuditReader(None, tmp_path)
    for _ in range(4): reader.poll()
    assert observed == list(range(9001))
    reader.close()


def test_captured_event_survives_worker_cgroup_removal_and_revocation(sec_root, tmp_path):
    import time
    from runtime.lease import LaunchLeaseStore
    from securityd.kernel_syscall_audit import record_kernel_event
    from securityd.syscall_audit import SyscallAuditStore
    leases = LaunchLeaseStore(tmp_path / 'leases.db')
    issued = leases.issue(agent_id='runtime', policy={'worker_agent_id': 'gone-worker'},
        requested_mode='sandbox', effective_mode='sandbox', backend='bwrap', sandbox_required=True)
    started = time.monotonic_ns()
    leases.commit(issued['lease_id'], instance_id='gone-instance', pid=99999999,
        cgroup_path='/already-deleted', attestation={}, audit_identity={
            'cgroup_id': 987, 'boot_id': 'test-boot', 'started_ns': started})
    captured = time.monotonic_ns()
    leases.revoke_agent('runtime', 'test shutdown')
    engine = SimpleNamespace(runtime_engine=SimpleNamespace(leases=leases), syscall_audit=SyscallAuditStore())
    event = {'pid': 9999999, 'cgroup_id': 987, 'number': 273, 'code': 0x50000,
        'arch': 'riscv64', 'event_id': 'exited-worker', 'time': time.time(),
        'boot_id': 'test-boot', 'monotonic_ns': captured}
    assert record_kernel_event(engine, event)
    for change in ({'boot_id': 'other-boot'}, {'monotonic_ns': started-1},
                   {'monotonic_ns': time.monotonic_ns()}, {'cgroup_id': 12}):
        assert not record_kernel_event(engine, dict(event, **change))
