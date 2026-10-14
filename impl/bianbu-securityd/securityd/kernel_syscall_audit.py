"""Consume root-owned kernel observations, including already-exited children.

This path is deliberately separate from the Runtime reporting API: only the
privileged observer can supply a cgroup identity captured at interception time.
"""
from __future__ import annotations
import json
import logging
import os
import stat
import time
from pathlib import Path
from .seccomp_builder import _ARCH_TABLE

ROOT = Path('/run/bianbu-syscall-audit')
logger = logging.getLogger(__name__)


def trusted_open(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    info = os.fstat(fd)
    if info.st_uid != 0 or info.st_mode & 0o022 or not stat.S_ISREG(info.st_mode):
        os.close(fd)
        raise PermissionError('kernel audit spool must be a root-owned, non-writable regular file')
    return os.fdopen(fd, 'r')


def kernel_observer_status():
    try:
        with trusted_open(ROOT / 'status.json') as f:
            row = json.load(f)
        if (row.get('status') == 'active' and 0 <= time.time() - float(row['updated_at']) <= 10
                and Path(f'/proc/{int(row["pid"])}').exists()):
            return row
    except (OSError, ValueError, KeyError, TypeError):
        pass
    return None


def matches_instance(row, event):
    try:
        identity = json.loads(row.get('audit_identity_json', '{}'))
        if identity:
            captured = int(event['monotonic_ns'])
            ended = int(row.get('audit_ended_ns', 0))
            return (row['state'] in {'running', 'revoked'}
                and identity['boot_id'] == event['boot_id']
                and int(identity['cgroup_id']) == int(event['cgroup_id'])
                and int(identity['started_ns']) <= captured
                and (not ended or captured <= ended)
                and (row['state'] != 'revoked' or ended > 0))
        # Leases created by older versions have no durable kernel identity.
        # Keep their conservative live-cgroup check; never trust attestation.
        if row['state'] != 'running' or float(event['time']) < int(row['started_at']):
            return False
        cg = Path(row['cgroup_path'])
        if not str(cg).startswith('/sys/fs/cgroup/'):
            cg = Path('/sys/fs/cgroup') / str(cg).lstrip('/')
        return cg.stat().st_ino == int(event['cgroup_id'])
    except (OSError, ValueError, TypeError, KeyError):
        return False


def record_kernel_event(engine, event):
    """Private trusted-spool entry point; never exposed through D-Bus or UDS."""
    try:
        if int(event['code']) & 0xffff0000 != 0x50000 or int(event['pid']) <= 0:
            return False
        table = _ARCH_TABLE[event['arch']][1]
        name = next((n for n, v in table.items() if v == int(event['number'])), None)
        if name is None:
            return False
        for row in engine.runtime_engine.leases.syscall_audit_instances():
            if not matches_instance(row, event):
                continue
            lease = engine.runtime_engine.leases.get(row['lease_id'])
            if not lease or lease['state'] not in {'committed', 'revoked'}:
                continue
            policy = lease['policy']
            engine.syscall_audit.record(row['agent_id'], int(event['pid']), event['arch'],
                name, int(event['number']), 'ebpf-seccomp',
                int((policy.get('seccomp_profile') or {}).get('policy_version', 0)),
                worker_agent_id=policy.get('worker_agent_id', row['agent_id']),
                instance_id=row['instance_id'], lease_id=row['lease_id'],
                cgroup_id=int(event['cgroup_id']), event_id=event['event_id'])
            return True
    except (ValueError, TypeError, KeyError):
        return False
    return False


class KernelAuditReader:
    def __init__(self, engine, root=ROOT):
        self.engine, self.root, self.stream = engine, Path(root), None

    def poll(self):
        try:
            if self.stream is None:
                # Replaying after a daemon restart is safe: kernel event IDs
                # are stable and SyscallAuditStore deduplicates them.
                previous = self.root / 'events.jsonl.1'
                self.stream = trusted_open(previous if previous.exists() else self.root / 'events.jsonl')
            exhausted = self._consume(self.stream)
            if exhausted and os.fstat(self.stream.fileno()).st_ino != (self.root / 'events.jsonl').stat().st_ino:
                self.stream.close()
                self.stream = trusted_open(self.root / 'events.jsonl')
                self._consume(self.stream)
        except (OSError, ValueError):
            pass
        except Exception:
            logger.exception('kernel syscall audit ingestion failed')
        return True

    def _consume(self, stream):
        for _ in range(4096):
            offset = stream.tell()
            line = stream.readline()
            if not line:
                return True
            if not line.endswith('\n'):
                stream.seek(offset)
                return False
            try:
                record_kernel_event(self.engine, json.loads(line))
            except (ValueError, TypeError):
                logger.warning('invalid kernel audit record')
        return False

    def close(self):
        if self.stream is not None:
            self.stream.close()
