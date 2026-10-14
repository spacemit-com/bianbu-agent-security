#!/usr/bin/python3
"""Privileged, read-only kernel observer. Never accepts Runtime-supplied events."""
import json
import os
import platform
import signal
import subprocess
import time
from pathlib import Path

ROOT = Path('/run/bianbu-syscall-audit')
PROGRAM = r'''
kprobe:audit_seccomp /((arg2 & 0xffff0000) == 0x50000)/ {
    printf("EVENT %llu %d %d %llu %d %u\n", nsecs(monotonic), cpu, pid, cgroup, arg0, arg2);
}
BEGIN { printf("READY\n"); }
interval:s:2 { printf("READY\n"); }
'''


def main():
    os.umask(0o022)
    ROOT.mkdir(mode=0o755, exist_ok=True)
    # Some target kernels provide kprobes but omit the function-tracer list.
    # Only this known audit hook is used, and its presence is checked first.
    if not any(line.split()[-1:] == ['audit_seccomp'] for line in Path('/proc/kallsyms').read_text().splitlines()):
        raise RuntimeError('kernel does not provide audit_seccomp')
    functions = ROOT / 'traceable-functions'
    functions.write_text('audit_seccomp\n')
    boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    arch = platform.machine()
    if arch not in {'x86_64', 'riscv64'}:
        raise RuntimeError('unsupported syscall audit architecture')
    proc = subprocess.Popen(['/usr/bin/bpftrace', '-q', '-B', 'line',
        '--traceable-functions', str(functions), '-e', PROGRAM],
        stdout=subprocess.PIPE, text=True)
    def stop(*_):
        proc.terminate()
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    log = ROOT / 'events.jsonl'
    stream = log.open('a')
    try:
        for line in proc.stdout:
            fields = line.split()
            if fields == ['READY']:
                tmp = ROOT / 'status.tmp'
                tmp.write_text(json.dumps({'status': 'active', 'backend': 'ebpf-seccomp',
                    'pid': os.getpid(), 'updated_at': time.time()}))
                tmp.replace(ROOT / 'status.json')
            elif len(fields) == 7 and fields[0] == 'EVENT':
                ns, cpu, pid, cgroup, number, code = map(int, fields[1:])
                event = {'event_id': f'kernel-{boot}-{ns}-{cpu}-{pid}',
                    'time': time.time(), 'monotonic_ns': ns, 'boot_id': boot,
                    'pid': pid, 'cgroup_id': cgroup,
                    'number': number, 'code': code, 'arch': arch}
                stream.write(json.dumps(event) + '\n'); stream.flush()
                if stream.tell() >= 8 * 1024 * 1024:
                    stream.close(); log.replace(ROOT / 'events.jsonl.1')
                    stream = log.open('a')
        return proc.wait() or 1
    finally:
        (ROOT / 'status.json').unlink(missing_ok=True)
        stream.close()
        if proc.poll() is None:
            proc.terminate()
        proc.wait(timeout=5)

if __name__ == '__main__':
    raise SystemExit(main())
