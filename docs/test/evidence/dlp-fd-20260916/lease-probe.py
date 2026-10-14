import os, sys, socket, json, time, subprocess, sqlite3, urllib.request
from pathlib import Path
sys.path.insert(0, '/usr/lib/bianbu-securityd')
from securityd.uds_protocol import send_frame, recv_frame
with urllib.request.urlopen('http://127.0.0.1:9899/api/v1/runtime/workers') as response:
    workers = json.load(response)['data']['workers']
worker = next(w for w in workers if w['agent_id'] == 'com.bianbu.278200e1617c')
assert worker['state'] in ('running', 'starting'), worker
worker_pid = int(worker['pid'])
conn = sqlite3.connect('file:/etc/bianbu/runtime-leases.db?mode=ro', uri=True)
try:
    row = conn.execute('SELECT lease_id, agent_id FROM runtime_instance WHERE instance_id=? AND state=?',
                       (worker['instance_id'], 'running')).fetchone()
    assert row, worker
finally:
    conn.close()
cg = Path(f'/proc/{worker_pid}/cgroup').read_text().strip().split('::')[1]
# 仅诊断子进程加入现有 scope；使用服务端实际 SO_PEERCRED，不伪造 PID。
Path('/sys/fs/cgroup' + cg + '/cgroup.procs').write_text(str(os.getpid()))
worker_stat = Path(f'/proc/{worker_pid}').stat()
groups = next(line for line in Path(f'/proc/{worker_pid}/status').read_text().splitlines() if line.startswith('Groups:'))
os.setgroups([int(g) for g in groups.split()[1:]])
base = dict(agent_id='com.bianbu.278200e1617c',
            _worker_security_agent_id=row[1],
            _worker_instance_id=worker['instance_id'],
            _worker_lease_id=row[0])
def request(op, **kw):
    os.setegid(worker_stat.st_gid)
    os.seteuid(worker_stat.st_uid)
    try:
        with socket.socket(socket.AF_UNIX) as s:
            s.settimeout(15)
            s.connect('/run/bianbu/securityd.sock')
            send_frame(s, dict(base, op=op, **kw))
            return recv_frame(s, 1024*1024)
    finally:
        os.seteuid(0)
        os.setegid(0)
def stats():
    pid=int(subprocess.check_output(['systemctl','show','bianbu-securityd','-p','MainPID','--value']))
    fds=list(Path(f'/proc/{pid}/fd').iterdir())
    dlp=0
    for f in fds:
        try: dlp += 'dlp_policy.db' in os.readlink(f)
        except FileNotFoundError: pass
    return {'pid':pid,'fds':len(fds),'dlp_fds':dlp}
report={'before':stats(),'worker_pid':worker_pid,'probe':'existing committed lease, diagnostic child in worker cgroup'}
first=request('worker.identity')
report['identity']=first
if not first.get('ok'):
    print(json.dumps(report,ensure_ascii=False));sys.exit(1)
start=time.monotonic()
for i in range(1000):
    r=request('dlp.policy')
    assert r.get('ok'),r
report['requests']=1000
report['seconds']=round(time.monotonic()-start,3)
for op in ['dlp.scan','token.budget','security.mode']:
    r=request(op, text='test@example.com')
    assert r.get('ok'),r
    report[op]='passed'
r=request('worker.identity',_worker_lease_id='invalid-regression-probe')
assert not r.get('ok'),r
report['invalid_lease']='denied'
time.sleep(1)
report['after']=stats()
assert report['after']['dlp_fds']==0, report
assert report['after']['fds']<=report['before']['fds']+8,report
print(json.dumps(report,ensure_ascii=False,indent=2))
