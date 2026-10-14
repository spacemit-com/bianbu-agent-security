#!/bin/bash
# P0-06: securityd unavailable -> fail-closed; then recover and smoke.
E=/var/tmp/bnsec-cc-tester-20260911/faults; B=io.bianbu.Security; P=/io/bianbu/Security; A=com.bianbu.c6f40f30a6e5
exec > $E/p0-06-securityd-down.txt 2>&1
echo "### P0-06 securityd stop -> fail-closed -> recover"; date -Is
echo "== before"; systemctl is-active bianbu-securityd bianbu-agent-runtime@bianbu bianbu-security-webui; pgrep -af "role agent-worker" | cut -c1-60
OLD_INST=$(tr "\\0" "\\n" < /proc/$(pgrep -f "role agent-worker" | head -1)/environ | grep ^BIANBU_WORKER_INSTANCE_ID= | cut -d= -f2); echo "old instance $OLD_INST"
echo "== stop securityd"; sudo systemctl stop bianbu-securityd.service 2>&1 | grep -v "password" ; sleep 4
echo "== states after stop"; systemctl is-active bianbu-securityd bianbu-agent-runtime@bianbu bianbu-security-webui; systemctl list-units --no-pager --plain --no-legend "bianbu-agent-*.scope"; pgrep -af "role agent-worker" | cut -c1-60 || echo "no worker process"
echo "== HTTP 9899 during outage"; curl -sS -m 5 -o /dev/null -w "http=%{http_code}\n" http://127.0.0.1:9899/api/v1/agents || echo "connection refused/timeout (fail-closed by Requires=)"
echo "== UDS"; ls -la /run/bianbu/securityd.sock 2>&1; echo "== bus name"; busctl list --no-pager | grep -c io.bianbu.Security
echo "== runtime journal tail"; journalctl -u bianbu-agent-runtime@bianbu.service --since -1min --no-pager -o short-iso | tail -8 | cut -c1-200
echo "== WebUI health during outage"; curl -sS -m 5 http://127.0.0.1:8788/api/health; echo
echo "== start services"; sudo systemctl start bianbu-securityd.service bianbu-security-webui.service bianbu-agent-runtime@bianbu.service 2>&1 | grep -v password; sleep 25
echo "== states after start"; systemctl is-active bianbu-securityd bianbu-agent-runtime@bianbu bianbu-security-webui bianbu-syscall-observer
for i in $(seq 1 20); do curl -sS -m 3 -o /dev/null http://127.0.0.1:9899/api/v1/agents && break; sleep 3; done
echo "== agents"; curl -sS -m 10 http://127.0.0.1:9899/api/v1/agents | head -c 300; echo
for i in $(seq 1 20); do pgrep -f "role agent-worker" >/dev/null && break; sleep 3; done
NEW_PID=$(pgrep -f "role agent-worker" | head -1); echo "new worker pid $NEW_PID"
NEW_INST=$(tr "\\0" "\\n" < /proc/$NEW_PID/environ | grep ^BIANBU_WORKER_INSTANCE_ID= | cut -d= -f2); echo "new instance $NEW_INST (old $OLD_INST) changed=$([ "$NEW_INST" != "$OLD_INST" ] && echo yes || echo no)"
grep -E "^(Seccomp|NoNewPrivs):" /proc/$NEW_PID/status; cat /proc/$NEW_PID/cgroup
echo "== lease instances state"; python3 -c "
import sqlite3
c=sqlite3.connect(\"file:/etc/bianbu/runtime-leases.db?mode=ro\",uri=True)
for r in c.execute(\"select instance_id, state, pid, started_at from runtime_instance order by started_at desc limit 4\"): print(r)
for r in c.execute(\"select lease_id, state, reason from runtime_lease order by issued_at desc limit 4\"): print(r)"
echo "== seccomp policy applied version"; busctl call $B $P $B GetSecurityExecutionStatus s $A | grep -o "policy_version[^,]*, [^,]*applied_policy_version[^,]*, [^,]*pending_restart[^}]*" | head -1
echo "== smoke run"; python3 - <<PY
import json,time,urllib.request
def http(m,p,b=None):
    req=urllib.request.Request("http://127.0.0.1:9899"+p, data=json.dumps(b).encode() if b is not None else None, headers={"content-type":"application/json"}, method=m)
    with urllib.request.urlopen(req, timeout=60) as r: return json.loads(r.read().decode() or "null")
sid="cc-p006-%d"%int(time.time()); http("POST","/api/v1/sessions",{"id":sid,"agent_id":""})
rid=http("POST",f"/api/v1/sessions/{sid}/prompt",{"message_id":"m1","content":"只回复一个字：好"})["data"]["run_id"]
for _ in range(40):
    ev=http("GET",f"/api/v1/sessions/{sid}/events?max_messages=50")["data"]
    t=[e for e in ev if e.get("run_id")==rid and e.get("type") in ("run/completed","run/failed")]
    if t: print("smoke", t[0]["type"], json.dumps(t[0]["data"],ensure_ascii=False)[:200]); break
    time.sleep(3)
else: print("smoke timeout")
PY
echo "== securityd journal after restart"; journalctl -u bianbu-securityd.service --since -2min --no-pager -o cat | grep -vE "^\s|Traceback|File" | tail -5 | cut -c1-200
echo "== audit runtime rows"; python3 -c "
import sqlite3
c=sqlite3.connect(\"file:/var/log/bianbu/audit/202609.db?mode=ro\",uri=True)
for r in c.execute(\"select seq, ts, agent_id, op_type, substr(result,1,80) from audit_record where ts > strftime(\x27%Y-%m-%dT%H:%M:%S\x27,\x27now\x27,\x27-4 minutes\x27) and op_type like \x27runtime%\x27 order by seq\"): print(r)"
date -Is; echo "### DONE"
