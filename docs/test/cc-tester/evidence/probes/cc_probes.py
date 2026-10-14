#!/usr/bin/env python3
"""cc-tester manual E2E probes on Worker: SC-01 seccomp deny, CAP-02 CONFIRM approvals, NET-01 deny_all.
Sequential; restores agent mode / grants / network policy in finally blocks."""
import json, os, sqlite3, subprocess, sys, time, urllib.request, urllib.error
import dbus
AGENT = "com.bianbu.c6f40f30a6e5"; PA = "http://127.0.0.1:9899"
OUT = sys.argv[1] if len(sys.argv) > 1 else "/var/tmp/bnsec-cc-tester-20260911/probes"
bus = dbus.SystemBus(); iface = dbus.Interface(bus.get_object("io.bianbu.Security", "/io/bianbu/Security"), "io.bianbu.Security")
def log(*a):
    line = time.strftime("[%H:%M:%S] ") + " ".join(str(x) for x in a); print(line, flush=True)
def http(m, p, b=None, timeout=60):
    req = urllib.request.Request(PA + p, data=json.dumps(b).encode() if b is not None else None, headers={"content-type": "application/json"}, method=m)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r: return r.status, json.loads(r.read().decode() or "null")
    except urllib.error.HTTPError as e: return e.code, e.read().decode()[:300]
def audit_seq():
    c = sqlite3.connect("file:/var/log/bianbu/audit/202609.db?mode=ro", uri=True); v = c.execute("select max(seq) from audit_record").fetchone()[0]; c.close(); return int(v or 0)
def audit_since(seq):
    c = sqlite3.connect("file:/var/log/bianbu/audit/202609.db?mode=ro", uri=True)
    rows = c.execute("select seq, ts, agent_id, op_type, target, result from audit_record where seq > ? order by seq", (seq,)).fetchall(); c.close()
    return [dict(zip(("seq","ts","agent_id","op_type","target","result"), r)) for r in rows]
def print_audit(rows, agent=AGENT, skip=("bind_caller",)):
    for r in rows:
        if r["agent_id"] == agent and r["op_type"] not in skip: log(f"   audit seq={r['seq']} {r['op_type']} {str(r['target'])[:70]} -> {str(r['result'])[:110]}")
def new_session(tag):
    sid = f"cc-{tag}-{int(time.time())}"; st, r = http("POST", "/api/v1/sessions", {"id": sid, "agent_id": AGENT}); assert st in (200, 201), (st, r); return sid
def events(sid):
    st, r = http("GET", f"/api/v1/sessions/{sid}/events?max_messages=50", timeout=30); return (r or {}).get("data", []) if st == 200 else []
def terminal(sid, rid, evs):
    return next((e for e in reversed(evs) if str(e.get("run_id")) == rid and e.get("type") in ("run/completed","run/failed","run/cancelled")), None)
def run_prompt(sid, prompt, timeout=150, on_approval=None):
    st, r = http("POST", f"/api/v1/sessions/{sid}/prompt", {"message_id": f"m-{int(time.time()*1000)}", "content": prompt}); assert st in (200,201,202), (st, r)
    rid = r["data"]["run_id"]; log(f"run_id={rid} session={sid}"); deadline = time.time() + timeout; handled = set()
    while time.time() < deadline:
        evs = events(sid); t = terminal(sid, rid, evs)
        if t: return rid, t, evs
        if on_approval:
            for e in evs:
                if str(e.get("run_id")) == rid and e.get("type") in ("approval/requested", "approval_required"):
                    aid = (e.get("data") or {}).get("approval_id")
                    if aid and aid not in handled:
                        handled.add(aid); on_approval(sid, rid, aid, e)
        time.sleep(3)
    return rid, None, events(sid)
def summarize(t):
    d = (t or {}).get("data") or {}; res = d.get("result") if isinstance(d.get("result"), dict) else {}
    return {"type": (t or {}).get("type"), "status": d.get("status") or res.get("status"), "error": d.get("error") or res.get("error"), "content": str(d.get("content") or res.get("content") or d.get("output") or "")[:400]}
def mode(): return str(iface.GetAgentSecurityMode(AGENT)["mode"])
def set_mode(m): iface.SetAgentSecurityMode(AGENT, m); log(f"mode -> {m}")
def cap(name): return {str(k): str(v) for k, v in next((x for x in iface.GetCapabilities(AGENT) if str(x["capability"]) == name), {}).items()}
def sh(cmd): p = subprocess.run(cmd, shell=True, capture_output=True, text=True); return (p.stdout + p.stderr).strip()

# ───────── SC-01 seccomp deny (yolo, terminal allowed) ─────────
if os.environ.get("SKIP_SC01") != "1":
  log("### SC-01 seccomp deny inside real Worker via terminal tool"); log("mode:", mode()); log("audit status before:", sh("busctl call io.bianbu.Security /io/bianbu/Security io.bianbu.Security GetSyscallAuditStatus")[:200])
  seq0 = audit_seq(); sid = new_session("sc01")
  prompt = ("请只调用一次 terminal 工具执行下面这条命令，并把命令的完整输出原样回复给我（不要解释，不要调用其他工具）：\n"
            "python3 -c 'import ctypes,os; l=ctypes.CDLL(None,use_errno=True); r=l.syscall(273,0,0,0); e=ctypes.get_errno(); "
            "print(\"finit_module\", r, e, os.strerror(e)); r2=l.syscall(172); print(\"getpid\", r2); "
            "print(\"Seccomp\", open(\"/proc/self/status\").read().split(\"Seccomp:\")[1].split()[0])'")
  rid, t, evs = run_prompt(sid, prompt)
  for e in evs:
      if str(e.get("run_id")) == rid and ("tool" in str(e.get("type")) or "message/assistant" in str(e.get("type"))): log("   event", e.get("type"), json.dumps(e.get("data"), ensure_ascii=False)[:500])
  log("terminal:", json.dumps(summarize(t), ensure_ascii=False)[:600]); time.sleep(3); print_audit(audit_since(seq0))
  log("syscall audit events:", sh(f'busctl call io.bianbu.Security /io/bianbu/Security io.bianbu.Security GetSyscallAuditEvents ssii {AGENT} "" 10 0')[:700])
  log("audit status after:", sh("busctl call io.bianbu.Security /io/bianbu/Security io.bianbu.Security GetSyscallAuditStatus")[:200])
  log("kernel spool:", sh("cat /run/bianbu-syscall-audit/status.json; wc -l < /run/bianbu-syscall-audit/events.jsonl; tail -2 /run/bianbu-syscall-audit/events.jsonl")[:500])
  log("observer journal:", sh("journalctl -u bianbu-syscall-observer.service --since -3min --no-pager -o cat | tail -4")[:400])

# ───────── CAP-02 CONFIRM via approvals (normal mode, system.execute L4 confirm=always) ─────────
log("### CAP-02 CONFIRM -> HITL approvals (normal mode)")
prev = mode(); orig = cap("system.execute"); log("system.execute before:", orig)
b = {str(k): str(v) for k, v in iface.GetTokenBudget(AGENT).items()}
try:
    set_mode("normal")
    b = {str(k): str(v) for k, v in iface.GetTokenBudget(AGENT).items()}; log("real budget:", b)
    iface.SetTokenBudget(AGENT, dbus.Int64(10**9), dbus.Int64(10**9), b.get("on_exceed", "pause_and_notify"))
    for decision in ("reject", "approve"):
        log(f"-- decision={decision}"); seq0 = audit_seq(); sid = new_session(f"confirm-{decision}"); seen = {}
        def on_approval(sid, rid, aid, e, decision=decision):
            seen["approval"] = e.get("data"); log("   approval requested:", json.dumps(e.get("data"), ensure_ascii=False)[:500])
            st, ls = http("GET", "/api/v1/sessions"); row = next((x for x in (ls or {}).get("data", []) if x.get("id") == sid), {}); log("   session list row:", json.dumps({k: row.get(k) for k in ("status","pending_interaction","active_run_id","waiting")}, ensure_ascii=False))
            st, r = http("POST", f"/api/v1/sessions/{sid}/approvals/{aid}", {"decision": decision, "reason": "cc-tester"}); log(f"   POST approvals -> {st} {str(r)[:200]}"); seen["post"] = (st, r)
            st, r = http("POST", f"/api/v1/sessions/{sid}/approvals/{aid}", {"decision": decision, "reason": "dup"}); log(f"   duplicate POST -> {st} (expect 409)")
        rid, t, evs = run_prompt(sid, "请只调用一次 terminal 工具执行命令 `echo BNSEC-CONFIRM`，并把输出原样回复。不要调用其他工具。", timeout=150, on_approval=on_approval)
        log("   terminal:", json.dumps(summarize(t), ensure_ascii=False)[:500]); log("   approval seen:", bool(seen.get("approval"))); time.sleep(2); print_audit(audit_since(seq0))
finally:
    iface.SetTokenBudget(AGENT, dbus.Int64(int(b.get("limit_per_conversation", 100000))), dbus.Int64(int(b.get("limit_per_day", 500000))), b.get("on_exceed", "pause_and_notify")); log("budget restored", b.get("limit_per_conversation"), b.get("limit_per_day"))
    set_mode(prev); log("system.execute after:", cap("system.execute"))

# ───────── NET-01 deny_all (yolo; host backend; systemd IPAddressDeny hot-apply) ─────────
log("### NET-01 network policy deny_all on running Worker")
np0 = json.loads(str(iface.GetNetworkPolicy(AGENT)["json"])); log("policy before:", json.dumps({k: np0.get(k) for k in ("mode","domains","apply","enforcement")}, ensure_ascii=False)[:400])
scope_unit = sh("systemctl list-units --no-pager --plain --no-legend 'bianbu-agent-*.scope' | awk '{print $1}' | head -1"); log("scope unit:", scope_unit)
try:
    ok = iface.SetNetworkPolicy(AGENT, dbus.Array([], signature="s"), "deny_all"); log("SetNetworkPolicy deny_all ->", bool(ok)); time.sleep(3)
    np1 = json.loads(str(iface.GetNetworkPolicy(AGENT)["json"])); log("policy after:", json.dumps({k: np1.get(k) for k in ("mode","version","apply")}, ensure_ascii=False)[:400])
    log("scope IPAddressDeny/Allow:", sh(f"systemctl show {scope_unit} -p IPAddressDeny,IPAddressAllow"))
    seq0 = audit_seq(); sid = new_session("net-deny")
    rid, t, evs = run_prompt(sid, "请只调用一次 terminal 工具执行命令 `curl -sS -m 5 -o /dev/null -w %{http_code} http://10.0.50.55/ ; echo rc=$?`，并把输出原样回复。不要调用其他工具。", timeout=120)
    for e in evs:
        if str(e.get("run_id")) == rid and ("tool" in str(e.get("type"))): log("   event", e.get("type"), json.dumps(e.get("data"), ensure_ascii=False)[:400])
    log("   terminal:", json.dumps(summarize(t), ensure_ascii=False)[:500]); print_audit(audit_since(seq0))
finally:
    ok = iface.SetNetworkPolicy(AGENT, dbus.Array([str(d) for d in np0.get("domains", [])], signature="s"), str(np0.get("mode", "allow_all"))); log("restored network policy ->", bool(ok), np0.get("mode")); time.sleep(3)
    log("scope IPAddressDeny/Allow after restore:", sh(f"systemctl show {scope_unit} -p IPAddressDeny,IPAddressAllow"))
sid = new_session("net-restore"); rid, t, evs = run_prompt(sid, "只回复一个字：好", timeout=90); log("smoke after restore:", json.dumps(summarize(t), ensure_ascii=False)[:200])
log("### DONE mode:", mode(), "network:", json.loads(str(iface.GetNetworkPolicy(AGENT)["json"]))["mode"])
