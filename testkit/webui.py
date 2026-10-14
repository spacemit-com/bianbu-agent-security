"""测试监视 WebUI —— 零依赖（仅标准库 http.server）。

  GET /                 监视页面
  GET /api/events       事件流增量（?offset=N 按行偏移拉取）
  GET /api/report       最终报告
  POST /api/run         启动一轮测试（后台进程）
  GET /api/status       当前运行状态

⚠️ 无认证，仅限内网/本机使用。
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs

HERE = Path(__file__).resolve().parent
OUT = Path(os.environ.get("BNSEC_OUT", "/var/tmp/bnsec-testrun"))
PORT = int(os.environ.get("BNSEC_WEB_PORT", "9700"))

_proc: subprocess.Popen | None = None
_lock = threading.Lock()

PAGE = r"""<!doctype html>
<html lang="zh"><head><meta charset="utf-8">
<title>BNAgent Security 测试监视</title>
<style>
:root{--bg:#0d1117;--fg:#e6edf3;--dim:#8b949e;--line:#30363d;--card:#161b22;
--ok:#3fb950;--bad:#f85149;--warn:#d29922;--run:#58a6ff}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);
font:14px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",Helvetica,Arial,"PingFang SC","Microsoft YaHei",sans-serif}
header{padding:16px 22px;border-bottom:1px solid var(--line);display:flex;
align-items:center;gap:16px;flex-wrap:wrap;position:sticky;top:0;background:var(--bg);z-index:9}
h1{font-size:16px;margin:0;font-weight:600}
button{background:#238636;color:#fff;border:0;padding:7px 16px;border-radius:6px;
cursor:pointer;font-size:13px;font-weight:500}
button:disabled{background:#30363d;color:var(--dim);cursor:not-allowed}
.stats{display:flex;gap:14px;margin-left:auto;flex-wrap:wrap;font-size:13px}
.stat b{font-size:17px;margin-right:4px}
.wrap{display:grid;grid-template-columns:minmax(0,1.15fr) minmax(0,1fr);gap:0;
height:calc(100vh - 62px)}
.col{overflow-y:auto;padding:14px 18px}
.col+.col{border-left:1px solid var(--line)}
h2{font-size:12px;text-transform:uppercase;letter-spacing:.08em;color:var(--dim);
margin:0 0 10px;font-weight:600}
.item{background:var(--card);border:1px solid var(--line);border-left-width:3px;
border-radius:6px;padding:9px 12px;margin-bottom:7px;cursor:pointer}
.item:hover{border-color:#484f58}
.item.pending{border-left-color:#484f58;opacity:.55}
.item.running{border-left-color:var(--run)}
.item.passed{border-left-color:var(--ok)}
.item.failed,.item.error{border-left-color:var(--bad)}
.item .top{display:flex;align-items:center;gap:9px}
.id{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:11px;
color:var(--dim);min-width:76px}
.tt{flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.badge{font-size:10px;padding:2px 7px;border-radius:10px;font-weight:600;
text-transform:uppercase;letter-spacing:.03em}
.b-pending{background:#21262d;color:var(--dim)}
.b-running{background:#0d419d;color:#cae8ff}
.b-passed{background:#0f5323;color:#aff5b4}
.b-failed,.b-error{background:#67060c;color:#ffdcd7}
.ms{font-size:11px;color:var(--dim);font-variant-numeric:tabular-nums}
.msg{font-size:12px;color:#ffa198;margin-top:5px;padding-left:85px;
word-break:break-word;line-height:1.5}
.req{font-size:10px;color:var(--dim);border:1px solid var(--line);
padding:1px 5px;border-radius:3px}
pre{background:#010409;border:1px solid var(--line);border-radius:6px;padding:10px;
overflow:auto;font-size:11.5px;line-height:1.55;max-height:none;margin:0 0 12px;
font-family:ui-monospace,SFMono-Regular,Menlo,monospace;white-space:pre-wrap;
word-break:break-word}
.step{padding:4px 0 4px 20px;position:relative;font-size:12.5px;border-bottom:1px solid #1c2128}
.step:last-child{border-bottom:0}
.step::before{position:absolute;left:2px;font-weight:700}
.step.y::before{content:"✓";color:var(--ok)}
.step.n::before{content:"✗";color:var(--bad)}
.step .d{color:var(--dim);font-size:11.5px;margin-top:2px}
.empty{color:var(--dim);font-size:13px;padding:22px 0;text-align:center}
.sec{margin-bottom:16px}
.sec>h3{font-size:11px;text-transform:uppercase;letter-spacing:.06em;
color:var(--dim);margin:0 0 6px;font-weight:600}
table{width:100%;border-collapse:collapse;font-size:11.5px}
th,td{text-align:left;padding:3px 8px 3px 0;border-bottom:1px solid #1c2128;
font-family:ui-monospace,Menlo,monospace}
th{color:var(--dim);font-weight:600}
.r-allow{color:var(--ok)}.r-deny{color:var(--bad)}.r-confirm{color:var(--warn)}
.filter{display:flex;gap:6px;margin-bottom:10px;flex-wrap:wrap}
.filter span{font-size:11px;padding:3px 9px;border:1px solid var(--line);
border-radius:11px;cursor:pointer;color:var(--dim)}
.filter span.on{background:#1f6feb;border-color:#1f6feb;color:#fff}
</style></head><body>
<header>
  <h1>BNAgent Security 测试监视</h1>
  <button id="go" onclick="start()">开始测试</button>
  <div class="stats">
    <div class="stat"><b id="s-total">0</b><span style="color:var(--dim)">总计</span></div>
    <div class="stat"><b id="s-pass" style="color:var(--ok)">0</b><span style="color:var(--dim)">通过</span></div>
    <div class="stat"><b id="s-fail" style="color:var(--bad)">0</b><span style="color:var(--dim)">失败</span></div>
    <div class="stat"><b id="s-err" style="color:var(--warn)">0</b><span style="color:var(--dim)">错误</span></div>
    <div class="stat"><span id="s-time" style="color:var(--dim)"></span></div>
  </div>
</header>
<div class="wrap">
  <div class="col">
    <div class="filter" id="filter"></div>
    <div id="list"><div class="empty">点击「开始测试」运行全部测试项</div></div>
  </div>
  <div class="col">
    <h2 id="dt">详情</h2>
    <div id="detail"><div class="empty">点击左侧任一测试项查看详情</div></div>
  </div>
</div>
<script>
let off=0, T={}, order=[], sel=null, timer=null, filt="all";
const E=i=>document.getElementById(i);

async function start(){
  E("go").disabled=true; E("go").textContent="运行中…";
  T={};order=[];sel=null;off=0;
  E("detail").innerHTML='<div class="empty">测试进行中…</div>';
  await fetch("/api/run",{method:"POST"});
  if(timer)clearInterval(timer);
  timer=setInterval(poll,900); poll();
}

async function poll(){
  const r=await fetch("/api/events?offset="+off);
  const j=await r.json(); off=j.offset;
  for(const e of j.events) apply(e);
  render();
  if(j.done){clearInterval(timer);timer=null;
    E("go").disabled=false;E("go").textContent="重新测试";}
}

function apply(e){
  if(e.kind==="start"){
    for(const t of e.tests){T[t.id]={...t,status:"pending",steps:[]};order.push(t.id);}
    E("s-total").textContent=e.total;
  }else if(e.kind==="test_start"){
    if(T[e.id])T[e.id].status="running";
  }else if(e.kind==="test_end"){
    Object.assign(T[e.id]||{},{status:e.status,duration_ms:e.duration_ms,
      message:e.message,steps:e.steps||[],audit_count:e.audit_count});
  }else if(e.kind==="done"){
    E("s-time").textContent="耗时 "+(e.duration_ms/1000).toFixed(1)+"s";
  }
}

function cats(){
  const c={};for(const id of order)c[T[id].category]=(c[T[id].category]||0)+1;return c;
}

function render(){
  let p=0,f=0,er=0;
  for(const id of order){const s=T[id].status;
    if(s==="passed")p++;else if(s==="failed")f++;else if(s==="error")er++;}
  E("s-pass").textContent=p;E("s-fail").textContent=f;E("s-err").textContent=er;

  const fl=E("filter");
  if(!fl.dataset.done&&order.length){
    const c=cats();let h='<span class="on" data-f="all">全部 '+order.length+'</span>';
    for(const k in c)h+='<span data-f="'+k+'">'+k+' '+c[k]+'</span>';
    h+='<span data-f="_bad">仅失败</span>';
    fl.innerHTML=h;fl.dataset.done="1";
    fl.querySelectorAll("span").forEach(s=>s.onclick=()=>{
      filt=s.dataset.f;fl.querySelectorAll("span").forEach(x=>x.classList.remove("on"));
      s.classList.add("on");render();});
  }

  const vis=order.filter(id=>filt==="all"||
    (filt==="_bad"?["failed","error"].includes(T[id].status):T[id].category===filt));
  E("list").innerHTML=vis.map(id=>{const t=T[id];
    return '<div class="item '+t.status+'" onclick="pick(\''+id+'\')">'+
      '<div class="top"><span class="id">'+id+'</span>'+
      '<span class="tt">'+esc(t.title)+'</span>'+
      (t.requirement?'<span class="req">'+t.requirement+'</span>':'')+
      '<span class="badge b-'+t.status+'">'+t.status+'</span>'+
      '<span class="ms">'+(t.duration_ms!=null?t.duration_ms+"ms":"")+'</span></div>'+
      (t.message?'<div class="msg">'+esc(t.message)+'</div>':'')+'</div>';
  }).join("")||'<div class="empty">该分类下无测试项</div>';
  if(sel)detail(sel);
}

function pick(id){sel=id;detail(id);}

async function detail(id){
  const t=T[id];if(!t)return;
  E("dt").textContent=id+" 详情";
  let h='<div class="sec"><h3>'+esc(t.title)+'</h3>';
  if(t.requirement)h+='<div style="font-size:12px;color:var(--dim)">需求 '+t.requirement+' · 分类 '+t.category+'</div>';
  h+='</div>';
  if(t.steps&&t.steps.length){
    h+='<div class="sec"><h3>断言 '+t.steps.filter(s=>s.ok).length+'/'+t.steps.length+'</h3>';
    for(const s of t.steps){
      h+='<div class="step '+(s.ok?"y":"n")+'">'+esc(s.name)+
         (s.detail&&!s.ok?'<div class="d">'+esc(s.detail)+'</div>':'')+'</div>';}
    h+='</div>';
  }
  // 报告已生成时拉取完整日志与审计
  const rep=await fetch("/api/report").then(r=>r.json()).catch(()=>null);
  if(rep&&rep.results){
    const r=rep.results.find(x=>x.id===id);
    if(r){
      if(r.error)h+='<div class="sec"><h3>异常堆栈</h3><pre>'+esc(r.error)+'</pre></div>';
      if(r.audit_delta&&r.audit_delta.length){
        h+='<div class="sec"><h3>securityd 审计增量 '+r.audit_delta.length+' 条</h3><table>'+
           '<tr><th>seq</th><th>op</th><th>target</th><th>result</th></tr>';
        for(const a of r.audit_delta.slice(0,40))
          h+='<tr><td>'+a.seq+'</td><td>'+esc(a.op_type)+'</td><td>'+
             esc(String(a.target).slice(0,34))+'</td><td class="r-'+
             String(a.result).toLowerCase()+'">'+esc(a.result)+'</td></tr>';
        h+='</table></div>';
      }
      if(r.logs&&r.logs.length)
        h+='<div class="sec"><h3>执行日志 '+r.logs.length+' 行</h3><pre>'+
           esc(r.logs.join("\n"))+'</pre></div>';
    }
  }
  E("detail").innerHTML=h;
}

function esc(s){return String(s==null?"":s).replace(/[&<>"']/g,
  c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));}

fetch("/api/status").then(r=>r.json()).then(j=>{
  if(j.running){E("go").disabled=true;E("go").textContent="运行中…";
    timer=setInterval(poll,900);poll();}
  else if(j.has_report){poll();E("go").textContent="重新测试";}
});
</script></body></html>"""


class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _send(self, code: int, body: bytes, ctype: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, obj, code: int = 200) -> None:
        self._send(code, json.dumps(obj, ensure_ascii=False).encode(),
                   "application/json; charset=utf-8")

    def do_GET(self) -> None:  # noqa: N802
        u = urlparse(self.path)
        if u.path == "/":
            self._send(200, PAGE.encode(), "text/html; charset=utf-8")
        elif u.path == "/api/events":
            off = int((parse_qs(u.query).get("offset") or ["0"])[0])
            ev, done = [], False
            f = OUT / "events.jsonl"
            if f.exists():
                lines = f.read_text().splitlines()
                for ln in lines[off:]:
                    if not ln.strip():
                        continue
                    try:
                        rec = json.loads(ln)
                        ev.append(rec)
                        if rec.get("kind") == "done":
                            done = True
                    except Exception:
                        pass
                off = len(lines)
            with _lock:
                alive = _proc is not None and _proc.poll() is None
            self._json({"events": ev, "offset": off, "done": done or not alive})
        elif u.path == "/api/report":
            f = OUT / "report.json"
            self._json(json.loads(f.read_text()) if f.exists() else {})
        elif u.path == "/api/status":
            with _lock:
                running = _proc is not None and _proc.poll() is None
            self._json({"running": running,
                        "has_report": (OUT / "report.json").exists()})
        else:
            self._json({"error": "not found"}, 404)

    def do_POST(self) -> None:  # noqa: N802
        global _proc
        if urlparse(self.path).path != "/api/run":
            return self._json({"error": "not found"}, 404)
        with _lock:
            if _proc is not None and _proc.poll() is None:
                return self._json({"error": "已有测试在运行"}, 409)
            OUT.mkdir(parents=True, exist_ok=True)
            log = (OUT / "runner.log").open("w")
            _proc = subprocess.Popen(
                [sys.executable, str(HERE / "runner.py")],
                cwd=str(HERE), stdout=log, stderr=subprocess.STDOUT,
                env={**os.environ, "PYTHONUNBUFFERED": "1"})
        self._json({"started": True, "pid": _proc.pid})

    def log_message(self, *a) -> None:  # 静音 access log
        pass


if __name__ == "__main__":
    OUT.mkdir(parents=True, exist_ok=True)
    print(f"测试监视 WebUI → http://0.0.0.0:{PORT}  (输出目录 {OUT})")
    print("⚠️  无认证，仅限内网使用")
    ThreadingHTTPServer(("0.0.0.0", PORT), H).serve_forever()
