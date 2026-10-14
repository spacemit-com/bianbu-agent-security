"""BNAgent Security 测试引擎

通过 personal-agent 的 HTTP API + securityd 的 D-Bus 接口执行端到端测试。
每个测试项产出：状态、耗时、断言明细、原始日志、securityd 审计增量。

设计要点：
  - 测试项声明式注册（TESTS 列表），每项一个函数，返回 (passed, detail)
  - 全过程写 JSONL 事件流，WebUI 靠轮询该文件实现动态监视
  - 审计增量按 seq 差分获取，能证明"这次调用真的到达了 securityd"
  - 失败不中断，全部跑完出报告
"""
from __future__ import annotations

import json
import os
import subprocess
import sqlite3
import sys
import time
import traceback
import http.cookiejar
import urllib.error
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Callable


def dbus_int64(value: int):
    """需要显式 Int64 的 D-Bus 调用（如 GetSyscallPolicy）使用的转换助手。"""
    import dbus  # noqa: PLC0415
    return dbus.Int64(int(value))

PA_BASE = os.environ.get("PA_BASE", "http://127.0.0.1:9899")
SECD_HOME = os.environ.get("BIANBU_SECURITYD_HOME", "/home/bianbu/impl/bianbu-securityd")


def _default_audit_db() -> str:
    """优先读取正式 systemd 审计库，不存在时回退开发用户目录。"""
    production = Path("/var/log/bianbu/audit")
    if production.is_dir() and os.access(production, os.R_OK | os.X_OK):
        return str(production)
    return os.path.expanduser("~/.local/share/bianbu-securityd/var/log/bianbu/audit")


AUDIT_DB = os.environ.get("BNSEC_AUDIT_DB", _default_audit_db())


def audit_chain_db() -> Path | None:
    """定位 securityd 主审计链库（audit_record 所在的按月分段库）。

    正式 AUDIT_DIR 下同时存在 `YYYYMM.db`（主审计链）、`network-learning.db`、
    `syscall-events.db` 三种库。旧实现 `sorted(glob("*.db"))[-1]` 在生产目录上
    必然选中 `syscall-events.db`（无 audit_record 表），导致 AUDIT-01/02、HOOK-03、
    DLP-04 在真机上全部误判为"无审计增量 / 表不存在"（2026-09-11 交付报告）。
    这里优先取月份分段库中最新的一个，再回退到任何含 audit_record 表的库。
    """
    root = Path(AUDIT_DB)
    monthly = sorted(p for p in root.glob("*.db") if p.stem.isdigit() and len(p.stem) == 6)
    if monthly:
        return monthly[-1]
    for cand in sorted(root.glob("*.db"), reverse=True):
        try:
            con = sqlite3.connect(f"file:{cand}?mode=ro", uri=True)
            ok = con.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='audit_record'"
            ).fetchone()
            con.close()
        except Exception:
            continue
        if ok:
            return cand
    return None
def _default_webui_base() -> str:
    """正式安装以 /etc/bianbu/webui.env 的 BIANBU_WEBUI_PORT 为准（实机为 8788），
    避免连到占用 8787 的其它进程；读不到时回退 unit 默认 8787。"""
    env_file = Path(os.environ.get("BNSEC_SECURITY_WEBUI_ENV", "/etc/bianbu/webui.env"))
    port = "8787"
    try:
        for raw in env_file.read_text(encoding="utf-8").splitlines():
            if raw.startswith("BIANBU_WEBUI_PORT="):
                port = raw.split("=", 1)[1].strip() or port
    except OSError:
        pass
    return f"http://127.0.0.1:{port}"


SECURITY_WEBUI_BASE = os.environ.get("BNSEC_SECURITY_WEBUI_BASE", _default_webui_base())


def _production_webui_token() -> str:
    token = os.environ.get("BNSEC_SECURITY_WEBUI_TOKEN", "").strip()
    if token:
        return token
    env_file = Path(os.environ.get(
        "BNSEC_SECURITY_WEBUI_ENV", "/etc/bianbu/webui.env"))
    try:
        for raw in env_file.read_text(encoding="utf-8").splitlines():
            if raw.startswith("BIANBU_WEBUI_TOKEN="):
                return raw.split("=", 1)[1].strip()
    except OSError:
        pass
    return ""


SECURITY_WEBUI_TOKEN = _production_webui_token()
PA_AGENT = os.environ.get("PA_AGENT_ID", "bianbu-agent-default")
AGENT_ID = os.environ.get("BIANBU_PA_AGENT_ID", PA_AGENT)
TEST_AGENT_ID = os.environ.get("BNSEC_TEST_AGENT_ID", f"{AGENT_ID}.testkit")
OUT_DIR = Path(os.environ.get("BNSEC_OUT", "/var/tmp/bnsec-testrun"))

DECISION = {0: "ALLOW", 1: "CONFIRM", 2: "DENY"}


# ────────────────────────────── 基础设施 ──────────────────────────────
@dataclass
class Step:
    """测试内部的一步，供报告展开。"""
    name: str
    ok: bool
    detail: str = ""
    data: Any = None


@dataclass
class Result:
    id: str
    title: str
    requirement: str
    category: str
    status: str = "pending"       # pending|running|passed|failed|skipped|error
    duration_ms: int = 0
    steps: list[Step] = field(default_factory=list)
    message: str = ""
    logs: list[str] = field(default_factory=list)
    audit_delta: list[dict] = field(default_factory=list)
    error: str = ""


class Ctx:
    """测试上下文：HTTP/D-Bus 调用 + 日志收集 + 审计差分。"""

    def __init__(self) -> None:
        self.logs: list[str] = []
        self._iface = None

    # —— 日志 ——
    def log(self, msg: str) -> None:
        line = f"[{time.strftime('%H:%M:%S')}] {msg}"
        self.logs.append(line)

    # —— HTTP ——
    def http(self, method: str, path: str, body: Any = None, timeout: int = 60) -> tuple[int, Any]:
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(
            f"{PA_BASE}{path}", data=data,
            headers={"Content-Type": "application/json"}, method=method)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                raw = r.read().decode()
                self.log(f"{method} {path} → {r.status}")
                return r.status, (json.loads(raw) if raw else None)
        except urllib.error.HTTPError as e:
            raw = e.read().decode()
            self.log(f"{method} {path} → {e.code} {raw[:200]}")
            try:
                return e.code, json.loads(raw)
            except Exception:
                return e.code, raw
        except Exception as e:
            self.log(f"{method} {path} → 异常 {type(e).__name__}: {e}")
            raise

    def security_webui(self, method: str, path: str,
                       body: Any = None, timeout: int = 30) -> tuple[int, Any]:
        """经认证 WebUI 管理 API 操作生产策略，不绕过专用用户权限。"""
        if not SECURITY_WEBUI_TOKEN:
            raise RuntimeError("缺少 BNSEC_SECURITY_WEBUI_TOKEN 或可读的生产 webui.env")
        jar = http.cookiejar.CookieJar()
        opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
        auth = urllib.request.Request(
            f"{SECURITY_WEBUI_BASE}/api/auth",
            data=json.dumps({"token": SECURITY_WEBUI_TOKEN}).encode(),
            headers={"Content-Type": "application/json"}, method="POST")
        with opener.open(auth, timeout=timeout) as response:
            if response.status != 200:
                raise RuntimeError(f"WebUI 认证失败 HTTP {response.status}")
        csrf = next((cookie.value for cookie in jar if cookie.name == "bnsec_csrf"), "")
        data = json.dumps(body).encode() if body is not None else None
        headers = {"Content-Type": "application/json"}
        if method in {"POST", "PUT", "PATCH", "DELETE"}:
            headers["X-CSRF-Token"] = csrf
        request = urllib.request.Request(
            f"{SECURITY_WEBUI_BASE}{path}", data=data,
            headers=headers, method=method)
        try:
            with opener.open(request, timeout=timeout) as response:
                raw = response.read().decode()
                self.log(f"security-webui {method} {path} → {response.status}")
                return response.status, (json.loads(raw) if raw else None)
        except urllib.error.HTTPError as exc:
            raw = exc.read().decode()
            self.log(f"security-webui {method} {path} → {exc.code}")
            try:
                return exc.code, json.loads(raw)
            except Exception:
                return exc.code, raw

    # —— D-Bus ——
    def dbus(self):
        """取 securityd 的 D-Bus 接口，系统总线与会话总线都试。

        securityd 起在哪条总线取决于部署方式：装了
        /etc/dbus-1/system.d/io.bianbu.Security.conf 且用户在
        bianbu-security 组 → 系统总线；否则只能用会话总线
        （BIANBU_SEC_SESSION=1）。测试不该假定其中一种 ——
        实测中两种都出现过，写死 SessionBus 会让 8 项测试全错。
        """
        if self._iface is not None:
            return self._iface

        for p in (SECD_HOME, f"{SECD_HOME}/client"):
            if p not in sys.path:
                sys.path.append(p)
        os.environ.setdefault(
            "DBUS_SESSION_BUS_ADDRESS", "unix:path=/run/user/1000/bus")
        import dbus  # noqa: PLC0415

        errors = []
        for kind, factory in (("system", dbus.SystemBus),
                              ("session", dbus.SessionBus)):
            try:
                bus = factory()
                obj = bus.get_object("io.bianbu.Security", "/io/bianbu/Security")
                iface = dbus.Interface(obj, "io.bianbu.Security")
                # P0 caller 绑定启用后，未绑定 probe.agent 调 CheckPermission
                # 必须被 PermissionDenied；不能再用“任意未绑定 Agent 返回 DENY”
                # 作为连通性探针。改用标准 Introspect 验证真实业务接口存在。
                intro = dbus.Interface(
                    obj, "org.freedesktop.DBus.Introspectable").Introspect()
                if '<method name="CheckPermission">' not in str(intro):
                    raise RuntimeError("io.bianbu.Security 缺少 CheckPermission")
                # 直接 D-Bus 用例不得冒充真实 PA。测试进程以独立 Agent 身份
                # 建立绑定；PA 的 com.bianbu.agent 仅由 PA 自身 sender 使用。
                iface.BindAgent(TEST_AGENT_ID)
                self.log(f"securityd 在 {kind} 总线上")
                self._iface = iface
                return iface
            except Exception as e:  # noqa: BLE001 — 逐条总线试
                errors.append(f"{kind}: {type(e).__name__}: {str(e)[:90]}")
        raise RuntimeError("securityd 两条总线都连不上 —— " + "; ".join(errors))

    def check_permission(self, cap: str, scope: str = "") -> str:
        d = int(self.dbus().CheckPermission(TEST_AGENT_ID, cap, scope))
        name = DECISION.get(d, str(d))
        self.log(f"CheckPermission({cap!r}) → {name}")
        return name

    # —— 审计差分 ——
    def audit_seq(self) -> int:
        """当前最大 seq；用于圈定某次操作产生的审计增量。"""
        try:
            db = audit_chain_db()
            if db is None:
                return -1
            con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
            row = con.execute("SELECT MAX(seq) FROM audit_record").fetchone()
            con.close()
            return int(row[0]) if row and row[0] is not None else 0
        except Exception as e:
            self.log(f"audit_seq 失败: {e}")
            return -1

    def audit_since(self, seq: int) -> list[dict]:
        if seq < 0:
            return []
        try:
            db = audit_chain_db()
            if db is None:
                return []
            con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
            rows = con.execute(
                "SELECT seq, ts, agent_id, op_type, target, result "
                "FROM audit_record WHERE seq > ? ORDER BY seq", (seq,)).fetchall()
            con.close()
            return [dict(zip(("seq", "ts", "agent_id", "op_type", "target", "result"), r))
                    for r in rows]
        except Exception as e:
            self.log(f"audit_since 失败: {e}")
            return []

    # —— 安全模式 ——
    def security_mode(self, agent_id: str) -> str:
        return str(self.dbus().GetAgentSecurityMode(agent_id).get("mode", ""))

    class _ModeGuard:
        def __init__(self, ctx: "Ctx", agent_id: str, mode: str, *, lift_budget: bool = True) -> None:
            self.ctx, self.agent_id, self.mode = ctx, agent_id, mode
            self.previous = ""

        def __enter__(self):
            self.previous = self.ctx.security_mode(self.agent_id)
            if self.previous != self.mode:
                self.ctx.dbus().SetAgentSecurityMode(self.agent_id, self.mode)
                self.ctx.log(f"安全模式 {self.agent_id}: {self.previous} → {self.mode}（测试期间临时）")
            else:
                self.ctx.log(f"安全模式 {self.agent_id}: 已是 {self.mode}")
            return self

        def __exit__(self, *exc):
            if self.previous and self.previous != self.mode:
                try:
                    self.ctx.dbus().SetAgentSecurityMode(self.agent_id, self.previous)
                    self.ctx.log(f"安全模式 {self.agent_id}: 恢复为 {self.previous}")
                except Exception as e:  # noqa: BLE001
                    self.ctx.log(f"恢复安全模式失败（需人工检查）：{str(e)[:160]}")
            return False

    def enforcing_mode(self, agent_id: str, *, lift_budget: bool = True):
        """把 Agent 临时切到 normal（强制判权）模式，退出时恢复原模式。

        ``lift_budget`` 仅为兼容既有调用方保留 —— token 配额模型已删除，
        该参数不再有副作用。

        securityd 自 0.1.27 起把新注册 Agent 默认置为 yolo（capability/scope 全放行、
        仅审计）。验证 DENY/BLOCK 真实生效的用例必须在 normal 下运行，否则 run 会
        completed，测试无从判断（2026-09-11 报告中 HOOK-03/DLP-04/ERR-01 即因此误判）。
        """
        return Ctx._ModeGuard(self, agent_id, "normal", lift_budget=lift_budget)

    # —— run 编排 ——
    def run_prompt(self, prompt: str, timeout: int = 240,
                   session_id: str | None = None,
                   approve_tools: tuple[str, ...] = ()) -> dict:
        """通过当前 Session API 发起执行并从权威事件流读取终态。

        默认每次新建 Session；传入已存在的 `session_id` 可在同一会话内连续发起
        run（会话级 Token 配额等语义需要）。返回值含 `session_id`。
        """
        sid = session_id or ("t-" + uuid.uuid4().hex[:10])
        if session_id is None:
            st, r = self.http("POST", "/api/v1/sessions", {
                "id": sid, "agent_id": PA_AGENT})
            if st not in (200, 201):
                raise RuntimeError(f"创建 Session 失败 HTTP {st}: {str(r)[:200]}")
        message_id = "m-" + uuid.uuid4().hex
        st, r = self.http("POST", f"/api/v1/sessions/{sid}/prompt", {
            "message_id": message_id, "content": prompt})
        if st not in (200, 201, 202):
            raise RuntimeError(f"提交 Session prompt 失败 HTTP {st}: {str(r)[:200]}")
        rid = (r or {}).get("data", {}).get("run_id")
        if not rid:
            raise RuntimeError(f"Session prompt 未返回 run_id: {str(r)[:200]}")
        self.log(f"run_id={rid} session={sid}")
        resolved_approvals: set[str] = set()
        deadline = time.time() + timeout
        while time.time() < deadline:
            st, page = self.http(
                "GET", f"/api/v1/sessions/{sid}/events?max_messages=50", timeout=30)
            if st != 200:
                raise RuntimeError(
                    f"Session 事件查询失败 HTTP {st}: {str(page)[:200]}")
            events = (page or {}).get("data", [])
            # Explicit per-case approval of harmless test actions. Security DENY
            # still has to reject execution after Runtime's generic approval.
            for event in events:
                if event.get("type") != "approval/requested" or event.get("run_id") != rid:
                    continue
                payload = event.get("data") or {}
                approval_id = str(payload.get("approval_id") or "")
                actions = payload.get("actions") or []
                if (approval_id and approval_id not in resolved_approvals and actions
                        and all(action.get("name") in approve_tools for action in actions)):
                    code, response = self.http("POST", f"/api/v1/sessions/{sid}/approvals/{approval_id}",
                        {"decision": "approve", "reason": "Explicitly authorized harmless acceptance probe"})
                    if code != 200:
                        raise RuntimeError(f"Probe approval failed: {code}: {response}")
                    resolved_approvals.add(approval_id)
                    self.log(f"测试用例批准工具 {[a.get('name') for a in actions]}")
            terminal = next((event for event in reversed(events)
                             if str(event.get("run_id") or "") == str(rid)
                             and event.get("type") in {
                                 "run/completed", "run/failed", "run/cancelled"}), None)
            if terminal is not None:
                payload = terminal.get("data") or {}
                result = payload.get("result") if isinstance(payload.get("result"), dict) else {}
                status = str(payload.get("status") or result.get("status") or
                             terminal["type"].split("/", 1)[1])
                value = {**result, **payload, "status": status, "run_id": str(rid),
                         "session_id": sid}
                self.log(f"run 终态={status}")
                return value
            time.sleep(3)
        raise TimeoutError(f"run {rid} 轮询超时 {timeout}s")

    def shell(self, cmd: str, timeout: int = 120) -> tuple[int, str]:
        p = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        out = (p.stdout + p.stderr)[-4000:]
        self.log(f"$ {cmd[:90]} → rc={p.returncode}")
        return p.returncode, out


# ────────────────────────────── 注册表 ──────────────────────────────
TESTS: list[dict] = []


def test(id: str, title: str, requirement: str = "", category: str = "general"):
    def deco(fn: Callable[[Ctx], list[Step]]):
        TESTS.append({"id": id, "title": title, "requirement": requirement,
                      "category": category, "fn": fn})
        return fn
    return deco


# ────────────────────────────── 事件流 ──────────────────────────────
class Emitter:
    """把测试进度写成 JSONL，WebUI 轮询它做动态监视。"""

    def __init__(self, out: Path) -> None:
        out.mkdir(parents=True, exist_ok=True)
        self.events = out / "events.jsonl"
        self.report = out / "report.json"
        self.events.write_text("")

    def emit(self, kind: str, **kw) -> None:
        rec = {"ts": time.time(), "kind": kind, **kw}
        with self.events.open("a") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")

    def write_report(self, payload: dict) -> None:
        self.report.write_text(json.dumps(payload, ensure_ascii=False, indent=2))


# ────────────────────────────── 执行器 ──────────────────────────────
def run_all(selected: set[str] | None = None) -> dict:
    em = Emitter(OUT_DIR)
    items = [t for t in TESTS if selected is None or t["id"] in selected]
    em.emit("start", total=len(items),
            tests=[{"id": t["id"], "title": t["title"],
                    "requirement": t["requirement"], "category": t["category"]}
                   for t in items])

    results: list[Result] = []
    t0 = time.time()
    for t in items:
        res = Result(id=t["id"], title=t["title"],
                     requirement=t["requirement"], category=t["category"],
                     status="running")
        em.emit("test_start", id=res.id, title=res.title)
        ctx = Ctx()
        seq0 = ctx.audit_seq()
        s = time.time()
        try:
            steps = t["fn"](ctx) or []
            res.steps = steps
            failed = [x for x in steps if not x.ok]
            res.status = "failed" if failed else "passed"
            if failed:
                res.message = "; ".join(f"{x.name}: {x.detail}" for x in failed[:3])
        except Exception as e:
            res.status = "error"
            res.error = traceback.format_exc()[-2500:]
            res.message = f"{type(e).__name__}: {e}"
        res.duration_ms = int((time.time() - s) * 1000)
        res.logs = ctx.logs
        res.audit_delta = ctx.audit_since(seq0)
        results.append(res)
        em.emit("test_end", id=res.id, status=res.status,
                duration_ms=res.duration_ms, message=res.message,
                steps=[asdict(x) for x in res.steps],
                audit_count=len(res.audit_delta))

    summary = {
        "total": len(results),
        "passed": sum(1 for r in results if r.status == "passed"),
        "failed": sum(1 for r in results if r.status == "failed"),
        "error": sum(1 for r in results if r.status == "error"),
        "skipped": sum(1 for r in results if r.status == "skipped"),
        "duration_ms": int((time.time() - t0) * 1000),
        "started_at": t0,
        "finished_at": time.time(),
    }
    payload = {"summary": summary, "results": [asdict(r) for r in results]}
    em.write_report(payload)
    em.emit("done", **summary)
    return payload


if __name__ == "__main__":
    import tests_all  # noqa: F401  — 注册测试项
    sel = set(sys.argv[1:]) or None
    out = run_all(sel)
    s = out["summary"]
    print(f"\n{'='*60}")
    print(f"总计 {s['total']} | 通过 {s['passed']} | 失败 {s['failed']} | 错误 {s['error']}")
    print(f"报告: {OUT_DIR/'report.json'}")
    print(f"{'='*60}")
    for r in out["results"]:
        if r["status"] not in ("passed",):
            print(f"  [{r['status'].upper()}] {r['id']} {r['title']}")
            if r["message"]:
                print(f"      {r['message'][:200]}")
    sys.exit(1 if (s["failed"] or s["error"]) else 0)
