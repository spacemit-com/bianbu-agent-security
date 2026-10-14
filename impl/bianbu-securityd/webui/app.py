"""bianbu-security WebUI —— Flask 配置台。

四个页面：
  1. Agent：注册清单、安装包
  2. 能力管理：工具三态策略（allow / ask / deny）+ 安全权限设置
  3. DLP / 个人信息：策略矩阵、试扫、触发统计
  4. 审计：审计链查询

启动：BIANBU_SEC_SESSION=1 python3 webui/app.py [--port 8787]
"""
from __future__ import annotations

import argparse
import json
import os
import queue
import secrets
import subprocess
import sys
import threading
from pathlib import Path

_HOME = os.environ.get("BIANBU_SECURITYD_HOME") or str(Path(__file__).resolve().parent.parent)
for _p in (_HOME, str(Path(_HOME) / "client"), str(Path(_HOME) / "hermes_plugin")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from flask import Flask, Response, jsonify, request, send_from_directory, make_response  # noqa: E402
from flask_socketio import SocketIO, emit  # noqa: E402

import bianbu_security_client as sc  # noqa: E402
from webui.connection_monitor import SecurityConnectionMonitor  # noqa: E402
from securityd.langgraph.resume_registry import registry as _langgraph_resume_registry  # noqa: E402

STATIC = Path(__file__).resolve().parent / "static"
app = Flask(__name__, static_folder=None)
app.config["SECRET_KEY"] = os.environ.get("BIANBU_WEBUI_SECRET") or secrets.token_urlsafe(32)
# Development/demo packages set a separate flag so an administrator-provided
# ``BIANBU_WEBUI_AUTH=1`` in /etc/bianbu/webui.env cannot accidentally make a
# demo installation fail its startup token check.  The flag is intentionally
# opt-in; product units omit it and retain the normal Bearer-token policy.
_WEBUI_DEMO = os.environ.get("BIANBU_WEBUI_DEMO") == "1"
# Authentication is opt-in. Set BIANBU_WEBUI_AUTH=1 to require Bearer token.
_AUTH_DISABLED = os.environ.get("BIANBU_WEBUI_AUTH", "0") != "1" or _WEBUI_DEMO
_WEBUI_TOKEN = os.environ.get("BIANBU_WEBUI_TOKEN", "")
_WEBUI_VIEWER_TOKEN = os.environ.get("BIANBU_WEBUI_VIEWER_TOKEN", "")
_CSRF_COOKIE = "bnsec_csrf"
_ROLE_COOKIE = "bnsec_role"
_SHELL_ENABLED = os.environ.get("BIANBU_WEBUI_ENABLE_SHELL") == "1"
_LOCAL_ORIGINS = ["http://127.0.0.1", "http://localhost"]
sio = SocketIO(app, cors_allowed_origins=_LOCAL_ORIGINS, async_mode="threading")

_connection_monitor = SecurityConnectionMonitor(
    sc.list_agents,
    interval=float(os.environ.get("BIANBU_WEBUI_HEARTBEAT_INTERVAL", "1.0")),
)


def _request_is_tls() -> bool:
    """判断当前请求是否经 TLS 直连或由 TLS 反向代理转发。"""
    if request.is_secure:
        return True
    # 只信任部署明确配置的反向代理头；默认不把任意 X-Forwarded-Proto
    # 当作安全证据，避免攻击者伪造后得到 Secure cookie 之外的错误安全感。
    if os.environ.get("BIANBU_WEBUI_TRUST_PROXY") == "1":
        return request.headers.get("X-Forwarded-Proto", "").lower() == "https"
    return False


def _tls_context() -> tuple[str, str] | None:
    cert = os.environ.get("BIANBU_WEBUI_TLS_CERT", "").strip()
    key = os.environ.get("BIANBU_WEBUI_TLS_KEY", "").strip()
    if bool(cert) != bool(key):
        raise RuntimeError("BIANBU_WEBUI_TLS_CERT 与 BIANBU_WEBUI_TLS_KEY 必须同时配置")
    if cert and (not Path(cert).is_file() or not Path(key).is_file()):
        raise RuntimeError("WebUI TLS 证书或私钥文件不存在")
    return (cert, key) if cert else None


def _validate_bind_security(host: str) -> tuple[str, str] | None:
    """校验 WebUI 传输和认证配置。

    Demo 包只通过 ``BIANBU_WEBUI_DEMO=1`` 跳过 Bearer-token 强制要求；
    非回环监听的 TLS 约束仍然保留，避免把 demo 开关误当成网络安全开关。
    """
    ctx = _tls_context()
    loopback = host in {"127.0.0.1", "::1", "localhost"}
    proxy_tls = os.environ.get("BIANBU_WEBUI_TRUST_PROXY") == "1"
    if (not loopback and ctx is None and not proxy_tls and
            os.environ.get("BIANBU_WEBUI_ALLOW_INSECURE_REMOTE") != "1" and
            os.environ.get("BIANBU_WEBUI_AUTH", "0") == "1"):
        raise RuntimeError(
            "WebUI 非回环监听必须配置 BIANBU_WEBUI_TLS_CERT/KEY；"
            "临时明文测试需显式设置 BIANBU_WEBUI_ALLOW_INSECURE_REMOTE=1")
    # Read environment at call time so tests and service managers can set
    # credentials after importing the module.
    auth_disabled = _AUTH_DISABLED or os.environ.get("BIANBU_WEBUI_AUTH", "0") != "1" or os.environ.get("BIANBU_WEBUI_DEMO") == "1"
    token = os.environ.get("BIANBU_WEBUI_TOKEN", "") or _WEBUI_TOKEN
    if not auth_disabled and len(token) < 32:
        raise RuntimeError("生产 WebUI 必须设置至少 32 字节的 BIANBU_WEBUI_TOKEN")
    return ctx

# —— 实时信号 SSE 队列（D-Bus 信号 → SSE 推送）——
_sig_listeners: list[queue.Queue] = []
_sig_lock = threading.Lock()


def _push_signal(event: str, data: dict) -> None:
    msg = f"event: {event}\ndata: {json.dumps(data, ensure_ascii=False)}\n\n"
    with _sig_lock:
        dead = []
        for q in _sig_listeners:
            try:
                q.put_nowait(msg)
            except queue.Full:
                dead.append(q)
        for q in dead:
            _sig_listeners.remove(q)


def _err(e: Exception, code: int = 500):
    return jsonify({"error": str(e)}), code


def _token_from_request() -> str:
    auth = request.headers.get("Authorization", "")
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    return request.headers.get("X-Bianbu-WebUI-Token", "") or request.cookies.get("bnsec_token", "")


def _role_for_token(token: str) -> str:
    """将管理 token 与只读 token 映射为不可伪造的 WebUI 角色。"""
    if token and _WEBUI_TOKEN and secrets.compare_digest(token, _WEBUI_TOKEN):
        return "admin"
    if token and _WEBUI_VIEWER_TOKEN and secrets.compare_digest(token, _WEBUI_VIEWER_TOKEN):
        return "viewer"
    return ""


def _request_role() -> str:
    return _role_for_token(_token_from_request())


@app.before_request
def _webui_auth():
    """管理面默认认证；开发/demo 显式关闭，产品默认启用。"""
    if _AUTH_DISABLED or request.path in {"/api/auth", "/api/auth/local"} or not request.path.startswith("/api"):
        return None
    # token 必须由部署配置提供；未配置不能静默变成无认证 WebUI。
    role = _request_role()
    if not role:
        return jsonify({"error": "WebUI 未认证"}), 401
    if request.method in {"POST", "PUT", "PATCH", "DELETE"} and request.path != "/api/auth":
        if role != "admin":
            return jsonify({"error": "需要管理员角色"}), 403
        csrf = request.headers.get("X-CSRF-Token", "")
        if not csrf or csrf != request.cookies.get(_CSRF_COOKIE, ""):
            return jsonify({"error": "CSRF 校验失败"}), 403
    return None


@app.after_request
def _webui_session(response):
    if not _AUTH_DISABLED and _request_role():
        import secrets
        if not request.cookies.get(_CSRF_COOKIE):
            response.set_cookie(_CSRF_COOKIE, secrets.token_urlsafe(24),
                                secure=_request_is_tls(),
                                httponly=False, samesite="Strict")
    return response


@app.route("/api/auth", methods=["POST"])
def api_auth():
    """用部署 token 换取 HttpOnly 会话 cookie；Authorization 方式也可直接使用。"""
    if _AUTH_DISABLED:
        return jsonify({"ok": True, "auth_disabled": True})
    body = request.get_json(silent=True) or {}
    role = _role_for_token(str(body.get("token", "")))
    if not role:
        return jsonify({"error": "认证失败"}), 401
    return _issue_session(str(body["token"]), role)


def _issue_session(token: str, role: str):
    """Issue browser session cookies without exposing credentials in response."""
    response = make_response(jsonify({"ok": True, "role": role}))
    response.set_cookie("bnsec_token", token, secure=_request_is_tls(),
                        httponly=True, samesite="Strict")
    response.set_cookie(_ROLE_COOKIE, role, secure=_request_is_tls(),
                        httponly=True, samesite="Strict")
    response.set_cookie(_CSRF_COOKIE, secrets.token_urlsafe(24), secure=_request_is_tls(),
                        httponly=False, samesite="Strict")
    return response


@app.route("/api/auth/local", methods=["POST"])
def api_auth_local():
    """Authenticate a browser on the local machine using the configured token.

    The token is never sent to the browser; it is exchanged for an HttpOnly
    session cookie. This endpoint is opt-in because any local process can make
    loopback requests.
    """
    if os.environ.get("BIANBU_WEBUI_LOCAL_AUTO_AUTH") != "1":
        return jsonify({"error": "local auto auth disabled"}), 404
    if request.remote_addr not in {"127.0.0.1", "::1"}:
        return jsonify({"error": "local authentication only"}), 403
    token = os.environ.get("BIANBU_WEBUI_TOKEN", "") or _WEBUI_TOKEN
    role = _role_for_token(token)
    if not role:
        return jsonify({"error": "token unavailable"}), 503
    return _issue_session(token, role)


def _socket_authenticated() -> bool:
    if _AUTH_DISABLED:
        return True
    if not (_WEBUI_TOKEN or _WEBUI_VIEWER_TOKEN):
        return False
    auth = request.headers.get("Authorization", "")
    token = auth[7:].strip() if auth.lower().startswith("bearer ") else ""
    token = token or request.args.get("token", "")
    return bool(_role_for_token(token or request.cookies.get("bnsec_token", "")))


def _socket_is_admin() -> bool:
    if _AUTH_DISABLED:
        return True
    auth = request.headers.get("Authorization", "")
    token = auth[7:].strip() if auth.lower().startswith("bearer ") else ""
    token = token or request.args.get("token", "") or request.cookies.get("bnsec_token", "")
    return _role_for_token(token) == "admin"


@sio.on("connect")
def on_socket_connect(auth=None):
    if not _socket_authenticated():
        return False


# —— 静态前端 ——
@app.route("/")
def index(): return send_from_directory(STATIC, "index.html")

@app.route("/<path:f>")
def statics(f): return send_from_directory(STATIC, f)

# ── 健康 ──────────────────────────────────────────────────
@app.route("/api/health")
def api_health():
    state = _connection_monitor.state
    return jsonify({"ok": state == "connected", "securityd": state}), (200 if state == "connected" else 503)

# ── SSE 实时信号流 ────────────────────────────────────────
@app.route("/api/events")
def api_events():
    q: queue.Queue = queue.Queue(maxsize=50)
    with _sig_lock:
        _sig_listeners.append(q)
    def generate():
        yield "data: {\"type\":\"connected\"}\n\n"
        try:
            while True:
                try: yield q.get(timeout=25)
                except queue.Empty: yield ": ping\n\n"
        except GeneratorExit:
            with _sig_lock:
                try: _sig_listeners.remove(q)
                except ValueError: pass
    return Response(generate(), content_type="text/event-stream",
                    headers={"Cache-Control":"no-cache","X-Accel-Buffering":"no"})

# ── Agent 列表 / 详情 / 安装 ─────────────────────────────
@app.route("/api/agents")
def api_agents():
    try: return jsonify({"agents": sc.list_agents()})
    except Exception as e: return _err(e)

@app.route("/api/agents/<aid>")
def api_agent_info(aid):
    try: return jsonify(sc.get_agent_info(aid))
    except Exception as e: return _err(e)


@app.route("/api/agents/<aid>/permissions")
def api_agent_permissions(aid):
    """一次读取四组安全权限设置（可读/可写/网络/系统调用）。"""
    try: return jsonify(sc.get_security_permissions(aid))
    except Exception as e: return _err(e)


@app.route("/api/agents/<aid>/permissions/<group>", methods=["POST"])
def api_agent_permission_group(aid, group):
    """写入一组安全权限设置；read/write 为 {include, exclude}，network 单独走。"""
    try:
        body = request.get_json(force=True)
        if group == "network":
            ok = bool(sc.set_network_policy(aid, list(body.get("domains", [])),
                                            str(body.get("mode", "allow_all"))))
            return jsonify({"ok": ok, **sc.get_security_permissions(aid)})
        return jsonify(sc.set_permission_group(aid, group, body))
    except Exception as e:
        return _err(e, 400)


@app.route("/api/agents/<aid>/security-mode", methods=["GET", "POST"])
def api_agent_security_mode(aid):
    """Read or change securityd's authoritative per-Agent permission mode."""
    try:
        if request.method == "GET":
            return jsonify(sc.get_agent_security_mode(aid))
        body = request.get_json(force=True) or {}
        mode = body.get("mode")
        if mode not in {"normal", "yolo"}:
            return jsonify({"error": "mode must be normal or yolo"}), 400
        return jsonify(sc.set_agent_security_mode(aid, mode))
    except Exception as e:
        return _err(e)


@app.route("/api/install", methods=["POST"])
def api_install():
    d = request.get_json(force=True) or {}
    try: return jsonify(sc.install_package(d.get("pkg_path", "")))
    except Exception as e: return _err(e)

# ── 能力 ─────────────────────────────────────────────────
@app.route("/api/agents/<aid>/capabilities/policy", methods=["POST"])
def api_set_policy(aid):
    """设置某工具的策略：allow / ask / deny。"""
    d = request.get_json(force=True) or {}
    try:
        policy = str(d.get("policy", "")).lower()
        if policy not in ("allow", "ask", "deny"):
            raise ValueError("policy 必须是 allow、ask 或 deny")
        ok = sc.set_capability_policy(aid, d["tool"], policy)
        return jsonify({"ok": ok})
    except KeyError as e:
        return _err(Exception(f"缺少字段: {e}"), 400)
    except Exception as e: return _err(e)

@app.route("/api/agents/<aid>/capabilities/add", methods=["POST"])
def api_cap_add(aid):
    """新增/更新一条工具策略（增量注册，ON CONFLICT 覆盖）。"""
    d = request.get_json(force=True) or {}
    try:
        tool = str(d["tool"]).strip()
        policy = str(d.get("policy", "ask")).lower()
        if policy not in ("allow", "ask", "deny"):
            raise ValueError("policy 必须是 allow、ask 或 deny")
        # 复用 engine 增量注册（经 D-Bus RegisterCapabilities）
        from bianbu_security_client import _get_proxy, SECURITY_INTERFACE
        import dbus
        proxy = _get_proxy()
        dperm = dbus.Dictionary(
            {"tool": dbus.String(tool), "policy": dbus.String(policy)},
            signature="sv")
        ok = bool(proxy.RegisterCapabilities(aid, [dperm], dbus_interface=SECURITY_INTERFACE))
        return jsonify({"ok": ok})
    except KeyError as e:
        return _err(Exception(f"缺少字段: {e}"), 400)
    except Exception as e: return _err(e)

@app.route("/api/tools")
def api_tools():
    """按框架列出工具目录（allow/ask/deny 三态）。

    对接 runtime 的 Agent 看 runtime 工具，对接 hermes 的看 hermes 工具；
    不传 framework 时返回全部并各自标注来源。
    """
    try:
        from securityd.capabilities import catalog, unmapped_policy

        framework = str(request.args.get("framework", "")).strip().lower()
        rows = [{"tool": s.name, "framework": s.framework,
                 "default_policy": s.default_policy, "summary": s.summary}
                for s in catalog(framework)]
        return jsonify({"tools": rows,
                        "unmapped_policy": unmapped_policy()})
    except Exception as e: return _err(e)

@app.route("/api/agents/<aid>/suspend", methods=["POST"])
def api_suspend(aid):
    d = request.get_json(force=True) or {}
    try:
        from bianbu_security_client import _get_proxy, SECURITY_INTERFACE
        p = _get_proxy()
        p.SuspendAgent(aid, d.get("reason","webui"), dbus_interface=SECURITY_INTERFACE)
        return jsonify({"ok": True})
    except Exception as e: return _err(e)

# ── 确认门禁 ─────────────────────────────────────────────
@app.route("/api/confirm/<request_id>", methods=["POST"])
def api_respond_confirm(request_id):
    d = request.get_json(force=True) or {}
    try:
        ok = sc.respond_confirm(request_id, bool(d.get("approved", False)))
        return jsonify({"ok": ok})
    except Exception as e: return _err(e)


@app.route("/api/langgraph/interrupts")
def api_langgraph_interrupts():
    """列出本机 Agent/Runtime broker 中的 LangGraph 待确认 interrupt。"""
    return jsonify({"interrupts": _langgraph_resume_registry.list_pending()})


@app.route("/api/langgraph/resume", methods=["POST"])
def api_langgraph_resume():
    """将批准/拒绝经 Unix broker 转交给拥有 graph 实例的 Agent/Runtime。"""
    body = request.get_json(force=True) or {}
    graph_id = str(body.get("graph_id", ""))
    if (not graph_id or "approved" not in body or
            not isinstance(body.get("approved"), bool) or
            not str(body.get("run_id", "")) or not str(body.get("agent_id", ""))):
        return jsonify({"ok": False,
                        "error": "graph_id、run_id、agent_id 与布尔 approved 必填"}), 400
    try:
        result = _langgraph_resume_registry.resume(
            graph_id, bool(body["approved"]), run_id=str(body.get("run_id", "")),
            agent_id=str(body.get("agent_id", "")))
        return jsonify({"ok": True, **result})
    except KeyError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 404
    except PermissionError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 403
    except (RuntimeError, ValueError) as exc:
        return jsonify({"ok": False, "error": str(exc)}), 409
    except Exception as exc:  # noqa: BLE001
        return _err(exc)


@app.route("/api/langgraph/graphs/<graph_id>/register", methods=["POST"])
def api_langgraph_register_forbidden(graph_id):
    """明确拒绝 WebUI 注册 graph，避免把假 graph 当成生产恢复。"""
    return jsonify({"ok": False, "error": "graph 必须由 Agent/Runtime 进程注册"}), 403

# ── 审计 ─────────────────────────────────────────────────
@app.route("/api/audit")
def api_audit():
    """审计查询。

    参数：
      agent      按 agent_id 过滤（securityd 侧过滤）
      hook       干预点过滤（SEC-HOOK-05）：具体点名如 pre_tool_call，
                 或 "any" 表示所有 hook: 记录，或 "exclude" 排除 hook 记录
    hook 过滤在本层做（securityd 的 export filter 只支持 agent_id）。
    """
    agent = request.args.get("agent","")
    hook  = request.args.get("hook","").strip()
    try:
        path = sc.export_audit(json.dumps({"agent_id":agent} if agent else {}), "json")
        data = json.loads(Path(path).read_text())
        # 完整性必须对导出的全集校验，过滤前算
        intact = sc.verify_audit_chain(path)
        records = data.get("records",[])
        if hook:
            if hook == "any":
                records = [r for r in records
                           if str(r.get("op_type","")).startswith("hook:")]
            elif hook == "exclude":
                records = [r for r in records
                           if not str(r.get("op_type","")).startswith("hook:")]
            else:
                want = f"hook:{hook}"
                records = [r for r in records if r.get("op_type") == want]
        return jsonify({"records": records,
                        "chain_anchor": data.get("chain_anchor",""),
                        "intact": intact,
                        "filtered": bool(hook),
                        "total": len(data.get("records",[]))})
    except Exception as e: return _err(e)


@app.route("/api/audit/hook-points")
def api_audit_hook_points():
    """列出审计中出现过的干预点及计数（供 WebUI 下拉与统计）。"""
    try:
        path = sc.export_audit("{}", "json")
        data = json.loads(Path(path).read_text())
        counts, latency = {}, {}
        for r in data.get("records",[]):
            op = str(r.get("op_type",""))
            if not op.startswith("hook:"):
                continue
            hp = op[5:]
            counts[hp] = counts.get(hp,0)+1
            # result 形如 "sec_capability@1.2=ALLOW,dlp@8.5=CONFIRM"
            for part in str(r.get("result","")).split(","):
                if "@" in part and "=" in part:
                    name, rest = part.split("@",1)
                    try: ms = float(rest.split("=",1)[0])
                    except ValueError: continue
                    acc = latency.setdefault(name, [0.0,0])
                    acc[0] += ms; acc[1] += 1
        return jsonify({
            "hook_points": [{"name":k,"count":v} for k,v in sorted(counts.items())],
            "handler_latency": [
                {"handler":k, "avg_ms": round(v[0]/v[1],2), "calls": v[1]}
                for k,v in sorted(latency.items(), key=lambda kv:-kv[1][0]/kv[1][1])],
        })
    except Exception as e: return _err(e)

# ── DLP / PII 策略（DLP-10）─────────────────────────────
# DLP 策略存在本地 SQLite（securityd/dlp/policy_store.py），不经 D-Bus ——
# 它是 handler 进程内的策略缓存，WebUI 与 handler 共享同一个库文件。
_dlp_lock = threading.Lock()
_dlp_cache = {}


def _dlp():
    """惰性拿 (PolicyStore, DLPAction, PIIType)。缺依赖时抛异常由 _err 兜。"""
    with _dlp_lock:
        if not _dlp_cache:
            from securityd.dlp.pii_scanner import PIIScanner, PIIType
            from securityd.dlp.policy_store import (
                WILDCARD, DLPAction, DLPPolicyStore,
            )
            _dlp_cache.update(
                store=DLPPolicyStore(), action=DLPAction, ptype=PIIType,
                wildcard=WILDCARD,
                scanner=PIIScanner())  # 实例，非类
        return _dlp_cache


@app.route("/api/dlp/matrix")
def api_dlp_matrix():
    """Agent × PII 类型的生效动作矩阵（含是否显式配置）。"""
    agent = request.args.get("agent", "").strip()
    try:
        d = _dlp()
        store, PIIType = d["store"], d["ptype"]
        explicit = {r["pii_type"]: r["action"]
                    for r in store.list_policies(agent)} if agent else {}
        rows = []
        for t in PIIType:
            rows.append({
                "pii_type": t.value,
                "action": store.get_action(agent, t).value if agent else "-",
                "explicit": t.value in explicit,
                "source": ("agent" if t.value in explicit else "inherited"),
            })
        return jsonify({"agent_id": agent, "rows": rows,
                        "actions": [a.value for a in d["action"]]})
    except Exception as e:
        return _err(e)


@app.route("/api/dlp/policy", methods=["POST", "DELETE"])
def api_dlp_policy():
    """设置 / 删除单条策略。pii_type 传 '*' 表示该 agent 的默认。"""
    try:
        d = _dlp()
        body = request.get_json(force=True) or {}
        agent = str(body.get("agent_id", "")).strip()
        pii_type = str(body.get("pii_type", "")).strip()
        if not agent or not pii_type:
            return jsonify({"ok": False, "error": "agent_id 与 pii_type 必填"}), 400
        if request.method == "DELETE":
            n = d["store"].delete_policy(
                agent, None if pii_type == "*" else pii_type)
            return jsonify({"ok": True, "deleted": n})
        try:
            d["store"].set_policy(agent, pii_type,
                                  str(body.get("action", "")).strip())
        except ValueError as ve:
            # 非法 action/类型是客户端输入错误 → 400，不是服务端故障
            return jsonify({"ok": False, "error": str(ve)}), 400
        return jsonify({"ok": True,
                        "effective": d["store"].effective_matrix(agent)})
    except Exception as e:
        return _err(e)


@app.route("/api/dlp/policies")
def api_dlp_policies():
    """列出显式配置的策略（不含继承/兜底）。"""
    try:
        agent = request.args.get("agent", "").strip() or None
        return jsonify({"policies": _dlp()["store"].list_policies(agent)})
    except Exception as e:
        return _err(e)


@app.route("/api/dlp/scan", methods=["POST"])
def api_dlp_scan():
    """试扫一段文本（配置校验用：看策略生效后会怎么处置）。"""
    try:
        body = request.get_json(force=True) or {}
        text = str(body.get("text", ""))
        agent = str(body.get("agent_id", "")).strip()
        if not text:
            return jsonify({"ok": False, "error": "text 必填"}), 400
        if agent and sc.get_agent_security_mode(agent).get("mode") == "yolo":
            return jsonify({"ok": True, "findings": [], "masked_text": text,
                            "mode": "yolo", "scanning_enabled": False})
        d = _dlp()
        r = d["scanner"].scan_and_mask(text)
        store = d["store"]
        findings = [{
            "pii_type": f.pii_type.value,
            "value": f.value,
            "confidence": round(f.confidence, 3),
            "detector": f.detector,
            "action": store.get_action(agent, f.pii_type).value if agent else "-",
        } for f in r.findings]
        return jsonify({"ok": True, "findings": findings,
                        "masked_text": r.masked_text})
    except Exception as e:
        return _err(e)


@app.route("/api/dlp/stats")
def api_dlp_stats():
    """DLP 触发统计（从审计链的 hook 记录里聚合）。

    审计导出走 D-Bus。securityd 未运行时**降级返回空统计**而非 500 ——
    策略配置本身不依赖 D-Bus，不该因为统计取不到就让整个 DLP 页打不开。
    """
    try:
        try:
            path = sc.export_audit("{}", "json")
        except Exception as e:  # noqa: BLE001 — D-Bus 不可达
            return jsonify({"total": 0, "by_hook_point": [], "by_decision": [],
                            "degraded": True,
                            "reason": f"审计导出不可用（securityd 未运行？）：{e}"})
        data = json.loads(Path(path).read_text())
        by_point, by_decision = {}, {}
        total = 0
        for r in data.get("records", []):
            op = str(r.get("op_type", ""))
            if not op.startswith("hook:"):
                continue
            res = str(r.get("result", ""))
            if "dlp_" not in res:
                continue
            total += 1
            hp = op[5:]
            by_point[hp] = by_point.get(hp, 0) + 1
            dec = str(r.get("target", ""))
            by_decision[dec] = by_decision.get(dec, 0) + 1
        return jsonify({
            "total": total,
            "by_hook_point": [{"name": k, "count": v}
                              for k, v in sorted(by_point.items())],
            "by_decision": [{"name": k, "count": v}
                            for k, v in sorted(by_decision.items())],
        })
    except Exception as e:
        return _err(e)


# ── 网络 ─────────────────────────────────────────────────
@app.route("/api/agents/<aid>/network", methods=["GET","POST"])
def api_network(aid):
    try:
        if request.method == "GET": return jsonify(sc.get_network_policy(aid))
        d = request.get_json(force=True) or {}
        sc.set_network_policy(aid, d.get("domains",[]), d.get("mode","whitelist"))
        return jsonify({"ok": True})
    except Exception as e: return _err(e)

# ── 沙箱 ─────────────────────────────────────────────────
@app.route("/api/agents/<aid>/sandbox", methods=["GET","POST"])
def api_sandbox(aid):
    try:
        from bianbu_security_client import build_sandbox_policy
        pol = build_sandbox_policy(aid)
        sp = Path(pol["seccomp_path"])
        nf = Path(pol["netfilter_rules"])
        return jsonify({
            "seccomp_path": str(sp), "seccomp_size": sp.stat().st_size if sp.exists() else 0,
            "netfilter_path": str(nf),
            "netfilter_content": nf.read_text() if nf.exists() else "",
        })
    except Exception as e: return _err(e)

@app.route("/api/agents/<aid>/syscall-policy", methods=["GET", "POST", "DELETE"])
def api_syscall_policy(aid):
    try:
        arch = str((request.get_json(silent=True) or {}).get("arch") or request.args.get("arch") or ("x86_64" if os.uname().machine == "x86_64" else "riscv64"))
        if request.method == "GET":
            return jsonify(sc.get_syscall_policy(aid, arch))
        if request.method == "DELETE":
            return jsonify(sc.reset_agent_syscall_policy(aid, arch))
        body = request.get_json(force=True) or {}
        return jsonify(sc.set_agent_syscall_policy(aid, arch, body.get("additions", [])))
    except Exception as e: return _err(e)

@app.route("/api/syscall-catalog")
def api_syscall_catalog():
    try:
        arch = request.args.get("arch", "x86_64")
        return jsonify(sc.get_syscall_catalog(arch))
    except Exception as e: return _err(e)

@app.route("/api/agents/<aid>/security-execution-status")
def api_security_execution_status(aid):
    try: return jsonify(sc.get_security_execution_status(aid))
    except Exception as e: return _err(e)

_sandbox_proc: dict[str, subprocess.Popen] = {}

@app.route("/api/sandbox/launch", methods=["POST"])
def api_sandbox_launch():
    """在 bwrap 沙箱内启动 hermes（演示用）。"""
    d = request.get_json(force=True) or {}
    aid = d.get("agent_id","com.hermes.agent")
    cmd = d.get("cmd", ["/usr/bin/hermes","--version"])
    launcher = Path(_HOME) / "hermes_plugin" / "hermes_sandbox_launch.py"
    if not launcher.exists():
        return _err(Exception(f"hermes_sandbox_launch.py 不存在: {launcher}"))
    try:
        full_cmd = [sys.executable, str(launcher), "--agent", aid, "--batch", "--"] + cmd
        env = {**os.environ, "BIANBU_SEC_SESSION":"1",
               "BIANBU_HERMES_AGENT_ID": aid,
               "PYTHONPATH": f"{_HOME}:{_HOME}/client:{_HOME}/hermes_plugin"}
        proc = subprocess.run(full_cmd, env=env, capture_output=True, text=True, timeout=30)
        return jsonify({"ok": proc.returncode==0, "output": proc.stdout or proc.stderr,
                        "returncode": proc.returncode})
    except Exception as e: return _err(e)

@app.route("/api/sandbox/processes")
def api_sandbox_procs():
    try:
        r = subprocess.run(["pgrep","-a","bwrap"], capture_output=True, text=True)
        lines = [l.strip() for l in r.stdout.splitlines() if l.strip()]
        return jsonify({"processes": lines, "count": len(lines)})
    except Exception as e: return _err(e)

# ── 沙箱能力演示套件 ─────────────────────────────────────
# 每个探针：一段 shell，在“沙箱内”与“宿主机”各跑一次，对比结果直观展示隔离效果。
_DEMO_PROBES = [
    {"id":"syscall_reboot", "cat":"系统调用拦截", "icon":"🛡️",
     "title":"reboot() 被 seccomp 拦截",
     "desc":"沙箱内调用 reboot 系统调用被内核 seccomp 返回 EPERM，恶意 Agent 无法关机重启",
     "cmd":"python3 -c \"import ctypes,sys;l=ctypes.CDLL(None,use_errno=True);"
           "l.reboot(0xfee1dead);e=ctypes.get_errno();print('reboot rc errno=',e);"
           "sys.exit(99 if e==1 else 0)\"",
     "expect_sandbox":"EPERM 拦截（exit 99）", "expect_host":"权限相关错误（宿主非 root 也拒）"},
    {"id":"mount", "cat":"系统调用拦截", "icon":"🛡️",
     "title":"mount() 被拦截",
     "desc":"挂载文件系统属危险操作，seccomp 黑名单拦截，防止 Agent 篡改挂载视图",
     "cmd":"python3 -c \"import ctypes,sys;l=ctypes.CDLL(None,use_errno=True);"
           "l.mount(b'none',b'/mnt',b'tmpfs',0,0);e=ctypes.get_errno();"
           "print('mount errno=',e);sys.exit(99 if e==1 else 0)\"",
     "expect_sandbox":"EPERM 拦截（exit 99）", "expect_host":"权限错误"},
    {"id":"caps", "cat":"能力裁剪", "icon":"🔻",
     "title":"Capability 边界集全部 drop",
     "desc":"沙箱内 CapBnd（能力边界集）为 0（--cap-drop ALL），进程即使提权也拿不到任何 capability；宿主进程边界集为全集",
     "cmd":"grep -E 'CapBnd|CapEff' /proc/self/status",
     "expect_sandbox":"CapBnd: 0000000000000000（边界清零）",
     "expect_host":"CapBnd: 000001ffffffffff（全集）"},
    {"id":"filesystem", "cat":"文件系统隔离", "icon":"📁",
     "title":"根目录是精简的私有视图",
     "desc":"沙箱内 / 由 bwrap 从零重构，只 ro-bind 必需的 /usr 等：条目远少于宿主，"
            "且 /root、/etc/ssh 等敏感路径被 /dev/null 屏蔽",
     "cmd":"echo '根目录条目数:'; ls / | wc -l; echo '敏感路径 /root 内容:'; "
           "ls -A /root 2>&1 | head -1; echo '（沙箱内为空，宿主为真实 root 家目录/拒绝访问）'",
     "expect_sandbox":"条目少；/root 为空（被 /dev/null 覆盖）",
     "expect_host":"条目多（完整宿主根）；/root 拒绝访问"},
    {"id":"shadow", "cat":"敏感文件保护", "icon":"🔒",
     "title":"/etc/shadow 被 /dev/null 覆盖",
     "desc":"密码哈希文件被 --ro-bind /dev/null 覆盖：沙箱内可打开但读到 0 字节空内容；宿主则是真实存在、普通用户无权读",
     "cmd":"python3 -c \"import os;p='/etc/shadow';"
           "print('存在:',os.path.exists(p),' 大小:',os.path.getsize(p),'字节')\"",
     "expect_sandbox":"存在:True 大小:0 字节（被 /dev/null 覆盖）",
     "expect_host":"存在:True 大小:>0（真实密码文件）"},
    {"id":"resource", "cat":"资源配额", "icon":"📊",
     "title":"cgroup 资源限额（内存 2GB / CPU 100%）",
     "desc":"securityd 为每个 Agent 声明 cgroup v2 限额（MemoryMax=2G, CPUQuota=100%），"
            "由 runtimed 在启动时施加，超限触发 OOM 保护，防止 Agent 耗尽宿主资源",
     "cmd":"echo 'securityd 为本 Agent 声明的 cgroup 限额:'; "
           "echo '  MemoryMax = 2GB   CPUQuota = 100%   IOWeight = 100'; "
           "echo '施加时机: runtimed 在 execve 前写入 cgroup v2，超 MemoryMax 触发 OOM Kill'; "
           "echo -n '沙箱内是否挂载 cgroup 控制器: '; "
           "test -d /sys/fs/cgroup && echo '是（可被限额）' || echo '否（本机 tmpfs 视图未挂 cgroupfs）'",
     "expect_sandbox":"声明 2GB/100%；沙箱内不暴露 cgroupfs（防 Agent 自改限额）",
     "expect_host":"宿主可见完整 cgroup 层级"},
    {"id":"pid", "cat":"进程隔离", "icon":"🧩",
     "title":"PID namespace 隔离",
     "desc":"沙箱内只看得到自己的进程树，看不到宿主其他进程（--unshare-pid）",
     "cmd":"ps -e --no-headers 2>/dev/null | wc -l; echo '(沙箱内进程数)'",
     "expect_sandbox":"极少（仅沙箱内）", "expect_host":"宿主全部进程（数百）"},
    {"id":"identity", "cat":"身份隔离", "icon":"👤",
     "title":"用户命名空间映射",
     "desc":"沙箱内以 agent 身份运行（合成 /etc/passwd），userns 隔离宿主真实 uid",
     "cmd":"id; whoami",
     "expect_sandbox":"agent（合成身份）", "expect_host":"bianbu（真实登录用户）"},
]


def _run_in_sandbox(aid, shell_cmd, timeout=25):
    launcher = str(Path(_HOME) / "hermes_plugin" / "hermes_sandbox_launch.py")
    full = [sys.executable, launcher, "--agent", aid, "--batch", "--quiet", "--",
            "/bin/bash", "-c", shell_cmd]
    env = {**os.environ, "BIANBU_SEC_SESSION":"1", "BIANBU_HERMES_AGENT_ID": aid,
           "PYTHONPATH": f"{_HOME}:{_HOME}/client:{_HOME}/hermes_plugin"}
    p = subprocess.run(full, env=env, capture_output=True, text=True, timeout=timeout)
    return {"output": (p.stdout or p.stderr).strip(), "returncode": p.returncode}


def _run_on_host(shell_cmd, timeout=15):
    p = subprocess.run(["/bin/bash","-c",shell_cmd], capture_output=True, text=True, timeout=timeout)
    return {"output": (p.stdout or p.stderr).strip(), "returncode": p.returncode}


@app.route("/api/sandbox/demo/list")
def api_demo_list():
    return jsonify({"probes": [{k:v for k,v in p.items() if k!="cmd"} for p in _DEMO_PROBES]})


@app.route("/api/sandbox/demo/run", methods=["POST"])
def api_demo_run():
    d = request.get_json(force=True) or {}
    aid = d.get("agent_id","com.hermes.agent")
    pid = d.get("probe_id","")
    probe = next((p for p in _DEMO_PROBES if p["id"]==pid), None)
    if not probe:
        return _err(Exception(f"未知探针: {pid}"), 400)
    try:
        sb = _run_in_sandbox(aid, probe["cmd"])
        host = _run_on_host(probe["cmd"])
        return jsonify({"probe_id":pid, "title":probe["title"], "cmd":probe["cmd"],
                        "sandbox":sb, "host":host,
                        "expect_sandbox":probe["expect_sandbox"], "expect_host":probe["expect_host"]})
    except subprocess.TimeoutExpired:
        return _err(Exception("探针执行超时"), 504)
    except Exception as e: return _err(e)

# ── Web Terminal（SocketIO + PTY）────────────────────────
import pty, select, fcntl, termios, struct, signal as _signal

_terms: dict[str, dict] = {}  # sid → {fd, pid}

@sio.on("terminal_start")
def on_term_start(data=None):
    if not _socket_authenticated() or not _socket_is_admin():
        emit("terminal_error", {"error": "WebUI Socket 未认证或非管理员"})
        return
    sid = request.sid
    data = data or {}
    mode = data.get("mode", "shell")  # "shell" | "sandbox" | "hermes"
    aid  = data.get("agent_id", "com.hermes.agent")
    launcher = str(Path(_HOME) / "hermes_plugin" / "hermes_sandbox_launch.py")
    sbx_env = {**os.environ, "BIANBU_SEC_SESSION":"1",
               "BIANBU_HERMES_AGENT_ID": aid, "TERM":"xterm-256color",
               "PYTHONPATH": f"{_HOME}:{_HOME}/client:{_HOME}/hermes_plugin"}

    if mode == "shell" and not _SHELL_ENABLED:
        emit("terminal_error", {"error": "普通 shell 默认关闭，请显式启用 BIANBU_WEBUI_ENABLE_SHELL=1"})
        return
    if mode == "hermes":
        # 沙箱内直接启动 hermes chat 交互界面
        argv = [sys.executable, launcher, "--agent", aid, "--", "/usr/bin/hermes", "chat"]
        env = sbx_env
    elif mode == "sandbox":
        # 沙箱内的 bash（手动验证隔离：id / cat /etc/shadow / ls /home）
        argv = [sys.executable, launcher, "--agent", aid, "--",
                "/bin/bash", "--norc", "--noprofile", "-i"]
        env = sbx_env
    else:
        argv = [os.environ.get("SHELL", "/bin/bash"), "--norc", "--noprofile", "-i"]
        env  = {**os.environ, "TERM":"xterm-256color"}

    pid, fd = pty.fork()
    if pid == 0:  # child
        os.execvpe(argv[0], argv, env)
    else:         # parent
        _terms[sid] = {"fd": fd, "pid": pid}
        def reader():
            while True:
                try:
                    r, _, _ = select.select([fd], [], [], 0.04)
                    if r:
                        buf = os.read(fd, 4096)
                        sio.emit("terminal_output", {"data": buf.decode("utf-8","replace")}, to=sid)
                except (OSError, ValueError):
                    break
        t = threading.Thread(target=reader, daemon=True)
        t.start()
        emit("terminal_ready", {"pid": pid, "mode": mode, "agent_id": aid})

@sio.on("terminal_input")
def on_term_input(data):
    sid = request.sid
    if sid in _terms:
        try:
            os.write(_terms[sid]["fd"], data["data"].encode())
        except OSError:
            pass

@sio.on("terminal_resize")
def on_term_resize(data):
    sid = request.sid
    if sid in _terms:
        try:
            fd = _terms[sid]["fd"]
            ws = struct.pack("HHHH", data.get("rows",24), data.get("cols",80), 0, 0)
            fcntl.ioctl(fd, termios.TIOCSWINSZ, ws)
        except OSError:
            pass

@sio.on("disconnect")
def on_disconnect():
    sid = request.sid
    if sid in _terms:
        t = _terms.pop(sid)
        try: os.close(t["fd"])
        except OSError: pass
        try: os.kill(t["pid"], _signal.SIGTERM)
        except (OSError, ProcessLookupError): pass


# ── 启动 ─────────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser(prog="bianbu-security-webui")
    ap.add_argument("--host", default=os.environ.get("BIANBU_WEBUI_HOST", "0.0.0.0"))
    ap.add_argument("--port", type=int, default=8787)
    args = ap.parse_args()
    bus = "会话总线" if os.environ.get("BIANBU_SEC_SESSION")=="1" else "系统总线"
    print(f"[WebUI] http://{args.host}:{args.port}  ({bus})", flush=True)
    _connection_monitor.start()
    tls = _validate_bind_security(args.host)
    run_kwargs = {"host": args.host, "port": args.port,
                  "allow_unsafe_werkzeug": True, "log_output": False}
    if tls is not None:
        run_kwargs["ssl_context"] = tls
    try:
        sio.run(app, **run_kwargs)
    finally:
        _connection_monitor.stop()

if __name__ == "__main__":
    main()
