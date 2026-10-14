"""WebUI 认证/角色边界：viewer 只读，admin 才能修改和开终端。"""
from __future__ import annotations

import pytest


def test_viewer_cannot_mutate_but_can_authenticate(monkeypatch):
    import webui.app as mod

    monkeypatch.setattr(mod, "_AUTH_DISABLED", False)
    monkeypatch.setattr(mod, "_WEBUI_TOKEN", "a" * 40)
    monkeypatch.setenv("BIANBU_WEBUI_AUTH", "1")
    monkeypatch.setenv("BIANBU_WEBUI_AUTH", "1")
    monkeypatch.setattr(mod, "_WEBUI_VIEWER_TOKEN", "viewer-secret")
    client = mod.app.test_client()

    # 只读请求通过 WebUI 认证层（后端 D-Bus 不可用时可返回 500，但不能被
    # 认证层误判为未认证）。
    read = client.get("/api/agents", headers={"X-Bianbu-WebUI-Token": "viewer-secret"})
    assert read.status_code != 401
    write = client.post("/api/agents/a/capabilities/policy",
                        json={"tool": "read_file", "policy": "allow"},
                        headers={"X-Bianbu-WebUI-Token": "viewer-secret"})
    assert write.status_code == 403


def test_admin_mutation_requires_csrf(monkeypatch):
    import webui.app as mod

    monkeypatch.setattr(mod, "_AUTH_DISABLED", False)
    monkeypatch.setattr(mod, "_WEBUI_TOKEN", "a" * 40)
    monkeypatch.setattr(mod, "_WEBUI_VIEWER_TOKEN", "viewer-secret")
    client = mod.app.test_client()
    response = client.post("/api/agents/a/capabilities/policy",
                           json={"tool": "read_file", "policy": "allow"},
                           headers={"X-Bianbu-WebUI-Token": "a" * 40})
    assert response.status_code == 403


def test_langgraph_resume_requires_bound_identity_and_boolean(monkeypatch):
    import webui.app as mod

    monkeypatch.setattr(mod, "_AUTH_DISABLED", False)
    monkeypatch.setattr(mod, "_WEBUI_TOKEN", "a" * 40)
    monkeypatch.setattr(mod, "_WEBUI_VIEWER_TOKEN", "")
    client = mod.app.test_client()
    # 先取得同一会话 CSRF cookie。
    auth = client.post("/api/auth", json={"token": "a" * 40})
    csrf_cookie = client.get_cookie("bnsec_csrf")
    csrf = csrf_cookie.value if csrf_cookie else ""
    headers = {"X-Bianbu-WebUI-Token": "a" * 40, "X-CSRF-Token": csrf}
    missing = client.post("/api/langgraph/resume", json={"graph_id": "g", "approved": True},
                          headers=headers)
    assert missing.status_code == 400
    wrong_type = client.post("/api/langgraph/resume", json={
        "graph_id": "g", "run_id": "r", "agent_id": "a", "approved": "true"},
        headers=headers)
    assert wrong_type.status_code == 400
    register = client.post("/api/langgraph/graphs/g/register", json={}, headers=headers)
    assert register.status_code == 403


def test_remote_webui_requires_tls_and_admin_token(monkeypatch, tmp_path):
    import webui.app as mod

    monkeypatch.setattr(mod, "_AUTH_DISABLED", False)
    monkeypatch.setattr(mod, "_WEBUI_TOKEN", "a" * 40)
    monkeypatch.delenv("BIANBU_WEBUI_TLS_CERT", raising=False)
    monkeypatch.delenv("BIANBU_WEBUI_TLS_KEY", raising=False)
    monkeypatch.delenv("BIANBU_WEBUI_ALLOW_INSECURE_REMOTE", raising=False)
    assert mod._validate_bind_security("0.0.0.0") is None

    cert = tmp_path / "server.crt"
    key = tmp_path / "server.key"
    cert.write_text("placeholder")
    key.write_text("placeholder")
    monkeypatch.setenv("BIANBU_WEBUI_TLS_CERT", str(cert))
    monkeypatch.setenv("BIANBU_WEBUI_TLS_KEY", str(key))
    assert mod._validate_bind_security("0.0.0.0") == (str(cert), str(key))
    monkeypatch.delenv("BIANBU_WEBUI_TLS_CERT")
    monkeypatch.delenv("BIANBU_WEBUI_TLS_KEY")
    monkeypatch.setenv("BIANBU_WEBUI_TRUST_PROXY", "1")
    assert mod._validate_bind_security("0.0.0.0") is None


def test_demo_mode_disables_token_requirement_and_api_auth(monkeypatch):
    """Demo flag bypasses both startup token validation and REST Bearer auth."""
    import webui.app as mod

    monkeypatch.setattr(mod, "_WEBUI_DEMO", True)
    monkeypatch.setattr(mod, "_AUTH_DISABLED", True)
    monkeypatch.setattr(mod, "_WEBUI_TOKEN", "")
    monkeypatch.setattr(mod, "_WEBUI_VIEWER_TOKEN", "")
    monkeypatch.delenv("BIANBU_WEBUI_TOKEN", raising=False)
    # Loopback keeps this test focused on authentication rather than TLS.
    assert mod._validate_bind_security("127.0.0.1") is None
    client = mod.app.test_client()
    response = client.post("/api/auth", json={})
    assert response.status_code == 200
    assert response.json == {"ok": True, "auth_disabled": True}
    response = client.get("/api/agents")
    assert response.status_code != 401


def test_authentication_is_opt_in_without_token(monkeypatch):
    """Without explicit auth enablement, WebUI starts without a token."""
    import webui.app as mod

    monkeypatch.setattr(mod, "_WEBUI_DEMO", False)
    monkeypatch.setattr(mod, "_AUTH_DISABLED", True)
    monkeypatch.setattr(mod, "_WEBUI_TOKEN", "")
    assert mod._validate_bind_security("127.0.0.1") is None


def test_local_auto_auth_sets_session_without_exposing_token(monkeypatch):
    import webui.app as mod

    monkeypatch.setattr(mod, "_AUTH_DISABLED", False)
    monkeypatch.setattr(mod, "_WEBUI_TOKEN", "a" * 40)
    monkeypatch.setenv("BIANBU_WEBUI_LOCAL_AUTO_AUTH", "1")
    client = mod.app.test_client()
    response = client.post("/api/auth/local", environ_base={"REMOTE_ADDR": "127.0.0.1"})
    assert response.status_code == 200
    assert response.json == {"ok": True, "role": "admin"}
    assert "a" * 40 not in response.get_data(as_text=True)
    assert client.get_cookie("bnsec_token") is not None


def test_local_auto_auth_rejects_remote_and_disabled(monkeypatch):
    import webui.app as mod

    monkeypatch.setattr(mod, "_AUTH_DISABLED", False)
    monkeypatch.setattr(mod, "_WEBUI_TOKEN", "a" * 40)
    monkeypatch.setenv("BIANBU_WEBUI_LOCAL_AUTO_AUTH", "1")
    client = mod.app.test_client()
    assert client.post("/api/auth/local", environ_base={"REMOTE_ADDR": "10.0.0.5"}).status_code == 403
    monkeypatch.setenv("BIANBU_WEBUI_LOCAL_AUTO_AUTH", "0")
    assert client.post("/api/auth/local", environ_base={"REMOTE_ADDR": "127.0.0.1"}).status_code == 404


def test_agent_security_mode_routes_use_admin_client_wrappers(monkeypatch):
    import webui.app as mod

    monkeypatch.setattr(mod, "_AUTH_DISABLED", True)
    calls = []
    monkeypatch.setattr(mod.sc, "get_agent_security_mode", lambda aid: calls.append(
        ("get", aid)) or {"agent_id": aid, "mode": "normal"}, raising=False)
    monkeypatch.setattr(mod.sc, "set_agent_security_mode", lambda aid, mode: calls.append(
        ("set", aid, mode)) or {"agent_id": aid, "old_mode": "normal", "mode": mode},
        raising=False)
    client = mod.app.test_client()

    read = client.get("/api/agents/agent.demo/security-mode")
    write = client.post("/api/agents/agent.demo/security-mode", json={"mode": "yolo"})

    assert read.status_code == 200
    assert read.json["mode"] == "normal"
    assert write.status_code == 200
    assert write.json["mode"] == "yolo"
    assert calls == [("get", "agent.demo"), ("set", "agent.demo", "yolo")]


def test_agent_security_mode_route_rejects_invalid_mode_before_dbus(monkeypatch):
    import webui.app as mod

    monkeypatch.setattr(mod, "_AUTH_DISABLED", True)
    monkeypatch.setattr(mod.sc, "set_agent_security_mode",
                        lambda *args: pytest.fail("invalid mode reached D-Bus"), raising=False)
    response = mod.app.test_client().post(
        "/api/agents/agent.demo/security-mode", json={"mode": "full"})
    assert response.status_code == 400


def test_yolo_dlp_preview_does_not_initialize_or_invoke_scanner(monkeypatch):
    import webui.app as mod
    monkeypatch.setattr(mod, '_AUTH_DISABLED', True)
    monkeypatch.setattr(mod.sc, 'get_agent_security_mode', lambda aid: {'mode': 'yolo'})
    monkeypatch.setattr(mod, '_dlp', lambda: pytest.fail('YOLO preview must not scan'))
    response = mod.app.test_client().post('/api/dlp/scan', json={
        'agent_id': 'agent.yolo', 'text': '手机号 13812345678'})
    assert response.status_code == 200
    assert response.json['scanning_enabled'] is False
    assert response.json['masked_text'] == '手机号 13812345678'
