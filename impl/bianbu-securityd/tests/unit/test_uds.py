"""ARCH-01 — UDS 数据面协议与服务端。"""
from __future__ import annotations

import io
import os
import socket
import struct
import sys
import threading
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "client"))

from securityd.uds_protocol import (  # noqa: E402
    HEADER_SIZE,
    PayloadTooLarge,
    ProtocolError,
    encode_frame,
    recv_frame,
    send_frame,
)
from securityd.uds_server import UdsServer, peer_uid  # noqa: E402


# ————————————————————————————————————————————————————————————
# 协议层（用 socketpair，不落地文件）
# ————————————————————————————————————————————————————————————
@pytest.fixture
def pair():
    a, b = socket.socketpair()
    yield a, b
    a.close()
    b.close()


def test_encode_frame_layout():
    """帧 = 4 字节 big-endian 长度 + JSON。"""
    frame = encode_frame({"op": "ping"})
    (length,) = struct.unpack(">I", frame[:HEADER_SIZE])
    assert length == len(frame) - HEADER_SIZE
    assert b'"op"' in frame[HEADER_SIZE:]


def test_roundtrip(pair):
    a, b = pair
    send_frame(a, {"op": "dlp.scan", "text": "hello"})
    got = recv_frame(b, 1 << 20)
    assert got == {"op": "dlp.scan", "text": "hello"}


def test_roundtrip_unicode(pair):
    """中文不被转义（ensure_ascii=False）且能正确还原。"""
    a, b = pair
    send_frame(a, {"text": "手机号 13812345678"})
    assert recv_frame(b, 1 << 20)["text"] == "手机号 13812345678"


def test_large_payload_roundtrip(pair):
    """1MB 载荷完整往返（数据面的核心场景）。"""
    a, b = pair
    big = "x" * (1024 * 1024)
    t = threading.Thread(target=send_frame, args=(a, {"text": big}))
    t.start()
    got = recv_frame(b, 8 << 20)
    t.join()
    assert len(got["text"]) == 1024 * 1024


def test_clean_close_returns_none(pair):
    """对端干净关闭 → None（调用方据此结束循环）。"""
    a, b = pair
    a.close()
    assert recv_frame(b, 1 << 20) is None


def test_truncated_header_raises(pair):
    """帧头不完整 → ProtocolError（而非静默 hang）。"""
    a, b = pair
    a.sendall(b"\x00\x00")  # 只 2 字节
    a.close()
    with pytest.raises(ProtocolError, match="帧头不完整"):
        recv_frame(b, 1 << 20)


def test_truncated_body_raises(pair):
    """声明 100 字节实发 5 字节 → ProtocolError。"""
    a, b = pair
    a.sendall(struct.pack(">I", 100) + b"short")
    a.close()
    with pytest.raises(ProtocolError, match="连接在读取中断开"):
        recv_frame(b, 1 << 20)


def test_payload_too_large_rejected_before_alloc(pair):
    """超限长度在分配内存前就被拒（防 OOM）——只发帧头即可触发。"""
    a, b = pair
    a.sendall(struct.pack(">I", 999_999_999))
    with pytest.raises(PayloadTooLarge):
        recv_frame(b, 4096)


def test_zero_length_frame(pair):
    a, b = pair
    a.sendall(struct.pack(">I", 0))
    assert recv_frame(b, 1 << 20) == {}


def test_invalid_json_raises(pair):
    a, b = pair
    body = b"{not json"
    a.sendall(struct.pack(">I", len(body)) + body)
    with pytest.raises(ProtocolError, match="合法 UTF-8 JSON"):
        recv_frame(b, 1 << 20)


# ————————————————————————————————————————————————————————————
# 服务端
# ————————————————————————————————————————————————————————————
@pytest.fixture
def server(tmp_path):
    srv = UdsServer(socket_path=tmp_path / "test.sock")
    srv.register("ping", lambda req, uid: {"pong": True})
    srv.register("echo", lambda req, uid: {"echo": req.get("text", "")})
    srv.register("whoami", lambda req, uid: {"uid": uid})
    srv.register("boom", lambda req, uid: (_ for _ in ()).throw(
        RuntimeError("handler 故意炸")))
    srv.register("badret", lambda req, uid: "not a dict")
    srv.start()
    yield srv
    srv.stop()


@pytest.fixture
def client(server):
    import bianbu_security_uds as uds

    c = uds.UdsClient(socket_path=server.socket_path, timeout=5.0)
    yield c
    c.close()


def test_socket_created_with_mode(server):
    p = Path(server.socket_path)
    assert p.exists()
    assert oct(p.stat().st_mode)[-3:] == "660"  # 同组可访问


def test_allowed_gids_accepts_runtime_group(monkeypatch, tmp_path):
    from securityd import uds_server as uds_server_mod

    server = UdsServer(socket_path=tmp_path / "runtime.sock",
                       allowed_gids={1001, 1000})
    assert server.allowed_gids == {1000, 1001}
    monkeypatch.setattr(server, "_own_uid", 999)
    monkeypatch.setattr(uds_server_mod, "peer_credentials",
                        lambda _sock: uds_server_mod.PeerCredentials(1, 1000, 1000))
    assert server._authorized(uds_server_mod.PeerCredentials(1, 1000, 1000))


def test_ping(client):
    r = client.call({"op": "ping"})
    assert r["ok"] is True and r["pong"] is True


def test_client_resolves_explicit_environment_at_construction(monkeypatch, tmp_path):
    """A late production UDS override must beat the import-time config path."""
    import bianbu_security_uds as uds

    selected = tmp_path / "production.sock"
    monkeypatch.setenv("BIANBU_SEC_UDS", str(selected))
    client = uds.UdsClient()
    try:
        assert client.socket_path == str(selected)
    finally:
        client.close()


def test_client_prefers_formal_socket_when_environment_is_unset(monkeypatch):
    """直接运行 testkit/runner.py 也必须连接正式 systemd UDS。"""
    import bianbu_security_uds as uds

    monkeypatch.delenv("BIANBU_SEC_UDS", raising=False)
    original_is_socket = uds.Path.is_socket

    def fake_is_socket(path):
        if str(path) == "/run/bianbu/securityd.sock":
            return True
        return original_is_socket(path)

    monkeypatch.setattr(uds.Path, "is_socket", fake_is_socket)
    client = uds.UdsClient()
    try:
        assert client.socket_path == "/run/bianbu/securityd.sock"
    finally:
        client.close()


def test_echo(client):
    assert client.call({"op": "echo", "text": "hi"})["echo"] == "hi"


def test_connection_reuse(client):
    """同一连接连发多请求（长连接，省握手）。"""
    for i in range(5):
        assert client.call({"op": "echo", "text": str(i)})["echo"] == str(i)


def test_large_payload_over_uds(client):
    """512KB 经真实 UDS 往返 —— 这是走 UDS 而非 D-Bus 的理由。"""
    big = "y" * (512 * 1024)
    assert len(client.call({"op": "echo", "text": big})["echo"]) == len(big)


def test_peer_uid_visible(client):
    """服务端能拿到对端 uid（SO_PEERCRED）。"""
    r = client.call({"op": "whoami"})
    expected = os.geteuid() if hasattr(os, "geteuid") else None
    assert r["uid"] == expected


def test_three_argument_handler_receives_peer_credentials(tmp_path):
    import bianbu_security_uds as uds

    srv = UdsServer(socket_path=tmp_path / "peer.sock")
    srv.register("peer", lambda req, uid, peer: {
        "uid": uid, "pid": peer.pid if peer else 0})
    srv.start()
    try:
        client = uds.UdsClient(socket_path=srv.socket_path, timeout=5.0)
        response = client.call({"op": "peer"})
        assert response["uid"] == os.geteuid()
        assert response["pid"] == os.getpid()
        client.close()
    finally:
        srv.stop()


def test_unknown_op(client):
    r = client.call({"op": "nonexistent"})
    assert r["ok"] is False and "未知 op" in r["error"]


def test_handler_exception_isolated(client):
    """handler 抛异常 → 返回错误，服务端仍可继续服务。"""
    r = client.call({"op": "boom"})
    assert r["ok"] is False and "handler 故意炸" in r["error"]
    assert client.call({"op": "ping"})["ok"] is True  # 服务未挂


def test_handler_bad_return(client):
    r = client.call({"op": "badret"})
    assert r["ok"] is False and "非 dict" in r["error"]


def test_oversized_request_rejected(server):
    """超 max_payload 的请求被拒（收到明确错误帧），且服务端不崩。

    服务端在分配内存前拒绝，并回一帧 {"ok":false,"error":...} 再关连接 ——
    比直接断连更可诊断。
    """
    srv = UdsServer(socket_path=Path(server.socket_path).parent / "small.sock",
                    max_payload=1024)
    srv.register("echo", lambda req, uid: {"echo": req.get("text", "")})
    srv.start()
    try:
        import bianbu_security_uds as uds

        c = uds.UdsClient(socket_path=srv.socket_path, timeout=5.0)
        r = c.call({"op": "echo", "text": "z" * 4096})
        assert r["ok"] is False
        assert "超过上限" in r["error"]
        c.close()
        # 服务端仍存活，可继续服务正常请求
        c2 = uds.UdsClient(socket_path=srv.socket_path, timeout=5.0)
        assert c2.call({"op": "echo", "text": "ok"})["echo"] == "ok"
        c2.close()
    finally:
        srv.stop()


def test_list_ops(server):
    assert server.list_ops() == ["badret", "boom", "echo", "ping", "whoami"]


def test_stop_removes_socket(tmp_path):
    srv = UdsServer(socket_path=tmp_path / "gone.sock")
    srv.register("ping", lambda req, uid: {})
    srv.start()
    assert Path(srv.socket_path).exists()
    srv.stop()
    assert not Path(srv.socket_path).exists()


def test_restart_over_stale_socket(tmp_path):
    """残留 socket 文件不阻碍重启（bind 前先 unlink）。"""
    p = tmp_path / "stale.sock"
    p.write_text("")  # 伪造残留
    srv = UdsServer(socket_path=p)
    srv.register("ping", lambda req, uid: {"pong": 1})
    srv.start()
    try:
        import bianbu_security_uds as uds

        c = uds.UdsClient(socket_path=p, timeout=5.0)
        assert c.call({"op": "ping"})["pong"] == 1
        c.close()
    finally:
        srv.stop()


def test_second_server_cannot_replace_active_socket(tmp_path):
    """第二实例不得 unlink 活跃 socket 形成 split-brain。"""
    import bianbu_security_uds as uds

    p = tmp_path / "active.sock"
    first = UdsServer(socket_path=p)
    first.register("ping", lambda req, uid: {"owner": "first"})
    first.start()
    second = UdsServer(socket_path=p)
    try:
        with pytest.raises(RuntimeError, match="活跃服务占用"):
            second.start()
        client = uds.UdsClient(socket_path=p, timeout=5.0)
        assert client.call({"op": "ping"})["owner"] == "first"
        client.close()
    finally:
        second.stop()
        first.stop()


def test_context_manager(tmp_path):
    p = tmp_path / "ctx.sock"
    with UdsServer(socket_path=p) as srv:
        srv.register("ping", lambda req, uid: {})
        assert Path(p).exists()
    assert not Path(p).exists()


def test_client_unavailable_when_no_socket(tmp_path):
    import bianbu_security_uds as uds

    c = uds.UdsClient(socket_path=tmp_path / "nope.sock")
    with pytest.raises(uds.UdsUnavailable, match="socket 不存在"):
        c.connect()
    assert c.ping() is False


def test_client_reconnects_after_server_close(server):
    """服务端断连后客户端自动重连（长连接场景的健壮性）。"""
    import bianbu_security_uds as uds

    c = uds.UdsClient(socket_path=server.socket_path, timeout=5.0)
    assert c.call({"op": "ping"})["ok"] is True
    # 强制关掉客户端侧连接，模拟服务端超时关连接
    c._sock.close()
    assert c.call({"op": "ping"})["ok"] is True  # 重连成功
    c.close()


def test_replayed_request_id_returns_cached_response(tmp_path):
    """同一 uid + request id 只执行一次 handler。"""
    import bianbu_security_uds as uds

    calls = []
    srv = UdsServer(socket_path=tmp_path / "dedupe.sock")
    srv.register("mutate", lambda req, uid: {
        "count": len(calls) + 1, "value": calls.append(req.get("value"))})
    srv.start()
    try:
        client = uds.UdsClient(socket_path=srv.socket_path, timeout=5.0)
        req = {"op": "mutate", "value": "x", "_request_id": "fixed-id"}
        first = client.call(req)
        second = client.call(req)
        assert first == second
        assert calls == ["x"]
        client.close()
    finally:
        srv.stop()


def test_request_id_reuse_with_different_payload_is_rejected(tmp_path):
    import bianbu_security_uds as uds

    calls = []
    srv = UdsServer(socket_path=tmp_path / "conflict.sock")
    srv.register("mutate", lambda req, uid: {
        "count": len(calls) + 1, "value": calls.append(req.get("value"))})
    srv.start()
    try:
        client = uds.UdsClient(socket_path=srv.socket_path, timeout=5.0)
        assert client.call({"op": "mutate", "value": "x",
                            "_request_id": "fixed-id"})["ok"] is True
        conflict = client.call({"op": "mutate", "value": "y",
                                "_request_id": "fixed-id"})
        assert conflict["ok"] is False
        assert "不同请求载荷" in conflict["error"]
        assert calls == ["x"]
        client.close()
    finally:
        srv.stop()


def test_large_response_uses_tombstone_without_reexecution(tmp_path):
    import bianbu_security_uds as uds

    calls = []
    srv = UdsServer(socket_path=tmp_path / "large-tombstone.sock",
                    dedupe_max_response_bytes=128)
    srv.register("large-mutate", lambda req, uid: {
        "payload": "x" * 1024, "count": len(calls) + 1,
        "value": calls.append(req.get("value"))})
    srv.start()
    try:
        client = uds.UdsClient(socket_path=srv.socket_path, timeout=5.0)
        request = {"op": "large-mutate", "value": "x",
                   "_request_id": "large-id"}
        first = client.call(request)
        assert first["ok"] is True and len(first["payload"]) == 1024
        replay = client.call(request)
        assert replay["ok"] is False
        assert "已执行" in replay["error"] and "无法安全重放" in replay["error"]
        assert calls == ["x"]
        client.close()
    finally:
        srv.stop()


def test_dedupe_cache_enforces_total_byte_budget(tmp_path):
    import bianbu_security_uds as uds

    srv = UdsServer(socket_path=tmp_path / "bounded-cache.sock",
                    dedupe_capacity=100, dedupe_max_bytes=512,
                    dedupe_max_response_bytes=512)
    srv.register("echo", lambda req, uid: {"payload": req["payload"]})
    srv.start()
    try:
        client = uds.UdsClient(socket_path=srv.socket_path, timeout=5.0)
        for i in range(20):
            assert client.call({"op": "echo", "payload": "x" * 100,
                                "_request_id": f"id-{i}"})["ok"] is True
        assert srv._response_cache_bytes <= 512
        assert len(srv._response_cache) < 20
        client.close()
    finally:
        srv.stop()


def test_concurrent_replay_executes_handler_once(tmp_path):
    import bianbu_security_uds as uds

    calls = []
    entered = threading.Event()
    release = threading.Event()

    def mutate(req, uid):
        calls.append(req.get("value"))
        entered.set()
        assert release.wait(timeout=5.0)
        return {"count": len(calls)}

    srv = UdsServer(socket_path=tmp_path / "concurrent.sock")
    srv.register("mutate", mutate)
    srv.start()
    responses = []

    def invoke():
        client = uds.UdsClient(socket_path=srv.socket_path, timeout=5.0)
        try:
            responses.append(client.call({
                "op": "mutate", "value": "x", "_request_id": "same-id"}))
        finally:
            client.close()

    first = threading.Thread(target=invoke)
    second = threading.Thread(target=invoke)
    try:
        first.start()
        assert entered.wait(timeout=5.0)
        second.start()
        release.set()
        first.join(timeout=5.0)
        second.join(timeout=5.0)
        assert not first.is_alive() and not second.is_alive()
        assert calls == ["x"]
        assert len(responses) == 2
        assert responses[0] == responses[1]
    finally:
        release.set()
        srv.stop()


def test_client_retry_preserves_request_id_and_avoids_duplicate(monkeypatch, tmp_path):
    """响应已执行但客户端丢包时，自动重试不得重复执行非幂等 handler。"""
    import bianbu_security_uds as uds

    calls = []
    srv = UdsServer(socket_path=tmp_path / "retry-dedupe.sock")
    srv.register("mutate", lambda req, uid: {
        "count": len(calls) + 1, "value": calls.append(req.get("value"))})
    srv.start()
    original_recv = uds.recv_frame
    received = 0

    def lose_first_response(sock, max_payload):
        nonlocal received
        response = original_recv(sock, max_payload)
        received += 1
        if received == 1:
            raise ProtocolError("模拟响应丢失")
        return response

    monkeypatch.setattr(uds, "recv_frame", lose_first_response)
    try:
        client = uds.UdsClient(socket_path=srv.socket_path, timeout=5.0)
        response = client.call({"op": "mutate", "value": "x"})
        assert response["count"] == 1
        assert calls == ["x"]
        client.close()
    finally:
        srv.stop()


def test_invalid_request_id_is_rejected(client):
    response = client.call({"op": "ping", "_request_id": ""})
    assert response["ok"] is False
    assert "_request_id" in response["error"]


# ————————————————————————————————————————————————————————————
# 通道选择（ARCH-01 的 4KB 分界）
# ————————————————————————————————————————————————————————————
def test_should_use_uds_threshold():
    import bianbu_security_uds as uds

    assert uds.should_use_uds(5000, threshold=4096) is True
    assert uds.should_use_uds(100, threshold=4096) is False
    assert uds.should_use_uds(4096, threshold=4096) is False  # 等于阈值走 D-Bus
    assert uds.should_use_uds(4097, threshold=4096) is True
