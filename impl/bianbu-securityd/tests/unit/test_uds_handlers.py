"""ARCH-01 正式 securityd UDS handler 与身份/审计闭环。"""
from __future__ import annotations

import os
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
for _path in (ROOT, ROOT / "client"):
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))


def _bound_engine():
    from securityd.caller_identity import caller_from_process
    from securityd.engine import SecurityEngine

    engine = SecurityEngine()
    caller = caller_from_process(
        os.geteuid(), os.getpid(), sender=f"test:{os.getpid()}")
    engine.bind_agent("com.test.uds", caller)
    return engine


def test_production_uds_dlp_scan_requires_bound_identity(sec_root, tmp_path):
    import bianbu_security_uds as uds
    from securityd.uds_handlers import SecurityUdsHandlers
    from securityd.uds_server import UdsServer

    engine = _bound_engine()
    handlers = SecurityUdsHandlers(engine)
    server = UdsServer(socket_path=tmp_path / "securityd.sock")
    handlers.register(server)
    server.start()
    try:
        client = uds.UdsClient(socket_path=server.socket_path, timeout=5.0)
        response = client.call({
            "op": "dlp.scan", "agent_id": "com.test.uds",
            "session_id": "session-1", "run_id": "run-1",
            "text": "联系人手机号 13812345678"})
        assert response["ok"] is True
        assert response["has_pii"] is True
        assert "13812345678" not in response["masked_text"]
        assert response["findings"][0]["pii_type"] == "phone"
        assert "value" not in response["findings"][0]
        policy = client.call({
            "op": "dlp.policy", "agent_id": "com.test.uds"})
        assert policy["ok"] is True
        assert policy["effective_policy"]["phone"] == "mask"
        denied = client.call({
            "op": "dlp.scan", "agent_id": "com.other.agent",
            "text": "13812345678"})
        assert denied["ok"] is False
        assert "无权代表" in denied["error"]
        client.close()
    finally:
        server.stop()
        handlers.close()
        engine.close()


def test_audit_batch_is_persistently_idempotent(sec_root, tmp_path):
    import bianbu_security_uds as uds
    from securityd.uds_handlers import SecurityUdsHandlers
    from securityd.uds_server import UdsServer

    request = {
        "op": "audit.batch", "agent_id": "com.test.uds",
        "session_id": "session-1", "run_id": "run-1",
        "_request_id": "persistent-request",
        "entries": [{"op_type": "tool_result", "target": "weather",
                     "result": "allow", "payload": "full tool payload"}],
    }
    engine = _bound_engine()
    handlers = SecurityUdsHandlers(engine)
    socket_path = tmp_path / "audit.sock"
    server = UdsServer(socket_path=socket_path)
    handlers.register(server)
    server.start()
    client = uds.UdsClient(socket_path=socket_path, timeout=5.0)
    first = client.call(request)
    client.close()
    server.stop()
    handlers.close()
    engine.close()

    # 模拟 securityd 重启；同一 request id 必须返回同一 seq，不追加第二条载荷。
    engine2 = _bound_engine()
    handlers2 = SecurityUdsHandlers(engine2)
    server2 = UdsServer(socket_path=socket_path)
    handlers2.register(server2)
    server2.start()
    try:
        client2 = uds.UdsClient(socket_path=socket_path, timeout=5.0)
        second = client2.call(request)
        assert first["audit_seq"] == second["audit_seq"]
        assert second["accepted"] == 1
        conflict = client2.call({**request,
                                 "entries": [{"op_type": "tool_result",
                                              "payload": "changed"}]})
        assert conflict["ok"] is False
        assert "不同" in conflict["error"]
        client2.close()
    finally:
        server2.stop()
        handlers2.close()
        engine2.close()
