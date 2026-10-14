"""P1-05：Confirm 待决请求在关闭/重启边界必须 fail-closed。"""
from __future__ import annotations

import threading


def test_close_rejects_and_wakes_pending_confirm():
    from securityd.confirm import ConfirmGatekeeper

    emitted = threading.Event()
    request_ids = []

    def emit(request_id, _agent_id, _capability, _detail):
        request_ids.append(request_id)
        emitted.set()

    gate = ConfirmGatekeeper(signal_emit=emit, timeout=30)
    result = []
    worker = threading.Thread(target=lambda: result.append(
        gate.request("com.test", "terminal", "rm")))
    worker.start()
    assert emitted.wait(timeout=2)
    assert gate.get_pending(request_ids[0]) is not None
    assert gate.close() == 1
    worker.join(timeout=2)
    assert worker.is_alive() is False
    assert result == [False]
    assert gate.get_pending(request_ids[0]) is None
    assert gate.respond(request_ids[0], True) is False


def test_restart_never_accepts_old_request_id_or_reuses_approval():
    from securityd.confirm import ConfirmGatekeeper

    first_ids, second_ids = [], []
    first_event, second_event = threading.Event(), threading.Event()
    first = ConfirmGatekeeper(
        signal_emit=lambda rid, *_args: (first_ids.append(rid), first_event.set()),
        timeout=30)
    first_result = []
    thread1 = threading.Thread(target=lambda: first_result.append(
        first.request("com.test", "write_file", "old")))
    thread1.start()
    assert first_event.wait(timeout=2)
    old_id = first_ids[0]
    first.close()
    thread1.join(timeout=2)
    assert first_result == [False]

    # 模拟 securityd 重启后的全新 Gatekeeper：旧响应必须拒绝。
    second = ConfirmGatekeeper(
        signal_emit=lambda rid, *_args: (second_ids.append(rid), second_event.set()),
        timeout=30)
    assert second.respond(old_id, True) is False
    second_result = []
    thread2 = threading.Thread(target=lambda: second_result.append(
        second.request("com.test", "write_file", "new")))
    thread2.start()
    assert second_event.wait(timeout=2)
    assert second_ids[0] != old_id
    assert second.respond(second_ids[0], False) is True
    assert second.respond(second_ids[0], True) is False
    thread2.join(timeout=2)
    assert second_result == [False]
    second.close()
