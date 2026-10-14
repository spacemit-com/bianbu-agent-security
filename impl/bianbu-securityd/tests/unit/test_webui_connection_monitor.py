from __future__ import annotations

import threading
import time

from webui.connection_monitor import SecurityConnectionMonitor


def _wait_for(predicate, timeout: float = 2.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.01)
    return predicate()


def test_monitor_retries_every_second_until_securityd_connects():
    calls = 0
    states: list[str] = []

    def check():
        nonlocal calls
        calls += 1
        if calls < 3:
            raise ConnectionError("securityd unavailable")
        return True

    monitor = SecurityConnectionMonitor(check, on_state=states.append, interval=0.02)
    monitor.start()
    try:
        assert _wait_for(lambda: monitor.state == "connected")
        assert calls >= 3
        assert states[0] == "reconnecting"
        assert states[-1] == "connected"
    finally:
        monitor.stop()


def test_monitor_reenters_reconnect_after_disconnect():
    available = True
    states: list[str] = []

    def check():
        if not available:
            raise ConnectionError("securityd disconnected")
        return True

    monitor = SecurityConnectionMonitor(check, on_state=states.append, interval=0.02)
    monitor.start()
    try:
        assert _wait_for(lambda: monitor.state == "connected")
        available = False
        assert _wait_for(lambda: monitor.state == "reconnecting")
        available = True
        assert _wait_for(lambda: monitor.state == "connected")
        assert states.count("connected") >= 2
    finally:
        monitor.stop()


def test_monitor_stop_ends_background_heartbeat():
    stopped = threading.Event()

    def check():
        return True

    monitor = SecurityConnectionMonitor(check, interval=0.02)
    monitor.start()
    assert _wait_for(lambda: monitor.state == "connected")
    monitor.stop()
    assert monitor.stopped
    stopped.set()
