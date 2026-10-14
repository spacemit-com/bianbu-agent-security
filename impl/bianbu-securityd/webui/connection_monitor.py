"""Background securityd connectivity heartbeat for the WebUI."""
from __future__ import annotations

import threading
from collections.abc import Callable


class SecurityConnectionMonitor:
    """Probe securityd continuously and recover after transient D-Bus loss."""

    def __init__(
        self,
        probe: Callable[[], object],
        *,
        on_state: Callable[[str], None] | None = None,
        interval: float = 1.0,
    ) -> None:
        if interval <= 0:
            raise ValueError("heartbeat interval must be positive")
        self._probe = probe
        self._on_state = on_state
        self._interval = float(interval)
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self._state = "reconnecting"

    @property
    def state(self) -> str:
        with self._lock:
            return self._state

    @property
    def stopped(self) -> bool:
        return self._stop.is_set()

    def _set_state(self, value: str) -> None:
        callback = None
        with self._lock:
            if self._state == value:
                return
            self._state = value
            callback = self._on_state
        if callback is not None:
            try:
                callback(value)
            except Exception:
                pass

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                self._probe()
            except Exception:
                self._set_state("reconnecting")
            else:
                self._set_state("connected")
            self._stop.wait(self._interval)

    def start(self) -> None:
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                return
            self._stop.clear()
            self._thread = threading.Thread(
                target=self._run,
                name="bianbu-securityd-heartbeat",
                daemon=True,
            )
            if self._on_state is not None:
                try:
                    self._on_state("reconnecting")
                except Exception:
                    pass
            self._thread.start()

    def stop(self, timeout: float = 2.0) -> None:
        self._stop.set()
        thread = self._thread
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=max(0.0, timeout))


__all__ = ["SecurityConnectionMonitor"]
