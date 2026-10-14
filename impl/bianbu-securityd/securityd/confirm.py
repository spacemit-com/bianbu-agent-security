"""Confirm Gatekeeper（FR-SEC-03 / CFM-01~04）。

确认门禁：发 ConfirmRequest 信号 → 等待响应/超时 → L4 二次确认。
UI 后端可插拔：默认 auto-policy（用于无人值守测试），生产接通知中心/GUI。
对齐设计 §3.2 / §6.4。
"""
from __future__ import annotations

import threading
import uuid
from dataclasses import dataclass
from typing import Callable, Optional

from . import config
from .models import CallerContext


@dataclass
class ConfirmContext:
    agent_id: str
    capability: str
    detail: str
    request_id: str
    caller: CallerContext | None = None


# UI 回调签名：cb(ctx, is_second) -> bool（是否批准）
UICallback = Callable[[ConfirmContext, bool], bool]


class ConfirmGatekeeper:
    def __init__(self, ui_callback: Optional[UICallback] = None,
                 signal_emit: Optional[Callable] = None,
                 timeout: int = config.CONFIRM_TIMEOUT_SEC):
        self._ui = ui_callback
        self._emit = signal_emit  # emit(request_id, agent_id, capability, detail)
        self._timeout = timeout
        self._pending: dict[str, threading.Event] = {}
        self._results: dict[str, bool] = {}
        self._contexts: dict[str, ConfirmContext] = {}
        self._lock = threading.Lock()
        self._closed = False

    def set_ui_callback(self, cb: UICallback) -> None:
        self._ui = cb

    def request(self, agent_id: str, capability: str, detail: str,
                caller: CallerContext | None = None) -> bool:
        """触发一次确认，返回最终是否批准。"""
        with self._lock:
            if self._closed:
                return False
        ctx = ConfirmContext(agent_id, capability, detail, uuid.uuid4().hex, caller)
        return bool(self._ask(ctx, is_second=False))

    def _ask(self, ctx: ConfirmContext, is_second: bool) -> bool:
        # UI 回调（同步阻塞等待用户，用于单进程内嵌 UI）
        if self._ui is not None:
            if self._emit:
                try:
                    self._emit(ctx.request_id, ctx.agent_id, ctx.capability,
                               ("[二次确认] " if is_second else "") + ctx.detail)
                except Exception:  # noqa: BLE001
                    pass
            try:
                return bool(self._ui(ctx, is_second))
            except Exception:  # noqa: BLE001
                return False
        # 无 UI：先注册等待，再发信号（避免"信号先到、respond() 被丢弃"的竞态），
        # 然后阻塞等 respond() 或超时。GUI 经 D-Bus RespondConfirm 回传结果。
        ev = threading.Event()
        with self._lock:
            if self._closed:
                return False
            self._pending[ctx.request_id] = ev
            self._contexts[ctx.request_id] = ctx
        if self._emit:
            try:
                self._emit(ctx.request_id, ctx.agent_id, ctx.capability,
                           ("[二次确认] " if is_second else "") + ctx.detail)
            except Exception:  # noqa: BLE001 — 信号失败不应阻断门禁
                pass
        got = ev.wait(timeout=self._timeout)
        with self._lock:
            approved = self._results.pop(ctx.request_id, False)
            self._pending.pop(ctx.request_id, None)
            self._contexts.pop(ctx.request_id, None)
        return bool(got and approved)

    def respond(self, request_id: str, approved: bool) -> bool:
        """外部（GUI 经 D-Bus）回传确认结果。"""
        with self._lock:
            if self._closed:
                return False
            ev = self._pending.get(request_id)
            if not ev or request_id in self._results:
                return False
            self._results[request_id] = approved
            ev.set()
            return True

    def get_pending(self, request_id: str) -> ConfirmContext | None:
        """返回待决请求上下文；仅服务授权层使用，不暴露给普通客户端。"""
        with self._lock:
            # request_id 与 event 分离存储时无法取上下文，保留独立表以支持响应者绑定。
            return getattr(self, "_contexts", {}).get(request_id)

    def list_pending(self) -> list[ConfirmContext]:
        """关闭审计使用的只读快照，不暴露可变内部字典。"""
        with self._lock:
            return list(self._contexts.values())

    def close(self) -> int:
        """服务退出时拒绝并唤醒全部待决请求，禁止跨重启复用旧批准。"""
        with self._lock:
            if self._closed:
                return 0
            self._closed = True
            pending = list(self._pending.items())
            for request_id, _event in pending:
                self._results[request_id] = False
            for _request_id, event in pending:
                event.set()
            return len(pending)
