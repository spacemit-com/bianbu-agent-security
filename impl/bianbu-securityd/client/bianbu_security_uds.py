"""UDS 数据面客户端（ARCH-01）。

用法：
    with UdsClient() as c:
        r = c.call({"op": "dlp.scan", "text": big_text})

自动重连：连接在空闲超时后会被服务端关闭，call() 遇断开重连一次再重试。
"""
from __future__ import annotations

import logging
import os
import socket
import sys
import uuid
from pathlib import Path
from typing import Optional

# 允许独立于 securityd 包使用（部署时可能只有 client/ 目录）
try:
    from securityd import config as _cfg
    from securityd.uds_protocol import ProtocolError, recv_frame, send_frame

    _DEFAULT_SOCK = str(_cfg.UDS_SOCKET_PATH)
    _DEFAULT_MAX = _cfg.UDS_MAX_PAYLOAD
    _DEFAULT_THRESHOLD = _cfg.UDS_DBUS_THRESHOLD
except Exception:  # noqa: BLE001 — 无 securityd 包时用内置默认
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from securityd.uds_protocol import ProtocolError, recv_frame, send_frame  # type: ignore

    _DEFAULT_SOCK = os.environ.get(
        "BIANBU_SEC_UDS", "/run/bianbu/securityd.sock")
    _DEFAULT_MAX = 64 * 1024 * 1024
    _DEFAULT_THRESHOLD = 4 * 1024

logger = logging.getLogger("bianbu-security.uds")

__all__ = ["UdsClient", "UdsUnavailable", "should_use_uds"]


class UdsUnavailable(Exception):
    """UDS 服务不可达（socket 不存在 / 连接被拒）。"""


def _default_socket_path() -> str:
    """选择数据面 socket，避免测试入口误连用户级开发实例。

    显式 ``BIANBU_SEC_UDS`` 仍是最高优先级。未设置时，正式 systemd
    socket 存在就优先使用它；只有没有正式 socket 才回退到导入时解析的
    开发路径。该选择在每次构造客户端时进行，适配 securityd 启动晚于
    PA/testkit 导入模块的场景。
    """
    override = os.environ.get("BIANBU_SEC_UDS", "").strip()
    if override:
        return override
    production = Path("/run/bianbu/securityd.sock")
    if production.is_socket():
        return str(production)
    return _DEFAULT_SOCK


def should_use_uds(payload_bytes: int, threshold: int | None = None) -> bool:
    """按载荷大小决定走 UDS 还是 D-Bus（ARCH-01 的 4KB 临界点）。"""
    return payload_bytes > (threshold if threshold is not None
                            else _DEFAULT_THRESHOLD)


class UdsClient:
    def __init__(
        self,
        socket_path: str | Path | None = None,
        max_payload: int | None = None,
        timeout: float = 10.0,
    ):
        # securityd.config can be imported before the launcher has finished
        # assembling the production environment.  Resolve an explicit UDS
        # override when each client is created, rather than freezing a
        # user-scoped development socket at module import time.
        self.socket_path = str(socket_path or _default_socket_path())
        self.max_payload = max_payload or _DEFAULT_MAX
        self.timeout = timeout
        self._sock: Optional[socket.socket] = None

    # —— 连接管理 ——
    def connect(self) -> None:
        if self._sock is not None:
            return
        if not Path(self.socket_path).exists():
            raise UdsUnavailable(f"socket 不存在：{self.socket_path}")
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        try:
            s.connect(self.socket_path)
        except OSError as e:
            s.close()
            raise UdsUnavailable(f"连接失败：{self.socket_path}（{e}）") from e
        self._sock = s

    def close(self) -> None:
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, *exc):
        self.close()
        return False

    # —— 调用 ——
    def call(self, req: dict, _retried: bool = False) -> dict:
        """发一帧请求、收一帧响应。连接断开时以同一 request id 重试一次。"""
        if not _retried:
            req = dict(req)
            req.setdefault("_request_id", uuid.uuid4().hex)
        self.connect()
        try:
            send_frame(self._sock, req)
            resp = recv_frame(self._sock, self.max_payload)
            if resp is None:
                raise ProtocolError("服务端关闭连接且未响应")
            return resp
        except (OSError, ProtocolError) as e:
            self.close()
            if _retried:
                raise UdsUnavailable(f"调用失败：{e}") from e
            logger.debug("连接断开，重连重试：%s", e)
            return self.call(req, _retried=True)

    def ping(self) -> bool:
        try:
            return bool(self.call({"op": "ping"}).get("ok"))
        except UdsUnavailable:
            return False
