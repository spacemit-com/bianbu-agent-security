"""UDS 数据面服务端（ARCH-01）。

职责边界（与 D-Bus 的分工）：
  · D-Bus（控制面）：CheckPermission、能力变更、信号广播 —— 小消息、需 polkit
  · UDS（数据面）：PII 扫描内容、审计载荷全文、工具返回值 —— 大载荷、高频、低延迟

安全：
  · socket 文件 0660（同组可访问）
  · SO_PEERCRED 取对端 uid，非同 uid（且服务端非 root）直接拒绝
  · 载荷上限先于内存分配检查，防恶意长度 OOM
"""
from __future__ import annotations

import logging
import grp
import hashlib
import json
import os
import socket
import stat
import struct
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass
import inspect
from pathlib import Path
from typing import Callable, Optional

from . import config
from .uds_protocol import ProtocolError, recv_frame, send_frame

logger = logging.getLogger("securityd.uds")

__all__ = ["UdsServer", "PeerCredentials", "peer_credentials", "peer_uid"]

# struct ucred { pid_t pid; uid_t uid; gid_t gid; } —— 均为 32 位
_UCRED_FMT = "3i"
_UCRED_SIZE = struct.calcsize(_UCRED_FMT)


@dataclass(frozen=True)
class PeerCredentials:
    pid: int
    uid: int
    gid: int


def peer_credentials(sock: socket.socket) -> Optional[PeerCredentials]:
    """取对端 pid/uid/gid（SO_PEERCRED）。不支持的平台返回 None。"""
    try:
        raw = sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, _UCRED_SIZE)
        pid, uid, gid = struct.unpack(_UCRED_FMT, raw)
        return PeerCredentials(pid=pid, uid=uid, gid=gid)
    except (AttributeError, OSError) as e:  # 平台不支持
        logger.debug("SO_PEERCRED 不可用：%s", e)
        return None


def peer_uid(sock: socket.socket) -> Optional[int]:
    """向后兼容：只返回对端 uid。"""
    creds = peer_credentials(sock)
    return creds.uid if creds else None


# Handler 签名兼容两种形态：
#   (request_dict, peer_uid) -> response_dict
#   (request_dict, peer_uid, PeerCredentials|None) -> response_dict
UdsHandler = Callable[..., dict]


class UdsServer:
    """单 socket 多线程 UDS 服务端（每连接一线程）。

    按 op 字段路由到注册的 handler：
        {"op": "dlp.scan", "text": "...", ...} → handler
    响应统一形如 {"ok": bool, ...} 或 {"ok": false, "error": "..."}。
    """

    def __init__(
        self,
        socket_path: Path | str | None = None,
        max_payload: int | None = None,
        recv_timeout: float | None = None,
        enforce_peer_uid: bool = True,
        dedupe_capacity: int = 4096,
        dedupe_max_bytes: int = 16 * 1024 * 1024,
        dedupe_max_response_bytes: int = 1024 * 1024,
        allowed_gid: int | None = None,
        allowed_gids: set[int] | None = None,
    ):
        self.socket_path = Path(socket_path or config.UDS_SOCKET_PATH)
        self.max_payload = max_payload or config.UDS_MAX_PAYLOAD
        self.recv_timeout = (
            config.UDS_RECV_TIMEOUT_SEC if recv_timeout is None else recv_timeout)
        self.enforce_peer_uid = enforce_peer_uid
        self.dedupe_capacity = max(1, int(dedupe_capacity))
        self.dedupe_max_bytes = max(1, int(dedupe_max_bytes))
        self.dedupe_max_response_bytes = max(1, int(dedupe_max_response_bytes))
        self.allowed_gids = {
            int(value) for value in (allowed_gids or set())
        }
        if allowed_gid is not None:
            self.allowed_gids.add(int(allowed_gid))
        self._handlers: dict[str, tuple[UdsHandler, bool]] = {}
        self._sock: Optional[socket.socket] = None
        self._owns_socket_path = False
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self._conn_threads: list[threading.Thread] = []
        self._connections: set[socket.socket] = set()
        self._connections_lock = threading.Lock()
        self._own_uid = os.geteuid() if hasattr(os, "geteuid") else None
        self._dedupe_lock = threading.Lock()
        self._response_cache: "OrderedDict[tuple[Optional[int], str], tuple[str, Optional[dict], int]]" = OrderedDict()
        self._response_cache_bytes = 0
        self._inflight: dict[tuple[Optional[int], str], tuple[str, threading.Event]] = {}

    # —— 注册 ——
    def register(self, op: str, handler: UdsHandler) -> None:
        try:
            params = list(inspect.signature(handler).parameters.values())
            wants_peer = (any(p.kind == inspect.Parameter.VAR_POSITIONAL for p in params)
                          or sum(p.kind in (inspect.Parameter.POSITIONAL_ONLY,
                                           inspect.Parameter.POSITIONAL_OR_KEYWORD)
                                 for p in params) >= 3)
        except (TypeError, ValueError):
            wants_peer = False
        self._handlers[op] = (handler, wants_peer)

    def list_ops(self) -> list[str]:
        return sorted(self._handlers)

    # —— 生命周期 ——
    def start(self) -> None:
        """绑定 socket 并起 accept 线程。"""
        self.socket_path.parent.mkdir(parents=True, exist_ok=True)
        self._remove_stale_socket()

        self._sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._sock.bind(str(self.socket_path))
        self._owns_socket_path = True
        self._sock.listen(64)
        self._sock.settimeout(0.5)  # 让 accept 循环能周期性检查 _stop
        try:
            self.socket_path.chmod(config.UDS_SOCKET_MODE)
            # The socket is the dedicated Runtime data-plane boundary.  Keep
            # /run/bianbu itself traversable and assign only this socket to
            # the Runtime user's group; all other files retain their own
            # restrictive ownership and modes.
            self.socket_path.parent.chmod(0o755)
            runtime_group = os.environ.get("BIANBU_RUNTIME_GROUP", "bianbu").strip()
            if runtime_group:
                os.chown(self.socket_path, -1, grp.getgrnam(runtime_group).gr_gid)
        except OSError as e:
            logger.warning("socket chmod 失败：%s", e)
        except KeyError:
            logger.warning("Runtime group 不存在，保留 socket 原属组")

        self._stop.clear()
        self._thread = threading.Thread(
            target=self._accept_loop, name="uds-accept", daemon=True)
        self._thread.start()
        logger.info("UDS 服务已启动：%s（ops=%s）",
                    self.socket_path, ",".join(self.list_ops()))

    def _remove_stale_socket(self) -> None:
        """只删除残留 socket；活跃实例必须阻止第二个服务抢占路径。"""
        try:
            mode = self.socket_path.lstat().st_mode
        except FileNotFoundError:
            return
        if not stat.S_ISSOCK(mode):
            self.socket_path.unlink()
            return
        probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        probe.settimeout(0.2)
        try:
            probe.connect(str(self.socket_path))
        except (ConnectionRefusedError, FileNotFoundError):
            self.socket_path.unlink(missing_ok=True)
        except OSError as exc:
            # 无法证明是残留时保持 fail-closed，避免误删其他实例或权限边界。
            raise RuntimeError(f"无法确认 UDS socket 是否残留: {self.socket_path}: {exc}") from exc
        else:
            raise RuntimeError(f"UDS socket 已被活跃服务占用: {self.socket_path}")
        finally:
            probe.close()

    def stop(self, timeout: float = 2.0) -> None:
        deadline = time.monotonic() + timeout
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=max(0.0, deadline - time.monotonic()))
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None
        with self._connections_lock:
            connections = list(self._connections)
        for conn in connections:
            try:
                conn.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                conn.close()
            except OSError:
                pass
        for t in self._conn_threads:
            t.join(timeout=max(0.0, deadline - time.monotonic()))
        alive = [t.name for t in self._conn_threads if t.is_alive()]
        self._conn_threads.clear()
        with self._dedupe_lock:
            for _fingerprint, event in self._inflight.values():
                event.set()
            self._inflight.clear()
            self._response_cache.clear()
            self._response_cache_bytes = 0
        if self._owns_socket_path and self.socket_path.exists():
            try:
                self.socket_path.unlink()
            except OSError:
                pass
        self._owns_socket_path = False
        if alive:
            raise RuntimeError(f"UDS 连接线程关闭超时: {','.join(alive)}")
        logger.info("UDS 服务已停止")

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *exc):
        self.stop()
        return False

    # —— 内部 ——
    def _accept_loop(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _ = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break  # socket 已关
            t = threading.Thread(
                target=self._serve_conn, args=(conn,),
                name="uds-conn", daemon=True)
            t.start()
            # 清掉已结束的线程句柄，避免长期运行时列表无界增长
            self._conn_threads = [x for x in self._conn_threads if x.is_alive()]
            self._conn_threads.append(t)

    def _serve_conn(self, conn: socket.socket) -> None:
        with self._connections_lock:
            self._connections.add(conn)
        creds = peer_credentials(conn)
        uid = creds.uid if creds else None
        try:
            if not self._authorized(creds):
                send_frame(conn, {"ok": False,
                                  "error": f"peer uid {uid} 未授权"})
                logger.warning("拒绝未授权连接：peer uid=%s", uid)
                return
            conn.settimeout(self.recv_timeout)
            while not self._stop.is_set():
                try:
                    req = recv_frame(conn, self.max_payload)
                except socket.timeout:
                    break  # 空闲超时，关连接（客户端可重连）
                except ProtocolError as e:
                    try:
                        send_frame(conn, {"ok": False, "error": str(e)})
                    except OSError:
                        pass
                    break
                if req is None:
                    break  # 对端干净关闭
                send_frame(conn, self._dispatch(req, uid, creds))
        except OSError as e:
            logger.debug("连接异常结束：%s", e)
        finally:
            with self._connections_lock:
                self._connections.discard(conn)
            try:
                conn.close()
            except OSError:
                pass

    def _authorized(self, creds: Optional[PeerCredentials]) -> bool:
        """同 uid 或显式服务组放行；root 仍由 socket 文件权限把关。"""
        if not self.enforce_peer_uid:
            return True
        if creds is None:  # 平台不支持 SO_PEERCRED，退回文件权限把关
            return True
        if self._own_uid == 0:
            return True
        if creds.uid == self._own_uid:
            return True
        if not self.allowed_gids:
            return False
        if creds.gid in self.allowed_gids:
            return True
        try:
            status = Path(f"/proc/{creds.pid}/status").read_text()
            groups_line = status.split("Groups:", 1)[1].splitlines()[0]
            return bool(self.allowed_gids.intersection(
                int(value) for value in groups_line.split()
            ))
        except (OSError, IndexError, ValueError):
            return False

    def _dispatch(self, req: dict, uid: Optional[int],
                  creds: Optional[PeerCredentials] = None) -> dict:
        if not isinstance(req, dict):
            return {"ok": False, "error": "请求必须是 JSON object"}
        has_request_id = "_request_id" in req
        request_id = req.get("_request_id", "")
        if has_request_id and (not isinstance(request_id, str)
                               or not request_id or len(request_id) > 128):
            return {"ok": False, "error": "_request_id 必须是 1~128 字符的字符串"}
        cache_key = (uid, request_id) if has_request_id else None
        fingerprint = ""
        owner = True
        if cache_key is not None:
            fingerprint = hashlib.sha256(json.dumps(
                req, ensure_ascii=False, sort_keys=True,
                separators=(",", ":")).encode("utf-8")).hexdigest()
            with self._dedupe_lock:
                cached = self._response_cache.get(cache_key)
                if cached is not None:
                    cached_fingerprint, cached_response, _cached_size = cached
                    if cached_fingerprint != fingerprint:
                        return {"ok": False,
                                "error": "_request_id 已被不同请求载荷使用"}
                    self._response_cache.move_to_end(cache_key)
                    if cached_response is None:
                        return {"ok": False,
                                "error": "原请求已执行，但响应过大无法安全重放"}
                    return dict(cached_response)
                pending = self._inflight.get(cache_key)
                if pending is None:
                    event = threading.Event()
                    self._inflight[cache_key] = (fingerprint, event)
                else:
                    pending_fingerprint, event = pending
                    if pending_fingerprint != fingerprint:
                        return {"ok": False,
                                "error": "_request_id 正被不同请求载荷使用"}
                    owner = False
            if not owner:
                if not event.wait(timeout=self.recv_timeout):
                    return {"ok": False, "error": "重复请求等待原请求完成超时"}
                with self._dedupe_lock:
                    cached = self._response_cache.get(cache_key)
                    if cached is None:
                        return {"ok": False, "error": "原请求在服务停止前未完成"}
                    cached_fingerprint, cached_response, _cached_size = cached
                    if cached_fingerprint != fingerprint:
                        return {"ok": False,
                                "error": "_request_id 完成结果与请求载荷不一致"}
                    self._response_cache.move_to_end(cache_key)
                    if cached_response is None:
                        return {"ok": False,
                                "error": "原请求已执行，但响应过大无法安全重放"}
                    return dict(cached_response)
        op = req.get("op")
        handler_entry = self._handlers.get(op)
        if handler_entry is None:
            resp = {"ok": False,
                    "error": f"未知 op：{op}（可用：{','.join(self.list_ops())}）"}
        else:
            handler, wants_peer = handler_entry
            try:
                resp = handler(req, uid, creds) if wants_peer else handler(req, uid)
            except Exception as e:  # noqa: BLE001 — handler 异常不能拖垮服务
                logger.exception("handler %s 异常", op)
                resp = {"ok": False, "error": f"{type(e).__name__}: {e}"}
            if not isinstance(resp, dict):
                resp = {"ok": False, "error": f"handler {op} 返回值非 dict"}
            resp.setdefault("ok", True)
        if request_id:
            resp.setdefault("_request_id", request_id)
        if cache_key is not None:
            try:
                response_size = len(json.dumps(
                    resp, ensure_ascii=False, sort_keys=True,
                    separators=(",", ":")).encode("utf-8"))
            except (TypeError, ValueError) as exc:
                resp = {"ok": False, "_request_id": request_id,
                        "error": f"handler {op} 返回值不可 JSON 序列化: {exc}"}
                response_size = len(json.dumps(
                    resp, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))
            replayable = response_size <= min(
                self.dedupe_max_response_bytes, self.dedupe_max_bytes)
            with self._dedupe_lock:
                self._response_cache[cache_key] = (
                    fingerprint, dict(resp) if replayable else None,
                    response_size if replayable else 0)
                if replayable:
                    self._response_cache_bytes += response_size
                self._response_cache.move_to_end(cache_key)
                while (len(self._response_cache) > self.dedupe_capacity
                       or self._response_cache_bytes > self.dedupe_max_bytes):
                    _key, (_fp, _response, evicted_size) = self._response_cache.popitem(
                        last=False)
                    self._response_cache_bytes -= evicted_size
                _fingerprint, event = self._inflight.pop(cache_key)
                event.set()
        return resp
