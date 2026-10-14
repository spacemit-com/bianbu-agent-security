"""UDS 数据面线协议（ARCH-01）。

帧格式（长度前缀，避免流式粘包）：
    [4 字节 big-endian 长度][UTF-8 JSON 载荷]

为什么不用 D-Bus 传大载荷：D-Bus 单消息虽可达 128MB，但要经 dbus-daemon 中转
（多一次内核态拷贝 + 序列化），大载荷延迟显著；UDS 是点对点 stream，一次 sendall
即可，适合 PII 扫描内容、审计载荷全文这类数据面流量。

协议是同步请求/响应：客户端发一帧请求，服务端回一帧响应，之后可复用连接。
"""
from __future__ import annotations

import json
import socket
import struct

__all__ = [
    "HEADER_SIZE",
    "ProtocolError",
    "PayloadTooLarge",
    "encode_frame",
    "send_frame",
    "recv_frame",
]

HEADER_SIZE = 4
_HEADER = ">I"  # big-endian uint32


class ProtocolError(Exception):
    """帧格式错误 / 连接中途断开。"""


class PayloadTooLarge(ProtocolError):
    """载荷超过 max_payload 上限（防内存耗尽）。"""


def encode_frame(obj) -> bytes:
    """把 dict 编码为一帧（长度前缀 + JSON）。"""
    body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
    return struct.pack(_HEADER, len(body)) + body


def send_frame(sock: socket.socket, obj) -> None:
    """发送一帧。sendall 保证完整写出。"""
    sock.sendall(encode_frame(obj))


def _recv_exactly(sock: socket.socket, n: int) -> bytes:
    """读满 n 字节；不足即视为连接断开（stream 无消息边界，必须自己数）。"""
    chunks = []
    remaining = n
    while remaining > 0:
        chunk = sock.recv(min(remaining, 1 << 16))
        if not chunk:
            raise ProtocolError(
                f"连接在读取中断开（还差 {remaining}/{n} 字节）")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def recv_frame(sock: socket.socket, max_payload: int):
    """读取一帧并解析 JSON。

    连接正常关闭（对端 close 且无残留数据）返回 None，调用方据此结束循环。
    """
    header = b""
    while len(header) < HEADER_SIZE:
        chunk = sock.recv(HEADER_SIZE - len(header))
        if not chunk:
            if not header:
                return None  # 干净关闭
            raise ProtocolError(
                f"帧头不完整（{len(header)}/{HEADER_SIZE} 字节）")
        header += chunk

    (length,) = struct.unpack(_HEADER, header)
    if length > max_payload:
        # 先于分配内存拒绝，避免恶意长度导致 OOM
        raise PayloadTooLarge(f"载荷 {length} 字节超过上限 {max_payload}")
    if length == 0:
        return {}

    body = _recv_exactly(sock, length)
    try:
        return json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        raise ProtocolError(f"载荷不是合法 UTF-8 JSON：{e}") from e
