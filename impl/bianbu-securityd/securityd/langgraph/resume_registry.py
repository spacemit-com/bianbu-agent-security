"""LangGraph interrupt/resume 的本地注册表和跨进程 broker。

LangGraph 的 graph 实例只能由拥有它的 Agent/Runtime 进程调用
``update_state``。本模块提供两层适配：

* Agent 进程注册 graph，并在本进程启动受 Unix 权限保护的 broker；
* WebUI 进程只通过 broker 查看 pending 和提交一次性批准/拒绝。

WebUI 永远不会序列化、伪造或在自身进程创建 graph。broker 仅暴露
``list``/``resume`` 两个只读/控制操作；注册和发布只能由持有 graph 的进程
通过本地 Python API 完成。socket 默认 0600，可通过部署配置指定目录/组。
"""
from __future__ import annotations

import json
import hmac
import os
import re
import socket
import socketserver
import stat
import threading
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class PendingInterrupt:
    graph_id: str
    run_id: str
    agent_id: str
    tool_name: str
    capability: str
    message: str
    payload: dict[str, Any]
    created_at: float


class _BrokerHandler(socketserver.StreamRequestHandler):
    """一请求一响应 JSON 协议；只允许 list/resume/ping。"""

    def handle(self) -> None:  # noqa: D401
        try:
            raw = self.rfile.readline(1024 * 1024)
            if not raw:
                return
            req = json.loads(raw.decode("utf-8"))
            result = self.server.registry._handle_remote(req)  # type: ignore[attr-defined]
            self._write({"ok": True, "result": result})
        except PermissionError as exc:
            self._write({"ok": False, "error": str(exc), "code": "permission"})
        except KeyError as exc:
            self._write({"ok": False, "error": str(exc), "code": "missing"})
        except (RuntimeError, ValueError) as exc:
            self._write({"ok": False, "error": str(exc), "code": "invalid"})
        except Exception as exc:  # noqa: BLE001
            self._write({"ok": False, "error": str(exc), "code": "error"})

    def _write(self, value: dict[str, Any]) -> None:
        self.wfile.write((json.dumps(value, ensure_ascii=False, default=str) + "\n").encode())
        self.wfile.flush()


class _UnixBroker(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, path: str, registry: "LangGraphResumeRegistry") -> None:
        self.registry = registry
        super().__init__(path, _BrokerHandler)


class LangGraphResumeRegistry:
    """线程安全的 graph 注册、一次性 resume 和跨进程 broker。"""

    _ID = re.compile(r"^[A-Za-z0-9_.:-]{1,160}$")
    DEFAULT_TTL = 15 * 60

    def __init__(self, *, socket_dir: str | os.PathLike[str] | None = None,
                 ttl_seconds: int = DEFAULT_TTL,
                 broker_token: str | None = None) -> None:
        self._lock = threading.RLock()
        self._graphs: dict[str, tuple[Any, Any, str, str]] = {}
        self._pending: dict[str, PendingInterrupt] = {}
        self._broker: _UnixBroker | None = None
        self._broker_thread: threading.Thread | None = None
        configured = socket_dir or os.environ.get("BIANBU_LANGGRAPH_BROKER_DIR")
        self.socket_dir = Path(configured).expanduser() if configured else (
            Path(os.environ.get("XDG_RUNTIME_DIR", "/tmp")) / "bianbu-langgraph")
        self.ttl_seconds = max(1, int(ttl_seconds))
        # 多用户 systemd 部署可额外配置 token；默认仍由 socket UID/GID
        # 权限保护，避免把 token 写进 pending 或 WebUI 响应。
        self.broker_token = (broker_token if broker_token is not None else
                             os.environ.get("BIANBU_LANGGRAPH_BROKER_TOKEN", ""))

    @classmethod
    def _validate_id(cls, value: str, name: str) -> str:
        value = str(value or "")
        if not cls._ID.fullmatch(value):
            raise ValueError(f"{name} 非法")
        return value

    def start_broker(self, socket_path: str | os.PathLike[str] | None = None,
                     *, mode: int | None = None,
                     directory_mode: int | None = None) -> str:
        """在 Agent/Runtime 进程启动 broker，返回 socket 路径。

        仅移除同一目标的 stale socket；不会触碰目录中的其它文件。
        """
        with self._lock:
            if self._broker is not None:
                return str(self._broker.server_address)
            raw = socket_path or os.environ.get("BIANBU_LANGGRAPH_SOCKET")
            path = Path(raw).expanduser() if raw else (
                self.socket_dir / f"graph-{os.getpid()}.sock")
            path.parent.mkdir(parents=True, exist_ok=True)
            if directory_mode is None:
                directory_mode = int(os.environ.get("BIANBU_LANGGRAPH_BROKER_DIR_MODE", "700"), 8)
            if mode is None:
                mode = int(os.environ.get("BIANBU_LANGGRAPH_BROKER_SOCKET_MODE", "600"), 8)
            os.chmod(path.parent, directory_mode)
            if path.exists():
                # 只有 Unix socket 才允许复用；普通文件一律拒绝。
                if not stat_is_socket(path):
                    raise RuntimeError(f"broker 路径不是 socket，拒绝覆盖: {path}")
                path.unlink()
            broker = _UnixBroker(str(path), self)
            os.chmod(path, mode)
            self._broker = broker
            self._broker_thread = threading.Thread(
                target=broker.serve_forever, name="langgraph-broker", daemon=True)
            self._broker_thread.start()
            return str(path)

    def stop_broker(self) -> None:
        with self._lock:
            broker, self._broker = self._broker, None
        if broker is None:
            return
        path = Path(str(broker.server_address))
        broker.shutdown()
        broker.server_close()
        if path.exists() and stat_is_socket(path):
            path.unlink()

    def register(self, graph_id: str, graph: Any, *, config: Any = None,
                 run_id: str = "", agent_id: str = "",
                 socket_path: str | os.PathLike[str] | None = None) -> str | None:
        """注册 graph；传入 socket_path 时同时启动本进程 broker。"""
        gid = self._validate_id(graph_id, "graph_id")
        if not (callable(graph) or callable(getattr(graph, "update_state", None))):
            raise TypeError("graph 必须是 resume callback 或带 update_state 的对象")
        if socket_path is not None or os.environ.get("BIANBU_LANGGRAPH_SOCKET"):
            self.start_broker(socket_path)
        with self._lock:
            self._graphs[gid] = (graph, config, str(run_id or ""), str(agent_id or ""))
        return str(self._broker.server_address) if self._broker else None

    # 明确的 Agent/Runtime 语义别名，避免调用方误以为 WebUI 能注册 graph。
    register_graph = register

    def unregister(self, graph_id: str) -> None:
        with self._lock:
            self._graphs.pop(str(graph_id), None)
            self._pending.pop(str(graph_id), None)

    def discard_pending(self, graph_id: str, *, run_id: str = "") -> bool:
        gid = self._validate_id(graph_id, "graph_id")
        with self._lock:
            item = self._pending.get(gid)
            if item is None or (run_id and item.run_id != str(run_id)):
                return False
            self._pending.pop(gid, None)
            return True

    def publish(self, payload: dict[str, Any]) -> PendingInterrupt:
        gid = self._validate_id(str(payload.get("graph_id", "")), "graph_id")
        run_id = str(payload.get("run_id", "") or "")
        if not run_id:
            raise ValueError("run_id 必填")
        item = PendingInterrupt(
            graph_id=gid,
            run_id=run_id,
            agent_id=str(payload.get("agent_id", "") or ""),
            tool_name=str(payload.get("tool_name", "") or ""),
            capability=str(payload.get("capability", "") or ""),
            message=str(payload.get("message", "") or ""),
            payload=dict(payload),
            created_at=time.time(),
        )
        with self._lock:
            self._purge_locked()
            if gid not in self._graphs:
                raise RuntimeError("graph 未在当前 Agent Runtime 注册")
            previous = self._pending.get(gid)
            if previous is not None:
                # LangGraph 在 interrupt 恢复时会从节点开头重放；同一个
                # graph/run 的 publish 必须幂等，否则恢复会被自己的 pending
                # 记录再次阻断。不同 run/agent 复用 graph_id 则拒绝覆盖。
                if previous.run_id == item.run_id and previous.agent_id == item.agent_id:
                    return previous
                raise RuntimeError("graph 已有其它 run 的未处理 interrupt")
            self._pending[gid] = item
        return item

    def list_pending(self) -> list[dict[str, Any]]:
        local = self._list_local()
        seen = {str(x.get("graph_id")) for x in local}
        for path in self._broker_paths():
            try:
                rows = _rpc(path, {"op": "list", "token": self.broker_token})
                for row in rows:
                    if str(row.get("graph_id")) not in seen:
                        local.append(row)
                        seen.add(str(row.get("graph_id")))
            except (OSError, TimeoutError, RuntimeError, ValueError, PermissionError):
                continue
        return local

    def resume(self, graph_id: str, approved: bool, *, run_id: str = "",
               agent_id: str = "") -> dict[str, Any]:
        gid = self._validate_id(graph_id, "graph_id")
        # WebUI 自身注册的 graph 优先；否则寻找持有 graph 的远程 broker。
        with self._lock:
            if gid in self._graphs:
                return self._resume_local(gid, approved, run_id=run_id, agent_id=agent_id)
        last_missing: Exception | None = None
        for path in self._broker_paths():
            try:
                return _rpc(path, {"op": "resume", "token": self.broker_token, "graph_id": gid,
                                   "approved": bool(approved), "run_id": str(run_id or ""),
                                   "agent_id": str(agent_id or "")})
            except KeyError as exc:
                last_missing = exc
                continue
            except PermissionError:
                # 发现目标 broker 但 token 错误时必须返回拒绝，不能伪装成
                # “不存在”并继续尝试其它 socket。
                raise
            except (OSError, TimeoutError):
                continue
        raise last_missing or KeyError("graph interrupt 不存在、已处理或已过期")

    def _list_local(self) -> list[dict[str, Any]]:
        with self._lock:
            self._purge_locked()
            return [asdict(x) for x in self._pending.values()]

    def _resume_local(self, gid: str, approved: bool, *, run_id: str = "",
                      agent_id: str = "") -> dict[str, Any]:
        with self._lock:
            self._purge_locked()
            item = self._pending.get(gid)
            entry = self._graphs.get(gid)
            if item is None:
                raise KeyError("graph interrupt 不存在、已处理或已过期")
            if run_id and item.run_id != str(run_id):
                raise PermissionError("run_id 不匹配")
            if agent_id and item.agent_id != str(agent_id):
                raise PermissionError("agent_id 不匹配")
            if entry is None:
                raise RuntimeError("graph 未在当前 Runtime 注册，拒绝跨进程伪造 resume")
            graph, config, registered_run, registered_agent = entry
            if registered_run and registered_run != item.run_id:
                raise PermissionError("注册的 run_id 不匹配")
            if registered_agent and item.agent_id and registered_agent != item.agent_id:
                raise PermissionError("注册的 agent_id 不匹配")
            values = {"approved": bool(approved)}
            if callable(graph) and not callable(getattr(graph, "update_state", None)):
                result = graph(bool(approved), item)
            else:
                result = graph.update_state(config or {}, values=values,
                                            as_node="__interrupt__")
            self._pending.pop(gid, None)
            return {"graph_id": gid, "run_id": item.run_id,
                    "agent_id": item.agent_id, "approved": bool(approved),
                    "result": result}

    def _handle_remote(self, req: dict[str, Any]) -> Any:
        if self.broker_token and not hmac.compare_digest(
                str(req.get("token", "")), self.broker_token):
            raise PermissionError("broker token 不匹配")
        op = str(req.get("op", ""))
        if op == "ping":
            return {"pid": os.getpid()}
        if op == "list":
            return self._list_local()
        if op == "resume":
            return self._resume_local(
                str(req.get("graph_id", "")), bool(req.get("approved", False)),
                run_id=str(req.get("run_id", "")), agent_id=str(req.get("agent_id", "")))
        raise ValueError("broker 操作不允许")

    def _purge_locked(self) -> None:
        cutoff = time.time() - self.ttl_seconds
        for gid, item in list(self._pending.items()):
            if item.created_at < cutoff:
                self._pending.pop(gid, None)

    def _broker_paths(self) -> list[Path]:
        paths: list[Path] = []
        raw = os.environ.get("BIANBU_LANGGRAPH_SOCKET")
        if raw:
            paths.append(Path(raw).expanduser())
        directory = self.socket_dir
        if directory.exists():
            paths.extend(sorted(p for p in directory.glob("*.sock") if p not in paths))
        # 自己的 broker 已经可直接读本地，避免重复 RPC。
        own = Path(str(self._broker.server_address)) if self._broker else None
        return [p for p in paths if own is None or p != own]


def stat_is_socket(path: Path) -> bool:
    return stat.S_ISSOCK(path.stat().st_mode) if path.exists() else False


def _rpc(path: Path, request: dict[str, Any]) -> Any:
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(2.0)
    try:
        sock.connect(str(path))
        sock.sendall((json.dumps(request, ensure_ascii=False) + "\n").encode())
        data = b""
        while not data.endswith(b"\n"):
            chunk = sock.recv(1024 * 1024)
            if not chunk:
                break
            data += chunk
        if not data:
            raise RuntimeError("broker 无响应")
        reply = json.loads(data.decode("utf-8"))
        if reply.get("ok"):
            return reply.get("result")
        code = reply.get("code")
        error = str(reply.get("error", "broker 请求失败"))
        if code == "missing":
            raise KeyError(error)
        if code == "permission":
            raise PermissionError(error)
        if code == "invalid":
            raise ValueError(error)
        raise RuntimeError(error)
    finally:
        sock.close()


registry = LangGraphResumeRegistry()


def register_graph(*args, **kwargs):
    return registry.register_graph(*args, **kwargs)


def unregister_graph(*args, **kwargs):
    return registry.unregister(*args, **kwargs)


__all__ = [
    "PendingInterrupt", "LangGraphResumeRegistry", "registry",
    "register_graph", "unregister_graph",
]
