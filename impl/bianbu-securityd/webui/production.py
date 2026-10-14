"""生产 WebUI 启动器。

systemd 只调用本模块，不直接运行 Flask/Werkzeug 开发服务器。Gunicorn 使用
单 worker + gthread：单进程保证 Flask-SocketIO 的内存态会话/PTY 注册表一致，
线程池同时承载 REST、SSE 与 WebSocket；simple-websocket 提供 threading 模式
下的 WebSocket 传输。
"""
from __future__ import annotations

import os


def _bounded_int(name: str, default: int, minimum: int, maximum: int) -> int:
    raw = os.environ.get(name, str(default))
    try:
        value = int(raw)
    except ValueError as exc:
        raise RuntimeError(f"{name} 必须是整数") from exc
    if not minimum <= value <= maximum:
        raise RuntimeError(f"{name} 必须在 {minimum}..{maximum} 范围内")
    return value


def build_options() -> dict[str, object]:
    """从环境生成经过安全校验的 Gunicorn 配置。"""
    from webui.app import _validate_bind_security

    host = os.environ.get("BIANBU_WEBUI_HOST", "0.0.0.0").strip()
    if not host or any(ch.isspace() for ch in host):
        raise RuntimeError("BIANBU_WEBUI_HOST 非法")
    port = _bounded_int("BIANBU_WEBUI_PORT", 8787, 1, 65535)
    threads = _bounded_int("BIANBU_WEBUI_THREADS", 32, 4, 256)
    timeout = _bounded_int("BIANBU_WEBUI_TIMEOUT", 120, 10, 3600)
    tls = _validate_bind_security(host)
    options: dict[str, object] = {
        "bind": f"{host}:{port}",
        "workers": 1,
        "worker_class": "gthread",
        "threads": threads,
        "timeout": timeout,
        "graceful_timeout": 30,
        "keepalive": 5,
        "accesslog": "-",
        "errorlog": "-",
        "capture_output": True,
        # Gunicorn 26 enables a management Unix socket by default.  The
        # packaged WebUI is supervised by systemd and has no gunicornc
        # control-plane consumer; leaving it enabled makes Gunicorn try to
        # create ``$HOME/.gunicorn``.  The service account deliberately has
        # no writable home (ProtectHome/ProtectSystem), so this only emits a
        # misleading read-only-filesystem warning at every startup.
        "control_socket_disable": True,
    }
    if tls is not None:
        options["certfile"], options["keyfile"] = tls
    return options


def main() -> None:
    try:
        from gunicorn.app.base import BaseApplication
        import simple_websocket  # noqa: F401  # Flask-SocketIO threading transport
    except ImportError as exc:
        raise SystemExit(
            "生产 WebUI 缺少 gunicorn/simple-websocket；请使用冻结发布 venv"
        ) from exc
    from webui.app import app, _connection_monitor
    _connection_monitor.start()

    class _Application(BaseApplication):
        def load_config(self) -> None:
            for key, value in build_options().items():
                self.cfg.set(key, value)

        def load(self):
            return app

    options = build_options()
    print(f"[WebUI] Gunicorn {options['bind']} workers=1 threads={options['threads']}",
          flush=True)
    _Application().run()


if __name__ == "__main__":
    main()
