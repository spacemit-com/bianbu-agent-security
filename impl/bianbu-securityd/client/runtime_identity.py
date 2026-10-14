"""Runtime 侧的 Security 身份绑定适配器。

Security 判权只信任内核推导的 caller（uid/exe/cgroup），不信任请求参数里的
``agent_id``。Runtime 每启动一次执行，就用自己真实的 D-Bus sender 通过
``BindAgentV2`` 建立 (agent_id, session_id, run_id) 绑定，之后的 CheckPermission
才有可信主体。

本模块只做身份绑定，不做任何计量或配额——配额/用量不是安全边界的一部分。
"""
from __future__ import annotations

import os
from typing import Any


class RuntimeSecurityIdentity:
    """把一次执行上下文绑定到 Runtime 的 D-Bus 身份。"""

    def __init__(self, *, agent_id: str = "", session_id: str = "",
                 run_id: str = "", bus: Any | None = None):
        self.agent_id = str(agent_id)
        self.session_id = str(session_id)
        self.run_id = str(run_id)
        self._bus = bus

    def _bus_or_default(self) -> Any:
        import dbus

        if self._bus is not None:
            return self._bus
        session = os.environ.get("BIANBU_SEC_SESSION") == "1"
        return dbus.SessionBus() if session else dbus.SystemBus()

    def bind_security_identity(self, bus: Any | None = None) -> bool:
        """用 Runtime 自身 sender 建立 Security caller 绑定。"""
        import dbus

        if not (self.agent_id and self.session_id and self.run_id):
            raise ValueError("bind requires agent_id/session_id/run_id")
        target = bus or self._bus_or_default()
        proxy = target.get_object("io.bianbu.Security", "/io/bianbu/Security")
        context = dbus.Dictionary({
            "session_id": dbus.String(self.session_id),
            "run_id": dbus.String(self.run_id),
            "source": dbus.String("agent-runtime"),
        }, signature="sv")
        return bool(proxy.BindAgentV2(
            self.agent_id, context, dbus_interface="io.bianbu.Security"))

    def close(self) -> None:
        self._bus = None


__all__ = ["RuntimeSecurityIdentity"]
