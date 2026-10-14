"""执行后端推导：只有在声明了安全设置时才启用沙箱。

host 与 sandbox 不是人指定的开关，而是「这个 Agent 有没有额外安全设置」的
结果：可读/可写范围、受限的网络访问范围、系统调用黑名单追加项——只要声明
了其中任何一项，就需要命名空间/seccomp 才能落实，于是走 sandbox；什么都没
声明时用 host，避免为默认 Agent 平白增加一层隔离成本。

唯一的例外是可信度：缺少可信 manifest/固定启动程序的 Agent 无论有没有安全
设置都被挡在 host 之外（fail-closed），因为 host 会执行宿主上的真实程序。
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence

SANDBOX = "sandbox"
HOST = "host"


def _paths_declared(value: object) -> bool:
    if not isinstance(value, Mapping):
        return bool(value) if isinstance(value, Sequence) and not isinstance(
            value, (str, bytes, bytearray)) else False
    include = value.get("include") or []
    exclude = value.get("exclude") or []
    return bool(include) or bool(exclude)


def _network_restricted(network: object) -> bool:
    if not isinstance(network, Mapping):
        return False
    mode = str(network.get("mode", "allow_all") or "allow_all").strip().lower()
    if mode in {"whitelist", "deny_all"}:
        return True
    return False


def decide(*, read: object = None, write: object = None, network: object = None,
           syscall_additions: object = (), trusted: bool = True) -> dict:
    """返回 ``{mode, reasons, trusted}``；``reasons`` 说明为什么需要沙箱。"""
    reasons: list[str] = []
    if _paths_declared(read):
        reasons.append("可读范围")
    if _paths_declared(write):
        reasons.append("可写范围")
    if _network_restricted(network):
        reasons.append("网络访问范围")
    additions = [str(item).strip() for item in (syscall_additions or ()) if str(item).strip()]
    if additions:
        reasons.append("系统调用黑名单")

    if reasons:
        mode = SANDBOX
    elif not trusted:
        mode = SANDBOX
        reasons.append("缺少可信 manifest 或固定启动程序")
    else:
        mode = HOST
    return {"mode": mode, "reasons": reasons, "trusted": bool(trusted)}


__all__ = ["HOST", "SANDBOX", "decide"]
