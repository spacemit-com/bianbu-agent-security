"""INT-LG-02 — LangGraph 工具→策略解析。

新模型下判权维度只有一个：**工具名**。工具名本身就是策略键，因此这里的
"映射"退化为恒等映射 —— 不再有"工具 → 能力名"的第二套命名，也不会出现
`system.exec` 与 `system.execute` 这类同义不同名的问题。

`resolve()` 保留 (tool, scope) 的返回形状供既有调用方使用；scope 恒为空，
不再从参数里提取范围。
"""
from __future__ import annotations

from typing import Optional

from securityd.capabilities import (  # noqa: E402,F401
    UNMAPPED_TOOL,
    is_known,
    unmapped_decision,
    unmapped_policy,
)

__all__ = ["resolve", "DEFAULT_ALLOW", "is_known"]

# 已弃用：未映射工具的处置由 capabilities.unmapped_policy() 决定，默认 allow。
# 本常量保留只为不破坏 `from .mapping import DEFAULT_ALLOW` 的既有导入。
DEFAULT_ALLOW = unmapped_policy() == "allow"

# 兼容旧导入名；新模型不再使用独立的能力映射表。
CAPABILITY_MAP: dict[str, tuple[str, str]] = {}


def resolve(tool_name: str, args: dict | None = None) -> Optional[tuple[str, str]]:
    """把工具名解析为 (tool, scope)；空工具名返回 None。"""
    if not tool_name:
        return None
    return (str(tool_name), "")
