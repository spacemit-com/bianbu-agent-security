"""Agent 安全权限设置：可读范围 / 可写范围 / 网络访问范围 / 系统调用黑名单。

能力管理（``capability`` 表）回答"这个 tool 能不能调"；本模块回答"调用之后
Worker 到底能碰什么"：文件系统可读范围、可写范围、出站网络访问范围、内核
系统调用黑名单。

每个文件系统范围都是「包含 + 排除」二段式：``include`` 列出允许触碰的
绝对路径，``exclude`` 列出必须从其中挖掉（或不给写权限）的子路径。二者是
同一份声明的两个字段，分开存会让"读一半再挖掉一块"无从表达。

存储只保存声明值，不做解释；真正的强制由 Runtime 的沙箱/mount 边界完成：
``include`` 编译成只读/读写挂载，``exclude`` 编译成不可访问或只读覆盖。
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from pathlib import Path, PurePosixPath

GROUP_READ = "read"
GROUP_WRITE = "write"
GROUPS = (GROUP_READ, GROUP_WRITE)
RANGE_KEYS = ("include", "exclude")

MAX_PATHS = 256
MAX_PATH_LEN = 4096


class PermissionSettingsError(ValueError):
    """安全权限设置非法（组名或路径）。"""


def _group(group: object) -> str:
    value = str(group or "").strip().lower()
    if value not in GROUPS:
        raise PermissionSettingsError(
            f"未知安全权限组：{group!r}（可选 {', '.join(GROUPS)}）")
    return value


def group_name(group: object) -> str:
    """校验并归一化组名（对外公开入口）。"""
    return _group(group)


def normalise_paths(values: object, *, group: str = "") -> list[str]:
    """把声明路径归一并校验：绝对路径、无父目录片段、去重、保序。

    Runtime 会在挂载前重新做一次存在性检查；这里只做词法校验，因为
    ``bianbu-securityd`` 带 ``ProtectHome=yes``，看不到用户 Runtime 的目录。
    """
    if values is None:
        return []
    if isinstance(values, (str, bytes, bytearray)) or not isinstance(values, Sequence):
        raise PermissionSettingsError(f"{group or '范围'}需要是路径数组")
    out: list[str] = []
    for raw in values:
        text = str(raw or "").strip()
        if not text:
            continue
        if len(text) > MAX_PATH_LEN:
            raise PermissionSettingsError(f"路径超过 {MAX_PATH_LEN} 字符：{text[:64]}…")
        path = PurePosixPath(text)
        if not path.is_absolute():
            raise PermissionSettingsError(f"范围条目需要以 / 开头的绝对路径：{text}")
        if ".." in path.parts:
            raise PermissionSettingsError(f"路径不得包含父目录片段：{text}")
        normalised = str(Path(text))
        if normalised not in out:
            out.append(normalised)
    if len(out) > MAX_PATHS:
        raise PermissionSettingsError(f"路径数量超过上限 {MAX_PATHS}")
    return out


def normalise(value: object, *, group: str = "") -> dict:
    """按组校验并归一化一个「包含 + 排除」范围声明。

    接受 ``{"include": [...], "exclude": [...]}``；两个字段都可以省略，
    省略即空。拒绝把可写范围排除项写成包含项的子路径之外——不做强制，
    只做校验，避免管理员写出永远不会生效的死配置。
    """
    if value in (None, ""):
        value = {}
    if not isinstance(value, Mapping):
        raise PermissionSettingsError(f"{group or '范围'}需要是 {{include, exclude}} 对象")
    unknown = sorted(str(k) for k in value if str(k) not in RANGE_KEYS)
    if unknown:
        raise PermissionSettingsError(
            f"{group or '范围'}只接受 include / exclude，收到：{', '.join(unknown)}")
    include = normalise_paths(value.get("include"), group=f"{group}.include" if group else "include")
    exclude = normalise_paths(value.get("exclude"), group=f"{group}.exclude" if group else "exclude")
    for path in exclude:
        if not _covered_by(include, path):
            raise PermissionSettingsError(
                f"排除路径必须落在某个包含范围内：{path}")
    return {"include": include, "exclude": exclude}


def _covered_by(include: Sequence[str], path: str) -> bool:
    """``path`` 是否等于或位于某个包含范围之下。"""
    target = PurePosixPath(path)
    for entry in include:
        base = PurePosixPath(entry)
        if target == base or base in target.parents:
            return True
    return False


__all__ = [
    "GROUP_READ", "GROUP_WRITE", "GROUPS", "MAX_PATHS", "MAX_PATH_LEN",
    "PermissionSettingsError", "RANGE_KEYS", "group_name", "normalise",
    "normalise_paths",
]
