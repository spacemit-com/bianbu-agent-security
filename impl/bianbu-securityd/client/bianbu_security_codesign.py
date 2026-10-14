"""Canonical package digest shared by the standalone client and daemon."""
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Optional

# 不参与摘要的路径：运行期产物与缓存，签名时不存在
_IGNORED_NAMES = frozenset({"__pycache__", ".git", ".mypy_cache", ".pytest_cache"})
_IGNORED_SUFFIXES = (".pyc", ".pyo")

# 包内签名文件名 —— 必须排除出摘要，否则写入签名就改了被签的摘要（自指涉）。
# 只排除这一个确定的名字，不排除 `*.sig` 这类模式：那会让包里任何
# `payload.sig` 逃出摘要覆盖范围，等于开了个夹带文件的口子。
_INTERNAL_SIG_NAME = ".signature"


def _relevant_files(root: Path) -> list[Path]:
    """参与摘要的文件，按相对路径排序（跨机器可复现）。"""
    out = []
    for p in root.rglob("*"):
        if p.is_symlink():
            # 符号链接不参与：其目标在签名者与校验者机器上可能不同，
            # 会让摘要不可复现；PA 的 loader 本身也拒绝符号链接。
            continue
        if not p.is_file():
            continue
        parts = p.relative_to(root).parts
        if any(seg in _IGNORED_NAMES for seg in parts):
            continue
        if p.name.endswith(_IGNORED_SUFFIXES):
            continue
        if parts == (_INTERNAL_SIG_NAME,):
            continue        # 包内签名文件本身不进摘要（见 _INTERNAL_SIG_NAME）
        out.append(p)
    return sorted(out, key=lambda x: x.relative_to(root).as_posix())


def compute_digest(pkg_path: str | Path) -> str:
    """代码包的规范摘要 sha256(hex)。

    喂进哈希的是 `<相对路径>\\0<文件字节>\\0` 序列 —— 路径也进摘要，
    所以重命名文件、增删文件都会改摘要。单个文件被换掉更不必说。
    """
    root = Path(pkg_path).resolve()
    if root.is_file():
        files, base = [root], root.parent
    elif root.is_dir():
        files, base = _relevant_files(root), root
    else:
        raise FileNotFoundError(f"代码包不存在：{pkg_path}")

    h = hashlib.sha256()
    for f in files:
        h.update(f.relative_to(base).as_posix().encode("utf-8"))
        h.update(b"\0")
        h.update(f.read_bytes())
        h.update(b"\0")
    return h.hexdigest()


def _signature_file(root: Path) -> Optional[Path]:
    """签名文件位置：`<pkg>.sig`，或目录内的 `.signature`。

    两种都支持：前者便于包外分发（不改包内容也就不改摘要），
    后者便于打包进 tar —— 后者已在 `_relevant_files` 里排除出摘要，
    不会自指涉。
    """
    external = root.parent / (root.name + ".sig")
    if external.exists():
        return external
    internal = root / _INTERNAL_SIG_NAME if root.is_dir() else None
    if internal is not None and internal.exists():
        return internal
    return None


def describe_code_package(pkg_path: str | Path) -> tuple[str, str]:
    """在调用方命名空间读取包，返回规范摘要与可选分离签名文本。

    生产 securityd 使用 ``PrivateTmp``/``ProtectHome``，不能安全地通过调用方传入
    的路径读取其临时目录或 home。本函数供受信 installer 在本地读取，随后只把
    digest/signature 发送给 securityd 验证信任根。
    """
    root = Path(pkg_path).expanduser().resolve()
    digest = compute_digest(root)
    sig_file = _signature_file(root)
    return digest, sig_file.read_text().strip() if sig_file is not None else ""


