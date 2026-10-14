"""代码签名校验（D-6 / BN-SEC-CAPMAP-001 §6.5）—— Hook 等可执行内容的安装期门禁。

## 为什么是安装期，而不是运行期判权

Hook 是可执行代码，权力**大于** tool：它挂在 8 个干预点上，能读改整个
run 的上下文。但它此前没有任何判权 —— 装上即全权。

给每个 hook 一条 `hook.<id>` 能力做运行期判权，有个根本矛盾：
**securityd 的判权入口本身就是 hook**（`security.before_tool`），
用 hook 判 hook 会循环依赖。而且每 run × 8 个点都要判，开销也不划算。

安装期校验没有这两个问题，且能复用 manifest 已有的 ed25519 验签实现。

## 校验对象

一个"代码包"就是一个目录：hook 目录（只含 `hook.py`）、tool 目录、skill 目录。
按目录内容算规范摘要，再验这个摘要上的分离签名。

    <pkg>/                    被校验的目录
    <pkg>.sig                 分离签名（hex），签的是 digest 而非单个文件
    <keys>/*.pub              受信公钥（hex，一行一个文件）

签 digest 而非逐文件：目录里增删文件都会改 digest，所以"加一个恶意文件"
也会验签失败 —— 逐文件签名挡不住新增文件。

## 三档策略

密钥分发体系尚未建立，enforce 作默认会让**所有既有 hook 装不上**，
所以默认 `warn`。但 warn 只对**未签名**宽容：

| 情形 | off | warn（默认） | enforce |
|------|-----|--------------|---------|
| 无签名文件 | 放行 | 放行 + 告警 + 审计 | 拒绝 |
| 有签名但验不过（被篡改/密钥不受信） | 放行 | **拒绝** | 拒绝 |

「有签名却验不过」在任何档位（除 off）都硬拒：那不是"还没建签名体系"，
而是明确的篡改信号 —— 对它宽容等于签名机制形同虚设。

策略用 BIANBU_SECURITY_CODESIGN=off|warn|enforce 覆盖。
"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from . import config
from client.bianbu_security_codesign import (
    compute_digest, describe_code_package, _signature_file,
)

logger = logging.getLogger("bianbu-security.codesign")

__all__ = [
    "SignatureVerdict",
    "codesign_policy",
    "compute_digest",
    "describe_code_package",
    "verify_code_package",
    "verify_code_digest",
    "trusted_keys_dir",
    "revoked_keys_file",
    "revoked_key_ids",
    "is_trusted_public_key",
    "prevents_rollback",
]

_POLICIES = ("off", "warn", "enforce")
_DEFAULT_POLICY = "warn"

def _version_tuple(version: str) -> tuple[int, ...]:
    """仅接受数字点分版本，避免词典序绕过防回滚。"""
    try:
        parts = tuple(int(x) for x in version.strip().split("."))
        if not parts or any(x < 0 for x in parts):
            raise ValueError
        return parts
    except (TypeError, ValueError):
        return ()


def prevents_rollback(current: str, candidate: str) -> bool:
    """返回 candidate 是否允许覆盖 current；版本必须不降低。"""
    old, new = _version_tuple(current), _version_tuple(candidate)
    return bool(old and new and new >= old)


def codesign_policy() -> str:
    """代码签名策略：off | warn | enforce。"""
    v = (os.environ.get("BIANBU_SECURITY_CODESIGN") or "").strip().lower()
    return v if v in _POLICIES else _DEFAULT_POLICY


def trusted_keys_dir() -> Path:
    """受信公钥目录。默认 <ETC>/codesign-keys，可用 env 覆盖。"""
    v = os.environ.get("BIANBU_SECURITY_CODESIGN_KEYS")
    return Path(v) if v else (config.ETC_DIR / "codesign-keys")


def revoked_keys_file() -> Path:
    """吊销清单：每行一个公钥文件名（如 dev.pub）。"""
    v = os.environ.get("BIANBU_SECURITY_CODESIGN_REVOKED")
    return Path(v) if v else trusted_keys_dir() / "revoked.list"


def revoked_key_ids() -> set[str]:
    try:
        return {line.strip() for line in revoked_keys_file().read_text().splitlines()
                if line.strip() and not line.lstrip().startswith("#")}
    except OSError:
        return set()


def is_trusted_public_key(pubkey_hex: str) -> tuple[bool, str]:
    """判断 manifest 携带的公钥是否属于部署信任根，并返回 key id。"""
    normalized = pubkey_hex.strip().lower()
    if len(normalized) != 64:
        return False, "公钥长度非法"
    try:
        bytes.fromhex(normalized)
    except ValueError:
        return False, "公钥不是合法 hex"
    revoked = revoked_key_ids()
    for key_id, trusted in _load_trusted_keys():
        if key_id in revoked:
            continue
        if trusted.strip().lower() == normalized:
            return True, key_id
    return False, "公钥不在部署信任根或已吊销"


def enforce_ready() -> tuple[bool, str]:
    """enforce 发布门禁：策略为 enforce 时必须存在可读受信公钥。"""
    if codesign_policy() != "enforce":
        return True, "policy_not_enforce"
    d = trusted_keys_dir()
    keys = [p for p in d.glob("*.pub") if p.is_file()]
    if not keys:
        return False, f"enforce requires trusted public key in {d}"
    revoked = revoked_key_ids()
    usable = 0
    for p in keys:
        if p.name in revoked:
            continue
        try:
            raw = p.read_text().strip()
            if len(bytes.fromhex(raw)) != 32:
                return False, f"invalid Ed25519 public key: {p.name}"
        except (OSError, ValueError):
            return False, f"invalid Ed25519 public key: {p.name}"
        usable += 1
    if not usable:
        return False, f"all trusted public keys are revoked in {revoked_keys_file()}"
    return True, "ready"


@dataclass(frozen=True)
class SignatureVerdict:
    """校验结论。

    `allowed` 是给调用方的最终答案（已把策略算进去）；
    `signed` / `valid` / `reason` 供审计与运维排查。
    """

    allowed: bool
    signed: bool          # 是否找到签名文件
    valid: bool           # 签名是否验证通过（signed=False 时无意义）
    digest: str
    policy: str
    reason: str = ""
    key_id: str = ""      # 验过的公钥文件名，便于追溯"谁签的"

    def to_dict(self) -> dict:
        return {
            "allowed": self.allowed, "signed": self.signed, "valid": self.valid,
            "digest": self.digest, "policy": self.policy,
            "reason": self.reason, "key_id": self.key_id,
        }


def verify_code_digest(digest: str, signature: str = "", *,
                       kind: str = "hook", package_label: str = "package") -> SignatureVerdict:
    """验证调用方已计算的规范摘要，避免跨 systemd mount namespace 传路径。"""
    policy = codesign_policy()
    digest = str(digest).strip().lower()
    try:
        if len(digest) != 64 or len(bytes.fromhex(digest)) != 32:
            raise ValueError
    except ValueError:
        return SignatureVerdict(False, bool(signature), False, "", policy,
                                "代码包摘要必须是 32 字节 SHA-256 hex")

    sig = str(signature or "").strip()
    if not sig:
        if policy == "enforce":
            return SignatureVerdict(
                False, False, False, digest, policy,
                f"{kind} 未签名，策略 enforce 拒绝安装（包={package_label}）")
        if policy == "warn":
            logger.warning("%s %s 未签名（digest=%s…）—— 当前策略 warn 放行",
                           kind, package_label, digest[:16])
        return SignatureVerdict(True, False, False, digest, policy,
                                f"{kind} 未签名（策略 {policy} 放行）")

    if policy == "off":
        return SignatureVerdict(True, True, False, digest, policy, "策略 off，不校验")
    if ":" in sig:
        algo, _, sig = sig.partition(":")
        if algo.strip().lower() != "ed25519":
            return SignatureVerdict(False, True, False, digest, policy,
                                    f"不支持的签名算法 {algo}")
    sig = sig.strip()
    keys = _load_trusted_keys()
    if not keys:
        return SignatureVerdict(
            False, True, False, digest, policy,
            f"{kind} 已签名但无受信公钥可验（请配置 {trusted_keys_dir()}）")

    from .manifest import _verify_ed25519
    from .errors import InvalidManifest

    payload = digest.encode("ascii")
    for key_id, hexkey in keys:
        try:
            if _verify_ed25519(hexkey, sig, payload):
                return SignatureVerdict(True, True, True, digest, policy, "", key_id)
        except (InvalidManifest, ValueError) as exc:
            logger.debug("公钥 %s 验签异常：%s", key_id, exc)
    return SignatureVerdict(
        False, True, False, digest, policy,
        f"{kind} 签名校验失败（内容被改动，或签名者不在受信公钥列表内）；"
        f"digest={digest[:16]}…")


def _load_trusted_keys() -> list[tuple[str, str]]:
    """读受信公钥，返回 [(key_id, pubkey_hex)]。目录不存在则为空。"""
    d = trusted_keys_dir()
    if not d.is_dir():
        return []
    keys = []
    revoked = revoked_key_ids()
    for p in sorted(d.glob("*.pub")):
        if p.name in revoked:
            logger.warning("代码签名公钥 %s 已吊销，跳过", p.name)
            continue
        try:
            hexkey = p.read_text().strip()
        except OSError as e:
            logger.warning("公钥 %s 读取失败：%s", p, e)
            continue
        if hexkey:
            keys.append((p.name, hexkey))
    return keys


def verify_code_package(pkg_path: str | Path, *,
                        kind: str = "hook") -> SignatureVerdict:
    """校验一个代码包，返回是否放行安装。

    kind 只进审计文本，不影响判定 —— hook / tool / skill 用同一套规则。
    """
    policy = codesign_policy()
    root = Path(pkg_path).expanduser()
    if not root.exists():
        return SignatureVerdict(False, False, False, "", policy,
                                f"代码包不存在：{pkg_path}")
    root = root.resolve()

    try:
        digest = compute_digest(root)
    except OSError as e:
        return SignatureVerdict(policy == "off", False, False, "", policy,
                                f"摘要计算失败：{e}")

    sig_file = _signature_file(root)
    try:
        signature = sig_file.read_text().strip() if sig_file is not None else ""
    except OSError as e:
        return SignatureVerdict(False, True, False, digest, policy,
                                f"签名文件读取失败：{e}")
    return verify_code_digest(digest, signature, kind=kind,
                              package_label=root.name)


def sign_digest_hex(privkey_hex: str, digest: str) -> str:
    """给定 ed25519 私钥（hex）对摘要签名，返回签名 hex。

    仅供开发/测试与打包工具用；生产签名应在离线机器上做。
    """
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
        )
        sk = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(privkey_hex))
        return sk.sign(digest.encode("ascii")).hex()
    except ImportError:
        import nacl.signing
        sk = nacl.signing.SigningKey(bytes.fromhex(privkey_hex))
        return sk.sign(digest.encode("ascii")).signature.hex()
