"""Manifest 校验（FR-SEC-01 / CAP-01）。

- TOML 解析（[agent] + [permissions] + [permissions.network]）
- ed25519 签名验证（优先 cryptography，回退 pynacl）
- 约束校验：policy ∈ {allow, ask, deny}
- Agent 包结构：<pkg>/manifest.toml + <pkg>/manifest.toml.sig(可选，raw ed25519) + 公钥
"""
from __future__ import annotations

import tomllib
from pathlib import Path

from .errors import InvalidManifest
from .models import Manifest, Permission, Policy


_RUNTIME_KEYS = frozenset({"entrypoint"})


def _verify_ed25519(pubkey_hex: str, signature_hex: str, payload: bytes) -> bool:
    """用 cryptography 验证 ed25519 签名，回退 pynacl。签名/公钥均为 hex。"""
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PublicKey,
        )
        from cryptography.exceptions import InvalidSignature

        pk = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pubkey_hex))
        try:
            pk.verify(bytes.fromhex(signature_hex), payload)
            return True
        except InvalidSignature:
            return False
    except ImportError:
        pass
    try:  # 回退 pynacl
        import nacl.signing
        import nacl.exceptions

        vk = nacl.signing.VerifyKey(bytes.fromhex(pubkey_hex))
        try:
            vk.verify(payload, bytes.fromhex(signature_hex))
            return True
        except nacl.exceptions.BadSignatureError:
            return False
    except ImportError as e:
        raise InvalidManifest(f"无可用 ed25519 后端: {e}") from e


_NETWORK_MODES = frozenset({"whitelist", "deny_all", "allow_all", "learning"})
_FRAMEWORKS = frozenset({"runtime", "hermes"})


def _parse_framework(agent_block: dict) -> str:
    """读取 [agent].framework；未声明返回空串（目录范围未知）。

    A signed package declares which framework's tool catalog it is wired to,
    so the console lists exactly those tools.  An unknown value is rejected
    instead of silently showing the wrong catalog.
    """
    raw = agent_block.get("framework", "")
    value = str(raw or "").strip().lower()
    if value and value not in _FRAMEWORKS:
        raise InvalidManifest(
            f"[agent].framework 不支持: {value}（可选 runtime / hermes）")
    return value


def _parse_permissions(perms_block: dict) -> tuple[list[Permission], list[str], str]:
    """解析 [permissions] 块，返回 (权限列表, 网络域名, 网络模式)。"""
    permissions: list[Permission] = []
    allowed_domains: list[str] = []
    network_mode = "allow_all"

    for key, val in perms_block.items():
        if key == "network":
            if isinstance(val, dict):
                allowed_domains = list(val.get("allowed_domains", []))
                # Older manifests used allowed_domains without a mode. Keep
                # their restrictive whitelist semantics; newly generated
                # manifests always carry an explicit mode.
                default_mode = "whitelist" if allowed_domains else "allow_all"
                network_mode = str(val.get("mode", default_mode)).strip().lower()
                if network_mode not in _NETWORK_MODES:
                    raise InvalidManifest(f"网络策略 mode 不支持: {network_mode}")
            continue
        # 权限项可以是裸字符串（policy 值），也可以是 {policy=...} 表。
        if isinstance(val, str):
            raw_policy = val
        elif isinstance(val, dict):
            raw_policy = val.get("policy", val.get("confirm", ""))
        else:
            raise InvalidManifest(f"权限项 {key} 必须为字符串或表，实际为 {type(val)}")
        try:
            perm = Permission(tool=str(key), policy=Policy(str(raw_policy)))
            perm.validate()
        except ValueError as e:
            raise InvalidManifest(f"权限项 {key} 非法: {e}") from e
        permissions.append(perm)

    return permissions, allowed_domains, network_mode


def _parse_runtime(runtime_block: object) -> tuple[str, ...]:
    """Parse the optional signed Runtime binding.

    Capability-only manifests remain valid for the legacy Security API.  Once
    a package declares ``[runtime]``, however, accepting a partial or malformed
    binding would make it possible to register permissions while leaving the
    process entrypoint trust decision ambiguous. Therefore the section is
    all-or-nothing and is validated before signature verification.
    """
    if runtime_block is None:
        return ()
    if not isinstance(runtime_block, dict):
        raise InvalidManifest("[runtime] 必须为表（dict）")
    unknown = set(runtime_block) - _RUNTIME_KEYS
    if unknown:
        raise InvalidManifest(f"[runtime] 包含未知字段: {sorted(unknown)}")
    missing = sorted(_RUNTIME_KEYS - set(runtime_block))
    if missing:
        raise InvalidManifest(f"[runtime] 缺少字段: {', '.join(missing)}")
    raw_entrypoint = runtime_block["entrypoint"]
    if (isinstance(raw_entrypoint, (str, bytes)) or
            not isinstance(raw_entrypoint, (list, tuple)) or not raw_entrypoint):
        raise InvalidManifest("[runtime].entrypoint 必须是非空 argv 数组")
    entrypoint: list[str] = []
    for item in raw_entrypoint:
        if not isinstance(item, str) or not item.strip() or "\x00" in item:
            raise InvalidManifest("[runtime].entrypoint 含非法 argv")
        entrypoint.append(item.strip())
    return tuple(entrypoint)


def parse_manifest_bytes(raw: bytes, *, allow_unsigned: bool = False) -> Manifest:
    """解析 manifest.toml 内容为 Manifest 对象（不验签）。

    ``allow_unsigned`` 只供显式 ``BIANBU_SECURITY_CODESIGN=off`` 的开发/演示
    安装路径使用；默认及产品路径仍要求 signature 字段。
    """
    try:
        data = tomllib.loads(raw.decode("utf-8"))
    except (tomllib.TOMLDecodeError, UnicodeDecodeError) as e:
        raise InvalidManifest(f"manifest.toml 解析失败: {e}") from e

    agent = data.get("agent")
    if not agent:
        raise InvalidManifest("缺少 [agent] 段")
    required = ("id", "version", "name") if allow_unsigned else (
        "id", "version", "name", "signature")
    for f in required:
        if f not in agent:
            raise InvalidManifest(f"[agent] 缺少字段: {f}")

    perms, domains, network_mode = _parse_permissions(data.get("permissions", {}))
    runtime_entrypoint = _parse_runtime(data.get("runtime"))
    framework = _parse_framework(agent)
    return Manifest(
        agent_id=str(agent["id"]),
        version=str(agent["version"]),
        name=str(agent["name"]),
        signature=str(agent.get("signature", "")),
        permissions=perms,
        allowed_domains=domains,
        network_mode=network_mode,
        runtime_entrypoint=runtime_entrypoint,
        framework=framework,
    )


def verify_manifest(pkg_path: str) -> tuple[bool, str, Manifest | None]:
    """校验 Agent 包（FR-SEC-01）。

    包目录结构：
      <pkg>/manifest.toml         必需
      <pkg>/manifest.toml.sig     ed25519 签名(hex)，对 manifest.toml 原文
      <pkg>/pubkey.hex            开发者公钥(hex)
    signature 字段格式 "ed25519:<hex>" 时优先取字段内签名。

    返回 (valid, reason, manifest)。
    """
    pkg = Path(pkg_path)
    manifest_file = pkg / "manifest.toml" if pkg.is_dir() else pkg
    if not manifest_file.exists():
        return False, "manifest.toml not found", None

    from .code_signing import codesign_policy

    policy = codesign_policy()
    raw = manifest_file.read_bytes()
    try:
        manifest = parse_manifest_bytes(raw, allow_unsigned=policy == "off")
    except InvalidManifest as e:
        return False, str(e), None

    # Development/demo delivery explicitly disables the complete Agent
    # manifest signature gate. Structural, permission, runtime binding and
    # digest-format validation above remains active.
    if policy == "off":
        return True, "", manifest

    # 签名校验
    sig = ""
    if manifest.signature.startswith("ed25519:"):
        sig = manifest.signature.split(":", 1)[1]
    sig_file = manifest_file.with_suffix(manifest_file.suffix + ".sig")
    if sig_file.exists():
        sig = sig_file.read_text().strip()

    if not sig or sig in ("xxxx", "PLACEHOLDER", "TEST_SIGNATURE_PLACEHOLDER"):
        return False, "missing signature", None

    pubkey_file = (pkg if pkg.is_dir() else pkg.parent) / "pubkey.hex"
    if not pubkey_file.exists():
        return False, "pubkey.hex not found (无法验签)", None
    pubkey = pubkey_file.read_text().strip()

    # enforce 模式下，包内 pubkey 必须锚定到部署信任根；否则攻击者可替换
    # pubkey.hex 与 manifest.sig 自签一套新密钥，绕过供应链门禁。
    from .code_signing import is_trusted_public_key
    if policy == "enforce":
        trusted, detail = is_trusted_public_key(pubkey)
        if not trusted:
            return False, f"生产 enforce 拒绝：{detail}", None

    # 验签负载 = manifest.toml 原文（去除 signature 行影响：对整文件签名）
    payload = _payload_for_signing(raw)
    try:
        ok = _verify_ed25519(pubkey, sig, payload)
    except InvalidManifest as e:
        return False, str(e), None
    if not ok:
        return False, "invalid signature", None

    return True, "", manifest


def _payload_for_signing(raw: bytes) -> bytes:
    """签名负载：manifest.toml 中除 signature 行外的规范化内容。

    这样开发者可先写占位 signature、对文件其余内容签名，避免自指涉。
    """
    lines = []
    for line in raw.decode("utf-8").splitlines():
        if line.strip().startswith("signature"):
            continue
        lines.append(line)
    return ("\n".join(lines)).encode("utf-8")
