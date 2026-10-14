"""生成测试 Agent 包 fixtures（HMA-02/03）。

产出：
  test-security-agent/         有效包（manifest.toml + manifest.toml.sig + pubkey.hex）
  no-sig-agent/                占位签名（无效）
  no-manifest/                 无 manifest.toml
覆盖 allow/ask/deny 三种策略 + 网络（工具名取自 runtime 工具目录）。
"""
from __future__ import annotations

from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

HERE = Path(__file__).resolve().parent

MANIFEST_BODY = """[agent]
id        = "com.bianbu.test-security-agent"
version   = "1.0.0"
name      = "Hermes Security Test Agent"
signature = "ed25519:PLACEHOLDER"

[permissions]
read_file     = "allow"
search_files  = "allow"
write_file    = "ask"
terminal      = "ask"
process       = "deny"

[permissions.network]
allowed_domains  = ["test.bianbu.local"]
"""


def _payload_for_signing(raw: str) -> bytes:
    lines = [ln for ln in raw.splitlines() if not ln.strip().startswith("signature")]
    return ("\n".join(lines)).encode("utf-8")


def make_valid_agent() -> Path:
    pkg = HERE / "test-security-agent"
    pkg.mkdir(parents=True, exist_ok=True)
    manifest_path = pkg / "manifest.toml"
    manifest_path.write_text(MANIFEST_BODY)

    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    from cryptography.hazmat.primitives import serialization
    pub_bytes = pub.public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
    sig = priv.sign(_payload_for_signing(MANIFEST_BODY))

    (pkg / "manifest.toml.sig").write_text(sig.hex())
    (pkg / "pubkey.hex").write_text(pub_bytes.hex())
    return pkg


def make_no_sig_agent() -> Path:
    pkg = HERE / "no-sig-agent"
    pkg.mkdir(parents=True, exist_ok=True)
    (pkg / "manifest.toml").write_text(MANIFEST_BODY)  # signature=PLACEHOLDER，无 .sig 文件
    return pkg


def make_no_manifest() -> Path:
    pkg = HERE / "no-manifest"
    pkg.mkdir(parents=True, exist_ok=True)
    (pkg / "README").write_text("no manifest here")
    return pkg


def main() -> None:
    v = make_valid_agent()
    make_no_sig_agent()
    make_no_manifest()
    print(f"fixtures generated under {HERE}")
    print(f"  valid: {v}")


if __name__ == "__main__":
    main()
