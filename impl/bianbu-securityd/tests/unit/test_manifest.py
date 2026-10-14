"""TC-UNIT-01~03：Manifest 校验（有效/无签名/无 manifest）。"""
from __future__ import annotations

import pytest


def test_valid_manifest(sec_root, fixtures_dir):  # TC-UNIT-01
    from securityd.manifest import verify_manifest
    valid, reason, m = verify_manifest(str(fixtures_dir / "test-security-agent"))
    assert valid is True, reason
    assert m is not None
    assert len(m.permissions) == 5
    caps = {p.tool for p in m.permissions}
    assert caps == {"read_file", "search_files", "write_file",
                    "terminal", "process"}


def test_no_signature(sec_root, fixtures_dir):  # TC-UNIT-02
    from securityd.manifest import verify_manifest
    valid, reason, m = verify_manifest(str(fixtures_dir / "no-sig-agent"))
    assert valid is False
    assert "signature" in reason


def test_off_policy_allows_unsigned_manifest_without_public_key(
        sec_root, fixtures_dir, tmp_path, monkeypatch):
    """开发/演示 off 不要求 signature、.sig 或 pubkey.hex。"""
    import shutil
    from securityd.manifest import verify_manifest

    src = fixtures_dir / "no-sig-agent"
    dst = tmp_path / "unsigned-demo-agent"
    shutil.copytree(src, dst)
    manifest = dst / "manifest.toml"
    manifest.write_text("\n".join(
        line for line in manifest.read_text().splitlines()
        if not line.strip().startswith("signature")) + "\n")

    monkeypatch.setenv("BIANBU_SECURITY_CODESIGN", "off")
    valid, reason, parsed = verify_manifest(str(dst))

    assert valid is True, reason
    assert parsed is not None
    assert parsed.signature == ""
    assert len(parsed.permissions) == 5


def test_warn_policy_still_rejects_manifest_without_signature_field(
        sec_root, fixtures_dir, tmp_path, monkeypatch):
    """demo 例外不能削弱 warn/enforce 的结构与签名要求。"""
    import shutil
    from securityd.manifest import verify_manifest

    src = fixtures_dir / "no-sig-agent"
    dst = tmp_path / "unsigned-warn-agent"
    shutil.copytree(src, dst)
    manifest = dst / "manifest.toml"
    manifest.write_text("\n".join(
        line for line in manifest.read_text().splitlines()
        if not line.strip().startswith("signature")) + "\n")

    monkeypatch.setenv("BIANBU_SECURITY_CODESIGN", "warn")
    valid, reason, parsed = verify_manifest(str(dst))

    assert valid is False
    assert "signature" in reason
    assert parsed is None


def test_no_manifest(sec_root, fixtures_dir):  # TC-UNIT-03
    from securityd.manifest import verify_manifest
    valid, reason, m = verify_manifest(str(fixtures_dir / "no-manifest"))
    assert valid is False
    assert "not found" in reason


def test_tampered_manifest_bad_signature(sec_root, fixtures_dir, tmp_path):
    """篡改 manifest 内容 → 签名失配。"""
    import shutil
    from securityd.manifest import verify_manifest
    src = fixtures_dir / "test-security-agent"
    dst = tmp_path / "tampered"
    shutil.copytree(src, dst)
    # 篡改：把 L3 改成 trusted 之外的内容（改 name 即可破坏签名负载）
    mf = dst / "manifest.toml"
    mf.write_text(mf.read_text().replace("Hermes Security Test Agent", "Evil Agent"))
    valid, reason, m = verify_manifest(str(dst))
    assert valid is False
    assert "signature" in reason.lower()

def test_runtime_binding_is_parsed_and_validated(sec_root, tmp_path):
    from securityd.manifest import parse_manifest_bytes

    raw = b'''[agent]
id = "com.example.runtime"
version = "1.0.0"
name = "Runtime Agent"
signature = "ed25519:PLACEHOLDER"

[runtime]
entrypoint = ["/usr/bin/bianbu-agent", "--role", "agent-worker"]
'''
    manifest = parse_manifest_bytes(raw)
    assert manifest.runtime_entrypoint == (
        "/usr/bin/bianbu-agent", "--role", "agent-worker")


@pytest.mark.parametrize(
    "runtime, expected",
    [
        ('entrypoint = []\n', "entrypoint"),
        ('entrypoint = ["/usr/bin/a"]\npackage_digest = "bad"\n', "未知字段"),
        ('entrypoint = ["/usr/bin/a"]\nconfig_digest = "bad"\n', "未知字段"),
    ],
)
def test_runtime_binding_rejects_partial_or_malformed_values(runtime, expected):
    from securityd.errors import InvalidManifest
    from securityd.manifest import parse_manifest_bytes

    raw = (
        '[agent]\nid="com.example.runtime"\nversion="1.0.0"\n'
        'name="Runtime"\nsignature="ed25519:PLACEHOLDER"\n\n'
        '[runtime]\n' + runtime
    ).encode()
    with pytest.raises(InvalidManifest, match=expected):
        parse_manifest_bytes(raw)


def test_agent_framework_scopes_the_tool_catalog():
    """签名包用 [agent].framework 声明对接的框架，控制台据此限定工具目录。"""
    from securityd.manifest import parse_manifest_bytes

    base = (
        '[agent]\nid="com.example.runtime"\nversion="1.0.0"\n'
        'name="Runtime"\nsignature="ed25519:PLACEHOLDER"\n{extra}'
    )
    assert parse_manifest_bytes(
        base.format(extra='framework = "runtime"\n').encode()).framework == "runtime"
    assert parse_manifest_bytes(
        base.format(extra='framework = "hermes"\n').encode()).framework == "hermes"
    # 未声明时作用域未知，交给上层兜底，绝不猜成任一框架。
    assert parse_manifest_bytes(base.format(extra="").encode()).framework == ""
    # 大小写与两侧空白归一化后仍要识别。
    assert parse_manifest_bytes(
        base.format(extra='framework = "  Runtime  "\n').encode()).framework == "runtime"


def test_agent_framework_rejects_unknown_value():
    """未知框架要显式报错，而不是悄悄放任错误目录。"""
    from securityd.errors import InvalidManifest
    from securityd.manifest import parse_manifest_bytes

    raw = (
        '[agent]\nid="com.example.runtime"\nversion="1.0.0"\n'
        'name="Runtime"\nsignature="ed25519:PLACEHOLDER"\n'
        'framework = "openai"\n'
    ).encode()
    with pytest.raises(InvalidManifest, match="framework"):
        parse_manifest_bytes(raw)
