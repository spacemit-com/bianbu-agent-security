"""D-6 代码签名（securityd/code_signing.py）—— 安装期门禁。

Hook 是可执行代码、权力大于 tool，此前装上即全权。这里验的是：
  · 摘要对目录内容/文件名/文件数量都敏感（挡"加一个恶意文件"）
  · 未签名 → 按策略（enforce 拒、warn/off 放行但留痕）
  · 有签名却验不过 → 任何非 off 策略都硬拒（篡改信号，不是"体系未建"）
"""
from __future__ import annotations

import pytest


@pytest.fixture
def keys_dir(tmp_path, monkeypatch):
    d = tmp_path / "codesign-keys"
    d.mkdir()
    monkeypatch.setenv("BIANBU_SECURITY_CODESIGN_KEYS", str(d))
    return d


@pytest.fixture
def pkg(tmp_path):
    """一个最小 hook 包。"""
    p = tmp_path / "security.demo"
    p.mkdir()
    (p / "hook.py").write_text("def create_hook(context): return None\n")
    return p


@pytest.fixture
def keypair():
    """(privkey_hex, pubkey_hex)。无 ed25519 后端则跳过整组测试。"""
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
        )
    except ImportError:  # pragma: no cover
        pytest.skip("无 cryptography，跳过签名用例")
    sk = Ed25519PrivateKey.generate()
    priv = sk.private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
        serialization.NoEncryption()).hex()
    pub = sk.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    return priv, pub


def _sign(pkg, priv, keys_dir=None, pub=None):
    from securityd import code_signing as cs

    if keys_dir is not None and pub is not None:
        (keys_dir / "dev.pub").write_text(pub)
    sig = cs.sign_digest_hex(priv, cs.compute_digest(pkg))
    (pkg.parent / (pkg.name + ".sig")).write_text("ed25519:" + sig)
    return sig


class TestPolicy:
    def test_default_is_warn(self, monkeypatch):
        from securityd.code_signing import codesign_policy

        monkeypatch.delenv("BIANBU_SECURITY_CODESIGN", raising=False)
        assert codesign_policy() == "warn"

    def test_illegal_value_falls_back_to_warn(self, monkeypatch):
        """配置写错不该变成 off —— 那等于静默关掉门禁。"""
        from securityd.code_signing import codesign_policy

        monkeypatch.setenv("BIANBU_SECURITY_CODESIGN", "enfroce")   # 手滑
        assert codesign_policy() == "warn"

    @pytest.mark.parametrize("v", ["off", "warn", "enforce"])
    def test_env_override(self, monkeypatch, v):
        from securityd.code_signing import codesign_policy

        monkeypatch.setenv("BIANBU_SECURITY_CODESIGN", v)
        assert codesign_policy() == v

    def test_version_rollback_guard(self):
        from securityd.code_signing import prevents_rollback
        assert prevents_rollback("1.0.0", "1.0.1")
        assert prevents_rollback("1.0.0", "1.0.0")
        assert not prevents_rollback("1.0.1", "1.0.0")
        assert not prevents_rollback("main", "2.0.0")


class TestDigest:
    def test_stable_across_calls(self, pkg):
        from securityd.code_signing import compute_digest

        assert compute_digest(pkg) == compute_digest(pkg)

    def test_content_change_changes_digest(self, pkg):
        from securityd.code_signing import compute_digest

        before = compute_digest(pkg)
        (pkg / "hook.py").write_text("def create_hook(c): import os\n")
        assert compute_digest(pkg) != before

    def test_added_file_changes_digest(self, pkg):
        """逐文件签名挡不住"新增恶意文件"，摘要必须挡住。"""
        from securityd.code_signing import compute_digest

        before = compute_digest(pkg)
        (pkg / "evil.py").write_text("import os\n")
        assert compute_digest(pkg) != before

    def test_rename_changes_digest(self, pkg):
        from securityd.code_signing import compute_digest

        before = compute_digest(pkg)
        (pkg / "hook.py").rename(pkg / "hook2.py")
        assert compute_digest(pkg) != before

    def test_pycache_ignored(self, pkg):
        """运行期产物不能改摘要，否则装完跑一次就"验签失败"。"""
        from securityd.code_signing import compute_digest

        before = compute_digest(pkg)
        cache = pkg / "__pycache__"
        cache.mkdir()
        (cache / "hook.cpython-313.pyc").write_bytes(b"\x00\x01")
        assert compute_digest(pkg) == before

    def test_dot_sig_files_inside_package_are_covered(self, pkg):
        """包内 `*.sig` 必须进摘要 —— 只有 `.signature` 这一个名字例外。

        早期实现按 `.endswith(".sig")` 整类排除，等于给"夹带 payload.sig"
        开了口子：改它不改摘要，签名验得过。
        """
        from securityd.code_signing import compute_digest

        before = compute_digest(pkg)
        (pkg / "payload.sig").write_text("smuggled\n")
        assert compute_digest(pkg) != before, "包内 .sig 逃出了摘要覆盖"

    def test_missing_package(self, tmp_path):
        from securityd.code_signing import compute_digest

        with pytest.raises(FileNotFoundError):
            compute_digest(tmp_path / "nope")

    def test_describe_returns_digest_and_external_signature(self, pkg):
        from securityd.code_signing import describe_code_package

        (pkg.parent / (pkg.name + ".sig")).write_text("ed25519:abcd")
        digest, signature = describe_code_package(pkg)
        assert len(digest) == 64
        assert signature == "ed25519:abcd"

    def test_digest_api_rejects_malformed_digest(self, keys_dir, monkeypatch):
        from securityd.code_signing import verify_code_digest

        monkeypatch.setenv("BIANBU_SECURITY_CODESIGN", "warn")
        verdict = verify_code_digest("not-sha256", "")
        assert not verdict.allowed
        assert "SHA-256" in verdict.reason


class TestUnsigned:
    def test_enforce_rejects(self, pkg, keys_dir, monkeypatch):
        from securityd.code_signing import verify_code_package

        monkeypatch.setenv("BIANBU_SECURITY_CODESIGN", "enforce")
        v = verify_code_package(pkg)
        assert v.allowed is False and v.signed is False
        assert "未签名" in v.reason

    @pytest.mark.parametrize("policy", ["warn", "off"])
    def test_warn_and_off_allow(self, pkg, keys_dir, monkeypatch, policy):
        from securityd.code_signing import verify_code_package

        monkeypatch.setenv("BIANBU_SECURITY_CODESIGN", policy)
        v = verify_code_package(pkg)
        assert v.allowed is True and v.signed is False
        # 摘要仍要算出来 —— 运维评估 enforce 影响面时要靠它
        assert len(v.digest) == 64

    def test_manifest_public_key_trust_root_helper(self, keys_dir, keypair):
        from securityd.code_signing import is_trusted_public_key
        _priv, pub = keypair
        assert is_trusted_public_key(pub) == (False, "公钥不在部署信任根或已吊销")
        (keys_dir / "release.pub").write_text(pub)
        assert is_trusted_public_key(pub) == (True, "release.pub")


class TestEnforceReady:
    def test_non_enforce_policy_is_ready_without_keys(self, keys_dir, monkeypatch):
        from securityd.code_signing import enforce_ready

        monkeypatch.setenv("BIANBU_SECURITY_CODESIGN", "warn")
        assert enforce_ready() == (True, "policy_not_enforce")

    def test_enforce_requires_a_readable_key(self, keys_dir, monkeypatch):
        from securityd.code_signing import enforce_ready

        monkeypatch.setenv("BIANBU_SECURITY_CODESIGN", "enforce")
        ok, reason = enforce_ready()
        assert not ok and "requires trusted public key" in reason

    def test_all_trusted_keys_revoked_fail_closed(self, keys_dir, keypair, monkeypatch):
        from securityd.code_signing import enforce_ready

        _priv, pub = keypair
        (keys_dir / "release.pub").write_text(pub)
        (keys_dir / "revoked.list").write_text("release.pub\n")
        monkeypatch.setenv("BIANBU_SECURITY_CODESIGN", "enforce")
        ok, reason = enforce_ready()
        assert not ok and "all trusted public keys are revoked" in reason

    def test_enforce_accepts_at_least_one_valid_non_revoked_key(
            self, keys_dir, keypair, monkeypatch):
        from securityd.code_signing import enforce_ready

        _priv, pub = keypair
        (keys_dir / "release.pub").write_text(pub)
        (keys_dir / "revoked.list").write_text("other.pub\n")
        monkeypatch.setenv("BIANBU_SECURITY_CODESIGN", "enforce")
        assert enforce_ready() == (True, "ready")


class TestSigned:
    @pytest.mark.parametrize("policy", ["warn", "enforce"])
    def test_valid_signature_allowed(self, pkg, keys_dir, keypair, monkeypatch, policy):
        from securityd.code_signing import verify_code_package

        priv, pub = keypair
        _sign(pkg, priv, keys_dir, pub)
        monkeypatch.setenv("BIANBU_SECURITY_CODESIGN", policy)
        v = verify_code_package(pkg)
        assert v.allowed is True and v.signed and v.valid
        assert v.key_id == "dev.pub"

    def test_digest_signature_api_matches_path_api(
            self, pkg, keys_dir, keypair, monkeypatch):
        from securityd import code_signing as cs

        priv, pub = keypair
        _sign(pkg, priv, keys_dir, pub)
        monkeypatch.setenv("BIANBU_SECURITY_CODESIGN", "enforce")
        digest, signature = cs.describe_code_package(pkg)
        by_digest = cs.verify_code_digest(digest, signature, kind="hook")
        by_path = cs.verify_code_package(pkg, kind="hook")
        assert by_digest.allowed and by_digest.valid
        assert by_digest.to_dict() == by_path.to_dict()

    @pytest.mark.parametrize("policy", ["warn", "enforce"])
    def test_tampered_rejected_even_in_warn(self, pkg, keys_dir, keypair,
                                            monkeypatch, policy):
        """核心断言：warn 只对未签名宽容，对篡改不宽容。"""
        from securityd.code_signing import verify_code_package

        priv, pub = keypair
        _sign(pkg, priv, keys_dir, pub)
        (pkg / "hook.py").write_text("import os; os.system('rm -rf /')\n")
        monkeypatch.setenv("BIANBU_SECURITY_CODESIGN", policy)
        v = verify_code_package(pkg)
        assert v.allowed is False and v.signed is True and v.valid is False

    def test_added_file_rejected(self, pkg, keys_dir, keypair, monkeypatch):
        from securityd.code_signing import verify_code_package

        priv, pub = keypair
        _sign(pkg, priv, keys_dir, pub)
        (pkg / "backdoor.py").write_text("pass\n")
        monkeypatch.setenv("BIANBU_SECURITY_CODESIGN", "warn")
        assert verify_code_package(pkg).allowed is False

    def test_untrusted_signer_rejected(self, pkg, keys_dir, keypair, monkeypatch):
        """签名有效但签名者不在受信列表 —— 拒绝。"""
        from securityd.code_signing import verify_code_package

        priv, _pub = keypair
        _sign(pkg, priv)               # 不写入公钥
        monkeypatch.setenv("BIANBU_SECURITY_CODESIGN", "warn")
        v = verify_code_package(pkg)
        assert v.allowed is False
        assert "受信公钥" in v.reason

    def test_wrong_key_rejected(self, pkg, keys_dir, keypair, monkeypatch):
        from securityd.code_signing import verify_code_package

        try:
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric.ed25519 import (
                Ed25519PrivateKey,
            )
        except ImportError:  # pragma: no cover
            pytest.skip("无 cryptography")
        priv, _ = keypair
        other = Ed25519PrivateKey.generate().public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
        _sign(pkg, priv, keys_dir, other)      # 装的是别人的公钥
        monkeypatch.setenv("BIANBU_SECURITY_CODESIGN", "warn")
        assert verify_code_package(pkg).allowed is False

    def test_revoked_key_rejected(self, pkg, keys_dir, keypair, monkeypatch):
        from securityd.code_signing import verify_code_package
        priv, pub = keypair
        _sign(pkg, priv, keys_dir, pub)
        (keys_dir / "revoked.list").write_text("dev.pub\n")
        monkeypatch.setenv("BIANBU_SECURITY_CODESIGN", "enforce")
        assert verify_code_package(pkg).allowed is False

    def test_off_skips_verification(self, pkg, keys_dir, keypair, monkeypatch):
        from securityd.code_signing import verify_code_package

        priv, pub = keypair
        _sign(pkg, priv, keys_dir, pub)
        (pkg / "hook.py").write_text("evil\n")
        monkeypatch.setenv("BIANBU_SECURITY_CODESIGN", "off")
        assert verify_code_package(pkg).allowed is True

    def test_bare_hex_signature_accepted(self, pkg, keys_dir, keypair, monkeypatch):
        """签名文件可以不带 "ed25519:" 前缀。"""
        from securityd import code_signing as cs

        priv, pub = keypair
        (keys_dir / "dev.pub").write_text(pub)
        (pkg.parent / (pkg.name + ".sig")).write_text(
            cs.sign_digest_hex(priv, cs.compute_digest(pkg)))
        monkeypatch.setenv("BIANBU_SECURITY_CODESIGN", "enforce")
        assert cs.verify_code_package(pkg).allowed is True

    def test_unknown_algo_rejected(self, pkg, keys_dir, keypair, monkeypatch):
        from securityd.code_signing import verify_code_package

        priv, pub = keypair
        (keys_dir / "dev.pub").write_text(pub)
        (pkg.parent / (pkg.name + ".sig")).write_text("rsa:deadbeef")
        monkeypatch.setenv("BIANBU_SECURITY_CODESIGN", "warn")
        v = verify_code_package(pkg)
        assert v.allowed is False and "不支持的签名算法" in v.reason

    def test_internal_signature_file_not_self_referential(
            self, pkg, keys_dir, keypair, monkeypatch):
        """包内 .signature 不能进摘要，否则写入签名就改了被签的摘要。"""
        from securityd import code_signing as cs

        priv, pub = keypair
        (keys_dir / "dev.pub").write_text(pub)
        digest = cs.compute_digest(pkg)
        (pkg / ".signature").write_text("ed25519:" + cs.sign_digest_hex(priv, digest))
        assert cs.compute_digest(pkg) == digest        # 摘要没变
        monkeypatch.setenv("BIANBU_SECURITY_CODESIGN", "enforce")
        assert cs.verify_code_package(pkg).allowed is True


class TestEngineIntegration:
    def test_engine_audits_verdict(self, pkg, keys_dir, monkeypatch, tmp_path):
        """装不上要留痕；未签名放行也要留痕，否则无法评估 enforce 影响面。"""
        monkeypatch.setenv("BIANBU_SEC_ROOT", str(tmp_path / "root"))
        monkeypatch.setenv("BIANBU_SECURITY_CODESIGN", "warn")
        import importlib

        from securityd import config

        importlib.reload(config)
        from securityd.engine import SecurityEngine

        eng = SecurityEngine()
        try:
            d = eng.verify_code_package(str(pkg), "hook")
            assert d["allowed"] is True and d["signed"] is False
            assert d["policy"] == "warn" and len(d["digest"]) == 64
            export = eng.export_audit('{"agent_id": "system"}', "json")
            import json
            from pathlib import Path

            rows = json.loads(Path(export).read_text())
            entries = rows["records"]
            assert any(e.get("op_type") == "verify_code_package" for e in entries), \
                "未写审计 —— 运维看不到有包在被校验"
        finally:
            eng.close()
            importlib.reload(config)
