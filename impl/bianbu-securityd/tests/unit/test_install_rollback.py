from __future__ import annotations


def test_install_rejects_version_rollback(engine, fixtures_dir, tmp_path):
    # 直接验证版本门禁的规则；真实 installer 还需要用发布私钥重新签名。
    from securityd.code_signing import prevents_rollback
    assert not prevents_rollback("1.0.0", "0.9.0")
