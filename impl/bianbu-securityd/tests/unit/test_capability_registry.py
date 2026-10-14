"""TC-UNIT-04~09：CheckPermission 算法（allow / ask / deny）。"""
from __future__ import annotations

import sqlite3

import pytest

from securityd.models import Decision, Permission, Policy


def test_network_policy_is_persisted_in_registry(tmp_path):
    from securityd.capability_registry import CapabilityRegistry
    registry = CapabilityRegistry(tmp_path / "cap.db")
    registry.register_agent("com.example.agent")
    saved = registry.set_network_policy("com.example.agent", [" API.Example.com. "], "whitelist")
    assert saved == {"agent_id": "com.example.agent", "mode": "whitelist",
                     "domains": ["api.example.com"], "version": 2}
    assert registry.get_network_policy("com.example.agent") == saved
    registry.close()


def test_register_agent_initializes_allow_all_network_policy(tmp_path):
    from securityd.capability_registry import CapabilityRegistry

    registry = CapabilityRegistry(tmp_path / "cap.db")
    try:
        registry.register_agent("com.example.new-agent")
        assert registry.get_network_policy("com.example.new-agent") == {
            "agent_id": "com.example.new-agent",
            "mode": "allow_all",
            "domains": [],
            "version": 1,
        }
    finally:
        registry.close()


def test_manifest_refresh_preserves_existing_network_policy(tmp_path):
    from securityd.capability_registry import CapabilityRegistry

    registry = CapabilityRegistry(tmp_path / "cap.db")
    try:
        registry.register_agent("com.example.existing")
        saved = registry.set_network_policy(
            "com.example.existing", ["api.example.com"], "whitelist"
        )
        registry.record_manifest(
            "com.example.existing", "2.0.0", "Existing", "signature", "", "now"
        )
        assert registry.get_network_policy("com.example.existing") == saved
    finally:
        registry.close()


def test_allow_all_network_policy_is_persisted(tmp_path):
    from securityd.capability_registry import CapabilityRegistry

    registry = CapabilityRegistry(tmp_path / "cap.db")
    saved = registry.set_network_policy(
        "com.example.allow-all", ["ignored.example.com"], "allow_all"
    )
    assert saved == {
        "agent_id": "com.example.allow-all",
        "mode": "allow_all",
        "domains": [],
        "version": 1,
    }
    assert registry.get_network_policy("com.example.allow-all") == saved
    registry.close()


def test_network_policy_schema_migrates_existing_database_for_allow_all(tmp_path):
    from securityd.capability_registry import CapabilityRegistry

    path = tmp_path / "cap.db"
    connection = sqlite3.connect(path)
    connection.executescript(
        "CREATE TABLE agent_manifest ("
        "agent_id TEXT PRIMARY KEY, version TEXT NOT NULL, name TEXT NOT NULL, "
        "signature TEXT NOT NULL, manifest_raw TEXT NOT NULL DEFAULT '', "
        "installed_at TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'active');"
        "CREATE TABLE network_policy ("
        "agent_id TEXT PRIMARY KEY, "
        "mode TEXT NOT NULL CHECK(mode IN ('whitelist','deny_all','learning')), "
        "domains_json TEXT NOT NULL DEFAULT '[]', version INTEGER NOT NULL DEFAULT 0, "
        "updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, "
        "FOREIGN KEY (agent_id) REFERENCES agent_manifest(agent_id) ON DELETE CASCADE);"
        "INSERT INTO agent_manifest VALUES "
        "('com.existing','1.0.0','Existing','','','now','active');"
        "INSERT INTO network_policy(agent_id,mode,domains_json,version) VALUES "
        "('com.existing','whitelist','[\"api.example.com\"]',7);"
    )
    connection.close()

    registry = CapabilityRegistry(path)
    try:
        assert registry.get_network_policy("com.existing")["version"] == 7
        saved = registry.set_network_policy("com.existing", [], "allow_all")
        assert saved["mode"] == "allow_all"
        assert saved["version"] == 8
    finally:
        registry.close()


def test_added_columns_are_migrated_on_existing_database(tmp_path):
    """升级既有部署时，老表缺少的新列要自动补上。

    旧库的 ``agent_manifest`` 没有 ``framework`` 列，``CREATE TABLE IF NOT
    EXISTS`` 不会补列，``GetAgentInfo`` 直接抛 ``no such column:
    framework``，Runtime 因此起不来。
    """
    from securityd.capability_registry import CapabilityRegistry

    path = tmp_path / "cap.db"
    connection = sqlite3.connect(path)
    connection.executescript(
        "CREATE TABLE agent_manifest ("
        "agent_id TEXT PRIMARY KEY, version TEXT NOT NULL, name TEXT NOT NULL, "
        "signature TEXT NOT NULL, manifest_raw TEXT NOT NULL DEFAULT '', "
        "installed_at TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'active');"
        "INSERT INTO agent_manifest VALUES "
        "('com.existing','1.0.0','Existing','','','now','active');"
    )
    connection.close()

    registry = CapabilityRegistry(path)
    try:
        info = registry.get_manifest_info("com.existing")
        assert info is not None
        assert info["version"] == "1.0.0"
        assert info["framework"] == ""
        registry.register_agent("com.existing", framework="runtime")
        assert registry.get_framework("com.existing") == "runtime"
    finally:
        registry.close()


def _reg(sec_root):
    from securityd.capability_registry import CapabilityRegistry
    return CapabilityRegistry()


def _seed(reg):
    reg.register_capabilities("com.test", [
        Permission("read_proc_list", Policy.ALLOW),
        Permission("file_write_docs", Policy.ASK),
        Permission("network_config", Policy.ASK),
        Permission("payment_create", Policy.DENY),
    ])


def test_allow_policy_allows(sec_root):  # TC-UNIT-04
    reg = _reg(sec_root); _seed(reg)
    assert reg.check_permission("com.test", "read_proc_list") == Decision.ALLOW


def test_ask_policy_first_asks(sec_root):  # TC-UNIT-05
    reg = _reg(sec_root); _seed(reg)
    assert reg.check_permission("com.test", "file_write_docs", session_id="s1") == Decision.ASK


def test_ask_policy_session_allow(sec_root):  # TC-UNIT-06
    reg = _reg(sec_root); _seed(reg)
    reg.grant_session_trust("s1", "com.test", "file_write_docs", "2026-07-14T00:00:00")
    assert reg.check_permission("com.test", "file_write_docs", session_id="s1") == Decision.ALLOW


def test_deny_policy_denies(sec_root):  # TC-UNIT-07
    reg = _reg(sec_root); _seed(reg)
    reg.grant_session_trust("s1", "com.test", "payment_create", "2026-07-14T00:00:00")
    assert reg.check_permission("com.test", "payment_create", session_id="s1") == Decision.DENY


def test_unregistered_defaults_to_allow(sec_root):  # TC-UNIT-08
    """未登记的工具走目录未映射兜底策略，与 capabilities 默认值一致。"""
    reg = _reg(sec_root); _seed(reg)
    assert reg.check_permission("com.test", "system.shutdown") == Decision.ALLOW


def test_invalid_policy_rejected(sec_root):  # TC-UNIT-09
    reg = _reg(sec_root)
    with pytest.raises(ValueError):
        reg.register_capabilities("com.bad", [Permission("x", "maybe")])


def test_engine_grant_session_trust_only_for_ask(engine):
    """PA HITL 批准写 trust；allow 与 deny 不需要/不允许借此绕过。"""
    _seed(engine.registry)
    assert engine.grant_session_trust("com.test", "file_write_docs", "", "s1") is True
    assert engine.registry.check_permission(
        "com.test", "file_write_docs", session_id="s1"
    ) == Decision.ALLOW
    assert engine.grant_session_trust("com.test", "read_proc_list", "", "s1") is False
    assert engine.grant_session_trust("com.test", "payment_create", "", "s1") is False


def test_revoke_sets_deny(sec_root):
    reg = _reg(sec_root); _seed(reg)
    assert reg.revoke_permission("com.test", "read_proc_list") is True
    assert reg.check_permission("com.test", "read_proc_list") == Decision.DENY


def test_permission_settings_roundtrip_and_defaults(tmp_path):
    from securityd.capability_registry import CapabilityRegistry

    registry = CapabilityRegistry(tmp_path / "cap.db")
    try:
        registry.register_agent("com.example.perms")
        assert registry.get_permission_settings("com.example.perms") == {
            "read": {"include": [], "exclude": []},
            "write": {"include": [], "exclude": []}}
        registry.set_permission_group("com.example.perms", "read",
                                      {"include": ["/opt/data", "/opt/data", "/etc/app"]})
        registry.set_permission_group("com.example.perms", "write",
                                      {"include": ["/var/lib/app"]})
        settings = registry.get_permission_settings("com.example.perms")
        assert settings["read"] == {"include": ["/opt/data", "/etc/app"], "exclude": []}
        assert settings["write"] == {"include": ["/var/lib/app"], "exclude": []}
        # 单组更新不影响其它组（防止重设策略把细节冲掉）。
        registry.set_permission_group("com.example.perms", "read",
                                      {"include": ["/srv"], "exclude": []})
        assert registry.get_permission_settings("com.example.perms")["write"] == {
            "include": ["/var/lib/app"], "exclude": []}
    finally:
        registry.close()


def test_permission_settings_reject_non_absolute_paths(tmp_path):
    from securityd.capability_registry import CapabilityRegistry
    from securityd.permissions import PermissionSettingsError

    registry = CapabilityRegistry(tmp_path / "cap.db")
    try:
        registry.register_agent("com.example.perms")
        with pytest.raises(PermissionSettingsError):
            registry.set_permission_group("com.example.perms", "read",
                                          {"include": ["relative/path"]})
        with pytest.raises(PermissionSettingsError):
            registry.set_permission_group("com.example.perms", "read",
                                          {"include": ["/opt/../etc"]})
        with pytest.raises(PermissionSettingsError):
            registry.set_permission_group("com.example.perms", "unknown", {})
        # 排除项必须落在某个包含范围之内，否则是永远不会生效的死配置。
        with pytest.raises(PermissionSettingsError):
            registry.set_permission_group("com.example.perms", "read",
                                          {"include": ["/opt/data"],
                                           "exclude": ["/srv/other"]})
    finally:
        registry.close()


def test_security_permissions_aggregates_four_groups(monkeypatch, tmp_path):
    from securityd.engine import SecurityEngine

    engine = SecurityEngine()
    try:
        engine.register_agent("com.example.aggregate", {"framework": "runtime"})
        engine.set_agent_security_mode("com.example.aggregate", "normal", "test")
        engine.set_permission_group("com.example.aggregate", "read",
                                    {"include": ["/opt/data"],
                                     "exclude": ["/opt/data/secret"]})
        engine.set_permission_group("com.example.aggregate", "write",
                                    {"include": ["/var/lib/app"]})
        engine.set_network_policy("com.example.aggregate", ["api.example.com"], "whitelist")
        merged = engine.get_security_permissions("com.example.aggregate")
        assert merged["read"] == {"include": ["/opt/data"],
                                  "exclude": ["/opt/data/secret"]}
        assert merged["write"] == {"include": ["/var/lib/app"], "exclude": []}
        assert merged["network"]["mode"] == "whitelist"
        assert merged["network"]["domains"] == ["api.example.com"]
        assert merged["syscall"]["effective"] == []  # 默认不做系统调用限制
        assert "custom" not in merged
    finally:
        engine.close()


def test_record_manifest_persists_and_preserves_framework(tmp_path):
    """签名包声明的 framework 落库；老包重申时不能清空既有作用域。"""
    from securityd.capability_registry import CapabilityRegistry

    registry = CapabilityRegistry(tmp_path / "cap.db")
    try:
        registry.record_manifest(
            "com.bianbu.runtime", "1.2.56", "Runtime", "sig", "", "now",
            framework="Runtime")
        assert registry.get_framework("com.bianbu.runtime") == "runtime"
        # 未声明 framework 的旧包重装，不能把已知作用域抹掉。
        registry.record_manifest(
            "com.bianbu.runtime", "1.2.55", "Runtime", "sig", "", "later")
        assert registry.get_framework("com.bianbu.runtime") == "runtime"
        # 新包显式换框架时必须生效。
        registry.record_manifest(
            "com.bianbu.runtime", "1.2.57", "Runtime", "sig", "", "later",
            framework="hermes")
        assert registry.get_framework("com.bianbu.runtime") == "hermes"
    finally:
        registry.close()
