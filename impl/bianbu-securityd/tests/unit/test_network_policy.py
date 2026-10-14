from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest


@pytest.mark.parametrize("output,properties,expected", [
    ("IPAddressDeny=::/0 0.0.0.0/0\nIPAddressAllow=\n", ["IPAddressDeny=any"], True),
    ("IPAddressDeny=0.0.0.0/0\nIPAddressAllow=\n", ["IPAddressDeny=any"], False),
    ("IPAddressDeny=::/0 0.0.0.0/0\nIPAddressAllow=10.0.0.100/32\n",
     ["IPAddressDeny=any", "IPAddressAllow=10.0.0.10"], False),
    ("IPAddressDeny=::/0 0.0.0.0/0\nIPAddressAllow=10.0.0.10/32 ::1/128\n",
     ["IPAddressDeny=any", "IPAddressAllow=10.0.0.10", "IPAddressAllow=::1"], True),
    ("IPAddressDeny=::/0 0.0.0.0/0\nIPAddressAllow=0.0.0.0/0\n",
     ["IPAddressDeny=any"], False),
])
def test_verify_systemd_network_matches_exact_policy(sec_root, monkeypatch, output, properties, expected):
    from securityd import network_policy
    monkeypatch.setattr(network_policy.subprocess, "run", lambda *args, **kwargs: SimpleNamespace(stdout=output))
    assert network_policy.verify_systemd_unit("agent.service", properties) is expected


def test_deny_all_can_be_registered_as_verified(sec_root):
    from securityd import network_policy
    assert network_policy.mark_systemd_unit_applied(
        "com.offline", "agent.service", ["IPAddressDeny=any"], verified=True,
    )
    assert network_policy.enforcement_status("com.offline")["enforced"] is True


def test_backend_binary_alone_is_not_enforcement(sec_root, monkeypatch):
    from securityd import network_policy
    monkeypatch.setattr(network_policy.shutil, "which",
                        lambda name: "/usr/bin/nft" if name == "nft" else None)
    monkeypatch.delenv("BIANBU_SECURITY_NETNS", raising=False)
    monkeypatch.delenv("BIANBU_SECURITY_NETNS_READY", raising=False)
    state = network_policy.enforcement_status("com.a")
    assert state["mode"] == "artifact_only" and state["enforced"] is False


def test_apply_requires_explicit_privileged_switch(sec_root, monkeypatch, tmp_path):
    from securityd import network_policy
    rules = network_policy.build_rules("com.a", [], "whitelist")
    monkeypatch.delenv("BIANBU_SECURITY_NET_APPLY", raising=False)
    assert network_policy.apply_rules(rules, "com.a") is False


def test_persisted_policy_round_trips_after_allow_all_default(sec_root):
    from securityd import network_policy
    from securityd.capability_registry import CapabilityRegistry
    registry = CapabilityRegistry()
    registry.register_agent("com.a")
    saved = registry.set_network_policy("com.a", [" API.Example.com. ", "api.example.com"], "whitelist")
    assert saved["mode"] == "whitelist"
    assert saved["domains"] == ["api.example.com"]
    assert saved["version"] == 2
    assert registry.get_network_policy("com.a")["version"] == 2
    registry.close()


def test_engine_reports_allow_all_for_legacy_agent_without_policy(engine):
    engine.registry.register_agent("com.legacy")
    engine.registry.delete_network_policy("com.legacy")

    policy = engine.get_network_policy("com.legacy")

    assert policy["agent_id"] == "com.legacy"
    assert policy["mode"] == "allow_all"
    assert policy["domains"] == []
    assert policy["version"] == 0


def test_sandbox_policy_uses_allow_all_for_legacy_agent_without_policy(engine, monkeypatch):
    from securityd import network_policy

    engine.registry.register_agent("com.legacy")
    engine.registry.delete_network_policy("com.legacy")
    captured = {}
    monkeypatch.setattr(
        network_policy,
        "build_rules",
        lambda agent_id, domains, mode: captured.update(
            agent_id=agent_id, domains=domains, mode=mode
        ) or "/run/legacy.rules",
    )

    engine.build_sandbox_policy("com.legacy")

    assert captured == {
        "agent_id": "com.legacy",
        "domains": [],
        "mode": "allow_all",
    }


def test_deny_all_does_not_allow_dns(sec_root):
    from securityd import network_policy
    path = network_policy.build_rules("com.deny", ["api.example.com"], "deny_all")
    text = Path(path).read_text()
    assert "--dport 53" not in text
    assert "-A OUTPUT -j DROP" in text


def test_policy_write_rolls_back_when_rule_build_fails(engine, monkeypatch):
    from securityd import network_policy
    engine.registry.register_agent("com.rollback")
    engine.registry.set_network_policy("com.rollback", ["old.example.com"], "whitelist")
    monkeypatch.setattr(network_policy, "build_rules", lambda *args: (_ for _ in ()).throw(OSError("build failed")))
    with pytest.raises(OSError):
        engine.set_network_policy("com.rollback", ["new.example.com"], "whitelist")
    assert engine.registry.get_network_policy("com.rollback")["domains"] == ["old.example.com"]


def test_systemd_ip_filter_requires_default_deny_and_allow(sec_root, monkeypatch):
    from securityd import network_policy
    monkeypatch.setattr(network_policy, "_resolve",
                        lambda domains: {domains[0]: ["10.0.0.10"]})
    props = network_policy.systemd_ip_filter_properties(
        ["api.example.com"], dns_servers=["127.0.0.53"])
    assert props == ["IPAddressDeny=any", "IPAddressAllow=10.0.0.10",
                     "IPAddressAllow=127.0.0.53"]
    assert network_policy.mark_systemd_unit_applied("com.a", "agent-a.service", props)
    status = network_policy.enforcement_status("com.a")
    assert status["enforced"] is False and status["mode"] == "artifact_only"
    assert network_policy.mark_systemd_unit_applied("com.a", "agent-a.service", props,
                                                    verified=True)
    status = network_policy.enforcement_status("com.a")
    assert status["enforced"] and status["mode"] == "systemd"
    assert not network_policy.mark_systemd_unit_applied("com.b", "", props)


@pytest.mark.parametrize("mode", ["allow_all", "learning"])
def test_unrestricted_modes_compile_to_no_systemd_filter(sec_root, mode):
    from securityd import network_policy

    assert network_policy.systemd_ip_filter_properties(
        ["api.example.com"], mode=mode, dns_servers=["127.0.0.53"],
    ) == []


def test_verify_systemd_network_accepts_cleared_filter(sec_root, monkeypatch):
    from securityd import network_policy

    monkeypatch.setattr(
        network_policy.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(
            stdout="IPAddressDeny=\nIPAddressAllow=\n"
        ),
    )

    assert network_policy.verify_systemd_unit("agent.service", []) is True


def test_network_policy_update_applies_to_active_systemd_instance(engine, monkeypatch):
    from securityd import network_policy

    engine.registry.set_network_policy("com.live", ["old.example.com"], "whitelist")
    engine.runtime_engine = type("Runtime", (), {
        "instances": lambda self, _agent: [{
            "instance_id": "i1", "lease_id": "l1", "state": "running",
            "backend": "host-process", "attestation_json":
                '{"unit":"agent.service","systemd_scope":"user",'
                '"network_properties":["IPAddressDeny=any",'
                '"IPAddressAllow=10.0.0.10"]}'
        }]
    })()
    monkeypatch.setattr(network_policy, "_resolve",
                        lambda domains: {domains[0]: ["10.0.0.20"]})
    monkeypatch.setattr("client.runtime_launcher.update_runtime_network",
                        lambda *args, **kwargs: {"ok": True, "rolled_back": False})
    assert engine.set_network_policy("com.live", ["new.example.com"], "whitelist") is True
    result = engine.get_network_policy_apply_status("com.live")
    assert result["active_instances"] == 1
    assert result["applied_instances"] == 1
    assert engine.registry.get_network_policy("com.live")["domains"] == ["new.example.com"]


def test_network_policy_update_accepts_verified_empty_old_properties(engine, monkeypatch):
    updates = []
    engine.registry.set_network_policy("com.open", [], "allow_all")
    engine.runtime_engine = type("Runtime", (), {
        "active_instances": lambda self, _agent: [{
            "instance_id": "i1", "lease_id": "l1", "state": "running",
            "backend": "host-process", "attestation_json":
                '{"unit":"agent.scope","systemd_scope":"system",'
                '"network_properties":[]}'
        }],
        "update_instance_network_policy":
            lambda self, instance_id, policy, **kwargs:
                updates.append((instance_id, policy, kwargs)),
    })()
    monkeypatch.setattr(
        "client.runtime_launcher.update_runtime_network",
        lambda unit, new, old, **kwargs: {
            "ok": unit == "agent.scope" and new == [] and old == [],
            "rolled_back": False,
        },
    )

    assert engine.set_network_policy("com.open", [], "learning") is True
    assert updates[0][2]["network_properties"] == []
    assert engine.get_network_policy_apply_status("com.open")["effective"] is True


def test_network_policy_update_failure_restores_registry(engine, monkeypatch):
    from securityd import network_policy

    old = engine.registry.set_network_policy("com.rollback-live", ["old.example.com"], "whitelist")
    engine.runtime_engine = type("Runtime", (), {
        "instances": lambda self, _agent: [{
            "instance_id": "i1", "lease_id": "l1", "state": "running",
            "backend": "host-process", "attestation_json":
                '{"unit":"agent.service","systemd_scope":"user",'
                '"network_properties":["IPAddressDeny=any",'
                '"IPAddressAllow=10.0.0.10"]}'
        }]
    })()
    monkeypatch.setattr(network_policy, "_resolve",
                        lambda domains: {domains[0]: ["10.0.0.20"]})
    monkeypatch.setattr("client.runtime_launcher.update_runtime_network",
                        lambda *args, **kwargs: {"ok": False, "rolled_back": True,
                                                 "reason": "verification failed"})
    with pytest.raises(Exception):
        engine.set_network_policy("com.rollback-live", ["new.example.com"], "whitelist")
    current = engine.registry.get_network_policy("com.rollback-live")
    assert current["domains"] == old["domains"]
    assert current["version"] == old["version"]


def test_network_policy_update_saves_active_bwrap_as_restart_required(engine):
    engine.registry.set_network_policy("com.bwrap-live", ["old.example.com"], "whitelist")
    engine.runtime_engine = type("Runtime", (), {
        "instances": lambda self, _agent: [{
            "instance_id": "i1", "lease_id": "l1", "state": "running",
            "backend": "bwrap", "attestation_json": "{}"
        }]
    })()
    assert engine.set_network_policy(
        "com.bwrap-live", ["new.example.com"], "whitelist",
    ) is True
    assert engine.registry.get_network_policy("com.bwrap-live")["domains"] == [
        "new.example.com",
    ]
    status = engine.get_network_policy_apply_status("com.bwrap-live")
    assert status == {
        "requested": True, "active_instances": 1, "applied_instances": 0,
        "failed_instances": 0, "effective": False,
        "restart_required": True, "restart_required_instances": 1,
    }


def test_network_policy_update_matches_logical_worker_instances(engine):
    calls = []

    class Runtime:
        def active_instances_for_worker(self, worker_agent_id):
            calls.append(worker_agent_id)
            return [{
                "instance_id": "worker-1", "lease_id": "lease-1",
                "state": "running", "backend": "bwrap",
                "attestation_json": "{}",
            }]

        def update_instance_network_policy(self, *args, **kwargs):
            return None

    engine.runtime_engine = Runtime()

    assert engine.set_network_policy("agent-a", [], "learning") is True

    assert calls == ["agent-a"]
    assert engine.get_network_policy_apply_status("agent-a") == {
        "requested": True, "active_instances": 1, "applied_instances": 0,
        "failed_instances": 0, "effective": False,
        "restart_required": True, "restart_required_instances": 1,
    }


@pytest.mark.parametrize("wire_encoded", ["native", "json", "repr"])
def test_policy_status_reconciles_current_worker_and_verified_filters(engine, monkeypatch, wire_encoded):
    import json
    from securityd import network_policy
    policy = engine.registry.set_network_policy('worker-a', ['127.0.0.1'], 'whitelist')
    props = ['IPAddressDeny=any', 'IPAddressAllow=127.0.0.1']
    encoded = json.dumps(props) if wire_encoded == "json" else repr(props) if wire_encoded == "repr" else props
    rows = []
    engine.runtime_engine = SimpleNamespace(active_instances_for_worker=lambda aid: rows)
    engine._network_apply_statuses = {'worker-a': {'requested': True, 'restart_required': True}}
    rows.append({'instance_id': 'new-worker', 'network_apply_state': 'initial',
                 'lease_network_policy': policy,
                 'attestation_json': json.dumps({'unit': 'worker.scope', 'systemd_scope': 'system',
                    'network_properties': encoded})})
    monkeypatch.setattr(network_policy, 'verify_systemd_unit', lambda unit, properties, **kw: properties == props)
    status = engine.get_network_policy_apply_status('worker-a')
    assert status['effective'] is True and status['restart_required'] is False
    assert status['applied_instances'] == 1
    assert engine.get_network_policy('worker-a')['enforcement']['enforced'] is True
    # A stale applied version must not be reported as the newly configured policy.
    rows[0]['lease_network_policy'] = {**policy, 'version': policy['version'] - 1}
    assert engine.get_network_policy_apply_status('worker-a')['restart_required'] is True
    rows[0]['lease_network_policy'] = policy
    monkeypatch.setattr(network_policy, 'verify_systemd_unit', lambda *a, **kw: False)
    assert engine.get_network_policy_apply_status('worker-a')['failed_instances'] == 1
    assert engine.get_network_policy('worker-a')['enforcement']['enforced'] is False
    rows.clear()
    assert engine.get_network_policy_apply_status('worker-a')['active_instances'] == 0
    assert engine.get_network_policy('worker-a')['enforcement']['enforced'] is False


def test_legacy_default_policy_is_effective_without_saved_policy(engine, monkeypatch):
    import json
    from securityd import network_policy
    engine.registry.register_agent('legacy-worker')
    engine.registry.delete_network_policy('legacy-worker')
    rows = [{'network_apply_state': 'initial',
             'lease_network_policy': {'version': 0, 'mode': 'allow_all', 'domains': []},
             'attestation_json': json.dumps({'unit': 'legacy.scope', 'network_properties': []})}]
    engine.runtime_engine = SimpleNamespace(active_instances_for_worker=lambda aid: rows)
    monkeypatch.setattr(network_policy, 'verify_systemd_unit', lambda *a, **kw: True)
    status = engine.get_network_policy_apply_status('legacy-worker')
    assert status['effective'] is True
    assert status['restart_required'] is False
    assert status['requested'] is False
