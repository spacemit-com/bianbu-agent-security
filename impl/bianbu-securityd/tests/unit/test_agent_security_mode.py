"""Per-Agent YOLO mode persistence, evaluation, and audit contracts."""
from __future__ import annotations

import pytest

from securityd.models import Decision, Permission, Policy


def _permission(name: str, policy=Policy.ALLOW) -> Permission:
    return Permission(name, policy)


def _register(engine) -> None:
    engine.register_agent("agent.yolo", {"name": "YOLO test"})
    engine.sync_agent_capabilities("agent.yolo", [
        _permission("allowed.cap", Policy.ALLOW),
        _permission("denied.cap", Policy.DENY),
        _permission("ask.cap", Policy.ASK),
    ])


def test_registered_agent_defaults_to_yolo_and_unknown_agent_is_rejected(engine):
    _register(engine)

    assert engine.get_agent_security_mode("agent.yolo")["mode"] == "yolo"
    with pytest.raises(ValueError, match="未注册|registered"):
        engine.get_agent_security_mode("agent.missing")


@pytest.mark.parametrize("mode", ["", "YOLO", "unsafe", None])
def test_setting_mode_rejects_invalid_values(engine, mode):
    _register(engine)

    with pytest.raises(ValueError, match="normal|yolo"):
        engine.set_agent_security_mode("agent.yolo", mode, "uid=0;pid=1")


def test_yolo_allows_denied_confirm_and_unknown_capabilities(engine):
    _register(engine)
    engine.set_agent_security_mode("agent.yolo", "normal", "uid=0")
    before = {
        cap: engine.check_permission("agent.yolo", cap)
        for cap in ("denied.cap", "ask.cap", "future.unregistered")
    }
    assert before == {
        "denied.cap": Decision.DENY,
        "ask.cap": Decision.ASK,
        "future.unregistered": Decision.ALLOW,
    }

    changed = engine.set_agent_security_mode(
        "agent.yolo", "yolo", "uid=0;pid=123;exe=/usr/bin/bncli"
    )

    assert changed["old_mode"] == "normal"
    assert changed["mode"] == "yolo"
    for capability in before:
        assert engine.check_permission("agent.yolo", capability, "/original/scope") == Decision.ALLOW


def test_sync_does_not_overwrite_yolo_and_normal_restores_granular_policy(engine):
    _register(engine)
    engine.set_agent_security_mode("agent.yolo", "yolo", "uid=0")

    engine.sync_agent_capabilities("agent.yolo", [
        _permission("replacement.denied", Policy.DENY),
    ])

    assert engine.get_agent_security_mode("agent.yolo")["mode"] == "yolo"
    assert engine.check_permission("agent.yolo", "replacement.denied") == Decision.ALLOW
    engine.set_agent_security_mode("agent.yolo", "normal", "uid=0")
    assert engine.check_permission("agent.yolo", "replacement.denied") == Decision.DENY


def test_yolo_permission_and_mode_transition_audits_include_mode_actor_and_request(engine):
    _register(engine)
    engine.set_agent_security_mode(
        "agent.yolo", "yolo", "uid=0;pid=123;exe=/usr/bin/bncli"
    )
    engine.check_permission("agent.yolo", "brand.new", "/tmp/example")

    rows = engine.audit._conn.execute(
        "SELECT op_type,target,result FROM audit_record ORDER BY seq"
    ).fetchall()
    transition = next(row for row in rows if row[0] == "security_mode_change")
    assert "agent=agent.yolo" in transition[1]
    assert "old_mode=yolo" in transition[1]
    assert "new_mode=yolo" in transition[1]
    assert "actor=uid=0;pid=123;exe=/usr/bin/bncli" in transition[1]
    assert transition[2] == "success"
    decision = rows[-1]
    assert tuple(decision) == (
        "check_permission",
        "brand.new:/tmp/example",
        "decision=ALLOW;mode=yolo",
    )


def test_unregister_removes_persisted_mode(engine):
    _register(engine)
    engine.set_agent_security_mode("agent.yolo", "yolo", "uid=0")

    assert engine.unregister_agent("agent.yolo") is True
    with pytest.raises(ValueError, match="未注册|registered"):
        engine.get_agent_security_mode("agent.yolo")


def test_mode_transition_audit_failure_rolls_back_to_previous_mode(engine, monkeypatch):
    _register(engine)
    engine.set_agent_security_mode("agent.yolo", "normal", "uid=0")
    original_audit = engine.audit_log

    def fail_transition(agent_id, op_type, target, result, **kwargs):
        if op_type == "security_mode_change":
            raise RuntimeError("audit unavailable")
        return original_audit(agent_id, op_type, target, result, **kwargs)

    monkeypatch.setattr(engine, "audit_log", fail_transition)

    with pytest.raises(RuntimeError, match="audit unavailable"):
        engine.set_agent_security_mode("agent.yolo", "yolo", "uid=0")

    assert engine.get_agent_security_mode("agent.yolo")["mode"] == "normal"
    assert engine.check_permission("agent.yolo", "denied.cap") == Decision.DENY


def test_agent_info_marks_unregistered_agents(engine):
    """D-8：未注册 Agent 不得返回默认 permissions/network 伪装成已注册。"""
    info = engine.get_agent_info('com.never.registered')
    assert info['registered'] is False
    assert info['manifest'] is None and info['capabilities'] == []
    assert info['permissions'] is None and info['network'] is None
    _register(engine)
    info = engine.get_agent_info('agent.yolo')
    assert info['registered'] is True
    assert info['permissions'] == {
        'read': {'include': [], 'exclude': []},
        'write': {'include': [], 'exclude': []}}


def test_execution_status_worker_view_comes_from_lease_db(engine):
    """D-4：worker.state 由 lease DB 推导，而非固定 unknown。"""
    class Runtime:
        def __init__(self, rows):
            self.rows = rows
            self.leases = self

        def active_instances_for_worker(self, aid):
            return self.rows

        def syscall_audit_instances(self):
            return []

    engine.runtime_engine = Runtime([])
    assert engine.get_security_execution_status('agent.yolo')['worker'] == {'state': 'stopped', 'instances': 0}
    engine.runtime_engine = Runtime([{'instance_id': 'i1', 'lease_id': 'l1', 'pid': 42,
                                      'cgroup_path': '/cg', 'backend': 'host-process',
                                      'started_at': 1}])
    worker = engine.get_security_execution_status('agent.yolo')['worker']
    assert worker['state'] == 'running' and worker['pid'] == 42 and worker['backend'] == 'host-process'


def test_yolo_network_effective_policy_preserves_saved_normal_policy(engine):
    _register(engine)
    engine.set_network_policy('agent.yolo', ['example.com'], 'deny_all')
    assert engine.get_network_policy('agent.yolo')['mode'] == 'allow_all'
    assert engine.get_network_policy('agent.yolo')['domains'] == []
    assert engine.registry.get_network_policy('agent.yolo')['mode'] == 'deny_all'
    engine.set_agent_security_mode('agent.yolo', 'normal', 'test')
    assert engine.get_network_policy('agent.yolo')['mode'] == 'deny_all'


def test_yolo_uds_scan_skips_scanner_and_keeps_audit(engine, monkeypatch):
    from securityd.uds_handlers import SecurityUdsHandlers
    _register(engine)
    handlers = SecurityUdsHandlers(engine)
    monkeypatch.setattr(handlers, '_require_agent', lambda *args: ('agent.yolo', None))
    def forbidden(*args):
        pytest.fail('YOLO must not invoke scanner')
    monkeypatch.setattr(handlers.scanner, 'scan_and_mask', forbidden)
    result = handlers.dlp_scan({'text': '手机号 13812345678'}, None)
    assert result['masked_text'] == '手机号 13812345678'
    assert result['has_pii'] is False and result['audit_seq'] > 0
    assert handlers.dlp_policy({}, None)['scanning_enabled'] is False
    handlers.close()


@pytest.mark.parametrize('name', ['input_handler', 'pre_model_handler', 'post_model_handler', 'pre_tool_handler', 'post_tool_handler', 'output_handler'])
def test_yolo_dlp_handlers_skip_before_accessing_scanner(name):
    from securityd.dlp import handlers
    from securityd.interceptor import HookPoint
    from types import SimpleNamespace
    result = getattr(handlers, name)('agent', HookPoint.INPUT, '手机号 13812345678', {
        'client_provider': lambda: SimpleNamespace(get_agent_security_mode=lambda aid: {'mode': 'yolo'})})
    assert result.decision.value == 'ALLOW'
    assert result.metadata['mode'] == 'yolo'


def test_mode_transition_applies_network_and_rolls_back_on_failure(engine, monkeypatch):
    _register(engine)
    engine.registry.set_network_policy('agent.yolo', [], 'deny_all')
    applied = []
    def apply(aid, configured, old, **kwargs):
        applied.append(configured['mode'])
        if configured['mode'] == 'deny_all':
            raise RuntimeError('enforcement failed')
    monkeypatch.setattr(engine, '_apply_network_policy', apply)
    with pytest.raises(RuntimeError, match='enforcement failed'):
        engine.set_agent_security_mode('agent.yolo', 'normal', 'test')
    assert engine.get_agent_security_mode('agent.yolo')['mode'] == 'yolo'
    assert applied == ['deny_all', 'allow_all']
    assert engine.registry.get_network_policy('agent.yolo')['mode'] == 'deny_all'


def test_yolo_runtime_launch_lease_uses_effective_network(engine):
    from runtime.policy import build_execution_policy
    _register(engine)
    engine.registry.set_network_policy('agent.yolo', [], 'deny_all')
    result = build_execution_policy(engine, 'agent.yolo', 'sandbox')
    assert result.policy['network']['mode'] == 'allow_all'
    assert result.policy['network']['default'] == 'allow'
    assert result.policy['network']['observe'] is True


def test_yolo_mode_change_clears_live_filter_and_normal_restores_it(engine, monkeypatch):
    import json
    from types import SimpleNamespace
    _register(engine)
    engine.registry.set_network_policy('agent.yolo', [], 'deny_all')
    rows = [{'instance_id': 'one', 'backend': 'host-process', 'attestation_json': json.dumps({
        'unit': 'agent.service', 'network_properties': []})}]
    def update(iid, policy, **kwargs):
        rows[0]['attestation_json'] = json.dumps({'unit': 'agent.service', 'network_properties': kwargs['network_properties']})
    engine.runtime_engine = SimpleNamespace(instances=lambda aid: rows, update_instance_network_policy=update)
    monkeypatch.setenv('BIANBU_RUNTIME_MODE', 'production')
    changes = []
    def apply(unit, new, old, **kwargs):
        changes.append((new, old))
        return {'ok': True}
    monkeypatch.setattr('client.runtime_launcher.update_runtime_network', apply)
    engine.set_agent_security_mode('agent.yolo', 'normal', 'test')
    engine.set_agent_security_mode('agent.yolo', 'yolo', 'test')
    assert changes[0][0] == ['IPAddressDeny=any']
    assert changes[1][0] == []
    assert changes[1][1] == ['IPAddressDeny=any']
    assert engine.registry.get_network_policy('agent.yolo')['mode'] == 'deny_all'


def test_stopped_agent_can_restore_normal_before_restart_in_production(engine, monkeypatch):
    _register(engine)
    engine.registry.set_network_policy('agent.yolo', [], 'deny_all')
    monkeypatch.setenv('BIANBU_RUNTIME_MODE', 'production')
    engine.set_agent_security_mode('agent.yolo', 'normal', 'test')
    assert engine.get_network_policy('agent.yolo')['mode'] == 'deny_all'


def test_bwrap_mode_transition_requires_restart_and_preserves_mode(engine):
    from types import SimpleNamespace
    from securityd.errors import PermissionDenied
    _register(engine)
    engine.registry.set_network_policy('agent.yolo', [], 'deny_all')
    engine.runtime_engine = SimpleNamespace(instances=lambda aid: [{'backend': 'bwrap'}])
    with pytest.raises(PermissionDenied, match='requires restart'):
        engine.set_agent_security_mode('agent.yolo', 'normal', 'test')
    assert engine.get_agent_security_mode('agent.yolo')['mode'] == 'yolo'
    assert engine.registry.get_network_policy('agent.yolo')['mode'] == 'deny_all'


def test_yolo_uds_audit_failure_does_not_enforce_dlp(engine, monkeypatch, caplog):
    from securityd.uds_handlers import SecurityUdsHandlers
    _register(engine)
    handlers = SecurityUdsHandlers(engine)
    monkeypatch.setattr(handlers, '_require_agent', lambda *args: ('agent.yolo', None))
    def unavailable(*args, **kwargs):
        raise RuntimeError('audit unavailable')
    monkeypatch.setattr(engine, 'audit_log', unavailable)
    result = handlers.dlp_scan({'text': 'unchanged'}, None)
    assert result['masked_text'] == 'unchanged' and result['scanning_enabled'] is False
    assert result['audit_seq'] == 0
    assert 'audit' in caplog.text
    handlers.close()


def test_yolo_accepts_passive_network_records_without_learning_policy(engine, monkeypatch):
    import time
    _register(engine)
    engine.registry.set_network_policy('agent.yolo', [], 'deny_all')
    monkeypatch.setattr(engine, '_require_network_learning_worker', lambda identity: 'agent.yolo')
    identity = {'agent_id': 'agent.yolo', 'instance_id': 'worker', 'lease_id': 'lease', 'pid': 123}
    assert engine.report_network_learning_collector(identity, 'active')
    assert engine.record_network_learning_event(identity, {
        'event_id': 'connect-1', 'observed_at': time.time(), 'event_type': 'connect',
        'protocol': 'tcp', 'remote_ip': '203.0.113.8', 'remote_port': 443,
        'outcome': 'success', 'backend': 'strace', 'policy_version': 1})
    assert engine.get_network_learning_events('agent.yolo')['events'][0]['remote_ip'] == '203.0.113.8'
