from __future__ import annotations


def test_probe_passes_complete_identity_and_runtime_contract(monkeypatch):
    from deploy import runtime_production_probe as probe

    monkeypatch.setattr(probe, "_show_unit", lambda unit, scope: {
        "_rc": "0", "ActiveState": "active", "MainPID": "123",
        "User": "bianbu-runtime", "Group": "bianbu-runtime",
        "ControlGroup": "/system.slice/bianbu-agent-runtimed.service",
    })
    monkeypatch.setattr(probe, "_introspect", lambda bus: (set(probe.REQUIRED_METHODS), ""))
    result = probe.probe(unit="bianbu-agent-runtimed.service", scope="system",
                         bus="system", expected_user="bianbu-runtime",
                         expected_group="bianbu-runtime")
    assert result["ok"] is True


def test_probe_blocks_missing_unit_and_methods(monkeypatch):
    from deploy import runtime_production_probe as probe

    monkeypatch.setattr(probe, "_show_unit", lambda unit, scope: {
        "_rc": "0", "ActiveState": "inactive", "MainPID": "0",
        "User": "", "Group": "",
    })
    monkeypatch.setattr(probe, "_introspect", lambda bus: (set(), "service missing"))
    result = probe.probe(unit="bianbu-agent-runtimed.service", scope="system",
                         bus="system", expected_user="bianbu-runtime",
                         expected_group="bianbu-runtime")
    assert result["ok"] is False
    assert all(not bool(item["ok"]) for item in result["checks"])


def test_introspect_accepts_systemd_259_dotted_members(monkeypatch):
    from deploy import runtime_production_probe as probe

    output = "\n".join(f".{name} method - - -" for name in probe.REQUIRED_METHODS)
    monkeypatch.setattr(probe, "_run", lambda argv, timeout=5.0: (0, output, ""))
    methods, error = probe._introspect("system")
    assert error == ""
    assert methods == probe.REQUIRED_METHODS
