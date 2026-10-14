from __future__ import annotations


def test_runtime_launcher_compiles_resource_and_network_limits(monkeypatch):
    import securityd.network_policy as np
    monkeypatch.setattr(np, "_resolve", lambda d: {d[0]: ["10.0.0.10"]})
    from client.runtime_launcher import RuntimeLaunchSpec, build_systemd_run_argv
    spec = RuntimeLaunchSpec("com.example/a", ["/usr/bin/agent"],
                             ["api.example.com"], ["127.0.0.53"],
                             "64M", "25%", 32, 200)
    argv, props = build_systemd_run_argv(spec)
    assert argv[0] == "systemd-run" and argv[-1] == "/usr/bin/agent"
    for expected in ("MemoryMax=64M", "CPUQuota=25%", "TasksMax=32",
                     "IOWeight=200", "IPAddressDeny=any",
                     "IPAddressAllow=10.0.0.10", "IPAddressAllow=127.0.0.53"):
        assert expected in props


def test_deny_all_without_domains_requires_network_verification(monkeypatch):
    """An empty domain list must not bypass verification of IPAddressDeny=any."""
    from client import runtime_launcher

    calls = []
    monkeypatch.setattr(
        runtime_launcher.network_policy,
        "verify_systemd_unit",
        lambda *args, **kwargs: False,
    )
    monkeypatch.setattr(runtime_launcher, "verify_runtime_resources",
                        lambda *args, **kwargs: True)
    monkeypatch.setattr(
        runtime_launcher.subprocess,
        "run",
        lambda argv, **kwargs: calls.append(argv)
        or type("R", (), {"stdout": "", "stderr": ""})(),
    )

    spec = runtime_launcher.RuntimeLaunchSpec(
        "com.example.deny-all", ["/usr/bin/agent"], network_mode="deny_all"
    )
    result = runtime_launcher.launch_runtime(spec)

    assert result.ok is False
    assert "网络属性无法复核" in result.reason
    assert ["systemctl", "--user", "stop", result.unit] in calls


def test_runtime_resource_verification_rejects_unbounded(monkeypatch):
    from client.runtime_launcher import verify_runtime_resources
    monkeypatch.setattr("client.runtime_launcher.subprocess.run",
                        lambda *a, **k: type("R", (), {"stdout": "MemoryMax=infinity\nCPUQuotaPerSecUSec=infinity\nTasksMax=infinity\nIOWeight=0\n"})())
    assert not verify_runtime_resources(
        "agent.service",
        ["MemoryMax=64M", "CPUQuota=25%", "TasksMax=32", "IOWeight=200"],
    )


def test_runtime_resource_verification_accepts_canonical_values(monkeypatch):
    from client.runtime_launcher import verify_runtime_resources
    monkeypatch.setattr("client.runtime_launcher.subprocess.run",
                        lambda *a, **k: type("R", (), {"stdout": "MemoryMax=67108864\nCPUQuotaPerSecUSec=250ms\nTasksMax=32\nIOWeight=200\n"})())
    assert verify_runtime_resources(
        "agent.service",
        ["MemoryMax=64M", "CPUQuota=25%", "TasksMax=32", "IOWeight=200"],
    )


def test_update_runtime_network_sets_properties_and_reads_them_back(monkeypatch):
    from client import runtime_launcher

    calls = []
    monkeypatch.setattr(runtime_launcher.network_policy, "verify_systemd_unit",
                        lambda unit, props, scope="system": props == [
                            "IPAddressDeny=any", "IPAddressAllow=10.0.0.20"])

    def fake_run(argv, **kwargs):
        calls.append(argv)
        return type("R", (), {"stdout": "", "stderr": ""})()

    monkeypatch.setattr(runtime_launcher.subprocess, "run", fake_run)
    result = runtime_launcher.update_runtime_network(
        "agent.service", ["IPAddressDeny=any", "IPAddressAllow=10.0.0.20"],
        ["IPAddressDeny=any", "IPAddressAllow=10.0.0.10"], scope="user")
    assert result["ok"] is True
    assert calls == [["systemctl", "--user", "set-property", "--runtime",
                      "agent.service", "IPAddressDeny=any",
                      "IPAddressAllow=10.0.0.20"]]


def test_update_runtime_network_rolls_back_when_verification_fails(monkeypatch):
    from client import runtime_launcher

    calls = []
    monkeypatch.setattr(runtime_launcher.network_policy, "verify_systemd_unit",
                        lambda unit, props, scope="system": props == [
                            "IPAddressDeny=any", "IPAddressAllow=10.0.0.10"])
    monkeypatch.setattr(runtime_launcher.subprocess, "run",
                        lambda argv, **kwargs: calls.append(argv) or
                        type("R", (), {"stdout": "", "stderr": ""})())
    result = runtime_launcher.update_runtime_network(
        "agent.service", ["IPAddressDeny=any", "IPAddressAllow=10.0.0.20"],
        ["IPAddressDeny=any", "IPAddressAllow=10.0.0.10"], scope="user")
    assert result["ok"] is False
    assert result["rolled_back"] is True
    assert len(calls) == 2


def test_update_runtime_network_clears_old_filter_properties(monkeypatch):
    from client import runtime_launcher

    calls = []
    monkeypatch.setattr(
        runtime_launcher.network_policy,
        "verify_systemd_unit",
        lambda unit, props, scope="system": props == [],
    )
    monkeypatch.setattr(
        runtime_launcher.subprocess,
        "run",
        lambda argv, **kwargs: calls.append(argv)
        or type("R", (), {"stdout": "", "stderr": ""})(),
    )

    result = runtime_launcher.update_runtime_network(
        "agent.service",
        [],
        ["IPAddressDeny=any", "IPAddressAllow=10.0.0.10"],
        scope="system",
    )

    assert result == {"ok": True, "rolled_back": False}
    assert calls == [[
        "systemctl", "set-property", "--runtime", "agent.service",
        "IPAddressDeny=", "IPAddressAllow=",
    ]]
