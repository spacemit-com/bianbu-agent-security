"""security.runtime 执行模式与策略单元测试。"""

from __future__ import annotations

import stat
from pathlib import Path

import pytest


class _Registry:
    def __init__(self, rows):
        self.rows = rows

    def get_manifest_info(self, _agent_id):
        return {"version": "1.0", "status": "active"}

    def get_allowed_domains(self, _agent_id):
        return ["api.example.test"]

    def get_network_policy(self, _agent_id):
        return None

    def get_entrypoint(self, _agent_id):
        return ["/usr/bin/agent-runtime", "--agent"]

class _Engine:
    # 沙箱与否由「声明了什么安全设置」推导；测试按需覆盖原因列表。
    boundary_reasons: list[str] = []

    def __init__(self, rows):
        self.registry = _Registry(rows)
        self.rows = rows

    def get_capabilities(self, _agent_id):
        return list(self.rows)

    def execution_mode_for(self, _agent_id):
        return {"mode": "sandbox" if self.boundary_reasons else "host",
                "reasons": list(self.boundary_reasons), "trusted": True}

    def build_sandbox_policy(self, _agent_id):
        return "/run/seccomp", "/run/net.rules"


def test_auto_selects_host_for_low_risk_trusted_package():
    from runtime.policy import build_execution_policy

    result = build_execution_policy(
        _Engine([{"policy": "allow"}]), "com.example.agent", "auto")
    assert result.effective_mode == "host"
    assert result.backend == "host-process"
    assert result.policy["sandbox_required"] is False
    assert result.policy["entrypoint"] == ["/usr/bin/agent-runtime", "--agent"]
    assert "policy_digest" not in result.policy


def test_prepare_policy_uses_persisted_network_policy():
    from runtime.policy import build_execution_policy
    class ConfiguredRegistry(_Registry):
        def get_network_policy(self, _agent_id):
            return {"mode": "deny_all", "domains": [], "version": 3}
    class ConfiguredEngine(_Engine):
        def __init__(self):
            self.registry = ConfiguredRegistry([])
            self.rows = []
    result = build_execution_policy(ConfiguredEngine(), "com.example.agent", "host")
    assert result.policy["network"] == {
        "mode": "deny_all", "domains": [], "default": "drop", "rules_path": "",
        "version": 3,
    }


def test_prepare_policy_uses_logical_worker_network_policy():
    from runtime.policy import build_execution_policy

    requested_ids = []

    class ConfiguredRegistry(_Registry):
        def get_network_policy(self, agent_id):
            requested_ids.append(agent_id)
            if agent_id == "agent-0fefac549b59":
                return {"mode": "learning", "domains": [], "version": 10}
            return {"mode": "whitelist", "domains": ["example.com"], "version": 5}

    class ConfiguredEngine(_Engine):
        def __init__(self):
            self.registry = ConfiguredRegistry([])
            self.rows = []

    result = build_execution_policy(
        ConfiguredEngine(), "com.bianbu.runtime", "host",
        request={"worker_agent_id": "agent-0fefac549b59"},
    )

    assert requested_ids == ["agent-0fefac549b59"]
    assert result.agent_id == "com.bianbu.runtime"
    assert result.policy["worker_agent_id"] == "agent-0fefac549b59"
    assert result.policy["network"] == {
        "mode": "learning", "domains": [], "default": "allow",
        "rules_path": "", "version": 10,
    }


def test_prepare_policy_defaults_to_allow_all_without_persisted_policy():
    from runtime.policy import build_execution_policy

    result = build_execution_policy(
        _Engine([{"policy": "allow"}]), "com.example.agent", "host",
    )

    assert result.policy["network"] == {
        "mode": "allow_all", "domains": [], "default": "allow",
        "rules_path": "", "version": 0,
    }


def test_declared_security_settings_are_what_selects_sandbox():
    """沙箱来自声明的安全设置，不由能力风险或调用方请求决定。"""
    from runtime.policy import build_execution_policy

    engine = _Engine([{"policy": "allow"}])
    host = build_execution_policy(engine, "com.example.agent", "auto")
    assert host.effective_mode == "host"
    assert host.policy["sandbox_required"] is False
    assert host.reason == "未声明额外安全设置，使用 host"

    engine.boundary_reasons = ["可读范围"]
    sandbox = build_execution_policy(engine, "com.example.agent", "auto")
    assert sandbox.effective_mode == "sandbox"
    assert sandbox.sandbox_required is True
    assert sandbox.policy["seccomp_profile"]["path"] == "/run/seccomp"
    assert sandbox.reason == "已声明 可读范围，需要沙箱落实"


def test_declared_settings_switch_a_low_risk_agent_to_sandbox():
    """调用方请求 sandbox 时，legacy 参数与实际模式一致即生效。"""
    from runtime.policy import build_execution_policy

    engine = _Engine([{"policy": "allow"}])
    engine.boundary_reasons = ["可写范围"]

    result = build_execution_policy(engine, "com.example.agent", "sandbox")
    assert result.effective_mode == "sandbox"
    assert result.reason == "已声明 可写范围，需要沙箱落实"


def test_caller_requested_mode_cannot_widen_the_boundary():
    """调用方不能用 requested_mode 把自己的边界放宽到 host。"""
    from runtime.policy import build_execution_policy

    engine = _Engine([{"policy": "allow"}])
    engine.boundary_reasons = ["网络访问范围"]

    result = build_execution_policy(engine, "com.example.agent", "host")
    assert result.effective_mode == "sandbox"
    assert result.policy["requested_mode"] == "sandbox"


def test_seccomp_policy_file_is_readable_by_runtime_user(tmp_path, monkeypatch):
    from securityd import config, seccomp_builder

    sandbox_root = tmp_path / "sandbox"
    monkeypatch.setattr(config, "SANDBOX_RUN_DIR", sandbox_root)
    path = seccomp_builder.build_policy_file("com.example.agent", arch="riscv64",
                                             denylist=["ptrace"])

    assert stat.S_IMODE(sandbox_root.stat().st_mode) == 0o755
    assert stat.S_IMODE((sandbox_root / "com.example.agent").stat().st_mode) == 0o755
    assert stat.S_IMODE(Path(path).stat().st_mode) == 0o644


def test_manifest_entrypoint_is_parsed_by_registry(sec_root):
    from securityd.capability_registry import CapabilityRegistry

    registry = CapabilityRegistry()
    registry.record_manifest(
        "com.example.entrypoint", "1.0.0", "Example", "sig",
        "[agent]\nid='com.example.entrypoint'\n"
        "[runtime]\nentrypoint=['/usr/bin/example', '--serve']\n",
        "now",
    )
    assert registry.get_entrypoint("com.example.entrypoint") == [
        "/usr/bin/example", "--serve"
    ]
def test_invalid_mode_is_rejected():
    from runtime.policy import RuntimePolicyError, build_execution_policy

    with pytest.raises(RuntimePolicyError):
        build_execution_policy(_Engine([]), "com.example.agent", "invalid")


def test_worker_mounts_are_bound_to_the_immutable_policy(tmp_path):
    from runtime.policy import build_execution_policy

    socket_root = tmp_path / "instances"
    socket_root.mkdir()
    result = build_execution_policy(
        _Engine([{"policy": "allow"}]), "com.example.agent", "sandbox",
        request={"worker_data_root": str(tmp_path),
                 "worker_socket_root": str(socket_root)},
    )
    readonly = result.policy["readonly_bind_mounts"]
    assert {item["target"] for item in readonly} >= {"/home/agent"}
    assert {item["host"] for item in readonly} >= {str(tmp_path)}
    mounts = result.policy["writable_mounts"]
    assert {item["target"] for item in mounts} == {
        "/home/agent/workspace",
        "/home/agent/sessions/checkpoints",
        "/home/agent/runtime/worker",
        "/home/agent/logs/provider-capture",
        "/run/bianbu-agent/instances",
    }
    assert str(tmp_path) not in {item["host"] for item in mounts}
    assert str(socket_root) in {item["host"] for item in mounts}


def test_worker_paths_use_canonical_sandbox_targets(tmp_path):
    from runtime.policy import build_execution_policy

    config_path = tmp_path / "config.yaml"
    config_path.write_text("data_dir: .\n", encoding="utf-8")
    socket_root = tmp_path / "instances"
    socket_root.mkdir()
    result = build_execution_policy(
        _Engine([{"policy": "allow"}]), "com.example.agent", "sandbox",
        request={"worker_data_root": str(tmp_path),
                 "worker_socket_root": str(socket_root),
                 "worker_config_path": str(config_path)},
    )
    assert result.policy["worker_config_path"] == "/home/agent/config.yaml"
    assert result.policy["worker_socket_root"] == "/run/bianbu-agent/instances"
    readonly = result.policy["readonly_bind_mounts"]
    assert {item["target"] for item in readonly} >= {"/home/agent"}
    mounts = result.policy["writable_mounts"]
    assert "/home/agent" not in {item["target"] for item in mounts}
    assert "/run/bianbu-agent/instances" in {item["target"] for item in mounts}
    assert str(tmp_path) not in {item["host"] for item in mounts}
    assert str(socket_root) in {item["host"] for item in mounts}


def test_worker_policy_allows_supervisor_rpc_token_only_as_issued_environment():
    from runtime.policy import build_execution_policy

    result = build_execution_policy(
        _Engine([{"policy": "allow"}]), "com.example.agent", "sandbox",
    )
    assert "BIANBU_WORKER_RPC_TOKEN" in result.policy["environment_allowlist"]
    assert "BIANBU_SEC_ROOT" in result.policy["environment_allowlist"]


def test_worker_paths_are_validated_without_securityd_mount_visibility():
    """ProtectHome=yes must not make a valid user-home path fail PrepareStart."""
    from runtime.policy import build_execution_policy

    result = build_execution_policy(
        _Engine([{"policy": "allow"}]), "com.example.agent", "sandbox",
        request={
            "worker_data_root": "/home/bianbu/.bianbu-agent",
            "worker_socket_root": "/run/user/1000/bianbu-agent/instances",
            "worker_config_path": "/home/bianbu/.bianbu-agent/config.yaml",
            "security_uds": "/run/bianbu/securityd.sock",
        },
    )
    assert result.policy["worker_config_path"] == "/home/agent/config.yaml"
    assert result.policy["worker_socket_root"] == "/run/bianbu-agent/instances"


@pytest.mark.parametrize("field", ["worker_data_root", "worker_socket_root", "worker_config_path"])
def test_worker_paths_reject_parent_directory_segments(field):
    from runtime.policy import RuntimePolicyError, build_execution_policy

    request = {field: "/home/bianbu/../tmp/runtime"}
    with pytest.raises(RuntimePolicyError, match="父目录|路径"):
        build_execution_policy(
            _Engine([{"policy": "allow"}]), "com.example.agent", "sandbox", request=request,
        )


def test_ask_or_deny_tool_policy_always_gets_a_sandbox():
    """ask/deny 是用户显式收紧的能力策略，误答不应逃出沙箱。"""
    from runtime.policy import build_execution_policy
    for policy in ('ask', 'deny'):
        result = build_execution_policy(_Engine([{'policy': policy}]),
                                        'com.example.agent', 'host')
        assert result.effective_mode == 'sandbox'
        assert result.policy['sandbox_required'] is True
        assert result.reason == '存在 ask/deny 工具策略，误答不得逃出沙箱'


@pytest.mark.parametrize('requested', ['host', 'auto'])
def test_missing_trusted_entrypoint_never_allows_host(requested):
    from runtime.policy import build_execution_policy
    engine = _Engine([{'policy': 'allow'}])
    engine.registry.get_entrypoint = lambda _: []
    assert build_execution_policy(engine, 'com.example.agent', requested).effective_mode == 'sandbox'


def test_seccomp_profile_exposes_applied_denylist_version():
    from runtime.policy import build_execution_policy
    class Engine(_Engine):
        boundary_reasons = ['系统调用黑名单']
        def get_syscall_policy(self, agent_id, arch):
            return {'applied_policy_version': 17}
    result = build_execution_policy(Engine([]), 'com.bianbu.runtime', 'sandbox')
    assert result.policy['seccomp_profile']['policy_version'] == 17


def test_host_mode_consumes_versioned_seccomp_profile_when_engine_supports_it():
    """D-10：host-process Worker 也应拿到版本化 seccomp 过滤器并标记 applied。"""
    from runtime.policy import build_execution_policy

    class HostEngine(_Engine):
        def __init__(self):
            super().__init__([{"policy": "allow"}])
            self.built = []

        def build_seccomp_profile(self, aid):
            self.built.append(aid)
            return "/run/host-seccomp", 7

    engine = HostEngine()
    result = build_execution_policy(engine, "com.example.agent", "host",
                                    request={"worker_agent_id": "com.example.worker"})
    assert result.effective_mode == "host"
    # 过滤器与 applied 版本按逻辑 Agent（worker_agent_id）生成，而非 lease 主体
    assert engine.built == ["com.example.worker"]
    assert result.policy["seccomp_profile"] == {"path": "/run/host-seccomp", "policy_version": 7}


def test_host_mode_without_profile_builder_keeps_no_seccomp_profile():
    from runtime.policy import build_execution_policy

    result = build_execution_policy(_Engine([{"policy": "allow"}]), "com.example.agent", "host")
    assert result.policy["seccomp_profile"] is None


def test_declared_read_write_ranges_become_mounts():
    from runtime.policy import build_execution_policy

    class Engine(_Engine):
        boundary_reasons = ["可读范围"]

        def get_permission_settings(self, _agent_id):
            return {
                "read": {"include": ["/opt/data"], "exclude": ["/opt/data/secret"]},
                "write": {"include": ["/var/lib/app"], "exclude": ["/var/lib/app/cache"]},
            }

    result = build_execution_policy(Engine([{"policy": "allow"}]),
                                    "com.example.agent", "sandbox")
    readonly = [m for m in result.policy["readonly_bind_mounts"]
                if m["target"] == "/opt/data"]
    writable = [m for m in result.policy["writable_mounts"]
                if m["target"] == "/var/lib/app"]
    assert readonly == [{"host": "/opt/data", "target": "/opt/data"}]
    assert writable == [{"host": "/var/lib/app", "target": "/var/lib/app"}]
    assert result.policy["permissions"] == {
        "read": {"include": ["/opt/data"], "exclude": ["/opt/data/secret"]},
        "write": {"include": ["/var/lib/app"], "exclude": ["/var/lib/app/cache"]},
    }
    # 排除项是最后的覆盖层：可读排除＝不可见，可写排除＝只读。
    assert result.policy["inaccessible_overrides"] == ["/opt/data/secret"]
    assert result.policy["read_only_overrides"] == ["/opt/data/secret", "/var/lib/app/cache"]


def test_write_exclusion_survives_write_include_widening():
    """可写排除必须挡住同一路径下的可写包含，不能被重排冲掉。"""
    from runtime.policy import build_execution_policy

    class Engine(_Engine):
        boundary_reasons = ["可读范围"]

        def get_permission_settings(self, _agent_id):
            return {
                "read": {"include": ["/srv"], "exclude": []},
                "write": {"include": ["/srv"], "exclude": ["/srv/private"]},
            }

    result = build_execution_policy(Engine([{"policy": "allow"}]),
                                    "com.example.agent", "sandbox")
    writable = [m["host"] for m in result.policy["writable_mounts"]]
    assert "/srv" in writable
    assert "/srv/private" not in writable
    assert "/srv/private" in result.policy["read_only_overrides"]


def test_read_exclusion_blocks_overlapping_write_grant():
    """被可读排除的路径不能因为出现在可写范围而重新可见。"""
    from runtime.policy import build_execution_policy

    class Engine(_Engine):
        boundary_reasons = ["可读范围"]

        def get_permission_settings(self, _agent_id):
            return {
                "read": {"include": ["/srv"], "exclude": ["/srv/private"]},
                "write": {"include": ["/srv/private"], "exclude": []},
            }

    result = build_execution_policy(Engine([{"policy": "allow"}]),
                                    "com.example.agent", "sandbox")
    assert "/srv/private" not in [m["host"] for m in result.policy["writable_mounts"]]
    assert "/srv/private" in result.policy["inaccessible_overrides"]


def test_missing_permission_settings_keeps_empty_defaults():
    from runtime.policy import build_execution_policy

    result = build_execution_policy(_Engine([{"policy": "allow"}]),
                                    "com.example.agent", "sandbox")
    assert result.policy["permissions"] == {
        "read": {"include": [], "exclude": []},
        "write": {"include": [], "exclude": []},
    }
