from __future__ import annotations

import importlib


def test_policy_store_merges_and_versions(sec_root):
    from securityd.syscall_policy import SyscallPolicyStore
    store = SyscallPolicyStore()
    first = store.set_global("x86_64", ["ptrace"])
    assert "ptrace" in first["global_additions"]
    assert first["policy_version"] == 1
    result = store.set_agent("agent-a", "x86_64", ["reboot", "bpf"])
    assert result["effective"].count("reboot") == 1
    assert "bpf" in result["agent_additions"]
    assert result["pending_restart"] is True


def test_policy_store_rejects_unknown_and_wrong_arch(sec_root):
    from securityd.syscall_policy import SyscallPolicyStore, SyscallPolicyError
    store = SyscallPolicyStore()
    import pytest
    with pytest.raises(SyscallPolicyError, match="UnknownSyscall"):
        store.set_global("x86_64", ["not_a_syscall"])
    with pytest.raises(SyscallPolicyError, match="SyscallNotApplicable"):
        store.set_global("x86_64", ["openat2"])


def test_default_policy_is_unrestricted(sec_root):
    """没有强制基线：没配置就是不限制，不装载任何过滤器。"""
    from securityd.seccomp_builder import build_policy_file
    from securityd.syscall_policy import SyscallPolicyStore

    store = SyscallPolicyStore()
    policy = store.get("agent-a", "x86_64")
    assert policy["effective"] == []
    assert policy["global_additions"] == [] and policy["agent_additions"] == []
    # 空 denylist 不落盘，调用方据此跳过 `--seccomp`。
    assert build_policy_file("agent-a", "x86_64", policy["effective"]) == ""


def test_user_additions_are_the_only_enforced_syscalls(sec_root):
    from securityd.syscall_policy import SyscallPolicyStore

    store = SyscallPolicyStore()
    store.set_global("x86_64", ["ptrace"])
    result = store.set_agent("agent-a", "x86_64", ["bpf"])
    assert result["effective"] == ["ptrace", "bpf"]
