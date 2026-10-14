"""执行后端推导：有安全设置才进沙箱，不是人来指定。"""
from __future__ import annotations

from securityd.execution_mode import decide


def test_no_declared_settings_stays_on_host():
    result = decide(read={"include": [], "exclude": []},
                    write={"include": [], "exclude": []},
                    network={"mode": "allow_all", "domains": []},
                    syscall_additions=[])
    assert result["mode"] == "host"
    assert result["reasons"] == []


def test_each_declared_setting_forces_sandbox():
    cases = {
        "可读范围": dict(read={"include": ["/opt/data"], "exclude": []}),
        "可写范围": dict(write={"include": [], "exclude": ["/srv/cache"]}),
        "网络访问范围": dict(network={"mode": "whitelist", "domains": ["api.x"]}),
        "系统调用黑名单": dict(syscall_additions=["ptrace"]),
    }
    for reason, override in cases.items():
        kwargs = {"read": None, "write": None, "network": None,
                  "syscall_additions": []}
        kwargs.update(override)
        result = decide(**kwargs)
        assert result["mode"] == "sandbox", reason
        assert result["reasons"] == [reason]


def test_allow_all_network_is_not_a_restriction():
    result = decide(network={"mode": "allow_all", "domains": ["whatever.example"]})
    assert result["mode"] == "host"


def test_untrusted_launch_never_gets_host():
    result = decide(trusted=False)
    assert result["mode"] == "sandbox"
    assert result["reasons"] == ["缺少可信 manifest 或固定启动程序"]
