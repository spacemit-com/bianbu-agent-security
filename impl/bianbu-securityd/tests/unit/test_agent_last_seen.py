""""最近活动"（last_seen）契约测试。

WebUI 的 Agent 清单用 ``last_seen`` 展示最近活动时间。Securityd 没有独立的
心跳表，因此该字段由审计链、系统调用拦截事件和 caller 绑定三类真实活动证据
合并而来；这里逐条固定这些来源，并固定"没有活动证据时不给安装时间冒充活动"
与"时间戳带时区"两条契约，防止界面再次出现空值或差 8 小时的时间。
"""
from __future__ import annotations


def _manifest(engine, agent_id: str, installed_at: str) -> None:
    engine.registry.record_manifest(agent_id, "1.0.0", agent_id, "", "", installed_at)


def _audit_timestamps(engine, agent_id: str) -> list[str]:
    import json

    page = engine.audit.query(json.dumps(
        {"filter": "all", "agent_id": agent_id, "limit": 100}))
    return [str(record["ts"]) for record in page["records"]]


def test_list_agents_without_activity_has_no_last_seen(engine):
    """装了但从没跑过的 Agent 不能把安装时间冒充成最近活动。"""
    _manifest(engine, "com.quiet", "2026-01-02 03:04:05")

    (row,) = engine.list_agents()

    assert row["agent_id"] == "com.quiet"
    assert row["last_seen"] == ""


def test_list_agents_normalizes_install_time_to_utc_iso(engine):
    """裸 ``YYYY-MM-DD HH:MM:SS`` 是 UTC；带时区下发，前端本地化才不会差 8 小时。"""
    _manifest(engine, "com.quiet", "2026-01-02 03:04:05")

    (row,) = engine.list_agents()

    assert row["installed_at"] == "2026-01-02T03:04:05.000+00:00"


def test_list_agents_keeps_iso_install_time_untouched(engine):
    _manifest(engine, "com.iso", "2026-01-02T03:04:05.600+00:00")

    (row,) = engine.list_agents()

    assert row["installed_at"] == "2026-01-02T03:04:05.600+00:00"


def test_list_agents_last_seen_prefers_newer_audit_activity(engine):
    _manifest(engine, "com.active", "2020-01-02 03:04:05")

    from securityd.models import Permission

    engine.register_capabilities("com.active", [Permission.from_dict({
        "capability": "file.read", "domain": "data", "risk_level": "L1",
        "confirm": "trusted", "scope": ""})])

    (row,) = engine.list_agents()
    newest_audit = max(_audit_timestamps(engine, "com.active"))

    assert row["last_seen"] == newest_audit
    assert row["last_seen"] > "2020-01-02T03:04:05.000+00:00"


def test_list_agents_last_seen_includes_caller_binding(engine):
    from securityd.models import CallerContext

    _manifest(engine, "com.bound", "2020-01-02 03:04:05")
    engine.registry.bind_agent("com.bound", CallerContext(
        sender=":1.42", uid=1000, pid=4242, executable="/usr/bin/agent",
        cgroup="/system.slice/agent.service", session_id="session-1"),
        "2031-05-06T07:08:09.100+00:00")

    (row,) = engine.list_agents()

    assert row["last_seen"] == "2031-05-06T07:08:09.100+00:00"


def test_list_agents_last_seen_includes_syscall_events(engine):
    _manifest(engine, "com.syscall", "2020-01-02 03:04:05")
    engine.syscall_audit.record(
        "com.bianbu.runtime", 4242, "riscv64", "ptrace", 117, "seccomp", 1,
        worker_agent_id="com.syscall", instance_id="com.syscall-1")

    (row,) = engine.list_agents()
    (event,) = engine.syscall_audit.query(agent_id="com.syscall", limit=1)

    assert row["last_seen"] == event["ts"]


def test_activity_index_reads_older_audit_shards(sec_root):
    from securityd import config
    from securityd.audit_chain import AuditChainEngine

    current = AuditChainEngine()
    current.log("com.current", "register", "com.current", "success")
    older = AuditChainEngine(config.AUDIT_DIR / "202001.db")
    older.log("com.older", "check_permission", "file.read", "ALLOW")
    try:
        index = current.activity_index(["com.current", "com.older", "com.missing"])
    finally:
        older.close()
        current.close()

    assert set(index) == {"com.current", "com.older"}
    assert index["com.current"].endswith("+00:00")
    assert index["com.older"].endswith("+00:00")


def test_syscall_latest_seen_matches_either_identity(engine):
    store = engine.syscall_audit
    store.record("com.bianbu.runtime", 11, "riscv64", "mount", 40, "seccomp", 1,
                 worker_agent_id="agent.worker", event_id="evt-1")
    (event,) = store.query(agent_id="agent.worker", limit=1)

    assert store.latest_seen(["agent.worker"]) == {"agent.worker": event["ts"]}
    assert store.latest_seen(["com.bianbu.runtime"]) == {"com.bianbu.runtime": event["ts"]}
    assert store.latest_seen(["agent.unknown"]) == {}
