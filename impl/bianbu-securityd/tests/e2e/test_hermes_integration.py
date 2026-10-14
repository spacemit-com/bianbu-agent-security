"""TC-E2E-01：hermes agent 经 D-Bus 全功能覆盖（7.5 节 9 步骤）。

前置：securityd 已在会话/系统总线运行（BIANBU_SEC_SESSION=1 走会话总线）。
以 bianbu_security_client 作为 hermes agent 的调用封装。
自动确认由 securityd 侧 confirm auto-policy 决定；本用例聚焦决策/审计正确性。

运行：需要真实 D-Bus 服务，独立于 unit（标记 e2e）。
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT / "client"))

pytestmark = pytest.mark.skipif(
    os.environ.get("BIANBU_E2E") != "1",
    reason="需真实 D-Bus securityd（设 BIANBU_E2E=1 且服务已启动）")


def test_e2e_full_flow():
    import bianbu_security_client as sc

    aid = "com.bianbu.test-security-agent"
    fixtures = ROOT / "tests" / "fixtures" / "test-security-agent"

    # 步骤 1：安装（验签 + 注册）
    r = sc.verify_manifest(str(fixtures))
    assert r["valid"], r["reason"]
    assert len(r["permissions"]) == 5
    ok = sc.register_capabilities(aid, r["permissions"])
    assert ok

    # 步骤 2：声明 allow 的只读工具 → ALLOW(0)
    assert sc.check_permission(aid, "read_file") == 0
    assert sc.check_permission(aid, "search_files") == 0

    # 步骤 3：声明 ask 的写入工具 → 首次 ASK(1)
    assert sc.check_permission(aid, "write_file", "~/Documents/bianbu-test") == 1
    assert sc.check_permission(aid, "terminal") == 1

    # 步骤 4：声明 deny 的工具 → DENY(2)
    assert sc.check_permission(aid, "process") == 2

    # 步骤 9：审计导出 + 验证
    sc.audit_log(aid, "e2e_test", "marker", "allow")
    path = sc.export_audit('{"agent_id":"%s"}' % aid, "json")
    assert sc.verify_audit_chain(path) is True

    # 沙箱策略生成
    pol = sc.build_sandbox_policy(aid)
    assert Path(pol["seccomp_path"]).exists()
