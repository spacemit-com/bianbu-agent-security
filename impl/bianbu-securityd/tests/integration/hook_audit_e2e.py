#!/usr/bin/env python3
"""SEC-HOOK-05 端到端实证：干预点 trace 真的写进审计链（走 SecurityEngine 本地直调）。

不经 D-Bus（避免依赖 securityd 在跑），直接用 SecurityEngine 作为审计后端，
验证 registry → sink → audit_chain → export → 可查 的完整链路。

用法：BIANBU_SEC_ROOT=/tmp/hooke2e python3 tests/integration/hook_audit_e2e.py
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1].parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "client"))

if not os.environ.get("BIANBU_SEC_ROOT"):
    os.environ["BIANBU_SEC_ROOT"] = tempfile.mkdtemp(prefix="hook_e2e_")

from securityd.engine import SecurityEngine  # noqa: E402
from securityd.interceptor import (  # noqa: E402
    Decision,
    HookPoint,
    InterceptResult,
    InterceptorRegistry,
)
from securityd.models import Permission  # noqa: E402

AGENT = "com.e2e.hookagent"
OK = "\033[32m✅\033[0m"
BAD = "\033[31m❌\033[0m"

failures = []


def check(cond, label, detail=""):
    print(f"  {OK if cond else BAD} {label}" + (f" — {detail}" if detail else ""))
    if not cond:
        failures.append(label)


def main() -> int:
    print(f"数据根：{os.environ['BIANBU_SEC_ROOT']}")
    engine = SecurityEngine()

    # 用 engine 作为审计后端的 client 替身
    class EngineClient:
        def check_permission(self, aid, cap, scope=""):
            return engine.check_permission(aid, cap, scope)

        def audit_log(self, aid, op_type, target, result):
            return engine.audit_log(aid, op_type, target, result)

    ec = EngineClient()

    print("\n[1] 注册 Agent 能力（file.read=trusted/L1，system.execute 不授予）")
    engine.register_capabilities(AGENT, [
        Permission.from_dict({"capability": "file.read", "domain": "data",
                              "risk_level": "L1", "confirm": "trusted",
                              "scope": "/tmp"}),
    ])
    check(any(a["agent_id"] == AGENT for a in engine.list_agents()),
          "Agent 已注册")

    print("\n[2] 挂载干预点框架 + 审计 sink")
    import bianbu_security_handlers as h

    reg = InterceptorRegistry()
    h.register_core_handlers(reg, with_audit=False)
    reg.set_audit_sink(h.make_audit_sink(AGENT, client_provider=lambda: ec))
    handlers = reg.list_handlers(HookPoint.PRE_TOOL_CALL)
    check(handlers == [(10, "sec_capability")],
          "sec_capability@10 已注册", str(handlers))

    print("\n[3] ALLOW 路径：file.read /tmp（trusted）")
    r = reg.invoke(HookPoint.PRE_TOOL_CALL, AGENT,
                   {"tool": "read_file", "capability": "file.read",
                    "scope": "/tmp"},
                   client_provider=lambda: ec)
    check(r.decision == Decision.ALLOW, "决策 ALLOW", r.decision.value)
    check(len(r.metadata["_handler_trace"]) == 1, "trace 含 1 个 handler")

    print("\n[4] BLOCK 路径：system.execute（未授予）")
    r = reg.invoke(HookPoint.PRE_TOOL_CALL, AGENT,
                   {"tool": "terminal", "capability": "system.execute",
                    "scope": ""},
                   client_provider=lambda: ec)
    check(r.decision == Decision.BLOCK, "决策 BLOCK", r.decision.value)
    check("未授权或已撤销" in r.message, "拒绝理由正确")

    print("\n[5] 追加 DLP handler，验证 ALLOW→CONFIRM 提升（DLP-06 机制）")

    def dlp_stub(aid, hp, data, ctx):
        if "13812345678" in json.dumps(data.get("args", {}), ensure_ascii=False):
            return InterceptResult(decision=Decision.CONFIRM,
                                   message="检出手机号")
        return InterceptResult(decision=Decision.ALLOW)

    reg.register(HookPoint.PRE_TOOL_CALL, dlp_stub, name="dlp_stub", priority=50)
    r = reg.invoke(HookPoint.PRE_TOOL_CALL, AGENT,
                   {"tool": "read_file", "capability": "file.read",
                    "scope": "/tmp", "args": {"note": "call 13812345678"}},
                   client_provider=lambda: ec)
    check(r.decision == Decision.CONFIRM, "SEC=ALLOW + DLP 检出 → CONFIRM",
          r.decision.value)
    names = [t[0] for t in r.metadata["_handler_trace"]]
    check(names == ["sec_capability", "dlp_stub"], "执行顺序 10→50", str(names))

    print("\n[6] 导出审计链，验证 hook trace 落库")
    path = engine.export_audit(json.dumps({"agent_id": AGENT}), "json")
    data = json.loads(Path(path).read_text())
    records = data.get("records", [])
    hook_recs = [x for x in records
                 if str(x.get("op_type", "")).startswith("hook:")]
    check(len(hook_recs) >= 3, f"hook 审计记录 ≥3 条（实得 {len(hook_recs)}）")

    ops = {x["op_type"] for x in hook_recs}
    check(ops == {"hook:pre_tool_call"}, "op_type 前缀正确", str(ops))

    targets = [x["target"] for x in hook_recs]
    check("ALLOW" in targets and "BLOCK" in targets and "CONFIRM" in targets,
          "三种决策均已记录", str(targets))

    traced = [x for x in hook_recs if "sec_capability@" in str(x.get("result", ""))]
    check(len(traced) == len(hook_recs), "每条都带 handler 延迟数据")

    confirm_rec = [x for x in hook_recs if x["target"] == "CONFIRM"]
    check(confirm_rec and "dlp_stub@" in confirm_rec[0]["result"],
          "CONFIRM 记录含两个 handler 的 trace",
          confirm_rec[0]["result"] if confirm_rec else "-")

    print("\n[7] 完整性校验（hook 记录不破坏哈希链）")
    check(engine.verify_audit_chain(path), "导出链完整性 intact")
    check(engine.audit.verify_live(), "在线链完整性 intact")

    print("\n[8] 延迟聚合（模拟 WebUI /api/audit/hook-points）")
    latency = {}
    for x in hook_recs:
        for part in str(x.get("result", "")).split(","):
            if "@" in part and "=" in part:
                nm, rest = part.split("@", 1)
                try:
                    ms = float(rest.split("=", 1)[0])
                except ValueError:
                    continue
                acc = latency.setdefault(nm, [0.0, 0])
                acc[0] += ms
                acc[1] += 1
    check("sec_capability" in latency, "可聚合出 sec_capability 平均延迟",
          f"avg={latency['sec_capability'][0]/latency['sec_capability'][1]:.2f}ms "
          f"calls={latency['sec_capability'][1]}" if "sec_capability" in latency else "-")

    engine.close()
    print()
    if failures:
        print(f"{BAD} 失败 {len(failures)} 项：{failures}")
        return 1
    print(f"{OK} 全部通过")
    return 0


if __name__ == "__main__":
    sys.exit(main())
