"""SEC-HOOK-05 — 审计的 hook_point 过滤与延迟统计（纯过滤逻辑，不起 Flask）。

WebUI 的 /api/audit?hook=... 与 /api/audit/hook-points 的过滤/聚合是纯函数逻辑，
这里对同样的语义做单测（避免测试依赖 Flask test client 与 D-Bus）。
"""
from __future__ import annotations


def _filter_by_hook(records, hook):
    """与 webui/app.py::api_audit 的 hook 过滤同语义。"""
    if not hook:
        return records
    if hook == "any":
        return [r for r in records if str(r.get("op_type", "")).startswith("hook:")]
    if hook == "exclude":
        return [r for r in records
                if not str(r.get("op_type", "")).startswith("hook:")]
    want = f"hook:{hook}"
    return [r for r in records if r.get("op_type") == want]


def _aggregate(records):
    """与 webui/app.py::api_audit_hook_points 的聚合同语义。"""
    counts, latency = {}, {}
    for r in records:
        op = str(r.get("op_type", ""))
        if not op.startswith("hook:"):
            continue
        hp = op[5:]
        counts[hp] = counts.get(hp, 0) + 1
        for part in str(r.get("result", "")).split(","):
            if "@" in part and "=" in part:
                name, rest = part.split("@", 1)
                try:
                    ms = float(rest.split("=", 1)[0])
                except ValueError:
                    continue
                acc = latency.setdefault(name, [0.0, 0])
                acc[0] += ms
                acc[1] += 1
    return counts, {k: (round(v[0] / v[1], 2), v[1]) for k, v in latency.items()}


RECORDS = [
    {"seq": 1, "op_type": "hook:pre_tool_call", "target": "ALLOW",
     "result": "sec_capability@1.0=ALLOW"},
    {"seq": 2, "op_type": "read_file", "target": "file.read:/tmp",
     "result": "executed"},
    {"seq": 3, "op_type": "hook:pre_tool_call", "target": "BLOCK",
     "result": "sec_capability@2.0=BLOCK"},
    {"seq": 4, "op_type": "hook:output", "target": "ALLOW",
     "result": "dlp_output@9.0=ALLOW"},
    {"seq": 5, "op_type": "terminal", "target": "system.execute:", "result": "deny"},
]


def test_filter_specific_hook_point():
    got = _filter_by_hook(RECORDS, "pre_tool_call")
    assert [r["seq"] for r in got] == [1, 3]


def test_filter_any_hook():
    got = _filter_by_hook(RECORDS, "any")
    assert [r["seq"] for r in got] == [1, 3, 4]


def test_filter_exclude_hook():
    """排除 hook 记录 → 只剩业务审计（老看法不受新噪声干扰）。"""
    got = _filter_by_hook(RECORDS, "exclude")
    assert [r["seq"] for r in got] == [2, 5]


def test_filter_empty_returns_all():
    assert _filter_by_hook(RECORDS, "") == RECORDS


def test_filter_unknown_hook_point():
    assert _filter_by_hook(RECORDS, "nonexistent") == []


def test_aggregate_counts():
    counts, _ = _aggregate(RECORDS)
    assert counts == {"pre_tool_call": 2, "output": 1}


def test_aggregate_latency():
    _, latency = _aggregate(RECORDS)
    # sec_capability: (1.0 + 2.0) / 2 = 1.5，2 次调用
    assert latency["sec_capability"] == (1.5, 2)
    assert latency["dlp_output"] == (9.0, 1)


def test_aggregate_ignores_business_records():
    """业务审计记录（result 非 trace 格式）不进延迟统计。"""
    _, latency = _aggregate(RECORDS)
    assert "executed" not in latency
    assert "deny" not in latency


def test_aggregate_malformed_latency():
    """畸形延迟值跳过，不抛异常。"""
    recs = [{"op_type": "hook:input", "result": "h@notanumber=ALLOW,ok@1.5=ALLOW"}]
    counts, latency = _aggregate(recs)
    assert counts == {"input": 1}
    assert "h" not in latency
    assert latency["ok"] == (1.5, 1)


def test_aggregate_empty():
    counts, latency = _aggregate([])
    assert counts == {} and latency == {}
