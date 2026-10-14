"""DLP-10 — WebUI DLP 接口的聚合/矩阵逻辑（纯函数语义，不起 Flask）。

与 test_hook_audit_filter.py 同思路：把 webui/app.py 里的聚合逻辑按同语义
在此单测，避免测试依赖 Flask test client 与 D-Bus。
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from securityd.dlp.pii_scanner import PIIScanner, PIIType  # noqa: E402
from securityd.dlp.policy_store import DLPAction, DLPPolicyStore  # noqa: E402

AGENT = "com.test.agent"
ID_CARD = "110101199003076173"
PHONE = "13812345678"


@pytest.fixture
def store(tmp_path):
    s = DLPPolicyStore(db_path=tmp_path / "dlp.db")
    yield s
    s.close()


def _matrix(store, agent):
    """与 webui/app.py::api_dlp_matrix 同语义。"""
    explicit = {r["pii_type"]: r["action"]
                for r in store.list_policies(agent)} if agent else {}
    return [{
        "pii_type": t.value,
        "action": store.get_action(agent, t).value if agent else "-",
        "explicit": t.value in explicit,
        "source": "agent" if t.value in explicit else "inherited",
    } for t in PIIType]


def _dlp_stats(records):
    """与 webui/app.py::api_dlp_stats 同语义。"""
    by_point, by_decision, total = {}, {}, 0
    for r in records:
        op = str(r.get("op_type", ""))
        if not op.startswith("hook:"):
            continue
        if "dlp_" not in str(r.get("result", "")):
            continue
        total += 1
        hp = op[5:]
        by_point[hp] = by_point.get(hp, 0) + 1
        dec = str(r.get("target", ""))
        by_decision[dec] = by_decision.get(dec, 0) + 1
    return total, by_point, by_decision


# ———————————————————— 矩阵 ————————————————————
def test_matrix_covers_all_eight_types(store):
    rows = _matrix(store, AGENT)
    assert len(rows) == 8
    assert {r["pii_type"] for r in rows} == {t.value for t in PIIType}


def test_matrix_shows_fallback_actions(store):
    """未配置时统一走兜底动作 mask，不再按风险级分档。"""
    by = {r["pii_type"]: r for r in _matrix(store, AGENT)}
    assert all(r["action"] == "mask" for r in by.values())
    assert all(not r["explicit"] for r in _matrix(store, AGENT))


def test_matrix_marks_explicit(store):
    """显式配置的行要能与继承区分 —— 否则用户不知道哪些是自己设的。"""
    store.set_policy(AGENT, PIIType.PHONE, DLPAction.DENY)
    by = {r["pii_type"]: r for r in _matrix(store, AGENT)}
    assert by["phone"]["explicit"] is True
    assert by["phone"]["source"] == "agent"
    assert by["phone"]["action"] == "deny"
    assert by["email"]["explicit"] is False
    assert by["email"]["source"] == "inherited"


def test_matrix_omits_risk_level(store):
    """矩阵不再暴露风险级：处置由动作决定，不由风险档位决定。"""
    rows = _matrix(store, AGENT)
    assert all("risk_level" not in r for r in rows)


def test_matrix_no_agent_returns_dash(store):
    """未选 Agent 时不显示动作（避免误以为是全局策略）。"""
    rows = _matrix(store, "")
    assert all(r["action"] == "-" for r in rows)


def test_matrix_reflects_wildcard_default(store):
    """agent 级 * 默认要体现在矩阵里（继承来源，非显式行）。"""
    store.set_policy(AGENT, "*", DLPAction.DENY)
    by = {r["pii_type"]: r for r in _matrix(store, AGENT)}
    assert by["email"]["action"] == "deny"
    assert by["email"]["explicit"] is False  # * 不是 email 这一行的显式配置


def test_delete_restores_fallback(store):
    """恢复默认后回到兜底。"""
    store.set_policy(AGENT, PIIType.ID_CARD, DLPAction.ALLOW)
    assert _matrix(store, AGENT)[
        [t.value for t in PIIType].index("id_card")]["action"] == "allow"
    store.delete_policy(AGENT, PIIType.ID_CARD)
    by = {r["pii_type"]: r for r in _matrix(store, AGENT)}
    assert by["id_card"]["action"] == "mask"
    assert by["id_card"]["explicit"] is False


# ———————————————————— 试扫 ————————————————————
def test_scan_reports_action_per_finding(store):
    """试扫要显示每处命中在该 Agent 下的处置 —— 这是配置校验的用途。"""
    store.set_policy(AGENT, PIIType.PHONE, DLPAction.DENY)
    scanner = PIIScanner()
    r = scanner.scan_and_mask(f"电话 {PHONE}，身份证 {ID_CARD}")
    actions = {f.pii_type.value: store.get_action(AGENT, f.pii_type).value
               for f in r.findings}
    assert actions["phone"] == "deny"
    assert actions["id_card"] == "mask"


def test_scan_returns_masked_text(store):
    scanner = PIIScanner()
    r = scanner.scan_and_mask(f"身份证 {ID_CARD}")
    assert ID_CARD not in r.masked_text


def test_scan_clean_text(store):
    r = PIIScanner().scan_and_mask("今天天气不错")
    assert r.findings == []
    assert r.masked_text == "今天天气不错"


# ———————————————————— 统计 ————————————————————
RECORDS = [
    {"op_type": "hook:input", "target": "MODIFY",
     "result": "dlp_input@2.1=MODIFY"},
    {"op_type": "hook:input", "target": "BLOCK",
     "result": "dlp_input@1.8=BLOCK"},
    {"op_type": "hook:pre_tool_call", "target": "CONFIRM",
     "result": "sec_capability@0.4=ALLOW,dlp_pre_tool@3.2=CONFIRM"},
    {"op_type": "hook:pre_tool_call", "target": "ALLOW",
     "result": "sec_capability@0.3=ALLOW"},          # 无 dlp_ → 不计入
    {"op_type": "read_file", "target": "file.read:/tmp",
     "result": "executed"},                          # 业务审计 → 不计入
]


def test_stats_counts_only_dlp_records():
    total, by_point, _ = _dlp_stats(RECORDS)
    assert total == 3  # 两条 dlp_input + 一条 dlp_pre_tool
    assert by_point == {"input": 2, "pre_tool_call": 1}


def test_stats_by_decision():
    _, _, by_decision = _dlp_stats(RECORDS)
    assert by_decision == {"MODIFY": 1, "BLOCK": 1, "CONFIRM": 1}


def test_stats_excludes_non_dlp_hook_records():
    """只有 SEC handler 的 hook 记录不计入 DLP 统计。"""
    total, _, _ = _dlp_stats([RECORDS[3]])
    assert total == 0


def test_stats_excludes_business_audit():
    total, _, _ = _dlp_stats([RECORDS[4]])
    assert total == 0


def test_stats_empty():
    assert _dlp_stats([]) == (0, {}, {})


# ———————————————————— 动作枚举一致性 ————————————————————
def test_frontend_action_list_matches_backend():
    """前端下拉的 4 个动作必须与后端枚举一致 —— 否则会写入非法值。"""
    frontend = ["allow", "ask", "deny", "mask"]
    assert frontend == [a.value for a in DLPAction]


def test_invalid_action_rejected_by_store(store):
    with pytest.raises(ValueError):
        store.set_policy(AGENT, PIIType.PHONE, "obliterate")
