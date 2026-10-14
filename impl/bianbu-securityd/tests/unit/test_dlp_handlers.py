"""DLP-02/03/04 — 干预点 handler 行为。"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from securityd.dlp.handlers import (  # noqa: E402
    DLPSessionStore,
    input_handler,
    pre_model_handler,
    register_dlp_handlers,
    startup_handler,
)
from securityd.dlp.pii_scanner import PIIScanner, PIIType  # noqa: E402
from securityd.dlp.policy_store import (  # noqa: E402
    WILDCARD,
    DLPAction,
    DLPPolicyStore,
)
from securityd.interceptor import (  # noqa: E402
    Decision,
    HookPoint,
    InterceptorRegistry,
)

AGENT = "com.test.agent"
PHONE = "13812345678"
ID_CARD = "110101199003076173"


@pytest.fixture
def ctx(tmp_path):
    store = DLPPolicyStore(db_path=tmp_path / "dlp.db")
    sessions = DLPSessionStore()
    c = {"dlp_scanner": PIIScanner(), "dlp_store": store,
         "dlp_sessions": sessions, "session_id": "sess-1"}
    yield c
    store.close()


# ———————————————————————— DLP-02 startup ————————————————————————
def test_startup_loads_manifest_policy(ctx):
    r = startup_handler(AGENT, HookPoint.AGENT_STARTUP,
                        {"manifest": {"dlp": {"phone": "deny"}}}, ctx)
    assert r.decision == Decision.ALLOW
    assert r.metadata["dlp_policies_loaded"] == 1
    assert ctx["dlp_store"].get_action(AGENT, PIIType.PHONE) == DLPAction.DENY


def test_startup_no_dlp_section_ok(ctx):
    """无 [dlp] 节不报错，沿用兜底策略。"""
    r = startup_handler(AGENT, HookPoint.AGENT_STARTUP,
                        {"manifest": {"agent": {"id": AGENT}}}, ctx)
    assert r.decision == Decision.ALLOW
    assert r.metadata["dlp_policies_loaded"] == 0


def test_startup_empty_data(ctx):
    assert startup_handler(AGENT, HookPoint.AGENT_STARTUP, None,
                           ctx).decision == Decision.ALLOW


# ———————————————————————— DLP-03 input ————————————————————————
def test_input_clean_text_allow(ctx):
    r = input_handler(AGENT, HookPoint.INPUT, "今天天气不错", ctx)
    assert r.decision == Decision.ALLOW
    assert r.modified_data is None


def test_input_high_risk_masked_by_default(ctx):
    """身份证兜底策略 mask → MODIFY + 脱敏。"""
    r = input_handler(AGENT, HookPoint.INPUT, f"身份证 {ID_CARD}", ctx)
    assert r.decision == Decision.MODIFY
    assert ID_CARD not in r.modified_data
    assert "[PII-身份证-001]" in r.modified_data
    assert r.metadata["max_risk"] == "L3"


def test_input_default_policy_masks(ctx):
    """手机号未配置 → 兜底 mask，脱敏后放行。"""
    r = input_handler(AGENT, HookPoint.INPUT, f"电话 {PHONE}", ctx)
    assert r.decision == Decision.MODIFY
    assert PHONE not in r.modified_data
    assert "phone" in r.metadata["pii_types"]


def test_input_allow_policy_not_masked(ctx):
    ctx["dlp_store"].set_policy(AGENT, PIIType.PHONE, DLPAction.ALLOW)
    r = input_handler(AGENT, HookPoint.INPUT, f"电话 {PHONE}", ctx)
    assert r.decision == Decision.ALLOW
    assert r.modified_data is None


def test_input_block_policy(ctx):
    ctx["dlp_store"].set_policy(AGENT, PIIType.PHONE, DLPAction.DENY)
    r = input_handler(AGENT, HookPoint.INPUT, f"电话 {PHONE}", ctx)
    assert r.decision == Decision.BLOCK
    assert "phone" in r.message or "受限敏感信息" in r.message


def test_input_mask_map_saved_to_session(ctx):
    input_handler(AGENT, HookPoint.INPUT, f"身份证 {ID_CARD}", ctx)
    saved = ctx["dlp_sessions"].get("sess-1")
    assert saved["[PII-身份证-001]"] == ID_CARD


def test_input_mixed_policy_masks_only_target(ctx):
    """姓名 allow + 身份证 mask → 只脱身份证，姓名保留。

    无脑全脱会破坏正常业务语义。
    """
    ctx["dlp_store"].set_policy(AGENT, PIIType.NAME, DLPAction.ALLOW)
    r = input_handler(AGENT, HookPoint.INPUT,
                      f"姓名：张伟，身份证 {ID_CARD}", ctx)
    assert r.decision == Decision.MODIFY
    assert "张伟" in r.modified_data       # allow 不脱
    assert ID_CARD not in r.modified_data  # mask 脱掉


def test_input_worst_action_wins(ctx):
    """同段文本多类型时取最严处置。"""
    ctx["dlp_store"].set_policy(AGENT, PIIType.PHONE, DLPAction.DENY)
    r = input_handler(AGENT, HookPoint.INPUT,
                      f"电话 {PHONE}，身份证 {ID_CARD}", ctx)
    assert r.decision == Decision.BLOCK  # BLOCK > MASK


def test_input_dict_form(ctx):
    r = input_handler(AGENT, HookPoint.INPUT, {"text": f"身份证 {ID_CARD}"}, ctx)
    assert r.decision == Decision.MODIFY


def test_input_empty(ctx):
    assert input_handler(AGENT, HookPoint.INPUT, "", ctx).decision == Decision.ALLOW


def test_input_prefers_agent_aware_dataplane_scanner(ctx):
    """PA 注入混合扫描器时，handler 必须把可信 agent_id 传入 UDS 选路。"""
    local = PIIScanner()

    class AgentAwareScanner:
        def __init__(self):
            self.calls = []

        def scan_mask_subset_for_agent(self, agent_id, text, store):
            self.calls.append((agent_id, text))
            return local.scan_and_mask(text)

    scanner = AgentAwareScanner()
    ctx["dlp_scanner"] = scanner
    ctx["dlp_store"].set_policy(AGENT, PIIType.PHONE, DLPAction.MASK)
    r = input_handler(AGENT, HookPoint.INPUT, f"电话 {PHONE}", ctx)
    assert scanner.calls == [(AGENT, f"电话 {PHONE}")]
    assert r.decision == Decision.MODIFY
    assert PHONE not in r.modified_data


# ———————————————————————— DLP-04 pre_model_call ————————————————————————
def test_local_model_low_risk_allow(ctx):
    ctx["dlp_store"].set_policy(AGENT, PIIType.PHONE, DLPAction.ALLOW)
    r = pre_model_handler(AGENT, HookPoint.PRE_MODEL_CALL,
                          {"prompt": f"电话 {PHONE}",
                           "endpoint": "http://localhost:8080"}, ctx)
    assert r.decision == Decision.ALLOW


def test_cloud_high_risk_forced_mask(ctx):
    """云端 + L3 → 强制脱敏，即使策略是 allow。"""
    ctx["dlp_store"].set_policy(AGENT, PIIType.ID_CARD, DLPAction.ALLOW)
    r = pre_model_handler(AGENT, HookPoint.PRE_MODEL_CALL,
                          {"prompt": f"身份证 {ID_CARD}",
                           "endpoint": "https://api.example.com/v1"}, ctx)
    assert r.decision == Decision.MODIFY
    assert ID_CARD not in r.modified_data
    assert r.metadata["cloud_forced_mask"] is True


def test_local_high_risk_respects_allow(ctx):
    """本地 + L3 + allow → 放行不脱（本地不出网，可接受）。"""
    ctx["dlp_store"].set_policy(AGENT, PIIType.ID_CARD, DLPAction.ALLOW)
    r = pre_model_handler(AGENT, HookPoint.PRE_MODEL_CALL,
                          {"prompt": f"身份证 {ID_CARD}",
                           "endpoint": "http://127.0.0.1:11434"}, ctx)
    assert r.decision == Decision.ALLOW


def test_cloud_block_policy(ctx):
    ctx["dlp_store"].set_policy(AGENT, PIIType.ID_CARD, DLPAction.DENY)
    r = pre_model_handler(AGENT, HookPoint.PRE_MODEL_CALL,
                          {"prompt": f"身份证 {ID_CARD}",
                           "endpoint": "https://api.example.com"}, ctx)
    assert r.decision == Decision.BLOCK


def test_cloud_low_risk_only_not_forced(ctx):
    """云端但只有 L1/L2 且策略为 allow → 不强制脱敏。"""
    ctx["dlp_store"].set_policy(AGENT, PIIType.PHONE, DLPAction.ALLOW)
    r = pre_model_handler(AGENT, HookPoint.PRE_MODEL_CALL,
                          {"prompt": f"电话 {PHONE}",
                           "endpoint": "https://api.example.com"}, ctx)
    assert r.decision == Decision.ALLOW
    assert not r.metadata.get("cloud_forced_mask")


def test_is_cloud_explicit_override(ctx):
    """context["is_cloud"] 显式指定优先于 endpoint 推断。"""
    ctx["is_cloud"] = True
    r = pre_model_handler(AGENT, HookPoint.PRE_MODEL_CALL,
                          {"prompt": f"身份证 {ID_CARD}",
                           "endpoint": "http://localhost:8080"}, ctx)
    assert r.decision == Decision.MODIFY
    assert r.metadata["is_cloud"] is True


def test_unix_socket_treated_local(ctx):
    r = pre_model_handler(AGENT, HookPoint.PRE_MODEL_CALL,
                          {"prompt": f"身份证 {ID_CARD}",
                           "endpoint": "unix:/run/model.sock"}, ctx)
    assert r.metadata["is_cloud"] is False


def test_prompt_string_form(ctx):
    ctx["endpoint"] = "https://api.example.com"
    r = pre_model_handler(AGENT, HookPoint.PRE_MODEL_CALL,
                          f"身份证 {ID_CARD}", ctx)
    assert r.decision == Decision.MODIFY


def test_no_endpoint_treated_local(ctx):
    """无 endpoint 信息按本地处理（保守放行，不误拦本地推理）。"""
    ctx["dlp_store"].set_policy(AGENT, PIIType.ID_CARD, DLPAction.ALLOW)
    r = pre_model_handler(AGENT, HookPoint.PRE_MODEL_CALL,
                          {"prompt": f"身份证 {ID_CARD}"}, ctx)
    assert r.metadata["is_cloud"] is False
    assert r.decision == Decision.ALLOW


# ———————————————————————— SessionStore ————————————————————————
def test_session_store_merge_and_get():
    s = DLPSessionStore()
    s.merge("s1", {"[PII-手机号-001]": PHONE})
    s.merge("s1", {"[PII-邮箱-001]": "a@b.com"})
    assert len(s.get("s1")) == 2


def test_session_store_clear():
    s = DLPSessionStore()
    s.merge("s1", {"[PII-手机号-001]": PHONE})
    assert s.clear("s1") == 1
    assert s.get("s1") == {}
    assert s.clear("s1") == 0  # 幂等


def test_session_store_isolation():
    s = DLPSessionStore()
    s.merge("s1", {"a": "1"})
    s.merge("s2", {"b": "2"})
    assert s.get("s1") == {"a": "1"}
    s.clear("s1")
    assert s.get("s2") == {"b": "2"}  # 互不影响


def test_session_store_get_returns_copy():
    """返回副本，外部改动不污染内部状态。"""
    s = DLPSessionStore()
    s.merge("s1", {"a": "1"})
    s.get("s1")["a"] = "tampered"
    assert s.get("s1")["a"] == "1"


# ———————————————————————— 注册与链路 ————————————————————————
def test_register_dlp_handlers_idempotent():
    reg = InterceptorRegistry()
    register_dlp_handlers(reg)
    register_dlp_handlers(reg)
    assert [n for _, n in reg.list_handlers(HookPoint.INPUT)] == ["dlp_input"]
    assert [n for _, n in reg.list_handlers(HookPoint.AGENT_STARTUP)] == \
        ["dlp_startup"]
    assert [n for _, n in reg.list_handlers(HookPoint.PRE_MODEL_CALL)] == \
        ["dlp_pre_model"]


def test_dlp_registered_at_priority_50():
    reg = InterceptorRegistry()
    register_dlp_handlers(reg)
    assert reg.list_handlers(HookPoint.INPUT) == [(50, "dlp_input")]


def test_end_to_end_through_registry(ctx):
    """经 registry 调用，MODIFY 的脱敏结果能传出。"""
    reg = InterceptorRegistry()
    register_dlp_handlers(reg)
    r = reg.invoke(HookPoint.INPUT, AGENT, f"身份证 {ID_CARD}", **ctx)
    assert r.decision == Decision.MODIFY
    assert ID_CARD not in r.modified_data
