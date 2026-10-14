"""DLP-07/08/09 — 返回值脱敏、最终输出审查与水印、session 清零。"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from securityd.dlp.handlers import (  # noqa: E402
    DLPSessionStore,
    embed_watermark,
    extract_watermark,
    output_handler,
    post_tool_handler,
    register_dlp_handlers,
    shutdown_handler,
    strip_watermark,
)
from securityd.dlp.pii_scanner import PIIScanner, PIIType  # noqa: E402
from securityd.dlp.policy_store import DLPAction, DLPPolicyStore  # noqa: E402
from securityd.interceptor import (  # noqa: E402
    Decision,
    HookPoint,
    InterceptorRegistry,
)

AGENT = "com.test.agent"
PHONE = "13812345678"
ID_CARD = "110101199003076173"
CARD = "4539578763621486"


@pytest.fixture
def ctx(tmp_path):
    store = DLPPolicyStore(db_path=tmp_path / "dlp.db")
    c = {"dlp_scanner": PIIScanner(), "dlp_store": store,
         "dlp_sessions": DLPSessionStore(), "session_id": "s1"}
    yield c
    store.close()


# ———————————————————— DLP-07 post_tool_call ————————————————————
def test_post_tool_clean_allow(ctx):
    r = post_tool_handler(AGENT, HookPoint.POST_TOOL_CALL,
                          {"tool": "read_file", "result": "普通文本内容"}, ctx)
    assert r.decision == Decision.ALLOW


def test_post_tool_masks_high_risk(ctx):
    """返回值必须脱 —— 不脱则 PII 进上下文后多轮传播。"""
    r = post_tool_handler(AGENT, HookPoint.POST_TOOL_CALL,
                          {"tool": "read_file",
                           "result": f"客户身份证 {ID_CARD}"}, ctx)
    assert r.decision == Decision.MODIFY
    assert ID_CARD not in r.modified_data
    assert r.metadata["pii_source"] == "tool_result"
    assert r.metadata["tool"] == "read_file"


def test_post_tool_allow_not_masked(ctx):
    ctx["dlp_store"].set_policy(AGENT, PIIType.PHONE, DLPAction.ALLOW)
    r = post_tool_handler(AGENT, HookPoint.POST_TOOL_CALL,
                          {"tool": "grep", "result": f"电话 {PHONE}"}, ctx)
    assert r.decision == Decision.ALLOW


def test_post_tool_block_policy(ctx):
    ctx["dlp_store"].set_policy(AGENT, PIIType.BANK_CARD, DLPAction.DENY)
    r = post_tool_handler(AGENT, HookPoint.POST_TOOL_CALL,
                          {"tool": "http_get", "result": f"卡号 {CARD}"}, ctx)
    assert r.decision == Decision.BLOCK
    assert "进入上下文" in r.message


def test_post_tool_mask_map_to_session(ctx):
    post_tool_handler(AGENT, HookPoint.POST_TOOL_CALL,
                      {"tool": "cat", "result": f"身份证 {ID_CARD}"}, ctx)
    assert ctx["dlp_sessions"].get("s1")["[PII-身份证-001]"] == ID_CARD


def test_post_tool_payload_size_recorded(ctx):
    """记录载荷大小 —— 供 ARCH-01 判是否该走 UDS。"""
    r = post_tool_handler(AGENT, HookPoint.POST_TOOL_CALL,
                          {"tool": "cat", "result": f"身份证 {ID_CARD}"}, ctx)
    assert r.metadata["payload_bytes"] > 0


def test_post_tool_non_string_result(ctx):
    """返回值是 dict/list 时序列化后再扫。"""
    r = post_tool_handler(AGENT, HookPoint.POST_TOOL_CALL,
                          {"tool": "api", "result": {"user": {"id": ID_CARD}}},
                          ctx)
    assert r.decision == Decision.MODIFY


def test_post_tool_empty_result(ctx):
    assert post_tool_handler(AGENT, HookPoint.POST_TOOL_CALL,
                             {"tool": "x", "result": ""},
                             ctx).decision == Decision.ALLOW
    assert post_tool_handler(AGENT, HookPoint.POST_TOOL_CALL,
                             {"tool": "x"},
                             ctx).decision == Decision.ALLOW


# ———————————————————— 水印 ————————————————————
def test_watermark_roundtrip():
    out = embed_watermark("这是正常输出内容。", "sess-abc123")
    assert extract_watermark(out) == "sess-abc123"


def test_watermark_invisible():
    """水印只用零宽字符 —— 可见文本不变。"""
    text = "这是正常输出内容。"
    out = embed_watermark(text, "s1")
    assert strip_watermark(out) == text
    assert len(out) > len(text)  # 确实嵌了东西


def test_watermark_unicode_payload():
    out = embed_watermark("输出", "会话-中文-01")
    assert extract_watermark(out) == "会话-中文-01"


def test_watermark_absent_returns_none():
    assert extract_watermark("没有水印的文本") is None


def test_watermark_empty_payload_noop():
    assert embed_watermark("文本", "") == "文本"


def test_strip_watermark_idempotent():
    text = "内容"
    assert strip_watermark(strip_watermark(embed_watermark(text, "x"))) == text


# ———————————————————— DLP-08 output ————————————————————
def test_output_restores_session_placeholders(ctx):
    """用户有权看自己提供的信息 → 还原本 session 的占位符。"""
    ctx["dlp_sessions"].merge("s1", {"[PII-手机号-001]": PHONE})
    ctx["dlp_store"].set_policy(AGENT, PIIType.PHONE, DLPAction.ALLOW)
    r = output_handler(AGENT, HookPoint.OUTPUT,
                       "您的号码是 [PII-手机号-001]", ctx)
    assert r.decision == Decision.MODIFY
    assert PHONE in r.modified_data
    assert r.metadata["restored_placeholders"] == 1


def test_output_does_not_restore_other_session(ctx):
    """跨 session 的占位符不还原 —— 防会话间泄露。"""
    ctx["dlp_sessions"].merge("other", {"[PII-手机号-001]": PHONE})
    r = output_handler(AGENT, HookPoint.OUTPUT,
                       "号码 [PII-手机号-001]", ctx)
    assert PHONE not in (r.modified_data or "号码 [PII-手机号-001]")
    assert r.metadata["restored_placeholders"] == 0


def test_output_rescans_after_restore(ctx):
    """还原后复扫 —— 策略中途改严时能重新拦住。"""
    ctx["dlp_sessions"].merge("s1", {"[PII-身份证-001]": ID_CARD})
    # 策略仍是兜底 mask → 还原出的身份证会被重新脱敏
    r = output_handler(AGENT, HookPoint.OUTPUT, "身份证 [PII-身份证-001]", ctx)
    assert r.decision == Decision.MODIFY
    assert ID_CARD not in r.modified_data
    assert r.metadata["restored_placeholders"] == 1


def test_output_block_policy_masks_whole(ctx):
    """block 策略 → 整体替换为屏蔽提示（不能直接 BLOCK，用户会看到空响应）。"""
    ctx["dlp_store"].set_policy(AGENT, PIIType.ID_CARD, DLPAction.DENY)
    r = output_handler(AGENT, HookPoint.OUTPUT, f"身份证 {ID_CARD}", ctx)
    assert r.decision == Decision.MODIFY
    assert "已屏蔽" in r.modified_data
    assert ID_CARD not in r.modified_data


def test_output_watermark_applied(ctx):
    ctx["dlp_watermark"] = "trace-001"
    r = output_handler(AGENT, HookPoint.OUTPUT, "正常输出", ctx)
    assert r.decision == Decision.MODIFY
    assert extract_watermark(r.modified_data) == "trace-001"
    assert r.metadata["watermarked"] is True


def test_output_clean_no_watermark_allow(ctx):
    """无 PII、无水印 → 不改写。"""
    r = output_handler(AGENT, HookPoint.OUTPUT, "今天天气不错", ctx)
    assert r.decision == Decision.ALLOW
    assert r.modified_data is None


def test_output_dict_form(ctx):
    ctx["dlp_watermark"] = "w"
    r = output_handler(AGENT, HookPoint.OUTPUT, {"output": "内容"}, ctx)
    assert r.decision == Decision.MODIFY


def test_output_empty(ctx):
    assert output_handler(AGENT, HookPoint.OUTPUT, "",
                          ctx).decision == Decision.ALLOW


# ———————————————————— DLP-09 agent_shutdown ————————————————————
def test_shutdown_clears_session(ctx):
    ctx["dlp_sessions"].merge("s1", {"[PII-手机号-001]": PHONE,
                                     "[PII-身份证-001]": ID_CARD})
    r = shutdown_handler(AGENT, HookPoint.AGENT_SHUTDOWN,
                         {"exit_reason": "normal"}, ctx)
    assert r.decision == Decision.ALLOW
    assert r.metadata["pii_mappings_cleared"] == 2
    assert ctx["dlp_sessions"].get("s1") == {}


def test_shutdown_idempotent(ctx):
    ctx["dlp_sessions"].merge("s1", {"a": "1"})
    shutdown_handler(AGENT, HookPoint.AGENT_SHUTDOWN, None, ctx)
    r = shutdown_handler(AGENT, HookPoint.AGENT_SHUTDOWN, None, ctx)
    assert r.metadata["pii_mappings_cleared"] == 0


def test_shutdown_never_blocks(ctx):
    """退出是终态，拦也没意义。"""
    ctx["dlp_sessions"].merge("s1", {"a": "1"})
    r = shutdown_handler(AGENT, HookPoint.AGENT_SHUTDOWN, None, ctx)
    assert r.decision == Decision.ALLOW


def test_shutdown_no_session_store(ctx):
    """未提供 session store 时不崩。"""
    c = dict(ctx)
    c.pop("dlp_sessions")
    assert shutdown_handler(AGENT, HookPoint.AGENT_SHUTDOWN, None,
                            c).metadata["pii_mappings_cleared"] == 0


# ———————————————————— 8 个干预点闭环 ————————————————————
def test_all_eight_hook_points_registered():
    """DLP 覆盖全部 8 个干预点。"""
    reg = InterceptorRegistry()
    register_dlp_handlers(reg)
    got = {hp.value: [n for _, n in reg.list_handlers(hp)] for hp in HookPoint}
    assert got == {
        "agent_startup": ["dlp_startup"],
        "input": ["dlp_input"],
        "pre_model_call": ["dlp_pre_model"],
        "post_model_call": ["dlp_post_model"],
        "pre_tool_call": ["dlp_pre_tool"],
        "post_tool_call": ["dlp_post_tool"],
        "output": ["dlp_output"],
        "agent_shutdown": ["dlp_shutdown"],
    }


def test_register_all_idempotent():
    reg = InterceptorRegistry()
    register_dlp_handlers(reg)
    register_dlp_handlers(reg)
    for hp in HookPoint:
        assert len(reg.list_handlers(hp)) == 1


def test_full_lifecycle_through_registry(ctx):
    """完整生命周期：脱敏 → 还原 → 清零。"""
    reg = InterceptorRegistry()
    register_dlp_handlers(reg)

    # input 脱敏
    r1 = reg.invoke(HookPoint.INPUT, AGENT, f"我的身份证是 {ID_CARD}", **ctx)
    assert r1.decision == Decision.MODIFY
    assert ID_CARD not in r1.modified_data

    # output 还原（策略放开后用户可见）
    ctx["dlp_store"].set_policy(AGENT, PIIType.ID_CARD, DLPAction.ALLOW)
    r2 = reg.invoke(HookPoint.OUTPUT, AGENT,
                    f"已记录：{r1.modified_data}", **ctx)
    assert ID_CARD in r2.modified_data

    # shutdown 清零
    r3 = reg.invoke(HookPoint.AGENT_SHUTDOWN, AGENT, None, **ctx)
    assert r3.metadata["pii_mappings_cleared"] >= 1
    assert ctx["dlp_sessions"].get("s1") == {}
