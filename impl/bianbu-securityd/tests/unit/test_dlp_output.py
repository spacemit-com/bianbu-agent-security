"""DLP-05/06 — 模型输出检测与工具参数 PII 提升。"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from securityd.dlp.handlers import (  # noqa: E402
    DLPSessionStore,
    detect_verbatim_leak,
    post_model_handler,
    pre_tool_handler,
    register_dlp_handlers,
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

CORPUS = [
    "人工智能的发展经历了三次浪潮，第一次浪潮始于上世纪五十年代，"
    "以符号主义和专家系统为主要特征，研究者相信通过逻辑推理即可实现智能；"
    "第二次浪潮出现在八十年代，联结主义与神经网络重新受到重视，"
    "反向传播算法的提出使多层网络的训练成为可能；第三次浪潮自二零一二年起，"
    "深度学习在大规模数据与算力支撑下取得了突破性进展。",
    "深度学习通过多层神经网络自动提取特征，避免了传统机器学习中"
    "人工设计特征的繁琐过程，在图像识别与语音处理领域取得突破。"
    "卷积神经网络利用局部连接与权值共享大幅减少参数量，"
    "循环神经网络则通过时序状态传递处理变长序列数据。",
]


@pytest.fixture
def ctx(tmp_path):
    store = DLPPolicyStore(db_path=tmp_path / "dlp.db")
    c = {"dlp_scanner": PIIScanner(), "dlp_store": store,
         "dlp_sessions": DLPSessionStore(), "session_id": "s1"}
    yield c
    store.close()


# ———————————————————— 逐字泄露检测 ————————————————————
def test_verbatim_leak_detected():
    """整段照抄 → 覆盖率 100%。"""
    hit = detect_verbatim_leak(CORPUS[0], CORPUS)
    assert hit is not None
    ratio, idx = hit
    assert ratio == 1.0 and idx == 0


def test_verbatim_leak_partial_below_threshold():
    """只抄一小段（短于 min_span）+ 大量自有内容 → 不判泄露。"""
    out = CORPUS[0][:30] + "。" + "此外还有许多其他因素需要考虑" * 10
    assert detect_verbatim_leak(out, CORPUS, threshold=0.8, min_span=100) is None


def test_verbatim_leak_padding_cannot_evade():
    """**补长绕过防护**：抄够 min_span 后追加大量无关文本仍判泄露。

    单用覆盖率会被绕过 —— 分母随输出增长，比例被稀释。
    实测（语料 64 字样本）：尾部追加 15 字，覆盖率 100%→77.6% 即漏判；
    追加 66 字降到 52.3%。绝对连续长度不受此影响。
    """
    padding = "，另外补充一些完全无关的内容用于稀释检测结果" * 6
    out = CORPUS[0] + padding
    hit = detect_verbatim_leak(out, CORPUS, threshold=0.8, min_span=100)
    assert hit is not None, "补长后漏判 —— 绝对长度信号失效"
    ratio, idx = hit
    assert idx == 0
    assert ratio < 0.8, f"该样本覆盖率应已被稀释到门限下（实测 {ratio:.3f}）"


def test_verbatim_leak_min_span_configurable():
    """min_span 可调：调高则同样的抄袭量不再命中。"""
    out = CORPUS[0][:60] + "。" + "补充说明供参考" * 20
    assert detect_verbatim_leak(out, CORPUS, min_span=50) is not None
    assert detect_verbatim_leak(out, CORPUS, min_span=200) is None


def test_verbatim_leak_long_excerpt_caught():
    """抄了大半 → 仍应命中。"""
    out = CORPUS[1] + "以上是相关介绍。"
    hit = detect_verbatim_leak(out, CORPUS, threshold=0.7)
    assert hit is not None and hit[1] == 1


def test_verbatim_leak_normal_output_clean():
    assert detect_verbatim_leak("今天的会议安排在下午三点，请准时参加。",
                                CORPUS) is None


def test_verbatim_leak_whitespace_bypass_blocked():
    """插空格不能绕过（归一化后再比）。"""
    spaced = " ".join(CORPUS[0])
    assert detect_verbatim_leak(spaced, CORPUS) is not None


def test_verbatim_leak_no_corpus_skips():
    """未提供语料 → 跳过检测而非报错。"""
    assert detect_verbatim_leak("任意文本", []) is None
    assert detect_verbatim_leak("任意文本", None) is None


def test_verbatim_leak_short_output_skipped():
    """短于 n-gram 窗口 → 无法判定，跳过。"""
    assert detect_verbatim_leak("太短", CORPUS) is None


# ———————————————————— DLP-05 post_model_call ————————————————————
def test_post_model_clean_allow(ctx):
    r = post_model_handler(AGENT, HookPoint.POST_MODEL_CALL,
                           "会议在下午三点开始。", ctx)
    assert r.decision == Decision.ALLOW


def test_post_model_verbatim_leak_blocked(ctx):
    """逐字泄露一律拦截并告警。"""
    ctx["dlp_reference_corpus"] = CORPUS
    r = post_model_handler(AGENT, HookPoint.POST_MODEL_CALL, CORPUS[0], ctx)
    assert r.decision == Decision.BLOCK
    assert r.metadata["verbatim_leak"] is True
    assert r.metadata["alert"] == "training_data_leak"
    assert r.metadata["leak_ratio"] == 1.0


def test_post_model_leak_ignores_pii_policy(ctx):
    """泄露拦截不受 PII 策略影响 —— 这是模型行为异常，非数据敏感度问题。"""
    ctx["dlp_reference_corpus"] = CORPUS
    for t in PIIType:
        ctx["dlp_store"].set_policy(AGENT, t, DLPAction.ALLOW)
    r = post_model_handler(AGENT, HookPoint.POST_MODEL_CALL, CORPUS[1], ctx)
    assert r.decision == Decision.BLOCK


def test_post_model_leak_checked_before_pii(ctx):
    """同时含泄露与 PII 时，报泄露（更严重的问题）。"""
    ctx["dlp_reference_corpus"] = CORPUS
    r = post_model_handler(AGENT, HookPoint.POST_MODEL_CALL,
                           CORPUS[0] + f" 电话 {PHONE}", ctx)
    assert r.decision == Decision.BLOCK
    assert r.metadata.get("verbatim_leak") is True


def test_post_model_high_risk_masked(ctx):
    """身份证兜底 mask → 输出脱敏。"""
    r = post_model_handler(AGENT, HookPoint.POST_MODEL_CALL,
                           f"查询结果：身份证 {ID_CARD}", ctx)
    assert r.decision == Decision.MODIFY
    assert ID_CARD not in r.modified_data
    assert r.metadata["pii_source"] == "model_output"


def test_post_model_low_risk_allow(ctx):
    ctx["dlp_store"].set_policy(AGENT, PIIType.PHONE, DLPAction.ALLOW)
    r = post_model_handler(AGENT, HookPoint.POST_MODEL_CALL,
                           f"联系电话 {PHONE}", ctx)
    assert r.decision == Decision.ALLOW
    assert "phone" in r.metadata["pii_types"]


def test_post_model_default_policy_masks(ctx):
    r = post_model_handler(AGENT, HookPoint.POST_MODEL_CALL,
                           f"联系电话 {PHONE}", ctx)
    assert r.decision == Decision.MODIFY
    assert PHONE not in r.modified_data


def test_post_model_block_policy(ctx):
    ctx["dlp_store"].set_policy(AGENT, PIIType.ID_CARD, DLPAction.DENY)
    r = post_model_handler(AGENT, HookPoint.POST_MODEL_CALL,
                           f"身份证 {ID_CARD}", ctx)
    assert r.decision == Decision.BLOCK


def test_post_model_mask_map_to_session(ctx):
    post_model_handler(AGENT, HookPoint.POST_MODEL_CALL,
                       f"身份证 {ID_CARD}", ctx)
    assert ctx["dlp_sessions"].get("s1")["[PII-身份证-001]"] == ID_CARD


def test_post_model_dict_form(ctx):
    r = post_model_handler(AGENT, HookPoint.POST_MODEL_CALL,
                           {"response": f"身份证 {ID_CARD}"}, ctx)
    assert r.decision == Decision.MODIFY


def test_post_model_empty(ctx):
    assert post_model_handler(AGENT, HookPoint.POST_MODEL_CALL, "",
                              ctx).decision == Decision.ALLOW


def test_post_model_threshold_configurable(ctx):
    """覆盖率门限可经 context 调整（抄袭量短于 min_span 时才由它决定）。"""
    ctx["dlp_reference_corpus"] = CORPUS
    ctx["dlp_leak_min_span"] = 500  # 抬高绝对长度门限，让覆盖率成为决定因素
    out = CORPUS[0][:40] + "，另外还需要补充一些背景情况供参考说明。"
    ctx["dlp_leak_threshold"] = 0.99
    assert post_model_handler(AGENT, HookPoint.POST_MODEL_CALL, out,
                              ctx).decision != Decision.BLOCK
    ctx["dlp_leak_threshold"] = 0.3
    assert post_model_handler(AGENT, HookPoint.POST_MODEL_CALL, out,
                              ctx).decision == Decision.BLOCK


def test_post_model_min_span_configurable(ctx):
    """min_span 可经 context 调整。"""
    ctx["dlp_reference_corpus"] = CORPUS
    ctx["dlp_leak_threshold"] = 0.99  # 排除覆盖率信号干扰
    out = CORPUS[1][:80] + "。" + "以下是补充内容" * 25
    ctx["dlp_leak_min_span"] = 60
    assert post_model_handler(AGENT, HookPoint.POST_MODEL_CALL, out,
                              ctx).decision == Decision.BLOCK
    ctx["dlp_leak_min_span"] = 400
    assert post_model_handler(AGENT, HookPoint.POST_MODEL_CALL, out,
                              ctx).decision != Decision.BLOCK


# ———————————————————— DLP-06 pre_tool_call ————————————————————
def test_pre_tool_clean_allow(ctx):
    r = pre_tool_handler(AGENT, HookPoint.PRE_TOOL_CALL,
                         {"tool": "read_file", "args": {"path": "/tmp/a.txt"}},
                         ctx)
    assert r.decision == Decision.ALLOW


def test_pre_tool_pii_escalates_to_confirm(ctx):
    """含 PII 的工具参数 → CONFIRM（不脱敏，脱了工具就没法用）。"""
    r = pre_tool_handler(AGENT, HookPoint.PRE_TOOL_CALL,
                         {"tool": "write_file",
                          "args": {"path": f"/tmp/{ID_CARD}.txt"}}, ctx)
    assert r.decision == Decision.CONFIRM
    assert r.metadata["escalated_to_confirm"] is True
    assert r.metadata["pii_source"] == "tool_args"
    assert r.modified_data is None  # 未改写参数


def test_pre_tool_default_policy_also_escalates(ctx):
    """兜底 mask 也提升 —— 工具调用意味着 PII 要离开 Agent 进程。"""
    r = pre_tool_handler(AGENT, HookPoint.PRE_TOOL_CALL,
                         {"tool": "send_email",
                          "args": {"body": f"电话 {PHONE}"}}, ctx)
    assert r.decision == Decision.CONFIRM


def test_pre_tool_block_policy(ctx):
    ctx["dlp_store"].set_policy(AGENT, PIIType.BANK_CARD, DLPAction.DENY)
    r = pre_tool_handler(AGENT, HookPoint.PRE_TOOL_CALL,
                         {"tool": "http_post", "args": {"card": CARD}}, ctx)
    assert r.decision == Decision.BLOCK
    assert "http_post" in r.message


def test_pre_tool_allow_policy_not_escalated(ctx):
    """显式 allow 的类型不提升（明确豁免）。"""
    ctx["dlp_store"].set_policy(AGENT, PIIType.PHONE, DLPAction.ALLOW)
    r = pre_tool_handler(AGENT, HookPoint.PRE_TOOL_CALL,
                         {"tool": "dial", "args": {"number": PHONE}}, ctx)
    assert r.decision == Decision.ALLOW


def test_pre_tool_nested_args_scanned(ctx):
    """嵌套结构里的 PII 也能扫出。"""
    r = pre_tool_handler(AGENT, HookPoint.PRE_TOOL_CALL,
                         {"tool": "api_call",
                          "args": {"body": {"user": {"id": ID_CARD}}}}, ctx)
    assert r.decision == Decision.CONFIRM


def test_pre_tool_unserializable_args(ctx):
    """参数不可 JSON 序列化时不崩（default=str 兜底）。"""
    class Weird:
        def __str__(self):
            return f"obj({ID_CARD})"

    r = pre_tool_handler(AGENT, HookPoint.PRE_TOOL_CALL,
                         {"tool": "x", "args": {"o": Weird()}}, ctx)
    assert r.decision == Decision.CONFIRM


def test_pre_tool_string_args(ctx):
    r = pre_tool_handler(AGENT, HookPoint.PRE_TOOL_CALL,
                         {"tool": "sh", "args": f"echo {ID_CARD}"}, ctx)
    assert r.decision == Decision.CONFIRM


def test_pre_tool_no_args(ctx):
    assert pre_tool_handler(AGENT, HookPoint.PRE_TOOL_CALL,
                            {"tool": "list"}, ctx).decision == Decision.ALLOW


# ———————————————————— 注册与协同 ————————————————————
def test_dlp05_06_handlers_registered():
    """DLP-05/06 两个点已注册（全 8 点闭环见 test_dlp_final.py）。"""
    reg = InterceptorRegistry()
    register_dlp_handlers(reg)
    assert [n for _, n in reg.list_handlers(HookPoint.POST_MODEL_CALL)] == \
        ["dlp_post_model"]
    assert [n for _, n in reg.list_handlers(HookPoint.PRE_TOOL_CALL)] == \
        ["dlp_pre_tool"]


def test_register_idempotent():
    reg = InterceptorRegistry()
    register_dlp_handlers(reg)
    register_dlp_handlers(reg)
    assert [n for _, n in reg.list_handlers(HookPoint.PRE_TOOL_CALL)] == \
        ["dlp_pre_tool"]


def test_sec_deny_shortcuts_dlp_scan(ctx):
    """SEC 判 DENY 时短路，DLP 不执行 —— 省掉 PII 扫描开销。"""
    reg = InterceptorRegistry()
    register_dlp_handlers(reg)

    def sec_deny(aid, hp, data, c):
        from securityd.interceptor import InterceptResult
        return InterceptResult(decision=Decision.BLOCK, message="no permission",
                               metadata={"reason": "denied"})

    reg.register(HookPoint.PRE_TOOL_CALL, sec_deny, name="sec", priority=10)
    r = reg.invoke(HookPoint.PRE_TOOL_CALL, AGENT,
                   {"tool": "write_file", "args": {"p": ID_CARD}}, **ctx)
    assert r.decision == Decision.BLOCK
    assert r.metadata["reason"] == "denied"
    # DLP 未执行 → 无 pii_source 字段
    assert "pii_source" not in r.metadata
    assert [t[0] for t in r.metadata["_handler_trace"]] == ["sec"]


def test_sec_allow_then_dlp_confirm(ctx):
    """SEC ALLOW + DLP 检出 PII → 最终 CONFIRM（DLP-06 核心机制）。"""
    reg = InterceptorRegistry()
    register_dlp_handlers(reg)

    def sec_allow(aid, hp, data, c):
        from securityd.interceptor import InterceptResult
        return InterceptResult(decision=Decision.ALLOW)

    reg.register(HookPoint.PRE_TOOL_CALL, sec_allow, name="sec", priority=10)
    r = reg.invoke(HookPoint.PRE_TOOL_CALL, AGENT,
                   {"tool": "write_file", "args": {"p": ID_CARD}}, **ctx)
    assert r.decision == Decision.CONFIRM
    assert r.metadata["escalated_to_confirm"] is True
    assert [t[0] for t in r.metadata["_handler_trace"]] == ["sec", "dlp_pre_tool"]
