"""DLP-01 — PII 检测引擎单测（行为正确性；召回/误报指标见 pii_benchmark.py）。"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from securityd.dlp.pii_scanner import (  # noqa: E402
    PIIFinding,
    PIIScanner,
    PIIType,
    RiskLevel,
    cn_id_checksum_valid,
    luhn_valid,
)


@pytest.fixture
def scanner():
    return PIIScanner()


# ———————————————————————————————————— 校验算法 ————————————————————————————————————
def test_luhn_valid_known_numbers():
    assert luhn_valid("4539578763621486")  # 合法测试卡号
    assert luhn_valid("6011111111111117")
    assert not luhn_valid("4539578763621487")  # 末位改动


def test_luhn_rejects_short():
    assert not luhn_valid("123456")


def test_cn_id_checksum():
    assert cn_id_checksum_valid("110101199003076173")   # 校验位为数字
    assert cn_id_checksum_valid("11010119900307109X")   # 校验位为 X 的分支
    assert not cn_id_checksum_valid("110101199003076170")


def test_cn_id_rejects_bad_date():
    """出生日期不合理直接排除（压误报）。"""
    assert not cn_id_checksum_valid("110101199913076171")  # 13 月
    assert not cn_id_checksum_valid("110101190000076171")  # 0 月


def test_cn_id_rejects_wrong_length():
    assert not cn_id_checksum_valid("1101011990030761")


# ———————————————————————————————————— 各类型检测 ————————————————————————————————————
def test_detect_phone(scanner):
    r = scanner.scan("请拨打 13812345678 联系我")
    assert r.has_pii
    f = r.by_type(PIIType.PHONE)[0]
    assert f.value == "13812345678"
    assert f.risk_level == RiskLevel.L2


def test_phone_not_in_longer_digits(scanner):
    """长数字串中的 11 位片段不算手机号（边界断言）。"""
    r = scanner.scan("订单 20138123456789012 已支付")
    assert r.by_type(PIIType.PHONE) == []


def test_detect_id_card(scanner):
    r = scanner.scan("身份证 110101199003076173 已核验")
    f = r.by_type(PIIType.ID_CARD)[0]
    assert f.value == "110101199003076173"
    assert f.risk_level == RiskLevel.L3
    assert f.detector == "regex+checksum"


def test_id_card_bad_checksum_rejected(scanner):
    """校验位错的 18 位数字不判为身份证 —— 误报控制的核心。"""
    r = scanner.scan("编号 110101199003076170 无效")
    assert r.by_type(PIIType.ID_CARD) == []


def test_detect_email(scanner):
    r = scanner.scan("邮箱 zhang.wei@example.com 已验证")
    assert r.by_type(PIIType.EMAIL)[0].value == "zhang.wei@example.com"


def test_detect_bank_card(scanner):
    r = scanner.scan("卡号 4539578763621486 扣款成功")
    f = r.by_type(PIIType.BANK_CARD)[0]
    assert f.risk_level == RiskLevel.L3
    assert f.detector == "regex+bin+checksum"  # BIN + 长度 + Luhn 三重


def test_bank_card_requires_valid_bin(scanner):
    """Luhn 过但 BIN 非法（9 开头无此卡种）→ 不判银行卡。

    单靠 Luhn 会放过约 1/10 的随机数字串，BIN + 长度约束是必要的第二道。
    """
    from securityd.dlp.pii_scanner import luhn_valid, plausible_card_bin
    # 构造一个 Luhn 合法但 BIN 非法的 16 位号
    body = "999999999999999"
    total = 0
    for i, ch in enumerate(reversed(body)):
        d = int(ch)
        if i % 2 == 0:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    num = body + str((10 - total % 10) % 10)
    assert luhn_valid(num)                    # Luhn 通过
    assert not plausible_card_bin(num)        # 但 BIN 不合规
    assert scanner.scan(f"记录 {num}").by_type(PIIType.BANK_CARD) == []


def test_plausible_card_bin_known_schemes():
    from securityd.dlp.pii_scanner import plausible_card_bin
    assert plausible_card_bin("4539578763621486")      # Visa 16
    assert plausible_card_bin("5105105105105100")      # Mastercard
    assert plausible_card_bin("6011111111111117")      # Discover
    assert plausible_card_bin("340000000000009")       # AmEx 15
    assert plausible_card_bin("6212264000000000000")   # 银联 19
    assert not plausible_card_bin("5105105105105")     # MC 长度不对
    assert not plausible_card_bin("1234567890123456")  # 无此 BIN


def test_id_card_not_misread_as_bank_card(scanner):
    """18 位身份证含合法出生日期 → 不判银行卡（Luhn 可能碰巧通过）。"""
    r = scanner.scan("编号 330106198011071798 记录")
    assert r.by_type(PIIType.BANK_CARD) == []


def test_bank_card_bad_luhn_rejected(scanner):
    r = scanner.scan("卡号 4539578763621487 校验失败")
    assert r.by_type(PIIType.BANK_CARD) == []


def test_phone_not_misread_as_bank_card(scanner):
    """11 位以 1 开头的优先判手机号，不重复判为银行卡。"""
    r = scanner.scan("电话 13812345678")
    assert r.by_type(PIIType.PHONE)
    assert r.by_type(PIIType.BANK_CARD) == []


def test_detect_address(scanner):
    r = scanner.scan("地址：北京市朝阳区建国路88号")
    assert r.by_type(PIIType.ADDRESS)


def test_partial_address_not_detected(scanner):
    """缺门牌号的不算完整地址。"""
    r = scanner.scan("在北京市朝阳区上班")
    assert r.by_type(PIIType.ADDRESS) == []


def test_detect_medical(scanner):
    r = scanner.scan("患者确诊糖尿病，需长期用药")
    f = r.by_type(PIIType.MEDICAL)[0]
    assert f.risk_level == RiskLevel.L4


def test_detect_biometric(scanner):
    r = scanner.scan("已采集指纹特征并入库")
    assert r.by_type(PIIType.BIOMETRIC)[0].risk_level == RiskLevel.L4


def test_detect_name_heuristic(scanner):
    """无 NER 时用称谓词启发式，置信度如实标低。"""
    r = scanner.scan("姓名：张伟")
    f = r.by_type(PIIType.NAME)[0]
    assert f.value == "张伟"
    assert f.detector == "heuristic"
    assert f.confidence < 0.8  # 启发式不谎报高置信度


def test_name_stopword_filtered(scanner):
    r = scanner.scan("姓名：测试数据")
    assert r.by_type(PIIType.NAME) == []


# ———————————————————————————————————— 风险级别 ————————————————————————————————————
def test_max_risk_picks_highest(scanner):
    r = scanner.scan("张伟的邮箱 a@b.com，身份证 110101199003076173")
    assert r.max_risk() == RiskLevel.L3  # 身份证 L3 > 邮箱 L2 > 姓名 L1


def test_max_risk_none_when_clean(scanner):
    assert scanner.scan("今天天气不错").max_risk() is None


def test_l4_beats_l3(scanner):
    r = scanner.scan("身份证 110101199003076173，确诊糖尿病")
    assert r.max_risk() == RiskLevel.L4


# ———————————————————————————————————— 脱敏与还原 ————————————————————————————————————
def test_mask_replaces_pii(scanner):
    r = scanner.scan_and_mask("电话 13812345678 邮箱 a@example.com")
    assert "13812345678" not in r.masked_text
    assert "a@example.com" not in r.masked_text
    assert "[PII-手机号-001]" in r.masked_text
    assert "[PII-邮箱-001]" in r.masked_text


def test_mask_map_records_originals(scanner):
    r = scanner.scan_and_mask("电话 13812345678")
    assert r.mask_map["[PII-手机号-001]"] == "13812345678"


def test_mask_numbering_per_type(scanner):
    r = scanner.scan_and_mask("电话 13812345678 和 13987654321")
    assert "[PII-手机号-001]" in r.masked_text
    assert "[PII-手机号-002]" in r.masked_text


def test_unmask_restores(scanner):
    text = "电话 13812345678 邮箱 a@example.com"
    r = scanner.scan_and_mask(text)
    assert PIIScanner.unmask(r.masked_text, r.mask_map) == text


def test_unmask_unknown_placeholder_kept():
    """映射表里没有的占位符保持原样（跨 session 不还原）。"""
    out = PIIScanner.unmask("值 [PII-手机号-999]", {})
    assert out == "值 [PII-手机号-999]"


def test_mask_preserves_surrounding_text(scanner):
    r = scanner.scan_and_mask("前缀 13812345678 后缀")
    assert r.masked_text.startswith("前缀 ")
    assert r.masked_text.endswith(" 后缀")


def test_clean_text_unchanged(scanner):
    r = scanner.scan_and_mask("这段文本没有敏感信息")
    assert r.masked_text == "这段文本没有敏感信息"
    assert r.mask_map == {}


# ———————————————————————————————————— 配置 ————————————————————————————————————
def test_enabled_types_filter():
    """只启用手机号 → 邮箱不被检出。"""
    s = PIIScanner(enabled_types=[PIIType.PHONE])
    r = s.scan("电话 13812345678 邮箱 a@example.com")
    assert r.types == {PIIType.PHONE}


def test_min_confidence_filter():
    """提高置信度门限可滤掉启发式姓名。"""
    s = PIIScanner(min_confidence=0.9)
    r = s.scan("姓名：张伟")
    assert r.by_type(PIIType.NAME) == []


def test_ner_backend_used():
    """NER 后端注入后其结果被纳入。"""
    def fake_ner(text):
        idx = text.find("李娜")
        if idx >= 0:
            yield PIIFinding(
                pii_type=PIIType.NAME, start=idx, end=idx + 2, value="李娜",
                confidence=0.93, risk_level=RiskLevel.L1, detector="ner")

    s = PIIScanner(ner_backend=fake_ner)
    r = s.scan("报告作者是李娜")  # 无称谓词，启发式抓不到
    f = r.by_type(PIIType.NAME)[0]
    assert f.detector == "ner" and f.confidence == 0.93


def test_ner_replaces_heuristic():
    """有 NER 时不再跑姓名启发式（避免重复/冲突）。"""
    def empty_ner(text):
        return []

    s = PIIScanner(ner_backend=empty_ner)
    r = s.scan("姓名：张伟")
    assert r.by_type(PIIType.NAME) == []


# ———————————————————————————————————— 边界 ————————————————————————————————————
def test_empty_text(scanner):
    r = scanner.scan("")
    assert not r.has_pii and r.masked_text == ""


def test_none_text(scanner):
    r = scanner.scan(None)
    assert not r.has_pii


def test_overlap_prefers_longer(scanner):
    """重叠时取更长的命中。"""
    r = scanner.scan("身份证 110101199003076173")
    ids = r.by_type(PIIType.ID_CARD)
    assert len(ids) == 1
    assert ids[0].length == 18


def test_findings_sorted_by_position(scanner):
    r = scanner.scan("邮箱 a@example.com 电话 13812345678")
    starts = [f.start for f in r.findings]
    assert starts == sorted(starts)


def test_multiple_types_in_one_text(scanner):
    r = scanner.scan(
        "姓名：张伟，电话 13812345678，邮箱 zw@example.com，"
        "身份证 110101199003076173，地址：北京市朝阳区建国路88号")
    assert {PIIType.NAME, PIIType.PHONE, PIIType.EMAIL,
            PIIType.ID_CARD, PIIType.ADDRESS} <= r.types


def test_unicode_nfkc_and_zero_width_phone(scanner):
    r = scanner.scan("电话：１３８\u200b１２３４５６７８")
    assert r.by_type(PIIType.PHONE)


def test_base64_wrapped_phone(scanner):
    import base64
    encoded = base64.b64encode(b"phone=13812345678").decode()
    r = scanner.scan("payload=" + encoded)
    assert r.by_type(PIIType.PHONE)
    assert r.by_type(PIIType.PHONE)[0].detector.endswith("+base64")


def test_streaming_finds_cross_chunk_phone():
    from securityd.dlp.pii_scanner import StreamingPIIScanner
    s = StreamingPIIScanner(window=64)
    assert not s.feed("电话 13812").by_type(PIIType.PHONE)
    assert s.feed("345678 后缀").by_type(PIIType.PHONE)
