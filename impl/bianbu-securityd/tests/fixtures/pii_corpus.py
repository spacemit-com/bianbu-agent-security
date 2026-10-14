"""PII 基准语料（DLP-01 验收：召回 ≥95%、误报 ≤3%）。

正样本：每类 ≥200 条（结构化的用算法生成合法值，非结构化手写模板扩展）
负样本：形似但非 PII —— 这是误报率的真正考验（订单号、流水号、版本号、
        校验位错误的身份证/银行卡等）
"""
from __future__ import annotations

import random

from securityd.dlp.pii_scanner import PIIType

_rng = random.Random(20260811)  # 固定种子，语料可复现

# ————————————————————————————————————————————————————————————
# 结构化 PII 生成器（生成合法值，含正确校验位）
# ————————————————————————————————————————————————————————————
_ID_WEIGHTS = (7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2)
_ID_CHECK = "10X98765432"
_AREA_CODES = ["110101", "310115", "440305", "510107", "330106",
               "420111", "610113", "230108", "370211", "500106"]


def gen_id_card() -> str:
    area = _rng.choice(_AREA_CODES)
    year = _rng.randint(1950, 2005)
    month = _rng.randint(1, 12)
    day = _rng.randint(1, 28)
    seq = _rng.randint(0, 999)
    body = f"{area}{year:04d}{month:02d}{day:02d}{seq:03d}"
    total = sum(int(c) * w for c, w in zip(body, _ID_WEIGHTS))
    return body + _ID_CHECK[total % 11]


def gen_id_card_bad_checksum() -> str:
    """校验位故意错 —— 负样本核心。"""
    valid = gen_id_card()
    wrong = "0123456789X"
    bad = _rng.choice([c for c in wrong if c != valid[-1]])
    return valid[:17] + bad


def gen_phone() -> str:
    """11 位：1 + 网号(3-9) + 9 位。"""
    return f"1{_rng.choice('3456789')}{_rng.randint(0, 999999999):09d}"


# 真实发卡行 BIN 前缀 + 该卡种法定长度（检测器要求 BIN 合规，不能用随机前缀）
_CARD_BINS = [
    ("4", 16), ("4", 13), ("453958", 16),      # Visa
    ("51", 16), ("52", 16), ("55", 16),        # Mastercard
    ("2221", 16), ("2720", 16),                # Mastercard 新段
    ("62", 19), ("621226", 19), ("622202", 16),  # 银联
    ("34", 15), ("37", 15),                    # AmEx
    ("3528", 16), ("3589", 16),                # JCB
    ("6011", 16), ("65", 16),                  # Discover
]


def _luhn_check_digit(body: str) -> str:
    total = 0
    for i, ch in enumerate(reversed(body)):
        d = int(ch)
        if i % 2 == 0:  # 校验位视角的奇数位要翻倍
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return str((10 - total % 10) % 10)


def gen_bank_card() -> str:
    """生成 BIN 合规且 Luhn 合法的卡号。"""
    prefix, length = _rng.choice(_CARD_BINS)
    body = prefix + "".join(
        str(_rng.randint(0, 9)) for _ in range(length - len(prefix) - 1))
    return body + _luhn_check_digit(body)


def gen_bank_card_bad_luhn() -> str:
    valid = gen_bank_card()
    bad = str((int(valid[-1]) + 5) % 10)
    return valid[:-1] + bad


_EMAIL_USER = ["zhang.wei", "li_na", "wang88", "chen.xiaoming", "liu_yang",
               "zhaolei", "sun.qi", "zhou_min", "wu.jie", "xu_fang"]
_EMAIL_DOM = ["example.com", "test.org", "mail.cn", "corp.example.net",
              "foo.example.co", "demo.example.io"]


def gen_email() -> str:
    return f"{_rng.choice(_EMAIL_USER)}{_rng.randint(1, 999)}@{_rng.choice(_EMAIL_DOM)}"


_SURNAME = ["张", "王", "李", "赵", "陈", "刘", "杨", "黄", "周", "吴",
            "徐", "孙", "马", "朱", "胡", "郭", "何", "高", "林", "罗"]
_GIVEN = ["伟", "芳", "娜", "秀英", "敏", "静", "丽", "强", "磊", "军",
          "洋", "勇", "艳", "杰", "涛", "明", "超", "秀兰", "霞", "平"]


def gen_name() -> str:
    return _rng.choice(_SURNAME) + _rng.choice(_GIVEN)


_PROV = ["北京", "上海", "广东", "四川", "浙江", "湖北", "陕西", "山东"]
_CITY = ["北京市", "上海市", "深圳市", "成都市", "杭州市", "武汉市", "西安市", "济南市"]
_DIST = ["朝阳区", "浦东新区", "南山区", "武侯区", "西湖区", "洪山区", "雁塔区", "历下区"]
_STREET = ["中山路", "建国路", "科技大道", "人民街", "解放路", "文化路", "长江道"]


def gen_address() -> str:
    return (f"{_rng.choice(_CITY)}{_rng.choice(_DIST)}"
            f"{_rng.choice(_STREET)}{_rng.randint(1, 999)}号")


_MEDICAL_TPL = [
    "患者诊断为{d}", "确诊{d}", "病历号 {n}", "住院号{n}",
    "既往史：{d}", "门诊号 {n}", "药物过敏：青霉素",
]
_DISEASE = ["糖尿病", "高血压", "乙肝", "抑郁症", "肿瘤", "精神分裂", "艾滋"]


def gen_medical() -> str:
    tpl = _rng.choice(_MEDICAL_TPL)
    return tpl.format(d=_rng.choice(_DISEASE), n=_rng.randint(100000, 999999))


_BIO = ["指纹特征", "人脸数据", "虹膜模板", "声纹信息", "掌纹识别",
        "DNA序列", "fingerprint template", "face_embedding", "iris_scan"]


def gen_biometric() -> str:
    return _rng.choice(_BIO)


# ————————————————————————————————————————————————————————————
# 正样本：PII 嵌入自然句
# ————————————————————————————————————————————————————————————
_CARRIERS = [
    "请联系{v}处理此事。",
    "客户提供的信息是 {v}，请核对。",
    "备注：{v}",
    "系统记录 {v} 已归档。",
    "{v}",
    "以下为待确认内容 —— {v} —— 结束。",
    "工单描述：用户反馈 {v} 无法使用。",
]

_NAME_CARRIERS = [
    "姓名：{v}",
    "联系人 {v} 已确认",
    "收件人：{v}",
    "患者{v}于今日就诊",
    "经办人是{v}",
    "签收人：{v}",
]

_GENERATORS = {
    PIIType.PHONE: gen_phone,
    PIIType.ID_CARD: gen_id_card,
    PIIType.EMAIL: gen_email,
    PIIType.BANK_CARD: gen_bank_card,
    PIIType.ADDRESS: gen_address,
    PIIType.MEDICAL: gen_medical,
    PIIType.BIOMETRIC: gen_biometric,
}


def positives(n_per_type: int = 200) -> list[tuple[str, PIIType, str]]:
    """返回 [(文本, 期望类型, 期望命中值), ...]。"""
    out = []
    for t, gen in _GENERATORS.items():
        for _ in range(n_per_type):
            v = gen()
            carrier = _rng.choice(_CARRIERS)
            out.append((carrier.format(v=v), t, v))
    # 姓名单独用带上下文的载体（启发式依赖称谓词）
    for _ in range(n_per_type):
        v = gen_name()
        out.append((_rng.choice(_NAME_CARRIERS).format(v=v), PIIType.NAME, v))
    return out


# ————————————————————————————————————————————————————————————
# 负样本：形似但非 PII
# ————————————————————————————————————————————————————————————
def negatives(n: int = 400) -> list[str]:
    out = [
        # 长数字串（订单号/流水号/时间戳）
        "订单号 20260811123456789 已支付",
        "交易流水 987654321098765432 处理中",
        "时间戳 1754899200000 对应 2026-08-11",
        "序列号 SN2026081100001234",
        # 版本号 / IP / 端口
        "升级到 v10.13.15.19 版本",
        "服务地址 192.168.100.243:8787",
        "commit 3f5a9c1e8b2d4f6a7c9e0b1d2f3a4b5c6d7e8f90",
        # 校验位错误的身份证 / 银行卡
        *[f"编号 {gen_id_card_bad_checksum()} 无效" for _ in range(60)],
        *[f"卡号 {gen_bank_card_bad_luhn()} 校验失败" for _ in range(60)],
        # 形似手机号但不是（12 位、13 位、以 2 开头）
        "编码 123456789012 已登记",
        "参数 20260811999 传入",
        "代号 12345678901234",
        # 形似邮箱但不是
        "路径 a@b 不合法",
        "格式 user@localhost 内网",
        "at 符号 @channel 提醒全体",
        # 中文但非地址（缺门牌或行政区划）
        "北京市朝阳区办公",
        "杭州西湖景区游览",
        "去上海出差三天",
        # 中文但非姓名（停用词）
        "姓名：测试数据",
        "联系人 未知",
        "收件人：系统",
        # 普通技术文本
        "def calculate_total(items): return sum(items)",
        "SELECT id, name FROM users WHERE active = 1",
        "docker run -p 8080:80 nginx:latest",
        "内存占用 2048MB，CPU 使用率 45%",
        "错误码 E1001：连接超时（30000ms）",
        "配置项 max_retries=5 timeout=3000",
    ]
    # 补充随机长数字串到目标量
    while len(out) < n:
        length = _rng.choice([12, 13, 14, 15, 17, 19, 20])
        digits = "".join(str(_rng.randint(0, 9)) for _ in range(length))
        if digits.startswith("1") and length == 11:
            continue
        out.append(f"记录 {digits} 已入库")
    return out[:n]
