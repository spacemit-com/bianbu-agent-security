"""PII 检测引擎（DLP-01）。

设计取舍：**正则 + 校验位为基线，NER 为可插拔增强**。

为什么不直接上 NER：目标平台（K3 riscv64）没有 spaCy/transformers，装模型代价大；
而 8 类基线 PII 里 6 类是结构化的（手机/身份证/邮箱/银行卡/护照/车牌），正则配上
校验算法（身份证 GB 11643 校验码、银行卡 Luhn）就能做到高召回 + 低误报。
姓名和地址确实需要 NER，缺失时用关键词邻近启发式兜底，并如实标低置信度。

误报控制的关键是校验位：11 位数字满足手机号正则的很多（订单号、流水号），
但身份证校验码错的直接排除、银行卡 Luhn 不过的直接排除。
"""
from __future__ import annotations

import re
import base64
import binascii
import unicodedata
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Iterable, Optional

__all__ = [
    "PIIType",
    "RiskLevel",
    "PIIFinding",
    "ScanResult",
    "PIIScanner",
    "StreamingPIIScanner",
    "luhn_valid",
    "cn_id_checksum_valid",
]


class RiskLevel(str, Enum):
    """PII 敏感级别 —— DLP-04 用它决定云端是否放行。"""

    L1 = "L1"  # 低敏：姓名单独出现
    L2 = "L2"  # 中敏：邮箱、手机号、地址
    L3 = "L3"  # 高敏：身份证、银行卡、护照
    L4 = "L4"  # 极敏：医疗记录、生物特征


class PIIType(str, Enum):
    """8 类基线 PII（SRS DLP-01）。"""

    NAME = "name"
    PHONE = "phone"
    ID_CARD = "id_card"
    EMAIL = "email"
    BANK_CARD = "bank_card"
    ADDRESS = "address"
    MEDICAL = "medical"
    BIOMETRIC = "biometric"


RISK_OF: dict[PIIType, RiskLevel] = {
    PIIType.NAME: RiskLevel.L1,
    PIIType.EMAIL: RiskLevel.L2,
    PIIType.PHONE: RiskLevel.L2,
    PIIType.ADDRESS: RiskLevel.L2,
    PIIType.ID_CARD: RiskLevel.L3,
    PIIType.BANK_CARD: RiskLevel.L3,
    PIIType.MEDICAL: RiskLevel.L4,
    PIIType.BIOMETRIC: RiskLevel.L4,
}


@dataclass(frozen=True)
class PIIFinding:
    """一处命中。"""

    pii_type: PIIType
    start: int
    end: int
    value: str
    confidence: float
    risk_level: RiskLevel
    detector: str = "regex"  # regex / regex+checksum / ner / heuristic

    @property
    def length(self) -> int:
        return self.end - self.start


@dataclass
class ScanResult:
    """扫描结果。"""

    findings: list[PIIFinding] = field(default_factory=list)
    masked_text: str = ""
    mask_map: dict[str, str] = field(default_factory=dict)  # 占位符 → 原值

    @property
    def has_pii(self) -> bool:
        return bool(self.findings)

    @property
    def types(self) -> set[PIIType]:
        return {f.pii_type for f in self.findings}

    def max_risk(self) -> Optional[RiskLevel]:
        """最高敏感级别（DLP-04 判云端放行用）。"""
        if not self.findings:
            return None
        order = [RiskLevel.L1, RiskLevel.L2, RiskLevel.L3, RiskLevel.L4]
        return max((f.risk_level for f in self.findings), key=order.index)

    def by_type(self, t: PIIType) -> list[PIIFinding]:
        return [f for f in self.findings if f.pii_type == t]


# ————————————————————————————————————————————————————————————
# 校验算法 —— 压误报的核心
# ————————————————————————————————————————————————————————————
def luhn_valid(number: str) -> bool:
    """银行卡 Luhn 校验（ISO/IEC 7812）。"""
    digits = [int(c) for c in number if c.isdigit()]
    if len(digits) < 12:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


_ID_WEIGHTS = (7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2)
_ID_CHECK = "10X98765432"


def plausible_card_bin(digits: str) -> bool:
    """卡号是否落在真实发卡行 BIN 范围与对应长度（ISO/IEC 7812 + 银联规范）。

    只靠 Luhn 不够：Luhn 是 10 取模，**随机数字串约 1/10 概率碰巧通过**。
    实测 400 条负样本（随机 12-20 位数字）里有 20+ 条过 Luhn。
    加上"BIN 前缀 + 该卡种法定长度"双重约束才能把随机串排除 ——
    这也是真实 DLP 产品的做法。
    """
    n = len(digits)
    if not digits.isdigit():
        return False
    p1, p2, p4, p6 = digits[:1], digits[:2], digits[:4], digits[:6]
    # Visa：4 开头，13/16/19 位
    if p1 == "4":
        return n in (13, 16, 19)
    # Mastercard：51-55 或 2221-2720，16 位
    if p2 in {"51", "52", "53", "54", "55"}:
        return n == 16
    if p4.isdigit() and 2221 <= int(p4) <= 2720:
        return n == 16
    # 银联：62 开头，16-19 位
    if p2 == "62":
        return 16 <= n <= 19
    # AmEx：34/37，15 位
    if p2 in {"34", "37"}:
        return n == 15
    # JCB：3528-3589，16 位
    if p4.isdigit() and 3528 <= int(p4) <= 3589:
        return n == 16
    # Discover：6011 / 65 / 644-649，16/19 位
    if p4 == "6011" or p2 == "65" or (p1 == "6" and p6[:3].isdigit()
                                     and 644 <= int(p6[:3]) <= 649):
        return n in (16, 19)
    # Diners：300-305 / 3095 / 36 / 38-39，14 位
    if p2 in {"36", "38", "39"} or (p6[:3].isdigit() and 300 <= int(p6[:3]) <= 305):
        return n == 14
    return False


def _looks_like_cn_id(digits: str) -> bool:
    """18 位数字是否为身份证形态（第 7-14 位是合法出生日期）。

    用于把身份证从银行卡候选中剔除：Luhn 是 10 取模，18 位身份证有约 1/10
    概率碰巧通过 Luhn（实测 400 条负样本里出现过）。判形态比判校验位更宽 ——
    校验位错的身份证也不该被当成银行卡。
    """
    if len(digits) != 18 or not digits.isdigit():
        return False
    year, month, day = int(digits[6:10]), int(digits[10:12]), int(digits[12:14])
    return 1900 <= year <= 2099 and 1 <= month <= 12 and 1 <= day <= 31


def cn_id_checksum_valid(number: str) -> bool:
    """中国大陆身份证 18 位校验码（GB 11643-1999）。"""
    s = number.strip().upper()
    if len(s) != 18 or not s[:17].isdigit():
        return False
    # 出生日期合理性（1900-2099，月 01-12，日 01-31）
    year = int(s[6:10])
    month = int(s[10:12])
    day = int(s[12:14])
    if not (1900 <= year <= 2099 and 1 <= month <= 12 and 1 <= day <= 31):
        return False
    total = sum(int(c) * w for c, w in zip(s[:17], _ID_WEIGHTS))
    return s[17] == _ID_CHECK[total % 11]


# ————————————————————————————————————————————————————————————
# 正则库
# ————————————————————————————————————————————————————————————
# 手机号：中国大陆 1[3-9]xxxxxxxxx，两侧不能紧邻其他数字（否则是长数字串的一段）
_RE_PHONE = re.compile(r"(?<!\d)1[3-9]\d{9}(?!\d)")
# 身份证：18 位，末位可为 X；校验码另行验证
_RE_ID = re.compile(r"(?<![0-9Xx])\d{17}[\dXx](?![0-9Xx])")
# 邮箱：RFC 5322 的实用子集
_RE_EMAIL = re.compile(
    r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
# 银行卡：13~19 位，允许空格/连字符分组；Luhn 另行验证
_RE_BANK = re.compile(r"(?<!\d)(?:\d[ \-]?){12,18}\d(?!\d)")
# 地址：[省]市区 + 街道 + 门牌（省级可缺 —— 直辖市的"市"即省级）
# 必须同时有行政区划后缀和门牌号，否则只是地名（"在北京市朝阳区上班"不算地址）
_RE_ADDRESS = re.compile(
    r"(?:[一-龥]{2,10}(?:省|自治区|特别行政区))?"
    r"[一-龥]{2,10}(?:市|自治州|地区)"
    r"[一-龥]{2,10}(?:区|县|市|旗)"
    r"[一-龥A-Za-z0-9]{2,20}(?:路|街|道|巷|村|大道|胡同)"
    r"[一-龥0-9\-]{1,15}(?:号|栋|单元|室|层)")
# 医疗：病名直接命中；诊断类关键词带紧随其后的病名/编号
# 不用宽泛的 {0,30} 尾巴 —— 会吃掉后面无关文本（"诊断为糖尿病 无法使用"）
_RE_MEDICAL = re.compile(
    r"(?:诊断为|确诊|既往史[：:]?|药物过敏[：:]?)\s*[一-龥]{2,10}"
    r"|(?:病历号|住院号|门诊号)\s*[：:]?\s*[A-Za-z0-9\-]{3,20}"
    r"|(?:HIV|艾滋病?|恶性肿瘤|肿瘤|癌症|糖尿病|高血压|"
    r"精神分裂症?|抑郁症|乙肝|梅毒)")
# 生物特征：指纹/人脸/虹膜等标识 + 数据引用
_RE_BIOMETRIC = re.compile(
    r"(?:指纹|人脸|虹膜|声纹|掌纹|视网膜|DNA|基因序列|face_embedding|"
    r"fingerprint|iris_scan|voiceprint)"
    r"(?:特征|数据|模板|识别|信息|embedding|hash|template)?")
# 姓名（NER 缺失时的启发式）：称谓/上下文词 + 2-4 字中文姓名
# 不能用 (?![一-龥]) —— "患者陈芳于今日就诊" 里姓名后紧跟中文，会整体失配。
# 改为非贪婪 2-4 字，靠姓氏表在 _detect_all 里二次确认。
# 捕获 2-4 字后由姓氏表 + 停用词二次确认；不加右侧 lookahead ——
# 加了会在"签收人：郭明"（行尾）和"患者陈芳于今日"（后接中文）两类场景失配。
_RE_NAME_CTX = re.compile(
    r"(?:姓名|名字|叫做|叫|签收人|联系人|收件人|患者|客户|先生|女士|同学|"
    r"经办人|负责人|申请人)"
    r"[：:是为\s]{0,3}([一-龥]{2,4})")

# 常见姓氏 —— 启发式姓名的二次确认，压误报。
# 覆盖大陆人口占比 ~95% 的姓氏（按第七次人口普查常见姓氏整理）。
_SURNAMES = frozenset(
    "王李张刘陈杨黄赵吴周徐孙马朱胡郭何高林罗郑梁谢宋唐许韩冯邓曹彭曾"
    "肖田董袁潘于蒋蔡余杜叶程苏魏吕丁任沈姚卢姜崔钟谭陆汪范金石廖贾夏"
    "韦傅方白邹孟熊秦邱江尹薛闫段雷侯龙史陶黎贺顾毛郝龚邵万钱严覃武戴"
    "莫孔向汤常温康施文牛樊葛邢安齐易乔伍庞颜倪庄聂章鲁岳翟殷詹申欧耿"
    "关兰焦俞左柳甘祝包宁尚符舒阮柯纪梅童凌毕单季裴霍涂成苗谷盛曲翁冉"
    "骆蓝路游辛靳管柴蒙鲍华喻祁蒲房滕屈饶解牟艾尤阳时穆农司卓古吉缪简"
    "车项连芦麦褚娄窦戚岑景党宫费卜冷晏席卫米柏宗瞿桂全佟应臧闵苟邬边"
    "卞姬师和仇栾隋商刁沙荣巫寇桑郎甄丛仲虞敖巩明佘池查麻苑迟邝")

# 常见非姓名词，避免"姓名：测试数据"这类误报
_NAME_STOPWORDS = frozenset({
    "测试", "数据", "内容", "信息", "未知", "空白", "示例", "样例",
    "无效", "临时", "系统", "管理", "用户", "客户", "先生", "女士",
})

# 虚词/助词 —— 出现在捕获串里说明多吃了字（"陈芳于今" 的 "于"）
_NAME_TAIL_STOPCHARS = frozenset("于是的已在与和就将把被让给对从到向为所而且或")
_ZERO_WIDTH = frozenset("\u200b\u200c\u200d\u2060\ufeff")


def _normalize_with_positions(text: str) -> tuple[str, list[int]]:
    """NFKC 归一化并删除零宽字符，同时保留归一化字符到原文的索引。"""
    out, positions = [], []
    for idx, ch in enumerate(text):
        if ch in _ZERO_WIDTH:
            continue
        normalized = unicodedata.normalize("NFKC", ch)
        for n in normalized:
            out.append(n)
            positions.append(idx)
    return "".join(out), positions


class PIIScanner:
    """PII 检测引擎。

    NER 后端可选：`ner_backend` 是 `Callable[[str], Iterable[PIIFinding]]`，
    传入即启用（用于姓名/地址等非结构化 PII）；不传则用启发式兜底。

    掩码占位符形如 `[PII-手机号-001]`，`mask_map` 记录占位符→原值，
    供 DLP-08 在最终输出时还原（同一 session 内）。
    """

    _LABEL = {
        PIIType.NAME: "姓名",
        PIIType.PHONE: "手机号",
        PIIType.ID_CARD: "身份证",
        PIIType.EMAIL: "邮箱",
        PIIType.BANK_CARD: "银行卡",
        PIIType.ADDRESS: "地址",
        PIIType.MEDICAL: "医疗",
        PIIType.BIOMETRIC: "生物特征",
    }

    def __init__(
        self,
        enabled_types: Optional[Iterable[PIIType]] = None,
        ner_backend: Optional[Callable[[str], Iterable[PIIFinding]]] = None,
        min_confidence: float = 0.5,
    ):
        self.enabled_types = set(enabled_types) if enabled_types else set(PIIType)
        self.ner_backend = ner_backend
        self.min_confidence = min_confidence

    # —— 检测 ——
    def scan(self, text: str) -> ScanResult:
        """检测但不改写。"""
        if not text:
            return ScanResult(masked_text=text or "")
        raw = list(self._detect_all(text))
        # Unicode NFKC + 零宽字符归一化，防全角数字、零宽插入绕过。
        normalized, positions = _normalize_with_positions(text)
        if normalized != text:
            for f in self._detect_all(normalized):
                if f.start >= len(positions) or f.end <= 0:
                    continue
                start = positions[f.start]
                end = positions[min(f.end - 1, len(positions) - 1)] + 1
                raw.append(PIIFinding(f.pii_type, start, end, text[start:end],
                                      f.confidence, f.risk_level,
                                      f.detector + "+unicode-normalized"))
        raw.extend(self._detect_base64(text))
        findings = self._resolve_overlaps(raw)
        findings = [f for f in findings if f.confidence >= self.min_confidence]
        findings.sort(key=lambda f: f.start)
        return ScanResult(findings=findings, masked_text=text)

    def _detect_base64(self, text: str) -> Iterable[PIIFinding]:
        """检测 Base64 包裹的 UTF-8 PII；命中时覆盖整个编码串。"""
        for m in re.finditer(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{16,}={0,2}(?![A-Za-z0-9+/])", text):
            token = m.group()
            if len(token) % 4:
                continue
            try:
                decoded = base64.b64decode(token, validate=True).decode("utf-8")
            except (binascii.Error, UnicodeDecodeError, ValueError):
                continue
            if not decoded or len(decoded) > 1024 * 1024:
                continue
            nested = list(self._detect_all(decoded))
            for f in nested:
                yield PIIFinding(f.pii_type, m.start(), m.end(), token,
                                 min(f.confidence, 0.90), f.risk_level,
                                 f.detector + "+base64")

    def scan_and_mask(self, text: str) -> ScanResult:
        """检测并生成脱敏文本 + 还原映射。"""
        result = self.scan(text)
        if not result.findings:
            return result
        counters: dict[PIIType, int] = {}
        parts, mask_map, cursor = [], {}, 0
        for f in result.findings:
            counters[f.pii_type] = counters.get(f.pii_type, 0) + 1
            placeholder = (f"[PII-{self._LABEL[f.pii_type]}-"
                           f"{counters[f.pii_type]:03d}]")
            parts.append(text[cursor:f.start])
            parts.append(placeholder)
            mask_map[placeholder] = f.value
            cursor = f.end
        parts.append(text[cursor:])
        result.masked_text = "".join(parts)
        result.mask_map = mask_map
        return result

    @staticmethod
    def unmask(text: str, mask_map: dict[str, str]) -> str:
        """用映射表还原（DLP-08）。占位符不在表中则保持原样。"""
        for placeholder, original in mask_map.items():
            text = text.replace(placeholder, original)
        return text

    # —— 内部 ——
    def _detect_all(self, text: str) -> Iterable[PIIFinding]:
        want = self.enabled_types

        if PIIType.EMAIL in want:
            for m in _RE_EMAIL.finditer(text):
                yield self._mk(PIIType.EMAIL, m.start(), m.end(), m.group(), 0.95)

        if PIIType.ID_CARD in want:
            for m in _RE_ID.finditer(text):
                v = m.group()
                if cn_id_checksum_valid(v):
                    yield self._mk(PIIType.ID_CARD, m.start(), m.end(), v,
                                   0.99, "regex+checksum")
                # 校验码不过 → 不是身份证，直接丢（这是压误报的关键）

        if PIIType.PHONE in want:
            for m in _RE_PHONE.finditer(text):
                yield self._mk(PIIType.PHONE, m.start(), m.end(), m.group(), 0.92)

        if PIIType.BANK_CARD in want:
            for m in _RE_BANK.finditer(text):
                v = m.group()
                digits = re.sub(r"\D", "", v)
                # 11 位以 1 开头 → 手机号，不重复判银行卡
                if len(digits) == 11 and digits.startswith("1"):
                    continue
                # 18 位且内含合法出生日期 → 身份证形态，不判银行卡
                if len(digits) == 18 and _looks_like_cn_id(digits):
                    continue
                # 紧跟 X/x 的 17 位是身份证被正则截断的前半段
                if len(digits) == 17 and m.end() < len(text) \
                        and text[m.end()] in "Xx":
                    continue
                # BIN + 长度 + Luhn 三重校验（单靠 Luhn 会放过 ~1/10 随机串）
                if plausible_card_bin(digits) and luhn_valid(digits):
                    yield self._mk(PIIType.BANK_CARD, m.start(), m.end(), v,
                                   0.96, "regex+bin+checksum")

        if PIIType.ADDRESS in want:
            for m in _RE_ADDRESS.finditer(text):
                yield self._mk(PIIType.ADDRESS, m.start(), m.end(), m.group(), 0.85)

        if PIIType.MEDICAL in want:
            for m in _RE_MEDICAL.finditer(text):
                yield self._mk(PIIType.MEDICAL, m.start(), m.end(),
                               m.group().strip(), 0.80)

        if PIIType.BIOMETRIC in want:
            for m in _RE_BIOMETRIC.finditer(text):
                yield self._mk(PIIType.BIOMETRIC, m.start(), m.end(), m.group(), 0.82)

        # 姓名：有 NER 用 NER，否则启发式（如实标低置信度）
        if PIIType.NAME in want:
            if self.ner_backend is None:
                for m in _RE_NAME_CTX.finditer(text):
                    name = self._trim_name(m.group(1))
                    if name is None:
                        continue
                    yield self._mk(PIIType.NAME, m.start(1),
                                   m.start(1) + len(name), name,
                                   0.70, "heuristic")

        if self.ner_backend is not None:
            for f in self.ner_backend(text):
                if f.pii_type in want:
                    yield f

    @staticmethod
    def _is_stopword_name(name: str) -> bool:
        """姓名是否为非人名词。停用词可能是捕获串的前缀或后缀。"""
        if name in _NAME_STOPWORDS:
            return True
        return any(name.startswith(w) or name.endswith(w)
                   for w in _NAME_STOPWORDS)

    @classmethod
    def _trim_name(cls, captured: str) -> Optional[str]:
        """从 2-4 字捕获串里截出真正的姓名。

        正则不带右侧 lookahead（否则行尾和后接中文两类场景失配），
        代价是会多吃字："患者陈芳于今日" 捕到 "陈芳于今"。
        这里从长到短试，取首字是姓氏、且不含虚词的最长前缀。
        """
        for n in (4, 3, 2):
            if len(captured) < n:
                continue
            cand = captured[:n]
            if cand[0] not in _SURNAMES:
                return None  # 首字非姓氏，整体判否
            if any(c in _NAME_TAIL_STOPCHARS for c in cand[1:]):
                continue  # 含虚词，试更短的
            if cls._is_stopword_name(cand):
                continue
            return cand
        return None

    def _mk(self, t: PIIType, start: int, end: int, value: str,
            conf: float, detector: str = "regex") -> PIIFinding:
        return PIIFinding(pii_type=t, start=start, end=end, value=value,
                          confidence=conf, risk_level=RISK_OF[t],
                          detector=detector)

    @staticmethod
    def _resolve_overlaps(findings: list[PIIFinding]) -> list[PIIFinding]:
        """重叠区间取优：先长度、再置信度、再高敏感级。

        身份证 18 位里可能同时匹配到手机号片段（虽有边界断言，仍可能因上下文交叠），
        取更长的那个才对。
        """
        if not findings:
            return []
        order = [RiskLevel.L1, RiskLevel.L2, RiskLevel.L3, RiskLevel.L4]
        ranked = sorted(
            findings,
            key=lambda f: (-(f.end - f.start), -f.confidence,
                           -order.index(f.risk_level)))
        kept: list[PIIFinding] = []
        for f in ranked:
            if any(not (f.end <= k.start or f.start >= k.end) for k in kept):
                continue  # 与已保留项重叠
            kept.append(f)
        return kept


class StreamingPIIScanner:
    """跨 chunk 的有界窗口扫描器。

    保存上一块尾部，足以覆盖结构化 PII 和 Base64 token 边界；只返回本次
    新形成的命中，避免调用方重复告警。窗口有上限，不随流式长度增长。
    """

    def __init__(self, scanner: PIIScanner | None = None, window: int = 4096):
        self.scanner = scanner or PIIScanner()
        self.window = max(256, int(window))
        self._tail = ""

    def feed(self, chunk: str) -> ScanResult:
        chunk = chunk or ""
        prefix = self._tail
        combined = prefix + chunk
        result = self.scanner.scan(combined)
        findings = [f for f in result.findings if f.end > len(prefix)]
        self._tail = combined[-self.window:]
        return ScanResult(findings=findings, masked_text=chunk)

    def reset(self) -> None:
        self._tail = ""
