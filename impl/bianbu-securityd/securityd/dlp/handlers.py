"""DLP 干预点 handler（DLP-02~09）。

全部注册在优先级 50 —— SEC capability(10) 判权之后、Audit(90) 之前。
判权先跑的理由：无权限直接 BLOCK，省掉 PII 扫描开销。

各 handler 的处置由 policy_store 的 (agent_id, pii_type) → action 决定，
同一段文本里不同类型 PII 可有不同处置（身份证 deny、姓名 allow）。
"""
from __future__ import annotations

import json
import logging
import threading
from typing import Optional

from ..interceptor import Decision, HookPoint, InterceptResult
from .pii_scanner import PIIScanner, PIIType, RiskLevel, ScanResult
from .policy_store import DLPAction, DLPPolicyStore

logger = logging.getLogger("securityd.dlp")

__all__ = [
    "DLPSessionStore",
    "startup_handler",
    "input_handler",
    "pre_model_handler",
    "post_model_handler",
    "pre_tool_handler",
    "post_tool_handler",
    "output_handler",
    "shutdown_handler",
    "detect_verbatim_leak",
    "embed_watermark",
    "extract_watermark",
    "strip_watermark",
    "register_dlp_handlers",
    "PRI_DLP",
]

PRI_DLP = 50

# 云端调用中禁止出现的风险级（DLP-04）
CLOUD_FORBIDDEN = frozenset({RiskLevel.L3, RiskLevel.L4})


class DLPSessionStore:
    """session 级脱敏映射表（DLP-03 写入，DLP-08 还原，DLP-09 清零）。

    映射表含明文 PII，是敏感数据 —— 只在内存、不落盘，session 结束即清。
    """

    def __init__(self):
        self._maps: dict[str, dict[str, str]] = {}
        self._lock = threading.Lock()

    def merge(self, session_id: str, mask_map: dict[str, str]) -> None:
        if not mask_map:
            return
        with self._lock:
            self._maps.setdefault(session_id or "-", {}).update(mask_map)

    def get(self, session_id: str) -> dict[str, str]:
        with self._lock:
            return dict(self._maps.get(session_id or "-", {}))

    def clear(self, session_id: str) -> int:
        """清零并覆写（DLP-09）。返回清掉的条数。"""
        with self._lock:
            m = self._maps.pop(session_id or "-", None)
            if not m:
                return 0
            n = len(m)
            # 覆写 value 再丢弃，减少明文在内存中的驻留窗口。
            # Python 字符串不可变，无法真正原地擦除 —— 见文档已知边界。
            for k in list(m):
                m[k] = "\x00" * len(m[k])
            m.clear()
            return n

    def stats(self) -> dict[str, int]:
        with self._lock:
            return {sid: len(m) for sid, m in self._maps.items()}


def _worst_action(result: ScanResult, store: DLPPolicyStore,
                  agent_id: str) -> tuple[DLPAction, list[PIIType]]:
    """取本次命中里最严的处置，以及触发它的类型。

    严格程度：DENY > ASK > MASK > ALLOW。
    """
    order = [DLPAction.ALLOW, DLPAction.MASK, DLPAction.ASK,
             DLPAction.DENY]
    worst = DLPAction.ALLOW
    triggers: list[PIIType] = []
    for t in result.types:
        act = store.get_action(agent_id, t)
        if order.index(act) > order.index(worst):
            worst, triggers = act, [t]
        elif act == worst and act != DLPAction.ALLOW:
            triggers.append(t)
    return worst, triggers


def _label(types) -> str:
    return "、".join(sorted(t.value for t in types))


def _yolo(agent_id: str, context: dict) -> bool:
    """Only adapter-supplied clients can attest the current policy mode."""
    provider = context.get("client_provider")
    if provider is None:
        return False
    client = provider()
    getter = getattr(client, "get_agent_security_mode", None)
    return callable(getter) and getter(agent_id).get("mode") == "yolo"


def _scan(scanner: PIIScanner, text: str, agent_id: str) -> ScanResult:
    """优先使用带 Agent 身份的数据面扫描器，普通 PIIScanner 保持兼容。"""
    scan_for_agent = getattr(scanner, "scan_for_agent", None)
    if callable(scan_for_agent):
        return scan_for_agent(agent_id, text)
    return scanner.scan(text)


def _scan_and_mask_types(scanner: PIIScanner, text: str, agent_id: str,
                         enabled_types: set[PIIType]) -> ScanResult:
    scan_for_agent = getattr(scanner, "scan_and_mask_for_agent", None)
    if callable(scan_for_agent):
        return scan_for_agent(agent_id, text, enabled_types=enabled_types)
    return PIIScanner(enabled_types=enabled_types,
                      ner_backend=scanner.ner_backend,
                      min_confidence=scanner.min_confidence).scan_and_mask(text)


def _mask_subset(scanner: PIIScanner, text: str, store: DLPPolicyStore,
                 agent_id: str) -> ScanResult:
    """只脱敏 action=mask/deny 的类型，allow/ask 的保持原样。

    不能无脑全脱 —— 若姓名策略是 allow，脱掉会破坏正常业务语义。
    """
    remote_subset = getattr(scanner, "scan_mask_subset_for_agent", None)
    if callable(remote_subset):
        return remote_subset(agent_id, text, store)

    full = _scan(scanner, text, agent_id)
    if not full.findings:
        return full
    keep = {t for t in full.types
            if store.get_action(agent_id, t) in
            (DLPAction.MASK, DLPAction.DENY)}
    if not keep:
        full.masked_text = text
        return full
    r = _scan_and_mask_types(scanner, text, agent_id, keep)
    # findings 用全量（审计要看到所有命中），masked_text 用子集脱敏结果
    return ScanResult(findings=full.findings, masked_text=r.masked_text,
                      mask_map=r.mask_map)


# ————————————————————————————————————————————————————————————
# DLP-02 — agent_startup：加载策略
# ————————————————————————————————————————————————————————————
def startup_handler(agent_id: str, hook_point: HookPoint, data,
                    context: dict) -> InterceptResult:
    """从 manifest 的 [dlp] 节导入策略。

    data 形如 {"manifest": {...}}；无 [dlp] 节则沿用系统兜底策略（不报错）。
    """
    store: DLPPolicyStore = context["dlp_store"]
    manifest = (data or {}).get("manifest") or {}
    section = manifest.get("dlp") or {}
    n = store.set_from_manifest(agent_id, section) if section else 0
    return InterceptResult(
        decision=Decision.ALLOW,
        message=f"DLP 策略已加载（{n} 条）" if n else "",
        metadata={"dlp_policies_loaded": n},
    )


# ————————————————————————————————————————————————————————————
# DLP-03 — input：用户输入过滤
# ————————————————————————————————————————————————————————————
def input_handler(agent_id: str, hook_point: HookPoint, data,
                  context: dict) -> InterceptResult:
    """扫描用户输入，按策略 allow / ask / deny / mask。"""
    if _yolo(agent_id, context):
        return InterceptResult(decision=Decision.ALLOW, metadata={"mode": "yolo", "dlp_skipped": True})
    scanner: PIIScanner = context["dlp_scanner"]
    store: DLPPolicyStore = context["dlp_store"]
    sessions: Optional[DLPSessionStore] = context.get("dlp_sessions")
    session_id = context.get("session_id", "")

    text = data if isinstance(data, str) else (data or {}).get("text", "")
    if not text:
        return InterceptResult(decision=Decision.ALLOW)

    result = _mask_subset(scanner, text, store, agent_id)
    if not result.findings:
        return InterceptResult(decision=Decision.ALLOW)

    action, triggers = _worst_action(result, store, agent_id)
    meta = {"pii_types": sorted(t.value for t in result.types),
            "max_risk": result.max_risk().value,
            "dlp_action": action.value}

    if action == DLPAction.DENY:
        return InterceptResult(
            decision=Decision.BLOCK,
            message=f"输入含受限敏感信息（{_label(triggers)}），已按 DLP 策略拒绝",
            metadata=meta)

    if action == DLPAction.ASK:
        return InterceptResult(
            decision=Decision.CONFIRM,
            message=f"输入含敏感信息（{_label(triggers)}），需确认后继续",
            metadata=meta)

    if action == DLPAction.MASK:
        if sessions is not None:
            sessions.merge(session_id, result.mask_map)
        return InterceptResult(
            decision=Decision.MODIFY,
            message=f"输入已脱敏（{_label(triggers)}）",
            modified_data=result.masked_text,
            metadata=meta)

    return InterceptResult(
        decision=Decision.ALLOW,
        message=f"检出 PII（{_label(result.types)}），按策略放行并记审计",
        metadata=meta)


# ————————————————————————————————————————————————————————————
# DLP-04 — pre_model_call：云端调用阻断
# ————————————————————————————————————————————————————————————
def pre_model_handler(agent_id: str, hook_point: HookPoint, data,
                      context: dict) -> InterceptResult:
    """LLM 调用前扫描 prompt。

    本地模型：按策略脱敏即可。
    云端模型：L3/L4 PII（身份证/银行卡/医疗/生物特征）**一律不出本机** ——
    策略为 block 则 BLOCK，否则脱敏后放行（脱敏值出网是可接受的）。
    云端判定：context["is_cloud"]，或 endpoint 非 localhost。
    """
    if _yolo(agent_id, context):
        return InterceptResult(decision=Decision.ALLOW, metadata={"mode": "yolo", "dlp_skipped": True})
    scanner: PIIScanner = context["dlp_scanner"]
    store: DLPPolicyStore = context["dlp_store"]
    sessions: Optional[DLPSessionStore] = context.get("dlp_sessions")
    session_id = context.get("session_id", "")

    if isinstance(data, str):
        prompt, endpoint = data, context.get("endpoint", "")
    else:
        d = data or {}
        prompt = d.get("prompt", "")
        endpoint = d.get("endpoint", context.get("endpoint", ""))
    if not prompt:
        return InterceptResult(decision=Decision.ALLOW)

    is_cloud = context.get("is_cloud")
    if is_cloud is None:
        is_cloud = bool(endpoint) and not any(
            h in endpoint for h in ("localhost", "127.0.0.1", "::1", "unix:"))

    result = _mask_subset(scanner, prompt, store, agent_id)
    if not result.findings:
        return InterceptResult(decision=Decision.ALLOW)

    action, triggers = _worst_action(result, store, agent_id)
    high = {t for t in result.types if t in
            {x for x in PIIType if _risk(x) in CLOUD_FORBIDDEN}}
    meta = {"pii_types": sorted(t.value for t in result.types),
            "max_risk": result.max_risk().value,
            "is_cloud": bool(is_cloud),
            "dlp_action": action.value}

    if action == DLPAction.DENY:
        return InterceptResult(
            decision=Decision.BLOCK,
            message=f"prompt 含受限敏感信息（{_label(triggers)}），已拒绝调用",
            metadata=meta)

    # 云端 + 高敏 → 必须脱敏，不受策略影响
    if is_cloud and high:
        if sessions is not None:
            sessions.merge(session_id, result.mask_map)
        if not result.mask_map:
            # 高敏类型策略是 allow/ask，_mask_subset 没脱它 → 强制脱
            forced = _scan_and_mask_types(scanner, prompt, agent_id, high)
            if sessions is not None:
                sessions.merge(session_id, forced.mask_map)
            masked = forced.masked_text
        else:
            masked = result.masked_text
        meta["cloud_forced_mask"] = True
        return InterceptResult(
            decision=Decision.MODIFY,
            message=f"云端调用含高敏信息（{_label(high)}），已强制脱敏后出网",
            modified_data=masked,
            metadata=meta)

    if action == DLPAction.MASK:
        if sessions is not None:
            sessions.merge(session_id, result.mask_map)
        return InterceptResult(
            decision=Decision.MODIFY,
            message=f"prompt 已脱敏（{_label(triggers)}）",
            modified_data=result.masked_text,
            metadata=meta)

    return InterceptResult(
        decision=Decision.ALLOW,
        message=f"检出 PII（{_label(result.types)}），本地调用按策略放行",
        metadata=meta)


def _risk(t: PIIType) -> RiskLevel:
    from .pii_scanner import RISK_OF

    return RISK_OF[t]


# ————————————————————————————————————————————————————————————
# DLP-05 — post_model_call：模型输出检测
# ————————————————————————————————————————————————————————————
def _shingles(text: str, n: int = 20) -> set[str]:
    """字符级 n-gram。

    中文没有天然词边界，按字符切比按词切更稳；同时归一化空白，
    防止插空格绕过检测。
    """
    norm = "".join(text.split())
    if len(norm) < n:
        return set()
    return {norm[i:i + n] for i in range(len(norm) - n + 1)}


def _longest_common_span(a: str, b: str, n: int = 20) -> int:
    """a 中与 b 逐字相同的最长连续片段长度（归一化后按字符算）。

    先用 n-gram 找锚点，再向右贪心延伸 —— 对本场景的文本量足够，
    不必上后缀自动机。
    """
    if len(a) < n or len(b) < n:
        return 0
    ref_grams = {b[i:i + n] for i in range(len(b) - n + 1)}
    best = 0
    i = 0
    while i <= len(a) - n:
        if a[i:i + n] not in ref_grams:
            i += 1
            continue
        # 命中锚点，向右延伸到不再是 b 的子串为止
        end = i + n
        while end < len(a) and a[i:end + 1] in b:
            end += 1
        span = end - i
        if span > best:
            best = span
        i = end - n + 1 if end - n + 1 > i else i + 1
    return best


def detect_verbatim_leak(
    output: str,
    corpus: list[str],
    n: int = 20,
    threshold: float = 0.8,
    min_span: int = 100,
) -> Optional[tuple[float, int]]:
    """检测输出是否逐字复现语料。返回 (覆盖率, 语料序号) 或 None。

    **双信号判定**，任一命中即判泄露：

    1. **绝对连续长度 ≥ min_span** —— 主信号。抄了 100+ 字连续原文就是泄露，
       后面拼多少自有内容都不改变这个事实。
    2. **覆盖率 ≥ threshold** —— 辅助信号，兜住短于 min_span 但通篇照抄的情况。

    单用覆盖率会被"补长"绕过：实测在语料 64 字的样本上，尾部只需追加 15 字
    无关文本，覆盖率就从 100% 掉到 77.6%（低于 0.8 门限）而漏判；追加 66 字
    降到 52.3%。分母随输出增长，比例天然被稀释。绝对长度不受此影响。

    覆盖率用「输出 n-gram 被语料覆盖的比例」而非 Jaccard：语料通常远长于
    输出，Jaccard 的分母被语料撑大，短输出即使整段照抄也算不出高分。
    """
    if not corpus:
        return None  # 未提供参考语料 → 跳过检测，不报错
    norm_out = "".join(output.split())
    out = _shingles(output, n)
    if not out:
        return None

    best_ratio = 0.0
    best_idx = -1
    hit_idx = -1
    for idx, doc in enumerate(corpus):
        ref = _shingles(doc, n)
        if not ref:
            continue
        ratio = len(out & ref) / len(out)
        if ratio > best_ratio:
            best_ratio, best_idx = ratio, idx
        # 主信号：绝对连续长度
        if ratio > 0 and hit_idx < 0:
            span = _longest_common_span(norm_out, "".join(doc.split()), n)
            if span >= min_span:
                hit_idx = idx
                best_ratio, best_idx = max(best_ratio, ratio), idx

    if hit_idx >= 0:
        return (best_ratio, hit_idx)
    if best_idx >= 0 and best_ratio >= threshold:
        return (best_ratio, best_idx)
    return None


def post_model_handler(agent_id: str, hook_point: HookPoint, data,
                       context: dict) -> InterceptResult:
    """扫描 LLM 输出。

    两类风险分开处理：
      · 输出含 PII —— 按策略 allow/ask/deny/mask
      · 逐字复现训练语料 —— **一律 BLOCK 并告警**，不受 PII 策略影响。
        这是模型行为异常（记忆泄露），不是数据敏感度问题。
    """
    if _yolo(agent_id, context):
        return InterceptResult(decision=Decision.ALLOW, metadata={"mode": "yolo", "dlp_skipped": True})
    scanner: PIIScanner = context["dlp_scanner"]
    store: DLPPolicyStore = context["dlp_store"]
    sessions: Optional[DLPSessionStore] = context.get("dlp_sessions")
    session_id = context.get("session_id", "")

    text = data if isinstance(data, str) else (data or {}).get("response", "")
    if not text:
        return InterceptResult(decision=Decision.ALLOW)

    # 逐字泄露优先判 —— 命中即短路，不必再看 PII
    corpus = context.get("dlp_reference_corpus") or []
    leak = detect_verbatim_leak(
        text, corpus,
        threshold=float(context.get("dlp_leak_threshold", 0.8)),
        min_span=int(context.get("dlp_leak_min_span", 100)))
    if leak:
        ratio, idx = leak
        return InterceptResult(
            decision=Decision.BLOCK,
            message=f"模型输出逐字复现参考语料（覆盖率 {ratio:.0%}，"
                    f"语料 #{idx}），疑似训练数据泄露，已拦截",
            metadata={"verbatim_leak": True, "leak_ratio": round(ratio, 4),
                      "leak_corpus_index": idx, "alert": "training_data_leak"})

    result = _mask_subset(scanner, text, store, agent_id)
    if not result.findings:
        return InterceptResult(decision=Decision.ALLOW)

    action, triggers = _worst_action(result, store, agent_id)
    meta = {"pii_types": sorted(t.value for t in result.types),
            "max_risk": result.max_risk().value,
            "dlp_action": action.value,
            "pii_source": "model_output"}

    if action == DLPAction.DENY:
        return InterceptResult(
            decision=Decision.BLOCK,
            message=f"模型输出含受限敏感信息（{_label(triggers)}），已拦截",
            metadata=meta)

    if action == DLPAction.ASK:
        return InterceptResult(
            decision=Decision.CONFIRM,
            message=f"模型输出含敏感信息（{_label(triggers)}），需确认后继续",
            metadata=meta)

    if action == DLPAction.MASK:
        if sessions is not None:
            sessions.merge(session_id, result.mask_map)
        return InterceptResult(
            decision=Decision.MODIFY,
            message=f"模型输出已脱敏（{_label(triggers)}）",
            modified_data=result.masked_text,
            metadata=meta)

    return InterceptResult(
        decision=Decision.ALLOW,
        message=f"模型输出检出 PII（{_label(result.types)}），按策略放行",
        metadata=meta)


# ————————————————————————————————————————————————————————————
# DLP-06 — pre_tool_call：工具参数 PII → 提升为 CONFIRM
# ————————————————————————————————————————————————————————————
def _args_to_text(args) -> str:
    """把工具参数摊成可扫描文本。参数形态不定，序列化要容错。"""
    if args is None:
        return ""
    if isinstance(args, str):
        return args
    try:
        return json.dumps(args, ensure_ascii=False, default=str)
    except (TypeError, ValueError):
        return str(args)


def pre_tool_handler(agent_id: str, hook_point: HookPoint, data,
                     context: dict) -> InterceptResult:
    """扫描工具参数中的 PII。

    **不脱敏，而是提升为 CONFIRM** —— 脱了工具就没法用了：
    路径里的手机号被替换成占位符会导致文件找不到，API body 里的
    身份证被脱会让请求失败。让用户明确批准把 PII 交给这个工具，
    批准后工具拿到的仍是原始参数。

    策略为 mask/ask 时也提升 —— 工具调用意味着 PII 要离开 Agent
    进程（写文件/发网络请求），比留在上下文里风险高一档。

    远端出境再提一档（D-9）：调用方标了 `egress.remote` 时，连
    `action=allow` 的类型也要确认。运维把"姓名"配成 allow，指的是本地
    工具用它无所谓；发到第三方 server 是另一回事，而且数据出境不可撤回。
    """
    if _yolo(agent_id, context):
        return InterceptResult(decision=Decision.ALLOW, metadata={"mode": "yolo", "dlp_skipped": True})
    scanner: PIIScanner = context["dlp_scanner"]
    store: DLPPolicyStore = context["dlp_store"]

    d = data if isinstance(data, dict) else {}
    tool_name = d.get("tool", "?")
    text = _args_to_text(d.get("args"))
    if not text:
        return InterceptResult(decision=Decision.ALLOW)

    result = _scan(scanner, text, agent_id)
    if not result.findings:
        return InterceptResult(decision=Decision.ALLOW)

    action, triggers = _worst_action(result, store, agent_id)
    meta = {"pii_types": sorted(t.value for t in result.types),
            "max_risk": result.max_risk().value,
            "dlp_action": action.value,
            "pii_source": "tool_args",
            "tool": tool_name}

    # —— D-9：远端 MCP 出境标记 ——
    egress = d.get("egress") if isinstance(d.get("egress"), dict) else None
    remote = bool(egress and egress.get("remote"))
    if remote:
        meta["egress_remote"] = True
        endpoint = str(egress.get("endpoint") or "")
        if endpoint:
            meta["egress_endpoint"] = endpoint
        if egress.get("transport_unknown"):
            # 读不到 mcp.json 时调用方按远端从严处理，这里记下原因，
            # 免得运维以为真配了远端 server
            meta["egress_transport_unknown"] = True

    if action == DLPAction.DENY:
        return InterceptResult(
            decision=Decision.BLOCK,
            message=f"{tool_name} 的参数含受限敏感信息（{_label(triggers)}），已拒绝",
            metadata=meta)

    if action == DLPAction.ALLOW and not remote:
        return InterceptResult(decision=Decision.ALLOW, metadata=meta)

    # mask / ask 一律提升为 CONFIRM（不脱敏，见 docstring）；
    # 远端出境时 allow 也提升。
    meta["escalated_to_confirm"] = True
    where = ""
    if remote:
        meta["escalation_reason"] = "remote_egress"
        endpoint = meta.get("egress_endpoint")
        where = f"，将发送至外部服务 {endpoint}" if endpoint else "，将发送至外部服务"
    return InterceptResult(
        decision=Decision.CONFIRM,
        message=f"{tool_name} 的参数含敏感信息（{_label(result.types)}）{where}，需确认",
        metadata=meta)


# ————————————————————————————————————————————————————————————
# DLP-07 — post_tool_call：工具返回值脱敏
# ————————————————————————————————————————————————————————————
def post_tool_handler(agent_id: str, hook_point: HookPoint, data,
                      context: dict) -> InterceptResult:
    """工具返回值进入上下文前脱敏。

    与 pre_tool_call 相反，这里**必须脱**：返回值只是给模型看的文本，
    脱敏不影响功能；不脱则 PII 进入上下文后会在后续多轮里反复传播，
    模型还可能把它复述到最终输出。

    大载荷（>4 KB）经 UDS 扫描（ARCH-01）—— 走 D-Bus 会被
    dbus-daemon 中转拖慢。context["uds_client"] 提供时启用。
    """
    if _yolo(agent_id, context):
        return InterceptResult(decision=Decision.ALLOW, metadata={"mode": "yolo", "dlp_skipped": True})
    scanner: PIIScanner = context["dlp_scanner"]
    store: DLPPolicyStore = context["dlp_store"]
    sessions: Optional[DLPSessionStore] = context.get("dlp_sessions")
    session_id = context.get("session_id", "")

    d = data if isinstance(data, dict) else {}
    tool_name = d.get("tool", "?")
    raw = d.get("result") if isinstance(data, dict) else data
    if raw is None or raw == "":
        return InterceptResult(decision=Decision.ALLOW)
    text = raw if isinstance(raw, str) else _args_to_text(raw)
    if not text:
        return InterceptResult(decision=Decision.ALLOW)

    result = _mask_subset(scanner, text, store, agent_id)
    if not result.findings:
        return InterceptResult(decision=Decision.ALLOW)

    action, triggers = _worst_action(result, store, agent_id)
    meta = {"pii_types": sorted(t.value for t in result.types),
            "max_risk": result.max_risk().value,
            "dlp_action": action.value,
            "pii_source": "tool_result",
            "tool": tool_name,
            "payload_bytes": len(text.encode("utf-8"))}

    if action == DLPAction.DENY:
        return InterceptResult(
            decision=Decision.BLOCK,
            message=f"{tool_name} 的返回值含受限敏感信息（{_label(triggers)}），"
                    f"已阻止进入上下文",
            metadata=meta)

    if action == DLPAction.ASK:
        return InterceptResult(
            decision=Decision.CONFIRM,
            message=f"{tool_name} 的返回值含敏感信息（{_label(triggers)}），需确认后继续",
            metadata=meta)

    if action == DLPAction.MASK:
        if sessions is not None:
            sessions.merge(session_id, result.mask_map)
        return InterceptResult(
            decision=Decision.MODIFY,
            message=f"{tool_name} 的返回值已脱敏（{_label(triggers)}）",
            modified_data=result.masked_text,
            metadata=meta)

    return InterceptResult(
        decision=Decision.ALLOW,
        message=f"{tool_name} 返回值检出 PII（{_label(result.types)}），按策略放行",
        metadata=meta)


# ————————————————————————————————————————————————————————————
# DLP-08 — output：最终输出审查（含还原与水印）
# ————————————————————————————————————————————————————————————
# 零宽字符编码水印：0 → ZWSP，1 → ZWNJ，边界 → ZWJ
_WM_ZERO = "​"
_WM_ONE = "‌"
_WM_MARK = "‍"
_WM_CHARS = frozenset({_WM_ZERO, _WM_ONE, _WM_MARK})


def embed_watermark(text: str, payload: str) -> str:
    """把 payload 以零宽字符编码嵌入文末（视觉不可见，可提取溯源）。"""
    if not payload:
        return text
    bits = "".join(f"{b:08b}" for b in payload.encode("utf-8"))
    encoded = "".join(_WM_ONE if b == "1" else _WM_ZERO for b in bits)
    return text + _WM_MARK + encoded + _WM_MARK


def extract_watermark(text: str) -> Optional[str]:
    """提取水印。无水印或格式不符返回 None。"""
    first = text.find(_WM_MARK)
    if first < 0:
        return None
    last = text.find(_WM_MARK, first + 1)
    if last < 0:
        return None
    encoded = text[first + 1:last]
    if not encoded or any(c not in (_WM_ZERO, _WM_ONE) for c in encoded):
        return None
    bits = "".join("1" if c == _WM_ONE else "0" for c in encoded)
    if len(bits) % 8:
        return None
    try:
        return bytes(int(bits[i:i + 8], 2)
                     for i in range(0, len(bits), 8)).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return None


def strip_watermark(text: str) -> str:
    """去掉所有零宽水印字符。"""
    return "".join(c for c in text if c not in _WM_CHARS)


def output_handler(agent_id: str, hook_point: HookPoint, data,
                   context: dict) -> InterceptResult:
    """最终输出审查：还原本 session 脱敏值 → 复扫 → 处置 → 可选水印。

    还原的理由：DLP-03/07 为了不让 PII 在 Agent 内部传播而脱敏，但用户
    本来就有权看自己提供的信息。**仅还原本 session 映射表里的占位符** ——
    跨 session 的占位符不还原，防会话间泄露。

    还原后必须复扫：还原可能把新的 PII 暴露出来（比如策略在会话中途改严了）。
    """
    if _yolo(agent_id, context):
        return InterceptResult(decision=Decision.ALLOW, metadata={"mode": "yolo", "dlp_skipped": True})
    scanner: PIIScanner = context["dlp_scanner"]
    store: DLPPolicyStore = context["dlp_store"]
    sessions: Optional[DLPSessionStore] = context.get("dlp_sessions")
    session_id = context.get("session_id", "")

    text = data if isinstance(data, str) else (data or {}).get("output", "")
    if not text:
        return InterceptResult(decision=Decision.ALLOW)

    original = text
    restored_n = 0
    if sessions is not None:
        mask_map = sessions.get(session_id)
        if mask_map:
            before = text
            text = PIIScanner.unmask(text, mask_map)
            restored_n = sum(1 for k in mask_map if k in before)

    result = _mask_subset(scanner, text, store, agent_id)
    meta = {"restored_placeholders": restored_n,
            "pii_source": "final_output"}

    if result.findings:
        action, triggers = _worst_action(result, store, agent_id)
        meta.update({"pii_types": sorted(t.value for t in result.types),
                     "max_risk": result.max_risk().value,
                     "dlp_action": action.value})
        if action == DLPAction.DENY:
            return InterceptResult(
                decision=Decision.MODIFY,
                message=f"输出含受限敏感信息（{_label(triggers)}），已屏蔽",
                modified_data=f"[内容已屏蔽：含 {_label(triggers)}]",
                metadata=meta)
        if action == DLPAction.ASK:
            return InterceptResult(
                decision=Decision.CONFIRM,
                message=f"输出含敏感信息（{_label(triggers)}），需确认后返回",
                metadata=meta)
        if action == DLPAction.MASK:
            text = result.masked_text

    wm = context.get("dlp_watermark")
    if wm:
        text = embed_watermark(text, str(wm))
        meta["watermarked"] = True

    parts = []
    if restored_n:
        parts.append(f"还原 {restored_n} 处占位符")
    if result.findings and meta.get("dlp_action") == DLPAction.MASK.value:
        parts.append("脱敏")
    if meta.get("watermarked"):
        parts.append("注入水印")

    # 判 MODIFY 看「是否发生过处理」，不能只比最终文本是否等于原文：
    # 还原 → 复扫 → 重新脱敏 会得到与原文逐字相同的串（占位符编号一致），
    # 那时若报 ALLOW，调用方就不知道中间还原过明文 PII，
    # restored_placeholders 这类审计字段也会被埋掉。
    if not parts:
        return InterceptResult(decision=Decision.ALLOW, metadata=meta)

    return InterceptResult(
        decision=Decision.MODIFY,
        message="输出已处理（" + "、".join(parts) + "）",
        modified_data=text,
        metadata=meta)


# ————————————————————————————————————————————————————————————
# DLP-09 — agent_shutdown：session 清零
# ————————————————————————————————————————————————————————————
def shutdown_handler(agent_id: str, hook_point: HookPoint, data,
                     context: dict) -> InterceptResult:
    """清零 session 内的脱敏映射表（含明文 PII）。

    退出是终态，拦也没意义 —— 只观察 + 清理。
    """
    sessions: Optional[DLPSessionStore] = context.get("dlp_sessions")
    session_id = context.get("session_id", "")
    n = sessions.clear(session_id) if sessions is not None else 0
    return InterceptResult(
        decision=Decision.ALLOW,
        message=f"已清零 {n} 条 PII 映射" if n else "",
        metadata={"pii_mappings_cleared": n})


# ————————————————————————————————————————————————————————————
# 注册
# ————————————————————————————————————————————————————————————
def register_dlp_handlers(registry) -> None:
    """把已实现的 DLP handler 注册到 registry（幂等）。"""
    pairs = [
        (HookPoint.AGENT_STARTUP, startup_handler, "dlp_startup"),
        (HookPoint.INPUT, input_handler, "dlp_input"),
        (HookPoint.PRE_MODEL_CALL, pre_model_handler, "dlp_pre_model"),
        (HookPoint.POST_MODEL_CALL, post_model_handler, "dlp_post_model"),
        (HookPoint.PRE_TOOL_CALL, pre_tool_handler, "dlp_pre_tool"),
        (HookPoint.POST_TOOL_CALL, post_tool_handler, "dlp_post_tool"),
        (HookPoint.OUTPUT, output_handler, "dlp_output"),
        (HookPoint.AGENT_SHUTDOWN, shutdown_handler, "dlp_shutdown"),
    ]
    for hp, fn, name in pairs:
        registry.unregister(hp, name)
        # DLP handler 异常/超时时不能让原文继续流向模型/工具/输出（R-1/R-2）
        registry.register(hp, fn, name=name, priority=PRI_DLP, on_error="block")
