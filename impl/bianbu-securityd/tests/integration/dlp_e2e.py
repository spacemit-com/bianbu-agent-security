#!/usr/bin/env python3
"""DLP-02/03/04 端到端实证：策略加载 → 输入过滤 → 云端阻断，全链路走真实 SQLite。

用法：python3 tests/integration/dlp_e2e.py
"""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1].parent
sys.path.insert(0, str(ROOT))

from securityd.dlp.handlers import DLPSessionStore, register_dlp_handlers  # noqa: E402
from securityd.dlp.pii_scanner import PIIScanner, PIIType  # noqa: E402
from securityd.dlp.policy_store import DLPAction, DLPPolicyStore  # noqa: E402
from securityd.interceptor import (  # noqa: E402
    Decision,
    HookPoint,
    InterceptorRegistry,
)

OK = "\033[32m✅\033[0m"
BAD = "\033[31m❌\033[0m"
AGENT = "com.e2e.dlpagent"
PHONE = "13812345678"
ID_CARD = "110101199003076173"
CARD = "4539578763621486"

failures = []


def check(cond, label, detail=""):
    print(f"  {OK if cond else BAD} {label}" + (f" — {detail}" if detail else ""))
    if not cond:
        failures.append(label)


def main() -> int:
    tmp = Path(tempfile.mkdtemp(prefix="dlp_e2e_"))
    store = DLPPolicyStore(db_path=tmp / "dlp.db")
    sessions = DLPSessionStore()
    reg = InterceptorRegistry()
    register_dlp_handlers(reg)

    ctx = {"dlp_scanner": PIIScanner(), "dlp_store": store,
           "dlp_sessions": sessions, "session_id": "e2e-sess"}

    print(f"数据根：{tmp}\n")

    print("[1] DLP-02 从 manifest 加载策略")
    manifest = {"agent": {"id": AGENT},
                "dlp": {"default": "allow", "id_card": "mask",
                        "bank_card": "deny"}}
    r = reg.invoke(HookPoint.AGENT_STARTUP, AGENT, {"manifest": manifest}, **ctx)
    check(r.decision == Decision.ALLOW, "启动放行")
    check(r.metadata.get("dlp_policies_loaded") == 3, "加载 3 条策略",
          str(r.metadata.get("dlp_policies_loaded")))
    check(store.get_action(AGENT, PIIType.BANK_CARD) == DLPAction.DENY,
          "bank_card=deny 已生效")
    check(store.get_action(AGENT, PIIType.PHONE) == DLPAction.ALLOW,
          "phone 走 default=allow")

    print("\n[2] 生效矩阵（WebUI 展示用）")
    matrix = store.effective_matrix(AGENT)
    for t, act in sorted(matrix.items()):
        print(f"     {t:<12} {act}")
    check(matrix["id_card"] == "mask" and matrix["bank_card"] == "deny",
          "矩阵覆盖 8 类且值正确")

    print("\n[3] DLP-03 输入过滤 — allow 类型不脱敏")
    r = reg.invoke(HookPoint.INPUT, AGENT, f"客户电话 {PHONE}", **ctx)
    check(r.decision == Decision.ALLOW, "phone(allow) → ALLOW",
          r.decision.value)
    check(r.modified_data is None, "原文未改写")

    print("\n[4] DLP-03 输入过滤 — mask 类型脱敏")
    r = reg.invoke(HookPoint.INPUT, AGENT, f"身份证 {ID_CARD} 已核验", **ctx)
    check(r.decision == Decision.MODIFY, "id_card(mask) → MODIFY",
          r.decision.value)
    check(ID_CARD not in (r.modified_data or ""), "脱敏文本不含原始身份证")
    print(f"     脱敏后：{r.modified_data}")
    check(sessions.get("e2e-sess").get("[PII-身份证-001]") == ID_CARD,
          "映射表已存 session（供 DLP-08 还原）")

    print("\n[5] DLP-03 输入过滤 — deny 类型拒绝")
    r = reg.invoke(HookPoint.INPUT, AGENT, f"卡号 {CARD}", **ctx)
    check(r.decision == Decision.BLOCK, "bank_card(deny) → BLOCK",
          r.decision.value)
    print(f"     拒绝理由：{r.message}")

    print("\n[6] 混合类型只脱该脱的（不破坏业务语义）")
    r = reg.invoke(HookPoint.INPUT, AGENT,
                   f"姓名：张伟，电话 {PHONE}，身份证 {ID_CARD}", **ctx)
    check(r.decision == Decision.MODIFY, "最严处置为 mask")
    out = r.modified_data or ""
    check("张伟" in out, "姓名(default=allow) 保留")
    check(PHONE in out, "电话(default=allow) 保留")
    check(ID_CARD not in out, "身份证(mask) 已脱")
    print(f"     结果：{out}")

    print("\n[7] DLP-04 本地推理 — 高敏按策略走")
    store.set_policy(AGENT, PIIType.ID_CARD, DLPAction.ALLOW)
    r = reg.invoke(HookPoint.PRE_MODEL_CALL, AGENT,
                   {"prompt": f"身份证 {ID_CARD}",
                    "endpoint": "http://127.0.0.1:11434"}, **ctx)
    check(r.decision == Decision.ALLOW, "本地 + allow → 放行不脱",
          r.decision.value)
    check(r.metadata.get("is_cloud") is False, "识别为本地端点")

    print("\n[8] DLP-04 云端推理 — 高敏强制脱敏（覆盖 allow 策略）")
    r = reg.invoke(HookPoint.PRE_MODEL_CALL, AGENT,
                   {"prompt": f"身份证 {ID_CARD}",
                    "endpoint": "https://api.example.com/v1/chat"}, **ctx)
    check(r.decision == Decision.MODIFY, "云端 + L3 → 强制脱敏",
          r.decision.value)
    check(r.metadata.get("cloud_forced_mask") is True, "标记 cloud_forced_mask")
    check(ID_CARD not in (r.modified_data or ""), "出网 prompt 不含原始身份证")
    print(f"     出网 prompt：{r.modified_data}")

    print("\n[9] DLP-04 云端 + 仅低敏 → 不强制")
    r = reg.invoke(HookPoint.PRE_MODEL_CALL, AGENT,
                   {"prompt": f"电话 {PHONE}",
                    "endpoint": "https://api.example.com"}, **ctx)
    check(r.decision == Decision.ALLOW, "云端 + L2 → 按策略放行",
          r.decision.value)
    check(not r.metadata.get("cloud_forced_mask"), "未触发强制脱敏")

    print("\n[10] DLP-09 预演：session 清零")
    before = len(sessions.get("e2e-sess"))
    cleared = sessions.clear("e2e-sess")
    check(before > 0 and cleared == before, f"清掉 {cleared} 条映射")
    check(sessions.get("e2e-sess") == {}, "清零后不可访问")

    print("\n[11] 策略实时生效（改策略后下次调用即变）")
    store.set_policy(AGENT, PIIType.PHONE, DLPAction.DENY)
    r = reg.invoke(HookPoint.INPUT, AGENT, f"电话 {PHONE}", **ctx)
    check(r.decision == Decision.BLOCK, "phone 改 block 后立即拦截",
          r.decision.value)

    print("\n[12] 干预点 trace 完整")
    trace = r.metadata.get("_handler_trace", [])
    check(len(trace) == 1 and trace[0][0] == "dlp_input",
          "trace 记录 dlp_input", str(trace))

    store.close()
    print()
    if failures:
        print(f"{BAD} 失败 {len(failures)} 项：{failures}")
        return 1
    print(f"{OK} 全部通过")
    return 0


if __name__ == "__main__":
    sys.exit(main())
