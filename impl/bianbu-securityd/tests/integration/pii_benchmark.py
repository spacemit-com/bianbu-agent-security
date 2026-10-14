#!/usr/bin/env python3
"""DLP-01 验收基准：召回率 ≥95%、误报率 ≤3%。

正样本每类 200 条（结构化的用算法生成合法值，含正确校验位）；
负样本 400 条形似但非 PII（订单号、校验位错的身份证/银行卡、技术文本等）。

用法：python3 tests/integration/pii_benchmark.py
"""
from __future__ import annotations

import sys
import time
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1].parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from fixtures import pii_corpus  # noqa: E402
from securityd.dlp.pii_scanner import PIIScanner, PIIType  # noqa: E402

OK = "\033[32m✅\033[0m"
BAD = "\033[31m❌\033[0m"
WARN = "\033[33m⚠\033[0m"

RECALL_TARGET = 0.95
FP_TARGET = 0.03

failures = []


def check(cond, label, detail=""):
    print(f"  {OK if cond else BAD} {label}" + (f" — {detail}" if detail else ""))
    if not cond:
        failures.append(label)


def main() -> int:
    scanner = PIIScanner()

    print("=" * 66)
    print("DLP-01 PII 检测基准（worker K3 riscv64）")
    print("=" * 66)

    # —— 召回率 ——
    pos = pii_corpus.positives(n_per_type=200)
    print(f"\n[1] 召回率（正样本 {len(pos)} 条，每类 200）")

    hit = defaultdict(int)
    total = defaultdict(int)
    missed_examples = defaultdict(list)

    t0 = time.perf_counter()
    for text, want_type, want_value in pos:
        total[want_type] += 1
        r = scanner.scan(text)
        # 命中判定：该类型有命中，且命中值覆盖期望值（允许边界宽一点）
        got = r.by_type(want_type)
        if any(want_value in f.value or f.value in want_value for f in got):
            hit[want_type] += 1
        elif len(missed_examples[want_type]) < 3:
            missed_examples[want_type].append((text, [f.value for f in got]))
    scan_elapsed = time.perf_counter() - t0

    print(f"\n     {'类型':<12} {'召回':<10} {'命中/总数':<12} 状态")
    print(f"     {'-'*12} {'-'*10} {'-'*12} {'-'*6}")
    overall_hit = overall_total = 0
    per_type_fail = []
    for t in PIIType:
        if total[t] == 0:
            continue
        recall = hit[t] / total[t]
        overall_hit += hit[t]
        overall_total += total[t]
        mark = OK if recall >= RECALL_TARGET else BAD
        if recall < RECALL_TARGET:
            per_type_fail.append((t.value, recall))
        print(f"     {t.value:<12} {recall:>7.1%}   {hit[t]:>4}/{total[t]:<7} {mark}")

    overall_recall = overall_hit / overall_total
    print(f"\n     总体召回 {overall_recall:.2%}（{overall_hit}/{overall_total}）")
    check(overall_recall >= RECALL_TARGET,
          f"总体召回 ≥{RECALL_TARGET:.0%}", f"{overall_recall:.2%}")

    if per_type_fail:
        print(f"\n     {WARN} 未达标类型：")
        for name, r in per_type_fail:
            print(f"       {name}: {r:.1%}")
            for text, got in missed_examples[PIIType(name)][:2]:
                print(f"         漏检示例：{text[:50]!r} → 命中={got}")

    # —— 误报率 ——
    neg = pii_corpus.negatives(n=400)
    print(f"\n[2] 误报率（负样本 {len(neg)} 条，形似但非 PII）")

    fp_count = 0
    fp_detail = defaultdict(list)
    for text in neg:
        r = scanner.scan(text)
        if r.has_pii:
            fp_count += 1
            for f in r.findings:
                if len(fp_detail[f.pii_type]) < 3:
                    fp_detail[f.pii_type].append((text[:48], f.value))

    fp_rate = fp_count / len(neg)
    print(f"\n     误报 {fp_count}/{len(neg)} = {fp_rate:.2%}")
    check(fp_rate <= FP_TARGET, f"误报率 ≤{FP_TARGET:.0%}", f"{fp_rate:.2%}")

    if fp_detail:
        print(f"\n     误报分布：")
        for t, items in sorted(fp_detail.items(), key=lambda kv: kv[0].value):
            print(f"       {t.value}（{len(items)}+ 例）：")
            for text, val in items:
                print(f"         {text!r} → 误判 {val!r}")

    # —— 校验位有效性 ——
    print("\n[3] 校验位对误报的贡献（关掉校验位会怎样）")
    bad_ids = [pii_corpus.gen_id_card_bad_checksum() for _ in range(200)]
    bad_cards = [pii_corpus.gen_bank_card_bad_luhn() for _ in range(200)]
    id_fp = sum(1 for x in bad_ids if scanner.scan(x).by_type(PIIType.ID_CARD))
    card_fp = sum(1 for x in bad_cards
                  if scanner.scan(x).by_type(PIIType.BANK_CARD))
    check(id_fp == 0, "200 个校验位错的身份证全部排除", f"误判 {id_fp}")
    check(card_fp == 0, "200 个 Luhn 不过的卡号全部排除", f"误判 {card_fp}")
    print(f"     若无校验位，这 400 条会全部误报（正则本身都匹配）")

    # —— 性能 ——
    print("\n[4] 扫描性能")
    per_text_ms = scan_elapsed / len(pos) * 1000
    print(f"     {len(pos)} 条正样本耗时 {scan_elapsed:.2f}s"
          f"，平均 {per_text_ms:.3f}ms/条")

    big = "客户张伟电话 13812345678，身份证 110101199003076173。" * 200
    t0 = time.perf_counter()
    r = scanner.scan_and_mask(big)
    big_ms = (time.perf_counter() - t0) * 1000
    print(f"     大文本（{len(big)} 字符，{len(r.findings)} 处命中）"
          f"扫描+脱敏 {big_ms:.1f}ms")
    check(per_text_ms < 5.0, "单条扫描 < 5ms", f"{per_text_ms:.3f}ms")

    # —— 脱敏可逆性 ——
    print("\n[5] 脱敏可逆性（DLP-08 依赖）")
    sample = ("联系人：李娜，手机 13987654321，"
              "邮箱 lina@example.com，身份证 110101199003076173")
    masked = scanner.scan_and_mask(sample)
    restored = PIIScanner.unmask(masked.masked_text, masked.mask_map)
    check(restored == sample, "脱敏后可完整还原")
    check("13987654321" not in masked.masked_text, "脱敏文本不含原始手机号")
    check("110101199003076173" not in masked.masked_text, "脱敏文本不含原始身份证")
    print(f"     脱敏后：{masked.masked_text}")

    print()
    if failures:
        print(f"{BAD} 未达标 {len(failures)} 项：{failures}")
        return 1
    print(f"{OK} DLP-01 全部指标达标")
    return 0


if __name__ == "__main__":
    sys.exit(main())
