"""测试运行入口。

必须独立于 engine.py：若用 `python engine.py`，则 tests_all 里的
`from engine import ...` 会创建**第二个** engine 模块实例，@test 装饰器
注册到那个实例的 TESTS，而 __main__ 里的 run_all 读到的是空列表
（实测跑出「总计 0」）。这里让 engine 与 tests_all 都作为普通模块导入，
共用同一个实例。
"""
from __future__ import annotations

import sys

import engine
import tests_all  # noqa: F401  — 导入即注册测试项


def main() -> int:
    sel = set(sys.argv[1:]) or None
    if sel:
        known = {t["id"] for t in engine.TESTS}
        unknown = sel - known
        if unknown:
            print(f"未知测试 ID: {sorted(unknown)}", file=sys.stderr)
            print(f"可用: {sorted(known)}", file=sys.stderr)
            return 2
    print(f"已注册 {len(engine.TESTS)} 个测试项"
          f"{'，本次运行 ' + str(len(sel)) if sel else '，全部运行'}")
    out = engine.run_all(sel)
    s = out["summary"]
    print(f"\n{'=' * 62}")
    print(f"总计 {s['total']} | 通过 {s['passed']} | 失败 {s['failed']} "
          f"| 错误 {s['error']} | 耗时 {s['duration_ms'] / 1000:.1f}s")
    print(f"报告: {engine.OUT_DIR / 'report.json'}")
    print("=" * 62)
    bad = [r for r in out["results"] if r["status"] not in ("passed", "skipped")]
    if bad:
        print("\n未通过的测试项：")
        for r in bad:
            print(f"  [{r['status'].upper():6s}] {r['id']:10s} {r['title']}")
            if r["message"]:
                print(f"             → {r['message'][:220]}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
