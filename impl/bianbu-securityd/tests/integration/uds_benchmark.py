#!/usr/bin/env python3
"""ARCH-01 实测：UDS 数据面延迟与吞吐（验证 P99 ≤ 1ms 指标）。

只测 UDS 本身（不与 D-Bus 对比 —— 对比需 securityd 在跑，另做）。
用法：python3 tests/integration/uds_benchmark.py
"""
from __future__ import annotations

import statistics
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1].parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "client"))

from securityd.uds_server import UdsServer  # noqa: E402

OK = "\033[32m✅\033[0m"
BAD = "\033[31m❌\033[0m"
failures = []


def check(cond, label, detail=""):
    print(f"  {OK if cond else BAD} {label}" + (f" — {detail}" if detail else ""))
    if not cond:
        failures.append(label)


def pct(values, p):
    s = sorted(values)
    k = max(0, min(len(s) - 1, int(round((p / 100) * len(s) + 0.5)) - 1))
    return s[k]


def bench(client, payload_size: int, n: int):
    text = "x" * payload_size
    lat = []
    for _ in range(n):
        t0 = time.perf_counter()
        r = client.call({"op": "echo", "text": text})
        lat.append((time.perf_counter() - t0) * 1000)
        assert r["ok"], r
    return lat


def main() -> int:
    tmp = Path(tempfile.mkdtemp(prefix="uds_bench_"))
    srv = UdsServer(socket_path=tmp / "bench.sock")
    srv.register("echo", lambda req, uid: {"echo": req.get("text", "")})
    srv.register("noop", lambda req, uid: {})
    srv.start()

    import bianbu_security_uds as uds

    client = uds.UdsClient(socket_path=srv.socket_path, timeout=30.0)
    client.connect()

    try:
        print("环境：worker K3 riscv64")
        print(f"socket：{srv.socket_path}\n")

        print("[1] 空载 round-trip（1000 次，测协议开销下界）")
        lat = []
        for _ in range(1000):
            t0 = time.perf_counter()
            client.call({"op": "noop"})
            lat.append((time.perf_counter() - t0) * 1000)
        p50, p99 = pct(lat, 50), pct(lat, 99)
        print(f"     p50={p50:.3f}ms  p99={p99:.3f}ms  "
              f"mean={statistics.mean(lat):.3f}ms  max={max(lat):.3f}ms")
        check(p99 <= 1.0, "空载 P99 ≤ 1ms（ARCH-01 指标）", f"p99={p99:.3f}ms")

        print("\n[2] 不同载荷的延迟（各 200 次）")
        rows = []
        for size in (1024, 4096, 64 * 1024, 1024 * 1024):
            lat = bench(client, size, 200)
            p50, p99 = pct(lat, 50), pct(lat, 99)
            thr = size / (statistics.mean(lat) / 1000) / (1024 * 1024)
            rows.append((size, p50, p99, thr))
            label = f"{size // 1024}KB" if size >= 1024 else f"{size}B"
            print(f"     {label:>7}: p50={p50:.3f}ms  p99={p99:.3f}ms  "
                  f"吞吐≈{thr:.1f} MB/s")

        # 4KB 是 ARCH-01 的通道分界，该尺寸下 UDS 应仍在 1ms 内
        p99_4k = next(r[2] for r in rows if r[0] == 4096)
        check(p99_4k <= 1.0, "4KB（通道分界）P99 ≤ 1ms", f"p99={p99_4k:.3f}ms")

        # 1MB 是数据面典型载荷，给出实测值供 SRS 引用（不设硬指标）
        p99_1m = next(r[2] for r in rows if r[0] == 1024 * 1024)
        print(f"\n     注：1MB 载荷 p99={p99_1m:.2f}ms —— 大载荷指标由吞吐而非延迟约束")

        print("\n[3] 连续吞吐（1MB × 50 次）")
        t0 = time.perf_counter()
        for _ in range(50):
            client.call({"op": "echo", "text": "y" * (1024 * 1024)})
        elapsed = time.perf_counter() - t0
        thr = (50 * 1024 * 1024) / elapsed / (1024 * 1024)
        print(f"     50MB / {elapsed:.2f}s = {thr:.1f} MB/s")
        check(thr > 10, "吞吐 > 10 MB/s", f"{thr:.1f} MB/s")

        print("\n[4] 长连接稳定性（复用同一连接 2000 次）")
        errs = 0
        for i in range(2000):
            try:
                if not client.call({"op": "noop"}).get("ok"):
                    errs += 1
            except Exception:  # noqa: BLE001
                errs += 1
        check(errs == 0, "2000 次复用零错误", f"errors={errs}")

    finally:
        client.close()
        srv.stop()

    print()
    if failures:
        print(f"{BAD} 失败 {len(failures)} 项：{failures}")
        return 1
    print(f"{OK} 全部达标")
    return 0


if __name__ == "__main__":
    sys.exit(main())
