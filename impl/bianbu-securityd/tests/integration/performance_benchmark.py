#!/usr/bin/env python3
"""发布候选性能门禁（NFR-P-01/NFR-P-02）。

测量本机 SecurityEngine 判权和真实 bwrap 冷启动，输出可直接归档的
``PERF_PASS``/``PERF_FAIL`` 记录。该脚本不依赖 pytest，也不启动系统服务。
"""
from __future__ import annotations

import argparse
import os
import statistics
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def _p99(values: list[float]) -> float:
    if not values:
        return float("inf")
    values = sorted(values)
    # nearest-rank P99，避免小样本线性插值掩盖尾延迟。
    return values[min(len(values) - 1, max(0, int(len(values) * 0.99) - 1))]


def _permission_benchmark(n: int) -> tuple[float, float, float]:
    from securityd.engine import SecurityEngine
    from securityd.models import Confirm, Domain, Permission, RiskLevel

    engine = SecurityEngine()
    try:
        aid = "com.bianbu.perf"
        engine.registry.register_capabilities(aid, [Permission(
            capability="perf.read", domain=Domain.DATA, risk_level=RiskLevel.L1,
            confirm=Confirm.TRUSTED)])
        samples: list[float] = []
        for _ in range(n):
            t0 = time.perf_counter_ns()
            engine.check_permission(aid, "perf.read")
            samples.append((time.perf_counter_ns() - t0) / 1e6)
        return statistics.mean(samples), _p99(samples), max(samples)
    finally:
        engine.close()


def _sandbox_python() -> str:
    """返回沙箱内可见的目标解释器，不误用宿主临时发布 venv 路径。"""
    configured = os.environ.get("BIANBU_PERF_SANDBOX_PYTHON")
    if configured:
        return configured
    system_python = Path("/usr/bin/python3")
    return str(system_python) if system_python.is_file() else sys.executable


def _bare_benchmark(n: int, executable: str) -> tuple[float, float, float]:
    """测量与 bwrap 内相同解释器的裸冷启动，作为相对开销基线。"""
    samples: list[float] = []
    for _ in range(n):
        t0 = time.perf_counter_ns()
        cp = subprocess.run([executable, "-c", "pass"],
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL, check=False)
        samples.append((time.perf_counter_ns() - t0) / 1e6)
        if cp.returncode != 0:
            raise RuntimeError(f"bare benchmark launch failed: rc={cp.returncode}")
    return statistics.mean(samples), _p99(samples), max(samples)


def _sandbox_benchmark(n: int, executable: str) -> tuple[float, float, float, list[float]] | None:
    from securityd.sandbox import SandboxSpec, launch

    if not __import__("shutil").which("bwrap"):
        return None
    import tempfile

    samples: list[float] = []
    with tempfile.TemporaryDirectory(prefix="bnsec-perf-") as d:
        spec = SandboxSpec(
            agent_id="com.bianbu.perf",
            agent_binary=[executable, "-c", "pass"],
            rw_dir=Path(d), unshare_net=False,
        )
        for _ in range(n):
            t0 = time.perf_counter_ns()
            result = launch(spec, wait=True, timeout=10)
            samples.append((time.perf_counter_ns() - t0) / 1e6)
            if not result.ok:
                raise RuntimeError(f"bwrap benchmark launch failed: {result.reason}")
    return statistics.mean(samples), _p99(samples), max(samples), samples


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--samples", type=int, default=100)
    ap.add_argument("--skip-sandbox", action="store_true")
    ap.add_argument("--check", action="store_true", help="超过指标时返回 1")
    args = ap.parse_args(argv)
    if args.samples < 10:
        ap.error("--samples 至少为 10")

    mean, p99, worst = _permission_benchmark(args.samples)
    print(f"PERF_PERMISSION samples={args.samples} avg_ms={mean:.3f} "
          f"p99_ms={p99:.3f} max_ms={worst:.3f}")
    ok = p99 <= 10.0
    if not args.skip_sandbox:
        sandbox_n = min(args.samples, 40)
        sandbox_python = _sandbox_python()
        print(f"PERF_SANDBOX_PYTHON executable={sandbox_python}")
        bare_avg, bare_p99, bare_max = _bare_benchmark(sandbox_n, sandbox_python)
        print(f"PERF_BARE samples={sandbox_n} avg_ms={bare_avg:.3f} "
              f"p99_ms={bare_p99:.3f} max_ms={bare_max:.3f}")
        sandbox = _sandbox_benchmark(sandbox_n, sandbox_python)
        if sandbox is None:
            print("PERF_SANDBOX skipped=bwrap_missing")
        else:
            s_avg, s_p99, s_max, s_samples = sandbox
            # 以同样本数的 P99 差值定义相对冷启动开销；同时保留绝对
            # bwrap P99 上限，避免基线抖动掩盖异常。
            overhead_p99 = max(0.0, s_p99 - bare_p99)
            print(f"PERF_SANDBOX samples={sandbox_n} avg_ms={s_avg:.3f} "
                  f"p99_ms={s_p99:.3f} max_ms={s_max:.3f} "
                  f"overhead_p99_ms={overhead_p99:.3f} overhead_budget_ms=200")
            ok = ok and s_p99 <= 200.0 and overhead_p99 <= 200.0
    if args.check and not ok:
        print("PERF_FAIL")
        return 1
    print("PERF_PASS" if ok else "PERF_NOT_MEETING_TARGET")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
