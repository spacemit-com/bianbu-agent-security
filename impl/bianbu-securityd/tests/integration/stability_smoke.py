#!/usr/bin/env python3
"""可控时长稳定性回归（默认 60 秒；正式发布需另外执行 24/72 小时）。"""
from __future__ import annotations

import argparse
import os
import tempfile
import time
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--seconds", type=float, default=60.0)
    args = ap.parse_args()
    with tempfile.TemporaryDirectory(prefix="bnsec-stability-") as d:
        os.environ["BIANBU_SEC_ROOT"] = d
        from securityd import config
        import importlib
        importlib.reload(config)
        from securityd.engine import SecurityEngine
        from securityd.models import Confirm, Domain, Permission, RiskLevel
        eng = SecurityEngine()
        eng.registry.register_capabilities("com.bianbu.stability", [
            Permission("health.read", Domain.DATA, RiskLevel.L1, Confirm.TRUSTED)])
        start = time.monotonic(); ops = 0; errors = []
        while time.monotonic() - start < args.seconds:
            try:
                eng.check_permission("com.bianbu.stability", "health.read")
                eng.audit_log("com.bianbu.stability", "stability", str(ops), "ok")
                ops += 1
            except Exception as exc:  # noqa: BLE001
                errors.append(repr(exc)); break
        live = eng.audit.verify_live()
        eng.close()
    if errors or not live:
        print(f"STABILITY_FAIL ops={ops} errors={errors} chain={live}")
        return 1
    print(f"STABILITY_PASS seconds={args.seconds:g} ops={ops} chain=True")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
