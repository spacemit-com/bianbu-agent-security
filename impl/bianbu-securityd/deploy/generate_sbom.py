#!/usr/bin/env python3
"""生成离线 SPDX-lite SBOM，并严格核对 requirements-lock。

默认命令只生成报告；``--strict`` 用于发布门禁：lockfile 中的每个依赖
都必须能被当前解释器发现、版本必须完全匹配，且许可证不能是 UNKNOWN。
漏洞扫描需要外部 advisory 数据库，不能由本脚本伪造“无漏洞”结论。
"""
from __future__ import annotations

import importlib.metadata
import json
import platform
import argparse
from datetime import datetime, timezone
from pathlib import Path

LICENSE_POLICY = {
    "cryptography": "Apache-2.0 OR BSD-3-Clause",
    "dbus-python": "MIT/X11",
    "pygobject": "LGPL-2.1-or-later",
    "pytest": "MIT",
    "flask": "BSD-3-Clause",
    "flask-socketio": "MIT",
    "python-socketio": "MIT",
    "gunicorn": "MIT",
    "simple-websocket": "MIT",
    "langgraph": "MIT",
}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--strict", action="store_true", help="缺包/版本或许可证未知时失败")
    ap.add_argument("--output", default="sbom.json")
    args = ap.parse_args(argv)
    root = Path(__file__).resolve().parents[1]
    lock = root / "requirements-lock.txt"
    wanted = {}
    if lock.is_file():
        for line in lock.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "==" in line:
                name, version = line.split("==", 1)
                wanted[name.lower().replace("_", "-")] = version
    installed = {}
    for dist in sorted(importlib.metadata.distributions(), key=lambda d: d.metadata["Name"] or ""):
        name = dist.metadata["Name"]
        if not name:
            continue
        key = name.lower().replace("_", "-")
        if key in wanted:
            metadata_license = dist.metadata.get("License") or ""
            # 系统 site-packages + venv 可能同时存在同名发行包；优先选择
            # 与 lockfile 精确匹配的实例，避免旧系统包覆盖新隔离环境。
            candidate = {"name": name, "version": dist.version,
                              "license": metadata_license or LICENSE_POLICY.get(key, "UNKNOWN"),
                              "license_source": "metadata" if metadata_license else "project-policy",
                              "locked_version": wanted[key],
                              "version_matches_lock": dist.version == wanted[key]}
            previous = installed.get(key)
            if previous is None or candidate["version_matches_lock"] or not previous["version_matches_lock"]:
                installed[key] = candidate
    packages = []
    missing = []
    for key, version in sorted(wanted.items()):
        item = installed.get(key)
        if item is None:
            missing.append(key)
            packages.append({"name": key, "version": None, "license": "UNKNOWN",
                             "locked_version": version, "version_matches_lock": False,
                             "installed": False, "license_source": "none"})
        else:
            item["installed"] = True
            packages.append(item)
    out = {"bomFormat": "SPDX-lite", "specVersion": "0.1",
           "created": datetime.now(timezone.utc).isoformat(),
           "platform": platform.platform(), "lockfile": str(lock),
           "license_policy": "THIRD_PARTY_LICENSES.md",
           "packages": packages,
           "missing_packages": missing,
           "license_unknown": [p["name"] for p in packages if p["license"] == "UNKNOWN"]}
    target = Path(args.output).resolve()
    target.write_text(json.dumps(out, ensure_ascii=False, indent=2) + "\n")
    mismatches = [p["name"] for p in packages if not p["version_matches_lock"]]
    unknown = out["license_unknown"]
    if args.strict and (mismatches or missing or unknown):
        print("SBOM_STRICT_FAIL " + json.dumps({"version_mismatch": mismatches,
              "missing": missing, "license_unknown": unknown}, ensure_ascii=False))
        return 1
    print("SBOM_PASS" if not mismatches else "SBOM_VERSION_MISMATCH " + ",".join(mismatches))
    return 0 if not mismatches else 1


if __name__ == "__main__":
    raise SystemExit(main())
