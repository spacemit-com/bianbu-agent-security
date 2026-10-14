#!/usr/bin/env python3
"""只读验收正式 Agent Runtime 的 systemd/D-Bus 生产身份。

该探针不启动、停止或修改任何服务。缺少正式 Runtime 时返回 2（BLOCKED），
而不是把仓库内的 Runtime consumer 私测当成生产接入通过。
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
from pathlib import Path


REQUIRED_METHODS = {
    "Start", "Pause", "Resume", "Stop", "Terminate", "Checkpoint", "Restore",
    "ListCheckpoints", "GetResourceStats", "ExportResourceHistory", "List",
    "SendMessage",
}


def _run(argv: list[str], timeout: float = 5.0) -> tuple[int, str, str]:
    try:
        cp = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        return cp.returncode, cp.stdout, cp.stderr
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 127, "", str(exc)


def _systemctl(scope: str, *args: str) -> list[str]:
    return ["systemctl"] + (["--user"] if scope == "user" else []) + list(args)


def _show_unit(unit: str, scope: str) -> dict[str, str]:
    rc, out, err = _run(_systemctl(scope, "show", unit,
                                   "--property=User,Group,ControlGroup,ActiveState,MainPID,ExecStart"))
    values: dict[str, str] = {}
    if rc == 0:
        for line in out.splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                values[k] = v.strip()
    values["_rc"] = str(rc)
    if err:
        values["_error"] = err.strip()
    return values


def _introspect(bus: str) -> tuple[set[str], str]:
    cmd = ["busctl", "--user" if bus == "user" else "--system",
           "introspect", "io.bianbu.Runtime", "/io/bianbu/Runtime"]
    rc, out, err = _run(cmd)
    methods: set[str] = set()
    if rc == 0:
        # busctl columns: NAME TYPE SIGNATURE RESULT FLAGS; only method rows
        for line in out.splitlines():
            fields = line.split()
            if len(fields) >= 2 and fields[1] == "method":
                # systemd 259 的 busctl tree 输出在成员名前加层级点（.Start），
                # 旧版本直接输出 Start；统一还原为 D-Bus 成员名。
                methods.add(fields[0].lstrip("."))
    return methods, err.strip() if rc else ""


def probe(*, unit: str, scope: str, bus: str, expected_user: str,
          expected_group: str = "") -> dict:
    checks: list[dict[str, object]] = []
    values = _show_unit(unit, scope)
    unit_ok = (values.get("_rc") == "0" and values.get("ActiveState") == "active"
               and values.get("MainPID", "0") not in {"", "0"}
               and values.get("User", "") == expected_user
               and (not expected_group or values.get("Group", "") == expected_group))
    checks.append({"name": "systemd_identity", "ok": unit_ok, "details": values})
    methods, introspect_error = _introspect(bus)
    dbus_ok = REQUIRED_METHODS.issubset(methods)
    checks.append({"name": "runtime_dbus_contract", "ok": dbus_ok,
                   "details": {"found": sorted(methods),
                               "missing": sorted(REQUIRED_METHODS - methods),
                               "error": introspect_error}})
    return {"ok": all(bool(c["ok"]) for c in checks), "unit": unit,
            "scope": scope, "bus": bus, "expected_user": expected_user,
            "checks": checks}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--unit", default="bianbu-agent-runtimed.service")
    ap.add_argument("--scope", choices=("system", "user"), default="system")
    ap.add_argument("--bus", choices=("system", "user"), default="system")
    ap.add_argument("--expected-user", default="bianbu-runtime")
    ap.add_argument("--expected-group", default="bianbu-runtime")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    result = probe(unit=args.unit, scope=args.scope, bus=args.bus,
                   expected_user=args.expected_user, expected_group=args.expected_group)
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    elif result["ok"]:
        print("RUNTIME_PRODUCTION_PASS")
    else:
        print("RUNTIME_PRODUCTION_BLOCKED")
        for check in result["checks"]:
            if not check["ok"]:
                print(f"- {check['name']}: {json.dumps(check['details'], ensure_ascii=False)}")
    return 0 if result["ok"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
