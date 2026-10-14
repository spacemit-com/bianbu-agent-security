"""bncli — securityd 命令行工具（CAP-07 / AUD-06）。

子命令：
  capability list <agent_id>          列出已注册能力
  capability revoke <agent_id> <cap>  撤销能力
  audit export --agent <id> [--format json|csv]
  audit verify <export_path>
  install <pkg_path>                  安装 Agent 包（验签+注册）

默认经 SecurityEngine 直调（本地）；--dbus 走 D-Bus。
"""
from __future__ import annotations

import argparse
import importlib
import json
import sys
from pathlib import Path

# 自举：把仓库根（cli/ 的上级）加入 sys.path，使 `python3 cli/bncli.py` 直接可用
# （无需手动 export PYTHONPATH）。
_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))


def _engine():
    from securityd.engine import SecurityEngine
    return SecurityEngine()


def cmd_capability(args) -> int:
    eng = _engine()
    try:
        if args.action == "list":
            perms = eng.get_capabilities(args.agent_id)
            print(json.dumps(perms, ensure_ascii=False, indent=2))
        elif args.action == "revoke":
            ok = eng.revoke_permission(args.agent_id, args.capability)
            print("revoked" if ok else "not found")
            return 0 if ok else 1
    finally:
        eng.close()
    return 0


def cmd_audit(args) -> int:
    eng = _engine()
    try:
        if args.action == "export":
            filt = json.dumps({"agent_id": args.agent} if args.agent else {})
            path = eng.export_audit(filt, args.format)
            print(path)
        elif args.action == "verify":
            ok = eng.verify_audit_chain(args.path)
            print("intact" if ok else "TAMPERED")
            return 0 if ok else 1
    finally:
        eng.close()
    return 0


def cmd_install(args) -> int:
    eng = _engine()
    try:
        ok, reason = eng.install_package(args.pkg_path)
        print("installed" if ok else f"failed: {reason}")
        return 0 if ok else 1
    finally:
        eng.close()


def cmd_doctor(args) -> int:
    from securityd.doctor import run
    result = run(strict=args.strict)
    if args.json_output:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print("DOCTOR_PASS" if result["ok"] else "DOCTOR_FAIL")
        for item in result["checks"]:
            print(f"- {item['name']}: {'PASS' if item['ok'] else 'FAIL'} {item['value']}")
    return 0 if result["ok"] else 1


def cmd_agent(args) -> int:
    """Manage authoritative Agent state through securityd's D-Bus control plane."""
    sc = importlib.import_module("client.bianbu_security_client")
    if args.value == "show":
        result = sc.get_agent_security_mode(args.agent_id)
    else:
        result = sc.set_agent_security_mode(args.agent_id, args.value)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="bncli", description="Bianbu securityd CLI")
    p.add_argument("--json", action="store_true", dest="json_output")
    sub = p.add_subparsers(dest="cmd", required=True)

    cap = sub.add_parser("capability", help="能力管理")
    cap_sub = cap.add_subparsers(dest="action", required=True)
    cl = cap_sub.add_parser("list"); cl.add_argument("agent_id")
    cr = cap_sub.add_parser("revoke"); cr.add_argument("agent_id"); cr.add_argument("capability")
    cap.set_defaults(func=cmd_capability)

    agent = sub.add_parser("agent", help="Agent 安全状态管理")
    agent_sub = agent.add_subparsers(dest="action", required=True)
    mode = agent_sub.add_parser("mode", help="查看或切换 normal/yolo 模式")
    mode.add_argument("agent_id")
    mode.add_argument("value", choices=["show", "normal", "yolo"])
    agent.set_defaults(func=cmd_agent)

    au = sub.add_parser("audit", help="审计日志")
    au_sub = au.add_subparsers(dest="action", required=True)
    ae = au_sub.add_parser("export")
    ae.add_argument("--agent", default=""); ae.add_argument("--format", default="json", choices=["json", "csv"])
    av = au_sub.add_parser("verify"); av.add_argument("path")
    au.set_defaults(func=cmd_audit)

    ins = sub.add_parser("install", help="安装 Agent 包")
    ins.add_argument("pkg_path"); ins.set_defaults(func=cmd_install)
    doc = sub.add_parser("doctor", help="部署环境与安全强制能力自检")
    doc.add_argument("--strict", action="store_true")
    doc.set_defaults(func=cmd_doctor)
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
