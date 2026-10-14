"""Prune stale registrations through securityd, never reset its databases."""
import argparse
import importlib
import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import urllib.request

SERVICE_IDS = {"com.bianbu.runtime", "com.bianbu.runtime.development", "com.bianbu.agent"}


def expert_ids(document):
    rows = document.get("data") if isinstance(document, dict) else None
    if not isinstance(rows, list) or not rows:
        raise ValueError("专家清单为空或格式错误，拒绝清理")
    if any(not isinstance(r, dict) or not isinstance(r.get("id"), str)
           or not r["id"].strip() for r in rows):
        raise ValueError("专家 ID 无效，拒绝清理")
    return {r["id"] for r in rows}


def stale_ids(rows, experts, keep):
    if not isinstance(rows, list) or any(not isinstance(r, dict)
            or not isinstance(r.get("agent_id"), str) or not r["agent_id"].strip() for r in rows):
        raise ValueError("安全注册清单无效")
    ids = {r["agent_id"] for r in rows}
    if experts - ids:
        raise ValueError(f"专家尚未注册到 Security：{sorted(experts - ids)}")
    return sorted(ids - experts - SERVICE_IDS - keep)


def fetch_experts(url):
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs):
            return None
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    with opener.open(url.rstrip("/") + "/api/v1/agents", timeout=10) as response:
        return expert_ids(json.load(response))


def load_client():
    for directory in ("/usr/lib/bianbu-securityd/client", "/usr/lib/bianbu-agent-securityd/client",
                      str(Path(__file__).resolve().parents[1] / "client")):
        if (Path(directory) / "bianbu_security_client.py").is_file():
            sys.path.insert(0, directory)
            return importlib.import_module("bianbu_security_client")
    raise RuntimeError("未找到安全客户端")


def main():
    parser = argparse.ArgumentParser(description="按当前 Runtime 专家清理旧安全注册，不清空数据库")
    parser.add_argument("--yes", action="store_true", help="实际清理，默认只预览")
    parser.add_argument("--dry-run", action="store_true", help="只预览，优先于 --yes")
    parser.add_argument("--runtime-url", default="http://127.0.0.1:9899")
    parser.add_argument("--keep-agent", action="append", default=[], help="额外保护其他应用的 Agent ID")
    parser.add_argument("--database", type=Path, default=Path("/etc/bianbu/capabilities.db"),
                        help="当前 system securityd 数据库，用于备份和一致性检查")
    args = parser.parse_args()
    client = load_client()
    experts = fetch_experts(args.runtime_url)
    rows = client.list_agents()
    candidates = stale_ids(rows, experts, set(args.keep_agent))
    print(f"当前专家 {len(experts)} 个，安全注册 {len(rows)} 个，待清理 {len(candidates)} 个。")
    for aid in candidates:
        print(f"  删除旧注册：{aid}")
    print("保留当前专家、Runtime 服务身份、Token/DLP 数据、历史审计及用户会话。")
    if not args.yes or args.dry_run or not candidates:
        return 0
    if os.geteuid() != 0:
        print("使用 sudo 重新校验并执行。", flush=True)
        os.execvp("sudo", ["sudo", sys.executable, str(Path(__file__).resolve()), *sys.argv[1:]])
    if fetch_experts(args.runtime_url) != experts:
        raise RuntimeError("专家清单已变化，未执行删除")
    db = args.database.expanduser().resolve()
    with sqlite3.connect(db.as_uri() + "?mode=ro", uri=True) as source:
        stored = {r[0] for r in source.execute("SELECT agent_id FROM agent_manifest")}
        if stored != {r["agent_id"] for r in rows}:
            raise RuntimeError("备份数据库与 D-Bus 清单不一致，拒绝清理")
        backup = Path(tempfile.mkdtemp(prefix="security-agent-prune-", dir=db.parent))
        with sqlite3.connect(backup / "capabilities.db") as destination:
            source.backup(destination)
    os.chmod(backup / "capabilities.db", 0o600)
    (backup / "plan.json").write_text(json.dumps({"agents_before": rows, "remove": candidates},
                                               ensure_ascii=False, indent=2))
    os.chmod(backup / "plan.json", 0o600)
    print(f"备份已保存：{backup}", flush=True)
    for aid in candidates:
        if fetch_experts(args.runtime_url) != experts:
            raise RuntimeError("专家清单已变化，已停止后续清理；详见备份计划")
        if not client.unregister_agent(aid):
            raise RuntimeError(f"注销未成功：{aid}；已停止后续清理")
    if stale_ids(client.list_agents(), fetch_experts(args.runtime_url), set(args.keep_agent)):
        raise RuntimeError("仍有旧注册，请再次预览")
    print(f"已清理 {len(candidates)} 个旧 Agent 注册；无需重启，刷新页面即可。")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"清理失败：{exc}", file=sys.stderr)
        raise SystemExit(1)
