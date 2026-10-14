"""Network Policy Manager（FR-SEC-07 / SBX-03 / NET-01~05）。

将声明域名编译为 netfilter/iptables 白名单规则（默认 DROP）。
worker K3 无 iptables/nft → 生成规则产物 + 记录，运行时隔离由 bwrap --unshare-net 兜底。
对齐设计 §3.5 / §6.7。
"""
from __future__ import annotations

import shutil
import socket
import subprocess
import os
import hashlib
import ipaddress
import json
import time
from pathlib import Path

from . import config

VALID_MODES = frozenset({"whitelist", "deny_all", "allow_all", "learning"})


def _normalise_domains(domains: list[str]) -> list[str]:
    out = []
    for value in domains:
        domain = str(value).strip().lower().rstrip(".")
        if domain and domain not in out:
            out.append(domain)
    return out


def _resolve(domains: list[str]) -> dict[str, list[str]]:
    """DNS 解析域名 → IP 集合。解析失败的域名记为空列表。"""
    out: dict[str, list[str]] = {}
    for d in domains:
        ips: list[str] = []
        try:
            for info in socket.getaddrinfo(d, None):
                ip = info[4][0]
                if ip not in ips:
                    ips.append(ip)
        except (socket.gaierror, OSError):
            pass
        out[d] = ips
    return out


def build_rules(agent_id: str, domains: list[str], mode: str = "whitelist") -> str:
    """生成 iptables 规则文本并写入 /run/bianbu/sandbox/<id>/netfilter.rules，返回路径。

    规则语义（每 Agent 一个 cgroup/uid 标记，示意用 comment 标注 agent）：
      -I OUTPUT -d <ip> -j ACCEPT   # 每个白名单 IP
      -A OUTPUT -j DROP             # 默认拒绝（whitelist 模式）
    learning 模式：仅 LOG 不 DROP。
    """
    out_dir = config.SANDBOX_RUN_DIR / agent_id
    out_dir.mkdir(parents=True, exist_ok=True)
    if mode not in VALID_MODES:
        raise ValueError(f"unsupported network policy mode: {mode}")
    domains = _normalise_domains(domains) if mode == "whitelist" else []
    resolved = _resolve(domains)

    lines = [f"# netfilter rules for agent {agent_id} (mode={mode})"]
    lines.append("# chain: BIANBU_<agent> (由 runtimed 关联到 Agent 出站流量)")
    for d, ips in resolved.items():
        if not ips:
            lines.append(f"# WARN: 域名 {d} 未解析到 IP")
        for ip in ips:
            lines.append(f"-A OUTPUT -d {ip} -j ACCEPT   # allow {d}")
    if mode in {"whitelist", "learning"}:
        lines.append("-A OUTPUT -p udp --dport 53 -j ACCEPT   # DNS")
    if mode == "learning":
        lines.append('-A OUTPUT -j LOG --log-prefix "BIANBU_LEARN "   # 学习模式仅记录')
    elif mode in {"whitelist", "deny_all"}:
        lines.append('-A OUTPUT -j LOG --log-prefix "BIANBU_DROP "')
        lines.append("-A OUTPUT -j DROP   # 默认拒绝未声明流量")

    path = out_dir / "netfilter.rules"
    path.write_text("\n".join(lines) + "\n")
    return str(path)


def apply_rules(rules_path: str, agent_id: str) -> bool:
    """尝试实际下发 iptables 规则（若可用且有权限）。worker 无 iptables 时返回 False（降级）。

    实际生产由 agent-runtimed 在 host-ns 以特权下发；此处提供可选直发能力。
    """
    # 规则下发必须由有 CAP_NET_ADMIN 的 runtimed/privileged helper 显式开启。
    # 仅安装 nft/iptables 二进制，或仅生成 rules 文件，都不代表已强制。
    if os.environ.get("BIANBU_SECURITY_NET_APPLY") != "1":
        return False
    if shutil.which("nft"):
        try:
            ips = []
            for line in Path(rules_path).read_text().splitlines():
                if " -d " in line and "-A OUTPUT" in line:
                    ip = line.split(" -d ", 1)[1].split()[0]
                    if ip not in ips:
                        ips.append(ip)
            suffix = hashlib.sha256(agent_id.encode()).hexdigest()[:12]
            chain = f"agent_{suffix}"
            v4 = [ip for ip in ips if ":" not in ip]
            v6 = [ip for ip in ips if ":" in ip]
            lines = ["table inet bianbu_security {", f" chain {chain} {{",
                     "  type filter hook output priority 0; policy drop;",
                     "  udp dport 53 accept;"]
            if v4:
                lines.append("  ip daddr { " + ", ".join(v4) + " } accept;")
            if v6:
                lines.append("  ip6 daddr { " + ", ".join(v6) + " } accept;")
            lines += [" }", "}"]
            subprocess.run(["nft", "-f", "-"], input="\n".join(lines), text=True,
                           check=True, capture_output=True, timeout=5)
            _mark_applied(agent_id, rules_path, "nft", chain)
            return True
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired,
                PermissionError, OSError, ValueError):
            return False
    if not shutil.which("iptables"):
        return False
    try:
        # 仅在具备能力时执行；无权限静默降级
        for line in Path(rules_path).read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            subprocess.run(["iptables", *line.split()], check=True,
                           capture_output=True, timeout=5)
        _mark_applied(agent_id, rules_path, "iptables", "")
        return True
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, PermissionError, OSError):
        return False


def apply_and_verify(rules_path: str, agent_id: str, *, probe=None) -> dict:
    """由 privileged helper 调用：下发后必须提供真实 probe 证明非白名单阻断。

    `probe` 接收 agent_id 并返回 `{allow_ok: bool, deny_ok: bool}`；没有 probe
    时只报告 applied=False，避免把成功执行 nft 命令误当成端到端流量验收。
    """
    applied = apply_rules(rules_path, agent_id)
    result = {"agent_id": agent_id, "applied": applied, "verified": False,
              "allow_ok": False, "deny_ok": False}
    if applied and probe is not None:
        try:
            verdict = dict(probe(agent_id))
            result.update({"allow_ok": bool(verdict.get("allow_ok")),
                           "deny_ok": bool(verdict.get("deny_ok"))})
            result["verified"] = result["allow_ok"] and result["deny_ok"]
        except Exception as exc:  # noqa: BLE001
            result["error"] = str(exc)
    return result


def enforcement_status(agent_id: str = "") -> dict:
    """返回真实网络强制能力，不把规则文件存在误报为已强制。"""
    backends = []
    for name, command in (("nft", "nft"), ("iptables", "iptables"),
                          ("ebpf", "bpftool")):
        if shutil.which(command):
            backends.append(name)
    applied = _read_applied(agent_id) if agent_id else None
    isolated = os.environ.get("BIANBU_SECURITY_NETNS", "") == "1" and \
        os.environ.get("BIANBU_SECURITY_NETNS_READY") == "1"
    if applied and applied.get("backend") in backends:
        mode, enforced = "kernel", True
    elif applied and applied.get("backend") == "systemd-ipfilter" and applied.get("verified") is True:
        mode, enforced = "systemd", True
    elif isolated:
        mode, enforced = "namespace", True
    else:
        mode, enforced = "artifact_only", False
    return {"agent_id": agent_id, "mode": mode, "enforced": enforced,
            "backends": backends, "reason": "" if enforced else
            "规则尚未由 privileged runtimed/helper 下发，当前仅生成规则产物"}


def _state_path(agent_id: str) -> Path:
    return config.SANDBOX_RUN_DIR / agent_id / "enforcement.json"


def _mark_applied(agent_id: str, rules_path: str, backend: str, chain: str) -> None:
    p = _state_path(agent_id)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps({"agent_id": agent_id, "rules_path": rules_path,
                             "backend": backend, "chain": chain}, ensure_ascii=False))


def systemd_ip_filter_properties(domains: list[str], *, mode: str = "whitelist",
                                 dns_servers: list[str] | None = None) -> list[str]:
    """把域名白名单编译成 systemd IPAddressAllow/Deny 属性。

    Runtime 用这些属性创建 transient unit，即可按 unit/cgroup 隔离 Agent，
    避免修改宿主全局 OUTPUT 链。DNS resolver 需显式加入白名单。
    """
    if mode not in VALID_MODES:
        raise ValueError(f"unsupported network policy mode: {mode}")
    if mode in {"allow_all", "learning"}:
        return []
    if mode == "deny_all":
        return ["IPAddressDeny=any"]
    ips = []
    for values in _resolve(domains).values():
        for ip in values:
            if ip not in ips:
                ips.append(ip)
    for ip in dns_servers or []:
        if ip and ip not in ips:
            ips.append(ip)
    return ["IPAddressDeny=any", *[f"IPAddressAllow={ip}" for ip in ips]]


def verify_systemd_unit(unit: str, properties: list[str], *, scope: str = "system") -> bool:
    """读取 systemd unit 实际属性，确认默认拒绝和白名单均已生效。"""
    if not unit:
        return False
    cmd = ["systemctl"]
    if scope == "user":
        cmd.append("--user")
    cmd += ["show", unit, "--property=IPAddressDeny,IPAddressAllow"]
    try:
        out = subprocess.run(cmd, check=True, capture_output=True, text=True,
                             timeout=5).stdout
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return False
    fields = dict(line.split("=", 1) for line in out.splitlines() if "=" in line)
    if not {"IPAddressDeny", "IPAddressAllow"} <= fields.keys():
        return False
    if not properties:
        return not fields["IPAddressDeny"].strip() and not fields["IPAddressAllow"].strip()
    if "IPAddressDeny=any" not in properties:
        return False
    try:
        denied = {ipaddress.ip_network(value, strict=False)
                  for value in fields["IPAddressDeny"].split()}
        allowed = {ipaddress.ip_network(value, strict=False)
                   for value in fields["IPAddressAllow"].split()}
        expected = {ipaddress.ip_network(value, strict=False)
                    for prop in properties if prop.startswith("IPAddressAllow=")
                    for value in prop.split("=", 1)[1].split()}
    except ValueError:
        return False
    return denied == {ipaddress.ip_network("0.0.0.0/0"), ipaddress.ip_network("::/0")} and allowed == expected


def mark_systemd_unit_applied(agent_id: str, unit: str, properties: list[str], *,
                              scope: str = "system", verified: bool = False) -> bool:
    """Runtime 创建并复核 unit 后登记状态；未复核不得计为强制。"""
    if not unit or "IPAddressDeny=any" not in properties:
        return False
    p = _state_path(agent_id)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps({"agent_id": agent_id, "backend": "systemd-ipfilter",
                             "unit": unit, "scope": scope, "verified": bool(verified),
                             "verified_at": time.time(), "properties": properties}, ensure_ascii=False))
    return True


def _read_applied(agent_id: str) -> dict | None:
    p = _state_path(agent_id)
    try:
        return json.loads(p.read_text()) if p.exists() else None
    except (OSError, ValueError):
        return None


def clear_rules(agent_id: str) -> None:
    """Agent 停止时清理规则产物（NET-05）。"""
    p = config.SANDBOX_RUN_DIR / agent_id / "netfilter.rules"
    if p.exists():
        p.unlink()
    state = _state_path(agent_id)
    if state.exists():
        state.unlink()


def read_rules(agent_id: str) -> dict:
    """只读查询当前网络策略（供 WebUI 展示）：从已生成的 netfilter.rules 解析白名单域名。

    返回 {agent_id, mode, domains, rules_path, exists}。规则文件用注释 `# allow <域名>`
    标注每条放行，从中反解出域名列表；文件不存在则 domains 为空。
    """
    p = config.SANDBOX_RUN_DIR / agent_id / "netfilter.rules"
    if not p.exists():
        return {"agent_id": agent_id, "mode": "none", "domains": [],
                "rules_path": str(p), "exists": False}
    text = p.read_text()
    domains: list[str] = []
    mode = "whitelist"
    for line in text.splitlines():
        if "# allow " in line:
            d = line.split("# allow ", 1)[1].strip()
            if d and d not in domains:
                domains.append(d)
        if "mode=learning" in line:
            mode = "learning"
    return {"agent_id": agent_id, "mode": mode, "domains": domains,
            "rules_path": str(p), "exists": True}
