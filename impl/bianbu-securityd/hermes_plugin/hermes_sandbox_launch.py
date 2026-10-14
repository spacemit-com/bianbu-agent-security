"""hermes-sandbox-launch —— 在 securityd 构建的 bwrap 沙箱内启动整个 hermes 进程。

这是 bwrap "集成到 hermes" 的进程级方案（对齐设计 §3.7：agent-runtimed 把整个
Agent 进程放进沙箱，而非逐工具改造）：
  1. 经 securityd.BuildSandboxPolicy 取该 Agent 的 seccomp BPF + netfilter 规则；
  2. 用 securityd.sandbox 的 bwrap 参数构造器包裹 hermes 启动命令；
  3. seccomp/cap-drop/文件视图随 fork-exec 被 hermes 及其 spawn 的每个工具进程继承。

零 hermes 改动、不复用 hermes 代码（AGENTS.md 合规）。与插件（pre/post_tool_call
判权审计）构成纵深防御：进程沙箱兜底危险 syscall，插件做细粒度授权。

用法：
  python hermes_sandbox_launch.py --agent com.hermes.agent -- python run_agent.py [hermes args...]
  # 沙箱内以 hermes 身份运行；其 terminal/code_execution 工具 spawn 的子进程一律受 seccomp 限制
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

# 自举 sys.path：BIANBU_SECURITYD_HOME 优先，否则用本文件上级（仓库根 impl/bianbu-securityd），
# 使 `python3 hermes_plugin/hermes_sandbox_launch.py` 直接可用，无需手设 PYTHONPATH。
_HOME = os.environ.get("BIANBU_SECURITYD_HOME") or str(Path(__file__).resolve().parent.parent)
for _p in (_HOME, str(Path(_HOME) / "client")):
    if _p not in sys.path:
        sys.path.insert(0, _p)


def _print_launch_detail(args, spec, seccomp_path, approval_mode, cmd) -> None:
    """进入 hermes CLI 之前打印详细启动日志，含最终执行的完整 bwrap 命令。"""
    import shlex
    from securityd.sandbox import build_bwrap_argv

    P = "[hermes-sandbox]"
    print(f"{P} ┌── 沙箱启动配置 ─────────────────────────────────────────", flush=True)
    print(f"{P} │ Agent ID      : {spec.agent_id}", flush=True)
    print(f"{P} │ 审批仲裁      : {approval_mode}"
          f"{'（已关 hermes approval：HERMES_YOLO_MODE=1）' if approval_mode == 'securityd' else ''}",
          flush=True)
    print(f"{P} │ 网络          : {'on（共享宿主网络+DNS+CA）' if args.net else 'off（--unshare-net 隔离）'}",
          flush=True)
    print(f"{P} │ 交互模式      : {'是（继承 tty，供 TUI）' if not args.batch else '否（批处理，捕获输出）'}",
          flush=True)
    print(f"{P} │ seccomp BPF   : {seccomp_path}", flush=True)
    print(f"{P} │ 沙箱 HOME     : {spec.home_dir}", flush=True)
    print(f"{P} │ 私有可写目录  : {spec.rw_dir} → /home/agent", flush=True)
    for src, dst in spec.rw_binds:
        print(f"{P} │ 可写绑定      : {src} → {dst}", flush=True)
    for b in spec.ro_binds:
        print(f"{P} │ 只读绑定      : {b}", flush=True)
    for src, dst in spec.ro_binds_map:
        print(f"{P} │ 只读映射      : {src} → {dst}", flush=True)
    print(f"{P} │ cgroup 限额   : mem={spec.memory_max} cpu={spec.cpu_quota}", flush=True)
    print(f"{P} │ hermes 命令   : {' '.join(cmd)}", flush=True)
    print(f"{P} ├── 最终执行的完整 bwrap 命令 ───────────────────────────", flush=True)
    # seccomp 经 fd 传入；此处用占位 fd 展示 --seccomp <fd> 的位置
    argv = build_bwrap_argv(spec, seccomp_fd=("<seccomp_fd>" if seccomp_path else None),
                            interactive=not args.batch)
    rendered = " \\\n    ".join(shlex.quote(str(a)) if a != "<seccomp_fd>" else a for a in argv)
    print(f"{P} │ {rendered}", flush=True)
    print(f"{P} └────────────────────────────────────────────────────────", flush=True)
    print(f"{P} 正在进入 hermes CLI ……", flush=True)


def main(argv=None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    p = argparse.ArgumentParser(prog="hermes-sandbox-launch", add_help=True)
    p.add_argument("--agent", default=os.environ.get("BIANBU_HERMES_AGENT_ID", "com.hermes.agent"))
    p.add_argument("--rw-dir", default="", help="Agent 私有可写目录（默认 AGENTS_HOME/<id>/rw）")
    p.add_argument("--net", dest="net", action="store_true", default=True,
                   help="沙箱共享宿主网络栈并绑定 DNS 解析文件（默认开，hermes 需联网）")
    p.add_argument("--no-net", dest="net", action="store_false",
                   help="沙箱禁网（--unshare-net，空网络命名空间，最强隔离）")
    p.add_argument("--hermes-config", default=str(Path.home() / ".hermes"),
                   help="hermes 配置/会话目录，可写绑定进沙箱（默认 ~/.hermes；空串则不绑）")
    p.add_argument("--batch", action="store_true",
                   help="批处理模式：捕获输出、带超时（默认交互模式，继承 tty 供 TUI）")
    p.add_argument("--quiet", action="store_true",
                   help="抑制启动详情/bwrap 命令打印（供 WebUI 演示等纯净捕获场景）")
    p.add_argument("cmd", nargs=argparse.REMAINDER, help="-- 之后为 hermes 启动命令")
    args = p.parse_args(argv)

    cmd = args.cmd[1:] if args.cmd and args.cmd[0] == "--" else args.cmd
    if not cmd:
        print("用法：hermes_sandbox_launch.py --agent <id> -- <hermes 启动命令>", file=sys.stderr)
        return 2

    from securityd import config, seccomp_builder
    from securityd.sandbox import SandboxSpec, launch

    # 1) 生成 seccomp 策略（本 arch）
    seccomp_path = seccomp_builder.build_policy_file(args.agent)

    # 2) 私有可写目录
    rw = Path(args.rw_dir) if args.rw_dir else (config.AGENTS_HOME / args.agent / "rw")
    rw.mkdir(parents=True, exist_ok=True)

    # 3) 构造沙箱规格并启动 hermes
    ro_binds = []
    hermes_home = os.environ.get("HERMES_HOME")
    if hermes_home and Path(hermes_home).exists():
        ro_binds.append(hermes_home)

    # 合成最小 /etc/passwd + /etc/group：userns 里当前 uid 无名字条目，
    # 否则 `id`/git 等工具报 "cannot find name for user ID"。ro-bind 覆盖进沙箱。
    uid = os.getuid() if hasattr(os, "getuid") else 1000
    gid = os.getgid() if hasattr(os, "getgid") else 1000
    passwd_f = rw / ".sandbox_passwd"
    group_f = rw / ".sandbox_group"
    passwd_f.write_text(
        f"agent:x:{uid}:{gid}:Bianbu Agent:/home/agent:/bin/sh\n"
        "root:x:0:0:root:/root:/bin/sh\n")
    # 65534=nobody/nogroup：userns 未映射的补充组会落到它，补上避免 id 噪声
    group_f.write_text(f"agent:x:{gid}:\nroot:x:0:\nnogroup:x:65534:\n")

    ro_binds_map = [(str(passwd_f), "/etc/passwd"), (str(group_f), "/etc/group")]

    # 联网模式：绑定 DNS 解析所需文件（沙箱只 bind /usr，缺这些则连域名都解析不了）。
    # resolv.conf 若是符号链接（systemd stub），绑其真实目标到 /etc/resolv.conf。
    if args.net:
        for host_f, sbx_f in (("/etc/resolv.conf", "/etc/resolv.conf"),
                              ("/etc/hosts", "/etc/hosts"),
                              ("/etc/nsswitch.conf", "/etc/nsswitch.conf"),
                              ("/etc/gai.conf", "/etc/gai.conf")):
            real = Path(host_f)
            if real.exists():
                ro_binds_map.append((str(real.resolve()), sbx_f))
        # TLS CA 证书（HTTPS 验证必需；沙箱只 bind /usr，/etc/ssl 需单独绑）。
        # 目录整体只读绑定，覆盖 ca-certificates.crt 及符号链接指向的 /usr/share/ca-certificates。
        for ca_dir in ("/etc/ssl", "/etc/pki", "/etc/ca-certificates"):
            if Path(ca_dir).is_dir():
                ro_binds.append(ca_dir)  # 原路径只读绑定

    # hermes 配置/凭据/会话在 ~/.hermes：可写绑定进沙箱原路径，并把 HOME 指向其父目录，
    # 否则沙箱内 hermes 读不到 auth.json/SOUL.md、也无法持久化 session/log。
    rw_binds: list[tuple[str, str]] = []
    sandbox_home = "/home/agent"
    cfg = args.hermes_config.strip()
    if cfg and Path(cfg).exists():
        cfg_path = str(Path(cfg).resolve())
        rw_binds.append((cfg_path, cfg_path))
        sandbox_home = str(Path(cfg_path).parent)  # HOME 使 hermes 找到 <HOME>/.hermes

    # 审批仲裁：mode=securityd（默认）时，进程级关闭 hermes 自带 approval
    # （HERMES_YOLO_MODE 在 hermes 导入时冻结，故必须在启动前设，最可靠）。
    approval_mode = os.environ.get("BIANBU_SEC_APPROVAL_MODE", "securityd").strip().lower()
    if approval_mode == "securityd":
        os.environ["HERMES_YOLO_MODE"] = "1"
        if not args.quiet:
            print("[hermes-sandbox] securityd 门禁为准，已进程级关闭 hermes approval"
                  "（HERMES_YOLO_MODE=1）", flush=True)

    spec = SandboxSpec(
        agent_id=args.agent,
        agent_binary=cmd,
        rw_dir=rw,
        seccomp_path=seccomp_path,
        ro_binds=ro_binds,
        ro_binds_map=ro_binds_map,
        rw_binds=rw_binds,
        home_dir=sandbox_home,
        unshare_net=not args.net,
    )
    if not args.quiet:
        _print_launch_detail(args, spec, seccomp_path, approval_mode, cmd)
    if args.batch:
        res = launch(spec, wait=True,
                     timeout=int(os.environ.get("HERMES_SANDBOX_TIMEOUT", "3600")))
        if not res.ok and res.returncode is None:
            print(f"[hermes-sandbox] 启动失败（Fail-Closed）：{res.reason}", file=sys.stderr)
            return 1
        if res.output:
            print(res.output, end="")
        return res.returncode or 0
    # 交互模式（默认）：继承 tty，供 hermes chat 等 TUI；阻塞到用户退出
    res = launch(spec, wait=True, interactive=True)
    if not res.ok and res.returncode is None:
        print(f"[hermes-sandbox] 启动失败（Fail-Closed）：{res.reason}", file=sys.stderr)
        return 1
    return res.returncode or 0


if __name__ == "__main__":
    sys.exit(main())
