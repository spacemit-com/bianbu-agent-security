"""bianbu-securityd 部署自检。"""
from __future__ import annotations

import os
import grp
import pwd
import shutil
import stat
import subprocess
import sys
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from . import config, network_policy
from .code_signing import codesign_policy, trusted_keys_dir, enforce_ready


@dataclass(frozen=True)
class Check:
    name: str
    ok: bool
    value: str
    detail: str = ""
    severity: str = "error"


def _tool(name: str) -> Check:
    found = shutil.which(name)
    return Check(name, bool(found), found or "missing", "可执行文件已发现" if found else "未发现")


def _read_env_file(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return values
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        if not key or not key.replace("_", "").isalnum():
            continue
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]
        values[key] = value
    return values


def _placeholder(value: str) -> bool:
    lowered = str(value or "").strip().lower()
    return not lowered or any(x in lowered for x in (
        "replace_with", "change_me", "changeme", "example", "placeholder"))


def _webui_checks(*, strict: bool) -> list[Check]:
    env_path = Path(os.environ.get(
        "BIANBU_SECURITY_WEBUI_ENV_FILE", "/etc/bianbu/webui.env"))
    values = _read_env_file(env_path)

    def setting(name: str, default: str = "") -> str:
        return os.environ.get(name, values.get(name, default)).strip()

    severity = "error" if strict else "warning"
    auth = setting("BIANBU_WEBUI_AUTH", "1")
    token = setting("BIANBU_WEBUI_TOKEN")
    viewer = setting("BIANBU_WEBUI_VIEWER_TOKEN")
    secret = setting("BIANBU_WEBUI_SECRET")
    token_ok = (auth != "0" and len(token.encode("utf-8")) >= 32
                and not _placeholder(token)
                and (not viewer or (viewer != token
                                    and len(viewer.encode("utf-8")) >= 32
                                    and not _placeholder(viewer))))
    token_detail = "认证启用，管理员 token 合规"
    if auth == "0":
        token_detail = "生产配置禁止 BIANBU_WEBUI_AUTH=0"
    elif len(token.encode("utf-8")) < 32 or _placeholder(token):
        token_detail = "管理员 token 必须是至少 32 字节的非占位随机值"
    elif viewer and viewer == token:
        token_detail = "viewer token 不得与管理员 token 相同"
    elif viewer and (len(viewer.encode("utf-8")) < 32 or _placeholder(viewer)):
        token_detail = "viewer token 必须是至少 32 字节的非占位随机值"

    secret_ok = (len(secret.encode("utf-8")) >= 32
                 and not _placeholder(secret) and secret != token)
    host = setting("BIANBU_WEBUI_HOST", "127.0.0.1")
    loopback = host in {"127.0.0.1", "::1", "localhost"}
    cert = setting("BIANBU_WEBUI_TLS_CERT")
    key = setting("BIANBU_WEBUI_TLS_KEY")
    trust_proxy = setting("BIANBU_WEBUI_TRUST_PROXY", "0") == "1"
    insecure = setting("BIANBU_WEBUI_ALLOW_INSECURE_REMOTE", "0") == "1"
    shell_enabled = setting("BIANBU_WEBUI_ENABLE_SHELL", "0") == "1"
    pair_consistent = bool(cert) == bool(key)
    pair = bool(cert) and bool(key)
    tls_files = pair and Path(cert).is_file() and Path(key).is_file()
    transport_ok = (not insecure and pair_consistent
                    and not (trust_proxy and not loopback)
                    and (loopback or tls_files))
    if bool(cert) != bool(key):
        transport_detail = "TLS 证书与私钥必须同时配置"
    elif insecure:
        transport_detail = "生产配置禁止明文远程监听"
    elif trust_proxy and not loopback:
        transport_detail = "受信反向代理模式要求 WebUI 自身只监听回环地址"
    elif not loopback and not tls_files:
        transport_detail = "非回环监听必须配置存在的 TLS 证书和私钥"
    else:
        transport_detail = "回环监听或 TLS 传输配置合规"

    env_ok = env_path.is_file()
    env_detail = "环境文件存在"
    if env_ok:
        try:
            st = env_path.stat()
            expected_uid = int(os.environ.get(
                "BIANBU_SECURITY_WEBUI_ENV_OWNER_UID", "0"))
            mode = stat.S_IMODE(st.st_mode)
            env_ok = (st.st_uid == expected_uid and mode & 0o027 == 0)
            env_detail = f"uid={st.st_uid} mode={mode:04o} expected_uid={expected_uid}"
        except (OSError, ValueError) as exc:
            env_ok = False
            env_detail = str(exc)
    else:
        env_detail = f"缺少 {env_path}"

    return [
        Check("webui_auth", token_ok, "configured" if token_ok else "invalid",
              token_detail, severity),
        Check("webui_session_secret", secret_ok,
              "configured" if secret_ok else "invalid",
              "持久会话 secret 合规" if secret_ok else
              "BIANBU_WEBUI_SECRET 必须是至少 32 字节、非占位且不同于 token",
              severity),
        Check("webui_transport", transport_ok, host, transport_detail, severity),
        Check("webui_shell_disabled", not shell_enabled,
              "disabled" if not shell_enabled else "enabled",
              "生产配置必须关闭普通 shell", severity),
        Check("webui_env_permissions", env_ok, str(env_path), env_detail, severity),
    ]


def _service_check(name: str, unit: str, expected_user: str,
                   *, strict: bool) -> Check:
    cmd = ["systemctl", "show", unit,
           "--property=User,Group,ActiveState,MainPID,ControlGroup"]
    try:
        cp = subprocess.run(cmd, check=False, capture_output=True, text=True, timeout=5)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return Check(name, False, unit, f"systemd unit 无法复核: {exc}",
                     "error" if strict else "warning")
    values: dict[str, str] = {}
    for line in cp.stdout.splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            values[key] = value.strip()
    ok = (cp.returncode == 0 and values.get("ActiveState") == "active"
          and values.get("MainPID", "0") not in {"", "0"}
          and values.get("User") == expected_user
          and bool(values.get("ControlGroup")))
    detail = (f"user={values.get('User','')} group={values.get('Group','')} "
              f"state={values.get('ActiveState','')} pid={values.get('MainPID','')} "
              f"cgroup={values.get('ControlGroup','')} rc={cp.returncode}")
    return Check(name, ok, unit, detail, "error" if strict else "warning")


def _polkit_policy_check(*, strict: bool) -> Check:
    path = Path(os.environ.get(
        "BIANBU_SECURITY_POLKIT_POLICY",
        "/usr/share/polkit-1/actions/io.bianbu.security.policy"))
    expected = {
        "io.bianbu.security.manage": ("no", "no", "auth_admin_keep"),
        "io.bianbu.security.confirm": ("no", "no", "auth_self_keep"),
    }
    try:
        root = ET.parse(path).getroot()
        actions = {}
        for action in root.findall("action"):
            defaults = action.find("defaults")
            if defaults is None:
                continue
            actions[action.get("id", "")] = tuple(
                (defaults.findtext(tag) or "").strip()
                for tag in ("allow_any", "allow_inactive", "allow_active"))
        bad = {name: actions.get(name) for name, value in expected.items()
               if actions.get(name) != value}
        ok = not bad
        detail = "manage/confirm action 与默认授权策略一致" if ok else f"不匹配: {bad}"
    except (OSError, ET.ParseError) as exc:
        ok = False
        detail = str(exc)
    return Check("polkit_policy", ok, str(path), detail,
                 "error" if strict else "warning")


def _uds_dataplane_check(*, strict: bool) -> Check:
    default_path = "/run/bianbu/securityd.sock" if strict else str(config.UDS_SOCKET_PATH)
    path = Path(os.environ.get("BIANBU_SECURITY_UDS_SOCKET", default_path))
    severity = "error" if strict else "warning"
    try:
        st = path.stat()
        mode = stat.S_IMODE(st.st_mode)
        expected_gid_env = os.environ.get("BIANBU_SECURITY_UDS_GID")
        if expected_gid_env is not None:
            expected_gid = int(expected_gid_env)
        else:
            expected_gid = grp.getgrnam("bianbu-security").gr_gid
        ok = (stat.S_ISSOCK(st.st_mode) and mode == 0o660
              and st.st_gid == expected_gid)
        detail = (f"socket={stat.S_ISSOCK(st.st_mode)} mode={mode:04o} "
                  f"gid={st.st_gid} expected_gid={expected_gid}")
    except (OSError, KeyError, ValueError) as exc:
        ok = False
        detail = str(exc)
    return Check("uds_dataplane", ok, str(path), detail, severity)


def _runtime_identity_check() -> Check:
    """读取真实 systemd unit，防止仅设置环境变量伪造生产身份矩阵。"""
    unit = os.environ.get("BIANBU_SECURITY_RUNTIME_UNIT", "")
    expected_uid = os.environ.get("BIANBU_SECURITY_RUNTIME_UID", "")
    expected_cgroup = os.environ.get("BIANBU_SECURITY_RUNTIME_CGROUP", "")
    scope = os.environ.get("BIANBU_SECURITY_RUNTIME_SCOPE", "system")
    if not (unit and expected_uid.isdigit() and expected_cgroup):
        return Check("runtime_identity_matrix", False, unit or "missing",
                     "需要 unit/UID/cgroup 配置", "error")
    cmd = ["systemctl"] + (["--user"] if scope == "user" else []) + [
        "show", unit, "--property=User,ControlGroup,ActiveState,MainPID"]
    try:
        out = subprocess.run(cmd, check=True, capture_output=True, text=True,
                             timeout=5).stdout
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        return Check("runtime_identity_matrix", False, unit,
                     f"systemd unit 无法复核: {exc}", "error")
    values = {}
    for line in out.splitlines():
        if "=" in line:
            k, v = line.split("=", 1); values[k] = v.strip()
    actual_user = values.get("User", "")
    try:
        # systemd 对以 root 运行且未显式写 User= 的 unit 返回空字符串。
        actual_uid = 0 if not actual_user else (
            int(actual_user) if actual_user.isdigit() else pwd.getpwnam(actual_user).pw_uid)
    except (KeyError, ValueError):
        actual_uid = -1
    uid_ok = actual_uid == int(expected_uid)
    cg_ok = values.get("ControlGroup", "") == expected_cgroup
    active_ok = values.get("ActiveState") == "active" and values.get("MainPID", "0") not in {"", "0"}
    ok = uid_ok and cg_ok and active_ok
    detail = f"uid={values.get('User','')} cgroup={values.get('ControlGroup','')} " \
             f"state={values.get('ActiveState','')} pid={values.get('MainPID','')}"
    return Check("runtime_identity_matrix", ok, unit, detail, "error")


def run(*, strict: bool = False) -> dict[str, Any]:
    checks: list[Check] = [_tool("bwrap"), _tool("dbus-daemon"), _tool("pkcheck")]
    if not strict and not checks[-1].ok:
        checks[-1] = Check(checks[-1].name, False, checks[-1].value,
                           checks[-1].detail, "warning")
    # 没有指定 Agent 时不能把宿主工具存在误认为网络已强制；生产 doctor
    # 应在 Runtime unit 创建后带上 agent_id 复核实际 unit 状态。
    doctor_agent = os.environ.get("BIANBU_SECURITY_DOCTOR_AGENT_ID", "")
    net = network_policy.enforcement_status(doctor_agent)
    checks.append(Check("network_enforcement", bool(net["enforced"]), net["mode"],
                         net.get("reason", "") or ",".join(net.get("backends", [])),
                         "error" if strict else "warning"))
    # 生产身份矩阵：严格模式必须显式声明 runtimed 的 unit/UID/cgroup 期望，
    # 避免仅凭“存在某个 systemd unit”误判调用者绑定已闭合。
    identity = _runtime_identity_check()
    if not strict and not identity.ok:
        identity = Check(identity.name, False, identity.value, identity.detail, "warning")
    checks.append(identity)
    cg = Path("/sys/fs/cgroup")
    try:
        controllers = (cg / "cgroup.controllers").read_text().strip()
    except OSError:
        controllers = ""
    missing = sorted({"cpu", "memory", "pids", "io"} - set(controllers.split()))
    checks.append(Check("cgroup_v2", not missing, controllers or "missing",
                         "" if not missing else f"缺少控制器: {','.join(missing)}",
                         "error" if strict else "warning"))
    keys = trusted_keys_dir()
    count = len(list(keys.glob("*.pub"))) if keys.is_dir() else 0
    codesign_ok, codesign_detail = enforce_ready()
    policy = codesign_policy()
    if strict and policy != "enforce":
        codesign_ok = False
        codesign_detail = f"strict 要求 BIANBU_SECURITY_CODESIGN=enforce，当前={policy}"
    checks.append(Check("codesign_trust_root", codesign_ok, str(keys),
                         codesign_detail if not codesign_ok else f"{count} 个公钥",
                         "error" if strict or policy == "enforce" else "warning"))
    checks.extend(_webui_checks(strict=strict))
    checks.append(_service_check(
        "securityd_service", os.environ.get(
            "BIANBU_SECURITY_SERVICE_UNIT", "bianbu-securityd.service"),
        os.environ.get("BIANBU_SECURITY_SERVICE_USER", "bianbu-security"),
        strict=strict))
    checks.append(_service_check(
        "webui_service", os.environ.get(
            "BIANBU_SECURITY_WEBUI_UNIT", "bianbu-security-webui.service"),
        os.environ.get("BIANBU_SECURITY_WEBUI_USER", "bianbu-security"),
        strict=strict))
    checks.append(_polkit_policy_check(strict=strict))
    checks.append(_uds_dataplane_check(strict=strict))
    # 发布资产/契约检查，避免只装 Python 包而遗漏 D-Bus、unit、回滚脚本。
    package_root = Path(__file__).resolve().parent.parent
    asset_roots = [package_root,
                   Path(sys.prefix) / "share/bianbu-securityd"]
    rel_assets = ["data/io.bianbu.Security.xml", "data/io.bianbu.Security.conf",
                  "data/io.bianbu.Runtime.xml", "deploy/io.bianbu.Runtime.conf",
                  "deploy/io.bianbu.Runtime.service",
                  "runtime/runtime_service.py",
                  "deploy/bianbu-securityd.service", "deploy/install.sh",
                  "deploy/bianbu-agent-runtimed.service",
                  "deploy/rollback.sh", "deploy/verify_install_assets.py",
                  "deploy/generate_sbom.py", "deploy/migrate_db.py",
                  "deploy/release_gate.py", "deploy/dependency_audit.py",
                  "deploy/generate_release_manifest.py",
                  "securityd/uds_handlers.py",
                  "requirements-lock.txt", "THIRD_PARTY_LICENSES.md"]
    missing_assets = [rel for rel in rel_assets
                     if not any((root / rel).is_file() for root in asset_roots)]
    checks.append(Check("release_assets", not missing_assets,
                        "present" if not missing_assets else ",".join(missing_assets),
                        "D-Bus/XML/systemd/install/rollback 资产",
                        "error" if strict else "warning"))
    try:
        config.LOG_DIR.mkdir(parents=True, exist_ok=True)
        free_gb = shutil.disk_usage(config.LOG_DIR).free / (1024 ** 3)
        checks.append(Check("disk_space", free_gb >= 1.0, f"{free_gb:.2f} GiB",
                             "日志目录可用空间"))
    except OSError as exc:
        checks.append(Check("disk_space", False, "unknown", str(exc)))
    errors = [asdict(c) for c in checks if not c.ok and c.severity == "error"]
    warnings = [asdict(c) for c in checks if not c.ok and c.severity != "error"]
    return {"ok": not errors, "strict": strict, "checks": [asdict(c) for c in checks],
            "errors": errors, "warnings": warnings}


__all__ = ["run", "Check"]
