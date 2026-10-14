# AgentSecurityD 手动运行验证指南

分本地（x86_64 开发机）和 worker（K3 riscv64, 10.0.90.243）两条路径，每步给出命令与预期输出。
命令默认在实现根目录 `impl/bianbu-securityd/` 下执行。

## 0. 前置说明

| 项 | 本地 x86_64 | worker K3 |
|----|------------|-----------|
| 沙箱集成用例 | AppArmor 禁用非特权 userns → 3 个 bwrap 用例 skip | 全部可跑 |
| 依赖 | cryptography/dbus-python/PyGObject 已装（无 pynacl，用 cryptography） | 同左 |
| pip | PEP 668 受限 → 用 venv | 同左 |

关键机制：`BIANBU_SEC_ROOT` 环境变量把 `/etc`、`/run`、`/var/log` 整体重定向到可写目录，
**全程无需 root**。

## 1. 一次性环境准备

本地：
```bash
cd impl/bianbu-securityd
python3 -m venv --system-site-packages /tmp/bnvenv2   # 继承系统 dbus/gi
/tmp/bnvenv2/bin/pip install -q pytest cryptography
export PY=/tmp/bnvenv2/bin/python
```

worker（登录 bianbu@10.0.90.243）：
```bash
# 传包（本地执行）
tar czf /tmp/securityd.tgz --exclude='__pycache__' --exclude='.pytest_cache' \
    --exclude='tests/fixtures/test-security-agent' bianbu-securityd
scp /tmp/securityd.tgz bianbu@10.0.90.243:/tmp/
# 机上执行
mkdir -p ~/bianbu-securityd-work && cd ~/bianbu-securityd-work
tar xzf /tmp/securityd.tgz
python3 -m venv --system-site-packages /tmp/bnv
/tmp/bnv/bin/pip install -q pytest
export PY=/tmp/bnv/bin/python
```

每个新 shell 都要设这三行（进入实现目录后）：
```bash
cd <...>/bianbu-securityd
export PYTHONPATH=$PWD:$PWD/client
export BIANBU_SEC_ROOT=/tmp/bnsec_manual   # 隔离的可写根
rm -rf /tmp/bnsec_manual
```

生成测试 Agent 包（有效签名 + 无签名 + 无 manifest 三种）：
```bash
$PY tests/fixtures/make_fixtures.py
# 预期：fixtures generated under .../tests/fixtures ; valid: .../test-security-agent
ls tests/fixtures/test-security-agent
# 预期：manifest.toml  manifest.toml.sig  pubkey.hex
```

## 2. 最快验证：一条命令冒烟（先跑这个）

```bash
PYTHON=$PY bash tests/smoke_test.sh
```
预期结尾：
```
[0/7] bwrap 非特权沙箱可用性...
  PASS: bwrap OK            # worker 才 PASS；本地会 FAIL 退出（AppArmor 预期）
...
DBUS_E2E_PASS
=== SMOKE TEST ALL PASS ===
```
> 本地因 userns 受限会在 [0/7] 处 fail-fast，这是预期的环境差异，请在 worker 上跑此脚本看全绿。

## 3. 分层自动化测试

```bash
# 纯逻辑单元测试（两端都应 25 passed）
$PY -m pytest tests/unit -v

# 集成测试
$PY -m pytest tests/integration -v
#   本地预期：2 passed, 3 skipped（userns）
#   worker预期：5 passed（含 seccomp 拦截 / deny-path / cap-drop）
```

单条排查用 -k，例如只看 L4 强制确认：
```bash
$PY -m pytest tests/unit -k l4 -v
```

## 4. 手动启动 securityd 并逐方法验证

### 4.1 启动守护进程（会话总线，无需 root）

终端 A：
```bash
cd <...>/bianbu-securityd
export PYTHONPATH=$PWD:$PWD/client BIANBU_SEC_ROOT=/tmp/bnsec_manual
$PY -m securityd.service --session
# 预期：bianbu-securityd started on session bus as io.bianbu.Security
```
生产用系统总线：`sudo python3 -m securityd.service`，需装 `data/io.bianbu.Security.conf`
到 `/etc/dbus-1/system.d/`。

### 4.2 确认服务可达 + 14 方法齐全（终端 B）

```bash
export PYTHONPATH=<...>/bianbu-securityd:<...>/bianbu-securityd/client
busctl --user introspect io.bianbu.Security /io/bianbu/Security \
  | awk '$2=="method" && $1!~/^\.(Ping|GetMachineId|Introspect)$/{print $1}'
# 预期 13 行（业务方法）：
#   VerifyManifest RegisterCapabilities CheckPermission RequestConfirm
#   RespondConfirm RevokePermission BuildSandboxPolicy AuditLog
#   ExportAudit VerifyAuditChain SetNetworkPolicy GetCapabilities SuspendAgent
# 注：introspect 另会列出 D-Bus 标准方法 .Ping/.GetMachineId/.Introspect，非业务方法，已过滤。
```

### 4.3 用客户端安装 Agent，再用 busctl 打方法

```bash
export BIANBU_SEC_SESSION=1     # 让客户端走会话总线
$PY - <<'PY'
import sys; sys.path.insert(0,"client")
import bianbu_security_client as sc
aid="com.bianbu.test-security-agent"
r=sc.verify_manifest("tests/fixtures/test-security-agent")
print("verify:", r["valid"], "perms:", len(r["permissions"]))
print("register:", sc.register_capabilities(aid, r["permissions"]))
PY
# 预期：verify: True perms: 5 / register: True
```

权限判定（返回值语义：0=ALLOW 1=ASK 2=DENY）：
```bash
A=com.bianbu.test-security-agent
B="busctl --user call io.bianbu.Security /io/bianbu/Security io.bianbu.Security"
$B CheckPermission sss "$A" read_proc_list ""   # 预期 i 0 (allow)
$B CheckPermission sss "$A" payment_create ""   # 预期 i 1 (ask)
$B CheckPermission sss "$A" unknown.cap ""      # 预期 i 2 (未注册→DENY)
```

审计写入 → 导出 → 验证链：
```bash
$B AuditLog ssss "$A" manual_test target1 allow      # 预期 x <seq>
P=$($B ExportAudit ss "{\"agent_id\":\"$A\"}" json | awk '{print $2}' | tr -d '"')
echo "export: $P"
$B VerifyAuditChain s "$P"                            # 预期 b true
```

沙箱策略生成（返回 seccomp 与 netfilter 路径）：
```bash
$B BuildSandboxPolicy s "$A"     # 预期 ss ".../seccomp.bpf" ".../netfilter.rules"
ls -l $BIANBU_SEC_ROOT/run/bianbu/sandbox/$A/    # seccomp.bpf 应 >0 字节
```

### 4.4 手动验证篡改检测（审计不可抵赖）

```bash
$PY - <<'PY'
import json
P="替换成上面导出的 $P 路径"
d=json.load(open(P)); d["records"][0]["result"]="deny"; json.dump(d,open(P,"w"))
PY
$B VerifyAuditChain s "$P"        # 预期 b false  ← 篡改被检出
```

### 4.5 观察信号（SecurityAlert / ConfirmRequest 等）

终端 C：
```bash
busctl --user monitor io.bianbu.Security
```
终端 B 触发，终端 C 应打印 SecurityAlert 信号：
```bash
$B SuspendAgent ss "$A" "manual test"   # 终端C 应见 SecurityAlert(...,suspend,...)
```
停止服务：终端 A 按 Ctrl-C。

## 5. 手动验证沙箱真隔离（仅 worker，需 bwrap + userns）

```bash
export PYTHONPATH=$PWD:$PWD/client BIANBU_SEC_ROOT=/tmp/bnsec_sbx
$PY -c "from securityd import seccomp_builder as s; print('bpf:', s.build_policy_file('com.demo'))"
```

验 seccomp 拦截 reboot（应得 EPERM）：
```bash
SC=$BIANBU_SEC_ROOT/run/bianbu/sandbox/com.demo/seccomp.bpf
cat > /tmp/try_reboot.py <<'E'
import ctypes,sys; libc=ctypes.CDLL(None,use_errno=True)
libc.reboot(0xfee1dead); sys.exit(99 if ctypes.get_errno()==1 else 0)
E
bwrap --unshare-user --ro-bind /usr /usr --symlink usr/bin /bin --symlink usr/lib /lib \
  --ro-bind /etc /etc --dev /dev --proc /proc --tmpfs /tmp --ro-bind /tmp /tmp \
  --die-with-parent --seccomp 9 -- /usr/bin/python3 /tmp/try_reboot.py 9<$SC
echo "exit=$?    # 预期 99 = reboot 被 seccomp EPERM 拦截"
```

验 cap-drop / deny-path / fail-closed（用集成用例）：
```bash
$PY -m pytest tests/integration/test_sandbox_manager.py -v    # 预期 4 passed
```

## 6. CLI（bncli）手动验证

```bash
export PYTHONPATH=$PWD:$PWD/client BIANBU_SEC_ROOT=/tmp/bnsec_cli; rm -rf /tmp/bnsec_cli

$PY -m cli.bncli install tests/fixtures/test-security-agent
# 预期：installed

$PY -m cli.bncli capability list com.bianbu.test-security-agent
# 预期：5 条能力的 JSON（含 granted:1）

$PY -m cli.bncli capability revoke com.bianbu.test-security-agent read_proc_list
# 预期：revoked

P=$($PY -m cli.bncli audit export --agent com.bianbu.test-security-agent)
$PY -m cli.bncli audit verify "$P"
# 预期：intact

# 负面：无签名包应装不上
$PY -m cli.bncli install tests/fixtures/no-sig-agent
# 预期：failed: missing signature
```

## 7. 排查速查

| 现象 | 原因 / 处理 |
|------|------------|
| `No module named securityd` | 没 `export PYTHONPATH=$PWD:$PWD/client` |
| `No module named pytest` | 用 venv 的解释器 `$PY`，非系统 python3 |
| busctl `Unknown object`/连不上 | 服务没起，或没加 `--user`；确认终端 A 在跑 |
| 客户端连到系统总线 | 设 `export BIANBU_SEC_SESSION=1` |
| 本地 3 个沙箱用例 SKIPPED | 预期：本机 AppArmor 禁 userns，去 worker 跑 |
| `bwrap: execvp /bin/true` | merged-usr，exec 用 `/usr/bin/true` + `--symlink`（脚本已处理） |
| 权限/审计"脏数据" | 换一个 `BIANBU_SEC_ROOT` 或 `rm -rf` 它重来 |

## 8. 已验证基线（参考）

- worker K3（riscv64, Py3.14）：unit+integration 30 passed，e2e 2 passed（含确认门禁全路径），smoke 4 阶段 ALL PASS。
- 本地 x86_64：27 passed，3 skipped（沙箱 userns 用例，环境预期）；确认门禁演示 4/4 通过。

## 9. hermes 接入·确认门禁全路径（RespondConfirm 打通）

hermes 经 `client/bianbu_security_client.py` 调用 `io.bianbu.Security`。L2/L3/L4 需
用户确认的能力，由确认前端（GUI）经 `RespondConfirm(request_id, approved)` 回传决定，
唤醒异步 `RequestConfirm`。演示脚本用"模拟GUI"（订阅 `ConfirmRequest` 信号→回传）覆盖
批准/拒绝/L4 二次确认全路径：

```bash
export PYTHONPATH=$PWD:$PWD/client BIANBU_SEC_ROOT=/tmp/bnsec_hc BIANBU_CONFIRM_TIMEOUT=10
$PY tests/fixtures/make_fixtures.py >/dev/null
dbus-run-session -- $PY tests/integration/hermes_confirm_demo.py   # 预期 HERMES_CONFIRM_PASS（4/4）
# 步骤 A L3 批准→True / B L3 拒绝→False / C L4 连批2次→True / D L4 首肯次否→False
```

也已包进 pytest 与 smoke：
```bash
BIANBU_E2E=1 BIANBU_SEC_SESSION=1 BIANBU_CONFIRM_TIMEOUT=10 \
  dbus-run-session -- $PY -m pytest tests/e2e -v     # 预期 2 passed
PYTHON=$PY BIANBU_CONFIRM_TIMEOUT=10 bash tests/smoke_test.sh   # 阶段 4/4 含此演示
```
