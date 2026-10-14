# Worker 重新部署与 35 项验证指南

| 项 | 内容 |
|---|---|
| 文档用途 | 从开发机代码准备完成开始，重新部署 securityd、personal-agent 与 testkit 到 worker，并执行完整验证 |
| 目标环境 | SpacemiT K3 worker（riscv64） |
| Worker | `10.0.90.243` |
| 当前验证规模 | testkit 端到端 35 项 |
| 最终通过标准 | `35 passed / 0 failed / 0 error / 0 skipped` |
| 更新日期 | 2026-08-19 |
| 状态 | 当前操作基线 |

本文描述一套完整、可重复的验证流程：从开发机上的代码已经准备好开始，将当前代码重新部署到 worker，按依赖顺序启动服务，执行安全子系统的 35 项端到端测试，并对测试报告做程序化验收。

项目内的权威入口文档还有：

- `Collaboration/CODEX-ONBOARDING.md`
- `testkit/README.md`

## 1. 环境与目录

### 1.1 开发机目录

```text
security 仓：
/data/workspace2026-new/work0618/bianbu-agent-security/bianbu-agent-security

PA 仓：
/data/workspace2026-new/work0618/bianbu-agent-security/bianbu-agent-runtime
```

### 1.2 Worker 连接信息

```text
主机：10.0.90.243
用户：bianbu
密码：bianbu（仅在尚未配置 SSH Key 时使用）
架构：riscv64
```

### 1.3 Worker 目录

```text
securityd 源码：/home/bianbu/impl/bianbu-securityd
securityd 安装：/usr/lib/bianbu-securityd
PA：             /home/bianbu/bianbu-agent
testkit：        /home/bianbu/bnsec-testkit
服务日志：       /var/tmp/bnsec-logs
测试报告：       /var/tmp/bnsec-testrun
```

### 1.4 服务与访问地址

| 服务 | 接口或地址 | 说明 |
|---|---|---|
| securityd | D-Bus `io.bianbu.Security` | 无 HTTP 端口 |
| securityd UDS | `/run/bianbu/securityd.sock` | PA 正式数据面 |
| personal-agent | `http://10.0.90.243:9899` | PA Web/API |
| securityd 配置台 | worker 本机 `http://127.0.0.1:8787` | 默认不对局域网开放 |
| testkit 监视台 | `http://10.0.90.243:9700` | 实时测试进度与报告 |

## 2. 开发机确认待部署代码

进入开发机终端并定义本次流程使用的路径：

```bash
export SEC_REPO=/data/workspace2026-new/work0618/bianbu-agent-security/bianbu-agent-security
export PA_REPO=/data/workspace2026-new/work0618/bianbu-agent-security/bianbu-agent-runtime
export WORKER=bianbu@10.0.90.243

test -d "$SEC_REPO/impl/bianbu-securityd"
test -d "$SEC_REPO/testkit"
test -d "$PA_REPO/bianbu_agent"
```

检查两个仓库的当前改动：

```bash
git -C "$SEC_REPO" status --short
git -C "$SEC_REPO" diff --check

git -C "$PA_REPO" status --short
git -C "$PA_REPO" diff --check
```

部署前需要明确以下事项：

1. 部署的是当前工作区内容，包括尚未提交的修改和新增文件。
2. `git status` 中的修改都应属于本次准备验证的代码。
3. PA Runtime 是独立仓库；默认先确认改动范围和远端归属。**本轮已按用户明确授权提交并推送** PA Runtime `e0966a1` 到 `origin/main`；未获明确授权时只提交不推送。
4. 不要把 worker 上的模型凭据复制进日志、聊天记录或提交内容。

## 3. 配置并验证 SSH

优先使用 SSH Key。先检查是否已经免密：

```bash
ssh -o BatchMode=yes -o StrictHostKeyChecking=no \
  "$WORKER" 'hostname && uname -m'
```

如果尚未免密，生成并安装密钥：

```bash
test -f ~/.ssh/id_ed25519.pub || \
  ssh-keygen -t ed25519 -N '' -f ~/.ssh/id_ed25519

sshpass -p 'bianbu' ssh-copy-id \
  -o StrictHostKeyChecking=no \
  -i ~/.ssh/id_ed25519.pub \
  "$WORKER"
```

再次验证：

```bash
ssh -o BatchMode=yes "$WORKER" 'hostname && uname -m'
```

架构应输出：

```text
riscv64
```

如果系统没有 `sshpass`，Debian/Ubuntu 可执行：

```bash
sudo apt-get install -y sshpass
```

## 4. 备份 Worker 当前部署

建议每次完整重新部署前保留 worker 当前副本。备份只留在 worker，避免将模型凭据复制回开发机。

```bash
ssh "$WORKER" '
backup_dir=/var/tmp/bnsec-redeploy-backup-$(date +%Y%m%d-%H%M%S)
mkdir -p "$backup_dir"

rsync -a \
  --exclude=.venv \
  --exclude=__pycache__ \
  /home/bianbu/impl/bianbu-securityd/ \
  "$backup_dir/securityd/"

rsync -a \
  --exclude=.venv \
  --exclude=.git \
  --exclude=runs \
  --exclude=sessions \
  --exclude=workspace \
  /home/bianbu/bianbu-agent/ \
  "$backup_dir/personal-agent/"

rsync -a \
  /home/bianbu/bnsec-testkit/ \
  "$backup_dir/testkit/"

printf "备份目录：%s\n" "$backup_dir"
'
```

## 5. 同步 Securityd 当前代码

### 5.1 预览同步内容

先用 `rsync -n` 预览，不实际修改 worker：

```bash
rsync -azn --delete --itemize-changes \
  --exclude='.git/' \
  --exclude='.venv/' \
  --exclude='__pycache__/' \
  --exclude='*.pyc' \
  "$SEC_REPO/impl/bianbu-securityd/" \
  "$WORKER:/home/bianbu/impl/bianbu-securityd/"
```

### 5.2 正式同步

确认预览结果符合预期后执行：

```bash
rsync -az --delete --itemize-changes \
  --exclude='.git/' \
  --exclude='.venv/' \
  --exclude='__pycache__/' \
  --exclude='*.pyc' \
  "$SEC_REPO/impl/bianbu-securityd/" \
  "$WORKER:/home/bianbu/impl/bianbu-securityd/"
```

这里使用 `--delete`，目的是删除 worker 上已经不属于当前代码的旧文件，避免旧 Python 模块或旧 WebUI 资源继续生效。

## 6. 同步 Personal-Agent 当前代码

PA 需要分两步同步：先同步主体源码，再同步 `.bianbu-agent` 中的代码型配置和插件，同时保留 worker 上的模型凭据及运行数据。

### 6.1 同步 PA 主体源码

先预览：

```bash
rsync -azn --delete --itemize-changes \
  --exclude='.git/' \
  --exclude='.venv/' \
  --exclude='.pytest_cache/' \
  --exclude='__pycache__/' \
  --exclude='*.pyc' \
  --exclude='/.bianbu-agent/' \
  --exclude='/.personal-agent/' \
  "$PA_REPO/" \
  "$WORKER:/home/bianbu/bianbu-agent/"
```

确认后正式同步：

```bash
rsync -az --delete --itemize-changes \
  --exclude='.git/' \
  --exclude='.venv/' \
  --exclude='.pytest_cache/' \
  --exclude='__pycache__/' \
  --exclude='*.pyc' \
  --exclude='/.bianbu-agent/' \
  --exclude='/.personal-agent/' \
  "$PA_REPO/" \
  "$WORKER:/home/bianbu/bianbu-agent/"
```

### 6.2 同步 `.bianbu-agent` 配置与插件

以下目录属于机器凭据或运行数据，部署代码时应保留：

- `models/`
- `runs/`
- `sessions/`
- `workspace/`
- `runtime/`
- `logs/`
- `cache/`
- `mcps/`

先预览：

```bash
rsync -azn --delete --itemize-changes \
  --exclude='/models/' \
  --exclude='/runs/' \
  --exclude='/sessions/' \
  --exclude='/workspace/' \
  --exclude='/runtime/' \
  --exclude='/logs/' \
  --exclude='/cache/' \
  --exclude='/mcps/' \
  --exclude='*.lock' \
  --exclude='__pycache__/' \
  --exclude='*.pyc' \
  "$PA_REPO/.bianbu-agent/" \
  "$WORKER:/home/bianbu/bianbu-agent/.bianbu-agent/"
```

正式同步：

```bash
rsync -az --delete --itemize-changes \
  --exclude='/models/' \
  --exclude='/runs/' \
  --exclude='/sessions/' \
  --exclude='/workspace/' \
  --exclude='/runtime/' \
  --exclude='/logs/' \
  --exclude='/cache/' \
  --exclude='/mcps/' \
  --exclude='*.lock' \
  --exclude='__pycache__/' \
  --exclude='*.pyc' \
  "$PA_REPO/.bianbu-agent/" \
  "$WORKER:/home/bianbu/bianbu-agent/.bianbu-agent/"
```

不要在部署命令中打印或复制 `models/*/provider.yaml` 内的 API Key。

## 7. 同步 Testkit 与独立启动脚本

同步 testkit 当前代码：

```bash
rsync -az --delete --itemize-changes \
  --exclude='__pycache__/' \
  --exclude='*.pyc' \
  "$SEC_REPO/testkit/" \
  "$WORKER:/home/bianbu/bnsec-testkit/"
```

将三个自带默认路径的独立启动脚本放到 worker 用户目录：

```bash
scp \
  "$SEC_REPO/testkit/scripts/start-bianbu-securityd.sh" \
  "$SEC_REPO/testkit/scripts/start-bianbu-agent.sh" \
  "$SEC_REPO/testkit/scripts/start-securityd-webui.sh" \
  "$WORKER:/home/bianbu/"
```

修正脚本权限并进行 testkit 语法检查：

```bash
ssh "$WORKER" '
chmod 755 \
  /home/bianbu/start-bianbu-securityd.sh \
  /home/bianbu/start-bianbu-agent.sh \
  /home/bianbu/start-securityd-webui.sh \
  /home/bianbu/bnsec-testkit/scripts/*.sh

cd /home/bianbu/bnsec-testkit
python3 -m py_compile engine.py tests_all.py runner.py webui.py
'
```

## 8. 清理 PA Hook 目录中的非法文件

每个安全 hook 子目录内只能存在 `hook.py`。`.bak`、`.pyc` 和 `__pycache__` 可能导致插件加载失败。

```bash
ssh "$WORKER" '
hook_root=/home/bianbu/bianbu-agent/.bianbu-agent/plugins/bianbu.security/hooks

find "$hook_root" \
  -type d -name __pycache__ \
  -prune -exec rm -rf -- {} +

find "$hook_root" \
  -type f \( -name "*.pyc" -o -name "*.bak" \) \
  -delete

echo "检查 hook 目录中的非 hook.py 文件："
find "$hook_root" \
  -mindepth 2 -maxdepth 2 \
  -type f ! -name hook.py -print
'
```

最后一条命令正常情况下不应输出任何文件。

## 9. 准备 PA Python 环境

PA 必须能够导入 worker 系统提供的 `dbus-python`，所以 venv 需要启用 system site packages。

先检查现有环境：

```bash
ssh "$WORKER" '
cd /home/bianbu/bianbu-agent
.venv/bin/python -c "import dbus; print(\"dbus import OK\")"
'
```

如果成功，按锁文件同步依赖：

```bash
ssh "$WORKER" '
cd /home/bianbu/bianbu-agent
/home/bianbu/.local/bin/uv sync --locked --no-dev
'
```

如果 `import dbus` 失败，或者是首次部署，重建 venv：

```bash
ssh "$WORKER" '
cd /home/bianbu/bianbu-agent

/home/bianbu/.local/bin/uv venv \
  --clear \
  --system-site-packages \
  --python /usr/bin/python3 \
  .venv

/home/bianbu/.local/bin/uv sync --locked --no-dev

.venv/bin/python -c "import dbus; print(\"dbus import OK\")"
'
```

## 10. 检查 PA 模型与 Agent 配置

当前验证环境使用：

```text
PA 配置：.bianbu-agent/config.yaml
Agent：personal-agent-default
Provider：custom:custom-provider
模型：deepseek-v4-flash
```

检查 PA 配置与 Agent 声明：

```bash
ssh "$WORKER" '
sed -n "1,80p" \
  /home/bianbu/bianbu-agent/.bianbu-agent/config.yaml

sed -n "1,100p" \
  /home/bianbu/bianbu-agent/.bianbu-agent/agents/personal-agent-default/agent.yaml
'
```

检查 provider 是否存在以及文件权限，但不要输出 API Key：

```bash
ssh "$WORKER" '
provider=/home/bianbu/bianbu-agent/.bianbu-agent/models/custom-custom-provider/provider.yaml

test -f "$provider" || {
  echo "缺少模型 Provider 配置：$provider"
  exit 1
}

chmod 600 \
  /home/bianbu/bianbu-agent/.bianbu-agent/models/*/provider.yaml

stat -c "%a %n" \
  /home/bianbu/bianbu-agent/.bianbu-agent/models/*/provider.yaml

awk -F: "/^(provider|id):/{print}" "$provider"
'
```

所有 `provider.yaml` 权限都必须为：

```text
600
```

如果启动时出现以下错误：

```text
Agent model is unavailable
Model record permissions unsafe
```

依次检查：

1. 启动时是否使用 `.bianbu-agent/config.yaml`。
2. `agent.yaml` 中的 provider 是否与 provider 记录一致。
3. `provider.yaml` 是否为 `0600`。
4. API Key 是否已经在 worker 上安全配置。

## 11. 安装并启动 Securityd

当前 worker 使用正式 systemd 部署。先确认已有可用的冻结运行环境：

```bash
ssh "$WORKER" '
test -x /usr/lib/bianbu-securityd/venv/bin/python &&
echo "securityd runtime venv OK"
'
```

执行安装器，将当前源码部署到正式安装目录：

```bash
ssh -t "$WORKER" '
cd /home/bianbu/impl/bianbu-securityd
sudo ./deploy/install.sh \
  --runtime-venv /usr/lib/bianbu-securityd/venv
'
```

安装器会完成以下工作：

1. 将当前代码安装到 `/usr/lib/bianbu-securityd`。
2. 部署 D-Bus policy 和 activation 文件。
3. 部署并刷新 systemd unit。
4. 迁移能力、Token 和审计数据库。
5. 启动 `bianbu-securityd.service`。
6. 安装过程失败时尝试恢复上一版本。

验证服务状态：

```bash
ssh "$WORKER" '
systemctl is-active bianbu-securityd.service

systemctl --no-pager --full status \
  bianbu-securityd.service | sed -n "1,25p"

busctl --system list | grep io.bianbu.Security

test -S /run/bianbu/securityd.sock &&
echo "UDS OK: /run/bianbu/securityd.sock"

/home/bianbu/start-bianbu-securityd.sh --status
'
```

有效状态应包括：

```text
active
io.bianbu.Security
UDS OK
判权探测: ✓
```

正式安装形态下，以 `systemctl status bianbu-securityd.service` 判断进程是否运行。独立脚本的进程匹配主要用于源码开发实例，可能只显示 D-Bus 已占名而不显示 systemd 主进程。

## 12. 启动 Personal-Agent

固定启动顺序：

```text
securityd → PA → 配置台/测试监视台
```

使用当前 `.bianbu-agent` 配置启动 PA：

```bash
ssh "$WORKER" '
BA_UV_NO_SYNC=1 BA_CONFIG=.bianbu-agent/config.yaml \
  /home/bianbu/start-bianbu-agent.sh
'
```

当前 worker 尚未安装 `../bianbu-agent-memory/sdk/python`，上述命令中的
`BA_UV_NO_SYNC=1` 仅用于本轮开发态 35 项验证，表示复用已有冻结 venv。正式交付
必须先部署 Agent Memory SDK/daemon，再去掉该开关；缺少 SDK 时脚本默认拒绝启动。

注意事项：

1. 不要遗漏 `BA_CONFIG=.bianbu-agent/config.yaml`。
2. 不要误用旧的 `.personal-agent/config.yaml`；安全交付使用 `.bianbu-agent/config.yaml`。
3. 当前独立脚本没有 `--restart` 参数；无参数运行会先停止旧 PA，再启动新实例。
4. 独立脚本和短版 `start-pa.sh` 均应通过 `run.sh` 启动；安全模式默认 `BIANBU_SANDBOX=agent`。

检查 PA 状态和兼容能力查询 API：

```bash
ssh "$WORKER" '
BA_UV_NO_SYNC=1 BA_CONFIG=.bianbu-agent/config.yaml \
  /home/bianbu/start-bianbu-agent.sh --status

curl -fsS -o /dev/null \
  -w "PA HTTP=%{http_code}\n" \
  http://127.0.0.1:9899/

curl -fsS -o /dev/null \
  -w "Hook API HTTP=%{http_code}\n" \
  http://127.0.0.1:9899/api/admin/v1/capabilities/hook
'
```

两个 HTTP 请求都应返回：

```text
200
```

PA 启动失败时，可前台运行查看真实错误：

```bash
ssh -t "$WORKER" '
BA_UV_NO_SYNC=1 BA_CONFIG=.bianbu-agent/config.yaml \
  /home/bianbu/start-bianbu-agent.sh --foreground
'
```

也可以直接查看日志：

```bash
ssh "$WORKER" 'tail -100 /var/tmp/bnsec-logs/pa.log'
```

## 13. 启动 WebUI

### 13.1 Securityd 配置台：8787

默认仅监听 worker 本机：

```bash
ssh "$WORKER" '
/home/bianbu/start-securityd-webui.sh
/home/bianbu/start-securityd-webui.sh --status
'
```

在开发机建立 SSH 隧道：

```bash
ssh -L 8787:127.0.0.1:8787 "$WORKER"
```

然后访问：

```text
http://127.0.0.1:8787
```

安全提示：开发/demo DEB 的配置台通过 systemd drop-in 关闭 Bearer Token，产品包要求
管理员 Token；配置台内置 Web Terminal。不要随意使用 `--lan` 将其绑定到所有网卡；使用完可以执行：

```bash
ssh "$WORKER" '/home/bianbu/start-securityd-webui.sh --stop'
```

### 13.2 Testkit 测试监视台：9700

```bash
ssh "$WORKER" '
cd /home/bianbu/bnsec-testkit/scripts
./start-webui.sh
'
```

浏览器访问：

```text
http://10.0.90.243:9700
```

该页面同样没有鉴权，并且会触发真实模型调用、能力变更和审计写入，只能在可信内网使用。

## 14. 测试前完整体检

在运行测试前，确认正式服务、D-Bus、UDS、HTTP 服务和 provider 权限全部正常：

```bash
ssh "$WORKER" '
set -e

echo "── securityd systemd"
systemctl is-active bianbu-securityd.service

echo "── D-Bus"
busctl --system list | grep io.bianbu.Security

echo "── UDS"
test -S /run/bianbu/securityd.sock
echo /run/bianbu/securityd.sock

echo "── PA"
curl -fsS -o /dev/null \
  -w "HTTP %{http_code}\n" \
  http://127.0.0.1:9899/

echo "── securityd WebUI"
curl -fsS -o /dev/null \
  -w "HTTP %{http_code}\n" \
  http://127.0.0.1:8787/

echo "── testkit WebUI"
curl -fsS -o /dev/null \
  -w "HTTP %{http_code}\n" \
  http://127.0.0.1:9700/

echo "── Provider 权限"
stat -c "%a %n" \
  /home/bianbu/bianbu-agent/.bianbu-agent/models/*/provider.yaml
'
```

预期结果：

```text
securityd：active
PA：       HTTP 200
8787：     HTTP 200
9700：     HTTP 200
provider： 600
```

## 15. 执行 35 项端到端验证

必须使用 `runner.py`：

```bash
ssh "$WORKER" '
cd /home/bianbu/bnsec-testkit
python3 runner.py
rc=$?
echo "runner exit code=$rc"
exit "$rc"
'
```

不要使用：

```bash
python3 engine.py
```

直接运行 `engine.py` 可能因为模块被加载成两个实例而得到：

```text
总计 0
```

正确的完整通过结果应为：

```text
已注册 35 个测试项，全部运行

总计 35 | 通过 35 | 失败 0 | 错误 0
```

退出码含义：

| 退出码 | 含义 |
|---|---|
| `0` | 全部通过 |
| `1` | 存在失败或错误 |
| `2` | 指定了不存在的测试 ID |

测试会执行真实模型调用、消耗 Token、写入审计记录，并临时修改后恢复部分能力状态。

## 16. 程序化验收测试报告

最终报告位于：

```text
/var/tmp/bnsec-testrun/report.json
```

运行严格检查：

```bash
ssh "$WORKER" '
python3 - <<'"'"'PY'"'"'
import json

path = "/var/tmp/bnsec-testrun/report.json"
with open(path, encoding="utf-8") as stream:
    report = json.load(stream)

summary = report["summary"]
bad = [
    (item["id"], item["status"], item.get("message", ""))
    for item in report["results"]
    if item["status"] != "passed"
]

print(json.dumps(summary, ensure_ascii=False, indent=2))
print("non_passed:", bad)

assert summary["total"] == 35
assert summary["passed"] == 35
assert summary["failed"] == 0
assert summary["error"] == 0
assert summary["skipped"] == 0
assert not bad

print("BNSEC 35/35 PASS")
PY
'
```

最终必须看到：

```text
BNSEC 35/35 PASS
```

## 17. 只重跑失败项或关键冒烟项

如果全量测试出现失败，可按测试 ID 单独重跑：

```bash
ssh "$WORKER" '
cd /home/bianbu/bnsec-testkit
python3 runner.py HOOK-03 ERR-01 SBX-05
'
```

关键安全链路冒烟测试：

```bash
ssh "$WORKER" '
cd /home/bianbu/bnsec-testkit
python3 runner.py \
  HOOK-01 \
  HOOK-03 \
  DLP-04 \
  TOKEN-02 \
  SBX-05 \
  ERR-01
'
```

修复任何单项后，都必须再次执行完整的：

```bash
cd /home/bianbu/bnsec-testkit
python3 runner.py
```

单项通过不能替代 35 项全量通过。

## 18. 扩展回归测试

35 项 testkit 是安全子系统接入的主要验收门槛。如果修改了 securityd 或 PA 主体，还应执行对应仓库回归。

### 18.1 Securityd 测试

```bash
ssh "$WORKER" '
cd /home/bianbu/impl/bianbu-securityd
python3 -m pytest tests/ -q
'
```

验收要求：

- `failed=0`
- `error=0`
- 默认模式下，仅仓库明确标记的可选 E2E skipped 可以接受
- 发布验证应使用仓库规定的 strict/release 入口

### 18.2 PA 安全开关回归对比

PA 在 worker 上可能存在与安全接入无关的环境失败，例如 worker 副本不是 git 仓库、缺浏览器 driver 或 riscv64 性能差异。因此不能只比较失败总数，必须比较安全关闭和开启时的失败集合。

建议先停止 PA：

```bash
ssh "$WORKER" '
BA_CONFIG=.bianbu-agent/config.yaml \
  /home/bianbu/start-bianbu-agent.sh --stop
'
```

执行两次测试并比较：

```bash
ssh "$WORKER" '
export PATH=/home/bianbu/.local/bin:$PATH
cd /home/bianbu/bianbu-agent

set +e
BIANBU_SECURITY=0 uv run pytest -q \
  > /var/tmp/pa-pytest-security-off.log 2>&1

BIANBU_SECURITY=1 uv run pytest -q \
  > /var/tmp/pa-pytest-security-on.log 2>&1
set -e

grep "^FAILED" /var/tmp/pa-pytest-security-off.log |
  sort > /var/tmp/pa-failed-off.txt || true

grep "^FAILED" /var/tmp/pa-pytest-security-on.log |
  sort > /var/tmp/pa-failed-on.txt || true

echo "── 安全开启后新增的失败"
comm -13 \
  /var/tmp/pa-failed-off.txt \
  /var/tmp/pa-failed-on.txt
'
```

`comm -13` 没有输出，说明安全开启后没有引入新的测试失败。

完成后重新启动 PA：

```bash
ssh "$WORKER" '
BA_CONFIG=.bianbu-agent/config.yaml \
  /home/bianbu/start-bianbu-agent.sh
'
```

## 19. 常见故障排查

### 19.1 PA 返回 HTTP 200，但安全测试大量失败

PA 在 securityd 不可用时仍可能启动成功，因此 HTTP 200 不能证明安全链路有效。

检查：

```bash
systemctl is-active bianbu-securityd.service
busctl --system list | grep io.bianbu.Security
test -S /run/bianbu/securityd.sock
```

### 19.2 `Agent model is unavailable`

检查 provider 权限：

```bash
stat -c '%a %n' \
  /home/bianbu/bianbu-agent/.bianbu-agent/models/*/provider.yaml
```

权限必须为 `600`。同时确认 PA 使用：

```text
BA_CONFIG=.bianbu-agent/config.yaml
```

### 19.3 HOOK-01 返回 404

通常表示 PA 不是当前源码，或旧进程仍在运行。检查并重新部署：

```text
bianbu_agent/api/capabilities.py
bianbu_agent/api/__init__.py
```

同步后重启 PA。

### 19.4 HOOK-03 一直等待人工审批

确认已经同步当前文件：

```text
bianbu_agent/engines/langgraph/engine.py
```

当前 LangChain 版本会把 `interrupt_on` 中的每项视为无条件审批项；旧逻辑可能导致普通工具永久等待审批。部署当前代码后必须重启 PA。

### 19.5 DLP-04 或 TOKEN-02 失败

重点检查：

1. 是否误用了旧的 `.personal-agent/config.yaml`（应使用 `.bianbu-agent/config.yaml`）。
2. `personal-agent-default` 是否配置了 `hooks: ['*']`。
3. `BIANBU_PA_AGENT_ID` 是否为 `com.bianbu.agent`。
4. security 插件的全部 hooks 和 `lib/` 是否已经部署。
5. PA venv 是否可以 `import dbus`。

`BIANBU_PA_AGENT_ID=com.bianbu.agent` 与 PA 本地 Agent ID `personal-agent-default` 属于不同命名空间，不能混用。

### 19.6 SBX-05 失败

该项验证沙箱内 DNS 解析和 `/etc/resolv.conf` 符号链接处理。确认 PA/securityd 两侧沙箱实现均为当前版本，并重启受影响的服务。

### 19.7 测试显示“总计 0”

测试入口错误。必须使用：

```bash
python3 runner.py
```

### 19.8 查看全部相关日志

```bash
ssh "$WORKER" '
echo "── securityd"
journalctl -u bianbu-securityd.service \
  --no-pager -n 100

echo "── PA"
tail -100 /var/tmp/bnsec-logs/pa.log

echo "── securityd WebUI"
tail -100 /var/tmp/bnsec-logs/sec-webui.log

echo "── testkit WebUI"
tail -100 /var/tmp/bnsec-logs/webui.log

echo "── test runner"
tail -100 /var/tmp/bnsec-testrun/runner.log \
  2>/dev/null || true
'
```

## 20. 改动位置与重启对应关系

| 修改位置 | 必须重启或重新安装 | 原因 |
|---|---|---|
| `impl/bianbu-securityd/securityd/**` | 重新运行 `deploy/install.sh`，或开发实例使用 `start-bianbu-securityd.sh --restart` | 否则验证的是旧判权逻辑 |
| PA `bianbu_agent/**` | 重新运行 `start-bianbu-agent.sh` | PA 进程不会自动加载新源码 |
| PA 插件 `lib/`、`hooks/` | 重新运行 `start-bianbu-agent.sh` | 插件在启动阶段加载 |
| `impl/bianbu-securityd/webui/**` | 重新运行 `start-securityd-webui.sh` | 否则页面资源仍是旧版本 |
| `testkit/tests_all.py` | 不需要重启服务 | 下一次 `runner.py` 会重新加载 |

## 21. 最终验收清单

完成部署和验证后，逐项确认：

- [ ] 当前 securityd 源码已同步到 `/home/bianbu/impl/bianbu-securityd`
- [ ] 当前 securityd 已安装到 `/usr/lib/bianbu-securityd`
- [ ] `bianbu-securityd.service` 为 `active`
- [ ] D-Bus `io.bianbu.Security` 已占名
- [ ] `/run/bianbu/securityd.sock` 存在
- [ ] 当前 PA 源码和安全插件已同步到 `/home/bianbu/bianbu-agent`
- [ ] PA 使用 `.bianbu-agent/config.yaml`
- [ ] `BIANBU_PA_AGENT_ID=com.bianbu.agent`
- [ ] provider 文件权限全部为 `0600`
- [ ] PA 9899 返回 HTTP 200
- [ ] securityd 配置台 8787 返回 HTTP 200
- [ ] testkit 监视台 9700 返回 HTTP 200
- [ ] testkit 当前代码已部署到 `/home/bianbu/bnsec-testkit`
- [ ] 使用 `python3 runner.py` 执行测试
- [ ] 报告为 35 passed / 0 failed / 0 error / 0 skipped
- [ ] 报告中的 `non_passed` 为空
- [ ] 修复过任何单项后，重新执行过完整 35 项测试

完整闭环为：

```text
准备代码
  → 备份 worker
  → 同步 securityd / PA / testkit
  → 安装 securityd
  → 按 securityd → PA → WebUI 顺序启动
  → 测试前体检
  → 运行 runner.py 全量 35 项
  → 程序化检查 report.json
  → 确认 35/35 通过
```
