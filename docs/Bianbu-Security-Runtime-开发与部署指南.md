# Bianbu Security Runtime 开发与部署指南

| 项 | 内容 |
|---|---|
| 文档编号 | BN-SEC-RUNTIME-DEV-001 |
| 版本 | V0.3 |
| 来源 | BN-SEC-RUNTIME-001、securityd 与 PA Runtime 当前实现 |
| 日期 | 2026-08-20 |
| 状态 | worker Security Runtime/PA/35 项验收通过，商用增强项待补证 |
| 适用对象 | securityd/PA Runtime 开发、worker 部署和问题排查 |

## 1. 代码仓与交付边界

本功能跨两个仓库：

| 仓库 | 目录 | 本次职责 | 提交规则 |
|---|---|---|---|
| Security 设计/实现仓 | `bianbu-agent-security` | `securityd`、`security.runtime`、D-Bus XML/policy、单测/集成测试、文档 | 可提交并推送 |
| PA Runtime | `bianbu-agent-runtime` | `SecurityRuntimeClient`、`ExecutionCoordinator`、host/bwrap 后端、端口代理、生命周期、生产门禁和 Skill DLP 身份绑定 | `e0966a1` 已提交并推送到 `origin/main`；worker bwrap 验收已通过 |

当前接口不是 `io.bianbu.Runtime`。PA 调用的是同一 securityd 总线名下的：

```text
服务名：io.bianbu.Security
对象：/io/bianbu/Security/Runtime
接口：io.bianbu.Security.Runtime
```

## 2. 开发机准备

```bash
cd /data/workspace2026-new/work0618/bianbu-agent-security/bianbu-agent-security
export PA_ROOT=/data/workspace2026-new/work0618/bianbu-agent-security/bianbu-agent-runtime
export PA_PYTHON="$PA_ROOT/.venv/bin/python"
```

确认 Python 编译：

```bash
python3 -m py_compile \
  impl/bianbu-securityd/securityd/service.py \
  impl/bianbu-securityd/runtime/policy.py \
  impl/bianbu-securityd/runtime/lease.py \
  impl/bianbu-securityd/runtime/engine.py
"$PA_PYTHON" -m py_compile \
  "$PA_ROOT/bianbu_agent/security_runtime.py" \
  "$PA_ROOT/bianbu_agent/server/runtime.py"
```

## 3. 本机测试

本机 securityd Runtime 单元测试：

```bash
PYTHONPATH=impl/bianbu-securityd \
  "$PA_PYTHON" -m pytest -q \
  impl/bianbu-securityd/tests/unit/test_runtime_policy.py \
  impl/bianbu-securityd/tests/unit/test_runtime_lease.py \
  impl/bianbu-securityd/tests/unit/test_runtime_engine.py
```

本机真实私有 session bus 测试（需要系统 Python 的 dbus-python/PyGObject）：

```bash
PYTHONPATH=impl/bianbu-securityd \
  dbus-run-session -- /usr/bin/python3 \
  impl/bianbu-securityd/tests/integration/runtime_security_dbus.py
```

PA 客户端与既有启动回归：

```bash
"$PA_PYTHON" -m pytest -q \
  "$PA_ROOT/tests/runtime/test_security_runtime.py" \
  "$PA_ROOT/tests/runtime/test_service.py" \
  "$PA_ROOT/tests/test_run_script.py"
```

PA 执行器与生产门禁定向测试：

```bash
"$PA_PYTHON" -m pytest -q \
  "$PA_ROOT/tests/runtime/test_execution_runtime.py" \
  "$PA_ROOT/tests/runtime/test_cli.py" \
  "$PA_ROOT/tests/runtime/test_service.py" \
  "$PA_ROOT/tests/test_run_script.py"
```

## 4. Worker 部署

Worker：`10.0.90.243`，工作目录：

```text
/home/bianbu/impl/bianbu-securityd
/home/bianbu/bianbu-agent
```

首次配置 SSH key（若尚未配置）：

```bash
ssh-copy-id -i ~/.ssh/id_ed25519.pub bianbu@10.0.90.243
```

同步 Security 仓实现（不覆盖 worker 的运行数据）：

```bash
rsync -az --delete \
  --exclude='.git' --exclude='__pycache__' --exclude='*.pyc' \
  impl/bianbu-securityd/ \
  bianbu@10.0.90.243:/home/bianbu/impl/bianbu-securityd/
```

同步 PA Runtime 代码：

```bash
scp "$PA_ROOT/bianbu_agent/security_runtime.py" \
  bianbu@10.0.90.243:/home/bianbu/bianbu-agent/bianbu_agent/security_runtime.py
scp "$PA_ROOT/bianbu_agent/server/runtime.py" \
  bianbu@10.0.90.243:/home/bianbu/bianbu-agent/bianbu_agent/server/runtime.py
scp "$PA_ROOT/bianbu_agent/execution_runtime.py" \
  bianbu@10.0.90.243:/home/bianbu/bianbu-agent/bianbu_agent/execution_runtime.py
scp "$PA_ROOT/run.sh" bianbu@10.0.90.243:/home/bianbu/bianbu-agent/run.sh
```

## 5. 重启顺序与检查

改 securityd 后必须先重启 securityd，再启动 PA：

```bash
ssh bianbu@10.0.90.243 \
  'cd /home/bianbu/bnsec-testkit/scripts && ./start-bianbu-securityd.sh --restart'
ssh bianbu@10.0.90.243 \
  'cd /home/bianbu/bnsec-testkit/scripts && ./start-bianbu-agent.sh --stop || true'
ssh bianbu@10.0.90.243 \
  'cd /home/bianbu/bnsec-testkit/scripts && BA_CONFIG=.bianbu-agent/config.yaml BIANBU_SANDBOX=agent ./start-bianbu-agent.sh'
```

检查 D-Bus 对象和自省：

```bash
ssh bianbu@10.0.90.243 \
  'busctl --system introspect io.bianbu.Security /io/bianbu/Security/Runtime io.bianbu.Security.Runtime'
```

若 worker 的生产 unit 未安装本次代码，先按现有安装流程执行 `sudo impl/bianbu-securityd/deploy/install.sh`，再重启 `bianbu-securityd.service`。不要启动仓库内的 `runtime/runtime_service.py` 冒充 PA Runtime。

## 6. PA 启动配置

开发验证至少设置：

```bash
export BIANBU_SECURITY=1
export BIANBU_SECURITYD_HOME=/home/bianbu/impl/bianbu-securityd
export BIANBU_SEC_UDS=/run/bianbu/securityd.sock
export BIANBU_PA_AGENT_ID=com.bianbu.agent
```

正式启动前必须部署 `../bianbu-agent-memory/sdk/python`（以及对应的
`bianbu-agent-memoryd`）。若只是复用已有虚拟环境做开发验证，才显式设置：

```bash
export BA_UV_NO_SYNC=1
```

该开关不会补齐缺失的 SDK，不得用于商用安装或发布验收。

执行偏好放在 PA Agent manifest 的 `metadata`：

```yaml
metadata:
  execution:
    requested_mode: auto   # auto | sandbox | host
```

旧的 `metadata.sandbox.mode` 仍由开发态工具/MCP 沙箱逻辑使用；它不替代
`execution.requested_mode`。PA Runtime 的 `ExecutionCoordinator` 按 securityd
返回的 `effective_mode/backend` 创建受控 host 或 bwrap 实例。当前 bwrap 端口代理
仅允许 host loopback 目标，代理监听地址固定为 `127.0.0.1`，并且 CommitStart
成功后才开放。

Agent manifest 的 `[runtime]` 区段是启动摘要绑定的信任来源，至少应包含：

```toml
[runtime]
entrypoint = ["/固定/agent-entrypoint", "serve"]
```

manifest 的值完全一致；缺失或不匹配只能得到 sandbox/拒绝，不能凭客户端自报摘要
取得 host 模式。配置文件变更后重新计算摘要、重新登记/签名 manifest，并重启 PA。

Skill DLP 调用必须使用 Security 命名空间的稳定身份：默认
`BIANBU_PA_AGENT_ID=com.bianbu.agent`。PA 本地 Agent ID（当前默认
`personal-agent-default`）只用于 PA 内部存储和 Run 路由；不能传给 securityd UDS，
否则正式 caller binding 会拒绝扫描。PA Runtime 启动绑定和 `security_skill_dlp` 已
统一使用 `BIANBU_PA_AGENT_ID`。

Child 生命周期 HTTP API 的完整请求/响应、禁止字段、错误码和运维命令见：
`docs/Bianbu-Security-Runtime-HTTP-API与运维手册.md`。

生产 systemd 服务注入 `BIANBU_RUNTIME_MODE=production` 和
`BIANBU_RUNTIME_MANAGED=1`。生产模式下直接执行 `run.sh` 或裸
`bianbu-agent serve` 会在任何副作用前失败；marker 只能由受信安装器/systemd
注入，不得由用户手工伪造。

## 7. 故障排查

| 现象 | 检查 | 处理 |
|---|---|---|
| `security.runtime PrepareStart 失败` | `systemctl status bianbu-securityd`、D-Bus 自省、`BIANBU_SECURITYD_HOME` | 先恢复 securityd；不要改成 fail-open |
| `要求 sandbox，但当前 PA 未在 sandbox` | `BIANBU_SANDBOX_ACTIVE`、启动日志 | 以 `BIANBU_SANDBOX=agent` 的开发入口重启，或把策略改成允许 host 后重新 Prepare |
| `cgroup_path 不匹配` | `/proc/<pid>/cgroup` 与 Commit 参数 | 不手工填写，使用 Runtime 读取的实际 cgroup |
| 9899 已占用 | `ss -ltnp | grep 9899` | 停止旧 PA 后再启动，避免验证旧代码 |
| 安全日志显示 fail 分档 | `start-bianbu-securityd.sh --status` | 说明 securityd 没有占用总线名，先修复服务 |

## 8. 当前交付限制

当前版本已经交付安全 Runtime 的策略/租约控制面和 PA 执行器开发实现，但以下能力仍需
worker 生产化验收或后续版本：

- worker 上 systemd user unit 的真实 cgroup/网络属性和 bwrap seccomp FD 传递；
- sandbox 目标端口代理（当前实现只允许 host loopback 目标）；
- 移除 Agent 执行实例对 securityd 源码和完整系统 D-Bus 的开发态依赖；
- OCI 后端、完整 eBPF/egress broker 与商用签名证明；
- 生产安装包的长期 soak、升级回滚和 worker 端到端证据。

因此本版本可交付为“Security Runtime 控制面 + PA 双模式执行器 worker 基础验收版”；
第 10 节验收报告会把尚未具备证据的 OCI、egress broker、长期 soak 和生产安装包
能力明确标为 BLOCKED，不将其写成商用 PASS。

## 9. 执行器故障排查

| 现象 | 检查 | 处理 |
|---|---|---|
| `systemd unit 启动失败` | `systemctl --user status bianbu-agent-*.service` | 确认 user manager、linger 和 `systemd-run` 可用；不可用时拒绝启动 |
| `Commit 后端口代理创建失败` | `ss -ltn` | 释放冲突端口；代理必须只出现在 `127.0.0.1` |
| 重启后有活动实例记录 | `cat ~/.bianbu-agent/runtime/executions.json` | Runtime 启动校验 unit MainPID/cgroup 后回收孤儿 |
| 生产裸启动被拒绝 | `echo "$BIANBU_RUNTIME_MODE $BIANBU_RUNTIME_MANAGED"` | 使用受信 systemd 服务，不手工伪造 marker |
