# Bianbu Security Runtime 测试与验收报告

| 项 | 内容 |
|---|---|
| 文档编号 | BN-SEC-RUNTIME-ACC-001 |
| 版本 | V0.3 |
| 日期 | 2026-08-20 |
| 状态 | worker 安全接入与 35 项端到端验收通过；商用增强项待补证 |
| 范围 | `bianbu-securityd` + PA `bianbu-agent-runtime` |

## 1. 交付版本

| 仓库 | 当前提交 | 说明 |
|---|---|---|
| Security 设计/实现仓 | 本轮提交后记录最终 hash（见文末提交记录） | policy、lease、engine、D-Bus、单测和集成驱动 |
| PA Runtime | `e0966a1` 已推送（最终远端提交） | `ExecutionCoordinator`、host/bwrap、端口代理、生产门禁、Skill DLP 身份绑定修复 |

PA Runtime 的执行路径为：

```text
ExecutionRequest
  → security.runtime PrepareStart（一次性 lease + immutable policy）
  → policy digest/backend/entrypoint 校验
  → HostProcessBackend 或 BwrapBackend
  → PID/cgroup/namespace attestation
  → CommitStart
  → 127.0.0.1 loopback proxy（如配置）
```

任何启动失败都会停止后端、Abort（Commit 前）或 Revoke（Commit 后），并写入本地
execution ledger；Runtime 重启时只回收仍能证明属于原 unit/cgroup 的孤儿实例。

## 2. 本机自动化证据

### 2.1 Security Runtime 控制面

```bash
cd /data/workspace2026-new/work0618/bianbu-agent-security/bianbu-agent-security
PYTHONPATH=impl/bianbu-securityd \
  ../bianbu-agent-runtime/.venv/bin/python -m pytest -q \
  impl/bianbu-securityd/tests/unit/test_runtime_policy.py \
  impl/bianbu-securityd/tests/unit/test_runtime_lease.py \
  impl/bianbu-securityd/tests/unit/test_runtime_engine.py
# 结果：53 passed（Runtime 策略/租约/执行器/UDS 本机定向）

PYTHONPATH=impl/bianbu-securityd \
  dbus-run-session -- /usr/bin/python3 \
  impl/bianbu-securityd/tests/integration/runtime_security_dbus.py
# 结果：SECURITY_RUNTIME_DBUS_PASS
```

### 2.2 PA Runtime 执行器和门禁

```bash
cd /data/workspace2026-new/work0618/bianbu-agent-security/bianbu-agent-runtime
./.venv/bin/python -m pytest -q \
  tests/runtime/test_security_skill_dlp.py \
  tests/runtime/test_security_runtime.py \
  tests/runtime/test_execution_runtime.py \
  tests/runtime/test_service.py \
  tests/test_run_script.py \
  tests/sdk/test_dependency_boundary.py \
  tests/sdk/test_default_engine.py
# 结果：42 passed, 1 warning（worker PA Runtime 定向）
```

覆盖：host/sandbox argv、环境清理、Prepare/Commit/Abort、digest 校验、停止/撤销、
loopback 端口代理的 Commit 前后生命周期、零 PID 孤儿记录、生产裸启动阻断。

PA 全量 `pytest` 在 worker 不是本报告的发布门禁：当前环境缺 Playwright 浏览器，且
工作树已有 Bibit 插件契约差异；这些环境/基线失败不能替代执行器定向测试。发布前须
在 worker 安装浏览器或按 testkit 说明将其标为 BLOCKED，并比较安全开关前后失败集合。

## 3. 手动/worker 验收矩阵

状态定义：`PASS` 需要命令输出或外部观测证据；`BLOCKED` 表示 worker 缺依赖/权限，
不能写成 PASS；`NOT RUN` 表示尚未执行。

| ID | 条件与命令 | 期望可观测结果 | 状态 |
|---|---|---|---|
| RT-EXEC-01 | worker 以 `.bianbu-agent/config.yaml` 启动 PA，Security Runtime 允许 sandbox | PA HTTP 200，启动租约提交；本次由 `run.sh` 进入 bwrap | PASS（worker） |
| RT-EXEC-02 | `BIANBU_SANDBOX=agent ./run.sh serve`，worker 安装 bwrap | 日志含 bwrap 启动，PA PID namespace 内 PID=6，`BIANBU_SANDBOX_ACTIVE=1` | PASS（worker） |
| RT-EXEC-03 | 无 lease/未绑定 caller 的 Runtime 请求 | D-Bus 返回拒绝，不创建进程 | PASS（本机/worker securityd 定向） |
| RT-EXEC-04 | 修改 policy/digest 后 Commit | Commit 被拒，lease 不可重复提交 | PASS（本机 Runtime 定向） |
| RT-EXEC-05 | 读取 PA bwrap 与 securityd 的 PID/cgroup/namespace 证明 | worker securityd 定向测试通过；PA 日志确认 sandbox namespace | PASS（worker 基础证据） |
| RT-EXEC-06 | 启动失败/Commit 失败清理 | Abort/Revoke 清理及失败租约有单测覆盖 | PASS（本机 Runtime 定向） |
| RT-EXEC-07 | stop/revoke 生命周期 | stop/revoke 有单测覆盖；独立 worker host child 尚未形成外部证据 | NOT RUN（独立 child） |
| RT-EXEC-08 | PA Runtime 重启孤儿回收 | ledger/reap 有单测覆盖；生产 transient unit 重启实测待补 | NOT RUN（生产 soak） |
| RT-EXEC-09 | loopback 端口代理 | 本机自动化 PASS；sandbox 代理按设计拒绝，仅允许 host loopback | PASS（本机）；sandbox NOT APPLICABLE |
| RT-EXEC-10 | `BIANBU_RUNTIME_MODE=production ./run.sh serve` | 返回码 78，副作用前拒绝 | PASS（本机自动化） |
| RT-EXEC-11 | 生产 systemd Runtime Manager | 当前 worker 未安装独立 PA Runtime Manager unit | BLOCKED（交付增强项） |
| RT-EXEC-12 | 缺少 bwrap/systemd-run 等强制能力 | fail-closed 单测通过；worker 缺能力注入未执行 | PASS（本机）；worker NOT RUN |

## 4. Worker 执行顺序

```bash
# 1. 同步 securityd 与 PA 改动，重启 securityd 后再启动 PA；PA 必须使用正确配置和 bwrap 入口
cd /home/bianbu/bnsec-testkit/scripts
./start-bianbu-securityd.sh --restart
./start-bianbu-agent.sh --stop || true
BA_UV_NO_SYNC=1 BA_CONFIG=.bianbu-agent/config.yaml BIANBU_SANDBOX=agent ./start-bianbu-agent.sh

# 2. Security Runtime D-Bus
cd /home/bianbu/impl/bianbu-securityd
/usr/lib/bianbu-securityd/venv/bin/python -m pytest -q \
  tests/unit/test_runtime_policy.py tests/unit/test_runtime_lease.py tests/unit/test_runtime_engine.py
BIANBU_SEC_ROOT=/var/tmp/bnsec-runtime-worker \
PYTHONPATH=/home/bianbu/impl/bianbu-securityd:/home/bianbu/impl/bianbu-securityd/client \
dbus-run-session -- /usr/bin/python3 tests/integration/runtime_security_dbus.py

# 3. PA Runtime 定向
cd /home/bianbu/bianbu-agent
./.venv/bin/python -m pytest -q \
  tests/runtime/test_security_skill_dlp.py \
  tests/runtime/test_security_runtime.py \
  tests/runtime/test_execution_runtime.py \
  tests/runtime/test_service.py tests/test_run_script.py \
  tests/sdk/test_dependency_boundary.py tests/sdk/test_default_engine.py

# 4. 外部可观测证据
ss -ltnp | grep -E '9899|127\.0\.0\.1'
systemctl --user list-units 'bianbu-agent-*.service'
cat ~/.bianbu-agent/runtime/executions.json
```

如果 worker 副本没有本轮新增测试文件，先同步整个 PA Runtime 相关文件；不能只重启
旧服务后把旧代码结果记为本轮证据。securityd 代码变更必须重启对应 service。

## 5. 本轮真实 worker 证据

| 项 | 结果 |
|---|---|
| securityd 正式 unit | `active (running)`；UDS `/run/bianbu/securityd.sock` 为 `bianbu-security:bianbu-security`、模式 `660` |
| securityd 定向测试 | `53 passed`（正式 `/usr/lib/bianbu-securityd/venv`） |
| Runtime D-Bus 生命周期 | `SECURITY_RUNTIME_DBUS_PASS` |
| PA Runtime 定向 | `42 passed, 1 warning` |
| PA 启动方式 | `.bianbu-agent/config.yaml` + `BIANBU_SANDBOX=agent` + `run.sh`/bwrap；HTTP `200` |
| testkit 端到端 | `35 passed, 0 failed, 0 error`，最新 worker 运行耗时 `37.6s` |
| DLP/Skill 身份 | PA 以 `BIANBU_PA_AGENT_ID=com.bianbu.agent` 绑定 securityd；Skill DLP 使用同一 Security 身份，未再出现 `personal-agent-default` caller 拒绝 |
| 失败集合 | 空；旧配置、PA 未重启和未绑定测试夹具产生的失败均不纳入最终结果 |

本轮 worker 代码一致性还以关键文件 SHA-256 复核：PA Runtime 的
`run.sh`、`security_runtime.py`、`execution_runtime.py`、`server/runtime.py`、
`pyproject.toml`、`uv.lock` 与开发机 `e0966a15360d1c61d93b02fd79cd85251db45011`
工作区一致；Security Runtime 三个实现文件与已安装 `/usr/lib/bianbu-securityd`
副本一致。

## 6. 交付结论

当前证据证明：Security Runtime 控制面、PA 执行器核心逻辑、bwrap sandbox 入口、
正式 UDS/DLP、判权、审计和 35 项端到端安全接入均已在 worker 验收通过。报告不把
未实测的独立 host child、OCI、完整 egress broker、生产 PA Runtime Manager、
长期 soak 和升级回滚宣称为商用 PASS；这些项目仍列为 NOT RUN/BLOCKED。

部署注意：当前 `bianbu-agent-runtime` 的锁文件仍声明外部
`../bianbu-agent-memory/sdk/python`（`bianbu-agent-memory-sdk`）源码依赖，worker
上未部署该目录。因此本轮 PA 使用既有冻结 venv 并设置 `UV_NO_SYNC=1` 完成安全
验收；正式安装包交付前必须提供该 SDK/`bianbu-agent-memoryd` 安装物，或由 PA
Runtime 发布版本明确移除该外部路径。不能把 `UV_NO_SYNC=1` 作为商用安装方案。

本轮最终提交：Security 仓提交后记录 `origin/master` 最终 hash；PA Runtime 为
`e0966a15360d1c61d93b02fd79cd85251db45011`（已推送 `origin/main`）。
