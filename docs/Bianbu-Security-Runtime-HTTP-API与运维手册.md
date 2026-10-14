# Bianbu Agent Runtime HTTP API 与运维手册

| 项 | 内容 |
|---|---|
| 文档编号 | BN-SEC-RUNTIME-HTTP-001 |
| 版本 | V0.1 |
| 来源 | `bianbu-agent-runtime` HTTP API、Security Runtime 商用设计方案 |
| 日期 | 2026-08-20 |
| 状态 | worker 验证可用；生产 Runtime Manager 仍需独立安装包 |
| 适用对象 | PA Runtime 运维、集成测试和安全验收人员 |

## 1. 服务边界与地址

当前生产对接对象是 PA `bianbu-agent-runtime`，不是仓库里的参考
`io.bianbu.Runtime` 服务。PA 通过 `io.bianbu.Security.Runtime` 请求启动租约，
再由自己的 `ExecutionCoordinator` 创建和回收 Agent child。

| 服务 | 地址/接口 | 用途 |
|---|---|---|
| PA Runtime | `http://10.0.90.243:9899` | 对话、Run 和 child lifecycle HTTP API |
| Security WebUI | worker `http://127.0.0.1:8787` | 策略、能力、DLP、审计运维；默认只监听回环 |
| testkit WebUI | `http://10.0.90.243:9700` | 测试进度和报告 |
| securityd D-Bus | `io.bianbu.Security` | 判权、确认、DLP、Token、审计 |
| securityd Runtime | `/io/bianbu/Security/Runtime`，接口 `io.bianbu.Security.Runtime` | Prepare/Commit/Abort/Revoke 租约控制面 |
| securityd UDS | `/run/bianbu/securityd.sock` | PA DLP/审计等大载荷数据面 |

不要把 `0.0.0.0:9899` 写入浏览器地址；对外访问使用 worker IP。开发/demo DEB
的 8787 配置台关闭 Bearer Token，产品包要求管理员 Token；配置台包含 Web Terminal，
禁止使用 `--lan` 长期暴露。

## 2. 启动和健康检查

启动顺序固定为 securityd → PA → WebUI/testkit。worker 开发验证命令如下；
`BA_UV_NO_SYNC=1` 只表示复用既有虚拟环境，不是商用安装方式。

```bash
cd /home/bianbu/bnsec-testkit/scripts
./start-bianbu-securityd.sh --status
./start-bianbu-agent.sh --stop || true
BA_UV_NO_SYNC=1 \
BA_CONFIG=.bianbu-agent/config.yaml \
BIANBU_SANDBOX=agent \
./start-bianbu-agent.sh
```

检查：

```bash
systemctl is-active bianbu-securityd.service
stat -c '%A %U %G %n' /run/bianbu/securityd.sock
curl -fsS http://127.0.0.1:9899/api/v1/agents
ss -ltnp | grep -E ':(8787|9899|9700)\\b'
```

生产环境必须由受信 Runtime Manager/systemd 启动 PA child，并注入：

```text
BIANBU_RUNTIME_MODE=production
BIANBU_RUNTIME_MANAGED=1
BIANBU_SECURITY=1
BIANBU_SEC_UDS=/run/bianbu/securityd.sock
BIANBU_PA_AGENT_ID=com.bianbu.agent
```

生产不得设置 `BIANBU_SECURITY=0`，也不得依赖 `BIANBU_SECURITYD_HOME` 源码根。

## 3. Child 生命周期 API

所有路径前缀为 `/api/v1`。请求模型为严格模型，额外字段返回 422。

### 3.1 启动

```http
POST /api/v1/agents/{agent_id}/executions
Content-Type: application/json
```

允许的 JSON 字段只有：

```json
{
  "requested_mode": "auto",
  "env": {"LANG": "C.UTF-8"},
  "target_port": 8080,
  "listen_port": 18080
}
```

字段说明：

| 字段 | 取值 | 说明 |
|---|---|---|
| `requested_mode` | `auto`/`sandbox`/`host` | 用户偏好，不是授权结果；最终使用 securityd 返回的 `effective_mode` |
| `env` | 最多 32 个键值 | 仅允许策略 `environment_allowlist` 中的键；不能覆盖 Runtime 注入的 Agent 身份 |
| `target_port` | 1–65535 | child 的目标端口；需要代理时必填 |
| `listen_port` | 0–65535 | PA Runtime 在 loopback 上监听的端口；必须同时提供 `target_port` |

客户端禁止提交以下字段：

```text
lease_id、bwrap 参数、mount、seccomp、network、resource
```

这些值必须由已安装 Agent manifest、securityd 策略快照和 Runtime 后端计算。
请求成功返回 HTTP 201：

```json
{
  "data": {
    "instance_id": "com.bianbu.agent-abc123",
    "agent_id": "com.bianbu.agent",
    "backend": "bwrap",
    "pid": 12345,
    "cgroup_path": "/user.slice/...",
    "unit": "",
    "state": "RUNNING",
    "lease_id": "lease-...",
    "started_at": 1787190000.0,
    "sandboxed": true,
    "container_id": "bwrap:12345",
    "reason": "",
    "proxy_port": 18080
  }
}
```

启动事务为 `PrepareStart → 校验 policy/digest/entrypoint → backend.start →
CommitStart`。任一步失败都会停止 child，并在 Commit 前 Abort、Commit 后 Revoke。

### 3.2 查询实例

```http
GET /api/v1/executions
GET /api/v1/executions/{instance_id}
```

状态包括 `STARTING`、`RUNNING`、`STOPPING`、`STOPPED`、`FAILED`、`REVOKED`。
不能由客户端修改。

### 3.3 停止实例

```http
POST /api/v1/executions/{instance_id}/stop
Content-Type: application/json

{"reason": "operator requested stop"}
```

成功返回：

```json
{"data": {"accepted": true}}
```

Runtime 会撤销 loopback 代理、停止后端进程并记录状态；实例不存在返回错误。

### 3.4 撤销 Agent 的全部实例

```http
POST /api/v1/agents/{agent_id}/revoke
Content-Type: application/json

{"reason": "security policy revoked"}
```

该操作作用于 securityd 命名空间的 `agent_id`。PA 本地 `personal-agent-default`
与默认 securityd 身份 `com.bianbu.agent` 不可混用；若调用默认 PA Agent，Runtime
会按 `BIANBU_PA_AGENT_ID` 转换。

## 4. 错误处理

| HTTP/错误 | 含义 | 运维动作 |
|---|---|---|
| 422 | 请求字段未知、端口/环境变量不合法 | 按 OpenAPI 模型删除未声明字段 |
| 404 | Agent 或 instance 不存在 | 查询 `/executions` 和 manifest |
| 409/4xx | lease、digest、caller 或状态冲突 | 检查 securityd 审计，不重试绕过 |
| 503 | securityd/Runtime 不可用 | 检查 systemd、D-Bus、UDS；生产保持 fail-closed |
| `effective_mode=sandbox 但 PA 未在 sandbox` | 裸启动绕过了 bwrap | 使用 `run.sh` 开发入口或受信 Runtime Manager |
| `package/config digest mismatch` | 运行包或配置不是已登记版本 | 重新安装签名包，不手工修改 digest |
| `PermissionDenied: UDS caller 无权代表 agent` | 进程身份与 securityd 绑定不一致 | 确认 `BIANBU_PA_AGENT_ID`，重启 PA 建立绑定 |

## 5. 运维排查命令

```bash
# PA 与 sandbox
cd /home/bianbu/bnsec-testkit/scripts
./start-bianbu-agent.sh --status
ps -eo pid,ppid,stat,cmd | grep -E 'bwrap|bianbu-agent' | grep -v grep
curl -fsS http://127.0.0.1:9899/api/v1/executions

# Security Runtime
systemctl status bianbu-securityd.service --no-pager
busctl --system introspect io.bianbu.Security /io/bianbu/Security/Runtime \
  io.bianbu.Security.Runtime
stat -c '%A %U %G %n' /run/bianbu/securityd.sock
journalctl -u bianbu-securityd.service -n 100 --no-pager

# 审计和测试
cd /home/bianbu/bnsec-testkit
python3 runner.py
cat /var/tmp/bnsec-testrun/report.json
```

若修改 securityd，必须重新执行安装器/重启 `bianbu-securityd.service`；若修改 PA
或插件，必须停止并重新启动 PA。不要只看 HTTP 200：最终安全验收必须同时有
`35 passed / 0 failed / 0 error`、D-Bus/UDS 可用、审计记录和正确 caller binding。

## 6. 发布限制

本版本已在 worker 验证 Security Runtime 控制面、PA sandbox 入口、正式 UDS/DLP、
判权、Token、审计及 35 项 testkit。独立 PA Runtime Manager systemd unit、OCI 后端、
完整 egress broker、长期 soak、升级回滚和生产 Agent Memory SDK 安装物仍是发布前
必须补齐的商用增强项；不得把 `BA_UV_NO_SYNC=1` 或裸 `run.sh` 写成商用安装步骤。
