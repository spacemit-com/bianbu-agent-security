# Bianbu Security PA-inclusive 长期测试继续验收记录

| 项 | 内容 |
|----|------|
| 文档编号 | BN-SEC-ACCEPT-003 |
| 版本 | V1.2 |
| 验收日期 | 2026-08-17 |
| 验收平台 | worker `10.0.90.243`，SpacemiT K3 riscv64 |
| 验收对象 | `impl/bianbu-securityd/`、`testkit/` 及 Personal Agent 安全接入 |
| 对应改动 | 商用 soak v2、PA canary、商用门禁和启动 fail-closed |
| 验收结论 | Security 功能和自动化门禁通过；PA-inclusive 长期可靠性和最终商用签收未通过 |

## 1. 本次处理

此前 worker 上同时存在一个遗留开发 securityd 进程和一个 systemd 生产实例。开发
进程占用了 `io.bianbu.Security`，导致测试写入开发目录而 testkit 读取生产审计目录，
表现为 `HOOK-03`、`AUDIT-01` 失败。本次只终止明确的遗留 PID `1536131`，未触碰
范围外服务；随后重启 `bianbu-securityd.service`，确认唯一总线 owner 等于 systemd
`MainPID`（本次为 `1547995`）。PA 也按操作手册重启。

## 2. 已验证结果

| 项目 | 结果 | 判定 |
|------|------|------|
| testkit 全量 | `35/35`，0 失败 | 通过 |
| securityd 默认全量 | `557 passed / 3 skipped` | 通过 |
| Token Runtime 消费链 | `TOKEN_RUNTIME_E2E_PASS` | 通过 |
| hermetic Security 发布入口 | `SECURITY_RELEASE_GATE_PASS` | 通过 |
| Security 责任域状态 | `security_scope_status=passed` | 通过 |
| 全产品状态 | `product_status=blocked_external` | 仅范围外 doctor/Runtime 集成阻断 |
| v2 专项测试 | `34 passed`（worker 预检） | 通过 |
| 当前真实 E2E 复验 | `35/35` | 通过；唯一生产 securityd owner + PA 9899 |

testkit 运行时确认 PA 真实进程、9899 HTTP 端口、securityd 系统总线均参与。测试中
出现的未签名 demo hook 和缺失远端 MCP 配置均按既有 warn/从严策略记录，不是测试失败。

## 3. 商用 soak v2 变化

商用执行器报告格式升级为 `bianbu-security-commercial-soak-v2`，每 6 小时真实执行
一次 PA canary。每次 canary 必须完成以下闭环：

1. PA 创建一个新的 run；
2. PA 真实调用 `bianbu.memory/memory` 一次；
3. run 返回正的 `total_tokens`，且 securityd Token 日用量或会话用量发生对应增长；
4. Security 审计中出现该时间窗口内的 `mcp.*` `check_permission`；
5. run、session、Token 和判权审计样本写入报告。

最终门禁要求至少 12 次 canary 全部成功，Token 计量和 MCP 判权审计不得缺样本。旧的
Security-only `bianbu-security-commercial-soak-v1` 报告会被门禁拒绝。启动脚本在正式
创建后台进程前检查 `systemctl is-system-running` 和 transient service 列表，不是
`running`（例如 `degraded`）或存在 `activating/failed` service 都直接 fail-closed。

Token 超限职责没有变化：Securityd 只拒绝当前调用、写审计并发送
`TokenExceededV2`；不停止服务、不关闭 Runtime，也不代替 Runtime/agent 执行暂停。
兼容接口 `MeterTokens` 因没有 `run_id` 只发送旧 `TokenExceeded`；只有
`MeterTokensV2` 提供非空 `session_id/run_id` 后才发送 Runtime/agent 可消费的
`TokenExceededV2`，防止空上下文误暂停其他 run。

## 4. PA-inclusive 预演

| 时长 | Security 样本 | PA canary | Token/审计 | P99 | 结论 |
|------|---------------:|----------:|------------:|----:|------|
| 180 s | 36 | 3/3 | Token 3/3，MCP 审计 3/3 | `24.809 ms` | P99 失败 |
| 600 s | 120 | 2/2 | Token 2/2，MCP 审计 2/2 | `12.159528 ms` | P99 失败 |

600 秒结果补充：PA token 总量 `182400`，securityd RSS 增长 `0.078 MB`，审计链完整，
服务零重启。多个 P99 超限样本与 worker 范围外 `hermes-agent` 权限错误重启窗口重合。
`hermes-agent` 不属于本项目，本次没有停止、修改或复用它；该预演不能冒充正式 72 小时
通过证据。

## 5. 当前阻断与下一步

本轮启动检查时 worker 的 `systemctl is-system-running` 为 `running`，但 transient
service 检查发现范围外 `hermes-agent.service` 处于 `activating/auto-restart`，因此
启动器按新门禁拒绝创建长测进程。实际输出为：

```text
COMMERCIAL_SOAK_START_FAIL systemd_transient_units=hermes-agent.service
```

正式 72 小时任务仍必须等 worker/相关服务所有者清理并观察重启风暴后再启动，避免共享环境污染
长期证据。启动后必须保存 24h 和 72h 里程碑、完整 `report.samples.jsonl`、报告哈希、
PA canary 样本和 systemd 状态；最终要求 `status=passed`、`failures=[]`、P99≤10 ms、
RSS≤64 MB、0 error、审计/SSE/systemd 全绿。

### 5.1 外部 owner 交接诊断（只读）

2026-08-17 15:02（UTC+8）只读采集到 `hermes-agent.service`：

| 项 | 实测值 |
|----|--------|
| Unit | `/usr/lib/systemd/system/hermes-agent.service` |
| User/Group | `hermes/hermes` |
| Restart | `on-failure`，`RestartSec=10s` |
| 失败原因 | `PermissionError: [Errno 13] Permission denied` |
| 失败路径 | `/var/lib/hermes-agent/.hermes/profiles/emp-ed50f4484378/.env` |
| 重启计数 | `NRestarts=48422`（采集时；之后仍在增长） |

该 unit、目录权限和 Hermes 代码均属于范围外，本项目未修改、停止或复用。外部 owner
需修复其运行用户对配置路径的访问并观察 `NRestarts` 不再增长；随后本项目才能重新
执行启动器前置检查并开始正式 72 小时测试。

长期报告完成后，仍需组织级 CA 安装/轮换/吊销/恢复、真实桌面 seat 四路径、第三方渗透、
双人审批和组织 Ed25519 签名。上述证据齐全并输出
`COMMERCIAL_ACCEPTANCE_PASS` 前，项目只能称为 Security 商用候选，不能称为最终 GA。
