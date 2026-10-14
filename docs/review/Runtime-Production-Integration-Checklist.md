# 正式 Agent Runtime 生产接入验收清单

本清单用于关闭 Security 评审中的 P0-01/P0-05、P1-01/P1-02；不把
`RuntimeSecurityBridge` 或私有 D-Bus 测试误认为正式 runtimed 已接入。

> 本清单是交给 Runtime/系统集成责任方的外部验收输入，不是本次 Security 交付待开发
> 清单。`/data/workspace2026-new/work0618/bianbu-next-agentos-dev-cc` 不在本次交付范围，
> 不得修改、安装或把其测试结果计入本项目完成度。

## 必须交付的配置

| 项目 | 证据 | 验收标准 |
|------|------|----------|
| systemd unit | `systemctl show <unit>` | `ActiveState=active`、`MainPID>0`、`User` 与部署矩阵一致 |
| caller 身份 | Security `BindAgentV2` 审计 | UID、executable、cgroup、session/run 与 unit 归属一致 |
| Runtime bridge | `runtime/runtime_service.py` 或外部 Runtime 构建产物 | 订阅 `TokenExceededV2`，模型和工具入口都调用门禁 |
| Token 超限 | 真实 D-Bus E2E | `MeterTokensV2` 使用非空 session/run；仅 `used > limit` 的合法事件可使 Runtime 进入 `PAUSED/TERMINATED`，后续调用拒绝 |
| 网络强制 | `systemctl show` + allow/deny probe | `IPAddressDeny=any`、白名单允许、非白名单阻断，并登记 `enforced=true` |
| 资源强制 | `systemctl show` + OOM probe | MemoryMax/CPUQuota/TasksMax/IOWeight 生效，OOM 状态可观测 |
| 管理授权 | polkit/桌面 seat 日志 | 非管理员拒绝，已认证管理员可执行管理方法 |

## 本仓库已交付的 Runtime 适配资产

| 资产 | 路径 | 边界 |
|------|------|------|
| Runtime 事件消费者 | `impl/bianbu-securityd/client/runtime_security_consumer.py` | 运行在 Runtime/agent 进程内；校验 V2 字段、策略版本、agent/session/run，持久化幂等并提供模型/工具门禁 |
| PA 集成适配 | `../personal-agent/bianbu_agent/service_runtime.py` | PA 启动时以自身 sender 建立 V1 稳定身份绑定，用于当前 PA E2E；不具备正式 runtimed unit、V2 run FSM 和生产身份矩阵，不能作为 P0-01/P0-05 关闭证据 |
| systemd unit 模板 | `impl/bianbu-securityd/deploy/bianbu-agent-runtimed.service` | 提供 runtime 用户、`bianbu-security` 补充组、资源/文件系统加固；`ExecStart` 二进制由 Runtime 发布物提供 |
| 接入约定 | `impl/bianbu-securityd/deploy/agent-runtimed-security-integration.md` | 规定 BindAgentV2、事件消费、状态回调和生产关闭证据 |
| 跨进程验收 | `impl/bianbu-securityd/tests/integration/token_runtime_e2e.py` | worker 私有 D-Bus 验证 `MeterTokensV2 → TokenExceededV2 → Runtime consumer → PAUSED → model/tool 拒绝` |
| 外部 Runtime 契约验收 | `impl/bianbu-securityd/tests/integration/external_runtime_security_e2e.py` | 必须显式传入仓外 Runtime 根；验证 Runtime 自身 sender/FSM/model-tool 门禁/重启恢复。候选来源为参考实现时只能证明契约，不计生产关闭 |
| 只读生产探针 | `impl/bianbu-securityd/deploy/runtime_production_probe.py --json` | 真实 unit/UID/cgroup/PID 与 `io.bianbu.Runtime` 方法集合均满足才返回 0；缺失时返回 2 并保持 fail-closed |
| 参考 Runtime 服务 | `runtime/runtime_service.py` + `data/io.bianbu.Runtime.xml` | 仓库内可部署参考实现；`RUNTIME_SERVICE_E2E_PASS` 只证明参考服务，不替代生产镜像身份验收 |

## 关闭条件

所有行均需保存命令输出、时间、镜像版本和责任人；本仓库适配层通过不等于正式
Runtime 二进制已部署。任意生产证据缺失时，发布状态
保持“商用候选/不通过 GA”。Securityd 不调用 Runtime 的 Pause/Stop，停止和
暂停动作由 Runtime 自身执行。

2026-08-14 已在 Runtime 不存在的 worker 生产总线上完成 Security-only Token 超限验证：
`MeterTokensV2` 返回 `within=false` 并收到字段完整的 `TokenExceededV2`，结果为
`SECURITY_TOKEN_NOTIFY_ONLY_PASS`。这关闭 Securityd 的通知、审计和当前计量拒绝职责；
Runtime 的真实暂停/终止仍由外部 Runtime/agent 交付。正式 Runtime 未安装时，
`runtime_production_probe.py` 必须继续阻断。
