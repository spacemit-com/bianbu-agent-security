# Agent Security 能力管理与 DLP 验收报告

## 1. 验收结论

在 Worker `10.0.90.243` 的最新安装环境上，能力管理、判权、能力映射、DLP、数据出境和安全错误透传专项共 18 项全部通过；配套 securityd 定向单元测试 71 项全部通过。

本报告的 E2E 结果来自真实 Runtime、securityd D-Bus/UDS 和生产审计链，不使用开发机 fallback。`SKILL-01` 曾因测试进程注入 fake client 的模块适配问题报 `securityd_unavailable`，不属于本次 18 项核心验收；该问题单独记录在第 6 节，未被伪装成通过。

## 2. 版本与环境

| 项目 | 实际值 |
|---|---|
| Worker | `10.0.90.243`，riscv64 |
| Security 包 | `bianbu-agent-securityd 0.1.29` |
| Runtime 包 | `bianbu-agent-runtime 0.1.30` |
| Runtime 源码 | `/var/tmp/bnsec-latest-build.VIyWDe/runtime` |
| Security 源码 | `/var/tmp/bnsec-latest-build.VIyWDe/security/impl/bianbu-securityd` |
| Testkit | `/home/bianbu/bnsec-testkit` |
| Agent ID | `com.bianbu.c6f40f30a6e5` |
| E2E 报告 | `/var/tmp/bnsec-testrun/report.json` |

## 3. E2E 执行与结果

执行命令：

```bash
cd /home/bianbu/bnsec-testkit
PA_ROOT=/var/tmp/bnsec-latest-build.VIyWDe/runtime \
BIANBU_SECURITYD_HOME=/var/tmp/bnsec-latest-build.VIyWDe/security/impl/bianbu-securityd \
PA_AGENT_ID=com.bianbu.c6f40f30a6e5 \
BIANBU_PA_AGENT_ID=com.bianbu.c6f40f30a6e5 \
python3 runner.py \
  PERM-01 PERM-02 PERM-03 PERM-04 YOLO-01 \
  CAP-01 CAP-02 CAP-03 CAP-04 MCP-01 SCOPE-01 CODE-01 \
  DLP-01 DLP-02 DLP-03 DLP-04 EGRESS-01 ERR-01
```

结果：`18 passed / 0 failed / 0 error`，耗时 17.9 秒。

| 类别 | 用例 | 结果 |
|---|---|---|
| 能力注册与三态判权 | `PERM-01~04` | 4/4 PASS |
| YOLO 模式 | `YOLO-01` | 1/1 PASS |
| 能力词汇和映射 | `CAP-01~04` | 4/4 PASS |
| MCP、scope、签名 | `MCP-01`、`SCOPE-01`、`CODE-01` | 3/3 PASS |
| DLP 核心 | `DLP-01~04` | 4/4 PASS |
| 数据出境与错误透传 | `EGRESS-01`、`ERR-01` | 2/2 PASS |
| **合计** | **18 项** | **18/18 PASS** |

## 4. 能力管理验证明细

| 用例 | 验证内容 | 结果证据 |
|---|---|---|
| `PERM-01` | 注册能力后可查询，能力名和属性持久化 | 4 个测试能力登记并可查，PASS |
| `PERM-02` | ALLOW、CONFIRM、DENY 三态判权 | 已授权能力 ALLOW，高风险能力 CONFIRM，未注册能力 DENY，PASS |
| `PERM-03` | L3/L4 能力禁止 `confirm=trusted` | 非法组合被 securityd 拒绝，PASS |
| `PERM-04` | 撤销授权后判权立即变为 DENY | 撤销后真实 `CheckPermission` 返回 DENY，PASS |
| `YOLO-01` | YOLO 对撤销和未知能力放行且逐次审计，切回 normal 恢复原策略 | 放行、审计、恢复三段均通过，PASS |
| `CAP-01` | 四张映射表引用的能力均存在于权威字典 | 无字典外能力、无悬空别名，PASS |
| `CAP-02` | MCP 按 server 身份判权，工具名不能绕过 | 不同工具名均归入 `mcp.<server>` 能力边界，PASS |
| `CAP-03` | 多个关键词命中时选择最高风险能力 | 高风险映射优先，PASS |
| `CAP-04` | 未映射工具默认交用户确认 | 未映射能力为 `unknown.tool`，默认 CONFIRM，不静默放行，PASS |
| `MCP-01` | 未授权 MCP server fail-closed 并登记待授权 | 拦截、登记待授权、恢复授权路径均通过，PASS |
| `SCOPE-01` | `system.execute` 命令级 scope 与复合命令保护 | 允许/拒绝和复合命令不假放行均通过，PASS |
| `CODE-01` | Hook、Tool、Skill 安装期签名校验 | 有效签名放行，篡改/缺签名按策略处理，PASS |

## 5. DLP 验证明细

| 用例 | 验证内容 | 结果证据 |
|---|---|---|
| `DLP-01` | 8 类 PII 实体检测覆盖 | 8 类实体均检出，PASS |
| `DLP-02` | 身份证、银行卡校验和及 BIN 前缀防误报 | 合法值检出，非法校验值不误报，PASS |
| `DLP-03` | 逐字泄露双信号检测 | 追加字符后仍可识别，PASS |
| `DLP-04` | 大载荷走正式 UDS 与中央策略 | 大于 4 KB 文本产生正式 `dlp.scan` 审计；大于 1 KB 治理载荷走 `audit.batch`；中央 BLOCK 策略真实生效，PASS |
| `EGRESS-01` | 远端 MCP 数据出境提档 | 远端出境由低风险路径提档至确认，PASS |
| `ERR-01` | 安全拦截原因透传到前端 | 返回结构化安全错误（如 `network_policy_blocked`），不是通用发送失败，PASS |

DLP 动作覆盖 `allow`、`audit_only`、`mask`、`block`：原文放行、审计放行、脱敏后放行和阻断均由 E2E/handler 断言覆盖。

## 6. 独立 securityd 单元测试

执行命令：

```bash
cd /var/tmp/bnsec-latest-build.VIyWDe/security/impl/bianbu-securityd
/usr/bin/python3 -m pytest -q --import-mode=importlib \
  tests/unit/test_agent_security_mode.py \
  tests/unit/test_dlp_policy.py \
  tests/unit/test_dlp_handlers.py \
  tests/test_syscall_policy.py
```

结果：`71 passed in 1.18s`。

覆盖 Agent security mode、DLP 策略回退和优先级、策略持久化、DLP handler、syscall policy 合并与保护规则。

### SKILL-01 测试适配器问题

`SKILL-01` 单项在当前 Worker 上得到：`SkillTextRejected(... securityd_unavailable)`。它在加载 `security_skill_dlp.py` 时未拿到测试注入的 fake client，因此没有进入 DLP finding、mask 或 block 断言。securityd UDS 本身存在且服务 active；同一轮中的 `DLP-01~04`、`EGRESS-01` 均通过。

该问题属于测试进程的模块导入/客户端注入隔离缺陷，不能作为 DLP 功能通过证据，也不影响本报告 18 项核心验收结论。后续应修复测试夹具后重新执行 `SKILL-01`，再关闭完整 DLP 回归门禁。

## 7. Worker 状态与恢复检查

- `bianbu-securityd.service`、`bianbu-syscall-observer.service`、`bianbu-agent-network-learning.service`、`bianbu-agent-runtime@bianbu.service`、`bianbu-security-webui.service` 全部为 `active`。
- Runtime `127.0.0.1:9899` 和 Security WebUI `127.0.0.1:8788` 均返回 HTTP 200。
- 网络策略已恢复为 `allow_all`，当前实例已应用，`restart_required=false`。
- Agent security mode 已恢复为 `yolo`。
- syscall audit 为 `active`，backend 为 `ebpf-seccomp`，`chain_valid=true`。

## 8. 最终判定

**能力管理与 DLP 核心功能验收 PASS：18/18 项 E2E 通过，相关 securityd 单测 71/71 通过。**

`SKILL-01` 的测试适配器异常已明确隔离并记录；在修复该夹具前，不应宣称 Security 全量测试门禁完全关闭。
