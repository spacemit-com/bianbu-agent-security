# Agent Security 能力管理端到端开发交付测试方案

**版本：** v1.0  
**范围：** Agent Security 能力管理（Capability Management）从能力目录展示、能力增删改、授权/撤销、判权到 Runtime Worker/WebUI 的完整链路。  
**目标：** 证明能力管理变更能够安全、可追溯、即时地影响 Agent 实际工具调用，并在 Worker 不可用或 Security 不可达时给出明确错误而不是伪造空数据或绕过安全控制。

## 1. 验收范围与架构边界

```text
WebUI / Runtime API
        ↓
Agent Control API（catalog、MCP、Agent 配置）
        ↓
Runtime Worker catalog（tool / skill / hook / MCP）
        ↓
Security client / D-Bus
        ↓
securityd Capability Registry（SQLite WAL）
        ↓
CheckPermission / CheckPermissionV2
        ↓
Runtime Hook → 实际工具调用 → 审计记录
```

能力管理必须区分两类目录：

- Runtime 可调用能力目录：Worker 返回的 tool、skill、hook、MCP；这是“能否被 Agent 使用”的来源。
- Security 权限能力字典：`securityd/capabilities.py` 中的 capability、domain、risk_level、confirm、scope 约束；这是“调用是否获准”的来源。

本方案不允许以 HTTP 200、空数组或前端缓存作为成功证据；每项变更都必须同时验证 API 响应、持久化状态、判权结果、实际下游行为和审计证据。

## 2. 交付前置条件

### 2.1 代码和服务

```bash
SEC=/home/duancheng/workspace/bianbu-agent/bianbu-agent-security
RT=/home/duancheng/workspace/bianbu-agent/bianbu-agent-runtime
cd "$SEC/impl/bianbu-securityd"
```

- 使用待交付 commit，记录两个仓库 `git rev-parse HEAD`。
- Security 控制面使用 session D-Bus：`io.bianbu.Security`。
- Worker 数据面使用 Security UDS；生产验收必须使用受管 Worker 和真实 lease/caller binding。
- 测试 Agent 使用独立 ID，例如 `com.e2e.capability.<timestamp>`，禁止使用真实 Agent 或生产数据库。
- 全部测试值、路径、URL、命令均使用合成数据和临时目录。

### 2.2 环境检查

```bash
date -Is
uname -a
python3 --version
git -C "$SEC" rev-parse HEAD
git -C "$RT" rev-parse HEAD
busctl --user status io.bianbu.Security
test -S "${BIANBU_SEC_UDS:-$HOME/.local/share/bianbu-securityd/run/bianbu/securityd.sock}"
```

若 Security 或 Worker 不可用，应标记为环境失败并验证明确的 `503 worker_unavailable`/fail-closed 行为，不得改用 mock 结果冒充端到端通过。

## 3. 交付测试阶段与计划

| 阶段 | 内容 | 通过门槛 | 产物 |
|---|---|---|---|
| P0 | 静态契约和目录基线 | API、D-Bus 方法、字段、能力字典一致 | 版本和接口清单 |
| P1 | Security Registry 单元/集成 | 持久化、scope、三态判权全部通过 | pytest 日志 |
| P2 | Security WebUI 管理 | 增删改、授权/撤销、判权测试即时生效 | API/浏览器截图或响应 |
| P3 | Runtime Worker 目录 | tool/skill/hook/MCP 真实可读，Worker 不可用不返回空目录 | catalog 响应 |
| P4 | Runtime 工具调用 | ALLOW/CONFIRM/DENY 与真实下游一致 | Run、Hook、下游 payload |
| P5 | 安全和异常 | caller binding、scope 越界、重启、不可达、回滚均安全 | 审计和错误记录 |
| P6 | 发布回归 | 全套测试、安装包、升级/回滚和文档复核 | 验收报告、签字记录 |

建议执行顺序：P0 → P1 → P2 → P3 → P4 → P5 → P6。任一阶段的 P0/P1/P5 失败，停止交付，不进入发布验收。

## 4. 测试用例总览

| 编号 | 用例 | 预期 |
|---|---|---|
| CAP-E2E-01 | 能力字典和工具映射 | 所有配置名来自权威字典，映射可解释 |
| CAP-E2E-02 | Worker 目录读取 | tool/skill/hook/MCP 返回真实可用项 |
| CAP-E2E-03 | Worker 不可用 | 返回 `503 worker_unavailable`，不返回空成功目录 |
| CAP-E2E-04 | 能力新增 | 新能力写入 Registry，字段约束生效 |
| CAP-E2E-05 | 能力编辑 | risk/confirm/scope/granted 修改持久化并即时影响判权 |
| CAP-E2E-06 | 授权/撤销 | ALLOW↔DENY 即时切换，撤销清理 session trust |
| CAP-E2E-07 | 三态判权 | ALLOW、CONFIRM、DENY 与表状态一致 |
| CAP-E2E-08 | scope 最长前缀 | 目录内允许，越界路径拒绝 |
| CAP-E2E-09 | confirm 会话语义 | `once_per_session` 首次确认、同会话复用、跨会话重新确认 |
| CAP-E2E-10 | 实际工具调用 | Hook 判权结果与工具是否真正执行一致 |
| CAP-E2E-11 | Hook/Skill/MCP 管理 | 选中项可用；删除/禁用后不能继续调用 |
| CAP-E2E-12 | caller binding | 不能冒充其他 Agent 读取或修改能力 |
| CAP-E2E-13 | 重启持久化 | securityd/Runtime 重启后配置和目录不丢失 |
| CAP-E2E-14 | 审计完整性 | 每次管理、判权、确认、拒绝均可追溯且哈希链完整 |
| CAP-E2E-15 | 安全不可达 | 高危能力 fail-closed，管理接口返回明确服务错误 |
| CAP-E2E-16 | 回滚和并发 | 失败 reload 不破坏旧 catalog，重复变更幂等 |

## 5. 详细测试步骤

### CAP-E2E-01：能力字典、映射和字段契约

1. 调用 Runtime `GET /api/v1/capabilities/tool`、`/skill`、`/hook`，以及 `GET /api/v1/mcp-servers`。
2. 调用 Security WebUI 映射接口 `GET /api/mapping`，检查 `capabilities` 来自 `securityd/capabilities.py`，而不是仅来自当前工具映射。
3. 对每个可配置 capability 校验 `domain`、`risk_level`、`confirm`、`scope_key` 和摘要；校验未映射工具处置策略为产品配置值（`allow|confirm|deny`）。
4. 用一个不存在的 capability 做新增，记录产品约定：若接口允许自由扩展，必须仍经过字段和风险约束；若只允许权威字典，必须返回 4xx。

**证据：** 响应 JSON、字典版本、未知能力的错误码；不得只截图页面。

### CAP-E2E-02/03：Worker 能力目录和不可用状态

1. 在真实 Worker 已启动时读取四个 catalog，确认返回项含稳定 ID、名称、来源、可用状态和 revision。
2. 对目录中的一个 tool、skill、hook、MCP 分别执行一次“可选择/可调用性”检查。
3. 停止或隔离测试 Worker，再次读取目录；预期 HTTP `503`，错误码为 `worker_unavailable`，消息说明原因。
4. 确认前端展示“Worker 不可用”，而不是“暂无内置工具”；恢复 Worker 后刷新，目录恢复且 revision 可比较。

**禁止：** Worker 不可用时用 `[]` 返回 200；这会把故障伪装成没有能力。

### CAP-E2E-04/05：新增和编辑能力

使用测试 Agent `com.e2e.capability.test`，新增：

```json
{
  "capability": "file.write",
  "domain": "resource",
  "risk_level": "L3",
  "confirm": "once_per_session",
  "scope": "/tmp/e2e-capability",
  "granted": 0
}
```

1. WebUI/API 新增后调用 Agent 能力列表或 D-Bus `GetCapabilities`，确认记录包含全部字段。
2. 查询 SQLite 仅用于测试证据，正式操作必须经 API/D-Bus，不得让 WebUI 直连数据库。
3. 修改 `granted=1`、`confirm=always`、scope 为子目录；再次 `GetCapabilities` 和 `CheckPermission`。
4. 重复提交同一 `(agent_id, capability, scope)`，确认 ON CONFLICT 更新而非产生重复记录。
5. 测试非法 `risk_level`、`confirm`、`granted`、空 capability、空 Agent ID；预期明确 4xx/协议错误且不落库。

### CAP-E2E-06/07：授权、撤销与三态判权

对同一能力准备三条记录：

| 状态 | 配置 | `CheckPermission` |
|---|---|---|
| 授权信任 | `granted=1, confirm=trusted` | `0 ALLOW` |
| 需确认 | `granted=1, confirm=always` | `1 CONFIRM` |
| 撤销 | `granted=0` 或 `-1` | `2 DENY` |

1. 通过 `POST /api/agents/<id>/capabilities/grant` 或 Security client 修改状态。
2. 通过 D-Bus `CheckPermission`/`CheckPermissionV2` 验证数值和 Runtime Hook 的 `ALLOW/CONFIRM/BLOCK` 映射。
3. 撤销后立即重复同一 session 请求，必须 DENY；不能因旧 `session_trust` 缓存继续 ALLOW。
4. 对 L4 能力确认“始终需要确认”的产品约束，不能通过 `trusted` 绕过。

### CAP-E2E-08：scope 越界与最长前缀

配置：`/tmp/e2e-capability` 允许，`/tmp/e2e-capability/private` 撤销。

1. 请求 `/tmp/e2e-capability/a.txt`：预期 ALLOW/对应确认。
2. 请求 `/tmp/e2e-capability/private/a.txt`：预期使用更长匹配并 DENY。
3. 请求 `/etc/passwd`：无匹配，预期 DENY。
4. 使用 `..`、符号链接、相对路径和路径大小写变体，确认 canonicalization 后不能逃逸授权目录。

### CAP-E2E-09：确认和会话信任

1. `confirm=once_per_session` 首次调用，预期 `CONFIRM` 并产生唯一 request ID。
2. 模拟批准后，同一 session、同一 capability/scope 再调用，预期 `ALLOW` 且不重复弹窗。
3. 新建 session 再调用，预期重新 `CONFIRM`。
4. 撤销能力、注销 Agent 或 securityd 重启后，旧 trust 不得继续放行。
5. 确认超时、拒绝、重复响应和未知 request ID 均应幂等且审计。

### CAP-E2E-10：真实工具调用和下游结果

1. 选择映射到 `file.write` 或 `system.execute` 的真实测试工具，使用测试目录和无害命令。
2. 先设 `granted=1/confirm=trusted`，确认工具实际执行并生成成功结果。
3. 改为 `confirm=always`，确认 UI/事件收到确认，未批准前下游没有执行。
4. 改为 `granted=0`，确认 Hook 返回 `BLOCK`/安全拒绝，下游没有收到原始参数。
5. 检查每次调用的 hook trace 至少包含 `sec_capability`、决策、能力、scope、耗时和审计引用。
6. 对 DLP 保护的工具参数，额外确认 capability 通过不等于绕过 DLP；DLP 和 audit hook 仍执行。

### CAP-E2E-11：Tool/Skill/Hook/MCP 管理

1. 安装一个最小测试 Plugin/MCP，确认新增后 Worker reload 和 catalog revision 变化。
2. 在 Agent 配置中选择 tool、skill、hook；提交非法 ID，必须在控制面拒绝。
3. 删除/禁用该包后 reload，目录不再声明可用，旧 Run 不能继续调用已删除项。
4. MCP server 的新增、读取、删除分别检查 catalog、启动参数、网络域名策略和审计。
5. reload 失败时确认旧 catalog 保持可用，错误返回 `worker_unavailable` 或明确 reload 错误，不产生半更新目录。

### CAP-E2E-12：身份绑定和越权

1. Agent A 注册能力，Agent B 仅拥有自己的能力。
2. 用 A 的 session/worker 身份读取 B 的能力、调用 B 的 scope、修改 B 的 granted；全部应拒绝。
3. 伪造或缺失 caller binding，验证 D-Bus sender、lease、Agent ID 三者不一致时拒绝。
4. 确认审计记录保存被拒请求和真实 caller，不记录可被伪造的前端 Agent ID 作为唯一身份。

### CAP-E2E-13/14：重启、持久化和审计

1. 记录重启前 `GetCapabilities`、目录 revision 和审计最大序号。
2. 重启 securityd，再重启 Worker/Runtime；重新查询能力和 catalog，内容应保持一致。
3. 重放带 `_request_id` 的管理或审计请求，确认幂等，不产生重复授权或重复审计记录。
4. 导出审计并验证哈希链；至少覆盖新增、编辑、授权、撤销、判权 ALLOW/CONFIRM/DENY、确认批准/拒绝和 reload。

### CAP-E2E-15：Security/Worker 不可达和 fail-closed

1. 在隔离环境停止 Security UDS 或 session D-Bus，不能影响生产实例。
2. 发起 L3/L4 工具调用，预期明确拒绝/fail-closed，不得将高危请求 fail-open。
3. 读取能力目录和管理 API，预期 503/`security_unavailable` 或 `worker_unavailable`，不能返回过期或空成功数据。
4. 恢复 Security 后确认服务重连、Worker 重新绑定、旧 lease 不被错误复用；再次调用恢复正常。

### CAP-E2E-16：并发、失败回滚和发布

1. 并发提交同一能力的 grant/revoke，最终状态符合串行化规则，数据库无重复主键。
2. 并发 reload、删除 MCP/Plugin 和读取 catalog，任何时刻不发布半截快照。
3. 模拟安装/签名/manifest 校验失败，确认旧版本能力和 Worker 目录仍可用。
4. 执行升级前后完整回归，验证 schema migration、旧 manifest、旧 client ABI 和回滚包。

## 6. 自动化命令清单

### Security

```bash
cd "$SEC/impl/bianbu-securityd"
.venv/bin/pytest -q tests/unit/test_capability_registry.py
.venv/bin/pytest -q tests/unit/test_hook_hermes.py tests/unit/test_interceptor.py
.venv/bin/pytest -q tests/unit/test_webui_connection_monitor.py tests/unit/test_uds.py
python3 tests/integration/hook_audit_e2e.py
python3 tests/integration/uds_service_e2e.py
```

### Runtime

```bash
cd "$RT"
.venv/bin/pytest -q tests/sdk/api/test_capabilities.py \
  tests/sdk/api/test_control_catalog.py \
  tests/sdk/api/test_mcp_servers.py \
  tests/runtime/test_worker_rpc.py \
  tests/runtime/test_service.py
```

### 真实开发启动

```bash
cd "$RT"
./run-security-amd.sh
```

验收记录至少保存：启动日志、`/api/v1/runtime/status`、`/api/v1/runtime/workers`、四个 catalog API、相关 Run/session ID、Security 审计导出和测试前后数据库摘要。若出现 `development optional host fallback`，必须标记为“开发态主机降级”，不能宣称 sandbox Worker 通过。

## 7. 交付验收门槛

- P0/P1/P5 所有用例通过；无未解释的失败或 flaky 测试。
- 未授权能力实际拦截率 100%；scope 越界无绕过路径。
- Worker 不可用时 API 明确报错，不返回空目录伪成功。
- 能力修改在下一次判权立即生效；撤销清除 session trust。
- 管理、判权、确认、拒绝和 reload 均有可验证审计，哈希链完整。
- Security/Runtime 重启和升级回滚后能力与目录不丢失。
- 生产验收必须使用受管 Worker/sandbox；`unmanaged host-process` 只能作为开发调试降级。
- 报告包含通过/失败/阻塞项、环境信息、命令输出摘要、风险和遗留项；未覆盖项不得写成通过。

## 8. 测试交付物和签字清单

```text
[ ] 版本、依赖和启动环境记录
[ ] 能力字典/工具映射快照
[ ] Security Registry、D-Bus、UDS 测试日志
[ ] WebUI/API 增删改授权撤销证据
[ ] Worker 四类 catalog 和不可用状态证据
[ ] ALLOW/CONFIRM/DENY 实际工具下游证据
[ ] scope、caller binding、session trust 安全证据
[ ] 审计导出与哈希链验证结果
[ ] 重启、升级、回滚和 fail-closed 结果
[ ] 已知限制、风险接受和专机复验记录
[ ] 最终验收报告与发布签字
```

## 9. 缺陷分级与处理规则

| 等级 | 示例 | 交付规则 |
|---|---|---|
| Blocker | 未授权工具可执行、caller 可冒充、L3/L4 fail-open、审计链断裂 | 禁止交付 |
| Critical | 能力撤销不即时生效、scope 越界、Worker 不可用返回空成功目录 | 禁止生产交付，修复后全量回归 |
| Major | WebUI 字段显示错误、reload 后目录短暂不一致、审计字段缺失 | 需风险评估和明确修复计划 |
| Minor | 文案、排序、非关键展示问题 | 可带已知问题交付，但不得影响安全语义 |

## 10. 最终报告模板

每次版本验收复制本节并填写：

```text
版本：
Security commit：
Runtime commit：
环境/架构：
securityd 传输：D-Bus / UDS
Worker backend：sandbox / host-process（开发降级）

通过：CAP-E2E-__、...
失败：CAP-E2E-__、...
阻塞：CAP-E2E-__、...

授权/撤销即时性：
未授权拦截率：
Worker 不可用错误码：
审计链验证：
升级/回滚：
遗留风险及负责人：
验收结论：通过 / 有条件通过 / 不通过
```
