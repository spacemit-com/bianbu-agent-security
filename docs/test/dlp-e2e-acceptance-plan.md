# DLP 端到端测试与验收计划

**状态：已执行；结果见 `dlp-e2e-acceptance-report.md`**  
**范围：** `bianbu-agent-security` 及其与 Agent Runtime 的真实 DLP 链路  
**目标：** 验证四种策略动作的完整语义：

- `allow`：放行，不因 DLP 阻断；
- `audit_only`：放行并产生 DLP 审计记录；
- `mask`：敏感内容脱敏后继续，下游不得看到原文；
- `block`：拒绝，下游不得收到敏感原文。

## 1. 测试目标与验收边界

本轮验收不只验证策略存储或 WebUI 试扫，而是验证以下链路：

```text
策略配置（WebUI / D-Bus）
        ↓
SQLite 策略存储与 effective fallback
        ↓
Security UDS DLP 数据面
        ↓
Runtime Worker 的输入、模型、工具和输出 Hook
        ↓
下游可见内容、Run 结果、DLP 审计和完整审计链
```

必须确认策略对至少一个独立测试 Agent 生效，并覆盖：

1. 策略写入、读取、删除及实时生效；
2. Agent 精确策略、Agent `*` 默认策略、全局 `*` 默认策略和系统兜底回退；
3. `INPUT`、`PRE_MODEL_CALL`、`PRE_TOOL_CALL`、`POST_TOOL_CALL`、`OUTPUT` 等实际干预点；
4. `allow/audit_only/mask/block` 的下游可见性和审计证据；
5. Runtime 通过正式 Security client/UDS 调用，不使用仅 mock 的成功结果；
6. 非法参数、未知 PII 类型、securityd 不可达时的安全行为。

不在本轮范围内：真实用户数据、真实外部收件人、真实生产 Agent 策略、不可逆地修改系统配置，以及将安全策略降级为 fail-open。

## 2. 测试环境与启动方式

### 2.1 代码与运行环境

| 项目 | 要求 |
|---|---|
| Security 仓库 | `/home/duancheng/workspace/bianbu-agent/bianbu-agent-security` |
| Security 实现 | `impl/bianbu-securityd` |
| Runtime 仓库 | `/home/duancheng/workspace/bianbu-agent/bianbu-agent-runtime` |
| Runtime 启动 | `./run-security-amd.sh` |
| Security 传输 | 管理控制面 D-Bus；Worker 数据面 Security UDS |
| 测试数据根 | 临时目录；禁止复用生产策略数据库 |
| 测试 Agent | 独立 `com.e2e.dlp.<timestamp>`，测试结束清理 |

开始测试前记录：

```bash
git -C /home/duancheng/workspace/bianbu-agent/bianbu-agent-security rev-parse HEAD
git -C /home/duancheng/workspace/bianbu-agent/bianbu-agent-runtime rev-parse HEAD
date -Is
uname -a
python3 --version
systemctl --user status bianbu-securityd 2>/dev/null || true
busctl --user status io.bianbu.Security 2>/dev/null || true
ls -l "${BIANBU_SEC_UDS:-$HOME/.local/share/bianbu-securityd/run/bianbu/securityd.sock}"
```

真实联调启动顺序：

1. 停止上一次测试遗留的 Runtime/Worker，确认没有复用旧 lease；
2. 使用最新 Security 代码启动 securityd；
3. 使用 `./run-security-amd.sh` 启动 Runtime；
4. 通过 `/api/v1/agents` 确认测试 Agent 已注册、Worker 可用；
5. 记录 Security 日志、Runtime 日志和测试前审计最大序号。

如果必须使用独立临时 securityd 数据根，需显式设置对应环境变量并记录；不得只在内存中构造 mock 来替代真实 D-Bus/UDS 验收。

## 3. 测试数据

所有值均为合成数据：

```text
PHONE    = 13812345678
EMAIL    = dlp-e2e@example.invalid
ID_CARD  = 110101199003076173
BANK_CARD = 4539578763621486
SECRET   = sk-e2e-THIS_IS_NOT_A_REAL_SECRET
```

建议测试文本：

```text
客户姓名：张伟；联系电话：13812345678；邮箱：dlp-e2e@example.invalid；
身份证：110101199003076173；银行卡：4539578763621486；密钥：sk-e2e-THIS_IS_NOT_A_REAL_SECRET
```

验收时不得只检查 `has_pii=true`。必须同时检查：`decision`、`modified_data` 或下游收到的 payload、`effective_policy`、`audit_seq`/审计记录，以及失败时的错误码。

## 4. 测试用例总览

| 编号 | 场景 | 策略 | 预期结果 |
|---|---|---|---|
| DLP-E2E-01 | 显式 allow | phone=`allow` | 原文放行；不因 DLP 拒绝 |
| DLP-E2E-02 | 显式 audit_only | phone=`audit_only` | 原文放行；新增 DLP 审计 |
| DLP-E2E-03 | 显式 mask | phone=`mask` | 继续执行；下游只收到脱敏值 |
| DLP-E2E-04 | 显式 block | phone=`block` | 拒绝；下游收不到原文 |
| DLP-E2E-05 | 多类型最严决策 | name=`audit_only`, phone=`mask`, id_card=`block` | 同一载荷按最严动作处理，不能被低风险类型覆盖 |
| DLP-E2E-06 | Agent 默认回退 | Agent `*`=`mask` | 未配置的 PII 类型继承 Agent 默认 |
| DLP-E2E-07 | 全局默认回退 | 全局 `*`=`audit_only` | 无 Agent 策略时继承全局默认 |
| DLP-E2E-08 | 系统兜底 | 删除所有匹配策略 | 按风险级别使用系统兜底，不出现未定义动作 |
| DLP-E2E-09 | 实时修改/删除 | 同一 PII 连续设置四种动作并删除 | 下一次调用立即看到新动作 |
| DLP-E2E-10 | 输入到输出全链路 | 四种动作分别覆盖输入、模型、工具、输出 | 每个干预点都保持动作语义和审计 |
| DLP-E2E-11 | 非法参数 | 非法 action、未知 PII、空 Agent | 拒绝请求；不写入策略 |
| DLP-E2E-12 | Security 不可达 | 停止/隔离 securityd | 高风险场景 fail-closed，不能把原文继续送下游 |

## 5. 四种核心动作的详细用例

每个核心用例都按以下顺序执行：读取基线 → 写入策略 → 读取确认 → 发起真实数据面调用 → 检查下游和审计 → 恢复/删除策略。

### DLP-E2E-01：allow 放行

**前置：** `phone=allow`，测试文本只包含 `PHONE`。  
**操作：** 通过 Security WebUI 或 D-Bus 写入；通过 UDS `dlp.scan`，再用真实 Runtime 输入/工具参数执行。  
**验收：**

- 返回 `ALLOW` 或等价成功结果；
- `PHONE` 在允许的下游 payload 中保持原文；
- 不产生 DLP 拒绝；若产品定义 allow 不审计，则不得把普通放行误报为 DLP block；
- capability、网络和其他安全控制仍正常执行。

### DLP-E2E-02：audit_only 放行并记录

**前置：** `phone=audit_only`。  
**验收：**

- 请求继续，返回 `ALLOW`；
- 下游收到原文 `PHONE`；
- DLP 审计新增一条，至少包含 Agent、PII 类型、动作/决策、时间、目标或 hook、序号；
- 审计哈希链验证保持完整；
- 审计内容不得泄露不必要的完整敏感值（以当前 Security 审计字段约定为准）。

### DLP-E2E-03：mask 脱敏后继续

**前置：** `phone=mask`。  
**验收：**

- 请求继续，返回 `MODIFY` 或等价脱敏成功结果；
- 下游 payload 不含原始 `PHONE`；
- 下游包含稳定的脱敏占位符/替换值；
- session mask map 只在内存保存，用于同一会话还原；
- 后续输出不会把原始值泄漏给不应看到它的下游；
- 产生 DLP 干预审计，记录 mask 决策。

### DLP-E2E-04：block 拒绝

**前置：** `phone=block`。  
**验收：**

- 返回 `BLOCK`/明确拒绝错误；
- 模型、工具或外发端点没有收到含 `PHONE` 的 payload；
- Run/Hook 状态与拒绝语义一致，不出现“界面报错但下游已执行”；
- 审计记录包含 block 决策及目标；
- 其他无 PII 的请求仍可正常运行。

## 6. 多类型、优先级与回退

### 6.1 同一载荷中的最严动作

配置 `name=audit_only`、`phone=mask`、`id_card=block`，发送包含三类 PII 的文本。验证结果按实现约定取最严动作 `block > mask > audit_only > allow`：

- block 命中时整体拒绝；
- 去掉身份证后应 mask 手机号、保留姓名；
- 不能因姓名的 allow/audit_only 使高风险类型原文流出。

### 6.2 策略回退

分别只配置：

1. Agent 精确 `phone=mask`；
2. Agent `*`=`mask`；
3. 全局 `*`=`audit_only`；
4. 全部删除，验证系统风险兜底。

每一步通过 `dlp.policy`/矩阵读取 `effective_policy`，确认来源和动作；修改一个层级后立即重复扫描，确认优先级为精确匹配 → Agent 默认 → 全局默认 → 系统兜底。

## 7. Runtime 实际 Hook 验证

对每种动作至少执行一次真实 Runtime 请求，并分别覆盖：

- 用户输入进入模型前（`INPUT`/`PRE_MODEL_CALL`）；
- 工具参数进入工具前（`PRE_TOOL_CALL`）；
- 工具返回值进入模型或用户前（`POST_TOOL_CALL`/`OUTPUT`）；
- 云端模型边界：高风险 PII 不得原文出网；
- 本地模型边界：按策略处理，不能把“本地”当作绕过 DLP 的理由。

对每次 Run 保存：Run/session ID、Hook 名、原始测试类别（不要在报告中扩散完整敏感值）、结果、下游可见文本摘要、DLP 审计序号和最终状态。

## 8. 控制面、数据面和审计证据

### 8.1 控制面

验证以下入口与 Security 内部状态一致：

- WebUI `/api/dlp/matrix`；
- WebUI `POST/DELETE /api/dlp/policy`；
- D-Bus `SetDLPPolicy`、`DeleteDLPPolicy`；
- Runtime `/security-api/invoke` 的 `dlp.matrix.v1`、`dlp.policy.update.v1`、`dlp.policy.delete.v1`。

### 8.2 数据面

通过正式 Security client/UDS 验证：

- `dlp.policy` 返回有效策略；
- `dlp.scan` 返回 finding、动作、脱敏结果和审计序号；
- Worker 身份/lease 校验通过；
- 非法或缺失身份不能借用另一个 Agent 的策略。

### 8.3 审计

每个核心用例至少保存一条对应审计证据。测试前后导出审计并验证：

```bash
# 具体命令以本机 Security client 安装路径为准
python3 -m pytest -q impl/bianbu-securityd/tests/unit/test_dlp_*.py
python3 impl/bianbu-securityd/tests/integration/dlp_e2e.py
```

报告中必须区分：DLP 审计、普通 capability 审计、Runtime 生命周期日志，不能用普通 HTTP 200 代替 DLP 证据。

## 9. 异常与安全性用例

### DLP-E2E-11：非法参数

逐项提交非法 action（如 `permit`）、未知 PII 类型、空 Agent ID、缺少必填字段。预期：返回可识别的 4xx/协议错误；数据库不新增或修改记录；不产生虚假的成功审计。

### DLP-E2E-12：securityd 不可达

仅在确认测试 Agent、测试数据库和可恢复启动方式后短暂停止 securityd 或隔离 UDS。对高风险输入、云端模型和工具外发请求执行验证。预期：按 fail-closed 拒绝，不使用 Runtime 本地 mock/旧策略继续外发；恢复 securityd 后重新建立连接并可继续测试。此用例必须记录停止/恢复时间和日志。

## 10. 测试命令与结果记录模板

建议先执行自动化基线，再执行真实 Runtime：

```bash
cd /home/duancheng/workspace/bianbu-agent/bianbu-agent-security
python3 -m pytest -q impl/bianbu-securityd/tests/unit/test_dlp_*.py
python3 impl/bianbu-securityd/tests/integration/dlp_e2e.py

cd /home/duancheng/workspace/bianbu-agent/bianbu-agent-runtime
.venv/bin/pytest -q tests/runtime/test_security_api.py
./run-security-amd.sh
```

结果表：

| 用例 | 配置/来源 | 实际命令或请求 | 实际决策 | 下游是否见原文 | 审计证据 | 结果 | 备注 |
|---|---|---|---|---|---|---|---|
| DLP-E2E-01 |  |  |  |  |  | 待执行 |  |
| DLP-E2E-02 |  |  |  |  |  | 待执行 |  |
| DLP-E2E-03 |  |  |  |  |  | 待执行 |  |
| DLP-E2E-04 |  |  |  |  |  | 待执行 |  |
| DLP-E2E-05~12 |  |  |  |  |  | 待执行 |  |

## 11. 通过标准、清理和风险

### 通过标准

只有同时满足以下条件才判定本轮通过：

1. 四种核心动作全部按定义通过；
2. mask/block 的原文不可达证据来自实际下游边界，而非只检查 UI 文本；
3. audit_only 和 block/mask 的审计证据可按 Agent、hook、决策关联；
4. 策略优先级、实时修改/删除、控制面与数据面一致；
5. securityd 不可达时高风险操作 fail-closed；
6. 自动化测试、真实 UDS/D-Bus 测试和 Runtime 联调无未解释失败。

### 清理

测试结束后：

- 删除测试 Agent、测试策略和临时文件；
- 恢复测试前的 DLP/能力/网络/Token 配置；
- 清理未完成审批、Worker、session mask map 和测试 lease；
- 若审计不可删除，保留测试记录并在报告明确标注 Agent、时间和清理限制；
- 确认 securityd、Runtime 和 Worker 进程状态恢复正常。

### 风险与未覆盖项

- Python/D-Bus ABI 不兼容可能使控制面调用失败，必须记录是否经过 helper bridge；
- 进程重启可能遗留旧 lease 或旧 securityd，测试前后需核对 PID、bus owner 和 socket；
- 审计中是否保存完整 PII 受当前实现约束，本计划只要求可证明决策和关联，不要求扩散明文；
- 本计划不等同于生产压力、并发、跨主机网络和真实第三方模型认证。

## 12. 验收报告交付内容

用户确认本计划后，执行阶段将提交一份报告，至少包含：环境快照、每个用例的实际命令与响应、四种动作的下游证据、审计序号/哈希校验、失败重试过程、清理结果、未覆盖风险和最终结论。报告不会把合成敏感值以外的真实个人信息写入文档。
