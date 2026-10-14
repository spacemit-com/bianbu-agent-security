# bianbu-agent-runtime + bianbu-agent-security 交付测试方案与测试用例

| 项目 | 内容 |
|---|---|
| 文档编号 | BN-SEC-RUNTIME-TEST-001 |
| 版本 | 1.0 |
| 测试对象 | `bianbu-agent-runtime`、`bianbu-agent-security`/`bianbu-securityd` |
| 测试入口 | Runtime `9899`、Security WebUI `8787`、Security D-Bus、Security UDS |
| 目标环境 | Worker `10.0.90.243`，以实际部署地址为准 |
| 状态 | 待测试执行 |

## 1. 测试目标

本次测试验证 Agent 从注册、策略装载、启动、运行到停止/撤销的完整安全闭环，重点证明：

- 未授权、身份不匹配、策略不一致、签名或 digest 校验失败时默认拒绝；
- Runtime 的 `PrepareStart → CommitStart → Stop/Revoke/Abort` 生命周期不会留下未受控进程；
- host/bwrap sandbox、PID/cgroup/namespace 证明、网络和资源边界与 Security 策略一致；
- capability、YOLO、confirm、Token quota、DLP、manifest/digest/caller binding 均会影响真实调用，而不只是返回成功的 API；
- syscall deny、采集器、审计链和故障降级保持 fail-closed；采集不可用时明确显示 `unavailable/degraded`，不得伪造“审计通过”；
- HTTP、D-Bus、UDS、WebUI 的错误状态、审计和恢复行为一致。

## 2. 范围与不包含项

### 2.1 纳入范围

| 域 | 覆盖内容 |
|---|---|
| 服务和接口 | Runtime HTTP、Security WebUI、D-Bus `io.bianbu.Security`、UDS `/run/bianbu/securityd.sock` |
| 生命周期 | 注册、Prepare、启动、Commit、运行、Stop、Abort、Revoke、过期、重启恢复 |
| 身份和完整性 | Agent/instance/lease/caller binding、manifest、entrypoint、package/policy digest、签名 |
| 执行隔离 | host/bwrap、user/PID/mount/network namespace、cgroup、资源限制、网络模式 |
| 能力和审批 | capability catalog、ALLOW/CONFIRM/DENY、scope、YOLO、MCP/Skill/Hook |
| 数据保护 | 8 类 PII、allow/audit_only/mask/block、输入/模型/工具/输出 hook、出境提档 |
| 配额和审计 | Token budget、审计事件、哈希链、syscall deny/collector/audit status |
| 发布回归 | 安装/卸载、版本记录、重启、并发、异常恢复和证据包 |

### 2.2 本次不作为通过证据的项目

以下项目必须单独标记 `BLOCKED` 或 `N/A`，不得用模拟结果替代：

- 独立生产 Runtime Manager systemd unit 尚未交付；
- OCI backend 尚未交付；本方案仅验已提供的 host/bwrap backend；
- 完整 egress broker 尚未交付；远端出境只验现有策略提档/拦截契约；
- 真实 eBPF/BPF 权限不足时，只能证明 syscall 阻断和 `unavailable/degraded`，不能标记“审计采集通过”；
- Runtime 重启后的生产孤儿回收 soak、长时间稳定性、升级/回滚、正式 Agent Memory SDK/memoryd 安装物缺失时，单独记录为阻塞项；
- `BA_UV_NO_SYNC=1` 仅可用于开发验证，不作为商用安装通过条件。

## 3. 版本、环境和测试数据

### 3.1 测试记录模板

每次执行前复制下表到测试报告并填写实际值：

| 项 | 实际值 |
|---|---|
| Runtime commit / package |  |
| Security commit / package / tag |  |
| `git status --short` |  |
| Worker IP、架构、内核 |  |
| Python、bwrap、systemd、DBus 版本 |  |
| Runtime HTTP URL | `http://<worker>:9899` |
| Security WebUI URL | `http://127.0.0.1:8787` |
| Security UDS | `/run/bianbu/securityd.sock` |
| 测试 Agent ID | `com.e2e.security.<timestamp>` |
| 测试目录 | `/tmp/bnsec-e2e-<timestamp>` |
| 执行人和时间 |  |

不得使用生产 Agent、生产数据库、真实收件人、真实密钥或真实外部设备。所有文件写入测试目录，所有网络目标使用无害测试域名/IP。

### 3.2 部署前静态检查

```bash
SEC=/home/duancheng/workspace/bianbu-agent/bianbu-agent-security
RT=/home/duancheng/workspace/bianbu-agent/bianbu-agent-runtime
git -C "$SEC" rev-parse HEAD
git -C "$RT" rev-parse HEAD
git -C "$SEC" status --short
git -C "$RT" status --short
uname -a
python3 --version
bwrap --version
```

发现未提交改动时，记录清单并确认部署包确实包含待测改动；不得通过清理工作树掩盖版本差异。

## 4. 启动、健康检查和清理

### 4.1 启动顺序

固定顺序为 `securityd → Runtime/PA → WebUI/testkit`。推荐使用仓库已有独立脚本；如使用 systemd，记录 unit 的 `MainPID`、`User/Group`、`ControlGroup` 和 `ActiveState`。

```bash
# Security 仓库或目标机上的对应启动脚本
./start-bianbu-securityd.sh --status
./start-bianbu-securityd.sh --restart

# Runtime 按交付包的 service/启动入口启动
systemctl status bianbu-agent-runtime --no-pager || true

# WebUI/testkit（需要时启动）
./start-securityd-webui.sh --status
```

### 4.2 健康检查

```bash
busctl --user list | grep io.bianbu.Security
busctl --user status io.bianbu.Security
stat /run/bianbu/securityd.sock
ss -ltnp | grep -E ':(8787|9899)\b'
curl -fsS http://127.0.0.1:9899/api/v1/agents
curl -fsS http://127.0.0.1:9899/api/v1/executions
```

若服务不可达，先执行 `P0-01` 和 `P0-02` 的故障结果记录；不得把空数组或 HTTP 200 当作服务正常。

### 4.3 清理

测试结束按顺序：停止测试 Run/Agent → 撤销临时能力和策略 → 删除测试包/Skill/MCP → 停止测试 Worker → 导出审计和日志 → 检查无残留进程/cgroup/socket。生产服务只能通过受管 unit 停止，不得 `kill -9` 误伤其他 Agent。

## 5. 自动化测试入口

### 5.1 Runtime 定向回归

```bash
cd /home/duancheng/workspace/bianbu-agent/bianbu-agent-runtime
.venv/bin/pytest -q \
  tests/runtime/test_security_runtime.py \
  tests/runtime/test_execution_runtime.py \
  tests/runtime/test_service.py \
  tests/runtime/test_security_api.py \
  tests/runtime/test_security_skill_dlp.py \
  tests/runtime/test_security_syscall_api.py \
  tests/runtime/test_syscall_collector.py \
  tests/runtime/test_seccomp_audit.py \
  tests/runtime/test_syscall_auditd_collector.py
```

### 5.2 Security Runtime 定向回归

```bash
cd /home/duancheng/workspace/bianbu-agent/bianbu-agent-security
PYTHONPATH=impl/bianbu-securityd \
  /home/duancheng/workspace/bianbu-agent/bianbu-agent-runtime/.venv/bin/python \
  -m pytest -q \
  impl/bianbu-securityd/tests/unit/test_runtime_policy.py \
  impl/bianbu-securityd/tests/unit/test_runtime_lease.py \
  impl/bianbu-securityd/tests/unit/test_runtime_engine.py \
  impl/bianbu-securityd/tests/test_syscall_audit.py \
  impl/bianbu-securityd/tests/test_syscall_policy.py
```

### 5.3 D-Bus 集成和 Security testkit

```bash
cd /home/duancheng/workspace/bianbu-agent/bianbu-agent-security
PYTHONPATH=impl/bianbu-securityd \
  dbus-run-session -- /usr/bin/python3 \
  impl/bianbu-securityd/tests/integration/runtime_security_dbus.py

# 真实服务启动后使用 runner.py，不要直接运行 engine.py
python3 testkit/runner.py
# 指定回归项示例
python3 testkit/runner.py CONN-01 CONN-02 CONN-03 PERM-01 PERM-02 \
  HOOK-01 HOOK-03 DLP-01 DLP-04 TOKEN-01 SBX-01 SBX-02 \
  AUDIT-01 AUDIT-02 CAP-01 MCP-01 CODE-01 SCOPE-01 ERR-01
```

以实际 `runner.py` 输出和测试 ID 列表为准，不手工固定“35/36 项”通过数量。

## 6. 测试用例总览

| ID | 优先级 | 测试点 | 通过门槛 |
|---|---|---|---|
| P0-01 | P0 | Security/Runtimes 连通性 | 所有服务、D-Bus、UDS、HTTP 状态可解释 |
| P0-02 | P0 | 正常 Agent Run | 真实 Run 完成并有审计 |
| P0-03 | P0 | sandbox 启动与证明 | bwrap、PID/cgroup/namespace 证据齐全 |
| P0-04 | P0 | 未授权工具拒绝 | 下游未执行，返回明确 DENY/CONFIRM |
| P0-05 | P0 | DLP block | 原文不出境、不到下游，产生审计 |
| P0-06 | P0 | Security 不可达 | 高危请求 fail-closed，API 返回 503/明确错误 |
| RT-01 | P0 | Prepare/Commit/Abort | 各状态转换合法且失败清理完整 |
| RT-02 | P1 | Stop/Revoke/Expire | 进程退出、lease 不可复用、审计完整 |
| RT-03 | P1 | manifest/digest/entrypoint | 任意不匹配都拒绝启动 |
| RT-04 | P1 | caller/lease/cgroup binding | 伪造或跨 Agent 访问拒绝 |
| RT-05 | P1 | Runtime 重启恢复 | 只回收能证明属于自身 unit/cgroup 的实例 |
| CAP-01 | P0 | capability 注册和目录 | 权威字典、映射和 Worker catalog 一致 |
| CAP-02 | P0 | ALLOW/CONFIRM/DENY | 判权结果与真实下游行为一致 |
| CAP-03 | P1 | scope 和路径规范化 | 最长前缀、`..`、软链接不能越界 |
| CAP-04 | P1 | YOLO 模式 | 临时放行、全量审计、关闭后恢复原策略 |
| CAP-05 | P1 | MCP/Skill/Hook | 未映射或删除项不绕过判权 |
| DLP-01 | P0 | 八类 PII 扫描 | name/email/phone/id/bank/address/medical/biometric 可识别 |
| DLP-02 | P1 | 四种 DLP action | allow/audit_only/mask/block 作用于真实 payload |
| DLP-03 | P1 | 八个 hook 链路 | input/model/tool/output 全部执行预期动作 |
| DLP-04 | P1 | DLP 不可达 | 高风险原文不继续送下游 |
| TOK-01 | P1 | Token quota | 用量持久化、超限 pause/deny、生效于下一次调用 |
| SIG-01 | P0 | 包签名和安装期校验 | 改包、改 manifest、非法目录均拒绝 |
| NET-01 | P1 | 网络策略 | whitelist/deny_all/learning/allow_all 语义一致 |
| NET-02 | P1 | learning 采集 | 事件含域名/IP/端口/结果，采集器故障降级 |
| SC-01 | P0 | seccomp deny | deny syscall 返回 EPERM，普通 syscall 正常 |
| SC-02 | P1 | syscall 策略版本 | 强制基线不可删，追加项重启后生效 |
| SC-03 | P1 | collector/审计链 | 事件身份可信、去重、链校验通过 |
| SC-04 | P1 | collector/BPF 故障 | 阻断仍生效，状态为 unavailable/degraded |
| API-01 | P0 | HTTP/D-Bus/UDS 错误契约 | 错误码、状态、审计字段稳定 |
| API-02 | P1 | WebUI 状态展示 | 展示实际 worker/seccomp/audit/policy 状态 |
| RES-01 | P1 | 并发和资源限制 | 无越权、无重复 lease、资源超限被限制 |
| RES-02 | P2 | 策略热更新和回滚 | 旧 Worker 使用旧快照，新 Worker 使用新版本 |
| REL-01 | P2 | 长稳/重启/升级回滚 | 仅在真实安装包和指定 soak 完成后关闭 |

## 7. P0 冒烟用例

### P0-01：服务连通性和接口基线

**前置：** Security、Runtime、测试数据目录已启动。

**步骤：**

1. 执行健康检查命令，保存原始输出。
2. `busctl --user introspect io.bianbu.Security /io/bianbu/Security`，确认 `PrepareStart`、`CommitStart`、`AbortStart`、`Revoke`/停止、能力、Token、DLP、manifest、审计和 syscall 方法存在。
3. 读取 Runtime `/api/v1/agents`、`/api/v1/executions` 和安全状态接口。
4. 读取 Security WebUI 首页和认证状态。

**预期：** HTTP、D-Bus、UDS 均可达；未绑定 caller 的判权请求被拒；接口错误不是空成功；版本和 policy/schema 信息可记录。

**证据：** 命令输出、D-Bus introspection、HTTP JSON、WebUI 截图。

### P0-02：最小正常 Run

**步骤：** 使用临时 Agent 发起只返回固定短文本的 Run，记录 `agent_id/session_id/run_id/instance_id/lease_id`；查询 Run 终态、Runtime execution ledger 和 Security 审计。

**预期：** Run 在合理超时内 `completed`；返回内容正确；启动、判权、Commit、结束事件能按同一身份关联；无残留进程和 active lease。

### P0-03：sandbox 启动和证明

**步骤：** 以 sandbox 模式启动无害 Worker，读取 Worker PID、cgroup、namespace inode、`/proc/<pid>/status`、backend、sandboxed、seccomp profile digest；在 Worker 内执行 PID 和挂载点检查。

**预期：** backend 为 bwrap/sandbox；`Seccomp=2`（若策略启用）；PID namespace、cgroup、mount/network 状态与 PrepareStart 返回值一致；Worker 无法读取测试范围外的宿主资源。

**限制：** host fallback 只能作为开发环境结果，不能替代生产 sandbox 通过证据。

### P0-04：未授权工具拒绝

**步骤：** 选用未注册 capability 的无害工具和一个 MCP 未映射工具，分别调用；再对 L3/L4 能力设置 `granted=0`。

**预期：** 返回 DENY 或产品定义的 CONFIRM；未批准前下游零调用、无文件变化、无网络请求；Security 审计含真实 caller、capability、target、decision。

### P0-05：DLP block

**步骤：** 对临时测试 Agent 将 `phone` 或 `id_card` 配为 `block`，把带合成 PII 的 payload 依次送入 input、model、tool、output 路径。

**预期：** 每个实际启用的 hook 都阻断原文，工具/模型/接收方收不到原始 payload；返回可解释 DLP 错误；DLP 审计和完整审计链新增记录。

### P0-06：Security 不可达 fail-closed

**步骤：** 在隔离测试环境停止 securityd 或临时隔离 UDS；发起 L3/L4 工具调用、DLP block 场景和新 Worker 启动。

**预期：** 高危调用和新启动均拒绝；Runtime/API 返回 `503`、`security_unavailable` 或等价明确错误；不得返回空 catalog、沿用过期授权或 fail-open；恢复后重新绑定身份，旧 lease 不复用。

## 8. Runtime 生命周期和启动完整性

### RT-01：Prepare/Commit/Abort 状态机

| 场景 | 操作 | 预期 |
|---|---|---|
| 正常 | Prepare → backend start → attestation → Commit | 只有证明全部匹配才进入 RUNNING |
| Prepare 失败 | policy/digest/entrypoint 错误 | 不启动进程；Abort/错误审计；无 active lease |
| backend 失败 | bwrap 参数或端口代理失败 | 停止已启动子进程；Commit 前 Abort |
| attestation 失败 | PID/cgroup/namespace 不匹配 | Revoke/Abort，进程退出，不得提交 |
| Commit 后错误 | ledger/状态提交失败 | Revoke，回收 unit/cgroup 内进程 |

每个分支都要保存状态转换、Security 返回值、ledger、`ps -ef`/cgroup 和审计。任何 Commit 前遗留活进程或 Commit 后未 Revoke 都是 P0 缺陷。

### RT-02：Stop、Revoke、Expire 和不可复用

1. 正常 Stop，确认 Worker、proxy、collector 全部退出，lease 状态为 stopped/revoked。
2. 主动 Revoke，确认正在运行的工具/模型调度停止，后续请求拒绝。
3. 等待 lease 过期后提交旧 lease、旧 instance、旧 PID 请求。
4. 重新启动同 Agent，确认新 lease/instance 与旧值不同。

预期：旧身份不能恢复或冒充新实例；PID 重用不归属旧 lease；审计记录包含原因和操作者。

### RT-03：manifest、digest、entrypoint 校验

准备一份有效测试包，分别修改 package digest、policy digest、entrypoint、runtime mode、版本或签名而不更新声明值。

预期：每种修改都在 Prepare/安装期拒绝；错误指出具体字段；不产生可运行实例。恢复有效包后能正常启动。

### RT-04：caller binding、lease 和 cgroup 绑定

使用 Agent A 的合法身份，分别伪造 Agent B、instance、lease、PID、cgroup、syscall arch、policy version 上报或调用 Security UDS/D-Bus。

预期：三者不一致全部拒绝并审计；不能读取/修改 B 的能力、Token、DLP 或审计；合法 A 不受影响。

### RT-05：Runtime 重启恢复

在至少一个正常运行 Worker 和一个非 Runtime 测试进程存在时重启 Runtime。检查重启前后的 ledger、unit、cgroup、PID 和 Security lease。

预期：只回收能够通过 unit/cgroup/instance 证明属于自身的孤儿；不杀外部进程；无法证明归属的实例标记 orphan/blocked 并人工处理。生产 soak 未完成时此用例只能记录 `BLOCKED`。

## 9. Capability、Agent registration 和 YOLO

### CAP-01：能力目录和注册

执行 testkit `CAP-01`、`PERM-01`，并通过 Runtime catalog 检查 tool/skill/hook/MCP 的稳定 ID、来源、revision、enabled 状态。所有映射能力必须来自 Security 权威字典；未知能力返回 4xx 或明确 DENY。

### CAP-02：三态判权到真实工具

对同一能力依次设置：

| 配置 | 预期判权 | 真实行为 |
|---|---|---|
| `granted=1, confirm=trusted`（仅允许低风险） | ALLOW | 下游执行一次 |
| `granted=1, confirm=always` | CONFIRM | 未批准前不执行，批准后仅执行一次 |
| `granted=0/-1` 或未注册 | DENY | 下游零调用 |

检查 scope、hook trace、审计和下游 payload，不能只检查 D-Bus 数值。

### CAP-03：scope、最长前缀和路径规范化

允许 `/tmp/bnsec-e2e`，撤销 `/tmp/bnsec-e2e/private`。验证允许目录、子目录、越界目录、`..`、相对路径、软链接和大小写变体。

预期：使用 canonical path 和最长匹配；不能通过符号链接或路径拼接逃逸；无匹配默认 DENY/CONFIRM，不得默认放行。

### CAP-04：YOLO

运行 testkit `YOLO-01`。确认 normal 下未授权能力 DENY，切换 YOLO 后临时放行已撤销和未来未知能力，每次判权均审计 `mode=yolo`、actor、old/new mode；关闭后恢复原 DENY。

### CAP-05：MCP/Skill/Hook 管理

验证未授权 MCP server、未知 MCP tool、禁用/删除 Skill 或 Hook、reload 失败、旧 Run 继续调用等场景。预期：MCP 按 server 边界判权；删除后旧目录不再声明可用；reload 失败保留旧完整 catalog，不发布半快照。

## 10. DLP 和数据流

### DLP-01：PII 识别

执行 testkit `DLP-01`、`DLP-02`、`DLP-03`，覆盖 name、email、phone、id_card、bank_card、address、medical、biometric，并使用校验合法的合成身份证/银行卡。记录误报样本和扫描类型。

### DLP-02：四种动作

对同一 payload 依次配置 `allow`、`audit_only`、`mask`、`block`：

- allow：原文继续，按产品定义不产生 DLP 拒绝；
- audit_only：原文继续，新增 DLP 审计；
- mask：继续执行，下游只能看到脱敏值；
- block：拒绝执行，下游和外发端看不到原文。

删除 Agent 级策略后验证全局默认和系统兜底，非法 action/PII/Agent 不落库。

### DLP-03：八个 hook 链路

验证 `before_run`、`after_context`、`before_model`、`after_model`、`before_tool`、`after_tool`、`after_run`、`on_error` 均已加载且启用。分别记录输入、模型请求/响应、工具参数/返回值、最终输出的原文/脱敏值、下游是否收到和审计。

### DLP-04：不可达和多类型最严

同一 payload 同时命中 `audit_only + mask + block`，预期按最严动作 block；隔离 Security 后高风险原文不能继续下游；恢复服务后不重复外发旧请求。

## 11. Token quota

### TOK-01：读写、计量和超限

1. 设置短额度和 `on_exceed=deny`，执行真实模型调用，核对返回 usage、持久化 used/limit、审计和 `TokenExceededV2`。
2. 设置 `pause_and_notify`，确认下一次模型调用前进入 PAUSED/HITL，批准只放行一次，拒绝保持阻断。
3. 重启 Runtime/Security，确认 used、limit、超限状态和 session 语义保持。
4. 并发调用时不得超额放行，不重复广播相同超限事件。

当前实现或环境不支持真实模型 usage 时，标记 `BLOCKED`，不能用手工增加数据库字段代替。

## 12. Manifest、签名、digest 和安装

### SIG-01：安装期和运行期完整性

准备有效签名测试包，然后分别修改 hook.py/tool、manifest capability、版本、路径、entrypoint，或在 hook 目录加入 `.bak`、`__pycache__`、额外文件。

预期：有效包安装成功；每种篡改包安装/加载拒绝；错误包含校验原因；安装期签名通过不等于运行期授权通过，后续仍执行 capability/DLP/审计验证。

## 13. 网络和资源隔离

### NET-01：网络模式

对测试 Agent 分别设置 `whitelist`、`deny_all`、`learning`、`allow_all`，重启 Worker 后执行 IPv4、IPv6、DNS、允许/未声明目标连接。

预期：策略由 Security 返回并写入启动快照；旧 Worker 不热更新；deny_all/白名单阻断越界；allow_all 按产品定义放行；learning 只采集不扩大权限。

### NET-02：learning 和采集器故障

learning 模式下检查域名、连接 IP/端口、成功/失败、次数、最近时间和持久化；杀 collector 或使权限不足，页面显示 `degraded/unavailable`，不伪造完整学习数据。恢复后事件按 lease/cgroup 关联、去重并可查询。

### RES-01：PID、cgroup、文件和资源

验证 Worker 只能写测试目录；读取宿主敏感路径、访问其他 Agent cgroup、创建超额进程、超过 CPU/内存/磁盘/打开文件限制时被拒或受限。检查无越界文件、socket、进程和权限变化。

## 14. Syscall deny、collector 和审计链

### SC-01：deny syscall 和继承

在 sandbox Worker 中执行策略 denylist 中的 syscall，例如对应架构的 `finit_module`，并执行一个普通无害 syscall。由 Worker fork/exec 子进程重复。

预期：deny syscall 返回 `-1/EPERM`，普通 syscall 成功，子进程继承限制；记录 `/proc/<pid>/status` 的 `Seccomp=2`、backend、profile digest。单凭 EPERM 不能宣称审计采集通过。

### SC-02：策略版本和强制基线

调用 `GetSyscallCatalog`/`GetSyscallPolicy`，确认 mandatory 基线项存在且不可删除。新增合法项后 policy version 递增、pending restart 生效；未知名、错误架构、删除 mandatory、过期版本均拒绝且不落库。

### SC-03：真实事件、身份和哈希链

collector active 时触发 deny syscall，查询 `GetSyscallAuditEvents`/WebUI，确认事件含 `agent_id`、`instance_id/lease_id`、PID、cgroup、arch、syscall/name/number、action、backend、policy_version。验证重复 event 去重、审计 seq 单调、hash chain 校验为 true。

### SC-04：securityd/collector/BPF 故障

分别停止 securityd、断开 UDS、杀 collector、注入 ring buffer 丢失、权限不足、策略版本不一致。预期 deny 仍返回 EPERM；状态为 `unavailable/degraded`；spool/恢复重放按身份校验、去重；任何 ALLOW 都是阻断性缺陷。

## 15. 接口和 WebUI 契约

### API-01：HTTP、D-Bus、UDS

对缺少认证、未知 Agent、过期 lease、错误 JSON、未知 capability、未知 policy version、重复 request ID、服务不可达分别请求 Runtime HTTP、Security WebUI API、D-Bus、UDS。

预期：状态码/错误码稳定且可解释；写接口失败不落库；重复请求幂等；不存在“HTTP 200 + 空数组”伪装故障；D-Bus sender/caller binding 仍强制校验。

### API-02：状态页面

页面/接口至少能区分：control、securityd、worker、sandbox/seccomp、policy/applied version、pending restart、collector backend、coverage、最近错误和事件数量。Worker 或 collector 不可用时展示降级原因，不显示“审计通过”或空成功列表。

## 16. 并发、重启和发布回归

### RES-02：并发、热更新和失败回滚

并发 grant/revoke、Prepare、reload、删除 MCP、读取 catalog、策略更新。预期最终状态满足串行化规则；无重复 lease/主键；任何时刻不发布半截策略；reload/签名失败保留旧可用版本。

### REL-01：重启、升级和长期运行

保存升级前版本、schema、manifest、catalog、审计最大 seq 和运行实例；安装升级包、重启服务、运行全量回归，再回滚到上一版本。

只有同时具备真实安装包、systemd 状态、升级/回滚日志、数据迁移校验和规定 soak 结果时才能标记 PASS；否则为 `BLOCKED`，不影响已完成的单元/接口测试结论。

## 17. 证据包要求

每次交付至少保存：

1. 两仓 commit、包版本、内核/架构/依赖版本和工作树状态；
2. 启动/停止/重启命令及原始 stdout/stderr；
3. Runtime HTTP、D-Bus introspection、UDS 请求响应；
4. Agent/instance/lease/run、PID/cgroup/namespace、sandbox/seccomp/policy 状态；
5. capability、DLP、Token、网络、syscall 策略和版本快照；
6. Security 审计导出、事件 JSON、哈希链验证、collector 状态和故障注入结果；
7. 关键 WebUI 页面截图，截图必须能对应到 JSON/日志中的时间和测试 ID；
8. 测试报告中每条用例的 `PASS/FAIL/BLOCKED/N/A`、实际结果、证据路径和缺陷单号。

建议目录：

```text
/var/tmp/bnsec-evidence-<date>/
  manifest.txt
  versions.txt
  commands/
  http/
  dbus/
  uds/
  runtime-ledger/
  security-audit/
  syscall/
  screenshots/
  junit-or-runner-output/
```

## 18. 发布准出标准

### 必须通过

- P0-01 至 P0-06、RT-01、RT-03、RT-04、CAP-01、CAP-02、DLP-01、DLP-02、SIG-01、SC-01、API-01 全部 PASS；
- 不存在未授权执行、caller/lease 冒充、digest/签名绕过、DLP 原文外发、syscall deny fail-open、审计链伪造；
- 所有测试结果都有可复核的原始证据；
- 代码测试、真实服务测试和故障注入结论分开记录。

### 允许带条件交付

P1/P2 仅在明确列出风险、负责人、关闭版本和临时限制后交付。collector/BPF 无权限时只能以“阻断通过、采集不可用”交付，不能以“完整 syscall 审计通过”交付。

### 禁止交付

任一 P0 失败；任何高风险场景 fail-open；存在未受控进程或跨 Agent 访问；审计事件身份不可验证；DLP/Token/网络策略只在 mock 或数据库层验证；将 `BLOCKED`、`N/A` 或环境缺失写成 PASS。

## 19. 结果记录表

| 用例 ID | 结果 | 实际摘要 | 证据路径 | 缺陷/备注 |
|---|---|---|---|---|
| P0-01 |  |  |  |  |
| P0-02 |  |  |  |  |
| P0-03 |  |  |  |  |
| P0-04 |  |  |  |  |
| P0-05 |  |  |  |  |
| P0-06 |  |  |  |  |
| RT-01~05 |  |  |  |  |
| CAP-01~05 |  |  |  |  |
| DLP-01~04 |  |  |  |  |
| TOK-01 |  |  |  |  |
| SIG-01 |  |  |  |  |
| NET-01~02 |  |  |  |  |
| SC-01~04 |  |  |  |  |
| API-01~02 |  |  |  |  |
| RES-01~02 |  |  |  |  |
| REL-01 |  |  |  |  |
