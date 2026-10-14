# Bianbu Next 高层与模块 API 定义

| 项 | 内容 |
|----|------|
| 文档编号 | BN-API-001 |
| 版本 | V1.0 |
| 来源 | 基于 HLD（BN-HLD-001）+ SRS（BN-SRS-001） |
| 日期 | 2026-07-07 |
| 状态 | 待评审 |

> 约定：D-Bus 类型用签名记法（s=string, i=int32, x=int64, d=double, b=bool, a=array, {}=dict, v=variant, ()=struct）。所有方法在鉴权失败时返回错误码域 `io.bianbu.Error.*`。时间戳为 UTC int64 毫秒。

---

## 1. 通用约定

### 1.1 统一错误码
| 错误名 | 含义 |
|--------|------|
| io.bianbu.Error.PermissionDenied | Capability 校验未通过 |
| io.bianbu.Error.ConfirmRequired | 需用户确认（门禁未通过） |
| io.bianbu.Error.NotFound | 目标（agent/model/skill/key）不存在 |
| io.bianbu.Error.InvalidArgument | 参数非法 |
| io.bianbu.Error.QuotaExceeded | token/资源超限 |
| io.bianbu.Error.Unavailable | 依赖（模型/云端/硬件）不可用 |
| io.bianbu.Error.Internal | 内部错误 |
| io.bianbu.Error.Timeout | 超时 |

### 1.2 通用数据结构（JSON schema 片段）
```jsonc
// Capability 声明（DR-01）
Permission = {
  "capability": "file.write",           // 能力标识
  "domain": "execute|resource|data|system",
  "risk_level": "L1|L2|L3|L4",
  "confirm": "always|once_per_session|trusted",
  "scope": "~/Documents"                 // 可选，文件类能力
}
// 约束：risk_level∈{L3,L4} 时 confirm≠trusted；L4 强制二次确认
```

---

## 2. io.bianbu.Security（L1 安全审计）

对应 FR-SEC-01~07 / FR-SBX-*。Object path: `/io/bianbu/Security`

| 方法 | 签名 in → out | 说明 | FR |
|------|---------------|------|----|
| VerifyManifest | s(agent_pkg_path) → (b valid, s reason, a{sv} perms) | 校验签名+解析权限 | FR-SEC-01 |
| RegisterCapabilities | s(agent_id), aa{sv}(perms) → b | 写入注册表 | FR-SEC-02 |
| CheckPermission | s(agent_id), s(capability), s(scope) → (i decision) | 0=允许,1=需确认,2=拒绝 | FR-SEC-02/03 |
| RequestConfirm | s(agent_id), s(capability), s(detail) → b(approved) | 触发门禁弹窗 | FR-SEC-03 |
| RevokePermission | s(agent_id), s(capability) → b | 撤销（高危二次确认） | FR-SEC-02/SET-03 |
| BuildSandboxPolicy | s(agent_id) → (s seccomp_path, s netfilter_rules) | 生成沙箱策略 | FR-SBX-03/04/05 |
| MeterTokens | s(agent_id), x(tokens), s(scope) → (b within, x remaining) | 计量+超限判定 | FR-SEC-04 |
| AuditLog | s(agent_id), s(op_type), s(target), s(result) → x(seq) | 写审计链 | FR-SEC-06 |
| ExportAudit | s(filter_json), s(format) → s(export_path) | 导出+哈希链 | FR-SEC-06 |
| VerifyAuditChain | s(export_path) → b(intact) | 完整性校验 | FR-SEC-06 |
| SetNetworkPolicy | s(scope), a s(domains), s(mode) → b | 白名单/学习模式 | FR-SEC-07/SET-18 |

Signals: `SecurityAlert(s agent_id, s type, s detail)`（FR-SET-19）。

---

## 3. io.bianbu.AIHal（L2 AI 能力）

对应 FR-AI-*。Object path: `/io/bianbu/AIHal`

| 方法 | 签名 in → out | 说明 | FR |
|------|---------------|------|----|
| Generate | s(prompt), s(model_name), a{sv}(params) → s(request_id) | 发起生成（流式经 signal） | FR-AI-09/10 |
| GenerateSync | s(prompt), s(model_name), a{sv}(params) → s(text) | 同步生成 | FR-AI-10 |
| Embed | s(text), s(model_name) → ad(vector) | 文本向量化 | FR-VEC-04/MEM-03 |
| LoadModel | s(model_name), s(model_path) → s(status) | 加载/共享 | FR-AI-01/02 |
| UnloadModel | s(model_name) → s(status) | 卸载 | FR-AI-04 |
| SwitchModel | s(agent_id), s(from), s(to) → s(status) | 热切换 | FR-AI-03 |
| GetStatus | — → a{sv}(status) | HAL/模型/内存状态 | FR-SET-06 |
| SetEndpointPolicy | s(scope), s(policy) → b | always_local/prefer_local/auto | FR-AI-18~20/SET-09 |
| ListModels | s(filter) → aa{sv}(models) | 模型列表 | FR-SET-06 |

Signals: `TokenStream(s request_id, s token, b done)`（流式，或走专用 fd）；`ModelStateChanged(s model_name, s state)`。
参数 params 约定：`{max_tokens:i, temperature:d, stream:b, priority:i, allow_cloud:b}`。

---

## 4. io.bianbu.Runtime（L3 运行时）

对应 FR-RTE-*。Object path: `/io/bianbu/Runtime`

| 方法 | 签名 in → out | 说明 | FR |
|------|---------------|------|----|
| Start | s(agent_id) → s(status) | 启动（分配沙箱） | FR-RTE-02 |
| Pause | s(agent_id), b(snapshot) → s(status) | 暂停可选快照 | FR-RTE-03 |
| Resume | s(agent_id) → s(status) | 恢复 | FR-RTE-04 |
| Stop | s(agent_id) → s(status) | 停止 | FR-RTE-05 |
| Terminate | s(agent_id) → s(status) | 终止+清理 | FR-RTE-06 |
| Checkpoint | s(agent_id) → s(ckpt_id) | 手动快照 | FR-RTE-08 |
| Restore | s(agent_id), s(ckpt_id) → s(status) | 从快照恢复 | FR-RTE-09 |
| ListCheckpoints | s(agent_id) → aa{sv} | 快照列表 | FR-RTE-11 |
| GetResourceStats | s(agent_id) → a{sv}(cpu,mem,io) | 资源统计 | FR-RTE-12 |
| ExportResourceHistory | s(agent_id), s(format) → s(path) | 历史导出 | FR-RTE-14 |
| List | — → aa{sv}(AgentStatus) | 所有 Agent | FR-SET-01 |
| SendMessage | s(from), s(to), s(payload) → b | Agent 间 IPC | FR-RTE-15 |

Signals: `StateChanged(s agent_id, s old, s new)`；`ResourceExceeded(s agent_id, s resource, x value)`（FR-RTE-13）。
AgentStatus 结构：`{agent_id, name, state, cpu_pct:d, mem_mb:x, uptime_s:x}`。

**Workspace 方法**（FR-WS-*，Workspace Manager 并入 Runtime；补 HLD §10 → API 断链）：
| 方法 | 签名 in → out | 说明 | FR |
|------|---------------|------|----|
| MountWorkspace | s(agent_id) → (s root_path) | 创建/挂载私有工作区（bind-mount） | FR-WS-01 |
| SnapshotWorkspace | s(agent_id), s(label) → s(snap_id) | 文件快照（与 Checkpoint 一致） | FR-WS-02 |
| RollbackWorkspace | s(agent_id), s(snap_id) → s(status) | 回滚到快照 | FR-WS-02 |
| ListArtifacts | s(agent_id) → aa{sv}(artifacts) | 列产物（artifacts/） | FR-WS-04 |
| ExportArtifact | s(agent_id), s(path) → s(export_path) | 导出产物 | FR-WS-04 |

---

## 4bis. io.bianbu.Loop（Agent 循环引擎）

对应 FR-LOOP-*。Object path: `/io/bianbu/Loop`。Loop Engine 内建于 agent-runtimed Executor，此接口暴露循环控制与观测（补 HLD §11 → API 断链）。

| 方法 | 签名 in → out | 说明 | FR |
|------|---------------|------|----|
| StartLoop | s(agent_id), s(goal), a{sv}(policy) → s(loop_id) | 启动循环（指定目标+Workflow 策略） | FR-LOOP-01/07 |
| PauseLoop | s(loop_id) → s(status) | 暂停循环 | FR-LOOP-04 |
| ResumeLoop | s(loop_id), b(approved) → s(status) | HITL 确认后恢复（approved=false 则终止） | FR-LOOP-04 |
| CancelLoop | s(loop_id) → s(status) | 用户取消 | FR-LOOP-03 |
| GetLoopState | s(loop_id) → a{sv}(state) | 当前循环态+步数+预算 | FR-LOOP-01 |

Signals: `LoopStep(s loop_id, s phase, i step, s detail)`（每步可观测，FR-LOOP-02）；`LoopFinished(s loop_id, s reason)`（reason∈{goal_met/max_steps/budget/timeout/cancelled/unrecoverable}，FR-LOOP-03）；`HumanGate(s loop_id, s capability, s detail)`（HITL 触发，FR-LOOP-04）。
policy 结构：`{workflow:s(single|multi_agent|dag), max_steps:i, budget_tokens:x, reflect_threshold:d}`。

---

## 5. io.bianbu.Memory（记忆服务）

对应 FR-MEM-*。Object path: `/io/bianbu/Memory`

| 方法 | 签名 in → out | 说明 | FR |
|------|---------------|------|----|
| Store | s(agent_id), s(key), s(value), x(ttl_ms) → s(status) | 写入（ttl=0 不过期） | FR-MEM-01/06 |
| Get | s(agent_id), s(key) → s(value) | 精确读取 | FR-MEM-02 |
| Retrieve | s(agent_id), s(query), i(top_k) → a(sd)(text,score) | 语义检索 | FR-MEM-03 |
| Delete | s(agent_id), s(key) → s(status) | 删除条目 | FR-MEM-08 |
| Clear | s(agent_id) → s(status) | 清空命名空间 | FR-MEM-08 |
| Backup | s(agent_id), s(account_token) → s(status) | 云端备份（P2） | FR-MEM-07 |

约束：调用方 agent_id 与调用者身份一致，跨命名空间返回 PermissionDenied（FR-MEM-04）。

---

## 6. io.bianbu.Skill（Skill Registry + MCP）

对应 FR-SKL-*。Object path: `/io/bianbu/Skill`

| 方法 | 签名 in → out | 说明 | FR |
|------|---------------|------|----|
| Register | s(skill_id), a{sv}(manifest) → b | 注册技能 | FR-SKL-01 |
| Discover | s(query) → aa{sv}(skills) | 发现（≤50ms） | FR-SKL-02 |
| Invoke | s(skill_id), s(function), a{sv}(args) → v(result) | 调用（经权限校验） | FR-SKL-03 |
| Install | s(skill_pkg_path) → (b ok, aa{sv} perms_to_confirm) | 安装+权限确认 | FR-SKL-06 |
| Uninstall | s(skill_id) → b | 卸载清理 | FR-SKL-06 |
| List | s(filter) → aa{sv} | 已安装列表 | FR-SET-11 |
| SetEnabled | s(skill_id), b(enabled) → b | 启停 | FR-SET-12 |
| McpExpose | s(skill_id) → s(mcp_endpoint) | 暴露为 MCP 工具 | FR-SKL-04 |
| McpCall | s(external_tool), a{sv}(args) → v | 调外部 MCP 工具 | FR-SKL-04 |

---

## 7. io.bianbu.Intent / io.bianbu.Calendar

### 7.1 Intent（对应 FR-INT / ASR）Object path: `/io/bianbu/Intent`
| 方法 | 签名 | 说明 | FR |
|------|------|------|----|
| Parse | s(text), s(session_id) → (s intent, a{sv} slots, d conf) | 意图+槽位（16 类） | FR-INT-01/02 |
| ParseWithContext | s(text), s(session_id) → (...) | 多轮指代 | FR-INT-03 |
| Transcribe | s(audio_path)/fd → s(text) | ASR | FR-ASR-02 |
| Speak | s(text), s(voice) → s(status)/fd | TTS | FR-ASR-03 |
| Wake | — → b | 唤醒（Super+B/词） | FR-ASR-01 |

### 7.2 Calendar（对应 FR-CAL）Object path: `/io/bianbu/Calendar`
| 方法 | 签名 | 说明 | FR |
|------|------|------|----|
| ListEvents | x(from), x(to) → aa{sv}(events) | 查询日程 | FR-CAL-01/03 |
| CreateEvent | a{sv}(event) → s(event_id) | 创建（需确认） | FR-CAL-02 |
| SetReminder | s(event_id), x(remind_at), b(tts) → b | 设提醒 | FR-CAL-04 |

Signals: `ReminderFired(s event_id, s title)`（±30s）。
event 结构：`{title, start, end, location, description}`。

---

## 8. 开发者 SDK API（Python `bianbu-agent-sdk`）

对应 FR-SDK-*。高层封装，内部转 D-Bus 调用。

```python
from bianbu_agent_sdk import Agent, tool, memory, permission, syscap, logger

class Agent:                      # FR-SDK-01 基类
    def on_start(self): ...
    def on_pause(self): ...
    def on_resume(self): ...
    def on_stop(self): ...
    def register_tool(self, fn): ...

@tool(permission="file.write",    # FR-SDK-02/03 工具+权限声明
      confirm="once_per_session",
      skill_package=False)         # =True 触发 FR-SDK-09 骨架生成
def fn(...): ...

# 记忆客户端（FR-SDK-04 → io.bianbu.Memory）
memory.store(key, value, ttl=0)
memory.get(key) -> str
memory.retrieve(query, top_k=5) -> list[tuple[str,float]]

# 系统能力（FR-SDK-05 → 各 D-Bus 服务）
syscap.files.read(path); syscap.app.invoke(skill_id, fn, **args)

# 分级日志（FR-SDK-06，自动附 agent_id）
logger.info(msg); logger.error(msg)
```
错误处理：SDK 将 D-Bus 错误码映射为 Python 异常（PermissionDenied, ConfirmRequired, QuotaExceeded ...）。

---

## 9. CLI 契约

### 9.1 bianbu-agent（FR-CLI-01~07）
| 命令 | 用法 | 退出码 |
|------|------|--------|
| init | `bianbu-agent init <name>` 生成模板 | 0 成功 |
| build | `bianbu-agent build [dir]` → `.bianbu-agent` | 0/非0 |
| install | `bianbu-agent install <pkg>` 装+权限确认 | 0/非0 |
| run | `bianbu-agent run [dir]` 开发热重载 | — |
| logs | `bianbu-agent logs <id> [--follow]` | — |
| status | `bianbu-agent status [<id>]` 与 DBus 一致 | — |
| uninstall | `bianbu-agent uninstall <id>` 清理 | 0/非0 |
| checkpoint | `bianbu-agent checkpoint <id>` | 0/非0 |

### 9.2 bianbu-skill（FR-SKL-09）
`bianbu-skill list` / `install <path>` / `call <skill-id>.<function> [args]` / `uninstall <skill-id>`。
输出格式：默认表格，`--json` 结构化。

### 9.3 bench / doctor
`bianbu-agent bench [--model m] [--compare m1,m2] [--json|--html]`（FR-BENCH-*）；
`bianbu-agent doctor`（FR-DOC-*）输出检查清单+修复命令，退出码非0表示存在待修项。

---

## 10. Skill 包清单格式（skill.toml / permissions.json）

对应 FR-SKL-05。
```toml
# skill.toml
name = "file-search"
description = "全盘语义文件检索"
trigger = ["找文件", "搜索文件", "find files"]
params = [{name="query", type="string", required=true}]
version = "1.0.0"
entry = "entry.py:execute"        # 或 shell 入口
```
```json
// permissions.json —— 复用 §1.2 Permission schema
[{"capability":"fs.read","domain":"data","risk_level":"L1","confirm":"once_per_session"}]
```

---

## 11. API 层可追溯性

| 服务/接口 | HLD 组件 | SRS FR |
|-----------|----------|--------|
| io.bianbu.Security | securityd（Capability/Confirm/Audit/Network/Meter） | FR-SEC-*/SBX-* |
| io.bianbu.AIHal | aihald（HAL/Model/Scheduler/Endpoint/KV） | FR-AI-* |
| io.bianbu.Loop | agent-runtimed（Loop Engine Executor） | FR-LOOP-* |
| io.bianbu.Runtime（Workspace 方法） | agent-runtimed（Workspace Manager，HLD §10） | FR-WS-* |
| io.bianbu.Runtime | agent-runtimed（FSM/Sandbox/Ckpt/Monitor/IPC） | FR-RTE-*/SBX-* |
| io.bianbu.Memory | memoryd | FR-MEM-* |
| io.bianbu.Skill | skilld（Registry/MCP） | FR-SKL-* |
| io.bianbu.Intent | intentd | FR-INT-*/ASR-* |
| io.bianbu.Calendar | calendard | FR-CAL-* |
| SDK/CLI | 工具链 | FR-SDK/CLI/BENCH/DOC |

TBD 影响：Memory 存储字段依 [TBD-5/6]；Calendar 后端依 [TBD-8]；Key Vault 依 [TBD-17]。

---
*BN-API-001 V1.0 · 输入 BN-HLD-001 + BN-SRS-001。内容由 AI 辅助生成。*
