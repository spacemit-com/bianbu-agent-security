# Runtime 安全接入代码导读

| 项目 | 内容 |
|---|---|
| 文档编号 | Bianbu-SEC-HANDOVER-003 |
| 版本 | V1.0 |
| 日期 | 2026-09-18 |
| 来源 | Security `9f085c2`；Runtime `145d1ea0`；现有测试与验收记录 |
| 状态 | MVP 已完成；维护交接资料，接手演练尚未执行 |

## 1. 先找当前路径

本篇路径均相对 R，即相邻 `bianbu-agent-runtime`。当前 Python 安全代码在 `bianbu_agent/security/`；旧文档中的 `bianbu_agent/security_runtime.py` 等路径已变化。内置插件源码在 `resources/plugins/bianbu.security/`，DEB 安装位置是 `/usr/share/bianbu-agent-runtime/plugins/bianbu.security/`。

| 文件/目录 | 作用 | 阅读时关注 |
|---|---|---|
| `bianbu_agent/security/security_runtime.py` | `SecurityRuntimeClient`、安全客户端发现和调用适配 | D-Bus 控制与 Worker UDS 选择、helper 使用条件 |
| `bianbu_agent/security/execution_runtime.py` | `ExecutionCoordinator`、`HostProcessBackend`、`BwrapBackend` | prepare/start/commit/abort/stop，网络与采集器更新 |
| `bianbu_agent/security/runtime_process/` | control、supervisor、worker、worker_rpc、protocol | 控制面与 Worker 的生命周期及通信 |
| `bianbu_agent/security/agent_registration.py` | `SecurityAgentRegistration`、逻辑 Agent 能力同步 | 注册、删除、内置 Agent 初始模式 |
| `bianbu_agent/security/security_middleware.py` | 确认、模式、Token 与模型/工具中间件 | 人工审批时序、Agent 上下文、模型边界 |
| `bianbu_agent/security/security_dlp.py` | `scan_request`、`scan_response`、`DLPDenied` | 历史/system 消息、输出流、错误终止 |
| `bianbu_agent/security/security_skill_dlp.py` | Skill 文本及扫描结果处理 | 读取 Skill 后进入 prompt 前的治理 |
| `bianbu_agent/security/security_tool_runner.py` | 工具执行边界 | 工具参数/返回值和安全上下文 |
| `bianbu_agent/security/security_errors.py` | 安全错误分类和呈现 | 不把网络超时一律叫“安全拦截” |
| `bianbu_agent/security/security_sandbox.py` | 沙箱配置、bwrap 参数与包装 | host/namespace 可见路径、资源约束 |
| `bianbu_agent/security/security_provider_policy.py` | 模型 Provider host 限制 | 网络失败和模型 endpoint 的关系 |
| `bianbu_agent/security/network_learning_privileged.py`、`network_learning_collector.py` | 采集注册与事件处理 | lease/cgroup 关联、状态与真实事件 |
| `bianbu_agent/security/syscall_collector.py`、`seccomp_audit.py` | syscall 采集与 seccomp 日志 | 真实执行证据与 Agent 关联 |
| `bianbu_agent/api/security.py` | Runtime 安全管理 API | operation 转发、管理权限、错误返回 |
| `bianbu_agent/runs/` | Run 生命周期及状态 | 拒绝后是否终止、有无继续执行 |

## 2. 插件现在如何执行

```text
resources/plugins/bianbu.security/plugin.yaml
  → hooks/security.<阶段>/hook.json
  → command 调用 scripts/<阶段>.py
  → lib/bridge.py、mapping.py、uds_transport.py 等
  → 共用安全客户端 / securityd
```

例如 `hooks/security.before_tool/hook.json` 声明 `PreToolUse`，命令使用 `${RUNTIME_PYTHON}` 执行 `$PLUGIN_ROOT/scripts/before_tool.py`。维护时同时检查声明、脚本和协议输出，不要继续新建旧式 `hook.py` 期望自动生效。

| 插件部分 | 作用 |
|---|---|
| `lib/mapping.py` | 工具名/元信息到 capability、scope 的映射，复合命令和 MCP 规则 |
| `lib/agent_id.py` | 当前逻辑 Agent ID 解析 |
| `lib/bridge.py` | 安全客户端连接、判权和降级处置 |
| `lib/uds_transport.py` | UDS 传输及 Worker 身份上下文 |
| `lib/__init__.py` | 脚本依赖的公开符号；新增符号时同步导出 |
| `scripts/before_run.py`、`after_run.py` | Run 前后安全处理 |
| `scripts/before_model.py`、`after_model.py`、`after_context.py` | 模型和上下文边界 |
| `scripts/before_tool.py`、`after_tool.py`、`on_error.py` | 工具前后与错误处理 |

脚本中的说明可能仍保留旧 hook 术语。判断真实调用方式看 `hook.json` 和 loader，不只看 Python 文件顶部注释。

## 3. 三条必须理解的调用链

### 3.1 人工审批在什么时候发生

模型生成工具调用后，中间件可以先触发 HITL；`before_tool` 发生得更晚。因此不能要求中间件读取“稍后才由 before_tool 写入”的决定。两处需要使用同一套能力与 scope 语义，避免出现页面没有审批却已经执行。

接手人应能在 `security_middleware.py`、插件 `scripts/before_tool.py` 和 `lib/mapping.py` 中追踪一次 CONFIRM。回归必须断言未批准时工具零执行，批准后只恢复对应操作。

### 3.2 DLP 覆盖哪些出口

当前输入、历史消息、system message、Skill、工具参数、工具结果和模型输出都可能携带敏感内容。`security_dlp.py` 在 normal 下根据当前策略重新扫描；历史数据不能因为曾经允许过，就跳过本次更严格策略。

模型原始流式回调如果先发布，再扫描最终文本，用户已看到原文。代码通过模型回调配置抑制原始流并发布治理后的消息；修改流式体验时必须保留这条约束，并跑 `tests/test_model_dlp_boundary.py`。

`DLPDenied` 明确携带终止语义。不要把它按普通低风险工具异常降级为放行。YOLO 则由可信模式查询决定跳过 DLP，不用本地 prompt/环境变量伪造。

### 3.3 不同解释器怎样使用安全客户端

安全客户端实现在 S 的 `impl/bianbu-securityd/client/`。Runtime 不维护第二套协议副本。受管 Worker 直接 UDS 调用，不能改由子进程代发以致 peer PID 变化；控制面 D-Bus 依赖 ABI 不兼容时才使用系统 Python helper。

客户端找不到、找到但 `dbus` 扩展 ABI 不匹配、找到但 securityd 拒绝身份，是三种不同问题，分别处理。不要把系统 Python 的所有 site-packages 塞入不同版本的虚拟环境。

## 4. 按需求定位改动范围

| 任务 | 第一站 | 至少验证 |
|---|---|---|
| 加一个有副作用的新工具 | `lib/mapping.py` + S 能力字典 | allow/confirm/deny、scope、真实工具零执行断言 |
| 修改模型上下文拼装 | `security_dlp.py` + 模型中间件 | 历史、system、工具结果、输出治理 |
| 修改 Worker 启动 | `execution_runtime.py` + `runtime_process/` | 租约成功/失败/过期、实例停止、PID/cgroup 匹配 |
| 修改网络模式 | API + execution coordinator + S 策略 | 保存值、effective 状态、真实请求与记录 |
| 修改安全页面 | API/operation + 前端源码仓 | contracts/adapter/mock/grant/测试，再构建资源 |

当前工作区未发现旧资料所称的相邻 `bibit-security-plugin/` 目录；Runtime 中存在构建资源。交接时需要由原维护人确认源码仓地址和构建同步流程，不应直接修改压缩后的 JS/CSS 当作源码维护。

## 5. 兼容性和仓库约束

Runtime 的安全客户端修复不意味着自动提高 `bianbu-agent-securityd` 最低依赖。确有新硬协议要求时，先说明兼容断点，再调整依赖。两仓各自提交，是否推送 Runtime 按该仓授权执行。

外部参考：[客户端传输说明](../../../bianbu-agent-runtime/docs/security-client-transports.md)、[Runtime 排障资料](../../../bianbu-agent-runtime/docs/ai-runtime-security-troubleshooting.md)。后者部分 YOLO 和旧插件路径说明早于当前实现，请结合本交接基线阅读。
