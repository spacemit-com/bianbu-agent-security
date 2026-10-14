# AgentOS Security — 产品需求表格

> 文档编号：BN-SEC-PRD-TABLE  版本：v1.1  日期：2026-08-11
> 来源：Bianbu_Next_PRD_V0.9.md § 5.1（SEC）+ § 5.3.7（SBX）

---

## 一、安全子系统核心需求（SEC）

| 编号 | 功能名称 | 产品描述 | 验收标准 | 依赖模块 | 工作量(P·D) | 优先级 | 里程碑 | 状态 |
|------|----------|----------|---------|---------|------------|--------|--------|------|
| SEC-01 | Agent 权限声明框架 | 开发者发布 Agent 时在 manifest.toml 中声明所需权限（域 + 风险等级），支持 always / once_per_session / trusted 三级策略 | 安装无 manifest 的包被拒绝并提示；三级策略均可按语义正确触发确认流程 | manifest.py、models.py、SQLite | 5 | P0 | M2（2026.09） | ✅ 已实现 |
| SEC-02 | 能力注册表 | 用户可在 Agent 管理器（WebUI / CLI）中查看、撤销 Agent 权限；开发者可通过 CLI 查询和调整 | CLI 可查询和修改 Agent 权限；WebUI 可见并生效 | capability_registry.py、bncli、WebUI | 8 | P0 | M2（2026.09） | ✅ 已实现 |
| SEC-03 | 敏感操作确认门禁 | Agent 执行敏感操作（发邮件、删除文件、支付等）时弹窗确认，支持"每次确认"或"本次会话内信任"两种模式；L4 风险操作需二次确认 | 敏感操作必须经确认后才执行；超时（30 s）自动拒绝 | confirm.py、service.py（D-Bus 信号）、hermes TUI | 7 | P0 | M2（2026.09） | ✅ 已实现 |
| SEC-04 | 资源配额控制 | 按 token_budget 规格限制用量：单次对话 ≤10 万 token、单日 ≤50 万 token，超限由 securityd 发出 pause_and_notify 事件 | 达 limit_per_conversation 立即返回超限、发 `TokenExceeded`/`SecurityAlert`、记审计；Agent Runtime/agent 消费事件后暂停或终止 Agent；达 limit_per_day 后同样处理，次日 00:00 重置 | token_meter.py、engine.py、audit_chain.py、Agent Runtime/agent 事件消费者 | 7 | P1 | M2（2026.09） | ✅ 已实现（securityd）；跨模块消费联调 |
| SEC-05 | 系统调用拦截层 | 底层拦截危险系统调用（关机、重启、加载内核模块等），即使 Agent 被恶意利用也无法执行；支持 x86_64 / riscv64 双架构 | 恶意 Agent 无法执行 reboot / kexec / init_module 等调用 | seccomp_builder.py、sandbox.py | 5 | P0 | M2（2026.09） | ✅ 已实现 |
| SEC-06 | 审计日志引擎 | 记录 Agent 所有操作（读文件、连网、调模型），写入 SHA-256 哈希链防篡改日志，支持查看、导出和完整性验证 | 审计日志可导出、可离线验证完整性；人为篡改可被检出 | audit_chain.py、SQLite（WAL）| 8 | P0 | M2（2026.09） | ✅ 已实现 |
| SEC-07 | 网络白名单 | Agent 只能访问 manifest 中声明的域名，其他网络请求被拦截；策略规则可通过 WebUI 配置 | 网络策略生效，未授权流量被阻断（受限：worker K3 无 netfilter） | network_policy.py、iptables（平台依赖）| 4 | P1 | M3（2026.11） | 🟡 受限 |

---

## 二、轻量沙箱需求（SBX）

| 编号 | 功能名称 | 产品描述 | 验收标准 | 依赖模块 | 工作量(P·D) | 优先级 | 里程碑 | 状态 |
|------|----------|----------|---------|---------|------------|--------|--------|------|
| SBX-01 | 文件系统隔离 | bubblewrap 限制 Agent 进程于声明目录 + 只读挂载；未声明路径不可读写 | 访问声明范围外路径 100% 被拦截 | sandbox.py、bubblewrap、SandboxSpec | 5 | P0 | M2（2026.09） | ✅ 已实现 |
| SBX-02 | 资源配额（cgroup v2） | 默认 CPUQuota=100%、MemoryMax=2 GB、IOWeight=100，可按 Agent 覆盖配置 | 内存超 MemoryMax 触发 OOM 保护 | sandbox.py、systemd transient unit（非 root 降级）| 4 | P0 | M2（2026.09） | 🟡 部分实现 |
| SBX-03 | 网络隔离 | netfilter 白名单，默认 DROP，仅放行声明域名（与 SEC-07 对齐） | 未声明域名请求被阻断 | sandbox.py、iptables / nftables（平台依赖）| 3 | P0 | M3（2026.11） | 🟡 受限 |
| SBX-04 | 系统调用过滤 | seccomp-bpf 默认黑名单：reboot / swapon / kexec / init_module 等；过滤继承到沙箱内子进程 | 黑名单调用被拒绝；子进程 rc=99 可验证 | seccomp_builder.py、sandbox.py（--seccomp fd）| 4 | P0 | M2（2026.09） | ✅ 已实现 |
| SBX-05 | Capability 裁剪 | 启动时 --cap-drop ALL，去除所有非必要 Linux capabilities | 沙箱进程不持有 CAP_SYS_ADMIN 等危险 capability | sandbox.py（bwrap --cap-drop ALL）| 2 | P0 | M2（2026.09） | ✅ 已实现 |
| SBX-06 | 沙箱创建性能 | 沙箱随 Agent 冷启动创建，开销透明 | 沙箱创建不使 Agent 冷启动增加超 200 ms | sandbox.py、性能测试套件 | 3 | P0 | M2（2026.09） | ✅ worker 已验证 |
| SBX-07 | Fail-Closed | 沙箱创建失败时拒绝 Agent 启动并告警，绝不降级为无沙箱运行 | 失败时 Agent 不启动，记审计 | sandbox.py::launch、audit_chain.py | 2 | P0 | M2（2026.09） | ✅ 已实现 |
| SBX-08 | 命名空间隔离（Level 2） | PID / UTS / IPC / User namespace 完全隔离（Phase 2 增强） | Agent 进程树与宿主完全隔离 | sandbox.py、bubblewrap（--unshare-all）| 5 | P1 | Phase 2 | ⬜ 待规划 |

---

## 三、Agent 生命周期干预点框架（SEC-HOOK）

> 定义 Agent 执行过程中的 **8 个标准切面**，供各治理功能（Capability 判权、DLP、审计、配额、HITL）注册 handler。
> 参考 agent-governance-toolkit 模型，每个干预点可注册多个 handler，按优先级顺序执行；任一 handler 返回 BLOCK 即短路。

### 3.1 干预点定义

```
agent_startup → input → pre_model_call → post_model_call
                                                        ↓
agent_shutdown ← output ← post_tool_call ← pre_tool_call
```

| 干预点 | 触发时机 | 输入参数 | 返回值 | 短路规则 |
|--------|---------|---------|--------|---------|
| `agent_startup` | Agent 进程启动时（manifest 加载后、首次交互前） | agent_id, manifest, env | ALLOW / BLOCK + reason | 任一 BLOCK → 拒绝启动 |
| `input` | 用户输入进入 Agent 前（包括初始 prompt 与多轮对话） | agent_id, raw_input, session_id | ALLOW / MODIFY(new_input) / BLOCK | 任一 BLOCK → 拒绝输入；MODIFY 链式传递 |
| `pre_model_call` | LLM 调用前（prompt 已组装完成） | agent_id, full_prompt, model_name, is_cloud | ALLOW / MODIFY(new_prompt) / BLOCK / DOWNGRADE(local) | BLOCK → 阻断；DOWNGRADE → 改本地模型 |
| `post_model_call` | LLM 返回后（Agent 拿到响应、注入上下文前） | agent_id, response, tokens_used, model_name | ALLOW / MODIFY(new_response) / BLOCK | 任一 BLOCK → 响应作废 |
| `pre_tool_call` | 工具调用参数确定后、执行前 | agent_id, tool_name, args, capability | ALLOW / CONFIRM / DENY / MODIFY(new_args) | DENY → 工具不执行；CONFIRM → 等待用户决策 |
| `post_tool_call` | 工具执行完成、返回值进入上下文前 | agent_id, tool_name, result, execution_time | ALLOW / MODIFY(new_result) / BLOCK | 任一 BLOCK → 结果不进上下文 |
| `output` | Agent 向用户返回最终答案前 | agent_id, final_output, session_id | ALLOW / MODIFY(new_output) / BLOCK | BLOCK → 返回"内容已屏蔽" |
| `agent_shutdown` | Agent 正常/异常退出时 | agent_id, exit_reason, session_state | — | 只观察，无拦截 |

### 3.2 框架需求

| 编号 | 功能名称 | 产品描述 | 验收标准 | 依赖模块 | 工作量(P·D) | 优先级 | 状态 |
|------|----------|----------|---------|---------|------------|--------|------|
| SEC-HOOK-01 | 干预点注册机制 | 提供 `InterceptorRegistry`，支持按干预点 × 优先级注册 handler（数字越小越优先）；handler 签名统一为 `fn(context) -> Decision`；内置 3 个优先级槽：10(SEC/Capability)、50(DLP)、90(Audit) | 注册 3 个 handler 到 `pre_tool_call` 后按优先级顺序执行；单测覆盖注册/注销/优先级排序 | `securityd/interceptor.py` | 3 | P0 | ✅ worker 已验证 |
| SEC-HOOK-02 | 短路与决策合并 | 执行 handler 链时：遇 BLOCK/DENY 立即短路返回；多个 MODIFY 依次作用（新输出作为下一个 handler 的输入）；CONFIRM 优先级高于 ALLOW；DOWNGRADE 仅 `pre_model_call` 有效 | 单测验证：handler_a(MODIFY) + handler_b(MODIFY) 结果为两次变换叠加；handler_a(ALLOW) + handler_b(BLOCK) 返回 BLOCK | `securityd/interceptor.py::invoke` | 2 | P0 | ✅ worker 已验证 |
| SEC-HOOK-03 | hermes 插件挂载 | 在 hermes plugin 的 `register()` 中调用 `InterceptorRegistry.setup_hooks(manager)`，自动在 hermes 原生 hook（pre_tool_call/post_tool_call/on_session_end）中插入干预点调用；兼容已有 SEC capability 判权代码 | hermes 启动后 `pre_tool_call` 依次触发 SEC → DLP → Audit 三层 handler | `hermes_plugin/bianbu_security/__init__.py`、`securityd/interceptor.py` | 3 | P0 | ✅ worker 已验证 |
| SEC-HOOK-04 | LangGraph Checkpoint 挂载 | 为 LangGraph 提供 `BianbuInterceptorNode`，在 graph 的关键位置（human node 前/后、tool node 前/后、output 前）调用干预点；支持 `interrupt()` 与 CONFIRM 联动 | LangGraph graph 执行时各干预点正确触发；CONFIRM 可通过 `interrupt()` 暂停 graph | `securityd/langgraph/tool_node.py`、`langgraph.types.interrupt` | 4 | P0 | ✅ 已实现（仓库） |
| SEC-HOOK-05 | 干预点审计透明 | 每个干预点调用（无论结果）写入审计链：hook_point、handler_name、decision、latency_us；WebUI 审计页支持按 hook_point 过滤查看 | 审计日志可查"pre_tool_call 点有哪些 handler 执行了多久"；P99 延迟 ≤ 10 ms（不含 handler 自身耗时） | `audit_chain.py`、`securityd/interceptor.py`、WebUI | 3 | P1 | ✅ worker 已验证 |

---

## 四、hermes Agent 接入需求（集成层）

| 编号 | 功能名称 | 产品描述 | 验收标准 | 依赖模块 | 工作量(P·D) | 优先级 | 状态 |
|------|----------|----------|---------|---------|------------|--------|------|
| INT-SEC-01 | hermes 插件接入 | 通过 hermes plugin API 注入 pre_tool_call hook，拦截所有工具调用并查询 bianbu-securityd 判权 | hermes 执行工具前必经 hook；DENY 工具不执行 | hermes_plugin/__init__.py、plugin.yaml、bianbu_security_client | 5 | P0 | ✅ 已实现 |
| INT-SEC-02 | 工具→能力映射 | 47 个 hermes 工具（19 个 toolset）全部映射到 13 种 capability；映射表可扩展 | 任意工具调用均能找到对应 capability 判权，无漏判 | hermes_plugin/mapping.py | 3 | P0 | ✅ 已实现 |
| INT-SEC-03 | hermes TUI 审批 | CONFIRM 判决时主动调用 hermes 原生 TUI 审批弹框，用户在终端看到 [Allow once / session / permanent / Deny] | 审批弹框出现，选择结果实时生效 | cli_confirm.py、terminal_tool._approval_callback | 4 | P0 | ✅ 已实现 |
| INT-SEC-04 | 能力配置实时生效 | WebUI 修改能力配置后，hermes 下次工具调用立即应用新规则（无需重启） | 改 DENY→ALLOW 后 hermes 可执行；改 ALLOW→DENY 后立即被拦截 | capability_registry.py（SQLite WAL）、WebUI /api/capabilities | 3 | P1 | ✅ 已实现 |
| INT-SEC-05 | 沙箱内运行 hermes | 提供 hermes_sandbox_launch.py 在 bwrap 沙箱内启动 hermes agent，保留交互终端 | hermes chat 在沙箱内可正常交互；隔离生效（文件/进程/syscall） | hermes_sandbox_launch.py、sandbox.py | 4 | P1 | ✅ 已实现 |

---

## 五、LangGraph Agent 接入需求（集成层）

> LangGraph 是基于有向图的 LLM Agent 编排框架，节点为函数/工具，边定义执行流。
> 接入方案：在 `ToolNode` 执行前注入 `BianbuSecurityToolNode` 包装层，经 D-Bus 查询判权。

| 编号 | 功能名称 | 产品描述 | 验收标准 | 依赖模块 | 工作量(P·D) | 优先级 | 状态 |
|------|----------|----------|---------|---------|------------|--------|------|
| INT-LG-01 | LangGraph ToolNode 包装层 | 提供 `BianbuSecurityToolNode`，在工具执行前调用 `CheckPermission`；ALLOW 直接执行，DENY 返回结构化错误，CONFIRM 通过 interrupt 暂停 | 工具调用经 CheckPermission 判权；DENY 工具不执行；ALLOW 正常返回 | `securityd/langgraph/tool_node.py`、`bianbu_security_client.py`、`io.bianbu.Security` D-Bus | 5 | P0 | ✅ 已实现（仓库） |
| INT-LG-02 | LangGraph 工具→能力映射 | 为 LangGraph 常用工具及自定义工具建立 capability 映射表，支持精确/前缀/关键字匹配 | 已覆盖映射及未识别工具策略，默认按安全策略处置 | `securityd/langgraph/mapping.py` | 3 | P0 | ✅ 已实现（仓库） |
| INT-LG-03 | Agent 身份注册 | LangGraph Agent 启动时注册 agent_id；支持 `BIANBU_AGENT_ID` 覆盖和无 manifest 默认能力集 | Agent 能力可查询并受 WebUI 配置影响 | `securityd/langgraph/tool_node.py`、`bianbu_security_client.py` | 3 | P0 | ✅ 已实现（仓库） |
| INT-LG-04-A | LangGraph CONFIRM 决策联动 | BianbuSecurityToolNode 发布带 `graph_id/run_id/agent_id` 的 pending，并调用 `interrupt(type="confirm", ...)`；批准/拒绝由真实 graph 所在进程经 Command API 恢复 | graph 执行到 CONFIRM 时暂停；外部 update_state 后继续；拒绝时工具被跳过；未注册/缺 run_id fail-closed | `langgraph.types.interrupt`、`langgraph.pregel.Pregel.update_state`、Unix broker、`bianbu_security_client::check_permission` | 3 | P0 | ✅ 已实现（需 Runtime 部署验收） |
| INT-LG-04-B | WebUI 确认门禁对 LangGraph 生效 | WebUI 展示 LangGraph CONFIRM；Agent/Runtime 通过 Unix broker 暴露 pending，WebUI 将 `graph_id/run_id/agent_id` 转交 graph 所在进程执行 `update_state` | 触发后 WebUI 出现待批项；批准后真实 graph 继续并执行工具；拒绝后工具被跳过；错 run/未注册/重复 resume 100% 拒绝 | WebUI `/api/langgraph/interrupts`、`/api/langgraph/resume`、LangGraph Command API、Unix socket broker | 2 | P0 | ✅ 已实现（需 Runtime 部署验收） |
| INT-LG-05 | 审计全链路记录 | 每次工具调用写入审计链并关联 graph_run_id | 审计日志可导出，完整性校验通过 | `audit_chain.py`、`bianbu_security_client.py::audit_log` | 3 | P0 | ✅ 已实现（仓库） |
| INT-LG-06 | Token 配额计量 | LangGraph Agent 通过 callback 上报 token 用量；超限抛出 `TokenBudgetExceededError` | conv/day 配额生效，超限 graph 中断并审计 | `token_meter.py`、`securityd/langgraph/callbacks.py` | 4 | P1 | ✅ 已实现（仓库） |
| INT-LG-07 | 沙箱内启动 LangGraph Agent | 复用受控 bwrap 启动 LangGraph Agent，支持批处理和交互参数 | 沙箱启动和隔离探针通过 | `securityd/langgraph/callbacks.py`、`hermes_sandbox_launch.py`、bubblewrap | 5 | P1 | ✅ 已实现（仓库） |
| INT-LG-08 | WebUI 能力配置对 LangGraph 生效 | WebUI 修改能力配置后下一次 LangGraph 工具调用实时读取策略 | 改 DENY/ALLOW 后判权结果立即变化 | `capability_registry.py`、WebUI、`securityd/langgraph/mapping.py` | 2 | P1 | ✅ 已实现（仓库） |

---

## 六、DLP / PII 数据防泄漏需求

> 基于 **SEC-HOOK 干预点框架**实现数据防泄漏。PII 类型基线：姓名、手机号、身份证号、邮箱、银行卡号、家庭住址、医疗记录、生物特征。
> 各策略作为 handler 注册到对应干预点（优先级 50，在 SEC Capability 之后、Audit 之前）。

| 编号 | 注册点 | 功能名称 | 产品描述 | 验收标准 | 依赖模块 | 工作量(P·D) | 优先级 | 状态 |
|------|--------|----------|----------|---------|---------|------------|--------|------|
| DLP-01 | — | PII 检测引擎 | 提供 `PIIScanner`，支持正则 + NER 双引擎检测 8 类基线 PII；返回命中位置、类型、置信度；支持脱敏（替换为 `[PII-手机号]`）和完整保留两种输出模式 | 基准测试集（每类 ≥200 条）PII 召回率 ≥95%、误报率 ≤3% | `securityd/dlp/pii_scanner.py`、`tests/integration/pii_benchmark.py` | 8 | P0 | ✅ worker 已验证 |
| DLP-02 | agent_startup | 启动策略加载 | Agent 启动时读取 manifest 中 `[dlp]` 节（pii_types 白名单、on_detect 策略 allow/mask/block/audit_only），写入 DLP 策略缓存；无 `[dlp]` 节时使用系统默认策略（mask + audit）；作为 handler 注册到 `agent_startup` (pri=50) | 启动后 `dlp policy show <agent_id>` 可查策略；策略变更无需重启生效 | `securityd/dlp/policy_store.py`、`securityd/dlp/handlers.py`、SQLite | 3 | P0 | ✅ worker 已验证 |
| DLP-03 | input | 用户输入过滤 | 注册到 `input` (pri=50)：用户输入经 PIIScanner 扫描；按策略执行 mask（返回 MODIFY + 脱敏文本）/ block（返回 BLOCK）/ audit_only（返回 ALLOW + 记审计）；脱敏映射表存 session 内存供后续还原 | block 策略下含 PII 的输入被拒并提示用户；mask 策略下脱敏值进入 Agent，原值不出 session | `securityd/dlp/handlers.py::input_handler`、`pii_scanner.py`、`InterceptorRegistry` | 4 | P0 | ✅ worker 已验证 |
| DLP-04 | pre_model_call | Prompt PII 脱敏 | 注册到 `pre_model_call` (pri=50)：对完整 prompt 扫描 PII；本地模型直接脱敏后调用；云端模型高风险 PII 强制脱敏或阻断 | 云端调用的 prompt 中不含 L3/L4 PII；阻断事件写审计 | `securityd/dlp/handlers.py::pre_model_handler`、`audit_chain.py` | 5 | P0 | ✅ worker 已验证 |
| DLP-05 | post_model_call | 模型输出 PII 检测 | 注册到 `post_model_call` (pri=50)：LLM 响应扫描 PII；检出时按策略返回 MODIFY/BLOCK；同时检测逐字泄露模式并记录告警元数据 | 模型输出中的 PII 被脱敏或阻断；泄露检测可测量 | `securityd/dlp/handlers.py::post_model_handler`、`audit_chain.py` | 4 | P0 | ✅ worker 已验证 |
| DLP-06 | pre_tool_call | 工具参数 PII 过滤 | 注册到 `pre_tool_call` (pri=50，在 SEC Capability pri=10 之后)：工具参数 JSON 经 PIIScanner 扫描；含 PII 的工具调用自动提升决策为 CONFIRM；block 策略下返回 BLOCK | 含手机号的工具调用触发确认或阻断；与 SEC 判权正确合并 | `securityd/dlp/handlers.py::pre_tool_handler`、`InterceptorRegistry::invoke` | 4 | P0 | ✅ worker 已验证 |
| DLP-07 | post_tool_call | 工具返回值 PII 过滤 | 注册到 `post_tool_call` (pri=50)：工具返回值扫描 PII；检出时返回 MODIFY(脱敏后的返回值)，防止 PII 在 Agent 内多轮传播；大载荷可走 UDS | 工具返回值中的 PII 脱敏后注入上下文；原始返回值不写入审计明文 | `securityd/dlp/handlers.py::post_tool_handler`、UDS 通道 | 3 | P1 | ✅ worker 已验证 |
| DLP-08 | output | 最终输出 PII 审查 | 注册到 `output` (pri=50)：Agent 向用户返回最终答案前做最后一道 PII 扫描；支持水印注入；block/mask 策略可区分处理 | block/mask 策略均可验证；水印可提取 | `securityd/dlp/handlers.py::output_handler` | 4 | P1 | ✅ worker 已验证 |
| DLP-09 | agent_shutdown | 内存 PII 清零 | 注册到 `agent_shutdown` (pri=50)：Agent 正常/异常退出时清理 session 内的 PII 脱敏映射表并记录清理数量 | Agent 退出后 session 映射表不可访问；清理结果可审计 | `securityd/dlp/handlers.py::shutdown_handler` | 2 | P1 | ✅ worker 已验证 |
| DLP-10 | — | PII 策略 WebUI 配置 | WebUI 提供 Agent × PII 类型策略矩阵、触发统计和实时生效 | WebUI 修改策略后下一次干预点即按新策略执行；统计接口返回类型与决策分布 | `webui/app.py`（`/api/dlp/*`）、`securityd/dlp/policy_store.py` | 5 | P1 | ✅ worker 已验证 |

---

## 七、传输通道设计规范（D-Bus vs UDS）

| 编号 | 功能名称 | 产品描述 | 验收标准 | 依赖模块 | 工作量(P·D) | 优先级 | 状态 |
|------|----------|----------|---------|---------|------------|--------|------|
| ARCH-01 | D-Bus vs UDS 通道分工 | 按载荷大小、频率、方向明确两条通道的职责边界，见下表 | 设计评审通过；UDS 小载荷 P99 ≤1ms、吞吐 ≥10MB/s；无大载荷走 D-Bus | `securityd/uds_server.py`、`tests/integration/uds_benchmark.py` | 5 | P0 | ✅ worker 已验证 |

**ARCH-01 分工细则：**

| 维度 | D-Bus（`io.bianbu.Security`） | UDS（`/run/bianbu/securityd.sock`） |
|------|------------------------------|-------------------------------------|
| **适用场景** | 控制面、元数据、信号广播 | 数据面、大载荷、高频流式 |
| **消息大小** | ≤ 4 KB（D-Bus 内核限制 128 MB，但高延迟） | 任意大小，零拷贝 sendmsg |
| **典型调用** | CheckPermission、SetCapabilityGranted、SecurityAlert 信号、RespondConfirm、MeterTokens | PII 扫描内容流、审计日志批量写入（>1 KB）、工具返回值全文、沙箱内文件传输、流式 LLM 输出 token |
| **访问控制** | polkit / D-Bus policy（uid/gid/SELinux label）| 文件权限（`chmod 660`）+ peer credential（`SO_PEERCRED` uid 校验）|
| **连接模型** | 无状态单次调用 + 信号订阅 | 长连接（每 Agent 一个连接）或短连接（按请求） |
| **延迟目标** | P99 ≤ 10 ms（控制面可接受） | 小载荷（≤4 KB）P99 ≤ 1 ms；大载荷按吞吐 ≥ 10 MB/s 约束 |
| **实现位置** | `securityd/service.py` | `securityd/uds_server.py`（新建）+ `client/uds_client.py` |
| **DLP 接入** | DLP 策略查询（CheckDLPPolicy）走 D-Bus | PII 扫描内容（>4 KB prompt/输出）走 UDS |
| **审计接入** | AuditLog 元数据（agent_id、op_type、decision）走 D-Bus | 审计载荷全文（>1 KB tool 参数/返回值）走 UDS 批量写入 |

---

## 八、bianbu-agent（personal-agent）接入需求（集成层）

> 目标系统：`personal-agent` 仓库的 `bianbu-agent` —— YAML 驱动的个人 Agent 服务（FastAPI + LangGraph + MCP，304 个 Python 文件）。
> **能力级判权以 securityd 为准**；允许修改 `bianbu_agent` 主干。
> 已查实：它自带 8 个 HookPoint，与 SEC-HOOK 的干预点几乎一一对应；全部工具（内置/插件/MCP）走同一条 `_adapt_tool` 路径。

### 8.1 A 类 —— Hook 适配层（新增插件，不改主干）

| 编号 | 功能名称 | 产品描述 | 验收标准 | 依赖模块 | 工作量(P·D) | 优先级 | 状态 |
|------|----------|----------|---------|---------|------------|--------|------|
| INT-PA-01 | Hook 适配层骨架 | 以插件形式（`plugins/bianbu.security/`）注册到 bianbu-agent 的 8 个 HookPoint，桥接到 securityd 的 `InterceptorRegistry`；`plugin.toml` + `adapter.py`，主干零改动 | 8 个 hook 均被调用；`hook verify` 通过；卸载插件后 bianbu-agent 行为回归原状 | `bianbu_agent/hooks/`、`plugins/contributions.py`、securityd `InterceptorRegistry` | 3 | P0 | ✅ 已验证 |
| INT-PA-02 | 判权拦截（`before_tool`） | 在 `before_tool` 查 securityd `CheckPermission`；BLOCK 时 `raise SecurityDenied`（继承 `PermissionError`，沿用项目既有权限门惯例） | 改 WebUI 能力配置后 bianbu-agent 工具调用被拦截；审计链留痕 | `client/bianbu_security_handlers.py`（`sec_capability@10`） | 3 | P0 | ✅ 已验证 |
| INT-PA-03 | 异步边界桥接 | bianbu-agent 的 hook 是 `async`，securityd D-Bus 客户端同步阻塞 → 用 `run_in_executor` 包裹，避免阻塞 FastAPI 事件循环 | 并发工具调用不阻塞事件循环；单次判权开销可量化（见 V-03） | `asyncio.run_in_executor` | 1 | P0 | ✅ 已验证 |
| INT-PA-04 | 工具→能力映射（含 MCP） | bianbu-agent 工具清单映射到 securityd 能力；MCP 工具按 `<mcp_id>/<tool>` 前缀映射（hook 收到的是真 `qualified_id`，非 hash 编码名） | 任意工具都能解析出能力；`cronjob`→`calendar.write`、`evolution_undo`→`system.execute`(L3) | `securityd/langgraph/mapping.py` 扩充 | 2 | P0 | ✅ 已验证 |
| INT-PA-05 | agent_id 分层映射 | bianbu-agent 是多 Agent 架构 → 分层：全局默认 `com.bianbu.agent` + 按需覆盖单个 Agent `com.bianbu.agent.<agent_id>`；客户端缓存探测结果 | 未配置的 Agent 继承全局；配了覆盖的 Agent 用自己的；WebUI 新增覆盖后可失效缓存 | `capability_registry.py`、适配层 | 1 | P0 | ✅ 已验证 |
| INT-PA-06 | 风险分档拦截行为 | L1/L2 越权 → 返回错误交回模型（Agent 可换路径，全程记审计）；L3/L4 越权 → 终止整轮 run。避免 Agent 反复试探高危操作 | L1/L2 拦截后 Agent 收到 ToolMessage 错误；L3/L4 拦截后整轮中断 | 中间件 catch `SecurityDenied` 后按 `risk_level` 分流 | 2 | P0 | ✅ 已验证 |
| INT-PA-07 | fail 策略分档 | securityd 不可达时：L1/L2 fail-open（放行+记日志），L3/L4 fail-closed（拒绝）。避免 securityd 一挂整个服务全废，同时守住高危 | 断开 securityd 后低危工具可用、高危被拒；两种情况都留痕 | `BIANBU_SECURITY_FAIL_OPEN` + 分档逻辑 | 1 | P0 | ✅ 已验证 |
| INT-PA-08 | MCP 两层判权 | 层 1 接现成的 `MCPAuthorizer(agent_id, mcp_id) -> bool` 做整台 server 授权；层 2 在 `before_tool` 按工具粒度判权 + DLP 扫参数 | 未授权的 MCP server 整台被拒；已授权 server 内的单个工具仍受能力管控 | `bianbu_agent/mcp/plugin.py::MCPAuthorizer`（现成钩子，无需改 MCP 模块） | 2 | P1 | ✅ 已验证 |
| INT-PA-09 | 审计与 `on_error` | 各干预点写 securityd 审计链（SHA-256 哈希链）；`on_error` 是 bianbu-agent 独有点，只记审计不判权 | 审计可按 `hook:<point>` 过滤查询；`on_error` 事件有记录 | `audit_chain.py`、适配层 | 1 | P1 | ✅ 已验证 |

### 8.2 B 类 —— 主干改造（DLP 脱敏 + 动态 HITL + Token）

| 编号 | 功能名称 | 产品描述 | 验收标准 | 依赖模块 | 工作量(P·D) | 优先级 | 状态 |
|------|----------|----------|---------|---------|------------|--------|------|
| INT-PA-10 | DLP 脱敏改写通道 | hook 层的 `ContextPatch` 无参数改写能力 → 在 LangChain 中间件里用 `request.override(tool_call=...)` 改写工具参数实现脱敏。**主干零改动**（原方案要改 `_adapt_tool`，因 `awrap_tool_call` 是 wrapper 式而简化） | 含 PII 的工具参数被脱敏后才执行；`audit_only` 类型保持原文不脱 | `awrap_tool_call` + `ToolCallRequest.override()`、securityd DLP handler | 1 | P0 | ✅ 已验证 |
| INT-PA-11 | DLP 全链路挂载 | 8 个 DLP handler 挂到对应 hook 点：`after_context`→input、`before_model`→云端 L3/L4 阻断、`after_model`→输出+逐字泄露、`before/after_tool`→参数与返回值、`after_run`→还原+水印、`before_run`/退出→策略加载与清零 | 各点 DLP 生效；云端调用不含 L3/L4 PII；输出还原仅限本 session | securityd `dlp/handlers.py`（8 个 handler 已实现） | 3 | P1 | ✅ 已验证 |
| INT-PA-12 | 动态 HITL（原生审批弹窗） | securityd 判 CONFIRM 时触发 bianbu-agent **原生 HITL 弹窗**（用户在自己的 WebUI 上 approve/reject）。用 `InterruptOnConfig.when`（逐次求值的 callable）实时查 securityd，不必重建 `interrupt_on` | 高危工具触发原生审批弹窗；approve 后执行、reject 后拒绝；判权动态（按 capability×scope×risk×会话信任）而非静态 `requires_approval` | `langgraph/engine.py`（约 15 行：把 `when` 塞进现有 `interrupt_on` 构造） | 3 | P0 | ✅ 已验证 |
| INT-PA-13 | Token 配额计量 | 挂 `BianbuTokenCallback` 到模型（复用 INT-LG-06 已实现）；`RunContext` 无 token usage 字段且 runtime 无 `AFTER_MODEL` 调用点，故走 callback 而非 hook | 达 conv/day 上限时中断并记审计；次日 00:00 重置 | `securityd/langgraph/callbacks.py`（现成） | 1 | P1 | ✅ 已验证 |

### 8.3 C 类 —— 三种沙箱模式（agent.yaml 自行配置）

| 编号 | 功能名称 | 产品描述 | 验收标准 | 依赖模块 | 工作量(P·D) | 优先级 | 状态 |
|------|----------|----------|---------|---------|------------|--------|------|
| INT-PA-14 | 沙箱模式配置项 | `agent.yaml` 增 `sandbox.mode`：`off` / `agent`（整服务进程）/ `mcp`（仅 MCP 子进程）/ `tool`（单工具容器），由 Agent 自行选择；`agent` 与 `mcp` 不叠加（agent 模式下 MCP 子进程自动继承） | 四种取值均可配置且校验；配置错误有明确报错 | `bianbu_agent/agents/`（agent.yaml schema）、securityd `sandbox.py` | 2 | P0 | ✅ 已验证 |
| INT-PA-15 | 模式 1：整 Agent 沙箱 | bwrap 包裹整个 FastAPI 服务进程：文件隔离 + seccomp + cap-drop；MCP 子进程自动继承限制 | 沙箱内 uvicorn 绑 `0.0.0.0:9899` 宿主与跨主机可达；SQLite WAL（含 aiosqlite）读写正常；越界路径 100% 拦截 | securityd `sandbox.py`、bubblewrap | 3 | P0 | ✅ 已验证 |
| INT-PA-16 | 模式 2：MCP 子进程沙箱 | 只沙箱化 stdio MCP 子进程（第三方代码，风险最高）；主服务不受影响 | `npx` 起的 MCP server 在沙箱内可用；stdio 管道通畅；未声明路径不可访问 | securityd `sandbox.py`、`bianbu_agent/mcp/managed.py` | 3 | P0 | ✅ 已验证 |
| INT-PA-17 | 模式 3：单工具容器 | 按工具粒度隔离，Agent 可指定哪些工具进容器；需通用 runner 序列化参数与返回值 | 配置为容器执行的工具在子进程内跑；参数/返回值正确往返；隔离生效 | securityd `sandbox.py`、工具 runner（新建） | 4 | P1 | ✅ 已验证 |
| INT-PA-18 | 沙箱资源限额 | 三种模式均支持 cgroup 限额（CPU/内存/进程数）；非 root 降级为 systemd transient unit | 超内存触发 OOM 保护；非 root 下降级可用且有提示 | securityd `sandbox.py`（cgroup 部分已实现） | 1 | P1 | ✅ 已验证 |

---

## 九、管理与可观测性需求

| 编号 | 功能名称 | 产品描述 | 验收标准 | 依赖模块 | 工作量(P·D) | 优先级 | 状态 |
|------|----------|----------|---------|---------|------------|--------|------|
| MGT-01 | WebUI 管理台 | 浏览器管理界面（8 个功能页）：Agent 列表、能力管理、沙箱演示、审计日志、配额网络、确认门禁、安全告警、Web 终端 | 各页核心操作可用且落库生效；跨主机 ip:8787 可访问 | webui/app.py（Flask + SocketIO）、webui/static/ | 8 | P1 | ✅ 已实现 |
| MGT-02 | 实时信号推送 | SecurityAlert / ConfirmRequest / TokenExceeded 信号经 SSE 实时推送到 WebUI；确认门禁页可直接批准/拒绝 | CONFIRM 触发时页面即时出现待批项 | webui/app.py（SSE）、service.py（D-Bus 信号）| 3 | P1 | ✅ 已实现 |
| MGT-03 | Web 终端 | WebUI 内嵌终端支持 3 种模式：hermes chat（沙箱内）/ bwrap 沙箱 shell / 普通 shell | 三模式均可交互；沙箱模式隔离生效 | webui/app.py（pty.fork + SocketIO）、xterm.js | 4 | P2 | ✅ 已实现 |
| MGT-04 | 命令行工具（bncli） | install / capability list·revoke / audit export·verify 子命令；非 root 可运行 | 全部子命令可用；非 root 用户测试通过 | cli/bncli.py、SecurityEngine | 2 | P0 | ✅ 已实现 |
| MGT-05 | Python 客户端 SDK | 封装全部 D-Bus 方法为 Python 函数；BIANBU_SEC_SESSION=1 走会话总线便于测试 | 每个 D-Bus 方法有对应封装；hermes 插件与 WebUI 均可用 | client/bianbu_security_client.py、dbus-python | 3 | P0 | ✅ 已实现 |

---

## 十、优先级与工作量汇总

| 优先级 | 条数 | 工作量合计(P·D) | 说明 |
|--------|------|----------------|------|
| P0 | 46 | 162 | 必须（无则不可用） |
| P1 | 21 | 74 | 重要（核心体验） |
| P2 | 1 | 4 | 增强（演示/便利） |
| **合计** | **68** | **240** | — |

| 里程碑 | 目标日期 | 包含需求 | 工作量（P·D） |
|--------|---------|---------|-------------|
| M2 安全基础 | 2026.09 | SEC-01~06、SEC-HOOK-01~05、SBX-01/02/04/05/07、INT-SEC-01~05、MGT-01~05 | 111 |
| M3 策略执行 | 2026.11 | SEC-07、SBX-03/06、ARCH-01 | 15 |
| M4 LangGraph 接入 | 2026.12 | INT-LG-01/02/03/04-A/04-B/05/06/07/08 | 30 |
| M5 DLP/PII | 2027.Q1 | DLP-01~10 | 42 |
| **M6 bianbu-agent 接入** | **2027.Q1** | **INT-PA-01~18（A 类 9 + B 类 4 + C 类 5）** | **37** |
| Phase 2 | TBD | SBX-08（命名空间 Level 2 隔离） | 5 |
| **合计** | — | **68 条** | **240** |

### 10.1 M6 分解（bianbu-agent 接入）

| 子类 | 需求 | 条数 | 工作量 | 说明 |
|------|------|------|--------|------|
| **A 类** Hook 适配层 | INT-PA-01~09 | 9 | 16 | 新增插件，**主干零改动**；判权+审计+MCP 两层授权 |
| **B 类** 主干改造 | INT-PA-10~13 | 4 | 8 | DLP 脱敏通道 + 全链路挂载 + 动态 HITL + Token |
| **C 类** 三种沙箱模式 | INT-PA-14~18 | 5 | 13 | agent / mcp / tool 三模式，由 `agent.yaml` 配置 |

**B 类工作量已按阶段 0 实测结论下修**（7 → 8 P·D 含新增项，其中 DLP 脱敏 2→1、动态 HITL 5→3）：
`awrap_tool_call` 是 wrapper 式且 `ToolCallRequest` 自带 `.override()`，脱敏通道无需改 `_adapt_tool`；
`InterruptOnConfig.when` 是逐次求值的 callable，动态 HITL 无需重建 `interrupt_on`。

---

**状态图例**：✅ 已实现 / 🟡 部分实现或受限 / ⬜ 待开发或待测量
