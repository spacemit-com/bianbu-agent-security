# 能力映射技术方案

| 项 | 内容 |
|----|------|
| 文档编号 | BN-SEC-CAPMAP-001 |
| 版本 | V1.1 |
| 日期 | 2026-08-27 |
| 上游 | BN-SEC-BA-TECH-001（bianbu-agent 集成技术方案） |
| 相关需求 | INT-PA-04（工具映射）、INT-PA-08（MCP 两层判权）、INT-PA-02（判权拦截） |
| 状态 | 10 项决策已全部按建议实施并验证（落地记录见 §10） |

> **历史 P0（均已解决）**
>
> 1. **§9 两侧能力词汇表不一致** —— 已由 D-1 的权威字典、别名与 CAP-01
>    跨表一致性测试解决。
> 2. **§3.3 MCP 层 1 文档与行为矛盾** —— 已由 D-2 统一为 fail-closed，并在
>    首次连接时自动登记待授权项和输出配置台指引。
>
> 历史分析与决策依据保留在 §6~§9，实际落地状态以 **§10** 为准。

---

## 1. 设计目标与分层

### 1.1 为什么要映射

securityd 的判权单位是**能力**（`file.write`、`system.execute`），bianbu-agent 的执行单位是**工具**（`write_file`、`terminal`）。两者不是同一套词汇：

- 一个能力对应多个工具（`file.write` ← `write_file` / `delete_file` / `move_file` / `copy_file`）
- 工具名由插件作者自由命名，会随插件迭代变化
- securityd 要服务多种 Agent 框架（bianbu-agent、独立 LangGraph Agent、未来其它），不能绑死某一家的工具名

所以中间需要一层映射。**PA 不认识"权限"，securityd 不认识"工具"**，靠 capability 字符串解耦。

### 1.2 两级串联

```
PA 发起工具调用
   │
   ├─ ① before_tool hook 拿到 (tool_name, args)
   │     resolve_capability()  →  (capability, scope)
   │       └─ lib/mapping.py（PA 侧，25 条显式表）
   │            └─ 兜底委托 securityd/langgraph/mapping.py（60+ 条生态表）
   │
   └─ ② CheckPermission(agent_id, capability, scope)
         securityd 查能力注册表 → ALLOW / CONFIRM / DENY
```

映射发生在 PA 侧（第 ①步），判权发生在 securityd 侧（第 ②步）。换 Agent 框架只需重写第 ①步。

### 1.3 两份映射表的分工

| 位置 | 文件 | 条数 | 内容 |
|------|------|------|------|
| PA 侧 | `.bianbu-agent/plugins/bianbu.security/lib/mapping.py` | 25 | bianbu-agent 内置与目录插件工具（`terminal` / `read_file` / `bianbu.memory/memory_retrieve` …） |
| securityd 侧 | `impl/bianbu-securityd/securityd/langgraph/mapping.py` | 60+ | LangChain 生态工具名（`TavilySearchResults` / `ShellTool` / `GmailSendMessage` …）+ 前缀与关键字规则 |

PA 侧表小而精确，只管自家工具；securityd 侧表大而通用，兼顾其它接入方，并承担关键字推断的兜底职责。

---

## 2. 三层解析

`lib/mapping.py::resolve_capability(tool_name, args, *, client_provider, tool_metadata)`

返回 `(capability, scope)` 或 `None`。`capability` 为空字符串表示**显式免判权**。

### 2.1 第 ① 层：根据 Tool 元数据识别真正的 MCP 工具

MCP 工具和普通目录插件工具的限定名都可能是 `<owner>/<local_name>`。例如
`bianbu.memory/memory_retrieve` 是普通目录插件工具，并不是 MCP；因此不能再用
“工具名包含 `/`”作为 MCP 判据。权威判据来自 `ToolSpec.metadata`：

| Tool 来源 | 必需元数据 | 映射规则 |
|-----------|------------|----------|
| MCP | `origin="mcp"`，并携带 `mcp_id` | `("mcp.<mcp_id>", local_name)` |
| 普通目录插件 | `origin="plugin"` | 取 `local_name` 后进入 §2.2 显式表 |
| 旧调用方/元数据缺失 | 无 | 限定名从严按 MCP 处理，防止升级期间外部 server 静默放行 |

真正的 MCP 工具仍遵守“一台 server 配一条能力管其全部工具”的约定，`scope`
填写 `local_name`，需要时可细到单个工具。关键字推断只记录运维提示，不改变
`mcp.<mcp_id>` 的能力边界。

实测：

```
bianbu.memory/memory_retrieve + origin=plugin
    → ('data.memory', '')
bianbu.memory/memory_retrieve + origin=mcp,mcp_id=bianbu.memory
    → ('mcp.bianbu.memory', 'memory_retrieve')
some.server/frobnicate + origin=mcp,mcp_id=some.server
    → ('mcp.some.server', 'frobnicate')
```

来源元数据必须贯穿模型输出预判、HITL 审批事件、执行前后 hook 与审批恢复；任一
环节丢失元数据，都可能把普通插件误判为 MCP，或让审批前后的能力不一致。

### 2.2 第 ② 层：内置工具精确表

`BUILTIN_MAP`，25 条：

| 类别 | 工具名 | 能力 |
|------|--------|------|
| 系统执行 | `terminal` `shell` `bash` | `system.execute` |
| | `evolution_undo` | `system.execute` |
| 代码执行 | `python_repl` `execute_code` | `execute.code` |
| 文件读 | `read_file` `list_directory` | `file.read` |
| 文件写 | `write_file` `delete_file` `move_file` `copy_file` | `file.write` |
| 网络 | `web_search` `fetch_url` `http_request` | `network.access` |
| 通信 | `send_email` `send_message` | `message.send` |
| 数据 | `sql_query` | `data.query` |
| 用户数据/长期记忆 | `memory` `memory_record` `memory_retrieve` `todo` | `data.memory` |
| 会话检索 | `session_search` | `data.read` |
| 日历 | `cronjob` | `calendar.write` |
| **免判权** | `clarify` | `""` |

`clarify → ("", "")` 是显式免判权约定：hook 见到空 capability 直接 `return None`，不调 securityd。纯交互类工具（向用户提问）没有判权意义。

### 2.3 第 ③ 层：关键字推断

委托 `securityd/langgraph/mapping.py::resolve()`，三级：

1. **精确匹配** 60+ 条 LangChain 生态工具名
2. **前缀匹配**：`read_*` `write_*` `search_*` `fetch_*` `send_*` `execute_*` `run_*`
3. **关键字包含**，按固定优先级扫描：

| 顺序 | 关键字 | 推断能力 |
|------|--------|----------|
| 1 | `search` `lookup` `query` `browse` `web` | `network.access` |
| 2 | `read` `load` `list` `find` `get_file` `open_file` | `file.read` |
| 3 | `write` `save` `delete` `remove` `move` `copy` `append` | `file.write` |
| 4 | `exec` `run` `shell` `terminal` `bash` `repl` `code` | `system.execute` |
| 5 | `send` `email` `sms` `slack` `notify` `message` `post` | `message.send` |

实测 `fetch_weather_data → ('network.access', '')`（`fetch_` 前缀命中）。

**顺序敏感**：`run_query` 同时含 `query`（第 1 条）与 `run`（第 4 条），会被判为 `network.access` 而非 `system.execute` —— 风险更低的那个。这是隐患，见 §6.3。

### 2.4 scope：文件类能力的路径粒度

只有 `file.*` 开头的能力提取 scope，从 args 里按 `_PATH_KEYS`（`path` / `file_path` / …）找第一个非空字符串：

```
write_file {"path": "/etc/passwd"}       → ('file.write', '/etc/passwd')
read_file  {"file_path": "/home/x.txt"}  → ('file.read',  '/home/x.txt')
terminal   {"command": "ls"}             → ('system.execute', '')   ← 非 file.* 不提取
```

securityd 用 scope 做**最长前缀匹配**：可以只授权 `~/workspace` 而拒绝 `/etc`，同一个 `file.write` 能力按路径分别判权。

**局限**：`terminal` 的 `command` 参数不提取 scope，所以 `system.execute` 只能整体授权/拒绝，无法按命令细分。要做命令级管控需扩展 scope 提取规则（见 §6.4）。

---

## 3. MCP 详细方案

MCP（Model Context Protocol）是外部工具的主要来源，也是风险最高的一环 —— server 是第三方代码，以服务用户身份运行。

### 3.1 两种传输，风险面完全不同

`bianbu_agent/mcp/client.py` 支持两种：

| 传输 | 形态 | 风险面 | 沙箱可行性 |
|------|------|--------|-----------|
| `stdio` | 本地子进程（如 `npx -y @modelcontextprotocol/server-filesystem`） | 第三方代码在本机执行，可读写文件、发起网络请求 | ✅ 可用 bwrap 隔离 |
| `streamable_http` | 远端 HTTP 端点 | 无本地进程，但**参数与返回值经网络出境** | ❌ 沙箱无意义，需 DLP + 网络策略 |

**当前沙箱只覆盖 stdio**，这一点在代码结构上是明确的（`mcp/client.py::_open_session`）：

```python
if config.transport == "stdio":
    command, args = _apply_mcp_sandbox(config)      # ← 沙箱只在这个分支里
    ...
    async with stdio_client(parameters) as (read, write): ...
    return                                          # ← 提前 return
# 以下是 HTTP 分支，完全不经过 _apply_mcp_sandbox
async with httpx.AsyncClient(...) as http_client:
    async with streamable_http_client(config.url, ...) as (read, write, _): ...
```

HTTP 分支在 `return` 之后，**结构上不可能被沙箱覆盖**。

这意味着远端 MCP 的管控只能靠：
- 层 1/层 2 判权（能不能用这台 server、能不能调这个工具）
- DLP 参数脱敏（`before_tool` 的 `dlp_pre_tool` handler）
- 网络策略（securityd 的 `SetNetworkPolicy`，但那管的是 Agent 出站，不是 PA 主进程调 MCP）

远端 MCP 的数据出境已由 D-9 专门管控：`lib/mcp_transport.py` 根据来源元数据与
MCP 配置识别远端传输，`dlp_pre_tool` 将 `audit_only/allow` 提升为 CONFIRM；
来源或传输未知时按远端处理，避免缺配置形成绕过口。

### 3.2 两层判权

#### 层 1：整台 server 授权

位置 `bianbu_agent/server/runtime.py::_securityd_allows_mcp()`，在 MCP server **启动/连接前**调用：

```python
capability = f"mcp.{mcp_id}"
return sc.check_permission(agent_id, capability, "") != 2   # != DENY
```

判定"这个 Agent 能不能用这台 server"。CONFIRM 在层 1 按放行处理 —— 真正的审批留给层 2 的工具粒度。

#### 层 2：单工具粒度 + DLP

位置 `before_tool` hook，每次工具调用都过：

```
resolve_capability("some.memory.server/memory_retrieve",
                   tool_metadata={"origin":"mcp","mcp_id":"some.memory.server"})
    → ("mcp.some.memory.server", "memory_retrieve")
   ↓
bridge.invoke(PRE_TOOL_CALL, agent_id, {tool, capability, scope, args})
   ├─ sec_capability@10  CheckPermission → ALLOW/CONFIRM/BLOCK
   ├─ dlp_pre_tool@50    扫 args 里的 PII，可把 ALLOW 提升为 CONFIRM
   └─ audit@90           写 SHA-256 哈希链
```

`scope=local_name` 让同一台 server 下的不同工具可以分别授权。

#### 两层的职责划分

| | 层 1 | 层 2 |
|---|------|------|
| 时机 | server 连接前，一次 | 每次工具调用 |
| 粒度 | 整台 server | 单个工具 + 参数 |
| capability | `mcp.<mcp_id>` | `mcp.<mcp_id>` + scope |
| CONFIRM | 按放行 | 触发 HITL 审批 |
| DLP | 无 | 扫参数 |

### 3.3 层 1 fail-closed 与待授权登记（D-2，已解决）

历史 docstring 曾写成“未配置时放行”，与实际 DENY 行为矛盾。D-2 已统一为
fail-closed，并增加首次发现自动登记 `granted=0`，让运维能在配置台直接看到
待授权的 server。当前行为：

```
mcp.acme.memory（已授权） → ALLOW/CONFIRM   层1放行，层2处理工具粒度审批
mcp.brand.new.server（首次）→ 登记 granted=0 + DENY，配置台显示待授权项
mcp.foo（已撤销）         → DENY，不覆盖用户的撤销决定
```

securityd 不可达时层 1不阻断 server 初始化，但层 2 的 before_tool hook 仍按风险
分档处理，高危能力 fail-closed；这避免“服务暂时不可达”直接拖垮全部 MCP，同时
不允许高危工具静默执行。

### 3.4 MCP 能力命名约定

```
mcp.<mcp_id>              能力名
    └─ scope = <local_name>   可选，细到单个工具
```

`mcp_id` 是 MCP server 的公开 ID（如 `acme.memory`、`acme.filesystem`），来自 server 注册配置，不是进程名。普通目录插件 ID 即使恰好相同，也由 `origin="plugin"` 区分。

配置建议：

| 场景 | 配置方式 |
|------|----------|
| 整台 server 可信 | 注册 `mcp.<id>`，`granted=1`，`confirm=trusted`（仅当 risk_level ≤ L2） |
| 需要逐次确认 | `confirm=always` |
| 只放行部分工具 | 注册 `mcp.<id>` 并按 scope 分别 `SetCapabilityGranted(agent, cap, local_name, 1)` |
| 完全禁用 | `granted=-1`（已撤销）或不注册（fail-closed 自然拦截） |

### 3.5 stdio MCP 的沙箱

`mode=mcp` 时 `_apply_mcp_sandbox()` 用 bwrap 包裹子进程：

```
--unshare-user/pid/ipc/uts    命名空间隔离
--cap-drop ALL                丢弃全部 capability
--die-with-parent             父进程退出即清理
--ro-bind /usr /etc           只读系统目录
--bind <rw_dirs>              仅声明的目录可写
--tmpfs /tmp                  独立临时区
[--unshare-net]               net=false 时断网
```

白名单控制：只对 `cfg.mcp_servers` 列出的 server 应用沙箱。

**已知约束**：
- `npx -y` 首次拉包需网络，`net=false` 会失败 → 预装或单独放行
- `net=true` 时需绑 DNS 配置（`_dns_binds()`，处理 systemd-resolved 的符号链接）
- 沙箱配置是**进程级**（经环境变量传递），多 Agent 各配不同 mode 时后建覆盖先建

---

## 4. Skill 的能力管控定位

### 4.0 Skill 是什么

Skill 的载体是一个目录，必须含 `SKILL.md`（YAML frontmatter + 正文）：

```
skills/my-skill/
  SKILL.md        必需：frontmatter 里 name/description 必填，正文即 instructions
  <其它文件>       可选，被收集进 SkillSpec.resources
```

`SkillSpec` 七个字段：`name` / `description` / `instructions` / `resources` / `metadata` / `display_name` / `version`。

### 4.1 调研结论：Skill 不需要能力判权

读 `bianbu_agent/skills/loader.py` 与 `SkillSpec` 后确认，Skill 是**纯文本**：

```python
# default_engine.py:34-37 —— Skill 的唯一用途
sections.extend(
    f"## Skill: {generation.skills[name].spec.display_name}\n\n"
    f"{generation.skills[name].spec.instructions}"
    for name in agent.skills)
```

Skill 的 `instructions` 被拼进 system prompt，**没有执行路径**。

`SkillSpec.resources` 字段看似可疑（它收集 SKILL.md 之外的所有文件），但实测它只是**路径字符串映射表**：

```python
resources = {相对路径: 绝对路径 for 文件 in 目录下非 SKILL.md 的文件}
```

全代码库搜索 `.resources` 的使用点，只有 `contributions.py:186` 一处 —— 在 `__post_init__` 里做类型规范化。**没有任何代码读取或执行这些文件**。

### 4.2 但 Skill 有间接风险

Skill 不执行，却能**影响 LLM 的行为**：

| 风险 | 说明 | 现有管控 |
|------|------|----------|
| 提示注入 | 恶意 Skill 的 instructions 可诱导 LLM 调用高危工具 | ✅ 工具调用仍过 `before_tool` 判权 —— Skill 说服不了 securityd |
| 越权引导 | Skill 可教 LLM 绕过业务约束（如"忽略之前的限制"） | ⚠️ 无专门管控，但实际能力边界由判权决定 |
| 敏感信息泄露 | Skill 文本里若含密钥/内部信息，会进 prompt 送到云端 LLM | ⚠️ `after_context` 的 DLP 扫的是**用户输入**，不扫 Skill 注入的 context |

**核心判断**：Skill 的危害上限受工具判权约束。它能让 LLM *尝试* 调用 `terminal`，但调用本身仍要过 `system.execute` 判权。所以不需要为 Skill 单独设计能力模型。

### 4.3 建议的管控方式（非能力判权）

| 措施 | 层次 | 建议 |
|------|------|------|
| Skill 安装完整性 | 已有 | `content_digest`（目录 SHA-256）已在 SkillSpec.metadata 里，可用于篡改检测 |
| Skill 来源可信 | 建议新增 | 插件签名校验（securityd 已有 `VerifyManifest`，但未接 Skill） |
| Skill 文本 DLP | 建议新增 | 把 Skill instructions 一并交 `after_context` 的 DLP 扫描，防止 Skill 里的敏感信息进 prompt |
| Agent 可选 Skill 范围 | 已有 | `agent.skills` 白名单（`_validate_selector`） |

---

## 5. 其余需要能力管控的面

按 `plugins/installer.py` 的五类顶层目录白名单 `{tools, skills, hooks, lib, mcps}` 逐项审视，加上运行时的其它注册点：

| 能力面 | 是否执行代码 | 当前管控 | 需要能力判权？ | 说明 |
|--------|-------------|----------|---------------|------|
| **Tool** | ✅ | `before_tool` 判权 + DLP + 沙箱 | ✅ **已实现** | 主战场 |
| **MCP** | ✅ | 层 1 + 层 2 + stdio 沙箱 | ✅ **已实现** | 见 §3 |
| **Skill** | ❌ 纯文本 | Agent 白名单 + digest | ❌ 不需要 | 见 §4 |
| **Hook** | ✅ | ⚠️ **无判权** | ⚠️ **待评估** | 见下 |
| **lib** | ✅ 被 hook/tool 导入 | 随宿主 | ❌ 不需要 | 无独立执行入口 |
| **Console** | ✅ | ⚠️ **无判权** | ⚠️ **待评估** | 见下 |
| **Model / Provider** | ❌ 配置 | Admin API | ⚠️ 建议管控 | 见下 |

### 5.1 Hook：自身就是判权机制，但无人判权它

Hook 是**可执行代码**，且拥有比 Tool 更大的权力：

- 8 个干预点全程可见 run 的输入、输出、工具参数、返回值
- `BEFORE_RUN` / `BEFORE_TOOL` / `BEFORE_MODEL` 可抛 `PermissionError` **阻断执行**
- `ContextPatch` 可注入 context section、改 metadata、给 `direct_reply` 短路整轮

现有约束只有声明式 `permissions`：

```python
permissions=frozenset({"run.observe", "tool.inspect", "tool.decide"})
```

以及 `agent_selectable` 决定 Agent 能否选择性启用。但**没有任何 securityd 判权** —— 装上一个 hook 就无条件对每个 run 生效。

**风险**：恶意 hook 可以
- 在 `after_model` 里静默篡改 LLM 输出
- 在 `before_tool` 里放行本该拒绝的调用（它跑在 securityd 判权之前/之后取决于优先级）
- 在 `after_context` 里读取全部用户输入并外发

**这是当前最大的未管控面**。但也要看到：hook 的安装路径是文件系统（`.personal-agent/plugins/`），能往那里放文件的人本来就有本机权限。真正的边界在**插件安装**而非运行时判权。

建议见 §6.5。

### 5.2 Console：插件管理面

`ConsoleContribution` 提供 `describe` / `invoke` 两个回调，经 `POST /api/admin/v1/plugin-consoles/{plugin_id}/actions/{action}` 暴露给 WebUI。

实测这条路径**无鉴权**（PA 的 WebUI 整体无鉴权），且 `invoke` 是插件自定义代码。当前 `bianbu.memory` / `bianbu.channels` / `bianbu.scheduler` 都注册了 console。

风险等级低于 hook（需要主动调用，不是每个 run 都跑），但同样无判权。

### 5.3 Model / Provider：不执行代码但影响数据流向

`POST /api/admin/v1/providers` 可以注册任意 `base_url` 的 OpenAI 兼容端点。改一下 provider 就能把**全部对话内容导向任意服务器**。

这不是"执行代码"类风险，而是**数据出境**风险。现有管控：
- ✅ DLP 的云端 L3/L4 阻断（`before_model` hook 检出高敏 PII 时终止 run）
- ❌ 但没有"哪些 base_url 可用"的白名单

建议见 §6.6。

---

### 5.4 各能力面的判权必要性判据

判断一个能力面是否需要能力判权，看三个问题：

1. **它能否执行代码？** 不能 → 通常不需要判权（Skill）
2. **它的危害上限是否已被别的判权约束？** 是 → 不需要重复判权（Skill 的危害上限受工具判权约束）
3. **它的安装路径是否已构成边界？** 是 → 优先在安装期管控而非运行期（Hook）

按这三条，各面的结论：

| 能力面 | 能执行代码 | 危害受约束 | 安装即边界 | 结论 |
|--------|-----------|-----------|-----------|------|
| Tool | ✅ | ❌ 它就是危害源 | ❌ 可动态启用 | **需运行期判权**（已实现） |
| MCP | ✅ | ❌ 外部代码 | ❌ 可动态注册 | **需运行期判权**（已实现，两层） |
| Skill | ❌ | ✅ 受工具判权约束 | — | 不需要判权，管完整性即可 |
| Hook | ✅ | ❌ 权力大于 Tool | ✅ 需文件系统写权限 | **安装期签名校验**优于运行期判权 |
| lib | ✅ 被导入 | ✅ 随宿主 hook/tool | ✅ 同上 | 不需要独立管控 |
| Console | ✅ | ❌ 自定义代码 | ✅ 同上 | 低优先级，随 Hook 一并签名 |
| Model/Provider | ❌ | ❌ 影响数据流向 | ❌ Admin API 可改 | **需白名单**（非能力判权） |

---

## 6. 历史待决策项（已按 §10 落地）

### 6.1 【P0，已解决】MCP 层 1 的 fail 策略：统一文档与行为

**现状**：docstring 说 fail-open，代码实为 fail-closed（未注册 → DENY → 拦截）。实测确认。

| 选项 | 效果 | 代价 |
|------|------|------|
| **A. 保持 fail-closed，改文档** | 外部 server 默认不可用，安全 | 装新 server 要先配能力，且失败信息不直观 |
| B. 改代码为 fail-open | 符合原注释，运维顺手 | 装一台 MCP 就多一批免判权工具 |
| C. fail-closed + 首次连接时自动注册为 `granted=0`（待授权） | 安全且可发现 —— WebUI 能看到"有台 server 等授权" | 需实现自动注册 |

**最终采用 C**。既保持默认拒绝，又让运维在 WebUI 里看得见待授权项，不用去猜 server ID。

层 1 拦截日志会包含“请在 securityd 配置 `mcp.<id>`”的指引。

### 6.2 【P1，已解决】MCP 工具的推断优先级：1b 是否该降到 1c 之后

**现状**：`acme.fs/read_config` 因 `local_name` 含 `read` 被推断成 `file.read`，**不再受 `mcp.acme.fs` 能力管辖**。

实测对比（同一工具名，传不传 `client_provider` 结果不同）：

```
acme.fs/read_config   不传 provider → ('mcp.acme.fs', 'read_config')
                      传 provider   → ('file.read', '')
```

后果：
- 运维为 `acme.fs` 配了能力，却管不住它下面名字带 `read`/`write` 的工具
- `file.read` 常配成 L2/trusted 已授权 → 外部 MCP 工具直接拿到放行

| 选项 | 效果 |
|------|------|
| **A. 把 1b 移到 1c 之后**（MCP 优先用 `mcp.<server>`，推断仅兜底） | MCP 能力管辖完整，语义分类能力丧失 |
| B. 保持现状，文档标注 | 推断带来的分类便利保留，但管辖有洞 |
| C. 双能力校验：`mcp.<server>` 与推断能力**都要**通过 | 最严，实现成本高（要改 hook 逻辑） |

**最终采用 A**。MCP 的能力边界应由 server 身份决定，而非工具名字面。语义分类可以放在 `scope` 或 risk_level 上表达。

### 6.3 【P1，已解决】关键字推断的顺序敏感与误判

**现状**：关键字扫描按固定顺序，先命中先返回。`run_query` 含 `query`（第 1 条 network）与 `run`（第 4 条 system.execute），会判成风险更低的 `network.access`。

一个名为 `run_shell_query` 的工具会被判为 `network.access` 而实际是命令执行。

| 选项 | 效果 |
|------|------|
| **A. 改为「取所有命中中风险最高的」** | 保守，不会低判 |
| B. 命中多条时返回 `None`（交 DEFAULT_ALLOW/CONFIRM） | 明确不猜 |
| C. 保持现状 | 有低判风险 |

**最终采用 A**。推断本身就是启发式，宁可高判让用户确认，不可低判放行。

### 6.4 【P2，已解决】`system.execute` 的 scope 粒度

**现状**：只有 `file.*` 提取 scope，`terminal {"command": "rm -rf /"}` 与 `terminal {"command": "ls"}` 判权完全相同。

建议扩展 scope 提取：`system.execute` 用命令的第一个 token（可执行名）作 scope，这样能配"允许 `ls`/`cat`，拒绝 `rm`/`dd`"。需同步扩展 securityd 侧的匹配规则（目前是路径最长前缀，命令名需改为精确/前缀匹配）。

### 6.5 【P1，已解决】Hook 是否纳入能力管控

**现状**：hook 是可执行代码、权力大于 tool、无 securityd 判权。

| 选项 | 效果 | 代价 |
|------|------|------|
| A. 不管控，靠插件安装边界 | 零成本 | 装上即全权 |
| **B. 安装期校验签名**（接 securityd 已有的 `VerifyManifest`） | 挡住未签名/被篡改的 hook | 需建签名体系与密钥分发 |
| C. 运行期判权（每个 hook 一条 `hook.<id>` 能力） | 最细 | 每 run × 8 点额外判权开销；且判权本身要靠 hook 实现，有循环依赖 |

**最终采用 B**。运行期判权（C）有个根本矛盾：securityd 的判权入口本身就是 hook，用 hook 判 hook 会循环。安装期校验没有这个问题，且 securityd 已有 `VerifyManifest` 可复用。

### 6.6 【P2，已解决】Provider base_url 白名单

**现状**：可注册任意 `base_url`，等于可把全部对话导向任意服务器。

建议在 securityd 增一条能力 `model.provider`，scope 为 base_url 的 host，配合白名单。或更轻量：PA 侧加配置项列出允许的 host，非白名单拒绝注册。

---

## 7. 现状汇总

### 7.1 已实现且实测通过

| 项 | 状态 | 验证 |
|----|------|------|
| 三层映射（来源元数据 / 显式表 / 关键字推断） | ✅ | 普通插件、真实 MCP 与无元数据兼容路径均有回归测试，见 §2 |
| scope 路径提取 + 最长前缀匹配 | ✅ | `write_file {"path":"/etc/passwd"}` → scope 正确 |
| 显式免判权（`clarify`） | ✅ | 返回 `("", "")`，hook 直接放行 |
| MCP 层 1（整台 server） | ✅ | fail-closed + 首次发现登记待授权项，见 §3.3 / §6.1 |
| MCP 层 2（单工具 + DLP + 审计） | ✅ | testkit CAP-02：显式 MCP 元数据下按 server 能力判权 |
| MCP 工具不再落 DEFAULT_ALLOW | ✅ | testkit HOOK-04；普通插件 memory 同项验证为 `data.memory` |
| stdio MCP 沙箱 | ✅ | testkit SBX-01~05 + 真实 `server-filesystem` 全链路 |
| 判权三态 + fail-closed | ✅ | testkit PERM-02 |

### 7.2 缺口一览

| 编号 | 缺口 | 优先级 | 章节 |
|------|------|--------|------|
| G-1 | MCP 层 1 文档与行为矛盾 | ~~P0~~ ✅ 已解决 | §6.1 |
| G-2 | MCP 推断优先于 server 能力，管辖有洞 | ~~P1~~ ✅ 已解决 | §6.2 |
| G-3 | 关键字推断顺序敏感，可能低判 | ~~P1~~ ✅ 已解决 | §6.3 |
| G-4 | Hook 无任何判权/签名校验 | ~~P1~~ ✅ 已解决 | §6.5 |
| G-5 | `system.execute` 无命令级 scope | ~~P2~~ ✅ 已解决 | §6.4 |
| G-6 | Provider base_url 无白名单（数据出境） | ~~P2~~ ✅ 已解决 | §6.6 |
| G-7 | 远端 HTTP MCP 无数据出境管控（沙箱不覆盖） | ~~P2~~ ✅ 已解决 | §3.1 |
| G-8 | Skill 文本不过 DLP（敏感信息可进 prompt） | ~~P2~~ ✅ 已解决 | §4.3 |
| G-9 | Console `invoke` 无判权 | P3 | §5.2 |
| G-10 | 非 MCP 未知工具仍 `DEFAULT_ALLOW=True` | ~~P1~~ ✅ 已解决 | §7.3 |

### 7.3 G-10：`DEFAULT_ALLOW` 的取舍

非 MCP 的未知工具（`my_custom_widget` 这类推断不出的）现按 `unknown.tool`
能力交由 securityd，默认策略为 CONFIRM，不再静默放行。可用
`BIANBU_SECURITY_UNMAPPED=allow|confirm|deny` 显式调整开发/产品策略；非法值
回退到 `confirm`。

三个选项：

| 选项 | 效果 |
|------|------|
| A. 保持 `True` | 运维顺手，有洞 |
| **B. 改为返回 CONFIRM 而非 ALLOW** | 未知工具首次调用弹审批，用户决定；比全拒绝温和，比全放行安全（已采用） |
| C. 改为 `False`（全拒绝） | 最严，运维成本高 |

**最终采用 B**。与 §6.3 的思路一致：不确定时交给人，而不是替用户决定放行。

---

### 7.4 待你决策的清单

以下记录保留历史决策轨迹，最终采用方案见 §10.1：

| # | 决策点 | 我的建议 | 章节 |
|---|--------|---------|------|
| 1 | **能力词汇表统一**（`system.execute` vs `system.exec` 等 8 处不一致） | 以 securityd 清单为准改映射表 + 清单写入 SRS + 加 CI 校验 | §9.4 |
| 2 | **MCP 层 1 fail 策略**（文档说放行，实为拦截） | fail-closed + 首次连接自动注册为待授权 | §6.1 |
| 3 | **MCP 推断优先级**（推断会绕过 server 能力管辖） | 把关键字推断降到 `mcp.<server>` 之后 | §6.2 |
| 4 | **关键字推断顺序敏感**（`run_query` 被低判） | 取所有命中中风险最高的 | §6.3 |
| 5 | **未知工具的 DEFAULT_ALLOW** | 改为返回 CONFIRM 而非 ALLOW | §7.3 |
| 6 | **Hook 是否纳入管控** | 安装期签名校验（复用 `VerifyManifest`），不做运行期判权 | §6.5 |
| 7 | `system.execute` 命令级 scope | 用命令首 token 作 scope | §6.4 |
| 8 | Provider base_url 白名单 | PA 侧配置项列白名单 | §6.6 |
| 9 | 远端 HTTP MCP 数据出境 | 靠 DLP + 层 2 判权，不追加沙箱 | §3.1 |
| 10 | Skill 文本过 DLP | 把 instructions 一并交 `after_context` 扫描 | §4.3 |

第 1、2 项曾是 P0；现已分别由 D-1、D-2 落地解决。

---

## 8. 附：能力清单

securityd 当前已知能力（`GET /api/mapping` 返回）：

```
agent.delegate      data.memory       data.read         device.read
file.read           file.write        message.send      network.access
resource.generate   resource.train    skill.manage      system.execute
```

映射表实际用到的：

| 能力 | 典型 risk_level | 来源 |
|------|----------------|------|
| `file.read` | L2 | 内置表 + 推断 |
| `file.write` | L3 | 内置表 + 推断 |
| `system.execute` | L4 | 内置表 + 推断 |
| `execute.code` | L3 | 内置表 |
| `network.access` | L2 | 内置表 + 推断 |
| `message.send` | L3 | 内置表 + 推断 |
| `data.query` | L2 | 内置表 |
| `data.memory` | L2 | memory/todo 目录插件显式表 |
| `data.read` | L2 | session_search 显式表 |
| `calendar.write` | L2 | 内置表 |
| `mcp.<server>` | 按 server 定 | MCP 第 ① 层 |

---

## 9. 【历史 P0，已解决】两侧能力词汇表不一致

写本文档时逐项核对，发现一个此前未被察觉的严重问题：**映射表与 securityd 用的是两套不同的能力名**。

### 9.1 修复前实测数据

映射表引用 11 个能力，securityd 的 `/api/mapping` 清单有 13 个，**只有 3 个重叠**：

| 映射表用的名字 | securityd 清单里的名字 | 关系 |
|---------------|---------------------|------|
| `file.read` | `file.read` | ✅ 一致 |
| `file.write` | `file.write` | ✅ 一致 |
| `network.access` | `network.access` | ✅ 一致 |
| `system.execute` | `system.exec` | ❌ **同义不同名** |
| `communication.send` | `message.send` | ❌ **同义不同名** |
| `data.access` | `data.read` | ❌ **同义不同名** |
| `execute.code` | （无） | ❌ 缺失 |
| `execute.model` | （无） | ❌ 缺失 |
| `system.info` | `system.config` | ❌ 疑似同义不同名 |
| `calendar.read` / `calendar.write` | （无） | ❌ 缺失 |
| （未用） | `agent.delegate` `device.read` `data.memory` `resource.generate` `resource.train` `skill.manage` | 清单有但映射表不用 |

逐个真实判权（`com.bianbu.agent`）：

```
file.read            ALLOW
file.write           CONFIRM
network.access       ALLOW
system.execute       CONFIRM   ← 仅因测试期手工注册过才通
calendar.read        DENY
calendar.write       DENY
communication.send   DENY
data.access          DENY
execute.code         DENY
execute.model        DENY
system.info          DENY
```

**11 个能力里 7 个被拒**。`system.execute` 能通只是因为我在 testkit 测试期手工 `RegisterCapabilities` 注册过它 —— 掩盖了词汇不一致。

### 9.2 影响

在**干净部署**（没人手工注册过这些能力名）上：

- `send_email` / `send_message` → `communication.send` → **DENY**，通信类工具全不可用
- `python_repl` / `execute_code` → `execute.code` → **DENY**
- `cronjob` → `calendar.write` → **DENY**
- `sql_query` → `data.access` → **DENY**
- `terminal` / `shell` / `bash` → `system.execute` → **DENY**

即：**除了文件读写和网络访问，其它工具全被 fail-closed 拦掉**，而运维会以为是判权配置问题，实际是能力名根本对不上。

反过来，若有人按 securityd 清单注册了 `system.exec`（正确名），映射表送来的仍是 `system.execute`，照样 DENY —— 配了也不生效。

### 9.3 根因

两套词汇有不同来源：

- `system.exec` / `message.send` / `data.read` 出自早期 **hermes 接入文档**（`BNAgent-Hermes-Integration.md:94`、`BNAgent-Hermes-Approval.md:309`）
- `system.execute` / `communication.send` / `data.access` 出自**本次 bianbu-agent 接入**新写的映射表，也被 TechSpec 采用（`BNAgent-Security-BianbuAgent-TechSpec.md:414` 的 `_HIGH_RISK`）

两次接入各自造词，中间没有权威清单约束 —— securityd 侧也没有能力名枚举（代码里搜不到 `system.exec` 的定义，`/api/mapping` 的清单来自运行时数据而非常量声明）。

### 9.4 当时的待决策（最终选择 D，见 §10.1）

| 选项 | 效果 | 代价 |
|------|------|------|
| **A. 以 securityd `/api/mapping` 清单为准，改映射表** | 与既有 hermes 部署兼容 | 改 PA 侧显式表 + securityd 侧 60+ 条映射；TechSpec 的 `_HIGH_RISK` 同步改 |
| B. 以映射表为准，改 securityd 清单 | 语义更清晰（`execute` 比 `exec` 完整） | 破坏既有 hermes 部署的能力注册 |
| C. securityd 侧加别名表（`system.exec` ≡ `system.execute`） | 两边都不用改，向后兼容 | 词汇长期二元化，新人易困惑 |
| D. 定权威清单（写入 SRS）+ 双侧对齐 + 加 CI 校验 | 根治 | 工作量最大 |

**建议 D，分两步**：先按 A 快速止血（securityd 清单是既有部署的事实标准），同时把清单固化进 SRS 并加一条测试项校验"映射表引用的每个能力都在权威清单内" —— 这类问题应该由测试而非人工核对来兜住。

补充：`execute.code` / `execute.model` / `calendar.*` 在 securityd 清单里完全没有对应项，需要**新增能力定义**并确定其 domain / risk_level / confirm，不只是改名。

### 9.5 为什么 testkit 24 项全通过却没抓到

testkit 的 PERM-01/02 用的是自己注册的 4 个能力（`file.read` / `file.write` / `network.access` / `system.execute`），恰好是"3 个一致的 + 1 个我手工注册的"，所以判权三态验证通过。

HOOK-03 还曾在测试准备阶段临时注册并授予 `mcp.bianbu.memory`，把普通目录插件
`bianbu.memory/memory` 的错误 MCP 映射掩盖成“已授权可用”。V1.1 已移除该准备逻辑：
HOOK-03 改用 `read_file` 验证真实 `file.read` 审计；HOOK-04 同时断言普通 memory
插件映射为 `data.memory`、携带 MCP 元数据的真实 server 映射为 `mcp.<server>`。

修复前没有测试项校验“映射表引用的能力是否在 securityd 权威清单内”；现在由
CAP-01 校验 PA、LangGraph、hermes 三张映射表与权威字典的一致性。

---

## 10. 决策落地记录（D-1 ~ D-10 全部按建议执行）

§7.4 的 10 项决策已全部按"我的建议"实施并在 worker（SpacemiT K3，riscv64）上验证。
本节记录每项的**实际落点与取舍**，以及实施中发现的、原分析未预见的问题。

### 10.1 落地一览

| # | 决策 | 落点 | 关键取舍 |
|---|------|------|---------|
| D-1 | 能力词汇表统一 | 新增 `securityd/capabilities.py`（20 条 + `ALIASES`） | 以 hermes 为基准但把缩写补全（`system.exec`→`system.execute`），旧名进别名表 |
| D-2 | MCP 层 1 fail-closed | `server/runtime.py::_securityd_allows_mcp` | 拦截 + 自动登记 `granted=0`，让配置台能看到"有台 server 在等授权" |
| D-3 | MCP 推断优先级 | `lib/mapping.py` MCP 分支 | 一律返回 `mcp.<id>`，推断结果只写日志 |
| D-4 | 推断取最高风险 | `securityd/langgraph/mapping.py` | 前缀层与关键字层**合并成单一候选集**后取最高风险 |
| D-5 | 未映射工具处置 | `capabilities.unmapped_policy()` + 四处消费点 | 默认 `confirm`；非法配置值回落 `confirm` 而非 `allow` |
| D-6 | Hook 安装期签名 | 新增 `securityd/code_signing.py` + D-Bus `VerifyCodePackage` | 默认 `warn` 只对**未签名**宽容，篡改一律硬拒 |
| D-7 | 命令级 scope | 新增 `securityd/scope.py` | 复合命令返回哨兵 `<shell>`，不给"这条命令是什么"的假答案 |
| D-8 | base_url 白名单 | 新增 `bianbu_agent/security_provider_policy.py` | 挂在 store 写事务内，覆盖 HTTP/CLI/直接调 store 三条路 |
| D-9 | 远端 MCP 出境 | 新增 `lib/mcp_transport.py` + `dlp_pre_tool` 提档 | 不追加沙箱；`egress.remote` 时连 `allow` 也提 CONFIRM |
| D-10 | Skill 文本过 DLP | 新增 `bianbu_agent/security_skill_dlp.py` | 脱敏而非拦截；不弹确认（组装 prompt 时无人可问） |

### 10.2 V1.1：目录插件与 MCP 的来源判别修复

`bianbu.memory/memory_retrieve` 曾因限定名含 `/` 被误判为 MCP，导致 securityd
收到不存在且未授权的 `mcp.bianbu.memory:memory_retrieve`，WebUI 直接显示 DENY。
修复后以 `ToolSpec.metadata` 为权威来源，并把元数据贯穿模型输出预判、HITL、
before/after tool hook 和审批恢复；普通 memory 插件映射为 `data.memory`，真正 MCP
仍映射为 `mcp.<mcp_id>`。旧调用方若未传元数据，限定名继续从严按 MCP 处理。

2026-08-27 在 `10.0.90.237:9899` 用“输出你对我的记忆”真实验收：Run 经两次
`data.memory` 人工确认后完成并返回内容；同期审计 target 均为 `data.memory:`，
不再出现 `mcp.bianbu.memory:memory_retrieve → deny`。未修改能力数据库或永久授权。

### 10.3 原分析未预见的问题（实施中发现）

这几处都不是"按方案做"能带出来的，记下来是因为它们指向同一类盲区：
**同一语义在多处各自实现，其中一处漏改就是洞，而测试若不跨处比对就抓不到**。

**① D-4 的低判不止在关键字层**。§6.3 只指出关键字规则顺序敏感，实际前缀层有
完全相同的问题：`search_and_execute` 被前缀 `search_` 截住，走不到 `exec` 关键字，
判成 L2。两层各自"先命中先返回"，修一层等于没修。现在两层合并成单一候选集。

**② hermes 的命令级 scope 从未生效**。§6.4 说"只有 `file.*` 提取 scope"，
但 hermes 表其实早就给 `terminal` 配了 `scope_key="command"` —— 只是把**整条命令串**
原样塞进 scope。securityd 按最长前缀匹配声明 scope，运维配 `"rm"` 匹配不上
`"rm -rf /"`（既不相等也不构成 `rm/` 前缀），所以配任何命令名都无效。
不是"没有命令级 scope"，而是"有但是坏的"，后者更危险：配置台上看着已配好。

**③ `HIGH_RISK_CAPABILITIES` 被 D-1 的重命名打漏**。`lib/bridge.py` 的
fail-closed 档位清单里写的是 `communication.send`，而 D-1 后映射表产出
`message.send` —— securityd 不可达时「代表用户外发消息」不在高危档内，
被当低危 fail-open 放行了。**改能力名会静默破坏所有按名字硬编码的清单**，
这类清单本应引用权威字典。

**④ `granted` 的默认值与 engine 的硬编码冲突**（D-2 实施时发现）。
`engine.register_capabilities` 原本硬编码 `granted=1`，覆盖调用方传的值 ——
D-2 的"自动登记待授权"登记完立刻变成已授权，等于开了个洞而不是补上。
改 engine 尊重字段值后，`Permission.granted` 的默认值必须从 0 改成 1，
否则所有"注册即可用"的既有调用方全部退化成待授权。

**⑤ `.sig` 后缀整类排除会开夹带口子**（D-6 实施时发现）。摘要要排除包内签名
文件（否则写入签名就改了被签的摘要，自指涉），但按 `endswith(".sig")` 整类排除
会让包里任何 `payload.sig` 逃出摘要覆盖 —— 改它不改摘要，签名照样验得过。
现在只排除 `.signature` 这一个确定名字。

**⑥ D-5 新增符号漏加 `lib/__init__.py` 导出，导致 runtime 起不来**。
hook 从 `lib` 导入 `UNMAPPED_CAPABILITY` 等，而 `__init__.py` 未重新导出 →
`ImportError` → `RuntimeStartupError`。在 worker 上实测复现后修复。
这说明**插件的 `lib/__init__.py` 是隐式契约**，加符号必须同步。

### 10.4 D-7 的核心取舍：不给假答案

§6.4 建议"用命令的第一个 token 作 scope"。实施时发现这个建议照做就是个洞：

```
"ls; rm -rf /"      首 token 归一化后是 ls   —— 白名单放行，实际执行 rm
"ls && rm -rf /"    首 token 是 ls
"ls | tee /etc/x"   首 token 是 ls
"echo $(rm -rf /)"  首 token 是 echo
"env ls"            首 token 是 env（包装器，真正执行的是参数）
```

**命令串里只要含 shell 元字符，"这条命令是什么"就没有单一答案**。所以实现不给
答案：返回哨兵 `<shell>`，它不是合法可执行名、也不含 `/`，配任何命令名都匹配
不到，于是落回该能力的默认声明（`system.execute` 是 L4 恒确认）。

同理 `command_scope` 永不产出含 `/` 的 scope —— 否则会被 registry 的**路径**前缀
规则误匹配（声明 `ls` 会匹配请求 `ls/x`）。这条不变量由测试断言守住。

### 10.5 测试覆盖

| 层 | 数量 | 覆盖 |
|----|------|------|
| securityd pytest | 406 passed / 3 skipped | 含 `test_code_signing`(28)、`test_scope`(51) |
| PA pytest | `test_provider_host_policy` 29 + `test_security_error_surface` 13 passed | D-8 白名单含后缀欺骗/userinfo/无 scheme；错误透传含前后端契约断言 |
| testkit（真 securityd + 真 PA） | 34/34 | CAP-01~04、MCP-01、CODE-01、SCOPE-01、EGRESS-01、SKILL-01、ERR-01 |

新增的 9 项 testkit 用例都带**跨处一致性断言**，针对 §10.3 那类盲区：
- CAP-01 三张映射表的能力名都在权威字典内（当初正是它缺失才让 21 个名字分散三处）
- CAP-04 PA 插件与 securityd 的 `unmapped_policy()` 必须一致（不一致会让两条判权路径行为分叉）
- SCOPE-01 精确匹配表 64 条无一被推断层改写

### 10.6 附带修复：安全拦截的原因透传（用户报的原始症状）

goal 的第 2 项：撤销授权后 `web_search` 在前端只显示「发送失败，请稍后再试」。
HITL 链路本身是另一个问题（已在 D-0 阶段修好 —— `InterruptOnConfig.when` 在
`after_model` 求值，比 `before_tool` hook 早一整个阶段，读不到 hook 写的
metadata）。这里记的是**错误呈现**这一段。

三段信息丢失，缺任一段用户就只能看到通用文案：

| 位置 | 丢了什么 |
|------|---------|
| `run_manager` 的 except 分支 | 一律 `RunError(code="run_failed")`，把 `SecurityDenied` 的结构压成泛化 code |
| `api/runs.py::_project_events` 兜底分支 | 只取 code/message，丢掉 `details` |
| 前端 SSE `item.type === 'error'` | 无条件 `addBotMessage(t('error_send'))`，后端给的 code 与 message 整条丢弃 |

**为什么这不只是"文案不好"**：用户看到"系统故障，重试可能会好"，
实际是"没有授权，重试一万次也一样"。方向完全相反 —— 一个让人等，
一个让人去授权。运维同样定位不到是哪个工具缺哪条能力。

修复要点：

- 新增 `bianbu_agent/security_errors.py`，**按属性识别而非 isinstance**：
  `SecurityDenied` 定义在插件目录，而插件可卸载，硬 import 会让主干依赖一个
  可能不存在的插件。要求同时具备 `capability` + `reason` + `risk_level`，
  避免把普通 `PermissionError`（文件权限不足）误判成安全拦截 ——
  那会提示用户"去配置台授权能力"，而问题在文件系统。
- 区分 `security_denied`（明确拒绝 → 去授权）与 `security_unavailable`
  （securityd 不可达的 fail-closed → 去修总线）。混为一谈会让人走错方向。
- 前端 `details` 里的 `tool` / `scope` 可能源自模型生成的参数（外部输入），
  一律 `escapeHtml`，不进 `renderMarkdown`。

实测（真实 PA + 真实 securityd，撤销 `network.access` 后调 `web_search`）：

```
code    = security_denied
message = [bianbu-security] 权限被拒绝：web_search 需能力 network.access（scope=-），未授权或已撤销
details = {tool: web_search, capability: network.access, risk_level: L3,
           decision: BLOCK, degraded: false, terminate_run: true}
```

testkit **ERR-01** 守住这条链路（真实 run，非 mock）；
`tests/sdk/test_security_error_surface.py` 13 项含前后端契约断言 ——
code 常量必须同时出现在 JS 的 `SECURITY_ERROR_CODES` 里、SSE error 分支
必须走 `addRunErrorMessage`、安全提示不得对外部输入走 markdown 渲染。

### 10.7 关于 PA 全量回归的数字

worker 上 PA 全量是 **72 failed / 802 passed**。用 `BIANBU_SECURITY=0`
（关掉全部安全接入）跑同一套，结果**完全一致（72 failed / 802 passed）**，
证明这 72 项与安全接入无关。已定位的原因：

| 原因 | 影响面 |
|------|--------|
| worker 上的副本不是 git 仓库，`git ls-files` 退出 128 | 仓库卫生类测试（`test_single_source_implementations` 等） |
| 无浏览器 driver（`Connection closed while reading from the driver`） | `tests/sdk/console/test_browser_contract.py` 全部 |
| 非交互 SSH 缺 `~/.local/bin`，`uv` 找不到 | 打包类测试（须 `export PATH` 才能跑） |
| riscv64 上 2 秒超时不够 | `test_queued_steering` 等含固定 deadline 的用例 |

早前记录的"6 failed 基线"是另一环境的数字，在这台 worker 上不成立。
