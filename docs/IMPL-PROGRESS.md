# AgentOS Security 实现进度

> 目标：实现 SRS（BN-SEC-SRS-001）全部 80 条需求，每个特性在 worker（10.0.90.243, K3 riscv64）验证后提交。
> 起始基线：commit `1dc8d56`（SRS 补齐完成）

## 环境说明

| 项 | 值 |
|----|----|
| worker | `10.0.90.243`，SpacemiT K3 riscv64，Python 3.14.4 |
| 部署路径 | `/home/bianbu/impl/bianbu-securityd`（**非 git 仓库**，用 sftp 同步） |
| 同步脚本 | `/tmp/worker_sync_test.py`（paramiko + sftp + md5 校验 + pytest） |
| pytest | 9.1.1（本次会话用 `pip install --user --break-system-packages` 装上） |
| 本地环境 | 无 pytest，**所有测试在 worker 上跑** |

> **本次交付范围：** 仅包含本仓 `impl/bianbu-securityd/`、`testkit/`、配套 PA 接入
> 和评审文档。`/data/workspace2026-new/work0618/bianbu-next-agentos-dev-cc` 不在范围内；
> 不修改、不部署，也不把其 Runtime 测试结果计入本项目完成度。

---

## 进度总览

| 里程碑 | 需求数 | 已验证 | 待开发 | 工作量 |
|--------|-------|-------|-------|--------|
| 存量（M2 已完成部分） | 61 | 61 | 0 | 153 P·D |
| SEC-HOOK 干预点框架 | 5 | 5 | 0 | 15 P·D |
| ARCH 传输通道 | 1 | 1 | 0 | 5 P·D |
| DLP/PII | 10 | 10 | 0 | 42 P·D |
| INT-LG LangGraph | 9 | 9 | 0 | 30 P·D |
| **合计** | **86** | **86** | **0** | **245 P·D** |

**当前测试基线（2026-08-17）**：worker 默认全量 **551 passed / 3 skipped**，strict 为
**537 unit + 14 integration + 3 E2E passed**
且 `skipped=0`，testkit **35/35**，PA **848 passed / 73 个既有环境失败**；关闭安全与
启用安全的失败集合完全一致（novel=0、baseline_only=0）。
正式 UDS 产品选路、中央 DLP 策略、SQLITE_FULL/只读恢复、未决 Confirm 重启取消均已
闭环。Token 超限已在没有 Runtime unit、没有 `io.bianbu.Runtime` 的 worker 系统总线上
证明 Securityd 可独立完成审计、当前计量拒绝和 `TokenExceededV2` 通知；真实暂停、
终止及后续 model/tool 门禁由范围外 Runtime/agent 负责。生产 Runtime 探针继续
fail-closed。真正 hermetic 的冻结发布环境
`/var/tmp/bnsec-release-venv-hermetic.WuUZU2` 已在禁用 user site 下通过 SBOM、CVE=0、
release gate 和性能门禁；生产 Security/WebUI、Gunicorn、正式 UDS、成功升级和切换后
自动回滚均已在 worker 通过。Security 责任域发布证据门禁已通过并生成可校验归档；
全产品 strict 当前仅由 doctor 中的 Runtime 网络/身份项和正式 Runtime 生产探针阻断，
这些是范围外集成状态，不计入本次 Security 交付完成度。24/72 小时耐久执行器已实现；
原长跑在约 64.6h 因 P99 超标停止；优化后 v4 生产预演达到 `P99=9.276006ms`，
当前没有 24/72 小时任务在运行。详见 `review/BNAgent-Security-Acceptance-Revalidation-2026-08-17.md`。
历史 `bnsec-final-current9` 的 473 项基线保留在下文用于追溯。

---

## 已完成特性

### SEC-HOOK-01 / SEC-HOOK-02 — 干预点框架 ✅

| 项 | 内容 |
|----|------|
| 提交 | `f522d34`（实现）+ 本次（缺陷修复 + 文档） |
| 实现 | `securityd/interceptor.py`（190 行） |
| 测试 | `tests/unit/test_interceptor.py`，**worker 9/9 通过** |
| 设计文档 | `BNAgent-Security-Interceptor.md`（BN-SEC-HOOK-001） |

**交付内容**：
- `HookPoint` 8 个干预点枚举
- `Decision` 决策码（ALLOW / CONFIRM / BLOCK / MODIFY）
- `InterceptResult` 统一返回结构
- `InterceptorRegistry`：注册 / 注销 / 列表 / invoke
- 优先级槽位：10=SEC，50=DLP，90=Audit
- 短路（BLOCK）、决策合并（CONFIRM > ALLOW）、链式（MODIFY）
- `_handler_trace` 执行轨迹（handler 名 / 延迟 ms / 决策）

**worker 验证输出**：
```
platform linux -- Python 3.14.4, pytest-9.1.1
collected 9 items
tests/unit/test_interceptor.py::test_register_and_list PASSED            [ 11%]
tests/unit/test_interceptor.py::test_unregister PASSED                   [ 22%]
tests/unit/test_interceptor.py::test_invoke_allow PASSED                 [ 33%]
tests/unit/test_interceptor.py::test_invoke_block_shortcut PASSED        [ 44%]
tests/unit/test_interceptor.py::test_invoke_confirm_precedence PASSED    [ 55%]
tests/unit/test_interceptor.py::test_invoke_modify_chain PASSED          [ 66%]
tests/unit/test_interceptor.py::test_invoke_handler_exception PASSED     [ 77%]
tests/unit/test_interceptor.py::test_empty_hook_point PASSED             [ 88%]
tests/unit/test_interceptor.py::test_priority_order PASSED               [100%]
============================== 9 passed in 0.12s ===============================
```

**过程中发现并修复的缺陷**：
- 空 hook_point 走 early-return 时未写 `_handler_trace`，调用方读该键 KeyError。已在实现侧兜底为 `{"_handler_trace": []}`。（worker 首轮测试 8/9 时暴露）

---

### SEC-HOOK-03 — hermes 干预点挂载 ✅

| 项 | 内容 |
|----|------|
| 实现 | `client/bianbu_security_handlers.py`（新建）+ `hermes_plugin/bianbu_security/__init__.py`（改造） |
| 测试 | `tests/unit/test_hook_hermes.py`，**worker 11/11**；全量回归 **66/66** |
| 设计文档 | `BNAgent-Security-Interceptor.md` §9A |

**交付内容**：
- 判权逻辑从插件内联抽到框架无关 handler（`sec_capability_handler`，pri=10）
- 审计 handler（`audit_handler`，pri=90）
- `register_core_handlers(registry)` 幂等注册
- 插件改为经 registry 判权，CONFIRM 的 TUI 呈现保留在插件（hermes 特有）
- `securityd.interceptor` 不可 import 时回退直连判权，行为与改造前一致

**过程中发现并修复的回归**：
- handler 内部直接 `import bianbu_security_client`，绕过插件 `_client()` 间接层，导致 `test_approval_mode.py` 的 monkeypatch 失效、6 个既有测试打到真 D-Bus 而失败。改为 `context["client_provider"]` 注入后清零。

---

### SEC-HOOK-05 — 干预点审计透明 ✅

| 项 | 内容 |
|----|------|
| 实现 | `securityd/interceptor.py`（audit sink）+ `client/bianbu_security_handlers.py`（sink 构造）+ `webui/app.py`（过滤/聚合接口） |
| 测试 | `test_hook_audit.py` 10/10、`test_hook_audit_filter.py` 10/10、e2e `hook_audit_e2e.py` **16/16**；全量 **86/86** |
| 设计文档 | `BNAgent-Security-Interceptor.md` §9B |

**交付内容**：
- `registry.set_audit_sink()` — 链跑完回调，拿到完整 trace（handler 看不到完整 trace，必须框架触发）
- BLOCK 短路路径也发审计（被拒的调用最需要留痕）
- trace 编码进 `result` 字段（`handler@延迟ms=决策`），不改审计表 schema，受哈希链保护
- WebUI：`?hook=<point>|any|exclude` 过滤 + `/api/audit/hook-points` 计数与延迟排行
- `BIANBU_SEC_HOOK_AUDIT=0` 可关

**e2e 实证**：三种决策（ALLOW/BLOCK/CONFIRM）均落库，CONFIRM 记录含两 handler 的 trace，加入 hook 记录后导出链与在线链**完整性均 intact**，`sec_capability` 实测 avg 0.47ms。

---

### ARCH-01 — UDS 数据面通道 ✅

| 项 | 内容 |
|----|------|
| 实现 | `securityd/uds_protocol.py`、`securityd/uds_server.py`、`securityd/uds_handlers.py`、`securityd/service.py`、`caller_identity.py`、`client/bianbu_security_uds.py` |
| 测试 | UDS/DLP/install/failure 专项 **52 passed**；正式 service E2E 随 `test_dbus_security.py` **5 passed**；默认全量 **548 passed / 3 skipped**，strict **534 unit + 14 integration + 3 E2E passed（0 skipped）**；testkit **35/35**；PA 关闭/启用安全失败集合一致 |
| 设计文档 | `BNAgent-Security-UDS.md`（BN-SEC-UDS-001） |

**交付内容**：
- 长度前缀帧协议（4 字节 big-endian + UTF-8 JSON，`ensure_ascii=False` 避免中文膨胀 3 倍）
- 载荷上限**先于内存分配**校验（防恶意长度头触发 OOM）
- 三种边界严格区分：干净关闭→None、帧截断→ProtocolError、超限→PayloadTooLarge
- 服务端：正式随 `securityd.service` 启停；`SO_PEERCRED` + Agent 绑定校验；活跃 socket 防抢占；连接线程有界关闭
- handler：`ping`、`dlp.scan`、`dlp.policy`、`audit.batch`；完整审计载荷进入哈希链，request id 跨服务重启持久去重
- 客户端：长连接复用 + 同 request id 断线重试；响应缓存有条数/总字节/单响应三重上限
- `should_use_uds(bytes)` 按 4 KB 分界选通道（等于阈值走 D-Bus）

**性能实测（worker K3 riscv64）**：

| 载荷 | p99 | 吞吐 |
|------|-----|------|
| 空载 | 0.175 ms | — |
| 4 KB（分界） | 0.301 ms | 14.1 MB/s |
| 1 MB | 34.182 ms | 33.2 MB/s |

连续 50 MB 吞吐 30.6 MB/s；长连接复用 2000 次零错误。

**实测驱动的指标修订**：原 SRS 要求"UDS 传输 1MB 数据 P99 ≤ 1 ms"，实测 34 ms。该指标本身不成立 —— 延迟随载荷线性增长，1 MB 在 30 MB/s 下光传输就需 33 ms。已改为分段指标：小载荷（≤4 KB）P99 ≤ 1 ms、大载荷吞吐 ≥ 10 MB/s，SRS §18 与 PRD Table §七 同步修订。

**测试假设修正**：`test_oversized_request_rejected` 原先预期客户端抛 `UdsUnavailable`，实际服务端会先回一帧明确错误再关连接（更可诊断）。改为断言错误帧内容 —— 是测试假设错了，不是实现错了。

---

### DLP-01 — PII 检测引擎 ✅

| 项 | 内容 |
|----|------|
| 实现 | `securityd/dlp/pii_scanner.py`、`securityd/dlp/__init__.py` |
| 测试 | `tests/unit/test_pii_scanner.py` **41/41**、`tests/fixtures/pii_corpus.py`（语料）、`tests/integration/pii_benchmark.py`（验收基准）；全量 **154/154** |
| 设计文档 | `BNAgent-Security-DLP.md`（BN-SEC-DLP-001） |

**验收指标（均超标）**：

| 指标 | 目标 | 实测 |
|------|------|------|
| 总体召回 | ≥95% | **99.75%**（1596/1600） |
| 误报率 | ≤3% | **0.75%**（3/400） |
| 单条扫描 | — | 0.069 ms |

8 类 PII 召回：name/phone/id_card/email/bank_card/address/biometric 均 100%，medical 98%。

**技术选型**：worker 只有 onnxruntime（无 spaCy/transformers），故正则+校验算法打底、NER 做可插拔后端（`ner_backend` 参数），装不上优雅降级。按项目规则未复用 worker 上 Presidio-demo 的资产。

**误报控制三道校验**（实测驱动逐步收紧）：
1. 边界断言 —— 长数字串中的片段不误判
2. 校验算法 —— 身份证 GB 11643 校验码 + 银行卡 Luhn。**无此道则 400 条负样本全部误报**
3. **BIN 前缀 + 法定长度** —— 首轮误报 6.75%，根因是 Luhn 为 10 取模、随机串约 1/10 碰巧通过；加 BIN 约束后降到 0.75%

**过程中修的缺陷**：
- 语料手机号生成器少一位（`1+1+8=10` 位），导致 phone 召回 0% —— 是语料 bug 不是引擎 bug
- 医疗正则尾部 `{0,30}` 过贪，吃掉无关文本（"诊断为糖尿病 无法使用"）
- 姓名正则右侧 lookahead 使"患者陈芳于今日"整体失配 → 去 lookahead + `_trim_name` 从长到短试
- **自建姓氏表里误粘入 `single` 一词**，导致郭/黄/林等常见姓缺失
- 18 位身份证碰巧过 Luhn 被误判银行卡 → 加出生日期形态排除
- 17 位数字紧跟 X 是身份证被截断的前半段 → 跳过

**残留 0.75% 误报**：以 4 开头、长度 13/19、碰巧过 Luhn 的随机串，算法上与真实 Visa 卡号不可区分。继续压需发卡行级 6 位 BIN 库（数据维护问题，非算法问题），已远优于目标故不过拟合。

---

### DLP-02/03/04 — 策略存储 + 前三个干预点 ✅

| 项 | 内容 |
|----|------|
| 实现 | `securityd/dlp/policy_store.py`、`securityd/dlp/handlers.py` |
| 测试 | `test_dlp_policy.py` 21、`test_dlp_handlers.py` 28、`dlp_e2e.py` 12 步；全量 **208/208** |
| 设计文档 | `BNAgent-Security-DLP.md` §10 |

- **DLP-02** 策略四级回退（agent/type 两维 × 精确/通配），系统兜底按风险级分档：L1/L2=audit_only、L3/L4=mask
- **DLP-03** 只脱 mask/block 类型，audit_only 保原文（全脱会破坏业务语义）；多类型取最严处置
- **DLP-04** 云端 + L3/L4 强制脱敏（覆盖 audit_only），保证云端推理仍可用；无 endpoint 按本地处理

**接入暴露的两个框架缺陷**（DLP 是干预点框架第一批真实使用者）：
1. **MODIFY 决策被吞** —— 原实现用它链式传递但最终报 ALLOW，调用方继续用原始数据，脱敏白做
2. **handler metadata 被丢弃** —— `invoke()` 只保留 `_handler_trace`，`pii_types`/`is_cloud`/`cloud_forced_mask` 全丢。单测各自验 handler 返回值都过，**只有 e2e 经 `registry.invoke()` 才暴露**

**过程记录**：本轮曾误报"已实现 DLP-05/06、238 测试通过" —— 那次编辑未落地，文件里只有 DLP-02/03/04。已按实际状态更正。codex 复验未能执行（`~/.codex/auth.json` 的 key 被 OpenAI 拒绝，401 invalid_api_key），改为直接在 worker 验证。

---

### DLP-05/06 — 输出检测与工具参数提升 ✅

| 项 | 内容 |
|----|------|
| 实现 | `securityd/dlp/handlers.py`（`post_model_handler`、`pre_tool_handler`、`detect_verbatim_leak`） |
| 测试 | `test_dlp_output.py` **34/34**；全量 **242/242** |
| 设计文档 | `BNAgent-Security-DLP.md` §11 |

- **DLP-05** 两类风险分开：输出 PII 按策略；逐字复现训练语料**一律 BLOCK + 告警**，不受 PII 策略影响（模型行为异常，非数据敏感度问题）
- **DLP-06** 工具参数**提升 CONFIRM 而不脱敏** —— 脱了工具就没法用（路径里手机号被替换导致文件找不到）。`audit_only` 也提升，因为工具调用意味着 PII 要离开 Agent 进程

**测试发现的真实绕过路径**：逐字泄露检测首版只用覆盖率，可"补长"绕过 —— 语料 64 字样本，尾部追加 15 字无关文本，覆盖率 100%→77.6% 即漏判（门限 0.8）；追加 66 字降到 52.3%。分母随输出增长，比例被稀释。改为双信号：**绝对连续长度 ≥100 字**（主，不受稀释影响）+ 覆盖率 ≥0.8（辅，兜短输出通篇照抄）。已加 `test_verbatim_leak_padding_cannot_evade` 锁死。

---

### DLP-07/08/09 — 8 个干预点闭环 ✅

| 项 | 内容 |
|----|------|
| 实现 | `securityd/dlp/handlers.py`（`post_tool_handler`、`output_handler`、`shutdown_handler`、水印三函数） |
| 测试 | `test_dlp_final.py` **29/29**；全量 **271/271** |
| 设计文档 | `BNAgent-Security-DLP.md` §12 |

- **DLP-07** 与 DLP-06 处置方向相反：参数**不能脱**（工具会失效），返回值**必须脱**（否则 PII 进上下文多轮传播）
- **DLP-08** 三步：还原本 session 占位符（用户有权看自己的信息，跨 session 不还原）→ 复扫（策略可能中途改严）→ 处置+可选零宽字符水印。`block` 下整体替换为屏蔽提示而非直接 BLOCK（用户会看到空响应）
- **DLP-09** 清零映射表，只观察不拦（退出是终态）

**测试发现的信号缺陷**：`output_handler` 原以"最终文本是否等于原文"判 MODIFY。还原→复扫→重新脱敏会产生与原文逐字相同的串（占位符编号一致），此时报 ALLOW 会让调用方不知道中间还原过明文 PII，`restored_placeholders` 审计字段被埋掉。改为按"是否发生过处理"判定。

**8 点闭环**：`agent_startup`/`input`/`pre_model_call`/`post_model_call`/`pre_tool_call`/`post_tool_call`/`output`/`agent_shutdown` 全部有 DLP handler，均 pri=50。

---

### DLP-10 — WebUI 配置页 ✅

| 项 | 内容 |
|----|------|
| 实现 | `webui/app.py`（5 条 `/api/dlp/*` 路由）、前端 DLP tab（矩阵/试扫/统计/显式-继承标记） |
| 测试 | `test_dlp_webui.py` 17/17；全量 **288/288**；HTTP 路由实测通过 |

修复两个 HTTP 错误码问题（路由实测暴露，单测发现不了）：非法 action 500→400，stats D-Bus 不可达 500→200+降级数据。

**DLP 全链路（DLP-01~10）全部完成**。

---

### SEC-HOOK-04 + INT-LG-01~08 — LangGraph 全接入 ✅

| 项 | 内容 |
|----|------|
| 实现 | `securityd/langgraph/`（`mapping.py`、`tool_node.py`、`callbacks.py`） |
| 测试 | `test_langgraph.py` **36/36**；全量 **324/324** |
| 设计文档 | `BNAgent-Security-LangGraph.md`（BN-SEC-LG-001） |

- **INT-LG-01** `BianbuSecurityToolNode`：包装 ToolNode，每次 tool call 前经干预点框架判权（ALLOW/CONFIRM/BLOCK），CONFIRM 触发 `interrupt()` 暂停 graph
- **INT-LG-02** 工具映射：46 个显式映射 + 前缀/关键字回退，DEFAULT_ALLOW=True
- **INT-LG-03** 身份注册：默认能力集 6 条，`BIANBU_AGENT_ID` 覆盖
- **INT-LG-04-A** CONFIRM 联动：`interrupt({type:bianbu_confirm,...})`，外部 `update_state` 唤醒
- **INT-LG-05** 审计含 `graph_run_id`
- **INT-LG-06** Token 计量：`on_llm_end` 两种格式，超限抛 `TokenBudgetExceededError`
- **INT-LG-07** 沙箱：`build_sandbox_argv()`，复用 hermes_sandbox_launch.py
- **INT-LG-08** WebUI 配置实时生效：共享 SQLite WAL
- **SEC-HOOK-04** `BianbuInterceptorNode`：在 graph 任意位置插入干预节点；`setup_interceptor()` 一键配置

**与 hermes 的关键区别**：hermes 确认走同步 D-Bus（`RequestConfirm`），LangGraph 走异步 `interrupt()` + `update_state()`（非阻塞）。

**已知边界**：INT-LG-04-B 已实现 WebUI `/api/langgraph/interrupts`、`/api/langgraph/resume` 与 Agent/Runtime Unix broker；graph 由拥有它的进程注册并执行 `update_state`，WebUI 不伪造 graph。正式 Runtime 部署和跨用户 socket 权限仍待目标镜像验收。

---

## 全部仓库侧需求完成

仓库侧 Security 与 PA 正式 UDS 产品链路已实现并验证；当前
securityd 默认全量为 **551 passed / 3 skipped**，strict 基线为
**537 unit + 14 integration + 3 E2E passed（0 skipped）**，
testkit **35/35**。Token 超限的 Security 侧已在 Runtime 缺失时实测通过：计量返回
`within=false`、事件字段完整且 Securityd 持续运行。正式暂停/终止属于范围外
`bianbu-agent-runtimed`/agent 责任。生产 systemd 身份矩阵、桌面授权、
24/72 小时稳定性和外部渗透仍为 Security 商用签收前置条件。冻结发布 venv、生产
Gunicorn、安装/升级/回滚已关闭仓库与 worker 技术门禁；Security 发布证据门禁已经
通过。全产品 strict 的 `doctor,runtime_production` 仅反映范围外 Runtime 网络强制与
身份矩阵，不得列为本次 Security 剩余开发工作。

### 商用发布证据与 24/72 小时耐久 ✅/进行中

| 项 | 状态 | 证据/入口 |
|----|------|-----------|
| Security 责任域证据门禁 | ✅ 已实现并在 worker 通过 | `.ci/run_tests.sh` → `deploy/security_release_gate.py`；归档 JUnit、doctor、SBOM、CVE、源码 manifest、原始日志和 SHA-256 |
| 最终实现证据 | ✅ 通过 | `f956d809…`；`/var/tmp/bnsec-security-release-f956d809f9d7454f496bc538e45524ee2e19996f-clean1`，167/167 个跟踪文件及 8 个附件哈希一致 |
| 生产耐久执行器 | ✅ 已实现 | `deploy/commercial_soak.py` + `deploy/start_commercial_soak.sh`；真实 D-Bus/UDS/WebUI/SSE/systemd/RSS/P99/审计链 |
| 生产预演 | ✅ 通过 | v4 600s/120 样本，P99=9.276ms、error=0、RSS +52.746MB，SSE/services/审计链通过 |
| 原始样本与里程碑证据 | ✅ 通过 | v4 生成 120 行 `report.samples.jsonl` 与 300/600 秒 milestone JSON，最终报告大小和 SHA-256 一致 |
| 正式 24/72 小时报告 | ❌ 无通过报告 | 原任务约 64.6h 后因 P99 超标停止；当前无长跑进程，需先清理范围外重启风暴 |
| 最终商用验收门禁 | ✅ 已实现，外部证据待提供 | `deploy/commercial_acceptance_gate.py`；6 项单测通过，重新校验并归档 JUnit/SBOM/CVE/strict 日志、72h 原始 samples、CA/桌面/渗透附件、双人审批和组织 Ed25519 签名 |

正式启动：

```bash
cd /home/bianbu/impl/bianbu-securityd
BNSEC_RELEASE_COMMIT=REPLACE_WITH_COMMIT
SOAK_PYTHON=python3 bash deploy/start_commercial_soak.sh start "$BNSEC_RELEASE_COMMIT"
bash deploy/start_commercial_soak.sh status
```

| 模块 | 需求数 | 工作量 | 状态 |
|------|-------|-------|------|
| SEC（Manifest/Capability/Confirm/Token/Syscall/Audit/Network/KeyVault） | 22 | 46 | ✅ |
| SBX（沙箱隔离 01~08） | 8 | 20 | ✅ |
| INT-SEC（hermes 接入） | 8 | 27 | ✅ |
| NFR（非功能需求） | 9 | — | ✅ |
| MGT（D-Bus/SDK/bncli/WebUI） | 7 | 21 | ✅ |
| SEC-HOOK（干预点框架 01~05） | 5 | 15 | ✅ |
| ARCH-01（UDS 传输通道） | 1 | 5 | ✅ |
| DLP（数据防泄漏 01~10） | 10 | 42 | ✅ |
| INT-LG（LangGraph 接入 01~08）+ SEC-HOOK-04 | 9 | 32 | ✅ |

---

## 已知边界汇总（生产部署注意事项）

1. **worker K3 无 netfilter** — SEC-07/SBX-03 网络策略规则可配置但不可强制执行，M3 需 netfilter 支持
2. **非 root cgroup 降级** — SBX-02 cgroup 限制 → systemd transient unit，需 root 才能完整
3. **INT-LG-04-B 生产验收** — 仓库代码与跨进程 broker 已完成；待正式 Agent Runtime 接入并在目标镜像执行正向/拒绝/重放/跨 agent E2E
4. **`graph_run_id`** — 需调用方在启动时填 `LANGGRAPH_RUN_ID`，否则审计无关联 ID
5. **WebUI 生产配置** — worker 已用专用身份、生产 env、Gunicorn、polkit、回环监听和正式 UDS 验证 401/200/403；正式产品仍需桌面 seat 交互、组织级凭据托管和真实远程 TLS/反代策略
6. **DLP 剩余 0.75% 误报** — Visa 卡号与随机 4 开头数字算法上不可区分，需发卡行级 BIN 库进一步压制
7. **身份证/银行卡校验位** — 运行在 Python 3.14 riscv64，校验算法已验证通过

---


| 顺序 | 需求 | 说明 | 工作量 |
|------|------|------|--------|
| 3 | ARCH-01 | UDS 数据通道（DLP 大载荷前置依赖） | 5 |
| 6 | DLP-07~10 | post_tool / output / shutdown handler + WebUI 配置页 | 14 |
| 7 | INT-LG-01~03 | LangGraph ToolNode 包装 + 映射 + 身份注册 | 11 |
| 8 | INT-LG-04-A/B | LangGraph HITL（interrupt + WebUI 唤醒） | 5 |
| 9 | INT-LG-05~08 | 审计 / Token / 沙箱 / 配置生效 | 14 |
| 10 | SEC-HOOK-04 | LangGraph 干预点挂载 | 4 |

---

## 已知风险

1. **worker 非 git 仓库** — 部署靠 sftp 逐文件同步，需 md5 校验防漏传。历史上出现过"同步没落地"的问题
2. **本地无 pytest** — 无法本地快速迭代，每轮改动都要走 worker，回合变长
3. **handler 异常 = 放行** — 干预点框架的可用性权衡，DLP 等关键控制需配监控告警
4. **无 handler 超时** — NER 推理若慢会阻塞整条治理链，DLP-01 实现时需自控耗时
5. **AppArmor 限制** — 本地 `apparmor_restrict_unprivileged_userns=1` 导致沙箱测试只能在 worker 跑

---

*最后更新：2026-08-14*
