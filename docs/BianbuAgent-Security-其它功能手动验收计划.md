# bianbu agent + security 其它功能手动验收计划

| 项 | 内容 |
|---|---|
| 目的 | 汇总已完成的 file.read、file.write、system.execute 手测基线，并继续验收 bianbu agent + bianbu-securityd 的其它能力和安全链路 |
| 环境 | worker 10.0.90.243（riscv64）；PA http://10.0.90.243:9899；Security WebUI worker 回环 127.0.0.1:8787；testkit http://10.0.90.243:9700 |
| 权威实现 | impl/bianbu-securityd/securityd/capabilities.py、PA 的 bianbu.security 插件、testkit/README.md |
| 原则 | 真实 PA 工具调用是端到端验收；/api/check、D-Bus 只能构造策略/辅助定位，不能代替真实工具调用 |

## 1. 验收前准备

### 1.1 服务和地址

所有验证默认在 worker 上，启动顺序固定为 securityd → PA → WebUI/testkit。

~~~bash
ssh -o BatchMode=yes -o StrictHostKeyChecking=no bianbu@10.0.90.243 \
  'hostname; uname -m; ./start-bianbu-securityd.sh --status; ./start-bianbu-agent.sh --status'
curl -fsS http://10.0.90.243:9899/api/v1/agents
curl -fsS http://10.0.90.243:9700/api/status
~~~

uname -m 必须是 riscv64。securityd 未启动时 PA 仍可能 HTTP 200，但判权处于降级状态，不能据此验收。改 securityd 后执行 start-bianbu-securityd.sh --restart；改 PA 主体或插件后重启 PA。

### 1.2 访问配置台

Security WebUI 默认只监听 worker 的 127.0.0.1:8787，开发机开隧道：

~~~bash
ssh -N -L 8787:127.0.0.1:8787 bianbu@10.0.90.243
~~~

浏览器访问 http://127.0.0.1:8787。不要为测试长期使用 --lan；WebUI 有管理接口和 Web Terminal。生产开启认证时，所有写请求必须通过认证会话并带 CSRF。

| 用途 | 接口 |
|---|---|
| Agent 列表/详情 | GET /api/agents；GET /api/agents/<id> |
| 工具/能力映射 | GET /api/mapping |
| 手动判权 | POST /api/check |
| 注册/授权/撤销 | POST /api/agents/<id>/capabilities/add；POST /api/agents/<id>/capabilities/grant |
| 审计 | GET /api/audit?agent=<id> |
| DLP | GET /api/dlp/matrix?agent=<id>；POST /api/dlp/policy；POST /api/dlp/scan |
| Token/网络/沙箱 | GET/POST /api/agents/<id>/token；GET/POST /api/agents/<id>/network；GET /api/agents/<id>/sandbox |

### 1.3 身份和基线

PA 本地 Agent ID 与 securityd Agent ID 不能混用：

- PA Run 通常使用 personal-agent-default；
- securityd 能力主键通常是 com.bianbu.agent，实际值以 BIANBU_PA_AGENT_ID 和 WebUI 为准。

记录 config、/api/v1/agents、WebUI Agent 详情，保存能力 granted/scope/risk/confirm、Token 用量、网络策略、DLP 矩阵和审计最大 seq。所有测试使用临时目录 security-manual-日期，不碰真实文件、系统配置、真实收件人和真实设备。

## 2. 通用测试步骤和证据

### 2.1 配置能力

能力名必须来自 capabilities.py。推荐先 granted=0，再 granted=1：

~~~bash
BASE=http://127.0.0.1:8787
SEC_AGENT=com.bianbu.agent
curl -sS -X POST "$BASE/api/agents/$SEC_AGENT/capabilities/add" \
  -H 'Content-Type: application/json' \
  -d '{"capability":"network.access","domain":"resource","risk_level":"L2","confirm":"trusted","scope":"","granted":0}'
curl -sS -X POST "$BASE/api/agents/$SEC_AGENT/capabilities/grant" \
  -H 'Content-Type: application/json' \
  -d '{"capability":"network.access","scope":"","granted":1}'
~~~

L3/L4 不能设置 confirm=trusted；L4 即使 granted=1 也必须每次确认。

### 2.2 真实 PA Run 和审批

~~~bash
PA=http://10.0.90.243:9899
SID=sec-manual-$(date +%s)
KEY=sec-manual-$(date +%s)-0001
curl -sS -X POST "$PA/api/v1/runs" -H 'Content-Type: application/json' \
  -d "{\"session_id\":\"$SID\",\"agent_id\":\"personal-agent-default\",\"idempotency_key\":\"$KEY\",\"prompt\":\"在安全测试目录完成指定操作\"}"
curl -sS "$PA/api/v1/runs/<run_id>"
curl -N "$PA/api/v1/runs/<run_id>/events?cursor=0"
~~~

waiting 表示等待审批。approval_id 从 pending_actions[].approval_id 或 SSE approval_required 事件取得：

~~~bash
curl -sS -X POST "$PA/api/v1/runs/<run_id>/approvals/<approval_id>" \
  -H 'Content-Type: application/json' -d '{"decision":"approve","reason":"手动验收批准"}'
curl -sS -X POST "$PA/api/v1/runs/<run_id>/approvals/<approval_id>" \
  -H 'Content-Type: application/json' -d '{"decision":"reject","reason":"手动验收拒绝"}'
~~~

不要把 securityd request_id 当成 PA approval_id。

### 2.3 每项必须收集的证据

- 授权前/后和批准/拒绝时的真实副作用（文件、mock 网络、日历、任务、消息、provider）。
- Run 快照和 SSE 的 waiting、approval_required、approval_resolved、done/error。
- WebUI 审计中的 check_permission；确认项还要有 confirm/拒绝结果。
- 实际 capability、scope、risk、decision（ALLOW/CONFIRM/DENY）。
- 测试后的策略和数据清理结果。

只看到 HTTP 200 或模型回答“已完成”不算通过。

## 3. 能力逐项手测

下列风险和默认确认策略以 capabilities.py 为准。标为“运行时缺口”的项目先做映射检查；必须装入真实 PA 工具后才能给端到端 PASS。

### 3.0 已完成基线：read / write / execute

以下三项是本轮已经在真实 bianbu agent + securityd 上手动验证过的能力，纳入本计划作为后续回归对照基线。这里的 execute 指 `system.execute`；`execute.code` 是另一条独立能力，见 3.5。

| 用户功能 | PA 工具示例 | securityd capability | 已验证的核心行为 |
|---|---|---|---|
| read | `read_file`、`search_files`、目录读取工具 | `file.read` | 读取测试文件；未授权时不返回内容；授权后按策略放行；审计有 `check_permission` |
| write | `write_file`、文件修改/删除工具 | `file.write` | 审批前不落盘；Reject 后不落盘；Approve 后才写入；审计有判权和确认结果 |
| execute | `terminal`、`shell`、`bash` | `system.execute` | 未授权/拒绝不执行；授权的安全命令按 scope 判权；复合或危险命令不因首个 token 安全而放行 |

#### 3.0.1 read 手测记录

构造一个只含固定内容的临时文件，例如 `SEC-READ-001`。先将 `file.read` 设为 `granted=0`，通过 PA 请求读取；再改为 `granted=1` 且使用字典默认的 `L1/trusted` 策略重新读取。

验收标准：

1. 未授权时 Run/工具结果为 `DENY` 或安全错误，不能返回文件内容。
2. 授权后只返回测试文件内容，不允许借 `file.read` 修改、删除或读取测试目录之外的文件。
3. WebUI 审计中出现 `check_permission`，capability 为 `file.read`，scope 对应实际路径。
4. 撤销授权后立即再次读取，必须恢复为 `DENY`，不能因 PA 进程缓存旧结果而放行。

#### 3.0.2 write 手测记录

准备不存在的临时文件和一个已有文件，使用 PA 的 `write_file` 或实际文件修改工具。将 `file.write` 配置为已授权但需要确认的策略，分别执行批准和拒绝两次。

验收标准：

1. 工具调用在审批前进入 `waiting`，目标路径和操作可在审批信息中识别。
2. Reject 后目标文件不存在或内容保持原值，不能出现部分写入、临时文件残留或目录被创建的意外副作用。
3. Approve 后文件内容与请求完全一致；重复调用的结果可预测，不能写入其它路径。
4. 审计至少包含 `check_permission`、`confirm`/拒绝结果、工具名和文件 scope。
5. 撤销 `file.write` 后再次调用必须拒绝；确认弹窗不能被旧的 ALLOW/CONFIRM 缓存绕过。

#### 3.0.3 execute 手测记录

本项使用 `system.execute`，准备两个命令：无害的 `echo SEC-EXEC-001` 或 `ls`，以及危险/复合命令 `rm -rf <测试目录>`、`ls; <危险动作>`、`env ls`。危险命令只做判权和拒绝验证，不实际执行破坏性动作。

验收标准：

1. `system.execute` 未授权时命令不启动；授权但需要确认时 Run 先 `waiting`。
2. Reject 后没有命令输出、文件变化或子进程残留；Approve 后仅执行明确批准的无害命令。
3. 简单命令的 scope 能识别可执行名；含 shell 元字符、wrapper 或复合命令的 scope 应为不确定值并回到强制确认，不能只按第一个安全 token 放行。
4. `system.execute` 每次调用在 securityd 审计留下 `check_permission`；拒绝还应有 `permission_denied` 或对应安全错误。
5. 停止 securityd 做降级验证时，`system.execute` 必须 fail-closed；恢复 securityd 后重新回到正常三态。

### 3.1 network.access：网络、搜索、抓取、浏览器

工具候选：web_search、web_extract、browser_navigate、browser_snapshot、browser_click、browser_type、browser_press、browser_scroll、browser_back、browser_get_images、browser_console、browser_vision。

构造：

1. 网络策略设 whitelist，只放行 example.com；检查 worker 的 SearXNG 配置。
2. network.access 先 granted=0，再 granted=1 + L2/trusted，最后用 once_per_session/always 测确认。
3. 准备白名单 URL 和不在白名单的 URL。

验收：白名单内放行；白名单外 DENY；撤销后仍 DENY；once_per_session 第一次批准后同一 session 再调用放行、新 session 再确认；拒绝时无真实网络请求；审计 check_permission 的 scope 是 URL/endpoint。

### 3.2 data.read：会话/历史只读

先查 GET /api/mapping 和实际审计。session_search 未映射为 data.read 时不能直接算通过。

构造唯一标记 SEC-DATA-READ-001。data.read=0 时读取必须 DENY；data.read=1（L2/trusted）时只能读出测试标记；修改/删除历史必须走独立更高风险能力。无真实工具时记录“PA 端到端未接入”。

### 3.3 data.memory：长期记忆和待办

候选工具 memory、memory_record、memory_retrieve、todo。使用 SEC-MEM-001：

1. data.memory=0，记录操作不应产生 memory.json/jsonl 或 todo 状态变化。
2. data.memory=1（L2/once_per_session），第一次确认，批准后记录；同 session 第二次按 session trust 放行；新 session 再确认。
3. retrieve 读回标记，验证读写都被记录。

拒绝不落盘，批准只生成一条测试记录；审计有 check_permission、confirm 和工具名。

### 3.4 data.query：SQL/结构化查询

当前 PA 可能没有 sql_query；LangGraph 有 sql_db_query、sql_db_schema、sql_db_list_tables。无真实工具时用签名临时工具连接只读 /var/tmp SQLite，不得用 execute_code 代替。

data.query=0 时无数据库访问；data.query=1（L2/once_per_session）时首次确认、同 session 放行、新 session 再确认；INSERT/UPDATE/DELETE/DROP 由工具拒绝。审计不能把 query 误判为 network.access。

### 3.5 execute.code：Python/解释器

候选工具 execute_code、python_repl、python_repl_tool，不能把 terminal 结果计入本项。

用 print("SEC-CODE-001") 这种无副作用代码。execute.code=0 时无执行；execute.code=1（L3/always）每次确认，批准执行、拒绝无输出。以读取 /etc/passwd、访问凭据、联网作负向样例，确认 sandbox/工具权限未被绕过。审计必须是 execute.code，不是 system.execute 或 unknown。

### 3.6 agent.delegate：派生子 Agent

候选 delegate_task。若实际审计为 unknown.tool，先补正式映射或签名临时工具。

子任务只返回 SEC-DELEGATE-001，不联网不写文件。agent.delegate=0 不创建子 Agent；agent.delegate=1（L3/always）每次确认；批准回传，拒绝/超时无后台任务；给子 Agent 更窄工具集，尝试 terminal/write_file 必须不能继承父 Agent 未授权能力。审计要能关联父/子 run/session。

### 3.7 resource.generate：图像/语音/视觉生成

当前默认工具可能没有 image_generate、text_to_speech、vision_analyze，属于运行时缺口。接入签名 mock，只返回 /var/tmp/security-generate-001.bin，不访问云端。resource.generate=0 无执行；L2/once_per_session 授权后第一次确认、同 session 放行、新 session 再确认；真实云工具还要同时验 network.access。无工具不能宣称端到端通过。

### 3.8 resource.train：训练/大规模推理

当前可能没有训练工具，必须 dry-run/mock，不得启动真实训练。mock rl_start_training、rl_stop_training、rl_edit_config 只写 /var/tmp/security-train-state.json。resource.train=0 状态不变；L3/always 每次确认；设置很小 CPU/内存/Token 限制，超限应暂停/告警。无真实工具不能给端到端 PASS。

### 3.9 execute.model：模型调用门禁

普通聊天成功不等于 execute.model 已通过。先确认当前实现是否在模型请求前注册该能力；如果只在工具调用前判权，记录“模型前置门禁未接入”。

若支持：本地固定输出 mock provider；execute.model=0 时 provider 不得收到请求；授权 trusted 时放行；确认策略时 waiting/批准/拒绝均符合预期；Token 用量、provider 请求和审计一一对应。否则记录实现缺口。

### 3.10 message.send：邮件、短信、消息外发

候选 send_email、send_message、send_slack、send_gmail、TwilioSMS。使用只监听 127.0.0.1 的 mock SMTP/HTTP receiver，绝不发真实消息。

message.send=0 时 receiver 无请求；L3/always 授权时 Run 必须 waiting；拒绝无请求，批准恰好一条测试消息。正文加入“联系电话：13812345678”，叠加 DLP block/mask，验证 DLP 先于外发和确认。审计含目标、能力、DLP、确认结果。

### 3.11 system.config：系统配置、定时任务、设备动作

候选 cronjob、ha_call_service 或实际配置工具；不要把 todo 当 cronjob。使用临时 crontab 文件或 mock Home Assistant。system.config=0 状态不变；L3/always 授权每次确认，拒绝无变化；禁止真实 /etc、门锁、电源。若实际工具映射成 calendar.write，先明确映射后分别验收。

### 3.12 system.info：进程、负载和系统信息只读

候选 get_process_list、get_system_info。PA 的 process 是进程会话管理，不自动等于 system.info。system.info=0 时 DENY；授权 L1/trusted 时直接 ALLOW、不弹框；无写文件、联网、命令执行副作用；审计必须是 system.info。

### 3.13 device.read：设备/传感器只读

候选 ha_get_state、ha_list_entities、ha_list_services 或只读 mock。mock 返回 SEC-DEVICE-001。device.read=0 无请求；L1/trusted 授权后 ALLOW；设备控制必须走 system.config。读不弹确认，写不能复用读能力，审计含实体和 capability。

### 3.14 skill.manage：Skill 安装、修改、删除

真实候选 skill_manage，风险 L3/always。临时创建 security-manual-skill：

1. skill.manage=0：create/edit/delete 不得改变目录。
2. 授权后每次动作确认；批准 create 后可查看，拒绝 edit/delete 后原文保留。
3. Skill 放手机号/密钥样式文本，叠加 DLP：audit_only 原样审计、mask 脱敏、block 拒绝。
4. 篡改已签名包内容但保留旧签名，重新安装必须被 CODE-01 拒绝。

审批、DLP、签名都必须发生在执行前，且只修改临时目录。

### 3.15 calendar.read / calendar.write：日历

当前 PA 可能没有 calendar 工具；LangGraph 有 GoogleCalendarViewTool、create_calendar_event、update_calendar_event、delete_calendar_event。没有真实工具时用 mock Calendar API。

mock 只有 SEC-CALENDAR-001。calendar.read=0 DENY；授权 L1/trusted ALLOW 且不弹框。calendar.write=0 的创建/修改/删除 DENY；授权 L2/once_per_session 首次确认、同 session 放行、新 session 再确认；拒绝删除后事件仍在。验收读写分离、event ID 审计和无真实数据泄露。

### 3.16 unknown.tool：未映射工具兜底

必须验证默认 confirm，不能静默 ALLOW。

安装无副作用签名临时工具 zzz_totally_unmapped_tool，返回 SEC-UNKNOWN-001。不设置 BIANBU_SECURITY_UNMAPPED，映射 API 应显示 unmapped_policy=confirm。调用第一次 waiting/CONFIRM；批准执行、拒绝不执行，审计留下 unknown.tool。临时设置 deny 和 allow，重启 PA 验证切换，最后恢复 confirm；非法值必须回落 confirm。

## 4. MCP 和数据出境

### 4.1 MCP 第一层 fail-closed

准备无副作用 stdio MCP server，只含合法 mcp.json，工具返回固定字符串。Agent 选择该 server，但 securityd 未注册 mcp.<mcp_id>。调用 <mcp_id>/ping：

- 第一次被拦截；
- 自动登记 mcp.<mcp_id> 且 granted=0；
- 第二次仍拦截，不能因登记自动授权；
- 授权该 server 能力后才放行；
- 工具名含 read/write 也不能脱离 server 边界。

### 4.2 本地 stdio 与远端 streamable-http

准备相同查询服务的本地 stdio 和远端 streamable-http 配置，name=allow，参数“姓名：张伟 的客户资料”：

- 本地 stdio 按 allow 放行；
- 远端 HTTP 提升 CONFIRM，审批消息含 endpoint；
- 无 PII 的远端请求不应无端弹框；
- 拒绝后没有 HTTP 请求。

## 5. DLP 手动验收

### 5.1 八类 PII

在 DLP 试扫或真实 PA 输入中逐项使用：

| 类型 | 样本 |
|---|---|
| name | 姓名：陈芳 |
| phone | 联系电话：13812345678 |
| id_card | 身份证：110105199003070121 |
| email | 邮箱：zhang.san@example.com |
| bank_card | 银行卡：6222020000000000000 |
| address | 住址：北京市海淀区中关村大街1号 |
| medical | 诊断：2型糖尿病，需长期服药 |
| biometric | 已采集指纹特征数据用于身份核验 |

每种检出正确 pii_type、风险等级、detector。非法身份证和随机卡号必须不误报（校验位 + BIN）。

### 5.2 四种 DLP action

对手机号/邮箱分别设 allow、audit_only、mask、block，用真实 PA 的用户输入、工具参数、工具返回值各跑一次：

- allow：原文通过；
- audit_only：原文通过且有 DLP 审计；
- mask：继续执行，下游只看到 PHONE/EMAIL 占位符；
- block：Run 失败/停止，工具或模型收不到原文。

每次从 DLP 矩阵确认生效值，结束恢复原策略。

### 5.3 大载荷正式 UDS

构造超过 4KB 的 prompt/工具参数，末尾放“联系电话：13812345678”，手机号 action=block。真实 Run 后检查中央策略阻断、审计 uds_dlp_scan 且 target >4096，以及超过 1KB 的完整治理载荷有 uds_audit_batch/hook_payload:*；不能只有本地摘要。

## 6. 审计、Token、沙箱和签名

### 6.1 审计链

产生 ALLOW、CONFIRM、DENY、DLP block、sandbox 事件。在 WebUI 审计页检查 seq、时间、agent、op_type、target、result、prev_hash、hash；check_permission 与实际调用对应；导出非空且 intact。只篡改导出副本再校验，不能改生产审计库，必须能报告断链。

### 6.2 Token 配额

记录原始预算，临时设置 limit_conv=100、limit_day=300、on_exceed=pause_and_notify。短 prompt 应使 day_used 增长；长 prompt/多轮使其超限，Run 应暂停/失败并有 TokenExceeded/告警；超限后不能静默继续。恢复配额。

### 6.3 沙箱

使用无害 Python probe 验证 mode=tool、mode=mcp，启用 agent 模式时再验 mode=agent：

- net=false 出网失败，net=true 对 mock endpoint 可达；
- PID namespace 下 PID 约为 1/2，不应看到宿主进程树；
- 未列入 rw_dirs 的路径不可写；
- 不可序列化参数/返回值被 runner 拒绝；
- WebUI 显示 seccomp/netfilter 文件存在且非空。

bwrap 不可用是环境失败，不是通过。不要使用真实凭据或破坏性命令。

### 6.4 Hook/Tool/Skill 安装签名

准备有效签名临时包：原包安装成功；只改 hook.py/tool 或 manifest capability/版本/路径但保留旧签名时安装失败；hook 目录出现 .bak、__pycache__ 或额外文件时拒绝/不加载。安装期签名通过不代表运行期授权通过，随后还需验 skill.manage/工具调用。

## 7. 降级和错误展示

### 7.1 securityd 不可达

确认无其它测试后停止 securityd：

~~~bash
ssh bianbu@10.0.90.243 './start-bianbu-securityd.sh --stop'
~~~

高危 system.execute、execute.code、file.write、message.send、skill.manage 必须 fail-closed；file.read、system.info 等低危可按配置 fail-open，但必须有降级日志/审计。恢复 securityd 后同一调用应回到正常三态。停止期间不要改生产策略。

### 7.2 错误透传

撤销 network.access，发起 web_search。Run 快照和 SSE 错误至少包含工具名、能力名、风险/处置原因和授权建议，不能只显示“发送失败，请稍后再试”。恢复授权后再验正常路径。

## 8. 执行顺序、记录和清理

推荐顺序：连通性/身份/映射 → network、data.read、system.info、device.read → data.memory、data.query、calendar.write、resource.generate → execute.code、agent.delegate、resource.train、message.send、system.config、skill.manage → unknown/MCP/出境 → DLP、审计、Token、沙箱、签名、降级 → testkit。

记录表：

| ID | 能力/功能 | 工具→实际 capability | 未授权 | 授权/批准 | 副作用证据 | 审计证据 | 清理 | 结论 |
|---|---|---|---|---|---|---|---|---|
| M-01 | network.access | web_search → network.access | DENY | ALLOW/CONFIRM | mock 无/有请求 | seq/op/scope | 恢复策略 | PASS/FAIL |

结束恢复临时能力、DLP/网络/Token 策略、环境变量 BIANBU_SECURITY_UNMAPPED/BIANBU_SECURITY_FAIL_OPEN，删除临时 MCP/Skill/Agent/mock/目录，确认无未完成审批和后台进程。

## 9. testkit 交叉验收

入口必须是 runner.py：

~~~bash
ssh bianbu@10.0.90.243 \
  'cd /home/bianbu/bnsec-testkit && python3 runner.py'
~~~

| 手测范围 | testkit |
|---|---|
| 三态、撤销、映射、unknown、MCP、scope、签名 | PERM-*、CAP-*、MCP-01、CODE-01、SCOPE-01 |
| PA hook、错误展示 | HOOK-*、ERR-01 |
| DLP、远端出境、Skill | DLP-*、EGRESS-01、SKILL-01 |
| Token、沙箱、审计 | TOKEN-*、SBX-*、AUDIT-* |

最低证据是每个真实已接入工具均有：授权前拦截、授权后按策略执行、拒绝无副作用、securityd 审计。只有能力字典/判权逻辑而无对应 PA 工具的项目，必须写“PA 端到端待接入”，不能用其它工具代替。
