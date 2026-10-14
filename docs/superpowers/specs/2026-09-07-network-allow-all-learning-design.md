# 网络 Allow All 与 Learning 模式设计

## 目标

配置中心为每个 Agent 提供四种明确的网络模式：

| 模式 | 出站网络 | 观测 | 用途 |
|---|---|---|---|
| `whitelist` | 默认拒绝，仅允许配置域名当前解析出的 IP 和 DNS resolver | 不新增学习事件 | 生产最小权限 |
| `deny_all` | 拒绝全部外部 IPv4/IPv6 网络 | 不新增学习事件 | 完全离线 |
| `allow_all` | 不设置 Agent 级 IP 地址过滤 | 不新增学习事件 | 明确允许任意网络 |
| `learning` | 不设置 Agent 级 IP 地址过滤 | 记录该 Worker 的 DNS 查询和连接目标 | 收集形成白名单所需证据 |

本次交付完成 `allow_all`，以及 `learning` 的采集、持久化、查询、Runtime 9899 页面展示、降级状态和 K3 实机验收。每个可以独立验证的行为完成测试后立即提交，不把多个未验证行为压在一个提交中。

## 非目标与隐私边界

- 不采集 HTTP URL、Header、Cookie、请求正文、响应正文或 TLS 明文。
- 不承诺由目标 IP 唯一反推出原始域名。DNS 查询和 IP 连接作为两类独立事实展示。
- 不拦截 DoH/DoT 内容；这类流量仍显示其目标 IP/端口，但域名可能不可见。
- 不在宿主全局安装用于策略执行的 OUTPUT DROP 规则。
- 不修改 `bibit-security-plugin`。
- 不在本次实现自动把学习结果写回白名单；管理员可以从页面复制或勾选学习结果，自动审批流程另行设计。

## 权威边界

Security 是网络模式、策略版本、学习事件和采集状态的权威。Runtime 是 Worker 生命周期和 9899 用户界面的权威。Runtime 不直接写 Security 数据库，浏览器也不直接调用 8787 Security WebUI。

调用链如下：

```text
Runtime 9899 页面
  -> POST /security-api/invoke
  -> bianbu_security_client
  -> io.bianbu.Security D-Bus
  -> Security engine/store
```

Worker 启动和观测链如下：

```text
Security PrepareStart 返回 network mode/version
  -> Runtime 创建 transient systemd scope
  -> whitelist/deny_all: 设置 IPAddressDeny/Allow
  -> allow_all/learning: 不设置 IPAddressDeny/Allow
  -> learning: Runtime 启动该 Worker 专属网络观测器
  -> 观测器输出结构化事件
  -> Runtime 使用真实 lease/PID/cgroup 身份转发
  -> Security 再校验活动 lease 和 cgroup 后持久化
```

## 模式编译和热更新

Runtime 与 Security 使用相同的模式语义：

- `whitelist` 编译为 `IPAddressDeny=any` 加解析出的 `IPAddressAllow=<IP>`。
- `deny_all` 编译为 `IPAddressDeny=any`，没有业务地址 allow 项。
- `allow_all` 和 `learning` 编译为空的 Agent 网络属性集合。
- bwrap 在 `whitelist` 有有效域名、`allow_all` 或 `learning` 时保留网络；`deny_all` 和空白名单使用隔离网络命名空间。

运行中 host-process scope 支持四种模式间热更新。更新到 `allow_all` 或 `learning` 时，Security 必须显式清空旧 `IPAddressDeny` 和 `IPAddressAllow`，然后通过 `systemctl show` 验证二者均为空。更新失败时恢复旧属性、旧 Registry 策略和旧版本。

运行中 bwrap 的网络命名空间拓扑不能安全热切换，继续返回明确的 `restart_required`/失败状态并恢复旧策略。重启后使用新模式。

`allow_all` 与 `learning` 的 `enforcement` 状态含义是“已验证没有 Agent 级阻断属性”，不是“内核正在执行 allow 规则”。返回字段包含 `mode`、`effective`、活动/成功/失败实例数和失败原因。

## 学习采集器

K3 已提供 `strace`，现有生产 Worker 也已有按实例 trace 目录。learning 模式仅为对应 Worker 增加网络系统调用跟踪，避免宿主全局抓包：

- 连接类：`connect`，并兼容无连接 UDP 的 `sendto`/`sendmsg` 目标地址。
- DNS 类：从发往 53 端口的标准 DNS 查询报文中解析 QNAME、QTYPE；只保存问题区元数据。
- 结果类：保存系统调用成功或 errno，不把失败连接计作成功访问。
- IPv4 与 IPv6 都规范化为标准文本；IPv4-mapped IPv6 保持内核观测值。

采集器输出每行一个 JSON 对象。Runtime 不信任其中的 `agent_id`、`instance_id`、`lease_id` 或 PID 归属，而是使用自己持有的不可变 Worker 句柄补齐身份。Security 接收事件后再次读取 `/proc/<pid>/cgroup`，并要求它属于提交过且仍为 running 的 lease。

观测器启动失败或意外退出不阻断 learning 网络访问，但必须把采集状态设为 `degraded`，包含可操作原因。页面不能用空表冒充“未发生访问”。非 learning 模式不启动网络观测器，也拒绝写入 learning 事件。

## 学习事件模型

Security 使用独立 SQLite 表，不复用普通能力审计或 syscall 审计：

```text
network_learning_event(
  event_id TEXT PRIMARY KEY,
  observed_at REAL NOT NULL,
  agent_id TEXT NOT NULL,
  instance_id TEXT NOT NULL,
  lease_id TEXT NOT NULL,
  pid INTEGER NOT NULL,
  event_type TEXT NOT NULL,       -- dns_query | connect
  protocol TEXT NOT NULL,         -- tcp | udp
  domain TEXT NOT NULL DEFAULT '',
  remote_ip TEXT NOT NULL DEFAULT '',
  remote_port INTEGER NOT NULL DEFAULT 0,
  dns_qtype TEXT NOT NULL DEFAULT '',
  outcome TEXT NOT NULL,          -- success | failed
  errno TEXT NOT NULL DEFAULT '',
  backend TEXT NOT NULL,
  policy_version INTEGER NOT NULL
)
```

查询层按以下键聚合，减少页面噪声：

```text
(agent_id, event_type, protocol, domain, remote_ip, remote_port, dns_qtype, outcome)
```

每条聚合结果返回 `first_seen`、`last_seen`、`count` 和最近的 `instance_id`。事件按 `last_seen` 倒序。默认保留 7 天，每个 Agent 最多保留最新 5000 条原始事件；每次写入后做有界清理。分页 `limit` 范围为 1 到 200，cursor 为非负偏移。

`event_id` 用于幂等去重。无效 IP、端口越界、未知事件类型、空 DNS 域名、身份校验失败或非 learning 策略事件全部拒绝并留下安全审计记录。

## 接口

Security D-Bus 增加：

```text
RecordNetworkLearningEvent(s agent_id, s instance_id, s lease_id,
  x pid, a{sv} event) -> b
ReportNetworkLearningCollector(s agent_id, s instance_id, s lease_id,
  x pid, s state, s reason) -> b
GetNetworkLearningEvents(s agent_id, i limit, i cursor) -> a{sv}
GetNetworkLearningStatus(s agent_id) -> a{sv}
ClearNetworkLearningEvents(s agent_id) -> b
```

查询返回字典中的复杂列表使用现有 JSON 字段编码约定，客户端统一解码为 Python 字典/列表。清理属于管理员操作；记录和状态报告方法仅允许已绑定 Runtime 调用者，并继续执行 lease/cgroup 校验。状态报告只接受 `active`、`degraded`、`inactive`，以 `(agent_id, instance_id)` 保存最近状态和更新时间；活动 lease 没有有效状态报告时按 degraded 返回。

Runtime `/security-api/invoke` 增加操作：

```text
network-learning.events.v1
network-learning.status.v1
network-learning.clear.v1
```

现有 `network-policy.get.v1` 和 `network-policy.update.v1` 保持协议版本 1；更新成功响应继续返回权威策略、版本和 apply 状态。

## Runtime 9899 页面

“安全 -> 配置中心 -> 网络策略”模式选择增加：

- 仅允许指定域名
- 禁止网络访问
- 允许全部网络
- 学习模式

选择 `allow_all` 或 `deny_all` 时禁用域名输入；选择 `learning` 时域名输入不参与执行并禁用。保存提示明确说明 bwrap 活动实例是否需要重启。

learning 模式下显示“学习到的访问目标”区域：

- 采集状态：`active`、`degraded`、`inactive`。
- 目标类型：DNS 查询或网络连接。
- 域名、IP、端口、协议、结果、首次发现、最近发现、次数、Worker。
- 刷新和清空按钮；清空需要确认。
- 无数据且采集 active 时显示“尚未观测到访问”；degraded 时显示具体错误，不显示空状态结论。

页面只通过 9899 Runtime API 调用 Security，8787 继续作为独立调试控制台，不是本功能的人工验收入口。

## 错误处理和状态转换

- 输入模式不属于四种合法值时拒绝，不修改版本。
- `whitelist` 中任一域名无法解析时保留域名及解析失败信息；是否拒绝整个更新沿用现有 fail-closed 规则。
- 过滤属性更新失败时回滚所有已经更新的活动 host-process scope，避免同一 Agent 多实例策略分裂。
- 从 learning 切出时停止采集器；历史学习事件保留到过期或管理员清空。
- 从其他模式切入 learning 时，活动 host-process 完成网络属性清理后启动采集；bwrap 返回需要重启。
- Runtime 或 Security 重启后，根据活动 lease 和当前策略恢复采集状态；不能恢复时标记 degraded。
- Security 不可用时 Runtime 页面显示不可用错误，不缓存伪成功策略。

## 提交边界

按照“一个可测试点一次提交”执行：

1. Security `allow_all` 策略存储、编译、热更新和单元测试。
2. Runtime `allow_all` 启动语义、API/UI 选项和测试。
3. Security learning 事件存储、身份校验、D-Bus/客户端查询和测试。
4. Runtime learning 采集器、事件转发和测试。
5. Runtime 9899 learning 查询与页面展示和测试。
6. Debian 版本、打包契约和验收文档。

跨仓依赖保持向后兼容：部署顺序先 Security、后 Runtime；旧 Runtime 不调用新接口，新 Runtime 遇到旧 Security 时显示 `incompatible`，不得静默假装 learning 已启用。

## 自动验收

1. 四种模式均被 Registry、策略生成器和 Runtime 接受，其他值被拒绝。
2. `allow_all`/`learning` 的新 Worker 没有 `IPAddressDeny`/`IPAddressAllow`，bwrap 不使用 `--unshare-net`。
3. 从 whitelist/deny_all 热更新到 allow_all/learning 会清空并回读 systemd 属性；模拟失败完整回滚。
4. 非 learning 策略拒绝学习事件，伪造 lease/PID/cgroup 被拒绝。
5. DNS/IPv4/IPv6/失败连接样例解析、幂等、聚合、分页、保留和清理测试通过。
6. Runtime API 操作映射、错误 envelope、页面四模式及 active/degraded/empty/event 状态测试通过。
7. 两仓相关测试、D-Bus XML 一致性检查、Debian 源包契约和 `git diff --check` 通过。

## K3 人工验收

在 `10.0.90.243` 原生构建并安装两个 riscv64 deb，使用独立测试 Agent，避免影响已有 Worker：

1. 从 9899 设置 `allow_all`，启动 Worker，验证 scope 没有 IP 过滤，并成功访问两个未预先声明的 IPv4/IPv6 目标。
2. 从 whitelist 切到 `allow_all`，验证 host-process 不重启即可恢复访问；bwrap 明确提示重启。
3. 设置 `learning` 并启动/重启 Worker，发起 DNS 查询、HTTPS 连接、直接 IP 连接和失败端口连接。
4. 在 9899 页面看到 DNS 域名和连接 IP/端口、成功/失败、次数及最近时间；刷新后数据仍存在。
5. 验证页面状态为 active；停止观测器后为 degraded 且显示原因。
6. 清空事件后页面为空，再次访问会重新出现。
7. 切到 `deny_all` 后外网失败且不再新增 learning 事件；切回 whitelist 后只允许白名单目标。

验收证据包括 deb 版本、服务状态、策略 API 响应、`systemctl show` 网络属性、Worker 内连接结果、learning 查询响应和 9899 页面截图。
