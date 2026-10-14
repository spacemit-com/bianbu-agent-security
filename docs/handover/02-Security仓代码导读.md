# Security 仓代码导读

| 项目 | 内容 |
|---|---|
| 文档编号 | Bianbu-SEC-HANDOVER-002 |
| 版本 | V1.0 |
| 日期 | 2026-09-18 |
| 来源 | Security `9f085c2`；Runtime `145d1ea0`；现有测试与验收记录 |
| 状态 | MVP 已完成；维护交接资料，接手演练尚未执行 |

## 1. 从哪里开始读

本篇路径均相对 S。先打开 `impl/bianbu-securityd/securityd/service.py` 看服务入口，再沿 `engine.py` 找业务决定，最后看存储模块和测试。不要一开始通读所有历史设计。

| 目录 | 用途 |
|---|---|
| `impl/bianbu-securityd/securityd/` | 安全服务业务实现 |
| `impl/bianbu-securityd/runtime/` | Security 侧启动策略、lease、执行实例登记 |
| `impl/bianbu-securityd/client/` | 两仓共用的安全客户端；协议修复在此维护 |
| `impl/bianbu-securityd/webui/` | 独立安全配置台 |
| `impl/bianbu-securityd/data/` | D-Bus XML 等协议资产 |
| `impl/bianbu-securityd/deploy/` | 安装、systemd、验证、数据库迁移和维护工具 |
| `debian/` | 当前仓库级 DEB 构建与安装生命周期 |
| `testkit/` | 真实 Runtime + Security 端到端测试 |
| `deploy/` | 根目录整理来的开发启动和历史补丁脚本；不等于实现目录下的 deploy |

## 2. 模块地图

下表文件位于 `impl/bianbu-securityd/`。

| 文件 | 关键职责/入口 | 常见维护场景 |
|---|---|---|
| `securityd/service.py` | `SecurityService`、`SecurityRuntimeService`；D-Bus 方法及 sender 校验 | 新接口、UnknownMethod、签名不匹配 |
| `securityd/engine.py` | `SecurityEngine`；汇总判权、模式、Token、网络和审计操作 | 行为调整先找此处，再定位存储 |
| `securityd/capabilities.py` | 能力名称、风险及别名的权威定义 | 新增工具能力、兼容旧能力名 |
| `securityd/capability_registry.py` | Agent/能力授权、模式及相关策略持久化 | 注册、授权撤销、同步覆盖问题 |
| `securityd/scope.py` | 命令/路径等 scope 的判断 | 复合 shell 命令、范围匹配 |
| `securityd/caller_identity.py` | D-Bus/操作系统调用者身份 | 绑定拒绝、PID/cgroup 不符 |
| `securityd/confirm.py` | 人工确认流程 | 确认超时、响应关联 |
| `securityd/uds_server.py`、`uds_protocol.py`、`uds_handlers.py` | socket、消息协议、peer 身份和业务分发 | Worker 数据面失败、报文错误 |
| `securityd/dlp/pii_scanner.py` | 扫描、位置、类型和脱敏结果 | 误报/漏报、Unicode 偏移 |
| `securityd/dlp/policy_store.py`、`handlers.py` | DLP 策略与干预动作 | 按 Agent 覆盖、动作非法、连接释放 |
| `securityd/interceptor.py` | 安全干预链 | 多个 handler 的决定合并与异常处理 |
| `securityd/audit_chain.py` | 审计存储、哈希链、导出验证 | 事件丢失、链校验、轮转 |
| `securityd/token_meter.py` | Token 累计及预算 | Session/日配额、计量恢复 |
| `securityd/network_policy.py`、`network_learning.py` | 网络规则与观测落库 | configured/effective 不一致、采集无数据 |
| `securityd/syscall_policy.py`、`seccomp_builder.py` | syscall 策略与 seccomp 产物 | 架构编号、黑名单更新 |
| `securityd/syscall_audit.py`、`kernel_syscall_audit.py` | syscall 拦截事件和内核采集对接 | 真实拦截有结果但审计为空 |
| `securityd/code_signing.py`、`manifest.py` | 签名、信任根、包声明 | manifest 不兼容、升级信任版本 |
| `runtime/policy.py`、`engine.py`、`lease.py` | 决策、进程核验、一次性租约 | Worker 起不来、错误 lease、实例回收 |
| `securityd/config.py` | 数据、socket、日志路径及环境覆盖 | 开发/安装路径混用 |

## 3. 推荐的第一次代码走读

### 3.1 “为什么这个工具被拒绝”

从 Runtime 拿到实际 `agent_id / capability / scope`，查 `uds_handlers.permission_check` 或 D-Bus `CheckPermissionV2`，进入 `SecurityEngine.check_permission`，再看 registry 的授权与 scope 判断。最后查同一请求的审计结果。

注意 `DENY` 有两类不同来源：身份未获授权，或身份正确但业务能力不允许。前者不应通过“给某能力打勾”解决。

### 3.2 “DLP 为什么没有脱敏”

从 `uds_handlers.dlp_scan` 看是否处于 YOLO；normal 下检查 scanner findings、policy action 和 `masked_text`。再到 Runtime 确认调用方确实采用了治理后的值。Security 返回了 mask 结果，不代表原文不会被另一个发布路径发送出去。

### 3.3 “Worker 为什么无法启动”

沿 `SecurityRuntimeService.PrepareStart → runtime.engine.prepare_start → policy/lease`，再跟 `CommitStart → _validate_attestation/lease.commit`。对照 Runtime 真正创建的 PID/cgroup，不靠手填请求体证明身份成立。

## 4. 存储与生命周期

| 内容 | 正式安装位置/确定方法 | 维护注意 |
|---|---|---|
| 能力/Agent 策略 | `/etc/bianbu/capabilities.db` | 不直接 SQL 改授权或模式，使用管理接口 |
| Token 数据 | `/etc/bianbu/token_budget.db` | 与会话身份一起核查，不因切 YOLO 清零 |
| 主审计 | `/var/log/bianbu/audit/YYYYMM.db` | 选正确月份；不能取目录内第一个 `.db` |
| syscall 审计 | 同审计目录的 `syscall-events.db` | 与主审计是不同数据集 |
| 网络观测 | 同审计目录的 `network-learning.db` | collector active 不等于已有事件 |
| DLP/lease 等数据库 | 以 `policy_store.py`、`runtime/lease.py` 和运行环境为准 | 备份完整数据集，不遗漏 WAL |
| 临时执行资产 | `/run/bianbu/`、sandbox 子目录 | 重启后需重建；不能用旧 socket/lease 恢复身份 |
| 信任公钥 | `/etc/bianbu/codesign-keys/` | 由安装/发布流程维护 |

开发态可通过 `BIANBU_SEC_ROOT` 收敛到独立目录；非 root 默认还有 XDG 回退。正式 service 显式设置 `/etc/bianbu`、`/run/bianbu`、`/var/log/bianbu`，所以不能仅按“是否 root”猜路径。

## 5. 修改时必须一起检查

- 增加 D-Bus 方法：service 签名、客户端、XML 描述、调用方、权限与测试同步；重启后用 introspect 验证。
- 增加 UDS 动作：handler 注册、输入限制、peer/lease 身份、客户端封装、错误兼容与测试同步。
- 修改数据库访问：确认连接和游标真正关闭。`with sqlite3.connect(...)` 的事务上下文不等于自动关闭连接，曾导致 FD 耗尽。
- 修改 lease 时间：保留单调时钟、boot identity、一次性 commit 和旧数据兼容的测试。
- 修改打包：使用仓库完整快照测试；只复制 `impl/` 会使引用根目录 `debian/` 的安装测试失败。

基础规则见 [AGENTS.md](../../AGENTS.md)，操作入口见 [testkit README](../../testkit/README.md)。旧 Hermes 相关目录是历史兼容资料，不是当前 Runtime 实现依赖。
