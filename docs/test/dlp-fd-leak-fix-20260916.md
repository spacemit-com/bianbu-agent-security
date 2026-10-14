# DLP SQLite 连接泄漏修复

问题：10.0.91.146 的 Worker 返回 `PermissionDenied: Worker 未通过已提交 Runtime lease 身份校验`。

## 根因与改动

securityd PID 623639 打开 1023/1024 个文件描述符，其中 498 个指向
`/etc/bianbu/dlp_policy.db`、497 个指向 WAL。Worker PID 659317 的已提交
lease、instance、cgroup 与数据库一致；资源耗尽令身份验证失败。

DLPPolicyStore 原来缓存每线程 SQLite 连接。UDS 短连接对应短命请求线程，
SQLite 事务上下文不关闭连接，线程退出后的释放依赖 GC；临时 store 也有相同问题。
改为每次操作持有独立连接，在 finally 中确定关闭，保留事务提交/回滚和策略回退语义。
没有放宽 lease 校验、修改限额或清空数据库。

## 回归方法

禁用 GC 后，分别对共享 store 与临时 store 执行 8 批并发读写、删除与 SQL 异常；
断言完成后数据库 FD 不超过基线。旧实现分别从 3 增至 67/131，修复后通过。
本地 DLP 策略测试 23 passed。本地完整测试环境缺少 D-Bus 等依赖，
完整回归以 243 的隔离源码目录为准。

146 的线上探针以原 Worker UID、既有 Worker cgroup 和 committed lease 请求真实 UDS。
探针是单独诊断进程，不是桌面聊天验收；不修改 lease。修复前成功复现原始错误。
脚本及原始输出位于 `evidence/dlp-fd-20260916/`。

243 验证：全量单元/集成测试 798 passed；独立 D-Bus 会话中的 E2E 为
3 passed、0 skipped。首次源码包缺少仓库级目录导致 7 个路径失败，补齐目录后
全量重跑通过。代码提交后再部署 146 并追加现场验收记录。

## 146 部署及验收

修复代码先提交为 `e58d6fa`，随后原位更新
`/usr/lib/bianbu-securityd/securityd/dlp/policy_store.py`，并重启
`bianbu-securityd`、`bianbu-security-webui`。原文件备份在
`/var/tmp/dlp-fix-backup-20260916/policy_store.py`。
安装文件 SHA-256：`3b6e6bc64c5afc38858f40253695dc022fe53c228e75e84ab11c48dcb1d69082`。
这是 0.1.31 安装包上的代码热修复，未构建新 DEB 或发布 tag；后续包需包含该提交。

服务依赖链同时重启 Runtime，原 Worker 退出。首次预热出现
`Runtime startup failed: message must not be empty`，通过正常 Worker 请求重试后恢复。
新 Worker PID 708107、instance 后缀 `008b816fd61f`，最终状态 running，
Memory registration active，`/api/health` 为 `AGENT_READY`。
此冷启动异常未作代码修复，不能将其算作本次 DLP 修复覆盖的问题。

真实 UDS 验收使用新 committed lease：

| 检查 | 结果 |
|---|---|
| 有效 Worker cgroup/UID/lease 身份 | authorized=true |
| 1000 次独立连接 DLP 策略请求 | 1000 成功，11.008 秒 |
| securityd FD | 27 → 27（故障前为 1023） |
| 空闲时 DLP DB/WAL FD | 0 → 0 |
| DLP scan / Token budget / Security mode | 全部成功 |
| 错误 lease | 仍拒绝 |

探针仅将自身加入已提交 Worker scope，不移动 Worker，不修改 lease 或数据库内容。
没有执行完整桌面聊天、长时间耐久或原生桌面构建验收。
