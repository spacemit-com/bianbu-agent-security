# 审计列表分页合同与验证

日期：2026-09-20。状态：独立 worktree 实现，未发布。

## 原因与处理

旧列表由 Runtime 调用 ExportAudit，全量导出、解析、Python 筛选、自动校验哈希链，最后前端全量渲染。日志增长会同时放大磁盘、CPU、内存和 DOM 工作量。

新增管理接口 `io.bianbu.Security.QueryAudit(s query_json) -> s page_json`，客户端入口 `query_audit`。Runtime 的 `audit.query.v1` 直接转发查询和结果。列表不导出文件、不自动校验；显式 `audit.verify.v1` 保留原行为。

| 查询字段 | 合同 |
| --- | --- |
| agent_id | 可选字符串，非空时精确匹配 Agent |
| filter | all（默认）、hook（op_type 前缀 hook:）、deny（result 忽略大小写含 deny） |
| limit | 1–200 的整数，默认 100；UI 固定 100 |
| cursor | 非负整数，默认 0；非零时只取 seq < cursor |
| snapshot_seq | 首次省略，后续沿用首屏返回值（包括 0）；只取 seq <= snapshot_seq |
| from / to | 可选时间字符串，沿用存储 ts 的字典序闭区间比较 |

响应包含 `records`（seq、ts、agent_id、op_type、target、result）、`snapshot_seq`、`has_more`、`next_cursor`。记录按 seq 倒序；还有下一页时 next_cursor 是本页末尾 seq，否则为 null。不返回总数或完整哈希链。刷新/改变筛选/切换 Agent 清空游标历史和快照；上一页使用保存的游标。

SQL 将快照与游标合并为单一上限 `min(snapshot_seq, cursor - 1)`，防止 SQLite 从快照上限开始扫描大量中间记录。建立 Agent/seq 联合索引及 Hook、deny 部分索引；使用独立只读 WAL 连接和 limit+1，不获取写入线程的 Python 锁。新增索引不改记录内容、哈希算法或校验规则。首次启动会为历史库建立索引，启动时间需考虑库大小。

## 验证

在 K3（10.0.90.243）的 `/home/bianbu/audit-pagination-20260920` 隔离源码副本验证，未替换线上服务。

- `python3 -m pytest tests/ --import-mode=importlib -q`：842 passed、3 skipped（既有可选 E2E）。Windows 上传副本的 Shell 文件先转换 LF；importlib 模式解决既有同名测试模块冲突。
- 最终单上限优化及新增 SQL 工作量回归：`python3 -m pytest tests/unit/test_audit_query.py tests/unit/test_audit_chain.py tests/integration/test_dbus_security.py -q -rs`：41 passed，包括真实私有 D-Bus 服务、客户端 QueryAudit 调用与哈希链校验。
- `python3 testkit/benchmark_audit_query.py --rows 10000 100000 1000000`：隔离临时库、合成有效链、每场景 25 次查询。百万条下 all 首页/中间页中位数均 1.73 ms，p95 为 2.17/1.78 ms；hook 中位数 3.02/2.98 ms；deny 中位数 2.94/2.61 ms。以上是查询引擎耗时，不是桌面端到端延迟，不包含建库/启动、网络或渲染。

## 联动发布与边界

先安装并重启包含 QueryAudit 的 Security（服务与客户端），再更新 Runtime 和 Bibit 插件。保持既有包版本与 Runtime 最低依赖声明不变，版本发布另行处理。旧 Security 不支持时明确报错，不回退到全量导出。Runtime 自带控制台同步增加翻页。

本轮解决按日志条数增长导致的列表卡顿。时间范围筛选仍可能扫描更多候选记录，单条超大文本未限制字节数；显式全量校验仍可能较慢。仍需发布后在真实 Bibit 桌面验收点击、筛选、翻页和刷新；组件测试与引擎压测不能替代桌面端到端测量。
