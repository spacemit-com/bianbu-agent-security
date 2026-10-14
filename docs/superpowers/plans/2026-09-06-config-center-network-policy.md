# 配置中心网络策略完善实施计划

> **For agentic workers:** 按任务逐项执行并在每项后运行对应测试。

**Goal:** 完成 Runtime 到 Security 的网络策略配置、持久化、启动应用、模式统一、fail-closed 与单元测试闭环。

**Architecture:** Security capability registry 使用同一 SQLite 数据库持久化 per-agent 网络策略；`PrepareStart` 与 sandbox 规则生成均读取该有效策略。Runtime 与 Security 共用 `whitelist`、`deny_all`、`learning` 契约，策略更新返回版本和 enforcement 状态。

**Tech Stack:** Python 3.14、SQLite、D-Bus、systemd IP filtering、pytest。

## 任务

- [ ] Security registry 增加 network_policy 表及规范化读写 API。
- [ ] Security engine、规则生成和 `PrepareStart` 统一读取持久化策略，并支持回滚/状态返回。
- [ ] Runtime 执行器和 API 统一网络模式、域名校验及 fail-closed 语义。
- [ ] 补充 Security/Runtime 单元测试与跨模块回归测试。
- [ ] 在 10.0.90.237 安装/使用测试依赖，运行相关测试和可执行端到端检查。
- [ ] 更新 review 文档并记录验证结果。

## 2026-09-07 继续收敛

- [x] Runtime 接受 learning；空域名 learning 保留网络，deny_all 即使携带域名也隔离 bwrap 网络。
- [x] Security systemd 属性校验支持无允许地址的 deny_all，精确比较 IPv4/IPv6 网络集合，拒绝地址子串误匹配和额外放行。
- [ ] learning 的真实流量记录链路；当前 Runtime 改动仅解决非阻断执行语义，尚不能宣称已记录流量。
- [ ] 实际配置中心源码位于相邻 bibit-security-plugin；同步页面、契约、Adapter、构建产物及浏览器验证。
- [ ] 更新现有 lease 的网络策略并验证失败恢复；补充有效版本与执行状态展示。
- [ ] 动态 DNS 刷新、解析失败行为及 IPv4/IPv6 流量回归。
- [ ] 目标机 HTTP 到 D-Bus、PrepareStart、真实允许/阻断流量验收。
- [ ] 重跑全量测试，逐项定位历史失败；不得直接把失败归为环境问题。
- [ ] 使用现有 debian/ 原生构建并验证安装升级；此前“仓库没有 debian/”的描述不符合当前文件状态。
- [ ] 统一 review 文档历史结论，附最新原始验收证据。

本轮现时验证：Runtime execution 63 passed；Security network_policy、capability_registry、runtime_policy 37 passed；两仓 git diff --check 通过。新增用例先观察到失败，再实现修复。以上仅为本地定向证据，尚未部署本轮改动到目标机。
