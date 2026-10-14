# 安全验收缺陷修复计划

**目标**：修复 2026-09-15 报告中可复现的 Runtime、Security 与桌面集成缺陷，并记录实际验证边界。

**依据**：`/home/duancheng/workspace-test/desktop+runtime+security-test-report.md` 及 `security-test/outputs/mvp-security-20260915/`。

**架构边界**：securityd 保持判权/DLP/审计职责；Runtime 应用安全 Hook 的结果；Bibit 与插件展示服务真实状态。YOLO 只旁路能力确认，不旁路 DLP。保持各仓版本、依赖下限与发布标签不变，按用户要求逐项本地提交后在 Worker 验证，不推送。

## 执行顺序

- [x] DLP：在 Runtime `tests/` 增加输入、模型与工具 BLOCK 在 YOLO 仍阻断的行为回归；修正 `resources/plugins/bianbu.security/scripts/` 的旁路分支。验证 normal/yolo 与 mask/block 的组合。
- [x] mask：在 Runtime 真实 RunManager→engine 边界断言实际模型输入不含合成手机号；修正 `runs/manager.py` 对脱敏结果的消费，保留消息身份、附件和技能引用。
- [x] 工具终态：复现 Run 失败后工具仍等待/执行中的问题；在 Runtime 事件与 Bibit 投影边界补回归，确保失败原因、能力和范围可见。
- [x] 暂停：现有 `SuspendAgent` 仅发出审计/告警。按报告允许的“明确请求语义”修复 Runtime/桌面按钮、提示和 API 回执，不能声称已暂停。
- [x] 网络：扩展插件 DTO，保留 allow_all/learning；使用 effective/restart_required 展示保存与生效状态。Runtime WebUI 同步修正。UI 回归覆盖刷新、保存和失败。
- [x] 错误：非法 L4/trusted 应返回可操作校验错误，不暴露 D-Bus/Python 堆栈或伪称服务不可用。
- [x] 专家入口：核对 Bibit 现有宿主导航能力，补齐可实现的专家聊天入口；若缺协议实现，准确记录所需合同与未完成边界。
- [x] K3 验证：同步到独立测试路径，优先运行新增回归；部署改动时备份并重启受影响服务。运行 testkit/runner.py 与相应回归，保留日志，恢复测试策略。
- [x] 文档：记录每个验收项的根因、修改文件、验证结果及未验证步骤；追加插件 process.md。

## 验收原则

每个行为修复先运行失败回归，再实现并重跑。mask 的决定性证据为模型调用入口或 HTTP 载荷中的脱敏文本，不能只看扫描结果。内核拒绝与模型拒绝分别计数。未完成桌面/真实请求验收的项不标记端到端通过。
