# 模型请求脱敏修复

| 项 | 值 |
|---|---|
| 对应缺陷 | WEB-05 / DESK-05 |
| 日期 | 2026-09-15 |
| Runtime 提交 | 7d206a1b |
| 验证机器 | 10.0.90.243 |

根因：BEFORE_MODEL 返回的脱敏文本只进入 metadata，RunManager 仍把原始文本交给模型。现在对完成上下文组装的输入应用脱敏；结构化 inbox 逐条过滤，并保留身份、时间戳、附件与技能引用。

本地提交前：生命周期与 DLP 42 项通过，middleware 独立运行 15 项通过。Worker 安装补丁并重启 Runtime 后，生命周期与 DLP 42 项通过，完整 testkit 37 项全部通过。

真实 HTTP 捕获在 normal 和 YOLO 两种模式下均验证：模型请求正文含脱敏占位符，不含合成手机号。测试 Agent 已删除，捕获配置已恢复。没有重跑桌面 GUI，本项决定性验收是实际模型 HTTP 请求正文。

证据：[模型请求正文](evidence/dlp-mask-20260915/http-request-evidence.json)、[testkit](evidence/dlp-mask-20260915/testkit-report.json)。
