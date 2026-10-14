# 工具返回值 DLP 验收（F-04 补充）

Runtime 提交 `b395c0ef` 将真实工具返回文本传入 AFTER_TOOL，并在返回模型前消费脱敏和 BLOCK 结果。BLOCK 无论工具风险等级均终止 Run。

先新增三项失败断言（mask 原文泄漏、BLOCK 未拒绝、扫描收到空文本），再修复；本地工具适配/安全 hook/安全中间件 41 项通过。本地提交后部署 Worker 10.0.90.243 并重启 Runtime；Worker 工具适配 14 项通过。

确定性本地模型驱动真实 sandbox terminal 生成合成手机号。normal/yolo × mask/block 四组均通过：mask 后续 HTTP 请求包含 PII 占位符且无原文；block Run 失败且没有第二次模型请求。临时 Agent/Provider 已自动删除。证据与可复跑脚本在 `evidence/tool-result-dlp-20260915/`。

本项不代表历史上下文和模型流式输出已验收，仍需独立补测。

回归旧断言提交 `add9c8a2` 本地/Worker 各 43 项通过。初次 Worker 运行读到了旧源码快照的 console.js，更新测试快照后复跑通过；生产 WebUI 已在此前部署新版本。
