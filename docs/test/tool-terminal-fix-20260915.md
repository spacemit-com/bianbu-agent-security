# 工具终态与安全拒绝详情修复

| 项 | 值 |
|---|---|
| 对应缺陷 | WEB-03 / DESK-03 |
| 日期 | 2026-09-15 |
| Runtime 提交 | e10ea9e5 |
| Bibit 提交 | 8c1c908 |

两端事件投影均未在 Run 终态结束未完成工具；Runtime 的增量气泡更新还会被工具步骤覆盖错误正文。现统一关闭未完成工具，保留成功工具及其他 Run；安全拒绝卡片随气泡增量更新和历史回放保留。Bibit 诊断只选取原因、工具、能力和范围，不复制任意详情字段。

本地提交前：Runtime 浏览器及会话回归 111 passed；Bibit 投影回归 29 passed，TypeScript 检查通过。后续完整 Web 生产构建通过（先补齐本地扩展构建产物）。

提交后 Worker：备份并部署 Runtime 两份 JS，重启服务；会话投影 3 passed。浏览器经 SSH 隧道加载 Worker 实际 WebUI，回放工具开始与 security_denied 事件，断言工具失败、不转圈、安全卡片只有一份、file.read 与 /etc/hostname 可见。Bibit 同一提交投影通过 Vite 打包后在 Worker Node 回放三个终态，断言均通过。

本项 Worker 验收使用确定性事件回放，没有重新让模型生成被拒绝工具调用；未重新安装 Bibit 原生可执行文件，不能据此声称原生桌面 GUI 全链路复测通过。Worker 产物与备份：`/var/tmp/bnsec-d8a8f04c/`。

证据：[Worker 页面断言结果](evidence/tool-terminal-20260915/worker-webui.json)。
