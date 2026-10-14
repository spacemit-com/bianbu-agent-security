# YOLO 下 DLP BLOCK 旁路修复

| 项 | 值 |
|---|---|
| 对应缺陷 | WEB-09 / DESK-09 |
| 日期 | 2026-09-15 |
| Runtime 提交 | d8a8f04c |
| Security 提交 | aa6f11e |
| 验证机器 | 10.0.90.243，Runtime 0.1.65 / Security 0.1.30 + 上述补丁 |

根因有两层：Runtime 安全 Hook 按 YOLO 忽略 BLOCK；Security 通用干预链再次把任何 handler 的 BLOCK/CONFIRM 与 fail-closed 错误改为放行。能力模式应由能力判权层处理，不能覆盖 DLP 的独立裁决。另修复低风险工具把 DLP BLOCK 当成服务不可达而降级放行的问题。

本地：Runtime 35 项通过；Security 干预链、DLP 与模式 73 项通过。均在提交前执行。

Worker：安装插件 Hook 12 项通过，Security 干预链 26 项通过。真实临时 sandbox Agent 在 normal 和 YOLO 两种模式中分别提交合成手机号，两次均为 `security_denied`，无模型用量，临时 Agent 已恢复 normal 后删除。

Worker Security 全量首次 791 passed / 5 failed，5 项因测试快照遗漏根目录 debian 文件而报 FileNotFoundError；补齐同一提交完整源码后 test_install_flow.py 的 20 项全部通过。既有 testkit 实际注册 37 项，37 passed / 0 failed / 0 skipped。未把数量过时的文档标注当作测试结果。

证据：[真实请求](evidence/yolo-dlp-20260915/live-yolo.json)、[testkit 报告](evidence/yolo-dlp-20260915/testkit-report.json)。本项验证是 API/真实运行链路，未重新操作桌面 GUI。首次部署途中外部包安装将 Runtime 从 0.1.62 升至 0.1.65；已在安装完成后重新部署和重启，两份旧插件备份保留在 Worker `/var/tmp/bnsec-d8a8f04c/`。
