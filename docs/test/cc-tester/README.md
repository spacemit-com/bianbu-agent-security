# cc-tester：Runtime × Security 安全子系统梳理与端到端验收（2026-09-11）

本目录是本轮由 Claude Code 执行的「功能梳理 → 测试方案 → 实机验收」完整产出。阅读顺序：

| 文件 | 内容 |
|---|---|
| [01-security-feature-inventory-and-status.md](01-security-feature-inventory-and-status.md) | 两仓安全架构、一次工具调用的完整安全链路、身份模型；Runtime 29 项 / securityd 21 项功能的开发状态矩阵（已完成 / 部分 / 未开始）；未交付与范围外清单；对 20260911 历史报告三个 P0 判定的修正 |
| [02-e2e-delivery-test-plan-and-cases.md](02-e2e-delivery-test-plan-and-cases.md) | 环境契约（端口 8788、身份、yolo 前提）、四层测试入口、用例总览与详细用例（testkit 37 项 + 手工探针 + 故障注入）、脚本与证据目录、准出标准 |
| [03-e2e-acceptance-report-20260911.md](03-e2e-acceptance-report-20260911.md) | 本轮实机验收结果：回归、testkit 三次运行、手工探针、故障注入；缺陷清单（含根因与建议修复位置）；结论 |
| [04-defect-list-and-fix-plan.md](04-defect-list-and-fix-plan.md) | 缺陷梳理：4 项必须解决（UDS 身份字段、会话级 Token 计数、网络策略 polkit、lease 实例收敛）+ 8 项其它问题，每项含现象/根因/修复方案/验证；修复顺序与工作量；修复分支 `fix/cc-tester-defects` |
| [05-fix-verification-report-20260911.md](05-fix-verification-report-20260911.md) | 修复分支两轮实机复验：testkit 37/37，D-1~D-10 逐项闭合证据、协议变更与兼容处理、未完成项；证据在 `evidence/fix-round/` |
| `evidence/` | Worker 上 `/var/tmp/bnsec-cc-tester-20260911/` 的证据副本（pytest 日志、testkit `report.json`、探针输出、探针脚本）。WebUI token 已脱敏 |

本轮同时修改了仓内测试资产（已随 commit `ea92b28` 提交）：

- `testkit/engine.py`：`audit_chain_db()` 修正审计库选择；新增 `Ctx.enforcing_mode()`（临时 normal + 抬高 Token 配额，退出恢复）；`dbus_int64()`。
- `testkit/tests_all.py`：YOLO-01 对齐新默认；HOOK-03 / DLP-04 / ERR-01 在 normal 下运行并加强断言；ERR-01 改用 L4 `terminal`；新增 TOKEN-03。
- `impl/bianbu-securityd/tests/test_syscall_audit.py`：两条单测隔离宿主内核观测器。

Worker 侧被测源码副本 `/var/tmp/bnsec-delivery-20260911/{runtime,security}` 与 `/home/bianbu/bnsec-testkit` 已同步上述 testkit 文件。
