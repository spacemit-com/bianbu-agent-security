# 243 原生桌面验收记录（2026-09-15）

- 构建机：10.0.90.176，`bibit-gui` SHA256 `2282846b7f0d544f56edfc4147ca2e7a68572e6a7cae4120654213481e89219e`。
- 安装机：10.0.90.243，`/usr/bin/bibit-gui` 与构建产物 hash 一致；runtime 插件加载 `0.2.18`。
- 原生 noVNC 实际点击确认：专家卡片“使用专家”进入聊天并选中 `Network acceptance e5450c44`；暂停显示“暂停请求已发送，Agent 未停止，仍可能继续执行”；网络策略保存后显示“策略已保存，需重启 Worker；尚未对全部运行实例生效”，并提供“重建 Worker 并应用策略”及确认弹窗。
- 243 testkit：37 项通过，0 失败/错误/跳过。
- Runtime normal/security-on 两轮回归：均 2385 passed、13 failed、3 skipped；失败集合均为修复前基线的 14 条子集，无新增失败，on/off 集合一致。对照见 `evidence/native-desktop-20260915/runtime-failure-comparison.json`。

未在本次原生 GUI 中宣称已覆盖的宏分支（mask/block 全动作逐会话、非法 L4/trusted、工具拒绝细节、syscall 事件）已有 Runtime/WebUI/服务层证据，仍需按报告的细分清单复测后再签收。
