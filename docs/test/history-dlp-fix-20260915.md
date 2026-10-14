# 历史消息 DLP 验收（F-04 补充）

Runtime 提交 `f7f78801` 在每次模型请求前扫描历史消息、工具结果/参数、system prompt 与文本内容块，并在压缩摘要模型调用前扫描摘要输入。复制数据，不更改消息 ID、工具调用 ID 或原始历史；每次重新查询中央策略，不缓存旧的 allow 决策。扫描异常时阻止模型外发。

本地相关 75 项通过，本地提交后部署 Worker 并重启 Runtime，Worker 模型边界/摘要回归 11 项通过。

真实 HTTP 验收在同一会话先允许合成手机号进入历史，再更改 phone 策略。normal/yolo × mask/block 四组通过：mask 时下一请求只含占位符，block 时 Run 失败且模型端点零请求。临时 Agent/Provider 自动删除。首次探针撞上 Runtime 重启窗口，未创建资源；待服务就绪后完整复跑通过。

证据见 `evidence/history-dlp-20260915/`。模型回复发布前的流式治理仍作为下一项独立修复。
