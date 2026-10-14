# 非法安全策略错误反馈修复

Runtime 提交 `ccd95e1b`。本地先复现 3 条失败回归，修复后 security API 29 项通过；提交后部署 Worker 并重启，29 项同样通过。

Worker 修复前真实 L4/trusted 请求返回 unavailable 和完整 Python/D-Bus 堆栈；修复后返回 invalid_request、retryable=false，并提示选择 always 或 once_per_session。调用在写入前拒绝，没有修改目标能力。服务故障的堆栈改为日志排查提示，保留无堆栈的可操作 ABI 错误。

证据：[Worker 真实响应](evidence/invalid-policy-20260915/worker-response.json)。
