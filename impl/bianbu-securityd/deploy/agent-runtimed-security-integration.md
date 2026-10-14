# Agent Runtime 安全集成约定

`bianbu-agent-runtimed` 必须在自身进程内完成以下动作，Securityd 不代替
Runtime 执行暂停、终止或停止服务：

1. 进程启动后，用自身 D-Bus sender 调用 `BindAgentV2(agent_id, context)`，
   `context` 至少包含稳定的 `session_id`、`run_id` 和 `source=agent-runtime`。
2. 运行时 unit 使用本文件同目录的 `bianbu-agent-runtimed.service`，并在部署
   后保存 `systemctl show` 输出，登记 UID、`MainPID`、`ControlGroup`、unit 和
   session/run 关联。未能复核时必须拒绝进入生产运行态。

该 unit 是安装/验收模板，不表示外部 Runtime 二进制已经存在；只有构建产物、
真实 systemd 状态与生产探针原始输出齐全后，才可关闭生产 Runtime 门禁。

## 只读生产探针

部署 Runtime 二进制后执行：

```bash
python3 deploy/runtime_production_probe.py --json
```

探针只读取 `systemctl show` 和 `busctl introspect`，检查 unit 的
`ActiveState/MainPID/User/Group/ControlGroup` 以及 `io.bianbu.Runtime` 生命周期
方法。缺失 unit、调用者身份不匹配或 D-Bus 契约不完整时返回退出码 `2`，并输出
`RUNTIME_PRODUCTION_BLOCKED`；它不会启动、停止或修改任何服务。
