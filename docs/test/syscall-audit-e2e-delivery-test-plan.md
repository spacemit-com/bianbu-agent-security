# 系统调用拦截审计 MVP 端到端交付测试方案

**目标：** 证明 Sandbox Worker 中命中 denylist 的 syscall 被阻断并进入独立审计链；同时证明采集器、安全服务和 Worker 故障不会导致放行。  
**范围：** Runtime sandbox、securityd 策略、eBPF MVP（或明确 unavailable）、独立哈希链、WebUI/API。

## 1. 前置与隔离

```bash
SEC=/home/duancheng/workspace/bianbu-agent/bianbu-agent-security
RT=/home/duancheng/workspace/bianbu-agent/bianbu-agent-runtime
cd "$SEC/impl/bianbu-securityd"
python3 -m pytest -q tests/test_syscall_policy.py tests/test_syscall_audit.py
busctl --user status io.bianbu.Security
test -S "$HOME/.local/share/bianbu-securityd/run/bianbu/securityd.sock"
```

使用临时 Agent ID、临时数据库/运行目录和测试 Worker；禁止在生产数据库上执行清理或策略重置。记录两个仓库 commit、内核版本、架构、bwrap 版本及 collector 权限。

## 2. 交付阶段

| 阶段 | 用例 | 通过标准 |
|---|---|---|
| P0 契约 | policy/catalog/status/event schema | 字段、错误码、版本语义一致 |
| P1 策略 | 强制基线、追加、重启生效 | 12 项不可删，旧 Worker 不热更新 |
| P2 阻断 | 逐项 syscall + fork/exec | 命中返回 EPERM，普通调用可用 |
| P3 采集 | cgroup 过滤、映射、落库 | 独立 DB 新增事件，链校验通过 |
| P4 故障 | securityd/collector/BPF 权限 | 状态 degraded/unavailable，仍阻断 |
| P5 产品 | Runtime API/WebUI | Agent、Worker、syscall、版本可筛选 |
| P6 发布 | x86_64 + riscv64、升级回滚 | 证据包完整，门禁通过 |

## 3. 关键手工用例

### SA-E2E-01：策略与快照

1. 查询 `GetSyscallCatalog(x86_64)`，确认 12 项 `mandatory=true` 且含描述。
2. 为测试 Agent 增加 `finit_module` 之外的追加项，确认 `policy_version` 递增、`pending_restart=true`。
3. 启动 Worker，记录应用版本；修改策略后确认旧 Worker 版本不变，新 Worker 使用新版本。
4. 尝试删除强制项、未知名、跨架构名，均应返回明确 4xx/D-Bus 错误且不落库。

### SA-E2E-02：阻断与继承

在 sandbox Worker 内执行（x86_64 示例）：

```bash
python3 -c 'import ctypes,os; fd=os.open("/dev/null",os.O_RDONLY); r=ctypes.CDLL(None,use_errno=True).syscall(313,fd,b"",0); print(r,ctypes.get_errno())'
```

预期 `-1/EPERM`；执行一个非 denylist 的无害 syscall 应成功。再由 Worker fork/exec 子进程重复测试，确认仍受 seccomp 约束。记录 `/proc/<pid>/status` 中 `Seccomp=2` 和实际 sandbox backend；不要仅凭 EPERM 宣称审计已完成。

### SA-E2E-03：MVP 事件落库

1. 确认 collector 状态为 `active/ebpf`，目标 cgroup 已注册。
2. 执行 SA-E2E-02，等待事件同步。
3. 调用 `GetSyscallAuditEvents` 或读取测试库，断言最新记录包含 `agent_id、instance_id/lease_id、pid、cgroup_id、arch=x86_64、syscall=finit_module、number=313、action=deny、backend=ebpf-tracepoint、policy_version`。
4. 调用 `VerifySyscallAuditChain`，断言 true；重复 event_id 不产生重复 seq。
5. 若环境无 BPF 权限，必须返回 `unavailable` 并在报告中注明“阻断通过、审计采集未启用”，不能伪造通过。

### SA-E2E-04：securityd/collector 故障

分别停止 securityd、断开 UDS、杀 collector、注入 ring buffer 丢失和策略版本不一致。每次执行危险 syscall 均仍返回 EPERM；状态显示 degraded/unavailable；spool 追加事件并在服务恢复后重放、校验、去重。任何 ALLOW 均为阻断性缺陷。

### SA-E2E-05：身份与伪造

伪造 Agent/instance/lease、跨 cgroup PID、错误 syscall 编号/架构、过期策略版本和非法 backend 上报。securityd 必须拒绝落库并记录安全错误；合法 Worker 事件不受影响。验证 PID 重用不会归属到旧 lease。

### SA-E2E-06：WebUI/Runtime 体验

在安全页面选择 Agent，确认显示执行模式（sandbox/host）、seccomp 状态、审计 backend、coverage、policy/applied 版本、pending restart、事件数和最近错误。Worker 或 securityd 不可用时显示可解释错误，而不是空列表或“暂无事件”。

## 4. 完整版 Broker 验收追加项

- listener FD 创建和传递不经过 shell 丢失；
- deny syscall 由 Broker 收到通知后返回 EPERM，并生成 `backend=seccomp-user-notify` 事件；
- 普通 syscall 不触发通知；
- Broker 崩溃、lease 失效、securityd 不可达时 Worker 退出/暂停而不放行；
- seccomp notifier 与 cgroup/lease 校验覆盖 fork、exec、PID 重用和并发多 Worker。

## 5. 证据包与发布门禁

每次交付保存：测试命令和原始输出、两个仓库 commit、策略 JSON、Worker/runtime status、collector 指标、独立 DB 导出、哈希链验证结果、故障注入结果和 WebUI 截图。以下任一项缺失不得标记“完整审计通过”：事件真实落库、身份字段可信、链校验通过、采集不可用时明确降级、任何故障均保持 fail-closed。

