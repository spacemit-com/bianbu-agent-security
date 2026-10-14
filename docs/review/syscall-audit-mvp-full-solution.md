# 系统调用拒绝审计：MVP 与完整版方案

**文档状态：** 方案与交付边界（2026-09-06）  
**适用组件：** `bianbu-agent-runtime`、`bianbu-agent-security`  结果是评审和实施依据，不代表采集器已经部署。

## 1. 当前基线与缺口

已经具备的能力：

- `securityd` 维护 12 项强制 syscall denylist，并支持按架构/Agent 的追加策略和版本号；
- `seccomp_builder` 生成 cBPF，命中项返回 `EPERM`，架构不匹配终止进程；
- Sandbox Worker 通过 bwrap 继承 seccomp，fork/exec 子进程同样受约束；
- `SyscallAuditStore` 使用独立 `syscall-events.db` 和独立 SHA-256 链；
- D-Bus/HTTP 已有策略配置、状态和审计存储边界。

尚未具备的能力：seccomp 命中后自动产生审计事件。当前过滤器直接由内核返回 `EPERM`，不会自动调用 `RecordSyscallInterception`；`SyscallAuditStore.status()` 只是后端探测，不是采集器。因此“命令返回 EPERM”不能单独证明事件已写入独立审计链。

## 2. 安全不变量

1. seccomp 是唯一的强制阻断路径，审计采集失败不得改为放行。
2. 强制基线不可删除；策略变更只对新启动/重启 Worker 生效。
3. Agent、instance、lease、PID/cgroup 必须绑定，不能信任 Broker/collector 自报的 Agent ID。
4. 审计数据库由 securityd 最终写入，采集器不得直接写 SQLite。
5. securityd 不可用时仍阻断；事件允许进入本地 append-only spool，恢复后校验、去重、重放。

## 3. MVP：eBPF 旁路采集

### 3.1 架构

```text
Worker cgroup
  ├─ seccomp-BPF（真正返回 EPERM）
  └─ raw_syscalls:sys_enter/exit → collector → securityd UDS → syscall-events.db
```

Runtime 在 Worker 启动后记录 PID、cgroup ID、lease/instance、策略版本。collector 使用 `bpf_get_current_cgroup_id()` 过滤目标 cgroup，从 ring buffer 读取 syscall 编号、PID/TID、UID、时间和返回值；用户态按 cgroup/lease 映射 Agent 后调用 `RecordSyscallInterception`。

### 3.2 MVP 范围

- 覆盖 cgroup v2；子进程继承 cgroup 自动纳入；
- 监听 `raw_syscalls:sys_enter`，可选关联 `sys_exit` 的 `-EPERM`；
- 仅记录 denylist 中的 syscall，默认不采集参数；
- backend 标记为 `ebpf-tracepoint`，记录 `policy_version`；
- 无 BPF 权限、内核不支持或 ring buffer 丢失时，状态明确为 `unavailable/degraded`，不伪造 active；
- securityd 对 lease、cgroup、架构/编号、策略版本、event_id 做最终校验和去重。

### 3.3 MVP 局限

tracepoint 能证明“Worker 尝试了 denylist syscall”，并可观察到最终 `EPERM`，但不能严格区分 EPERM 来自 seccomp、Capability 或其他 LSM。需要在事件中使用 `observed_result` 和 `evidence=attempt+exit`，不要展示为“seccomp 唯一命中证明”。

## 4. 完整版：seccomp user-notification Broker

每个 Sandbox Worker 配一个受 lease 管理的 Broker。Broker 持有 `SECCOMP_FILTER_FLAG_NEW_LISTENER` 返回的 listener FD；危险 syscall 采用 `SECCOMP_RET_USER_NOTIF`，Broker 校验 PID/cgroup/lease 后调用 securityd 记录事件，再通过 `SECCOMP_IOCTL_NOTIF_SEND` 返回 `EPERM`。普通 syscall 仍 `ALLOW`，架构异常仍 `KILL_PROCESS`。

完整版能精确证明“该 syscall 由 seccomp 策略处理”，但需要改造当前 bwrap FD 传递和 Worker 启动顺序；Broker 崩溃或 securityd 不可达时必须保持阻断（暂停/退出 Worker，或本地 spool 后返回 EPERM），绝不能切换为 `ALLOW`。

## 5. securityd 事件契约

建议扩展 `RecordSyscallInterception` 字段：

```text
event_id, agent_id, instance_id, lease_id, pid, cgroup_id,
arch, syscall, number, action=deny, backend, policy_version, observed_result
```

securityd 通过 UDS `SO_PEERCRED` 获取真实 UID/PID，并校验：lease 有效、instance/Agent 绑定、PID 与记录或 cgroup 一致、syscall 名称/编号与架构匹配、仍在有效 denylist、策略版本合法、backend 在白名单。`seq/prev_hash/hash` 只能由 securityd 生成；数据库独立于普通能力审计。

查询接口至少包括：

- `GetSyscallAuditEvents(agent_id, limit, cursor)`；
- `GetSyscallAuditStatus(agent_id)`；
- `VerifySyscallAuditChain()`。

## 6. 分阶段交付

| 阶段 | 交付物 | 退出门槛 |
|---|---|---|
| M0 | 事件 schema、lease/cgroup 映射、权限探测 | 契约测试通过 |
| M1 MVP | eBPF collector、spool、securityd 校验/落库 | x86_64 sandbox 端到端新增事件 |
| M2 产品化 | WebUI 事件列表、状态/降级提示、告警和轮转 | 失败注入仍 fail-closed |
| F1 完整版 | user-notification Broker、bwrap 启动链改造 | 可证明 seccomp 来源，Broker 故障安全 |
| F2 发布 | riscv64、升级/回滚、性能/丢失率报告 | 发布门禁和签字证据齐全 |

## 7. 观测与运维指标

必须暴露 collector 状态（backend、attached cgroup 数、events、dropped、spooled、replayed、last_error）和 securityd 审计链状态。事件采集延迟、丢失率、spool 大小、策略版本不一致均应可查询；达到阈值时标记 degraded，但不放宽 seccomp。

