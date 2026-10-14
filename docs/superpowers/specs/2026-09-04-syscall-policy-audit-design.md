# Syscall 黑名单策略与独立拦截审计 MVP 设计

## 目标与非目标

本功能允许管理员按架构配置 syscall 黑名单追加项，统一查看安全执行状态，并独立记录黑名单命中事件。FR-SEC-05 的既有行为必须保持：seccomp 使用 `SECCOMP_RET_ERRNO | EPERM`，架构不匹配仍然终止进程，已运行 Worker 不热更新策略。

本 MVP 不允许删除内置基线、不支持任意手工 syscall 名称、不改变 `BuildSandboxPolicy(agent_id) -> (seccomp_path, netfilter_rules)` 契约、不默认采集 syscall 参数，也不以审计采集结果决定是否阻断。

## 权威组件和数据流

`securityd` 是策略唯一权威。WebUI/CLI 通过 D-Bus 修改策略；securityd 校验架构和目录后持久化 additions、递增版本并写普通安全审计。Runtime 在每次 Worker 启动的 `PrepareStart`/`BuildSandboxPolicy` 路径读取 effective denylist，生成不可变 seccomp 文件并把应用版本写入启动快照。运行中的 Worker 保留旧快照，后续启动才使用新版本。

拦截审计是旁路：优先探测 eBPF，无法使用时探测 auditd；两者都不可用时仍保持 seccomp 阻断，并在状态接口标记 `unavailable`，不得伪造“已审计”。

## 策略模型和持久化

内置基线由代码固定（当前 12 项）并按 `x86_64`、`riscv64` 分别维护。数据库仅保存追加项：

```text
syscall_policy(scope TEXT, agent_id TEXT NULL, arch TEXT,
  additions_json TEXT, policy_version INTEGER, updated_by TEXT,
  updated_at TEXT, PRIMARY KEY(scope, agent_id, arch))
```

`scope` 为 `global` 或 `agent`；agent 行的 `agent_id` 必填。输入必须来自内置 syscall 目录且适配目标架构；重复项去重并按目录稳定排序。effective 集合严格为：

```text
mandatory ∪ global_additions ∪ agent_additions
```

每次成功变更都递增全局单调 `policy_version`，保留 `applied_policy_version`（最近一次生成/启动使用的版本）和 `pending_restart = policy_version != applied_policy_version`。删除/重置只影响 additions，不能触碰 mandatory。

## D-Bus 接口

在 `io.bianbu.Security` 增加以下方法；现有 `BuildSandboxPolicy` 保持不变：

```text
GetSyscallCatalog(s arch) -> a{sv}
GetSyscallPolicy(s agent_id, s arch) -> a{sv}
SetGlobalSyscallPolicy(s arch, as additions) -> a{sv}
SetAgentSyscallPolicy(s agent_id, s arch, as additions) -> a{sv}
ResetAgentSyscallPolicy(s agent_id, s arch) -> a{sv}
GetSecurityExecutionStatus(s agent_id) -> a{sv}
```

返回字典统一包含 `arch`, `mandatory`, `global_additions`, `agent_additions`, `effective`, `policy_version`, `applied_policy_version`, `pending_restart`；catalog 额外包含每个 syscall 的 `name`, `number`, `description`, `mandatory`。管理员检查沿用现有 D-Bus/polkit 身份；非管理员返回 `io.bianbu.Error.PermissionDenied`。错误使用明确消息：`UnsupportedArch`、`UnknownSyscall`、`SyscallNotApplicable`、`InvalidAgent`、`PolicyStoreUnavailable`。

## Runtime 和执行状态

`BuildSandboxPolicy` 调用策略合并函数并把生成文件绑定到当前启动实例。`GetSecurityExecutionStatus` 返回 control/securityd/worker/seccomp/audit 五块状态，至少包括 worker PID、mode、backend、sandboxed、seccomp profile digest、策略版本和审计 backend/coverage。若策略已修改而 Worker 未重启，状态为 `pending_restart`，不伪造 active。

## 独立 syscall 审计

事件写入独立 SQLite 表和独立哈希链，字段包括独立序号、时间、agent_id、worker PID、架构、syscall 名称/编号、动作（`deny`）、采集后端和策略版本。普通能力审计表不复用序号或链。默认 `metadata` 级别始终开启；`summary` 由管理员开启；`full` 仅调试短时开启并带 TTL、原因和二次确认，默认关闭。MVP 首先实现后端探测、存储接口、状态和导出/验证边界；采集器不可用不得影响 seccomp。

## WebUI

安全总览新增“安全执行状态”卡片；Agent 详情新增 syscall 策略页。页面展示 12 项强制基线、架构追加项、effective 数量、当前/待生效版本、重启提示、审计后端和覆盖状态。修改控件仅管理员可见/可提交，syscall 使用目录多选并显示中文功能说明；保存成功提示“仅新启动或重启 Worker 后生效”。

## 验收标准

1. 默认 12 项在两架构存在且不可删除；未知名和跨架构名被拒绝。
2. global/agent additions 合并、去重、版本递增和 pending_restart 正确。
3. 现有 seccomp 测试仍验证命中 EPERM、非黑名单放行、错误架构终止。
4. 非管理员不能写策略；每次变更都有安全审计记录。
5. 新 Worker 使用新版本，旧 Worker 保持旧版本。
6. 审计后端不可用时接口明确显示 unavailable，seccomp 仍阻断。
7. D-Bus 合约、Runtime 状态和 WebUI 端到端测试通过。
