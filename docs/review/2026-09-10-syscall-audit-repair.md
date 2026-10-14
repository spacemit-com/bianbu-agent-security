# 系统调用拦截审计修复与 243 验收

日期：2026-09-10。机器：10.0.90.243，riscv64，Linux 6.18.3。

## 原因

原先 seccomp 黑名单仍然返回 EPERM，但默认 strace 采集已被停用，普通
ERRNO 过滤器也没有请求内核记录拦截。旧状态检测仅看到 auditctl/bpftool
存在就显示 active，掩盖了采集链路不可用的问题。

只补充 auditd SECCOMP 日志解析仍不足：短命进程退出后，基于
/proc/PID/cgroup 的异步归属检查会失效。实测第一版只能记录立即退出探测的
6/24 条事件，不能据此宣称完整修复。

## 修复

- Runtime Worker 启动时对原有过滤器增加 SECCOMP_FILTER_FLAG_LOG。
  原有 bwrap 过滤器保持生效，黑名单仍返回 EPERM；不重新启用 Worker strace。
- Security 包增加独立的 bianbu-syscall-observer 服务，在 audit_seccomp
  内核钩子中同步捕获真实 PID、cgroup ID、系统调用号和拒绝动作。
  该实现不依赖目标机缺失的 BTF，依赖 bpftrace >= 0.25 和相应内核功能。
- 只有该特权服务写入 /run/bianbu-syscall-audit。Security 主服务保持原有
  非 root 身份和权限，读取 root 所有且不可被普通用户改写的记录，按已提交
  的 Worker 租约和实际 cgroup inode 关联 Agent、实例及策略版本。
  此通道不暴露给 Runtime 的 D-Bus/UDS 上报接口。
- 保留退出进程的真实 PID；事件 ID 去重；对并发写入的审计链追加加锁。
- Security 在 CommitStart 时独立读取并持久化 cgroup ID、boot ID 和单调时钟
  起始时间，和调用方 attestation 分开存放。租约撤销记录结束时间，采集事件
  使用内核的单调捕获时间匹配，因此整个 Worker 退出后、撤销前已捕获的事件
  仍可入库；跨启动或租约生命周期之外的事件不能借此归属。
- 日志轮转时跨批次读完旧文件，再切换新文件；9,001 条记录回归测试通过。
  独立复核发现的退出竞态与轮转漏读均已修正并复核。
- D-Bus 和 UDS 使用同一上报逻辑，内核采集正常时避免 auditd 重复入库。
- 内核采集不可用但 auditd 仍可用时显示 degraded / live-process-only，
  明示退出进程可能漏记；均不可用时显示 unavailable。
- 审计策略版本来自实际 seccomp 策略，而非 Runtime 协议 schema 版本。
- 未提高 Runtime 对 bianbu-agent-securityd 的最低依赖版本（仍为 >= 0.1.18）。

## 验收证据

安装包由本次未提交修复代码构建，尚未创建发布 tag：

| 包 | 版本 | SHA-256 |
|---|---|---|
| bianbu-agent-runtime | 0.1.19 | 4fc2084b592455e8a90b6d965aa8b077aec4849ab089cf3005cbfc2c6e88d740 |
| bianbu-agent-securityd | 0.1.22 | 9ce32e73149d534b6a32da759ac953a5793c7474eabf29fbea8be42279bd35d7 |

机器上的构建、deb、安装日志和验收原始结果：
`/home/bianbu/builds/syscall-audit-fix-20260910/`。
最终验收子目录为 `verification/final-reviewed/`，包含可重跑的 `verify.py`。

新建 Agent：`com.bianbu.3a00fec3bdf0`（拦截事件审计最终复核 20260910）。

- 探测脚本通过真实 Agent terminal 工具执行，不手工插入事件。
- 父、exec 子进程分别执行 12 项强制黑名单调用，使用无效参数，均返回 EPERM。
- 移除测试等待时间，父、子进程立即退出；普通 getpid 调用仍正常。
- 新增恰好 24 条 ebpf-seccomp 事件，系统调用各 2 条，事件 ID 不重复。
- 真实宿主 PID 1687943 和 1687944 各 12 条；检查时两个进程均已退出。
- worker_agent_id、实例、租约、cgroup、riscv64 架构和策略版本 2 均正确。
- 审计总数从 94 增至 118，chain_valid=true。
- 停止采集服务：degraded / auditd-seccomp / live-process-only。
- 重启采集服务：active / ebpf-seccomp / deny-only，总数仍为 118。
- Runtime、Security、采集服务、Security WebUI 均 active；采集服务已 enable。
- dpkg -V 两个安装包均无差异；auditctl -l 为 No rules，没有遗留测试规则。
- 相关自动化测试：Runtime 99 项、Security 48 项，全部通过。

## 范围

本次修复审计链路，不修改每个逻辑 Agent 的追加黑名单选择或 openat2
过滤器表问题。无 BPF/kprobe 支持的平台会明确降级，不承诺其短命进程审计完整性。
现有用户配置和审计历史保留。
