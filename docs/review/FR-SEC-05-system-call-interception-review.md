# FR-SEC-05 系统调用拦截功能评审

**评审范围：** Agent Security 的 seccomp-bpf 系统调用拦截及其 Runtime sandbox 集成  
**评审基线：** Security `f6fc2f7cf58df3dd0c9f2121200fae9fdbfeb589`；Runtime `8438e617be97666e17e0b6efe0cd16a46dbab456`  
**评审结论：** 核心实现完成；x86_64 sandbox 集成验证通过；riscv64 实机逐项验证、全黑名单 syscall 覆盖和生产受管 Worker 证据仍需补齐。

## 1. 需求基线

FR-SEC-05 要求：

1. 生成 seccomp cBPF；
2. 黑名单 syscall 命中返回 EPERM，其余 syscall 放行；
3. 架构不匹配时终止进程；
4. 覆盖 x86_64 与 riscv64；
5. 沙箱内父进程及其 fork/exec 子进程均受过滤器约束。

当前黑名单包括：

```text
reboot, swapon, swapoff,
kexec_load, kexec_file_load,
init_module, finit_module, delete_module,
mount, umount2, pivot_root, perf_event_open
```

## 2. 实现链路

```text
PrepareStart
  → securityd.engine.build_sandbox_policy()
  → seccomp_builder.build_policy_file()
  → 生成 seccomp.bpf
  → Runtime 获取 seccomp_profile.path
  → BwrapBackend 校验并暂存策略文件
  → systemd-run 以 stdin/fd 0 打开 BPF
  → bwrap --seccomp 0
  → Worker 及其 fork/exec 子进程继承过滤器
```

关键文件：

- `impl/bianbu-securityd/securityd/seccomp_builder.py`：纯 Python cBPF 生成器；
- `impl/bianbu-securityd/securityd/sandbox.py`：bwrap 参数编排、seccomp FD 传递、缺失策略 fail-closed；
- `impl/bianbu-securityd/runtime/policy.py`：生成并返回 sandbox/seccomp 策略；
- `bianbu-agent-runtime/bianbu_agent/security/execution_runtime.py`：受管 Worker 的 seccomp staging、systemd 输入和 `--seccomp 0`。

## 3. 需求完成度

| 子需求 | 状态 | 证据 |
|---|---|---|
| FR-SEC-05-01 BPF 生成 | 已完成 | `test_seccomp_builder.py`；字节长度为 8 的倍数，黑名单指令存在 |
| 黑名单 syscall | 已完成 | `SECCOMP_DENYLIST` 覆盖 12 项危险调用 |
| 命中返回 EPERM | 已验证 | sandbox 内 `reboot()` 返回 EPERM，测试退出码 99 |
| 非黑名单放行 | 已实现 | 默认动作 `SECCOMP_RET_ALLOW` |
| 架构不符 KILL | 已实现 | arch 校验失败返回 `SECCOMP_RET_KILL_PROCESS` |
| x86_64 | 已验证 | x86_64 syscall 表及 sandbox 内核测试通过 |
| riscv64 | 静态验证 | arch 常量和 syscall 表覆盖；当前主机未做 riscv64 内核实测 |
| bwrap 加载 | 已验证 | `--seccomp` FD 参数、策略文件加载测试通过 |
| FR-SEC-05-03 fork/exec 继承 | 已验证 | Hermes 模拟父进程 spawn 子进程后 syscall 仍被拦截 |
| 缺失策略 fail-closed | 已验证 | seccomp 文件不存在时拒绝启动 |
| Runtime 受管 Worker 传递 | 已实现/测试 | systemd `StandardInput=file:` + fd 0 传递，22 项 Runtime 测试通过 |
| Host 模式拦截 | 当前不适用 | HostProcessBackend 不加载 seccomp；拦截仅由 sandbox backend 提供 |

## 4. 测试证据

### 4.1 Security 测试

```bash
cd impl/bianbu-securityd
.venv/bin/pytest -q \
  tests/unit/test_seccomp_builder.py \
  tests/integration/test_sandbox_manager.py \
  tests/integration/test_hermes_sandbox.py
```

结果：**12 passed**。

覆盖：

- BPF 结构、指令和 arch；
- x86_64 `reboot()` 内核拦截；
- bwrap 文件视图与 capability drop；
- Hermes 父进程 spawn 的子进程继承 seccomp；
- seccomp 文件缺失时 fail-closed；
- cgroup 强制失败时拒绝启动。

### 4.2 Runtime 测试

```bash
cd bianbu-agent-runtime
.venv/bin/pytest -q tests/runtime/test_execution_runtime.py \
  -k 'seccomp or bwrap'
```

结果：**22 passed**。

覆盖：

- sandbox 命令行含 `--seccomp 0`；
- BPF staging 路径及权限；
- systemd service/scope 的 `StandardInput=file:`；
- BPF FD 不经 shell wrapper 直接传给 bwrap；
- 策略缺失、后端不一致和启动失败的拒绝路径。

## 5. 运行时安全分析

### 5.1 Sandbox 模式

Sandbox 模式由 Security 返回 `effective_mode=sandbox`、`backend=bwrap` 和 `seccomp_profile`。Runtime 校验策略文件存在且非空，将文件暂存到 Worker socket 目录，再由 systemd-run 以标准输入打开，bwrap 使用 FD 0 加载。过滤器在 exec 前安装，因此 Worker 和其子进程继承约束。

### 5.2 Host 模式

Host 模式使用 `HostProcessBackend`，不加载 seccomp。当前设计把 FR-SEC-05 定义为 sandbox 的底层隔离能力；Host 模式依赖 capability 判权、审计和其他 Runtime 控制，不应在文档或 UI 中宣称具备同等级 syscall 内核隔离。

### 5.3 Fail-closed

以下条件会拒绝 sandbox 启动：

- seccomp 策略路径为空或文件不存在/为空；
- bwrap 不可用；
- 必需 cgroup 无法建立或附加；
- 受管 Worker 的 policy mount/socket 约束不满足；
- Runtime 策略与 backend/effective_mode 不一致。

## 6. 风险与未完成项

### R1：riscv64 缺少目标机内核实测

当前 x86_64 开发机只能验证 riscv64 syscall 表和 BPF 生成，不能证明 riscv64 内核实际加载和拦截行为。需要在 riscv64 worker 逐项执行 `reboot()`、子进程继承和不匹配 arch 测试。

### R2：黑名单尚未逐项内核实测

真实内核测试重点覆盖 `reboot()`；其他 11 项主要通过 syscall 表/BPF 结构验证。建议增加参数化集成测试，逐项确认 EPERM。

### R3：生产受管 Worker 证据不足

开发脚本 `run-security-amd.sh` 在当前主机可能进入 `development optional host fallback`，不能作为生产 sandbox/seccomp 证据。生产验收必须使用 systemd 受管 Worker、bwrap、user namespace、Security UDS 和固定 manifest entrypoint。

### R4：syscall 拒绝未形成独立 Security 审计事件

seccomp 命中由内核直接返回 EPERM。当前已有策略生成、Runtime/Hook 和工具判权审计，但没有证据表明每次 syscall 命中都生成独立 Security 审计/告警。若产品要求逐次 syscall 审计，需要增加 seccomp notifier、内核 audit 或 Runtime 错误上报方案。

### R5：Host 模式不拦截 syscall

若产品要求 HOST 与 sandbox 都必须具备 FR-SEC-05 的内核拦截能力，当前架构不满足，需要设计 host-process 的 seccomp 加载点；否则应在产品规格中明确 FR-SEC-05 仅适用于 sandbox。

## 7. 交付判定

| 交付层级 | 判定 |
|---|---|
| 开发联调 | 通过 |
| x86_64 sandbox | 通过 |
| syscall 生成器 | 通过 |
| 子进程继承 | 通过 |
| fail-closed 启动保护 | 通过 |
| riscv64 生产验收 | 待目标机复验 |
| 全黑名单逐项内核覆盖 | 待补充 |
| Host 模式 syscall 拦截 | 当前未实现 |
| 生产发布签署 | 有条件通过 |

## 8. 建议后续动作

1. 在 riscv64 worker 上运行完整 sandbox/seccomp 集成测试并留存内核日志；
2. 新增参数化 syscall 黑名单测试，至少覆盖 12 个调用；
3. 在生产受管 Worker 上验证 BPF 文件 staging、systemd FD 和 bwrap 加载；
4. 明确 Host 模式是否纳入 FR-SEC-05；
5. 若要求 syscall 级审计，补充 notifier/audit 采集并加入发布门禁。
