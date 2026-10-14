# 网络访问控制验收（2026-09-10）

结论：本轮基础网络阻断用例通过，学习记录正确性、策略生效状态和采集器故障恢复未通过，不能整体验收通过。本次仅测试与调查，未修改产品代码或提交发布。

## 环境与方法

- 设备：10.0.90.243，RISC-V，Linux 6.18.3；已安装 Runtime 0.1.19、Security 0.1.22，包含前次系统调用审计修复。本次未重新构建；包版本不能代表当前 main 的所有后续提交。
- 新建专用 sandbox Agent：`com.bianbu.ce787b2b4708`，名称“网络访问控制验收 20260910”。
- 原始证据：设备 `/home/bianbu/builds/network-acceptance-20260910/`；探针、API 脚本、Worker/lease/systemd 属性、终端事件及采集结果均保留。
- 测试服务器只监听本机三个地址 `127.0.0.1:39081`、`10.0.90.243:39081`、`[::1]:39081`；39082 不监听，作为失败对照。DNS 测试解析 `example.com`。
- `allow_all`、`learning` 和采集恢复通过真实 Agent 的 terminal 工具执行 Python 探针及 exec 子进程。
- 限制模式使用 UID 1000 探针，加入目标 Worker 的真实 cgroup 及网络、挂载、PID 命名空间；核对 cgroup、netns 和实际 systemd IP 过滤属性。该方法验证网络执行边界，不等同于完整 Worker 后代沙箱测试，未继承 Worker 的全部 seccomp/user namespace 配置。
- 本轮连接矩阵以 TCP 为主，并覆盖系统 DNS 解析；未穷举 UDP、自定义 DNS、域名地址变更、共享 IP、代理或重定向。域名白名单当前按解析后的 IP 执行，不能据此宣称 HTTP Host/SNI 隔离。

## 验收矩阵

| 项目 | 实测 | 结论 |
|---|---|---|
| 主机基线 | 三个测试服务和 DNS 可达，39082 返回 ECONNREFUSED | 通过 |
| allow_all | Agent 终端及子进程均可访问三个服务、解析 DNS | 通过 |
| learning 放行 | Agent 终端及子进程均可访问三个服务、解析 DNS | 通过 |
| 策略待重启 | 更新白名单但不重启时仍执行旧策略；更新响应提示需重启 | 通过 |
| IPv4 白名单 127.0.0.1 | 仅该测试地址可达；主机 IP 和 ::1 被阻断，子进程一致 | 通过 |
| 域名白名单 localhost | 127.0.0.1、::1 可达；主机 IP 被阻断，子进程一致 | 通过 |
| deny_all | 三个服务及 DNS 均失败，子进程一致 | 通过 |
| 空白名单 | 三个服务及 DNS 均失败，子进程一致 | 通过 |
| 学习连接记录 | 有记录，但失败结果及采集来源不准确，未生成 DNS 记录 | 未通过 |
| 重启后生效状态 | 新 lease 和实际过滤已生效，接口仍显示需重启、artifact_only | 未通过 |
| 采集器故障提示 | 服务 inactive 后接口仍报 active | 未通过 |
| 采集器自动恢复 | 仅重启采集器后记录不再增长；重启 Worker 才恢复 | 未通过 |

IPv4 白名单实际 systemd 属性：`IPAddressDeny=::/0 0.0.0.0/0`，`IPAddressAllow=127.0.0.53/32 127.0.0.1/32`；其中解析器地址被单独放行。localhost 白名单额外包含 `::1/128`。

## 缺陷与证据

1. **失败连接误报成功。** `learning-agent-probe.json` 中父子进程连接 39082 均为 errno 111；`learning-records-after.json` 却记录该端口 `outcome=success`、空 errno、count=2。源码 `scripts/network-learning-preload.c` 将 `EINPROGRESS` 当成功，未跟踪后续最终连接结果，可解释本次非阻塞连接误报。
2. **采集来源标记错误。** 同一批事件 ID 为 `preload-...`，backend 却为 `ebpf-tracepoint`。Runtime `bianbu_agent/security/execution_runtime.py` 的学习事件上报硬编码了该 backend。
3. **DNS 学习缺口。** 实际探针解析 example.com 成功，采集结果只有 connect、domain 为空，没有对应 DNS/domain 事件。当前 preload 只挂接 connect；本轮未观察到完整域名学习能力。
4. **生效状态与执行事实不一致。** `whitelist_v4-snapshot.json` 表明新 Worker 使用 version 4 且已应用 IP 过滤，连接矩阵也证实阻断；`whitelist_v4-policy.json` 仍为 `enforced=false`、`artifact_only`、`restart_required=true`、`effective=false`。更新时提示需重启是合理的，重启后的状态未正确反映实际执行才是缺陷。
5. **采集器失联未降级且无自动重连。** 停服前确认仅本测试 Agent 有活跃 learning cgroup（`fault-active-learning-instances.json`）。停服后每隔 2 秒取样，共三次，服务 inactive 而状态仍 active（`fault-stopped-*.json`）。finally 恢复采集服务后，真实 Agent 再次成功访问测试服务，但 `fault-events-before-probe.json` 与 `fault-events-after-probe.json` 的 result 完全相同。重启本测试 Worker 后，version 9 的 39081 记录出现（`learning-recovered-records.json`）。源码 `network_learning_privileged.py` 在读取 EOF 时直接退出，未报告降级或自动重连，与现象一致。

## 回归与收尾

本地已有相关测试：Runtime 五个 network learning 测试文件共 24 passed；Security network_policy、network_learning、service_network_learning 共 43 passed、1 skipped（dbus 导入条件）。这些单元测试不替代设备验收；当前通过的单元测试未覆盖上述端到端缺陷。

收尾结果见设备 `cleanup.json`：测试策略恢复为 `allow_all`、domains=[]（版本自然递增）；恢复后再次检查连接矩阵。临时 HTTP 服务及工作区探针清理，测试 Agent、会话和验收证据保留供复核；核心服务与学习采集服务恢复运行。
