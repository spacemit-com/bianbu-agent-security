# 网络访问控制修复与设备复测（2026-09-10）

本次修复前次验收发现的五类问题，相关设备复测通过。验证包由提交前的工作区构建，已在 10.0.90.243 安装；本次未创建发布 tag。最终阻断矩阵及收尾结果在报告末尾记录。

## 修复内容

1. **连接最终结果**：preload 不再将 EINPROGRESS 当作成功，跟踪 SO_ERROR 和实际连接状态；同步拒绝和非阻塞拒绝均保留 errno。关闭未完成连接记录为取消，避免伪造成功。使用 socket cookie 防止 dup2/fd 复用将新连接结果错误归给旧目标；保留应用原有返回值和 errno。
2. **DNS 学习记录**：挂接 getaddrinfo，按现有 dns_query 协议上报域名、A/AAAA、解析地址、结果及错误；collector 保留这些字段。数值 IP 不作为域名解析记录。该观测是 libc 解析调用，不是原始 DNS 抓包，可能包含 hosts/缓存解析；protocol=udp 沿用现有 DNS 事件协议，不代表验证了实际传输方式。
3. **采集来源**：Runtime 透传 backend；preload 事件标为 preload，可选 bpftrace 事件显式标为 ebpf-tracepoint。
4. **策略生效状态**：Security 按逻辑 Worker 查询当前活跃租约及策略版本，复核 systemd 实际 IPAddressAllow/IPAddressDeny。兼容初始租约、热更新状态、旧 Agent 默认 allow_all，以及 D-Bus 历史 Python 列表文本、JSON 字符串和原生列表三种网络属性格式。无运行实例、旧版本、校验失败均不宣称当前策略已生效。
5. **失联与恢复**：客户端 EOF/连接错误报告 degraded，以有上限的退避重新连接并注册，正确处理分段 JSON，首次采集器不可用时也保留重试，停止 Worker 时终止重试。仅重连 Runtime 客户端还不够：原 bwrap 单 socket 绑定固定了旧 inode；现改为只读挂载专用目录 `/run/bianbu/network-learning`，socket 为其中的 `collector.sock`，采集器重启后新 socket 对既有 Worker 可见。服务、postinst、Runtime ExecStartPre 均保证目录为 root:bianbu-security、0770，socket 为 0660；未挂载整个 /run/bianbu。Runtime Wants/After 采集服务，采集服务中断不停止 Runtime。

Runtime 对 Security 的最低依赖仍为 >= 0.1.18。本轮不修改最低依赖或发布版本。Security 0.1.23 与 bibit-intent >= 0.1.23 来自此前已拉取的主线；243 原 bibit-intent 0.1.17 无法满足当前 Runtime 包依赖，安装时通过软件源只升级该依赖到 0.1.23，无包移除。

## 构建与安装

构建根目录：`/home/bianbu/builds/network-fix-20260910/`，包含源码快照、最终补丁、构建/安装日志和验证脚本。

| 包 | 版本 | 最终 SHA-256 |
|---|---|---|
| bianbu-agent-runtime | 0.1.19 | 4096c1c20c3fcaec47fa65842e4ec60eb5fca7c7b1ede417b020eb54ac4507f9 |
| bianbu-agent-securityd | 0.1.23 | 2efe1f18ef19921281b2c61f72fa8f355a23dc4e4d9a5c4a8afd0f18725eaca3 |

Runtime 基线 ea8c05ebb50fa100da63956bebd1673ed47c5eed，Security 基线 fa8787aaee9704214407cdd80a53bcdea032bc30，叠加本次未提交修复。归档未包含用户本地 config.yaml 修改和无关未跟踪文件。安装后 dpkg -V 两个包无差异，已比较关键安装文件与构建源文件一致。

## 回归测试

- Runtime 网络采集、systemd 配置、执行协调器：115 passed。
- Security 网络策略、学习记录、服务接口、租约与执行引擎：58 passed，1 skipped（本地缺 dbus）。
- 243 系统 Python 最终补跑 network_policy 与 service_network_learning：33 passed，覆盖本地跳过项；有既有 GLib 弃用警告。
- 243 RISC-V 原生编译运行 preload 回归：3 passed；系统 pytest 提示未识别 asyncio_mode，所选测试均为同步测试。
- preload 使用 gcc -Wall -Wextra -Werror 编译通过；真实 socket 测试覆盖阻塞/非阻塞拒绝、成功、DNS 和 fd 复用。
- 独立代码复核发现的 fd 复用、legacy 默认策略和冷启动目录问题均已处理。

## 设备复测证据

新测试 Agent：`com.bianbu.09d8bef53a94`，名称“网络修复验收 20260910”，sandbox/bwrap。

证据目录：`/home/bianbu/builds/network-fix-20260910/verification/`。

- `learning-records.json`、`learning-final-records.json`：真实 Agent terminal 工具执行父进程与 exec 子进程探针，39082 拒绝连接为 failed、errno=111；39081 三个地址成功；example.com 的 dns_query 域名/地址记录存在，backend=preload。
- `learning-final-policy.json`：当前 Worker 为 effective=true、restart_required=false、enforced=true。
- `fault-stopped-2.json`：采集服务 inactive 时状态 degraded。
- `reconnect-verdict.json`：采集器恢复后同一 Worker 实例 `com.bianbu.09d8bef53a94-fe78706647a147ce9d849dfbebcd6617` 不重启，39082 学习记录 count 从 4 增为 6。
- `pre-directory-fix/`：保留首次只修客户端重连而未修 socket 挂载时的失败证据，不将这轮误计为通过。

限制模式继续使用 UID 1000 探针加入实际 Worker 的 cgroup 与网络/挂载/PID 命名空间，核对实际 systemd 属性；该探针并非完整 Worker 后代，不继承全部 seccomp/user namespace。学习与恢复测试使用真实 Agent terminal 工具。

## 范围与限制

本次修复与验证针对当前启用的 preload 学习链路；学习采集不等同于强制访问控制，也不是不可绕过的内核审计。静态链接程序、直接系统调用、自定义 DNS/DoH 等不在此次 getaddrinfo 观测覆盖内。采集器停机期间不承诺回补记录，会明确显示降级。域名白名单仍按解析后的 IP 执行，不提供 HTTP Host/SNI 隔离；未进行整机重启验收，可选 eBPF 后端内部进程异常恢复不在此次设备测试范围。

## 最终矩阵与收尾

设备 `matrix-verdicts.json` 的 5 项均通过，父进程与 exec 子进程结果一致；每项均核对 `effective=true`、`restart_required=false`、`enforced=true` 与实际 systemd 属性和连接结果。

| 策略 | 127.0.0.1:39081 | 10.0.90.243:39081 | [::1]:39081 | DNS |
|---|---|---|---|---|
| 白名单 127.0.0.1 | 可达 | 阻断 | 阻断 | 可用 |
| 白名单 localhost | 可达 | 阻断 | 可达 | 可用 |
| deny_all | 阻断 | 阻断 | 阻断 | 不可用 |
| 空白名单 | 阻断 | 阻断 | 阻断 | 不可用 |
| 恢复 allow_all | 可达 | 可达 | 可达 | 可用 |

更新策略但尚未重启时仍正确提示需重启，重启后上述状态恢复正确。`pre-literal-fix/` 保留首次非空属性编码复测的失败证据。

`cleanup.json` 确认：测试 Agent 恢复 allow_all、空 domains；专用 HTTP 服务已停止，工作区探针已删除；测试 Agent、会话、学习历史及构建/复测证据保留。Runtime、Security、网络采集器、Security WebUI 和 syscall observer 均 active；dpkg -V 两个包无差异。
