# 配置中心网络策略与域名功能验收审查

| 项目 | 内容 |
|---|---|
| 范围 | `bianbu-agent-runtime`、`bianbu-agent-security` |
| 分支 | `feature/config-center-network-domain` |
| Security 版本 | `0.1.15` |
| Runtime 版本 | `0.1.0+systemd37`，manifest `1.2.16` |
| 目标机 | `10.0.90.243`（riscv64） |
| 人工验收入口 | `http://10.0.90.243:9899` |
| 状态 | 核心功能已完成，端到端链路已在目标机验证 |

## 1. 结论

配置中心的网络策略/域名功能已经完成最小可用闭环：页面保存策略后，Runtime 通过安全协议调用 Security，Security 持久化策略并参与后续 Worker 启动；策略编译为 bwrap 网络隔离或 systemd IP 过滤规则。已在 243 上安装 deb 包并验证 `deny_all`、`allow_all`、`whitelist` 和 `learning` 四种模式。

策略更新采用选项 B：保存成功后，已运行的 bwrap Worker 不立即改变，接口返回 `restart_required=true`；重启 Worker 后使用新策略。旧 lease 会按 PID 和实际 cgroup 校验并过滤，避免 stale lease 被当作活动实例。

## 2. 模式语义

| 模式 | 语义 |
|---|---|
| `whitelist` | 仅允许白名单域名解析出的地址及必要 DNS 地址，其他出站连接阻断 |
| `deny_all` | Worker 网络命名空间仅保留 loopback，所有外部网络访问阻断 |
| `allow_all` | 不启用网络隔离，允许 Worker 正常访问网络 |
| `learning` | 允许运行并采集 DNS/connect 成功或失败事件，事件可查询、聚合、分页和清空 |

无显式持久化策略时默认 `deny_all`，不会再从 manifest 域名隐式回退为白名单。Runtime 页面支持四种模式和域名编辑。

## 3. 端到端链路

```text
9899 配置中心
  -> network-policy.update.v1
  -> Runtime Security Client
  -> Security D-Bus SetNetworkPolicy
  -> SQLite network_policy（模式、域名、版本）
  -> PrepareStart 读取持久化策略
  -> bwrap 或 systemd scope 网络限制
  -> Worker 实际流量
```

`learning` 事件通过 collector 采集 DNS endpoint/connect、IPv4/IPv6 connect 和失败连接，并在 Security 侧持久化及查询。

## 4. 243 实机证据

### 4.1 安装与服务

已构建并安装：

```text
/home/bianbu/build-config-center-network-domain/bianbu-agent-securityd_0.1.15_riscv64.deb
SHA256 65f2b8c5736ed10d92a543183bd76fa0b1976497a42131c864266383774eb76c

/home/bianbu/build-config-center-network-domain/bianbu-agent-runtime_0.1.0+systemd37_riscv64.deb
SHA256 13560c7827d1dc66452e553ed1f9585deacba7ff434d4c1c14c372158701c9ee
```

以下服务均为 active：

```text
bianbu-securityd.service
bianbu-security-webui.service
bianbu-agent-runtime@bianbu.service
```

`http://10.0.90.243:9899` 返回 HTTP 200。

### 4.2 deny_all

保存策略后返回：

```json
{
  "mode": "deny_all",
  "version": 2,
  "apply": {
    "active_instances": 4,
    "restart_required": true,
    "restart_required_instances": 4,
    "effective": false
  }
}
```

重启 Runtime 后，最新 lease 均为 `deny_all/version=2`，bwrap 参数包含 `--unshare-net`，Worker netns 只有 loopback；DNS、IPv4 `1.1.1.1` 和 IPv6 `2606:4700:4700::1111` 均无法连接。

### 4.3 allow_all

保存 version 3 并重启后，bwrap 不带 `--unshare-net`。Worker 内 DNS 成功，`https://example.com` 返回 HTTP 200，`https://8.8.8.8` 返回 HTTP 302。

### 4.4 whitelist

设置 `domains=["example.com"]` 并重启后，真实 systemd scope 属性包含：

```text
IPAddressAllow=172.66.147.243/32 127.0.0.53/32 104.20.23.154/32
IPAddressDeny=::/0 0.0.0.0/0
```

把临时测试进程加入真实 Worker cgroup 后，`https://example.com` 返回 HTTP 200，`https://8.8.8.8` 超时。仅使用 `nsenter -n` 会绕过 systemd cgroup BPF，因此人工验收必须在真实 Worker cgroup 内验证。

### 4.5 learning

保存并重启后状态为 `active`，4 个活动实例均已上报。真实 Session API 触发后，Security 查询到 DNS stub、远端连接、失败连接，并带有 `instance_id`、`lease_id`、`policy_version`；调用 `network-learning.clear.v1` 后事件数从 3 变为 0。

## 5. 自动化验证

开发机回归结果：

```text
Runtime 相关回归：128 passed
Security 网络策略/Runtime policy/lease/安装流程：58 passed
Runtime JS syntax：passed
Runtime Debian source contract：passed
```

Security 全量为 `674 passed, 6 skipped, 21 failed`。失败项来自测试 venv 缺少 `dbus`/`langgraph`，与本次网络策略实现无关。

243 testkit 在正式 Agent 身份和路径下为 `28 passed, 7 failed, 1 error`；剩余失败集中在模型超时、YOLO/HOOK、DLP 正式 UDS 审计断言、token callback 和审计库选择，不是网络策略失败。

## 6. 已知限制

1. 目标机没有 IPv6 默认路由，因此只能验证 deny_all 下 IPv6 被阻断，不能证明 allow_all 的 IPv6 外网成功。
2. 本次真实 learning trace 捕获到了 DNS endpoint 连接，但没有拿到 DNS payload 中的域名字符串；DNS payload parser 已有单元测试覆盖。
3. `artifact_only` 只表示规则产物已生成，不能单独作为 privileged helper 已下发的证明。
4. 已运行 bwrap Worker 的策略更新按选项 B 延迟到重启生效；接口会明确返回 `restart_required`。
5. 本次范围不包含 token quota，也不修改 `bibit-security-plugin`。

## 7. 人工验收入口

1. 打开 `http://10.0.90.243:9899`。
2. 选择模式并填写域名，保存后确认返回的版本和 `restart_required`。
3. 重启对应 Runtime Worker。
4. 在真实 Worker cgroup 内分别验证允许域名、未声明域名、`deny_all` 出站连接和 `learning` 事件查询/清空。
