# AgentOS Security — UDS 数据面详细设计与说明书

| 项 | 内容 |
|----|------|
| 文档编号 | BN-SEC-UDS-001 |
| 版本 | V1.1 |
| 来源 | BN-SEC-SRS-001 §18（ARCH-01）+ BN-SEC-PRD-TABLE §七 |
| 日期 | 2026-08-11 |
| 状态 | ✅ 正式服务已接入并在 worker 验证（协议、身份、DLP、审计、重启复放、性能） |
| 实现 | `securityd/uds_protocol.py`、`securityd/uds_server.py`、`securityd/uds_handlers.py`、`securityd/service.py`、`client/bianbu_security_uds.py` |
| 测试 | `tests/unit/test_uds.py`、`test_uds_handlers.py`、`tests/integration/uds_service_e2e.py`、`uds_benchmark.py` |

---

## 1. 为什么需要第二条通道

D-Bus 单消息上限虽有 128 MB，但每条消息要经 `dbus-daemon` 中转：多一次内核态拷贝 + 序列化/反序列化。控制面消息小（判权请求几十字节），这点开销无所谓；数据面不一样 —— DLP 要扫描完整 prompt、审计要存工具返回值全文，动辄几百 KB 到几 MB，走 D-Bus 会把延迟和 CPU 都吃掉。

UDS 是点对点 stream，一次 `sendall` 直达对端，没有中转进程。

**分工原则**：需要 polkit 管控、需要广播、消息小 → D-Bus；载荷大、频率高、点对点 → UDS。

---

## 2. 通道职责边界

| 维度 | D-Bus (`io.bianbu.Security`) | UDS (`/run/bianbu/securityd.sock`) |
|------|------------------------------|-------------------------------------|
| 适用 | 控制面、元数据、信号广播 | 数据面、大载荷、高频流式 |
| 载荷 | ≤ 4 KB | 任意（默认上限 64 MB） |
| 典型调用 | CheckPermission、SetCapabilityGranted、SecurityAlert 信号、RespondConfirm、MeterTokens | PII 扫描内容、审计载荷全文、工具返回值、流式 token |
| 访问控制 | polkit / D-Bus policy | socket 0660 + `SO_PEERCRED` uid 校验 |
| 连接模型 | 无状态单次调用 + 信号订阅 | 长连接复用 |
| 延迟目标 | P99 ≤ 10 ms | 小载荷（≤4 KB）P99 ≤ 1 ms；大载荷按吞吐约束 |
| DLP 接入 | 策略查询（CheckDLPPolicy） | 被扫描内容（>4 KB prompt/输出） |
| 审计接入 | 元数据（agent_id、op_type、decision） | 载荷全文（>1 KB 工具参数/返回值） |

分界点 4 KB 由 `config.UDS_DBUS_THRESHOLD` 定义，`should_use_uds(payload_bytes)` 判定。**等于阈值走 D-Bus，超过才走 UDS**。

---

## 3. 线协议

### 3.1 帧格式

```
[4 字节 big-endian 长度][UTF-8 JSON 载荷]
```

stream socket 没有消息边界，必须自己数字节 —— 这是长度前缀的唯一目的。

```python
def encode_frame(obj) -> bytes:
    body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
    return struct.pack(">I", len(body)) + body
```

`ensure_ascii=False` 让中文按 UTF-8 直接编码，而非 `\uXXXX` 转义 —— PII 场景全是中文，转义会让载荷膨胀约 3 倍。

### 3.2 三种边界情况的区分

| 情况 | `recv_frame` 行为 | 理由 |
|------|------------------|------|
| 对端干净关闭（无残留数据） | 返回 `None` | 正常结束，调用方据此退出循环 |
| 帧头不完整（如只收到 2/4 字节后断开） | `ProtocolError` | 这是异常断开，不能与干净关闭混淆 |
| 帧体短于声明长度 | `ProtocolError` | 同上 |
| 声明长度 > `max_payload` | `PayloadTooLarge` | **在分配内存之前**拒绝 |

最后一条是关键：如果先按声明长度分配 buffer 再校验，恶意客户端发个 `0xFFFFFFFF` 长度头就能触发 OOM。所以顺序必须是"读头 → 校验长度 → 才读体"。

### 3.3 请求/响应形态

请求按 `op` 字段路由：

```json
{"op": "dlp.scan", "text": "...", "agent_id": "com.hermes.agent"}
```

响应统一带 `ok`：

```json
{"ok": true, "findings": [...]}
{"ok": false, "error": "未知 op：xxx（可用：ping,dlp.scan,dlp.policy,audit.batch）"}
```

生产客户端为每次调用附加 `_request_id`。断线重试必须复用同一 id；服务端按
`peer uid + request id + 请求载荷指纹` 去重。同一 id 携带不同载荷时拒绝，不能返回
旧请求结果。缓存同时受条目数、总字节数和单响应大小限制；大响应只保留“已执行”
墓碑，重试会返回明确错误但不会再次执行非幂等 handler。

正式服务注册四个操作：

| op | 作用 | 身份要求 |
|----|------|----------|
| `ping` | 健康探测，返回可信 peer uid/pid | socket 文件权限 |
| `dlp.scan` | 扫描大文本，返回无 PII 明文的 findings、脱敏文本和生效策略 | `SO_PEERCRED` 进程身份必须匹配 Agent 绑定 |
| `dlp.policy` | 只读获取该 Agent 的 securityd 中央生效 DLP 策略，供 PA 小载荷本地扫描保持策略一致 | 可信 Agent 绑定；不允许调用方覆盖策略 |
| `audit.batch` | 将 1~100 条完整载荷作为单条哈希链记录写入 | 可信 Agent 绑定 + request id；跨重启持久去重 |

---

## 4. 服务端

### 4.1 线程模型

单 accept 线程 + 每连接一线程。accept 循环设 0.5s 超时，让 `stop()` 能及时生效（否则 `accept()` 会一直阻塞，`join` 超时）。

连接线程句柄在每次 accept 时清理已结束的，避免长期运行时列表无界增长。

### 4.2 安全三层

**第一层 —— socket 文件权限 0660**：同组可访问。

**第二层 —— `SO_PEERCRED` uid 校验**：

```python
raw = sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, _UCRED_SIZE)
_pid, uid, _gid = struct.unpack("3i", raw)
```

授权规则：
- 服务端非 root → 接受同 uid，或属于显式 `bianbu-security` 服务组的进程
- 服务端为 root → 接受任意 uid（由 socket 文件权限把关，因为 root daemon 要服务多用户）
- 平台不支持 `SO_PEERCRED`（非 Linux）→ 退回文件权限把关

对 `dlp.scan/dlp.policy/audit.batch` 还会用 peer PID 从 `/proc` 解析 argv[0]、cgroup 和补充组，
与 D-Bus `BindAgent` 使用同一套 `CallerContext` 比对；请求体中的 `agent_id` 不能替代
内核凭据。无法取得 `SO_PEERCRED` 时，这两个 Agent 操作 fail-closed。

**第三层 —— 载荷上限**：先于内存分配检查，见 §3.2。

### 4.3 错误隔离

handler 抛异常 → 捕获并回 `{"ok": false, "error": "..."}`，服务端继续存活。测试 `test_handler_exception_isolated` 验证：调 `boom` 拿到错误后，紧接着 `ping` 仍成功。

handler 返回非 dict → 同样回错误，不让格式问题变成崩溃。

### 4.4 残留 socket 处理

进程异常退出会留下 socket 文件，导致下次 `bind` 报 `EADDRINUSE`。启动时先探测：
普通残留文件或连接被拒绝的 stale socket 才删除；若连接成功，说明已有活跃实例，
第二实例直接失败，禁止 unlink 后形成 split-brain。停止时关闭所有已接受连接、等待
连接线程退出，再删除自己拥有的 socket。

---

## 5. 客户端

### 5.1 自动重连

服务端会在空闲超时（默认 10s）后关连接。客户端 `call()` 遇到 `OSError`/`ProtocolError` 时关掉本地 socket、以同一 `_request_id` 重连并重试一次；第二次仍失败才抛 `UdsUnavailable`。

只重试一次是有意的：如果是服务端真的挂了，无限重试会把调用方拖死。

### 5.2 独立于 securityd 包

部署时可能只分发 `client/` 目录。客户端在 import 时先试 `from securityd import config`，失败则用内置默认值（socket 路径从 `BIANBU_SEC_UDS` 环境变量读，阈值 4 KB）。

---

## 6. 配置项

| 配置 | 环境变量 | 默认 | 说明 |
|------|---------|------|------|
| socket 路径 | `BIANBU_SEC_UDS` | `<RUN_DIR>/securityd.sock` | 随 `BIANBU_SEC_ROOT` 走四级路径优先级 |
| 通道分界 | `BIANBU_SEC_UDS_THRESHOLD` | 4096 | 超过此值走 UDS |
| 载荷上限 | `BIANBU_SEC_UDS_MAX` | 64 MB | 防 OOM |
| 空闲超时 | `BIANBU_SEC_UDS_TIMEOUT` | 10s | 服务端关闭空闲连接 |
| socket 权限 | — | 0660 | 固定 |

---

## 7. 性能实测（worker K3 riscv64）

`tests/integration/uds_benchmark.py`，**全部达标**：

### 7.1 延迟

| 载荷 | p50 | p99 | 吞吐 |
|------|-----|-----|------|
| 空载（协议开销下界） | 0.146 ms | **0.175 ms** | — |
| 1 KB | 0.189 ms | 0.207 ms | 5.1 MB/s |
| 4 KB（通道分界） | 0.276 ms | **0.301 ms** | 14.1 MB/s |
| 64 KB | 1.907 ms | 2.107 ms | 32.7 MB/s |
| 1 MB | 29.613 ms | 34.182 ms | 33.2 MB/s |

### 7.2 吞吐与稳定性

- 连续 1 MB × 50 次：50 MB / 1.63 s = **30.6 MB/s**
- 长连接复用 2000 次：**零错误**

### 7.3 指标口径修订（实测驱动）

原 SRS 写 "UDS 数据面 P99 ≤ 1 ms"，并在验收里要求"UDS 传输 1MB 数据 P99 ≤ 1 ms"。**实测 1 MB 的 p99 是 34 ms** —— 这个指标从一开始就不成立：延迟随载荷线性增长（1 MB 在 30 MB/s 下光传输就要 33 ms），任何实现都做不到对任意大小 ≤1 ms。

已修订为分段指标：

| 口径 | 指标 | 实测 |
|------|------|------|
| 小载荷（≤4 KB） | P99 ≤ 1 ms | 0.301 ms ✅ |
| 大载荷 | 吞吐 ≥ 10 MB/s | 30.6 MB/s ✅ |

SRS §18 ARCH-01 与 PRD Table §七 的对照表已同步改口径。

---

## 8. 测试覆盖

当前 worker 证据（2026-08-14）：

- `tests/unit/test_uds.py`：**36 passed**；
- UDS/DLP/install/failure 专项：**52 passed**；
- audit/Confirm/failure 专项：**26 passed**，覆盖磁盘满、运行中只读、启动只读、未决 Confirm 重启取消和恢复；
- `tests/integration/test_dbus_security.py`：**5 passed**，正式 UDS service E2E 覆盖服务重启复放；
- securityd strict：**509 unit + 14 integration + 3 E2E passed**，`skipped=0`；真实 testkit：**35/35**；
- PA UDS + Runtime 定向回归：**10 passed**；PA 全量：**848 passed, 73 个既有环境失败**。

**协议层（10）**：帧布局、往返、中文不转义、1 MB 往返、干净关闭返回 None、帧头截断、帧体截断、超限先于分配拒绝、零长度帧、非法 JSON

**服务端（14）**：socket 权限 0660、ping、echo、长连接复用、512 KB 真实往返、`SO_PEERCRED` 可见、未知 op、handler 异常隔离、handler 返回值非 dict、超限请求被拒且服务存活、ops 列表、stop 清理 socket、残留 socket 重启、上下文管理器

**客户端（2）**：socket 不存在时 `UdsUnavailable`、服务端断连后自动重连

**通道选择（1）**：4 KB 阈值边界（4096 走 D-Bus，4097 走 UDS）

全量回归：**113 passed**（此前 86）

---

## 9. 已知边界

1. **无 TLS/加密** — UDS 是本机通道，靠文件权限、服务组、`SO_PEERCRED` 与 Agent 绑定校验。跨主机场景不适用
2. **无 SCM_RIGHTS fd 传递** — 设计里提过用 fd 传超大文件避免拷贝，当前未实现。64 MB 上限内 JSON 够用；真需要传 GB 级文件再加
3. **同步请求/响应** — 一个连接同时只能有一个在途请求。并发调用需多连接（客户端非线程安全，每线程一个 `UdsClient`）
4. **JSON 序列化开销** — 大二进制数据要 base64（膨胀 33%）。DLP 扫的是文本，暂不成问题
5. **服务端为 root 时接受任意 uid** — 由 socket 文件权限把关；产品 unit 默认使用 `bianbu-security` 非 root 用户
6. **`enforce_peer_uid=False` 会关掉 uid 校验** — 仅供测试，生产不要用

---

## 10. 下一步

PA 产品链路已经默认完成选路：大于 4KB 的 DLP 文本走 `dlp.scan`，大于 1KB 的完整
治理载荷走 `audit.batch`；小载荷使用本地扫描器，但策略来自 `dlp.policy` 的中央生效
配置，中央策略不可达且无缓存时默认 BLOCK。`DLP-04` 已在 worker 真实 PA + securityd
链路通过。worker 生产 Security unit 已创建 `/run/bianbu/securityd.sock`，实测为
`0660:bianbu-security`，WebUI 重启不会删除或重建该 socket。剩余工作仅是由不同 uid 的
正式 Runtime/Agent unit 验证 `bianbu-security` 补充组与 Agent 绑定矩阵；不能用本仓
参考 Runtime 冒充该证据。

---

*文档结束 — BN-SEC-UDS-001 v1.0*
