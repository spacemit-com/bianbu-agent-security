# bianbu-securityd — AgentOS 安全子系统（AgentSecurityD）

BN-SEC-SOL-001 设计方案的可运行实现。信任根守护进程，经 D-Bus `io.bianbu.Security`
对外提供 Capability 判定、Manifest 验签、确认门禁、seccomp/网络策略编译、审计哈希链、
软件密钥库。

## 目录结构

```
securityd/           核心包
  config.py          路径/默认值（BIANBU_SEC_ROOT 可整体重定向，便于非 root/测试）
  models.py          Domain/RiskLevel/Confirm/Decision/Permission/Manifest
  errors.py          io.bianbu.Error.* 错误码
  manifest.py        Manifest 校验 + ed25519 验签（FR-SEC-01）
  capability_registry.py  SQLite WAL + CheckPermission + session_trust（FR-SEC-02/03）
  confirm.py         确认门禁 + L4 二次 + 超时（FR-SEC-03）
  audit_chain.py     SHA-256 哈希链 + 单写线程 + 导出/验证（FR-SEC-06）
  seccomp_builder.py 纯 Python cBPF 生成，x86_64/riscv64（FR-SEC-05/SBX-04）
  network_policy.py  域名→systemd IPFilter/netfilter 白名单与真实强制状态（FR-SEC-07/SBX-03）
  sandbox.py         bwrap 参数构造 + cgroup + Fail-Closed（FR-SBX-01~07）
  key_vault.py       加密文件密钥库 + 门控（FR-AI-21）
  engine.py          组合全部模块的业务引擎
  service.py         D-Bus 服务层（业务方法 + 信号）
client/              hermes/第三方 D-Bus 客户端封装
  runtime_security_consumer.py  正式 Runtime 侧 V2 事件消费者、状态回调与调用门禁
cli/bncli.py         capability/agent mode/audit/install 命令
data/                introspection XML + systemd unit + dbus policy
tests/               unit / integration / e2e / fixtures + smoke_test.sh
```

## 运行

```bash
# 依赖：python3, cryptography, dbus-python, PyGObject, bwrap
# 启动（系统总线，需 root）
sudo python3 -m securityd.service
# 测试用会话总线
python3 -m securityd.service --session

# CLI
python3 -m cli.bncli install tests/fixtures/test-security-agent
python3 -m cli.bncli capability list com.bianbu.test-security-agent
python3 -m cli.bncli agent mode com.bianbu.test-security-agent show
python3 -m cli.bncli agent mode com.bianbu.test-security-agent yolo
python3 -m cli.bncli agent mode com.bianbu.test-security-agent normal
python3 -m cli.bncli audit export --agent com.bianbu.test-security-agent
```

## Agent normal / YOLO 安全模式

`normal` 使用每个 tool 的现有 `allow / ask / deny` 策略；`yolo` 将工具判定改为 `allow`，
包含尚未注册和未来新增的工具，不执行 DLP 扫描、网络策略检查/审批/限制，因此不会触发
权限 HITL。模式按 Agent 独立持久化，能力同步不会覆盖它，关闭 YOLO 后原粒度授权
立即恢复。

这是管理员控制面状态，只能经 `GetAgentSecurityMode` / `SetAgentSecurityMode` 或上述
CLI 修改。禁止新增环境变量、prompt、Agent manifest/metadata 等旁路。YOLO 不绕过
caller 绑定校验和 sandbox；审计和网络访问观察继续记录，也不改变 securityd 不可用时的
fail-closed。每次 YOLO 判权的审计 `result` 必须为
`decision=ALLOW;mode=yolo`；模式转换审计必须包含 actor、Agent、old/new mode 和
timestamp。测试或排障临时开启时必须在 `finally` 恢复 `normal`。

## 测试

```bash
export PYTHONPATH=$PWD:$PWD/client
python3 tests/fixtures/make_fixtures.py
python3 -m pytest tests/unit -q               # worker 当前基线 453 passed
python3 -m pytest tests/integration -q        # bwrap/seccomp/dbus（缺依赖自动 skip）
bash tests/smoke_test.sh                       # 私有总线全链路回归
BIANBU_E2E=1 python3 -m pytest tests/e2e -q   # 需真实 securityd
```

## 环境适配说明

- **arch**：seccomp BPF 与 bwrap bind 均按 `platform.machine()` 适配（riscv64 无 `/lib64`）。
- **网络策略**：worker K3 无 iptables/nft → `network_policy` 生成规则产物，运行时隔离
  由 bwrap `--unshare-net` 兜底；有 iptables 且具权限时 `apply_rules` 可直发。
- **密钥库**：无 TEE → cryptography 加密文件（0600），经 CheckPermission 门控。
- **非特权**：整套默认无需 root；`BIANBU_SEC_ROOT` 把 /etc、/run、/var/log 重定向到可写目录。


### YOLO 检查旁路（2026-09-16）

UDS `dlp.scan` 与 Agent DLP hooks 在调用扫描器前旁路；`dlp.policy` 返回 `mode` 和 `scanning_enabled`。DLP 审计写入失败只记录日志，不重新执行扫描或阻断。

有效网络策略为 `allow_all`、空 domains，签名启动策略附带 `observe=true` 以保留被动访问记录。normal 的网络和 DLP 配置保持不变；host 模式切换热更新网络过滤并在失败时恢复原模式，bwrap 实例需由 Runtime 停止后重启。无运行实例时恢复 normal 记录 `pending_launch`，由下次启动执行保存的过滤策略。

Runtime 对经过系统 provisioning 标记确认的 Bibit 专家可以调用正式管理 API 初始化 YOLO，仅限 Security 从未记录模式选择时；普通专家、manifest/metadata、显式 normal/yolo 设置不能触发默认值重置。Security 注册接口本身仍默认 normal。

本次源码验证：YOLO/模式接口/运行引擎相关测试通过；完整测试 727 passed、4 skipped、2 failed。两个失败均为 `tests/unit/test_client_without_dbus.py::test_worker_budget_uses_real_uds_without_importing_dbus`，已在未修改的 `8dad50a` git archive 中独立复现，属于既有 Worker 预算客户端尝试导入 D-Bus 的问题。 K3 真实会话与计量验收，未执行发布。
