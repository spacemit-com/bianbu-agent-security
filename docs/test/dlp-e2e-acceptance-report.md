# DLP 端到端验收报告

## 结论

Security 的 DLP 控制面、UDS 数据面、审计链和 Runtime Hook 语义已通过隔离环境验收。`allow`、`audit_only`、`mask`、`block` 四种动作均得到预期结果；非法参数被拒绝，策略删除后能回退到默认策略。securityd 不可达时的 fail-closed 由现有 Security/Runtime 回归测试确认。

完整 WebUI 对话链路未作为本轮通过条件：在当前 x86/Ubuntu 开发机执行 `run-security-amd.sh` 时，受管 Worker 依赖的 systemd/security runtime 环境不可用，Runtime 按开发配置降级为 unmanaged host-process。因此本报告不把该降级误记为沙箱 Worker 验收通过。

## 环境

| 项目 | 值 |
|---|---|
| Security HEAD | `a52c5631ad7a3aa27961a0c4b53a45078e1ac069` |
| Runtime HEAD | `8438e617be97666e17e0b6efe0cd16a46dbab456` |
| 时间 | `2026-09-04T19:44:38+05:00` |
| 主机 | x86_64 Ubuntu，Linux `7.0.0-30-generic` |
| Python | 3.12.3（Security D-Bus 服务使用 `/usr/bin/python3.12`） |
| Security 传输 | session D-Bus 控制面 + Security UDS 数据面 |
| 测试数据 | 临时 `BIANBU_SEC_ROOT`，仅使用合成手机号 `13812345678` 等值 |

## 执行命令与结果

```text
cd bianbu-agent-security/impl/bianbu-securityd
.venv/bin/pytest -q tests/unit/test_dlp_*.py       → 130 passed
python3 tests/integration/dlp_e2e.py                → 全部通过
/usr/bin/python3 tests/integration/uds_service_e2e.py → UDS_SERVICE_E2E_PASS audit_seq=2
python3 tests/integration/pii_benchmark.py          → 召回 99.75%，误报 0.75%，性能指标通过

cd bianbu-agent-runtime
.venv/bin/pytest -q tests/runtime/test_security_api.py \
  tests/runtime/test_security_runtime.py \
  tests/runtime/test_security_skill_dlp.py           → 21 passed
```

fail-closed 回归用例：Security `test_hook_hermes.py`/`test_uds.py` 相关用例 2 passed；Runtime 不可达 DLP 用例 1 passed。

PII 检测基准覆盖 8 类、1600 条正样本和 400 条负样本：总体召回率 99.75%（要求 ≥95%），误报率 0.75%（要求 ≤3%），单条平均扫描 0.022ms；脱敏可逆性和校验位误报防护均通过。

Runtime 启动探针：`timeout 25s ./run-security-amd.sh` 成功完成应用启动（Uvicorn 监听 9899），日志显示受管 Worker 启动失败后进入 `development optional host fallback`。这是当前开发机缺少受管 systemd Worker 运行条件的已知边界。

## 四种核心动作

| 动作 | UDS finding | Runtime Hook | 原文进入下游 | 审计证据 | 结果 |
|---|---|---|---|---|---|
| `allow` | `allow` | `ALLOW` | 是 | scan 产生 `audit_seq` | 通过 |
| `audit_only` | `audit_only` | `ALLOW` | 是 | DLP 审计新增 | 通过 |
| `mask` | `mask` | `MODIFY` | 否 | mask 干预审计 | 通过 |
| `block` | `block` | `BLOCK` | 否 | block 决策审计 | 通过 |

UDS `dlp.scan` 的 `masked_text` 是安全展示字段，四种动作都可能返回占位符；不能用它单独判断 `allow` 是否放行原文。最终语义以 Runtime Hook 的 `Decision` 和实际下游 payload 为准。

## 覆盖内容

- manifest 策略加载、Agent 默认、全局默认和系统兜底；
- `INPUT`/DLP handler trace，以及本地模型和云端高风险强制脱敏；
- 混合 PII 的最严动作（`block > mask > audit_only > allow`）；
- mask session 映射创建与清零；
- 策略实时修改，下一次调用立即生效；
- D-Bus/UDS 重启后审计请求幂等复放；本次复放保持同一 `audit_seq`，数据库请求/记录各 1 条；
- 非法 action、未知 PII 类型、空 Agent ID 均被拒绝，未写入伪成功策略；
- 删除 `phone=allow` 后，`dlp.policy` 恢复为 `audit_only`。

## 未完成或需专机复验

1. 在具备完整 systemd 受管 Worker、固定 entrypoint 和 sandbox backend 的目标机上，通过 WebUI 新建 Agent，分别选择 HOST 与 sandbox 完成真实对话验收。
2. 在隔离测试 Agent 上停止并恢复 securityd，执行一次真实 Runtime 高风险输入/工具外发请求，保存 fail-closed 日志和恢复后的重连证据。本轮使用已有不可达回归测试，未停止当前开发机共享的 securityd。
3. 不应把 `development optional host fallback` 用于生产；生产应要求受管 Worker 和 Security 服务都可用，失败即拒绝启动或 fail-closed。

## 清理与安全边界

所有集成脚本使用临时数据根，并在 `finally` 中终止 securityd 子进程；未修改用户 `.bianbu-agent/config.yaml`、生产策略或真实个人信息。报告只保留合成数据和摘要。
