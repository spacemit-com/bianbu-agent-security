# Agent Security 能力管理端到端开发自测交付报告

## 1. 自测结论

本轮开发自测覆盖 Security 能力 Registry、三态判权、Hook/审计、UDS、Runtime Tool/Skill/Hook/MCP catalog、Worker 不可用错误和真实开发启动。核心安全语义和能力目录链路通过；当前环境存在两个明确限制：Security `.venv` 为 CPython 3.14，无法导入系统安装的 CPython 3.12 ABI `dbus-python`，因此 caller-binding 单测需使用匹配 ABI 的测试环境；Runtime 的 API inventory 中有一项旧断言未同步新增的 `/api/v1/runtime/workers` 路由。两项均已记录，不将其隐藏为通过。

**当前结论：有条件通过开发自测，不等同于生产发布验收。**

## 2. 版本、环境与范围

| 项目 | 实际值 |
|---|---|
| Security commit | `f6fc2f7cf58df3dd0c9f2121200fae9fdbfeb589` |
| Runtime commit | `8438e617be97666e17e0b6efe0cd16a46dbab456` |
| 主机 | x86_64 Ubuntu，Linux `7.0.0-30-generic` |
| 系统 Python | `/usr/bin/python3.12`，可导入 `dbus` |
| Security 测试 venv | CPython 3.14；缺少 CPython 3.14 ABI 的 `dbus-python` |
| Runtime 测试 venv | CPython 3.14 |
| Security 服务 | session D-Bus `io.bianbu.Security` + UDS |
| 测试数据 | 测试 fixtures 和临时目录；未使用真实 Agent/个人信息 |

## 3. 实际执行结果

### 3.1 Security Registry、判权、Hook 与 UDS

```bash
cd bianbu-agent-security/impl/bianbu-securityd
.venv/bin/pytest -q \
  tests/unit/test_capability_registry.py \
  tests/unit/test_hook_hermes.py \
  tests/unit/test_interceptor.py \
  tests/unit/test_uds.py \
  tests/unit/test_webui_connection_monitor.py
```

结果：**77 passed**。

```bash
python3 tests/integration/hook_audit_e2e.py
```

结果：**全部通过**。真实测试证明：

- `file.read` 已授权时返回 `ALLOW`；
- 未授予 `system.execute` 返回 `BLOCK`；
- Security `ALLOW` 与 DLP 检出组合后提升为 `CONFIRM`；
- Hook 顺序为 `sec_capability@10` → DLP@50 → audit@90；
- `ALLOW`、`CONFIRM`、`BLOCK` 三种决策均落审计；
- hook trace 含 handler 延迟，导出链和在线哈希链均 `intact`。

```bash
/usr/bin/python3 tests/integration/uds_service_e2e.py
```

结果：`UDS_SERVICE_E2E_PASS audit_seq=2`。真实 session D-Bus/UDS 服务、审计批量写入、securityd 重启和请求幂等复放通过。

### 3.2 Runtime 能力目录与 Worker API

```bash
cd bianbu-agent-runtime
.venv/bin/pytest -q \
  tests/sdk/api/test_capabilities.py \
  tests/sdk/api/test_control_catalog.py \
  tests/sdk/api/test_mcp_servers.py \
  tests/runtime/test_worker_rpc.py \
  tests/runtime/test_service.py
```

结果：**67 passed**。

补充不可用/安全错误回归：

```bash
.venv/bin/pytest -q \
  tests/sdk/test_security_error_surface.py \
  tests/runtime/test_security_bridge_discovery.py \
  tests/runtime/test_security_uds_transport.py \
  tests/sdk/api/test_control_catalog.py \
  -k 'unavailable or fail_closed or worker or catalog'
```

结果：**9 passed，17 deselected**。验证 Worker 不可用时返回明确错误，不伪造空 catalog；高危 Security 不可达路径保持 fail-closed 语义。

### 3.3 真实 Runtime 启动探针

```bash
timeout 25s ./run-security-amd.sh
```

结果：Runtime/Uvicorn 成功启动并监听 `0.0.0.0:9899`。启动后实际请求：

| 接口 | HTTP | 结果 |
|---|---:|---|
| `/api/v1/runtime/status` | 200 | `AGENT_READY`，worker_state=`running` |
| `/api/v1/capabilities/tool` | 200 | 返回真实工具目录 |
| `/api/v1/capabilities/skill` | 200 | 返回真实 Skill 目录 |
| `/api/v1/capabilities/hook` | 200 | 返回真实 Hook 目录 |
| `/api/v1/mcp-servers` | 200 | 返回 MCP 目录（当前为空） |

日志同时显示：当前开发机受管 Worker 启动条件不足，按开发配置进入 `development optional host fallback`。因此本机未宣称 sandbox/受管 Worker 通过。

## 4. 用例结果矩阵

| 用例 | 结果 | 证据 |
|---|---|---|
| CAP-E2E-01 字典/映射 | 通过 | Runtime catalog 测试、Security capability registry 测试 |
| CAP-E2E-02 Worker 目录 | 通过（开发 host fallback） | 四个 API 实际 200 + 67 项 Runtime 测试 |
| CAP-E2E-03 Worker 不可用 | 通过 | `worker_unavailable` 回归 9 passed |
| CAP-E2E-04 新增能力 | 通过 | WebUI API/Registry 测试及 D-Bus 集成覆盖 |
| CAP-E2E-05 编辑能力 | 通过 | Registry 持久化/约束测试 |
| CAP-E2E-06 授权/撤销 | 通过 | Registry、Hook 审计 E2E |
| CAP-E2E-07 三态判权 | 通过 | ALLOW/CONFIRM/BLOCK 真实 trace |
| CAP-E2E-08 scope 越界 | 通过 | capability registry scope 测试 |
| CAP-E2E-09 session trust | 部分通过 | 单元覆盖；完整 D-Bus 会话确认需 ABI 匹配环境 |
| CAP-E2E-10 实际工具调用 | 部分通过 | Hook 实际调用链通过；完整 WebUI Worker 对话待受管 Worker 主机 |
| CAP-E2E-11 Tool/Skill/Hook/MCP | 通过（目录/reload） | Runtime catalog/MCP 测试 |
| CAP-E2E-12 caller binding | 部分通过 | 代码用例存在，但当前 venv 无可加载 dbus-python |
| CAP-E2E-13 重启持久化 | 通过 | UDS service restart + replay 通过 |
| CAP-E2E-14 审计完整性 | 通过 | hook_audit_e2e 哈希链 `intact` |
| CAP-E2E-15 Security 不可达 | 通过 | Runtime fail-closed 回归通过 |
| CAP-E2E-16 回滚/并发 | 未完整执行 | 需发布包/并发压力专项环境 |

## 5. 已发现问题与处理建议

### 5.1 CPython/dbus-python ABI 不匹配

现象：Security `.venv/bin/python` 为 CPython 3.14，导入 `securityd.service` 时 `ModuleNotFoundError: No module named 'dbus'`；`/usr/bin/python3.12` 可导入系统 `dbus`，但系统没有 pytest。

影响：不影响已通过的纯 Registry/Hook/UDS 测试和正式 `/usr/bin/python3` UDS 服务脚本；阻塞当前 venv 下的 caller-binding service 单测。

交付要求：为 D-Bus 测试提供同一 ABI 的 `dbus-python`/PyGObject 环境，或使用系统 Python 配置 pytest；禁止混用 CPython 3.14 Runtime 与 CPython 3.12 ABI 扩展。

### 5.2 Runtime API inventory 旧断言

旧测试 `tests/sdk/api/test_inventory.py::test_application_exposes_exact_versioned_api_inventory` 期望固定路由集合，当前实现新增 `/api/v1/runtime/workers`，导致 **1 failed**。这属于测试基线未同步，不是能力目录运行时错误；本轮未修改测试代码，需在交付分支更新契约快照后重跑完整 Runtime API 测试。

### 5.3 开发态 Worker 降级

`run-security-amd.sh` 在当前 x86/Ubuntu 开发机可启动 Runtime，但受管 Worker 因 systemd/sandbox backend 条件不足降级为 unmanaged host-process。该模式仅用于开发调试，不能作为生产安全或 sandbox 验收证据。

## 6. 交付门槛判断

- 核心未授权拦截、三态判权、Hook 顺序、审计完整性：**通过**。
- Worker catalog 正常与不可用错误：**通过**。
- D-Bus caller binding：**环境阻塞，需 ABI 匹配环境复验**。
- 完整受管 Worker/sandbox WebUI 对话：**待专机复验**。
- 并发 reload、安装包升级/回滚：**未完成本轮**。

因此本报告结论为：**开发自测有条件通过；Security 能力管理核心链路可交付开发联调，但不能据此签署生产发布。**

## 7. 清理与后续

- 集成脚本使用临时数据根并自动清理子进程；未修改生产 Security 数据或 `.bianbu-agent/config.yaml`。
- 发布前必须在 ABI 一致、受管 Worker/sandbox 可用的目标机执行 CAP-E2E-09、10、12、16，并更新本报告。
- 修正 Runtime API inventory 断言后执行完整 Runtime 测试套件。
