# hermes Agent 接入 AgentSecurityD 完整方案

| 项 | 内容 |
|----|------|
| 文档编号 | BN-SEC-HERMES-001 |
| 版本 | V1.0 |
| 来源 | BN-SEC-SOL-001（安全子系统设计）§7 + impl/bianbu-securityd 实现 + worker 10.0.90.243 实机验证 |
| 日期 | 2026-07-15 |
| 状态 | 已实现并实机验证 |
| 目标读者 | 集成工程师 / 部署 / 安全评审 |

> 本文说明如何把 **hermes agent** 接入 **AgentSecurityD**（`bianbu-securityd`），
> 让 hermes 的每个工具调用都受权限判定、确认门禁、审计与沙箱隔离约束。
> 全部方案**零 hermes 源码改动、不复用 hermes 代码**（遵守 AGENTS.md 复用边界）：
> 插件走 hermes 公开插件 API，沙箱在进程外层包裹。所有结论均在 worker（K3/riscv64）实测。

---

## 1. 总览：纵深防御两层

hermes 接入采用两层协同，可独立启用，生产建议同时开：

| 层 | 机制 | 作用 | 载体 |
|----|------|------|------|
| **① 调用级** | hermes 插件（`pre_tool_call`/`post_tool_call`/`on_session_*` 钩子） | 细粒度：判权、确认门禁、审计、审批仲裁 | `hermes_plugin/bianbu_security/` |
| **② 进程级** | 整进程 bwrap 沙箱 | 兜底隔离：seccomp 拦危险 syscall、cap-drop、文件视图、网络管控 | `hermes_plugin/hermes_sandbox_launch.py` |

**纵深防御含义**：即便某工具绕过 ① 的判权（插件被跳过/映射遗漏），② 的内核级
seccomp 仍兜底拦住危险系统调用。两层都以 securityd 为策略权威（设计 §7.2）。

```
┌────────────────────────────────────────────────────────────┐
│  hermes_sandbox_launch.py  （层② 进程沙箱）                  │
│  bwrap: seccomp + cap-drop + 文件视图 + 网络管控             │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  hermes agent 进程（/usr/bin/hermes chat）            │  │
│  │   每次工具调用 → 插件钩子（层①）                      │  │
│  │     pre_tool_call  → securityd.CheckPermission        │  │
│  │                      /RequestConfirm                  │  │
│  │     post_tool_call → securityd.AuditLog               │  │
│  │   spawn 的工具子进程 → 继承 seccomp（层②兜底）        │  │
│  └──────────────────────────────────────────────────────┘  │
└───────────────────────────┬────────────────────────────────┘
                            │ D-Bus io.bianbu.Security
                            ▼
                    bianbu-securityd（策略权威）
```

---

## 2. 层①：调用级管控（hermes 插件）

### 2.1 插件构成

`hermes_plugin/bianbu_security/` 是标准 hermes 插件：

| 文件 | 作用 |
|------|------|
| `plugin.yaml` | 声明插件名、版本、注册的 hooks |
| `__init__.py` | `register(manager)` 入口 + 三个钩子实现 + 审批仲裁 + CLI 命令 |
| `mapping.py` | 工具名 → securityd 能力 的映射表（可编辑） |

hermes 启动时 `discover_and_load` 扫描 `plugins/`，调用本插件的 `register(manager)`。

### 2.2 钩子接线（均为 hermes 公开 API）

| hermes 钩子 | 插件行为 | securityd 调用 |
|-------------|---------|---------------|
| `pre_tool_call` | 工具执行**前**判权。返回 `{"action":"block","message":...}` 拦截，`None` 放行 | `CheckPermission`；CONFIRM 时 `RequestConfirm` |
| `post_tool_call` | 工具执行**后**写审计链（观察者） | `AuditLog` |
| `on_session_start` | 按审批开关仲裁 hermes 自带 approval | —（设 yolo） |
| `on_session_end` | 会话结束记一条审计 | `AuditLog` |

**pre_tool_call 判权流**（`__init__.py`）：
```
tool_name, args → mapping.resolve() → (capability, scope)
  未映射且 DEFAULT_ALLOW → 放行（不误伤 hermes 只读内部工具）
  CheckPermission(agent_id, capability, scope):
    ALLOW(0)  → 放行（None）
    DENY(2)   → block + AuditLog(deny)
    CONFIRM(1)→ RequestConfirm 阻塞等用户/GUI；批准→放行，拒绝/超时→block
  securityd 不可达 → 按 FAIL_OPEN：默认 fail-closed（block），可配置放行
```

### 2.3 工具→能力映射（`mapping.py`，方案关键点）

hermes 工具名（`write_file`/`terminal`/…）→ securityd 能力（`file.write`/`system.exec`/…），
并从参数就地提取 scope（如 `write_file` 的 `path`，securityd 按目录粒度定 L1/L2）。

| hermes 工具 | securityd 能力 | scope 来源 |
|-------------|---------------|-----------|
| write_file / patch | file.write | path |
| read_file | file.read | path |
| terminal / execute_code | system.exec | command |
| browser / http_request | network.access | url |
| send_email | mail.send | — |
| payment | payment.create | — |

- 未在表中的工具：`DEFAULT_ALLOW=True` 时默认放行（只记审计），避免误伤 hermes
  大量只读内部工具（think、clarify 等）。
- 能力名必须与 Agent manifest 声明一致；映射表可按需扩展。

### 2.4 CLI 命令（若 hermes 版本支持 register_cli_command）

- `hermes securityd-install <pkg>`：验签 + 注册 Agent 能力（安装准备）
- `hermes securityd-audit-export [agent_id]`：导出并校验审计链

---

## 3. 审批仲裁：securityd 门禁与 hermes approval 的关系

hermes 自带一套 approval 系统（危险命令弹窗）。securityd 也有确认门禁。用开关
`BIANBU_SEC_APPROVAL_MODE` 决定二者关系，避免双重确认：

| 值 | 行为 | 场景 |
|----|------|------|
| **`securityd`**（默认，推荐） | securityd 确认门禁**为准**，自动关闭 hermes approval | 生产 |
| `both` | securityd 判权/确认 + hermes approval **叠加**（双确认） | 高安全 |
| `hermes` | 仅 hermes approval；securityd 的 CONFIRM **降级为放行**（只判 DENY + 审计） | 过渡/兼容 |

**关闭 hermes approval 的实现**（`securityd` 模式，经源码核实 hermes 短路条件）：

- **进程级（最可靠，首选）**：`hermes_sandbox_launch` 在启动 hermes 前注入
  `HERMES_YOLO_MODE=1`。hermes 在 import 时冻结此值，全程 approval 短路为 approved。
- **运行时兜底**：插件 `on_session_start` 调 `approval.enable_session_yolo(session_key)`。
- 两者都未生效时，插件日志提示手动 `export HERMES_YOLO_MODE=1`；此时 securityd
  门禁**仍为准**，仅 hermes 侧可能重复弹一次（不影响安全，只影响体验）。

> hermes approval 的三个短路点（`tools/approval.py`）：`HERMES_YOLO_MODE` 环境变量 /
> session yolo / `~/.hermes/config.yaml` 的 `approvals.mode=off`。用启动器时无需手动设。

---

## 4. 层②：进程级 bwrap 沙箱

### 4.1 为何是"整进程"而非"逐工具"

实测 hermes 无"让单个工具调用进沙箱"的插件缝隙：
- `pre_tool_call` 钩子**只认 `action:"block"`**，不能改写参数把命令包成 `bwrap -- <cmd>`；
- `_create_environment` 是硬编码 if/elif（local/docker/ssh/modal…），无 `register_environment`。
  加 bwrap 后端须改 hermes 源码 → 违反 AGENTS.md。

故按设计 §3.7 采用**整进程沙箱**：用 bwrap 启动**整个 hermes 进程**，seccomp/cap-drop/
文件视图随 fork-exec **被 hermes 及其 spawn 的每个工具子进程继承**。worker 实测：沙箱内
父进程 spawn 的子进程执行 reboot 被 seccomp EPERM 拦截（rc=99）。

### 4.2 启动器 `hermes_sandbox_launch.py`

```
BuildSandboxPolicy(agent) → seccomp BPF（本 arch）
  → bwrap 包裹：--unshare-user/pid/ipc/uts + --cap-drop ALL + --seccomp <fd>
              + --die-with-parent + 文件视图 + 网络 + HOME/tty
  → execve hermes 启动命令
```

参数：

| 参数 | 默认 | 说明 |
|------|------|------|
| `--agent <id>` | `com.hermes.agent` | securityd 侧 Agent id（判权/审计主键） |
| `--rw-dir <dir>` | `AGENTS_HOME/<id>/rw` | Agent 私有可写目录 |
| `--hermes-config <dir>` | `~/.hermes` | hermes 配置/凭据/会话目录，可写绑定进沙箱 |
| `--net` / `--no-net` | `--net`（开） | 联网（共享宿主网络+DNS+CA）/ 禁网（空网络命名空间） |
| `--batch` | 关（默认交互） | 批处理捕获输出；默认交互继承 tty（供 hermes chat TUI） |

### 4.3 沙箱文件/环境适配（实机踩坑与解法）

沙箱默认只 ro-bind `/usr`，运行真实 hermes 需补齐若干宿主资源（均已在启动器实现）：

| 需求 | 现象（未处理时） | 解法 |
|------|----------------|------|
| hermes 配置/凭据 | 读不到 auth.json/model 配置 | 可写绑定 `~/.hermes` 到原路径，HOME 指向其父 |
| 用户名解析 | `id: cannot find name for user/group ID` | 合成最小 `/etc/passwd`+`/etc/group` 覆盖进沙箱 |
| DNS 解析 | `Could not resolve host` | 绑 `/etc/resolv.conf`（解析符号链接真实目标）、`/etc/hosts`、`nsswitch.conf` |
| TLS 证书 | `error adding trust anchors` | ro-bind `/etc/ssl` 等 CA 目录 |
| 交互 TUI | `hermes chat` 启动横幅后卡死 | interactive 模式：继承父进程 tty，不捕获 IO |

**文件持久化边界（重要）**：沙箱内 HOME=`/home/<user>`，但真正绑到宿主机的只有
`/home/agent`（Agent 私有 rw）和 `~/.hermes`。hermes 写到 HOME 根目录（如
`/home/<user>/x.txt`）落在沙箱 tmpfs，**退出即丢**；只有写到 `~/.hermes/` 或
Agent rw 目录才持久化到宿主机。需要产物留存时应把工作目录指向持久绑定目录。

### 4.4 网络策略与 SEC-07 边界

- `--net`（默认）：共享宿主网络栈 + 绑 DNS/CA，hermes 可调模型 API。
- `--no-net`：空网络命名空间（仅 loopback），最强隔离。
- **SEC-07 域名白名单的现实边界**：worker 无 iptables/nft，白名单无法在该机**强制**
  （securityd 仅生成规则产物）。因此当前联网模式是"共享宿主网络，全通或全断"。
  域名级白名单强制需在具备 netfilter 的目标环境启用（设计 §3.5 / §11 已注明）。

---

## 5. 部署步骤

### 5.1 部署插件（软链，不改 hermes 目录内容）

```bash
export BIANBU_SECURITYD_HOME=<...>/impl/bianbu-securityd
ln -s $BIANBU_SECURITYD_HOME/hermes_plugin/bianbu_security \
      ~/aiws/hermes-agent/plugins/bianbu-security      # 若 hermes 支持 plugins/ 目录
# hermes 启动即 discover_and_load
```

### 5.2 安装 Agent（验签 + 能力注册）

```bash
# 经 bncli（本地直调）或插件 CLI
python3 cli/bncli.py install <agent_pkg>
# 或 securityd 运行后经 hermes securityd-install <pkg>
```

### 5.3 在沙箱内启动 hermes

```bash
export BIANBU_SECURITYD_HOME=<...>/impl/bianbu-securityd
python3 hermes_plugin/hermes_sandbox_launch.py \
  --agent com.hermes.agent -- /usr/bin/hermes chat
# 默认：securityd 门禁为准（关 hermes approval）、联网开、交互 tty
```

环境变量总览：

| 变量 | 默认 | 作用 |
|------|------|------|
| `BIANBU_HERMES_AGENT_ID` | `com.hermes.agent` | 会话对应的 securityd Agent id |
| `BIANBU_SEC_APPROVAL_MODE` | `securityd` | 审批仲裁三态（§3） |
| `BIANBU_SECURITY_FAIL_OPEN` | `0` | securityd 不可达时：0 拦截 / 1 放行 |
| `BIANBU_SEC_SESSION` | 未设=系统总线 | `1`=会话总线（测试） |
| `BIANBU_SECURITYD_HOME` | — | 指向实现根，供插件/启动器 import |

---

## 6. 验证

### 6.1 自动化测试

| 测试 | 覆盖 | 运行 |
|------|------|------|
| `tests/unit/test_approval_mode.py` | 审批开关三态 × DENY/ALLOW/CONFIRM（9 项） | `pytest tests/unit` |
| `tests/integration/hermes_plugin_demo.py` | 插件钩子分发：放行/DENY 拦/确认门禁/审计（6 项） | 见下 |
| `tests/integration/hermes_confirm_demo.py` | 确认门禁全路径：批准/拒绝/L4 二次确认 | 见下 |
| `tests/integration/test_hermes_sandbox.py` | 进程沙箱：子进程 syscall 被 seccomp 拦截 | `pytest tests/integration` |
| `tests/e2e/test_hermes_plugin.py` / `_confirm.py` / `_integration.py` | 真实 D-Bus 端到端 | 见下 |

```bash
export PYTHONPATH=$PWD:$PWD/client:$PWD/hermes_plugin BIANBU_SECURITYD_HOME=$PWD
python3 tests/fixtures/make_fixtures.py
python3 -m pytest tests/unit tests/integration -q          # 40 passed（worker）
BIANBU_E2E=1 BIANBU_SEC_SESSION=1 dbus-run-session -- \
  python3 -m pytest tests/e2e -q                            # 3 passed
bash tests/smoke_test.sh                                    # 6 阶段 ALL PASS
```

### 6.2 已验证基线（worker K3, riscv64, Py3.14）

- 插件调用级 demo：6/6（未映射放行 / L1 直放 / 未注册 DENY 拦 / 确认批准放行 / 拒绝拦 / 审计链完整）
- 确认门禁 demo：4/4（L3 批准→放行 / L3 拒绝→拦 / L4 双确认→放行 / L4 首肯次否→拦）
- 进程沙箱：子进程 reboot 被 seccomp EPERM 拦截（rc=99）
- 真实 hermes：`/usr/bin/hermes chat` 在沙箱内进入 agent 循环，配置读入、approval 关闭、
  联网可调 MiniMax API（HTTPS HTTP 301 连通）、id 解析干净
- 全回归：unit+integration 40 passed，e2e 3 passed，smoke 6 阶段 ALL PASS

---

## 7. 追溯矩阵

| 需求 | 接入实现 | 验证 |
|------|---------|------|
| FR-SEC-01/02（判权） | 插件 pre_tool_call → CheckPermission | plugin_demo 步骤 2/3 |
| FR-SEC-03（确认门禁） | pre_tool_call → RequestConfirm + RespondConfirm 回路 | confirm_demo 全路径 |
| FR-SEC-04（Token 配额） | 待接：post_tool_call/独立计量（hermes 无 post_llm_call 触发点） | — [后续] |
| FR-SEC-05/SBX-04（syscall 拦截） | 层② 整进程 sandbox，seccomp 继承 | test_hermes_sandbox |
| FR-SEC-06（审计） | post_tool_call → AuditLog；哈希链导出/验证 | plugin_demo 审计步 |
| FR-SEC-07/SBX-03（网络） | 层② `--net/--no-net`；白名单强制待 netfilter 环境 | curl 连通性实测 |
| FR-SBX-01/05（文件/cap） | 层② bwrap 文件视图 + cap-drop ALL | test_sandbox_manager |
| 审批仲裁 | BIANBU_SEC_APPROVAL_MODE 三态 | test_approval_mode |

---

## 8. 已知边界与后续

- **Token 配额（FR-SEC-04）接入**：hermes `post_llm_call` 钩子在 VALID_HOOKS 声明但无
  触发点；需改走 `post_tool_call` 读工具结果 usage，或从 hermes 计量侧另接。
- **域名白名单强制（SEC-07）**：worker 无 netfilter，仅生成规则产物；目标环境具备
  iptables/nft 时启用强制。
- **once_per_session 缓存复用**：D-Bus 的 CheckPermission/RequestConfirm 签名未带
  session_id，跨调用的会话信任缓存复用暂无法经 D-Bus 回环（引擎逻辑本身有单测覆盖）。
- **产物持久化**：需要 hermes 产出文件留存时，把工作目录指向持久绑定目录（§4.3）。

---
*BN-SEC-HERMES-001 V1.0 · 基于 impl/bianbu-securityd 实现 + worker 10.0.90.243 实测。*
