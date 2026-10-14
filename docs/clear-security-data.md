# 重置 Security 运行数据

`impl/bianbu-securityd/deploy/clear-security-data.sh` 将 Security 自有数据恢复到首次初始化前的状态。
默认只预览，必须提供 `--yes` 才会停止服务并永久删除数据。**不会自动备份，也不会自动重启服务。**
清理前自行保存需要保留的策略、审计和 Vault 内容；重置后旧密钥无法恢复。

```bash
# 已安装的 deb
sudo bianbu-agentic-security-reset --dry-run
sudo bianbu-agentic-security-reset --yes
```

deb 将 `/usr/sbin/bianbu-agentic-security-reset` 链接到已安装的 `clear-security-data.sh`，
由包管理器负责安装、升级和卸载。若当前 PATH 未包含 `/usr/sbin`，可使用完整命令路径；
原 `/usr/lib/bianbu-securityd/deploy/clear-security-data.sh` 路径仍可使用。

`--dry-run` 优先于 `--yes`。旧参数 `--no-backup` 保留兼容，行为与默认一致。
清理仅需系统 Python 标准库，不依赖被重置的数据库或 Security Python 环境。

清理也会删除 `com.bianbu.runtime` 安装包登记的固定 entrypoint。配套 Runtime 必须包含
启动前 `register-security-manifest.py --if-missing` 恢复检查；只更新本脚本而保留旧 Runtime，
可能导致 Agent 重新注册后仍无法启动。旧 Runtime 在启动前需手工重新登记已安装清单：

```bash
sudo systemctl start bianbu-securityd.service
sudo /usr/bin/python3.14 -I /usr/lib/bianbu-agent-runtime/register-security-manifest.py \
  /usr/share/bianbu-agent-runtime/security-manifest/com.bianbu.runtime \
  --expected-agent-id com.bianbu.runtime
```

## 清理范围

- `/etc/bianbu` 下的 capabilities、token_budget、dlp_policy、runtime-leases、syscall_policy 数据库及 SQLite WAL/SHM/journal 文件。
- `keys/` 内的 Vault 主密钥和 Agent 密文；旧 `security-agent-prune-*` 备份目录。
- `/var/log/bianbu/audit/` 中全部审计链、系统调用拦截记录、网络学习记录、导出及旁文件；旧 `security-clear-backups/` 内容。
- `/run/bianbu` 下 Security UDS、sandbox、syscall-audit、network-learning 和旧网络采集 socket。
- `/run/bianbu-syscall-audit/` 内观察器事件、轮转日志和状态。
- `/var/lib/bianbu/agents/` 的 Security 沙箱私有数据；参考 SDK Runtime 的 `/var/lib/bianbu/runtime/` 数据。
- 当前调用环境指定的开发启动日志和 PID 文件：`$XDG_RUNTIME_DIR/bianbu-security-dev`（默认 `/tmp/bianbu-security-dev`），以及 `$SECD_LOG_DIR`（默认 `/var/tmp/bnsec-logs`）中的已知 Security 日志、轮转文件和启动脚本。

专用目录本身保留 inode、属主和权限，避免重建为 root 所有后，`bianbu-security` 账号无法写入。
安装代码、venv、systemd/D-Bus 配置、`codesign-keys/` 信任公钥、`webui.env` 管理配置保留。
Runtime 用户目录默认保留；交互执行时可单独确认删除（见下节）。其他服务 socket/日志不在清理范围内。

系统共享 journal、系统审计日志、外部备份、其他用户自行指定的日志路径和复制出去的文件不删除；
这不是磁盘取证意义的安全擦除。不会调用全局 journal vacuum 或 flush 主机防火墙。

## 可选删除 Runtime 用户目录

执行 `sudo bianbu-agentic-security-reset --yes` 时，如果检测到 Runtime 用户的 `.bianbu-agent`，
会逐个显示完整路径并提示：

```text
可选删除 Runtime 用户目录: /home/bianbu/.bianbu-agent
删除该目录会清除 Bianbu Agent Runtime 的所有用户配置信息、Agent 数据和聊天历史，无法恢复。
是否删除 /home/bianbu/.bianbu-agent？输入 yes 确认，直接回车保留:
```

- 只有输入 `yes` 才删除；回车或其他回答均保留。`--yes` 只确认 Security 重置，不替代这次确认。
- 非交互调用不等待输入，自动保留用户目录；`--dry-run` 仅显示候选目录，不提示确认、不删除。
- 根据 Runtime systemd 实例用户和安装记录查询系统账号的 home，不直接使用 sudo 后的 `$HOME`；无记录时使用非 root 的 `SUDO_USER`。多个用户分别确认。
- 确认在停止服务前完成，实际删除在相关服务停止并通过路径检查之后；发现非托管 Runtime 进程仍运行则拒绝删除。
- 拒绝目录符号链接和嵌套挂载点。仅删除选定的 `.bianbu-agent`，不删除整个 home。
- `--root` 隔离模式不查找或删除宿主机用户目录。

选择删除后，下次 Runtime 启动会重新生成默认用户配置；被删除的聊天历史和用户配置不会恢复。
系统安装目录中的默认 Agent 定义不属于该用户目录的删除范围。

## 停止和重新运行

系统模式先发现相关 Security、WebUI、Runtime、adapter、采集器和生成的 Worker unit，
对持久化服务临时 mask 并确认生效，然后停止；瞬态 Worker 随启动器停止后清除，并再次检查停止期间新建的 Worker。清理结束或出错均撤销本次新增的 mask，保留原有启用/屏蔽设置。
隔离模式中匹配同一数据根的独立 Python daemon 使用 pidfd 停止；生产模式发现非托管 daemon 时要求先停止其启动器，避免进程自动重启。无法停止则退出并保留数据。

如本地 `/etc/systemd/system` unit 覆盖导致运行期 mask 无效，脚本写入临时运行期 drop-in，
通过 `ConditionPathExists` 阻止重新激活，并用 systemd D-Bus 属性确认条件生效；结束后移除。
原有 unit 文件不修改。如果 mask 和临时条件都不能生效，则报错，不进行删除。旧式 iptables 模式写入过无归属标记的共享 OUTPUT
规则，必须先人工撤销对应规则并核对记录；脚本遇到该状态会保留数据并退出。
支持移除 Security 专用 nft `inet bianbu_security` 表，以及由沙箱目录确认归属的旧式 cgroup。
当前 systemd IPAddress 策略随 Worker unit 停止而释放。

清理成功后按安装的服务启动，例如：

```bash
sudo systemctl start bianbu-securityd.service
sudo systemctl start bianbu-syscall-observer.service bianbu-agent-network-learning.service
sudo systemctl start bianbu-security-webui.service
sudo systemctl start bianbu-agent-runtime@bianbu.service
# 若使用 adapter 或参考 SDK runtimed，再启动相应 unit
```

Security 会重新创建数据库、默认状态和 Vault 密钥。旧注册、授权、预算、策略、租约与审计不恢复；
Runtime 需要重新注册 Agent，旧 Worker 必须重启后取得新租约。

## 开发和隔离验证

非 root 默认匹配 Security 的 XDG 数据目录；支持 `BIANBU_ETC/RUN/LOG`、
`BIANBU_AGENTS_HOME` 和 `BIANBU_SEC_UDS` 覆盖。清理时必须使用与服务相同的路径设置。
已安装系统服务请用 `sudo`，不要用普通用户模式冒充系统重置。

```bash
# 隔离目录：不操作宿主 systemd 或内核规则
export BIANBU_SEC_ROOT=/tmp/my-security-test
export BIANBU_AGENTS_HOME="$BIANBU_SEC_ROOT/var/lib/bianbu/agents"
export BIANBU_SEC_UDS="$BIANBU_SEC_ROOT/run/bianbu/securityd.sock"
./impl/bianbu-securityd/deploy/clear-security-data.sh --root "$BIANBU_SEC_ROOT" --yes
```

`--root` 将系统路径映射到该根下，默认 Agent 数据位置为根内 `var/lib/bianbu/agents`。
**daemon 自身的 `BIANBU_SEC_ROOT` 不会改写 AGENTS_HOME，启动测试 daemon 时也必须显式设置上面的变量。**
若发现运行中 daemon 的 Agent 路径不匹配，或显式路径越过隔离根，脚本拒绝清理。
脚本拒绝危险根目录、清理根/祖先符号链接和嵌套挂载点；数据内普通符号链接只解除链接，不跟随删除。

此前“按 Runtime 专家清单注销旧 Agent”的功能仍在独立工具中：

```bash
python3 impl/bianbu-securityd/deploy/prune-security-agents.py --help
```

## 验证记录（2026-09-11）

- 单元/集成回归覆盖默认预览、重复执行、目录权限保留、符号链接边界、隔离路径、停止失败、无效 mask、实际 PID 停止和专用 nft 清理。
- 本地真实 SecurityEngine：初始化并注册/写审计 → 清理 → 再初始化、重新注册、审计链校验成功，生成不同的新 Vault 主密钥。
- worker `10.0.90.243`：独立 session D-Bus 上真实 securityd 启动 → 脚本停止并清理 → 新进程再次取得 D-Bus 名称、建立 UDS、生成新密钥。
- 243 上创建独立 `/etc/systemd/system` 测试 unit：确认运行期 mask 被覆盖，临时条件阻止启动，撤销条件后成功启动；随后移除测试 unit。
- 隔离验证后，经用户授权在 243 执行真实清理：确认数据库和专用状态目录为空，随后成功重新初始化。
- 实机验证发现旧 Runtime 缺少安装包清单恢复流程；配套补上启动检查后，BibitEdgeAssistant 达到 AGENT_READY，Worker 为 running，error=null。

最终回归：243 隔离副本中清理、旧 Agent 注销、安装流程及安装回滚共 **43 项通过**；安装资源检查通过。

新增可选 Runtime 用户目录删除后，243 隔离回归共 **51 项通过**，包含真实 PTY 确认流程；只读核对 sudo 下目标为 `/home/bianbu/.bianbu-agent`。


### 243 真实删除与首次启动验收

随后经用户明确授权执行真实测试：在 PTY 中看到完整目录和配置/聊天历史删除提示后输入 `yes`。
脚本退出码为 0；停止期间确认 `/home/bianbu/.bianbu-agent` 不存在，Security 数据库、审计与 Vault 为空，
`/home/bianbu` 和信任公钥仍存在。

重新启动后，Runtime 自动登记 `com.bianbu.runtime` 清单（22 条能力），重新生成用户目录和 config.yaml，
属主 UID 为 1000。默认 BibitEdgeAssistant Worker 为 running、host，error=null；Runtime 为 AGENT_READY。
七个相关服务全部 active。旧用户配置和聊天历史没有恢复。

已在 243 安装同版本脚本及 `/usr/sbin/bianbu-agentic-security-reset` 入口，并验证 `--help` 可执行。
这是实机热更新；新 deb 仍需通过后续打包发布交付。
