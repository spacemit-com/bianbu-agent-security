# bianbu-security WebUI 配置台

经浏览器可视化配置 hermes agent（及任意 Agent）的安全策略。**一切经 D-Bus**
（`io.bianbu.Security`），后端不直连 SQLite，符合 AGENTS.md。

## 架构

```
浏览器 (static/*.html+js)
   │ fetch /api/*
Gunicorn gthread（生产：webui/production.py）
或 Flask/Werkzeug（仅开发：webui/app.py）
   │ import bianbu_security_client
   ▼ D-Bus io.bianbu.Security（会话/系统总线）
bianbu-securityd
```

## 启动

```bash
cd impl/bianbu-securityd
PYTHON=/tmp/bnv/bin/python bash webui/run.sh     # 开发调试，默认 127.0.0.1:8787
sudo systemctl start bianbu-security-webui       # 生产：冻结 venv + Gunicorn
```

浏览器打开 `http://127.0.0.1:8787`。远程 worker 可用 SSH 端口转发：
`ssh -L 8787:127.0.0.1:8787 bianbu@10.0.90.243`，再开本机浏览器。

生产 unit 固定使用单 Gunicorn worker + gthread 线程池。单 worker 保证
Flask-SocketIO 的内存态 PTY/会话注册表一致，多线程承载 REST、SSE 和 WebSocket；
`simple-websocket` 提供 threading 模式的 WebSocket 传输。生产不得把
`webui/app.py` 的 Werkzeug 开发启动器直接写入 systemd unit。

## 四大功能

| Tab | 功能 | 对应 D-Bus |
|-----|------|-----------|
| Agent 列表 | 列出所有 agent（能力数/状态）、安装 Agent 包 | ListAgents / InstallPackage |
| 能力管理 | 查看工具策略，allow/ask/deny 三态 | GetAgentInfo / SetCapabilityPolicy |
| 审计日志 | 按 agent 查审计链 + 完整性校验 | ExportAudit / VerifyAuditChain |
| 配额与网络 | Token 上限编辑 + 用量、域名白名单编辑 | Get/SetTokenBudget / Get/SetNetworkPolicy |

## 安全边界

- 默认只监听 `127.0.0.1`。生产必须设置 `BIANBU_WEBUI_TOKEN`（管理员 token）；可选设置
  `BIANBU_WEBUI_VIEWER_TOKEN` 提供只读观察权限。viewer 可以查询 GET API，但所有写 API、确认响应、
  策略变更和 Web Terminal 均返回 403/拒绝。
- 开发/demo DEB 会通过 systemd drop-in 设置 `BIANBU_WEBUI_DEMO=1`，因此不要求管理员
  token，API 与 WebSocket 也不做 Bearer 校验。该开关仅随 demo 包安装，产品包不安装
  drop-in；认证、角色和 CSRF 代码始终保留，产品发布时仍由 `/etc/bianbu/webui.env`
  的 token 强制启用。demo 开关不等于网络放行，非回环监听仍须 TLS（或显式的临时明文
  测试开关）。
- 管理写请求必须同时携带同一会话下发的 `X-CSRF-Token`。监听非回环地址时启动器会强制要求
  `BIANBU_WEBUI_TLS_CERT` 与 `BIANBU_WEBUI_TLS_KEY`；若使用 TLS 反向代理，需显式设置
  `BIANBU_WEBUI_TRUST_PROXY=1`。网络 ACL 和管理员 token 仍是必需条件，不得直接暴露公网。
- 仅用于临时隔离测试的明文远程监听必须显式设置 `BIANBU_WEBUI_ALLOW_INSECURE_REMOTE=1`，
  该配置不允许作为生产 systemd 环境变量。
- 数据根随 securityd（普通用户为 `~/.local/share/bianbu-securityd`）。**勿设 `BIANBU_SEC_ROOT`**，
  否则连到隔离根导致查不到 hermes 的真实数据。

## API 速查

```
GET  /api/agents                                → {agents:[...]}
GET  /api/agents/<id>                           → {agent_id,manifest,capabilities,network,permissions}
POST /api/agents/<id>/capabilities/policy       {tool,policy:allow|ask|deny}
POST /api/install                               {pkg_path} → {ok,agent_id,count,reason}
GET  /api/audit?agent=<id>                       → {records,intact,chain_anchor}
GET/POST /api/agents/<id>/network                {domains,mode}
GET  /api/agents/<id>/permissions                安全权限设置（read/write/network/syscall/custom）
POST /api/agents/<id>/permissions/<group>        {value}
```
