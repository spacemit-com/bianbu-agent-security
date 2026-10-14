# 测试服务实现方案与操作指南

| 项 | 值 |
|----|-----|
| 文档编号 | BN-SEC-TESTKIT-GUIDE-001 |
| WebUI 地址 | `http://10.0.90.243:9700` |
| 代码位置（仓库） | `agent-os-security-design-dev/testkit/` |
| 部署位置（worker） | `/home/bianbu/bnsec-testkit/` |
| 输出目录 | `/var/tmp/bnsec-testrun/` |
| 日志目录 | `/var/tmp/bnsec-logs/` |
| 测试项 | 24 项，7 大类 |

> **不要用 `/tmp`。** worker 的 `/tmp` 是 tmpfs（重启即失），且
> systemd-tmpfiles 配了 `q /tmp … 10d` 清理 10 天前的文件。早期版本把脚本
> 和产物放在 `/tmp`，重启后全丢 —— 现在一律用 `$HOME` 与 `/var/tmp`。

---

## 第一部分：实现方案

### 1.1 为什么这样设计

**不用 pytest 而自建引擎**，三个原因：

1. 断言目标是**跨进程的外部事实** —— securityd 的审计库、D-Bus 返回值、PA 的 HTTP 响应。pytest 的 fixture 模型对"按 seq 圈定某次操作产生的审计增量"这类需求不顺手。
2. 需要**实时事件流**驱动 WebUI。pytest 的插件钩子能做，但要额外写 plugin，不如直接发 JSONL。
3. 测试产物要含**日志 + 审计增量 + 断言明细**三类结构化数据，pytest 的报告格式需要大量定制。

**零依赖 WebUI**（只用标准库 `http.server`）：worker 是 riscv64，装 Flask/FastAPI 要拉一串轮子，而这个 UI 只需要 4 个接口 + 一个静态页面。

### 1.2 四个文件的分工

```
engine.py      测试引擎 —— Ctx（能力）+ Result（结果）+ Emitter（事件）+ run_all（调度）
tests_all.py   24 个测试项定义，靠 @test 装饰器注册到 engine.TESTS
runner.py      命令行入口
webui.py       HTTP 服务 —— 4 个 API + 内嵌单页前端
```

**为什么 runner.py 必须独立存在**（这是个踩过的坑）：

直接 `python3 engine.py` 会跑出「总计 0」。原因是 `engine.py` 作为 `__main__` 运行时，`tests_all` 里的 `from engine import ...` 会**再次导入** engine 并创建第二个模块实例。`@test` 装饰器注册到第二个实例的 `TESTS`，而 `__main__` 里的 `run_all` 读的是第一个实例的空列表。

`runner.py` 让 `engine` 与 `tests_all` 都作为普通模块导入，共用同一实例。

### 1.3 后端：数据流

```
POST /api/run
  └─ subprocess.Popen([python3, runner.py])      # 后台进程，不阻塞 HTTP
       └─ runner.main()
            └─ engine.run_all()
                 ├─ Emitter.emit("start", ...)   ─┐
                 ├─ 逐项执行:                      │ 追加写
                 │    emit("test_start", ...)      ├→ $BNSEC_OUT/events.jsonl
                 │    fn(ctx) → list[Step]         │
                 │    emit("test_end", ...)       ─┘
                 └─ write_report()               ──→ $BNSEC_OUT/report.json
                    emit("done", ...)

GET /api/events?offset=N
  └─ 读 events.jsonl 的第 N 行往后 → {events: [...], offset: 新行数, done: bool}

GET /api/report
  └─ 原样返回 report.json
```

**关键设计：事件流用「行偏移」而非时间戳增量。**

前端记住 `offset`（已消费的行数），每次带上它请求。后端 `lines[off:]` 切片返回新增部分并回传新 `offset`。这样：
- 无状态，后端不需要为每个客户端维护游标
- 断线重连后从 `offset=0` 拉一次就能重建完整状态
- 多个浏览器标签各自独立，互不干扰

**`done` 的判定**（`webui.py:277`）：

```python
self._json({"events": ev, "offset": off, "done": done or not alive})
```

两个条件取或：
- `done` —— 事件流里出现了 `kind == "done"`（正常完成）
- `not alive` —— 子进程已退出（`_proc.poll() is not None`）

第二个条件是兜底：如果 runner 崩了、没来得及发 `done`，前端不会永远转圈。

**并发控制**（`webui.py:289-302`）：`_lock` 保护 `_proc`，已有测试在跑时 `POST /api/run` 返回 409，避免两轮测试同时写同一个 `events.jsonl`。

### 1.4 前端：单页 + 轮询

内嵌在 `webui.py` 的 `PAGE` 常量里（`r"""..."""` 原始字符串），无构建步骤、无外部资源。

**状态机**：

```js
let off=0,     // 已消费的事件行数
    T={},      // {测试ID: {status, steps, duration_ms, message, ...}}
    order=[],  // 测试ID 顺序（保持声明顺序，不按完成顺序跳动）
    sel=null,  // 当前选中的测试ID
    filt="all";// 当前分类筛选
```

**轮询循环**（900ms）：

```js
poll() → fetch(/api/events?offset=off)
       → 对每个事件调 apply(e) 更新 T
       → render() 重绘左栏
       → 若 done 则 clearInterval
```

`apply()` 按事件类型更新状态（`webui.py:141-153`）：
- `start` → 用 `tests` 列表初始化全部 24 项为 `pending`，填 `order`
- `test_start` → 该项转 `running`
- `test_end` → 写入 `status` / `duration_ms` / `message` / `steps`
- `done` → 显示总耗时

**为什么先发 `start` 事件带全量清单**：这样一开始就能把 24 项全部渲染为灰色 `pending`，用户看到的是"进度条"而不是"逐条冒出来"。

**详情面板**（`detail()`，`webui.py:192-227`）：

断言明细来自内存里的 `T[id].steps`（`test_end` 事件已带上），**立即可见**。
执行日志与审计增量来自 `GET /api/report`，只在 `report.json` 生成后才有 —— 所以测试进行中点某项只能看到断言，跑完后再点才有完整日志。这是有意的取舍：把日志塞进事件流会让 `events.jsonl` 膨胀好几倍，而日志的价值主要在事后复盘。

**页面刷新后的恢复**（`webui.py:231-234`）：

```js
fetch("/api/status").then(j => {
  if (j.running) { /* 继续轮询 */ }
  else if (j.has_report) { poll(); /* 拉一次，显示上轮结果 */ }
});
```

### 1.5 测试引擎：Ctx 提供的能力

每个测试项签名是 `fn(ctx: Ctx) -> list[Step]`。`Ctx` 封装了 6 类能力：

| 方法 | 用途 | 要点 |
|------|------|------|
| `http(method, path, body)` | 调 PA 的 HTTP API | 自动记日志，HTTPError 不抛而是返回 `(code, body)` |
| `dbus()` | 取 securityd 的 D-Bus 接口 | **两条总线都试**，见下 |
| `check_permission(cap, scope)` | 判权快捷方式 | 返回 `"ALLOW"`/`"CONFIRM"`/`"DENY"` |
| `audit_seq()` / `audit_since(seq)` | 审计差分 | 直接读 SQLite（只读模式） |
| `run_prompt(prompt)` | 发一次完整 run 并轮询到终态 | 自动生成 `session_id`/`idempotency_key` |
| `shell(cmd)` | 跑本地命令 | 沙箱测试用 |
| `log(msg)` | 记日志 | 带时间戳，进 `report.json` |

**D-Bus 总线自适配**（`engine.py:101-133`）是必要的：

securityd 起在哪条总线取决于部署方式 —— 装了 `/etc/dbus-1/system.d/io.bianbu.Security.conf` 且用户在 `bianbu-security` 组则用系统总线，否则只能会话总线（`BIANBU_SEC_SESSION=1`）。写死 `SessionBus()` 时，部署形态一变就让 8 项测试全错。现在两条都试，且**真调一次 `CheckPermission`** 确认可用（光 `get_object` 不会报错）。

### 1.6 审计差分：证明"调用真的到达了 securityd"

这是整套测试最有价值的设计。

只验函数返回值会漏掉集成层断裂。举个实际发生的例子：`before_tool` hook 每次都执行（插桩证实），但因能力映射返回 `None` 落到 `DEFAULT_ALLOW` 直接放行，**从未调用 securityd**。单元测试测 hook 函数会通过，测 `resolve_capability` 也会通过，但合起来判权是失效的。

审计差分能抓住它：

```python
seq0 = ctx.audit_seq()              # 操作前的最大 seq
d = ctx.run_prompt("...用 memory 工具...")
delta = ctx.audit_since(seq0)       # 这次操作产生的审计记录
checks = [r for r in delta if r["op_type"] == "check_permission"]
assert len(checks) > 0              # 没有 → 判权没发生
```

`report.json` 里每项都带 `audit_delta`，WebUI 详情面板直接以表格展示。

### 1.7 测试项清单

| 类别 | ID | 验什么 |
|------|-----|--------|
| connectivity | CONN-01 | PA HTTP 可达 |
| | CONN-02 | securityd 占名且 `CheckPermission` 可调 |
| | CONN-03 | 25 个关键 D-Bus 方法全部导出 |
| permission | PERM-01 | `RegisterCapabilities` 生效且可查 |
| | PERM-02 | 判权三态 + 未注册→DENY 的 fail-closed |
| | PERM-03 | L3/L4 禁止 `confirm=trusted`（PRD §5.1.3） |
| | PERM-04 | 撤销后不再 ALLOW |
| | YOLO-01 | YOLO 放行撤销/未知能力并审计，关闭后恢复 DENY |
| hook | HOOK-01 | 8 个 hook 加载且 `enabled=True` |
| | HOOK-02 | 纯对话 run 可完成（hook 不阻断） |
| | **HOOK-03** | **工具调用必须在审计留下 `check_permission`** |
| | HOOK-04 | MCP 工具一律进判权，不落 `DEFAULT_ALLOW` |
| dlp | DLP-01 | 8 类 PII 全部可检出 |
| | DLP-02 | 非法身份证/卡号不误报 |
| | DLP-03 | 逐字泄露双信号（追加字符规避仍检出） |
| token | TOKEN-01 | Token 预算可读 |
| | **TOKEN-02** | **真实 LLM 调用后 `day_used` 应增长** |
| sandbox | SBX-01 | bwrap 可用，argv 含隔离标志 |
| | SBX-02 | 沙箱内可执行且 PID 重编号 |
| | SBX-03 | `net=false` 断网、`net=true` 可达 |
| | SBX-04 | 参数与**返回值**不可序列化都须显式拒绝 |
| | SBX-05 | `net=true` 时沙箱内 DNS 可解析 |
| audit | AUDIT-01 | 审计写入且含 result |
| | AUDIT-02 | 哈希链连续（防篡改） |
| | AUDIT-03 | `ExportAudit` 导出非空 |

HOOK-03 与 TOKEN-02 是**决定性测试** —— 它们各自抓出过一个真缺陷，改完才转绿。

### 1.8 沙箱模块的隔离加载

worker 上两个 Python 环境依赖互补但都不完整：

| 环境 | 版本 | `dbus` | `jsonschema` |
|------|------|--------|--------------|
| 系统 `python3` | 3.14 | ✅ | ❌ |
| PA venv | 3.13 | ✅（后装的） | ✅ |

C 扩展不能跨版本，所以不能简单把一个环境的 `site-packages` 加到另一个的 `sys.path`。

沙箱测试要用 `bianbu_agent.security_sandbox`，但 `import bianbu_agent` 会执行包的 `__init__`，拉进 pydantic 等 C 扩展依赖。

解法（`tests_all.py::_load_sandbox_mods()`）：这两个模块**只依赖标准库**，所以用 `importlib` 按文件路径加载，并塞一个空壳 `bianbu_agent` 模块进 `sys.modules`，绕过真正的 `__init__`：

```python
pkg = types.ModuleType("bianbu_agent")
pkg.__path__ = [str(base)]        # 空壳包
sys.modules["bianbu_agent"] = pkg
spec = importlib.util.spec_from_file_location(
    "bianbu_agent.security_sandbox", base / "security_sandbox.py")
```

---

## 第二部分：操作指南

### 2.0 文件构成

仓库 `testkit/`：

```
engine.py       测试引擎
tests_all.py    24 个测试项
runner.py       运行入口
webui.py        HTTP 服务 + 内嵌前端
GUIDE.md        本文档
README.md       简要说明
scripts/
  env.sh              公共配置与函数（其它脚本 source 它）
  deploy.sh           装到持久位置
  start-securityd.sh  起 securityd（总线自适配）
  start-pa.sh         起 personal-agent
  start-webui.sh      起测试 WebUI
  start-all.sh        按依赖顺序起三个
  stop-all.sh         停服务
  status.sh           三服务体检 + 上轮结果
  run-tests.sh        命令行跑测试（带前置检查）
```

所有路径都可用环境变量覆盖，默认值在 `scripts/env.sh` 顶部：

| 变量 | 默认 | 含义 |
|------|------|------|
| `BNSEC_TESTKIT` | `/home/bianbu/bnsec-testkit` | testkit 部署位置 |
| `BIANBU_SECURITYD_HOME` | `/home/bianbu/impl/bianbu-securityd` | securityd 源码根 |
| `BNSEC_PA_HOME` | `/home/bianbu/bianbu-agent` | PA 源码根 |
| `BNSEC_OUT` | `/var/tmp/bnsec-testrun` | 测试产物 |
| `BNSEC_LOG_DIR` | `/var/tmp/bnsec-logs` | 服务日志 |
| `BNSEC_WEB_PORT` | `9700` | WebUI 端口 |
| `BNSEC_BUS` | `auto` | securityd 总线：auto/system/session |
| `BIANBU_PA_AGENT_ID` | `${PA_AGENT_ID:-bianbu-agent-default}` | securityd 侧能力注册主键；默认与 Runtime Session Agent 一致 |

### 2.1 首次部署

把仓库 `testkit/` 传到 worker，然后：

```bash
ssh bianbu@10.0.90.243
cd <testkit 所在目录>
./scripts/deploy.sh
```

deploy 会把代码装到 `$BNSEC_TESTKIT`、脚本装到 `$BNSEC_TESTKIT/scripts/`、
建好产物与日志目录，并做一次语法自检。

装到别处：

```bash
BNSEC_TESTKIT=/opt/bnsec ./scripts/deploy.sh
```

### 2.2 起服务

```bash
cd /home/bianbu/bnsec-testkit/scripts
./start-all.sh
```

输出：

```
═══ 1/3 securityd ═══
securityd 已在 system 总线上占名，无需重启

═══ 2/3 personal-agent ═══
停止旧的 PA 进程…
启动 PA…
  ✓ personal-agent 就绪（5次探测）

═══ 3/3 测试 WebUI ═══
  ✓ WebUI 就绪（2次探测）

  监视页面：http://10.0.90.243:9700
  ⚠️  无认证，仅限内网

═══ 体检 ═══
── securityd        ✓ 已占名（system 总线）
── personal-agent   ✓ HTTP 200
── 测试 WebUI       ✓ HTTP 200
── testkit 安装     ✓ /home/bianbu/bnsec-testkit
```

**顺序不能颠倒**：PA 启动时会连 securityd。securityd 没起，PA 会把安全层
降级（低危 fail-open），跑出来的结果不可信。`start-all.sh` 已固定顺序。

也可单独起：

```bash
./start-securityd.sh
./start-pa.sh
./start-webui.sh
```

#### securityd 占名失败怎么办

`start-securityd.sh` 会打出原因与处置命令。两条路：

**① 补齐系统总线的前提**（推荐，跨用户可见、不随登录会话消失）

```bash
sudo cp /home/bianbu/impl/bianbu-securityd/deploy/io.bianbu.Security.conf \
        /etc/dbus-1/system.d/
sudo groupadd -f bianbu-security
sudo groupadd -f bianbu-admin
sudo usermod -aG bianbu-security,bianbu-admin $USER
sudo systemctl reload dbus
# 重新登录 SSH 让组生效
exit && ssh bianbu@10.0.90.243
cd /home/bianbu/bnsec-testkit/scripts && ./start-securityd.sh
```

**② 退回会话总线**（免 policy、免 root）

```bash
BNSEC_BUS=session ./start-securityd.sh
```

测试引擎两条总线都试，所以哪种都能跑。

### 2.3 跑测试

#### 方式 A：WebUI（推荐）

浏览器开 `http://10.0.90.243:9700`，点「开始测试」。

- 左栏 24 项实时刷新（灰=待测、蓝=运行中、绿=通过、红=失败）
- 顶部统计通过/失败/错误数与总耗时
- 分类标签筛选，「仅失败」快速定位
- 点任一项 → 右栏看断言明细；跑完后再点 → 还能看执行日志、审计增量、异常堆栈

#### 方式 B：命令行

```bash
cd /home/bianbu/bnsec-testkit/scripts
./run-tests.sh                      # 全量 24 项
./run-tests.sh HOOK-03 TOKEN-02     # 只跑两个决定性测试
./run-tests.sh PERM-01 PERM-02 PERM-03 PERM-04       # 判权全组
./run-tests.sh SBX-01 SBX-02 SBX-03 SBX-04 SBX-05    # 沙箱全组
```

`run-tests.sh` 会先检查 securityd 与 PA，缺任一就直接报错退出 ——
否则会得到一堆 `ServiceUnknown` / `Connection refused` 干扰判断。

退出码：全通过 `0`、有失败 `1`、传错测试 ID `2`（可直接接 CI）。

### 2.4 看结果

#### 快速摘要

```bash
cd /home/bianbu/bnsec-testkit/scripts && ./status.sh
```

末尾会显示上轮结果与距今时间，未通过的逐项列出。

#### 某项的完整产出

```bash
python3 - <<'EOF'
import json
tid = 'HOOK-03'
r = json.load(open('/var/tmp/bnsec-testrun/report.json'))
t = next(x for x in r['results'] if x['id'] == tid)
print(f"=== {t['id']} {t['title']} ({t['status']}, {t['duration_ms']}ms) ===")
print('\n断言:')
for s in t['steps']:
    print(f"  {'✓' if s['ok'] else '✗'} {s['name']}")
    if not s['ok']: print(f"      {s['detail'][:300]}")
print('\n日志:')
for l in t['logs']: print('  ' + l)
print('\n审计增量:')
for a in t['audit_delta']:
    print(f"  seq={a['seq']} {a['op_type']} {a['target']} → {a['result']}")
if t['error']: print('\n堆栈:\n' + t['error'])
EOF
```

#### 输出文件

| 文件 | 内容 |
|------|------|
| `/var/tmp/bnsec-testrun/events.jsonl` | 事件流，WebUI 数据源 |
| `/var/tmp/bnsec-testrun/report.json` | 完整报告（每项断言/日志/审计/堆栈） |
| `/var/tmp/bnsec-testrun/runner.log` | WebUI 启动那次运行的 stdout |
| `/var/tmp/bnsec-logs/securityd.log` | securityd 日志 |
| `/var/tmp/bnsec-logs/pa.log` | personal-agent 日志 |
| `/var/tmp/bnsec-logs/webui.log` | WebUI 日志 |

`report.json` 结构：

```json
{
  "summary": {"total":24,"passed":24,"failed":0,"error":0,
              "duration_ms":24429,"started_at":...,"finished_at":...},
  "results": [{
    "id":"HOOK-03", "title":"...", "requirement":"INT-PA-02",
    "category":"hook", "status":"passed", "duration_ms":29134,
    "steps":[{"name":"...","ok":true,"detail":"...","data":null}],
    "message":"", "logs":["[17:13:19] POST /api/v1/runs → 202"],
    "audit_delta":[{"seq":4062,"ts":"...","agent_id":"com.bianbu.agent",
                    "op_type":"check_permission","target":"mcp.bianbu.memory:",
                    "result":"allow"}],
    "error":""
  }]
}
```

### 2.5 停服务

```bash
cd /home/bianbu/bnsec-testkit/scripts
./stop-all.sh           # 停 WebUI + PA（securityd 保留）
./stop-all.sh --secd    # 连 securityd 一起停
./stop-all.sh --webui   # 只停 WebUI（演示完收摊）
```

默认不停 securityd —— 它可能被别的东西用着。

### 2.6 改代码后重新部署

```bash
# 本地改完，传到 worker 的源目录
scp -r testkit bianbu@10.0.90.243:/home/bianbu/bnsec-src/

# worker 上重新部署并重启
ssh bianbu@10.0.90.243
cd /home/bianbu/bnsec-src && ./scripts/deploy.sh
cd /home/bianbu/bnsec-testkit/scripts && ./start-webui.sh
```

只改了 `tests_all.py` 的话，WebUI 不用重启（每次 `POST /api/run` 都新起
一个 runner 进程，会读到最新代码）；改了 `webui.py` 才需要重启 WebUI。

### 2.7 加新测试项

在 `tests_all.py` 里加一个函数即可，无需改 engine 或 WebUI：

```python
@test("PERM-05", "同一能力不同 scope 独立判权", "INT-PA-02", "permission")
def t_perm_scope(c: Ctx):
    _register_caps(c)
    c.dbus().SetCapabilityGranted(AGENT_ID, "file.read", "/tmp", dbus.Int32(1))
    return [
        Step("授权的 scope 放行",
             c.check_permission("file.read", "/tmp") == "ALLOW"),
        Step("未授权的 scope 不放行",
             c.check_permission("file.read", "/etc") != "ALLOW"),
    ]
```

四个参数：`id` / `title` / `requirement`（PRD 编号）/ `category`（WebUI 筛选用）。

**写断言的原则**：落在**外部可观测事实**上。要验"判权真的发生了"，就查
审计增量，而不是查 hook 函数的返回值 —— 后者会漏掉集成层断裂。

### 2.8 排错

| 现象 | 原因 | 处理 |
|------|------|------|
| 跑出「总计 0」 | 直接跑了 `python3 engine.py` | 用 `runner.py` 或 `./run-tests.sh` |
| `ServiceUnknown: io.bianbu.Security` | securityd 没起 | `./start-securityd.sh` |
| `Connection refused` | PA 没起 | `./start-pa.sh` |
| securityd `AccessDenied` 占名失败 | 缺 D-Bus policy 或不在组 | 见 §2.2，或 `BNSEC_BUS=session` |
| `ModuleNotFoundError: dbus` | 用 PA venv 跑测试 | 用系统 `python3`（脚本已固定） |
| `ModuleNotFoundError: jsonschema` | 沙箱测试走了 `import bianbu_agent` | 应用 `_load_sandbox_mods()` |
| WebUI 点了没反应 | 已有测试在跑（409） | 等当前轮结束 |
| SSH 起后台进程时通道挂住 | 用了 `nohup … &` | 用 `bnsec_spawn`（`setsid … </dev/null`） |
| PA 报 `Hook package must contain only hook.py` | hook 目录有多余文件 | 清掉 `.bak` 与 `__pycache__` |
| 重启后脚本/产物消失 | 放在了 `/tmp`（tmpfs） | 用 `deploy.sh` 装到 `$HOME` |

看日志：

```bash
tail -f /var/tmp/bnsec-logs/pa.log
tail -f /var/tmp/bnsec-logs/securityd.log
tail -f /var/tmp/bnsec-logs/webui.log
tail -f /var/tmp/bnsec-testrun/runner.log
```

PA 日志混了 uvicorn 的 access log，过滤一下：

```bash
grep -avE 'GET /api|POST /api' /var/tmp/bnsec-logs/pa.log | tail -30
```

### 2.9 安全提醒

**WebUI 无认证。** 绑 `0.0.0.0:9700`，任何能访问 worker 的人都能触发测试。
测试会真实调用 LLM（消耗 token）、真实注册/授予能力、真实往审计库写记录。

只在可信内网用。演示完：

```bash
./stop-all.sh --webui
```

要限制来源，把 `webui.py` 末尾的绑定地址改成 `127.0.0.1`，用 SSH 转发访问：

```bash
ssh -L 9700:127.0.0.1:9700 bianbu@10.0.90.243
# 本机开 http://127.0.0.1:9700
```

---

## 附：完整流程（复制即用）

首次：

```bash
scp -r testkit bianbu@10.0.90.243:/home/bianbu/bnsec-src/
ssh bianbu@10.0.90.243
cd /home/bianbu/bnsec-src && ./scripts/deploy.sh
cd /home/bianbu/bnsec-testkit/scripts && ./start-all.sh
./run-tests.sh
```

日常：

```bash
ssh bianbu@10.0.90.243
cd /home/bianbu/bnsec-testkit/scripts
./status.sh          # 看三服务与上轮结果
./start-all.sh       # 有服务没起就拉起
./run-tests.sh       # 或浏览器点「开始测试」
```
