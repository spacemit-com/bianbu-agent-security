# AGENTS.md — Bianbu Next 设计文档仓库

## 仓库定位
这是 **Bianbu Next**（面向 RISC-V + AI 的 Agent 原生 OS 底座）的产品与设计文档仓库。主体产出物是一条可追溯的工程文档链：

```
PRD → SRS → HLD → API → LLD
```

对 Bianbu Next 产品本身的说明，以 `docs/Bianbu_Next_PRD_V0.9.md` 为准，不要凭记忆作答。

**例外：安全子系统已有可运行实现。** `impl/bianbu-securityd/`（判权/DLP/审计/沙箱服务）与 `testkit/`（端到端测试系统）是真实代码，配套的 personal-agent 接入在**另一个仓** `../personal-agent`。改这部分前先读 `testkit/README.md`（见下节），它是该子系统的唯一操作入口。除此之外本仓仍以文档为主。

## 目录结构
| 路径 | 内容 |
|------|------|
| `docs/Bianbu_Next_PRD_V0.9.md` / `Bianbu_Next_PRD_V0.9.html` | 现行产品需求文档（权威版本，MD 与 HTML 内容对应） |
| `Bianbu_Next_PRD_V0.7.html` | 历史 PRD（勿改，仅供追溯） |
| `Bianbu_Next_PRD_V0.7_Review.md` | V0.7 评审报告 + 开发就绪度评估 |
| `Bianbu_Next_SRS_V0.8-draft.md` | 早期 SRS 增量草稿（已被 `design/01` 取代，保留存档） |
| `design/01_Bianbu_Next_SRS.md` | 软件需求规格说明书（BN-SRS-001） |
| `design/02_Bianbu_Next_HLD.md` | 概要设计（BN-HLD-001） |
| `design/03_Bianbu_Next_API.md` | 高层与模块 API 定义（BN-API-001） |
| `design/04_Bianbu_Next_LLD.md` | 详细设计（BN-LLD-001） |
| `docs/BNAgent-Security-Capability-Mapping.md` | 能力映射技术方案（BN-SEC-CAPMAP-001），§10 是 D-1~D-10 落地记录 |
| `docs/BNAgent-Security-Remediation-Plan.md` | 安全整改方案（BN-SEC-REMED-001） |
| `impl/bianbu-securityd/` | **securityd 实现**（Python，D-Bus 服务 + 配置台 WebUI） |
| `testkit/` | **安全子系统端到端测试系统**（36 项），含启动脚本与操作文档 |
| `Collaboration/CODEX-ONBOARDING.md` | **AI coder 上手指南** —— 代码仓关系、跑起来、改动闭环、硬约束、排查手册 |

## 文档链与追溯规则
- 上游改动必须向下游传导：改 PRD → 检查 SRS 的 FR → HLD 组件 → API 签名 → LLD 实现。
- 需求编号是追溯主键，改动时保持一致：
  - PRD 用 `SEC/AI/RTE/SDK/CLI/BENCH/DOC/INT/ASR/DCO/OCR/VEC/SKL/APP/MEM/CAL/SET/ECO/SBX`
  - SRS 用 `FR-<域>-<序号>`，与 PRD 编号双向映射
  - 待确认项统一用 `【待确认】`（PRD）/ `[TBD-n]`（SRS 及下游），编号对齐 PRD 12.2 的 19 项
- 六层架构与命名以 HLD 为准。核心常驻服务：`bianbu-securityd` / `bianbu-aihald` / `bianbu-agent-runtimed` / `bianbu-memoryd` / `bianbu-skilld` / `bianbu-intentd` / `bianbu-calendard` / `bianbu-indexerd`。
- D-Bus 接口名在 `io.bianbu.*` 命名空间（如 `io.bianbu.Runtime`），与进程名解耦——改进程名不改接口名。

## 安全子系统（有可运行实现，改动前必读）

`impl/bianbu-securityd/` + `../personal-agent` 的安全接入是本仓唯一有真实
代码与端到端测试的部分。本节只给概要，完整内容看这两份：

- **`Collaboration/CODEX-ONBOARDING.md`** —— 第一次接手先读这份。代码仓关系、
  一次工具调用的完整链路、改动闭环、6 条硬约束、排查手册。
- **`testkit/README.md`** —— 测试系统操作手册、36 项清单、脚本开关。

### 三个服务

| 服务 | 位置 | 起法 | 端口 |
|------|------|------|------|
| securityd | `impl/bianbu-securityd/` | `./start-bianbu-securityd.sh` | D-Bus `io.bianbu.Security` |
| securityd 配置台 | `impl/bianbu-securityd/webui/` | `./start-securityd-webui.sh` | 8787 |
| personal-agent | `../personal-agent`（另一个仓） | `./start-bianbu-agent.sh` | 9899 |

三个独立启动脚本在 `testkit/scripts/`，自带默认值、拷到 worker 直接跑。
**启动顺序固定**：securityd → PA / 配置台。securityd 没起时 PA 仍能启动，
但判权走 fail 分档（高危拦截、低危放行）—— 看着"能用"其实安全已半失效。

### 跑测试

```bash
# 端到端（36 项，真实 PA + 真实 securityd）
cd /home/bianbu/bnsec-testkit && python3 runner.py        # 不要跑 engine.py
# securityd 默认全量（523 passed / 3 skipped；strict 会真实执行这 3 条 E2E）
cd /home/bianbu/impl/bianbu-securityd && python3 -m pytest tests/ -q
# PA 回归 —— 关闭/启用安全必须逐项比较失败集合，不能只看总数
export PATH=/home/bianbu/.local/bin:$PATH
cd /home/bianbu/bianbu-agent && uv run pytest -q
```

浏览器看实时进度与报告：`http://10.0.90.243:9700`。

### 硬约束（违反会让安全静默失效）

1. **新增能力名必须先进 `securityd/capabilities.py`**。SQLite schema 对能力名
   无任何校验，写错不报错，只会在判权时因"未注册"返回 DENY，看起来像配置问题。
   改名要同步 `ALIASES` 与所有按名字硬编码的清单（如 `HIGH_RISK_CAPABILITIES`）。
2. **插件 `lib/__init__.py` 是隐式契约**，hook 用到的符号必须同步 re-export，
   否则 PA 整个起不来。
3. **`hooks/<name>/` 内只能有 `hook.py`**，`.bak` 与 `__pycache__` 都会让启动失败。
4. **`BIANBU_PA_AGENT_ID`（默认 `com.bianbu.agent`）与 PA 本地 `agent.id` 不是
   同一命名空间**，用错会把判权与 Token 用量记到未注册的 agent 上。
5. **判权/推断的取向是「不确定时交给人」**：推断命中多条取风险最高的、未映射
   工具默认 CONFIRM、复合命令不给假答案。新增逻辑请沿用。
6. **改了代码必须重启对应服务再验**，否则验到旧代码（`testkit/README.md` 有重启对照表）。

### 改动闭环

```
改代码 → sftp 推 worker → 重启受影响服务 → 跑对应测试
      → 补测试项（新行为必须有防回归断言）→ 两个仓分别 commit
```

`../personal-agent` 简称PA 的代码在本项目的统计目录，文件夹名：bianbu-agent-runtime
`../personal-agent` 的 remote 属他人，**只本地 commit，不要 push**。

## 写作约定
- **语言**：简体中文。
- **版本表头**：每份设计文档保留顶部元信息表（文档编号/版本/来源/日期/状态）。
- **验收标准**：必须可测量（延迟、准确率、成功率、百分比），禁止"功能正常"这类循环定义。
- **五维评审**：需求/设计变更以完整性、可测试性、无歧义性、一致性、可实现性自检。
- **表格优先**：功能细项、接口、映射关系用表格；流程用文字步骤或代码块，不依赖外部图片。
- HTML 版 PRD 内嵌 mermaid 图；MD 版用表格/文字流程等价表达，二者需保持内容一致。

## 修改与提交
- 编辑用精确字符串替换，保持既有表格列结构与编号顺序。
- 批量重命名先确认全量引用（`grep -rn`），用占位符法避免嵌套替换，改完校验无残留、无嵌套。
- 提交信息用 `docs: <简述>`，正文说明改了哪些文档、为什么。
- 提交信息中**不写任何 AI 协助者署名**（如 `Co-Authored-By: Claude ...`、`Generated with ...` 等），保持 commit log 干净。
- 仅在用户明确要求时提交/推送；`main` 为默认分支，推送前确认改动范围。
- 历史版本文件（V0.7 等）除非明确要求，不要改动。

## 发布 Tag 规则

用户约定（2026-09-09）：Security 仓库的发布 tag 必须使用
`bianbu/<版本号>`，例如 `bianbu/0.1.22`，推送该格式的 tag 才能触发发布 CI。
不要使用 `v0.1.22` 或不带 `bianbu/` 前缀的版本 tag。

- 版本号与 `debian/changelog` 顶部版本保持一致。
- 创建 tag 前，先向用户展示完整 tag 名称并取得确认；确认后的创建、推送按用户授权执行。
- 使用附注 tag，指向包含对应 changelog 的发布提交；推送后核对远端 tag 指向。
- 修正已推送的错误 tag 时，按用户授权删除错误的本地及远端 tag，再推送正确名称。

## 常用校验
```bash
# 查某需求编号的全链路引用
grep -rn "FR-SEC-01\|SEC-01" --include="*.md" .
# 校验 MD 无残留占位符 / 代码块闭合
grep -c "<!-- " design/*.md
grep -c '^```' design/04_Bianbu_Next_LLD.md   # 应为偶数
```

## Worker 机器
如果明确提示再开发测试，那就是默认在Worker机上测试验证

> ⚠️ 内部凭据，仅限内网使用。以下为纯文本密码，注意本文件已随仓库提交。

| 项 | 值 |
|----|----|
| 主机 | `10.0.90.243` |
| 用户名 | `bianbu` |
| 密码 | `bianbu` |
| 工作路径 | `/home/bianbu/bianbu-agent-security` |

如果已经设置好了免密的SSH Key就不要使用密码SSH。没有设置可以先设置好SSH Key，第一次使用用户和密码配置ssh key,后续就不要使用用户名和密码访问了。使用这个命令配置SSH Key：ssh-copy-id -i ~/.ssh/id_ed25519.pub bianbu@10.0.90.243
**连接规则：SSH 连接时不要交互式提示输入密码，直接使用上面的密码。** 用 `sshpass` 携带密码非交互连接：

```bash
# 直接执行远程命令
sshpass -p 'bianbu' ssh -o StrictHostKeyChecking=no bianbu@10.0.90.243 'cd /home/bianbu/bianbu-agentos && <command>'

# 交互式登录
sshpass -p 'bianbu' ssh -o StrictHostKeyChecking=no bianbu@10.0.90.243

# 传文件
sshpass -p 'bianbu' scp -o StrictHostKeyChecking=no <local> bianbu@10.0.90.243:/home/bianbu/bianbu-agentos/
```

若无 `sshpass`，先安装（Debian/Ubuntu：`apt-get install -y sshpass`）；无安装权限时可用 Python `paramiko` 携带密码连接。

### 复用边界（重要）
**本项目不复用 worker 机器上的 `bianbu-agentforce` 与 `hermes-agent`。** 二者仅作为**环境实况参考**（了解目标平台的软硬件、已有能力形态），不得作为本项目设计的实现来源或依赖：

- 设计（HLD/LLD）与实现以本仓库 PRD/SRS 为准，自研 D-Bus 系统服务与 SDK，不桥接、不封装、不移植 agentforce/hermes 的代码或运行时。
- 可以观察它们来校准硬件假设、验证方向可行性、对比接口概念，但不写"复用 hermes 资产"这类落地依赖。
- 文档中若出现与本规则冲突的"复用现有实现"表述，以本规则为准并予以修正。

## 运行平台与本地 AI 栈（重要，后续开发基线）

目标运行平台为 worker 机（SpacemiT K3，`10.0.90.243`）。**本地 AI 推理使用 SpacemiT 定制栈，不是通用 llama.cpp / 通用 onnxruntime / 纯 RVV**。设计与实现必须按此栈落地：

### 硬件加速分层
- **IME**（Integrated Matrix Engine，矩阵加速引擎）+ **TCM**（Tightly-Coupled Memory，紧耦合内存）是本地推理的主加速通路。
- **A100 簇** → 使用 **IME2 + TCM**。
- **X100 簇** → 使用 **IME1**。
- 算子不被 IME 覆盖时 **回退 RVV**（RISC-V Vector），再回退 **CPU 标量**。

### 软件栈分工
| 任务类别 | 运行栈 | 说明 |
|----------|--------|------|
| LLM 本地推理 | **定制版 `llama.cpp` + `ggml-spacemit` 后端** | A100=IME2+TCM，X100=IME1，回退 RVV/CPU |
| 图形 / 视觉类（OCR/Vision 等） | **`onnxruntime` + `spacemit-ep`**（SpacemiT Execution Provider，riscv64 IME/TCM 适配版） | 非通用 CPU EP |

### 编译前提（关键约束）
- 编译 `llama.cpp` 与 `onnxruntime` 均需 **SpacemiT 定制版 toolchain** 才能启用 IME/TCM 支持，**标准 riscv64-linux-gnu 工具链无法编出加速版本**。
- 因此 HLD/LLD 的 AI HAL 后端、AI Runtime EP Dispatcher、性能 baseline（[TBD-15]）均须以此栈为准：本地 LLM 后端 = ggml-spacemit；视觉/OCR 后端 = onnxruntime + spacemit-ep；EP 调度顺序 = IME(2/1)+TCM → RVV → CPU。
- doctor 工具须检测：定制 toolchain、ggml-spacemit、spacemit-ep、IME/TCM 驱动是否就绪，缺失时给出提示。

### 交叉编译工具链（面向 worker 机 / K3）
运行目标为 worker 机（SpacemiT K3，riscv64）时，在开发主机（x86_64 Linux）上**交叉编译** `llama.cpp`、`onnxruntime` 及一般 C/C++ 项目，统一使用 SpacemiT 官方交叉编译工具链（即上文"SpacemiT 定制 toolchain"，含 LLVM + GCC，能编出 IME/TCM 加速版本）：在K3 riscv64 上不需要使用交叉编译工具链。直接使用本机上安装的编译工具链即可。

| 项 | 值 |
|----|----|
| 工具链 | `spacemit-toolchain-linux-glibc-x86_64-v1.2.7`（LLVM+GCC） |
| 下载 | `https://nexus.bianbu.xyz/repository/toolchain/llvm-gcc/spacemit-toolchain-linux-glibc-x86_64-v1.2.7.tar.xz` |
| host → target | x86_64 Linux（开发机） → riscv64 glibc（K3 / worker） |
| 用途 | 交叉编译 ggml-spacemit / spacemit-ep 及所有下发到 worker 的 C/C++ 产物 |

- **备用版本**：若 `v1.2.7` 编译异常，回退使用 `v1.1.2`：`https://nexus.bianbu.xyz/repository/toolchain/llvm-gcc/spacemit-toolchain-linux-glibc-x86_64-v1.1.2.tar.xz`
- 标准 `riscv64-linux-gnu` 工具链**不可用于**本项目 AI 栈编译（编不出 IME/TCM 加速）。
- 版本随官方发布更新，当前基线 `v1.2.7`、备用 `v1.1.2`；升级时同步修订本条。
