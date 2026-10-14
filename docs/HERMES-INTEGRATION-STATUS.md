# bianbu-security + hermes 集成状态报告与待办

**日期**: 2026-07-15  
**worker**: 10.0.90.243  
**测试用户**: bianbu

---

## 一、已解决的问题 ✓

### 1. dbus-python 依赖缺失(Silent Fail 根因)
- **修复**: 在 hermes venv 安装 `dbus-python`
- **验证**: `import dbus` 成功,D-Bus 调用通

### 2. D-Bus 总线不匹配
- **修复**: `~/.hermes/.env` 加 `BIANBU_SEC_SESSION=1`
- **验证**: session bus 上 `io.bianbu.Security` 可达

### 3. 插件加载与 hook 触发
- **状态**: 插件注册成功,`pre_tool_call` hook 每次工具调用都触发
- **验证**: agent.log 最近 PRE_TOOL_CALL:CheckPermission = 10:10 完全对齐

### 4. Capability 映射
- **状态**: 工具→能力映射正确
  - terminal → system.exec
  - write_file → file.write
  - read_file → file.read
  - web_search → network.access

### 5. ALLOW/DENY 决策链路
- **状态**: securityd 真实返回决策(ALLOW=0 / DENY=2)
- **验证**: agent.log 里全是 `decision=2` (DENY)

### 6. hermes 自带 approval 已关闭
- **修复**: `HERMES_YOLO_MODE=1` 写入 `~/.hermes/.env`
- **验证**: `approval.py` L603/L706 两处短路,无弹窗

### 7. 环境变量持久化(P0 修复)
- **修复**: `~/.hermes/.env` 现包含全部 4 个必需变量:
  ```
  HERMES_MAX_ITERATIONS=90
  BIANBU_SEC_SESSION=1
  BIANBU_SECURITYD_HOME=/home/bianbu/bianbu-securityd-work/bianbu-securityd
  HERMES_YOLO_MODE=1
  ```
- **效果**: 下次重启 hermes 自动生效

---

## 二、待解决的问题(按优先级)

### P1: L1 架构限制——DENY 无法真拦截工具执行 ✓ 已修复

**根因**: `model_tools.py:500-511` 忽略 `invoke_hook()` 返回值,即便 securityd 返回 DENY(2),工具仍执行。

**关键修正(2026-07-17)**: `invoke_hook` 返回的是 **`List[Any]`**（各插件返回值汇总）,
不是单个 dict。首版补丁误用 `isinstance(hook_result, dict)` 判断,永远为 False → 拦截失效
（实测漏过率 terminal 46% / execute_code 43% / patch 39%）。已改为**遍历 list** 找
`{"action":"block"}`,worker 实测拦截逻辑正确、语法通过。

**影响**: 当前 bianbu-security 只做**决策+审计**,但**执行层拦截失效**——terminal 工具被 DENY 后 echo 命令照样跑。

**解决方案**: 打补丁使 hook 返回 `{"action":"block"}` 时短路。

**执行步骤**(需在 worker 手动操作):

```bash
# 1. 传补丁脚本到 worker
scp deploy/hermes-hook-block-patch.sh bianbu@10.0.90.243:~/

# 2. 在 worker 执行
ssh bianbu@10.0.90.243
bash ~/hermes-hook-block-patch.sh
# 输入 sudo 密码,自动备份+替换

# 3. 重启 hermes 验证
/usr/bin/hermes chat
# 尝试调 terminal 工具,应看到 "Tool blocked by security policy" 错误而非执行
```

**预期效果**: 补丁后,DENY 的工具返回 `{"error":"Tool blocked by security policy","blocked_by":"bianbu-security"}`,不再执行。

---

### P2: securityd 审计链查不到数据

**现象**: `export_audit({"agent_id":"com.hermes.agent"})` 返回 0 条。

**可能原因**:
1. plugin 调 `AuditLog` 的参数不对(agent_id/op_type/target/result)
2. securityd 存储后端未启用
3. 导出时的 filter key 不匹配

**排查步骤**:
1. 在 plugin `__init__.py` 的 `_check_permission` 加打印,确认实际调用的 `audit_log(...)` 参数
2. 在 securityd 侧开 debug 日志,看 `AuditLog` D-Bus 调用是否到达
3. 直接查 SQLite `~/.local/share/bianbu-securityd/audit/YYYYMM.db` 的 `audit_record` 表

---

### P3: 进程级沙箱未启用(可选加固)

**现状**: hermes 直接启动,未经 `hermes_sandbox_launch.py` 包裹。

**影响**: 没有 bwrap seccomp/cap-drop 兜底——即使插件层被绕过,OS 层也无拦截。

**解决方案**: 用 `hermes_sandbox_launch.py` 启动 hermes,获得进程级隔离。

**执行**:
```bash
cd ~/bianbu-securityd-work/bianbu-securityd
python3 hermes_plugin/hermes_sandbox_launch.py --agent com.hermes.agent -- /usr/bin/hermes chat
```

**收益**: seccomp 兜底拦截 reboot/mount 等危险 syscall(已在 worker 实测 rc=99 EPERM)。

---

## 三、总结

### 当前真实安全等级

| 防护层 | 状态 |
|--------|------|
| 插件决策(CheckPermission) | ✓ 生效 |
| DENY 真拦截 | ✗ L1 限制(待 P1 补丁) |
| 审计链持久化 | ✗ 查不到(待 P2 排查) |
| 进程沙箱兜底 | ✗ 未启用(P3 可选) |

### 建议修复顺序

1. **P1**(最高优先级): 在 worker 执行 `hermes-hook-block-patch.sh`,使 DENY 真拦截
2. **P2**(次优先): 排查审计链存储,确保可追溯
3. **P3**(可选加固): 生产环境用 `hermes_sandbox_launch.py` 启动 hermes

---

## 附录: 回滚与验证

### 回滚 P1 补丁
```bash
# worker 上
sudo cp /usr/lib/hermes-agent/src/model_tools.py.bak.<时间戳> \
        /usr/lib/hermes-agent/src/model_tools.py
```

### 验证 P1 生效
1. 启动 hermes chat
2. 让 agent 调 terminal 工具
3. 观察返回:`{"error":"Tool blocked by security policy","blocked_by":"bianbu-security"}` ✓

### 验证审计链(P2 修复后)
```bash
python3 cli/bncli.py audit export com.hermes.agent
# 应输出 JSON,含最近工具调用的 DENY 记录
```

---

**生成时间**: 2026-07-15  
**相关文档**: BN-SEC-HERMES-001, BN-SEC-DEV-001
