#!/bin/bash
# hermes hook 拦截补丁——使 pre_tool_call 返回 {"action":"block"} 时真正短路工具执行
# 在 worker (10.0.90.243) 以 bianbu 用户执行: bash hermes-hook-block-patch.sh

set -e

TARGET=/usr/lib/hermes-agent/src/model_tools.py
BACKUP=${TARGET}.bak.$(date +%Y%m%d-%H%M%S)

echo "[1/4] 备份原文件 → $BACKUP"
sudo cp "$TARGET" "$BACKUP"

echo "[2/4] 生成补丁后的代码"
cat > /tmp/model_tools_hook_block.py.part <<'PYCODE'
        try:
            from hermes_cli.plugins import invoke_hook
            hook_result = invoke_hook(
                "pre_tool_call",
                tool_name=function_name,
                args=function_args,
                task_id=task_id or "",
                session_id=session_id or "",
                tool_call_id=tool_call_id or "",
            )
            # bianbu-security 接入：invoke_hook 返回 List[Any]（各插件返回值汇总）,
            # 遍历找到任一 {"action":"block"} 即短路,不执行工具。
            if isinstance(hook_result, list):
                for _hr in hook_result:
                    if isinstance(_hr, dict) and _hr.get("action") == "block":
                        blocked_msg = _hr.get("message", "Tool blocked by security policy")
                        return json.dumps({
                            "error": blocked_msg,
                            "blocked_by": "bianbu-security",
                            "tool": function_name
                        })
        except Exception:
            pass
PYCODE

echo "[3/4] 基于原始 invoke_hook 块替换（幂等：先找干净块，避免在已打补丁文件上错位）"
# 用 python 精确定位原始 12 行 invoke_hook 块并替换，重复执行安全
sudo /usr/lib/hermes-agent/python3.11/bin/python3.11 - "$TARGET" /tmp/model_tools_hook_block.py.part <<'PYEOF'
import sys
target, part = sys.argv[1], sys.argv[2]
src = open(target).read()
patch = open(part).read().rstrip("\n")
orig_block = '''        try:
            from hermes_cli.plugins import invoke_hook
            invoke_hook(
                "pre_tool_call",
                tool_name=function_name,
                args=function_args,
                task_id=task_id or "",
                session_id=session_id or "",
                tool_call_id=tool_call_id or "",
            )
        except Exception:
            pass'''
if orig_block in src:
    open(target, "w").write(src.replace(orig_block, patch, 1))
    print("  替换原始块成功")
elif "blocked_by" in src and "isinstance(hook_result, list)" in src:
    print("  已是最新 list 遍历补丁，跳过")
else:
    print("  WARN: 未找到原始块也非已知补丁，请人工核对"); sys.exit(1)
PYEOF

echo "[4/4] 验证修改"
echo "--- 修改后的 500-520 行 ---"
sed -n '500,520p' "$TARGET"

echo ""
echo "✓ 补丁完成。原文件备份: $BACKUP"
echo "下次启动 hermes 时,DENY 的工具会真正被拦截(不执行)。"
echo ""
echo "回滚命令(如需): sudo cp $BACKUP $TARGET"
