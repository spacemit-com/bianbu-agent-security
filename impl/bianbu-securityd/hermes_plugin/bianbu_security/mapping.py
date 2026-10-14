"""hermes 工具 → 策略解析。

新模型下判权维度只有一个：**工具名**。hermes 的工具名本身就是策略键，
所以这里的"映射"退化为恒等映射 —— 不再有独立的"能力名"第二套命名。

`resolve()` 保留 (tool, scope) 的返回形状供既有调用方使用；scope 恒为空。
"""
from __future__ import annotations

from typing import Optional

__all__ = ["resolve", "DEFAULT_ALLOW", "TOOL_CAPABILITY"]

try:
    from securityd.capabilities import unmapped_policy as _unmapped_policy
    DEFAULT_ALLOW = _unmapped_policy() == "allow"
except ImportError:      # 无 securityd 的裸插件部署：保守默认 ask
    DEFAULT_ALLOW = False

# 框架内已知工具名集合（供管理端列出 hermes 工具）。
TOOL_CAPABILITY: dict[str, tuple[str, Optional[str]]] = {
    name: (name, None) for name in (
        "read_file", "search_files", "write_file", "patch",
        "terminal", "process", "execute_code",
        "web_search", "web_extract",
        "browser_navigate", "browser_click", "browser_type", "browser_press",
        "browser_scroll", "browser_back", "browser_snapshot",
        "browser_get_images", "browser_console", "browser_vision",
        "send_message", "ha_call_service", "ha_get_state",
        "ha_list_entities", "ha_list_services", "cronjob",
        "skill_manage", "skill_view", "skills_list",
        "memory", "todo", "session_search",
        "image_generate", "text_to_speech", "vision_analyze",
        "mixture_of_agents", "delegate_task",
        "rl_start_training", "rl_stop_training", "rl_edit_config",
        "rl_select_environment", "rl_test_inference", "rl_check_status",
        "rl_get_results", "rl_get_current_config", "rl_list_environments",
        "rl_list_runs", "clarify",
    )
}


def resolve(tool_name: str, args: dict) -> Optional[tuple[str, str]]:
    """返回 (tool, scope)；空工具名返回 None。"""
    if not tool_name:
        return None
    return (str(tool_name), "")
