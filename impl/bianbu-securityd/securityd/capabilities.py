"""工具目录（tool catalog）—— 全系统的工具名与默认策略事实来源。

## 模型

能力管理只剩一个维度：**工具**。每个工具一条策略，三选一：

    allow   直接放行
    ask     调用前交用户确认
    deny    拒绝

旧的 domain / risk_level / confirm / scope 四维已删除：域和风险要么是工具
本身就能表达的信息，要么是重复推断，维护成本高、容易与实际执行脱节。

## 框架来源

工具属于两个框架之一：

  runtime   bianbu-agent-runtime 的 Agent 可用工具
  hermes    hermes-agent 的 Agent 可用工具

对接某个框架的 Agent，配置台只显示该框架的工具。两个框架的工具名可能重名
（如 read_file），因此目录按框架分表存放，查询一律带 framework。

## 未映射工具

映射表与目录都没命中的工具走 ``unmapped_policy()``（默认 allow）：与目录默认
值一致，未声明的工具也直接放行，需要收紧时由使用者显式配置。
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Optional

__all__ = [
    "ToolSpec",
    "FRAMEWORK_RUNTIME",
    "FRAMEWORK_HERMES",
    "FRAMEWORKS",
    "TOOLS",
    "catalog",
    "framework_of",
    "spec_of",
    "is_known",
    "default_policy",
    "UNMAPPED_TOOL",
    "unmapped_policy",
    "unmapped_decision",
]

FRAMEWORK_RUNTIME = "runtime"
FRAMEWORK_HERMES = "hermes"
FRAMEWORKS = (FRAMEWORK_RUNTIME, FRAMEWORK_HERMES)


@dataclass(frozen=True)
class ToolSpec:
    """一个工具的权威定义。"""

    name: str
    framework: str
    default_policy: str   # allow | ask | deny
    summary: str

    def __post_init__(self) -> None:
        if self.framework not in FRAMEWORKS:
            raise ValueError(f"{self.name}: 未知框架 {self.framework}")
        if self.default_policy not in ("allow", "ask", "deny"):
            raise ValueError(f"{self.name}: 非法默认策略 {self.default_policy}")


def _t(name, framework, policy, summary) -> ToolSpec:
    return ToolSpec(name, framework, policy, summary)


# 默认全部放行：能力管理只描述「这个 tool 能不能调」，默认值取用户
# 最省事的一档，需要收紧时由使用者逐工具改成 ask / deny。
_RUNTIME_TOOLS = (
    _t("read_file", FRAMEWORK_RUNTIME, "allow", "读取文件内容"),
    _t("read_image", FRAMEWORK_RUNTIME, "allow", "读取图片"),
    _t("search_files", FRAMEWORK_RUNTIME, "allow", "按内容/名字搜索文件"),
    _t("write_file", FRAMEWORK_RUNTIME, "allow", "写入或创建文件"),
    _t("patch", FRAMEWORK_RUNTIME, "allow", "修改文件补丁"),
    _t("terminal", FRAMEWORK_RUNTIME, "allow", "执行系统命令"),
    _t("process", FRAMEWORK_RUNTIME, "allow", "管理后台进程"),
    _t("web_search", FRAMEWORK_RUNTIME, "allow", "联网搜索"),
    _t("web_extract", FRAMEWORK_RUNTIME, "allow", "抓取网页内容"),
    _t("browser_navigate", FRAMEWORK_RUNTIME, "allow", "浏览器导航"),
    _t("browser_click", FRAMEWORK_RUNTIME, "allow", "浏览器点击"),
    _t("browser_type", FRAMEWORK_RUNTIME, "allow", "浏览器输入"),
    _t("browser_press", FRAMEWORK_RUNTIME, "allow", "浏览器按键"),
    _t("browser_scroll", FRAMEWORK_RUNTIME, "allow", "浏览器滚动"),
    _t("browser_back", FRAMEWORK_RUNTIME, "allow", "浏览器后退"),
    _t("browser_snapshot", FRAMEWORK_RUNTIME, "allow", "读取页面快照"),
    _t("browser_get_images", FRAMEWORK_RUNTIME, "allow", "读取页面图片"),
    _t("browser_console", FRAMEWORK_RUNTIME, "allow", "读取浏览器控制台"),
    _t("skill_view", FRAMEWORK_RUNTIME, "allow", "查看 Skill"),
    _t("skills_list", FRAMEWORK_RUNTIME, "allow", "列出 Skill"),
    _t("skill_manage", FRAMEWORK_RUNTIME, "allow", "安装/修改 Skill"),
    _t("todo", FRAMEWORK_RUNTIME, "allow", "读写待办"),
    _t("kanban_list", FRAMEWORK_RUNTIME, "allow", "读取看板"),
    _t("kanban_show", FRAMEWORK_RUNTIME, "allow", "查看看板项"),
    _t("kanban_attachments", FRAMEWORK_RUNTIME, "allow", "列出看板附件"),
    _t("kanban_create", FRAMEWORK_RUNTIME, "allow", "创建看板项"),
    _t("kanban_attach", FRAMEWORK_RUNTIME, "allow", "给看板项加附件"),
    _t("kanban_attach_url", FRAMEWORK_RUNTIME, "allow", "给看板项加链接"),
    _t("kanban_comment", FRAMEWORK_RUNTIME, "allow", "评论看板项"),
    _t("kanban_complete", FRAMEWORK_RUNTIME, "allow", "完成看板项"),
    _t("kanban_block", FRAMEWORK_RUNTIME, "allow", "阻塞看板项"),
    _t("kanban_unblock", FRAMEWORK_RUNTIME, "allow", "解除看板项阻塞"),
    _t("kanban_link", FRAMEWORK_RUNTIME, "allow", "关联看板项"),
    _t("kanban_heartbeat", FRAMEWORK_RUNTIME, "allow", "看板项心跳"),
)

_HERMES_TOOLS = (
    _t("read_file", FRAMEWORK_HERMES, "allow", "读取文件"),
    _t("search_files", FRAMEWORK_HERMES, "allow", "搜索文件"),
    _t("write_file", FRAMEWORK_HERMES, "allow", "写入文件"),
    _t("patch", FRAMEWORK_HERMES, "allow", "修改文件补丁"),
    _t("terminal", FRAMEWORK_HERMES, "allow", "执行系统命令"),
    _t("process", FRAMEWORK_HERMES, "allow", "管理后台进程"),
    _t("execute_code", FRAMEWORK_HERMES, "allow", "执行代码"),
    _t("web_search", FRAMEWORK_HERMES, "allow", "联网搜索"),
    _t("web_extract", FRAMEWORK_HERMES, "allow", "抓取网页"),
    _t("browser_navigate", FRAMEWORK_HERMES, "allow", "浏览器导航"),
    _t("browser_click", FRAMEWORK_HERMES, "allow", "浏览器点击"),
    _t("browser_type", FRAMEWORK_HERMES, "allow", "浏览器输入"),
    _t("browser_press", FRAMEWORK_HERMES, "allow", "浏览器按键"),
    _t("browser_scroll", FRAMEWORK_HERMES, "allow", "浏览器滚动"),
    _t("browser_back", FRAMEWORK_HERMES, "allow", "浏览器后退"),
    _t("browser_snapshot", FRAMEWORK_HERMES, "allow", "读取页面快照"),
    _t("browser_get_images", FRAMEWORK_HERMES, "allow", "读取页面图片"),
    _t("browser_console", FRAMEWORK_HERMES, "allow", "读取控制台"),
    _t("browser_vision", FRAMEWORK_HERMES, "allow", "页面视觉分析"),
    _t("send_message", FRAMEWORK_HERMES, "allow", "代表用户外发消息"),
    _t("ha_call_service", FRAMEWORK_HERMES, "allow", "执行智能家居动作"),
    _t("ha_get_state", FRAMEWORK_HERMES, "allow", "读取设备状态"),
    _t("ha_list_entities", FRAMEWORK_HERMES, "allow", "列出设备实体"),
    _t("ha_list_services", FRAMEWORK_HERMES, "allow", "列出可用服务"),
    _t("cronjob", FRAMEWORK_HERMES, "allow", "注册定时任务"),
    _t("skill_manage", FRAMEWORK_HERMES, "allow", "安装/修改 Skill"),
    _t("skill_view", FRAMEWORK_HERMES, "allow", "查看 Skill"),
    _t("skills_list", FRAMEWORK_HERMES, "allow", "列出 Skill"),
    _t("memory", FRAMEWORK_HERMES, "allow", "读写长期记忆"),
    _t("todo", FRAMEWORK_HERMES, "allow", "读写待办"),
    _t("session_search", FRAMEWORK_HERMES, "allow", "检索历史会话"),
    _t("image_generate", FRAMEWORK_HERMES, "allow", "生成图像"),
    _t("text_to_speech", FRAMEWORK_HERMES, "allow", "文本转语音"),
    _t("vision_analyze", FRAMEWORK_HERMES, "allow", "视觉分析"),
    _t("mixture_of_agents", FRAMEWORK_HERMES, "allow", "多 Agent 混合推理"),
    _t("delegate_task", FRAMEWORK_HERMES, "allow", "派生子 Agent"),
    _t("rl_start_training", FRAMEWORK_HERMES, "allow", "启动训练"),
    _t("rl_stop_training", FRAMEWORK_HERMES, "allow", "停止训练"),
    _t("rl_edit_config", FRAMEWORK_HERMES, "allow", "编辑训练配置"),
    _t("rl_select_environment", FRAMEWORK_HERMES, "allow", "选择训练环境"),
    _t("rl_test_inference", FRAMEWORK_HERMES, "allow", "测试推理"),
    _t("rl_check_status", FRAMEWORK_HERMES, "allow", "查看训练状态"),
    _t("rl_get_results", FRAMEWORK_HERMES, "allow", "读取训练结果"),
    _t("rl_get_current_config", FRAMEWORK_HERMES, "allow", "读取训练配置"),
    _t("rl_list_environments", FRAMEWORK_HERMES, "allow", "列出训练环境"),
    _t("rl_list_runs", FRAMEWORK_HERMES, "allow", "列出训练运行"),
    _t("clarify", FRAMEWORK_HERMES, "allow", "向用户澄清提问"),
)

# (framework, name) -> ToolSpec。同名的 runtime/hermes 工具各自成条。
TOOLS: dict[tuple[str, str], ToolSpec] = {
    (spec.framework, spec.name): spec for spec in (*_RUNTIME_TOOLS, *_HERMES_TOOLS)
}


def catalog(framework: str = "") -> list[ToolSpec]:
    """按框架列出工具；framework 为空时列出全部。"""
    return [spec for spec in TOOLS.values()
            if not framework or spec.framework == framework]


def framework_of(name: str) -> str:
    """工具名所属框架；两个框架都有同名工具时取第一个（runtime 优先）。"""
    for fw in FRAMEWORKS:
        if (fw, name) in TOOLS:
            return fw
    return ""


def spec_of(name: str, framework: str = "") -> Optional[ToolSpec]:
    if not name:
        return None
    if framework:
        return TOOLS.get((framework, name))
    for fw in FRAMEWORKS:
        spec = TOOLS.get((fw, name))
        if spec is not None:
            return spec
    return None


def is_known(name: str, framework: str = "") -> bool:
    return spec_of(name, framework) is not None


def default_policy(name: str, framework: str = "") -> str:
    """工具在目录里的默认策略；未知工具返回未映射策略。"""
    spec = spec_of(name, framework)
    return spec.default_policy if spec else unmapped_policy()


# ─────────────────────────────────────────────────────────────────
# 未映射工具的处置策略
# ─────────────────────────────────────────────────────────────────
#
# 目录与映射表都没命中的工具，默认 allow：与目录默认值保持一致，未声明
# 的工具也直接放行。用 BIANBU_SECURITY_UNMAPPED=ask|deny 可收紧，生产模式下
# 该覆盖被忽略。
UNMAPPED_TOOL = "*"

_UNMAPPED_POLICIES = ("allow", "ask", "deny")
_UNMAPPED_DEFAULT = "allow"


def unmapped_policy() -> str:
    """未映射工具的默认策略：allow | ask | deny。"""
    v = (os.environ.get("BIANBU_SECURITY_UNMAPPED") or "").strip().lower()
    if v == "allow" and os.environ.get("BIANBU_RUNTIME_MODE", "").strip().lower() == "production":
        return _UNMAPPED_DEFAULT
    return v if v in _UNMAPPED_POLICIES else _UNMAPPED_DEFAULT


def unmapped_decision() -> int:
    """把策略翻成 Decision 码（0=ALLOW 1=ASK 2=DENY），供各消费点统一使用。"""
    return {"allow": 0, "ask": 1, "deny": 2}[unmapped_policy()]
