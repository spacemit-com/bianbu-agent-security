"""共享数据模型：工具策略（allow / deny / ask）、决策、Permission。

能力管理只有一个维度：**工具**。每个工具一条策略，三选一：

    allow   直接放行
    ask     调用前交用户确认
    deny    拒绝

不再有域（domain）、风险等级（risk_level）、确认策略（confirm）和范围
（scope）—— 那些维度要么是工具本身就能表达的信息，要么是重复的推断，
维护成本高且容易与实际执行脱节。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Policy(str, Enum):
    """工具策略：三态。"""

    ALLOW = "allow"
    ASK = "ask"
    DENY = "deny"


class Decision(int, Enum):
    """判权结果的线上编码（D-Bus 保持 0/1/2）。"""

    ALLOW = 0
    ASK = 1
    DENY = 2


# 兼容旧名：确认语义现在就是 ask。
CONFIRM = Decision.ASK

_POLICY_TO_DECISION = {
    Policy.ALLOW: Decision.ALLOW,
    Policy.ASK: Decision.ASK,
    Policy.DENY: Decision.DENY,
}


def policy_value(policy: "str | Policy") -> str:
    """归一化策略值：Policy 枚举取 .value，字符串原样。"""
    return policy.value if isinstance(policy, Policy) else str(policy)


def policy_decision(policy: "str | Policy") -> Decision:
    return _POLICY_TO_DECISION[Policy(policy_value(policy))]


@dataclass(frozen=True)
class CallerContext:
    """服务端从 D-Bus sender 推导的可信调用上下文。

    `agent_id` 不属于调用者输入的可信字段；它只能和该上下文已建立的
    绑定一起使用。PID 仅用于审计和诊断，身份比较使用 uid/exe/cgroup，
    这样 Agent 重启后不会因 PID 变化而继承或丢失错误身份。
    """

    sender: str
    uid: int
    pid: int
    executable: str = ""
    cgroup: str = ""
    session_id: str = ""
    groups: tuple[int, ...] = ()

    @property
    def is_root(self) -> bool:
        return self.uid == 0

    def identity_key(self) -> tuple[int, str, str]:
        return self.uid, self.executable, self.cgroup

    def same_identity(self, other: "CallerContext") -> bool:
        return self.identity_key() == other.identity_key()


@dataclass
class Permission:
    """一条工具策略声明：工具名 + allow/ask/deny。"""

    tool: str
    policy: Policy = Policy.ASK
    # 该工具由哪个框架提供（runtime / hermes），仅供分类展示；
    # 未声明时按调用方框架推断。
    framework: str = ""

    # 兼容旧字段名，便于渐进迁移的调用方向量构造。
    @property
    def capability(self) -> str:
        return self.tool

    def validate(self) -> None:
        if not str(self.tool).strip():
            raise ValueError("tool must not be empty")
        try:
            Policy(policy_value(self.policy))
        except ValueError as exc:
            raise ValueError(f"tool {self.tool}: 非法 policy {self.policy}") from exc

    def to_dict(self) -> dict:
        d = {"tool": self.tool, "policy": Policy(policy_value(self.policy)).value}
        if self.framework:
            d["framework"] = self.framework
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "Permission":
        try:
            tool = str(d.get("tool", d.get("capability", d.get("name", ""))) or "")
            policy = d.get("policy")
            if policy is None:
                # 兼容旧的确认策略写法：只有明确 deny 才拒绝，其余按需确认。
                legacy = str(d.get("confirm", "") or "")
                policy = Policy.DENY.value if legacy == "deny" else Policy.ASK.value
            return cls(tool=tool, policy=Policy(policy_value(policy)),
                       framework=str(d.get("framework", "") or ""))
        except (KeyError, ValueError) as e:
            raise ValueError(f"非法 Permission 字典 {d}: {e}") from e


@dataclass
class Manifest:
    """Agent 包 manifest（对齐 §4.4）。"""

    agent_id: str
    version: str
    name: str
    signature: str
    permissions: list[Permission] = field(default_factory=list)
    allowed_domains: list[str] = field(default_factory=list)
    # ``[runtime]`` is optional for legacy capability-only packages.  A
    # production PA Runtime package must provide a fixed entrypoint.
    runtime_entrypoint: tuple[str, ...] = field(default_factory=tuple)
    # Initial outbound network policy declared by the signed package.
    # Operator changes are persisted separately in network_policy.
    network_mode: str = "allow_all"
    # Which framework's tool catalog this Agent is wired to (runtime / hermes).
    # A signed package declares it so the console lists exactly that framework's
    # tools; an empty value leaves the scope unknown.
    framework: str = ""


# 兼容旧导入名：域/风险枚举已废弃，保留空壳避免历史导入立刻炸掉。
class Domain(str, Enum):
    pass


class RiskLevel(str, Enum):
    pass
