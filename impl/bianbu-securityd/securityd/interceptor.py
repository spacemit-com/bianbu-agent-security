"""干预点框架 — InterceptorRegistry + 8 个标准切面。

按 SEC-HOOK-01~05 需求实现：
- 8 个干预点：agent_startup / input / pre_model_call / post_model_call /
  pre_tool_call / post_tool_call / output / agent_shutdown
- 可插拔 handler 注册（按优先级排序，10=SEC capability，50=DLP，90=Audit）
- 短路与决策合并：BLOCK 短路，MODIFY 链式，CONFIRM > ALLOW
- 审计透明（每个 handler 执行延迟记录）
"""
from __future__ import annotations

import logging
import os
import time
from concurrent.futures import Future, ThreadPoolExecutor
from concurrent.futures import TimeoutError as _FutureTimeout
from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable, Optional

logger = logging.getLogger("securityd.interceptor")

# handler 异常/超时的处置策略。修复前 handler 异常只记 trace 并继续，最终决策仍为
# ALLOW —— DLP/判权 handler 崩溃或挂死即等于静默放行（cc-tester 缺陷 R-1 / R-2）。
# 取向与 D-4/D-5 一致：不确定时交给人（confirm）；治理型 handler 显式注册为 block。
_ON_ERROR_POLICIES = ("allow", "confirm", "block")
_ON_ERROR_DEFAULT = "confirm"
_HANDLER_TIMEOUT_DEFAULT = 12.0  # 秒；须小于插件 hook 的外层超时（15s / 35s）


def default_on_error() -> str:
    value = (os.environ.get("BIANBU_HOOK_ON_ERROR") or "").strip().lower()
    if value == "allow" and (os.environ.get("BIANBU_RUNTIME_MODE", "")
                             .strip().lower() == "production"):
        # 生产模式不允许用环境变量把 handler 故障变成全放行。
        return _ON_ERROR_DEFAULT
    return value if value in _ON_ERROR_POLICIES else _ON_ERROR_DEFAULT


def default_handler_timeout() -> float:
    raw = (os.environ.get("BIANBU_HOOK_HANDLER_TIMEOUT") or "").strip()
    try:
        value = float(raw) if raw else _HANDLER_TIMEOUT_DEFAULT
    except ValueError:
        value = _HANDLER_TIMEOUT_DEFAULT
    return max(0.0, value)

__all__ = [
    "default_handler_timeout",
    "default_on_error",
    "HookPoint",
    "Decision",
    "InterceptResult",
    "InterceptorRegistry",
    "global_registry",
]


class HookPoint(str, Enum):
    """8 个标准干预点（生命周期顺序）。"""

    AGENT_STARTUP = "agent_startup"
    INPUT = "input"
    PRE_MODEL_CALL = "pre_model_call"
    POST_MODEL_CALL = "post_model_call"
    PRE_TOOL_CALL = "pre_tool_call"
    POST_TOOL_CALL = "post_tool_call"
    OUTPUT = "output"
    AGENT_SHUTDOWN = "agent_shutdown"


class Decision(str, Enum):
    """决策码（与 CheckPermission 的 0/1/2 对应）。"""

    ALLOW = "ALLOW"  # 0
    CONFIRM = "CONFIRM"  # 1
    BLOCK = "BLOCK"  # 2 — DENY 的同义词
    MODIFY = "MODIFY"  # 修改内容（链式传递）


@dataclass
class InterceptResult:
    """Handler 返回值（统一结构）。"""

    decision: Decision = Decision.ALLOW
    message: str = ""  # BLOCK 时的拒绝理由 / MODIFY 时的变更说明
    modified_data: Optional[Any] = None  # MODIFY 时的新数据（下游 handler 接收）
    metadata: dict = None  # 附加信息（如 DLP 检测到的 PII 类型）

    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}


# Handler 签名：(agent_id, hook_point, data, **context) -> InterceptResult
InterceptHandler = Callable[[str, HookPoint, Any, dict], InterceptResult]


@dataclass
class _Registered:
    priority: int
    name: str
    handler: InterceptHandler
    on_error: Optional[str] = None       # None → registry 默认（env BIANBU_HOOK_ON_ERROR）
    timeout_seconds: Optional[float] = None  # None → registry 默认；0 → 不限时


class _HandlerTimeout(Exception):
    """handler 超过 timeout_seconds 未返回。"""


class InterceptorRegistry:
    """可插拔 handler 注册表。

    每个 hook_point 维护一个按优先级排序的 handler 列表；
    执行时按序调用，BLOCK 短路，MODIFY 链式传递。
    """

    def __init__(self, *, on_error: Optional[str] = None,
                 handler_timeout: Optional[float] = None):
        # {hook_point: [_Registered, ...]}
        self._handlers: dict[HookPoint, list[_Registered]] = {
            hp: [] for hp in HookPoint
        }
        if on_error is not None and on_error not in _ON_ERROR_POLICIES:
            raise ValueError(f"on_error must be one of {_ON_ERROR_POLICIES}")
        self._on_error = on_error
        self._handler_timeout = handler_timeout
        # 限时执行用的线程池。DLP policy store 等使用 thread-local sqlite 连接，
        # 复用线程可避免每次调用都新建连接；超时的 handler 会占住一个 worker
        # 直到其自身返回（D-Bus/UDS 有各自超时），池子随后自动恢复。
        self._executor: Optional[ThreadPoolExecutor] = None
        # 审计 sink：链执行完后回调，签名 (hook_point, agent_id, decision, trace)
        # 由 client 层注入，框架本身不依赖审计模块
        self._audit_sink: Optional[Callable[..., None]] = None

    def set_audit_sink(self, sink: Optional[Callable[..., None]]) -> None:
        """设置审计 sink（SEC-HOOK-05）。传 None 关闭。

        sink 在每条 handler 链执行完后被调用一次，拿到完整 trace。
        handler 本身看不到完整 trace（链是增量构建的），故必须由框架回调。
        sink 抛异常不影响主流程。
        """
        self._audit_sink = sink

    def _emit_audit(
        self, hook_point: HookPoint, agent_id: str, decision: Decision, trace: list
    ) -> None:
        if self._audit_sink is None:
            return
        try:
            self._audit_sink(hook_point, agent_id, decision, trace)
        except Exception:  # noqa: BLE001 — 审计失败不阻断治理链
            pass

    def register(
        self,
        hook_point: HookPoint,
        handler: InterceptHandler,
        name: str,
        priority: int = 50,
        *,
        on_error: Optional[str] = None,
        timeout_seconds: Optional[float] = None,
    ):
        """注册 handler。

        优先级越小越先执行（10=SEC capability，50=DLP，90=Audit）。
        同优先级按注册顺序。

        on_error：该 handler 异常/超时时的处置 —— "block"（治理型 handler，
        fail-closed）、"confirm"（默认，交给人）、"allow"（仅审计型 handler）。
        timeout_seconds：单个 handler 允许的最长执行时间；None 用 registry 默认，
        0 表示不限时（仅测试或明确无阻塞 I/O 的 handler 使用）。
        """
        if on_error is not None and on_error not in _ON_ERROR_POLICIES:
            raise ValueError(f"on_error must be one of {_ON_ERROR_POLICIES}")
        handlers = self._handlers[hook_point]
        handlers.append(_Registered(priority, name, handler, on_error, timeout_seconds))
        # 排序：优先级升序，同优先级保持注册顺序（stable sort）
        handlers.sort(key=lambda t: t.priority)

    def unregister(self, hook_point: HookPoint, name: str) -> bool:
        """注销 handler（按名称）。"""
        handlers = self._handlers[hook_point]
        before = len(handlers)
        self._handlers[hook_point] = [h for h in handlers if h.name != name]
        return len(self._handlers[hook_point]) < before

    def _effective_on_error(self, entry: _Registered) -> str:
        return entry.on_error or self._on_error or default_on_error()

    def _effective_timeout(self, entry: _Registered) -> float:
        if entry.timeout_seconds is not None:
            return max(0.0, float(entry.timeout_seconds))
        if self._handler_timeout is not None:
            return max(0.0, float(self._handler_timeout))
        return default_handler_timeout()

    def _pool(self) -> ThreadPoolExecutor:
        if self._executor is None:
            self._executor = ThreadPoolExecutor(
                max_workers=int(os.environ.get("BIANBU_HOOK_WORKERS", "16") or 16),
                thread_name_prefix="hook")
        return self._executor

    def _run_handler(self, entry: _Registered, timeout: float, agent_id: str,
                     hook_point: HookPoint, data: Any, context: dict) -> InterceptResult:
        """执行单个 handler；timeout>0 时在线程池中运行并限时等待。

        超时的 handler 无法被强制终止，只能放弃其结果；调用方按 on_error 策略
        处置，并在 trace 中标记 TIMEOUT，便于定位慢 handler。
        """
        if timeout <= 0:
            return entry.handler(agent_id, hook_point, data, context)
        future: Future = self._pool().submit(entry.handler, agent_id, hook_point, data, context)
        try:
            return future.result(timeout=timeout)
        except _FutureTimeout as exc:
            raise _HandlerTimeout(f"{entry.name} exceeded {timeout:g}s") from exc

    def invoke(
        self,
        hook_point: HookPoint,
        agent_id: str,
        data: Any,
        **context: Any,
    ) -> InterceptResult:
        """执行 hook_point 的全部 handler（按优先级）。

        短路规则：任一 handler 返回 BLOCK → 立即停止，返回 BLOCK
        链式规则：MODIFY 的 modified_data 传给下一 handler 作为 data
        合并规则：CONFIRM > ALLOW（只要有一个 CONFIRM，最终决策=CONFIRM）
        审计透明：记录每个 handler 执行延迟到 result.metadata["_handler_trace"]
        """
        handlers = self._handlers[hook_point]
        # YOLO 仅由能力判权层处理，通用干预链必须保留 DLP 与失败策略。
        if not handlers:
            # 空 hook_point 也返回 trace 键，调用方无需判空；不发审计（无治理动作）
            return InterceptResult(
                decision=Decision.ALLOW, metadata={"_handler_trace": []}
            )

        current_data = data
        final_decision = Decision.ALLOW
        modified = False  # 是否有 handler 改写过数据
        trace = []  # [(name, latency_ms, decision), ...]
        messages = []
        merged_meta: dict = {}  # 各 handler 的 metadata 按序合并

        for entry in handlers:
            name = entry.name
            t0 = time.perf_counter()
            try:
                result = self._run_handler(entry, self._effective_timeout(entry),
                                           agent_id, hook_point, current_data, context)
                if not isinstance(result, InterceptResult):
                    raise TypeError(f"{name} returned {type(result).__name__}, not InterceptResult")
                latency_ms = (time.perf_counter() - t0) * 1000
                trace.append((name, latency_ms, result.decision.value))

                # 合并 handler 的 metadata（后者覆盖前者的同名键）。
                # 不合并的话调用方只能拿到 _handler_trace，看不到任何 handler
                # 的判定细节（pii_types / is_cloud / cloud_forced_mask 等），
                # 而 WebUI 统计与审计都依赖这些字段。
                if result.metadata:
                    merged_meta.update(
                        {k: v for k, v in result.metadata.items()
                         if k != "_handler_trace"})

                # 短路：BLOCK 立即停止
                if result.decision == Decision.BLOCK:
                    # BLOCK 短路也要带上此前 handler 的 metadata
                    merged_meta["_handler_trace"] = trace
                    result.metadata = merged_meta
                    self._emit_audit(hook_point, agent_id, Decision.BLOCK, trace)
                    return result

                # 合并决策：CONFIRM > ALLOW
                if result.decision == Decision.CONFIRM:
                    final_decision = Decision.CONFIRM

                # 链式传递：MODIFY 的 modified_data 作为下游 data
                if result.decision == Decision.MODIFY and result.modified_data is not None:
                    current_data = result.modified_data
                    modified = True

                # 收集消息
                if result.message:
                    messages.append(f"{name}: {result.message}")

            except Exception as e:
                # handler 异常/超时：按 on_error 策略处置，绝不静默放行（R-1/R-2）。
                latency_ms = (time.perf_counter() - t0) * 1000
                kind = "handler_timeout" if isinstance(e, _HandlerTimeout) else "handler_error"
                label = "TIMEOUT" if kind == "handler_timeout" else "ERROR"
                policy = self._effective_on_error(entry)
                trace.append((name, latency_ms, f"{label}: {e}"))
                merged_meta.setdefault("handler_errors", []).append({
                    "handler": name, "kind": kind, "policy": policy,
                    "error": f"{type(e).__name__}: {e}"[:512],
                })
                logger.warning("hook %s handler %s %s（policy=%s）：%s",
                               hook_point.value, name, kind, policy, e)
                if policy == "block":
                    merged_meta["_handler_trace"] = trace
                    merged_meta["reason"] = kind
                    merged_meta["failed_handler"] = name
                    blocked = InterceptResult(
                        decision=Decision.BLOCK,
                        message=f"[bianbu-security] 安全 handler {name} {kind}，按 fail-closed 拒绝：{e}",
                        metadata=merged_meta,
                    )
                    self._emit_audit(hook_point, agent_id, Decision.BLOCK, trace)
                    return blocked
                if policy == "confirm":
                    final_decision = Decision.CONFIRM
                    messages.append(f"{name}: {kind}，需人工确认")

        # 合并决策。优先级：BLOCK（已短路） > CONFIRM > MODIFY > ALLOW。
        # MODIFY 必须体现在最终决策里 —— 否则调用方只看到 ALLOW，
        # 不知道数据被改写过（DLP-03 脱敏后调用方需据此改用脱敏文本）。
        if final_decision == Decision.ALLOW and modified:
            final_decision = Decision.MODIFY

        merged_meta["_handler_trace"] = trace
        final_result = InterceptResult(
            decision=final_decision,
            message=" | ".join(messages) if messages else "",
            modified_data=current_data if modified else None,
            metadata=merged_meta,
        )
        self._emit_audit(hook_point, agent_id, final_decision, trace)
        return final_result

    def list_handlers(self, hook_point: HookPoint) -> list[tuple[int, str]]:
        """列出 hook_point 注册的 handler（[(priority, name), ...]）。"""
        return [(h.priority, h.name) for h in self._handlers[hook_point]]

    def describe_handlers(self, hook_point: HookPoint) -> list[dict]:
        """列出 handler 及其生效的故障策略与超时（供 doctor/WebUI 展示）。"""
        return [{"priority": h.priority, "name": h.name,
                 "on_error": self._effective_on_error(h),
                 "timeout_seconds": self._effective_timeout(h)}
                for h in self._handlers[hook_point]]


# 全局单例
global_registry = InterceptorRegistry()
