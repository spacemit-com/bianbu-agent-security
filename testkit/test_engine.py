from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys

import pytest

from testkit import engine


def test_default_security_agent_matches_runtime_session_agent():
    env = os.environ.copy()
    env.pop("BIANBU_PA_AGENT_ID", None)
    env.pop("PA_AGENT_ID", None)

    proc = subprocess.run(
        [sys.executable, "-c", (
            "from testkit.engine import AGENT_ID, PA_AGENT; "
            "assert AGENT_ID == PA_AGENT, (AGENT_ID, PA_AGENT)"
        )],
        cwd=Path(__file__).resolve().parents[1],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )

    assert proc.returncode == 0, proc.stderr


class _PromptCtx(engine.Ctx):
    def __init__(self, events_status: int = 200) -> None:
        super().__init__()
        self.events_status = events_status
        self.requests: list[tuple[str, str]] = []

    def http(self, method: str, path: str, body=None, timeout: int = 60):
        self.requests.append((method, path))
        if path == "/api/v1/sessions":
            return 201, {"data": {}}
        if path.endswith("/prompt"):
            return 202, {"data": {"run_id": "run-1"}}
        if "/events?" in path:
            if self.events_status != 200:
                return self.events_status, {"detail": "invalid event query"}
            return 200, {"data": [{
                "run_id": "run-1",
                "type": "run/completed",
                "data": {"status": "completed"},
            }]}
        raise AssertionError(f"unexpected request: {method} {path}")


def test_run_prompt_uses_supported_event_page_limit():
    ctx = _PromptCtx()

    result = ctx.run_prompt("hello", timeout=1)

    assert result["status"] == "completed"
    event_paths = [path for method, path in ctx.requests if method == "GET"]
    assert len(event_paths) == 1
    assert event_paths[0].endswith("/events?max_messages=50")


def test_run_prompt_fails_fast_when_event_query_is_rejected(monkeypatch):
    ctx = _PromptCtx(events_status=422)
    clock = iter((0.0, 0.0, 2.0))
    monkeypatch.setattr(engine.time, "time", lambda: next(clock))
    monkeypatch.setattr(engine.time, "sleep", lambda _seconds: None)

    with pytest.raises(RuntimeError, match=r"Session 事件查询失败 HTTP 422"):
        ctx.run_prompt("hello", timeout=1)


@pytest.mark.parametrize("tools,action,run_id,expected", [
    ((), "terminal", "run-1", 0),
    (("read_file",), "terminal", "run-1", 0),
    (("terminal",), "terminal", "other-run", 0),
    (("terminal",), "terminal", "run-1", 1),
])
def test_probe_approval_is_explicit_scoped_and_not_repeated(tools, action, run_id, expected):
    class ApprovalCtx(_PromptCtx):
        def __init__(self):
            super().__init__()
            self.approvals = []

        def http(self, method, path, body=None, timeout=60):
            if "/approvals/" in path:
                self.approvals.append(body)
                return 200, {"data": {"accepted": True}}
            status, response = super().http(method, path, body, timeout)
            if "/events?" in path:
                approval = {"run_id": run_id, "type": "approval/requested", "data": {
                    "approval_id": "approval-1", "actions": [{"name": action}]}}
                response["data"] = [approval, approval, *response["data"]]
            return status, response

    ctx = ApprovalCtx()
    assert ctx.run_prompt("harmless probe", timeout=1, approve_tools=tools)["status"] == "completed"
    assert len(ctx.approvals) == expected
