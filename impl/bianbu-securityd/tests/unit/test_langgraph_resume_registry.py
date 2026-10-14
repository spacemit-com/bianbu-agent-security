from __future__ import annotations

import os
import socket
import time

import pytest


def test_resume_registry_requires_registered_graph_and_is_one_shot():
    from securityd.langgraph.resume_registry import LangGraphResumeRegistry

    reg = LangGraphResumeRegistry()
    seen = []
    reg.register("graph-1", lambda approved, item: seen.append((approved, item.run_id)),
                 run_id="run-1", agent_id="agent-1")
    reg.publish({"graph_id": "graph-1", "run_id": "run-1", "agent_id": "agent-1",
                 "tool_name": "write", "capability": "file.write", "message": "confirm"})
    result = reg.resume("graph-1", True, run_id="run-1", agent_id="agent-1")
    assert result["approved"] is True and seen == [(True, "run-1")]
    with pytest.raises(KeyError):
        reg.resume("graph-1", False, run_id="run-1")


def test_resume_registry_rejects_wrong_run_and_unregistered_graph():
    from securityd.langgraph.resume_registry import LangGraphResumeRegistry

    reg = LangGraphResumeRegistry()
    reg.register("graph-2", lambda *_: None, run_id="run-2", agent_id="agent-2")
    reg.publish({"graph_id": "graph-2", "run_id": "run-2", "agent_id": "agent-2"})
    with pytest.raises(PermissionError):
        reg.resume("graph-2", True, run_id="other")
    with pytest.raises(PermissionError):
        reg.resume("graph-2", True, run_id="run-2", agent_id="other")

    unregistered = LangGraphResumeRegistry()
    with pytest.raises(RuntimeError):
        unregistered.publish({"graph_id": "missing", "run_id": "run"})


def test_publish_same_run_is_idempotent_and_other_run_is_rejected():
    from securityd.langgraph.resume_registry import LangGraphResumeRegistry

    reg = LangGraphResumeRegistry()
    reg.register("graph-3", lambda *_: None, run_id="run-3", agent_id="agent-3")
    first = reg.publish({"graph_id": "graph-3", "run_id": "run-3", "agent_id": "agent-3"})
    assert reg.publish({"graph_id": "graph-3", "run_id": "run-3", "agent_id": "agent-3"}) == first
    with pytest.raises(RuntimeError):
        reg.publish({"graph_id": "graph-3", "run_id": "other", "agent_id": "agent-3"})


def test_cross_process_unix_broker_lists_and_resumes_real_graph(tmp_path):
    from securityd.langgraph.resume_registry import LangGraphResumeRegistry

    socket_path = tmp_path / "agent.sock"
    owner = LangGraphResumeRegistry(socket_dir=tmp_path)
    seen = []
    owner.register("graph-remote", lambda approved, item: seen.append((approved, item.run_id)),
                   run_id="run-remote", agent_id="agent-remote", socket_path=socket_path)
    owner.publish({"graph_id": "graph-remote", "run_id": "run-remote",
                   "agent_id": "agent-remote", "tool_name": "write"})

    # WebUI 侧没有 graph 实例，仅持有 broker 地址并调用 RPC。
    webui = LangGraphResumeRegistry(socket_dir=tmp_path)
    rows = webui.list_pending()
    assert rows and rows[0]["graph_id"] == "graph-remote"
    result = webui.resume("graph-remote", False, run_id="run-remote", agent_id="agent-remote")
    assert result["approved"] is False
    assert seen == [(False, "run-remote")]
    assert owner.list_pending() == []
    owner.stop_broker()


def test_cross_process_broker_calls_real_update_state(tmp_path):
    from securityd.langgraph.resume_registry import LangGraphResumeRegistry

    class FakeGraph:
        def __init__(self):
            self.calls = []

        def update_state(self, config, *, values, as_node):
            self.calls.append((config, values, as_node))
            return {"resumed": values["approved"]}

    graph = FakeGraph()
    owner = LangGraphResumeRegistry(socket_dir=tmp_path)
    owner.register("graph-update", graph, config={"configurable": {"thread_id": "t1"}},
                   run_id="run-update", agent_id="agent-update", socket_path=tmp_path / "update.sock")
    owner.publish({"graph_id": "graph-update", "run_id": "run-update",
                   "agent_id": "agent-update", "message": "confirm"})
    webui = LangGraphResumeRegistry(socket_dir=tmp_path)
    result = webui.resume("graph-update", True, run_id="run-update", agent_id="agent-update")
    assert result["result"] == {"resumed": True}
    assert graph.calls == [({"configurable": {"thread_id": "t1"}},
                            {"approved": True}, "__interrupt__")]
    owner.stop_broker()


def test_broker_does_not_overwrite_regular_file(tmp_path):
    from securityd.langgraph.resume_registry import LangGraphResumeRegistry

    path = tmp_path / "not-a-socket"
    path.write_text("do not overwrite")
    with pytest.raises(RuntimeError):
        LangGraphResumeRegistry().start_broker(path)
    assert path.read_text() == "do not overwrite"


def test_broker_optional_token_rejects_missing_and_accepts_matching(tmp_path):
    from securityd.langgraph.resume_registry import LangGraphResumeRegistry

    owner = LangGraphResumeRegistry(socket_dir=tmp_path, broker_token="secret")
    owner.register("graph-token", lambda *_: None, run_id="run-token",
                   agent_id="agent-token", socket_path=tmp_path / "token.sock")
    owner.publish({"graph_id": "graph-token", "run_id": "run-token", "agent_id": "agent-token"})
    denied = LangGraphResumeRegistry(socket_dir=tmp_path, broker_token="wrong")
    assert denied.list_pending() == []
    with pytest.raises(PermissionError):
        denied.resume("graph-token", True, run_id="run-token", agent_id="agent-token")
    allowed = LangGraphResumeRegistry(socket_dir=tmp_path, broker_token="secret")
    assert allowed.resume("graph-token", True, run_id="run-token", agent_id="agent-token")["approved"]
    owner.stop_broker()
