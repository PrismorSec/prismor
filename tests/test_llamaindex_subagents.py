"""Subagent attribution in the LlamaIndex adapter. Store keys from a live
AgentWorkflow run (llama-index-core 0.14): current_agent_name starts as the
root agent; a handoff changes it and sets next_agent."""
import asyncio
from unittest.mock import patch

import pytest

pytest.importorskip("llama_index.core")  # reads the workflow step context

import prismor_llamaindex as li  # noqa: E402
from prismor.runtime.runtime import Decision


class _Store:
    def __init__(self, **kv):
        self.kv = kv

    async def get(self, k, default=None):
        return self.kv.get(k, default)


class _Ctx:
    def __init__(self, store):
        self.store = store


def _run(store, guard="support-bot"):
    with patch("workflows.Context.get_step_context", lambda: _Ctx(store)):
        return asyncio.run(li._workflow_subagent(guard))


def test_root_agent_then_handoff_target():
    store = _Store(current_agent_name="Coordinator")
    assert _run(store) == (None, None, None)
    store.kv.update(current_agent_name="Researcher", next_agent="Researcher")
    sub_id, sub_type, parent = _run(store, guard="researcher-guard")
    assert sub_type == "Researcher" and sub_id.startswith("Researcher:")
    assert parent == "support-bot"  # the root's guard: its controls apply to the handoff target
    store.kv["current_agent_name"] = "Coordinator"   # handed back
    assert _run(store) == (None, None, None)


def test_outside_a_workflow_is_the_main_agent():
    assert asyncio.run(li._workflow_subagent()) == (None, None, None)


def test_agent_run_inside_a_guarded_tool_is_a_subagent(tmp_path):
    seen = []
    with patch("prismor_llamaindex.evaluate_tool_call",
               lambda *, event, **kw: seen.append(event["metadata"]) or Decision(allow=True)):
        def fetch_url(url: str) -> str:
            """Fetch."""
            return "ok"
        inner = li.guard_tools([fetch_url], name="Summarizer", workspace=tmp_path)[0]

        def ask_summarizer(q: str) -> str:
            """Runs another agent, which calls its own tool."""
            return str(inner.call(url=q))
        outer = li.guard_tools([ask_summarizer], name="Coordinator", workspace=tmp_path)[0]
        outer.call(q="https://x.test")
    assert seen[0]["subagent_type"] is None                       # Coordinator's own call
    assert seen[1]["subagent_type"] == "Summarizer"
    assert seen[1]["subagent_id"].startswith("Coordinator:")
