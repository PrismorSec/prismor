"""PrismorInterventionHandler attributes FunctionCalls by their sending agent.

Shapes from a live SingleThreadedAgentRuntime run: a "lead" agent and a
"researcher" agent each send FunctionCall to a ToolAgent; on_send gets
message_context.sender = AgentId(type, key).
"""
import asyncio
import sys
from pathlib import Path

import pytest

pytest.importorskip("autogen_core")
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "adapters" / "autogen-core"))

from autogen_core import AgentId, CancellationToken, FunctionCall, MessageContext  # noqa: E402

import prismor_autogen_core as pac  # noqa: E402


def _ctx(agent_type):
    return MessageContext(sender=AgentId(agent_type, "default"), topic_id=None, is_rpc=True,
                          cancellation_token=CancellationToken(), message_id="m")


@pytest.mark.parametrize("main_agent", [None, "lead"])
def test_main_agent_unattributed_other_senders_are_subagents(tmp_path, monkeypatch, main_agent):
    seen = []
    real = pac.evaluate_tool_call
    monkeypatch.setattr(pac, "evaluate_tool_call",
                        lambda *, event, **kw: seen.append(event["metadata"]) or real(event=event, **kw))
    h = pac.PrismorInterventionHandler(workspace=tmp_path, mode="observe", main_agent=main_agent)
    call = FunctionCall("c1", '{"url": "https://a.test"}', "fetch_url")
    tool_agent = AgentId("tool_executor", "default")

    async def run():
        await h.on_send(call, message_context=_ctx("lead"), recipient=tool_agent)
        await h.on_send(call, message_context=_ctx("researcher"), recipient=tool_agent)
        await h.on_send(call, message_context=_ctx("lead"), recipient=tool_agent)

    asyncio.run(run())
    assert [(m["subagent_id"], m["subagent_type"]) for m in seen] == [
        (None, None), ("researcher/default", "researcher"), (None, None)]
