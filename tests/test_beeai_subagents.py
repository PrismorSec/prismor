"""Subagent attribution in the BeeAI adapter (beeai-framework 0.1.85, live
verified). A HandoffTool runs its target agent inside its own call, on a clone
of that agent whose tools are clones: the guard must survive the clone, and
the target's calls are reported as subagent <target name>."""
import asyncio
from types import SimpleNamespace
from unittest.mock import patch

import pytest

pytest.importorskip("beeai_framework")
from beeai_framework.tools import tool  # noqa: E402

import prismor_beeai as pb  # noqa: E402
from prismor.runtime.runtime import Decision  # noqa: E402


def _fetch():
    @tool
    def fetch_url(url: str) -> str:
        """Fetch a URL."""
        return "ok"
    return fetch_url


class _Handoff:
    """HandoffTool's shape: runs a clone of the target agent's tool inside its own call."""
    name = "researcher"

    def __init__(self, target_tool):
        self._target = SimpleNamespace(meta=SimpleNamespace(name="Researcher"))
        self._inner = target_tool

    async def _run(self, input, options, context):
        cloned = await self._inner.clone()
        return await cloned._run(cloned.input_schema(url="https://x.test"), None, SimpleNamespace(run_id="r2"))

    async def clone(self):
        return self


def test_handoff_target_is_a_subagent_and_the_clone_stays_guarded(tmp_path):
    seen = []
    with patch("prismor_beeai.evaluate_tool_call",
               lambda *, event, **kw: seen.append(event["metadata"]) or Decision(allow=True)):
        own = pb.guard_tool(_fetch(), workspace=tmp_path)
        researcher_tool = pb.guard_tool(_fetch(), workspace=tmp_path)
        handoff = pb.guard_tool(_Handoff(researcher_tool), workspace=tmp_path)

        asyncio.run(own._run(own.input_schema(url="a"), None, SimpleNamespace(run_id="r0")))
        asyncio.run(handoff._run(SimpleNamespace(task="t"), None, SimpleNamespace(run_id="r1")))

    names = [(m["tool_name"], m["subagent_type"]) for m in seen]
    assert names == [("fetch_url", None), ("researcher", None), ("fetch_url", "Researcher")]
    assert seen[2]["subagent_id"] == "beeai:r1"  # the handoff call (by the main agent) that ran it
    assert seen[1].get("handoff_to") == "Researcher" and "handoff_to" not in seen[0]


def test_clone_is_guarded(tmp_path):
    t = pb.guard_tool(_fetch(), workspace=tmp_path)
    assert getattr(asyncio.run(t.clone()), "__prismor_guarded__", False)
