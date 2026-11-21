"""Subagent attribution in the Agno adapter. Shapes from a live Agno 3.1 Team
run: the leader's own call gets team only, a member running a delegated task
gets agent + team, a standalone Agent gets agent only."""
from types import SimpleNamespace
from unittest.mock import patch

import prismor_agno as pa
from prismor.runtime.runtime import Decision


def test_team_member_is_the_subagent(tmp_path):
    seen = []
    with patch("prismor_agno.evaluate_tool_call",
               lambda *, event, **kw: seen.append(event["metadata"]) or Decision(allow=True)):
        hook = pa.make_tool_hook(workspace=tmp_path, mode="enforce")
        team = SimpleNamespace(name="Coordinator")
        member = SimpleNamespace(name="Researcher")
        solo = SimpleNamespace(name="Solo")
        ok = lambda **kw: "ok"

        hook("fetch_url", ok, {"url": "a"}, agent=None, team=team)       # leader
        hook("fetch_url", ok, {"url": "b"}, agent=member, team=team)     # delegated member
        hook("fetch_url", ok, {"url": "c"}, agent=solo, team=None)       # standalone agent
        hook("fetch_url", ok, {"url": "d"})                              # no injection

        # A tool that runs another agent: its calls are a subagent's.
        inner = lambda **kw: hook("fetch_url", ok, {"url": "e"}, agent=SimpleNamespace(name="Helper"), team=None)
        hook("ask_helper", inner, {}, agent=solo, team=None)

    types = [m["subagent_type"] for m in seen]
    assert types == [None, "Researcher", None, None, None, "Helper"]
    assert seen[5]["subagent_id"].startswith("Solo:")
