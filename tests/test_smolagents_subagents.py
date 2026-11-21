"""guard_agent attributes a managed agent's tool calls to that subagent (no smolagents needed)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "adapters" / "smolagents"))

import prismor_smolagents as ps  # noqa: E402


class _Tool:
    def __init__(self):
        self.name = "fetch_url"

    def forward(self, url):
        return f"fetched {url}"


class _Agent:
    def __init__(self, name, managed=()):
        self.name, self.tools = name, {"fetch_url": _Tool()}
        self.managed_agents = {m.name: m for m in managed}  # smolagents keeps a name -> agent dict


def test_managed_agents_tools_are_subagent_calls(tmp_path, monkeypatch):
    seen = []
    real = ps.evaluate_tool_call
    monkeypatch.setattr(ps, "evaluate_tool_call",
                        lambda *, event, **kw: seen.append(event["metadata"]) or real(event=event, **kw))
    web = _Agent("web_search")
    manager = _Agent("manager", managed=[web])
    ps.guard_agent(manager, workspace=tmp_path, mode="observe")

    manager.tools["fetch_url"].forward("https://a.test")
    web.tools["fetch_url"].forward("https://b.test")

    assert seen[0]["subagent_type"] is None and seen[0]["subagent_id"] is None
    assert seen[1]["subagent_type"] == "web_search"
    assert seen[1]["subagent_id"].startswith("web_search-")
