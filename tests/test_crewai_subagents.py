"""guard_crew attributes delegated work to subagents (no crewai needed).

CrewAI runs a delegated task by calling the coworker's execute_task inside
the delegating agent's "Delegate work to coworker" tool, synchronously, so the
stand-ins below reproduce that nesting directly.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "adapters" / "crewai"))

import prismor_crewai as pc  # noqa: E402


class _Tool:
    def __init__(self, name):
        self.name = name

    def func(self, url):
        return f"fetched {url}"


class _Agent:
    def __init__(self, role, coworker=None):
        self.role, self.tools, self.coworker = role, [_Tool("fetch_url")], coworker

    def execute_task(self, url):
        self.tools[0].func(url)
        if self.coworker:  # delegation: runs the coworker's task inside this one
            self.coworker.execute_task(url + "/delegated")


class _Crew:
    def __init__(self, agents, process="sequential", manager=None):
        self.agents, self.process, self.manager_agent = agents, process, manager


def _spy(monkeypatch):
    seen = []
    real = pc.evaluate_tool_call

    def spy(*, event, **kw):
        seen.append(event["metadata"])
        return real(event=event, **kw)

    monkeypatch.setattr(pc, "evaluate_tool_call", spy)
    return seen


def test_sequential_crew_own_tasks_are_main_delegated_work_is_subagent(tmp_path, monkeypatch):
    seen = _spy(monkeypatch)
    writer = _Agent("Writer")
    lead = _Agent("Lead", coworker=writer)
    pc.guard_crew(_Crew([lead, writer]), workspace=tmp_path, mode="observe")

    lead.execute_task("https://a.test")    # Lead's own task, delegates to Writer
    writer.execute_task("https://b.test")  # Writer's own task in sequence

    assert [m["subagent_type"] for m in seen] == [None, "Writer", None]
    assert seen[1]["subagent_id"].startswith("Writer:")
    assert seen[2]["subagent_id"] is None


def test_hierarchical_workers_are_subagents(tmp_path, monkeypatch):
    seen = _spy(monkeypatch)
    worker = _Agent("Researcher")
    pc.guard_crew(_Crew([worker], process="hierarchical"), workspace=tmp_path, mode="observe")
    worker.execute_task("https://c.test")  # CrewAI's own manager handed it over
    assert seen[0]["subagent_type"] == "Researcher"
