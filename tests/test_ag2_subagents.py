"""AG2 0.x guard_agent: an agent run inside a guarded function is a subagent (no ag2 needed)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "adapters" / "ag2"))

import prismor_ag2 as pa  # noqa: E402


class _Executor:
    def __init__(self, fmap):
        self._function_map = fmap


def test_agent_run_inside_a_function_is_a_subagent(tmp_path, monkeypatch):
    seen = []
    real = pa.evaluate_tool_call
    monkeypatch.setattr(pa, "evaluate_tool_call",
                        lambda *, event, **kw: seen.append(event["metadata"]) or real(event=event, **kw))
    researcher = _Executor({"fetch_url": lambda url: f"fetched {url}"})
    pa.guard_agent(researcher, name="researcher", workspace=tmp_path, mode="observe")
    main = _Executor({
        "fetch_url": lambda url: f"fetched {url}",
        # e.g. initiate_chat with the researcher, whose executor runs its function
        "ask_researcher": lambda q: researcher._function_map["fetch_url"](url=q),
    })
    pa.guard_agent(main, name="support-bot", workspace=tmp_path, mode="observe")

    main._function_map["fetch_url"](url="https://a.test")
    main._function_map["ask_researcher"](q="https://b.test")

    got = [(m["tool_name"], m["subagent_type"]) for m in seen]
    assert got == [("fetch_url", None), ("ask_researcher", None), ("fetch_url", "researcher")]
    assert seen[2]["subagent_id"].startswith("support-bot:")
