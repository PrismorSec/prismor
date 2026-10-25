import asyncio

from prismor.runtime.subagent_context import nested_subagent, running


def test_nested_call_reports_the_launching_call():
    assert nested_subagent("main") == (None, None)
    with running("main", "c1"):
        assert nested_subagent("researcher") == ("main:c1", "researcher")
    assert nested_subagent("main") == (None, None)


def test_follows_asyncio_tasks():
    async def inner():
        return nested_subagent("researcher")

    async def outer():
        with running("main", "c2"):
            return await asyncio.create_task(inner())

    assert asyncio.run(outer()) == ("main:c2", "researcher")


def test_chain_tracks_nesting():
    from prismor.runtime.subagent_context import current_chain
    assert current_chain() == ()
    with running("main", "c1", agent_name="support-bot"):
        with running("support-bot", "c2"):  # the same agent again is not a level
            assert current_chain() == ("support-bot",)
        with running("researcher", "c3"):
            with running("summarizer", "c4"):
                assert current_chain() == ("support-bot", "researcher", "summarizer")
    assert current_chain() == ()


def test_eval_server_takes_depth_and_chain():
    from prismor.runtime.eval_server import _build_event
    meta = _build_event(tool_name="lookup", arguments={}, event_type="shell", agent="a", session_id="s", subagent={"id": "s:1", "type": "summarizer", "parent": "support-bot",
                                                "depth": 2, "chain": ["support-bot", "researcher"]})["metadata"]
    assert meta["subagent_depth"] == 2 and meta["subagent_chain"] == ["support-bot", "researcher"]
    meta = _build_event(tool_name="lookup", arguments={}, event_type="shell", agent="a", session_id="s", subagent={"id": "s:1", "depth": "9"})["metadata"]
    assert "subagent_depth" not in meta  # not an int: the runtime derives it
