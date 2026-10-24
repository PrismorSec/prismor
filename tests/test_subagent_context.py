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
