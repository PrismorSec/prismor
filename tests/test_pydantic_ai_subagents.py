"""PrismorToolset attributes an agent run inside a guarded tool to a subagent.

Pydantic AI delegates by awaiting another agent's run from inside a tool, so
the inner toolset's call_tool runs inside the outer one's. Uses real
pydantic_ai when installed, else a minimal stand-in for WrapperToolset.
"""
import asyncio
import sys
import types
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "adapters" / "pydantic-ai"))

try:
    import pydantic_ai.toolsets  # noqa: F401
except ImportError:
    class _Wrapper:
        def __init__(self, wrapped):
            self.wrapped = wrapped

        async def call_tool(self, name, tool_args, ctx, tool):
            return await self.wrapped.call_tool(name, tool_args, ctx, tool)

    pkg = types.ModuleType("pydantic_ai")
    pkg.toolsets = types.SimpleNamespace(WrapperToolset=_Wrapper)
    pkg.exceptions = types.SimpleNamespace(ToolFailed=type("ToolFailed", (Exception,), {}))
    _stub = {"pydantic_ai": pkg, "pydantic_ai.toolsets": pkg.toolsets,
             "pydantic_ai.exceptions": pkg.exceptions}
    sys.modules.update(_stub)
    import prismor_pydantic_ai as pp  # noqa: E402
    # Unregister the stand-in (and this stub-built adapter) so other tests
    # that importorskip pydantic_ai still skip.
    for _m in (*_stub, "prismor_pydantic_ai"):
        sys.modules.pop(_m, None)
else:
    import prismor_pydantic_ai as pp  # noqa: E402


class _Inner:
    def __init__(self, fn):
        self.fn = fn

    async def call_tool(self, name, tool_args, ctx, tool):
        return await self.fn(tool_args)


def test_agent_run_inside_a_tool_is_a_subagent(tmp_path, monkeypatch):
    seen = []
    real = pp.evaluate_tool_call
    monkeypatch.setattr(pp, "evaluate_tool_call",
                        lambda *, event, **kw: seen.append(event["metadata"]) or real(event=event, **kw))
    ctx = lambda cid: types.SimpleNamespace(run_id=None, tool_call_id=cid)  # noqa: E731

    async def fetch(args):
        return "fetched"

    researcher = pp.PrismorToolset(_Inner(fetch), name="researcher", workspace=tmp_path, mode="observe")

    async def ask_researcher(args):  # the researcher agent's run, calling its own tool
        return await researcher.call_tool("fetch_url", {"url": "https://b.test"}, ctx("inner"), None)

    main = pp.PrismorToolset(_Inner(fetch), name="support-bot", workspace=tmp_path, mode="observe")
    delegate = pp.PrismorToolset(_Inner(ask_researcher), name="support-bot", workspace=tmp_path, mode="observe")

    async def run():
        await main.call_tool("fetch_url", {"url": "https://a.test"}, ctx("c1"), None)
        await delegate.call_tool("ask_researcher", {"q": "x"}, ctx("c2"), None)

    asyncio.run(run())
    by_tool = [(m["tool_name"], m["subagent_type"], m["subagent_id"]) for m in seen]
    assert by_tool == [
        ("fetch_url", None, None),
        ("ask_researcher", None, None),
        ("fetch_url", "researcher", "support-bot:c2"),
    ]
