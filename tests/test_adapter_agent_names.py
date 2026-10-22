"""Every adapter can name its agent, so the console gives it its own row and
controls (field test 2026-10-22: Agno and Pydantic AI reported unnamed)."""
import asyncio
import sys
from pathlib import Path

import pytest

from prismor.runtime.runtime import Decision

_ROOT = Path(__file__).resolve().parent.parent


def _adapter_path(pkg: str) -> None:
    src = str(_ROOT / "adapters" / pkg)
    if src not in sys.path:
        sys.path.insert(0, src)


def _capture(monkeypatch, module):
    seen = {}

    def fake(**kw):
        seen.update(kw)
        return Decision(allow=True, findings=[], reason="")

    monkeypatch.setattr(module, "evaluate_tool_call", fake)
    monkeypatch.setattr(module, "redact_tool_result", lambda r, **_: r)
    return seen


def test_agno_hook_sends_agent_name(monkeypatch, tmp_path):
    _adapter_path("agno")
    import prismor_agno

    seen = _capture(monkeypatch, prismor_agno)
    hook = prismor_agno.make_tool_hook(workspace=tmp_path, name="support-agno")
    assert hook("lookup_order", lambda **kw: "ok", {"order_id": "1"}) == "ok"
    assert seen["agent"] == "agno" and seen["agent_name"] == "support-agno"


def test_pydantic_ai_toolset_sends_agent_name(monkeypatch, tmp_path):
    pytest.importorskip("pydantic_ai")
    _adapter_path("pydantic-ai")
    import prismor_pydantic_ai
    from pydantic_ai.toolsets import FunctionToolset, WrapperToolset

    seen = _capture(monkeypatch, prismor_pydantic_ai)

    async def inner(self, name, tool_args, ctx, tool):
        return "ok"

    monkeypatch.setattr(WrapperToolset, "call_tool", inner)
    ts = prismor_pydantic_ai.PrismorToolset(FunctionToolset([]), workspace=tmp_path, name="support-pydantic")
    assert asyncio.run(ts.call_tool("lookup_order", {"order_id": "1"}, None, None)) == "ok"
    assert seen["agent"] == "pydantic-ai" and seen["agent_name"] == "support-pydantic"


def test_claude_agent_sdk_hook_sends_agent_name(monkeypatch, tmp_path):
    _adapter_path("claude-agent-sdk")
    import prismor_claude_agent_sdk

    seen = {}

    def fake(**kw):
        seen.update(kw)
        return Decision(allow=True, findings=[], reason="")

    monkeypatch.setattr(prismor_claude_agent_sdk, "evaluate_tool_call", fake)
    hook = prismor_claude_agent_sdk.prismor_pre_tool_use_hook(workspace=tmp_path, name="support-claude")
    out = asyncio.run(hook({"tool_name": "Bash", "tool_input": {"command": "ls"}}, "t1", {}))
    assert out == {}
    assert seen["agent"] == "claude-agent-sdk" and seen["agent_name"] == "support-claude"
