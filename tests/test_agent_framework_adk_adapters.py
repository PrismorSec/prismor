"""Microsoft Agent Framework middleware + Google ADK name=/PrismorPlugin
(no live LLM, framework not required).

Fake contexts mimic each framework's shape and run against the real Prismor
policy pipeline; conftest.py wires the adapter shims onto prismor.__path__.
"""
import asyncio
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from prismor.agent_framework import PrismorBlocked, PrismorMiddleware
from prismor.google_adk import PrismorPlugin, make_before_tool_callback

SECRET = "ghp_" + "A" * 36


def _ctx(command):
    return SimpleNamespace(function=SimpleNamespace(name="run_shell"),
                           arguments={"command": command}, result=None)


def _run(mw, ctx, body):
    async def call_next():
        ctx.result = body(ctx)
    asyncio.run(mw.process(ctx, call_next))
    return ctx.result


# ── Agent Framework ──────────────────────────────────────────────────────────

def test_maf_allows_and_runs_the_tool(tmp_path):
    ran = []
    out = _run(PrismorMiddleware(workspace=tmp_path), _ctx("echo hi"),
               lambda c: ran.append(1) or "ok")
    assert out == "ok" and ran == [1]


def test_maf_enforce_blocks_without_running_the_tool(tmp_path):
    ran = []
    out = _run(PrismorMiddleware(workspace=tmp_path), _ctx("rm -rf /"),
               lambda c: ran.append(1) or "ok")
    assert "Prismor blocked" in out and ran == []


def test_maf_raise_on_block(tmp_path):
    with pytest.raises(PrismorBlocked):
        _run(PrismorMiddleware(workspace=tmp_path, raise_on_block=True),
             _ctx("rm -rf /"), lambda c: "ok")


def test_maf_observe_never_blocks(tmp_path):
    out = _run(PrismorMiddleware(workspace=tmp_path, mode="observe"),
               _ctx("rm -rf /"), lambda c: "ok")
    assert out == "ok"


def test_maf_redacts_the_tool_result(tmp_path):
    out = _run(PrismorMiddleware(workspace=tmp_path), _ctx("cat config.yaml"),
               lambda c: f"github_token: {SECRET}")
    assert SECRET not in str(out)


def test_maf_reports_its_name_and_framework(tmp_path):
    with patch("prismor_agent_framework.evaluate_tool_call",
               return_value=SimpleNamespace(allow=True, engine=None)) as ev:
        _run(PrismorMiddleware(name="support-bot", workspace=tmp_path),
             _ctx("echo hi"), lambda c: "ok")
    kw = ev.call_args.kwargs
    assert kw["agent_name"] == "support-bot" and kw["agent"] == "agent-framework"
    assert kw["event"]["metadata"]["tool_name"] == "run_shell"


# ── Google ADK ───────────────────────────────────────────────────────────────

def test_adk_name_reaches_the_runtime(tmp_path):
    with patch("prismor_google_adk.evaluate_tool_call",
               return_value=SimpleNamespace(allow=True)) as ev:
        make_before_tool_callback(name="support-adk", workspace=tmp_path)(
            SimpleNamespace(name="run_shell"), {"command": "echo hi"}, None)
    assert ev.call_args.kwargs["agent_name"] == "support-adk"


def test_adk_plugin_blocks_and_redacts(tmp_path):
    plugin = PrismorPlugin(workspace=tmp_path, mode="enforce")
    tool = SimpleNamespace(name="run_shell")
    denied = asyncio.run(plugin.before_tool_callback(
        tool=tool, tool_args={"command": "rm -rf /"}, tool_context=None))
    assert "Prismor blocked" in denied["error"]
    assert asyncio.run(plugin.before_tool_callback(
        tool=tool, tool_args={"command": "echo hi"}, tool_context=None)) is None
    masked = asyncio.run(plugin.after_tool_callback(
        tool=tool, tool_args={}, tool_context=None, result={"result": SECRET}))
    assert SECRET not in masked["result"]
