"""SDK adapter calls are typed from the tool name and its structured arguments,
and every framework's non-FunctionTool surface goes through policy."""
import asyncio
import json
import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1]
for _rel in ("adapters/langchain", "adapters/crewai", "adapters/openai-agents", "adapters/browser-use"):
    if str(_ROOT / _rel) not in sys.path:
        sys.path.insert(0, str(_ROOT / _rel))

from prismor.runtime.runtime import _retype_adapter_file_call  # noqa: E402


def _typed(tool, kwargs, kind="shell"):
    ev = {"type": kind, "command": " ".join(map(str, kwargs.values())),
          "metadata": {"framework": "x", "tool_name": tool, "kwargs": kwargs}}
    _retype_adapter_file_call(ev)
    return ev


def test_url_argument_is_network_with_the_rest_as_payload():
    ev = _typed("fetch", {"url": "https://api.example.com/x", "headers": {"A": "b"}})
    assert (ev["type"], ev["url"]) == ("network", "https://api.example.com/x")
    assert '"A"' in ev["outbound_payload"] and "command" not in ev


def test_download_and_upload_are_not_reads_by_load():
    assert _typed("download_file", {"url": "https://e.com/f", "path": "/tmp/f"})["type"] == "shell"
    up = _typed("upload_file", {"path": "/home/u/.ssh/id_rsa", "index": 3})
    assert (up["type"], up["path"]) == ("file_read", "/home/u/.ssh/id_rsa")


def test_path_and_content_is_a_write_with_content():
    ev = _typed("tool", {"file_name": "n.txt", "content": "BODY"})
    assert (ev["type"], ev["path"], ev["content"]) == ("file_write", "n.txt", "BODY")


def test_explicit_type_gets_fields_not_the_joined_payload():
    ev = _typed("save", {"path": "a.txt", "content": "b"}, kind="file_write")
    assert (ev["path"], ev["content"]) == ("a.txt", "b")


def test_command_argument_stays_shell():
    assert _typed("run", {"command": "ls", "url": "https://x"})["type"] == "shell"


def test_handoff_and_delegation_are_subagent_spawn():
    h = _typed("transfer_to_billing", {"reason": "refund please"})
    assert (h["type"], h["subagent_type"], h["prompt"]) == ("subagent_spawn", "billing", "refund please")
    d = _typed("Delegate work to coworker", {"task": "t", "context": "c", "coworker": "Writer"})
    assert (d["type"], d["subagent_type"], d["prompt"]) == ("subagent_spawn", "Writer", "t\nc")


def test_hook_events_untouched():
    ev = {"type": "shell", "command": "x", "metadata": {"tool_name": "fetch", "kwargs": {"url": "https://e"}}}
    _retype_adapter_file_call(ev)
    assert ev["type"] == "shell"


# ── adapters ─────────────────────────────────────────────────────────────────

def test_langchain_guards_a_run_only_tool(tmp_path, monkeypatch):
    monkeypatch.setenv("PRISMOR_HOME", str(tmp_path / "home"))
    from prismor_langchain import prismor_guard_tool

    class ShellLike:  # a BaseTool subclass: no func/coroutine, body in _run
        name = "terminal"
        def _run(self, commands, run_manager=None):
            return "RAN"

    tool = prismor_guard_tool(ShellLike(), workspace=str(tmp_path), mode="enforce")
    assert tool.__prismor_guarded__
    assert tool._run("rm -rf /", run_manager=object()) != "RAN"
    assert tool._run("echo hi", run_manager=None) == "RAN"


def test_langchain_nothing_to_wrap_is_not_marked():
    from prismor_langchain import prismor_guard_tool

    class Empty:
        name = "x"

    assert not getattr(prismor_guard_tool(Empty()), "__prismor_guarded__", False)


def test_crewai_evaluates_once(tmp_path, monkeypatch):
    monkeypatch.setenv("PRISMOR_HOME", str(tmp_path / "home"))
    import prismor_crewai
    calls = []
    real = prismor_crewai._evaluate
    monkeypatch.setattr(prismor_crewai, "_evaluate", lambda **kw: calls.append(1) or real(**kw))

    class Tool:  # CrewAI's Tool: _run calls func
        name = "echo"
        def func(self, text):
            return text
        def _run(self, text):
            return self.func(text)

    tool = prismor_crewai.prismor_guard_tool(Tool(), workspace=str(tmp_path))
    assert tool._run("hi") == "hi" and len(calls) == 1


def _openai_opts(tmp_path):
    return dict(subject=None, workspace=str(tmp_path), agent="openai-agents", name="",
                mode="enforce", session_id="s", approvals=False)


def test_openai_local_shell_executor_and_editor(tmp_path, monkeypatch):
    monkeypatch.setenv("PRISMOR_HOME", str(tmp_path / "home"))
    from types import SimpleNamespace as NS
    from prismor_openai import _guard_runtime_surfaces

    class LocalShellTool:
        name = "local_shell"
        def __init__(self):
            self.executor = lambda req: "RAN"

    class ApplyPatchTool:
        name = "apply_patch"
        def __init__(self):
            self.editor = NS(create_file=lambda op: "WROTE")

    shell, patch = LocalShellTool(), ApplyPatchTool()
    _guard_runtime_surfaces(NS(tools=[shell, patch], mcp_servers=[], handoffs=[]), _openai_opts(tmp_path))
    req = lambda argv: NS(data=NS(action=NS(command=argv)))  # noqa: E731
    assert asyncio.run(shell.executor(req(["rm", "-rf", "/"]))).startswith("⛔")
    assert asyncio.run(shell.executor(req(["echo", "hi"]))) == "RAN"
    op = NS(path=str(tmp_path / "a.txt"), diff="+hello")
    assert asyncio.run(patch.editor.create_file(op)) == "WROTE"


def test_openai_mcp_server_call_is_judged(tmp_path, monkeypatch):
    monkeypatch.setenv("PRISMOR_HOME", str(tmp_path / "home"))
    from types import SimpleNamespace as NS
    from prismor_openai import _guard_runtime_surfaces
    seen = []

    class Server:
        name = "fs"
        async def call_tool(self, tool_name, arguments=None):
            return "OK"

    server = Server()
    import prismor_openai
    real = prismor_openai._judge

    async def spy(event, name, o):
        seen.append(event)
        return await real(event, name, o)

    monkeypatch.setattr(prismor_openai, "_judge", spy)
    _guard_runtime_surfaces(NS(tools=[], mcp_servers=[server], handoffs=[]), _openai_opts(tmp_path))
    assert asyncio.run(server.call_tool("read", {"p": 1})) == "OK"
    assert (seen[0]["mcp_server"], seen[0]["mcp_tool"]) == ("fs", "read")
    assert json.loads(seen[0]["response"]) == {"p": 1}


def test_openai_handoff_is_judged_as_spawn(tmp_path, monkeypatch):
    monkeypatch.setenv("PRISMOR_HOME", str(tmp_path / "home"))
    from types import SimpleNamespace as NS
    import prismor_openai
    seen = []

    async def spy(event, name, o):
        from prismor.runtime.runtime import _retype_adapter_file_call
        _retype_adapter_file_call(event)
        seen.append(event)
        return None

    monkeypatch.setattr(prismor_openai, "_judge", spy)

    async def invoke(ctx, input_json):
        return "AGENT"

    h = NS(tool_name="transfer_to_billing", on_invoke_handoff=invoke)
    prismor_openai._guard_runtime_surfaces(NS(name="triage", tools=[], mcp_servers=[], handoffs=[h]), _openai_opts(tmp_path))
    assert asyncio.run(h.on_invoke_handoff(None, json.dumps({"reason": "go"}))) == "AGENT"
    assert (seen[0]["type"], seen[0]["prompt"]) == ("subagent_spawn", "go")
    # the agent handing off, for agent_connections - not the run's top-level agent
    assert seen[0]["metadata"]["from_agent"] == "triage"


@pytest.mark.parametrize("action,params,kind,field,value", [
    ("write_file", {"file_name": "n.md", "content": "x"}, "file_write", "path", "n.md"),
    ("read_file", {"file_name": "n.md"}, "file_read", "path", "n.md"),
    ("upload_file", {"index": 2, "path": "/etc/passwd"}, "file_read", "path", "/etc/passwd"),
    ("navigate", {"url": "https://e.com", "new_tab": True}, "network", "url", "https://e.com"),
    ("search", {"query": "rust async", "engine": "duckduckgo"}, "network", "url", ""),
    ("evaluate", {"code": "fetch('https://x')"}, "shell", "command", "fetch('https://x')"),
])
def test_browser_use_actions(action, params, kind, field, value):
    from prismor_browser_use import _build_event
    ev = _build_event(action_name=action, params=params, session_id="s", agent="b", subject=None)
    assert (ev["type"], ev[field]) == (kind, value)
