"""``prismor.sdk.PrismorClient`` — the client the framework adapters are built on.

PrismorSec/prismor#281. Real policy pipeline on a ``tmp_path`` workspace, no
live LLM. The approval and registration paths are stubbed with ``monkeypatch``
only (the autouse leak guard in conftest.py rejects bare attribute assignment).
"""
from __future__ import annotations

import asyncio
import os
from pathlib import Path

import pytest

from prismor.runtime.contract import validate_event
from prismor.runtime.enterprise import approvals as _approvals
from prismor.runtime.runtime import Decision
from prismor.sdk import BlockContext, BlockResolution, PrismorBlocked, PrismorClient, use_subject

#: A token the data-boundary classifier recognises on its own, assembled at
#: runtime so the tree never holds a token-shaped literal (oss-guard).
SECRET = "ghp_" + "A" * 36
LEAKY = f"config.yaml:\n  github_token: {SECRET}\n"
DESTRUCTIVE = "rm -rf /"


def _spy(decision=None):
    calls = []

    def evaluate(**kwargs):
        calls.append(kwargs)
        return decision or Decision(allow=True)

    return evaluate, calls


def _forced_deny(**_kw):
    # What the runtime returns for an org kill-switch: a hard deny whatever the
    # app-passed mode says.
    return Decision(allow=False, reason="[CRITICAL] agent disabled by org",
                    blocking={"action": "block", "ruleId": "agent-control"})


def _tool():
    calls = {"ran": 0, "last": None}

    def run_shell(command: str) -> str:
        calls["ran"] += 1
        calls["last"] = command
        return f"ran: {command}"

    return run_shell, calls


# ── check ────────────────────────────────────────────────────────────────────

def test_check_allows_safe_and_blocks_destructive_without_raising(tmp_path):
    client = PrismorClient(workspace=tmp_path, mode="enforce", raise_on_block=True)
    assert client.check("run_shell", kwargs={"command": "echo hi"}).allow is True
    decision = client.check("run_shell", kwargs={"command": DESTRUCTIVE})
    assert decision.allow is False
    assert decision.blocking is not None
    assert decision.verdict == "block"


def test_check_observe_allows_but_reports_would_block(tmp_path, capsys):
    client = PrismorClient(workspace=tmp_path, mode="observe")
    assert client.check("run_shell", kwargs={"command": DESTRUCTIVE}).allow is True
    assert "would block in enforce mode" in capsys.readouterr().err


def test_check_builds_contract_shaped_event(tmp_path):
    evaluate, calls = _spy()
    client = PrismorClient(workspace=tmp_path, agent="bot", agent_name="support", evaluate=evaluate)
    client.check("read_file", ("notes.txt",), {"n": 1}, event_type="tool_result",
                 subagent_id="researcher-1", subagent_type="researcher")
    (call,) = calls
    event = call["event"]
    assert validate_event(event) == []
    assert event["type"] == "tool_result" and event["response"] == "notes.txt 1"
    meta = event["metadata"]
    assert meta["tool_name"] == "read_file" and meta["framework"] == "bot"
    assert meta["args"] == ["notes.txt"] and meta["kwargs"] == {"n": 1}
    assert meta["subagent_id"] == "researcher-1" and meta["subagent_type"] == "researcher"
    assert meta["surface"] == "sdk-adapter"
    assert call["agent"] == "bot" and call["agent_name"] == "support" and call["mode"] == "observe"
    assert call["workspace"] == tmp_path


def test_session_and_budget_passthrough(tmp_path):
    evaluate, calls = _spy()
    client = PrismorClient(workspace=tmp_path, session_id="s-1", budget={"max_calls": 3}, evaluate=evaluate)
    client.check("t", kwargs={"x": 1})
    assert calls[0]["session_id"] == "s-1" and calls[0]["event"]["session_id"] == "s-1"
    assert calls[0]["event"]["metadata"]["budget"] == {"max_calls": 3}

    client.check("t", kwargs={"x": 1}, session_id="s-2", budget=7, metadata={"trace_id": "t-9"})
    assert calls[1]["session_id"] == "s-2" and calls[1]["event"]["session_id"] == "s-2"
    assert calls[1]["event"]["metadata"]["budget"] == 7
    assert calls[1]["event"]["metadata"]["trace_id"] == "t-9"

    # Caller metadata cannot relabel the fixed keys.
    client.check("t", metadata={"tool_name": "spoofed", "surface": "hook", "framework": "x"})
    meta = calls[2]["event"]["metadata"]
    assert meta["tool_name"] == "t" and meta["surface"] == "sdk-adapter" and meta["framework"] == "sdk"


def test_default_session_id_is_agent_and_pid(tmp_path):
    assert PrismorClient(workspace=tmp_path, agent="bot").session_id == f"bot-{os.getpid()}"


# ── subjects ─────────────────────────────────────────────────────────────────

def _write_iam(workspace: Path) -> None:
    iam_dir = workspace / ".prismor"
    iam_dir.mkdir(parents=True, exist_ok=True)
    # bob is denied shell tools (Bash); other users have no profile → unrestricted.
    (iam_dir / "iam.yaml").write_text(
        "agents:\n"
        "  user:bob:\n"
        "    allowed_tools: [Read]\n"
        "    deny_tools: [Bash]\n"
        "    deny_network: true\n"
        "    allowed_paths: ['**']\n",
        encoding="utf-8",
    )


def test_subject_resolution_bound_context_and_per_call(tmp_path, monkeypatch):
    monkeypatch.delenv("PRISMOR_AGENT_ID", raising=False)
    _write_iam(tmp_path)
    bound = PrismorClient(workspace=tmp_path, mode="enforce", subject="user:bob")
    assert bound.check("run_shell", kwargs={"command": "echo hi"}).allow is False  # bob may not use shell tools

    unbound = PrismorClient(workspace=tmp_path, mode="enforce")
    with use_subject("user:alice"):
        decision = unbound.check("run_shell", kwargs={"command": "echo hi"})
    assert decision.allow is True and decision.subject.user_id == "alice"

    # A per-call subject beats the bound one.
    assert bound.check("run_shell", kwargs={"command": "echo hi"}, subject="user:alice").allow is True


def test_use_subject_is_the_runtime_context():
    import prismor.runtime.principal as principal
    assert use_subject is principal.use_subject


# ── guard ────────────────────────────────────────────────────────────────────

def test_guard_sync_runs_safe_and_returns_denial_string(tmp_path):
    tool, calls = _tool()
    guarded = PrismorClient(workspace=tmp_path, mode="enforce").guard(tool)
    assert guarded.__prismor_guarded__ is True and guarded.__name__ == "run_shell"
    assert guarded(command="echo hi") == "ran: echo hi"
    out = guarded(command=DESTRUCTIVE)
    assert out.startswith("⛔ Prismor blocked this tool call: ")
    assert calls["ran"] == 1


def test_guard_async(tmp_path):
    calls = {"ran": 0}

    async def run_shell(command: str) -> str:
        calls["ran"] += 1
        return f"ran: {command}"

    guarded = PrismorClient(workspace=tmp_path, mode="enforce").guard(run_shell)
    assert asyncio.run(guarded(command="echo hi")) == "ran: echo hi"
    assert asyncio.run(guarded(command=DESTRUCTIVE)).startswith("⛔ Prismor blocked")
    assert calls["ran"] == 1


def test_guard_raise_on_block(tmp_path):
    tool, calls = _tool()
    guarded = PrismorClient(workspace=tmp_path, mode="enforce", raise_on_block=True).guard(tool)
    with pytest.raises(PrismorBlocked) as exc:
        guarded(command=DESTRUCTIVE)
    assert exc.value.decision.blocking is not None
    assert calls["ran"] == 0


def test_on_policy_block_receives_context_and_its_result_is_returned(tmp_path):
    tool, calls = _tool()
    seen = {}

    def on_block(decision, ctx):
        seen["decision"], seen["ctx"] = decision, ctx
        return {"denied": ctx.tool_name}

    client = PrismorClient(workspace=tmp_path, mode="enforce", raise_on_block=True, on_policy_block=on_block)
    assert client.guard(tool)(command=DESTRUCTIVE) == {"denied": "run_shell"}  # beats raise_on_block
    assert calls["ran"] == 0
    ctx = seen["ctx"]
    assert isinstance(ctx, BlockContext)
    assert ctx.kwargs == {"command": DESTRUCTIVE} and ctx.args == ()
    assert ctx.session_id == client.session_id
    assert ctx.event["type"] == "shell" and seen["decision"].allow is False


def test_on_policy_block_exceptions_propagate(tmp_path):
    def boom(decision, ctx):
        raise RuntimeError("app decided to abort")

    guarded = PrismorClient(workspace=tmp_path, mode="enforce", on_policy_block=boom).guard(_tool()[0])
    with pytest.raises(RuntimeError):
        guarded(command=DESTRUCTIVE)


def test_forced_deny_is_honored_in_observe_mode(tmp_path):
    tool, calls = _tool()
    guarded = PrismorClient(workspace=tmp_path, mode="observe", evaluate=_forced_deny).guard(tool)
    assert "blocked" in guarded(command="anything").lower()
    assert calls["ran"] == 0


# ── results ──────────────────────────────────────────────────────────────────

def test_redact_masks_secret_in_result_and_leaves_clean_alone(tmp_path):
    client = PrismorClient(workspace=tmp_path, mode="enforce")
    assert SECRET not in client.redact(f"token: {SECRET}")
    assert client.redact({"n": 1}) == {"n": 1}
    decision = client.check("cat", kwargs={"path": "config.yaml"})
    assert SECRET not in str(client.redact(LEAKY, decision))

    guarded = client.guard(lambda path: LEAKY, tool_name="cat")
    assert SECRET not in guarded(path="config.yaml")


# ── approvals ────────────────────────────────────────────────────────────────

def test_resolve_block_fails_closed(tmp_path, monkeypatch):
    client = PrismorClient(workspace=tmp_path, mode="enforce")
    decision = client.check("run_shell", kwargs={"command": DESTRUCTIVE})

    monkeypatch.setattr(_approvals, "await_step_up",
                        lambda decision, **kw: _approvals.ApprovalOutcome(False, status="denied"))
    assert client.resolve_block(decision, kwargs={"command": DESTRUCTIVE}).approved is False

    def boom(decision, **kw):
        raise RuntimeError("control plane unreachable")

    monkeypatch.setattr(_approvals, "await_step_up", boom)
    assert client.resolve_block(decision).approved is False

    called = []
    monkeypatch.setattr(_approvals, "await_step_up",
                        lambda decision, **kw: called.append(1) or _approvals.ApprovalOutcome(True))
    off = PrismorClient(workspace=tmp_path, mode="enforce", approvals=False)
    assert off.resolve_block(decision).approved is False
    assert called == []  # approvals=False never asks the control plane


def test_resolve_block_approved_as_is(tmp_path, monkeypatch):
    client = PrismorClient(workspace=tmp_path, mode="enforce")
    decision = client.check("run_shell", kwargs={"command": DESTRUCTIVE})
    monkeypatch.setattr(_approvals, "await_step_up", lambda decision, **kw: _approvals.ApprovalOutcome(True))
    res = client.resolve_block(decision, args=("a",), kwargs={"k": "v"})
    assert res == BlockResolution(True, ("a",), {"k": "v"}, redacted=False)


def test_resolve_block_approved_redacted_rewrites_args(tmp_path, monkeypatch):
    client = PrismorClient(workspace=tmp_path, mode="enforce")
    decision = client.check("send_mail", kwargs={"to": "ops"})
    monkeypatch.setattr(_approvals, "await_step_up",
                        lambda decision, **kw: _approvals.ApprovalOutcome(True, redacted=True))
    res = client.resolve_block(decision, args=("bob@realco.com",), kwargs={"email": "bob@realco.com", "n": 1})
    assert res.approved and res.redacted
    assert res.kwargs == {"email": "[REDACTED:email]", "n": 1}
    assert res.args == ("[REDACTED:email]",)

    def boom(payload, **kw):
        raise RuntimeError("classifier unavailable")

    monkeypatch.setattr(_approvals, "redact_approved_payload", boom)
    assert client.resolve_block(decision, kwargs={"email": "bob@realco.com"}).approved is False


def test_guard_runs_tool_with_redacted_args_after_approval(tmp_path, monkeypatch):
    tool, calls = _tool()
    monkeypatch.setattr(_approvals, "await_step_up",
                        lambda decision, **kw: _approvals.ApprovalOutcome(True, redacted=True))
    monkeypatch.setattr(_approvals, "redact_approved_payload",
                        lambda payload, **kw: {k: "[REDACTED]" for k in payload}
                        if isinstance(payload, dict) else payload)
    guarded = PrismorClient(workspace=tmp_path, mode="enforce").guard(tool)
    assert guarded(command=DESTRUCTIVE) == "ran: [REDACTED]"
    assert calls["last"] == "[REDACTED]"


def test_resolve_block_async_uses_the_async_variant(tmp_path, monkeypatch):
    client = PrismorClient(workspace=tmp_path, mode="enforce")
    decision = client.check("run_shell", kwargs={"command": DESTRUCTIVE})

    async def approve(decision, **kw):
        return _approvals.ApprovalOutcome(True)

    def sync_must_not_run(decision, **kw):
        raise AssertionError("sync await_step_up used from the async path")

    monkeypatch.setattr(_approvals, "await_step_up_async", approve)
    monkeypatch.setattr(_approvals, "await_step_up", sync_must_not_run)
    assert asyncio.run(client.resolve_block_async(decision, args=("x",))).approved is True


# ── registration ─────────────────────────────────────────────────────────────

def test_declare_tools_records_roster_and_intent_best_effort(tmp_path, monkeypatch):
    seen = {}
    monkeypatch.setattr("prismor.runtime.agents.record_seen",
                        lambda name, framework, workspace, **kw: seen.update(
                            name=name, framework=framework, workspace=workspace, **kw))
    monkeypatch.setattr("prismor.runtime.intent.capture_intent",
                        lambda goal, **kw: seen.update(goal=goal, **kw))
    client = PrismorClient(workspace=tmp_path, agent="sdk", agent_name="bot", session_id="s-1")
    client.declare_tools(["run_shell", None, "fetch"], goal="triage tickets")
    assert seen["name"] == "bot" and seen["framework"] == "sdk" and seen["workspace"] == tmp_path
    assert seen["tools"] == [{"name": "run_shell", "source": "declared"}, {"name": "fetch", "source": "declared"}]
    assert seen["session_id"] == "s-1"
    assert seen["goal"] == "triage tickets" and seen["available_tools"] == ["run_shell", "fetch"]
    assert seen["agent"] == "sdk"

    seen.clear()
    client.declare_tools(goal="only intent")
    assert "name" not in seen and seen["goal"] == "only intent" and seen["available_tools"] is None

    def boom(*a, **kw):
        raise RuntimeError("inventory unavailable")

    monkeypatch.setattr("prismor.runtime.agents.record_seen", boom)
    monkeypatch.setattr("prismor.runtime.intent.capture_intent", boom)
    client.declare_tools(["run_shell"], goal="g")  # never raises


# ── the adapters are thin layers over the client ────────────────────────────

def test_prismor_blocked_is_one_class_across_adapters():
    import prismor.browser_use
    import prismor.crewai
    import prismor.langchain
    import prismor.openai

    assert prismor.langchain.PrismorBlocked is PrismorBlocked
    assert prismor.crewai.PrismorBlocked is PrismorBlocked
    assert prismor.openai.PrismorBlocked is PrismorBlocked
    assert prismor.browser_use.PrismorBlocked is PrismorBlocked


def test_adapters_expose_on_policy_block(tmp_path):
    import prismor.langchain as lc

    class _Tool:
        def __init__(self, fn):
            self.name = "run_shell"
            self.func = fn

    tool, calls = _tool()
    wrapped = _Tool(tool)
    lc.guard_tools([wrapped], workspace=tmp_path, mode="enforce",
                   on_policy_block=lambda decision, ctx: f"denied:{ctx.tool_name}")
    assert wrapped.func(command=DESTRUCTIVE) == "denied:run_shell"
    assert calls["ran"] == 0
