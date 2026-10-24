"""Prismor adapter for Hugging Face smolagents (``pip install smolagents``).

Routes every tool call through ``prismor.runtime.runtime.evaluate_tool_call``
before the tool runs — same policy engine, observe/enforce model, and
per-user attribution as the other adapters.

Every smolagents tool call ends in ``Tool.__call__`` -> ``self.forward(...)``:
a ``ToolCallingAgent`` calls the tool object directly, and a ``CodeAgent``'s
local executor hands the same tool objects to the generated code, so a call
written inside the model's Python goes through ``forward`` too. Guarding
``forward`` on each tool instance therefore covers both agent types; a denied
call returns the denial string as the tool's output and never reaches your code.

What this does NOT cover: the Python a ``CodeAgent`` writes is not itself a
tool call. Code that does damage without calling a tool (``open(...)``,
``os.system`` where imports allow it) is up to smolagents' import allowlist
and executor sandbox, not Prismor. Remote executors (E2B, Docker, Modal)
serialize the tools into the sandbox, so guard those calls at the sandbox.

Easy path::

    from smolagents import ToolCallingAgent, OpenAIServerModel
    from prismor.smolagents import guard_agent

    agent = ToolCallingAgent(tools=[run_shell, lookup_order], model=model)
    guard_agent(agent, name="support-bot", mode="enforce")
"""
from __future__ import annotations

import functools
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, List, Optional, Sequence, Union

from prismor.runtime.principal import Subject, resolve_subject, use_subject
from prismor.runtime.redaction import redact_tool_result
from prismor.runtime.runtime import Decision, evaluate_tool_call, log_observe_findings

__all__ = ["guard_agent", "guard_tools", "prismor_guard_tool", "use_subject", "PrismorBlocked"]

_TYPE_FIELD = {
    "shell": "command",
    "file_read": "path",
    "file_write": "path",
    "network": "url",
    "prompt": "content",
    "tool_result": "content",
}
# The tool a smolagents agent uses to end its run: its argument is the answer
# text, not an action, so screening it as a command would only cause noise.
_SKIP = {"final_answer"}


class PrismorBlocked(Exception):
    """Raised when Prismor denies a tool call (``raise_on_block=True``)."""

    def __init__(self, reason: str, decision: Optional[Decision] = None) -> None:
        super().__init__(reason or "blocked by Prismor policy")
        self.decision = decision


def prismor_guard_tool(
    tool: Any,
    *,
    subject: Optional[Union[str, Subject]] = None,
    workspace: Optional[Union[str, Path]] = None,
    agent: str = "smolagents",
    name: str = "",
    mode: str = "observe",
    session_id: Optional[str] = None,
    event_type: str = "shell",
    raise_on_block: bool = False,
    subagent: Optional[tuple] = None,
) -> Any:
    """Guard one smolagents ``Tool`` in place (wraps its ``forward``).

    ``subagent``: (id, type) when the tool belongs to a managed agent, set by
    :func:`guard_agent`; None for the agent that runs the whole task.
    """
    if getattr(tool, "__prismor_guarded__", False) or getattr(tool, "name", "") in _SKIP:
        return tool
    ws = Path(workspace) if workspace else Path.cwd()
    sid = session_id or f"smolagents-{os.getpid()}"
    tool_name = getattr(tool, "name", None) or type(tool).__name__
    forward = tool.forward

    @functools.wraps(forward)
    def guarded_forward(*args: Any, **kwargs: Any) -> Any:
        field = _TYPE_FIELD.get(event_type, "command")
        event = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "session_id": sid,
            "agent": agent,
            "agent_event": "PreToolUse",
            "type": event_type,
            field: " ".join([str(a) for a in args] + [str(v) for v in kwargs.values()]).strip(),
            "metadata": {"tool_name": tool_name, "framework": "smolagents",
                         "args": [str(a) for a in args], "kwargs": {k: str(v) for k, v in kwargs.items()},
                         "subagent_id": subagent[0] if subagent else None,
                         "subagent_type": subagent[1] if subagent else None},
        }
        decision: Decision = evaluate_tool_call(
            event=event, workspace=ws, agent=agent, agent_name=name, mode=mode,
            session_id=sid, subject=resolve_subject(subject),
        )
        log_observe_findings(decision, mode=mode, tool_name=tool_name)
        if not decision.allow:
            reason = decision.reason or "policy violation"
            if raise_on_block:
                raise PrismorBlocked(reason, decision)
            return f"⛔ Prismor blocked this tool call: {reason}"
        return redact_tool_result(forward(*args, **kwargs), workspace=ws, engine=decision.engine)

    tool.forward = guarded_forward  # instance attribute: Tool.__call__ looks it up on self
    tool.__prismor_guarded__ = True
    return tool


def guard_tools(tools: Sequence[Any], **kwargs: Any) -> List[Any]:
    """Guard a list of smolagents tools in place. Returns the same list."""
    return [prismor_guard_tool(t, **kwargs) for t in tools]


def _managed(agent: Any) -> List[Any]:
    managed = getattr(agent, "managed_agents", None) or {}
    return list(managed.values()) if isinstance(managed, dict) else list(managed)


def guard_agent(agent: Any, **kwargs: Any) -> Any:
    """Guard every tool a ``ToolCallingAgent`` / ``CodeAgent`` holds, and the
    tools of its ``managed_agents`` (recursively). Call it after constructing
    the agent; returns the agent.

    The agent passed in is the main agent; a managed agent's tool calls are
    attributed to that subagent (type = its ``name``) for ``when: subagent.*``
    rules. Ownership is static: smolagents runs tool calls on a thread pool, so
    a run-time context would not reach them. A tool object shared between two
    agents keeps the attribution of the first agent that guarded it.
    """
    tools = list(getattr(agent, "tools", {}).values())
    guard_tools(tools, **kwargs)
    pending = _managed(agent)
    while pending:
        sub = pending.pop()
        sub_name = str(getattr(sub, "name", None) or type(sub).__name__)
        guard_tools(list(getattr(sub, "tools", {}).values()),
                    subagent=(f"{sub_name}-{id(sub)}", sub_name), **kwargs)
        pending.extend(_managed(sub))
    try:
        from prismor.runtime.agents import record_seen
        framework = kwargs.get("agent", "smolagents")
        record_seen(
            kwargs.get("name") or framework, framework=framework,
            workspace=Path(kwargs["workspace"]) if kwargs.get("workspace") else Path.cwd(),
            tools=[{"name": t.name, "source": "declared"} for t in tools if t.name not in _SKIP],
            session_id=kwargs.get("session_id") or f"smolagents-{os.getpid()}",
        )
    except Exception:
        pass
    return agent
