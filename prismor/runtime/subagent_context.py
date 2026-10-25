"""Which subagent a framework tool call comes from.

Most agent frameworks run a subagent by calling another agent from inside a
tool (an "agent as tool"), or from a step of the parent's run. Adapters guard
tools, so the guard sees the boundary: while a guarded tool runs, ``running()``
records which agent and call launched whatever happens underneath, and a
guarded call made inside it reads ``nested_subagent()`` to report itself as a
subagent. The values feed ``when: subagent.*`` and telemetry attribution.

Adapters whose framework names the active agent natively (a handoff target, a
sub-agent of a root agent) should prefer that and fall back to this.

contextvars follow asyncio tasks but not plain threads, so a framework that
runs a nested agent on a worker thread loses the parent here.
"""
from __future__ import annotations

import contextvars
import uuid
from contextlib import contextmanager
from typing import Iterator, Optional, Tuple

# (label, call id, the guard's agent name, type for an unnamed nested call,
#  agent names of every running tool's agent, outermost first)
_RUNNING: contextvars.ContextVar[Optional[Tuple[str, str, str, Optional[str], Tuple[str, ...]]]] = contextvars.ContextVar(
    "prismor_running_tool", default=None)


def nested_subagent(agent_label: str) -> Tuple[Optional[str], Optional[str]]:
    """(subagent_id, subagent_type) when called inside another guarded tool, else (None, None).

    The type is the calling toolset's own label (give each agent its own
    ``name=``); the id names the tool call that launched the subagent, so all
    of one subagent run's calls share it.
    """
    parent = _RUNNING.get()
    if parent is None:
        return None, None
    return f"{parent[0]}:{parent[1]}", agent_label or parent[3] or "agent"


def current_parent() -> Optional[str]:
    """The agent name (as its guard reports it) whose tool is running right
    now, if any: the parent of any subagent call made underneath it, whose
    per-agent controls also apply to that call."""
    parent = _RUNNING.get()
    return parent[2] if parent else None


def current_chain() -> Tuple[str, ...]:
    """Agent names of every guarded tool running right now, outermost
    first: the ancestors of a subagent call made underneath. Its length is
    that call's depth."""
    parent = _RUNNING.get()
    return parent[4] if parent else ()


# The session of the last main-agent call screened in this context. Frameworks
# give each agent run its own session id, so a subagent's calls are counted in
# the delegation records of the main agent's session instead.
_TREE: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar("prismor_tree_session", default=None)


def tree_session(session_id: str, is_subagent: bool) -> str:
    """The session a call's delegation records belong to."""
    if not is_subagent:
        _TREE.set(session_id)
        return session_id
    # Only while a guarded tool runs the subagent: outside one, a remembered
    # session may belong to an earlier, unrelated run.
    return (_TREE.get() if _RUNNING.get() is not None else None) or session_id


@contextmanager
def running(agent_label: str, call_id: Optional[str] = None, *,
            agent_name: Optional[str] = None, child_type: Optional[str] = None) -> Iterator[None]:
    """Mark the body as tool call ``call_id`` of ``agent_label``.

    ``agent_name`` is the name the guard evaluates this agent's calls under
    (default ``agent_label``); ``child_type`` is the type to report for a
    nested call whose own guard has no label (e.g. the agent a handoff runs).
    """
    label = agent_label or "agent"
    name = agent_name or label
    chain = current_chain()
    if not chain or chain[-1] != name:  # a tool calling its own agent's tool is not a level
        chain += (name,)
    token = _RUNNING.set((label, str(call_id or uuid.uuid4().hex[:12]), name, child_type, chain))
    try:
        yield
    finally:
        _RUNNING.reset(token)
