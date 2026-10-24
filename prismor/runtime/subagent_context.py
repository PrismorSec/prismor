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

_RUNNING: contextvars.ContextVar[Optional[Tuple[str, str]]] = contextvars.ContextVar(
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
    return f"{parent[0]}:{parent[1]}", agent_label or "agent"


@contextmanager
def running(agent_label: str, call_id: Optional[str] = None) -> Iterator[None]:
    """Mark the body as tool call ``call_id`` of ``agent_label``."""
    token = _RUNNING.set((agent_label or "agent", str(call_id or uuid.uuid4().hex[:12])))
    try:
        yield
    finally:
        _RUNNING.reset(token)
