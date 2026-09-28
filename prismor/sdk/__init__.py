"""Standalone Python client for Prismor's check/enforce surface.

::

    from prismor.sdk import PrismorClient, PrismorBlocked, use_subject

    client = PrismorClient(workspace=".", mode="enforce")
    run_shell = client.guard(run_shell)          # denied calls never run
    decision = client.check("run_shell", kwargs={"command": "ls"})   # never raises

Every call goes through the same pipeline as the coding-agent hooks
(``prismor.runtime.runtime.evaluate_tool_call``); only how a verdict is rendered
differs. The bundled framework adapters (LangChain, CrewAI, OpenAI Agents,
browser-use) are thin layers over this client, so anything they do a custom
integration can do with the same calls. See docs/sdk-clients.md.
"""
from __future__ import annotations

from prismor.runtime.contract import Decision
from prismor.runtime.principal import Subject, use_subject
from prismor.sdk.client import (
    BlockContext,
    BlockResolution,
    PrismorBlocked,
    PrismorClient,
    build_event,
)

__all__ = [
    "PrismorClient",
    "PrismorBlocked",
    "BlockContext",
    "BlockResolution",
    "Decision",
    "Subject",
    "use_subject",
    "build_event",
]
