"""Hermes transcript adapter.

Hermes writes session records under ``$HERMES_HOME/sessions/*.jsonl``. Its
plugin emits camelCase payloads — ``hookEvent`` / ``toolName`` / ``toolInput``
— which `hooks._normalize_hermes` consumes directly, so records replay with no
key rewriting.

``hookEvent`` values seen from the plugin: ``before_tool_call`` (the default and
the only pre-action gate), ``message_received`` (user input) and
``message_sending`` (agent output, post-action and therefore skipped).

**Verification status:** unlike the Claude and Codex adapters, this one has not
been run against real Hermes transcripts — no Hermes session data was available
when it was written. It is tested against fixtures derived from
`_normalize_hermes`'s contract. Treat a zero-payload sweep on a non-empty
Hermes store as a format mismatch to report, not as "nothing happened"; run
with ``--strict`` to make that fail loudly.

Files that already contain normalized Prismor events (rather than plugin
payloads) are handled by ``prismor analyze --input``, which passes engine-shaped
events straight through.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Iterator, List

from prismor.runtime.transcripts.base import (
    DiscoveredSession,
    JsonlAdapter,
    env_root,
    home,
)

#: Post-action events carry results, not proposals. Replaying them as
#: pre-action would inflate the would-block count with work already done.
_POST_ACTION_EVENTS = {"message_sending", "after_tool_call", "post_tool_call"}


class HermesAdapter(JsonlAdapter):
    agent = "hermes"
    label = "Hermes"
    pattern = "**/*.jsonl"

    def roots(self) -> List[Path]:
        base = env_root("HERMES_HOME", home() / ".hermes")
        return [base / "sessions"]

    def handles(self, record: Dict[str, Any]) -> bool:
        return (
            record.get("hookEvent") is not None
            or record.get("hook_event") is not None
            or record.get("toolName") is not None
            or record.get("tool_name") is not None
        )

    def record_to_payloads(
        self, record: Dict[str, Any], session: DiscoveredSession
    ) -> Iterator[Dict[str, Any]]:
        hook_event = record.get("hookEvent") or record.get("hook_event")
        tool_name = record.get("toolName") or record.get("tool_name")

        # A record that carries neither marker is not a plugin payload — most
        # likely a control or telemetry line. Skipping keeps the stats honest
        # (it lands in `skipped_records`, not `payloads_emitted`).
        if hook_event is None and tool_name is None:
            return
        if hook_event in _POST_ACTION_EVENTS:
            return

        tool_input = record.get("toolInput") or record.get("tool_input") or {}
        yield {
            "session_id": record.get("sessionId")
            or record.get("session_id")
            or session.session_id,
            "timestamp": record.get("timestamp"),
            "hookEvent": hook_event or "before_tool_call",
            "toolName": tool_name or "",
            "toolInput": tool_input if isinstance(tool_input, dict) else {},
            "gatewayId": record.get("gatewayId") or record.get("gateway_id"),
        }
