"""Prismor adapter for browser-use.

Routes every browser-use action invocation through
``prismor.runtime.runtime.evaluate_tool_call`` before the action executes — same
policy engine, observe/enforce model, and per-user attribution as the other
adapters.

browser-use dispatches all actions through a single method:
``Registry.execute_action(action_name, params, ...)``.  This adapter patches
that method on the controller's registry so every action — navigation,
clicks, form input, file ops — is evaluated before Playwright touches the
browser.

Easy path::

    from browser_use import Agent, Controller
    from prismor.browser_use import guard_controller

    controller = Controller()
    guard_controller(controller)          # every action now policy-checked

    agent = Agent(task="...", llm=llm, controller=controller)

Per-user / multi-tenant::

    from prismor.browser_use import use_subject

    guard_controller(controller)           # once, at startup

    with use_subject("user:alice"):        # per-request handler
        await agent.run()
"""
from __future__ import annotations

import functools
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional, Union

from prismor.runtime.redaction import redact_tool_result
from prismor.runtime.principal import Subject, resolve_subject, use_subject
from prismor.runtime.runtime import Decision, evaluate_tool_call, log_observe_findings

__all__ = ["guard_controller", "use_subject", "PrismorBlocked"]

# Actions whose primary risk is a network destination — map to event_type="network"
# Includes both older ("go_to_url", "search_google", "save_pdf") and current
# ("navigate", "search", "save_as_pdf") browser-use action names — the
# registered action set has been renamed across releases (confirmed against
# browser-use 0.13.3), and the old names may still be reachable via user code
# targeting an older pinned version. See PrismorSec/prismor#135.
_NETWORK_ACTIONS = {
    "go_to_url", "navigate",
    "search_google", "search",
    "open_tab",
}

# Actions whose primary risk is a file path — map to event_type="file_write"
_FILE_ACTIONS = {
    "upload_file",
    "save_pdf", "save_as_pdf",
    "download_file",
    "write_file", "replace_file",
}


class PrismorBlocked(Exception):
    def __init__(self, reason: str, decision: Optional[Decision] = None) -> None:
        super().__init__(reason or "blocked by Prismor policy")
        self.decision = decision


def _extract_event_fields(action_name: str, params: Any) -> tuple[str, str, str]:
    """Return (event_type, field_name, field_value) for a browser-use action."""
    dump: dict = {}
    if isinstance(params, dict):
        # The current Registry.execute_action signature (browser-use 0.13.x)
        # passes params as a plain dict, not a pydantic model — a dict has
        # neither .model_dump() nor __dict__, so without this branch every
        # field silently fell back to str({}) = "{}". See PrismorSec/prismor#135.
        dump = params
    elif hasattr(params, "model_dump"):
        dump = params.model_dump()
    elif hasattr(params, "__dict__"):
        dump = vars(params)

    if action_name in _NETWORK_ACTIONS:
        # go_to_url → params.url; search_google → params.query
        url = dump.get("url") or dump.get("query") or ""
        new_tab = dump.get("new_tab") or ""
        if new_tab:
            url = (str(url) + "\n" + str(new_tab)).strip()
        return "network", "url", str(url or dump)

    if action_name in _FILE_ACTIONS:
        path = dump.get("path") or dump.get("file_path") or dump.get("filename") or str(dump)
        return "file_write", "path", str(path)

    # Everything else (click, type, scroll, extract, …) → shell with serialised args
    parts = [action_name]
    for v in dump.values():
        if v is not None:
            parts.append(str(v))
    return "shell", "command", " ".join(parts)


def _build_event(
    *,
    action_name: str,
    params: Any,
    session_id: str,
    agent: str,
    subject: Optional[Subject],
) -> dict:
    event_type, field, value = _extract_event_fields(action_name, params)
    event = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "session_id": session_id,
        "agent": agent,
        "agent_event": "PreToolUse",
        "type": event_type,
        field: value,
        "metadata": {
            "tool_name": action_name,
            "framework": "browser-use",
            "subject": subject.as_dict() if subject else None,
        },
    }
    if event_type == "file_write" and isinstance(params, dict):
        event["content"] = str(params.get("content") or params.get("text") or "")
    return event


def guard_controller(
    controller: Any,
    *,
    subject: Optional[Union[str, Subject]] = None,
    workspace: Optional[Union[str, Path]] = None,
    agent: str = "browser-use",
    name: str = "",
    mode: str = "observe",
    session_id: Optional[str] = None,
    raise_on_block: bool = False,
    approvals: bool = True,
    goal: Optional[str] = None,
) -> Any:
    """Patch ``controller.registry.execute_action`` to route every browser
    action through the Prismor policy engine before Playwright executes it.

    Pass ``goal="..."`` to also capture the agent's intent so
    ``evaluate_tool_call`` enforces task-alignment for this headless agent (R2/R3).
    Returns the same controller object.
    """
    if goal:
        try:
            from prismor.runtime.intent import capture_intent
            capture_intent(
                goal,
                workspace=Path(workspace) if workspace else Path.cwd(),
                session_id=session_id or f"browser-use-{os.getpid()}",
                agent=agent,
            )
        except Exception:
            pass
    registry = getattr(controller, "registry", None)
    if registry is None:
        raise TypeError("controller has no .registry — is this a browser-use Controller?")

    if getattr(registry, "__prismor_guarded__", False):
        return controller

    original_execute = registry.execute_action
    ws = Path(workspace) if workspace else Path.cwd()
    sid = session_id or f"browser-use-{os.getpid()}"
    _agent_name = name  # per-instance label

    @functools.wraps(original_execute)
    async def _guarded_execute(action_name: str, params: Any, **kwargs: Any) -> Any:
        resolved = resolve_subject(subject)
        event = _build_event(
            action_name=action_name,
            params=params,
            session_id=sid,
            agent=agent,
            subject=resolved,
        )
        decision = evaluate_tool_call(
            event=event,
            workspace=ws,
            agent=agent,
            agent_name=_agent_name,
            mode=mode,
            session_id=sid,
            subject=resolved,
        )
        log_observe_findings(decision, mode=mode, tool_name=action_name)

        if not decision.allow:  # honor the runtime decision (incl. org kill-switch / forced-enforce), not the app-passed mode
            # Headless STEP_UP → post an approval request and block until an admin
            # decides. Approve → proceed; deny/timeout/not-enrolled → fail closed.
            if approvals:
                try:
                    from prismor.runtime.enterprise import approvals as _approvals
                    # async variant: the poll must not park the event loop that
                    # is also driving the CDP socket, or the browser times out
                    # before the human decides.
                    outcome = await _approvals.await_step_up_async(
                        decision, agent=agent, session_id=sid, tool=action_name, agent_name=_agent_name
                    )
                    if outcome:
                        if getattr(outcome, "redacted", False):
                            # "Approve redacted": strip flagged values on-device first.
                            params = _approvals.redact_approved_payload(params, workspace=ws)
                        return redact_tool_result(
                            await original_execute(action_name, params, **kwargs),
                            workspace=ws, engine=decision.engine)
                except Exception:
                    pass
            reason = decision.reason or "policy violation"
            if raise_on_block:
                raise PrismorBlocked(reason, decision)
            # Return a string error — browser-use surfaces this back to the LLM
            return f"⛔ Prismor blocked action '{action_name}': {reason}"

        # An allowed action still returns a page's content — redact it before
        # browser-use hands the ActionResult back to the model.
        return redact_tool_result(
            await original_execute(action_name, params, **kwargs), workspace=ws,
            engine=decision.engine)

    registry.execute_action = _guarded_execute
    registry.__prismor_guarded__ = True
    return controller
