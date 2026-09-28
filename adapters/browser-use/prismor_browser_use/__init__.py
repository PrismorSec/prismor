"""Prismor adapter for browser-use.

Routes every browser-use action invocation through
``prismor.runtime.runtime.evaluate_tool_call`` before the action executes — same
policy engine, observe/enforce model, and per-user attribution as the other
adapters.

browser-use dispatches all actions through a single method:
``Registry.execute_action(action_name, params, ...)``.  This adapter patches
that method on the controller's registry so every action — navigation,
clicks, form input, file ops — is evaluated before Playwright touches the
browser. A thin layer over :class:`prismor.sdk.PrismorClient`.

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
from pathlib import Path
from typing import Any, Callable, Optional, Union

from prismor.runtime.principal import Subject, use_subject
from prismor.runtime.runtime import Decision, evaluate_tool_call
from prismor.sdk import BlockContext, PrismorBlocked, PrismorClient

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


def _evaluate(**kwargs: Any) -> Decision:
    """Resolve ``evaluate_tool_call`` through this module's global at call time.

    A test (or an app) that patches ``prismor.browser_use.evaluate_tool_call``
    keeps seeing every call, whether the patch lands before or after guarding.
    """
    return evaluate_tool_call(**kwargs)


def _action_denial(decision: Decision, ctx: BlockContext) -> str:
    """Default block rendering: the string browser-use surfaces back to the LLM."""
    return f"⛔ Prismor blocked action '{ctx.tool_name}': {decision.reason or 'policy violation'}"


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
        url = dump.get("url") or dump.get("query") or str(dump)
        return "network", "url", str(url)

    if action_name in _FILE_ACTIONS:
        path = dump.get("path") or dump.get("file_path") or dump.get("filename") or str(dump)
        return "file_write", "path", str(path)

    # Everything else (click, type, scroll, extract, …) → shell with serialised args
    parts = [action_name]
    for v in dump.values():
        if v is not None:
            parts.append(str(v))
    return "shell", "command", " ".join(parts)


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
    on_policy_block: Optional[Callable[[Decision, BlockContext], Any]] = None,
) -> Any:
    """Patch ``controller.registry.execute_action`` to route every browser
    action through the Prismor policy engine before Playwright executes it.

    Pass ``goal="..."`` to also capture the agent's intent so
    ``evaluate_tool_call`` enforces task-alignment for this headless agent (R2/R3).
    A denied action returns a denial string to the model by default,
    ``raise_on_block=True`` raises :class:`PrismorBlocked`, and
    ``on_policy_block(decision, ctx)`` lets the app decide what it sees instead.
    Returns the same controller object.
    """
    client = PrismorClient(
        workspace=workspace, agent=agent, agent_name=name, mode=mode,
        session_id=session_id or f"browser-use-{os.getpid()}", subject=subject,
        approvals=approvals, raise_on_block=raise_on_block,
        on_policy_block=on_policy_block or (None if raise_on_block else _action_denial),
        framework="browser-use", evaluate=_evaluate,
    )
    if goal:
        client.declare_tools(goal=goal)
    registry = getattr(controller, "registry", None)
    if registry is None:
        raise TypeError("controller has no .registry — is this a browser-use Controller?")

    if getattr(registry, "__prismor_guarded__", False):
        return controller

    original_execute = registry.execute_action

    @functools.wraps(original_execute)
    async def _guarded_execute(action_name: str, params: Any, **kwargs: Any) -> Any:
        # params may be a pydantic model, so only the extracted value goes into
        # the event; the session store serialises every event as JSON.
        event_type, _field, value = _extract_event_fields(action_name, params)
        decision = client.check(action_name, payload=value, event_type=event_type)

        if not decision.allow:  # honor the runtime decision (incl. org kill-switch / forced-enforce), not the app-passed mode
            # Headless STEP_UP → post an approval request and block until an admin
            # decides. Approve → proceed; deny/timeout/not-enrolled → fail closed.
            # The async variant waits in a worker thread: the poll must not park
            # the event loop that is also driving the CDP socket, or the browser
            # times out before the human decides.
            res = await client.resolve_block_async(decision, args=(params,))
            if not res.approved:
                # Return a string error — browser-use surfaces this back to the LLM
                return client.on_blocked(
                    decision, BlockContext(action_name, (params,), dict(kwargs), client.session_id, None),
                )
            params = res.args[0]  # "approve redacted" stripped the flagged values

        # An allowed action still returns a page's content — redact it before
        # browser-use hands the ActionResult back to the model.
        return client.redact(await original_execute(action_name, params, **kwargs), decision)

    registry.execute_action = _guarded_execute
    registry.__prismor_guarded__ = True
    return controller
