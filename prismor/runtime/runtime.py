"""Shared tool-call evaluation pipeline.

Every adapter — coding-agent hooks (``cli.py hook-dispatch``), in-process
framework SDK adapters (``adapters/``), and the MCP proxy — funnels a single
normalized event through :func:`evaluate_tool_call`. It runs the policy engine,
session-scoped rules, IAM, cross-call learning correlation, persists the event,
forwards telemetry to sinks, records the enterprise heartbeat, and returns a
:class:`Decision` describing whether the call may proceed.

Keeping this in one place means a production framework agent gets the exact same
policy, observe/enforce semantics, and per-user attribution a local coding agent
already gets — the caller only differs in how it renders the decision (exit-2,
a JSON permission object, or a raised exception).
"""
from __future__ import annotations

import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from prismor.runtime import perf
from prismor.runtime import ratelimit
from prismor.runtime.contract import CONTRACT_VERSION, Decision
from prismor.runtime.hooks import legacy_should_block, should_block
from prismor.runtime.policy_engine import PolicyEngine
from prismor.runtime.principal import Subject, current_token, is_verified, resolve_subject
from prismor.runtime.store import (
    append_session_event,
    persist_runtime_findings,
    read_session_events,
    save_session_snapshot,
)

# ``Decision`` lives in contract.py (the surface-facing boundary) and is
# re-exported here because every adapter already imports it from this module.
__all__ = ["CONTRACT_VERSION", "Decision", "evaluate_tool_call", "log_observe_findings"]


def _call_text(event: Dict[str, Any]) -> str:
    """The one string an exact-call decision is matched against."""
    for key in ("command", "path", "url"):
        if event.get(key):
            return " ".join(str(event[key]).split())
    return ""


def _apply_rule_exemptions(
    findings: List[Dict[str, Any]],
    rule_exemptions: Optional[List[Dict[str, Any]]],
    *,
    session_id: str,
    subject: Optional[Subject],
    verified_users_only: bool = False,
    surface: str = "",
    event: Optional[Dict[str, Any]] = None,
    agent_names: tuple = (),
) -> List[Dict[str, Any]]:
    """Apply rule decisions: org-signed exemptions and local dashboard ones.

    Each entry is ``{ruleId, scope (org|user|device|agent|session), scopeId,
    action (allow|flag|ask|deny), pattern?, expires?}``, matched at eval time
    against the current context. ``allow`` drops the matched finding, ``flag``
    downgrades it to observe, ``ask`` turns it into a human-approval request
    (step_up) and ``deny`` makes it block whatever the mode.

    ``pattern`` limits the entry to one exact call (the command, path or URL,
    whitespace-normalised). Only such an exact-call entry may relax a
    safety-floor rule; the self-protection rules and the agent kill-switch are
    never relaxed, and ``deny`` can apply to anything.

    ``verified_users_only`` (set when the org verifies identity): a ``user``
    exemption then needs a verified subject, so ``subject: "user:alice"`` sent
    by anyone no longer carries Alice's exemptions.
    """
    if not rule_exemptions:
        return findings
    from prismor.runtime.policy_engine import (
        _NON_OVERRIDABLE_RULE_IDS, _CORE_BLOCK_CATEGORIES, is_self_protection_rule,
    )

    now_iso = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    user_id = subject.user_id if subject else None
    device_id = None
    try:
        from prismor.runtime.enterprise import identity as _identity
        ident = _identity.load_identity()
        device_id = ident.get("device_id") if ident else None
    except Exception:
        device_id = None
    call = _call_text(event or {})

    def _matches(ex: Dict[str, Any], rule_id: str) -> bool:
        if str(ex.get("ruleId") or "") != rule_id:
            return False
        exp = ex.get("expires")
        if exp and str(exp) < now_iso:
            return False
        pattern = ex.get("pattern")
        if pattern and " ".join(str(pattern).split()) != call:
            return False
        scope, scope_id = ex.get("scope"), ex.get("scopeId")
        if scope == "org":
            return True
        if scope == "user":
            if verified_users_only and not is_verified(subject, surface):
                return False
            return bool(user_id) and scope_id == user_id
        if scope == "device":
            return bool(device_id) and scope_id == device_id
        if scope == "agent":
            return bool(scope_id) and scope_id in agent_names
        if scope == "session":
            return bool(session_id) and scope_id == session_id
        return False

    out: List[Dict[str, Any]] = []
    for f in findings:
        rule_id = str(f.get("ruleId") or "")
        match = next((ex for ex in rule_exemptions if isinstance(ex, dict) and _matches(ex, rule_id)), None)
        action = str((match or {}).get("action") or "allow")
        layer = "local" if (match or {}).get("local") else "org"
        floor = rule_id in _NON_OVERRIDABLE_RULE_IDS or f.get("category") in _CORE_BLOCK_CATEGORIES
        pinned = (is_self_protection_rule(rule_id) or f.get("category") == "agent-control"
                  or (floor and not (match or {}).get("pattern")))
        if match is None or (pinned and action != "deny"):
            out.append(f)
        elif action == "deny":
            out.append({**f, "mode": "enforce", "action": "block", "authoritative": True,
                        "decidedBy": f"{layer} {match.get('scope')} deny", "policyLayer": layer})
        elif action == "ask":
            out.append({**f, "mode": "enforce", "action": "step_up", "category": "agent-control",
                        "decidedBy": f"{layer} {match.get('scope')} ask", "policyLayer": layer})
        elif action == "flag":
            # Keep the finding (auditable warning), but strip its ability to block.
            out.append({**f, "mode": "observe", "exempted": "flag", "policyLayer": layer})
        # action == "allow": drop the finding entirely.
    return out


_OBSERVE_WARNED: set = set()


def _load_local_decisions(engine: PolicyEngine, workspace: Path) -> None:
    """Attach dashboard decisions belonging to this policy's workspace."""
    try:
        from prismor.runtime import decisions
        rules, tools = decisions.for_runtime(
            workspace, managed=bool(getattr(engine, "workspace_managed", False)))
        if rules:
            engine.rule_exemptions = list(engine.rule_exemptions or []) + rules
        if tools:
            engine.tool_denies = list(engine.tool_denies or []) + tools
    except Exception as exc:
        sys.stderr.write(f"[prismor] local decisions error: {exc}\n")


def _warn_observe_adapter(framework: str, findings: List[Dict[str, Any]]) -> None:
    """Say once, loudly, that an SDK guard is only watching.

    The openai-agents, langchain, crewai and browser-use guards default to
    observe, so their literal quickstarts let `curl … | bash` run while the
    docs said every tool was "policy-checked". Printed at the first call that
    enforce would have refused, which is the moment it matters.
    """
    if framework in _OBSERVE_WARNED:
        return
    if not any(str(f.get("action") or "").lower() == "block" for f in findings):
        return
    _OBSERVE_WARNED.add(framework)
    sys.stderr.write(
        f"[prismor] {framework} guard is in OBSERVE mode — tools are not blocked, this "
        "call would have been. Pass mode=\"enforce\" to block.\n")


def _block_reason(finding: Dict[str, Any]) -> str:
    parts = [f"[{finding.get('severity', 'high')}] {finding.get('title', 'blocked')}"]
    # Scoped-agent and IAM findings carry the title sentence again as their
    # evidence; printing both showed every deny reason twice.
    # Project-memory evidence is instruction-file text; the reason goes back to
    # the agent and into its transcript, so name the source instead of quoting it.
    if finding.get("source") == "project_memory":
        parts.append("Matched text from an agent instruction file (not shown).")
    elif finding.get("evidence") and str(finding["evidence"]) not in parts[0]:
        parts.append(str(finding["evidence"]))
    if finding.get("remediation"):
        parts.append(f"Recommended fix: {finding['remediation']}")
    return "\n".join(parts)


# Surfaces whose workspace is a store, not a project the agent works in.
# The proxy governs an agent it does not host -- often in another container --
# so the instruction files near ITS OWN directory say nothing about the traffic
# it is judging, while a CLAUDE.md that quotes attack strings (a security repo's
# does, and $PRISMOR_HOME ships one) makes every request a block attributed to
# source: project_memory. Scanning the wrong project is not a weaker check, it
# is a check on the wrong subject.
#
# The MCP gateway and the SDK adapters (events carrying metadata.framework) are
# the same case: neither loads CLAUDE.md/AGENTS.md, so the operator's
# ~/.claude/CLAUDE.md was judged as if it were their instructions and its text
# came back in the block reason a production agent sees.
_NO_PROJECT_AGENTS = frozenset({"prismor-proxy", "mcp-gateway"})


_PATH_ARGS = ("path", "file_path", "filepath", "filename", "file", "file_name", "notebook_path")
_CMD_ARGS = ("command", "cmd", "commands", "script", "code")
_URL_ARGS = ("url", "urls", "uri", "href", "endpoint")
_CONTENT_ARGS = ("content", "contents", "file_text", "new_str", "new_source", "text", "data", "body")
# upload/download first: "load" in them used to make both a file read.
_UPLOAD_TOOL = re.compile(r"upload|attach", re.I)
_READ_TOOL = re.compile(r"read|open|cat|(?<!up)(?<!down)load|view|get_?file", re.I)
_WRITE_TOOL = re.compile(r"write|save|edit|append|create|put_?file|replace", re.I)
# Handing work to another agent: OpenAI Agents handoffs (transfer_to_<agent>)
# and CrewAI's delegation tools, sanitized or not.
_SPAWN_TOOL = re.compile(r"^(transfer_to_|delegate[ _]work|ask[ _]question)", re.I)
_SPAWN_ARGS = ("task", "question", "message", "prompt", "input", "context", "reason")
_URL_VALUE = re.compile(r"\b[a-z][a-z0-9+.-]*://[^\s'\"<>]+", re.I)


def _adapter_kwargs(meta: Dict[str, Any]) -> Dict[str, Any]:
    kwargs = meta.get("kwargs") or meta.get("args") or {}
    if isinstance(kwargs, dict) and set(kwargs) == {"input"} and isinstance(kwargs["input"], str):
        try:  # OpenAI Agents SDK FunctionTools hand over one JSON string
            kwargs = json.loads(kwargs["input"])
        except ValueError:
            return {}
    return kwargs if isinstance(kwargs, dict) else {}


def _flat(value: Any) -> List[str]:
    if value is None or value == "":
        return []
    if isinstance(value, (list, tuple)):
        return [s for v in value for s in _flat(v)]
    return [value if isinstance(value, str) else json.dumps(value, default=str)]


def _retype_adapter_file_call(event: Dict[str, Any]) -> None:
    """Type an SDK adapter's tool call from its tool name and argument names.

    Adapters hand over one fixed type (``shell`` by default) and every argument
    value joined into that type's field, so ``read_file(path=".env")`` was a
    "shell command" (#542), ``fetch(url=…)`` never met an egress rule, and an
    adapter that asked for ``file_write`` got ``path`` = "path content". Only
    adapter events (``metadata.framework``) are touched, from their structured
    ``kwargs``; a command argument keeps a call shell. Every value still reaches
    the text rules: the ones not placed in a typed field go to ``content``.
    """
    meta = event.get("metadata") or {}
    if not meta.get("framework") or event.get("type") not in ("shell", "file_read", "file_write", "network"):
        return
    kw = {str(k).lower(): v for k, v in _adapter_kwargs(meta).items()}
    name = str(meta.get("tool_name") or "")
    if event["type"] == "shell" and _SPAWN_TOOL.match(name):
        # The brief is instruction text that will drive another agent, screened
        # like a Claude Agent/Task charter.
        brief = [s for k in _SPAWN_ARGS for s in _flat(kw.get(k))] or [s for v in kw.values() for s in _flat(v)]
        event.update(type="subagent_spawn", prompt="\n".join(brief), description=name,
                      subagent_type=str(kw.get("coworker") or re.sub(r"^transfer_to_", "", name, flags=re.I)))
        event.pop("command", None)
        return
    if not kw or any(kw.get(k) not in (None, "", []) for k in _CMD_ARGS):
        return
    pick = lambda keys: [s for k in keys for s in _flat(kw.get(k))]  # noqa: E731
    paths, urls = pick(_PATH_ARGS), pick(_URL_ARGS)
    body = pick(_CONTENT_ARGS)
    kind = event["type"]
    if kind == "shell":
        if len(paths) == 1:
            # An upload sends a local file somewhere: the risk is what it reads.
            kind = ("file_read" if _UPLOAD_TOOL.search(name)
                    else "file_write" if body or _WRITE_TOOL.search(name)
                    else "file_read" if _READ_TOOL.search(name) else "")
        elif urls and not paths:
            kind = "network"
        if not kind:
            return
    placed = {*_PATH_ARGS, *_URL_ARGS, *_CONTENT_ARGS}
    rest = [s for k, v in kw.items() if k not in placed for s in _flat(v)]
    if kind == "network":
        found = urls or [u for s in rest for u in _URL_VALUE.findall(s)]
        if not found:
            return
        # Any URL-looking value counts as a destination: an agent can put one
        # in a parameter no rule expects (new_tab=, referer=).
        extra = [u for s in rest for u in _URL_VALUE.findall(s) if u not in found]
        event["url"] = "\n".join(found + extra)
        if rest:
            event["outbound_payload"] = " ".join(rest)
    else:
        if len(paths) != 1:
            return
        event["path"] = paths[0]
        if kind == "file_write" or rest:
            event["content"] = "\n".join(body + rest)
    event["type"] = kind
    event.pop("command", None)


# Types an admin may reclassify a tool into from the console.
_SCOPE_RANK = {"session": 0, "agent": 1, "device": 2, "org": 3}
_OVERRIDE_TYPES = ("shell", "file_read", "file_write", "network", "tool_result", "subagent_spawn")
# Where an unmapped hook payload keeps the tool's arguments, per agent.
_ARG_KEYS = ("tool_input", "toolInput", "toolArgs", "tool_args", "arguments", "args", "input", "params")


def _call_args(event: Dict[str, Any]) -> Dict[str, Any]:
    """The tool's own argument dict, from an SDK adapter or an unmapped hook payload."""
    meta = event.get("metadata") or {}
    if meta.get("framework"):
        return _adapter_kwargs(meta)
    try:
        payload = json.loads(event.get("response") or "")
    except (TypeError, ValueError):
        return {}
    if not isinstance(payload, dict):
        return {}
    if event.get("mcp_server"):
        return payload  # an MCP pre-call carries the arguments themselves
    if isinstance(payload.get("toolCall"), dict):
        payload = payload["toolCall"]  # Antigravity
    for key in _ARG_KEYS:
        value = payload.get(key)
        if isinstance(value, str):
            try:
                value = json.loads(value)
            except ValueError:
                continue
        if isinstance(value, dict):
            return value
    return {}


def _apply_tool_type_override(event: Dict[str, Any], entries: Any, agent_name: str,
                              parent: Optional[str], session_id: str) -> None:
    """Re-type a call an admin reclassified from the console.

    Entries are ``settings.tool_denies`` items with ``action: "classify"`` and a
    ``type`` (they ride the same signed list and sync, and a runtime that does
    not know the action skips them), matched by tool tag and scope like a deny. The
    new type's field is filled from the call's arguments by argument name; every
    original value also stays in ``content`` so the text rules lose nothing. The
    change is recorded in ``metadata.type_override`` for the audit trail.
    """
    if not isinstance(entries, list) or not entries:
        return
    from prismor.runtime.contract import TYPE_FIELD
    from prismor.runtime.scoped_agent import resolve_tool_tags, tag_matches
    tags = resolve_tool_tags(event, families=True)
    if not tags:
        return
    hit, best = None, len(_SCOPE_RANK)
    for e in entries:
        if not isinstance(e, dict) or e.get("type") not in _OVERRIDE_TYPES or not tag_matches(e.get("tool"), tags):
            continue
        scope, sid = e.get("scope") or "org", e.get("scopeId")
        if scope in ("org", "device") or (scope == "agent" and sid in (agent_name, parent)) \
                or (scope == "session" and sid == session_id):
            rank = _SCOPE_RANK.get(scope, len(_SCOPE_RANK))
            if rank < best:  # the narrowest matching scope wins, whatever the list order
                hit, best = e, rank
    old = event.get("type")
    if hit is None or hit["type"] == old:
        return
    new = hit["type"]
    kw = {str(k).lower(): v for k, v in _call_args(event).items()}
    pick = lambda keys: [x for k in keys for x in _flat(kw.get(k))]  # noqa: E731
    text = "\n".join(str(event.get(f)) for f in ("command", "path", "url", "prompt", "response", "content")
                     if event.get(f))
    if new == "shell":
        event["command"] = "\n".join(pick(_CMD_ARGS)) or " ".join(x for v in kw.values() for x in _flat(v)) or text
    elif new == "network":
        urls = pick(_URL_ARGS) or _URL_VALUE.findall(text)
        event["url"] = "\n".join(urls)
        event["outbound_payload"] = json.dumps(kw, default=str) if kw else text
    elif new in ("file_read", "file_write"):
        event["path"] = (pick(_PATH_ARGS) or [event.get("path") or ""])[0]
    elif new == "subagent_spawn":
        event["prompt"] = "\n".join(pick(_SPAWN_ARGS)) or text
    else:
        event[TYPE_FIELD[new]] = json.dumps(kw, default=str) if kw else text
    body = pick(_CONTENT_ARGS)
    event["content"] = "\n".join(body + ([text] if text else []))
    event["type"] = new
    event.setdefault("metadata", {})["type_override"] = {
        "from": old, "to": new, "tool": hit.get("tool"), "scope": hit.get("scope") or "org"}


def _parent_agent_of(event: Dict[str, Any], agent_name: str) -> Optional[str]:
    """The agent a subagent call runs under, when it differs from ``agent_name``.

    Adapters (and eval-server callers) name it in ``metadata.parent_agent_name``;
    otherwise, for a subagent call made inside another guarded tool of this
    process, it is the agent whose tool is running (subagent_context).
    """
    meta = event.get("metadata") if isinstance(event.get("metadata"), dict) else {}
    if not meta.get("subagent_id"):
        return None
    parent = meta.get("parent_agent_name")
    if not parent:
        from prismor.runtime.subagent_context import current_parent
        parent = current_parent()
    return str(parent) if parent and parent != agent_name else None


def evaluate_tool_call(
    *,
    event: Dict[str, Any],
    workspace: Path,
    agent: str,
    mode: str = "enforce",
    session_id: str = "",
    repo_root: Optional[Path] = None,
    subject: Optional[Subject] = None,
    persist: bool = True,
    record: bool = True,
    agent_name: str = "",
    taint_store: Optional[Any] = None,
    register_agent: bool = True,
    flush_at_exit: bool = True,
    resource: Optional[Dict[str, Any]] = None,
    identity_token: Optional[str] = None,
    explain: bool = False,
    session_seq: Optional[int] = None,
    deny_tools: Sequence[str] = (),
    rate_accounting: bool = True,
    rate_scope: Optional[ratelimit.Scope] = None,
) -> Decision:
    """Evaluate one normalized tool-call ``event`` against active policy.

    Args:
        event: canonical event (``type``, ``agent``, ``agent_event``, ...).
        workspace: workspace whose policy + session store apply.
        agent: agent/framework id (telemetry + heartbeat tagging).
        mode: ``enforce`` blocks on enforce-mode findings; ``observe`` is a local
            dry-run kill-switch (the control plane can still force enforce per rule).
        session_id: session to append to / read history from.
        repo_root: repo root for analysis (defaults to ``workspace``).
        subject: resolved end-user principal; if ``None`` it is resolved from
            ``PRISMOR_SUBJECT`` / device identity so single-user installs are unchanged.
        deny_tools: extra tool tags denied for this call by the caller's own
            scope, merged into the agent's deny list (same finding, logging and
            hiding as an operator deny). The MCP gateway passes a tool its
            server entry's tool selection leaves out.
        record: when False, decide only - no event, finding, telemetry, heartbeat
            or audit record. Used when another hook process (a global and a
            project install of the same agent) already records this call.
        persist: append the event + write a session snapshot (set ``False`` for
            pure pre-checks like ``immunity check``).
        session_seq: zero-based position of this event in its session when the
            caller handles persistence. Defaults to the last index in the
            loaded history (or zero for a standalone pre-check).
        rate_accounting: False only for host-owned probes or historical replay.
            Independent of persist/record: live proxies do their own recording.
        rate_scope: host-owned quota workspace/agent and optional hook call id.
            HTTP callers cannot select these through event/body fields.
        taint_store: optional session-taint store to use instead of the on-disk
            per-session file. Callers with no local box (the hosted
            inference-hook channel) pass one ``InMemoryTaintStore`` shared
            across the events of a replayed transcript.
        register_agent: record this agent + its observed tools in the
            workspace's agent inventory. Set ``False`` on a multi-tenant server,
            where the "workspace" is shared infrastructure rather than one
            developer's project: the inventory would then mix every tenant's
            agents into one file and put a disk write on the request path.
            Per-agent controls (kill-switch, mode override) are still resolved.
        flush_at_exit: upload the heartbeat and spooled findings when the
            process exits, so a short script's activity still reaches the
            console. Hook-dispatch passes ``False`` (one process per call).
        resource: the call's target (``{"kind", "id", "attr": {...}}``), read by
            ``when:`` rules as ``resource.*``. Overrides ``metadata.resource``.
        identity_token: the end user's IdP token (JWT). Verified against the
            org's ``settings.identity``; defaults to ``use_subject(token=...)``.
        explain: attach a decision trace (``Decision.explain``): matched rules,
            their policy layer and mode, each ``when`` result, policy version.

    Returns:
        A :class:`Decision`. ``allow`` is ``False`` only when a finding's effective
        mode is enforce; callers may further downgrade to observe (e.g. a local
        dry-run kill-switch).
    """
    repo_root = repo_root or workspace
    subject = subject or resolve_subject()
    # Normalise agent_name: default to the framework id for backward compat.
    _agent_name = agent_name or agent

    _retype_adapter_file_call(event)
    if event.get("type") == "shell" and event.get("command"):
        from prismor.runtime.cloaking.runtime import unwrap_decloak
        event["command"] = unwrap_decloak(str(event["command"]))

    # A subagent runs on its parent's authority: the parent's per-agent
    # controls are applied on top of its own (see agents.inherit_control).
    _parent_agent = _parent_agent_of(event, _agent_name)
    if _parent_agent:
        event.setdefault("metadata", {}).setdefault("parent_agent_name", _parent_agent)
    if (event.get("metadata") or {}).get("subagent_id"):
        # Where in the agent tree the call sits, for `when: subagent.depth/chain`.
        from prismor.runtime.subagent_context import current_chain
        _chain = [n for n in current_chain() if n != _agent_name] or ([_parent_agent] if _parent_agent else [])
        event["metadata"].setdefault("subagent_chain", _chain)
        event["metadata"].setdefault("subagent_depth", max(len(event["metadata"]["subagent_chain"]), 1))

    # Stamp principal and agent identity onto the event.
    meta = event.setdefault("metadata", {})
    if "subject" not in meta:
        meta["subject"] = subject.as_dict()
    meta.setdefault("agent_name", _agent_name)
    if resource is not None:
        meta["resource"] = resource

    # Hosted evaluation (PRISMOR_EVAL_URL): the Prismor-run server decides,
    # records and reports, so nothing is written or uploaded from here.
    from prismor.runtime import remote_eval as _remote_eval
    _remote = _remote_eval.remote_url()
    if _remote:
        return _remote_eval.evaluate_remote(
            _remote, event=event, agent=agent, agent_name=agent_name, mode=mode,
            session_id=session_id, subject=subject,
            identity_token=identity_token or current_token(), explain=explain,
        )

    from prismor.runtime import delegations as _delegations
    from prismor.runtime.subagent_context import tree_session
    _scope = str(meta.get("delegation_scope") or tree_session(session_id, bool(meta.get("subagent_id"))))
    _delegations.stamp(event, _agent_name, _scope, reserve=record)

    perf.lap()
    if not record:
        persist = False
    events = [event]
    analysis: Optional[Dict[str, Any]] = None
    if persist:
        try:
            append_session_event(workspace, session_id, event)
            events = read_session_events(workspace, session_id) or [event]
            from prismor.runtime.cli import analyze_session_incremental  # lazy: avoid import cycle
            analysis = analyze_session_incremental(
                events, repo_root=repo_root, workspace=workspace, session_id=session_id
            )
            save_session_snapshot(
                workspace=workspace,
                session_id=session_id,
                agent=agent,
                agent_name=_agent_name,
                source="hook",
                repo_url=None,
                events=events,
                analysis=analysis,
                append_only=True,
            )
        except Exception as exc:  # recording must never bypass enforcement
            sys.stderr.write(f"[prismor] session recording/analysis error: {exc}\n")
    perf.lap("session_analysis")

    # Keep the org policy fresh for every caller, not just hook-dispatch: an SDK
    # adapter or eval-server authenticated by PRISMOR_AGENT_KEY never runs
    # `prismor enroll`, so without this it never pulls the policy that carries
    # its telemetry sink, org mode and console tool denies. Debounced (~30s)
    # and a no-op when not enrolled, so hook-dispatch calling it too is free.
    try:
        from prismor.runtime.enterprise import remote_policy as _remote
        _remote.check_and_refresh()
    except Exception:
        pass

    engine = PolicyEngine(workspace=workspace)
    if taint_store is not None:
        engine.taint_override = taint_store
    # Allow / ask / deny decisions made on this machine's dashboard ride the
    # same matchers as the org's signed rule_exemptions and tool_denies.
    _load_local_decisions(engine, workspace)
    perf.lap("policy_load")

    # An admin's "classify as" from the console, before any rule sees the call.
    try:
        _apply_tool_type_override(
            event, [d for d in (getattr(engine, "tool_denies", None) or [])
                    if isinstance(d, dict) and d.get("action") == "classify"],
            _agent_name, _parent_agent, session_id)
    except Exception as exc:
        sys.stderr.write(f"[prismor] tool-type override error: {exc}\n")

    # Verified end-user identity. Off unless the signed org policy (or the
    # eval-server's flags) configure an issuer; then the subject comes from the
    # verified token, and `require` blocks calls that have none.
    _identity_finding = None
    _identity_cfg = None
    try:
        from prismor.runtime import identity_token as _idt
        _identity_cfg = _idt.effective_config(getattr(engine, "identity", None))
        if _identity_cfg:
            subject, meta["identity"], _identity_finding = _idt.apply(
                subject, identity_token or current_token(), _identity_cfg,
                surface=str(meta.get("surface") or ""), session_id=session_id)
            meta["subject"] = subject.as_dict()
    except Exception as exc:
        sys.stderr.write(f"[prismor] identity check error: {exc}\n")
        if _identity_cfg and str(_identity_cfg.get("mode")).lower() == "require":
            _identity_finding = {
                "id": f"{session_id}:identity-unverified", "ruleId": "identity-unverified",
                "severity": "high", "category": "agent-control", "mode": "enforce",
                "title": "End-user identity required — identity check failed",
                "evidence": str(exc), "eventIndex": 0,
            }

    # Resolve per-agent control (kill-switch, mode override, IAM profile).
    # Runs AFTER engine construction so the org's remote controls — carried in
    # the verified signed policy's settings.agent_controls, managed workspaces
    # only — merge with the local agents.yaml (tighten-only: see agents.py).
    _control = None
    try:
        from prismor.runtime.agents import resolve_agent_control, record_seen, make_disabled_finding
        _control = resolve_agent_control(
            _agent_name, workspace,
            remote_controls=getattr(engine, "agent_controls", None),
        )
        if _parent_agent:
            from prismor.runtime.agents import inherit_control
            _control = inherit_control(_control, resolve_agent_control(
                _parent_agent, workspace,
                remote_controls=getattr(engine, "agent_controls", None),
            ))
        # Throttled auto-registration.  The current tool is observed; an SDK
        # may declare its full roster in metadata.available_tools; exact tools
        # in a synthesized session scope are registered as scoped access.
        if register_agent:
            from prismor.runtime.scoped_agent import resolve_tool_tags, load_scoped_rules
            _capabilities = []
            # A skill call yields both the bare "Skill" tag and the qualified
            # "Skill:<name>" tag, so the console can inventory which skills this
            # agent actually reaches for — not just that it uses skills at all.
            for _tag in resolve_tool_tags(event):
                # The type this runtime judged it as - before any console
                # correction, so the console can show "was X" and an admin
                # removing the correction sees the runtime's own call again.
                _typed = (meta.get("type_override") or {}).get("from") or event.get("type")
                _capabilities.append({"name": _tag, "source": "observed", "type": str(_typed or "")})
            for _tool in meta.get("available_tools") or []:
                _capabilities.append({"name": str(_tool), "source": "declared"})
            _scoped = load_scoped_rules(workspace, session_id) if session_id else None
            for _tool in (_scoped or {}).get("allowed_tools") or []:
                # Skip wildcards ("*" and mcp__<server>__* families): they are
                # permissions, not tools the agent has been seen to hold.
                if "*" not in str(_tool):
                    _capabilities.append({"name": str(_tool), "source": "scoped"})
            record_seen(
                _agent_name, framework=agent, workspace=workspace,
                tools=_capabilities, session_id=session_id,
            )
        # Org mode wins over the hook flag. A local agents.yaml observe does
        # not: that file is what an agent writes to turn enforce into a dry run.
        # A local enforce still tightens an observe hook.
        if _control.org_mode:
            mode = _control.org_mode
        elif _control.mode == "enforce":
            mode = "enforce"
    except Exception as _exc:
        sys.stderr.write(f"[prismor] agent control error: {_exc}\n")

    # Only the current event drives the real-time decision (stale prior findings
    # must not block an unrelated event — see cli.py hook-dispatch rationale).
    # Timed from here through exemptions: the guard-evaluation duration reported
    # in telemetry (excludes session persistence/analysis above).
    perf.lap("agent_control")
    _guard_t0 = time.perf_counter()
    _session_seq = session_seq if session_seq is not None else len(events) - 1
    _trace: Optional[List[Dict[str, Any]]] = [] if explain else None
    try:
        findings = engine.evaluate(event, _session_seq, session_id=session_id, subject=subject,
                                   trace=_trace)
    except Exception as exc:
        # An engine that cannot decide must not let the call through: on
        # enforce this blocks, on observe it is reported like any finding.
        sys.stderr.write(f"[prismor] policy engine error: {exc}\n")
        findings = [{
            "id": f"{session_id}:policy-engine-error", "ruleId": "policy-engine-error",
            "severity": "high", "category": "policy-engine-error", "mode": "enforce",
            "title": "Policy engine failed on this call — blocked rather than unscreened",
            "evidence": f"{type(exc).__name__}: {exc}", "eventIndex": _session_seq,
        }]
    if analysis is not None:
        # A post-action event repeats its call's command/path, so every rule the
        # pre-action event already reported fires again. Report it once: the
        # duplicate was stored and sent as a second finding for the same call.
        from prismor.runtime.policy_engine import drop_post_twin_findings
        findings = drop_post_twin_findings(
            findings, events, _session_seq, analysis.get("findings") or [])
    _host_rate_findings: List[Dict[str, Any]] = []
    _host_rate_report = None
    # Stateful admission is performed ONCE, outside evaluate(): session replay,
    # memory scans and additional patch paths must never reserve extra slots.
    from prismor.runtime.hooks import _is_pre_action
    if (rate_accounting and (
            (rate_scope is not None and rate_scope.authoritative)
            or (_is_pre_action(str(event.get("agent_event") or ""))
                and event.get("agent_event") != "PreCheck"
                and event.get("type") not in {"prompt", "memory", "skill_manifest", "rate_limit"}))):
        _rate_scope = rate_scope or ratelimit.Scope(workspace, _agent_name)
        _rate_engine = (engine if _rate_scope.workspace.resolve() == workspace.resolve()
                        else PolicyEngine(workspace=_rate_scope.workspace))
        if _rate_engine is not engine:
            _load_local_decisions(_rate_engine, _rate_scope.workspace)
        if _rate_engine.rate_limit is not None or _rate_engine.rate_limit_error:
            _rate_subject = subject
            _rate_error = _rate_engine.rate_limit_error
            _rate_identity_findings = []
            if _rate_scope.authoritative:
                from prismor.runtime import identity_token as _rate_idt
                _rate_cfg = _rate_idt.effective_config(_rate_engine.identity)
                if _rate_cfg != _identity_cfg:
                    # A caller-selected workspace may have a different issuer
                    # (or no identity policy). It cannot prove quota identity
                    # on behalf of the host's policy authority.
                    _rate_subject = Subject()
                    if _rate_cfg:
                        try:
                            _rate_subject, _, _rate_identity_finding = _rate_idt.apply(
                                _rate_subject, identity_token or current_token(), _rate_cfg,
                                surface=str(meta.get("surface") or ""), session_id=session_id)
                        except Exception:
                            _rate_error = "Quota identity verification unavailable"
                            _, _, _rate_identity_finding = _rate_idt.apply(
                                Subject(), None, _rate_cfg, surface="eval-server", session_id=session_id)
                        if _rate_identity_finding:
                            _rate_identity_findings.append(_rate_identity_finding)
            _rate_identity = ratelimit.identity_key(
                _rate_subject, _rate_scope.agent, str(meta.get("surface") or ""))
            if _rate_error:
                _rate = {"count": 0, "limit": 0, "used": 0, "remaining": 0,
                         "retry_after": 0, "identity": _rate_identity,
                         "error": _rate_error}
            else:
                _rate = ratelimit.admit(_rate_scope.workspace, _rate_identity,
                                        _rate_engine.rate_limit, call_id=_rate_scope.call_id)
            _rate_event = {"type": "rate_limit", "agent_event": "PreToolUse",
                           "content": json.dumps(_rate, sort_keys=True)}
            _rate_findings = _rate_identity_findings + _rate_engine.evaluate(
                _rate_event, _session_seq, session_id=session_id, subject=_rate_subject,
                rate_context=_rate, trace=_trace)
            for _f in _rate_findings:
                _f["rateLimit"] = _rate
                _f["policyLayer"] = _rate_engine.rate_limit_source
                _f["remediation"] = (
                    "Inspect `prismor rate status`; wait for capacity or ask the operator to review the policy."
                    if _rate["error"] is None else
                    "Restore access to the rate-limit store/configuration, then retry; inspect `prismor rate status`.")
                if _rate_scope.authoritative or _rate_engine.rate_limit_source in {"remote", "exemption"}:
                    _f["authoritative"] = True
            if _rate_scope.authoritative:
                # Only the quota owner's decisions may relax its findings.
                # Request-selected workspace, agent/session labels and asserted
                # usernames cannot select exemptions from a different policy.
                _host_rate_findings = _rate_findings
                _host_rate_report = (_rate_engine, _rate_scope, _rate_event, _rate_subject)
                try:
                    _host_rate_findings = _apply_rule_exemptions(
                        _rate_findings, _rate_engine.rule_exemptions,
                        session_id="", subject=_rate_subject, verified_users_only=True,
                        surface=str(meta.get("surface") or ""), event=event,
                        agent_names=(_rate_scope.agent,))
                except Exception as exc:
                    sys.stderr.write(f"[prismor] quota-owner exemption error: {exc}\n")
            else:
                findings.extend(_rate_findings)
    # A multi-file patch is one event with one `path`; every other file it
    # touches gets the path rules too. Content is dropped so the content rules,
    # already run above, do not fire twice.
    for _extra in (meta.get("patch_paths") or [])[1:]:
        findings.extend(engine.evaluate(
            {**event, "path": _extra, "content": ""}, _session_seq,
            session_id=session_id, subject=subject))
    perf.lap("policy_eval")

    # Integrity findings (memory guard, #154) bypass the regex rule engine
    # because verify_memory_files() produces fully-structured findings with
    # title/severity/evidence already populated.  The integrity_warning field
    # route in default_policy.yaml never worked (field never produced by
    # _extract_fields) — integrity is now wired directly here.
    if event.get("integrity_findings"):
        _if_defaults: Dict[str, str] = {
            "ruleId": "memory-integrity-mismatch",
            "category": "memory_integrity",
        }
        for _f in event["integrity_findings"]:
            for _k, _v in _if_defaults.items():
                _f.setdefault(_k, _v)
        findings.extend(event["integrity_findings"])

    # ── Project-memory integrity ────────────────────────────────────────────
    # Two things happen here that the regex rules alone cannot cover.
    #
    # 1. Drift. `memory-embedded-directive` only catches poison someone already
    #    wrote a pattern for. The fingerprint check is provenance-independent:
    #    it reports that a trusted instruction file is no longer the file it was
    #    last session, whatever the wording.
    # 2. Reach. Only Claude wires a real SessionStart hook, so only Claude ever
    #    produced a `memory` event — leaving the other supported agents with no
    #    project-memory scanning at all. Piggy-backing the scan on the first
    #    event of a session keeps it a pre-action check without needing a
    #    session-start surface those agents do not expose.
    try:
        from prismor.runtime.hooks import _read_project_memory
        from prismor.runtime.scanner import check_memory_drift
        if event.get("type") == "memory":
            # Claude's real SessionStart event — engine.evaluate already ran the
            # content rules above; add the drift check on top.
            findings.extend(check_memory_drift(meta.get("memory_digests") or {}))
        elif (_session_seq == 0 and event.get("type") != "prompt"
              and agent not in _NO_PROJECT_AGENTS and not meta.get("framework")):
            _mem = _read_project_memory(Path(meta.get("cwd") or workspace))
            if _mem["content"]:
                _mem_event = {
                    "type": "memory",
                    "content": _mem["content"],
                    "metadata": {"memory_files": _mem["files"], "cwd": meta.get("cwd")},
                }
                findings.extend(engine.evaluate(
                    _mem_event, _session_seq, session_id=session_id, subject=subject))
                findings.extend(check_memory_drift(_mem["digests"]))
    except Exception as exc:  # best-effort; never block a tool call on this
        sys.stderr.write(f"[prismor] project-memory scan error: {exc}\n")

    # Codex cannot mutate Bash input or scrub Bash output from hooks. Block
    # literal cloak placeholders/read leaks before they execute, and persist the
    # finding so the dashboard explains the decision.
    if agent == "codex":
        try:
            from prismor.runtime.cloaking.runtime import codex_cloak_finding
            cloak_finding = codex_cloak_finding(event, session_id)
            if cloak_finding:
                findings.append(cloak_finding)
        except Exception as exc:
            sys.stderr.write(f"[prismor] codex cloak guard error: {exc}\n")

    # Session-scoped rules.
    try:
        from prismor.runtime.scoped_agent import load_scoped_rules, check_scoped_rules
        scoped = load_scoped_rules(workspace, session_id)
        if scoped is not None:
            sr_finding = check_scoped_rules(scoped, event, session_id=session_id)
            if sr_finding:
                findings.append(sr_finding)
    except Exception as exc:
        sys.stderr.write(f"[prismor] scoped enforcement error: {exc}\n")

    # An agent installing a plugin, skill or MCP server into itself. Warn-level:
    # the point is that the install is in the trail with the session that ran it.
    try:
        if str(event.get("agent_event") or "").lower().startswith("pre"):
            from prismor.runtime.extensions import install_finding
            _ext_finding = install_finding(event, session_id, mode=engine.device_mode or engine.default_mode)
            if _ext_finding:
                findings.append(_ext_finding)
    except Exception as exc:
        sys.stderr.write(f"[prismor] extension install check error: {exc}\n")

    # A finding raised while the session runs under an extension nobody has
    # reviewed says so: it is usually the first thing a responder needs.
    if findings:
        try:
            from prismor.runtime.extensions import unreviewed_in_session
            _under = unreviewed_in_session(workspace, session_id)
            if _under:
                for _f in findings:
                    _f.setdefault("unreviewedExtensions", _under)
        except Exception:
            pass

    # Per-agent kill-switch: inject a CRITICAL finding when the agent is disabled.
    # This runs before IAM so the disabled state always wins.
    if _control is not None and not _control.enabled:
        try:
            from prismor.runtime.agents import make_disabled_finding
            findings.insert(0, make_disabled_finding(
                _agent_name, session_id, disabled_by=_control.disabled_by))
        except Exception as exc:
            sys.stderr.write(f"[prismor] kill-switch error: {exc}\n")

    if _identity_finding is not None:
        findings.insert(0, _identity_finding)

    # A caller-scoped deny (the MCP gateway's per-server tool selection) joins
    # the agent's own list, so it hides, blocks and logs exactly like one.
    if deny_tools:
        from dataclasses import replace as _dc_replace
        from prismor.runtime.agents import AgentControl
        _base = _control if _control is not None else AgentControl(name=_agent_name)
        _control = _dc_replace(_base, deny_tools=tuple(_base.deny_tools) + tuple(deny_tools))

    # Per-agent / global tool-tag deny list (operator-set from the dashboard's
    # Tool Call panel). Resolves the tool tag the same way scoped rules do, so
    # arbitrary MCP tags (e.g. mcp__node_repl__js) work verbatim. Tagged
    # agent-control so it blocks in observe mode too — an explicit deny is an
    # operator decision, not a passive detection.
    if _control is not None and getattr(_control, "deny_tools", ()):  # noqa: SIM102
        try:
            from prismor.runtime.scoped_agent import resolve_tool_tags, tag_matches
            from prismor.runtime.agents import make_agent_tool_deny_finding
            # Deny on any tag this event answers to: the bare "Skill" tag
            # blocks every skill, "Skill:<name>" blocks just the one, and
            # "mcp__<server>__*" a whole MCP server.
            _tags = resolve_tool_tags(event, families=True)
            _hit_deny = next((d for d in _control.deny_tools if tag_matches(d, _tags)), None)
            if _hit_deny is not None:
                findings.append(make_agent_tool_deny_finding(_agent_name, _hit_deny, session_id))
        except Exception as exc:
            sys.stderr.write(f"[prismor] tool-deny error: {exc}\n")

    # A skill or MCP server turned off from the dashboard's Extensions page.
    try:
        from prismor.runtime.extensions import disabled_finding
        _off = disabled_finding(workspace, event, session_id)
        if _off is not None:
            findings.append(_off)
    except Exception as exc:
        sys.stderr.write(f"[prismor] extension-toggle error: {exc}\n")

    # Per-agent "ask" tools: the console's middle state. A matched tag emits a
    # step_up finding (human approval) rather than a hard deny — the gateway's
    # await_step_up routes it to the approvals queue; interactive hosts render
    # it inline. Only fires when the tag is NOT already denied above (deny wins,
    # and resolve_agent_control keeps the lists disjoint), so a call is never
    # both blocked and queued for approval.
    if _control is not None and getattr(_control, "ask_tools", ()):  # noqa: SIM102
        try:
            from prismor.runtime.scoped_agent import resolve_tool_tags, tag_matches
            from prismor.runtime.agents import make_agent_tool_step_up_finding
            _denied = getattr(_control, "deny_tools", ())
            _tags = resolve_tool_tags(event, families=True)
            if not any(tag_matches(d, _tags) for d in _denied):
                _hit_ask = next((a for a in _control.ask_tools if tag_matches(a, _tags)), None)
                if _hit_ask is not None:
                    findings.append(make_agent_tool_step_up_finding(
                        _agent_name, _hit_ask, session_id, scope_label="agent",
                        rule_id="agent-tool-step-up"))
        except Exception as exc:
            sys.stderr.write(f"[prismor] tool-ask error: {exc}\n")

    # Org signed-policy tool denies (settings.tool_denies, set by an admin from
    # the Prismor web console). Same tool-tag matcher; scope decides whether
    # this event is covered. Device-scoped entries are pre-filtered to this
    # device server-side, so org/device always apply here; agent/session match
    # on the event's agent name / session id. Blocks regardless of mode.
    _org_denies = getattr(engine, "tool_denies", None)
    if _org_denies:
        try:
            from prismor.runtime.scoped_agent import resolve_tool_tags, tag_matches
            from prismor.runtime.agents import (
                make_agent_tool_deny_finding,
                make_agent_tool_step_up_finding,
            )
            # families: one `mcp__<server>__*` entry switches off a whole server.
            _otags = resolve_tool_tags(event, families=True)
            if _otags:
                for _d in _org_denies:
                    # 'allow' entries are handled in the block below; anything
                    # else we do not understand is skipped rather than guessed
                    # at, so an unknown action can never weaken a decision.
                    if not isinstance(_d, dict) or _d.get("action", "deny") not in ("deny", "step_up"):
                        continue
                    _otn = _d.get("tool")
                    if not tag_matches(_otn, _otags):
                        continue
                    _scope = _d.get("scope") or "org"
                    _sid = _d.get("scopeId")
                    _hit = (
                        _scope in ("org", "device")
                        or (_scope == "agent" and _sid in (_agent_name, _parent_agent))
                        or (_scope == "session" and _sid == session_id)
                    )
                    if _hit:
                        _layer = "local" if _d.get("local") else "org"
                        _label = _layer if _scope == "org" else f"{_layer} {_scope}"
                        if _d.get("action") == "step_up":
                            findings.append(make_agent_tool_step_up_finding(
                                _agent_name, _otn, session_id,
                                scope_label=_label))
                        else:
                            findings.append(make_agent_tool_deny_finding(
                                _agent_name, _otn, session_id,
                                scope_label=_label, rule_id="org-tool-deny"))
                        break
        except Exception as exc:
            sys.stderr.write(f"[prismor] org tool-deny error: {exc}\n")

    # Org signed-policy tool ALLOWS (same settings.tool_denies list, entries
    # with action:'allow' — set by an admin clicking "Allowed" on prismor.dev
    # for a tool that a LOCAL layer still restricts). Org policy is
    # authoritative: an explicit org allow for this tool/scope drops the local
    # per-agent deny list (.prismor/agents.yaml) and the session-scoped
    # allowlist finding for the SAME event's tool, so a fleet admin's decision
    # always wins over a developer's local toggle or a stale synthesized scope.
    # It does NOT lift a separate org-level deny (a distinct admin decision —
    # see the block above) or the agent kill-switch (ruleId "agent-disabled"),
    # which stay authoritative floors regardless of any allow.
    if _org_denies:
        try:
            from prismor.runtime.scoped_agent import resolve_tool_tags
            _otags2 = resolve_tool_tags(event)
            if _otags2:
                for _a in _org_denies:
                    if not isinstance(_a, dict) or _a.get("action") != "allow":
                        continue
                    if _a.get("tool") not in _otags2:
                        continue
                    _ascope = _a.get("scope") or "org"
                    _asid = _a.get("scopeId")
                    _ahit = (
                        _ascope in ("org", "device")
                        # A subagent's own allow must not lift what its parent
                        # is denied; the parent's allow covers its subagents.
                        or (_ascope == "agent" and _asid == (_parent_agent or _agent_name))
                        or (_ascope == "session" and _asid == session_id)
                    )
                    if _ahit:
                        findings = [
                            f for f in findings
                            if not (
                                f.get("ruleId") == "agent-tool-deny"
                                or (
                                    f.get("ruleId") == "scoped-agent"
                                    and str(f.get("evidence") or "").startswith("Tool '")
                                )
                            )
                        ]
                        break
        except Exception as exc:
            sys.stderr.write(f"[prismor] org tool-allow error: {exc}\n")

    # IAM named-identity enforcement (now subject-aware + per-agent profile).
    try:
        from prismor.runtime.iam import check_iam
        iam_finding = check_iam(
            workspace=workspace,
            event=event,
            session_id=session_id,
            subject=subject,
            agent_profile=_control.iam_profile if _control else None,
            remote_controls=getattr(engine, "subject_controls", None),
        )
        # A subagent is also held to the IAM profile of the agents above it.
        for _profile in (getattr(_control, "parent_iam_profiles", ()) if not iam_finding else ()):
            iam_finding = check_iam(
                workspace=workspace, event=event, session_id=session_id,
                subject=subject, agent_profile=_profile,
                remote_controls=getattr(engine, "subject_controls", None),
            )
            if iam_finding:
                break
        if iam_finding:
            findings.append(iam_finding)
    except Exception as exc:
        sys.stderr.write(f"[prismor] IAM enforcement error: {exc}\n")

    # Provenance notices are informational; staged execution still needs to
    # inspect the untrusted artifact that produced them.
    if event.get("type") == "shell" and all(
        f.get("ruleId") == "cross-agent-flow" and f.get("action") == "log"
        for f in findings
    ):
        # A PostToolUse event carries the decloaked command. Re-cloak it so the
        # detectors compare it against the stored (placeholder) form of the same
        # call, and never write a raw secret into their tables (#808).
        from prismor.runtime.store import _recloak_event
        detector_event = _recloak_event(event)
        for fn_name in ("detect_evasion", "detect_staged_execution"):
            try:
                from prismor.runtime import learning
                detector = getattr(learning, fn_name)
                extra = detector(workspace, session_id, detector_event, findings)
                if extra:
                    findings.extend(extra)
            except Exception as exc:
                sys.stderr.write(f"[prismor] {fn_name} error: {exc}\n")

    # Memory self-reinforcement: untrusted content read earlier this session
    # being written verbatim into an instruction file. Unlike the shell
    # detectors above this runs even when the event already has findings — the
    # directive rules and the laundering signal are independent, and suppressing
    # one because the other fired would hide the more durable problem.
    if event.get("type") == "file_write":
        try:
            from prismor.runtime import learning
            extra = learning.detect_memory_self_reinforcement(
                workspace, session_id, event, findings)
            if extra:
                findings.extend(extra)
        except Exception as exc:
            sys.stderr.write(f"[prismor] detect_memory_self_reinforcement error: {exc}\n")

    # Per-event rule exemptions (admin-granted, signed): relax ("allow", drop the
    # finding) or downgrade ("flag", warn but don't block) a rule for the current
    # user / device / session. Applied after ALL findings are gathered, so it can
    # also relax scoped-agent denials — but never a core/floor protection.
    try:
        findings = _apply_rule_exemptions(
            findings, getattr(engine, "rule_exemptions", None),
            session_id=session_id, subject=subject,
            verified_users_only=bool(_identity_cfg),
            surface=str(meta.get("surface") or ""),
            event=event,
            agent_names=tuple(n for n in (_agent_name, _parent_agent) if n),
        )
    except Exception as exc:
        sys.stderr.write(f"[prismor] rule-exemption error: {exc}\n")

    findings.extend(_host_rate_findings)

    _eval_ms = int((time.perf_counter() - _guard_t0) * 1000)
    perf.lap("scoped_iam_learning")

    # Long-lived surfaces persist their events themselves (persist=False).
    # Stateful rate decisions cannot be reconstructed from that history, so
    # preserve them as runtime findings before a proxy rebuilds its snapshot.
    _to_persist = findings if persist else (
        [f for f in findings if "rateLimit" in f] if record else [])
    if _to_persist:
        try:
            persist_runtime_findings(workspace, session_id, _to_persist, _session_seq)
        except Exception as exc:
            sys.stderr.write(f"[prismor] finding persistence error: {exc}\n")

    # Per-call inspected-volume heartbeat (org observability), managed repos only.
    if record and getattr(engine, "workspace_managed", False):
        try:
            from prismor.runtime.enterprise import heartbeat
            heartbeat.record_call(
                agent=agent,
                agent_name=_agent_name if _agent_name != agent else "",
                session_id=session_id,
            )
            heartbeat.maybe_flush(workspace=workspace)
            if flush_at_exit:
                heartbeat.flush_at_exit()
        except Exception:
            pass

        # Daily shadow-AI inventory refresh, so the org's fleet view reflects
        # what is actually installed rather than whatever was true the day
        # somebody last ran `prismor discover` by hand. Spawns a detached
        # child: the scan is filesystem work this path must not wait on.
        # Gated on the managed workspace like the heartbeat above — a personal
        # repo never reports what is installed on the developer's machine.
        try:
            from prismor.runtime import discover as _discover
            _discover.maybe_report_background(workspace)
        except Exception:
            pass

    perf.lap("telemetry")
    blocking = should_block(findings, event)
    _rate_blocking = should_block([f for f in findings if "rateLimit" in f],
                                 {"agent_event": "PreToolUse"})
    if _rate_blocking is not None:
        from prismor.runtime.contract import strongest
        blocking = strongest([f for f in (blocking, _rate_blocking) if f is not None])
    if blocking is None and mode == "enforce" and getattr(engine, "is_legacy_policy", False):
        blocking = legacy_should_block(findings, event, engine.block_categories)

    # Local dry-run kill switch: a locally-passed observe mode suppresses blocks.
    # BUT once this machine is ENROLLED the org's signed policy is authoritative —
    # a local `--mode observe` (the install default) must not veto a block the
    # admin set to enforce (device_mode / enforce rules / tool_tags). So honor the
    # observe downgrade only when either (a) the org itself chose observe for this
    # agent (agent_controls, carried in `_control.mode`), or (b) this machine is
    # not enrolled (local-only dry run). The agent-control kill switch always
    # blocks regardless. This is what lets an admin flip a device to enforce from
    # the console and have it take effect with no local change.
    # A finding marked `authoritative` is also exempt: an org-signed decision
    # the local machine may not opt out of (today: settings.egress in enforce
    # mode, where a local observe downgrade would otherwise let a developer
    # step outside the fleet's egress boundary).
    if (blocking is not None and mode == "observe"
            and blocking.get("category") != "agent-control"
            and not blocking.get("authoritative")):
        _org_chose_observe = bool(
            _control is not None and getattr(_control, "org_mode", None) == "observe"
        )
        _enrolled = False
        try:
            from prismor.runtime.enterprise import identity as _identity
            _enrolled = _identity.is_enrolled()
        except Exception:
            _enrolled = False
        if _org_chose_observe or not _enrolled:
            # Re-scan rather than just dropping: should_block() returns the FIRST
            # enforce-rated finding, which may be an ordinary detection sitting
            # ahead of an authoritative one that observe mode must not suppress.
            _would_block = blocking
            blocking = should_block(
                [f for f in findings
                 if f.get("category") == "agent-control" or f.get("authoritative")],
                event,
            )
            # An org per-agent observe pin silently outranks --mode enforce and
            # device_mode, so say so (#256): stderr, and the audit verdict reads
            # "suppressed" instead of an ordinary "warned".
            if blocking is None and _org_chose_observe:
                _would_block["suppressedBy"] = f"org agent control: {_agent_name} mode=observe"
                sys.stderr.write(
                    f"[prismor] would block ({_would_block.get('ruleId') or _would_block.get('category')}); "
                    f"suppressed by org per-agent control '{_agent_name}' mode=observe\n"
                )

    # The finding that actually blocks reports as enforced. The legacy bridge
    # blocks by category while the finding still carries the rule's observe
    # mode, and the telemetry verdict is read from that mode, so the console
    # showed a stopped prompt as "allowed" (#541).
    if blocking is not None:
        blocking["mode"] = "enforce"
        # The local store saved this finding above, before the block was
        # decided, so the dashboard, `prismor status` and the stats counted a
        # blocked call as "warned". Re-save the decided version (upsert by id).
        # A copy: `action` on the live finding also drives modify/step-up
        # handling below and must keep its value.
        if persist and blocking.get("action") in (None, "", "warn", "observe"):
            try:
                persist_runtime_findings(
                    workspace, session_id, [dict(blocking, action="block")], _session_seq,
                )
            except Exception as exc:
                sys.stderr.write(f"[prismor] finding persistence error: {exc}\n")

    if record:
        _dispatch_telemetry(
            engine=engine,
            findings=findings,
            event=event,
            workspace=workspace,
            agent=agent,
            agent_name=_agent_name if _agent_name != agent else None,
            # The effective mode, not the caller's: an enrolled device (or an
            # always-enforced category) blocks even under a local observe, and
            # the console reads mode=observe as "would block".
            mode="enforce" if blocking is not None else mode,
            session_id=session_id,
            subject=subject,
            eval_ms=_eval_ms,
            session_seq=_session_seq,
        )
        if _host_rate_report and _host_rate_findings:
            _owner, _owner_scope, _summary_event, _owner_subject = _host_rate_report
            # Selecting a different action workspace cannot silence the
            # quota owner's alerts. Send only quota metadata there, never the
            # other workspace's command/arguments, and do not duplicate sinks
            # that already received the normal action record above.
            _owner_outputs = [out for out in _owner.outputs if out not in engine.outputs]
            _owner_sid = f"rate-limit-{_host_rate_findings[0]['rateLimit']['identity']}"
            _owner_findings = [dict(f, id=f"{_owner_sid}:{f.get('ruleId')}:{_session_seq}")
                               for f in _host_rate_findings]
            _dispatch_telemetry(
                engine=_owner, findings=_owner_findings, event=_summary_event,
                workspace=_owner_scope.workspace, agent=_owner_scope.agent,
                mode="enforce" if blocking is not None else mode,
                session_id=_owner_sid, subject=_owner_subject, eval_ms=_eval_ms,
                session_seq=_session_seq, outputs=_owner_outputs)
        if event.get("agent_event") == "UserPromptSubmit":
            _dispatch_refusals(engine=engine, event=event, workspace=workspace, agent=agent,
                               session_id=session_id, subject=subject)
        _dispatch_cloak_ledger(engine=engine, workspace=workspace, agent=agent,
                               session_id=session_id, subject=subject)

    # Tamper-evident signed audit trail: one chained + signed record per
    # evaluated call — every verdict, not just findings — so the local trail
    # is complete (see enterprise/audit_trail.py). Best-effort by default (a
    # skipped record is a detectable seq gap); PRISMOR_AUDIT_STRICT=1 fails
    # the action closed when the record cannot be written.
    try:
        from prismor.runtime.enterprise import audit_trail as _audit
        if record and _audit.enabled():
            _audit.append_action_record(
                event=event,
                findings=findings,
                blocking=blocking,
                workspace=workspace,
                agent=agent,
                agent_name=_agent_name,
                session_id=session_id,
                subject=subject.as_dict(),
                mode=mode,
                eval_ms=_eval_ms,
            )
    except Exception as exc:
        sys.stderr.write(f"[prismor] audit trail error: {exc}\n")
        if os.environ.get("PRISMOR_AUDIT_STRICT", "").lower() in ("1", "true", "yes", "on"):
            blocking = {
                "action": "block",
                "severity": "critical",
                "category": "agent-control",
                "ruleId": "audit-trail-strict",
                "title": "Audit trail write failed — action blocked (PRISMOR_AUDIT_STRICT=1)",
            }
            _delegations.release(event, _scope)
            return Decision(
                allow=False,
                findings=findings,
                blocking=blocking,
                reason=_block_reason(blocking),
                subject=subject,
                engine=engine,
            )

    _explain = None
    if explain:
        try:
            from prismor.runtime.enterprise import remote_policy as _rp
            _version = _rp.current_version()
        except Exception:
            _version = None
        _explain = {
            "rules": _trace or [],
            "policy_version": _version,
            "identity": meta.get("identity"),
            "subject_source": subject.source if subject else None,
            "decided_by": (blocking or {}).get("ruleId"),
        }
    if blocking is None and mode == "observe" and meta.get("framework"):
        _warn_observe_adapter(str(meta["framework"]), findings)
    if blocking is not None:
        _delegations.release(event, _scope)  # a refused launch uses no number
    _recheck = None
    if str((blocking or {}).get("action") or "").lower() == "step_up":
        import copy as _copy
        _snapshot = _copy.deepcopy(event)

        def _recheck(resource_now: Optional[Dict[str, Any]] = None) -> Decision:
            # Decide-only: no event, delegation number, rate count or audit
            # record — the approval outcome record covers this call.
            return evaluate_tool_call(
                event=_copy.deepcopy(_snapshot), workspace=workspace, agent=agent,
                mode=mode, session_id=session_id, repo_root=repo_root, subject=subject,
                persist=False, record=False, agent_name=agent_name,
                register_agent=False, flush_at_exit=False,
                resource=resource_now if resource_now is not None else resource,
                identity_token=identity_token, deny_tools=deny_tools,
                rate_accounting=False,
            )
    return Decision(
        allow=blocking is None,
        findings=findings,
        blocking=blocking,
        reason=_block_reason(blocking) if blocking else None,
        subject=subject,
        engine=engine,
        explain=_explain,
        recheck=_recheck,
    )


def log_observe_findings(decision: Decision, *, mode: str, tool_name: str = "") -> None:
    """Print a one-line stderr note for findings observe mode is hiding.

    ``evaluate_tool_call`` never blocks an enforce-rated finding when the
    caller's ``mode`` is ``observe`` — that's the whole point of observe mode —
    but it also means SDK adapters (which don't have a dashboard) give the
    developer zero visibility into what they'd be blocking if they flipped to
    enforce. Call this right after ``evaluate_tool_call`` in every adapter so
    "observe" doesn't mean "silent."
    """
    if mode != "observe" or not decision.allow:
        return  # the call was actually blocked; the adapter reports that itself
    would_block = [f for f in decision.findings if str(f.get("mode", "observe")).lower() == "enforce"]
    if not would_block:
        return
    label = f" ({tool_name})" if tool_name else ""
    for f in would_block:
        title = f.get("title", "policy violation")
        severity = f.get("severity", "high")
        sys.stderr.write(f"[prismor] observe{label}: would block in enforce mode - [{severity}] {title}\n")


def _dispatch_refusals(
    *, engine: PolicyEngine, event: Dict[str, Any], workspace: Path, agent: str,
    session_id: str, subject: Subject,
) -> None:
    """Ship a ``model_refusal`` row for each prompt the model's safety
    classifier refused. No hook fires for a refusal, so the next prompt is the
    first chance to see it in the transcript; the row carries the refusal's own
    time, which files it under the refused turn in the console. Category only,
    never the prompt. Best-effort."""
    transcript = ((event.get("metadata") or {}).get("raw") or {}).get("transcript_path")
    if not transcript or not session_id:
        return
    try:
        from prismor.runtime.store import prismor_home, transcript_refusals
        refusals = transcript_refusals(str(transcript))
        if not refusals:
            return
        seen_file = prismor_home() / "cache" / f"refusals-{re.sub(r'[^A-Za-z0-9_-]', '', session_id)}.txt"
        seen = set(seen_file.read_text(encoding="utf-8").split()) if seen_file.exists() else set()
        fresh = [r for r in refusals if r["uuid"] and r["uuid"] not in seen]
        if not fresh:
            return
        seen_file.parent.mkdir(parents=True, exist_ok=True)
        with open(seen_file, "a", encoding="utf-8") as fh:
            fh.writelines(r["uuid"] + "\n" for r in fresh)
    except Exception:
        return
    for r in fresh:
        _dispatch_telemetry(
            engine=engine,
            findings=[{"action": "allow", "severity": "info", "category": r["category"],
                       "ruleId": "model-refusal", "title": "Prompt refused by the model's safety classifier"}],
            event={"type": "model_refusal", "agent_event": "ModelRefusal", "ts": r["ts"], "occurred_at": r["ts"]},
            workspace=workspace, agent=agent, mode="observe", session_id=session_id, subject=subject,
        )


def _dispatch_cloak_ledger(
    *, engine: PolicyEngine, workspace: Path, agent: str, session_id: str, subject: Subject,
) -> None:
    """Ship what the bash cloak hooks caught since the last call
    (cloaking/ledger.py). Each line is filed under the session the hook saw
    and the time it happened; the vault name and pattern only, never a
    value. Best-effort, and a stat() when nothing is pending."""
    if not getattr(engine, "outputs", None):
        return
    try:
        from prismor.runtime.cloaking import ledger as _ledger
        records = _ledger.drain()
    except Exception:
        return
    for rec in records:
        finding = _ledger.to_finding(rec)
        _dispatch_telemetry(
            engine=engine,
            findings=[finding],
            event={"type": "cloak", "agent_event": "Cloak", "occurred_at": rec.get("ts"),
                   "metadata": {"tool_name": finding.get("toolName") or "cloak"}},
            workspace=workspace, agent=agent,
            mode="enforce" if rec.get("action") == "blocked" else "observe",
            session_id=str(rec.get("session_id") or "") or session_id,
            subject=subject,
        )


def _dispatch_telemetry(
    *,
    engine: PolicyEngine,
    findings: List[Dict[str, Any]],
    event: Dict[str, Any],
    workspace: Path,
    agent: str,
    agent_name: Optional[str] = None,
    mode: str,
    session_id: str,
    subject: Subject,
    eval_ms: Optional[int] = None,
    session_seq: Optional[int] = None,
    outputs: Optional[List[Dict[str, Any]]] = None,
) -> None:
    """Forward findings to configured sinks before the blocking decision so a
    SIEM sees every event, including blocked ones. Best-effort."""
    outputs = getattr(engine, "outputs", None) if outputs is None else outputs
    if not outputs:
        return
    if not findings:
        # Full session capture: under the org's full_capture opt-in every
        # evaluated call ships, not just the flagged ones, so the console's
        # session trail is the whole trail. Redacted orgs keep the old
        # findings-only behaviour (they already get per-session call counts
        # from the heartbeat).
        # A gateway server with logPayloads ships every call, like full capture.
        if not event.get("log_payloads"):
            try:
                from prismor.runtime.enterprise import remote_policy as _rp
                if not _rp.current_full_capture():
                    return
            except Exception:
                return
        findings = [{
            "action": "allow",
            "severity": "info",
            "category": "audit",
            "ruleId": "audit-allowed",
            "title": f"{event.get('type') or 'call'} allowed",
        }]
    try:
        from prismor.runtime.sinks import dispatch as sink_dispatch
        exm = getattr(engine, "active_exemption", None)
        policy_scope = (
            f"repo_exemption:{exm.get('id')}"
            if isinstance(exm, dict) and exm.get("id")
            else "org"
        )
        repo = None
        if getattr(engine, "workspace_managed", False):
            try:
                from prismor.runtime.enterprise import workspace_scope as ws
                repo = ws.detect_git_remote(workspace)
            except Exception:
                repo = None
        sink_dispatch(
            findings,
            outputs,
            extra={
                "session_id": session_id,
                "agent": agent,
                # Instance label (adapter `name=`), distinct from the framework
                # id above — lets the org dashboard tell "checkout-bot" apart
                # from every other agent on the same framework.
                "agent_name": agent_name,
                "mode": mode,
                "workspace": str(workspace),
                "policy_scope": policy_scope,
                "repo": repo,
                "subject": subject.as_dict(),
                # Guard-eval duration + on-device session position, surfaced in
                # the org dashboard's event inspector / latency KPIs.
                "eval_ms": eval_ms,
                "session_seq": session_seq,
            },
            raw_event=event,
        )
    except Exception as exc:
        sys.stderr.write(f"[prismor] sink dispatch error: {exc}\n")
