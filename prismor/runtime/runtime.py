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
from typing import Any, Dict, List, Optional

from prismor.runtime import perf
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


def _apply_rule_exemptions(
    findings: List[Dict[str, Any]],
    rule_exemptions: Optional[List[Dict[str, Any]]],
    *,
    session_id: str,
    subject: Optional[Subject],
    verified_users_only: bool = False,
    surface: str = "",
) -> List[Dict[str, Any]]:
    """Relax or downgrade findings per admin-granted, signed rule exemptions.

    Each exemption is ``{ruleId, scope (user|device|session), scopeId, action
    (allow|flag), expires?}``, matched at eval time against the current context.
    ``allow`` drops the matched finding (the call proceeds, nothing recorded);
    ``flag`` downgrades it to observe (reported as a warning, but non-blocking).

    Core protections are never exemptable: a floor rule id / core block category
    (and the agent kill-switch) is left untouched regardless of any exemption.

    ``verified_users_only`` (set when the org verifies identity): a ``user``
    exemption then needs a verified subject, so ``subject: "user:alice"`` sent
    by anyone no longer carries Alice's exemptions.
    """
    if not rule_exemptions:
        return findings
    from prismor.runtime.policy_engine import _NON_OVERRIDABLE_RULE_IDS, _CORE_BLOCK_CATEGORIES

    now_iso = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    user_id = subject.user_id if subject else None
    device_id = None
    try:
        from prismor.runtime.enterprise import identity as _identity
        ident = _identity.load_identity()
        device_id = ident.get("device_id") if ident else None
    except Exception:
        device_id = None

    def _matches(ex: Dict[str, Any], rule_id: str) -> bool:
        if str(ex.get("ruleId") or "") != rule_id:
            return False
        exp = ex.get("expires")
        if exp and str(exp) < now_iso:
            return False
        scope, scope_id = ex.get("scope"), ex.get("scopeId")
        if scope == "user":
            if verified_users_only and not is_verified(subject, surface):
                return False
            return bool(user_id) and scope_id == user_id
        if scope == "device":
            return bool(device_id) and scope_id == device_id
        if scope == "session":
            return bool(session_id) and scope_id == session_id
        return False

    out: List[Dict[str, Any]] = []
    for f in findings:
        rule_id = str(f.get("ruleId") or "")
        category = f.get("category")
        # Floor + admin kill-switch are never relaxable.
        if (rule_id in _NON_OVERRIDABLE_RULE_IDS
                or category in _CORE_BLOCK_CATEGORIES
                or category == "agent-control"):
            out.append(f)
            continue
        match = next((ex for ex in rule_exemptions if isinstance(ex, dict) and _matches(ex, rule_id)), None)
        if match is None:
            out.append(f)
        elif str(match.get("action") or "allow") == "flag":
            # Keep the finding (auditable warning), but strip its ability to block.
            downgraded = {**f, "mode": "observe", "exempted": "flag", "policyLayer": "org"}
            out.append(downgraded)
        # action == "allow": drop the finding entirely.
    return out


_OBSERVE_WARNED: set = set()


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


_PATH_ARGS = ("path", "file_path", "filepath", "filename", "file")
_READ_TOOL = re.compile(r"read|open|cat|load|view|get_?file", re.I)
_WRITE_TOOL = re.compile(r"write|save|edit|append|create|put_?file", re.I)


def _retype_adapter_file_call(event: Dict[str, Any]) -> None:
    """Treat an SDK tool that only takes a file path as the file access it is.

    Adapters default every tool to ``shell``, so ``read_file(path=".env")``
    arrived as a "shell command" consisting of a bare path and none of the
    file-read secret rules could see it (#542). Only adapter events (they carry
    ``metadata.framework``) with a single path argument and a read/write-named
    tool are re-typed; anything with a command argument stays shell.
    """
    meta = event.get("metadata") or {}
    if event.get("type") != "shell" or not meta.get("framework"):
        return
    kwargs = meta.get("kwargs") or meta.get("args") or {}
    if set(kwargs) == {"input"} and isinstance(kwargs["input"], str):
        try:  # OpenAI Agents SDK FunctionTools hand over one JSON string
            kwargs = json.loads(kwargs["input"])
        except ValueError:
            return
    if not isinstance(kwargs, dict):
        return
    paths = [v for k, v in kwargs.items() if k.lower() in _PATH_ARGS and isinstance(v, str) and v]
    if len(paths) != 1 or any(k.lower() in ("command", "cmd", "script") for k in kwargs):
        return
    name = str(meta.get("tool_name") or "")
    kind = "file_read" if _READ_TOOL.search(name) else "file_write" if _WRITE_TOOL.search(name) else ""
    if kind:
        event["type"] = kind
        event["path"] = paths[0]


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
        record: when False, decide only - no event, finding, telemetry, heartbeat
            or audit record. Used when another hook process (a global and a
            project install of the same agent) already records this call.
        persist: append the event + write a session snapshot (set ``False`` for
            pure pre-checks like ``immunity check``).
        session_seq: zero-based position of this event in its session when the
            caller handles persistence. Defaults to the last index in the
            loaded history (or zero for a standalone pre-check).
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
    if persist:
        append_session_event(workspace, session_id, event)
        events = read_session_events(workspace, session_id)
        try:
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
        except Exception as exc:  # best-effort; never block on analysis failure
            sys.stderr.write(f"[prismor] analysis error: {exc}\n")
    else:
        events = [event]
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
    perf.lap("policy_load")

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
                _capabilities.append({"name": _tag, "source": "observed"})
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
    findings = engine.evaluate(event, _session_seq, session_id=session_id, subject=subject,
                               trace=_trace)
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
                        _label = "org" if _scope == "org" else f"org {_scope}"
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

    # Cross-call learning correlation on otherwise-clean shell events.
    if not findings and event.get("type") == "shell":
        for fn_name in ("detect_evasion", "detect_staged_execution"):
            try:
                from prismor.runtime import learning
                detector = getattr(learning, fn_name)
                extra = detector(workspace, session_id, event, findings)
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
        )
    except Exception as exc:
        sys.stderr.write(f"[prismor] rule-exemption error: {exc}\n")

    _eval_ms = int((time.perf_counter() - _guard_t0) * 1000)
    perf.lap("scoped_iam_learning")

    if persist and findings:
        try:
            persist_runtime_findings(workspace, session_id, findings, _session_seq)
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
            heartbeat.maybe_flush()
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
            blocking = should_block(
                [f for f in findings
                 if f.get("category") == "agent-control" or f.get("authoritative")],
                event,
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
    return Decision(
        allow=blocking is None,
        findings=findings,
        blocking=blocking,
        reason=_block_reason(blocking) if blocking else None,
        subject=subject,
        engine=engine,
        explain=_explain,
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
) -> None:
    """Forward findings to configured sinks before the blocking decision so a
    SIEM sees every event, including blocked ones. Best-effort."""
    if not getattr(engine, "outputs", None):
        return
    if not findings:
        # Full session capture: under the org's full_capture opt-in every
        # evaluated call ships, not just the flagged ones, so the console's
        # session trail is the whole trail. Redacted orgs keep the old
        # findings-only behaviour (they already get per-session call counts
        # from the heartbeat).
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
            engine.outputs,
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
