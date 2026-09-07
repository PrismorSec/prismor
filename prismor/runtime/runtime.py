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

import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from prismor.runtime.contract import CONTRACT_VERSION, Decision
from prismor.runtime.hooks import legacy_should_block, should_block
from prismor.runtime.policy_engine import PolicyEngine
from prismor.runtime.principal import Subject, resolve_subject
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
) -> List[Dict[str, Any]]:
    """Relax or downgrade findings per admin-granted, signed rule exemptions.

    Each exemption is ``{ruleId, scope (user|device|session), scopeId, action
    (allow|flag), expires?}``, matched at eval time against the current context.
    ``allow`` drops the matched finding (the call proceeds, nothing recorded);
    ``flag`` downgrades it to observe (reported as a warning, but non-blocking).

    Core protections are never exemptable: a floor rule id / core block category
    (and the agent kill-switch) is left untouched regardless of any exemption.
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
            downgraded = {**f, "mode": "observe", "exempted": "flag"}
            out.append(downgraded)
        # action == "allow": drop the finding entirely.
    return out


def _block_reason(finding: Dict[str, Any]) -> str:
    parts = [f"[{finding.get('severity', 'high')}] {finding.get('title', 'blocked')}"]
    if finding.get("evidence"):
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
_NO_PROJECT_AGENTS = frozenset({"prismor-proxy"})


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
    agent_name: str = "",
    taint_store: Optional[Any] = None,
    register_agent: bool = True,
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
        persist: append the event + write a session snapshot (set ``False`` for
            pure pre-checks like ``immunity check``).
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

    Returns:
        A :class:`Decision`. ``allow`` is ``False`` only when a finding's effective
        mode is enforce; callers may further downgrade to observe (e.g. a local
        dry-run kill-switch).
    """
    repo_root = repo_root or workspace
    subject = subject or resolve_subject()
    # Normalise agent_name: default to the framework id for backward compat.
    _agent_name = agent_name or agent

    # Stamp principal and agent identity onto the event.
    meta = event.setdefault("metadata", {})
    if "subject" not in meta:
        meta["subject"] = subject.as_dict()
    meta.setdefault("agent_name", _agent_name)

    if persist:
        append_session_event(workspace, session_id, event)
        events = read_session_events(workspace, session_id)
        try:
            from prismor.runtime.cli import analyze_events  # lazy: avoid import cycle
            analysis = analyze_events(
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
            )
        except Exception as exc:  # best-effort; never block on analysis failure
            sys.stderr.write(f"[prismor] analysis error: {exc}\n")
    else:
        events = [event]

    engine = PolicyEngine(workspace=workspace)
    if taint_store is not None:
        engine.taint_override = taint_store

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
        # Per-agent mode override: takes precedence over the caller's mode.
        if _control.mode:
            mode = _control.mode
    except Exception as _exc:
        sys.stderr.write(f"[prismor] agent control error: {_exc}\n")

    # Only the current event drives the real-time decision (stale prior findings
    # must not block an unrelated event — see cli.py hook-dispatch rationale).
    # Timed from here through exemptions: the guard-evaluation duration reported
    # in telemetry (excludes session persistence/analysis above).
    _guard_t0 = time.perf_counter()
    _session_seq = len(events) - 1
    findings = engine.evaluate(event, _session_seq, session_id=session_id, subject=subject)

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
              and agent not in _NO_PROJECT_AGENTS):
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

    # Per-agent kill-switch: inject a CRITICAL finding when the agent is disabled.
    # This runs before IAM so the disabled state always wins.
    if _control is not None and not _control.enabled:
        try:
            from prismor.runtime.agents import make_disabled_finding
            findings.insert(0, make_disabled_finding(
                _agent_name, session_id, disabled_by=_control.disabled_by))
        except Exception as exc:
            sys.stderr.write(f"[prismor] kill-switch error: {exc}\n")

    # Per-agent / global tool-tag deny list (operator-set from the dashboard's
    # Tool Call panel). Resolves the tool tag the same way scoped rules do, so
    # arbitrary MCP tags (e.g. mcp__node_repl__js) work verbatim. Tagged
    # agent-control so it blocks in observe mode too — an explicit deny is an
    # operator decision, not a passive detection.
    if _control is not None and getattr(_control, "deny_tools", ()):  # noqa: SIM102
        try:
            from prismor.runtime.scoped_agent import resolve_tool_tags
            from prismor.runtime.agents import make_agent_tool_deny_finding
            # Deny on any tag this event answers to: the bare "Skill" tag
            # blocks every skill, "Skill:<name>" blocks just the one.
            for _tname in resolve_tool_tags(event):
                if _tname in _control.deny_tools:
                    findings.append(make_agent_tool_deny_finding(_agent_name, _tname, session_id))
                    break
        except Exception as exc:
            sys.stderr.write(f"[prismor] tool-deny error: {exc}\n")

    # Per-agent "ask" tools: the console's middle state. A matched tag emits a
    # step_up finding (human approval) rather than a hard deny — the gateway's
    # await_step_up routes it to the approvals queue; interactive hosts render
    # it inline. Only fires when the tag is NOT already denied above (deny wins,
    # and resolve_agent_control keeps the lists disjoint), so a call is never
    # both blocked and queued for approval.
    if _control is not None and getattr(_control, "ask_tools", ()):  # noqa: SIM102
        try:
            from prismor.runtime.scoped_agent import resolve_tool_tags
            from prismor.runtime.agents import make_agent_tool_step_up_finding
            _denied = getattr(_control, "deny_tools", ())
            for _tname in resolve_tool_tags(event):
                if _tname in _control.ask_tools and _tname not in _denied:
                    findings.append(make_agent_tool_step_up_finding(
                        _agent_name, _tname, session_id, scope_label="agent",
                        rule_id="agent-tool-step-up"))
                    break
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
            from prismor.runtime.scoped_agent import resolve_tool_tags
            from prismor.runtime.agents import (
                make_agent_tool_deny_finding,
                make_agent_tool_step_up_finding,
            )
            _otags = resolve_tool_tags(event)
            if _otags:
                for _d in _org_denies:
                    # 'allow' entries are handled in the block below; anything
                    # else we do not understand is skipped rather than guessed
                    # at, so an unknown action can never weaken a decision.
                    if not isinstance(_d, dict) or _d.get("action", "deny") not in ("deny", "step_up"):
                        continue
                    _otn = _d.get("tool")
                    if _otn not in _otags:
                        continue
                    _scope = _d.get("scope") or "org"
                    _sid = _d.get("scopeId")
                    _hit = (
                        _scope in ("org", "device")
                        or (_scope == "agent" and _sid == _agent_name)
                        or (_scope == "session" and _sid == session_id)
                    )
                    if _hit:
                        if _d.get("action") == "step_up":
                            findings.append(make_agent_tool_step_up_finding(
                                _agent_name, _otn, session_id,
                                scope_label=f"org {_scope}"))
                        else:
                            findings.append(make_agent_tool_deny_finding(
                                _agent_name, _otn, session_id,
                                scope_label=f"org {_scope}", rule_id="org-tool-deny"))
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
                        or (_ascope == "agent" and _asid == _agent_name)
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
        )
    except Exception as exc:
        sys.stderr.write(f"[prismor] rule-exemption error: {exc}\n")

    _eval_ms = int((time.perf_counter() - _guard_t0) * 1000)

    if persist and findings:
        try:
            persist_runtime_findings(workspace, session_id, findings, _session_seq)
        except Exception as exc:
            sys.stderr.write(f"[prismor] finding persistence error: {exc}\n")

    _dispatch_telemetry(
        engine=engine,
        findings=findings,
        event=event,
        workspace=workspace,
        agent=agent,
        agent_name=_agent_name if _agent_name != agent else None,
        mode=mode,
        session_id=session_id,
        subject=subject,
        eval_ms=_eval_ms,
        session_seq=_session_seq,
    )

    # Per-call inspected-volume heartbeat (org observability), managed repos only.
    if getattr(engine, "workspace_managed", False):
        try:
            from prismor.runtime.enterprise import heartbeat
            heartbeat.record_call(
                agent=agent,
                agent_name=_agent_name if _agent_name != agent else "",
                session_id=session_id,
            )
            heartbeat.maybe_flush()
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
        _org_chose_observe = bool(_control is not None and getattr(_control, "mode", None) == "observe")
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

    # Tamper-evident signed audit trail: one chained + signed record per
    # evaluated call — every verdict, not just findings — so the local trail
    # is complete (see enterprise/audit_trail.py). Best-effort by default (a
    # skipped record is a detectable seq gap); PRISMOR_AUDIT_STRICT=1 fails
    # the action closed when the record cannot be written.
    try:
        from prismor.runtime.enterprise import audit_trail as _audit
        if _audit.enabled():
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
            return Decision(
                allow=False,
                findings=findings,
                blocking=blocking,
                reason=_block_reason(blocking),
                subject=subject,
                engine=engine,
            )

    return Decision(
        allow=blocking is None,
        findings=findings,
        blocking=blocking,
        reason=_block_reason(blocking) if blocking else None,
        subject=subject,
        engine=engine,
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
    if mode != "observe":
        return
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
    if not (getattr(engine, "outputs", None) and findings):
        return
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
