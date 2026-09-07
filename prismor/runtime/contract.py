"""The Prismor decision contract: one normalized event in, one Decision out.

Prismor screens agents at several places — coding-agent hooks, the MCP gateway,
the mirrored built-ins, in-process SDK adapters, the local evaluation server,
and the hosted inference-hook channel. Those are *enforcement points*: they
differ only in how they discover a tool call and how they render a refusal. The
*decision* is made in exactly one place (:func:`prismor.runtime.runtime.
evaluate_tool_call`, over :class:`prismor.runtime.policy_engine.PolicyEngine`),
so one policy governs every one of them.

This module is that boundary written down. It holds the event shape each
surface must produce, the verdict vocabulary the engine may return, the
:class:`Decision` every surface receives, and the registry of surfaces that
exist. It deliberately imports nothing from the rest of Prismor at runtime, so
it can be read — or vendored into a third-party proxy — on its own.

Why a module and not just documentation: the same ranking table was written out
three times (hooks, the gateway's result-withhold path, and by hand in the
callers that inspect ``blocking["action"]``). Three copies of a security
precedence rule is two too many.

Stability
---------
``CONTRACT_VERSION`` is bumped when a change would break an existing surface:
removing an event type, renaming a value field, adding a verdict that older
callers would fail open on. Additive changes (a new optional metadata key, a
new surface) do not bump it.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Tuple

if TYPE_CHECKING:  # pragma: no cover - typing only, never imported at runtime
    from prismor.runtime.policy_engine import PolicyEngine
    from prismor.runtime.principal import Subject

CONTRACT_VERSION = "1"


# ── events ───────────────────────────────────────────────────────────────────

#: Event ``type`` → the field a surface must populate with the value the rules
#: match against.
#:
#: For the text-bearing types the engine folds ``prompt``/``response``/
#: ``content``/``stdout``/``stderr`` into one ``combined_text`` blob, so a
#: category rule fires whichever of them a surface used. Field-scoped rules
#: (``fields: [response]``) do NOT: they read the individual key. That makes
#: the choice of key a real compatibility surface rather than a style
#: preference, and the value below is the one the hook normalizers and the MCP
#: gateway already write — i.e. the one existing rules are written against.
#:
#: Kept as a literal rather than imported from the policy engine so this module
#: stays dependency-free and readable on its own; ``test_surface_conformance``
#: asserts it against the engine's ``_DEFAULT_FIELDS`` so the two cannot drift.
TYPE_FIELD: Dict[str, str] = {
    "shell": "command",
    "file_read": "path",
    "file_write": "path",
    "network": "url",
    "prompt": "prompt",
    "tool_result": "response",
    "memory": "content",
    "text": "content",
    "skill_manifest": "content",
    "subagent_spawn": "content",
    "ui_action": "control_label",
}

EVENT_TYPES: Tuple[str, ...] = tuple(TYPE_FIELD)

#: Text fields the engine folds into ``combined_text``. A surface may populate
#: any of them on a text-bearing event; ``TYPE_FIELD`` names the preferred one.
COMBINED_FIELDS: Tuple[str, ...] = ("prompt", "response", "content", "stdout", "stderr")

#: Types whose matchable value is the folded text blob, where any
#: COMBINED_FIELDS key is accepted.
TEXT_TYPES: Tuple[str, ...] = (
    "prompt", "tool_result", "memory", "text", "skill_manifest", "subagent_spawn",
)

#: ``agent_event`` values that describe an action that has NOT happened yet.
#: Only these can be refused; a post-action event is a record, and the honest
#: response to one is to redact or alert, never to pretend it was stopped.
PRE_ACTION_EVENTS: Tuple[str, ...] = ("PreToolUse", "pre_tool_use", "pre", "prompt")


# ── verdicts ─────────────────────────────────────────────────────────────────

ALLOW = "allow"
BLOCK = "block"
STEP_UP = "step_up"
DEFER = "defer"
MODIFY = "modify"

#: Verdicts a rule may carry as its ``action``. ``warn``/``log`` are reporting
#: actions: they produce findings but never a blocking decision, so they are
#: not verdicts and are ranked as BLOCK if one ever reaches the decision path
#: on an enforce-mode finding (see VERDICT_RANK).
VERDICTS: Tuple[str, ...] = (BLOCK, STEP_UP, DEFER, MODIFY)

#: DENY-wins precedence. When several enforce-mode findings fire on one event
#: with different actions, the strongest wins — not whichever the engine
#: happened to surface first. Lower rank is stronger.
#:
#: An unknown or reporting action on an *enforce* finding ranks as BLOCK: the
#: policy author said "enforce", and the safe reading of "enforce + verdict we
#: don't understand" is stop, never proceed.
VERDICT_RANK: Dict[str, int] = {BLOCK: 0, STEP_UP: 1, DEFER: 2, MODIFY: 3}


def verdict_of(blocking: Optional[Dict[str, Any]]) -> str:
    """Verdict a blocking finding calls for. ``None`` → ``allow``."""
    if not blocking:
        return ALLOW
    action = str(blocking.get("action") or BLOCK).lower()
    return action if action in VERDICT_RANK else BLOCK


def strongest(findings: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """Pick the finding whose verdict governs, by DENY-wins precedence.

    Callers filter for eligibility first (enforce mode, category, context) —
    this only decides which of the eligible ones is authoritative. ``min`` is
    stable, so ties keep the order the engine surfaced them in.
    """
    if not findings:
        return None
    return min(findings, key=lambda f: VERDICT_RANK.get(
        str(f.get("action") or BLOCK).lower(), 0))


def is_pre_action(agent_event: str) -> bool:
    """Whether this event describes an action that can still be refused."""
    return str(agent_event or "") in PRE_ACTION_EVENTS


# ── decision ─────────────────────────────────────────────────────────────────

@dataclass
class Decision:
    """Outcome of evaluating one tool call.

    ``blocking`` is the single source of truth for the verdict; ``verdict`` and
    ``transform`` derive from it rather than duplicating it, so a caller that
    mutates ``blocking`` (the hook path clears it when a deferred check
    adjudicates ALLOW) can never leave a stale verdict behind.
    """

    allow: bool
    findings: List[Dict[str, Any]] = field(default_factory=list)
    blocking: Optional[Dict[str, Any]] = None
    reason: Optional[str] = None
    subject: Optional["Subject"] = None
    # Engine kept so callers that need post-decision config (e.g. the Claude
    # sandbox rewrite path) don't have to re-instantiate it.
    engine: Optional["PolicyEngine"] = None

    @property
    def verdict(self) -> str:
        """``allow`` | ``block`` | ``step_up`` | ``defer`` | ``modify``.

        What the surface is being asked to DO, as opposed to ``allow``, which
        only says whether the call may proceed unchanged. A surface that cannot
        honor its verdict must fail closed to a refusal — never a silent allow.
        """
        return verdict_of(self.blocking)

    @property
    def transform(self) -> Optional[str]:
        """Named input transform for a ``modify`` verdict (e.g. ``pii_redact``)."""
        return (self.blocking or {}).get("transform") or None

    @property
    def rule_id(self) -> Optional[str]:
        """Rule that produced the verdict — the key every override is keyed on."""
        return (self.blocking or {}).get("ruleId") or None

    def as_dict(self) -> Dict[str, Any]:
        """Wire form, for surfaces that answer over HTTP rather than in-process."""
        return {
            "contract_version": CONTRACT_VERSION,
            "allow": self.allow,
            "verdict": self.verdict,
            "transform": self.transform,
            "rule_id": self.rule_id,
            "reason": self.reason,
            "findings": self.findings,
            "blocking": self.blocking,
            "subject": self.subject.as_dict() if self.subject else None,
        }


# ── surfaces ─────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class Surface:
    """One enforcement point: where Prismor intercepts, and what it can do there.

    ``can_refuse`` — the surface can stop the call before it runs.
    ``can_rewrite`` — it can alter the tool input (``modify`` verdicts).
    ``can_redact``  — it sees the tool OUTPUT and can repair it. This is the
    capability a pre-action hook structurally cannot have, and the reason the
    mirror exists at all.
    """

    id: str
    title: str
    kind: str  # hook | gateway | adapter | service
    module: str
    normalizer: str
    can_refuse: bool
    can_rewrite: bool
    can_redact: bool
    notes: str = ""


#: Every enforcement point in the tree. `prismor doctor` and the docs render
#: from this, so a new surface is announced by adding it here rather than by
#: being remembered in three places.
SURFACES: Tuple[Surface, ...] = (
    Surface(
        id="hook",
        title="Coding-agent hooks",
        kind="hook",
        module="prismor.runtime.cli:hook-dispatch",
        normalizer="prismor.runtime.hooks:normalize_payload",
        can_refuse=True, can_rewrite=True, can_redact=False,
        notes="Widest coverage: the agent keeps its own tools and every call is "
              "screened. Input rewriting is Claude/Qwen PreToolUse only; output "
              "scrubbing is a separate PostToolUse shell path.",
    ),
    Surface(
        id="mcp-gateway",
        title="MCP gateway",
        kind="gateway",
        module="prismor.runtime.mcp_gateway",
        normalizer="prismor.runtime.mcp_gateway:_build_call_event",
        can_refuse=True, can_rewrite=True, can_redact=True,
        notes="One connector in front of every MCP server. Evaluates the call "
              "pre-flight and the result post-flight, and can withhold a "
              "poisoned response.",
    ),
    Surface(
        id="mirror",
        title="Mirrored built-in tools",
        kind="gateway",
        module="prismor.runtime.mirror",
        normalizer="prismor.runtime.mirror:shape_call_event",
        can_refuse=True, can_rewrite=True, can_redact=True,
        notes="Look-alike Bash/Read/Write served over MCP so the tool runs "
              "inside Prismor. Shapes to native event types, so one rule covers "
              "a hooked and a mirrored call alike.",
    ),
    Surface(
        id="sdk-adapter",
        title="Framework SDK adapters",
        kind="adapter",
        module="adapters/*",
        normalizer="per-adapter (in-process tool wrapper)",
        can_refuse=True, can_rewrite=False, can_redact=True,
        notes="In-process interception for LangChain, CrewAI, OpenAI Agents and "
              "the rest. Refuses by raising; no host surface to rewrite through. "
              "Holds the tool's return value before the framework hands it to "
              "the model, so it redacts the result too — except where the "
              "framework's only hook is pre-action (the Claude Agent SDK "
              "PreToolUse hook, BeeAI's tool 'start' event).",
    ),
    Surface(
        id="eval-server",
        title="Evaluation server",
        kind="service",
        module="prismor.runtime.eval_server",
        normalizer="prismor.runtime.eval_server:_build_event",
        can_refuse=True, can_rewrite=True, can_redact=True,
        notes="Local HTTP policy decision point. The lane for non-Python "
              "callers, and the delegation target for an external proxy that "
              "wants Prismor's verdict for traffic it is already carrying.",
    ),
    Surface(
        id="llm-proxy",
        title="LLM proxy",
        kind="gateway",
        module="prismor.runtime.proxy",
        normalizer="prismor.runtime.proxy:Screen.tool_event",
        can_refuse=True, can_rewrite=True, can_redact=True,
        notes="Sits on the model traffic itself (ANTHROPIC_BASE_URL / "
              "OPENAI_BASE_URL), so it governs agents with no hook support at "
              "all. Screens the outbound prompt and every tool_use the model "
              "proposes, reshaped through the mirror's normalizer so one rule "
              "table covers a hooked, mirrored and proposed call alike.",
    ),
    Surface(
        id="inference-hook",
        title="Inference hook channel",
        kind="service",
        module="prismor.runtime.inference_hook",
        normalizer="prismor.runtime.inference_hook (reuses hooks._normalize_claude)",
        can_refuse=True, can_rewrite=False, can_redact=False,
        notes="Hosted webhook channel: replays a transcript turn as events over "
              "a shared taint store and reduces them to one turn verdict.",
    ),
)

SURFACE_IDS: Tuple[str, ...] = tuple(s.id for s in SURFACES)


def surface(surface_id: str) -> Optional[Surface]:
    """Look up a surface by id."""
    return next((s for s in SURFACES if s.id == surface_id), None)


# ── validation ───────────────────────────────────────────────────────────────

def validate_event(event: Any) -> List[str]:
    """Return human-readable problems with a normalized event; empty == valid.

    Advisory, and deliberately not called on the hot path: a malformed event
    should still be evaluated (fewer rules match, but the call is screened)
    rather than throwing and taking the agent down with it. This exists so
    tests and new surfaces can assert they produce what the engine expects,
    instead of discovering a mis-shaped event as a silently missing rule hit.
    """
    problems: List[str] = []
    if not isinstance(event, dict):
        return [f"event must be a dict, got {type(event).__name__}"]

    etype = event.get("type")
    if not etype:
        problems.append("missing 'type'")
    elif etype not in TYPE_FIELD:
        problems.append(
            f"unknown type {etype!r} (known: {', '.join(EVENT_TYPES)}) — "
            "type-scoped rules will not match this event")
    elif etype in TEXT_TYPES:
        # Any folded text field satisfies a text-bearing event, because the
        # engine matches them as one blob. Naming the non-preferred one is
        # legal but costs field-scoped rules, so it is reported as a warning.
        present = [f for f in COMBINED_FIELDS if isinstance(event.get(f), str) and event[f]]
        if not present:
            problems.append(
                f"type {etype!r} requires one of {', '.join(COMBINED_FIELDS)} "
                f"(preferred: {TYPE_FIELD[etype]!r})")
        elif TYPE_FIELD[etype] not in present:
            problems.append(
                f"type {etype!r} uses {present[0]!r}; rules scoped to "
                f"{TYPE_FIELD[etype]!r} will not match this event")
    else:
        value_field = TYPE_FIELD[etype]
        if value_field not in event:
            problems.append(f"type {etype!r} requires a {value_field!r} field")
        elif not isinstance(event[value_field], str):
            problems.append(
                f"{value_field!r} must be a str, got {type(event[value_field]).__name__}")

    meta = event.get("metadata")
    if meta is not None and not isinstance(meta, dict):
        problems.append(f"'metadata' must be a dict, got {type(meta).__name__}")

    agent_event = event.get("agent_event")
    if agent_event is not None and not isinstance(agent_event, str):
        problems.append("'agent_event' must be a str")

    sid = event.get("session_id")
    if sid is not None and not isinstance(sid, str):
        problems.append("'session_id' must be a str")

    return problems


def new_event(
    *,
    etype: str,
    value: str,
    agent: str = "",
    agent_event: str = "PreToolUse",
    session_id: str = "",
    surface_id: str = "",
    tool_name: str = "",
    metadata: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Build a canonical event. Convenience for surfaces and tests.

    Surfaces with real payloads to translate (hooks, the gateway) keep their
    own normalizers — this is for the ones assembling an event from parts, and
    for tests that need one event expressed six ways.
    """
    from datetime import datetime, timezone

    meta: Dict[str, Any] = dict(metadata or {})
    if surface_id:
        meta.setdefault("surface", surface_id)
    if tool_name:
        meta.setdefault("tool_name", tool_name)
    return {
        "ts": datetime.now(timezone.utc).isoformat(),
        "session_id": session_id,
        "agent": agent,
        "agent_event": agent_event,
        "type": etype,
        TYPE_FIELD.get(etype, "command"): value,
        "metadata": meta,
    }
