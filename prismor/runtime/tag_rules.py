"""Tag-rule expression language — policy-as-code over tool tags.

A tiny, dependency-free rule DSL for ``settings.tool_tags.rules``. One rule per
line-string; three keywords; whitespace-tokenized:

    rule      := seq [ "->" action ]
    seq       := term ( ("then" | "with") term )*
    term      := TAG                      # [a-z0-9][a-z0-9_.-]*
    action    := "block" | "warn" | "redact"   # omitted -> "block"

Semantics:
  * ``with`` groups adjacent terms into one unordered step (all tags must
    co-occur in the session — exactly the legacy ``incompatible`` semantics).
  * ``then`` separates ordered steps: every tag of step N must have occurred
    before the occurrences satisfying step N+1.
  * The call that satisfies the *final* step is the one blocked/warned.

Examples:
    untrusted_content with critical_action -> block
    untrusted_content then critical_action -> block
    untrusted_content then private_data then external_comms -> block
    web_read with secrets_access -> warn
    customer_pii then external_comms          (implicit -> block)
    untrusted_content then data.email with dest.external -> redact

``redact`` rewrites the completing call through the ``pii_redact`` transform
(strips classified values from the outbound payload) instead of denying it;
where the surface cannot rewrite input it degrades like any data-boundary
modify verdict (see cli.py).

``not``, ``or``, ``within`` and ``count`` are reserved for future grammar
growth and raise a ParseError today.

Legacy compatibility: :func:`compile_tool_tag_rules` is the single funnel that
compiles both the new ``rules:`` strings and the legacy ``incompatible:`` lists
into one internal representation (:class:`CompiledRule`), so existing policies
keep working byte-for-byte.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from prismor.runtime.trifecta import DEFAULT_RULES, _as_list

ACTIONS = ("block", "warn", "redact")
CONNECTORS = ("then", "with")
RESERVED = ("not", "or", "within", "count")
_TAG_RE = re.compile(r"^[a-z0-9][a-z0-9_.\-]*$")


class ParseError(ValueError):
    """Raised on an invalid rule expression. Carries ``pos`` (0-based char
    offset into the source string) for caret diagnostics."""

    def __init__(self, message: str, expr: str = "", pos: int = 0) -> None:
        super().__init__(message)
        self.expr = expr
        self.pos = pos

    def caret(self) -> str:
        """Two-line diagnostic: the expression and a caret under the error."""
        return f"{self.expr}\n{' ' * self.pos}^ {self.args[0]}"


@dataclass
class CompiledRule:
    """Internal representation shared by DSL rules and legacy incompatible sets."""

    steps: List[Set[str]]  # ordered steps; each step is an unordered tag set
    action: str = "block"  # "block" | "warn" | "redact"
    source: str = ""  # original expression, or "incompatible" for legacy rows
    rule_id: str = field(default="")

    def __post_init__(self) -> None:
        if not self.rule_id:
            norm = ";".join(",".join(sorted(s)) for s in self.steps) + "|" + self.action
            self.rule_id = hashlib.sha256(norm.encode("utf-8")).hexdigest()[:10]

    @property
    def ordered(self) -> bool:
        return len(self.steps) > 1

    @property
    def all_tags(self) -> Set[str]:
        out: Set[str] = set()
        for s in self.steps:
            out |= s
        return out


def _tokenize(expr: str) -> List[Tuple[str, int]]:
    """Split on whitespace, keeping each token's start offset."""
    toks: List[Tuple[str, int]] = []
    for m in re.finditer(r"\S+", expr):
        toks.append((m.group(0), m.start()))
    return toks


def compile_rule(expr: str) -> CompiledRule:
    """Compile one rule expression string into a :class:`CompiledRule`."""
    if not isinstance(expr, str):
        raise ParseError("rule must be a string", str(expr), 0)
    toks = _tokenize(expr)
    if not toks:
        raise ParseError("empty rule", expr, 0)

    # Optional trailing "-> action".
    action = "block"
    if any(t == "->" for t, _ in toks):
        arrow_i = next(i for i, (t, _) in enumerate(toks) if t == "->")
        tail = toks[arrow_i + 1 :]
        if arrow_i != len(toks) - 2 or not tail:
            pos = toks[arrow_i][1]
            raise ParseError("'->' must be followed by exactly one action", expr, pos)
        act_tok, act_pos = tail[0]
        if act_tok not in ACTIONS:
            raise ParseError(
                f"unknown action '{act_tok}' (expected {' or '.join(ACTIONS)})",
                expr, act_pos,
            )
        action = act_tok
        toks = toks[:arrow_i]
        if not toks:
            raise ParseError("rule has no tags before '->'", expr, 0)

    # seq := term ( connector term )*
    steps: List[Set[str]] = []
    current: Set[str] = set()
    expect_term = True
    for tok, pos in toks:
        if expect_term:
            low = tok.lower()
            if low in RESERVED:
                raise ParseError(
                    f"'{tok}' is reserved for future use", expr, pos
                )
            if low in CONNECTORS or tok == "->":
                raise ParseError(f"expected a tag, got '{tok}'", expr, pos)
            if not _TAG_RE.match(tok):
                raise ParseError(
                    f"invalid tag '{tok}' (allowed: [a-z0-9][a-z0-9_.-]*)",
                    expr, pos,
                )
            current.add(tok)
            expect_term = False
        else:
            if tok == "then":
                steps.append(current)
                current = set()
                expect_term = True
            elif tok == "with":
                expect_term = True
            else:
                raise ParseError(
                    f"expected 'then', 'with' or '->', got '{tok}'", expr, pos
                )
    if expect_term:
        # Trailing connector like "a then".
        tok, pos = toks[-1]
        raise ParseError(f"dangling '{tok}' at end of rule", expr, pos)
    steps.append(current)

    if len(steps) == 1 and len(steps[0]) < 2:
        raise ParseError(
            "a rule needs at least two tags (a single tag can never be a "
            "combination)", expr, 0,
        )
    return CompiledRule(steps=steps, action=action, source=expr.strip())


def lint_rules(exprs: List[str]) -> List[Tuple[str, ParseError]]:
    """Validate rule strings; return (expr, error) pairs for the invalid ones."""
    errors: List[Tuple[str, ParseError]] = []
    for expr in exprs:
        try:
            compile_rule(expr)
        except ParseError as e:
            errors.append((expr, e))
    return errors


def _coerce_rule_entry(entry: Any) -> Optional[CompiledRule]:
    """Compile one ``rules:`` entry — a DSL string or an {expr, action} map."""
    if isinstance(entry, str):
        return compile_rule(entry)
    if isinstance(entry, dict):
        expr = entry.get("expr")
        if not isinstance(expr, str):
            raise ParseError("rule map needs an 'expr' string", str(entry), 0)
        rule = compile_rule(expr)
        act = entry.get("action")
        if act in ACTIONS and act != rule.action:
            # Explicit map action overrides the expression's (or the default).
            rule = CompiledRule(steps=rule.steps, action=act, source=rule.source)
        return rule
    raise ParseError("rule must be a string or an {expr, action} map", str(entry), 0)


def compile_tool_tag_rules(tt: Optional[Dict[str, Any]]) -> List[CompiledRule]:
    """Compile ``settings.tool_tags`` (both ``rules`` and legacy ``incompatible``)
    into one rule list. Invalid DSL entries are skipped (policy loading must not
    crash the engine); use :func:`lint_rules` to surface them. Falls back to
    :data:`prismor.runtime.trifecta.DEFAULT_RULES` only when both lists yield
    nothing."""
    tt = tt or {}
    out: List[CompiledRule] = []

    raw_rules = tt.get("rules")
    if isinstance(raw_rules, (list, tuple)):
        for entry in raw_rules:
            try:
                rule = _coerce_rule_entry(entry)
            except ParseError:
                continue
            if rule is not None:
                out.append(rule)

    raw_incompat = tt.get("incompatible")
    if isinstance(raw_incompat, (list, tuple)):
        for item in raw_incompat:
            tags = {str(t) for t in _as_list(item)}
            if len(tags) >= 2:  # single-tag "set" can never be a combination
                out.append(
                    CompiledRule(steps=[tags], action="block", source="incompatible")
                )

    if not out:
        for expr in DEFAULT_RULES:
            try:
                rule = compile_rule(expr)
            except ParseError:  # pragma: no cover - constants are linted in CI
                continue
            rule.source = "default"
            out.append(rule)
    return out
