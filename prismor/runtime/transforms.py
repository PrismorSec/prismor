"""Named action transforms for the R4 MODIFY verdict.

A policy rule may resolve to ``action: modify`` and name a transform via
``transform: <name>``. When such a finding blocks a ``PreToolUse`` event on an
agent that can rewrite tool input (see :mod:`prismor.runtime.hook_caps`), the
hook dispatcher rewrites the input through the named transform and emits it in
that agent's shape — the action still runs, but in a safer form. On any surface
that cannot rewrite tool input (Copilot, Cursor, framework adapters), the caller
fails closed to DENY rather than silently allowing the un-transformed action.

A transform receives the raw hook ``payload`` plus context and returns a Claude
hook-output dict (carrying ``updatedInput``), or ``None`` when it declines / is
not applicable — in which case the caller treats the MODIFY as unsatisfiable and
denies.

Two transforms ship today; both generalize behavior that already existed as
one-off paths:

  - ``sandbox`` — wrap a Bash command into the Docker sandbox runner
    (reuses :func:`prismor.runtime.sandbox.claude_updated_input`).
  - ``cloak``   — secret substitution; applied out-of-band by the decloak hook,
    so the inline rewrite is a no-op placeholder registered for policy symmetry.

New transforms register with :func:`register` and become available to policy
authors immediately.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Callable, Dict, Optional, Tuple

# A transform maps (payload, workspace, mode) -> Claude hookSpecificOutput dict
# with an ``updatedInput`` key, or None if it cannot apply.
TransformFn = Callable[..., Optional[Dict[str, Any]]]

_REGISTRY: Dict[str, TransformFn] = {}


def register(name: str) -> Callable[[TransformFn], TransformFn]:
    """Decorator: register ``fn`` as the transform named ``name``."""

    def _wrap(fn: TransformFn) -> TransformFn:
        _REGISTRY[name] = fn
        return fn

    return _wrap


def available(name: str) -> bool:
    """True when a transform named ``name`` is registered."""
    return name in _REGISTRY


def names() -> list[str]:
    """Sorted list of registered transform names (for docs / validation)."""
    return sorted(_REGISTRY)


def apply_transform(
    name: str,
    *,
    payload: Dict[str, Any],
    workspace: Path,
    mode: str,
) -> Optional[Dict[str, Any]]:
    """Run the named transform.

    Returns a Claude hook-output dict with ``updatedInput`` when the transform
    applied, or ``None`` when the transform is unknown, declined, or raised
    (the caller must then fail closed to DENY).
    """
    fn = _REGISTRY.get(name)
    if fn is None:
        return None
    try:
        return fn(payload=payload, workspace=workspace, mode=mode)
    except Exception:
        # A transform that errors must not fall through to ALLOW — return None
        # so the caller denies. Failures are best-effort observable upstream.
        return None


@register("sandbox")
def _sandbox_transform(*, payload, workspace, mode):
    """Rewrite a Bash command to run inside the Docker sandbox."""
    from prismor.runtime import sandbox as _sandbox

    return _sandbox.claude_updated_input(
        payload=payload, workspace=Path(workspace), mode=mode
    )


@register("cloak")
def _cloak_transform(*, payload, workspace, mode):
    """Secret substitution is applied by the decloak hook, not here.

    Registered so ``action: modify, transform: cloak`` validates; the inline
    rewrite is a no-op (returns None), so this transform alone will fail closed
    unless secret substitution has already been handled out-of-band.
    """
    return None


@register("memory_redact")
def _memory_redact_transform(*, payload, workspace, mode):
    """Strip flagged operational directives from a write to an instruction file.

    The memory-poisoning rules are detection-only by design — a poisoned line
    already on disk cannot be un-read, which is what the SessionStart
    counter-instruction is for. A *write*, though, is interceptable: this drops
    the offending lines before they ever land, so the next session has nothing
    to load.

    Reuses the compiled ``memory-directive-on-write`` patterns rather than
    restating them, so an overlay that tunes the rule automatically tunes what
    gets redacted. Declines (``None``) when nothing matched, which the caller
    treats as an unsatisfiable MODIFY and denies — so this never silently
    passes a write it failed to clean.
    """
    from prismor.runtime.policy_engine import PolicyEngine

    tool_input = payload.get("tool_input")
    if not isinstance(tool_input, dict):
        return None
    # Write carries `content`; a plain Edit carries `new_string`.
    key = next((k for k in ("content", "new_string") if tool_input.get(k)), "")
    if not key:
        return None

    rule = next(
        (r for r in PolicyEngine(workspace=Path(workspace)).rules
         if r.id == "memory-directive-on-write"),
        None,
    )
    if rule is None:
        return None

    kept: list[str] = []
    removed = 0
    for line in str(tool_input[key]).splitlines(keepends=True):
        if line.strip() and rule.patterns.search(line):
            removed += 1
            continue
        kept.append(line)
    if not removed:
        return None

    new_input = dict(tool_input)
    new_input[key] = "".join(kept)
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "updatedInput": new_input,
        }
    }


@register("pii_redact")
def _pii_redact_transform(*, payload, workspace, mode):
    """Strip sensitive values from an outbound shell command before it runs.

    Applies only to values the data-boundary classifier found in URL query
    strings and request bodies (``curl -d … https://…?email=…``). Values passed
    as CLI flags are never redacted here — the engine downgrades those to
    step_up, because dropping a required flag breaks the command and sends the
    agent hunting for another way to supply the value. Declines (``None`` →
    deny) when nothing could be located, so a call is never silently passed
    through un-cleaned.
    """
    from prismor.runtime.data_boundary import (
        DataBoundaryPolicy, classify, extract_outbound, redact_command,
    )
    from prismor.runtime.policy_engine import PolicyEngine

    tool_input = payload.get("tool_input")
    if not isinstance(tool_input, dict):
        return None
    command = tool_input.get("command")
    if not isinstance(command, str) or not command.strip():
        return None

    try:
        policy = PolicyEngine(workspace=Path(workspace)).data_boundary
    except Exception:
        policy = DataBoundaryPolicy()

    matches = []
    for ob in extract_outbound({"type": "shell", "command": command}):
        if ob.dest is not None and ob.dest.is_private:
            continue
        for ctx, text in ob.parts:
            if ctx in ("query", "body", "header"):
                matches.extend(m for m in classify(text, policy=policy, context=ctx)
                               if not m.synthetic)
    if not matches:
        return None
    new_command, n = redact_command(command, matches)
    if not n or new_command == command:
        return None
    kinds = sorted({m.kind for m in matches})
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "updatedInput": {**tool_input, "command": new_command},
        },
        # Surfaced to the user (and model) so a changed call is never a mystery.
        "systemMessage": (
            f"Prismor redacted {', '.join(kinds)} from this outbound call "
            f"(policy: data_boundary). {n} value(s) replaced with [REDACTED:*]."
        ),
    }


def _rewrite_strings(value: Any, settings: Any) -> Tuple[Any, int]:
    """Mask PII in every string of a tool-input tree. Returns ``(value, count)``."""
    from prismor.runtime.pii import anonymize, detect

    count = 0

    def _one(text: str) -> str:
        nonlocal count
        found = detect(text, settings)
        if not found.hits:
            return text
        updated = anonymize(text, found.hits, settings.mask_style)
        if updated != text:
            count += len(found.hits)
        return updated

    def _walk(node: Any) -> Any:
        if isinstance(node, str):
            return _one(node)
        if isinstance(node, dict):
            return {k: _walk(v) for k, v in node.items()}
        if isinstance(node, list):
            return [_walk(v) for v in node]
        return node

    return _walk(value), count


@register("pii_ner_redact")
def _pii_ner_redact_transform(*, payload, workspace, mode):
    """Mask NER/Presidio hits in a tool's input before the call runs.

    Applies when ``settings.pii.action`` is ``redact`` and ``mode`` is
    ``enforce``. Entity types are named in the system message; the values
    are not. Declines (``None`` → deny) when nothing was masked, so a call
    is never passed through un-cleaned after a redact verdict.
    """
    from prismor.runtime.policy_engine import PolicyEngine

    tool_input = payload.get("tool_input")
    if not isinstance(tool_input, dict):
        return None
    try:
        settings = PolicyEngine(workspace=Path(workspace)).pii
    except Exception:
        return None
    if not settings.enabled or settings.action != "redact" or settings.mode != "enforce":
        return None
    rewritten, count = _rewrite_strings(tool_input, settings)
    if not count or rewritten == tool_input:
        return None
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "updatedInput": rewritten,
        },
        "systemMessage": (
            f"Prismor redacted {count} PII value(s) from this call "
            "(policy: settings.pii, style: "
            f"{settings.mask_style})."
        ),
    }
