"""DEFER verdict — hold an ambiguous action and escalate to a deeper evaluator.

The fast policy path decides ALLOW/DENY/MODIFY/STEP_UP on the current event. A
rule that resolves to ``action: defer`` is saying "this action is too ambiguous
to adjudicate on the fast path — pause and gather more context before deciding."

DEFER routes the held action to the **semantic guard** (the hybrid heuristic +
local-LLM judge that is too costly to run on every call), then **caches** the
verdict per session+action so the agent's retry of the same action resolves
instantly and consistently — the "gather once, then remember" contract.

Resolution: a block-level semantic verdict → DENY; anything else → ALLOW. A cache
hit short-circuits the evaluator. Any evaluator error fails closed (DENY): a
deferred action that cannot be adjudicated is never allowed through.

The cache lives at ``$PRISMOR_HOME/deferred/<session>.json`` (one small file per
session). Never raises into the caller — worst case returns DENY.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Dict, Optional

from prismor.runtime.enterprise import identity as _identity

_ALLOW = "allow"
_DENY = "deny"


def _cache_dir() -> Path:
    return _identity.prismor_home() / "deferred"


def _cache_path(session_id: str) -> Path:
    safe = "".join(c if c.isalnum() or c in "-_." else "_" for c in (session_id or "nosession"))[:120]
    return _cache_dir() / f"{safe}.json"


def _load_cache(session_id: str) -> Dict[str, str]:
    try:
        data = json.loads(_cache_path(session_id).read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _save_cache(session_id: str, cache: Dict[str, str]) -> None:
    try:
        path = _cache_path(session_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(cache), encoding="utf-8")
        tmp.replace(path)
    except OSError:
        pass


def _fingerprint(session_id: str, finding: Dict[str, Any], event: Optional[Dict[str, Any]] = None) -> str:
    """Stable key for one logical deferred action within a session. The call
    itself is part of it, so one call's ALLOW never covers a different call
    that trips the same rule."""
    from prismor.runtime.enterprise.approvals import call_key
    tool = str(finding.get("toolName") or finding.get("tool") or "")
    marker = str(
        finding.get("evidence_hash")
        or finding.get("evidenceHash")
        or finding.get("pattern")
        or finding.get("ruleId")
        or ""
    )
    raw = f"{session_id}\x1f{tool}\x1f{marker}\x1f{call_key(event)}".encode("utf-8")
    return hashlib.sha256(raw).hexdigest()[:32]


def _adjudicate(event: Optional[Dict[str, Any]]) -> str:
    """Run the deeper semantic evaluator over the held action. Block-level
    verdict → deny; else allow. Any failure → deny (fail closed)."""
    if not isinstance(event, dict):
        return _DENY
    try:
        from prismor.runtime.semantic_guard_v2 import SemanticGuardV2

        risk = SemanticGuardV2().analyze_event(event)
        action = str(getattr(risk.final, "recommended_action", "") or "").lower()
        return _DENY if action == "block" else _ALLOW
    except Exception:
        return _DENY


def resolve_defer(
    finding: Dict[str, Any],
    event: Optional[Dict[str, Any]],
    *,
    session_id: str = "",
    workspace: Optional[Path] = None,
) -> bool:
    """Adjudicate a DEFER finding. Returns True to ALLOW, False to DENY.

    Cache hit → cached verdict. Miss → run the deeper evaluator, cache it, return.
    Never raises; fails closed to DENY on any error.
    """
    fp = _fingerprint(session_id, finding, event)
    cache = _load_cache(session_id)
    cached = cache.get(fp)
    if cached in (_ALLOW, _DENY):
        return cached == _ALLOW

    verdict = _adjudicate(event)
    cache[fp] = verdict
    _save_cache(session_id, cache)
    return verdict == _ALLOW
