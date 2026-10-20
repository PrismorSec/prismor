"""Safety-floor rules a human turned off with the unlock password.

The floor (``policy_engine._NON_OVERRIDABLE_RULE_IDS`` plus the core block
categories) ignores ``enabled: false`` in every policy file, so no agent and no
stray YAML edit can switch it off. Sometimes the person at the keyboard really
does want one off, though, and the only way used to be editing the package.

This file is that switch, gated the same way as ``prismor unlock``: the
dashboard turns a floor rule off only after ``unlock.verify`` accepts the
password, and the record carries a MAC keyed from the stored credential, so a
file written without the password is ignored. As with the unlock grant, the
MAC is a speed bump against a same-user writer; the boundary is the hook, which
blocks agents from writing this file or calling the dashboard API.

Never honored for the self-protection rules (an agent free to rewrite Prismor's
policy makes every other setting meaningless; ``prismor unlock`` covers the
one-off case) or on an org-managed workspace, where the floor is the org's.
"""
from __future__ import annotations

import hashlib
import hmac
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Set

from prismor.runtime import unlock

_SCHEMA = "prismor.floor-off.v1"


def path() -> Path:
    return unlock.prismor_home() / "floor-off.json"


def _mac(rules: Dict[str, Any], key: bytes) -> str:
    payload = json.dumps({"schema": _SCHEMA, "rules": rules}, sort_keys=True, separators=(",", ":"))
    return hmac.new(key, payload.encode(), hashlib.sha256).hexdigest()


def _load() -> Dict[str, Any]:
    """The verified ``{rule_id: {at, by}}`` map; empty when absent, unsigned or tampered."""
    rec = unlock._read(path())
    key = unlock._grant_key()
    if not rec or not key or rec.get("schema") != _SCHEMA or not isinstance(rec.get("rules"), dict):
        return {}
    if not hmac.compare_digest(str(rec.get("mac") or ""), _mac(rec["rules"], key)):
        return {}
    return rec["rules"]


def _save(rules: Dict[str, Any]) -> None:
    key = unlock._grant_key()
    if key is None:
        raise ValueError("No unlock password is set. Run: prismor unlock --set-password")
    unlock._write_private(path(), {"schema": _SCHEMA, "rules": rules, "mac": _mac(rules, key)})


def active_ids() -> Set[str]:
    """Floor rules currently turned off. Never raises."""
    try:
        return set(_load())
    except Exception:
        return set()


def turn_off(rule_id: str, by: str = "") -> None:
    """Record ``rule_id`` as off. The caller must already have verified the password."""
    from prismor.runtime.policy_engine import is_self_protection_rule
    if is_self_protection_rule(rule_id):
        raise ValueError(f"{rule_id} guards Prismor itself and cannot be turned off; use prismor unlock")
    rules = _load()
    rules[rule_id] = {"at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"), "by": by[:120]}
    _save(rules)


def turn_on(rule_id: str) -> None:
    """Put ``rule_id`` back under the floor. Needs no password: it only tightens."""
    rules = _load()
    if rules.pop(rule_id, None) is not None:
        _save(rules)
