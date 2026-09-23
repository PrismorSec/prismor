"""`prismor allow` — make an exception to a policy rule from one command.

A block that ends in "paste this YAML into policy.yaml" is a block most people
resolve by turning Prismor off instead. This is the same narrow-to-broad ladder
`unblock.py` prints, as something a person can actually run:

    prismor allow <rule> --pattern '<literal>'   allow exactly this case
    prismor allow <rule> --observe               keep the rule, stop it blocking
    prismor allow <rule> --off                   turn the rule off in this repo

The order matters — each rung gives up more than the one above it, so the
default is the narrowest, and the broad ones ask for confirmation.

What this command will not do, no matter who runs it:

* touch a self-protection rule, or any rule on an org-managed workspace;
* turn a safety-floor rule off entirely.

And what it will not do *for an agent*: writing here is guarded by the
self-edit rules in default_policy.yaml, so an agent that runs this on its own
behalf is blocked before the command starts. It runs for an agent only inside
a password-verified unlock window (`prismor unlock`).
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from prismor.runtime.policy_engine import (
    _CORE_BLOCK_CATEGORIES,
    _NON_OVERRIDABLE_RULE_IDS,
    is_self_protection_rule,
)

# Longest evidence we will paste back as a literal pattern. Beyond this the
# string is probably a whole command line whose incidental parts (pids, temp
# paths, timestamps) never recur, so the entry would be dead on arrival while
# looking like a working exception.
_MAX_LITERAL_EVIDENCE = 120

_DURATION_RE = re.compile(r"^(\d+)\s*([smhd])$", re.IGNORECASE)
_UNIT_SECONDS = {"s": 1, "m": 60, "h": 3600, "d": 86400}


# ── shared with unblock.py ───────────────────────────────────────────────────

def literal_pattern(evidence: str) -> Optional[str]:
    """A regex matching exactly this evidence, or None if it won't generalize.

    Three things make a suggestion worse than none, because each yields an entry
    that looks right and silently never matches: truncated evidence, evidence
    long enough to be a whole command line, and embedded newlines (YAML folds
    those into spaces inside a quoted scalar). Evidence joins matched fields
    with newlines and allowlists match with `search`, so the first line alone
    still hits the joined blob.
    """
    first_line = str(evidence or "").strip().split("\n", 1)[0].strip()
    if not first_line or first_line.endswith("...") or len(first_line) > _MAX_LITERAL_EVIDENCE:
        return None
    return re.escape(first_line)


def yaml_single_quoted(value: str) -> str:
    """Quote a regex for YAML single-quoted style.

    Regexes are full of backslashes and YAML's double-quoted style would read
    `\\.` as an unknown escape and refuse to parse. Single-quoted is literal —
    only the quote itself needs doubling.
    """
    return "'" + value.replace("'", "''") + "'"


def parse_duration(text: str) -> Optional[int]:
    """`30m` / `2h` / `7d` → seconds. None if unparseable."""
    m = _DURATION_RE.match(str(text or "").strip())
    if not m:
        return None
    return int(m.group(1)) * _UNIT_SECONDS[m.group(2).lower()]


# ── policy file I/O ──────────────────────────────────────────────────────────

def policy_path(workspace: Path) -> Path:
    return workspace / ".prismor" / "policy.yaml"


def _load(path: Path) -> Tuple[List[str], Dict[str, Any]]:
    """Return (leading comment lines, parsed data).

    The header `prismor setup` writes explains what the file means, so it is
    carried across rewrites rather than dumped away by the YAML round-trip.
    """
    if not path.exists():
        return [], {}
    text = path.read_text(encoding="utf-8")
    header: List[str] = []
    for line in text.splitlines():
        if line.startswith("#") or not line.strip():
            header.append(line)
            continue
        break
    while header and not header[-1].strip():
        header.pop()
    try:
        import yaml
        data = yaml.safe_load(text)
    except ImportError:
        raise RuntimeError("PyYAML is required to edit policy.yaml (pip install pyyaml)")
    return header, data if isinstance(data, dict) else {}


def _save(path: Path, header: List[str], data: Dict[str, Any]) -> None:
    import yaml
    path.parent.mkdir(parents=True, exist_ok=True)
    # `default_flow_style=None` keeps lists of mappings in block style (the rules
    # and allowlist entries stay one field per line, which is what people read
    # and edit) while collapsing lists of plain scalars — `rule_ids: [risky-write]`
    # rather than four lines to say one rule id.
    body = yaml.safe_dump(data, sort_keys=False, default_flow_style=None, width=100)
    text = ("\n".join(header) + "\n" if header else "") + body
    path.write_text(text, encoding="utf-8")


# ── guards ───────────────────────────────────────────────────────────────────

def _default_rule(rule_id: str) -> Optional[Dict[str, Any]]:
    from prismor.runtime.policy_engine import _load_yaml
    data = _load_yaml(Path(__file__).resolve().parent / "default_policy.yaml") or {}
    for rule in data.get("rules", []) or []:
        if isinstance(rule, dict) and rule.get("id") == rule_id:
            return rule
    return None


def is_floor_rule(rule_id: str, rule: Optional[Dict[str, Any]] = None) -> bool:
    rule = rule if rule is not None else _default_rule(rule_id)
    category = str((rule or {}).get("category") or "")
    return rule_id in _NON_OVERRIDABLE_RULE_IDS or category in _CORE_BLOCK_CATEGORIES


def check_allowed(
    rule_id: str,
    *,
    scope: str,
    workspace: Path,
    confirmed: bool = False,
    explicit_selection: bool = False,
) -> Optional[str]:
    """Why this edit is refused, or None if it may proceed.

    ``scope`` is the rung of the ladder: "pattern", "observe" or "off".
    """
    if is_self_protection_rule(rule_id):
        return (
            f"{rule_id} is one of the rules Prismor uses to guard itself, so it "
            "cannot be relaxed from here — an agent that could would be able to "
            "undo every other rule too. Policy-file overrides on it are ignored "
            "for the same reason.\n"
            "If it is blocking legitimate work: run the command yourself in your "
            "own terminal (Prismor governs agent tool calls, not you), or open a "
            "short agent self-edit window with: prismor unlock"
        )

    try:
        from prismor.runtime.store import is_policy_editable
        editable = is_policy_editable(workspace)
    except Exception:
        editable = {"editable": True}
    if not editable.get("editable", True):
        return (
            "This workspace is managed by your organization — its signed policy "
            "would overwrite a local change on the next pull.\n"
            'Ask an admin instead: prismor exempt request --reason "<why>"'
        )

    rule = _default_rule(rule_id)
    if rule is None:
        return f"No rule named '{rule_id}'. List them with: prismor policy show"

    if is_floor_rule(rule_id, rule):
        if scope == "off":
            return (
                f"{rule_id} is a safety-floor rule; `enabled: false` is ignored for "
                "it in every policy layer, so turning it off would not clear the "
                "block — it would just look like it had.\n"
                f"Allow the one case instead: prismor allow {rule_id} --pattern '<literal>'"
            )
        if scope == "observe" and not explicit_selection:
            return (
                f"{rule_id} is a safety-floor rule and this policy does not use "
                "explicit selection, so `mode: observe` would be ignored for it.\n"
                f"Allow the one case instead: prismor allow {rule_id} --pattern '<literal>'"
            )
        if not confirmed:
            what = (
                "stop a safety-floor rule blocking" if scope == "observe"
                else "punch a hole in a safety-floor rule"
            )
            return f"This would {what}. Re-run with --yes if that is what you want."

    if scope == "off" and not confirmed:
        return (
            f"`--off` disables {rule_id} for this repo entirely — it will not even "
            "be reported. Re-run with --yes, or use --observe to keep the reporting."
        )
    return None


# ── the ladder ───────────────────────────────────────────────────────────────

def _next_allow_id(data: Dict[str, Any], rule_id: str) -> str:
    existing = {str(e.get("id")) for e in (data.get("allowlists") or []) if isinstance(e, dict)}
    base = f"allow-{rule_id}"
    if base not in existing:
        return base
    n = 2
    while f"{base}-{n}" in existing:
        n += 1
    return f"{base}-{n}"


def add_allowlist(
    workspace: Path,
    rule_id: str,
    pattern: str,
    *,
    reason: str = "",
    expires_seconds: Optional[int] = None,
) -> Dict[str, Any]:
    header, data = _load(policy_path(workspace))
    data.setdefault("version", "1.0")
    entries = list(data.get("allowlists") or [])
    default_reason = "added by `prismor allow`"
    expires = (
        (datetime.now(timezone.utc) + timedelta(seconds=expires_seconds))
        .isoformat().replace("+00:00", "Z")
        if expires_seconds else None
    )

    # Fold into an existing entry for the same rule when nothing distinguishes
    # them. Three `prismor allow risky-write --pattern ...` calls used to leave
    # three near-identical seven-line blocks; as one entry with three patterns
    # it means exactly the same thing to the engine and stays readable.
    # Entries carrying a reason or an expiry keep their own block, since those
    # are per-exception facts that a merge would silently widen.
    if not expires and not reason:
        for existing in entries:
            if (isinstance(existing, dict)
                    and list(existing.get("rule_ids") or []) == [rule_id]
                    and not existing.get("expires")
                    and str(existing.get("reason") or default_reason) == default_reason):
                pats = list(existing.get("patterns") or [])
                if pattern not in pats:
                    pats.append(pattern)
                    existing["patterns"] = pats
                    data["allowlists"] = entries
                    _save(policy_path(workspace), header, data)
                return existing

    entry: Dict[str, Any] = {
        "id": _next_allow_id(data, rule_id),
        "rule_ids": [rule_id],
        "patterns": [pattern],
        "reason": reason or default_reason,
    }
    if expires:
        entry["expires"] = expires
    entries.append(entry)
    data["allowlists"] = entries
    _save(policy_path(workspace), header, data)
    return entry


def set_rule_mode(workspace: Path, rule_id: str, mode: str) -> None:
    """Set (or clear) a rule's mode without disturbing the rest of its entry."""
    header, data = _load(policy_path(workspace))
    data.setdefault("version", "1.0")
    rules = list(data.get("rules") or [])
    for rule in rules:
        if isinstance(rule, dict) and rule.get("id") == rule_id:
            rule["mode"] = mode
            break
    else:
        rules.append({"id": rule_id, "mode": mode})
    data["rules"] = rules
    _save(policy_path(workspace), header, data)


def set_rule_enabled(workspace: Path, rule_id: str, enabled: bool) -> None:
    header, data = _load(policy_path(workspace))
    data.setdefault("version", "1.0")
    rules = list(data.get("rules") or [])
    for rule in rules:
        if isinstance(rule, dict) and rule.get("id") == rule_id:
            rule["enabled"] = enabled
            break
    else:
        rules.append({"id": rule_id, "enabled": enabled})
    data["rules"] = rules
    _save(policy_path(workspace), header, data)


def list_allows(workspace: Path) -> List[Dict[str, Any]]:
    _, data = _load(policy_path(workspace))
    out = []
    for entry in data.get("allowlists") or []:
        if isinstance(entry, dict) and entry.get("id"):
            out.append(entry)
    return out


def undo(workspace: Path, target: str) -> bool:
    """Remove an exception by entry id, or a single pattern out of one.

    Folding repeat allows into one entry keeps the file readable but would make
    exceptions harder to retract than to grant, so ``target`` also matches a
    pattern: the pattern goes, and the entry with it once it holds nothing.
    """
    header, data = _load(policy_path(workspace))
    entries = list(data.get("allowlists") or [])

    kept = [e for e in entries if not (isinstance(e, dict) and str(e.get("id")) == target)]
    if len(kept) != len(entries):
        data["allowlists"] = kept
        _save(policy_path(workspace), header, data)
        return True

    changed = False
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        patterns = list(entry.get("patterns") or [])
        if target in patterns:
            patterns.remove(target)
            entry["patterns"] = patterns
            changed = True
    if not changed:
        return False
    data["allowlists"] = [
        e for e in entries
        if not (isinstance(e, dict) and not (e.get("patterns") or []))
    ]
    _save(policy_path(workspace), header, data)
    return True


def last_evidence_for_rule(workspace: Path, rule_id: str) -> Optional[str]:
    """Evidence from the most recent finding for this rule, if one is recorded.

    Lets `prismor allow <rule>` fill in the pattern from the block that just
    happened, rather than making the user retype the command that failed.
    """
    import json
    import sqlite3
    try:
        from prismor.runtime.store import prismor_home
        db = prismor_home() / "prismor.db"
        if not db.exists():
            return None
        conn = sqlite3.connect(str(db))
        try:
            rows = conn.execute(
                "SELECT evidence, enrichment_json FROM findings "
                "WHERE enrichment_json LIKE ? ORDER BY rowid DESC LIMIT 25",
                (f'%"{rule_id}"%',),
            ).fetchall()
        finally:
            conn.close()
    except Exception:
        return None
    for evidence, enrichment in rows:
        try:
            if json.loads(enrichment or "{}").get("ruleId") == rule_id and evidence:
                return str(evidence)
        except Exception:
            continue
    return None
