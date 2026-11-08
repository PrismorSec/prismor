"""Local allow / ask / deny decisions made from the dashboard.

One decision says what to do with either a rule (optionally only for one exact
call) or a tool tag, at a scope:

    {"id", "target": "rule"|"tool", "ruleId"|"tool", "pattern"?,
     "action": "allow"|"ask"|"deny", "scope": "session"|"agent"|"workspace"|"device",
     "scopeId"?, "workspace"?, "created", "expires"?}

They are stored in ~/.prismor/decisions.json and handed to the runtime in the
same shapes the signed org policy uses (settings.rule_exemptions and
settings.tool_denies), so one matcher in runtime.py serves both the console
and this machine. Writing the file is guarded by prismor-self-edit, so an agent
cannot grant itself an allow.
"""
from __future__ import annotations

import secrets
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

ACTIONS = ("allow", "ask", "deny")
SCOPES = ("session", "agent", "workspace", "device")


def path() -> Path:
    from prismor.runtime.store import prismor_home
    return prismor_home() / "decisions.json"


def list_all() -> List[Dict[str, Any]]:
    import json
    try:
        data = json.loads(path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    items = data.get("decisions") if isinstance(data, dict) else None
    return [d for d in (items or []) if isinstance(d, dict) and not (d.get("expires") and d["expires"] < now)]


def add(decision: Dict[str, Any]) -> Dict[str, Any]:
    """Validate and store one decision; returns it with its id."""
    target = decision.get("target")
    action = decision.get("action")
    scope = decision.get("scope")
    if target not in ("rule", "tool"):
        raise ValueError("target must be rule or tool")
    if action not in ACTIONS:
        raise ValueError("action must be allow, ask or deny")
    if scope not in SCOPES:
        raise ValueError("scope must be session, agent, workspace or device")
    key = "ruleId" if target == "rule" else "tool"
    if not str(decision.get(key) or "").strip():
        raise ValueError(f"{key} required")
    if scope in ("session", "agent") and not decision.get("scopeId"):
        raise ValueError(f"scopeId required for {scope} scope")
    if scope == "workspace" and not decision.get("workspace"):
        raise ValueError("workspace required for workspace scope")
    if target == "rule":
        from prismor.runtime.policy_engine import is_self_protection_rule
        rule_id = str(decision["ruleId"])
        if action != "deny" and is_self_protection_rule(rule_id):
            raise ValueError(f"{rule_id} guards Prismor itself and cannot be relaxed")
        if action != "deny" and _is_floor(rule_id) and not decision.get("pattern"):
            raise ValueError(f"{rule_id} is a safety-floor rule: allow or ask only for one exact call (pattern)")
    keep = ("target", "ruleId", "tool", "pattern", "action", "scope", "scopeId", "workspace", "expires", "reason")
    rec = {k: decision[k] for k in keep if decision.get(k) not in (None, "")}
    rec["id"] = secrets.token_hex(4)
    rec["created"] = time.time()

    from prismor.runtime.store import locked_json_update
    with locked_json_update(path()) as data:
        items = [d for d in (data.get("decisions") or []) if isinstance(d, dict)]
        # The newest decision for the same thing at the same scope replaces the
        # old one, so flipping allow -> deny never leaves both behind.
        same = ("target", "ruleId", "tool", "pattern", "scope", "scopeId", "workspace")
        replaced = [d for d in items if all(d.get(k) == rec.get(k) for k in same)]
        items = [d for d in items if any(d.get(k) != rec.get(k) for k in same)]
        items.append(rec)
        data["decisions"] = items
    _audit("decision_added", rec, before=replaced[0] if replaced else None, after=rec)
    return rec


def remove(decision_id: str) -> bool:
    from prismor.runtime.store import locked_json_update
    with locked_json_update(path()) as data:
        items = [d for d in (data.get("decisions") or []) if isinstance(d, dict)]
        kept = [d for d in items if d.get("id") != decision_id]
        data["decisions"] = kept
    removed = [d for d in items if d.get("id") == decision_id]
    if removed:
        _audit("decision_removed", removed[0], before=removed[0])
    return len(kept) != len(items)


def _audit(event: str, decision: Dict[str, Any], **detail: Any) -> None:
    from prismor.runtime.allow import audit_policy_change
    ws = decision.get("workspace")
    audit_policy_change(
        event, Path(ws) if ws else None, rule_id=decision.get("ruleId"),
        source="dashboard", reason=str(decision.get("reason") or ""), **detail,
    )

    
def _is_floor(rule_id: str) -> bool:
    from prismor.runtime.allow import is_floor_rule
    return is_floor_rule(rule_id)


def for_runtime(workspace: Optional[Path], *, managed: bool) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """(rule_exemptions, tool_denies) in the signed-policy shapes, for this workspace.

    On an org-managed workspace only deny decisions apply: the org's policy is
    authoritative, so a local allow or ask could only weaken it.
    """
    ws = str(Path(workspace).resolve()) if workspace else ""
    rules: List[Dict[str, Any]] = []
    tools: List[Dict[str, Any]] = []
    for d in list_all():
        action = d.get("action")
        if managed and action != "deny":
            continue
        scope = d.get("scope")
        if scope == "workspace":
            if str(Path(str(d.get("workspace"))).resolve()) != ws:
                continue
            scope = "org"  # applies everywhere it is loaded
        elif scope == "device":
            scope = "org"
        common = {"id": "local:" + str(d.get("id")), "scope": scope, "scopeId": d.get("scopeId") or "", "local": True}
        if d.get("target") == "rule":
            rules.append({**common, "ruleId": d.get("ruleId"), "action": action,
                          **({"pattern": d["pattern"]} if d.get("pattern") else {})})
        else:
            tools.append({**common, "tool": d.get("tool"),
                          "action": {"ask": "step_up"}.get(str(action), action)})
    return rules, tools
