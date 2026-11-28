"""`prismor explain <session>`: re-run recorded events and show each step.

For one flagged event (or every event with a recorded finding) it prints the
command as stored, whether Prismor's cloak wrapper is still on it and what
unwrapping gives now, which rules match today and why, and the shell this
machine runs hooks under. Read-only: nothing is recorded or sent.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional


def explain(workspace: Path, session_id: str, event: Optional[int] = None) -> Dict[str, Any]:
    from prismor.runtime.store import get_session
    from prismor.runtime.policy_engine import PolicyEngine
    from prismor.runtime.cloaking.runtime import _DECLOAK_TAIL_RE, unwrap_decloak
    from prismor.runtime.enterprise.heartbeat import shell_info

    session = get_session(workspace, session_id)
    if session is None:
        raise LookupError(f"no session {session_id} in the local store")
    events = session["events"]
    recorded: Dict[int, List[Dict[str, Any]]] = {}
    for f in session["findings"]:
        if f.get("eventIndex") is not None:
            recorded.setdefault(int(f["eventIndex"]), []).append(f)
    indices = [event] if event is not None else sorted(recorded)
    engine = PolicyEngine(workspace=workspace)
    out: List[Dict[str, Any]] = []
    for i in indices:
        if not 0 <= i < len(events):
            raise LookupError(f"session {session_id} has no event {i} ({len(events)} events)")
        raw = dict(events[i]["raw"])
        step: Dict[str, Any] = {"index": i, "type": raw.get("type"), "tool": raw.get("tool_name")}
        cmd = raw.get("command")
        if isinstance(cmd, str) and cmd:
            unwrapped = unwrap_decloak(cmd)
            step["command"] = cmd
            step["cloak_wrapper"] = (
                "none" if not _DECLOAK_TAIL_RE.search(cmd)
                else "unwraps now" if unwrapped != cmd else "does not unwrap"
            )
            raw["command"] = unwrapped
        trace: List[Dict[str, Any]] = []
        now = engine.evaluate(raw, i, session_id, trace=trace)
        step["recorded"] = [{"title": f["title"], "severity": f["severity"], "evidence": f["evidence"]}
                            for f in recorded.get(i, [])]
        step["now"] = [{k: f.get(k) for k in ("ruleId", "action", "severity", "title", "evidence", "guidance")
                        if f.get(k) is not None} for f in now]
        step["rules_matched"] = trace
        out.append(step)
    return {"session": session_id, "shell": shell_info(), "events": out}


def _one_line(text: Any, limit: int = 300) -> str:
    t = " ".join(str(text or "").split())
    return t if len(t) <= limit else t[:limit] + "..."


def format_explain(info: Dict[str, Any]) -> str:
    sh = info["shell"]
    lines = [f"session {info['session']}  (this machine: bash {sh.get('bash') or '?'}, locale {sh.get('locale')})"]
    if not info["events"]:
        lines.append("  no recorded findings; pass --event N to explain one event")
    for ev in info["events"]:
        lines.append(f"\n#{ev['index']} {ev.get('type')} {ev.get('tool') or ''}".rstrip())
        if "command" in ev:
            lines.append(f"  command:  {_one_line(ev['command'])}")
            lines.append(f"  cloak wrapper: {ev['cloak_wrapper']}")
        for f in ev["recorded"]:
            lines.append(f"  recorded: {f['severity']} {f['title']}  evidence: {_one_line(f['evidence'])}")
        for f in ev["now"]:
            lines.append(f"  now:      {f.get('action')} by {f.get('ruleId')}: {f.get('title')}")
            if f.get("evidence"):
                lines.append(f"            matched: {_one_line(f['evidence'])}")
            if f.get("guidance"):
                lines.append(f"            why: {f['guidance']}")
        if not ev["now"]:
            lines.append("  now:      no finding (allowed)")
        for t in ev["rules_matched"]:
            state = "fired" if t.get("fired") else f"did not fire ({t.get('suppressed_by') or 'when false'})"
            lines.append(f"  rule {t['rule_id']}: {state}, mode {t.get('mode')}")
    return "\n".join(lines)
