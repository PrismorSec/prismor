"""What Prismor did inside a subagent, told to the person when it finishes.

Claude Code runs a subagent's tool calls through the same hooks as the main
agent, tagged with ``agent_id``/``agent_type``. Its blocks and warnings go to
the subagent, and a background subagent's work is never shown in the main
chat, so the person had no way to know a subagent was stopped, asked for
approval, or tried something it should not have.

Each screened call inside a subagent appends one line to a small per-session
ledger. When the subagent stops (``SubagentStop``), the ledger is summarized
into one human-facing line. Appending single lines keeps parallel subagents
from clobbering each other; nothing here ever blocks a call.
"""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Dict, List, Optional


_SEVERITY = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def _ledger(session_id: str) -> Path:
    from prismor.runtime.store import prismor_home

    safe = "".join(c for c in str(session_id) if c.isalnum() or c in "-_")[:80] or "unknown"
    return prismor_home() / "subagents" / f"{safe}.jsonl"


def subagent_of(payload: Dict[str, Any]) -> Optional[str]:
    """The subagent a hook payload came from, or None for the main agent."""
    aid = payload.get("agent_id") or payload.get("agentId")
    return str(aid) if aid else None


def record_call(payload: Dict[str, Any], findings: List[Dict[str, Any]],
                blocking: Optional[Dict[str, Any]], verdict: str = "") -> None:
    """Append this subagent call's outcome. Never raises."""
    verdict = verdict or str((blocking or {}).get("action") or "")
    try:
        aid = subagent_of(payload)
        if not aid:
            return
        event = str(payload.get("hook_event_name") or "")
        if event not in ("PreToolUse", "PostToolUse"):
            return
        # Name the worst finding: the first one was a HIGH raw-IP warning while
        # the same call also hit the CRITICAL instance-metadata rule.
        worst = min(findings, key=lambda f: _SEVERITY.get(str(f.get("severity") or "").upper(), 9),
                    default={})
        if blocking is not None:
            outcome = "asked" if verdict == "step_up" else "blocked"
            top = blocking
        elif any(f.get("mode") == "enforce" and f.get("action") == "block" for f in findings):
            outcome, top = "blocked", worst
        elif findings:
            outcome, top = "flagged", worst
        else:
            outcome, top = ("allowed" if event == "PreToolUse" else ""), {}
        if not outcome:
            return
        line = {
            "ts": time.time(), "agent_id": aid,
            "agent_type": str(payload.get("agent_type") or payload.get("agentType") or ""),
            "event": event, "tool": str(payload.get("tool_name") or ""), "outcome": outcome,
            "rule": str(top.get("ruleId") or ""), "title": str(top.get("title") or "")[:140],
            "host": str(top.get("egressHost") or ""),
        }
        path = _ledger(str(payload.get("session_id") or ""))
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(line) + "\n")
    except Exception:
        pass


def queue_notice(session_id: str, message: str) -> None:
    """Hold a line for the main chat. Claude Code files a SubagentStop hook's
    systemMessage under the subagent's own (sidechain) transcript, so printed
    there the person never sees it; the next main-thread hook shows it."""
    if not message:
        return
    try:
        path = _ledger(session_id).with_suffix(".notices")
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as fh:
            fh.write(message.replace("\n", " ") + "\n")
    except OSError:
        pass


def take_notices(payload: Dict[str, Any]) -> str:
    """Queued subagent lines for a main-agent hook, cleared once taken."""
    if subagent_of(payload):
        return ""  # a subagent's own hook output lands in its sidechain too
    path = _ledger(str(payload.get("session_id") or "")).with_suffix(".notices")
    taken = path.with_suffix(f".taking{time.time_ns()}")
    try:
        path.replace(taken)  # atomic: a parallel hook cannot show it twice
        text = taken.read_text(encoding="utf-8")
        taken.unlink()
    except OSError:
        return ""
    return "\n".join(x for x in text.splitlines() if x.strip())


def _read(session_id: str, agent_id: Optional[str]) -> List[Dict[str, Any]]:
    path = _ledger(session_id)
    try:
        rows = [json.loads(x) for x in path.read_text(encoding="utf-8").splitlines() if x.strip()]
    except (OSError, ValueError):
        return []
    if agent_id:
        return [r for r in rows if r.get("agent_id") == agent_id]
    return rows


def summary(payload: Dict[str, Any]) -> str:
    """One line for the person about the subagent that just stopped, or ""
    when it made no screened calls."""
    sid = str(payload.get("session_id") or "")
    aid = subagent_of(payload)
    rows = _read(sid, aid)
    if not rows:
        return ""
    calls = sum(1 for r in rows if r.get("event") == "PreToolUse")
    kind = next((r.get("agent_type") for r in rows if r.get("agent_type")), "") or "subagent"
    label = f"{kind} ({aid[:8]})" if aid else kind

    def _what(r: Dict[str, Any]) -> str:
        what = r.get("host") or r.get("rule") or r.get("tool") or "a call"
        return f"{what}" + (f" via {r['tool']}" if r.get("tool") and r.get("host") else "")

    def _uniq(items: List[str]) -> List[str]:
        seen: List[str] = []
        for i in items:
            if i and i not in seen:
                seen.append(i)
        return seen

    blocked = _uniq([_what(r) for r in rows if r["outcome"] == "blocked"])
    asked = _uniq([_what(r) for r in rows if r["outcome"] == "asked"])
    flagged = _uniq([_what(r) for r in rows if r["outcome"] == "flagged"])
    parts = [f"{calls} tool call{'s' if calls != 1 else ''} screened"]
    if blocked:
        parts.append(f"{len(blocked)} blocked ({', '.join(blocked[:3])}{', …' if len(blocked) > 3 else ''})")
    if asked:
        parts.append(f"{len(asked)} needed your OK and were refused ({', '.join(asked[:3])})")
    if flagged:
        parts.append(f"{len(flagged)} flagged ({', '.join(flagged[:3])})")
    if not (blocked or asked or flagged):
        parts.append("nothing blocked or flagged")
    return f"Prismor · {label}: " + " · ".join(parts) + ". Details: prismor sessions --findings-only"
