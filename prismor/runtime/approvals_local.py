"""Approve one blocked action, once, from your own terminal.

Before this, every way past a block was a policy change: an allowlist entry, a
rule set to observe, or the rule switched off. All of those outlive the moment.
Most of the time the person only means "yes, run *that*, this once".

So a block now carries a request id, and the human runs:

    prismor approvals                  # what is waiting
    prismor approvals approve <id>     # allow that exact action once
    prismor approvals deny <id>

The approval matches only the same agent making the same tool call (tool name
plus its exact input) in the same workspace, is used up by the first call it
lets through, and lapses after APPROVED_TTL seconds if nothing uses it.

How the agent gets going again, in order of preference:

1. Hold-open. With PRISMOR_APPROVAL_WAIT=<seconds> (Claude Code and Codex
   only, at most MAX_WAIT), the hook waits that long for a decision before
   denying, so approving lets the original call run - no retry, nothing to
   re-explain. Off by default: it holds the agent's turn.
2. Retry. Otherwise the call is denied with the id, and the next identical call
   after approval goes through. `approve` says which of the two happened,
   because claiming the agent resumed when it did not is worse than saying
   "go back and tell it to retry".

Agents cannot approve for themselves: the CLI verbs and this file are covered
by the prismor-self-edit rule, and `approve` also wants a terminal on stdin,
which an agent's shell tool does not have. That second check is what still
holds inside an unlock window, which lifts the rule but should not let an
agent wave through the very action the person was asked about.
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import subprocess
import sys
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional

PENDING_TTL = 24 * 3600  # an unanswered request is dropped after a day
APPROVED_TTL = 30 * 60  # an unused approval lapses after 30 minutes
# Hold-open must end before the agent's own hook timeout: Claude Code treats a
# hook it had to kill as a non-blocking error and RUNS the call (verified with a
# 10s timeout and a 30s wait). Our installers write 60s, so stay well under it,
# and only on agents where holding was verified end to end.
MAX_WAIT = 45
_HOLD_AGENTS = frozenset({"claude", "codex"})
_KEEP = 200  # newest records kept; older decided ones are pruned


def _home() -> Path:
    return Path(os.environ.get("PRISMOR_HOME", str(Path.home() / ".prismor")))


def path() -> Path:
    return _home() / "approvals.json"


@contextmanager
def _locked() -> Iterator[Dict[str, Any]]:
    """Read-modify-write under the store's lock: two identical calls racing in
    parallel hooks must not both spend one approval."""
    from prismor.runtime.store import locked_json_update
    with locked_json_update(path()) as data:
        if not isinstance(data.get("requests"), dict):
            data["requests"] = {}
        yield data
        _expire(data["requests"])


def _expire(reqs: Dict[str, Dict[str, Any]]) -> None:
    now = time.time()
    for rec in reqs.values():
        if rec.get("status") == "pending" and now - float(rec.get("created", 0)) > PENDING_TTL:
            rec["status"] = "expired"
        if rec.get("status") == "approved" and now > float(rec.get("valid_until", 0)):
            rec["status"] = "expired"
    if len(reqs) > _KEEP:
        done = sorted((r for r in reqs.values() if r.get("status") != "pending"),
                      key=lambda r: float(r.get("created", 0)))
        for rec in done[: len(reqs) - _KEEP]:
            reqs.pop(rec["id"], None)


def fingerprint(agent: str, workspace: Any, payload: Dict[str, Any], event: Dict[str, Any]) -> str:
    """The exact action: same agent, workspace, tool and tool input."""
    tool = payload.get("tool_name") or payload.get("toolName") or event.get("type") or ""
    inp = payload.get("tool_input") or payload.get("toolArgs") or payload.get("input")
    if not inp:
        inp = {k: event.get(k) for k in ("type", "command", "path", "url", "content") if event.get(k)}
    raw = json.dumps([agent, str(workspace or ""), tool, inp], sort_keys=True, default=str)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def consume(fp: str, call_id: str = "") -> Optional[Dict[str, Any]]:
    """Spend an approval for this action. Returns it, or None if there is none.

    `call_id` is the agent's id for this one tool call. With a global and a
    project install, two hooks screen the same call; the second must see the
    approval the first just spent on that call, or it blocks it under a new id."""
    with _locked() as state:
        _expire(state["requests"])
        for rec in state["requests"].values():
            if rec.get("fp") != fp:
                continue
            if rec.get("status") == "approved":
                rec["status"] = "used"
                rec["used_at"] = time.time()
                rec["used_by"] = call_id
                return dict(rec)
            if call_id and rec.get("status") == "used" and rec.get("used_by") == call_id:
                return dict(rec)
    return None


def request(fp: str, *, agent: str, session_id: str, finding: Dict[str, Any],
            summary: str, waiting_seconds: int = 0, workspace: str = "",
            tool: str = "") -> Dict[str, Any]:
    """Open (or reuse) the pending request for this action."""
    with _locked() as state:
        _expire(state["requests"])
        rec = next((r for r in state["requests"].values()
                    if r.get("fp") == fp and r.get("status") == "pending"), None)
        if rec is None:
            rid = secrets.token_hex(3)
            while rid in state["requests"]:
                rid = secrets.token_hex(3)
            rec = {
                "id": rid, "fp": fp, "status": "pending", "created": time.time(),
                "agent": agent, "session_id": session_id, "workspace": workspace, "tool": tool,
                "rule": str(finding.get("ruleId") or ""),
                "severity": str(finding.get("severity") or ""),
                "title": str(finding.get("title") or "")[:200],
                "summary": summary[:4000],
            }
            state["requests"][rid] = rec
        rec["attempts"] = int(rec.get("attempts", 0)) + 1
        rec["waiting_until"] = time.time() + waiting_seconds if waiting_seconds else 0
        return dict(rec)


def wait(rid: str, seconds: float) -> bool:
    """Hold the hook until the request is decided. True only on approval, and
    the approval is spent by this call."""
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        time.sleep(0.5)
        with _locked() as state:
            rec = state["requests"].get(rid)
            if rec is None or rec.get("status") in ("denied", "expired", "used"):
                return False
            if rec.get("status") == "approved":
                rec["status"] = "used"
                rec["used_at"] = time.time()
                rec["resumed"] = True
                return True
    with _locked() as state:
        rec = state["requests"].get(rid)
        if rec is not None:
            rec["waiting_until"] = 0
    return False


def resolve(fp: str) -> bool:
    """This exact call just ran without our approval (allowed in the agent's
    own prompt, by `prismor allow`, or a policy change): close its pending
    request. Runs on every allowed call, so read without the lock first and
    only take it when there is something to close."""
    try:
        reqs = json.loads(path().read_text(encoding="utf-8")).get("requests") or {}
    except (OSError, ValueError):
        return False
    if not any(r.get("fp") == fp and r.get("status") == "pending" for r in reqs.values()):
        return False
    hit = False
    with _locked() as state:
        for rec in state["requests"].values():
            if rec.get("fp") == fp and rec.get("status") == "pending":
                rec["status"] = "resolved"
                rec["decided_at"] = time.time()
                hit = True
    return hit


def decide(rid: str, approve: bool) -> Optional[Dict[str, Any]]:
    """Approve or deny a pending request. Returns the record as it was decided,
    including whether a hook was still holding the call open at that moment."""
    with _locked() as state:
        _expire(state["requests"])
        rec = state["requests"].get(rid.strip().lower())
        if rec is None or rec.get("status") != "pending":
            return dict(rec) if rec else None
        now = time.time()
        rec["status"] = "approved" if approve else "denied"
        rec["decided_at"] = now
        rec["valid_until"] = now + APPROVED_TTL
        out = dict(rec)
        out["was_waiting"] = float(rec.get("waiting_until") or 0) > now
        return out


def list_requests(include_done: bool = False) -> List[Dict[str, Any]]:
    with _locked() as state:
        _expire(state["requests"])
        recs = [dict(r) for r in state["requests"].values()
                if include_done or r.get("status") in ("pending", "approved")]
    return sorted(recs, key=lambda r: float(r.get("created", 0)), reverse=True)


def wait_seconds(agent: str) -> int:
    if agent not in _HOLD_AGENTS:
        return 0
    try:
        return max(0, min(MAX_WAIT, int(float(os.environ.get("PRISMOR_APPROVAL_WAIT", "0")))))
    except ValueError:
        return 0


def notify(title: str, body: str) -> None:
    """Desktop notification, best-effort - only used while a hook is holding."""
    try:
        if sys.platform == "darwin":
            script = f"display notification {json.dumps(body)} with title {json.dumps(title)}"
            subprocess.Popen(["osascript", "-e", script],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        elif sys.platform.startswith("linux") and os.environ.get("DISPLAY"):
            subprocess.Popen(["notify-send", title, body],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except OSError:
        pass


def _demo() -> None:
    import tempfile
    os.environ["PRISMOR_HOME"] = tempfile.mkdtemp()
    fp = fingerprint("codex", "/w", {"tool_name": "Bash", "tool_input": {"command": "rm -rf x"}}, {})
    assert consume(fp) is None
    r = request(fp, agent="codex", session_id="s", finding={"ruleId": "r"}, summary="rm -rf x")
    assert request(fp, agent="codex", session_id="s", finding={}, summary="")["id"] == r["id"]
    assert decide(r["id"], True)["status"] == "approved"
    assert consume(fp, "t1")["id"] == r["id"] and consume(fp) is None  # once only
    assert consume(fp, "t1")["id"] == r["id"]  # second hook on the same call
    assert consume(fp, "t2") is None  # a later call is not covered
    r2 = request(fp, agent="codex", session_id="s", finding={}, summary="")
    assert r2["id"] != r["id"]
    decide(r2["id"], False)
    assert consume(fp) is None
    r3 = request(fp, agent="codex", session_id="s", finding={}, summary="")
    assert resolve(fp) and not resolve(fp)  # ran another way: closed once
    assert all(r["id"] != r3["id"] for r in list_requests())
    print("ok")


if __name__ == "__main__":
    _demo()
