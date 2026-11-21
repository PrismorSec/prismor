"""Who started a turn, and which session a transcript continues.

Three things a session trail could not tell apart:

* A prompt the person typed inside a Claude desktop side session arrives
  wrapped in a long ``<system-reminder>`` the app adds, so the first 400
  characters (the title, the trail preview) are all wrapper.
* A task brief written by the parent session ("Task (from the session that
  started this one)") reads like a person's prompt but was written by an agent.
* A Stop hook that exits 2 makes Claude take another turn. No
  ``UserPromptSubmit`` fires for it; the transcript records the feedback as an
  ``isMeta`` user row starting ``Stop hook feedback:\\n[<command>]: …``.

And when the desktop app resumes a session it can start a new session id
whose transcript is a full copy of the old one (same entry ``uuid`` values,
``sessionId`` rewritten). Prismor then shows two unlinked sessions and counts
the copied history twice. `lineage` links them by the shared first uuid.
"""
from __future__ import annotations

import json
import os
import re
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

_REMINDER = re.compile(r"<system-reminder>.*?</system-reminder>", re.S)
_SIDE_SESSION = "You are a session started from another session"
_PARENT_TASK = "Task (from the session that started this one)"
_HOOK_FEEDBACK = re.compile(r"^(\w+) hook feedback:\s*\n?\[(.*?)\]:\s*(.*)", re.S)


def prompt_origin(text: str) -> Tuple[str, str]:
    """``(origin, said)`` for a prompt: who sent it and its text minus wrappers.

    origin is ``user`` (a person typed it), ``session`` (another agent session's
    task brief), ``hook`` (an agent hook's feedback) or ``harness`` (the app
    injected it and nobody typed anything).
    """
    text = text or ""
    hook = _HOOK_FEEDBACK.match(text.lstrip())
    if hook:
        return "hook", hook.group(3).strip()
    said = _REMINDER.sub(" ", text).strip()
    if said.startswith(_PARENT_TASK):
        return "session", said
    if not said:
        return "harness", ""
    return "user", said


def hook_name(command: str) -> str:
    """``wiki-stop-capture.sh`` from a quoted hook command line."""
    for tok in reversed(re.findall(r'"([^"]+)"|(\S+)', command)):
        word = tok[0] or tok[1]
        if "/" in word or word.endswith((".sh", ".py", ".js", ".mjs")):
            return os.path.basename(word.rstrip("/"))
    return command.strip()[:80]


def stop_hook_trigger(rows: List[Dict[str, Any]]) -> Optional[Dict[str, str]]:
    """The hook feedback that started the latest Claude turn, if a hook did.

    ``rows`` is the tail of the transcript. The turn was hook-started when the
    newest user row that is not a tool result is an ``isMeta`` hook-feedback row.
    """
    for row in reversed(rows):
        if row.get("type") != "user" or row.get("toolUseResult") is not None:
            continue
        content = (row.get("message") or {}).get("content")
        if isinstance(content, list):
            if any(isinstance(b, dict) and b.get("type") == "tool_result" for b in content):
                continue
            content = "\n".join(str(b.get("text") or "") for b in content if isinstance(b, dict))
        hit = _HOOK_FEEDBACK.match(str(content or "").lstrip()) if row.get("isMeta") else None
        if not hit:
            return None
        return {"event": hit.group(1), "hook": hook_name(hit.group(2)), "message": hit.group(3).strip()[:500]}
    return None


# --- lineage ---------------------------------------------------------------

_HEAD_LINES = 200  # the first uuid sits within the first few rows
_UUID = re.compile(r'"uuid":\s*"([^"]+)"')


def _first_uuid(path: Path) -> str:
    try:
        return _first_uuid_at(str(path), path.stat().st_mtime_ns)
    except OSError:
        return ""


@lru_cache(maxsize=4096)
def _first_uuid_at(path: str, _mtime: int) -> str:
    """Cached per (path, mtime): a session view or friction() pass checks every
    sibling transcript, and the first rows of a transcript never change."""
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            for i, line in enumerate(fh):
                if i >= _HEAD_LINES:
                    break
                if '"uuid"' not in line:
                    continue
                try:
                    uid = json.loads(line).get("uuid")
                except ValueError:
                    continue
                if uid:
                    return str(uid)
    except OSError:
        pass
    return ""


def _uuids(path: Path) -> Set[str]:
    out: Set[str] = set()
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                m = _UUID.search(line)
                if m:
                    out.add(m.group(1))
    except OSError:
        pass
    return out


def _born(path: Path) -> float:
    st = path.stat()
    # ponytail: birth time where the OS keeps it (macOS, Windows), else mtime of
    # the first write we can see; a parent rewritten after the fork can then look
    # newer than its child. Compare first divergent rows if that ever matters.
    return getattr(st, "st_birthtime", None) or st.st_ctime


def lineage(transcript: str) -> Dict[str, Any]:
    """``{"from": sid, "as": [sid, …], "inherited": {uuid, …}}`` for a Claude transcript.

    Siblings in the same project directory that start with the same entry uuid
    are copies of one conversation; the earliest-created is the original.
    ``inherited`` is the set of rows this transcript copied from its parent.
    """
    path = Path(transcript) if transcript else None
    if path is None or path.suffix != ".jsonl" or not path.is_file():
        return {}
    root = _first_uuid(path)
    if not root:
        return {}
    try:
        mine = _born(path)
        kin = [(p, _born(p)) for p in path.parent.glob("*.jsonl")
               if p != path and _first_uuid(p) == root]
    except OSError:
        return {}
    older = [k for k in kin if k[1] < mine]
    out: Dict[str, Any] = {}
    if older:
        parent = max(older, key=lambda k: k[1])[0]
        out["from"] = parent.stem
        out["inherited"] = _uuids(parent)
    later = sorted((k for k in kin if k[1] > mine), key=lambda k: k[1])
    if later:
        out["as"] = [p.stem for p, _ in later]
    return out
