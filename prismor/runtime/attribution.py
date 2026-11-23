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
# "Task (from the session that started this one)", and since the app's late-2026
# briefs, "Background (from the session …)".
_PARENT_TASK = re.compile(r"^\w+ \(from the session that started this one\)")
# A message one desktop session sent another (SendMessage between sessions).
_PEER = re.compile(r'<cross-session-message from="([^"]*)"(?: from-name="([^"]*)")?[^>]*>(.*?)(?:</cross-session-message>|$)', re.S)
_HOOK_FEEDBACK = re.compile(r"^(\w+) hook feedback:\s*\n?\[(.*?)\]:\s*(.*)", re.S)


def prompt_origin(text: str) -> Tuple[str, str]:
    """``(origin, said)`` for a prompt: who sent it and its text minus wrappers.

    origin is ``user`` (a person typed it), ``session`` (the brief of the session
    that started this one), ``peer`` (a message another session sent), ``hook``
    (an agent hook's feedback) or ``harness`` (the app injected it and nobody
    typed anything).
    """
    text = text or ""
    hook = _HOOK_FEEDBACK.match(text.lstrip())
    if hook:
        return "hook", hook.group(3).strip()
    said = _REMINDER.sub(" ", text).strip()
    peer = _PEER.search(said)
    if peer:
        return "peer", peer.group(3).strip()
    if _PARENT_TASK.match(said):
        return "session", said
    if not said:
        return "harness", ""
    return "user", said


def peer_sender(text: str) -> Optional[Dict[str, str]]:
    """``{"session": local_id, "name": title}`` of the session that sent a peer message."""
    m = _PEER.search(_REMINDER.sub(" ", text or ""))
    if not m:
        return None
    return {"session": m.group(1)[:80], "name": (m.group(2) or "")[:200]}


# --- spawn links (Claude desktop app) -------------------------------------
#
# The desktop app keeps one JSON record per session. A session another session
# started carries ``spawnedFrom.sessionId`` (the parent's app id, ``local_…``)
# and ``cliSessionId``, the Claude Code session id Prismor's hooks see. That is
# the only place the parent is written down: the child's hooks get no parent
# id, and the brief text names no session.

def _app_sessions_root() -> Optional[Path]:
    env = os.environ.get("PRISMOR_CLAUDE_APP_SESSIONS")
    if env:
        return Path(env)
    home = Path.home()
    # Only macOS is confirmed (read from a real app install). The rest are the
    # app's usual per-OS data dirs: Windows %APPDATA%, the Store (MSIX) build,
    # which keeps %APPDATA% inside its package folder, and Linux ~/.config.
    # Neither the st3ve (Linux) nor the Windows test VM has the desktop app.
    local = Path(os.environ.get("LOCALAPPDATA") or home / "AppData" / "Local")
    bases = [home / "Library" / "Application Support" / "Claude",
             Path(os.environ.get("APPDATA") or home / "AppData" / "Roaming") / "Claude",
             *sorted((local / "Packages").glob("Claude_*/LocalCache/Roaming/Claude")),
             home / ".config" / "Claude"]
    for base in bases:
        if (base / "claude-code-sessions").is_dir():
            return base / "claude-code-sessions"
    return None


@lru_cache(maxsize=4096)
def _app_record_at(path: str, _mtime: int) -> Tuple[str, Tuple[str, ...], str, str]:
    """(app id, Claude session ids, parent app id, title) of one app record."""
    try:
        with open(path, encoding="utf-8") as fh:
            d = json.load(fh)
    except (OSError, ValueError):
        return "", (), "", ""
    if not isinstance(d, dict):
        return "", (), "", ""
    clis = tuple(dict.fromkeys(str(d[k]) for k in ("cliSessionId", "lastAssistantCliSessionId") if d.get(k)))
    parent = d.get("spawnedFrom") if isinstance(d.get("spawnedFrom"), dict) else {}
    return str(d.get("sessionId") or ""), clis, str(parent.get("sessionId") or ""), str(d.get("title") or "")[:200]


def _app_records() -> List[Tuple[str, Tuple[str, ...], str, str]]:
    root = _app_sessions_root()
    if root is None:
        return []
    out = []
    # ponytail: stats every record on each call (json parse is cached per mtime);
    # index by directory mtime if a session view ever gets slow on large app histories.
    for p in root.glob("*/*/local_*.json"):
        try:
            out.append(_app_record_at(str(p), p.stat().st_mtime_ns))
        except OSError:
            continue
    return [r for r in out if r[0]]


def _ref(rec: Tuple[str, Tuple[str, ...], str, str]) -> Dict[str, str]:
    return {"session": rec[1][0] if rec[1] else rec[0], "app_id": rec[0], "title": rec[3]}


def spawn_links(session_id: str) -> Dict[str, Any]:
    """``{"spawned_from": ref, "spawned": [ref, …]}`` for a Claude session id.

    A ref is ``{"session": <Claude session id>, "app_id": "local_…", "title"}``.
    Empty when the app keeps no record of the session (CLI, other machine).
    """
    recs = _app_records()
    mine = next((r for r in recs if session_id in r[1] or session_id == r[0]), None)
    if mine is None:
        return {}
    out: Dict[str, Any] = {}
    if mine[2]:
        parent = next((r for r in recs if r[0] == mine[2]), None)
        out["spawned_from"] = _ref(parent) if parent else {"session": mine[2], "app_id": mine[2], "title": ""}
    kids = [_ref(r) for r in recs if r[2] == mine[0]]
    if kids:
        out["spawned"] = kids
    return out


def claude_session_for(app_id: str) -> str:
    """The Claude session id behind a desktop app id (``local_…``), or ``""``."""
    rec = next((r for r in _app_records() if r[0] == app_id), None)
    return rec[1][0] if rec and rec[1] else ""


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
