"""Artifact provenance — who wrote this file, and what was in them when they did.

Two agents that never exchange a message still communicate whenever one writes
a file the other reads. The filesystem is the protocol, and a per-agent
permission check cannot see it: agent A may hold internet access and no
production credentials while agent B holds production and no internet, yet if A
writes what it fetched into a note that B acts on, the pair has the union of
both permission sets and nobody granted it.

So an agent-to-agent interaction is defined here without reference to any
agent-to-agent protocol:

    B consumed state whose provenance includes A.

This module records the edge. A write remembers which session wrote the file
and what that session had read; a read hands those tags to the reading
session, which turns the cross-agent case into the ordinary in-session one that
``trifecta`` already governs. The chain ends up in the finding's evidence:
``web -> claude:s-1a2b -> /repo/plan.md -> codex:s-9f3e -> psql``.

Scope and its limits are deliberate:

  * Same machine. The store lives under ``$PRISMOR_HOME``, which every agent on
    the device shares. Carrying edges between machines (a git push one box and
    a pull on another) needs the control plane and is not done here.
  * Hooked writes only. An editor, or an agent Prismor does not hook, writes
    without leaving a record -- consistent with the rest of Prismor, which
    governs the agents it is installed in front of.
  * Session granularity. A session that read something untrusted marks
    everything it writes afterwards. Narrowing that to the bytes actually
    derived from the untrusted read needs per-value taint the runtime does not
    carry; the influence check in ``trifecta`` is what keeps the coarseness
    from turning into false blocks.
"""
from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

# Tags that describe a CALL rather than its content, and so must not travel
# with the artifact. "This agent ran a destructive command" is not a property
# of the note it wrote afterwards; "this agent read an untrusted web page" is.
_NOT_CONTENT = ("critical_action", "untrusted_influence")
_NOT_CONTENT_PREFIX = ("egress.", "dest.", "provenance.", "via.", "from.")

# Marks a read of an artifact another session wrote. Distinct from the content
# tags so a policy can be stricter about crossing an agent boundary than about
# the content itself:  ``via.artifact then critical_action -> warn``.
VIA_ARTIFACT = "via.artifact"

_MAX_ENTRIES = 5000
_MAX_READERS = 20


def store_path() -> Path:
    from prismor.runtime.store import prismor_home

    return prismor_home() / "provenance.json"


def resolve(path: str, cwd: Optional[Path] = None) -> str:
    """Absolute, symlink-resolved key for one artifact.

    Both ends must agree on the key or the edge is lost, so this is the single
    place a path becomes one. ``realpath`` rather than ``resolve`` so a path
    that does not exist yet (the write side, screened before it runs) still
    normalizes.
    """
    try:
        p = Path(str(path)).expanduser()
        if not p.is_absolute() and cwd is not None:
            p = Path(cwd) / p
        return os.path.realpath(str(p))
    except Exception:
        # `~nobody/x` raises rather than returning the path unchanged, and a
        # command naming one must not take the whole tag check down with it:
        # the caller's failure mode is a silently unscreened tool call.
        return str(path)


def propagatable(tags: Sequence[str]) -> List[str]:
    """The subset of a session's tags that describe content, not actions."""
    return sorted(
        t for t in tags
        if t not in _NOT_CONTENT and not t.startswith(_NOT_CONTENT_PREFIX)
    )


def record_write(
    path: str,
    tags: Sequence[str],
    *,
    agent: str,
    session: str,
    tool: str,
    index: int = 0,
    cwd: Optional[Path] = None,
) -> None:
    """Remember that ``session`` wrote ``path`` while holding ``tags``.

    Tags accumulate across *different* writers: a file that once held untrusted
    content is not laundered by a second agent appending a line to it.

    A session rewriting a file it wrote itself REPLACES its own contribution
    instead. Accumulating there meant a file could never come clean: an agent
    that drafted a note quoting a fetched page, then overwrote it with its own
    unrelated work, left the file marked untrusted for good -- and every later
    reader inherited that mark and then had the file's *current, clean* text
    treated as untrusted content it must not reuse. What a file holds is what
    was last written to it, so a writer's own later write is the authority on
    its own earlier one. Another agent's contribution still survives, which is
    what stops this being a laundering path.
    """
    key = resolve(path, cwd)
    if not key or key in ("/", "."):
        return
    from prismor.runtime.store import locked_json_update

    try:
        with locked_json_update(store_path()) as state:
            entries = state.get("artifacts")
            if not isinstance(entries, dict):
                entries = {}
            entry = entries.get(key)
            if not isinstance(entry, dict):
                entry = {"tags": [], "readers": []}
            _prior = (entry.get("writer") or {}).get("session")
            _keep: Set[str] = (
                set() if (_prior and _prior == session)
                else {str(t) for t in entry.get("tags") or []}
            )
            entry["tags"] = sorted(_keep | set(tags))
            if not entry["tags"]:
                # Nothing left to say about this file. Dropping it keeps an
                # ordinary write from recording anything at all (the common
                # case) and lets a same-session rewrite actually clear.
                entries.pop(key, None)
                state["artifacts"] = entries
                return
            entry["writer"] = {
                "agent": agent, "session": session, "tool": tool,
                "index": index, "ts": int(time.time()),
            }
            entries[key] = entry
            if len(entries) > _MAX_ENTRIES:
                ordered = sorted(
                    entries.items(),
                    key=lambda kv: (kv[1].get("writer") or {}).get("ts", 0),
                )
                entries = dict(ordered[-_MAX_ENTRIES:])
            state["artifacts"] = entries
    except Exception:
        # Never fail a tool call over bookkeeping.
        pass


def load() -> Dict[str, Any]:
    """Every recorded artifact, keyed by resolved path. ``{}`` when there are
    none, which is the common case and the cheap one.

    Callers screening a single tool call should read the store once through
    this and look candidates up in the result: a shell command can name half a
    dozen paths, and parsing the file per candidate would put a JSON parse of
    the whole store on the hot path of every ``grep``.
    """
    try:
        import json

        state = json.loads(store_path().read_text(encoding="utf-8"))
        artifacts = state.get("artifacts")
        return artifacts if isinstance(artifacts, dict) else {}
    except Exception:
        return {}


def lookup(path: str, cwd: Optional[Path] = None) -> Optional[Dict[str, Any]]:
    """The recorded entry for ``path``, or None. Read-only, no locking."""
    entry = load().get(resolve(path, cwd))
    return entry if isinstance(entry, dict) else None


def record_read(
    path: str,
    *,
    agent: str,
    session: str,
    tool: str,
    index: int = 0,
    cwd: Optional[Path] = None,
) -> None:
    """Append this session to the artifact's reader list (audit side)."""
    key = resolve(path, cwd)
    from prismor.runtime.store import locked_json_update

    try:
        with locked_json_update(store_path()) as state:
            entries = state.get("artifacts")
            if not isinstance(entries, dict) or key not in entries:
                return
            entry = entries[key]
            readers = entry.get("readers")
            if not isinstance(readers, list):
                readers = []
            readers = [
                r for r in readers
                if not (isinstance(r, dict) and r.get("session") == session)
            ]
            readers.append({
                "agent": agent, "session": session, "tool": tool,
                "index": index, "ts": int(time.time()),
            })
            entry["readers"] = readers[-_MAX_READERS:]
            state["artifacts"] = entries
    except Exception:
        pass


def read_tags(entry: Dict[str, Any], session: str) -> Set[str]:
    """Tags a reading session inherits from an artifact's entry.

    Empty when the reader is the session that wrote it -- a session re-reading
    its own scratch file has learned nothing new, and its own tags are already
    in its ledger.
    """
    writer = entry.get("writer") or {}
    if not writer or writer.get("session") == session:
        return set()
    tags = {str(t) for t in entry.get("tags") or []}
    tags.add(VIA_ARTIFACT)
    if writer.get("agent"):
        tags.add(f"from.{writer['agent']}")
    return tags


# ── Shell channels ───────────────────────────────────────────────────────────
# A shell-only agent (Codex does everything through Bash) never emits a
# file_read or file_write event, so without this the whole mechanism is blind
# to it -- verified in the lab, where a two-agent `curl -o` / `cat` / `psql`
# handoff produced complete logs and an empty ledger.
#
# ponytail: token scan, not a shell grammar. Redirects, tee, curl/wget output
# flags and cp/mv destinations cover what agents actually write with; a
# subshell or an in-script write is missed. Upgrade to a real parse only if
# something in the corpus needs it.

_WRITE_FLAGS = {"-o", "--output", "-O", "--output-document"}
_COPY_CMDS = {"cp", "mv", "install"}
_FETCH_CMDS = {"curl", "wget"}


def _segments(tokens: List[str]) -> List[List[str]]:
    seg: List[str] = []
    out: List[List[str]] = []
    for t in tokens:
        if t in ("|", "||", "&&", ";", "&"):
            if seg:
                out.append(seg)
            seg = []
        else:
            seg.append(t)
    if seg:
        out.append(seg)
    return out


def _scan(command: str, cwd: Optional[Path]) -> Dict[str, Set[str]]:
    """One pass over a command: read candidates, write targets, and which of
    those writes are a fetch landing on disk."""
    import shlex

    out: Dict[str, Set[str]] = {"reads": set(), "writes": set(), "fetched": set()}
    if not command:
        return out
    try:
        tokens = shlex.split(command, posix=True)
    except ValueError:
        return out

    for seg in _segments(tokens):
        if not seg:
            continue
        i = 0
        # Skip leading VAR=value assignments and env/sudo wrappers.
        while i < len(seg) and ("=" in seg[i] and not seg[i].startswith("-")):
            i += 1
        cmd = os.path.basename(seg[i]) if i < len(seg) else ""
        args = seg[i + 1:] if i < len(seg) else []
        seg_writes: Set[str] = set()

        positional: List[str] = []
        skip_next = False
        for j, tok in enumerate(args):
            if skip_next:
                skip_next = False
                continue
            if tok in (">", ">>"):
                if j + 1 < len(args):
                    seg_writes.add(resolve(args[j + 1], cwd))
                skip_next = True
            elif tok == "<":
                if j + 1 < len(args):
                    out["reads"].add(resolve(args[j + 1], cwd))
                skip_next = True
            elif tok in _WRITE_FLAGS and cmd in _FETCH_CMDS:
                if j + 1 < len(args):
                    seg_writes.add(resolve(args[j + 1], cwd))
                skip_next = True
            elif tok.startswith("-"):
                continue
            else:
                positional.append(tok)

        if cmd == "tee":
            seg_writes |= {resolve(a, cwd) for a in positional}
        elif cmd in _COPY_CMDS and len(positional) >= 2:
            out["reads"] |= {resolve(a, cwd) for a in positional[:-1]}
            seg_writes.add(resolve(positional[-1], cwd))
        elif cmd not in _FETCH_CMDS:
            for a in positional:
                key = resolve(a, cwd)
                try:
                    if os.path.isfile(key):
                        out["reads"].add(key)
                except Exception:
                    pass

        out["writes"] |= seg_writes
        if cmd in _FETCH_CMDS:
            # Whatever this segment wrote is off-machine content, whether it
            # got there through -o or through a redirect. The session need not
            # have read anything untrusted for the FILE to be untrusted: for a
            # shell-only agent this is the fetch.
            out["fetched"] |= seg_writes

    for key in out:
        out[key].discard("")
    out["reads"] -= out["writes"]
    return out


def shell_paths(command: str, cwd: Optional[Path] = None) -> Tuple[Set[str], Set[str]]:
    """``(reads, writes)`` for one shell command, as resolved artifact keys.

    Read candidates are generous on purpose: any argument that exists as a file
    counts, because a candidate that was never written by a tracked agent finds
    no entry and costs one dict lookup. Write candidates are strict, because a
    wrong one would mark an unrelated file as carrying another agent's content.
    """
    scan = _scan(command, cwd)
    return scan["reads"], scan["writes"]


def fetch_targets(command: str, cwd: Optional[Path] = None) -> Set[str]:
    """Files this command downloads onto disk (``curl -o``, ``wget > f``, ...).

    These carry ``untrusted_content`` on their own account rather than
    inheriting it from the writing session, which is what makes the mechanism
    work for an agent that never calls a tagged fetch tool -- Codex reaches the
    web through Bash, so without this its downloads are untracked.
    """
    return _scan(command, cwd)["fetched"]
