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
import re
import time
from pathlib import Path
from typing import Any, Dict, List, NamedTuple, Optional, Sequence, Set, Tuple

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
# A token scan, not a shell grammar, but one that follows where fetched bytes
# can go (#446). Operators are tokens of their own, so `-o a.html; echo` names
# `a.html` and not `a.html;`. A command substitution is lifted out and scanned
# on its own, and the word it sat in carries whatever it fetched: assigned to
# a variable, that name carries for the rest of the command; on a pipe, every
# segment downstream carries. A quoted heredoc body (`<<'EOF'`) is literal
# text and is skipped, so a script that merely mentions `$(curl ...)` is not a
# download; an unquoted body expands and is checked for what it references.
# Not followed, by choice: `eval`, arrays, `printf -v`, a wrapper that takes
# arguments of its own (`xargs`, `timeout 30`), a group's redirect (`{ curl
# u; } > f`) and a fetched file re-read later in the same command (`curl -o f
# && cp f g`), which the store covers across calls.

_WRITE_FLAGS = {"-o", "--output", "-O", "--output-document"}
_COPY_CMDS = {"cp", "mv", "install"}
_FETCH_CMDS = {"curl", "wget"}
# The short flag naming the output file, ending a cluster (`curl -sSLo f`,
# `wget -qO f`). ponytail: only as the last letter of the cluster; an
# attached value (`-sof`) is not followed.
_OUT_SHORT = {"curl": "o", "wget": "O"}
_OUT_LONG = ("--output=", "--output-document=")
_READ_CMDS = {"read", "mapfile", "readarray"}
_ASSIGN_CMDS = {"export", "local", "declare", "readonly", "typeset"}
# Words that come before the command without being it.
_PREFIX_WORDS = {
    "(", "{", "!", "if", "then", "else", "elif", "while", "until", "do",
    "time", "sudo", "env", "nohup", "command", "exec", "builtin",
}

_PUNCT = "();<>|&\n"
# Longest first; anything else in a run of punctuation is a single character.
_OPERATORS = ("<<<", ">>", "<<", "&&", "||", ";;", ">&", "<&", "&>", "|&", ">|")
_COMMAND_SEPARATORS = {";", ";;", "&&", "||", "&", "\n"}
_PIPES = {"|", "|&"}
_WRITE_REDIRECTS = {">", ">>", "&>", ">|"}
_SKIP_NEXT = {"<<", "<<<", ">&", "<&"}  # heredoc delimiter, here-string, fd dup
_WORD_START = " \t\n;|&("  # what can come right before a comment or an fd

_ASSIGN_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)(\+?)=(.*)$", re.DOTALL)
_VAR_RE = re.compile(r"\$\{?([A-Za-z_][A-Za-z0-9_]*)")
# A lifted expansion is replaced by a NUL-framed index. NUL cannot occur in a
# real argv, so a marker can never be mistaken for the agent's own text.
_MARK = "\x00"
_MARK_RE = re.compile("\x00(\\d+)\x00")
_MAX_DEPTH = 4


class ShellScan(NamedTuple):
    """What one shell command touches, as resolved artifact keys."""

    reads: Set[str]
    writes: Set[str]
    fetched: Set[str]  # the writes that are a fetch landing on disk


def _closing_paren(text: str, start: int) -> int:
    """Index of the ``)`` matching the ``(`` at ``start``, or -1. A paren
    inside quotes does not count."""
    depth = 0
    i, n = start, len(text)
    while i < n:
        c = text[i]
        if c == "\\":
            i += 2
            continue
        if c in "'\"":
            j = text.find(c, i + 1)
            if j < 0:
                return -1
            i = j + 1
            continue
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return -1


def _lift_expansions(text: str, mark) -> str:
    """``text`` with every ``$(...)``, ``<(...)``, ``>(...)`` and backtick
    span replaced by a marker for the command inside it, and with the shell's
    own reading applied where the tokenizer cannot see it: a single-quoted
    span expands nothing (its ``$`` goes, so no variable is read into it), a
    ``#`` comment goes, and a redirect of a descriptor other than stdin or
    stdout (``2>err``, ``2>&1``) goes with its target, since what it writes
    is not the command's output."""
    out: List[str] = []
    i, n = 0, len(text)
    in_double = False
    while i < n:
        c = text[i]
        if c == "\\":
            nxt = text[i + 1:i + 2]
            # A backslash-newline is a line continuation: the shell drops both.
            if nxt != "\n":
                out.append("\\" + ("" if nxt == "$" else nxt))
            i += 2
        elif c == '"':
            in_double = not in_double
            out.append(c)
            i += 1
        elif c == "'" and not in_double:
            j = text.find("'", i + 1)
            j = n if j < 0 else j + 1
            out.append(text[i:j].replace("$", ""))
            i = j
        elif c == "`":
            j = text.find("`", i + 1)
            if j < 0:
                out.append(text[i:])
                break
            out.append(mark("cmd", text[i + 1:j]))
            i = j + 1
        elif c in "$<>" and text.startswith("(", i + 1):
            j = _closing_paren(text, i + 1)
            if j < 0:
                out.append(text[i:])
                break
            out.append(mark("cmd", text[i + 2:j]))
            i = j + 1
        elif in_double:
            out.append(c)
            i += 1
        elif c == "#" and (i == 0 or text[i - 1] in _WORD_START):
            j = text.find("\n", i)
            i = n if j < 0 else j
        elif (
            c.isdigit() and (i == 0 or text[i - 1] in _WORD_START)
            and text[i + 1:i + 2] in ("<", ">")
        ):
            j = i + 1
            while j < n and text[j] in "<>&|":
                j += 1
            if c in "01":
                out.append(text[i + 1:j])
            else:
                while j < n and text[j] in " \t":
                    j += 1
                if j < n and text[j] in "'\"":
                    k = text.find(text[j], j + 1)
                    j = n if k < 0 else k + 1
                while j < n and text[j] not in " \t\n;|&()<>":
                    j += 1
            i = j
        else:
            out.append(c)
            i += 1
    return "".join(out)


def _lift(command: str, parts: List[Tuple[str, str]]) -> str:
    """``command`` with its expansions moved into ``parts`` and markers left
    in their place. A part is ``("cmd", text)`` for a command substitution or
    ``("text", body)`` for a heredoc body the shell expands."""
    from prismor.runtime.shell_context import heredocs

    def mark(kind: str, text: str) -> str:
        parts.append((kind, text))
        return f"{_MARK}{len(parts) - 1}{_MARK}"

    pieces: List[str] = []
    pos = 0
    for h in heredocs(command):
        # The body becomes one word right after its `<<EOF`, so it belongs to
        # the command that reads it and not to whatever else shares the line.
        pieces.append(command[pos:h.op_end])
        if h.expands:
            body = _lift_expansions(command[h.body_start:h.body_end], mark)
            pieces.append(" " + mark("text", body))
        pieces.append(command[h.op_end:h.body_start - 1])
        pos = h.end
    pieces.append(command[pos:])
    return _lift_expansions("".join(pieces), mark)


def _split_operators(run: str) -> List[str]:
    out: List[str] = []
    i = 0
    while i < len(run):
        for op in _OPERATORS:
            if run.startswith(op, i):
                out.append(op)
                i += len(op)
                break
        else:
            out.append(run[i])
            i += 1
    return out


def _tokenize(command: str) -> List[str]:
    """shlex words, with every shell operator as a token of its own. Raises
    ``ValueError`` on an unbalanced quote, as ``shlex.split`` does."""
    import shlex

    lex = shlex.shlex(command, posix=True, punctuation_chars=_PUNCT)
    lex.whitespace = " \t\r"  # a newline separates commands
    lex.whitespace_split = True
    lex.commenters = ""
    tokens: List[str] = []
    for tok in lex:
        if tok and all(ch in _PUNCT for ch in tok):
            tokens.extend(_split_operators(tok))
        else:
            tokens.append(tok)
    return tokens


def _pipelines(tokens: List[str]) -> List[List[List[str]]]:
    """Commands, split at ``;`` ``&&`` ``||`` ``&`` and newlines, each a list
    of pipe segments."""
    pipelines: List[List[List[str]]] = []
    pipeline: List[List[str]] = []
    seg: List[str] = []
    for t in tokens:
        if t in _PIPES or t in _COMMAND_SEPARATORS:
            if seg:
                pipeline.append(seg)
            seg = []
            if t in _COMMAND_SEPARATORS:
                if pipeline:
                    pipelines.append(pipeline)
                pipeline = []
        else:
            seg.append(t)
    if seg:
        pipeline.append(seg)
    if pipeline:
        pipelines.append(pipeline)
    return pipelines


def _word(tok: str) -> bool:
    """A token that can name a path: not an operator, not a lifted expansion,
    not the ``-`` that stands for stdin or stdout."""
    return (
        bool(tok) and tok != "-" and _MARK not in tok
        and not all(ch in _PUNCT for ch in tok)
    )


def shell_scan(command: str, cwd: Optional[Path] = None) -> ShellScan:
    """One pass over a command: read candidates, write targets, and which of
    those writes are a fetch landing on disk.

    Read candidates are generous on purpose: any argument that exists as a
    file counts, because a candidate that was never written by a tracked
    agent finds no entry and costs one dict lookup. Write candidates are
    strict, because a wrong one would mark an unrelated file as carrying
    another agent's content.
    """
    scanner = _Scanner(cwd)
    if command:
        try:
            # No real argv holds a NUL, so after this every marker is ours.
            scanner.scan(command.replace(_MARK, ""), 0)
        except Exception:
            # A scanner bug must not become a silently unscreened call: keep
            # whatever was found before it.
            pass
    out = scanner.out
    for paths in out:
        paths.discard("")
    out.reads.difference_update(out.writes)
    return out


class _Scanner:
    """One command's scan: its results, the variables holding fetched content
    so far, and the lifted expansions. Nested scans share all of it, so a
    marker means the same thing wherever it lands -- a heredoc inside a
    ``$(...)`` sits in the inner command's text but was lifted by the outer
    pass."""

    def __init__(self, cwd: Optional[Path]) -> None:
        self.cwd = cwd
        self.out = ShellScan(set(), set(), set())
        self.tainted: Set[str] = set()
        self.parts: List[Tuple[str, str]] = []
        self.evaluated: Dict[int, bool] = {}

    def carries(self, tok: str, depth: int) -> bool:
        """Whether expanding this word yields fetched content."""
        for m in _MARK_RE.finditer(tok):
            n = int(m.group(1))
            if n not in self.evaluated:
                kind, text = self.parts[n]
                if depth >= _MAX_DEPTH:
                    self.evaluated[n] = False
                elif kind == "cmd":
                    self.evaluated[n] = self.scan(text, depth + 1)
                else:
                    self.evaluated[n] = self.carries(text, depth)
            if self.evaluated[n]:
                return True
        return any(v in self.tainted for v in _VAR_RE.findall(tok))

    def assign(self, m, depth: int) -> None:
        name, append, value = m.group(1), m.group(2), m.group(3)
        if self.carries(value, depth):
            self.tainted.add(name)
        elif not append:
            self.tainted.discard(name)

    def path(self, tok: str) -> str:
        """``tok`` as an artifact key, or "" when it cannot be one. A device
        (`/dev/null`, `/dev/stderr`) is not an artifact. Checked before
        resolving too: on Linux `/dev/stderr` resolves through /proc to a pipe
        or a deleted file, not to anything under /dev."""
        if not _word(tok) or tok.startswith("/dev/"):
            return ""
        key = resolve(tok, self.cwd)
        return "" if key.startswith("/dev/") else key

    def scan(self, command: str, depth: int) -> bool:
        """Scan ``command``. True when it puts fetched content on its output,
        which is what a ``$(...)`` around it hands to the enclosing word."""
        try:
            tokens = _tokenize(_lift(command, self.parts))
        except ValueError:
            return False
        out = self.out

        fetched_any = False
        for pipeline in _pipelines(tokens):
            carrying = False  # fetched bytes on the pipe from upstream
            for seg in pipeline:
                i = 0
                while i < len(seg):
                    m = _ASSIGN_RE.match(seg[i])
                    if m:
                        self.assign(m, depth)
                    elif not (
                        seg[i] in _PREFIX_WORDS
                        and i + 1 < len(seg) and _word(seg[i + 1])
                    ):
                        break
                    i += 1
                cmd = os.path.basename(seg[i]) if i < len(seg) else ""
                args = seg[i + 1:]
                if cmd in _ASSIGN_CMDS:
                    for a in args:
                        m = _ASSIGN_RE.match(a)
                        if m:
                            self.assign(m, depth)
                seg_writes: Set[str] = set()

                positional: List[str] = []
                skip_next = False
                for j, tok in enumerate(args):
                    if skip_next:
                        skip_next = False
                        continue
                    nxt = args[j + 1] if j + 1 < len(args) else ""
                    if tok in _WRITE_REDIRECTS:
                        seg_writes.add(self.path(nxt))
                        skip_next = True
                    elif tok == "<":
                        out.reads.add(self.path(nxt))
                        skip_next = True
                    elif tok in _SKIP_NEXT:
                        skip_next = True
                    elif tok in _WRITE_FLAGS and cmd in _FETCH_CMDS:
                        seg_writes.add(self.path(nxt))
                        skip_next = True
                    elif cmd in _FETCH_CMDS and tok.startswith(_OUT_LONG):
                        seg_writes.add(self.path(tok.split("=", 1)[1]))
                    elif (
                        cmd in _FETCH_CMDS and len(tok) > 2 and tok[1:].isalpha()
                        and tok[0] == "-" and tok[-1] == _OUT_SHORT[cmd]
                    ):
                        seg_writes.add(self.path(nxt))
                        skip_next = True
                    elif _word(tok) and not tok.startswith("-"):
                        positional.append(tok)

                # Fetched content reaches this segment from a fetch it runs,
                # from the pipe, or from a word that expands to one.
                seg_carries = (
                    carrying or cmd in _FETCH_CMDS
                    or any(self.carries(t, depth) for t in seg)
                )
                if cmd in _READ_CMDS and seg_carries:
                    self.tainted.update(positional)

                if cmd == "tee":
                    seg_writes |= {self.path(a) for a in positional}
                elif cmd in _COPY_CMDS and len(positional) >= 2:
                    out.reads.update(self.path(a) for a in positional[:-1])
                    seg_writes.add(self.path(positional[-1]))
                elif cmd not in _FETCH_CMDS:
                    for a in positional:
                        key = self.path(a)
                        try:
                            if key and os.path.isfile(key):
                                out.reads.add(key)
                        except Exception:
                            pass

                out.writes.update(seg_writes)
                if seg_carries:
                    # Whatever this segment wrote is off-machine content,
                    # whether it got there through -o, a redirect, a pipe or
                    # a variable. The session need not have read anything
                    # untrusted for the FILE to be untrusted: for a
                    # shell-only agent this is the fetch.
                    out.fetched.update(seg_writes)
                    fetched_any = True
                carrying = seg_carries
        return fetched_any


def shell_paths(command: str, cwd: Optional[Path] = None) -> Tuple[Set[str], Set[str]]:
    """``(reads, writes)`` for one shell command, as resolved artifact keys."""
    scan = shell_scan(command, cwd)
    return scan.reads, scan.writes


def fetch_targets(command: str, cwd: Optional[Path] = None) -> Set[str]:
    """Files this command downloads onto disk: ``curl -o f``, ``wget > f``,
    ``curl u | tee f``, ``v=$(curl u); echo "$v" > f``.

    These carry ``untrusted_content`` on their own account rather than
    inheriting it from the writing session, which is what makes the mechanism
    work for an agent that never calls a tagged fetch tool -- Codex reaches the
    web through Bash, so without this its downloads are untracked.
    """
    return shell_scan(command, cwd).fetched
