"""Contextual verification for shell findings.

A regex rule matches the raw command string, so a pattern that appears inside an
inert string literal -- a commit message, a PR body, a grep pattern -- fires the
same as one in executable position. This module answers a narrower question for
a finding that already matched: does the match live in data, or in code?

The check is deliberately asymmetric. It downgrades only on positive evidence of
inertness and defaults to confirming the finding, so every ambiguous or
unparseable form (unclosed quote, unknown command, any interpreter anywhere in
the pipeline) keeps blocking.
"""
from __future__ import annotations

import re
from typing import List, Tuple

# Commands whose quoted argument is executed, not printed. A match inside one of
# these payloads is code and must never be downgraded.
_INTERPRETERS = frozenset({
    "bash", "sh", "zsh", "ksh", "dash", "csh", "tcsh", "fish",
    "python", "python2", "python3", "node", "deno", "bun", "ruby", "perl", "php",
    "psql", "mysql", "mariadb", "sqlite3", "mongosh", "redis-cli",
    "eval", "exec", "source", "xargs", "env", "sudo", "doas", "timeout", "nohup",
    "ssh", "docker", "kubectl", "awk", "sed",
})

# Commands that emit their argument as text. Only a match inside one of these,
# with no interpreter anywhere in the command, may be downgraded.
_INERT_SINKS = frozenset({
    "echo", "printf", "grep", "egrep", "fgrep", "rg", "ag", "ack", "jq", "pbcopy", "gh",
})

# Commands that run their payload in ANOTHER execution context -- a different
# host, container, or namespace. A local rule about Prismor's own policy or
# credential has no jurisdiction over what these run, because the thing they
# reach is a different install with its own policy (issue #344). Deliberately
# NOT used to downgrade rules about the payload's own effect: `ssh host
# "rm -rf /"` still destroys a real machine and must still block.
_REMOTE_CONTEXTS = frozenset({
    "ssh", "sshpass", "docker", "podman", "nerdctl", "kubectl", "oc",
    "lxc", "incus", "vagrant", "nsenter", "distrobox", "toolbox",
    "multipass", "machinectl", "chroot",
})

# git subcommands that take a human-authored message argument.
_GIT_MESSAGE_SUBCOMMANDS = frozenset({"commit", "tag", "notes", "stash"})

# gh subcommands whose quoted argument is prose (a PR body, an issue comment).
_GH_TEXT_SUBCOMMANDS = frozenset({"pr", "issue", "release", "gist"})

# A payload-bearing flag: -c, -e, and clustered forms such as -lc or -xec.
_PAYLOAD_FLAG = re.compile(r"^-[a-zA-Z]*[ce]$")

_SEPARATORS = ";|&"
_QUOTES = "\"" + chr(39)


def quoted_spans(command: str) -> List[Tuple[int, int, bool, bool]]:
    """Return (start, end, is_payload, is_closed) for each quoted span.

    ``start``/``end`` are the indices of the opening and closing quote. A span is
    a *payload* when it is the argument of an interpreter (so its contents are
    executed); ``is_closed`` is False for an unterminated quote, which callers
    must treat as unparseable rather than inert.
    """
    spans: List[Tuple[int, int, bool, bool]] = []
    words: List[str] = []
    token = ""
    i = 0
    n = len(command)
    while i < n:
        ch = command[i]
        if ch in _QUOTES:
            j = i + 1
            # POSIX: a single-quoted string has no escapes; a double-quoted one does.
            if ch == chr(39):
                while j < n and command[j] != ch:
                    j += 1
            else:
                while j < n and command[j] != ch:
                    j += 2 if command[j] == chr(92) else 1
            if token:
                words.append(token)
                token = ""
            recent = words[-3:]
            is_payload = any(_PAYLOAD_FLAG.match(w) for w in words[-2:]) and any(
                w.rsplit("/", 1)[-1] in _INTERPRETERS for w in recent
            )
            if words and words[-1].rsplit("/", 1)[-1] in ("eval", "exec", "source", "xargs"):
                is_payload = True
            spans.append((i, min(j, n), is_payload, j < n))
            i = j + 1
            continue
        if ch.isspace() or ch in _SEPARATORS:
            if token:
                words.append(token)
            if ch in _SEPARATORS:
                words = []
            token = ""
        else:
            token += ch
        i += 1
    return spans


def _outside_quotes(command: str, spans) -> str:
    """The command with every quoted span blanked, for structural scanning."""
    chars = list(command)
    for start, end, _payload, _closed in spans:
        for k in range(start, min(end + 1, len(chars))):
            chars[k] = " "
    return "".join(chars)


_HEREDOC_OPEN = re.compile(r"<<-?\s*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\1[^\n]*\n")
# Commands whose heredoc body is data: written to a file or printed, never run.
_HEREDOC_SINKS = frozenset({"cat", "tee"})


def heredoc_spans(command: str) -> List[Tuple[int, int, str]]:
    """``(body_start, body_end, opener_line)`` for every closed heredoc."""
    out: List[Tuple[int, int, str]] = []
    for m in _HEREDOC_OPEN.finditer(command):
        close = re.compile(r"^\s*" + re.escape(m.group(2)) + r"\s*$", re.M).search(command, m.end())
        if close is None:
            continue
        opener = command[:m.start()].rsplit("\n", 1)[-1]
        out.append((m.end(), close.start(), opener))
    return out


def _blank(text: str, spans) -> str:
    chars = list(text)
    for start, end, *_ in spans:
        for k in range(start, min(end, len(chars))):
            chars[k] = " "
    return "".join(chars)


def is_inert_match(command: str, match_start: int, match_end: int) -> bool:
    """True when the match lies wholly inside inert text.

    Two inert forms. A quoted argument, where all of the following must hold:
      * the match is inside a closed, non-payload quoted span;
      * no interpreter appears anywhere in the command (blocks the
        ``echo "..." | bash`` form, where quoted text is still executed);
      * the enclosing pipeline segment has no redirect (``echo "..." > run.sh``
        writes the text to a script rather than displaying it);
      * that segment starts with a known text-emitting command.

    Or a heredoc body whose opener is ``cat`` or ``tee`` -- a script being
    written to a file or printed, not run. ``bash <<EOF`` feeds the body to an
    interpreter and stays live, and so does ``cat > x.py <<EOF ... EOF &&
    python3 x.py``: the interpreter rule above scans the whole command, so a
    body that is executed later in the same call is never inert. A body that
    is written now and run in a later call is staged-execution's job.
    """
    if match_start < 0 or match_end > len(command):
        return False
    hspans = heredoc_spans(command)
    # Blank heredoc bodies before quote scanning: an apostrophe inside a
    # script body would otherwise open a span that swallows the rest of the
    # command, hiding a trailing ``; python3 x.py`` from the interpreter check.
    spans = quoted_spans(_blank(command, hspans))
    bare = _blank(_outside_quotes(command, spans), hspans)

    for word in bare.replace(_SEPARATORS[0], " ").replace(_SEPARATORS[1], " ").replace(_SEPARATORS[2], " ").split():
        if word.rsplit("/", 1)[-1] in _INTERPRETERS:
            return False

    for body_start, body_end, opener in hspans:
        if body_start <= match_start and match_end <= body_end:
            segment = opener
            for sep in _SEPARATORS:
                segment = segment.split(sep)[-1]
            tokens = segment.split()
            return bool(tokens) and tokens[0].rsplit("/", 1)[-1] in _HEREDOC_SINKS

    if not spans:
        return False

    for start, end, is_payload, is_closed in spans:
        if is_payload or not is_closed:
            continue
        # +1 tolerance: a pattern anchored on a trailing delimiter may consume
        # the closing quote itself.
        if not (match_start >= start and match_end <= end + 1):
            continue
        seg_start = 0
        for k in range(start):
            if bare[k] in _SEPARATORS:
                seg_start = k + 1
        seg_end = len(command)
        for k in range(start, len(command)):
            if bare[k] in _SEPARATORS:
                seg_end = k
                break
        segment = bare[seg_start:seg_end]
        if ">" in segment or "<" in segment:
            return False
        tokens = segment.split()
        if not tokens:
            return False
        argv0 = tokens[0].rsplit("/", 1)[-1]
        if argv0 == "gh":
            return len(tokens) > 1 and tokens[1] in _GH_TEXT_SUBCOMMANDS
        if argv0 == "git":
            return len(tokens) > 1 and tokens[1] in _GIT_MESSAGE_SUBCOMMANDS
        return argv0 in _INERT_SINKS
    return False


def is_remote_payload(command: str, match_start: int, match_end: int) -> bool:
    """True when the match lies inside the payload of a context-switching command.

    Answers "will the LOCAL shell run this?", not "is this dangerous?". Used
    only for rules whose jurisdiction is this machine -- Prismor's own policy,
    credential, and hook config -- where a match inside an `ssh`/`docker`
    argument describes an operation on a *different* install (issue #344).

    Conservative in the same direction as is_inert_match: it returns True only
    on positive evidence that the match sits inside a closed quoted argument of
    a recognised context-switching command. `ssh -V; prismor allow` runs
    `prismor allow` locally -- the match is outside every quoted span, so this
    returns False and the finding stands.
    """
    if match_start < 0 or match_end > len(command):
        return False
    spans = quoted_spans(command)
    if not spans:
        return False
    bare = _outside_quotes(command, spans)

    for start, end, _is_payload, is_closed in spans:
        if not is_closed:
            continue
        # Containment is judged on where the match ENDS, not where it starts.
        # Several self-edit patterns deliberately include the wrapper that
        # opens the quote, so the match begins outside the span while the
        # invocation itself sits inside it. The +1 mirrors is_inert_match: a
        # pattern anchored on a trailing delimiter may consume the closing
        # quote.
        if not (start < match_end <= end + 1):
            continue
        seg_start = 0
        for k in range(start):
            if bare[k] in _SEPARATORS:
                seg_start = k + 1
        tokens = bare[seg_start:start].split()
        if not tokens:
            return False
        return tokens[0].rsplit("/", 1)[-1] in _REMOTE_CONTEXTS
    return False
