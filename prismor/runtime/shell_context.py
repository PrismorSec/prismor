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
import shlex
from typing import List, NamedTuple, Tuple

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

# OpenSSH's getopt string (ssh.c), split by arity. Every flag VALUE is consumed
# on this machine -- a file it reads (-i, -F), a command it runs
# (-o ProxyCommand=...) -- so only words after the destination are the remote
# command (issue #607).
_SSH_ARG_FLAGS = frozenset("BbcDEeFIiJLlmOoPpQRSWw")
_SSH_NOARG_FLAGS = frozenset("46AaCfGgKkMNnqsTtVvXxYy")

# Subcommands of the other remote contexts that move LOCAL files in or out
# (`docker cp`, `lxc file push`, `machinectl copy-to`). Their quoted arguments
# are paths on this machine, not a remote payload.
_LOCAL_FILE_SUBCOMMANDS = frozenset({
    "cp", "push", "pull", "upload", "transfer", "mount", "bind",
    "copy-to", "copy-from",
})

# Unquoted openers of a local substitution. A quoted span after one is an
# argument of a LOCAL command nested in the remote one's argv
# (`ssh host $(sh -c "...")`), never the remote payload itself.
_LOCAL_EVAL_OPENERS = ("$(", "`", "<(", ">(")

_SEPARATORS = ";|&"
_QUOTES = "\"" + chr(39)


def _has_double_quote_command_substitution(value: str) -> bool:
    """True when a double-quoted shell span contains executable substitution.

    POSIX-style single quotes are inert data. Double quotes are not: command
    substitutions using ``$(...)`` and legacy backticks execute before the
    surrounding command receives its argument. A destructive match inside
    ``echo "$(rm -rf /)"`` therefore lives in code, not prose.
    """
    i = 0
    while i < len(value):
        ch = value[i]
        if ch == chr(92):
            i += 2
            continue
        if ch == "`":
            return True
        if ch == "$" and i + 1 < len(value) and value[i + 1] == "(":
            return True
        i += 1
    return False


def command_substitution_spans(value: str) -> List[Tuple[int, int]]:
    """Return (start, end) offsets of executable $(...) and `...` substitutions.

    In an unquoted heredoc, \\ escapes $, `, and \\. Unescaped $(...) and `...`
    execute before the heredoc sink receives its input.
    """
    spans: List[Tuple[int, int]] = []
    i = 0
    n = len(value)
    while i < n:
        ch = value[i]
        if ch == chr(92):
            i += 2
            continue
        if ch == "`":
            start = i
            i += 1
            while i < n and value[i] != "`":
                if value[i] == chr(92):
                    i += 2
                else:
                    i += 1
            end = min(i + 1, n)
            spans.append((start, end))
            i = end
            continue
        if ch == "$" and i + 1 < n and value[i + 1] == "(":
            start = i
            depth = 1
            i += 2
            while i < n and depth > 0:
                c = value[i]
                if c == chr(92):
                    i += 2
                    continue
                if c in (chr(39), chr(34)):
                    q = c
                    i += 1
                    while i < n and value[i] != q:
                        if q == chr(34) and value[i] == chr(92):
                            i += 2
                        else:
                            i += 1
                    if i < n:
                        i += 1
                    continue
                if c == "(":
                    depth += 1
                elif c == ")":
                    depth -= 1
                i += 1
            spans.append((start, i))
            continue
        i += 1
    return spans


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
            if ch == '"' and _has_double_quote_command_substitution(command[i + 1:min(j, n)]):
                is_payload = True
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


# `<<EOF`, `<<-EOF`, `<< "EOF"`, `<<\EOF`; not the `<<<` of a here-string.
_HEREDOC_OPEN = re.compile(
    r"(?<!<)(?P<op><<-?\s*(?P<q>['\"\\]?)(?P<d>[A-Za-z_][A-Za-z0-9_]*)['\"]?)[^\n]*\n"
)
# Commands whose heredoc body is data: written to a file or printed, never run.
_HEREDOC_SINKS = frozenset({"cat", "tee"})


class Heredoc(NamedTuple):
    """One closed heredoc; the offsets index the command it was found in."""

    start: int  # the ``<<``
    op_end: int  # just past the delimiter word
    body_start: int  # first character of the body
    body_end: int  # start of the closing delimiter line
    end: int  # end of the closing delimiter line
    expands: bool  # unquoted delimiter: the shell expands the body


def heredocs(command: str) -> List[Heredoc]:
    """Every closed heredoc, left to right. A ``<<`` inside another's body
    is body text, not an opener. This is the one heredoc grammar; the
    provenance scanner reads it too."""
    out: List[Heredoc] = []
    pos = 0
    for m in _HEREDOC_OPEN.finditer(command):
        if m.start() < pos:
            continue
        close = re.compile(
            r"^\s*" + re.escape(m.group("d")) + r"\s*$", re.M
        ).search(command, m.end())
        if close is None:
            continue
        out.append(Heredoc(
            m.start(), m.end("op"), m.end(), close.start(), close.end(),
            not m.group("q"),
        ))
        pos = close.end()
    return out


def heredoc_spans(command: str) -> List[Tuple[int, int, str]]:
    """``(body_start, body_end, opener_line)`` for every closed heredoc."""
    return [
        (h.body_start, h.body_end, command[:h.start].rsplit("\n", 1)[-1])
        for h in heredocs(command)
    ]


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
    written to a file or printed, not run. If the delimiter is unquoted (so
    the shell expands the body), any match overlapping an executable command
    substitution (``$(...)`` or ```...```) is live code, not inert text.
    ``bash <<EOF`` feeds the body to an interpreter and stays live, and so does
    ``cat > x.py <<EOF ... EOF && python3 x.py``: the interpreter rule above
    scans the whole command, so a body that is executed later in the same call
    is never inert. A body that is written now and run in a later call is
    staged-execution's job.
    """
    if match_start < 0 or match_end > len(command):
        return False
    hdocs = heredocs(command)
    hspans = [
        (h.body_start, h.body_end, command[:h.start].rsplit("\n", 1)[-1])
        for h in hdocs
    ]
    # Blank heredoc bodies before quote scanning: an apostrophe inside a
    # script body would otherwise open a span that swallows the rest of the
    # command, hiding a trailing ``; python3 x.py`` from the interpreter check.
    spans = quoted_spans(_blank(command, hspans))
    bare = _blank(_outside_quotes(command, spans), hspans)

    for word in bare.replace(_SEPARATORS[0], " ").replace(_SEPARATORS[1], " ").replace(_SEPARATORS[2], " ").split():
        if word.rsplit("/", 1)[-1] in _INTERPRETERS:
            return False

    for h in hdocs:
        effective_start = match_start
        while effective_start < match_end and command[effective_start].isspace():
            effective_start += 1
        effective_end = match_end
        while effective_end > effective_start and command[effective_end - 1].isspace():
            effective_end -= 1

        if h.body_start <= effective_start and effective_end <= h.body_end:
            opener = command[:h.start].rsplit("\n", 1)[-1]
            segment = opener
            for sep in _SEPARATORS:
                segment = segment.split(sep)[-1]
            tokens = segment.split()
            if not (bool(tokens) and tokens[0].rsplit("/", 1)[-1] in _HEREDOC_SINKS):
                return False
            if h.expands:
                body = command[h.body_start:h.body_end]
                for sub_start, sub_end in command_substitution_spans(body):
                    abs_start = h.body_start + sub_start
                    abs_end = h.body_start + sub_end
                    if match_start < abs_end and match_end > abs_start:
                        return False
            return True

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


def _ssh_command_start(words: List[str], i: int) -> int:
    """Index of the first remote-command word of the ssh argv at ``words[i]``.

    Mirrors OpenSSH's parse: options, the destination, more options, then the
    command. -1 when the argv cannot be parsed with confidence.
    """
    n = len(words)
    host_seen = False
    i += 1
    while i < n:
        word = words[i]
        if word == "--":
            return i + 1 if host_seen else i + 2
        if word.startswith("-") and len(word) > 1:
            for j in range(1, len(word)):
                if word[j] in _SSH_ARG_FLAGS:
                    if j == len(word) - 1:
                        i += 1  # the value is the next word
                    break
                if word[j] not in _SSH_NOARG_FLAGS:
                    return -1
            i += 1
            continue
        if host_seen:
            return i
        host_seen = True
        i += 1
    return n


def _is_remote_argument(words: List[str]) -> bool:
    """Is the last of ``words`` (one remote-context argv) run remotely?"""
    target = len(words) - 1
    name = words[0].rsplit("/", 1)[-1]
    if name in ("ssh", "sshpass"):
        i = 0
        if name == "sshpass":
            # sshpass's own options (the password, its file) come first.
            i = next((k for k in range(1, target)
                      if words[k].rsplit("/", 1)[-1] == "ssh"), -1)
            if i < 0:
                return False
        start = _ssh_command_start(words, i)
        return 0 <= start <= target
    if any(w in _LOCAL_FILE_SUBCOMMANDS for w in words[1:target]):
        return False
    # A flag value (`-v "..."`, `--env-file=...`) is read on this machine; the
    # `-c`/`-e` payload flags and `--` introduce the remote command.
    if words[target].startswith("-"):
        return False
    prev = words[target - 1] if target > 0 else ""
    return not (prev.startswith("-") and prev != "--" and not _PAYLOAD_FLAG.match(prev))


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

    Exemptions require confirmed remote execution:
      * Matches inside unescaped command substitutions (`$(...)` or ```...```)
        within double quotes execute locally before the remote command receives
        them, and therefore stay live (issue #607).
      * ssh option values (`-o ProxyCommand=...`, `-i`, `-F`) are consumed on
        this machine; only words after the destination are the remote command.
      * A span nested in an unquoted local substitution, or passed to a
        file-copy subcommand (`docker cp`) or a flag of another context, is
        local too (issue #607).
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

        # In double quotes, unescaped command substitutions ($(cmd) and `cmd`)
        # execute on the LOCAL machine before the enclosing command runs.
        # Any match overlapping an executable substitution is live local code.
        if command[start] == '"':
            inner = command[start + 1:end]
            effective_start = max(match_start, start + 1)
            effective_end = min(match_end, end)
            is_sub = False
            for sub_start, sub_end in command_substitution_spans(inner):
                abs_start = start + 1 + sub_start
                abs_end = start + 1 + sub_end
                if effective_start < abs_end and effective_end > abs_start:
                    is_sub = True
                    break
            if is_sub:
                return False

        # A newline separates commands as surely as `;` does.
        seg_start = 0
        for k in range(start):
            if bare[k] in _SEPARATORS or bare[k] == "\n":
                seg_start = k + 1
        prefix = bare[seg_start:start]
        if any(opener in prefix for opener in _LOCAL_EVAL_OPENERS):
            return False
        tokens = prefix.split()
        if not tokens or tokens[0].rsplit("/", 1)[-1] not in _REMOTE_CONTEXTS:
            return False
        try:
            words = shlex.split(command[seg_start:end + 1])
        except ValueError:
            return False
        return bool(words) and _is_remote_argument(words)
    return False
