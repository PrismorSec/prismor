"""What a shell command does, as facts a rule can match on.

A pattern rule sees the flattened command string, so ``.prismor/policy.yaml``
in ``sed -n 55,95p .prismor/policy.yaml`` reads the same as in ``sed -i``, a
loopback ``curl`` looks like egress, and ``yes |`` inside a heredoc test
fixture looks like a fork bomb. Replaying two live sessions put every false
positive in that shape: the text was there, the action was not.

:func:`extract` turns a command into four facets a rule can name in
``fields:`` instead of ``command``:

``exec``
    the shell text that runs -- comments and heredoc data bodies gone
``reads``
    paths the command reads (reader verbs, ``<`` sources, copy sources)
``writes``
    paths it writes, replaces or deletes (redirect targets, ``-i``, ``tee``,
    ``cp``/``mv``/``install`` destinations, ``dd of=``, ``rm``)
``net_dst``
    the hosts it contacts, with loopback and private addresses left out --
    the cloud-metadata block stays in, because that is the egress that matters

``reads``, ``writes`` and ``net_dst`` are rendered one per line as
``<verb> <operand>`` -- ``sed -i ~/.prismor/policy.yaml``, ``> /tmp/s``,
``curl http://151.101.1.195/x`` -- in the vocabulary the existing rule
patterns already speak. A rule moves from ``fields: [command]`` to
``fields: [writes]`` without rewriting a pattern, and on the doubt path (facet
== raw command) it matches exactly what it matched before.

The extractor is conservative on purpose. Anything it cannot read with
confidence -- an unterminated quote, ``eval``, ``xargs``, a heredoc fed to an
interpreter, a variable or command substitution in a path or host -- makes it
return ``None``, and the caller then matches the raw command exactly as before.
Precision improves only where the parse is sure; coverage never drops below
today's behaviour. That is the property a text-reading judge cannot offer: a
comment can talk a model round, it cannot change what a command writes.
"""
from __future__ import annotations

import ipaddress
import re
import shlex
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

from prismor.runtime.shell_context import _INTERPRETERS, _outside_quotes, quoted_spans

# ponytail: verb tables, not a shell grammar. Unknown verbs contribute nothing
# to reads/writes (their operands are still in `exec`), and the doubt list
# below is what keeps that safe. Upgrade to a real parser if the tables start
# growing per bug report.
_READERS = frozenset({
    "cat", "head", "tail", "less", "more", "grep", "egrep", "fgrep", "rg", "ag",
    "awk", "wc", "sort", "uniq", "cut", "diff", "cmp", "stat", "file", "xxd",
    "hexdump", "od", "strings", "base64", "md5sum", "sha256sum", "shasum", "jq",
    "yq", "tr", "column", "nl", "tac", "rev", "sed",
})
_COPY = frozenset({"cp", "mv", "install", "rsync"})
_DELETE = frozenset({"rm", "unlink", "shred", "truncate"})
_MUTATE = frozenset({"chmod", "chown", "chgrp", "touch", "mkdir", "ln"})
_FETCHERS = frozenset({"curl", "wget", "http", "https", "httpie", "xh", "aria2c"})
_REMOTE = frozenset({"ssh", "scp", "sftp", "rsync", "nc", "ncat", "netcat", "socat", "telnet"})
# A command whose argument or standard input is executed. Its payload cannot be
# read as data, so the whole command is left to the raw-string path.
_DOUBT = frozenset({
    "eval", "exec", "source", ".", "xargs", "env", "command", "builtin",
    "bash", "sh", "zsh", "ksh", "dash", "fish", "python", "python2", "python3",
    "node", "deno", "bun", "ruby", "perl", "php", "sudo", "doas", "su", "nohup",
    "timeout", "watch", "docker", "kubectl", "ssh",
})
_UNSAFE_OPERAND = re.compile(r"[$`]")
_HEREDOC = re.compile(r"<<-?\s*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\1")
_REDIRECT = re.compile(r"^(\d*)(>>|>\||>|&>|<)(.*)$")
_URL = re.compile(r"^[a-z][a-z0-9+.-]*://([^/?#]+)", re.IGNORECASE)
_SEPARATOR = re.compile(r"\|\||&&|[;|&\n]")
_LOCAL_NETS = tuple(ipaddress.ip_network(n) for n in (
    "127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16",
    "::1/128", "fc00::/7", "fe80::/10"))
_METADATA_HOSTS = frozenset({"169.254.169.254", "169.254.169.253", "169.254.170.2", "100.100.100.200",
                             "metadata.google.internal", "metadata"})


@dataclass
class Effects:
    exec: str = ""
    reads: List[str] = field(default_factory=list)
    writes: List[str] = field(default_factory=list)
    net_dst: List[str] = field(default_factory=list)


class _Doubt(Exception):
    """The command cannot be read with confidence; fall back to raw text."""


def extract(command: str) -> Optional[Effects]:
    if not command or not command.strip():
        return Effects()
    try:
        text, _bodies = _split_heredocs(command)
        text = _strip_comments(text)
        eff = Effects()
        for segment in _segments(text):
            words = _words(segment)
            if words:
                _classify(words, eff)
        # `exec` keeps the command's own separators and spacing: a rule's
        # anchors (`yes\s*\|`, `:\(\)\s*\{.*\|.*&`) are written against the
        # shell text, and a re-tokenised copy would stop matching real hits.
        # Quoted prose stays in: a match inside `echo "..."` is still reported
        # (and downgraded, not dropped) by shell_context.is_inert_match.
        eff.exec = text if text.strip() else ""
        return eff
    except _Doubt:
        return None
    except Exception:
        # A parser bug must never widen what the raw-string path already sees.
        return None


# ── Parsing ──────────────────────────────────────────────────────────────────

def _blank_quotes(line: str, state: Optional[str]) -> Tuple[str, Optional[str]]:
    """``line`` with quoted characters blanked, carrying quote state across lines.

    A double-quoted string may span lines (``ssh host "cd x\nmake"``); per-line
    span detection called every such command unterminated and gave up on it.
    """
    out: List[str] = []
    q = state
    i = 0
    while i < len(line):
        ch = line[i]
        if q:
            if ch == "\\" and q == '"':
                out.append("  ")
                i += 2
                continue
            if ch == q:
                q = None
            out.append(" ")
            i += 1
            continue
        if ch in "\"'":
            q = ch
            out.append(" ")
        else:
            out.append(ch)
        i += 1
    return "".join(out)[: len(line)], q


def _split_heredocs(command: str) -> Tuple[str, List[str]]:
    """Cut heredoc bodies out of ``command``.

    A body handed to a data sink (``cat > f <<EOF``, ``tee``) is a file being
    written, not commands being run, so it leaves ``exec``. A body handed to
    an interpreter (``python3 - <<PY``, ``bash <<EOF``) is code in a language
    this module does not read: doubt. Bodies are data and are never quote-
    scanned -- an apostrophe in prose must not unbalance the command.
    """
    lines = command.split("\n")
    out: List[str] = []
    bodies: List[str] = []
    q: Optional[str] = None
    i = 0
    while i < len(lines):
        line = lines[i]
        bare, q_after = _blank_quotes(line, q)
        m = _HEREDOC.search(line)
        if q is None and m and bare[m.start()] == "<":
            head = _words(bare[: m.start()])
            if any(w.rsplit("/", 1)[-1] in (_DOUBT | _INTERPRETERS) for w in head):
                raise _Doubt("heredoc fed to an interpreter")
            out.append(line[: m.start()] + line[m.end():])
            q = q_after
            terminator = m.group(2)
            body: List[str] = []
            i += 1
            while i < len(lines) and lines[i].strip() != terminator:
                body.append(lines[i])
                i += 1
            if i >= len(lines):
                raise _Doubt("unterminated heredoc")
            bodies.append("\n".join(body))
            i += 1
            continue
        out.append(line)
        q = q_after
        i += 1
    return "\n".join(out), bodies


def _strip_comments(text: str) -> str:
    spans = quoted_spans(text)
    if any(not closed for _s, _e, _p, closed in spans):
        raise _Doubt("unterminated quote")
    bare = _outside_quotes(text, spans)
    out: List[str] = []
    k = 0
    while k < len(text):
        if bare[k] == "#" and (k == 0 or bare[k - 1] in " \t\n;|&("):
            nl = text.find("\n", k)
            if nl < 0:
                break
            k = nl
            continue
        out.append(text[k])
        k += 1
    return "".join(out)


def _segments(text: str) -> List[str]:
    """Split on ; | & && || and newlines that sit outside quotes."""
    bare = _outside_quotes(text, quoted_spans(text))
    segs: List[str] = []
    start = 0
    for m in _SEPARATOR.finditer(bare):
        segs.append(text[start: m.start()])
        start = m.end()
    segs.append(text[start:])
    return [s for s in segs if s.strip()]


def _words(segment: str) -> List[str]:
    try:
        words = shlex.split(segment, posix=True)
    except ValueError as exc:
        raise _Doubt(str(exc))
    # Leading VAR=value assignments are environment, not the verb.
    while words and re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", words[0]):
        words.pop(0)
    return words


# ── Classification ───────────────────────────────────────────────────────────

def _operand(word: str) -> str:
    if _UNSAFE_OPERAND.search(word):
        raise _Doubt(f"unresolved expansion in operand: {word}")
    return word


def _pathlike(word: str) -> bool:
    """A file operand, as opposed to a bare count (`head -c 3000`)."""
    return bool(word) and not word.isdigit()


def _classify(words: List[str], eff: Effects) -> None:
    verb = words[0].rsplit("/", 1)[-1]
    if verb in _DOUBT:
        raise _Doubt(f"opaque verb: {verb}")

    args: List[str] = []
    k = 1
    while k < len(words):
        w = words[k]
        m = _REDIRECT.match(w)
        if m:
            op, target = m.group(2), m.group(3)
            if not target:
                k += 1
                target = words[k] if k < len(words) else ""
            if target and not target.startswith("&"):
                target = _operand(target)
                if op == "<":
                    eff.reads.append(f"< {target}")
                elif target not in ("/dev/null", "/dev/stderr", "/dev/stdout"):
                    eff.writes.append(f"{op} {target}")
            k += 1
            continue
        args.append(w)
        k += 1

    operands = [a for a in args if not a.startswith("-") and _pathlike(a)]

    def read(paths):
        eff.reads.extend(f"{verb} {_operand(a)}" for a in paths)

    def write(paths, how=None):
        eff.writes.extend(f"{how or verb} {_operand(a)}" for a in paths)

    if verb in _READERS:
        if verb == "sed" and any(a == "--in-place" or a.startswith("-i") for a in args):
            write(_sed_in_place_files(args), "sed -i")
        else:
            # The first operand of grep/sed/awk is a pattern or script, not a file.
            skip = 1 if verb in ("grep", "egrep", "fgrep", "rg", "ag", "awk", "sed") and operands else 0
            read(operands[skip:])
    elif verb in _COPY:
        if len(operands) >= 2:
            read(operands[:-1])
            write(operands[-1:])
    elif verb in _DELETE or verb in _MUTATE or verb == "tee":
        write(operands)
    elif verb == "dd":
        for a in args:
            if a.startswith("of="):
                eff.writes.append(f"dd of={_operand(a[3:])}")
            elif a.startswith("if="):
                eff.reads.append(f"dd if={_operand(a[3:])}")
    elif verb in _FETCHERS:
        for a in operands:
            host = _url_host(a)
            if host:
                _add_host(eff, verb, a, host)
    elif verb in _REMOTE:
        for a in operands:
            host = _remote_host(a)
            if host:
                _add_host(eff, verb, a, host)
    else:
        # Any verb may still take a URL argument (aws s3 cp s3://..., git clone).
        for a in operands:
            host = _url_host(a)
            if host:
                _add_host(eff, verb, a, host)


def _sed_in_place_files(args: List[str]) -> List[str]:
    """The files `sed -i` rewrites.

    Missing one is not a narrowing, it is a hole: the attack set caught
    `sed -i '' 's/mode: enforce/mode: observe/' ~/.prismor/policy.yaml`
    reading as no write at all, because the quoted script has spaces.
    """
    files: List[str] = []
    script_given = False
    k = 0
    while k < len(args):
        a = args[k]
        if a in ("-e", "--expression", "-f", "--file"):
            script_given = True
            k += 2
            continue
        if a == "-i" and k + 1 < len(args) and (args[k + 1] == "" or args[k + 1].startswith(".")):
            k += 2                      # BSD backup suffix: `-i ''`, `-i .bak`
            continue
        if a.startswith("-"):
            k += 1
            continue
        if not script_given:
            script_given = True         # first bare word is the script
        else:
            files.append(a)
        k += 1
    return files


def _url_host(word: str) -> Optional[str]:
    m = _URL.match(word)
    if not m:
        return None
    host = m.group(1)
    if "@" in host:
        host = host.rsplit("@", 1)[1]
    return host.rsplit(":", 1)[0] if not host.startswith("[") else host.strip("[]").split("]")[0]


def _remote_host(word: str) -> Optional[str]:
    if "://" in word:
        return _url_host(word)
    if word.startswith("-"):
        return None
    # `scp -i ~/.ssh/key.pem ./fix.tgz user@host:/tmp` -- the key and the
    # file are operands too, and a dotted filename is not a hostname.
    if "/" in word.split(":", 1)[0]:
        return None
    host = word
    if ":" in host and not host.startswith("["):
        host = host.split(":", 1)[0]
    if "@" in host:
        host = host.rsplit("@", 1)[1]
    return host if host and ("." in host or host == "localhost") else None


def _add_host(eff: Effects, verb: str, raw: str, host: str) -> None:
    _operand(raw)
    if _is_local(host):
        return
    eff.net_dst.append(f"{verb} {raw}")


def _is_local(host: str) -> bool:
    if host in _METADATA_HOSTS:
        return False
    if host.lower() in ("localhost", "localhost.localdomain"):
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return host.lower().endswith(".localhost")
    return ip.is_unspecified or any(ip in net for net in _LOCAL_NETS)
