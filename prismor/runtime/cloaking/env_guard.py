"""Unprotected-entry check for env-guard.sh.

``env-guard.sh`` denies a Read or a content-reading Bash command that targets
a dotenv-style file *only while that file holds values not yet registered in
the cloak vault* — once every entry is imported (``prismor cloak add
--env-file``), the guard stands down and the existing hooks take over
(read-guard denies Reads of registered values; decloak's output scrub masks
them in Bash output).

The "is this file fully imported?" question must be answered with exactly the
same parsing the import path uses, or a file could look unprotected forever
after a successful import. That is why this lives in Python next to
``secrets_store`` instead of being re-implemented in the hook's bash: both
sides share ``_parse_env_line``.

Invoked by the hook as:

    python3 -c 'from prismor.runtime.cloaking.env_guard import main; main()' FILE...

and prints a JSON object: ``{"files": {path: [entry names...]}, "total": N}``
listing, per file, the KEY names (never values) whose values are absent from
the vault. Parse errors are treated leniently — a malformed line is skipped
rather than failing the whole file, so one odd line cannot mask real secrets
on the lines around it.
"""
from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path
from typing import Dict, List, Set

from prismor.runtime.cloaking.secrets_store import _parse_env_line, decode_text, secrets_dir

# Values shorter than this are ignored, mirroring read-guard.sh's minimum —
# tiny values ("1", "true", "dev") are config, not secrets, and matching them
# against the vault would be noise either way.
MIN_VALUE_LEN = 4


# ── Windows path handling ───────────────────────────────────────────────────
# Git Bash hands this module `C:\work\x`, `/c/work/x`, `.\.env`, 8.3 names,
# `.env.` and `.env::$DATA`; Windows opens all of them as the same file.
def _win() -> bool:
    return os.name == "nt"   # tests patch this to exercise the Windows branch on any OS


def _drive_root(letter: str) -> str:
    return f"{letter.upper()}:/"   # tests patch this to point a drive at a tmp dir


_MSYS_RE = re.compile(r"^/(?:cygdrive/)?([A-Za-z])(?=/|$)/?(.*)$")
_WIN_PREFIX = r"(?:[A-Za-z]:|\.{1,2}|[\w-]+~\d+)"
_WIN_QUOTED = re.compile(r"([\"'])(" + _WIN_PREFIX + r"\\[^\"'\n]*?)\1")
_WIN_BARE = re.compile(r"(?<![\w\\/\"'])(" + _WIN_PREFIX + r"\\[^\s;&|()<>\"']*)")
_WIN_REL = re.compile(r"(?<![\w\\/\"'.~-])([\w.~-]+(?:\\[\w.~*?-]+)+)")


def winslash(command: str) -> str:
    """``command`` with backslash paths turned to ``/`` (shlex would eat the
    backslashes: `cat .\\.env` lexes as `cat ..env`). Only path-shaped words move:
    a drive or `.\\` / `..\\` / 8.3 prefix, or a relative path ending in an env
    file name. `\\cat`, `a\\ b` and other escapes are left alone."""
    if not _win() or "\\" not in command:
        return command
    fwd = lambda m: m.group(0).replace("\\", "/")  # noqa: E731
    command = _WIN_QUOTED.sub(fwd, command)
    command = _WIN_BARE.sub(fwd, command)
    return _WIN_REL.sub(lambda m: m.group(0).replace("\\", "/")
                        if is_env_basename(m.group(1).replace("\\", "/")) else m.group(0), command)


def native_path(p: str) -> str:
    """Resolve the spellings Windows treats as one file: MSYS `/c/x`, `\\`,
    trailing dots/spaces, `::$DATA` / `:stream`, 8.3 short names."""
    if not _win() or not p:
        return p
    p = p.replace("\\", "/")
    m = _MSYS_RE.match(p) or re.match(r"^([A-Za-z]):/+(.*)$", p)
    if m:
        p = _drive_root(m.group(1)) + m.group(2)
    head, _, base = p.rpartition("/")
    if ":" in base and not (not head and len(base) == 2):
        base = base.split(":", 1)[0]
    parts = (head + "/" + base if head or p.startswith("/") else base).split("/")
    p = "/".join(c if c in ("", ".", "..") or (len(c) == 2 and c[1] == ":") else c.rstrip(". ") for c in parts)
    if "~" in p and os.name == "nt":
        try:
            import ctypes
            buf = ctypes.create_unicode_buffer(32768)
            if ctypes.windll.kernel32.GetLongPathNameW(p, buf, len(buf)):
                p = buf.value.replace("\\", "/")
        except Exception:
            pass
    return p


def vault_values() -> Set[str]:
    """Every registered secret value, read fresh from the vault."""
    values: Set[str] = set()
    sdir = secrets_dir()
    if not sdir.is_dir():
        return values
    for child in sdir.iterdir():
        if not child.is_file():
            continue
        try:
            values.add(decode_text(child.read_bytes()))
        except (OSError, UnicodeDecodeError):
            continue
    return values


def unprotected_entries(path: Path, vault: Set[str] | None = None) -> List[str]:
    """KEY names in ``path`` whose values are not registered in the vault."""
    if vault is None:
        vault = vault_values()
    try:
        text = decode_text(path.read_bytes())   # BOM / UTF-16 files too
    except (OSError, UnicodeDecodeError):
        return []
    names: List[str] = []
    for line_no, raw_line in enumerate(text.splitlines(), start=1):
        try:
            item = _parse_env_line(raw_line, line_no)
        except ValueError:
            continue
        if item is None:
            continue
        key, value = item
        if len(value) < MIN_VALUE_LEN:
            continue
        if value not in vault:
            names.append(key)
    return names


def main(argv: List[str] | None = None) -> None:
    args = sys.argv[1:] if argv is None else argv
    vault = vault_values()
    files: Dict[str, List[str]] = {}
    total = 0
    for arg in args:
        names = unprotected_entries(Path(arg), vault)
        if names:
            files[arg] = names
            total += len(names)
    print(json.dumps({"files": files, "total": total}))


_WORD = re.compile(r"[A-Za-z0-9_.~/-]+")


def local_text(command: str) -> str:
    """``command`` with every word the LOCAL shell won't touch blanked out.

    A path inside ``ssh host '<cmd>'`` (or another context-switching command's
    quoted payload) names a file on the other machine; resolving it against
    this machine's cwd denied commands that never read a local file. Uses the
    same ``is_remote_payload`` the policy engine judges remote payloads with.
    """
    try:
        from prismor.runtime.shell_context import is_remote_payload
    except Exception:
        return command
    out = list(command)
    for m in _WORD.finditer(command):
        if is_remote_payload(command, m.start(), m.end()):
            out[m.start():m.end()] = " " * (m.end() - m.start())
    # A heredoc body that nothing executes (`cat > notes.md <<EOF`) is text
    # being written, not a file being read. Kept when any part of the command
    # could run it (`python3 - <<EOF` opening the file reads it for real).
    from prismor.runtime.egress import _network_text
    return _network_text("".join(out))[0]


def local_text_main() -> None:
    sys.stdout.write(local_text(sys.stdin.read()))


_CMD_SEP = {"&&", "||", ";", "|", "&", "\n", "(", ")", "|&", ";;"}
UNKNOWN = "?"
_PUNCT = ";&|()<>\n"
_OPS_RE = re.compile(r"&&|\|\||\|&|;;|&>>|&>|>>|>\||>&|<<<|<<-|<<|<>|<&|[;&|()<>\n]")
# Words that may precede the command name of a simple command.
_PREFIX_WORDS = {"{", "}", "!", "if", "then", "else", "elif", "fi", "do", "done",
                 "while", "until", "time", "command", "builtin"}
_ASSIGN_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(\[[^]]*\])?\+?=")
# `$IFS` / `${IFS}` / `${IFS:0:1}` expand to whitespace: `cat${IFS}.env`.
_IFS_RE = re.compile(r"\$\{IFS[^}]*\}|\$IFS(?![A-Za-z0-9_])")
# The fd number of a redirect (`2>&1`, `1>out`): bash reads it as part of the
# operator, shlex as a word, which made `docker build . 2>&1` look like context `2`.
_FD_RE = re.compile(r"(?:(?<=[\s;&|])|^)\d+(?=[<>])")


def _tokens(command: str):
    """Shell words and operators of ``command`` (quotes removed, so `"cat"`,
    `\\cat` and `c""at` are all `cat`; newlines kept as separators), or None
    when it does not lex (unbalanced quotes)."""
    import shlex
    try:
        lex = shlex.shlex(_FD_RE.sub("", _IFS_RE.sub(" ", winslash(command))), posix=True, punctuation_chars=_PUNCT)
        lex.whitespace = " \t\r"
        lex.whitespace_split = True
        lex.commenters = ""   # a comment swallowed the newline that ends it
        tokens = []
        for t in lex:
            # shlex glues adjacent punctuation (`);`, `)&&`, `2>&1`); split it
            # back into operators so a subshell's `)` is seen.
            if t and set(t) <= set(_PUNCT):
                tokens += _OPS_RE.findall(t)
            else:
                tokens.append(t)
        return tokens
    except ValueError:
        return None


def is_env_basename(path: str) -> bool:
    """The Python twin of env-guard.sh's ``_is_env_basename``."""
    b = os.path.basename(path).lower()
    if any(x in b for x in ("example", "sample", "template", "dist")):
        return False
    return b in (".env", ".envrc") or b.startswith(".env.") or b.endswith(".env") or ".env." in b


def _cd_target(arg: str | None, cur: str, prev: str) -> str:
    """Where ``cd arg`` lands from ``cur``, or UNKNOWN if it can't be known statically."""
    if arg is None:
        return os.path.expanduser("~")
    if arg == "-":
        return prev
    target = os.path.expandvars(os.path.expanduser(arg))
    if "$" in target or "`" in target:
        return UNKNOWN
    if cur == UNKNOWN and not os.path.isabs(target):
        return UNKNOWN
    return os.path.normpath(os.path.join(cur, target))


def word_dirs(command: str, cwd: str) -> List[tuple]:
    """``(word, dir, seg)`` for every word of ``command``: the directory the
    shell is in when that word runs, following ``cd``/``pushd``/``popd``
    (subshells and pipeline stages don't leak), and the number of the simple
    command it belongs to. ``dir`` is UNKNOWN after a ``cd`` whose target is a
    variable or command substitution.

    Unparseable input (unbalanced quotes) falls back to the session cwd for
    every word, which is the old behaviour, with ``seg`` -1 (no segments).
    """
    tokens = _tokens(command)
    if tokens is None:
        return [(w, cwd, -1) for w in command.split()]

    out: List[tuple] = []
    cur, prev, stack, dstack = cwd, cwd, [], []
    at_start = True
    seg = 0
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if tok in _CMD_SEP:
            seg += 1
            if tok == "(":
                stack.append((cur, prev))
            elif tok == ")" and stack:
                cur, prev = stack.pop()
            at_start = True
            i += 1
            continue
        out.append((tok, cur, seg))
        # `{ cd x; }`, `if cd x`, `command cd x`, `X=1 cd x` all change dir.
        if at_start and (tok in _PREFIX_WORDS or _ASSIGN_RE.match(tok)):
            i += 1
            continue
        if at_start and tok in ("cd", "pushd", "popd"):
            args, j = [], i + 1
            while j < len(tokens) and tokens[j] not in _CMD_SEP:
                out.append((tokens[j], cur, seg))
                args.append(tokens[j])
                j += 1
            ends = tokens[j] if j < len(tokens) else ""
            if ends not in ("|", "&", "|&"):  # a pipeline stage or background job runs in a subshell
                args = [a for a in args if a not in ("-L", "-P", "-e", "-@", "--")]
                if tok == "popd":
                    new = dstack.pop() if dstack else cur
                else:
                    new = _cd_target(args[0] if args else None, cur, prev)
                    if tok == "pushd":
                        dstack.append(cur)
                prev, cur = cur, new
            i = j
            continue
        at_start = False
        i += 1
    return out


_GREPPERS = {"grep", "egrep", "fgrep", "rg", "ag", "ack"}
# Flags of the grep family that take the next word as their value.
_GREP_VALUE_FLAGS = {"-A", "-B", "-C", "-m", "-g", "-t", "-T", "--glob", "--include",
                     "--exclude", "--type", "--max-count", "--context"}


def _grep_pattern_words(segs: Dict[int, List[str]]) -> set:
    """``(seg, word)`` for the search pattern of each grep-family command.

    `grep -rn '<pattern>' src/` searches src/ for that text; it does not open a
    file named like the pattern. A pattern given with -e/--regexp is that
    flag's value, and -f/--file names a real file, so it is never skipped.
    """
    out = set()
    for seg, ws in segs.items():
        if seg < 0 or not ws:
            continue
        name = os.path.basename(ws[0])
        args = ws[1:]
        if name == "git":
            if not args or args[0] != "grep":
                continue
            args = args[1:]
        elif name not in _GREPPERS:
            continue
        i = 0
        while i < len(args):
            a = args[i]
            if a in ("-e", "--regexp"):
                if i + 1 < len(args):
                    out.add((seg, args[i + 1]))
                break
            if a in ("-f", "--file"):
                break
            if a.startswith("-"):
                i += 2 if a in _GREP_VALUE_FLAGS else 1
                continue
            out.add((seg, a))
            break
    return out


def candidate_paths(command: str, cwd: str) -> List[str]:
    """Every path ``command`` could name, resolved against the directory the
    shell is in at that point. A relative path after an unresolvable ``cd`` is
    returned as ``?<word>`` so the hook can fail closed instead of guessing.

    Words of a ``prismor cloak ...`` simple command are skipped: the CLI
    prints names and byte counts, never values, so the env file it names is
    not read into context. Only that segment is exempt — a ``2>&1 | grep -v
    note`` tail passes, a ``| cat .env`` tail does not — and never one
    carrying `` ` `` or ``$`` (a substitution inside it runs its own reader)."""
    words = word_dirs(command, cwd)
    segs: Dict[int, List[str]] = {}
    for word, _, seg in words:
        segs.setdefault(seg, []).append(word)
    cloak = {seg for seg, ws in segs.items()
             if seg >= 0 and len(ws) >= 2 and os.path.basename(ws[0]) == "prismor"
             and ws[1] == "cloak" and not any("`" in w or "$" in w for w in ws)}
    patterns = _grep_pattern_words(segs)
    seen: List[str] = []
    for word, d, seg in words:
        if seg in cloak or (seg, word) in patterns:
            continue
        for m in _WORD.finditer(word):
            tok = m.group(0)
            path = os.path.expanduser(tok)
            if not os.path.isabs(path):
                path = UNKNOWN + tok if d == UNKNOWN else os.path.join(d, path)
            if path not in seen:
                seen.append(path)
    return seen


def candidate_paths_main() -> None:
    cwd = sys.argv[1] if len(sys.argv) > 1 else os.getcwd()
    sys.stdout.write("\n".join(candidate_paths(sys.stdin.read(), cwd)))


# ── which env files a Bash command READS ────────────────────────────────────
# Deny-by-default: any command that names an env file reads it, except these,
# which only look at its name or metadata, or write it. A reader list (`cat`,
# `sed`, ...) was bypassed by every reader it didn't list (`jq`, `dd`, `.`,
# `bash -x`) and by spelling a listed one differently (`"cat"`, `\cat`).
_SAFE_CMDS = {"ls", "stat", "test", "[", "[[", "touch", "rm", "rmdir", "chmod", "chown",
              "echo", "printf", "wc", "file", "mkdir", "du", "realpath", "readlink",
              "basename", "dirname", "tee", "true", "false", ":", "exit", "cd", "pushd",
              "popd", "which"}   # not `type`: cmd's `type .env` prints the file
_SAFE_GIT = {"add", "rm", "check-ignore", "ls-files", "status"}
_PRESENCE_RE = re.compile(r"^(-[A-Za-z]*[qclL][A-Za-z]*|--(quiet|silent|count|files-with-matches|files-without-match))$")
# These run text they are fed: an env path a "safe" command prints into them
# (`echo .env | xargs cat`) is read after all.
_RUNNERS = {"xargs", "parallel", "sh", "bash", "zsh", "dash", "ksh", "fish", "eval", "source", "."}
_EXPANSION_RE = re.compile(r"\$\{[^}]*\}|\$\([^)]*\)?|\$[A-Za-z0-9_@*#?!$-]*|`[^`]*`?")
_WRITE_REDIRS = {">", ">>", ">|", "&>", "&>>", ">&"}


def _segments(tokens: List[str]) -> List[Dict]:
    segs, cur = [], {"words": [], "redir_in": [], "skip": set()}
    i = 0
    while i < len(tokens):
        t = tokens[i]
        if t in _CMD_SEP:
            segs.append(cur)
            cur = {"words": [], "redir_in": [], "skip": set(), "after": t}
        elif t in _WRITE_REDIRS or t in ("<<", "<<-", "<<<", "<&"):
            i += 1   # write target, heredoc delimiter, here-string, fd: not a read
        elif t in ("<", "<>"):
            if i + 1 < len(tokens) and tokens[i + 1] not in _CMD_SEP:
                cur["redir_in"].append(tokens[i + 1])
            i += 1
        else:
            cur["words"].append(t)
        i += 1
    segs.append(cur)
    return segs


def _cmd_name(words: List[str]):
    """(index of the command name, name) after keywords and assignments."""
    for k, w in enumerate(words):
        if w in _PREFIX_WORDS or _ASSIGN_RE.match(w):
            continue
        return k, os.path.basename(w)
    return len(words), ""


def _is_safe(words: List[str], k: int, name: str) -> bool:
    args = words[k + 1:]
    if name in _SAFE_CMDS:
        return True
    if name == "git":
        return bool(args) and args[0] in _SAFE_GIT
    if name == "find":
        return not any(a.startswith(("-exec", "-ok", "-fprint", "-fls")) for a in args)
    if name in _GREPPERS:
        return any(_PRESENCE_RE.match(a) for a in args)
    if name == "prismor":
        # The ingestion path prints names and byte counts only; not when it
        # carries a substitution, which runs its own reader.
        return bool(args) and args[0] == "cloak" and not any("$" in w or "`" in w for w in words)
    return False


def _env_files_in(d: str) -> List[str]:
    try:
        return [n for n in os.listdir(d) if is_env_basename(n) and os.path.isfile(os.path.join(d, n))]
    except OSError:
        return []


def _pattern_hits(word: str, d: str, out: List[str]) -> None:
    """Env files a word with a glob or an expansion could name."""
    import fnmatch
    head, _, base = word.rpartition("/")
    dynamic = "$" in base or "`" in base
    pat = _EXPANSION_RE.sub("*", base)
    pat = re.sub(r"\{[^}]*,[^}]*\}", "*", pat)
    if "$" in head or "`" in head:
        if is_env_basename(pat.replace("*", "")) and "*" not in pat:
            out.append(UNKNOWN + word)
        return
    if head:
        head = os.path.expanduser(native_path(head))
        d = head if os.path.isabs(head) else os.path.join(d, head)
    elif d == UNKNOWN:
        return
    if any(c in d for c in "*?["):   # `proj*/.env`: every directory the glob names
        import glob
        dirs = [x for x in glob.glob(d)[:200] if os.path.isdir(x)]
    else:
        dirs = [d]
    for d in dirs:
        for n in _env_files_in(d):
            # A variable may hold a dotfile name; a bare glob `*` skips dotfiles.
            if fnmatch.fnmatchcase(n, pat) and (dynamic or not n.startswith(".") or pat.startswith(".")):
                out.append(os.path.join(d, n))


def _word_hits(word: str, d: str, out: List[str], *, dynamic: bool) -> None:
    toks = [m.group(0) for m in _WORD.finditer(word)]
    if _win() or " " in word:   # `"C:/my dir/.env"`: a quoted path is one word, not several
        toks.insert(0, word)
    for tok in toks:
        tok = native_path(tok)
        path = os.path.expanduser(tok)
        if not os.path.isabs(path):
            if d == UNKNOWN:
                if is_env_basename(tok):
                    out.append(UNKNOWN + tok)
                continue
            path = os.path.join(d, path)
        if os.path.lexists(path):
            real = os.path.realpath(path)   # a symlink to .env reads .env
            if os.path.isfile(real) and (is_env_basename(path) or is_env_basename(real)):
                out.append(real)
    if dynamic and ("$" in word or "`" in word or any(c in word for c in "*?[{")):
        _pattern_hits(word, d, out)


def _recursive(name: str, words: List[str]) -> bool:
    if name in ("rg", "ag"):   # recursive, but skip dotfiles unless told not to
        return any(w in ("--hidden", "-uu", "-uuu", "-.") for w in words)
    return any(w in ("--recursive", "--dereference-recursive") or
               (w.startswith("-") and not w.startswith("--") and ("r" in w or "R" in w)) for w in words)


def env_reads(command: str, cwd: str) -> List[str]:
    """Env files ``command`` would read, or ``?<word>`` for one whose directory
    can't be known before it runs (fail closed). Writes (`>> .env`), metadata
    commands (`ls`, `stat`, `test -f`), presence checks (`grep -q`) and the
    ``prismor cloak`` ingestion path don't count; anything else that names an
    env file does, however the command name is spelled or quoted."""
    tokens = _tokens(command)
    if tokens is None:   # unbalanced quotes: every word, against cwd
        out: List[str] = []
        for w in command.split():
            _word_hits(w, cwd, out, dynamic=True)
        return list(dict.fromkeys(out))
    # The directory each segment runs in comes from word_dirs' cd tracking.
    dirs: Dict[int, str] = {}
    for _, d, seg in word_dirs(command, cwd):
        dirs.setdefault(seg, d)
    segs = _segments(tokens)
    names = [_cmd_name(s["words"]) for s in segs]
    runner = any(n in _RUNNERS or n.startswith("python") for _, n in names)
    out = []
    for idx, (s, (k, name)) in enumerate(zip(segs, names)):
        d = dirs.get(idx, cwd)
        safe = not runner and _is_safe(s["words"], k, name)
        grep_pat = set()
        if name in _GREPPERS or (name == "git" and s["words"][k + 1:k + 2] == ["grep"]):
            grep_pat = {w for _, w in _grep_pattern_words({0: s["words"][k:]})}
        for j, w in enumerate(s["words"]):
            if name in ("cd", "pushd", "popd") and j > k:
                continue
            # A substitution inside any word runs, whatever command holds it.
            if "$(" in w or "`" in w:
                # `"$(cat .env)"`, `"$(cat $F)"`; a bare `"$(date)"` is no read.
                _word_hits(w, d, out, dynamic=w.count("$") > 1 or any(c in w for c in "*?["))
            if safe or w in grep_pat:
                continue
            _word_hits(w, d, out, dynamic=True)
            if name in _GREPPERS and j > k and _recursive(name, s["words"]) \
                    and not w.startswith("-") and d != UNKNOWN:
                p = os.path.join(d, os.path.expanduser(w))
                if os.path.isdir(p):   # `grep -r KEY .` prints .env's lines too
                    out.extend(grep_targets(p))
        for w in s["redir_in"]:
            # `< .env` feeds the file to whatever runs; `wc -l < .env` prints a count.
            if not safe or name not in _SAFE_CMDS:
                _word_hits(w, d, out, dynamic=True)
    return list(dict.fromkeys(out))


# Commands whose only output is stdout, in a form the decloak scrub redacts.
_VIEWERS = {"cat", "head", "tail", "less", "more", "bat", "nl", "wc", "sort", "uniq", "cut",
            "grep", "egrep", "fgrep", "rg", "ls", "stat", "test", "[", "[[", "echo", "printf",
            "true", "false", ":", "cd", "pushd", "popd", "file",
            # touch the file, never its bytes
            "touch", "rm", "chmod", "chown", "mkdir", "realpath", "readlink", "basename", "dirname",
            "du", "which", "type", "exit"}


_SED_UNSAFE = re.compile(r"^-i|^--in-place|\by/|[;}\s]w\s|/[a-zA-Z0-9]*w(?:\s|$)|(?:^|;)\s*e\b")


# Print names, sizes or modes, never the bytes: what they pipe on is safe.
_METADATA = {"echo", "printf", "ls", "stat", "test", "[", "[[", "file", "touch", "rm", "chmod", "chown", "mkdir",
             "realpath", "readlink", "basename", "dirname", "du", "which", "type"}


def _viewer(words: List[str]) -> bool:
    k, name = _cmd_name(words)
    if not words or name in _VIEWERS:
        return True
    rest = [w for w in words[k + 1:] if not w.startswith("-")]
    if name == "prismor" and rest[:1] == ["cloak"]:   # the remedy: vault it, run with it
        return True
    # `prismor check "<cmd>"` screens the text of a command; --from-log reads a file.
    if name == "prismor" and rest[:1] == ["check"] and not any(w.startswith("--from-log") for w in words):
        return True
    if name == "vercel" and rest[:2] == ["env", "pull"]:   # writes the file, reads nothing
        return True
    if name in ("cp", "mv", "ln") and len(rest) >= 2:
        # Another dotenv (or a directory, keeping the name) stays on disk under the
        # same vault values; the publish gate covers shipping it later.
        dst = rest[-1]
        return is_env_basename(dst) or dst in (".", "..") or dst.endswith("/")
    if name == "git":   # subcommands that only print (or delete), never send
        sub = [w for w in words[k + 1:] if not w.startswith("-")][:1]
        return sub in (["check-ignore"], ["ls-files"], ["status"], ["diff"], ["log"], ["show"], ["rm"], ["blame"],
                       ["commit"], ["clean"])   # the publish gate judges `git add` and `git push`
    # sed prints to stdout unless it edits in place, writes a file (w), runs a
    # command (e) or transliterates (y///, which the scrub can't see through).
    return name == "sed" and not any(_SED_UNSAFE.search(a) for a in words[k + 1:])


def _redirect_ok(dst: str) -> bool:
    # `>> .env` appends to it; `2>/dev/null`, `2>&1` send nothing out.
    return is_env_basename(dst) or dst.isdigit() or dst in ("/dev/null", "/dev/stdout", "/dev/stderr", "-")


# A path literal a script opens or binds: `open('.env')`, `Path(".env")`,
# `load_dotenv(".env")`, `config({ path: '.env' })`, `p = '.env'`. Code that
# only carries the name as text (`s.replace("cat .env", ...)`) is not a read.
# ponytail: names built at runtime (`'.e' + 'nv'`) get past this; that needs the sandbox layer.
_OPENED = re.compile(r"""(?:\(\s*|[\w\]]\s*=\s*|\bpath\s*[:=]\s*)['"]([^'"\s]+)['"]""")


def vaulted_flow(command: str, cwd: str, vaulted: List[str]) -> bool:
    """True when ``command`` sends one of the ``vaulted`` env files anywhere but
    the tool output.

    The decloak scrub only redacts what the agent's tool output carries. Once a
    vaulted env file is piped into a non-viewer, redirected, uploaded,
    committed, sourced, captured by $(...) or re-encoded, its real values
    leave by a channel the scrub never sees. Only the pipeline that names the
    file is judged: `cat a.ts; ls .env*; find src` is three separate commands."""
    targets = {os.path.realpath(p) for p in vaulted}
    # A heredoc body is text, not shell: lex the command without the bodies,
    # then judge each body by what reads it (`cat > notes.md` writes text,
    # `python3 -` runs code that can send the file anywhere).
    from prismor.runtime.shell_context import heredocs
    docs = heredocs(command)
    shell, bodies, pos = [], [], 0
    for h in docs:
        shell.append(command[pos:h.body_start])
        bodies.append(command[h.body_start:h.body_end])
        pos = h.body_end
    shell.append(command[pos:])
    tokens = _tokens("".join(shell))
    if tokens is None:
        return True

    def names(toks: List[str], dynamic: bool = True) -> bool:
        out: List[str] = []
        for w in toks:
            _word_hits(w, cwd, out, dynamic=dynamic)
        return any(os.path.realpath(p) in targets for p in out if not p.startswith(UNKNOWN))

    # A captured value ($(...) or backticks) goes wherever the command sends it.
    if any(("$(" in t or "`" in t) and names([t]) for t in tokens):
        return True
    for n, t in enumerate(tokens):   # the lexer splits `$(` into `...$`, `(`
        if t.endswith("$") and n + 1 < len(tokens) and tokens[n + 1] == "(":
            depth, m = 0, n + 1
            while m < len(tokens):
                depth += {"(": 1, ")": -1}.get(tokens[m], 0)
                if depth == 0:
                    break
                m += 1
            if names(tokens[n + 2:m]):
                return True
    pipes: List[List[str]] = [[]]
    for t in tokens:
        if t in _CMD_SEP and t not in ("|", "|&"):
            pipes.append([])
        else:
            pipes[-1].append(t)
    fed = iter(bodies)   # heredoc bodies, in `<<` order
    for pi, pipe in enumerate(pipes):
        segs = _segments(pipe)
        for i, t in enumerate(pipe):
            if t in ("<<", "<<-"):
                body = next(fed, "")
                cmd = _segments(pipe[:i])[-1]["words"]
                if not _viewer(cmd) and names(_OPENED.findall(body)):
                    return True
        # `for f in .env ...; do <body>; done`: the list only binds a name; the
        # loop is a viewer when every command in its body is one.
        if _cmd_name(pipe)[1] == "for" and "in" in pipe:
            body_ok = True
            for q in pipes[pi + 1:]:
                if q[:1] == ["done"]:
                    break
                body_ok = body_ok and all(_viewer(seg["words"]) for seg in _segments(q))
            if body_ok:
                continue
        if not names(pipe):
            continue
        # Bytes flow left to right: segments before the first one that prints
        # the file's content never see it; a metadata command (or echo of the
        # name) prints none, so where its output goes does not matter.
        static = [(i, _cmd_name(seg["words"])[1]) for i, seg in enumerate(segs)
                  if names(seg["words"] + seg["redir_in"], dynamic=False)]
        readers = [i for i, name in static if name not in _METADATA]
        if static and not readers:   # safe unless a runner reads the names
            if any(_cmd_name(seg["words"])[1] in _RUNNERS for seg in segs[static[0][0]:]):
                return True
            continue
        for n, t in enumerate(pipe):
            if t in _WRITE_REDIRS and not _redirect_ok(pipe[n + 1] if n + 1 < len(pipe) else ""):
                return True
        later = segs[readers[0]:] if readers else [seg for seg in segs if names(seg["words"])]
        if not all(_viewer(seg["words"]) for seg in later):
            return True
    return False


def bash_main() -> None:
    """env-guard.sh's Bash path in one process: stdin = command, argv[1] = cwd.
    Prints ``{"files": {path: [names]}, "total": N, "unknown": word,
    "vaulted_flow": path}``; ``vaulted_flow`` names a fully vaulted env file
    the command sends somewhere other than the scrubbed tool output."""
    cwd = native_path(sys.argv[1]) if len(sys.argv) > 1 else os.getcwd()
    command = local_text(winslash(sys.stdin.read()))
    reads = env_reads(command, cwd)
    unknown = next((p[1:] for p in reads if p.startswith(UNKNOWN)), "")
    vault = vault_values()
    files: Dict[str, List[str]] = {}
    vaulted: List[str] = []
    for p in reads:
        if not p.startswith(UNKNOWN):
            names = unprotected_entries(Path(p), vault)
            if names:
                files[p] = names
    # Every env file the command names, even by a "metadata" command like
    # `git add`: once vaulted, only viewers may touch it.
    named: List[str] = list(reads)
    for w in _tokens(command) or command.split():
        _word_hits(w, cwd, named, dynamic=False)
    for p in dict.fromkeys(named):
        if not p.startswith(UNKNOWN) and p not in files and not unprotected_entries(Path(p), vault):
            try:
                holds = any(len(v) >= MIN_VALUE_LEN and v in decode_text(Path(p).read_bytes()) for v in vault)
            except (OSError, UnicodeDecodeError):
                holds = False
            if holds:   # an env file with no secrets in it is no one's concern
                vaulted.append(p)
    flow = vaulted[0] if vaulted and vaulted_flow(command, cwd, vaulted) else ""
    from prismor.runtime.cloaking.publish_gate import check as publish_check
    publish = "" if files or flow else (publish_check(command, cwd, vault) or "")
    print(json.dumps({"files": files, "total": sum(map(len, files.values())), "unknown": unknown,
                      "vaulted_flow": flow, "publish": publish}))


def grep_targets(path: str, glob: str = "", ftype: str = "", limit: int = 20000) -> List[str]:
    """Env files a content-mode Grep over ``path`` could print lines of."""
    import fnmatch
    pats = []
    if glob:
        g = glob.rsplit("/", 1)[-1]
        m = re.search(r"\{([^}]*)\}", g)
        pats = [g[:m.start()] + alt + g[m.end():] for alt in m.group(1).split(",")] if m else [g]
    if ftype:
        pats.append(f"*.{ftype}")
    keep = lambda n: not pats or any(fnmatch.fnmatchcase(n, p) for p in pats)  # noqa: E731
    if os.path.isfile(path):
        return [path] if is_env_basename(path) and keep(os.path.basename(path)) else []
    out, seen = [], 0
    for root, dirs, fnames in os.walk(path):
        dirs[:] = [x for x in dirs if x not in (".git", "node_modules")]
        for n in fnames:
            seen += 1
            if is_env_basename(n) and keep(n):
                out.append(os.path.join(root, n))
        if seen > limit:   # ponytail: bounded walk; huge trees past it go unchecked
            break
    return out


def _resolve(path: str, cwd: str) -> str:
    path = os.path.expanduser(native_path(path)) if path else ""
    cwd = native_path(cwd) or os.getcwd()
    return path if path and os.path.isabs(path) else os.path.join(cwd, path) if path else cwd


def grep_main() -> None:
    """argv: path glob type cwd -> same report shape as ``main``. An empty or
    relative path means the session cwd, as the Grep tool treats it."""
    a = sys.argv[1:] + ["", "", "", ""]
    main(grep_targets(_resolve(a[0], a[3]), a[1], a[2]))


def read_main() -> None:
    """argv: file_path cwd. The Read tool's file, under every spelling Windows
    resolves to it (`.env.`, `.env::$DATA`, 8.3 names, `C:\\x`, `/c/x`), or a
    symlink to an env file."""
    a = sys.argv[1:] + ["", ""]
    p = _resolve(a[0], a[1])
    real = os.path.realpath(p) if os.path.lexists(p) else p
    if os.path.isfile(real) and (is_env_basename(p) or is_env_basename(real)):
        main([real])
    else:
        print(json.dumps({"files": {}, "total": 0}))


if __name__ == "__main__":
    main()
