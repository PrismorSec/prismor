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

from prismor.runtime.cloaking.secrets_store import _parse_env_line, secrets_dir

# Values shorter than this are ignored, mirroring read-guard.sh's minimum —
# tiny values ("1", "true", "dev") are config, not secrets, and matching them
# against the vault would be noise either way.
MIN_VALUE_LEN = 4


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
            values.add(child.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError):
            continue
    return values


def unprotected_entries(path: Path, vault: Set[str] | None = None) -> List[str]:
    """KEY names in ``path`` whose values are not registered in the vault."""
    if vault is None:
        vault = vault_values()
    try:
        text = path.read_text(encoding="utf-8")
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
    return "".join(out)


def local_text_main() -> None:
    sys.stdout.write(local_text(sys.stdin.read()))


_CMD_SEP = {"&&", "||", ";", "|", "&", "\n", "(", ")", "|&", ";;"}
UNKNOWN = "?"


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
    """``(word, dir)`` for every word of ``command``: the directory the shell is
    in when that word runs, following ``cd``/``pushd``/``popd`` (subshells and
    pipeline stages don't leak). ``dir`` is UNKNOWN after a ``cd`` whose target
    is a variable or command substitution.

    Unparseable input (unbalanced quotes) falls back to the session cwd for
    every word, which is the old behaviour.
    """
    import shlex
    try:
        lex = shlex.shlex(command, posix=True, punctuation_chars=";&|()")
        lex.whitespace_split = True
        tokens = []
        for t in lex:
            # shlex glues adjacent punctuation (`);`, `)&&`); split it back
            # into operators so a subshell's `)` is seen.
            if t and set(t) <= set(";&|()"):
                tokens += re.findall(r"&&|\|\||\|&|;;|[;&|()]", t)
            else:
                tokens.append(t)
    except ValueError:
        return [(w, cwd) for w in command.split()]

    out: List[tuple] = []
    cur, prev, stack, dstack = cwd, cwd, [], []
    at_start = True
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if tok in _CMD_SEP:
            if tok == "(":
                stack.append((cur, prev))
            elif tok == ")" and stack:
                cur, prev = stack.pop()
            at_start = True
            i += 1
            continue
        out.append((tok, cur))
        if at_start and tok in ("cd", "pushd", "popd"):
            args, j = [], i + 1
            while j < len(tokens) and tokens[j] not in _CMD_SEP:
                out.append((tokens[j], cur))
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


def candidate_paths(command: str, cwd: str) -> List[str]:
    """Every path ``command`` could name, resolved against the directory the
    shell is in at that point. A relative path after an unresolvable ``cd`` is
    returned as ``?<word>`` so the hook can fail closed instead of guessing."""
    seen: List[str] = []
    for word, d in word_dirs(command, cwd):
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


if __name__ == "__main__":
    main()
