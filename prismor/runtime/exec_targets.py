"""Resolve what a command will actually run, and inspect that content.

A rule only ever sees the command string. ``bash deploy.sh`` therefore looks
harmless no matter what ``deploy.sh`` contains, which makes the whole ruleset one
level of indirection away from irrelevant:

    rm -rf /                    -> destructive-command
    bash deploy.sh              -> nothing, whatever the file holds
    npm run build               -> nothing, whatever package.json holds

This module resolves the execution target from a command (a script argument, a
sourced file, an npm script, a make recipe, a Dockerfile) and returns its
runnable lines so the caller can evaluate them with the normal rule set.

Two things keep this from becoming a false-positive machine. First, only lines
that would actually run are returned: comments are dropped, and for non-shell
languages only the strings that reach a shell (``os.system``, ``subprocess``
with ``shell=True``, JSON script values) are considered, because a Python file
scanned line-wise as shell flags its own string literals. Second, the caller is
expected to run the same contextual check used for inline commands, so a rule
table or docstring that merely mentions a dangerous command stays inert.

Findings from this module are advisory by default: the intended rollout is
observe-only, gathering telemetry until the real false-positive rate on a fleet
is known.
"""
from __future__ import annotations

import json
import re
import shlex
from pathlib import Path
from typing import Iterable, List, NamedTuple, Optional, Set

# Interpreters whose first non-flag argument is a script to run.
_SCRIPT_INTERPRETERS = frozenset({
    "bash", "sh", "zsh", "ksh", "dash", "csh", "tcsh", "fish",
    "python", "python2", "python3", "node", "deno", "bun", "ruby", "perl", "php",
})

# Wrappers that delegate to the command that follows them.
_PREFIXES = frozenset({
    "sudo", "doas", "env", "time", "timeout", "nohup", "command", "exec", "stdbuf",
    "nice", "ionice", "setsid",
})

_SOURCE_BUILTINS = frozenset({"source", "."})
_NODE_MANAGERS = frozenset({"npm", "pnpm", "yarn", "bun"})

# Largest file we will read. Bigger than any plausible hand-written script, and
# small enough that reading it is never a latency problem.
_MAX_BYTES = 256 * 1024

# How deep to follow a script that runs another script.
_MAX_DEPTH = 3

_SHELL_COMMENT = re.compile(r"^\s*#")
_MAKE_RECIPE = re.compile(r"^\t\s*[-@+]?(?P<body>.*)$")

# A `case` branch label -- `start|up|yes) do_thing ;;`. The label is a pattern
# list, not a command, but it is full of shell metacharacters, so scanning it
# raw produces matches like `yes|` (fork-bomb rule) on ordinary option parsing.
# Only the body after the label is a command, so the label is stripped.
_CASE_LABEL = re.compile(r"^\s*\(?\s*[A-Za-z0-9_*?.@%+:\[\]{}|\\/-]+\s*\)\s+(?P<body>.*)$")

# Python/Ruby/Node calls that hand a string to a shell. Only the quoted argument
# of one of these is treated as a command; every other string in the file is
# data and is deliberately ignored.
_SHELL_SINKS = re.compile(
    r"""(?:os\.system|os\.popen|subprocess\.(?:run|call|check_call|check_output|Popen)|
         commands\.getoutput|child_process\.(?:exec|execSync|spawn|spawnSync)|
         Kernel\.system|IO\.popen|shell_exec|passthru)\s*\(""",
    re.VERBOSE,
)
_QUOTED = re.compile(r"""(?P<q>['"])(?P<body>(?:\\.|(?!(?P=q)).)*)(?P=q)""")


class Target(NamedTuple):
    """A file a command will run, and how the command reaches it."""

    path: Path
    kind: str  # interpreter | source | direct | npm-script | make | docker


class Line(NamedTuple):
    """A runnable line recovered from a target, with where it came from."""

    text: str
    origin: str  # "<path>:<lineno>"


_WRAPPER_ARG = re.compile(r"^\d+(\.\d+)?[smhd]?$")


def _strip_prefixes(tokens: List[str]) -> List[str]:
    """Drop wrapper commands and leading VAR=value assignments.

    A wrapper may take its own arguments before the real command -- `timeout 30
    bash x.sh`, `nice -n 10 python y.py` -- so flags and duration/numeric
    arguments are consumed along with it.
    """
    while tokens:
        head = tokens[0]
        if "=" in head and not head.startswith("=") and "/" not in head.split("=", 1)[0]:
            tokens = tokens[1:]
            continue
        if head.rsplit("/", 1)[-1] in _PREFIXES:
            tokens = tokens[1:]
            while tokens and (tokens[0].startswith("-") or _WRAPPER_ARG.match(tokens[0])):
                tokens = tokens[1:]
            continue
        break
    return tokens


def _first_non_flag(tokens: Iterable[str]) -> Optional[str]:
    for tok in tokens:
        if not tok.startswith("-"):
            return tok
    return None


def resolve_targets(command: str, cwd: Path) -> List[Target]:
    """Return the files ``command`` would run. Never raises."""
    try:
        segments = re.split(r"&&|\|\||[;|\n]", command)
    except Exception:  # noqa: BLE001
        return []

    targets: List[Target] = []
    for segment in segments:
        segment = segment.strip()
        if not segment:
            continue
        try:
            tokens = shlex.split(segment)
        except ValueError:
            tokens = segment.split()
        tokens = _strip_prefixes(tokens)
        if not tokens:
            continue

        argv0 = tokens[0].rsplit("/", 1)[-1]
        rest = tokens[1:]

        if argv0 in _SCRIPT_INTERPRETERS:
            script = _first_non_flag(rest)
            if script:
                targets.append(Target(cwd / script, "interpreter"))
        elif argv0 in _SOURCE_BUILTINS:
            script = _first_non_flag(rest)
            if script:
                targets.append(Target(cwd / script, "source"))
        elif argv0 in _NODE_MANAGERS and rest and rest[0] in ("run", "run-script"):
            if len(rest) > 1:
                targets.append(Target(cwd / "package.json", f"npm-script:{rest[1]}"))
        elif argv0 == "make":
            makefile = "Makefile"
            for i, tok in enumerate(rest):
                if tok == "-f" and i + 1 < len(rest):
                    makefile = rest[i + 1]
            targets.append(Target(cwd / makefile, "make"))
        elif argv0 == "docker" and rest and rest[0] == "build":
            dockerfile = "Dockerfile"
            for i, tok in enumerate(rest):
                if tok in ("-f", "--file") and i + 1 < len(rest):
                    dockerfile = rest[i + 1]
            targets.append(Target(cwd / dockerfile, "docker"))
        elif tokens[0].startswith("./") or tokens[0].startswith("/"):
            targets.append(Target(cwd / tokens[0], "direct"))

    return targets


def _read(path: Path) -> Optional[str]:
    try:
        if not path.is_file():
            return None
        if path.stat().st_size > _MAX_BYTES:
            return None
        return path.read_text(errors="replace", encoding="utf-8")
    except (OSError, ValueError):
        return None


def _shell_lines(text: str, label: str) -> List[Line]:
    out: List[Line] = []
    for n, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or _SHELL_COMMENT.match(raw):
            continue
        m = _CASE_LABEL.match(line)
        if m:
            # Keep the branch body -- `*) rm -rf / ;;` must still be caught.
            line = m.group("body").strip()
            if not line:
                continue
        out.append(Line(line, f"{label}:{n}"))
    return out


def _embedded_shell_lines(text: str, label: str) -> List[Line]:
    """Strings a Python/Ruby/Node file hands to a shell.

    Only the quoted argument of a known shell sink is returned. Scanning every
    line of such a file as if it were shell is what makes a security tool's own
    rule table look like an attack.
    """
    out: List[Line] = []
    for n, raw in enumerate(text.splitlines(), 1):
        if not _SHELL_SINKS.search(raw):
            continue
        for m in _QUOTED.finditer(raw):
            body = m.group("body").strip()
            if body:
                out.append(Line(body, f"{label}:{n}"))
    return out


def _make_lines(text: str, label: str) -> List[Line]:
    out: List[Line] = []
    for n, raw in enumerate(text.splitlines(), 1):
        m = _MAKE_RECIPE.match(raw)
        if not m:
            continue
        body = m.group("body").strip()
        if body and not body.startswith("#"):
            out.append(Line(body, f"{label}:{n}"))
    return out


def _dockerfile_lines(text: str, label: str) -> List[Line]:
    out: List[Line] = []
    for n, raw in enumerate(text.splitlines(), 1):
        stripped = raw.strip()
        if stripped.upper().startswith("RUN "):
            out.append(Line(stripped[4:].strip(), f"{label}:{n}"))
    return out


def _npm_script_lines(text: str, label: str, wanted: str) -> List[Line]:
    try:
        scripts = json.loads(text).get("scripts") or {}
    except (ValueError, AttributeError):
        return []
    out: List[Line] = []
    for name, body in scripts.items():
        if wanted not in ("", "*") and name != wanted:
            continue
        if isinstance(body, str) and body.strip():
            out.append(Line(body.strip(), f"{label}:scripts.{name}"))
    return out


_PY_LIKE = {".py", ".rb", ".js", ".mjs", ".cjs", ".ts", ".php"}


def runnable_lines(target: Target) -> List[Line]:
    """Lines from ``target`` that would run. Never raises."""
    text = _read(target.path)
    if text is None:
        return []
    label = target.path.name

    if target.kind.startswith("npm-script"):
        _, _, wanted = target.kind.partition(":")
        return _npm_script_lines(text, label, wanted)
    if target.kind == "make":
        return _make_lines(text, label)
    if target.kind == "docker":
        return _dockerfile_lines(text, label)
    if target.path.suffix in _PY_LIKE:
        return _embedded_shell_lines(text, label)
    return _shell_lines(text, label)


def collect(
    command: str,
    cwd: Path,
    _depth: int = 0,
    _seen: Optional[Set[str]] = None,
) -> List[Line]:
    """Runnable lines reachable from ``command``, following nested scripts.

    Recursion is bounded by ``_MAX_DEPTH`` and guarded against cycles by real
    path, so a script that sources itself terminates.
    """
    if _depth >= _MAX_DEPTH:
        return []
    seen = _seen if _seen is not None else set()

    lines: List[Line] = []
    for target in resolve_targets(command, cwd):
        try:
            key = str(target.path.resolve())
        except OSError:
            continue
        if key in seen:
            continue
        seen.add(key)

        own = runnable_lines(target)
        lines.extend(own)
        for line in own:
            lines.extend(collect(line.text, target.path.parent, _depth + 1, seen))
    return lines
