#!/usr/bin/env python3
"""prismor — unified CLI for the Prismor security toolkit.

Every command in the toolkit is reachable as ``prismor <command> [args...]``.
Run ``prismor --help`` for the full map. The umbrella dispatches to the
existing engines:

  - prismor.runtime.cli:main         runtime / session security, hooks, policy, sweep,
                            cloak, iam, canary, scope, learn, setup, audit ...
  - supplychain.cli:run_supply  package-install interception + project hardening
"""
from __future__ import annotations

import os
import sys
from functools import lru_cache
from typing import List, Optional, Set

from prismor.runtime import __version__

# ANSI helpers (mirrors prismor/runtime/cli.py palette so output is visually consistent)
_BOLD = "\033[1m"
_DIM = "\033[37m"
_RESET = "\033[0m"


def _c(text: str, code: str) -> str:
    if sys.stdout.isatty():
        return f"{code}{text}{_RESET}"
    return text


# ── Routing ───────────────────────────────────────────────────────────────────
#
# Routing is fully introspection-driven: `main()` forwards ANY real prismor
# command (see `_prismor_commands()`), and `_print_usage()` builds the help from
# the live parser (see `_command_table()`), so neither can drift out of sync.
_SUPPLY_DOMAIN = "supplychain"


@lru_cache(maxsize=1)
def _prismor_commands() -> Set[str]:
    """Authoritative set of top-level commands ``prismor.runtime.cli`` accepts.

    Introspected from prismor.runtime.cli's argparse parser so the umbrella stays a true
    superset automatically — every prismor subcommand is reachable as
    ``prismor <command>`` with no hand-maintained list to drift out of sync.
    """
    import argparse
    try:
        from prismor.runtime.cli import build_parser
        parser = build_parser()
    except Exception:
        return set()
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            return set(action.choices.keys())
    return set()


def _deprecation_notice() -> None:
    """Nudge users off the old `immunity` command and the `immunity-agent`
    package name. Fires once per invocation, only when the binary was called as
    `immunity`. Suppressable with PRISMOR_NO_DEPRECATION=1 for scripts/CI."""
    if os.environ.get("PRISMOR_NO_DEPRECATION"):
        return
    if os.path.basename(sys.argv[0] or "") != "immunity":
        return
    sys.stderr.write(
        "\033[33mnote:\033[0m the 'immunity' command is now 'prismor'. "
        "'immunity' still works for now but will be removed.\n"
        "      Switch with: pip install -U prismor   (then use 'prismor ...')\n"
    )


def _update_notice() -> None:
    """Passive nag when a newer prismor is on PyPI. The actual PyPI check is
    debounced (see version_check.latest_known_version — at most once/day), so
    this adds no network latency to most invocations. Never called for
    `hook-dispatch`, which fires on every tool call and cannot afford stderr
    noise or a network hit on that path. Suppressable with
    PRISMOR_NO_UPDATE_CHECK=1 for scripts/CI."""
    if os.environ.get("PRISMOR_NO_UPDATE_CHECK"):
        return
    try:
        from prismor.runtime.version_check import latest_known_version
        latest = latest_known_version()
    except Exception:
        return
    if not latest or not _is_newer(latest, __version__):
        return
    sys.stderr.write(
        f"\033[33mnote:\033[0m prismor {latest} is available (you're on {__version__}). "
        "Run `prismor update` to upgrade.\n"
    )


def _version_tuple(text: str) -> tuple:
    """Numeric release segment of a version, for ordering. Trailing
    pre-release/local parts are ignored — enough to answer "is this newer",
    without taking a dependency on `packaging` for a courtesy notice."""
    parts = []
    for chunk in str(text).split(".")[:4]:
        digits = ""
        for ch in chunk:
            if not ch.isdigit():
                break
            digits += ch
        parts.append(int(digits) if digits else 0)
    return tuple(parts)


def _is_newer(candidate: str, current: str) -> bool:
    """True only when `candidate` is strictly newer.

    An equality check is not enough: the cached "latest" is whatever PyPI last
    reported, so anyone running ahead of the index — a dev build, or every user
    for the cache's lifetime right after a release — was told an OLDER version
    was available and asked to "upgrade" to it.
    """
    try:
        return _version_tuple(candidate) > _version_tuple(current)
    except Exception:
        return candidate != current


def _force_utf8_streams() -> None:
    """Make stdout/stderr UTF-8 regardless of the console's codepage.

    Windows consoles default to a legacy codepage (cp1252 on an en-US box), so
    the first check mark, arrow or spinner frame Prismor prints raises
    UnicodeEncodeError and takes the whole command down mid-write — `prismor
    setup` died on the "Registering workspace" tick. `errors="replace"` is the
    belt and braces: a console that genuinely cannot render a glyph shows a
    placeholder instead of aborting the run.

    This is the single entry point for both console scripts and for the
    hook-dispatch shim, so fixing it here covers every path that prints.
    """
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError, OSError):
            # Not a TextIOWrapper (pytest capture, a pipe wrapper, ...) —
            # nothing to reconfigure, and nothing worth failing over.
            pass


def main(argv: Optional[List[str]] = None) -> None:
    _force_utf8_streams()
    if argv is None:
        argv = sys.argv[1:]

    _deprecation_notice()
    if argv and argv[0] != "hook-dispatch":
        _update_notice()

    if not argv:
        _print_usage()
        return

    # `prismor --help secret` reads as a search too, not a request for the full map.
    if argv[0] in ("-h", "--help") and len(argv) > 1:
        _help(argv[1:])
        return
    if argv[0] in ("-h", "--help"):
        _print_usage()
        return

    if argv[0] == "help":
        _help(argv[1:])
        return

    if argv[0] in ("-V", "--version"):
        print(f"prismor {__version__}")
        return

    cmd, rest = argv[0], argv[1:]

    # `prismor supplychain ...` — supply-chain enforcement engine.
    if cmd == _SUPPLY_DOMAIN:
        from supplychain.cli import run_supply
        run_supply(rest)
        return

    # Any genuine prismor top-level command (domains, shortcuts, and any future
    # prismor subcommand) forwards straight through: `prismor <cmd> ...`.
    if cmd in _prismor_commands():
        from prismor.runtime.cli import main as prismor_main
        prismor_main([cmd, *rest])
        return

    _unknown_command(cmd)


# Ordered grouping for `prismor help`. Every group lists the commands it
# owns; any introspected command NOT named here lands in the "Other" catch-all,
# so a new prismor.runtime.cli subcommand can never silently vanish from help.
_HELP_GROUPS = [
    ("Get started",          ["setup", "status", "doctor", "discover", "dashboard", "login", "update", "docs"]),
    ("Day to day",           ["check", "allow", "pause", "pause-hard", "resume", "unlock", "lock", "mode"]),
    ("Policy & scoping",     ["policy", "tags", "scope", "iam", "egress", "agents", "learn"]),
    ("Secrets",              ["cloak", "sweep", "canary"]),
    ("Scanning & audit",     ["audit", "scan", "deps", "skills", "extensions", "memory", "semantic-check", "supplychain"]),
    ("Enforcement surfaces", ["surfaces", "install-hooks", "uninstall-hooks", "mirror", "mcp-gateway", "proxy",
                              "sandbox", "inference-hook", "eval-server"]),
    ("Sessions & evidence",  ["sessions", "session", "analyze", "ingest", "tokens", "trail", "attest", "query"]),
    ("Org enrollment",       ["enroll", "enroll-status", "workspace", "exempt", "logout"]),
]

# Internal plumbing and back-compat aliases: routable, never listed.
_HELP_HIDDEN = {"hook-dispatch", "exec-hook", "inference-hook-server", "info", "serve"}

# supplychain is dispatched by this umbrella, not a prismor.runtime.cli subcommand, so it
# is injected manually with its own help + sub-actions.
_SUPPLY_HELP = ("Supply-chain install gating + project hardening", "supplychain")
_SUPPLY_ACTIONS = ["npm", "pip", "pnpm", "yarn", "uv", "cargo", "go", "harden"]


def _command_table():
    """Introspect build_parser() → {name: (help, [(sub, sub_help)], mode_flags)}.

    Generated from the live parser so help can never drift from the real CLI.
    """
    import argparse
    table = {}
    try:
        from prismor.runtime.cli import build_parser
        parser = build_parser()
    except Exception:
        return table
    for action in parser._actions:
        if not isinstance(action, argparse._SubParsersAction):
            continue
        helps = {ca.dest: (ca.help or "") for ca in action._get_subactions()}
        for name, sub in action.choices.items():
            nested, flags = [], []
            for sa in sub._actions:
                if isinstance(sa, argparse._SubParsersAction):
                    sub_helps = {ca.dest: (ca.help or "") for ca in sa._get_subactions()}
                    nested = [(k, sub_helps.get(k, "")) for k in sa.choices]
                elif isinstance(sa, argparse._StoreTrueAction):
                    flags += [o for o in sa.option_strings if o.startswith("--")]
            table[name] = (helps.get(name, ""), nested, flags)
        break
    # supplychain isn't in prismor.runtime.cli — add it so help is complete.
    table["supplychain"] = (_SUPPLY_HELP[0], [(a, f"Gate {a} installs" if a != "harden" else "Harden this project")
                                               for a in _SUPPLY_ACTIONS], [])
    return table


def _help_sections(table=None):
    """[(group title, [(name, help, sub_actions)])] — the visible command map.

    Commands with suppressed/empty help or in _HELP_HIDDEN never show; anything
    real that no group claims lands in "Other".
    """
    import argparse
    table = _command_table() if table is None else table
    visible = {n: v for n, v in table.items()
               if n not in _HELP_HIDDEN and v[0] and v[0] != argparse.SUPPRESS}
    sections, placed = [], set()
    for title, names in _HELP_GROUPS + [("Other", sorted(visible))]:
        rows = [(n, visible[n][0], visible[n][1]) for n in names if n in visible and n not in placed]
        placed.update(n for n, _, _ in rows)
        if rows:
            sections.append((title, rows))
    return sections


def _search(sections, query: str):
    """[(group, command, help, subs)] matching every word of `query`.

    Sub-commands are searched too and returned as their exact runnable form
    ("cloak add"), so a search answers "what do I type", not just "which area".
    An empty query returns the top-level commands only.
    """
    words = query.lower().split()
    hits = []
    for group, rows in sections:
        for name, help_text, subs in rows:
            candidates = [(name, help_text, subs)]
            if words:
                candidates += [(f"{name} {s}", f"{h}" if h else help_text, [])
                               for s, h in subs if h != "==SUPPRESS=="]
            for cmd, h, sub in candidates:
                hay = f"{cmd} {h}".lower()
                if all(w in hay for w in words):
                    hits.append((group, cmd, h, sub))
    return hits


def _fit(text: str, width: int) -> str:
    return text if len(text) <= width else text[: max(width - 1, 1)] + "…"


def _print_usage(query: str = "") -> None:
    """Static command map, one line per command. `query` filters by name/description."""
    import shutil
    def b(t: str) -> str: return _c(t, _BOLD)
    def d(t: str) -> str: return _c(t, _DIM)

    width = shutil.get_terminal_size((100, 24)).columns
    q = query.strip()
    hits = _search(_help_sections(), q)
    col = max(18, max((len(c) for _, c, _, _ in hits), default=0) + 2) if q else 18

    print()
    if q:
        if not hits:
            print(f"  No commands match '{query}'. Run {b('prismor help')} to see them all.")
            print()
            return
        print(f"  Commands matching '{query}':")
    else:
        print(f"  {b('prismor')} — runtime security for AI coding agents")
        print()
        print(f"  Usage: {b('prismor')} <command> [options]")
        print(f"  New here? Run {b('prismor setup')}, then {b('prismor status')}.")

    group = None
    for title, cmd, help_text, _ in hits:
        if title != group:
            group = title
            print()
            print(f"  {b(title)}")
        # Search results carry the `prismor` prefix so they paste straight in.
        label = f"prismor {cmd}" if q else cmd
        pad = col + 8 if q else col
        print(f"    {label.ljust(pad)}{d(_fit(help_text, width - pad - 5))}")
    if q:
        print()
        print(d(f"  Details: prismor help <command>, e.g. prismor help {hits[0][1]}"))

    if not q:
        print()
        print(f"  {b('prismor help <command>')}   {d('flags and sub-commands for one command')}")
        print(f"  {b('prismor help <word>')}      {d('search commands, e.g. prismor help secret')}")
        if sys.stdin.isatty() and sys.stdout.isatty() and _can_browse():
            print(f"  {b('prismor help')}             {d('browse interactively (this list when piped)')}")
        print(f"  {b('prismor --version')}        {d('show version')}")
        print()
        print(d("  Renamed: info → status, serve → dashboard --no-open (old names still work)"))
    print()


def _can_browse() -> bool:
    try:
        import termios  # noqa: F401  (POSIX only; Windows gets the static map)
        return True
    except ImportError:
        return False


def _help(args: List[str]) -> None:
    """`prismor help [command [sub] | word]`."""
    table = _command_table()
    if args and args[0] in table:
        main([*args, "--help"])
        return
    if args:
        _print_usage(" ".join(args))
        return
    if sys.stdin.isatty() and sys.stdout.isatty() and _can_browse():
        from prismor.runtime.help_browser import browse
        sections = _help_sections(table)
        picked = browse(lambda q: _search(sections, q))
        if picked:
            main([*picked.split(), "--help"])
        return
    _print_usage()


def _unknown_command(cmd: str) -> None:
    import difflib
    names = [n for n in _command_table() if n not in _HELP_HIDDEN]
    close = difflib.get_close_matches(cmd, names, n=3, cutoff=0.6)
    sys.stderr.write(f"prismor: unknown command '{cmd}'.\n")
    if close:
        sys.stderr.write(f"  Did you mean: {', '.join(close)}?\n")
    sys.stderr.write("  Run 'prismor help' to see all commands.\n")
    sys.exit(2)


if __name__ == "__main__":
    main()
