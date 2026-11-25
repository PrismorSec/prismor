"""Supply-chain enforcement layer for the unified ``prismor`` CLI.

Reachable as:

  prismor supplychain npm install express
  prismor supplychain pip install requests numpy
  prismor supplychain pnpm add lodash
  prismor supplychain uv add fastapi
  prismor supplychain cargo add serde
  prismor supplychain go get github.com/some/pkg
  prismor supplychain gem install rails        (also: bundle add)
  prismor supplychain composer require vendor/pkg
  prismor supplychain mvn dependency:get -Dartifact=g:a:v
  prismor supplychain harden [--dry-run] [PATH]

Any sub-argv that isn't a recognised package install is passed through
transparently — so the same wrapper can be used as a shell alias for
``npm`` / ``pip`` / etc. via ``alias npm='prismor supplychain npm'``.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import List, Optional

_REPO_ROOT = Path(__file__).resolve().parent.parent

# ── ANSI colours (same palette as prismor/runtime/cli.py) ─────────────────────────────
_RED    = "\033[0;31m"
_YELLOW = "\033[1;33m"
_GREEN  = "\033[0;32m"
_DIM    = "\033[37m"
_BOLD   = "\033[1m"
_RESET  = "\033[0m"


def _c(text: str, colour: str) -> str:
    if sys.stdout.isatty():
        return f"{colour}{text}{_RESET}"
    return text


def _ce(text: str, colour: str) -> str:
    if sys.stderr.isatty():
        return f"{colour}{text}{_RESET}"
    return text


# ── Feed helpers (reuse existing prismor modules, don't re-implement) ──────────

def _load_feed() -> dict:
    try:
        from prismor.runtime.feed import load_feed
        # load_feed resolves the bundled feed itself; _REPO_ROOT is only a
        # hint that works in a git checkout (it points at site-packages once
        # installed, where the resolver takes over).
        return load_feed(_REPO_ROOT)
    except Exception:
        return {"advisories": []}


def _check_feed(packages, feed: dict) -> list:
    try:
        from prismor.runtime.deps import check_against_feed
        deps = [{"name": p.name, "version": "", "ecosystem": ""} for p in packages]
        return check_against_feed(deps, feed)
    except Exception:
        return []


# ── Recommendations ───────────────────────────────────────────────────────────

def _format_pinned(name: str, version: str, ecosystem: str) -> str:
    """Render an install-ready pinned spec for the user's ecosystem."""
    if ecosystem in ("pip", "uv"):
        return f"{name}=={version}"
    if ecosystem in ("npm", "pnpm", "yarn", "bun", "cargo"):
        return f"{name}@{version}"
    if ecosystem in ("gem", "composer", "maven"):
        return f"{name}:{version}"
    return f"{name} {version}"


def _recommendations_for_blocks(verdicts, ecosystem):
    """Look up safe alternative versions for every BLOCKed registry package.

    Returns {spec.raw: SafeVersion}.
    """
    try:
        from supplychain.scoring.safe_version import recommend_safe_version
    except Exception:
        return {}

    out = {}
    for v in verdicts:
        if v.verdict != "block":
            continue
        if v.meta.source != "registry":
            continue
        # Skip recommending for known-malicious matches — the right answer
        # is "don't install this package at all", not "install a different
        # version of the same backdoor".
        if any(s.id.startswith("ioc_") for s in v.signals):
            continue
        try:
            rec = recommend_safe_version(
                v.spec.name, ecosystem,
                exclude_version=v.spec.version or v.meta.version or "",
            )
        except Exception:
            rec = None
        if rec is not None:
            out[v.spec.raw] = rec
    return out


# ── Output ────────────────────────────────────────────────────────────────────

def _print_report(event, verdicts, feed_hits: list, recommendations=None) -> None:
    from supplychain.scoring.engine import PackageVerdict

    recommendations = recommendations or {}

    print()
    print(f"  {_c('PRISMOR', _BOLD)}  supply chain  {_c(f'[{event.ecosystem}]', _DIM)}")
    print(f"  {_c('─' * 52, _DIM)}")
    print()

    for v in verdicts:
        if v.verdict == "block":
            badge = _c("BLOCK", _RED)
            score_str = _c(f"score {v.score:>3}", _RED)
        elif v.verdict == "warn":
            badge = _c("WARN ", _YELLOW)
            score_str = _c(f"score {v.score:>3}", _YELLOW)
        else:
            badge = _c("ALLOW", _GREEN)
            score_str = _c(f"score {v.score:>3}", _DIM)

        meta_parts: List[str] = []
        if v.meta.age_days is not None:
            meta_parts.append(f"age {v.meta.age_days}d")
        if v.meta.maintainer_count is not None:
            n = v.meta.maintainer_count
            meta_parts.append(f"{n} maintainer{'s' if n != 1 else ''}")
        if v.meta.fetch_error:
            meta_parts.append(_c(f"[{v.meta.fetch_error}]", _DIM))

        meta_str = "  " + ", ".join(meta_parts) if meta_parts else ""
        print(f"  {badge}  {score_str}  {v.spec.raw}{meta_str}")

        for sig in v.signals:
            print(f"             {_c(f'+{sig.points}', _DIM)} {sig.description}")

        rec = recommendations.get(v.spec.raw)
        if rec is not None:
            pinned = _format_pinned(v.spec.name, rec.version, event.ecosystem)
            print(
                f"             {_c('→', _GREEN)} safe alternative: "
                f"{_c(pinned, _GREEN)}  {_c(rec.reason, _DIM)}"
            )

        if v.signals or rec is not None:
            print()

    if not any(v.signals for v in verdicts):
        print()  # trailing blank line when all are clean

    if feed_hits:
        print(f"  {_c('Advisory matches:', _YELLOW)}")
        for hit in feed_hits:
            sev = hit.get("severity", "").upper()
            print(f"    {_ce(sev, _RED)}  {hit.get('title', '')}")
        print()


# ── Process replacement ───────────────────────────────────────────────────────

def _exec(argv: List[str]) -> None:
    """Replace the current process with the real command — transparent passthrough.

    For pip/pip3 installs on systems with PEP 668 externally-managed Python,
    falls back to pipx so the install still works instead of spewing an error.
    """
    import shutil
    import subprocess

    binary = shutil.which(argv[0])
    if binary is None:
        # Pre-flight scoring already ran and printed verdicts. Surface the
        # missing tool clearly so users know the score is good but the
        # install couldn't proceed (instead of a bare exit 127).
        sys.stderr.write(
            f"  {_ce('Install skipped:', _YELLOW)} `{argv[0]}` is not installed on this system.\n"
            f"  Scoring above is informational — install {argv[0]} to actually run this command.\n"
        )
        sys.exit(127)

    # Detect pip install on externally-managed Python (PEP 668) before exec-replacing.
    # Probing with --dry-run avoids actually installing anything.
    if argv[0] in ("pip", "pip3") and len(argv) > 1 and argv[1] == "install":
        probe = subprocess.run(
            [binary, "install", "--dry-run", *argv[2:]],
            capture_output=True, text=True,
        )
        if "externally-managed-environment" in probe.stderr:
            packages = " ".join(a for a in argv[2:] if not a.startswith("-"))
            sys.stderr.write(
                f"prismor: pip is externally managed on this system (PEP 668).\n"
                f"  Use a virtual environment:\n"
                f"    python3 -m venv .venv && .venv/bin/pip install {packages}\n"
                f"  Or install system-wide (not recommended):\n"
                f"    pip install --break-system-packages {packages}\n"
            )
            sys.exit(1)

    os.execv(binary, argv)


# ── Store integration ─────────────────────────────────────────────────────────

def _record_to_store(event, verdicts, recommendations=None) -> None:
    """Write scoring results to the prismor store. Fail-open."""
    try:
        import uuid
        from datetime import datetime, timezone
        from prismor.runtime.store import infer_default_workspace, write_supply_chain_event
        workspace = infer_default_workspace(Path.cwd())
        rec_map = {
            spec_raw: rec.version
            for spec_raw, rec in (recommendations or {}).items()
            if rec is not None
        }
        write_supply_chain_event(
            workspace=workspace,
            session_id=f"prismor-{uuid.uuid4().hex[:16]}",
            ts=datetime.now(timezone.utc).isoformat(),
            ecosystem=event.ecosystem,
            install_cmd=" ".join(sys.argv[1:]),
            verdicts=verdicts,
            recommendations=rec_map,
        )
    except Exception:
        pass


# ── Entry point ───────────────────────────────────────────────────────────────

def run_supply(argv: Optional[List[str]] = None) -> None:
    """Entry point for the ``prismor supplychain`` subcommand."""
    if argv is None:
        argv = sys.argv[1:]

    if not argv or argv[0] in ("-h", "--help"):
        _usage()
        return

    # Add repo root to path so prismor imports work when called as a script
    if str(_REPO_ROOT) not in sys.path:
        sys.path.insert(0, str(_REPO_ROOT))

    if argv[0] == "harden":
        _cmd_harden(argv[1:])
        return

    from supplychain.ecosystems.detector import detect_install, is_known_manager
    if not is_known_manager(argv):
        sys.stderr.write(
            f"prismor supplychain: unknown package manager `{argv[0]}` — "
            "expected npm, pnpm, yarn, bun, pip, uv, poetry, cargo, go, gem, bundle, composer or mvn "
            "(or `harden`).\n")
        sys.exit(2)
    event = detect_install(argv)

    # Not a recognised install command — hand off transparently
    if event is None:
        _exec(argv)
        return  # unreachable; satisfies type checkers

    # Bare manifest install (e.g. `npm install` with no packages) — pass through
    if not event.packages:
        _exec(argv)
        return

    # ── Evaluate ──────────────────────────────────────────────────────────────
    from supplychain.ecosystems.metadata import fetch_metadata
    from supplychain.scoring.engine import RiskScorer, load_allowlist

    try:
        from prismor.runtime.store import infer_default_workspace
        workspace = infer_default_workspace(Path.cwd())
    except Exception:
        workspace = Path.cwd()

    scorer = RiskScorer(allowlist=load_allowlist(workspace))
    verdicts = []
    for spec in event.packages:
        meta = fetch_metadata(spec, event.ecosystem)
        verdicts.append(scorer.score(spec, meta, event))

    # Cross-check against the existing Prismor advisory feed
    feed = _load_feed()
    feed_hits = _check_feed(event.packages, feed)

    # Look up safe alternative versions for blocked packages so an agent
    # has somewhere to go without bouncing the install.
    recommendations = _recommendations_for_blocks(verdicts, event.ecosystem)

    _print_report(event, verdicts, feed_hits, recommendations)
    sys.stdout.flush()
    _record_to_store(event, verdicts, recommendations)

    # ── Decision ──────────────────────────────────────────────────────────────
    blocked = [v for v in verdicts if v.verdict == "block"]
    warned  = [v for v in verdicts if v.verdict == "warn"]

    if blocked:
        names = ", ".join(v.spec.raw for v in blocked)
        suggested = [
            _format_pinned(v.spec.name, recommendations[v.spec.raw].version, event.ecosystem)
            for v in blocked if v.spec.raw in recommendations
        ]
        suggest_line = (
            f"  Try instead: {_c(', '.join(suggested), _GREEN)}\n"
            if suggested else ""
        )
        print(
            f"  {_c('Blocked:', _RED)} {names}\n"
            f"{suggest_line}"
            f"  To override: add to supply_chain.allowlist in "
            f".prismor/policy.yaml\n"
        )
        sys.exit(1)

    if warned:
        print(f"  {_c('Warning:', _YELLOW)} flagged packages above — proceeding.\n")

    _exec(argv)


def _cmd_harden(args: List[str]) -> None:
    """Scan the project for package manager configs and apply hardening."""
    from supplychain.hardener import harden_project, print_harden_report

    dry_run = "--dry-run" in args or "-n" in args
    path_args = [a for a in args if not a.startswith("-")]
    root = Path(path_args[0]).resolve() if path_args else Path.cwd()

    if not root.is_dir():
        sys.stderr.write(f"prismor supplychain harden: not a directory: {root}\n")
        sys.exit(2)

    results = harden_project(root, dry_run=dry_run)
    print_harden_report(results, root, dry_run=dry_run)


def _usage() -> None:
    print(f"  {_c('prismor supplychain', _BOLD)} — AI-native supply chain enforcement")
    print()
    print("  Usage: prismor supplychain <package-manager> <args...>")
    print("         prismor supplychain harden [--dry-run] [PATH]")
    print()
    print("  Install interception:")
    print("    prismor supplychain npm install express")
    print("    prismor supplychain pip install requests numpy")
    print("    prismor supplychain pnpm add lodash")
    print("    prismor supplychain uv add fastapi")
    print("    prismor supplychain cargo add serde")
    print("    prismor supplychain go get github.com/some/pkg")
    print("    prismor supplychain gem install rails")
    print("    prismor supplychain composer require monolog/monolog")
    print()
    print("  Config hardening:")
    print("    prismor supplychain harden              Apply hardening to project configs")
    print("    prismor supplychain harden --dry-run    Preview without writing")
    print("    prismor supplychain harden <path>       Harden a specific project root")
    print()
    print("  Non-install commands pass through transparently.")
    print()


# Back-compat shim — kept so `python -m supplychain.cli` keeps working for any
# external caller. New code should use `prismor.runtime.immunity_cli:main` instead.
def main() -> None:
    run_supply(sys.argv[1:])


if __name__ == "__main__":
    main()
