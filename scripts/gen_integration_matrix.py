#!/usr/bin/env python3
"""Regenerate the coverage tables in AGENT_INTEGRATIONS.md and README.md from the registry.

The registry (``prismor/runtime/integrations/registry.yaml``) is the source of truth;
the prose in AGENT_INTEGRATIONS.md is hand-written, but the coverage tables are
generated between marker comments so they never drift from the registry.

Usage:
    python3 scripts/gen_integration_matrix.py            # rewrite tables in place
    python3 scripts/gen_integration_matrix.py --check    # CI: fail if out of date

Mirrors the marker-based in-place edit approach used by
``prismor/runtime/cloaking/installer.py`` for settings.json.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO_ROOT))

from prismor.runtime.integrations.registry import Integration, load_registry  # noqa: E402

_DOC_PATH = _REPO_ROOT / "AGENT_INTEGRATIONS.md"
_BEGIN = "<!-- BEGIN GENERATED: coverage-matrix (scripts/gen_integration_matrix.py) -->"
_END = "<!-- END GENERATED: coverage-matrix -->"

_README_PATH = _REPO_ROOT / "README.md"
_README_BEGIN = "<!-- BEGIN GENERATED: agent-coverage (scripts/gen_integration_matrix.py) -->"
_README_END = "<!-- END GENERATED: agent-coverage -->"

_SURFACE_LABEL = {"hook-config": "native hooks", "sdk": "plugin", "mcp": "MCP proxy", "rules-only": "config scan"}

_STATUS_BADGE = {"shipped": "✅", "roadmap": "🟡", "sweep-only": "—"}


def _row(i: Integration) -> str:
    badge = _STATUS_BADGE.get(i.status, i.status)
    surface = i.surface
    blocking = "—" if i.blocking == "none" else f"`{i.blocking}`"
    event_types = ", ".join(f"`{t}`" for t in i.event_types) or "—"
    return f"| {i.name} | {i.kind} | {surface} | {badge} | {blocking} | {event_types} |"


def render_matrix() -> str:
    items = load_registry()
    coding = [i for i in items if i.kind == "coding-agent"]
    frameworks = [i for i in items if i.kind == "framework"]
    multiplexers = [i for i in items if i.kind == "multiplexer"]

    lines = [
        _BEGIN,
        "",
        "_Generated from `prismor/runtime/integrations/registry.yaml` — do not edit by hand._",
        "",
        "**Coding agents**",
        "",
        "| Agent | Kind | Surface | Status | Blocking | Event types |",
        "|---|---|---|---|---|---|",
        *[_row(i) for i in coding],
        "",
        "**Production frameworks**",
        "",
        "| Framework | Kind | Surface | Status | Blocking | Event types |",
        "|---|---|---|---|---|---|",
        *[_row(i) for i in frameworks],
    ]

    if multiplexers:
        lines += [
            "",
            "**Multiplexers**",
            "",
            "| Tool | Kind | Surface | Status | Blocking | Event types |",
            "|---|---|---|---|---|---|",
            *[_row(i) for i in multiplexers],
        ]

    lines += [
        "",
        "Legend: ✅ shipped · 🟡 roadmap · — sweep-only / not applicable. "
        "Surfaces: `hook-config` (config-file hooks) · `sdk` (in-process adapter) · "
        "`mcp` (proxy) · `http` (eval-server sidecar) · `rules-only` (static guardrails) · "
        "`pass-through` (spawns other agents; no interception surface of its own). "
        "Event types: what the adapter produces from what the agent actually sends; "
        "a rule on any other type never fires for that agent (— = not declared).",
        "",
        _END,
    ]
    return "\n".join(lines)


def render_readme() -> str:
    """The short table on the README: what each shipped coding agent gets."""
    coding = [i for i in load_registry() if i.kind == "coding-agent"]
    shipped = sorted((i for i in coding if i.status == "shipped"), key=lambda i: i.name.lower())
    others = sorted((i for i in coding if i.status != "shipped"), key=lambda i: i.name.lower())

    def row(i: Integration) -> str:
        blocks = "—" if i.blocking == "none" else "✅"
        mirror = "✅" if (i.mirror or {}).get("status") == "verified" else ""
        return (f"| {i.name} | {_SURFACE_LABEL.get(i.surface, i.surface)} | {blocks} "
                f"| {mirror} |")

    return "\n".join([
        _README_BEGIN,
        "",
        "| Agent | Interception | Blocks before the call | MCP mirror verified |",
        "|---|---|---|---|",
        *[row(i) for i in shipped],
        "",
        "Config scan only (no hook protocol to intercept): "
        + ", ".join(i.name for i in others if i.status == "sweep-only") + ". "
        "Next up: " + ", ".join(i.name for i in others if i.status == "roadmap") + ". "
        "Full matrix, frameworks and SDKs: [AGENT_INTEGRATIONS.md](AGENT_INTEGRATIONS.md) and "
        "[governance surfaces](docs/governance-surfaces.md).",
        "",
        _README_END,
    ])


def _splice(doc: str, block: str, begin: str = _BEGIN, end: str = _END, name: str = "") -> str:
    if begin in doc and end in doc:
        pre = doc.split(begin, 1)[0]
        post = doc.split(end, 1)[1]
        return f"{pre}{block}{post}"
    raise SystemExit(
        f"markers not found in {name or _DOC_PATH.name}; add:\n  {begin}\n  {end}\n"
        "where the coverage table should go."
    )


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--check", action="store_true", help="fail if the doc is out of date")
    args = ap.parse_args()

    targets = [
        (_DOC_PATH, lambda doc: _splice(doc, render_matrix())),
        (_README_PATH, lambda doc: _splice(doc, render_readme(), _README_BEGIN, _README_END, _README_PATH.name)),
    ]
    stale = []
    for path, update in targets:
        current = path.read_text(encoding="utf-8")
        updated = update(current)
        if current == updated:
            continue
        if args.check:
            stale.append(path.name)
        else:
            path.write_text(updated, encoding="utf-8")
            print(f"updated coverage table in {path.name}")

    if stale:
        sys.stderr.write(
            f"{', '.join(stale)} coverage table is out of date.\n"
            "Run: python3 scripts/gen_integration_matrix.py\n"
        )
        return 1
    print("coverage tables up to date.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
