#!/usr/bin/env python3
"""Regenerate the coverage matrix in AGENT_INTEGRATIONS.md from the registry.

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


def _splice(doc: str, block: str) -> str:
    if _BEGIN in doc and _END in doc:
        pre = doc.split(_BEGIN, 1)[0]
        post = doc.split(_END, 1)[1]
        return f"{pre}{block}{post}"
    raise SystemExit(
        f"markers not found in {_DOC_PATH.name}; add:\n  {_BEGIN}\n  {_END}\n"
        "where the coverage matrix should go."
    )


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--check", action="store_true", help="fail if the doc is out of date")
    args = ap.parse_args()

    current = _DOC_PATH.read_text(encoding="utf-8")
    updated = _splice(current, render_matrix())

    if args.check:
        if current != updated:
            sys.stderr.write(
                "AGENT_INTEGRATIONS.md coverage matrix is out of date.\n"
                "Run: python3 scripts/gen_integration_matrix.py\n"
            )
            return 1
        print("coverage matrix up to date.")
        return 0

    if current != updated:
        _DOC_PATH.write_text(updated, encoding="utf-8")
        print(f"updated coverage matrix in {_DOC_PATH.name}")
    else:
        print("coverage matrix already up to date.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
