"""`prismor discover` — find AI agents, MCP servers and provider keys on this
machine that Prismor is not governing.

Sections:
    (default)   all three inventories plus a coverage score
    agents      AI coding agents installed, and whether hooks are in place
    mcp         MCP servers declared anywhere, and whether they route through
                the gateway
    keys        AI-provider credentials, and whether Cloak has them
    webmcp      browsers where a page can register tools for an in-tab agent —
                reported, but never scored, since no surface governs it yet

The inventory and diff logic lives in ``discover``; this module is UX only.

Output never contains a secret value — the ``keys`` section reports provider
and location only, by construction (see ``discover.CredentialRecord``).
"""
from __future__ import annotations

import json
import sys
from dataclasses import asdict
from pathlib import Path
from typing import Any, Dict, List, Optional

from prismor.runtime import discover as _discover

# ── output helpers (match cli.py's ANSI style, no deps) ──────────────────────
_RESET = "\033[0m"
_BOLD = "\033[1m"
_DIM = "\033[2m"
_RED = "\033[31m"
_GREEN = "\033[32m"
_YELLOW = "\033[33m"
_CYAN = "\033[36m"


def _c(text: str, color: str) -> str:
    if not sys.stdout.isatty():
        return text
    return f"{color}{text}{_RESET}"


def _home_relative(path: str) -> str:
    home = str(Path.home())
    return path.replace(home, "~") if path.startswith(home) else path


_RISK_COLOR = {"high": _RED, "medium": _YELLOW, "low": _CYAN, "none": _DIM}


def _badge(managed: bool) -> str:
    return _c("governed", _GREEN) if managed else _c("SHADOW", _RED)


# ── sections ─────────────────────────────────────────────────────────────────


def _print_agents(agents: List[Dict[str, Any]]) -> None:
    print(f"  {_c('AGENTS', _BOLD)}")
    if not agents:
        print(f"    {_c('none found', _DIM)}")
        print()
        return
    for agent in agents:
        managed = agent["managed"]
        coverable = agent.get("coverable", True)
        # An agent Prismor has no hook for is not a shadow finding — nothing
        # was skipped. Badge it distinctly so it matches the shadow count.
        if managed:
            badge = _badge(True)
        elif coverable:
            badge = _badge(False)
        else:
            badge = _c("no coverage", _YELLOW)
        line = f"    {badge:<22} {agent['name']}"
        if managed and agent.get("mode"):
            line += _c(f"  ({agent['mode']})", _DIM)
        if not coverable:
            line += _c("  (Prismor has no hook for this agent)", _DIM)
        print(line)
        detail = _home_relative((agent.get("config_paths") or [""])[0])
        if detail:
            print(f"      {_c(detail, _DIM)}")
    print()


def _print_mcp(servers: List[Dict[str, Any]]) -> None:
    print(f"  {_c('MCP SERVERS', _BOLD)}")
    visible = [s for s in servers if not s.get("is_gateway")]
    if not visible:
        print(f"    {_c('none found', _DIM)}")
        print()
        return
    for server in visible:
        risk = server.get("risk", "none")
        line = f"    {_badge(server['managed']):<22} {server['name']}"
        line += _c(f"  [{server['agent']}]", _DIM)
        if risk != "none":
            line += "  " + _c(risk, _RISK_COLOR.get(risk, _DIM))
        print(line)
        target = server.get("url") or " ".join(server.get("command") or [])
        if target:
            print(f"      {_c(target[:88], _DIM)}")
        for finding in server.get("findings") or []:
            print(f"      {_c('· ' + finding, _DIM)}")
    print()


def _print_credentials(creds: List[Dict[str, Any]]) -> None:
    print(f"  {_c('PROVIDER KEYS', _BOLD)}")
    if not creds:
        print(f"    {_c('none found', _DIM)}")
        print()
        return
    for cred in creds:
        where = cred["location"]
        if cred["location_kind"] == "file":
            where = _home_relative(where)
        line = f"    {_badge(cred['managed']):<22} {cred['provider']}"
        line += _c(f"  {where}", _DIM)
        print(line)
    print()


def _elide_left(path: str, width: int = 88) -> str:
    """Trim a long path from the front, not the back.

    An extension bundle path is mostly a fixed Chromium prefix; the identifying
    part is the id and version at the end, which a plain truncation cuts off.
    """
    return path if len(path) <= width else "…" + path[-(width - 1):]


def _print_webmcp(surfaces: List[Dict[str, Any]]) -> None:
    print(f"  {_c('BROWSER (WebMCP)', _BOLD)}")
    if not surfaces:
        print(f"    {_c('none found', _DIM)}")
        print()
        return
    for surface in surfaces:
        # Never "SHADOW": nothing can govern this surface yet, so it is not a
        # gap in coverage. Matches how an agent Prismor has no hook for reads.
        line = f"    {_c('no coverage', _YELLOW):<22} {surface['name']}"
        line += _c(f"  [{surface['browser']}]", _DIM)
        if surface.get("profile"):
            line += _c(f"  {surface['profile']}", _DIM)
        print(line)
        print(f"      {_c(_elide_left(_home_relative(surface.get('location') or '')), _DIM)}")
        for finding in surface.get("findings") or []:
            print(f"      {_c('· ' + finding, _DIM)}")
    print(f"    {_c('Which tools a page exposes is decided at runtime and is not', _DIM)}")
    print(f"    {_c('visible from disk — inspect a page with a WebMCP inspector.', _DIM)}")
    print()


def _print_summary(report: Dict[str, Any]) -> None:
    summary = report["summary"]
    context = report["context"]
    coverage = summary["coverage"]

    print(f"  {_c('─' * 58, _DIM)}")
    if coverage is None:
        print(f"  {_c('No governable AI surface found on this machine.', _DIM)}")
        print()
        return

    color = _GREEN if coverage >= 80 else (_YELLOW if coverage >= 40 else _RED)
    print(f"  {_c('Coverage:', _BOLD)}  {_c(str(coverage) + '%', color)}"
          f"  {_c('of discovered AI surface is governed', _DIM)}")

    shadow_total = (summary["agents_shadow"] + summary["mcp_shadow"]
                    + summary["credentials_shadow"])
    if shadow_total:
        parts = []
        if summary["agents_shadow"]:
            parts.append(f"{summary['agents_shadow']} agent(s)")
        if summary["mcp_shadow"]:
            parts.append(f"{summary['mcp_shadow']} MCP server(s)")
        if summary["credentials_shadow"]:
            parts.append(f"{summary['credentials_shadow']} key(s)")
        print(f"  {_c('Shadow:', _BOLD)}    {_c(', '.join(parts), _RED)}")
    if summary["high_risk_mcp"]:
        print(f"  {_c('High risk:', _BOLD)} "
              f"{_c(str(summary['high_risk_mcp']) + ' ungoverned MCP server(s)', _RED)}")
    # Stated separately from Shadow, and not in the coverage figure above:
    # nothing can govern a browser tab yet, so this is a heads-up, not a gap.
    if summary.get("webmcp_total"):
        print(f"  {_c('Browser:', _BOLD)}   "
              f"{_c(str(summary['webmcp_total']) + ' WebMCP surface(s)', _YELLOW)}"
              f"  {_c('— not covered by any surface, not scored', _DIM)}")

    print()
    if not context["enrolled"]:
        print(f"  {_c('This device is not enrolled.', _YELLOW)} "
              f"Findings stay local and are not visible to your team.")
        print(f"  Next: {_c('prismor enroll', _CYAN)}"
              f"   {_c('— report coverage to the console', _DIM)}")
    elif shadow_total:
        print(f"  Next: {_c('prismor install', _CYAN)}"
              f"        {_c('— hook the unmanaged agents', _DIM)}")
        if summary["mcp_shadow"]:
            print(f"        {_c('prismor mcp-gateway install', _CYAN)}"
                  f" {_c('— route MCP servers through the gateway', _DIM)}")
        if summary["credentials_shadow"]:
            print(f"        {_c('prismor cloak add <name>', _CYAN)}"
                  f"   {_c('— cloak the exposed keys', _DIM)}")
    else:
        print(f"  {_c('All discovered AI surface is governed.', _GREEN)}")
    print()


# ── remediation ──────────────────────────────────────────────────────────────

_STATUS_STYLE = {
    "fixed": (_GREEN, "fixed"),
    "failed": (_RED, "FAILED"),
    "skipped": (_YELLOW, "skipped"),
    "planned": (_CYAN, "will fix"),
}


def _print_remediations(items, *, heading: str) -> None:
    if not items:
        return
    print(f"  {_c(heading, _BOLD)}")
    for item in items:
        color, label = _STATUS_STYLE.get(item.status, (_DIM, item.status))
        print(f"    {_c(label, color):<20} {item.target}")
        if item.detail:
            print(f"      {_c(item.detail, _DIM)}")
    print()


def _confirm(prompt: str) -> bool:
    """Ask before writing to the developer's agent configs.

    Not a TTY? Decline. A remediation that silently rewrote config files
    because it was piped through a script would be exactly the surprise this
    prompt exists to prevent — `--yes` is the way to opt in deliberately.
    """
    if not sys.stdin.isatty():
        print(f"  {_c('Not a terminal — re-run with --yes to apply.', _YELLOW)}")
        print()
        return False
    try:
        answer = input(f"  {prompt} [y/N] ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        return False
    return answer in ("y", "yes")


def run_fix(report: dict, *, workspace: Path, repo_root: Path, mode: str = "observe",
            kinds=None, assume_yes: bool = False) -> int:
    """Plan, confirm, apply. Returns the number of remaining shadow items."""
    from prismor.runtime import remediate as _remediate

    kinds = kinds or _remediate.FIXABLE_KINDS
    todo = _remediate.plan(report, kinds=kinds)

    if not todo.fixable and not todo.skipped:
        print(f"  {_c('Nothing to fix — every discovered surface is governed.', _GREEN)}")
        print()
        return 0

    _print_remediations(todo.fixable, heading="WILL FIX")
    _print_remediations(todo.skipped, heading="CANNOT FIX AUTOMATICALLY")

    if not todo.fixable:
        print(f"  {_c('Nothing here can be fixed automatically.', _YELLOW)}")
        print()
        return len(todo.skipped)

    if not assume_yes:
        print(f"  {_c('This writes to your agent config files.', _DIM)}")
        if not _confirm(f"Apply {len(todo.fixable)} fix(es)?"):
            print(f"  {_c('Nothing changed.', _DIM)}")
            print()
            return len(todo.fixable) + len(todo.skipped)
        print()

    results = _remediate.apply(report, repo_root=repo_root, workspace=workspace,
                               mode=mode, kinds=kinds, plan_obj=todo)
    counts = _remediate.summarize(results)

    _print_remediations([r for r in results if r.status == "fixed"], heading="FIXED")
    _print_remediations([r for r in results if r.status == "failed"], heading="FAILED")
    _print_remediations([r for r in results if r.status == "skipped"],
                        heading="LEFT FOR YOU")

    print(f"  {_c('─' * 58, _DIM)}")
    print(f"  {counts['fixed']} fixed · {counts['failed']} failed · "
          f"{counts['skipped']} left for you")
    if counts["fixed"]:
        print(f"  {_c('Re-run `prismor discover` to confirm the new coverage.', _DIM)}")
    print()
    return counts["failed"] + counts["skipped"]


# ── commands ─────────────────────────────────────────────────────────────────


def discover_all(workspace: Path, *, as_json: bool = False,
                 scan_files: bool = True, fail_on_shadow: bool = False,
                 report_to_console: bool = False, quiet: bool = False,
                 fix: bool = False, assume_yes: bool = False,
                 repo_root: Optional[Path] = None, mode: str = "observe") -> None:
    """Full report: agents, MCP servers, keys, and a coverage score."""
    report = _discover.build_report(workspace, scan_files=scan_files)
    sent: Optional[bool] = None
    if report_to_console:
        sent = _discover.send_report(report)
    if quiet:
        # The scheduled background refresh: it exists to upload, not to talk.
        return
    if as_json:
        print(json.dumps(report, indent=2))
    else:
        print()
        print(f"  {_c('PRISMOR', _BOLD)}  discover"
              f"   {_c(_home_relative(str(workspace)), _DIM)}")
        print(f"  {_c('─' * 58, _DIM)}")
        print()
        _print_agents(report["agents"])
        _print_mcp(report["mcp"])
        _print_credentials(report["credentials"])
        _print_webmcp(report.get("webmcp") or [])
        _print_summary(report)
        if sent is True:
            print(f"  {_c('Reported to your organization console.', _DIM)}")
            print()
        elif sent is False:
            # Say which of the two reasons it was — "not enrolled" is a
            # different action from "the console did not answer".
            enrolled = report["context"].get("enrolled")
            reason = ("this device is not enrolled" if not enrolled
                      else "the console could not be reached")
            print(f"  {_c('Not reported — ' + reason + '.', _YELLOW)}")
            print()

    if fix:
        run_fix(report, workspace=workspace,
                repo_root=repo_root or Path(__file__).resolve().parent.parent.parent,
                mode=mode, assume_yes=assume_yes)

    if fail_on_shadow:
        summary = report["summary"]
        shadow = (summary["agents_shadow"] + summary["mcp_shadow"]
                  + summary["credentials_shadow"])
        if shadow:
            sys.exit(1)


def discover_agents(workspace: Path, *, as_json: bool = False,
                    fix: bool = False, assume_yes: bool = False,
                    repo_root: Optional[Path] = None, mode: str = "observe") -> None:
    """AI coding agents installed here, and whether Prismor hooks them."""
    records = [asdict(a) for a in _discover.discover_agents(workspace)]
    if as_json:
        print(json.dumps({"agents": records}, indent=2))
        return
    print()
    _print_agents(records)
    if fix:
        run_fix({"agents": records}, workspace=workspace,
                repo_root=repo_root or Path(__file__).resolve().parent.parent.parent,
                mode=mode, kinds=("agent",), assume_yes=assume_yes)


def discover_mcp(workspace: Path, *, as_json: bool = False,
                 fix: bool = False, assume_yes: bool = False,
                 repo_root: Optional[Path] = None, mode: str = "observe") -> None:
    """MCP servers declared anywhere, and whether they route through the gateway."""
    records = [asdict(m) for m in _discover.discover_mcp(workspace)]
    if as_json:
        print(json.dumps({"mcp": records}, indent=2))
        return
    print()
    _print_mcp(records)
    if fix:
        run_fix({"mcp": records}, workspace=workspace,
                repo_root=repo_root or Path(__file__).resolve().parent.parent.parent,
                mode=mode, kinds=("mcp",), assume_yes=assume_yes)


def discover_webmcp(workspace: Path, *, as_json: bool = False) -> None:
    """Browser-resident WebMCP capability, and why none of it is governed.

    Takes no ``--fix``: there is nothing to install in front of a browser tab,
    so offering a remediation would be promising a fix that does not exist.
    """
    records = [asdict(w) for w in _discover.discover_webmcp(workspace)]
    if as_json:
        print(json.dumps({"webmcp": records}, indent=2))
        return
    print()
    _print_webmcp(records)


def discover_keys(workspace: Path, *, as_json: bool = False,
                  scan_files: bool = True, fix: bool = False,
                  assume_yes: bool = False, repo_root: Optional[Path] = None,
                  mode: str = "observe") -> None:
    """AI-provider credentials found here, and whether Cloak has them."""
    records = [asdict(c)
               for c in _discover.discover_credentials(workspace,
                                                       scan_files=scan_files)]
    if as_json:
        print(json.dumps({"credentials": records}, indent=2))
        return
    print()
    _print_credentials(records)
    if fix:
        run_fix({"credentials": records}, workspace=workspace,
                repo_root=repo_root or Path(__file__).resolve().parent.parent.parent,
                mode=mode, kinds=("credential",), assume_yes=assume_yes)
