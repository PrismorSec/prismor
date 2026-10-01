"""Render a sweep as the answer to "what would my policy have done?".

The report is built around one question an operator cannot otherwise answer
without waiting days in observe mode: *if I turn enforce on, what breaks?*
Because the would-block set comes from `hooks.should_block` — the same function
the live dispatcher calls — the counts here are what enforcement would actually
have done, not an approximation of it.
"""

from __future__ import annotations

import collections
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from prismor.runtime.transcripts.driver import SweepResult

_SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]


def _parse_ts(value: Any) -> Optional[datetime]:
    if not value:
        return None
    text = str(value).replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _ago(value: Any, *, now: Optional[datetime] = None) -> str:
    parsed = _parse_ts(value)
    if parsed is None:
        return ""
    now = now or datetime.now(timezone.utc)
    delta = now - parsed
    seconds = max(0, int(delta.total_seconds()))
    if seconds < 3600:
        return f"{seconds // 60}m ago"
    if seconds < 86400:
        return f"{seconds // 3600}h ago"
    return f"{seconds // 86400}d ago"


def _plural(count: int, noun: str) -> str:
    return f"{count} {noun}" + ("" if count == 1 else "s")


# Severity carries the weight in this report, so it gets the colour rather than
# the rule name. Disabled when stdout is not a terminal, so piping to a file or
# a diff stays clean.
_COLOR = {
    "CRITICAL": "\033[31m",
    "HIGH": "\033[33m",
    "MEDIUM": "\033[34m",
    "LOW": "\033[37m",
}
_DIM = "\033[2m"
_BOLD = "\033[1m"
_RESET = "\033[0m"


def _use_color() -> bool:
    import os
    import sys
    if os.environ.get("NO_COLOR"):
        return False
    try:
        return sys.stdout.isatty()
    except Exception:
        return False


def _c(text: str, *codes: str) -> str:
    if not codes or not _use_color():
        return text
    return "".join(codes) + text + _RESET


def _bar(count: int, largest: int, width: int = 12) -> str:
    """A proportional bar, so the shape of the distribution is visible.

    A column of numbers makes the reader do the arithmetic to see that one rule
    accounts for most of the findings; a bar shows it.
    """
    if largest <= 0:
        return " " * width
    filled = max(1, round(count / largest * width))
    return "█" * filled + " " * (width - filled)


def _rule_lines(grouped: List[Tuple[str, int, str, str]], limit: Optional[int] = None) -> List[str]:
    """Render grouped rule counts as an aligned, proportional table."""
    rows = grouped[:limit] if limit else grouped
    if not rows:
        return []
    largest = max(count for _, count, _, _ in rows)
    width = max(len(rule) for rule, _, _, _ in rows)
    width = min(max(width, 20), 40)
    out = []
    for rule, count, severity, latest in rows:
        color = _COLOR.get(severity.upper(), "")
        recency = _ago(latest)
        out.append(
            f"  {rule:<{width}}  {count:>5}  "
            f"{_c(_bar(count, largest), color)}  "
            f"{_c(f'{severity:<8}', color)}  "
            f"{_c(f'last {recency}', _DIM) if recency else ''}"
        )
    return out


def _group(entries: List[Dict[str, Any]]) -> List[Tuple[str, int, str, str]]:
    """Group findings by rule -> (ruleId, count, severity, most-recent-ts)."""
    counts: collections.Counter = collections.Counter()
    severities: Dict[str, str] = {}
    latest: Dict[str, Any] = {}
    for entry in entries:
        rule = str(entry.get("ruleId") or entry.get("id") or "unknown")
        counts[rule] += 1
        severities.setdefault(rule, str(entry.get("severity") or "UNKNOWN"))
        stamp = _parse_ts(entry.get("ts"))
        if stamp is not None:
            current = latest.get(rule)
            if current is None or stamp > current:
                latest[rule] = stamp
    ordered = sorted(
        counts.items(),
        key=lambda kv: (
            _SEVERITY_ORDER.index(severities.get(kv[0], "UNKNOWN"))
            if severities.get(kv[0], "UNKNOWN") in _SEVERITY_ORDER
            else len(_SEVERITY_ORDER),
            -kv[1],
        ),
    )
    return [
        (
            rule,
            count,
            severities.get(rule, "UNKNOWN"),
            latest[rule].isoformat() if rule in latest else "",
        )
        for rule, count in ordered
    ]


def partition(
    result: SweepResult,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Split findings into (would-block, would-warn).

    The driver stores a blocked verdict as a *copy* of the winning finding, so
    the two lists cannot be separated by object identity. Every finding carries
    a unique ``id`` (``<session>:<rule>-<index>``), which is what actually
    distinguishes them.
    """
    blocked = [b for s in result.sessions for b in s.would_block]
    blocked_keys = {str(b.get("id")) for b in blocked if b.get("id") is not None}
    warnings = [
        f
        for s in result.sessions
        for f in s.findings
        if str(f.get("id")) not in blocked_keys
    ]
    return blocked, warnings


def format_report(result: SweepResult, *, since_label: str = "all history") -> str:
    lines: List[str] = []
    agents = collections.Counter(s.agent for s in result.sessions)
    events = collections.Counter()
    labels: Dict[str, str] = {}
    for session in result.sessions:
        events[session.agent] += session.event_count
        labels[session.agent] = session.label

    lines.append("")
    lines.append(
        _c(f"Scanned {_plural(len(result.sessions), 'session')} · "
           f"{_plural(result.total_events, 'event')} · {since_label}", _BOLD)
        + _c(f"   ({result.elapsed_seconds:.1f}s)", _DIM)
    )
    lines.append("")
    for agent, count in agents.most_common():
        lines.append(
            f"  {labels.get(agent, agent):<14} {count:>5} sessions {events[agent]:>8} events"
        )
    for agent in result.empty_agents:
        lines.append(f"  {labels.get(agent, agent):<14} {_c('no transcripts found', _DIM)}")
    # An agent whose every transcript predates the window would otherwise be
    # absent from the report entirely, which reads as "no data" rather than
    # "nothing recent".
    for agent, count in sorted(result.filtered_out.items()):
        if agent in agents:
            continue
        lines.append(
            f"  {labels.get(agent, agent):<14}    "
            f"{_plural(count, 'transcript')} outside --since window"
        )
    lines.append("")

    would_block, warnings = partition(result)

    _RULE_LIMIT = 12

    if would_block:
        blocked_rules = _group(would_block)
        lines.append(
            _c(f"Would BLOCK  {len(would_block)}", _BOLD)
            + _c(f"   across {_plural(len(blocked_rules), 'rule')}", _DIM)
        )
        lines.append("")
        lines.extend(_rule_lines(blocked_rules, _RULE_LIMIT))
        hidden = len(blocked_rules) - _RULE_LIMIT
        if hidden > 0:
            lines.append(_c(f"  … and {_plural(hidden, 'more rule')}", _DIM))
    else:
        lines.append(_c("Would BLOCK  0", _BOLD))
        lines.append("")
        lines.append("  Nothing in this window would be blocked by the current policy.")
    lines.append("")

    if warnings:
        warn_rules = _group(warnings)
        lines.append(
            _c(f"Would WARN  {len(warnings)}", _BOLD)
            + _c(f"   across {_plural(len(warn_rules), 'rule')}", _DIM)
        )
        lines.append("")
        lines.extend(_rule_lines(warn_rules, _RULE_LIMIT))
        hidden = len(warn_rules) - _RULE_LIMIT
        if hidden > 0:
            lines.append(_c(f"  … and {_plural(hidden, 'more rule')}", _DIM))
        lines.append("")

    if result.silent_sessions:
        lines.append(
            _c("⚠  ", "\033[33m")
            + f"{_plural(len(result.silent_sessions), 'transcript')} produced no events "
            f"despite containing records the adapter recognizes."
        )
        # Basenames, not full paths. The paths are ~110 characters of home
        # directory and project slug that wrap over two lines each and bury the
        # one thing worth reading, which is how many and from which agent.
        for session in result.silent_sessions[:3]:
            # Name the record shapes that emitted nothing. "likely an adapter
            # format mismatch" on its own is untriageable without handing over
            # the transcript; the shape is schema, not content (issue #346).
            reasons = ", ".join(
                f"{shape} ×{count}"
                for shape, count in session.stats.top_skip_reasons[:3]
            )
            suffix = f"  ({reasons})" if reasons else ""
            lines.append(_c(f"     {session.agent}: …/{session.path.name}{suffix}", _DIM))
        extra = len(result.silent_sessions) - 3
        if extra > 0:
            lines.append(_c(f"     … and {extra} more", _DIM))
        lines.append(_c("     Full paths: prismor ingest --discover --json", _DIM))
        lines.append("")

    if result.truncated:
        lines.append(
            "⚠  Event budget reached — results are partial. "
            "Raise --max-events or narrow --since."
        )
        lines.append("")

    if would_block or warnings:
        example = (_group(would_block) or _group(warnings))[0][0]
        lines.append(_c("Next", _BOLD))
        lines.append(
            f"  prismor ingest --discover --show {example}"
            + _c("   see the calls behind a rule", _DIM)
        )
        if would_block:
            lines.append(
                "  prismor allow <rule> --pattern '<literal>'"
                + _c("   make an exception before enforcing", _DIM)
            )
        lines.append("")
    return "\n".join(lines)


def format_rule_detail(result: SweepResult, rule_id: str, *, limit: int = 25) -> str:
    """Show the individual calls behind one rule."""
    lines: List[str] = ["", f"Calls matching '{rule_id}'", ""]
    shown = 0
    for session in result.sessions:
        blocked_indices = {b.get("eventIndex") for b in session.would_block}
        for finding in session.findings:
            if str(finding.get("ruleId") or "") != rule_id:
                continue
            if shown >= limit:
                lines.append(f"  … and more; showing first {limit}")
                return "\n".join(lines) + "\n"
            verdict = "BLOCK" if finding.get("eventIndex") in blocked_indices else "warn"
            when = _ago(finding.get("ts"))
            evidence = " ".join(str(finding.get("evidence") or "").split())[:150]
            lines.append(
                f"  [{verdict:<5}] {session.agent}  {when:<9} "
                f"{session.original_session_id[:8]}"
            )
            lines.append(f"          {evidence}")
            shown += 1
    if shown == 0:
        lines.append(f"  No calls matched rule '{rule_id}' in this window.")
    lines.append("")
    return "\n".join(lines)


def report_payload(result: SweepResult) -> Dict[str, Any]:
    """Machine-readable form of the same report, for `--json`."""
    would_block, warnings = partition(result)
    return {
        "sessions": len(result.sessions),
        "events": result.total_events,
        "findings": result.total_findings,
        "elapsedSeconds": round(result.elapsed_seconds, 2),
        "truncated": result.truncated,
        "emptyAgents": result.empty_agents,
        # Objects, not bare path strings: a silent transcript is only
        # actionable if the report says which adapter read it and which record
        # shapes it could not turn into events (issue #346). `path` is kept as
        # the first key so existing readers that index it still work.
        "silentSessions": [
            {
                "path": str(s.path),
                "agent": s.agent,
                "recordsRead": s.stats.records_read,
                "malformedLines": s.stats.malformed_lines,
                "skippedRecords": s.stats.skipped_records,
                "skipReasons": [
                    {"shape": shape, "count": count}
                    for shape, count in s.stats.top_skip_reasons
                ],
                "errors": s.stats.errors[:5],
            }
            for s in result.silent_sessions
        ],
        "wouldBlock": [
            {"ruleId": r, "count": c, "severity": s, "mostRecent": t}
            for r, c, s, t in _group(would_block)
        ],
        "wouldWarn": [
            {"ruleId": r, "count": c, "severity": s, "mostRecent": t}
            for r, c, s, t in _group(warnings)
        ],
        "byAgent": [
            {
                "agent": agent,
                "sessions": sum(1 for s in result.sessions if s.agent == agent),
                "events": sum(s.event_count for s in result.sessions if s.agent == agent),
            }
            for agent in sorted({s.agent for s in result.sessions})
        ],
    }
