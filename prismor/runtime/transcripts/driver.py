"""Sweep on-disk transcripts, evaluate them, and persist the reconstruction.

The pipeline is deliberately thin, because everything it needs already exists::

    transcript file
      -> adapter            (the only new code: records -> hook payloads)
      -> normalize_payload  (the live normalizer, unchanged)
      -> PolicyEngine       (the live engine, unchanged)
      -> should_block       (the live enforcement decision, unchanged)
      -> save_session_snapshot

Routing through the live normalizer and the live `should_block` is what makes
the "what would my policy have blocked" answer trustworthy: it is computed by
the same code the hook dispatcher runs, so it cannot drift from real
enforcement.

Two invariants this module is responsible for:

**Replayed sessions never collide with live ones.** The store keys sessions by
``session_id`` and `save_session_snapshot` is INSERT-OR-REPLACE. A Claude
transcript carries the *same* ``sessionId`` the live hooks used, so persisting
it unprefixed would silently overwrite real enforcement history with a replay.
Every replayed session is therefore namespaced (`replay_session_id`).

**A sweep leaves no residue.** Evaluating events makes `PolicyEngine` write
per-session taint files. Those are keyed by the namespaced id so they cannot
corrupt a live session's taint, but they would still accumulate in the user's
state directory, so the driver removes its own afterwards.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from prismor.runtime.transcripts.adapters import get_adapters
from prismor.runtime.transcripts.base import DiscoveredSession, ParseStats

#: Namespace applied to every replayed session id.
REPLAY_PREFIX = "replay"

#: Source tag written to `sessions.source`, distinguishing reconstructed
#: activity from live hook capture (`hook`) and from the pre-existing
#: single-file `ingest --input` path (`ingest`).
REPLAY_SOURCE = "transcript"


def replay_session_id(agent: str, session_id: str) -> str:
    return f"{REPLAY_PREFIX}:{agent}:{session_id}"


def is_replay_session(session_id: str) -> bool:
    return str(session_id).startswith(f"{REPLAY_PREFIX}:")


def split_replay_session_id(session_id: str) -> Optional[Tuple[str, str]]:
    """``replay:claude:abc`` -> ``("claude", "abc")``; None if not a replay id."""
    if not is_replay_session(session_id):
        return None
    _, _, rest = str(session_id).partition(":")
    agent, _, original = rest.partition(":")
    return (agent, original) if original else None


@dataclass
class SweepOptions:
    workspace: Path
    repo_root: Path
    agents: Optional[List[str]] = None
    #: Only consider transcripts modified within this many days. None = all.
    since_days: Optional[float] = 30.0
    #: Hard ceiling on evaluated events, so a first run cannot take minutes.
    max_events: int = 50_000
    persist: bool = True
    #: Semantic guard is force-disabled during a sweep: it is off by default,
    #: but a user who enabled it would otherwise fire one LLM call per
    #: uncertain event across their entire history.
    semantic: bool = False
    #: Treat a non-empty transcript that yields no payloads as an error.
    strict: bool = False
    #: Keep normalized events on each result. Only the corpus exporter needs
    #: them; retaining by default would hold an entire history in memory for
    #: reports that never look at individual events.
    retain_events: bool = False


@dataclass
class SessionResult:
    agent: str
    label: str
    path: Path
    original_session_id: str
    replay_session_id: str
    workspace: Optional[Path]
    started_at: Optional[str]
    ended_at: Optional[str]
    event_count: int
    findings: List[Dict[str, Any]] = field(default_factory=list)
    #: Findings that `should_block` selected — i.e. what enforce mode would
    #: actually have stopped, one entry per blocked event.
    would_block: List[Dict[str, Any]] = field(default_factory=list)
    stats: ParseStats = field(default_factory=ParseStats)
    risk_score: int = 0
    #: Populated only when `SweepOptions.retain_events` is set.
    events: List[Dict[str, Any]] = field(default_factory=list)
    #: Events that matched no rule at all — the negative fixtures a precision
    #: corpus needs, and the half that hand-written test cases never cover.
    clean_events: List[Dict[str, Any]] = field(default_factory=list)

    @property
    def silent(self) -> bool:
        return self.stats.looks_silent


@dataclass
class SweepResult:
    sessions: List[SessionResult] = field(default_factory=list)
    truncated: bool = False
    elapsed_seconds: float = 0.0
    #: Adapters that found no files at all, so the report can distinguish
    #: "agent not installed" from "agent installed but nothing matched".
    empty_agents: List[str] = field(default_factory=list)
    #: agent -> transcripts skipped because they fell outside `--since`.
    #: Without this an agent whose history is all older than the window simply
    #: vanishes from the report, which reads as "this agent has no data".
    filtered_out: Dict[str, int] = field(default_factory=dict)

    @property
    def total_events(self) -> int:
        return sum(s.event_count for s in self.sessions)

    @property
    def total_findings(self) -> int:
        return sum(len(s.findings) for s in self.sessions)

    @property
    def total_would_block(self) -> int:
        return sum(len(s.would_block) for s in self.sessions)

    @property
    def silent_sessions(self) -> List[SessionResult]:
        return [s for s in self.sessions if s.silent]


def _severity_weight() -> Dict[str, int]:
    from prismor.runtime.cli import SEVERITY_WEIGHT

    return SEVERITY_WEIGHT


def build_analysis(
    events: List[Dict[str, Any]],
    findings: List[Dict[str, Any]],
    repo_root: Path,
    block_categories: List[str],
) -> Dict[str, Any]:
    """Produce the analysis dict `save_session_snapshot` expects.

    Mirrors `cli.analyze_events`'s output contract exactly. It is rebuilt here
    rather than called because a sweep needs one shared `PolicyEngine` across
    every session (`analyze_events` constructs its own per call, reloading and
    recompiling the policy each time) and needs the per-event `should_block`
    verdict, which that function does not return.
    """
    from prismor.runtime.cli import severity_breakdown
    from prismor.runtime.feed import load_feed, match_advisories

    weights = _severity_weight()
    return {
        "summary": {
            "totalEvents": len(events),
            "totalFindings": len(findings),
            "riskScore": min(
                100,
                sum(weights.get(f.get("severity", "UNKNOWN"), 1) for f in findings),
            ),
            "severityBreakdown": severity_breakdown(findings),
        },
        "findings": sorted(
            findings,
            key=lambda item: weights.get(item.get("severity", "UNKNOWN"), 0),
            reverse=True,
        ),
        "feedMatches": match_advisories(findings, load_feed(repo_root)),
        "blockCategories": sorted(block_categories),
    }


def _cutoff(since_days: Optional[float]) -> Optional[float]:
    if since_days is None:
        return None
    return time.time() - (since_days * 86400)


def sweep(options: SweepOptions) -> SweepResult:
    """Discover, evaluate and optionally persist every matching transcript."""
    from prismor.runtime.hooks import normalize_payload, should_block
    from prismor.runtime.policy_engine import PolicyEngine

    started = time.monotonic()
    engine = PolicyEngine(workspace=options.workspace)
    if not options.semantic:
        engine.semantic_guard_config = {}

    result = SweepResult()
    cutoff = _cutoff(options.since_days)
    budget = options.max_events
    replay_ids: List[str] = []

    for adapter in get_adapters(options.agents):
        found_any = False
        for session in adapter.discover():
            found_any = True
            if cutoff is not None and session.mtime < cutoff:
                result.filtered_out[adapter.agent] = (
                    result.filtered_out.get(adapter.agent, 0) + 1
                )
                continue
            if budget <= 0:
                result.truncated = True
                break

            outcome, consumed = _replay_session(
                adapter=adapter,
                session=session,
                engine=engine,
                options=options,
                budget=budget,
                normalize_payload=normalize_payload,
                should_block=should_block,
            )
            budget -= consumed
            if outcome is None:
                continue
            replay_ids.append(outcome.replay_session_id)
            result.sessions.append(outcome)
        if not found_any:
            result.empty_agents.append(adapter.agent)
        if result.truncated:
            break

    _cleanup_taint(options.workspace, replay_ids)
    result.elapsed_seconds = time.monotonic() - started
    return result


def _replay_session(
    *,
    adapter: Any,
    session: DiscoveredSession,
    engine: Any,
    options: SweepOptions,
    budget: int,
    normalize_payload: Any,
    should_block: Any,
) -> Tuple[Optional[SessionResult], int]:
    replay_id = replay_session_id(adapter.agent, session.session_id)
    stats = ParseStats()
    events: List[Dict[str, Any]] = []
    findings: List[Dict[str, Any]] = []
    blocked: List[Dict[str, Any]] = []
    clean: List[Dict[str, Any]] = []

    for payload in adapter.payloads_with_stats(session, stats):
        if len(events) >= budget:
            break
        try:
            normalized = normalize_payload(
                agent=adapter.agent, payload=payload, workspace=options.workspace
            )
        except Exception as exc:
            stats.errors.append(f"{session.path}: normalize: {type(exc).__name__}: {exc}")
            continue
        event = normalized.get("event") if isinstance(normalized, dict) else None
        if not isinstance(event, dict):
            continue
        index = len(events)
        events.append(event)
        try:
            hits = engine.evaluate(event, index, session_id=replay_id)
        except Exception as exc:
            stats.errors.append(f"{session.path}: evaluate: {type(exc).__name__}: {exc}")
            continue
        if not hits:
            if options.retain_events:
                clean.append(event)
            continue
        # Stamp each finding with the originating event's timestamp. Findings
        # carry only an event index, but a report about history has to say
        # *when* something happened, and the index alone cannot answer that.
        event_ts = event.get("ts")
        for hit in hits:
            hit.setdefault("ts", event_ts)
        findings.extend(hits)
        verdict = should_block(hits, event)
        if verdict:
            blocked.append({**verdict, "eventIndex": index, "ts": event_ts})

    if not events:
        # Still surface a silent non-empty file — that is the failure mode
        # where a sweep looks successful and protects nothing.
        if stats.looks_silent:
            return (
                SessionResult(
                    agent=adapter.agent,
                    label=getattr(adapter, "label", adapter.agent),
                    path=session.path,
                    original_session_id=session.session_id,
                    replay_session_id=replay_id,
                    workspace=session.workspace,
                    started_at=None,
                    ended_at=None,
                    event_count=0,
                    stats=stats,
                ),
                0,
            )
        return None, 0

    timestamps = sorted(str(e.get("ts")) for e in events if e.get("ts"))
    analysis = build_analysis(
        events, findings, options.repo_root, sorted(engine.block_categories)
    )
    outcome = SessionResult(
        agent=adapter.agent,
        label=getattr(adapter, "label", adapter.agent),
        path=session.path,
        original_session_id=session.session_id,
        replay_session_id=replay_id,
        workspace=session.workspace,
        started_at=timestamps[0] if timestamps else None,
        ended_at=timestamps[-1] if timestamps else None,
        event_count=len(events),
        findings=findings,
        would_block=blocked,
        stats=stats,
        risk_score=analysis["summary"]["riskScore"],
        events=events if options.retain_events else [],
        clean_events=clean,
    )

    if options.persist:
        from prismor.runtime.store import save_session_snapshot

        save_session_snapshot(
            workspace=options.workspace,
            session_id=replay_id,
            agent=adapter.agent,
            source=REPLAY_SOURCE,
            repo_url=None,
            events=events,
            analysis=analysis,
            agent_name=getattr(adapter, "label", adapter.agent),
        )

    return outcome, len(events)


def _cleanup_taint(workspace: Path, replay_ids: List[str]) -> None:
    """Delete taint files this sweep created.

    `PolicyEngine` persists per-session taint under the state directory. Replay
    ids are namespaced so they can never clobber a live session's taint, but
    leaving one file per replayed session behind on every sweep would litter
    the user's state directory indefinitely.
    """
    if not replay_ids:
        return
    try:
        from prismor.runtime.store import get_data_dir

        taint_dir = get_data_dir(workspace) / "taint"
    except Exception:
        return
    if not taint_dir.is_dir():
        return
    for replay_id in replay_ids:
        safe = "".join(c if c.isalnum() or c in "._-" else "_" for c in replay_id)
        for suffix in (".json", ".json.lock"):
            candidate = taint_dir / f"{safe}{suffix}"
            try:
                if candidate.is_file():
                    candidate.unlink()
            except OSError:
                continue
