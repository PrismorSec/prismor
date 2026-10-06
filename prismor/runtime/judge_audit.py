"""`prismor audit judge` — sampled, after-the-fact judge review of ALLOWED tool calls.

The regex rules decide every tool call on the hook path; the LLM judge is too
slow to sit there for all of them. This closes the gap offline: it picks a
deterministic sample of calls the rules let through (no finding at all), sends
each one, secret-scrubbed, to the workspace's configured judge, stores the
verdict in ``judge_audit`` and reports what the judge would have flagged.

Runs on the device against the local store because that is the only place the
content of an allowed call exists: in the default redacted mode the console
only ever receives counts for them. A flagged call produces one content-free
``judge_audit`` telemetry record through the normal sink path. Nothing is ever
blocked retroactively.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

DEFAULTS = {"sample_rate": 0.05, "max_per_run": 50, "window": "24h"}
RULE_ID = "judge-audit"
_TEXT_CAP = 3000  # one judge window (semantic_guard_v2._WINDOW)

DDL = """
CREATE TABLE IF NOT EXISTS judge_audit (
    event_id TEXT PRIMARY KEY,   -- "<session_id>:<event_index>", same key findings use
    session_id TEXT,
    event_index INTEGER,
    ts TEXT,                     -- when the audited call happened
    audited_at TEXT,
    verdict TEXT,                -- flagged | clean
    risk_score REAL,
    category TEXT,
    reason TEXT,
    model TEXT                   -- provider/model that judged it
);
"""

# Calls only: prompts, tool output and memory writes are screened elsewhere, and
# a post-call hook repeats the pre-call event it follows.
_SELECT_SQL = """
WITH ev AS (
    SELECT session_id, ts, type, agent_event, raw_json,
           ROW_NUMBER() OVER (PARTITION BY session_id ORDER BY id) - 1 AS idx
    FROM events
)
SELECT ev.session_id, ev.idx, ev.ts, ev.type, ev.raw_json, s.agent, s.workspace_path
FROM ev LEFT JOIN sessions s ON s.session_id = ev.session_id
WHERE ev.ts >= ?
  AND ev.type NOT IN ('prompt', 'tool_result', 'memory')
  AND (ev.agent_event IS NULL OR ev.agent_event = ''
       OR lower(ev.agent_event) LIKE 'pre%' OR lower(ev.agent_event) LIKE 'before%'
       OR ev.agent_event = 'PermissionRequest')
  AND ev.session_id NOT IN ({fixtures})
  AND NOT EXISTS (SELECT 1 FROM findings f
                  WHERE f.session_id = ev.session_id AND f.event_index = ev.idx)
  AND NOT EXISTS (SELECT 1 FROM judge_audit j
                  WHERE j.event_id = ev.session_id || ':' || ev.idx)
ORDER BY ev.ts DESC
"""


class JudgeNotConfigured(RuntimeError):
    pass


def settings(semantic_cfg: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """``semantic_guard.audit`` over the defaults."""
    out = dict(DEFAULTS)
    raw = (semantic_cfg or {}).get("audit")
    if isinstance(raw, dict):
        out.update({k: v for k, v in raw.items() if k in DEFAULTS and v is not None})
    return out


def sampled(event_id: str, rate: float) -> bool:
    """Deterministic: the same event is in or out of the sample on every run."""
    h = int(hashlib.sha256(event_id.encode("utf-8")).hexdigest()[:8], 16)
    return h / 0x100000000 < rate


def candidates(db_path: Path, since: datetime) -> List[Dict[str, Any]]:
    """Allowed, never-audited tool calls since ``since``, newest first."""
    from prismor.runtime.learning import _FIXTURE_SESSIONS_SQL

    conn = sqlite3.connect(db_path)
    try:
        conn.executescript(DDL)
        # ponytail: ROW_NUMBER over the whole events table; fine for a batch
        # command, index events by (session_id, id) window if stores get huge.
        rows = conn.execute(
            _SELECT_SQL.format(fixtures=_FIXTURE_SESSIONS_SQL),  # nosec B608 - constant only
            (since.strftime("%Y-%m-%dT%H:%M:%S"),),
        ).fetchall()
    finally:
        conn.close()
    keys = ("session_id", "event_index", "ts", "type", "raw_json", "agent", "workspace")
    out = []
    for row in rows:
        item = dict(zip(keys, row))
        item["event_id"] = f"{item['session_id']}:{item['event_index']}"
        out.append(item)
    return out


def _tool_and_input(raw: Dict[str, Any]) -> tuple:
    meta = raw.get("metadata") if isinstance(raw.get("metadata"), dict) else {}
    tool = str(meta.get("tool_name") or raw.get("type") or "tool")
    payload = (meta.get("raw") or {}).get("tool_input") if isinstance(meta.get("raw"), dict) else None
    if payload is None:
        payload = {k: raw[k] for k in ("command", "path", "url", "content") if raw.get(k)}
    return tool, payload


def judge_text(raw: Dict[str, Any], workspace: Optional[Path]) -> str:
    """The text the judge sees: tool + input, scrubbed, one window long.

    Same two passes a record leaving the device gets: registered cloak values
    and data-boundary values (redact_text), then the sink scrubber (secret
    patterns, URL passwords, key=value credentials; fails closed).
    """
    from prismor.runtime.redaction import redact_text
    from prismor.runtime.sinks import _scrub_for_sink

    tool, payload = _tool_and_input(raw)
    body = payload if isinstance(payload, str) else json.dumps(payload, ensure_ascii=False)
    # No "this was allowed" preamble: an injection-tuned judge reads a claim of
    # prior approval as social engineering (measured: 0.35 on a bare `ls -la`).
    text = f"AI coding agent tool call\ntool: {tool}\ninput: {body}"
    text, _ = redact_text(text, workspace=workspace)
    return _scrub_for_sink(text)[:_TEXT_CAP]


def build_guard(cfg: Dict[str, Any]):
    """The judge the hooks use, told to judge every text (no heuristic gate)."""
    from prismor.runtime.semantic_guard_v2 import SemanticGuardV2

    return SemanticGuardV2(
        cli_path=cfg.get("cli_path") or None,
        model=str(cfg.get("model") or ""),
        allow_cli=str(cfg.get("mode", "auto")).lower() == "hybrid",
        provider=str(cfg.get("provider") or "").lower(),
        low_threshold=0.0,
        high_threshold=2.0,
    )


def run(
    workspace: Path,
    *,
    since: Optional[str] = None,
    sample: Optional[float] = None,
    max_n: Optional[int] = None,
    dry_run: bool = False,
    engine: Any = None,
) -> Dict[str, Any]:
    from prismor.runtime.allow import parse_duration
    from prismor.runtime.policy_engine import PolicyEngine, _analyze_within
    from prismor.runtime.store import get_db_path, initialize_database

    engine = engine or PolicyEngine(workspace=workspace)
    cfg = engine.semantic_guard_config or {}
    conf = settings(cfg)
    window = since or str(conf["window"])
    secs = parse_duration(window)
    if not secs:
        raise ValueError(f"invalid window {window!r} (try 30m, 24h, 7d)")
    rate = float(conf["sample_rate"] if sample is None else sample)
    cap = int(conf["max_per_run"] if max_n is None else max_n)

    db = get_db_path(workspace)
    if not db.exists():
        initialize_database(workspace)
    pool = candidates(db, datetime.now(timezone.utc) - timedelta(seconds=secs))
    picked = [c for c in pool if sampled(c["event_id"], rate)][:max(cap, 0)]
    report: Dict[str, Any] = {"window": window, "sample_rate": rate, "max": cap,
                              "eligible": len(pool), "sampled": len(picked),
                              "judged": 0, "unjudged": 0, "flagged": [], "dry_run": dry_run}
    if dry_run:
        report["events"] = [{"event_id": c["event_id"], "ts": c["ts"], "type": c["type"]} for c in picked]
        return report

    guard = build_guard(cfg)
    if guard.mode == "heuristic_only":
        raise JudgeNotConfigured(
            "no LLM judge configured: set settings.semantic_guard.provider (prismor after "
            "`prismor login`, api + model, claude or codex) — see `prismor docs semantic-guard`")
    model = "/".join(p for p in (guard._provider or "default", guard._model) if p)
    warn_t = float(cfg.get("warn_threshold", 0.45))
    block_t = float(cfg.get("block_threshold", 0.75))
    budget = float(cfg.get("budget_ms") or 0) / 1000

    conn = sqlite3.connect(db)
    try:
        for c in picked:
            raw = json.loads(c["raw_json"] or "{}")
            ws = Path(c["workspace"]) if c.get("workspace") else workspace
            text = judge_text(raw, ws)
            result = _analyze_within(guard, text, budget) if budget > 0 else guard.analyze(text)
            llm = getattr(result, "llm", None)
            if llm is None or llm.mode not in ("local_llm", "api"):
                # Judge failed or overran its budget: not an audit. Left
                # unrecorded so the next run tries it again.
                report["unjudged"] += 1
                continue
            risk = result.final
            report["judged"] += 1
            verdict = "flagged" if risk.risk_score >= warn_t else "clean"
            conn.execute(
                "INSERT OR REPLACE INTO judge_audit VALUES (?,?,?,?,?,?,?,?,?,?)",
                (c["event_id"], c["session_id"], c["event_index"], c["ts"],
                 datetime.now(timezone.utc).isoformat(), verdict, round(risk.risk_score, 3),
                 risk.category, risk.reason[:500], model),
            )
            conn.commit()
            if verdict == "flagged":
                tool, _ = _tool_and_input(raw)
                hit = {"event_id": c["event_id"], "session_id": c["session_id"], "ts": c["ts"],
                       "tool": tool, "risk_score": round(risk.risk_score, 3),
                       "category": risk.category, "reason": risk.reason}
                report["flagged"].append(hit)
                _emit(engine, hit, raw, c, model=model, severity=severity(risk.risk_score, block_t))
    finally:
        conn.close()
    return report


def severity(risk_score: float, block_t: float) -> str:
    """Flagged (>= warn) maps to MEDIUM, at or over the block line to HIGH.
    Observe-only, so it stays a notch under what the live layer would say."""
    return "HIGH" if risk_score >= block_t else "MEDIUM"


def _emit(engine: Any, hit: Dict[str, Any], raw: Dict[str, Any], c: Dict[str, Any],
          *, model: str, severity: str) -> None:
    """One observe-only record per flagged call through the normal sink path.

    The event handed to the sinks is content-free on purpose (type, tool name,
    tool_use_id): the prismor sink chains, signs and assert_redacted()s it like
    any other record, and even under full capture there is no call content to
    ship. The judge's reason rides as evidence: hashed in redacted mode, under
    detail (scrubbed) in full capture, since it can echo the call. Everything
    the reviewer needs otherwise is an id, an enum or a number (judgeAudit).
    """
    if not getattr(engine, "outputs", None):
        return
    from prismor.runtime.enterprise.telemetry import _tool_use_id
    from prismor.runtime.sinks import _scrub_for_sink, dispatch

    finding = {
        "id": f"{c['session_id']}:{RULE_ID}-{c['event_index']}",
        "ruleId": RULE_ID,
        "category": hit["category"],
        "severity": severity,
        "title": "Judge audit flagged an allowed tool call",
        "evidence": _scrub_for_sink(hit["reason"]),  # the judge may echo the call
        "action": "warn",
        "mode": "observe",
        "judgeAudit": {"auditedEvent": c["event_id"], "riskScore": hit["risk_score"], "model": model},
    }
    event = {"type": "judge_audit",
             "metadata": {"tool_name": hit["tool"], "tool_use_id": _tool_use_id(raw)}}
    try:
        dispatch([finding], engine.outputs, raw_event=event,
                 extra={"session_id": c["session_id"], "agent": c.get("agent"),
                        "agent_name": c.get("agent"), "mode": "observe",
                        "workspace": c.get("workspace"), "session_seq": c["event_index"]})
    except Exception as exc:  # telemetry is best-effort, the local row is the record
        sys.stderr.write(f"[prismor] judge audit telemetry failed: {exc}\n")
