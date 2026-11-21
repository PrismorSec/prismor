"""prismor/runtime/logs.py — every recorded agent event, filterable, for the
dashboard's Logs page (GET /api/logs, GET /api/logs/event).

The tool name lives inside each event's raw_json, and reading those blobs for
a week of events takes seconds. So each workspace DB gets a small in-process
index of light rows (no blobs), built once and topped up with only the new
events on every request. Filters, facet counts and the chart run over it.

ponytail: the index grows for the life of the server (about 100 bytes a row,
~30 MB per 300k events); prune by ts if a long-lived server ever needs it.
"""
from __future__ import annotations

import json
import threading
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Tuple

from prismor.runtime.store import (
    _absolute_time_store, _connect_ro, _relative_time_store,
    _state_query_workspaces, get_db_path,
)

MAX_DAYS = 30
STATUSES = ("allowed", "blocked", "asked", "flagged")
_LOCK = threading.Lock()
_IDX: Dict[str, Dict[str, Any]] = {}

# Light rows only: no blobs kept, though the tool name is read out of one.
_ROWS_SQL = """
SELECT e.id, e.ts, e.session_id, e.type, e.agent_event,
       json_extract(e.raw_json, '$.metadata.tool_name') AS tool,
       json_extract(e.raw_json, '$.metadata.raw.tool_use_id') AS use_id,
       substr(coalesce(nullif(e.command_text, ''), nullif(e.path_text, ''),
                       nullif(e.url_text, ''), substr(e.content_text, 1, 300), ''), 1, 300) AS detail
FROM events e INDEXED BY idx_events_ts
WHERE e.ts >= ? AND e.id > ? AND e.type != 'supply_chain'
"""
_FINDINGS_SQL = """
SELECT rowid, session_id, event_index, severity, category, title,
       json_extract(enrichment_json, '$.action'), json_extract(enrichment_json, '$.mode'),
       json_extract(enrichment_json, '$.ruleId')
FROM findings WHERE rowid > ?
"""


def _status(findings: List[tuple]) -> str:
    """One outcome per event. `flagged` covers findings that did not stop the
    call: observe mode, warn/log rules, and old findings with no action."""
    if not findings:
        return "allowed"
    # finding tuple: (severity, category, title, action, mode, rule)
    acts = {(f[3] or "", f[4] or "") for f in findings}
    if any(a == "block" and m in ("enforce", "") for a, m in acts):
        return "blocked"
    if any(a == "step_up" for a, _ in acts):
        return "asked"
    return "flagged"


def _refresh(db) -> Dict[str, Any]:
    # post: call event id -> (result id, result ts, result rn); merged: result
    # ids folded into their call; pending: calls still waiting for a result.
    idx = _IDX.setdefault(str(db), {"last_id": 0, "last_f": 0, "rows": [], "findings": {},
                                    "post": {}, "merged": set(), "pending": {}})
    conn = _connect_ro(db)
    if conn is None:
        return idx
    try:
        cutoff = (datetime.now(timezone.utc) - timedelta(days=MAX_DAYS)).strftime("%Y-%m-%dT%H:%M:%S")
        last = idx["last_id"]
        new = conn.execute(_ROWS_SQL, (cutoff, idx["last_id"])).fetchall()
        # findings.event_index is the event's position in its WHOLE session,
        # so number every event of the sessions these rows belong to.
        sids = list({r["session_id"] for r in new})
        rn: Dict[int, int] = {}
        for k in range(0, len(sids), 500):
            chunk = sids[k:k + 500]
            prev, n = None, 0
            for sid, eid in conn.execute(
                    f"SELECT session_id, id FROM events WHERE session_id IN ({','.join('?' * len(chunk))}) "  # nosec B608
                    "ORDER BY session_id, id", chunk):
                n = n + 1 if sid == prev else 0
                prev = sid
                rn[eid] = n
        agents = dict(conn.execute("SELECT session_id, agent FROM sessions").fetchall()) if new else {}
        new.sort(key=lambda r: r["id"])
        for r in new:
            # One row per tool call: a PostToolUse folds into its PreToolUse,
            # matched on the agent's tool_use_id, else the oldest open call of
            # the same tool in the same session.
            ev = (r["agent_event"] or "").lower()
            if ev in ("pretooluse", "posttooluse"):
                key = (r["session_id"], "u", r["use_id"]) if r["use_id"] else (r["session_id"], "t", r["tool"] or "")
                if ev == "pretooluse":
                    idx["pending"].setdefault(key, []).append(r["id"])
                else:
                    open_calls = idx["pending"].get(key)
                    if open_calls:
                        pre = open_calls.pop(0)
                        if not open_calls:
                            del idx["pending"][key]
                        idx["post"][pre] = (r["id"], r["ts"] or "", rn.get(r["id"], -1))
                        idx["merged"].add(r["id"])
            tool = r["tool"] or ""
            server = tool[5:].split("__", 1)[0] if tool.startswith("mcp__") and "__" in tool[5:] else ""
            # The store types every MCP call `tool_result`; call it what it is.
            etype = "mcp" if server else (r["type"] or "")
            idx["rows"].append((r["id"], r["ts"] or "", r["session_id"], etype, r["agent_event"] or "",
                                tool, server, r["detail"] or "", rn.get(r["id"], -1), agents.get(r["session_id"]) or ""))
            idx["last_id"] = max(idx["last_id"], r["id"])
        if new:
            idx["rows"].sort(key=lambda x: x[1], reverse=True)
        for f in conn.execute(_FINDINGS_SQL, (idx["last_f"],)):
            idx["findings"].setdefault((f[1], f[2]), []).append(tuple(f)[3:])
            idx["last_f"] = max(idx["last_f"], f[0])
    finally:
        conn.close()
    return idx


def warm() -> None:
    """Build the index ahead of the first request (the cold read takes seconds)."""
    try:
        _all_rows(1)
    except Exception:
        pass


def _all_rows(days: int):
    """(workspace index, row, status, findings, result) for every call or
    event in the window, newest first. `result` is the folded-in PostToolUse."""
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%S")
    out = []
    with _LOCK:
        for wi, ws in enumerate(_state_query_workspaces()):
            idx = _refresh(get_db_path(ws))
            fmap, post, merged = idx["findings"], idx["post"], idx["merged"]
            for r in idx["rows"]:
                if r[1] < cutoff:
                    break
                if r[0] in merged:
                    continue
                res = post.get(r[0])
                fs = fmap.get((r[2], r[8]), [])
                if res and (r[2], res[2]) in fmap:
                    fs = fs + fmap[(r[2], res[2])]
                out.append((wi, r, _status(fs), fs, res))
    out.sort(key=lambda x: x[1][1], reverse=True)
    return out


def _tool_label(r) -> str:
    return r[5] or r[3] or r[4] or "event"


_FACETS = {
    "status": lambda x: x[2],
    "type": lambda x: x[1][3] or "other",
    "tool": lambda x: _tool_label(x[1]),
    "server": lambda x: x[1][6],
    "agent": lambda x: x[1][9],
    "session": lambda x: x[1][2],
}


def query_logs(filters: Dict[str, str], page: int = 1, limit: int = 50, days: int = 7) -> Dict[str, Any]:
    days = max(1, min(days or 7, MAX_DAYS))
    limit = max(1, min(limit, 200))
    rows = _all_rows(days)
    want = {k: set(v for v in (filters.get(k) or "").split(",") if v) for k in _FACETS}
    q = (filters.get("q") or "").strip().lower()

    def base_ok(x):
        r = x[1]
        return not q or q in r[7].lower() or q in r[5].lower() or q in r[2]

    base = [x for x in rows if base_ok(x)]

    def passes(x, skip=""):
        return all(not v or k == skip or _FACETS[k](x) in v for k, v in want.items())

    # Each facet counts what the OTHER filters leave, so its own boxes stay open.
    facets = {}
    for k, fn in _FACETS.items():
        counts: Dict[str, int] = {}
        for x in base:
            if passes(x, k):
                key = fn(x)
                if key:
                    counts[key] = counts.get(key, 0) + 1
        top = sorted(counts.items(), key=lambda kv: -kv[1])
        facets[k] = [{"value": v, "count": c} for v, c in (top if k == "status" else top[:300])]

    hits = [x for x in base if passes(x)]
    stats = {s: 0 for s in STATUSES}
    for x in hits:
        stats[x[2]] += 1
    stats["total"] = len(hits)
    stats["sessions"] = len({x[1][2] for x in hits})

    # Chart: hourly for one day, daily otherwise, stacked by outcome.
    now = datetime.now(timezone.utc)
    hourly = days == 1
    n = 24 if hourly else days
    step = timedelta(hours=1) if hourly else timedelta(days=1)
    start = (now.replace(minute=0, second=0, microsecond=0) if hourly
             else now.replace(hour=0, minute=0, second=0, microsecond=0)) - step * (n - 1)
    buckets = [{"t": (start + step * i).isoformat(), **{s: 0 for s in STATUSES}} for i in range(n)]
    for x in hits:
        try:
            ts = datetime.fromisoformat(x[1][1].replace("Z", "+00:00"))
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
        i = int((ts - start) / step)
        if 0 <= i < n:
            buckets[i][x[2]] += 1

    pages = max(1, -(-len(hits) // limit))
    page = max(1, min(page, pages))
    items = []
    for wi, r, status, fs, res in hits[(page - 1) * limit: page * limit]:
        items.append({
            "post": f"{wi}:{res[0]}" if res else "", "ms": _ms(r[1], res[1]) if res else None,
            "id": f"{wi}:{r[0]}", "ts": r[1], "rel": _relative_time_store(r[1]), "abs": _absolute_time_store(r[1]),
            "session": r[2], "type": r[3], "event": r[4], "tool": _tool_label(r), "server": r[6],
            "detail": r[7], "agent": r[9], "status": status,
            "findings": [{"severity": f[0], "category": f[1], "title": f[2], "action": f[3], "mode": f[4]} for f in fs[:3]],
        })
    return {"items": items, "total": len(hits), "page": page, "pages": pages, "limit": limit,
            "days": days, "hourly": hourly, "stats": stats, "histogram": buckets, "facets": facets}


def _ms(a: str, b: str):
    try:
        return max(0, int((datetime.fromisoformat(b) - datetime.fromisoformat(a)).total_seconds() * 1000))
    except (ValueError, TypeError):
        return None


def _clip(v, n=4000):
    if isinstance(v, str):
        return v if len(v) <= n else v[:n] + f"… ({len(v) - n} more chars)"
    if isinstance(v, dict):
        return {k: _clip(x, n) for k, x in v.items()}
    if isinstance(v, list):
        return [_clip(x, n) for x in v[:200]]
    return v


def _load_event(conn, eid: int):
    e = conn.execute("SELECT id, session_id, ts, type, agent_event, raw_json FROM events WHERE id = ?", (eid,)).fetchone()
    if e is None:
        return None, [], {}
    rn = conn.execute("SELECT COUNT(*) FROM events WHERE session_id = ? AND id < ?", (e["session_id"], eid)).fetchone()[0]
    fs = conn.execute("SELECT finding_id, severity, category, title, evidence, enrichment_json FROM findings "
                      "WHERE session_id = ? AND event_index = ?", (e["session_id"], rn)).fetchall()
    try:
        raw = json.loads(e["raw_json"] or "{}")
    except ValueError:
        raw = {"raw_json": e["raw_json"]}
    findings = []
    for f in fs:
        try:
            enr = json.loads(f["enrichment_json"] or "{}")
        except ValueError:
            enr = {}
        findings.append({"id": f["finding_id"], "severity": f["severity"], "category": f["category"],
                         "title": f["title"], "evidence": _clip(f["evidence"] or "", 2000),
                         "action": enr.get("action"), "mode": enr.get("mode"), "rule": enr.get("ruleId")})
    return e, findings, _clip(raw)


def get_log_event(ident: str, post: str = "") -> Dict[str, Any]:
    """One call in full: the stored call record and, when given, its result
    record (long strings clipped), with every finding on either."""
    try:
        wi, eid = (int(p) for p in ident.split(":", 1))
        pid = int(post.split(":", 1)[1]) if post else 0
        ws = _state_query_workspaces()[wi]
    except (ValueError, IndexError):
        return {"error": "unknown event"}
    conn = _connect_ro(get_db_path(ws))
    if conn is None:
        return {"error": "store unavailable"}
    try:
        e, findings, raw = _load_event(conn, eid)
        if e is None:
            return {"error": "unknown event"}
        result = None
        if pid:
            pe, pf, praw = _load_event(conn, pid)
            if pe is not None and pe["session_id"] == e["session_id"]:
                findings += [{**f, "on": "result"} for f in pf]
                result = {"ts": pe["ts"], "abs": _absolute_time_store(pe["ts"] or ""), "event": pe["agent_event"],
                          "ms": _ms(e["ts"], pe["ts"]), "raw": praw}
        return {"id": ident, "session": e["session_id"], "ts": e["ts"], "abs": _absolute_time_store(e["ts"] or ""),
                "type": e["type"], "event": e["agent_event"],
                "status": _status([(0, 0, 0, f["action"], f["mode"]) for f in findings]),
                "findings": findings, "raw": raw, "result": result}
    finally:
        conn.close()
