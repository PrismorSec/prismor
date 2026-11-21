"""Allowed models and spend budgets, checked before each action.

Policy settings (any layer; a later layer replaces the whole key)::

    settings:
      models:
        allow: ["claude-sonnet-*", "gpt-5*"]   # absent = every model
        deny:  ["*opus*"]                      # deny wins over allow
      spend_budgets:
        - {scope: session, usd: 5}                          # each session
        - {scope: agent, usd: 50, period: daily}            # each agent
        - {scope: agent, usd: 10, period: daily, match: ci-bot}
        - {scope: user, usd: 200, period: monthly}          # each user
        - {scope: device, usd: 500, period: monthly}        # this machine

A cap is per seat, not a shared pool: ``scope: user`` gives every user their
own $200. Periods reset on UTC calendar boundaries (Monday for weekly). A
session budget covers the whole session. ``usd: 0`` blocks every call.

Spend is read from the ``token_usage`` store (the proxy meter and the
transcript backfill both write it). On the hook path a turn is priced only
after it ends, so an over-cap budget blocks the next call, not the one in
flight; the proxy checks before it sends the request upstream.

The check only produces a report. The rules ``spend-budget-exceeded`` and
``model-not-allowed`` in default_policy.yaml decide what happens, so they
follow the same observe/enforce selection as every other rule.
"""
from __future__ import annotations

import fnmatch
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

SCOPES = ("session", "agent", "user", "device")
PERIODS = ("daily", "weekly", "monthly")
# A model with no known price is never free: the same per-million rates the
# model vendors' own gateways charge for an id they cannot place.
UNKNOWN_RATE = {"input": 5.0, "output": 25.0, "cache_read": 0.5, "cache_write": 6.25,
                "source": "unknown"}


def validate_models(raw: Any) -> List[str]:
    if not isinstance(raw, dict):
        return ["settings.models must be a mapping with allow and/or deny lists"]
    errors = []
    for key, value in raw.items():
        if key not in ("allow", "deny"):
            errors.append(f"settings.models: unknown setting {key!r}")
        elif not isinstance(value, list) or not all(isinstance(v, str) and v.strip() for v in value):
            errors.append(f"settings.models.{key} must be a list of model names or globs")
    return errors


def validate_budgets(raw: Any) -> List[str]:
    prefix = "settings.spend_budgets"
    if not isinstance(raw, list):
        return [f"{prefix} must be a list of budgets"]
    errors = []
    for i, b in enumerate(raw):
        where = f"{prefix}[{i}]"
        if not isinstance(b, dict):
            errors.append(f"{where} must be a mapping")
            continue
        for key in b.keys() - {"scope", "usd", "period", "match"}:
            errors.append(f"{where}: unknown setting {key!r}")
        if b.get("scope") not in SCOPES:
            errors.append(f"{where}.scope must be one of {', '.join(SCOPES)}")
        usd = b.get("usd")
        if isinstance(usd, bool) or not isinstance(usd, (int, float)) or usd < 0:
            errors.append(f"{where}.usd must be a number >= 0")
        if "period" in b and (b.get("scope") == "session" or b["period"] not in PERIODS):
            errors.append(f"{where}.period must be one of {', '.join(PERIODS)} "
                          "(a session budget has no period)")
        if "match" in b and (b.get("scope") not in ("agent", "user")
                             or not isinstance(b["match"], str) or not b["match"].strip()):
            errors.append(f"{where}.match names one agent or user (scope agent or user only)")
    return errors


def model_report(models: Optional[Dict[str, Any]], model: str) -> Optional[Dict[str, Any]]:
    """{model, allowed, reason}, or None when no list applies or the model is unknown."""
    if not models or not model:
        return None
    from prismor.runtime.pricing import normalize_model

    names = {model.lower(), normalize_model(model)}

    def hit(globs: List[str]) -> Optional[str]:
        return next((g for g in globs for n in names if fnmatch.fnmatchcase(n, g.lower())), None)

    denied = hit(models.get("deny") or [])
    if denied:
        return {"model": model, "allowed": False, "reason": f"matches deny {denied!r}", "error": None}
    allow = models.get("allow")
    if allow is not None and not hit(allow):
        return {"model": model, "allowed": False, "reason": "not on the allow list", "error": None}
    return {"model": model, "allowed": True, "reason": "", "error": None}


def period_start(period: str, now: Optional[datetime] = None) -> datetime:
    now = now or datetime.now(timezone.utc)
    day = now.replace(hour=0, minute=0, second=0, microsecond=0)
    if period == "daily":
        return day
    if period == "weekly":
        return day - timedelta(days=day.weekday())
    return day.replace(day=1)


def _connect():
    """The shared store read-only; an empty one when nothing was recorded yet
    (no spend is $0, not "unavailable"). None when it exists but cannot open."""
    from prismor.runtime.store import _connect_ro, prismor_home
    path = prismor_home() / "prismor.db"
    if path.exists():
        conn = _connect_ro(path)
    else:
        conn = sqlite3.connect(":memory:")
        conn.execute("CREATE TABLE token_usage (session_id TEXT, ts TEXT, model TEXT, input_tokens INTEGER,"
                     " output_tokens INTEGER, cache_read_tokens INTEGER, cache_creation_tokens INTEGER,"
                     " cache_1h_tokens INTEGER, reported_cost_usd REAL, agent TEXT, subject TEXT,"
                     " latency_ms INTEGER)")
    if conn is not None:
        conn.row_factory = sqlite3.Row
    return conn


def spend(conn: Any, scope: str, value: str, since: Optional[str]) -> float:
    """USD spent by one seat. Provider-reported cost wins, then list price,
    then UNKNOWN_RATE. ``since`` (ISO, UTC) is ignored for a session."""
    from prismor.runtime.pricing import price_for, request_cost

    where, params = [], []
    if scope == "session":
        where.append("session_id = ?")
        params.append(value)
    else:
        if scope in ("agent", "user"):
            where.append(("agent" if scope == "agent" else "subject") + " = ?")
            params.append(value)
        where.append("ts >= ?")
        params.append(since or "")
    sql = ("SELECT model, COALESCE(input_tokens,0) AS input, COALESCE(output_tokens,0) AS output,"
           " COALESCE(cache_read_tokens,0) AS cache_read,"
           " COALESCE(cache_creation_tokens,0) - COALESCE(cache_1h_tokens,0) AS cache_5m,"
           " COALESCE(cache_1h_tokens,0) AS cache_1h, reported_cost_usd AS reported"
           " FROM token_usage WHERE " + " AND ".join(where))  # nosec B608 - fixed column names only
    rates: Dict[str, Dict[str, Any]] = {}
    total = 0.0
    for r in conn.execute(sql, params):
        if r["reported"] is not None:
            total += float(r["reported"])
            continue
        model = r["model"] or ""
        if model not in rates:
            # fetch=False: never a network round-trip inside a hook
            rates[model] = price_for(model, fetch=False) or UNKNOWN_RATE
        total += request_cost(dict(r), rates[model])
    return total


def budget_report(budgets: Optional[List[Dict[str, Any]]], *, session_id: str,
                  agent: str, user: str) -> Optional[Dict[str, Any]]:
    """The tightest applicable budget: {scope, seat, period, limit, used,
    remaining, error}. None when no budget applies.

    Without a verified user id, ``scope: user`` counts the device's spend: on
    a hooked machine the device is the user."""
    if not budgets:
        return None
    seats = {"session": session_id, "agent": agent, "user": user or "this device", "device": "this device"}
    applicable = [b for b in budgets if seats.get(b["scope"]) and b.get("match") in (
        None, user if b["scope"] == "user" else seats[b["scope"]])]
    if not applicable:
        return None
    conn = _connect()
    if conn is None:
        return {"scope": applicable[0]["scope"], "seat": seats[applicable[0]["scope"]],
                "period": None, "limit": float(applicable[0]["usd"]), "used": 0.0,
                "remaining": 0.0, "error": "spend store unavailable"}
    worst: Optional[Dict[str, Any]] = None
    try:
        for b in applicable:
            scope = b["scope"]
            period = None if scope == "session" else b.get("period", "monthly")
            since = period_start(period).isoformat() if period else None
            counted = "device" if scope == "user" and not user else scope
            used = spend(conn, counted, seats[scope], since)
            limit = float(b["usd"])
            report = {"scope": scope, "seat": seats[scope], "period": period, "limit": limit,
                      "used": round(used, 6), "remaining": round(max(0.0, limit - used), 6),
                      "error": None}
            ratio = used / limit if limit else float("inf")
            if worst is None or ratio > worst["_ratio"]:
                worst = {**report, "_ratio": ratio}
    except Exception as exc:
        return {"scope": applicable[0]["scope"], "seat": seats[applicable[0]["scope"]],
                "period": None, "limit": float(applicable[0]["usd"]), "used": 0.0,
                "remaining": 0.0, "error": f"spend accounting failed: {exc}"}
    finally:
        conn.close()
    worst.pop("_ratio")
    return worst


def session_model(session_id: str) -> str:
    """The model a hooked session last used (hooks carry no model per call)."""
    conn = _connect()
    if conn is None or not session_id:
        return ""
    try:
        row = conn.execute("SELECT model FROM token_usage WHERE session_id = ? AND model != ''"
                           " ORDER BY ts DESC LIMIT 1", (session_id,)).fetchone()
        return row["model"] if row else ""
    except Exception:
        return ""
    finally:
        conn.close()


def status(budgets: Optional[List[Dict[str, Any]]], *, agent: str = "", user: str = "") -> Dict[str, Any]:
    """Every configured budget with this device's spend, for `prismor spend status`."""
    out: Dict[str, Any] = {"configured": bool(budgets), "budgets": [], "error": None}
    conn = _connect()
    if conn is None:
        out["error"] = "spend store unavailable" if budgets else None
        return out
    try:
        for b in budgets or []:
            scope = b["scope"]
            period = None if scope == "session" else b.get("period", "monthly")
            since = period_start(period).isoformat() if period else None
            seat = b.get("match") or {"agent": agent, "user": user}.get(scope, "")
            row = {"scope": scope, "period": period, "match": b.get("match"), "limit": float(b["usd"])}
            if scope == "session":
                # ponytail: prices the 200 most recent sessions; enough for one device's view
                recent = [r["session_id"] for r in conn.execute(
                    "SELECT session_id FROM token_usage GROUP BY session_id ORDER BY MAX(ts) DESC LIMIT 200")]
                row["top"] = sorted(({"session": sid, "used": round(spend(conn, "session", sid, None), 4)}
                                     for sid in recent), key=lambda x: -x["used"])[:5]
            elif scope in ("agent", "user") and not seat:
                col = "agent" if scope == "agent" else "subject"
                seats = [r[0] for r in conn.execute(
                    f"SELECT DISTINCT {col} FROM token_usage WHERE ts >= ? AND {col} IS NOT NULL",  # nosec B608
                    (since,))]
                row["top"] = sorted(({"seat": s, "used": round(spend(conn, scope, s, since), 4)} for s in seats),
                                    key=lambda x: -x["used"])[:5]
                if scope == "user" and not seats:
                    row["used"] = round(spend(conn, "device", "", since), 4)
            else:
                row["used"] = round(spend(conn, "device" if scope == "device" else scope, seat, since), 4)
            out["budgets"].append(row)
    except Exception as exc:
        out["error"] = f"spend accounting failed: {exc}"
    finally:
        conn.close()
    return out


def summary(budgets: Optional[List[Dict[str, Any]]], days: int = 30) -> Dict[str, Any]:
    """Spend today, this month and per model over ``days``, for the Logs page."""
    from prismor.runtime.pricing import price_for, request_cost

    now = datetime.now(timezone.utc)
    today, month = period_start("daily", now), period_start("monthly", now)
    since = min(month, now - timedelta(days=max(1, days)))
    out: Dict[str, Any] = {"today": 0.0, "month": 0.0, "days": days, "models": [], "budgets": [],
                           "configured": bool(budgets), "error": None}
    conn = _connect()
    if conn is None:
        return out
    by_model: Dict[str, Dict[str, Any]] = {}
    rates: Dict[str, Dict[str, Any]] = {}
    window = (now - timedelta(days=max(1, days))).isoformat()
    try:
        for r in conn.execute(
                "SELECT ts, model, COALESCE(input_tokens,0) AS input, COALESCE(output_tokens,0) AS output,"
                " COALESCE(cache_read_tokens,0) AS cache_read,"
                " COALESCE(cache_creation_tokens,0) - COALESCE(cache_1h_tokens,0) AS cache_5m,"
                " COALESCE(cache_1h_tokens,0) AS cache_1h, reported_cost_usd AS reported, latency_ms"
                " FROM token_usage WHERE ts >= ?", (since.isoformat(),)):
            model = r["model"] or "unknown"
            if r["reported"] is not None:
                usd = float(r["reported"])
            else:
                if model not in rates:
                    rates[model] = price_for(model, fetch=False) or UNKNOWN_RATE
                usd = request_cost(dict(r), rates[model])
            ts = r["ts"] or ""
            if ts >= today.isoformat():
                out["today"] += usd
            if ts >= month.isoformat():
                out["month"] += usd
            if ts < window:
                continue
            m = by_model.setdefault(model, {"model": model, "requests": 0, "tokens": 0, "usd": 0.0,
                                            "_lat": [], "unpriced": rates.get(model) is UNKNOWN_RATE})
            m["requests"] += 1
            m["tokens"] += r["input"] + r["output"] + r["cache_read"] + r["cache_5m"] + r["cache_1h"]
            m["usd"] += usd
            if r["latency_ms"] is not None:
                m["_lat"].append(int(r["latency_ms"]))
    except Exception as exc:
        out["error"] = f"spend accounting failed: {exc}"
    finally:
        conn.close()
    for m in by_model.values():
        lat = sorted(m.pop("_lat"))
        m["latency_ms"] = lat[len(lat) // 2] if lat else None
        m["usd"] = round(m["usd"], 4)
    out["models"] = sorted(by_model.values(), key=lambda m: -m["usd"])
    out["today"], out["month"] = round(out["today"], 4), round(out["month"], 4)
    if budgets:
        st = status(budgets)
        out["budgets"], out["error"] = st["budgets"], out["error"] or st["error"]
    return out
