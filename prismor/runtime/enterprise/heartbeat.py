"""Per-tool-call volume heartbeat — makes "tool calls inspected" a real number.

Findings-only telemetry tells the org what was *flagged*; it says nothing about
how much the agent actually did. This module counts every hook-dispatched tool
call locally and, at most once per ``FLUSH_INTERVAL`` seconds, uploads one
``agent_activity`` record *per agent instance* carrying the accumulated count.
The control plane sums the ``count`` column for the "tool calls inspected" KPI.

Counts are keyed per agent instance (``<framework>|<name>``) so a fleet of many
agents on the same framework reports separate volume — "checkout-bot did 400
calls, support-bot did 30" — instead of one indistinguishable device total. An
unnamed agent uses the empty name (key ``<framework>|``).

Privacy: the heartbeat carries *only* a number plus the same metadata enums as
any redacted record (agent id, agent name, session id). No commands, paths, or
content — it is volume, not activity detail.

Cost: one lock-guarded JSON read/write per tool call (sub-millisecond) and one
HTTP POST per minute at most, with the same short-timeout + offline-spool
semantics as finding telemetry (prismor/runtime/sinks.upload_telemetry). Failures never
raise into the hook path.
"""
from __future__ import annotations

import atexit
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from prismor.runtime.enterprise import identity as _identity

FLUSH_INTERVAL = 60.0
# How often a device_status record (version, install kind, per-agent hook
# coverage) rides along with a flush. The console's coverage view and
# version-drift tile read it; hourly is plenty for both.
STATUS_INTERVAL = 3600.0


def device_status_record() -> Dict[str, Any]:
    """What the console needs to answer "is this machine covered?": the
    running version, whether it is a system (every-user) or per-user install,
    and for each agent found on the machine whether a Prismor hook covers it
    machine-wide. Agent names only; no paths, commands or user data."""
    import platform
    import uuid
    from prismor.runtime import __version__, system_install
    from prismor.runtime.hooks import SYSTEM_HOOK_PATHS, coverage, hook_installed
    home = Path.home()
    agents: Dict[str, Any] = {}
    # An agent key is a workload, not a machine. Scanning here reported the
    # host's hooks under the key's name: the Cowork plugin, run by the desktop
    # app on a laptop, counted that laptop a second time.
    scan = _identity._env_identity() is None
    try:
        for agent, cov in (coverage(home).items() if scan else ()):
            system = agent in SYSTEM_HOOK_PATHS and hook_installed(agent, "system", home)
            via = "system" if system else ("global" if cov.get("global") and not cov.get("foreign")
                                           else ("project" if cov.get("project") else None))
            # Project-only hooks guard one repo, so they don't count as covering the machine.
            agents[agent] = {"covered": via in ("system", "global"), "via": via}
    except Exception:
        pass
    return {
        "schema": "prismor.runtime.telemetry.v1",
        "event_id": "evt_" + uuid.uuid4().hex,
        "ts": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "type": "device_status",
        "verdict": "observed",
        "title": "Device status",
        "redacted": True,
        "detail": {
            "prismor_version": __version__,
            "install": "system" if system_install.is_system_managed() else "user",
            "platform": platform.system().lower(),
            **({"agents": agents,
                "unguarded": sorted(a for a, v in agents.items() if not v["covered"])} if scan else {}),
        },
    }

# Bound the counter file + flush fan-out. A single device running >64 distinct
# agent instances is not a real topology (instances spread across a fleet of
# devices); overflow folds into the framework-level key so volume is never lost,
# only its per-instance attribution past the cap.
MAX_COUNTER_KEYS = 64

# Exit flush: short, so a dead control plane can't hold the process open long.
EXIT_FLUSH_TIMEOUT = 3.0

_exit_flush_registered = False


def _counter_path() -> Path:
    return _identity.prismor_home() / "heartbeat.json"


def _counter_key(agent: Optional[str], agent_name: Optional[str]) -> str:
    return f"{agent or ''}|{agent_name or ''}"


def _load(path: Path) -> Dict[str, Any]:
    """Load the counter file, migrating the v1 flat shape to v2 keyed counters.

    v1: {"count": N, "agent": a, "session_id": s, "last_flush": t}
    v2: {"v": 2, "last_flush": t, "counters": {"<framework>|<name>": {count, session_id}}}
    """
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"v": 2, "last_flush": time.time(), "counters": {}}
    if not isinstance(data, dict):
        return {"v": 2, "last_flush": time.time(), "counters": {}}
    if data.get("v") == 2 and isinstance(data.get("counters"), dict):
        return data
    # Migrate v1 → v2: fold the flat counter into a single framework-level key.
    counters: Dict[str, Any] = {}
    count = int(data.get("count", 0) or 0)
    if count > 0:
        key = _counter_key(data.get("agent"), "")
        counters[key] = {"count": count, "session_id": data.get("session_id")}
    return {"v": 2, "last_flush": float(data.get("last_flush", time.time())), "counters": counters}


def record_call(
    agent: Optional[str] = None,
    session_id: Optional[str] = None,
    agent_name: Optional[str] = None,
) -> None:
    """Count one inspected tool call for one agent instance. Never raises; no-op
    when not enrolled."""
    if not _identity.is_enrolled():
        return
    path = _counter_path()
    try:
        from prismor.runtime.store import file_lock
        path.parent.mkdir(parents=True, exist_ok=True)
        with file_lock(path):
            data = _load(path)
            counters: Dict[str, Any] = data.setdefault("counters", {})
            key = _counter_key(agent, agent_name)
            # Cap: an instance past the limit folds into the framework key so
            # its volume still counts, bounding file size and flush fan-out.
            if key not in counters and len(counters) >= MAX_COUNTER_KEYS:
                key = _counter_key(agent, "")
            slot = counters.setdefault(key, {"count": 0, "session_id": None})
            slot["count"] = int(slot.get("count", 0)) + 1
            if session_id:
                slot["session_id"] = session_id
            data.setdefault("last_flush", time.time())
            data["v"] = 2
            path.write_text(json.dumps(data), encoding="utf-8")
            try:  # audit #18: keep session metadata 0600, not world-readable
                path.chmod(0o600)
            except OSError:
                pass
    except OSError:
        pass


def maybe_flush(now: Optional[float] = None, force: bool = False, timeout: float = 6.0) -> bool:
    """Upload the accumulated counts as one agent_activity record *per agent
    instance*, at most once per FLUSH_INTERVAL. Returns True if a flush was
    attempted. Never raises.

    Counters are reset *before* the upload; on failure the records land in the
    offline spool (see sinks.upload_telemetry), so counts are never lost and
    never double-sent. All per-instance records ship in one batched upload.
    ``force`` skips the interval (process exit).
    """
    ident = _identity.load_identity()
    if not ident or _identity.revoked_backoff_active():
        return False

    path = _counter_path()
    records: list = []
    try:
        from prismor.runtime.store import file_lock
        if not path.exists():
            return False
        with file_lock(path):
            data = _load(path)
            counters: Dict[str, Any] = data.get("counters", {}) or {}
            last = float(data.get("last_flush", 0))
            last_status = float(data.get("last_status", 0))
            t = time.time() if now is None else now
            if not force and (t - last) < FLUSH_INTERVAL:
                return False
            send_status = (t - last_status) >= STATUS_INTERVAL
            import uuid
            for key, slot in counters.items():
                count = int(slot.get("count", 0))
                if count <= 0:
                    continue
                agent, _, agent_name = key.partition("|")
                rec = {
                    "schema": "prismor.runtime.telemetry.v1",
                    "event_id": "evt_" + uuid.uuid4().hex,
                    "ts": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                    "type": "agent_activity",
                    "verdict": "observed",
                    "title": "Agent activity heartbeat",
                    "agent": agent or None,
                    "session_id": slot.get("session_id"),
                    "count": count,
                    "redacted": True,
                }
                if agent_name:
                    rec["agent_name"] = agent_name
                records.append(rec)
            # Reset all counters, keep the flush (and status) timestamps.
            path.write_text(
                json.dumps({"v": 2, "last_flush": t, "counters": {},
                            "last_status": t if send_status else last_status}), encoding="utf-8"
            )
            try:  # audit #18
                path.chmod(0o600)
            except OSError:
                pass
    except (OSError, ValueError):
        return False

    if send_status:
        try:
            records.append(device_status_record())
        except Exception:
            pass  # status is bookkeeping; never let it cost the heartbeat
    # Always call through, even with no counts of our own: upload_telemetry
    # drains the telemetry spool, and findings now ride that spool instead of
    # one POST each. This tick is what ships them.
    try:
        from prismor.runtime.sinks import upload_telemetry
        upload_telemetry(records, timeout=timeout)
    except Exception as exc:  # spooled by upload_telemetry; just note it
        sys.stderr.write(f"[prismor] heartbeat upload deferred: {exc}\n")
    return True


def flush_at_exit() -> None:
    """Flush counts and spooled findings when this process exits.

    For long-lived callers (SDK adapters, eval-server): a script that finishes
    inside the first FLUSH_INTERVAL would otherwise leave its activity on disk
    until some later call on this device, which for an ephemeral container is
    never. Registered once per process. Hook-dispatch (one process per tool
    call) must not use this, or every call becomes a POST.
    """
    global _exit_flush_registered
    if _exit_flush_registered:
        return
    _exit_flush_registered = True
    # ponytail: atexit misses SIGTERM/SIGKILL (a plain `docker stop`); add a
    # signal hook only if deployed agents report missing tails.
    atexit.register(maybe_flush, force=True, timeout=EXIT_FLUSH_TIMEOUT)
