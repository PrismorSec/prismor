"""Local pause/resume for the Prismor runtime.

`prismor pause` suspends local ENFORCEMENT only, WITHOUT uninstalling the
hooks — observe-mode screening/telemetry keeps running as normal, so nothing
goes dark. Auto-resumes after 24h (or a custom `--for` window) unless started
via `prismor pause-hard`, which pauses indefinitely until `prismor resume`.
A lightweight heartbeat keeps emitting the whole time so the control plane
shows the machine as *paused* — a deliberate, attributable state — rather
than letting it silently go idle, which is the failure mode of just deleting
the hooks (indistinguishable from a closed laptop).

State lives in a single JSON marker at ``~/.prismor/pause.json``, mirroring the
revocation-marker pattern in ``enterprise/identity.py``. A ``--for`` window
makes the pause self-expire (checked on the hot path in :func:`active_state`),
so protection heals itself even if ``prismor resume`` is never run.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

_SCHEMA = "prismor.runtime.pause.v1"

# The paused heartbeat is emitted on user-turn boundaries (a prompt submit),
# NOT on a timer — see hook-dispatch. This is only a floor so several quick
# messages in a row still coalesce to one "still paused" beat rather than one
# each; an idle paused machine emits nothing.
_BEAT_DEBOUNCE_SECONDS = 60.0


def prismor_home() -> Path:
    """Return the Prismor home dir, honoring $PRISMOR_HOME (default ~/.prismor)."""
    return Path(os.environ.get("PRISMOR_HOME", str(Path.home() / ".prismor")))


def pause_path() -> Path:
    from prismor.runtime import system_install
    return system_install.policy_home() / "pause.json"


def _key_path() -> Path:
    return pause_path().parent / "pause.key"


_MAC_FIELDS = ("schema", "paused", "hard", "at", "until", "reason", "by")


def _existing_key() -> Optional[bytes]:
    """The pause MAC key, or None. Never creates one (a missing key means an
    unsigned marker is ignored)."""
    try:
        raw = _key_path().read_bytes()
    except OSError:
        return None
    return raw if len(raw) == 32 else None


def _ensure_key() -> bytes:
    key = _existing_key()
    if key is not None:
        return key
    from prismor.runtime import system_install
    path = _key_path()
    # A system install writes the marker as root and the user's hook reads it,
    # so the key takes the shared file mode there. The user still cannot write
    # that directory, which is what keeps a marker from being forged.
    if system_install.is_system_managed():
        system_install.mkdir_public(path.parent)
        mode = system_install.shared_file_mode()
    else:
        path.parent.mkdir(parents=True, exist_ok=True)
        mode = 0o600
    fresh = secrets.token_bytes(32)
    # O_EXCL so two writers don't each sign with a key the other just replaced.
    try:
        fd = os.open(str(path), os.O_CREAT | os.O_EXCL | os.O_WRONLY, mode)
    except FileExistsError:
        key = _existing_key()
        if key is None:
            raise
        return key
    try:
        os.write(fd, fresh)
        if hasattr(os, "fchmod"):  # the umask can strip bits from the open() mode
            os.fchmod(fd, mode)
    finally:
        os.close(fd)
    return fresh


def _mac(record: Dict[str, Any], key: bytes) -> str:
    body = {k: record.get(k) for k in _MAC_FIELDS}
    blob = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hmac.new(key, blob, hashlib.sha256).hexdigest()


def parse_duration(text: str) -> int:
    """Parse a human duration into seconds: ``30m`` / ``2h`` / ``90s`` / ``1d``.
    A bare number is read as minutes. Raises ``ValueError`` on anything else."""
    s = (text or "").strip().lower()
    if not s:
        raise ValueError("empty duration")
    units = {"s": 1, "m": 60, "h": 3600, "d": 86400}
    if s[-1] in units:
        value = float(s[:-1])  # raises ValueError on garbage like "abcm"
        return int(value * units[s[-1]])
    return int(float(s) * 60)  # bare number = minutes


def _now() -> float:
    return time.time()


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat().replace("+00:00", "Z")


_DEFAULT_DURATION_SECONDS = 86400  # `prismor pause` auto-resumes after 24h unless --for overrides it


def set_paused(duration_seconds: Optional[int] = None, reason: str = "", by: str = "", hard: bool = False) -> Dict[str, Any]:
    """Write the pause marker. ``hard=True`` (from `prismor pause-hard`) pauses
    indefinitely; otherwise defaults to 24h unless ``duration_seconds`` overrides
    it. Enforcement only — observe-mode screening/telemetry stays on regardless.
    Returns the record written."""
    now = _now()
    if hard:
        until = None
    else:
        until = now + (duration_seconds if duration_seconds else _DEFAULT_DURATION_SECONDS)
    record: Dict[str, Any] = {
        "schema": _SCHEMA,
        "paused": True,
        "hard": hard,
        "at": now,
        "until": until,
        "reason": (reason or "")[:300],
        "by": (by or "")[:120],
        "last_beat": 0.0,
    }
    record["mac"] = _mac(record, _ensure_key())
    from prismor.runtime import system_install
    system_install.write_shared(pause_path(), json.dumps(record, indent=2))
    return record


def clear_paused() -> bool:
    """Remove the pause marker (resume). Returns True if one existed. Never raises."""
    path = pause_path()
    try:
        if path.exists():
            path.unlink()
            return True
    except OSError:
        pass
    return False


def beat_resumed(agent: Optional[str] = None) -> bool:
    """Tell the control plane this machine just resumed, so the console clears
    the *paused* badge immediately instead of waiting for the next real tool
    call. The ingest endpoint clears ``pausedAt`` on any event whose type
    isn't ``paused_heartbeat`` — this sends exactly that, with no local
    debounce, since a resume is a one-off user action, not a hot-path event.
    No-op when not enrolled or on any error. Returns True iff it uploaded."""
    try:
        from prismor.runtime.enterprise import identity as _identity
        if not _identity.is_enrolled():
            return False
    except Exception:
        return False

    now = _now()
    record = {
        "schema": "prismor.runtime.telemetry.v1",
        "event_id": "evt_" + uuid.uuid4().hex,
        "ts": _iso(now),
        "type": "resumed_heartbeat",
        "verdict": "observed",
        "title": "Prismor resumed locally",
        "agent": agent or None,
        "count": 1,
        "redacted": True,
        "detail": {"resumed": True},
    }
    try:
        from prismor.runtime.sinks import upload_telemetry
        upload_telemetry([record])
        return True
    except Exception:
        return False


def _read_raw() -> Optional[Dict[str, Any]]:
    try:
        data = json.loads(pause_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict) or not data.get("paused"):
        return None
    # A hand-written {"paused": true} used to skip the deny. Only a marker
    # set_paused signed with pause.key counts. A missing or swapped key does
    # not: we never create the key on read.
    key = _existing_key()
    mac = data.get("mac")
    if key is None or not isinstance(mac, str):
        return None
    try:
        ok = hmac.compare_digest(mac, _mac(data, key))
    except (TypeError, ValueError):
        return None
    return data if ok else None


def _parse_iso(text: Any) -> Optional[float]:
    """Epoch seconds from an ISO-8601 timestamp, or None. Accepts the trailing
    ``Z`` the control plane emits, which fromisoformat rejects before 3.11."""
    if not isinstance(text, str) or not text:
        return None
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def org_state() -> Optional[Dict[str, Any]]:
    """The org's pause/resume for this machine from the cached SIGNED policy,
    normalized to the same shape as a local marker, or None.

    Only ever read from a verified policy (see remote_policy.remote_pause), so
    an unsigned or tampered file can't talk this machine out of enforcing. An
    org pause past its ``until`` resolves to None — protection heals itself even
    if nobody clears it in the console."""
    try:
        from prismor.runtime.enterprise import remote_policy as _remote
        rec = _remote.remote_pause()
    except Exception:
        return None
    if not rec:
        return None
    at = _parse_iso(rec.get("at"))
    if at is None:
        return None
    state = rec.get("state")
    until = _parse_iso(rec.get("until"))
    if state == "paused" and until is not None and _now() >= until:
        return None
    return {
        "schema": _SCHEMA,
        "paused": state == "paused",
        "state": state,
        "source": "org",
        "hard": until is None,
        "at": at,
        "until": until,
        "reason": rec.get("reason") or "",
        "by": rec.get("by") or "",
    }


def active_state() -> Optional[Dict[str, Any]]:
    """The pause record if enforcement is currently paused on this machine,
    else None. Never raises.

    Two sources, resolved by timestamp:

    * An ORG pause (pushed from the console) wins outright. ``prismor resume``
      cannot lift it — same precedence as the org agent kill switch, where a
      local re-enable can't override a fleet-wide disable.
    * An ORG resume clears a local pause marker OLDER than it, so an admin can
      bring back a machine they have no shell access to. A later local
      ``prismor pause`` still wins, so developers keep the ability to pause
      their own box.

    A local ``--for`` window that has elapsed clears the marker (auto-resume)
    and returns None, so the caller falls through to normal screening.
    """
    org = org_state()
    if org is not None and org.get("paused"):
        return org

    rec = _read_raw()
    if rec is None:
        return None
    until = rec.get("until")
    if until is not None:
        try:
            if _now() >= float(until):
                clear_paused()
                return None
        except (TypeError, ValueError):
            pass

    # An org resume issued after this marker was written overrides it. Clear the
    # marker rather than just ignoring it, so the machine converges on one
    # answer and `prismor status` doesn't keep claiming a pause that isn't
    # in effect.
    if org is not None and org.get("state") == "resumed":
        try:
            local_at = float(rec.get("at") or 0)
        except (TypeError, ValueError):
            local_at = 0.0
        if float(org.get("at") or 0) >= local_at:
            clear_paused()
            return None

    rec.setdefault("source", "local")
    return rec


def is_paused() -> bool:
    return active_state() is not None


def beat(agent: Optional[str] = None, state: Optional[Dict[str, Any]] = None) -> bool:
    """Emit a debounced "paused" heartbeat so the control plane keeps this
    device's ``lastSeenAt`` fresh and flags it as paused. No-op when not
    enrolled, inside the debounce window, or on any error. Returns True iff it
    uploaded a record."""
    rec = state or active_state()
    if rec is None:
        return False
    # An ORG pause came FROM the control plane, so reporting it back tells it
    # nothing it doesn't already know — and there's no local marker to stamp
    # last_beat onto, so every call would re-upload. Normal screening telemetry
    # keeps lastSeenAt fresh in that case.
    if rec.get("source") == "org":
        return False
    now = _now()
    try:
        last_beat = float(rec.get("last_beat") or 0)
    except (TypeError, ValueError):
        last_beat = 0.0
    if now - last_beat < _BEAT_DEBOUNCE_SECONDS:
        return False

    # Gate on enrollment before any network work — a personal (unenrolled)
    # machine reports nowhere, so there's nothing to heartbeat.
    try:
        from prismor.runtime.enterprise import identity as _identity
        if not _identity.is_enrolled():
            return False
    except Exception:
        return False

    until = rec.get("until")
    record = {
        "schema": "prismor.runtime.telemetry.v1",
        "event_id": "evt_" + uuid.uuid4().hex,
        "ts": _iso(now),
        "type": "paused_heartbeat",
        "verdict": "observed",
        "title": "Prismor paused locally",
        "agent": agent or None,
        "count": 1,
        "redacted": True,
        "detail": {
            "paused": True,
            "pausedAt": _iso(float(rec.get("at") or now)),
            "pausedUntil": _iso(float(until)) if until else None,
            "reason": rec.get("reason") or None,
        },
    }
    try:
        from prismor.runtime.sinks import upload_telemetry
        upload_telemetry([record])
    except Exception:
        return False

    # Note the beat so the next tool calls stay debounced. Best-effort: a write
    # failure just means we heartbeat again sooner, which is harmless.
    try:
        rec["last_beat"] = now
        from prismor.runtime import system_install
        system_install.write_shared(pause_path(), json.dumps(rec, indent=2))
    except OSError:
        pass
    return True
