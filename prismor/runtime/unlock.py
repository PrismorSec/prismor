"""Password-gated self-edit window.

Prismor blocks an agent from editing its own policy (see the self-protection
rules in ``default_policy.yaml``). That is the right default and a bad absolute:
sometimes the honest answer to a block really is "add an exception", and making
the human retype the agent's work by hand is how a security tool becomes the
thing people route around.

So the block lifts, briefly, when a human proves they are present:

    prismor unlock            # asks for the password, opens ~3 minutes
    prismor lock              # close it early

Inside the window the agent may run `prismor allow` and friends. Outside it,
every route is blocked. The window closes on its own — an expiry that has
lapsed resolves to "closed" and deletes the marker, so a forgotten unlock heals
instead of quietly becoming a permanent hole (the same self-healing shape as
``pause.py``).

**What this is and isn't.** The agent runs as the same user as the human, so
file permissions stop nothing on their own and the grant MAC below is a
speed bump, not a wall. The real boundary is that agent actions go through
hooks, so the credential is unreadable to the agent (reading it is itself a
blocked route) and the grant only means anything to code running on the hook
path. An agent that bypasses hooks entirely was never governed by Prismor and
is not governed by this either.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

_CRED_SCHEMA = "prismor.unlock.v1"
_GRANT_SCHEMA = "prismor.unlock-grant.v1"

# Three minutes: long enough for an agent to make the edit it just asked for,
# short enough that walking away from the keyboard closes it.
DEFAULT_WINDOW_SECONDS = 180
MAX_WINDOW_SECONDS = 3600

# scrypt, not a bare SHA-256: this is a human-chosen password, and the file it
# lives in is readable by anything running as the user. Cost parameters are the
# usual interactive-login figures (~100ms, 16MB).
_SCRYPT_N = 2 ** 14
_SCRYPT_R = 8
_SCRYPT_P = 1
_KEY_LEN = 32

# Failed attempts back off exponentially from the 5th, capped at an hour, so
# guessing costs time. Stored in the same file the guesser would have to be
# able to write anyway.
_FREE_ATTEMPTS = 5
_MAX_LOCKOUT_SECONDS = 3600


def prismor_home() -> Path:
    """Prismor home dir, honoring $PRISMOR_HOME (default ~/.prismor). On a
    system install this is /etc/prismor: only root may set the password or
    open a window, so a user can't unlock their own screening."""
    from prismor.runtime import system_install
    return system_install.policy_home()


def credential_path() -> Path:
    # Deliberately not inside identity.json: enrolling, unenrolling and device
    # revocation all rewrite that file, and none of them should cost the user
    # their unlock password.
    return prismor_home() / "unlock.json"


def grant_path() -> Path:
    return prismor_home() / "unlock-grant.json"


def _now() -> float:
    return time.time()


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat().replace("+00:00", "Z")


def _write_private(path: Path, record: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(record, indent=2), encoding="utf-8")
    try:
        path.chmod(0o600)
    except OSError:
        pass


def _read(path: Path) -> Optional[Dict[str, Any]]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else None
    except (OSError, ValueError):
        return None


# ── credential ───────────────────────────────────────────────────────────────

def _derive(password: str, salt: bytes) -> bytes:
    return hashlib.scrypt(
        password.encode("utf-8"), salt=salt,
        n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P, dklen=_KEY_LEN,
    )


def is_configured() -> bool:
    rec = _read(credential_path())
    return bool(rec and rec.get("schema") == _CRED_SCHEMA)


def method() -> Optional[str]:
    """"passphrase", "system", or None when unlock is not set up."""
    rec = _read(credential_path())
    return rec.get("method") if rec else None


def set_password(
    password: str,
    *,
    window_seconds: int = DEFAULT_WINDOW_SECONDS,
    system: bool = False,
) -> Dict[str, Any]:
    """Store the unlock credential.

    ``system=True`` records that unlocking should be verified against the
    operating system's own account password instead — nothing derived from a
    password is stored in that case, because there is nothing we should keep.
    """
    record: Dict[str, Any] = {
        "schema": _CRED_SCHEMA,
        "method": "system" if system else "passphrase",
        "created_at": _iso(_now()),
        "window_seconds": max(30, min(int(window_seconds), MAX_WINDOW_SECONDS)),
        "failed_attempts": 0,
        "locked_until": None,
    }
    if not system:
        salt = secrets.token_bytes(16)
        record.update({
            "kdf": "scrypt",
            "n": _SCRYPT_N, "r": _SCRYPT_R, "p": _SCRYPT_P,
            "salt": base64.b64encode(salt).decode(),
            "hash": base64.b64encode(_derive(password, salt)).decode(),
        })
    _write_private(credential_path(), record)
    return record


def clear_password() -> bool:
    """Forget the credential and close any open window."""
    close_window()
    try:
        if credential_path().exists():
            credential_path().unlink()
            return True
    except OSError:
        pass
    return False


def lockout_remaining() -> int:
    """Seconds until guessing is allowed again (0 when not locked out)."""
    rec = _read(credential_path())
    if not rec:
        return 0
    until = rec.get("locked_until")
    if not until:
        return 0
    try:
        return max(0, int(float(until) - _now()))
    except (TypeError, ValueError):
        return 0


def _record_attempt(success: bool) -> None:
    rec = _read(credential_path())
    if not rec:
        return
    if success:
        rec["failed_attempts"] = 0
        rec["locked_until"] = None
    else:
        n = int(rec.get("failed_attempts") or 0) + 1
        rec["failed_attempts"] = n
        if n > _FREE_ATTEMPTS:
            backoff = min(60 * (2 ** (n - _FREE_ATTEMPTS - 1)), _MAX_LOCKOUT_SECONDS)
            rec["locked_until"] = _now() + backoff
    _write_private(credential_path(), rec)


def _verify_system_password(password: str) -> bool:
    """Check a password against the OS account, without ever putting it in argv.

    macOS asks the login keychain (`security -i`), Linux asks sudo. Both read
    the password on stdin. Where neither is available the answer is no — an
    unverifiable "yes" here would be the whole feature undone.
    """
    try:
        if sys.platform == "darwin":
            proc = subprocess.run(
                ["security", "-i", "unlock-keychain"],
                input=f'unlock-keychain -p "{password}"\n'.encode(),
                capture_output=True, timeout=15,
            )
            return proc.returncode == 0
        if sys.platform.startswith("linux"):
            subprocess.run(["sudo", "-k"], capture_output=True, timeout=10)
            proc = subprocess.run(
                ["sudo", "-S", "-v"],
                input=(password + "\n").encode(),
                capture_output=True, timeout=15,
            )
            return proc.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False
    return False


def verify(password: str) -> Tuple[bool, str]:
    """(ok, message). Never raises."""
    rec = _read(credential_path())
    if not rec or rec.get("schema") != _CRED_SCHEMA:
        return False, "No unlock password is set. Run: prismor unlock --set-password"

    wait = lockout_remaining()
    if wait:
        return False, f"Too many failed attempts — try again in {wait}s."

    if rec.get("method") == "system":
        ok = _verify_system_password(password)
    else:
        try:
            salt = base64.b64decode(rec["salt"])
            expected = base64.b64decode(rec["hash"])
            ok = hmac.compare_digest(_derive(password, salt), expected)
        except (KeyError, ValueError, TypeError):
            return False, "The unlock credential is unreadable. Re-run: prismor unlock --set-password"

    _record_attempt(ok)
    return (True, "") if ok else (False, "That password is not right.")


# ── grant ────────────────────────────────────────────────────────────────────

def _grant_key() -> Optional[bytes]:
    """Key for the grant MAC, derived from the stored credential.

    Ties a grant to the credential that authorized it, so a marker written by
    something that never verified a password is rejected. Against a same-user
    attacker who can read the credential file this proves nothing — reading it
    is itself a blocked route, and the hook is the actual boundary.
    """
    rec = _read(credential_path())
    if not rec:
        return None
    material = f"{rec.get('hash') or ''}{rec.get('created_at') or ''}{rec.get('method') or ''}"
    return hashlib.sha256(("prismor-unlock-grant:" + material).encode()).digest()


def _mac(record: Dict[str, Any], key: bytes) -> str:
    payload = json.dumps(
        {k: record.get(k) for k in ("schema", "at", "until", "by", "workspace")},
        sort_keys=True, separators=(",", ":"),
    )
    return hmac.new(key, payload.encode(), hashlib.sha256).hexdigest()


def open_window(
    *,
    duration_seconds: Optional[int] = None,
    workspace: Optional[Path] = None,
    by: str = "",
) -> Dict[str, Any]:
    """Open the self-edit window. Assumes the password has been verified."""
    cred = _read(credential_path()) or {}
    configured = int(cred.get("window_seconds") or DEFAULT_WINDOW_SECONDS)
    seconds = int(duration_seconds) if duration_seconds else configured
    seconds = max(30, min(seconds, org_max_window_seconds() or MAX_WINDOW_SECONDS))

    now = _now()
    record: Dict[str, Any] = {
        "schema": _GRANT_SCHEMA,
        "at": _iso(now),
        "until": _iso(now + seconds),
        "by": (by or os.environ.get("USER") or "")[:120],
        "workspace": str(workspace.resolve()) if workspace else "",
    }
    key = _grant_key()
    if key:
        record["mac"] = _mac(record, key)
    _write_private(grant_path(), record)
    return record


def close_window() -> bool:
    """Close the window early. True if one was open. Never raises."""
    try:
        if grant_path().exists():
            grant_path().unlink()
            return True
    except OSError:
        pass
    return False


def _parse_iso(text: Any) -> Optional[float]:
    if not isinstance(text, str) or not text:
        return None
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def active_state(workspace: Optional[Path] = None) -> Optional[Dict[str, Any]]:
    """The grant if a self-edit window is open right now, else None. Never raises.

    Checked on the hook hot path, so it stays cheap and fails closed: anything
    unparseable, unsigned, expired or scoped to another workspace is "closed".
    """
    if org_self_edit_disabled():
        return None

    rec = _read(grant_path())
    if not rec or rec.get("schema") != _GRANT_SCHEMA:
        return None

    until = _parse_iso(rec.get("until"))
    if until is None or _now() >= until:
        close_window()  # heal rather than linger
        return None

    key = _grant_key()
    if key is None:
        return None
    mac = rec.get("mac")
    if not isinstance(mac, str) or not hmac.compare_digest(mac, _mac(rec, key)):
        return None

    scoped = str(rec.get("workspace") or "")
    if scoped and workspace is not None:
        try:
            if str(workspace.resolve()) != scoped:
                return None
        except OSError:
            return None
    return rec


def is_open(workspace: Optional[Path] = None) -> bool:
    return active_state(workspace) is not None


def remaining_seconds(workspace: Optional[Path] = None) -> int:
    rec = active_state(workspace)
    if not rec:
        return 0
    until = _parse_iso(rec.get("until")) or 0
    return max(0, int(until - _now()))


# ── org controls (served by the control plane, Phase 4) ──────────────────────

def _org_self_edit() -> Dict[str, Any]:
    """``settings.self_edit`` from the cached SIGNED policy, or {}.

    Only ever read from a verified policy — this can only ever *relax*
    enforcement, so an unsigned file must not be able to say anything about it.
    """
    try:
        from prismor.runtime.enterprise import remote_policy as _remote
        rec = _remote.remote_self_edit()
    except Exception:
        return {}
    return rec if isinstance(rec, dict) else {}


def org_self_edit_disabled() -> bool:
    """True when the org has turned self-edit off for this device."""
    rec = _org_self_edit()
    return rec.get("enabled") is False


def org_max_window_seconds() -> Optional[int]:
    """The org's cap on the window, if it set one."""
    rec = _org_self_edit()
    try:
        seconds = int(rec.get("window_seconds"))
    except (TypeError, ValueError):
        return None
    return max(30, min(seconds, MAX_WINDOW_SECONDS)) if seconds > 0 else None
