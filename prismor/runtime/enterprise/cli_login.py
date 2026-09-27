"""`prismor login` — device-authorization sign-in for the Prismor API.

A terminal cannot hold a browser session, so the CLI asks the control plane for a
short code, the human approves that code in a browser they are already signed
into, and the CLI polls until a device key is issued. The short code is what the
human compares against the screen; the long ``device_code`` is the secret the CLI
polls with and is never displayed.

Nothing here raises on a network blip: every call returns a readable RuntimeError
so the command can print one line instead of a traceback.
"""
from __future__ import annotations

import json
import platform as _platform
import socket
import time
import urllib.error
import urllib.request
from typing import Any, Callable, Dict, Optional

from prismor.runtime.enterprise import identity as _identity

_UA = "prismor-cli"


def _post(url: str, body: Dict[str, Any], timeout: float) -> Dict[str, Any]:
    req = urllib.request.Request(
        url, data=json.dumps(body).encode("utf-8"), method="POST",
        headers={"Content-Type": "application/json", "User-Agent": _UA},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # fixed or operator-configured URL  # nosec B310
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = ""
        try:
            detail = json.loads(exc.read().decode("utf-8")).get("message", "")
        except Exception:
            pass
        raise RuntimeError(detail or f"server returned HTTP {exc.code}") from exc
    except (urllib.error.URLError, OSError) as exc:
        raise RuntimeError(f"could not reach {url}: {exc}") from exc
    except ValueError as exc:
        raise RuntimeError("server sent a reply this CLI could not read") from exc


def machine_label() -> str:
    """What the approval screen shows, so the human recognises their own machine."""
    try:
        return socket.gethostname() or "unnamed-device"
    except Exception:
        return "unnamed-device"


def start(base: Optional[str] = None, label: Optional[str] = None,
          timeout: float = 20.0) -> Dict[str, Any]:
    """Ask for a login code. Returns device_code, user_code, verification URIs."""
    from prismor.runtime import __version__ as _ver

    base = (base or _identity.api_base()).rstrip("/")
    data = _post(f"{base}/api/v1/cli/login/start", {
        "label": label or machine_label(),
        "platform": _platform.system(),
        "cli_version": _ver,
    }, timeout)
    if not data.get("device_code") or not data.get("user_code"):
        raise RuntimeError("server did not issue a login code")
    return data


def poll_once(device_code: str, base: Optional[str] = None, timeout: float = 20.0) -> Dict[str, Any]:
    base = (base or _identity.api_base()).rstrip("/")
    return _post(f"{base}/api/v1/cli/login/poll", {"device_code": device_code}, timeout)


def wait_for_approval(device_code: str, base: Optional[str] = None, interval: float = 2.0,
                      expires_in: float = 900.0,
                      on_tick: Optional[Callable[[float], None]] = None) -> Dict[str, Any]:
    """Poll until the human decides. Returns the approved payload, or raises.

    ``on_tick`` is called with seconds waited so the caller can animate; polling
    itself stays here so the UI never drives the network.
    """
    deadline = time.time() + expires_in
    started = time.time()
    while time.time() < deadline:
        data = poll_once(device_code, base=base)
        status = str(data.get("status") or "")
        if status == "approved":
            return data
        if status == "denied":
            raise RuntimeError("the request was denied in the browser")
        if status == "expired":
            raise RuntimeError("the code expired before it was approved")
        if status == "already_claimed":
            raise RuntimeError("that code was already used by another machine")
        if on_tick:
            on_tick(time.time() - started)
        time.sleep(interval)
    raise RuntimeError("timed out waiting for approval")


def save(approved: Dict[str, Any], base: Optional[str] = None) -> Dict[str, Any]:
    """Persist the issued device key as this machine's identity."""
    ident = {
        "device_key": approved["device_key"],
        "device_id": approved.get("device_id"),
        "org_id": (approved.get("org") or {}).get("id"),
        "org_name": (approved.get("org") or {}).get("name"),
        "api_base": (base or _identity.api_base()).rstrip("/"),
    }
    _identity.save_identity(ident)
    return ident


def quota(base: Optional[str] = None, timeout: float = 10.0) -> Optional[Dict[str, Any]]:
    """This month's included judging, or None when it cannot be read."""
    ident = _identity.load_identity()
    if not ident:
        return None
    base = (base or ident.get("api_base") or _identity.api_base()).rstrip("/")
    req = urllib.request.Request(
        f"{base}/api/v1/judge/quota", method="GET",
        headers={"Authorization": f"Bearer {ident.get('device_key')}", "User-Agent": _UA},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # fixed or operator-configured URL  # nosec B310
            return json.loads(resp.read().decode("utf-8"))
    except Exception:
        return None


def run_interactive(base: Optional[str] = None, label: Optional[str] = None,
                    out=None, set_judge_for=None, open_browser: bool = True) -> bool:
    """The whole sign-in, drawn for a terminal. Returns True when connected.

    Shared by ``prismor login`` and the setup wizard's judge step so both show the
    same thing: a code to compare, a link, a wait, then what the machine now has.
    """
    import sys

    out = out or sys.stdout
    try:
        started = start(base=base, label=label)
    except RuntimeError as exc:
        out.write(f"  Could not start sign-in: {exc}\n")
        return False

    code = started["user_code"]
    url = started.get("verification_uri_complete") or started.get("verification_uri") or ""
    opened = False
    if open_browser:
        try:
            import webbrowser
            opened = webbrowser.open(url)
        except Exception:
            opened = False

    out.write("\n  PRISMOR API   1,000 verdicts a month, free\n\n")
    out.write(f"    Your code     {code}\n")
    out.write(f"    Approve at    {url}\n")
    out.write(f"                  {'opened in your browser' if opened else 'open this link to finish'}\n\n")
    out.flush()

    tty = hasattr(out, "isatty") and out.isatty()
    frames = "|/-\\"

    def tick(waited: float) -> None:
        if not tty:
            return
        out.write(f"\r    Waiting for approval {frames[int(waited) % len(frames)]} ({int(waited)}s)   ")
        out.flush()

    if not tty:
        out.write("    Waiting for approval...\n")
    try:
        approved = wait_for_approval(
            started["device_code"], base=base,
            interval=float(started.get("interval") or 2),
            expires_in=float(started.get("expires_in") or 900),
            on_tick=tick,
        )
    except RuntimeError as exc:
        if tty:
            out.write("\r" + " " * 50 + "\r")
        out.write(f"  Sign-in failed: {exc}\n")
        return False
    if tty:
        out.write("\r" + " " * 50 + "\r")

    save(approved, base=base)
    org = approved.get("org") or {}
    limit = (approved.get("quota") or {}).get("limit")
    out.write("  Connected.\n\n")
    out.write(f"    Organization  {org.get('name') or org.get('id') or 'unknown'}  ({org.get('plan', 'free')})\n")
    out.write(f"    Machine       {label or machine_label()}\n")
    out.write(f"    Included      {'unlimited' if limit is None else format(limit, ',')} verdicts a month\n")
    out.write("    Judge         Prismor API, about 2s a verdict\n\n")

    if set_judge_for is not None:
        try:
            from prismor.runtime.setup_wizard import _write_judge_setting
            _write_judge_setting(set_judge_for, "prismor", "")
            # Name the path: the workspace can come from $PRISMOR_WORKSPACE rather
            # than the directory the human is standing in.
            out.write(f"    Judge set for   {set_judge_for}\n\n")
        except Exception as exc:
            out.write(f"    Could not set the judge automatically: {exc}\n\n")
    out.flush()
    return True
