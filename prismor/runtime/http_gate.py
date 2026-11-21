"""prismor/runtime/http_gate.py — the browser gate every local HTTP surface shares.

A web page the user has open can reach any port on 127.0.0.1: a "simple"
cross-origin POST needs no preflight, and DNS rebinding turns an attacker's
hostname into a same-origin one. ``browser_gate`` refuses both, and leaves
non-browser clients (curl, SDKs: no Origin, no Sec-Fetch-*) alone.
"""
from __future__ import annotations

import ipaddress
from typing import Any, Optional
from urllib.parse import urlsplit


def is_loopback(host: str) -> bool:
    host = host.strip("[]")
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def hostname(netloc: str) -> str:
    return (urlsplit("//" + netloc).hostname or "").lower()


def browser_gate(handler: Any, *, check_host: bool = True) -> Optional[tuple]:
    """None when the request may proceed, else (status, message).

    ``check_host=False`` skips the rebinding check, for a server whose callers
    already prove themselves with a secret (an API key) and may reach it under
    another name (a tunnel, a reverse proxy).
    """
    host = handler.headers.get("Host", "")
    bound = str(handler.server.server_address[0])
    # DNS rebinding: an attacker's hostname resolving to 127.0.0.1 is
    # same-origin to the browser, so Origin alone can't catch it.
    if check_host and is_loopback(bound) and not is_loopback(hostname(host)):
        return 403, "forbidden host"
    # CSRF / cross-origin reads. Our own page is always same-origin; a
    # sandboxed frame or file:// page sends "Origin: null", which never matches.
    origin = handler.headers.get("Origin")
    if origin is not None and urlsplit(origin).netloc.lower() != host.lower():
        return 403, "cross-origin request refused"
    # A link to the page is fine (the page can't read the result);
    # a script fetch or form post from another site is not.
    navigation = handler.command == "GET" and handler.headers.get("Sec-Fetch-Mode") == "navigate"
    if handler.headers.get("Sec-Fetch-Site", "same-origin") not in ("same-origin", "none") and not navigation:
        return 403, "cross-site request refused"
    return None
