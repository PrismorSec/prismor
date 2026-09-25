"""Shared PyPI version lookup for `prismor update` and the startup notice.

Debounced and fail-silent: at most one PyPI hit per ``_CHECK_INTERVAL``,
cached at ``~/.prismor/update_check.json``, short timeout. Never raises —
callers get ``None`` on any failure rather than a delayed or noisy command.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Optional

_PACKAGE = "prismor"
_CHECK_INTERVAL = 24 * 60 * 60  # seconds
_TIMEOUT = 1.5


def _cache_path() -> Path:
    from prismor.runtime.store import prismor_home
    return prismor_home() / "update_check.json"


def _read_cache() -> dict:
    try:
        return json.loads(_cache_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _write_cache(data: dict) -> None:
    try:
        path = _cache_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data), encoding="utf-8")
    except OSError:
        pass


def fetch_latest(timeout: float = _TIMEOUT) -> Optional[str]:
    """Hit PyPI directly for the latest published version. None on failure.

    ``timeout`` defaults short (this is called from the passive startup
    notice); `prismor update` passes a longer one since a user who typed that
    command is deliberately waiting on it.
    """
    import urllib.error
    import urllib.request

    try:
        with urllib.request.urlopen(  # fixed or operator-configured URL  # nosec B310
            f"https://pypi.org/pypi/{_PACKAGE}/json", timeout=timeout
        ) as resp:
            return json.loads(resp.read())["info"]["version"]
    except (urllib.error.URLError, KeyError, ValueError, OSError):
        return None


def record_latest(latest: Optional[str]) -> None:
    """Write a freshly (live) fetched version into the shared cache, so a
    live check — e.g. from `prismor update` — also resets the passive
    startup notice instead of leaving it to show a stale value for up to
    ``_CHECK_INTERVAL`` after the user already resolved it.
    """
    if latest:
        _write_cache({"last_checked": time.time(), "package": _PACKAGE, "latest_version": latest})


def latest_known_version() -> Optional[str]:
    """Debounced latest version — refreshes from PyPI at most once per
    ``_CHECK_INTERVAL``, otherwise returns the cached value. Never raises.

    Cache entries written against a different ``_PACKAGE`` (e.g. left over
    from the pre-rename ``immunity-agent`` lookup) are treated as absent so
    a rename can't leave stale, wrongly-sourced version numbers on disk.
    """
    cache = _read_cache()
    if cache.get("package") != _PACKAGE:
        cache = {}
    if time.time() - cache.get("last_checked", 0) < _CHECK_INTERVAL:
        return cache.get("latest_version")
    latest = fetch_latest()
    _write_cache({
        "last_checked": time.time(),
        "package": _PACKAGE,
        "latest_version": latest or cache.get("latest_version"),
    })
    return latest or cache.get("latest_version")
