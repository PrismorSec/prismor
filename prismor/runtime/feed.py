from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from prismor.runtime.feed_signature import (
    MISMATCH,
    MISSING,
    SignatureResult,
    verify_feed_bytes,
)

CATEGORY_TO_FEED_TYPES = {
    "prompt_injection": {"prompt_injection", "jailbreak", "policy_bypass"},
    "destructive_command": {"unsafe_tool_execution", "policy_bypass"},
    "remote_execution": {"unsafe_tool_execution", "policy_bypass"},
    "secret_access": {"data_exfiltration", "policy_bypass"},
    "secret_exfiltration": {"data_exfiltration", "policy_bypass"},
    "pii_exposure": {"data_exfiltration"},
    "risky_write": {"unsafe_tool_execution", "dependency_vulnerability"},
    "dependency_risk": {"dependency_vulnerability"},
    "dos_resource_exhaustion": {"model_denial_of_service"},
    "rce_canary": {"unsafe_tool_execution"},
    "db_modification": {"unsafe_tool_execution", "policy_bypass"},
    "db_access": {"data_exfiltration"},
    "privilege_escalation": {"policy_bypass"},
    "path_traversal": {"data_exfiltration"},
    "skill_risk": {"unsafe_tool_execution", "policy_bypass", "prompt_injection"},
    "network_isolation": {"data_exfiltration", "unsafe_tool_execution"},
    "change_control": {"unsafe_tool_execution"},
}


def load_feed(repo_root: Optional[Path] = None) -> Dict[str, Any]:
    """Load the advisory feed, verifying its detached Ed25519 signature.

    ``repo_root`` is honoured for backward compatibility, but only when it
    actually contains the feed. Otherwise (e.g. an installed wheel, where the
    legacy ``repo_root`` would point at ``site-packages``) the bundled-data
    resolver in :mod:`prismor.runtime.paths` locates it instead.

    The signature is ``<feed>.sig`` next to the feed; the key is the bundled
    ``keys/public.pub``. The returned dict carries the outcome under
    ``"_signature"`` (see :mod:`prismor.runtime.feed_signature`):

    * ``verified`` -- the feed is returned as is.
    * ``mismatch`` / ``missing`` -- the feed is refused: an empty advisory list
      is returned and a warning logged. Deleting the ``.sig`` must not be an
      easier bypass than editing it. ``PRISMOR_FEED_ALLOW_UNSIGNED=1`` accepts
      an unsigned feed (marked unverified) for local pipeline work.
    * ``unavailable`` -- no backend could check (no ``cryptography``, no
      OpenSSL 3, no key): the feed is used, marked unverified, with a warning.
      Advisories only enrich reports; refusing them would not make a hook safer.
    """
    resolved = None
    if repo_root is not None:
        candidate = Path(repo_root) / "advisories" / "immunity-feed.json"
        if candidate.exists():
            resolved = candidate

    if resolved is None:
        from prismor.runtime.paths import feed_path
        resolved = feed_path()

    data = resolved.read_bytes()
    result = _verify(resolved, data)
    sig: Dict[str, Any] = dict(result.as_dict())

    if result.status in (MISMATCH, MISSING) and not (
        result.status == MISSING and os.environ.get("PRISMOR_FEED_ALLOW_UNSIGNED") == "1"
    ):
        # MISSING also covers a garbled .sig, so don't print the bare word.
        _warn_once(resolved, result,
                   "advisory feed signature %s (%s) for %s; refusing to use the feed",
                   "does not match" if result.status == MISMATCH else "is missing or unreadable",
                   result.detail, resolved)
        sig["trusted"] = False
        return {"version": None, "advisories": [], "_signature": sig}

    if not result.ok:
        _warn_once(resolved, result,
                   "advisory feed %s could not be verified (%s); using it unverified",
                   resolved, result.detail or result.status)
    sig["trusted"] = result.ok
    feed = json.loads(data.decode("utf-8"))
    if isinstance(feed, dict):
        feed["_signature"] = sig
    return feed


_WARNED: Set[Tuple[str, str]] = set()


def _verify(feed_file: Path, data: bytes) -> SignatureResult:
    from prismor.runtime.paths import public_key_path
    sig_path = feed_file.with_name(feed_file.name + ".sig")
    return verify_feed_bytes(data, sig_path, public_key_path())


def _warn_once(feed_file: Path, result: SignatureResult, msg: str, *args: Any) -> None:
    key = (str(feed_file), result.status)
    if key in _WARNED:
        return
    _WARNED.add(key)
    import logging  # lazy: only paid when there is something to say
    logging.getLogger("prismor.feed").warning("prismor: " + msg, *args)


def match_advisories(findings: List[Dict[str, Any]], feed: Dict[str, Any], limit: int = 5) -> List[Dict[str, Any]]:
    desired_types = set()
    for finding in findings:
      desired_types.update(CATEGORY_TO_FEED_TYPES.get(finding.get("category", ""), set()))

    if not desired_types:
        return []

    advisories = feed.get("advisories", [])
    matches = [advisory for advisory in advisories if advisory.get("type") in desired_types]
    matches.sort(key=lambda advisory: _severity_rank(advisory.get("severity", "unknown")), reverse=True)
    return matches[:limit]


def _severity_rank(severity: str) -> int:
    return {
        "critical": 5,
        "high": 4,
        "medium": 3,
        "low": 2,
        "unknown": 1,
    }.get(str(severity).lower(), 0)
