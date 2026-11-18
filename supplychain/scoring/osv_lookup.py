"""OSV.dev vulnerability lookup — version-aware, ecosystem-scoped.

Replaces the old NVD keyword-search approach. OSV's /v1/query endpoint
filters to vulnerabilities affecting the exact installed version in the
right ecosystem, eliminating CPE parsing, keyword collisions, and
version-blind matches in one move.

Also surfaces malicious-package advisories (MAL-* IDs from the OSV
malicious-packages corpus) that NVD does not track.

fetch_vulns returns None (not []) when OSV could not answer, and does not
cache it, so the install check can block what it could not verify.
"""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional, Tuple

OSV_QUERY_URL = "https://api.osv.dev/v1/query"
OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL_TEMPLATE = "https://api.osv.dev/v1/vulns/{id}"

# querybatch returns id+modified only (no severity/summary) by OSV design,
# to keep batch responses small — see fetch_vulns_batch. This caps how
# many *distinct* vulnerability IDs we'll fetch full details for in one
# scan, bounding worst-case latency independent of how many packages a
# lockfile lists (a tree of 250 packages sharing a handful of CVEs costs
# a handful of detail fetches, not 250).
_BATCH_DETAIL_FETCH_CAP = 60

# Map our internal ecosystem labels to OSV's ecosystem identifiers.
# See https://ossf.github.io/osv-schema/#defined-ecosystems
_ECOSYSTEM_MAP = {
    "npm": "npm",
    "pnpm": "npm",
    "yarn": "npm",
    "bun": "npm",
    "pip": "PyPI",
    "uv": "PyPI",
    "cargo": "crates.io",
    "go": "Go",
    "gem": "RubyGems",
    "composer": "Packagist",
    "maven": "Maven",
}

_CACHE: Dict[str, tuple] = {}  # key -> (expire_time, result)
_CACHE_TTL = 300


def _cache_get(key: str) -> Optional[List[Dict[str, Any]]]:
    if key in _CACHE:
        expire, result = _CACHE[key]
        if time.monotonic() < expire:
            return result
        del _CACHE[key]
    return None


def _cache_set(key: str, result: List[Dict[str, Any]]) -> None:
    _CACHE[key] = (time.monotonic() + _CACHE_TTL, result)


def _osv_ecosystem(ecosystem: str) -> Optional[str]:
    return _ECOSYSTEM_MAP.get(ecosystem)


def _get_json(url: str, timeout: int = 4) -> Optional[dict]:
    """GET JSON from OSV; return parsed response or None on any failure."""
    try:
        req = urllib.request.Request(
            url,
            headers={"Accept": "application/json", "User-Agent": "immunity-agent/1.0"},
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except Exception:
        return None


def _post_json(url: str, body: Dict[str, Any], timeout: int = 4) -> Optional[dict]:
    """POST JSON to OSV; return parsed response or None on any failure."""
    try:
        req = urllib.request.Request(
            url,
            data=json.dumps(body).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
                "User-Agent": "immunity-agent/1.0",
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except Exception:
        return None


def _classify_severity(vuln: Dict[str, Any]) -> str:
    """Pick a severity tier from an OSV vuln record.

    Order of preference:
      1. MAL-* IDs (malicious-packages corpus) → critical.
      2. database_specific.severity (GHSA text severity).
      3. CVSS vector impact metrics — rough heuristic, not a full calculator.
      4. Default "medium" so a confirmed-vulnerable version is never silent.
    """
    vid = vuln.get("id", "")
    if _is_malicious(vuln):
        return "critical"

    db = vuln.get("database_specific") or {}
    text = str(db.get("severity") or "").lower()
    if text in ("critical", "high", "medium", "low"):
        return text

    for sev in vuln.get("severity") or []:
        vector = str(sev.get("score") or "")
        if "CVSS" not in vector:
            continue
        n_high_impact = vector.count(":H")
        network = "AV:N" in vector
        if network and n_high_impact >= 3:
            return "critical"
        if network and n_high_impact >= 1:
            return "high"
        if n_high_impact >= 1:
            return "medium"
        return "low"

    return "medium"


def _format_title(vuln: Dict[str, Any]) -> str:
    vid = vuln.get("id", "OSV")
    summary = (vuln.get("summary") or "").strip()
    if not summary:
        # Fallback to first line of details.
        details = (vuln.get("details") or "").strip().splitlines()
        summary = details[0] if details else ""
    if not summary:
        return vid
    if len(summary) > 80:
        summary = summary[:77] + "..."
    return f"{vid}: {summary}"


def _is_malicious(vuln: Dict[str, Any]) -> bool:
    if vuln.get("id", "").startswith("MAL-"):
        return True
    db = vuln.get("database_specific") or {}
    if str(db.get("type") or "").upper() == "MALICIOUS_LIBRARY":
        return True
    # GitHub's malware advisories (GHSA "<pkg> is malware") carry CWE-506,
    # Embedded Malicious Code, rather than a MAL- id.
    return "CWE-506" in (db.get("cwe_ids") or [])


def fetch_vulns(
    package_name: str,
    ecosystem: str,
    version: str = "",
) -> Optional[List[Dict[str, Any]]]:
    """Query OSV for vulnerabilities affecting `package_name` at `version`.

    Returns a list of {id, severity, title, malicious} dicts, already
    filtered to the right ecosystem and (when version is given) the
    affected version range. None when OSV could not answer, so an
    unchecked version is never mistaken for a clean one ([]).
    """
    osv_eco = _osv_ecosystem(ecosystem)
    if not osv_eco or not package_name:
        return None

    cache_key = f"{osv_eco}:{package_name}:{version}"
    cached = _cache_get(cache_key)
    if cached is not None:
        return cached

    query: Dict[str, Any] = {
        "package": {"name": package_name, "ecosystem": osv_eco},
    }
    if version:
        query["version"] = version

    # OSV answers {} for a clean version; None is a failed request, which is
    # not cached so the next install asks again.
    data = _post_json(OSV_QUERY_URL, query)
    if data is None:
        return None

    out: List[Dict[str, Any]] = []
    for vuln in data.get("vulns") or []:
        if vuln.get("withdrawn"):
            continue
        out.append({
            "id": vuln.get("id", ""),
            "severity": _classify_severity(vuln),
            "title": _format_title(vuln),
            "malicious": _is_malicious(vuln),
        })

    _cache_set(cache_key, out)
    return out


def batch_has_vulns(
    package_name: str,
    ecosystem: str,
    versions: List[str],
) -> Dict[str, bool]:
    """Batch-check which versions have any known vulnerabilities.

    Returns {version: has_vulns}. Versions not in the response (or on
    network failure) are reported as having vulns — safer to skip an
    unknown version than to recommend something we couldn't verify.
    """
    osv_eco = _osv_ecosystem(ecosystem)
    if not osv_eco or not versions:
        return {v: True for v in versions}

    body = {
        "queries": [
            {"package": {"name": package_name, "ecosystem": osv_eco}, "version": v}
            for v in versions
        ]
    }
    data = _post_json(OSV_BATCH_URL, body, timeout=5)
    if not data:
        return {v: True for v in versions}

    results = data.get("results") or []
    out: Dict[str, bool] = {}
    for v, result in zip(versions, results):
        vulns = result.get("vulns") or []
        out[v] = bool(vulns)
    # Anything missing from the response stays marked as vulnerable.
    for v in versions:
        out.setdefault(v, True)
    return out


def fetch_vulns_batch(
    packages: List[Tuple[str, str, str]],
) -> Dict[Tuple[str, str, str], List[Dict[str, Any]]]:
    """Query OSV for vulnerabilities affecting many (name, ecosystem,
    version) tuples at once — built for scanning a whole resolved
    dependency tree (hundreds of packages) without one round trip per
    package, as `fetch_vulns()` would require.

    Two-phase by necessity: OSV's /v1/querybatch endpoint deliberately
    returns only {id, modified} per vuln (no severity/summary/malicious
    flag) to keep batch responses small. Phase 1 batches the presence
    check across all packages. Phase 2 fetches full details via
    /v1/vulns/{id} — but only once per *distinct* vuln ID found, capped
    at `_BATCH_DETAIL_FETCH_CAP`, so cost scales with how many different
    CVEs actually showed up, not with the package count. IDs beyond the
    cap still appear in the result (so a caller never silently loses a
    package), just with a default-medium synthetic entry instead of a
    fetched title/severity.

    Returns {(name, ecosystem, version): [vuln dicts]} in the same shape
    `fetch_vulns()` returns. Fails open: a key whose ecosystem isn't
    OSV-mapped, or whose batch sub-request fails entirely, maps to [].
    """
    out: Dict[Tuple[str, str, str], List[Dict[str, Any]]] = {}
    to_query: List[Tuple[str, str, str, str, str]] = []  # name, eco, version, osv_eco, cache_key
    for name, ecosystem, version in packages:
        key = (name, ecosystem, version)
        osv_eco = _osv_ecosystem(ecosystem)
        if not osv_eco or not name:
            out[key] = []
            continue
        cache_key = f"{osv_eco}:{name}:{version}"
        cached = _cache_get(cache_key)
        if cached is not None:
            out[key] = cached
            continue
        to_query.append((name, ecosystem, version, osv_eco, cache_key))

    if not to_query:
        return out

    # Phase 1: batch-query IDs only.
    id_map: Dict[Tuple[str, str, str], List[str]] = {}
    all_ids: set = set()
    chunk_size = 100
    for start in range(0, len(to_query), chunk_size):
        chunk = to_query[start:start + chunk_size]
        body = {
            "queries": [
                {"package": {"name": n, "ecosystem": e}, "version": v}
                for n, _eco, v, e, _ck in chunk
            ]
        }
        data = _post_json(OSV_BATCH_URL, body, timeout=10)
        results = (data or {}).get("results") or []
        for (n, eco, v, _e, _ck), result in zip(chunk, results):
            ids = [vv["id"] for vv in (result or {}).get("vulns") or [] if vv.get("id")]
            id_map[(n, eco, v)] = ids
            all_ids.update(ids)
        if not data:
            for (n, eco, v, _e, _ck) in chunk:
                id_map.setdefault((n, eco, v), [])

    # Phase 2: full details for each distinct ID, capped.
    ids_to_fetch = sorted(all_ids)[:_BATCH_DETAIL_FETCH_CAP]
    detail_cache: Dict[str, Optional[dict]] = {}
    for vid in ids_to_fetch:
        detail_cache[vid] = _get_json(OSV_VULN_URL_TEMPLATE.format(id=vid), timeout=4)

    # Phase 3: assemble per-package results.
    for (name, ecosystem, version, _osv_eco, cache_key) in to_query:
        key = (name, ecosystem, version)
        parsed: List[Dict[str, Any]] = []
        for vid in id_map.get(key, []):
            if vid not in detail_cache:
                # Beyond the detail-fetch cap — still report the package
                # as affected rather than silently dropping it.
                parsed.append({"id": vid, "severity": "medium", "title": vid, "malicious": False})
                continue
            vuln = detail_cache[vid]
            if not vuln or vuln.get("withdrawn"):
                continue
            parsed.append({
                "id": vid,
                "severity": _classify_severity(vuln),
                "title": _format_title(vuln),
                "malicious": _is_malicious(vuln),
            })
        _cache_set(cache_key, parsed)
        out[key] = parsed
    return out
