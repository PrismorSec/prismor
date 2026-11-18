"""Registry metadata fetcher — npm and PyPI, stdlib only, fail-open.

All network calls use a 3-second timeout. On any failure the PackageMetadata
is returned with fetch_error set and all optional fields as None — the scorer
treats missing data conservatively but never blocks solely on a failed fetch.
"""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

from supplychain.ecosystems.detector import PackageSpec


@dataclass
class PackageMetadata:
    name: str
    ecosystem: str
    version: Optional[str]
    age_days: Optional[int]          # days since first publish (None = unknown)
    maintainer_count: Optional[int]
    has_install_script: bool         # postinstall / preinstall present in package
    source: str                      # mirrors PackageSpec.source
    install_script_content: Optional[str] = None  # raw script string for IOC analysis
    fetch_error: Optional[str] = None
    # Age of the version being installed. A hijacked release of an old
    # package is days old even though the package is years old.
    version_age_days: Optional[int] = None
    not_found: bool = False          # registry answered 404: no such package
    # The installed version has an install script and the release before it
    # did not: the pattern of a hijacked publish (npm only).
    install_script_added: bool = False


# In-memory cache: key → (monotonic_ts, PackageMetadata)
_CACHE: dict = {}
_CACHE_TTL = 300  # 5 minutes


def fetch_metadata(spec: PackageSpec, ecosystem: str) -> PackageMetadata:
    """Fetch registry metadata for a package spec. Always returns a value."""
    if spec.source != "registry":
        # Non-registry sources (git, tarball, local) have no metadata to fetch.
        return PackageMetadata(
            name=spec.raw, ecosystem=ecosystem, version=None,
            age_days=None, maintainer_count=None,
            has_install_script=False, source=spec.source,
        )

    cache_key = f"{ecosystem}:{spec.name}@{spec.version}"
    cached = _CACHE.get(cache_key)
    if cached and (time.monotonic() - cached[0]) < _CACHE_TTL:
        return cached[1]

    if ecosystem in ("npm", "pnpm", "yarn", "bun"):
        meta = _fetch_npm(spec.name, ecosystem, spec.version)
    elif ecosystem in ("pip", "uv"):
        meta = _fetch_pypi(spec.name, ecosystem, spec.version)
    else:
        # Only the latest version is resolved here: without it the OSV lookup
        # has no version to filter by and would count every advisory the
        # package ever had (`gem install rails` scored 100/100).
        meta = PackageMetadata(
            name=spec.name, ecosystem=ecosystem, version=_latest_version(spec.name, ecosystem),
            age_days=None, maintainer_count=None,
            has_install_script=False, source="registry",
        )

    _CACHE[cache_key] = (time.monotonic(), meta)
    return meta


_NOT_FOUND: dict = {"__not_found__": True}


def _http_get(url: str, timeout: int = 3, not_found=None) -> Optional[dict]:
    """GET JSON. Returns None on any failure, or ``not_found`` on HTTP 404 so
    callers can tell "no such package" from "registry unreachable"."""
    try:
        req = urllib.request.Request(
            url,
            headers={
                "Accept": "application/json",
                "User-Agent": "immunity-agent/1.0",
            },
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return not_found if exc.code == 404 else None
    except Exception:
        return None


# (url template, path to the latest version in the JSON response)
_LATEST_VERSION_APIS = {
    "cargo": ("https://crates.io/api/v1/crates/{name}", ("crate", "max_stable_version")),
    "gem": ("https://rubygems.org/api/v1/gems/{name}.json", ("version",)),
    "go": ("https://proxy.golang.org/{name}/@latest", ("Version",)),
}


def _latest_version(name: str, ecosystem: str) -> Optional[str]:
    """Newest published version from the registry, or None (unsupported
    ecosystem, network failure). Never raises."""
    if ecosystem == "composer":
        data = _http_get(f"https://repo.packagist.org/p2/{name.lower()}.json")
        try:
            return str(data["packages"][name.lower()][0]["version"]).lstrip("v")
        except (KeyError, IndexError, TypeError):
            return None
    api = _LATEST_VERSION_APIS.get(ecosystem)
    if not api:
        return None
    if ecosystem == "go":  # module proxy case-encoding: "A" -> "!a"
        name = "".join(f"!{c.lower()}" if c.isupper() else c for c in name)
    data = _http_get(api[0].format(name=name))
    for key in api[1]:
        data = data.get(key) if isinstance(data, dict) else None
    return str(data).lstrip("v") if data else None


def _age_days(date_str: str) -> Optional[int]:
    """Parse an ISO-8601 date string and return days elapsed since then."""
    if not date_str:
        return None
    try:
        dt = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
        delta = datetime.now(timezone.utc) - dt
        return max(0, delta.days)
    except Exception:
        return None


def _not_found(name: str, ecosystem: str) -> PackageMetadata:
    return PackageMetadata(
        name=name, ecosystem=ecosystem, version=None,
        age_days=None, maintainer_count=None,
        has_install_script=False, source="registry",
        fetch_error="not found in registry", not_found=True,
    )


def _fetch_npm(name: str, ecosystem: str, requested: str = "") -> PackageMetadata:
    encoded = name.replace("/", "%2F")
    data = _http_get(f"https://registry.npmjs.org/{encoded}", not_found=_NOT_FOUND)

    if data is _NOT_FOUND:
        return _not_found(name, ecosystem)
    if not data:
        return PackageMetadata(
            name=name, ecosystem=ecosystem, version=None,
            age_days=None, maintainer_count=None,
            has_install_script=False, source="registry",
            fetch_error="registry unreachable",
        )

    # First publish date
    time_data = data.get("time") or {}
    age = _age_days(time_data.get("created", ""))

    # Current maintainers
    maintainers = data.get("maintainers") or []
    maintainer_count = len(maintainers) if maintainers else None

    # The version that will be installed: an exact pin if the registry has
    # it, else latest (ranges resolve to latest in the common case).
    versions = data.get("versions") or {}
    tags = data.get("dist-tags") or {}
    latest_version = tags.get("latest", "")
    if requested in versions:
        latest_version = requested
    elif requested in tags:  # npm install pkg@next
        latest_version = tags[requested]
    latest_data = versions.get(latest_version) or {}
    version_age = _age_days(time_data.get(latest_version, ""))
    scripts = latest_data.get("scripts") or {}
    lifecycle_keys = ("postinstall", "preinstall", "install")
    has_install_script = any(k in scripts for k in lifecycle_keys)
    # Previous release by publish time. ISO timestamps sort as strings.
    published = time_data.get(latest_version, "")
    earlier = [v for v in versions if v != latest_version and "" < time_data.get(v, "") < published]
    prev = max(earlier, key=lambda v: time_data[v]) if earlier else None
    prev_scripts = (versions.get(prev) or {}).get("scripts") or {} if prev else {}
    install_script_added = bool(prev) and has_install_script and not any(
        k in prev_scripts for k in lifecycle_keys)

    # Concatenate all lifecycle script strings for IOC pattern analysis
    install_script_content = " ".join(
        str(scripts[k]) for k in lifecycle_keys if k in scripts
    ) or None

    return PackageMetadata(
        name=name, ecosystem=ecosystem, version=latest_version,
        age_days=age, maintainer_count=maintainer_count,
        has_install_script=has_install_script, source="registry",
        install_script_content=install_script_content,
        version_age_days=version_age,
        install_script_added=install_script_added,
    )


def _fetch_pypi(name: str, ecosystem: str, requested: str = "") -> PackageMetadata:
    data = _http_get(f"https://pypi.org/pypi/{name}/json", not_found=_NOT_FOUND)

    if data is _NOT_FOUND:
        return _not_found(name, ecosystem)
    if not data:
        return PackageMetadata(
            name=name, ecosystem=ecosystem, version=None,
            age_days=None, maintainer_count=None,
            has_install_script=False, source="registry",
            fetch_error="registry unreachable",
        )

    info = data.get("info") or {}
    latest_version = info.get("version", "")

    # Earliest upload time across all releases
    releases = data.get("releases") or {}
    all_upload_times = []
    for version_files in releases.values():
        for f in version_files:
            ut = f.get("upload_time_iso_8601") or f.get("upload_time")
            if ut:
                all_upload_times.append(ut)

    age = _age_days(min(all_upload_times)) if all_upload_times else None

    if requested in releases:
        latest_version = requested
    version_uploads = [
        f.get("upload_time_iso_8601") or f.get("upload_time")
        for f in releases.get(latest_version) or []
    ]
    version_uploads = [u for u in version_uploads if u]
    version_age = _age_days(min(version_uploads)) if version_uploads else None

    # PyPI doesn't expose maintainer count in JSON; treat as 1 if author present
    maintainer_count = 1 if info.get("author") else None

    return PackageMetadata(
        name=name, ecosystem=ecosystem, version=latest_version,
        age_days=age, maintainer_count=maintainer_count,
        has_install_script=False, source="registry",
        version_age_days=version_age,
    )
