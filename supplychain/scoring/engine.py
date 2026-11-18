"""Risk scorer — maps package signals to a score and allow/warn/block verdict."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, List, Literal, Optional, Set

from supplychain.ecosystems.detector import InstallEvent, PackageSpec
from supplychain.ecosystems.metadata import PackageMetadata
from supplychain import ioc as _ioc
from supplychain.scoring.osv_lookup import fetch_vulns
from supplychain.scoring.typosquat import check_typosquat


@dataclass
class Signal:
    id: str
    points: int
    description: str


@dataclass
class PackageVerdict:
    spec: PackageSpec
    meta: PackageMetadata
    score: int
    verdict: Literal["allow", "warn", "block"]
    signals: List[Signal] = field(default_factory=list)
    allowlisted: bool = False


# Only a version OSV confirms has no known vulnerability installs: a known CVE
# (osv_*), or a package OSV could not check (unverified_*, git, tarball), blocks.
_UNCLEAN = ("osv_", "unverified_", "git_source", "tarball_source")
# A version was asked for but not an exact one (express@^4, requests>=2,
# serde@1): the package manager picks, so what OSV checked may not be what lands.
_VERSION_QUERY_RE = re.compile(r"[@:=<>~^! ]")


def _asks_for_range(spec: PackageSpec) -> bool:
    if spec.version or not spec.raw.lower().startswith(spec.name.lower()):
        return False
    rest = spec.raw[len(spec.name):]
    return rest != "@latest" and bool(_VERSION_QUERY_RE.search(rest))


def load_allowlist(workspace: Path) -> Set[str]:
    """Read supply_chain.allowlist from .prismor/policy.yaml.

    Accepts entries as bare names ("lodash") or ecosystem-qualified
    ("npm:lodash"). Both forms are returned lowercased.
    """
    policy_path = workspace / ".prismor" / "policy.yaml"
    if not policy_path.is_file():
        return set()
    try:
        import yaml  # type: ignore
        data = yaml.safe_load(policy_path.read_text(encoding="utf-8")) or {}
    except Exception:
        return set()
    entries: Iterable = ((data.get("supply_chain") or {}).get("allowlist")) or []
    return {str(e).lower() for e in entries if e}


class RiskScorer:
    WARN_THRESHOLD = 30
    BLOCK_THRESHOLD = 60

    def __init__(self, allowlist: Optional[Set[str]] = None) -> None:
        self.allowlist = {a.lower() for a in (allowlist or set())}

    def _is_allowlisted(self, spec: PackageSpec, ecosystem: str) -> bool:
        if not self.allowlist:
            return False
        name = spec.name.lower()
        return name in self.allowlist or f"{ecosystem}:{name}" in self.allowlist

    def score(
        self,
        spec: PackageSpec,
        meta: PackageMetadata,
        event: InstallEvent,
    ) -> PackageVerdict:
        signals: List[Signal] = []

        def add(id: str, points: int, desc: str) -> None:
            signals.append(Signal(id=id, points=points, description=desc))

        # ── Source-based (applies regardless of registry availability) ──
        # git and tarball block (no registry version OSV can check); a local
        # path is code already on disk, not pulled from anywhere.
        if meta.source == "git":
            add("git_source", 35, "git/GitHub dependency bypasses registry, no version OSV can check")
        elif meta.source == "tarball":
            add("tarball_source", 25, "tarball install bypasses registry, no version OSV can check")
        elif meta.source == "local":
            add("local_source", 10, "local path dependency")

        if event.custom_registry:
            add("custom_registry", 10, f"custom registry: {event.custom_registry}")

        # ── Registry-only signals (skip for non-registry sources) ────────
        if meta.source == "registry":
            if meta.age_days is not None:
                # Brand-new packages are the highest-risk supply-chain vector
                # (mini-shai-hulud, LiteLLM backdoor). In an agentic context
                # there's no human to review them, so <2d single-maintainer
                # crosses BLOCK on its own (50 + 10 = 60).
                if meta.age_days < 2:
                    add("extreme_new_package", 50, f"published {meta.age_days}d ago — unreviewed")
                elif meta.age_days < 7:
                    # 35 pts: enough to WARN alone but not BLOCK; a single-maintainer
                    # <7d package (35 + 10 = 45) still needs a second signal to cross 60.
                    add("very_new_package", 35, f"published {meta.age_days}d ago")
                elif meta.age_days < 30:
                    add("new_package", 15, f"published {meta.age_days}d ago")

            if meta.maintainer_count is None:
                add("no_maintainer_data", 8, "maintainer data unavailable")
            elif meta.maintainer_count == 1:
                add("single_maintainer", 10, "single maintainer")

            if meta.has_install_script:
                add("has_install_script", 20,
                    "no wheel: builds from source, setup code runs at install"
                    if meta.ecosystem in ("pip", "uv") else "has postinstall/preinstall script")

            # ── Vulnerability scoring via OSV (version-aware) ────────────────
            # Prefer the user-pinned version; fall back to whatever the
            # registry reports as latest. OSV filters by version internally.
            lookup_version = spec.version or meta.version or ""
            vulns = fetch_vulns(spec.name, meta.ecosystem, lookup_version)
            if not lookup_version or _asks_for_range(spec):
                add("unverified_version", 0, "exact version unknown, pin one (pkg@1.2.3 / pkg==1.2.3)")
            elif vulns is None:
                add("unverified_osv", 0, "OSV unreachable, could not verify this version is CVE-free")
            vulns = vulns or []
            if not lookup_version:
                # No version to filter by: OSV returns every advisory the
                # package ever had, so only malicious-package records (which
                # name the package itself, not a version) mean anything.
                vulns = [v for v in vulns if v.get("malicious")]
            _SEV_POINTS = {"critical": 50, "high": 30, "medium": 15, "low": 5}
            _SEV_RANK = {"critical": 3, "high": 2, "medium": 1, "low": 0}
            vulns_sorted = sorted(
                vulns, key=lambda v: _SEV_RANK.get(v.get("severity"), -1), reverse=True
            )
            for vuln in vulns_sorted[:3]:  # cap at 3 to avoid output noise
                if vuln.get("malicious"):
                    add(f"ioc_osv_{vuln['id']}", 100, f"malicious package: {vuln['title']}")
                    continue
                pts = _SEV_POINTS.get(vuln["severity"], 0)
                if pts:
                    add(f"osv_{vuln['severity']}", pts, vuln["title"])

            # ── Typosquatting detection ──────────────────────────────────────
            mimic = check_typosquat(spec.name, meta.ecosystem)
            if mimic:
                add("typosquat_suspect", 40, f"name resembles trusted package '{mimic}'")

        # ── IOC: known compromised packages (mini-shai-hulud and future attacks) ──
        # Prefer the user-requested version (spec.version) because meta.version
        # is fetched from the registry and may differ — e.g. "pip install pkg==2.4.6"
        # where the registry currently advertises 2.4.5 as the latest.
        ioc_check_version = spec.version or meta.version
        ioc_match = _ioc.check_package(spec.name, ioc_check_version)
        if ioc_match:
            points = 100 if ioc_match.force_block else 40
            add(f"ioc_{ioc_match.ioc_id}", points, ioc_match.description)

        # ── IOC: install script content analysis ─────────────────────────────
        if meta.install_script_content:
            for description, severity in _ioc.check_script(meta.install_script_content):
                script_points = 100 if severity == "CRITICAL" else 50
                add("ioc_script_pattern", script_points, description)

        total = min(100, sum(s.points for s in signals))

        # Force block on any IOC, known CVE or unverifiable version, regardless of threshold
        has_ioc = any(s.id.startswith("ioc_") for s in signals)
        unclean = any(s.id.startswith(_UNCLEAN) for s in signals)
        if has_ioc or unclean or total >= self.BLOCK_THRESHOLD:
            verdict: Literal["allow", "warn", "block"] = "block"
        elif total >= self.WARN_THRESHOLD:
            verdict = "warn"
        else:
            verdict = "allow"

        # Allowlist demotes BLOCK → WARN so signals stay visible but the
        # install proceeds. IOC matches (known-malicious packages) are
        # never demoted — the user explicitly opted in to a real attack.
        allowlisted = self._is_allowlisted(spec, meta.ecosystem)
        if allowlisted and verdict == "block" and not has_ioc:
            verdict = "warn"

        return PackageVerdict(
            spec=spec, meta=meta, score=total, verdict=verdict,
            signals=signals, allowlisted=allowlisted,
        )
