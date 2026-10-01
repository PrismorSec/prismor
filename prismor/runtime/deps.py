"""Dependency-to-feed correlation for Prismor.

Scans workspace manifest files, extracts dependency names and versions,
and cross-references them against the threat feed's dependency_vulnerability
advisories.

Usage (from CLI):
    prismor deps              # scan current workspace
    prismor deps --json       # machine-readable output
"""
from __future__ import annotations

import json
import os
import re
from fnmatch import fnmatch
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Tuple


# Manifest file patterns (kept in sync with default_policy.yaml).
_MANIFEST_GLOBS = {
    "package.json": "npm",
    "requirements.txt": "pip",
    "requirements-*.txt": "pip",
    "requirements_*.txt": "pip",
    "pyproject.toml": "pip",
    "Gemfile": "gem",
    "go.mod": "go",
    "Cargo.toml": "cargo",
    "pom.xml": "maven",
}

# Patterns for lockfiles paired with their manifests.
_LOCKFILE_PAIRS: Dict[str, List[str]] = {
    "package.json": ["package-lock.json", "yarn.lock", "pnpm-lock.yaml"],
    "requirements.txt": ["requirements.txt"],  # pip has no standard lockfile
    "pyproject.toml": ["poetry.lock", "uv.lock"],
    "Gemfile": ["Gemfile.lock"],
    "go.mod": ["go.sum"],
    "Cargo.toml": ["Cargo.lock"],
    "pom.xml": [],  # Maven has no standard lockfile
}


# Directories that are never part of *this* workspace's own dependency
# surface: vendored trees, build output, caches, and agent scratch space.
# Walking into them double-counts the same manifest many times over --
# see PrismorSec/prismor#289, where four `.claude/worktrees/` checkouts
# turned 53 findings into 265.
_SKIP_DIR_NAMES = frozenset({
    ".git", ".hg", ".svn",
    "node_modules", "bower_components", "vendor",
    ".venv", "venv", "__pycache__", ".mypy_cache", ".pytest_cache", ".tox",
    ".next", ".nuxt", ".cache", ".terraform",
    "dist", "build",
    ".claude", ".codex", ".cursor",
})


def _is_nested_checkout(path: Path) -> bool:
    """True for a directory that is its own git checkout - a submodule or
    a linked worktree (whose `.git` is a file, not a directory). Its
    manifests belong to that repo, not to the workspace being scanned.
    """
    return (path / ".git").exists()


def _iter_workspace_files(workspace: Path, *patterns: str) -> Iterator[Path]:
    """Yield files under `workspace` whose name matches one of `patterns`,
    pruning vendored/build/cache directories and nested checkouts.

    Every manifest-walking check goes through here so they all agree on
    what "the workspace" means - previously `find_manifests` globbed only
    the top level while the lockfile checks globbed `**/`, so one scan
    could report a single manifest alongside findings from five copies
    of it (PrismorSec/prismor#289).
    """
    for dirpath, dirnames, filenames in os.walk(workspace, followlinks=False):
        here = Path(dirpath)
        dirnames[:] = sorted(
            d for d in dirnames
            if d not in _SKIP_DIR_NAMES and not _is_nested_checkout(here / d)
        )
        for name in sorted(filenames):
            if any(fnmatch(name, pattern) for pattern in patterns):
                yield here / name


def find_manifests(workspace: Path) -> List[Dict[str, Any]]:
    """Find dependency manifest files in the workspace.

    Returns list of {path, type, ecosystem}.
    """
    results: List[Dict[str, Any]] = []
    seen: set = set()
    for match in _iter_workspace_files(workspace, *_MANIFEST_GLOBS):
        if match in seen or not match.is_file():
            continue
        ecosystem = next(
            (eco for pattern, eco in _MANIFEST_GLOBS.items() if fnmatch(match.name, pattern)),
            None,
        )
        if ecosystem is None:
            continue
        seen.add(match)
        results.append({
            "path": match,
            "name": match.name,
            "ecosystem": ecosystem,
        })
    return results


def check_lockfile_presence(workspace: Path) -> List[Dict[str, Any]]:
    """Check that lockfiles exist alongside manifests.

    Returns list of {manifest, missing_lockfiles, severity, message}.
    """
    findings: List[Dict[str, Any]] = []
    for pattern, lockfiles in _LOCKFILE_PAIRS.items():
        if not lockfiles:
            continue
        for manifest in _iter_workspace_files(workspace, pattern):
            if not manifest.is_file():
                continue
            parent = manifest.parent
            has_lock = any((parent / lf).exists() for lf in lockfiles)
            if not has_lock:
                findings.append({
                    "manifest": str(manifest),
                    "missing_lockfiles": lockfiles,
                    "severity": "MEDIUM",
                    "message": (
                        f"{manifest.name} has no lockfile — dependency versions "
                        f"are not pinned (expected one of: {', '.join(lockfiles)})"
                    ),
                })
    return findings


def parse_dependencies(
    manifest: Path,
    ecosystem: str,
    lockfile_map: Optional[Dict[str, str]] = None,
) -> List[Dict[str, str]]:
    """Extract dependency names and versions from a manifest file.

    Returns list of {name, version, ecosystem[, range, pinned_via_lock]}.
    `lockfile_map` is npm-only today and threaded through `_parse_package_json`.
    """
    try:
        text = manifest.read_text(encoding="utf-8")
    except OSError:
        return []

    if ecosystem == "npm":
        return _parse_package_json(text, lockfile_map)
    elif ecosystem == "pip":
        if manifest.name == "pyproject.toml":
            return _parse_pyproject_toml(text)
        return _parse_requirements_txt(text)
    elif ecosystem == "go":
        return _parse_go_mod(text)
    elif ecosystem == "cargo":
        return _parse_cargo_toml(text)
    return []


def _parse_package_json(text: str, lockfile_map: Optional[Dict[str, str]] = None) -> List[Dict[str, str]]:
    """Parse package.json dependencies. If lockfile_map is supplied, replace
    each floating range with the pinned version it resolves to.
    """
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []

    lockfile_map = lockfile_map or {}
    deps: List[Dict[str, Any]] = []
    for section in ("dependencies", "devDependencies"):
        for name, raw_version in (data.get(section) or {}).items():
            raw = str(raw_version)
            pinned = lockfile_map.get(name)
            dep: Dict[str, Any] = {
                "name": name,
                "version": pinned if pinned else raw,
                "ecosystem": "npm",
                "range": raw,
            }
            if pinned:
                dep["pinned_via_lock"] = True
            deps.append(dep)
    return deps


def _read_npm_lockfile(workspace: Path) -> Dict[str, str]:
    """Read package-lock.json (v2/v3) and return top-level {name: pinned_version}.

    Top-level entries are keyed by "node_modules/<name>" — nested
    "node_modules/<a>/node_modules/<b>" are transitive and skipped.
    """
    pins: Dict[str, str] = {}
    for lock in _iter_workspace_files(workspace, "package-lock.json"):
        try:
            data = json.loads(lock.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
        packages = data.get("packages") or {}
        if not isinstance(packages, dict):
            continue
        for path, meta in packages.items():
            if not path.startswith("node_modules/") or "/node_modules/" in path[len("node_modules/"):]:
                continue
            if not isinstance(meta, dict):
                continue
            name = path[len("node_modules/"):]
            version = meta.get("version")
            if name and isinstance(version, str):
                pins.setdefault(name, version)
    return pins


def read_npm_lockfile_full(workspace: Path) -> Dict[str, str]:
    """Read package-lock.json (v2/v3) and return the FULL resolved
    dependency tree as {name: version} — including transitive (nested
    node_modules) entries, unlike `_read_npm_lockfile` above which
    intentionally keeps only top-level pins for the static `immunity
    deps` scan. Used by the live transitive post-install CVE check
    (prismor/runtime/policy_engine.py), where a vulnerable package several levels
    deep is exactly the case a direct command/manifest check can't see.

    If the same package name resolves to more than one version in the
    tree (common in npm), the last one encountered wins — adequate for
    "does any resolved version of this name have a known CVE" scanning;
    we are not trying to enumerate every duplicate's exact path.
    """
    pins: Dict[str, str] = {}
    for lock in _iter_workspace_files(workspace, "package-lock.json"):
        try:
            data = json.loads(lock.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
        packages = data.get("packages") or {}
        if not isinstance(packages, dict):
            continue
        for path, meta in packages.items():
            if not path.startswith("node_modules/") or not isinstance(meta, dict):
                continue
            # "node_modules/a/node_modules/b" (transitive) -> "b": take
            # everything after the LAST "node_modules/" segment.
            name = path.rsplit("node_modules/", 1)[-1]
            version = meta.get("version")
            if name and isinstance(version, str):
                pins[name] = version
    return pins


# "<name>@<version>" / "/<name>@<version>" pnpm keys, where <name> may be a
# scoped "@scope/pkg". Anchored on the LAST '@' so the scope's own '@' is safe.
_PNPM_KEY_RE = re.compile(r'^/?(?P<name>(?:@[^/@\s]+/)?[^@/\s][^@\s]*)@(?P<version>[0-9][^\s(]*)')
# yarn v1: an indented `version "1.2.3"` line under a `pkg@range:` header.
_YARN_V1_VERSION_RE = re.compile(r'^\s+version\s+"?([^"\s]+)"?\s*$')
# yarn v1 header: one or more comma-separated `name@range` specs ending in ':'.
_YARN_V1_HEADER_RE = re.compile(r'^"?(?P<name>(?:@[^/@\s]+/)?[^@\s"]+)@')


def _lockfiles(workspace: Path, filename: str):
    """Yield candidate lockfiles, skipping vendored and VCS directories."""
    return _iter_workspace_files(workspace, filename)


def read_pnpm_lockfile_full(workspace: Path) -> Dict[str, str]:
    """Read pnpm-lock.yaml and return the full resolved tree as {name: version}.

    pnpm flattens every resolved package — direct and transitive alike — under
    a single top-level ``packages:`` map, so there is no tree to walk. Key
    shapes differ across lockfile versions (``/lodash@4.17.21`` in v6,
    ``lodash@4.17.21`` in v9, with an optional ``(peer)`` suffix on both), which
    the key regex normalizes.
    """
    pins: Dict[str, str] = {}
    try:
        import yaml
    except Exception:
        return pins
    for lock in _lockfiles(workspace, "pnpm-lock.yaml"):
        try:
            data = yaml.safe_load(lock.read_text(encoding="utf-8"))
        except Exception:
            continue
        if not isinstance(data, dict):
            continue
        packages = data.get("packages") or {}
        if not isinstance(packages, dict):
            continue
        for key, meta in packages.items():
            match = _PNPM_KEY_RE.match(str(key))
            if not match:
                continue
            version = match.group("version")
            # v9 moved the resolved version into the entry for some shapes;
            # prefer an explicit one when present.
            if isinstance(meta, dict) and isinstance(meta.get("version"), str):
                version = meta["version"]
            pins[match.group("name")] = version
    return pins


def read_yarn_lockfile_full(workspace: Path) -> Dict[str, str]:
    """Read yarn.lock and return the full resolved tree as {name: version}.

    Handles both dialects: classic v1 (a bespoke text format) and Berry v2+
    (YAML). Like pnpm, yarn resolves every package into one flat map, so the
    result already includes transitive dependencies.
    """
    pins: Dict[str, str] = {}
    for lock in _lockfiles(workspace, "yarn.lock"):
        try:
            text = lock.read_text(encoding="utf-8")
        except OSError:
            continue

        # Berry lockfiles are valid YAML and declare a __metadata block.
        if "__metadata" in text:
            try:
                import yaml
                data = yaml.safe_load(text)
            except Exception:
                data = None
            if isinstance(data, dict):
                for key, meta in data.items():
                    if key == "__metadata" or not isinstance(meta, dict):
                        continue
                    version = meta.get("version")
                    # "lodash@npm:^4.17.0, lodash@npm:^4.17.21" -> lodash
                    header = _YARN_V1_HEADER_RE.match(str(key).split(",")[0].strip())
                    if header and isinstance(version, str):
                        pins[header.group("name")] = version
                continue  # parsed as YAML; don't also run the v1 scanner

        # Classic v1: a `name@range:` header followed by an indented `version`.
        current: Optional[str] = None
        for line in text.splitlines():
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            if not line[0].isspace():
                header = _YARN_V1_HEADER_RE.match(line.split(",")[0].strip())
                current = header.group("name") if header else None
                continue
            if current:
                version_match = _YARN_V1_VERSION_RE.match(line)
                if version_match:
                    pins[current] = version_match.group(1)
                    current = None
    return pins


def read_js_lockfiles_full(workspace: Path) -> Dict[str, str]:
    """Union of every JS lockfile's resolved tree as {name: version}.

    npm, pnpm and yarn all resolve from the same registry, so OSV treats them
    as one ``npm`` ecosystem — a CVE in a transitive dependency is the same
    finding regardless of which client installed it. Merged newest-parser-last;
    duplicates across lockfiles in one workspace are rare and either version is
    adequate for "does any resolved version of this name have a known CVE".
    """
    pins: Dict[str, str] = {}
    pins.update(read_npm_lockfile_full(workspace))
    pins.update(read_pnpm_lockfile_full(workspace))
    pins.update(read_yarn_lockfile_full(workspace))
    return pins


def _parse_requirements_txt(text: str) -> List[Dict[str, str]]:
    """Parse requirements.txt (simple format)."""
    deps: List[Dict[str, str]] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        # Handle name==version, name>=version, name~=version, bare name,
        # optional PEP 508 extras (name[extra]==version) and PEP 440 tags such
        # as rc1/post1 that are not purely digits and dots. The \s* after the
        # operator keeps the spaced form pip also accepts ("flask == 2.0").
        # Stops at an environment marker (";") or trailing comment ("#").
        match = re.match(r'^([A-Za-z0-9_.-]+)\s*(?:\[[^\]]*\])?\s*([><=!~]+\s*[^\s;#]*)?', line)
        if match:
            name = match.group(1)
            version = (match.group(2) or "").strip()
            deps.append({"name": name, "version": version, "ecosystem": "pip"})
    return deps


def _parse_pyproject_toml(text: str) -> List[Dict[str, str]]:
    """Parse pyproject.toml dependencies (simple regex, no TOML parser)."""
    deps: List[Dict[str, str]] = []
    # Match lines like: "requests>=2.28", "flask", etc. inside dependencies array
    in_deps = False
    for line in text.splitlines():
        stripped = line.strip()
        if re.match(r'^dependencies\s*=\s*\[', stripped):
            in_deps = True
            continue
        if in_deps:
            if stripped.startswith("]"):
                in_deps = False
                continue
            # Extract package spec from quoted string. The optional
            # "[extra,extra]" group keeps PEP 508 extras from dropping the whole
            # dependency (e.g. "requests[security]>=2.28").
            match = re.match(
                r'^["\']([A-Za-z0-9_.-]+)\s*(?:\[[^\]]*\])?\s*([><=!~].*?)?["\']',
                stripped,
            )
            if match:
                deps.append({
                    "name": match.group(1),
                    "version": (match.group(2) or "").strip(),
                    "ecosystem": "pip",
                })
    return deps


def _parse_go_mod(text: str) -> List[Dict[str, str]]:
    """Parse go.mod require blocks."""
    deps: List[Dict[str, str]] = []
    in_require = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("require ("):
            in_require = True
            continue
        if in_require:
            if stripped == ")":
                in_require = False
                continue
            parts = stripped.split()
            if len(parts) >= 2:
                deps.append({"name": parts[0], "version": parts[1], "ecosystem": "go"})
        elif stripped.startswith("require "):
            parts = stripped.split()
            if len(parts) >= 3:
                deps.append({"name": parts[1], "version": parts[2], "ecosystem": "go"})
    return deps


def _parse_cargo_toml(text: str) -> List[Dict[str, str]]:
    """Parse Cargo.toml [dependencies] section."""
    deps: List[Dict[str, str]] = []
    in_deps = False
    for line in text.splitlines():
        stripped = line.strip()
        if re.match(r'^\[dependencies\]', stripped, re.IGNORECASE):
            in_deps = True
            continue
        if in_deps:
            if stripped.startswith("["):
                in_deps = False
                continue
            if not stripped or stripped.startswith("#"):
                continue
            # name = "version" or name = { version = "..." }
            match = re.match(r'^([A-Za-z0-9_-]+)\s*=\s*"([^"]*)"', stripped)
            if match:
                deps.append({"name": match.group(1), "version": match.group(2), "ecosystem": "cargo"})
            else:
                # name = { version = "..." }
                match = re.match(r'^([A-Za-z0-9_-]+)\s*=\s*\{.*version\s*=\s*"([^"]*)"', stripped)
                if match:
                    deps.append({"name": match.group(1), "version": match.group(2), "ecosystem": "cargo"})
    return deps


_AFFECTED_RE = re.compile(r"^\s*([A-Za-z0-9_./@-]+)\s*([<>=!]+)?\s*(.+)?\s*$")


def _affected_to_range(affected_str: str) -> Tuple[str, Tuple]:
    """Split "lodash<=4.17.20" into ("lodash", range-tuple).

    Range-tuple is parsed via supplychain.version_range.parse_npm_range using
    the operator prefix. Returns (name, (None, None)) if no version constraint
    (e.g. bare "lodash") — caller falls back to name-only matching.
    """
    from supplychain.version_range import parse_npm_range

    match = _AFFECTED_RE.match(affected_str or "")
    if not match:
        return ("", (None, None))
    name = match.group(1).lower()
    op = match.group(2) or ""
    ver = match.group(3) or ""
    if not op or not ver:
        return (name, (None, None))
    return (name, parse_npm_range(f"{op}{ver}"))


def check_against_feed(
    deps: List[Dict[str, str]],
    feed: Dict[str, Any],
) -> List[Dict[str, Any]]:
    """Match dependencies against threat-feed advisories using range-aware
    comparison. Falls back to name-only matching when either side lacks a
    version (e.g. supplychain CLI passes ``version=""``).
    """
    from supplychain.version_range import (
        is_floating, parse_npm_range, parse_version, ranges_overlap, version_in_range,
    )

    dep_advisories = [a for a in feed.get("advisories", []) if a.get("type") == "dependency_vulnerability"]

    by_name: Dict[str, List[Dict[str, Any]]] = {}
    for dep in deps:
        by_name.setdefault(dep["name"].lower(), []).append(dep)

    matches: List[Dict[str, Any]] = []
    for advisory in dep_advisories:
        for affected_str in advisory.get("affected", []):
            adv_name, adv_range = _affected_to_range(affected_str)
            candidates = by_name.get(adv_name, [])
            if not candidates:
                continue
            matched_deps: List[Dict[str, Any]] = []
            for dep in candidates:
                dep_version_str = str(dep.get("version", ""))
                if not dep_version_str or adv_range == (None, None):
                    # Name-only fallback: either we don't know the dep version
                    # or the advisory has no version constraint.
                    matched_deps.append(dep)
                    continue
                if dep.get("pinned_via_lock") or not is_floating(dep_version_str):
                    pv = parse_version(dep_version_str)
                    if pv is None:
                        matched_deps.append(dep)
                        continue
                    if version_in_range(pv, *adv_range):
                        matched_deps.append(dep)
                else:
                    # Unpinned floating range — overlap with the advisory's
                    # vulnerable range means a resolve *could* land vulnerable.
                    dep_range = parse_npm_range(dep_version_str)
                    if ranges_overlap(dep_range, adv_range):
                        matched_deps.append(dep)
            if matched_deps:
                matches.append({
                    "advisory_id": advisory.get("id", ""),
                    "severity": advisory.get("severity", "unknown"),
                    "title": advisory.get("title", ""),
                    "affected": affected_str,
                    "action": advisory.get("action", ""),
                    "matched_deps": matched_deps,
                })
    return matches


def check_floating_ranges(
    workspace: Path,
    lockfile_map: Optional[Dict[str, str]] = None,
) -> List[Dict[str, Any]]:
    """Flag floating semver ranges in package.json.

    Severity LOW when a lockfile pin exists (future install is the risk),
    MEDIUM when no pin exists. Manifests without any lockfile at all are
    already covered by `check_lockfile_presence` — skip them to dedup.
    """
    from supplychain.version_range import is_floating

    lockfile_map = lockfile_map or {}
    findings: List[Dict[str, Any]] = []
    for pkg_json in _iter_workspace_files(workspace, "package.json"):
        if not (pkg_json.parent / "package-lock.json").is_file():
            continue
        try:
            data = json.loads(pkg_json.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
        for section in ("dependencies", "devDependencies"):
            for name, raw in (data.get(section) or {}).items():
                raw_str = str(raw)
                if not is_floating(raw_str):
                    continue
                pinned = lockfile_map.get(name)
                findings.append({
                    "manifest": str(pkg_json),
                    "name": name,
                    "range": raw_str,
                    "pinned_version": pinned or "",
                    "severity": "LOW" if pinned else "MEDIUM",
                    "message": (
                        f"{name!r} uses floating range {raw_str!r}"
                        + (f" (lockfile pins {pinned})" if pinned else " (no lockfile pin)")
                    ),
                })
    return findings


def _reachable_lockfile_names(declared: set, packages: Dict[str, Any]) -> Optional[set]:
    """BFS the lockfile's per-package dependency edges starting from the
    manifest's declared dependency names, returning every package name
    reachable through the real dependency graph.

    npm hoists resolvable transitive dependencies to flat top-level
    `node_modules/<name>` entries whenever there's no version conflict -
    so a package that is NOT a direct dependency commonly still has a
    flat, non-nested lockfile path identical in shape to a real direct
    dependency. Without this reachability check, that hoisting pattern
    is indistinguishable from genuine lockfile injection (an entry npm
    will install that nothing in the actual dependency graph requires).

    Every entry contributes edges, including nested
    `node_modules/a/node_modules/b` records, keyed by the terminal
    package name: a hoisted package is frequently required *only* by a
    nested copy of its parent, and ignoring nested records made those
    look unreachable (PrismorSec/prismor#289). Workspace member entries
    (monorepo packages, whose paths are not under `node_modules/`) seed
    the frontier, since npm installs their dependencies into the root
    `node_modules` too.

    Returns None if no `node_modules/` entry carries dependency metadata
    (older or non-standard lockfile shapes) - callers should fall back
    to a softer signal rather than assert injection without being able
    to verify it.
    """
    if not declared:
        return None

    own_deps: Dict[str, List[str]] = {}
    workspace_seeds: set = set()
    has_dep_metadata = False
    for path, meta in packages.items():
        if not isinstance(meta, dict):
            continue
        if path.startswith("node_modules/"):
            # Installed package. devDependencies are NOT installed for
            # transitive packages, so they must not create edges here.
            # Terminal name of the path: node_modules/a/node_modules/@s/b -> @s/b
            name = path.rsplit("node_modules/", 1)[1]
            if meta.get("link") is True:
                # Symlink into a workspace member - npm created it from
                # the root manifest's `workspaces`, never an injection.
                workspace_seeds.add(name)
            edges: List[str] = []
            for field in ("dependencies", "optionalDependencies", "peerDependencies"):
                block = meta.get(field)
                if isinstance(block, dict):
                    # An empty dict still proves this lockfile records
                    # per-package edges, so reachability is verifiable.
                    has_dep_metadata = True
                    edges.extend(block.keys())
            if edges:
                own_deps.setdefault(name, []).extend(edges)
        else:
            # Root ("") or a workspace member ("packages/foo"). Their
            # dependencies - dev ones included - are installed at the root.
            for field in (
                "dependencies", "devDependencies",
                "optionalDependencies", "peerDependencies",
            ):
                block = meta.get(field)
                if isinstance(block, dict):
                    workspace_seeds.update(block.keys())

    if not has_dep_metadata:
        return None

    reachable: set = set()
    frontier = list(declared) + list(workspace_seeds)
    while frontier:
        name = frontier.pop()
        if name in reachable:
            continue
        reachable.add(name)
        frontier.extend(own_deps.get(name, []))
    return reachable


def check_lockfile_integrity(workspace: Path) -> List[Dict[str, Any]]:
    """Detect lockfile issues that indicate tampering or supply-chain risk.

    Specifically:
      1. ``file:`` or ``git+`` deps in lockfiles (supply-chain bypass).
      2. package-lock.json entries without ``integrity:`` hashes.
      3. Lockfile entries that are not a declared direct dependency AND
         not reachable from one through the real dependency graph
         (genuine lockfile injection — npm will install them anyway).
         A hoisted *transitive* dependency (npm's normal flat
         node_modules layout) looks identical in lockfile shape to a
         direct dependency but IS reachable, so it's correctly excluded
         here rather than flagged — see `_reachable_lockfile_names`.

    Returns list of {manifest, lockfile, issue, severity, message}.
    """
    findings: List[Dict[str, Any]] = []
    for pkg_json in _iter_workspace_files(workspace, "package.json"):
        lock_path = pkg_json.parent / "package-lock.json"
        if not lock_path.is_file():
            continue
        try:
            pkg = json.loads(pkg_json.read_text(encoding="utf-8"))
            lock = json.loads(lock_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue

        declared = set(
            list((pkg.get("dependencies") or {}).keys())
            + list((pkg.get("devDependencies") or {}).keys())
            + list((pkg.get("optionalDependencies") or {}).keys())
            + list((pkg.get("peerDependencies") or {}).keys())
        )

        packages = lock.get("packages") or {}
        if not isinstance(packages, dict):
            continue

        for pkg_path, meta in packages.items():
            # The root entry has path "" — skip
            if not pkg_path or not isinstance(meta, dict):
                continue

            # Resolved URL: flag git / file / tarball sources that skip
            # the registry integrity chain.
            resolved = str(meta.get("resolved", ""))
            version = str(meta.get("version", ""))
            if resolved.startswith(("git+", "git://", "ssh://")) or version.startswith(("git+", "file:")):
                pkg_name = pkg_path.split("node_modules/")[-1]
                findings.append({
                    "manifest": str(pkg_json),
                    "lockfile": str(lock_path),
                    "issue": "non-registry-source",
                    "severity": "HIGH",
                    "message": f"{pkg_name!r} in lockfile pulled from non-registry source ({resolved or version})",
                })
                continue

            # Registry deps without integrity hash → possible tampering
            if resolved.startswith("https://") and not meta.get("integrity"):
                pkg_name = pkg_path.split("node_modules/")[-1]
                findings.append({
                    "manifest": str(pkg_json),
                    "lockfile": str(lock_path),
                    "issue": "missing-integrity",
                    "severity": "MEDIUM",
                    "message": f"{pkg_name!r} in lockfile has no integrity hash",
                })

        # Lockfile entries not declared AND not reachable from a declared
        # dependency through the real graph. Nested transitive entries
        # are skipped outright (legitimate by construction); flat/hoisted
        # entries are checked against reachability before being flagged.
        reachable = _reachable_lockfile_names(declared, packages)
        for pkg_path in packages:
            if not pkg_path.startswith("node_modules/"):
                continue
            pkg_name = pkg_path[len("node_modules/"):]
            if "/node_modules/" in pkg_name:
                continue  # transitive (nested) — legitimate by construction
            if pkg_name in declared:
                continue
            if reachable is not None:
                if pkg_name in reachable:
                    continue  # hoisted transitive dep — not injection
                findings.append({
                    "manifest": str(pkg_json),
                    "lockfile": str(lock_path),
                    "issue": "lockfile-injection",
                    "severity": "HIGH",
                    "message": (
                        f"{pkg_name!r} is not declared in package.json and not "
                        f"reachable from any declared dependency — possible "
                        f"lockfile injection"
                    ),
                })
            else:
                # Reachability couldn't be computed for this lockfile
                # shape — report as a softer, unverified signal instead
                # of asserting injection.
                findings.append({
                    "manifest": str(pkg_json),
                    "lockfile": str(lock_path),
                    "issue": "undeclared-direct-entry",
                    "severity": "INFO",
                    "message": (
                        f"{pkg_name!r} is a direct lockfile entry not declared in "
                        f"package.json (may be a legitimately hoisted transitive "
                        f"dependency — reachability could not be verified for "
                        f"this lockfile's format)"
                    ),
                })

    return findings


def check_against_ioc(deps: List[Dict[str, str]]) -> List[Dict[str, Any]]:
    """Match dependencies against the bundled supply-chain IOC database
    (``supplychain.ioc``).

    This is independent of the signed advisory feed. The feed currently ships
    zero ``dependency_vulnerability`` advisories, so without this `prismor deps`
    could never flag a known-malicious package (e.g. ``mistralai==2.4.6``,
    ``@mistralai/mistralai`` in the mini-Shai-Hulud range) even though Prismor
    curates exactly those IOCs. Results are shaped like ``check_against_feed``
    matches so all existing rendering and exit-code logic applies unchanged.
    """
    try:
        from supplychain.ioc import check_package
    except Exception:
        return []

    def _exact_version(raw: str) -> Optional[str]:
        # A concrete pinned version enables the CRITICAL exact-range check.
        # pip keeps its operator ("==2.4.6"); npm stores a bare version.
        # Anything floating/range (>=, ~=, ^, *, a git url) -> None -> the
        # name-only (HIGH) IOC verdict rather than a bogus range comparison.
        v = (raw or "").strip()
        m = re.match(r"^==\s*([0-9][\w.\-+]*)$", v)
        if m:
            return m.group(1)
        if re.match(r"^[0-9][\w.\-+]*$", v):
            return v
        return None

    matches: List[Dict[str, Any]] = []
    for dep in deps:
        name = dep.get("name", "")
        if not name:
            continue
        raw_version = str(dep.get("version", ""))
        exact = _exact_version(raw_version)
        hit = check_package(name, exact)
        if not hit:
            continue
        shown = exact or raw_version
        matches.append({
            "advisory_id": hit.ioc_id,
            "severity": str(hit.severity).lower(),
            "title": hit.description,
            "affected": f"{name}@{shown}" if shown else name,
            "action": "Remove this package or pin to a known-safe version.",
            "matched_deps": [dep],
            "source": "ioc",
        })
    return matches


def scan_workspace(
    workspace: Path,
    feed: Dict[str, Any],
) -> Dict[str, Any]:
    """Full workspace dependency scan.

    Returns {manifests, dependencies, feed_matches, lockfile_issues,
    integrity_issues, floating_ranges}.
    """
    manifests = find_manifests(workspace)
    lockfile_map = _read_npm_lockfile(workspace)
    all_deps: List[Dict[str, str]] = []
    for m in manifests:
        lock = lockfile_map if m["ecosystem"] == "npm" else None
        deps = parse_dependencies(m["path"], m["ecosystem"], lockfile_map=lock)
        all_deps.extend(deps)

    feed_matches = check_against_feed(all_deps, feed)
    # The signed feed carries no dependency_vulnerability advisories today, so
    # also consult the bundled IOC database directly. Dedup by (id, dep name)
    # in case a future feed and the IOC list name the same compromise.
    _seen = {(m.get("advisory_id"), d.get("name"))
             for m in feed_matches for d in m.get("matched_deps", [])}
    for m in check_against_ioc(all_deps):
        key = (m.get("advisory_id"), m["matched_deps"][0].get("name"))
        if key not in _seen:
            feed_matches.append(m)
            _seen.add(key)
    lockfile_issues = check_lockfile_presence(workspace)
    integrity_issues = check_lockfile_integrity(workspace)
    floating_ranges = check_floating_ranges(workspace, lockfile_map)

    return {
        "manifests": [{"path": str(m["path"]), "ecosystem": m["ecosystem"]} for m in manifests],
        "dependencies": len(all_deps),
        "feed_matches": feed_matches,
        "lockfile_issues": lockfile_issues,
        "integrity_issues": integrity_issues,
        "floating_ranges": floating_ranges,
    }
