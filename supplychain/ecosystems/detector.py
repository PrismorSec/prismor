"""Install command parser — turns argv into a structured InstallEvent.

Supports: npm, pnpm, yarn, bun, pip, pip3, uv, poetry, cargo, go
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class PackageSpec:
    raw: str          # as given by user, e.g. "express", "github:user/repo"
    name: str         # normalized name without version, e.g. "express", "@scope/pkg"
    source: str       # "registry" | "git" | "tarball" | "local"
    version: str = "" # user-requested version extracted from raw, e.g. "2.4.6"


@dataclass
class InstallEvent:
    ecosystem: str            # "npm", "pip", "cargo", etc.
    argv: List[str]           # original full argv passed to immunity
    packages: List[PackageSpec]
    custom_registry: Optional[str] = None


# (binary, subcommand) -> ecosystem
_INSTALL_MAP: Dict[tuple, str] = {
    ("npm", "install"): "npm",
    ("npm", "i"): "npm",
    ("npm", "add"): "npm",
    ("pnpm", "install"): "pnpm",
    ("pnpm", "add"): "pnpm",
    ("pnpm", "i"): "pnpm",
    ("yarn", "add"): "yarn",
    ("bun", "add"): "bun",
    ("bun", "install"): "bun",
    ("pip", "install"): "pip",
    ("pip3", "install"): "pip",
    ("uv", "add"): "uv",
    ("poetry", "add"): "pip",
    ("cargo", "add"): "cargo",
    ("cargo", "install"): "cargo",
    ("go", "get"): "go",
    ("go", "install"): "go",
}

# Flags that consume the next token (so we don't mistake values for package names)
_VALUE_FLAGS = {
    "--registry", "--workspace", "-C", "--prefix", "--userconfig",
    "-r", "--requirement",
    "--target", "-t",
    "--index-url", "-i",
    "--extra-index-url",
    "--config-file",
}


def _classify_source(raw: str) -> str:
    if raw.startswith(("git+", "git://", "github:", "gitlab:", "bitbucket:")):
        return "git"
    if raw.startswith(("http://", "https://")) and re.search(r"\.(tgz|tar\.gz|zip)($|\?)", raw):
        return "tarball"
    if raw.startswith(("./", "../", "/")) or raw.startswith("file:"):
        return "local"
    return "registry"


def _normalize_name(raw: str, ecosystem: str) -> str:
    """Strip version specifier from a registry package name."""
    if ecosystem in ("npm", "pnpm", "yarn", "bun"):
        # @scope/name@version → @scope/name
        if raw.startswith("@"):
            bare = raw[1:].split("@")[0]
            return "@" + bare
        return raw.split("@")[0]
    elif ecosystem in ("pip", "uv"):
        m = re.match(r"^([A-Za-z0-9_.-]+)", raw)
        return m.group(1) if m else raw
    elif ecosystem == "cargo":
        return raw.split("@")[0]
    # go: full module path is the name
    return raw


def _extract_version(raw: str, ecosystem: str) -> str:
    """Extract the user-requested version from a package spec string.

    Returns an empty string when no version is pinned so the caller can
    fall back to whatever the registry reports.

    Only an exact version counts as pinned. A partial or range spec
    (`pkg@1`, `pkg@^1.2`, `pkg==1.*`) is not a version OSV can match, so it is
    treated like an unpinned install (#599).
    """
    if ecosystem in ("pip", "uv"):
        # pip: pkg==1.2.3  pkg>=1.0  pkg~=1.0  pkg[extra]==1.0
        m = re.search(r'==([A-Za-z0-9._-]+)(?![\w.*])', raw)
        return m.group(1) if m else ""
    if ecosystem in ("npm", "pnpm", "yarn", "bun", "cargo"):
        # @scope/pkg@1.2.3  pkg@1.2.3  crate@1.2.3
        parts = raw.lstrip("@").split("@")
        version = parts[1] if len(parts) > 1 else ""
        return version if re.fullmatch(r'\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.+-]+)?', version) else ""
    return ""


def detect_install(argv: List[str]) -> Optional[InstallEvent]:
    """Parse argv (e.g. ['npm', 'install', 'express']) → InstallEvent or None.

    Returns None if the command is not a recognised package install.
    Returns an InstallEvent with empty packages if it's a manifest-only install
    (e.g. bare 'npm install' with no package names specified).
    """
    if len(argv) < 2:
        return None

    binary = argv[0].lower()

    # Special case: "uv pip install ..."
    if binary == "uv" and len(argv) >= 3 and argv[1] == "pip" and argv[2] == "install":
        eco = "uv"
        rest = argv[3:]
    else:
        sub = argv[1].lower()
        eco = _INSTALL_MAP.get((binary, sub))
        if eco is None:
            return None
        rest = argv[2:]

    packages: List[PackageSpec] = []
    custom_registry: Optional[str] = None
    skip_next = False

    for i, arg in enumerate(rest):
        if skip_next:
            skip_next = False
            continue

        if arg.startswith("--registry="):
            custom_registry = arg.split("=", 1)[1]
        elif arg == "--registry" and i + 1 < len(rest):
            custom_registry = rest[i + 1]
            skip_next = True
        elif arg in _VALUE_FLAGS and i + 1 < len(rest):
            skip_next = True
        elif arg.startswith("-"):
            pass  # other flag, ignore
        else:
            source = _classify_source(arg)
            name = _normalize_name(arg, eco) if source == "registry" else arg
            version = _extract_version(arg, eco) if source == "registry" else ""
            packages.append(PackageSpec(raw=arg, name=name, source=source, version=version))

    return InstallEvent(
        ecosystem=eco,
        argv=argv,
        packages=packages,
        custom_registry=custom_registry,
    )
