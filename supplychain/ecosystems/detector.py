"""Install command parser — turns argv into a structured InstallEvent.

Supports: npm, pnpm, yarn, bun, pip, pip3, uv, poetry, cargo, go,
gem / bundle add (RubyGems), composer require (Packagist) and
mvn dependency:get (Maven). Gradle has no "add a dependency" command --
those land via build-file edits -- so it is not an install command here.
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
    ("gem", "install"): "gem",
    ("gem", "i"): "gem",
    ("bundle", "add"): "gem",
    ("bundler", "add"): "gem",
    ("composer", "require"): "composer",
    ("composer", "req"): "composer",
    # mvn dependency:get is parsed by _detect_maven (goal can follow options).
}

# Per-ecosystem flags that consume the next token, on top of _VALUE_FLAGS.
_ECO_VALUE_FLAGS: Dict[str, frozenset] = {
    # gem install NAME -v 1.2.3 ; bundle add NAME --version "~> 1.2" --group dev
    "gem": frozenset({
        "-v", "--version", "-s", "--source", "-i", "--install-dir",
        "-n", "--bindir", "-g", "--group", "--require", "--path", "--git",
        "--github", "--branch", "--ref", "--platform", "-P", "--trust-policy",
    }),
    "composer": frozenset({"-d", "--working-dir"}),
    "maven": frozenset({"-f", "--file", "-s", "--settings", "-P",
                        "--activate-profiles", "-pl", "--projects", "-gs",
                        "--global-settings", "-l", "--log-file"}),
}

# Flags whose value is a non-default package source (custom registry).
_SOURCE_FLAGS = {"--registry", "-s", "--source", "--repository"}
# bundle add flags that point the gem at a VCS checkout instead of rubygems.org.
_GEM_VCS_FLAGS = {"--git", "--github"}
_MAVEN_BINARIES = {"mvn", "mvnw", "mvn.cmd", "mvnw.cmd"}

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
    if raw in (".", "..") or raw.startswith(("./", "../", "/")) or raw.startswith("file:"):
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
    elif ecosystem == "gem":
        # gem install rails:7.1.3  → rails
        return raw.split(":")[0]
    elif ecosystem == "composer":
        # vendor/pkg:^1.2  vendor/pkg=1.2.3  "vendor/pkg 1.2.3"  → vendor/pkg
        return re.split(r"[:= ]", raw, maxsplit=1)[0].lower()
    elif ecosystem == "maven":
        # groupId:artifactId[:version[:packaging[:classifier]]] → groupId:artifactId
        return ":".join(raw.split(":")[:2])
    # go: module path, without the @version / @latest query
    return raw.split("@")[0]


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
    if ecosystem == "go":
        # module@v1.2.3 → 1.2.3 (OSV and the go proxy take it without the v)
        version = raw.partition("@")[2]
        version = version[1:] if version[:1] == "v" else version
        return version if re.fullmatch(r'\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.+-]+)?', version) else ""
    if ecosystem in ("gem", "composer", "maven"):
        if ecosystem == "gem":
            parts = raw.split(":", 1)
        elif ecosystem == "composer":
            parts = re.split(r"[:= ]", raw, maxsplit=1)
        else:
            parts = raw.split(":")[2:3]
            parts = ["", parts[0]] if parts else []
        version = parts[1].strip() if len(parts) > 1 else ""
        version = version[1:] if ecosystem == "composer" and version[:1] == "v" else version
        # Maven versions are often two-part (guava 33.0-jre); gem/composer
        # need the full x.y.z to be an exact pin rather than a prefix.
        parts_re = r'{1,3}' if ecosystem == "maven" else r'{2,3}'
        exact = r'\d+(?:\.\d+)' + parts_re + r'(?:[-.][0-9A-Za-z.-]+)?'
        return version if re.fullmatch(exact, version) else ""
    return ""


_PY_RE = re.compile(r"^python(?:\d+(?:\.\d+)*)?$")
_PIP_RE = re.compile(r"^pip(?:\d+(?:\.\d+)*)?$")


def _canonical_argv(argv: List[str]) -> List[str]:
    """Same install, other spellings: `python3 -m pip`, `/usr/bin/pip3.12`,
    `pipx install`. Without this `python3 -m pip install <typosquat>` went
    straight past the gate that `pip install <typosquat>` hits."""
    if not argv:
        return argv
    binary = argv[0].replace("\\", "/").rsplit("/", 1)[-1].lower()
    if _PY_RE.match(binary) and len(argv) >= 3 and argv[1] == "-m":
        return _canonical_argv(argv[2:])
    if _PIP_RE.match(binary) or binary == "pipx":
        return ["pip", *argv[1:]]
    return [binary, *argv[1:]]


def detect_install(argv: List[str]) -> Optional[InstallEvent]:
    """Parse argv (e.g. ['npm', 'install', 'express']) → InstallEvent or None.

    Returns None if the command is not a recognised package install.
    Returns an InstallEvent with empty packages if it's a manifest-only install
    (e.g. bare 'npm install' with no package names specified).
    """
    argv = _canonical_argv(argv)
    if len(argv) < 2:
        return None

    binary = argv[0].lower()
    if binary.replace("\\", "/").rsplit("/", 1)[-1] in _MAVEN_BINARIES:
        return _detect_maven(argv)

    # Special case: "uv pip install ..."
    if binary == "uv" and len(argv) >= 3 and argv[1] == "pip" and argv[2] == "install":
        eco = "uv"
        rest = argv[3:]
    # "composer global require vendor/pkg"
    elif binary == "composer" and len(argv) >= 3 and argv[1].lower() == "global":
        eco = _INSTALL_MAP.get((binary, argv[2].lower()))
        if eco is None:
            return None
        rest = argv[3:]
    else:
        sub = argv[1].lower()
        eco = _INSTALL_MAP.get((binary, sub))
        if eco is None:
            return None
        rest = argv[2:]

    # The newer ecosystems get only their own value flags: pip's `-r`/`-i`
    # mean something else to gem (`-r` is --remote and takes no value).
    value_flags = _ECO_VALUE_FLAGS.get(eco, _VALUE_FLAGS)
    source_flags = _SOURCE_FLAGS if eco in _ECO_VALUE_FLAGS else {"--registry"}

    packages: List[PackageSpec] = []
    custom_registry: Optional[str] = None
    flag_version = ""
    vcs_source = False
    skip_next = False

    for i, arg in enumerate(rest):
        if skip_next:
            skip_next = False
            continue

        flag, eq, value = arg.partition("=")
        has_next = i + 1 < len(rest)
        if arg.startswith("-") and eq and flag in source_flags:
            custom_registry = value
        elif arg in source_flags and has_next:
            custom_registry = rest[i + 1]
            skip_next = True
        elif eco == "gem" and flag in ("-v", "--version"):
            if eq:
                flag_version = value
            elif has_next:
                flag_version = rest[i + 1]
                skip_next = True
        elif eco == "gem" and flag in _GEM_VCS_FLAGS:
            # bundle add NAME --git URL / --github user/repo
            vcs_source = True
            skip_next = not eq and has_next
        elif arg in value_flags and has_next:
            skip_next = True
        elif arg.startswith("-"):
            pass  # other flag, ignore
        elif eco == "composer" and "/" not in arg:
            # `composer require vendor/pkg 1.2.3`, or a platform package
            # (php, ext-json) that never comes from the registry.
            if packages and not packages[-1].version and re.match(r"^[v\d]", arg):
                prev = packages[-1]
                packages[-1] = PackageSpec(raw=prev.raw, name=prev.name, source=prev.source,
                                           version=_extract_version(f"{prev.name}:{arg}", eco))
        else:
            source = _classify_source(arg)
            name = _normalize_name(arg, eco) if source == "registry" else arg
            version = _extract_version(arg, eco) if source == "registry" else ""
            packages.append(PackageSpec(raw=arg, name=name, source=source, version=version))

    if eco == "gem":
        if vcs_source:
            packages = [PackageSpec(raw=p.raw, name=p.name, source="git") for p in packages]
        elif flag_version and len(packages) == 1 and not packages[0].version:
            p = packages[0]
            version = _extract_version(f"{p.name}:{flag_version}", eco)
            # An inexact -v (`~> 7.1`) stays on raw, so it reads as a range, not a bare name.
            packages = [PackageSpec(raw=p.raw if version else f"{p.raw}:{flag_version}",
                                    name=p.name, source=p.source, version=version)]

    return InstallEvent(
        ecosystem=eco,
        argv=argv,
        packages=packages,
        custom_registry=custom_registry,
    )


def _detect_maven(argv: List[str]) -> Optional[InstallEvent]:
    """``mvn [opts] dependency:get -Dartifact=g:a:v [-DremoteRepositories=url]``.

    Also accepts the split ``-DgroupId= -DartifactId= -Dversion=`` form and the
    fully-qualified goal. Any other mvn invocation (build, test) is not an
    install.
    """
    goals = {"dependency:get", "org.apache.maven.plugins:maven-dependency-plugin:get"}
    if not any(a in goals or (a.startswith("org.apache.maven.plugins:maven-dependency-plugin:")
                              and a.endswith(":get")) for a in argv[1:]):
        return None
    props: Dict[str, str] = {}
    for arg in argv[1:]:
        if arg.startswith("-D") and "=" in arg:
            key, _, value = arg[2:].partition("=")
            props[key] = value
    raw = props.get("artifact", "")
    if not raw and props.get("groupId") and props.get("artifactId"):
        raw = f"{props['groupId']}:{props['artifactId']}"
        if props.get("version"):
            raw += f":{props['version']}"
    packages: List[PackageSpec] = []
    if ":" in raw:
        packages.append(PackageSpec(raw=raw, name=_normalize_name(raw, "maven"),
                                    source="registry", version=_extract_version(raw, "maven")))
    repo = props.get("remoteRepositories") or props.get("repoUrl")
    return InstallEvent(ecosystem="maven", argv=argv, packages=packages,
                        custom_registry=repo or None)
