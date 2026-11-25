"""Package manager config hardener.

`prismor supplychain harden [--dry-run]` scans the project root for package manager
manifests, detects existing configs, and applies security hardening that
shrinks the install-script attack surface and tightens version pinning to
complement prismor's runtime age-gate checks.

Supported targets:
  .npmrc               npm / pnpm / bun
  .yarnrc              Yarn Classic
  .yarnrc.yml          Yarn Berry (2/3/4)
  pip.conf / pip.ini   pip  (pip.ini on Windows; needs PIP_CONFIG_FILE or venv)
  .cargo/config.toml   Cargo / Rust
"""
from __future__ import annotations

import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Tuple


# ── Colour helpers (same palette as cli.py) ───────────────────────────────────

_RED    = "\033[0;31m"
_YELLOW = "\033[1;33m"
_GREEN  = "\033[0;32m"
_CYAN   = "\033[0;36m"
_DIM    = "\033[37m"
_BOLD   = "\033[1m"
_RESET  = "\033[0m"


def _c(text: str, colour: str) -> str:
    if sys.stdout.isatty():
        return f"{colour}{text}{_RESET}"
    return text


# ── Data types ────────────────────────────────────────────────────────────────

@dataclass
class HardeningChange:
    key: str
    value: str
    reason: str


@dataclass
class HardeningResult:
    path: Path
    ecosystem: str
    created: bool
    applied: List[HardeningChange] = field(default_factory=list)
    already_set: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)

    @property
    def any_changes(self) -> bool:
        return bool(self.applied)


def _is_windows() -> bool:
    return sys.platform == "win32"


# ── String helpers ────────────────────────────────────────────────────────────

def _append_block(existing: str, block: str) -> str:
    """Append block to existing content with proper newline separation."""
    content = existing
    if content and not content.endswith("\n"):
        content += "\n"
    if content:
        content += "\n"
    return content + block + "\n"


# ── .npmrc  (npm / pnpm / bun) ────────────────────────────────────────────────

_NPMRC_RULES: List[Tuple[str, str, str]] = [
    (
        "ignore-scripts", "true",
        "blocks preinstall/postinstall lifecycle scripts — the primary delivery vector"
        " in every npm supply chain attack in the IOC database (mini-shai-hulud, AntV, etc.)",
    ),
    (
        "save-exact", "true",
        "pins exact versions on install — SemVer ranges can silently resolve to a newly"
        " published version between writing a manifest and the next fresh install",
    ),
    (
        "audit", "true",
        "ensures npm audit runs on every install",
    ),
]


def _npmrc_has(content: str, key: str, value: str) -> bool:
    return bool(re.search(
        rf"^\s*{re.escape(key)}\s*=\s*{re.escape(value)}\s*$",
        content, re.MULTILINE | re.IGNORECASE,
    ))


def _npmrc_key_exists(content: str, key: str) -> bool:
    return bool(re.search(
        rf"^\s*{re.escape(key)}\s*=",
        content, re.MULTILINE | re.IGNORECASE,
    ))


def _harden_npmrc(root: Path, dry_run: bool) -> Optional[HardeningResult]:
    path = root / ".npmrc"
    if not (root / "package.json").exists() and not path.exists():
        return None

    existing = path.read_text() if path.exists() else ""
    created = not path.exists()
    new_lines: List[str] = []
    applied: List[HardeningChange] = []
    already_set: List[str] = []

    for key, value, reason in _NPMRC_RULES:
        if _npmrc_has(existing, key, value):
            already_set.append(f"{key}={value}")
        elif _npmrc_key_exists(existing, key):
            already_set.append(f"{key} (custom value — not overwritten)")
        else:
            new_lines.append(f"{key}={value}")
            applied.append(HardeningChange(key=key, value=value, reason=reason))

    if new_lines and not dry_run:
        block = "# prismor supplychain harden\n" + "\n".join(new_lines)
        path.write_text(_append_block(existing, block))

    notes: List[str] = []
    ignore_scripts_active = (
        any(c.key == "ignore-scripts" for c in applied)
        or "ignore-scripts=true" in already_set
    )
    if ignore_scripts_active:
        notes.append(
            "ignore-scripts blocks install hooks globally. Some packages legitimately need them"
            " (node-gyp native modules). Allow per-package via 'npm rebuild <pkg> --foreground-scripts'"
            " or pnpm's onlyBuiltDependencies allowlist."
        )

    return HardeningResult(
        path=path, ecosystem="npm / pnpm / bun",
        created=created, applied=applied, already_set=already_set, notes=notes,
    )


# ── .yarnrc  (Yarn Classic) ───────────────────────────────────────────────────

def _harden_yarnrc_classic(root: Path, dry_run: bool) -> Optional[HardeningResult]:
    path = root / ".yarnrc"
    if not path.exists():
        return None

    existing = path.read_text()
    applied: List[HardeningChange] = []
    already_set: List[str] = []

    if re.search(r"^--ignore-scripts\s+true\s*$", existing, re.MULTILINE | re.IGNORECASE):
        already_set.append("--ignore-scripts true")
    elif re.search(r"^--ignore-scripts\b", existing, re.MULTILINE | re.IGNORECASE):
        already_set.append("--ignore-scripts (custom value — not overwritten)")
    else:
        applied.append(HardeningChange(
            key="--ignore-scripts", value="true",
            reason="blocks Yarn Classic lifecycle scripts",
        ))
        if not dry_run:
            block = "# prismor supplychain harden\n--ignore-scripts true"
            path.write_text(_append_block(existing, block))

    return HardeningResult(
        path=path, ecosystem="Yarn Classic",
        created=False, applied=applied, already_set=already_set,
    )


# ── .yarnrc.yml  (Yarn Berry 2/3/4) ──────────────────────────────────────────

def _harden_yarnrc_yml(root: Path, dry_run: bool) -> Optional[HardeningResult]:
    path = root / ".yarnrc.yml"
    if not path.exists():
        return None

    existing = path.read_text()
    applied: List[HardeningChange] = []
    already_set: List[str] = []

    if re.search(r"^\s*enableScripts\s*:\s*false\s*$", existing, re.MULTILINE | re.IGNORECASE):
        already_set.append("enableScripts: false")
    elif re.search(r"^\s*enableScripts\s*:", existing, re.MULTILINE | re.IGNORECASE):
        already_set.append("enableScripts (custom value — not overwritten)")
    else:
        applied.append(HardeningChange(
            key="enableScripts", value="false",
            reason="disables Yarn Berry lifecycle scripts (Berry's equivalent of npm ignore-scripts)",
        ))
        if not dry_run:
            block = "# prismor supplychain harden\nenableScripts: false"
            path.write_text(_append_block(existing, block))

    return HardeningResult(
        path=path, ecosystem="Yarn Berry",
        created=False, applied=applied, already_set=already_set,
    )


# ── pip.conf  (pip / uv) ─────────────────────────────────────────────────────

_PIPCONF_RULES: List[Tuple[str, str, str]] = [
    (
        "no-input", "true",
        "prevents pip from blocking on prompts in CI/automated environments",
    ),
    (
        "disable-pip-version-check", "true",
        "suppresses upgrade prompts that could pull a newer pip mid-pipeline",
    ),
]

_PIPCONF_MANIFESTS = ("requirements.txt", "pyproject.toml", "setup.py", "setup.cfg")


def _harden_pip(root: Path, dry_run: bool) -> Optional[HardeningResult]:
    has_manifest = any((root / f).exists() for f in _PIPCONF_MANIFESTS)
    # pip reads pip.ini on Windows and pip.conf elsewhere; keep whichever exists.
    if (root / "pip.conf").exists():
        name = "pip.conf"
    else:
        name = "pip.ini" if (root / "pip.ini").exists() or _is_windows() else "pip.conf"
    path = root / name
    if not has_manifest and not path.exists():
        return None

    existing = path.read_text() if path.exists() else ""
    created = not path.exists()
    new_lines: List[str] = []
    applied: List[HardeningChange] = []
    already_set: List[str] = []

    for key, value, reason in _PIPCONF_RULES:
        if re.search(rf"^\s*{re.escape(key)}\s*=", existing, re.MULTILINE | re.IGNORECASE):
            already_set.append(key)
        else:
            new_lines.append(f"{key} = {value}")
            applied.append(HardeningChange(key=key, value=value, reason=reason))

    if new_lines and not dry_run:
        block = "[global]\n# prismor supplychain harden\n" + "\n".join(new_lines)
        path.write_text(_append_block(existing, block))

    activate = (f'$env:PIP_CONFIG_FILE = "{name}"' if _is_windows() else f"export PIP_CONFIG_FILE={name}")
    notes = [
        f"{name} is not auto-read from the project root. Activate with:"
        f"  {activate}"
        f"  (or copy to $VIRTUAL_ENV/{name} after creating a venv).",
        "For stronger pip hardening, generate hashes (pip-compile --generate-hashes)"
        " and set require-hashes = true under [install] in pip.conf.",
    ]

    return HardeningResult(
        path=path, ecosystem="pip",
        created=created, applied=applied, already_set=already_set, notes=notes,
    )


# ── .cargo/config.toml  (Cargo / Rust) ───────────────────────────────────────

_CARGO_NET_BLOCK = (
    "[net]\n"
    "retry = 2\n"
    "git-fetch-with-cli = true\n"
)


def _harden_cargo(root: Path, dry_run: bool) -> Optional[HardeningResult]:
    if not (root / "Cargo.toml").exists():
        return None

    config_path = root / ".cargo" / "config.toml"
    existing = config_path.read_text() if config_path.exists() else ""
    created = not config_path.exists()
    applied: List[HardeningChange] = []
    already_set: List[str] = []

    if re.search(r"^\[net\]", existing, re.MULTILINE):
        already_set.append("[net] section (manual review recommended)")
    else:
        applied.append(HardeningChange(
            key="[net]", value="retry=2, git-fetch-with-cli=true",
            reason=(
                "retry=2 handles transient network failures; "
                "git-fetch-with-cli routes git deps through your system git "
                "(respects gitconfig credentials and SSH keys, instead of cargo's "
                "built-in libgit2 fetcher)"
            ),
        ))
        if not dry_run:
            if not config_path.parent.exists():
                config_path.parent.mkdir(parents=True, exist_ok=True)
            block = "# prismor supplychain harden\n" + _CARGO_NET_BLOCK.rstrip()
            config_path.write_text(_append_block(existing, block))

    return HardeningResult(
        path=config_path, ecosystem="Cargo",
        created=created, applied=applied, already_set=already_set,
    )


# ── Orchestrator ──────────────────────────────────────────────────────────────

def harden_project(root: Path, dry_run: bool = False) -> List[HardeningResult]:
    """Scan root for package manager configs and apply hardening.

    Returns one HardeningResult per config examined or created.
    If dry_run is True, no files are written.
    """
    candidates = [
        _harden_npmrc(root, dry_run),
        _harden_yarnrc_classic(root, dry_run),
        _harden_yarnrc_yml(root, dry_run),
        _harden_pip(root, dry_run),
        _harden_cargo(root, dry_run),
    ]
    return [r for r in candidates if r is not None]


# ── Output ────────────────────────────────────────────────────────────────────

def print_harden_report(
    results: List[HardeningResult], root: Path, dry_run: bool
) -> None:
    print()
    suffix = _c("  [dry run — no files written]", _YELLOW) if dry_run else ""
    print(f"  {_c('PRISMOR', _BOLD)}  harden  {_c(str(root), _DIM)}{suffix}")
    print(f"  {_c('─' * 60, _DIM)}")
    print()

    if not results:
        print(f"  {_c('No package manager manifests found in this directory.', _DIM)}")
        print(f"  {_c('Looked for: package.json, .yarnrc(.yml), Cargo.toml, requirements.txt, pyproject.toml.', _DIM)}")
        print()
        return

    total_applied = 0
    total_created = 0

    for r in results:
        rel = _display_path(r.path, root)
        if r.created:
            state = _c("CREATED", _CYAN)
        elif r.applied:
            state = _c("UPDATED", _GREEN)
        else:
            state = _c("OK", _DIM)
        print(f"  {_c(rel, _BOLD)}  {_c(f'[{r.ecosystem}]', _DIM)}  {state}")

        for change in r.applied:
            verb = "would set" if dry_run else "set"
            label = f"{change.key}={change.value}" if not change.key.startswith("[") else change.key
            print(f"    {_c('+', _GREEN)} {verb} {_c(label, _BOLD)}")
            print(f"        {_c(change.reason, _DIM)}")

        for entry in r.already_set:
            print(f"    {_c('=', _DIM)} {entry}")

        for note in r.notes:
            print(f"    {_c('note:', _YELLOW)} {note}")

        print()
        total_applied += len(r.applied)
        if r.created:
            total_created += 1

    total_configs = len(results)
    changed = sum(1 for r in results if r.any_changes)
    if dry_run:
        print(f"  {_c(f'{total_applied} setting(s) would be applied across {total_configs} config(s).', _BOLD)}")
        print(f"  {_c('Remove --dry-run to write changes.', _DIM)}")
    else:
        created_str = f", {total_created} created" if total_created else ""
        if total_applied == 0:
            print(f"  {_c('All discovered configs are already hardened.', _GREEN)}")
        else:
            print(f"  {_c(f'{total_applied} setting(s) applied across {changed} config(s){created_str}.', _BOLD)}")
    print()


def _display_path(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)
