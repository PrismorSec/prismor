"""Secret-detection pattern management for Prismor cloaking.

Two pattern sources, in priority order:

  1. **Built-in** — ``builtin_patterns.txt`` shipped in this package. Conservative,
     known-prefix credential formats. The single source of truth shared with the
     bash hooks (``hooks/_patterns.sh`` reads the same file).
  2. **Custom** — a user-editable file at ``$PRISMOR_HOME/cloak_patterns.txt``
     (override with ``$PRISMOR_CLOAK_PATTERNS``) for org-specific token formats.
  3. **Org** — ``$PRISMOR_HOME/cloak_patterns.org.txt``, materialized from the
     signed remote policy's ``settings.cloak_patterns`` on every fetch (see
     :func:`write_org_patterns`). Read-only on the device: the console owns it.

Each line is one POSIX-ERE. Blank lines and ``#`` comments are ignored. The
``prismor cloak pattern`` CLI manages the custom file; built-ins are read-only.
"""
from __future__ import annotations

import os
import re
from pathlib import Path
from typing import List

# builtin_patterns.txt lives one directory up from this module.
_BUILTIN_FILE = Path(__file__).resolve().parent / "builtin_patterns.txt"


def custom_patterns_file() -> Path:
    """Path to the user's editable custom-pattern file.

    Honors ``$PRISMOR_CLOAK_PATTERNS``; otherwise ``$PRISMOR_HOME/cloak_patterns.txt``
    (default ``~/.prismor/cloak_patterns.txt``). Mirrors ``hooks/_patterns.sh``.
    """
    override = os.environ.get("PRISMOR_CLOAK_PATTERNS")
    if override:
        return Path(override).expanduser()
    home = Path(os.environ.get("PRISMOR_HOME", Path.home() / ".prismor"))
    return home / "cloak_patterns.txt"


def org_patterns_file() -> Path:
    """The org-pushed pattern file, next to the custom one. Mirrors
    ``hooks/_patterns.sh``; not overridable, because the file is only ever
    written from a verified policy and a stray env var must not redirect it."""
    home = Path(os.environ.get("PRISMOR_HOME", Path.home() / ".prismor"))
    return home / "cloak_patterns.org.txt"


def _read_patterns(path: Path) -> List[str]:
    if not path.exists():
        return []
    out: List[str] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        out.append(line)
    return out


def builtin_patterns() -> List[str]:
    """Return the bundled built-in patterns."""
    return _read_patterns(_BUILTIN_FILE)


def list_custom_patterns() -> List[str]:
    """Return the user's custom patterns (empty if none registered)."""
    return _read_patterns(custom_patterns_file())


def list_org_patterns() -> List[str]:
    """Patterns the org pushed through the signed policy (empty if none)."""
    return _read_patterns(org_patterns_file())


def all_patterns() -> List[str]:
    """Built-ins, then custom, then org patterns — the effective detection set."""
    return builtin_patterns() + list_custom_patterns() + list_org_patterns()


def write_org_patterns(patterns: List[str]) -> int:
    """Materialize the org's ``settings.cloak_patterns`` for the bash hooks.

    The hooks are pure bash and read pattern files, not policy YAML, so the
    verified remote policy is projected to a file here. Invalid regexes are
    skipped rather than failing the whole list - one bad org entry must not
    switch off the others. An empty list removes the file. Returns the number
    of patterns written.
    """
    path = org_patterns_file()
    kept: List[str] = []
    for raw in patterns or []:
        regex = str(raw).strip()
        if not regex or regex.startswith("#") or regex in kept:
            continue
        try:
            re.compile(regex)
        except re.error:
            continue
        kept.append(regex)
    if not kept:
        try:
            path.unlink()
        except FileNotFoundError:
            pass
        return 0
    path.parent.mkdir(parents=True, exist_ok=True)
    body = (
        "# Prismor cloaking - patterns pushed by your org's signed policy.\n"
        "# Managed by `prismor` on policy refresh; edits here are overwritten.\n"
        + "\n".join(kept) + "\n"
    )
    path.write_text(body, encoding="utf-8")
    try:
        path.chmod(0o600)
    except OSError:
        pass
    return len(kept)


def add_pattern(regex: str) -> bool:
    """Append ``regex`` to the custom pattern file.

    Validates that the regex compiles before saving. Returns True if added,
    False if it was already present (built-in or custom). Raises ``ValueError``
    on an invalid regex.
    """
    regex = regex.strip()
    if not regex:
        raise ValueError("Pattern is empty.")
    try:
        re.compile(regex)
    except re.error as exc:
        raise ValueError(f"Invalid regex {regex!r}: {exc}") from exc

    if regex in builtin_patterns() or regex in list_custom_patterns() or regex in list_org_patterns():
        return False

    path = custom_patterns_file()
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        path.parent.chmod(0o700)
    except PermissionError:
        pass
    if not path.exists():
        header = (
            "# Prismor cloaking — custom (org-specific) secret patterns.\n"
            "# One POSIX ERE per line. Managed by `prismor cloak pattern add/remove`.\n"
        )
        path.write_text(header, encoding="utf-8")
    with path.open("a", encoding="utf-8") as f:
        f.write(regex + "\n")
    return True


def remove_pattern(regex: str) -> bool:
    """Remove ``regex`` from the custom pattern file.

    Returns True if a line was removed. Built-in patterns cannot be removed
    (raises ``ValueError`` if ``regex`` is a built-in).
    """
    regex = regex.strip()
    if regex in builtin_patterns():
        raise ValueError(
            f"{regex!r} is a built-in pattern and cannot be removed."
        )
    if regex in list_org_patterns():
        raise ValueError(
            f"{regex!r} is pushed by your org's policy and cannot be removed here."
        )
    path = custom_patterns_file()
    if not path.exists():
        return False
    lines = path.read_text(encoding="utf-8").splitlines()
    kept = [ln for ln in lines if ln.strip() != regex]
    if len(kept) == len(lines):
        return False
    path.write_text("\n".join(kept) + "\n", encoding="utf-8")
    return True
