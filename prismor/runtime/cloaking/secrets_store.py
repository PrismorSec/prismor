"""Secret registry for Prismor cloaking.

Stores real secret values on disk under ``$PRISMOR_SECRETS_DIR`` (default:
``~/.prismor/secrets``) with tight permissions (directory ``0700``, files
``0600``). Each file's name is the placeholder identifier the model will
reference as ``@@SECRET:<name>@@``; the file contents are the real value.

Design notes:
  * Values are never printed by ``list_secrets``. Only names are listed.
  * ``add_secret`` refuses empty values and rejects names that would traverse
    out of the secrets directory.
  * Removing a secret leaves any commands that referenced it failing closed
    — the decloak hook denies the tool call when a referenced secret
    file is missing.
"""
from __future__ import annotations

import os
import re
import stat
from collections import OrderedDict
from pathlib import Path
from typing import Dict, List, Optional

# Valid placeholder names mirror the regex used by the decloak hook.
_NAME_RE = re.compile(r"^[a-zA-Z0-9_-]{1,64}$")


def secrets_dir() -> Path:
    """Return the secrets directory path, honoring $PRISMOR_SECRETS_DIR."""
    override = os.environ.get("PRISMOR_SECRETS_DIR")
    if override:
        return Path(override).expanduser()
    return Path(os.environ.get("PRISMOR_HOME", Path.home() / ".prismor")) / "secrets"


def pinned_secrets_dir() -> Optional[Path]:
    """The secrets dir to write into an agent's hook config, or None to let the
    hooks resolve ``${PRISMOR_HOME:-$HOME/.prismor}/secrets`` themselves when
    they run.

    Pinned only when it was chosen on purpose. The default needs no pin, and a
    pin is what broke a sandbox HOME: Prismor's own settings.json ``env`` block
    exports PRISMOR_SECRETS_DIR into every agent shell, so an install run from
    one copied that session's vault path into another HOME's hooks. Inside an
    agent session the variable says where that session's vault is, not where
    this install's should be.
    """
    from prismor.runtime.agent_env import running_under_agent

    chosen = secrets_dir()
    if chosen == Path.home() / ".prismor" / "secrets":
        return None
    if os.environ.get("PRISMOR_SECRETS_DIR") and running_under_agent():
        return None
    return chosen


def _ensure_dir() -> Path:
    path = secrets_dir()
    path.mkdir(parents=True, exist_ok=True)
    try:
        path.chmod(0o700)
    except PermissionError:
        pass
    return path


def _validate_name(name: str) -> str:
    if not _NAME_RE.fullmatch(name):
        raise ValueError(
            f"Invalid secret name {name!r}: must match {_NAME_RE.pattern}"
        )
    return name


def add_secret(name: str, value: str) -> Path:
    """Register a real secret value under ``name``. Overwrites if exists.

    The caller is responsible for reading ``value`` from a safe source
    (stdin or a file) rather than argv, to avoid leaking via process lists.
    """
    _validate_name(name)
    if not value:
        raise ValueError("Secret value is empty — refusing to store.")
    path = _ensure_dir() / name
    path.write_text(value, encoding="utf-8")
    try:
        path.chmod(0o600)
    except PermissionError:
        pass
    return path


def _parse_env_line(raw_line: str, line_no: int) -> tuple[str, str] | None:
    line = raw_line.strip()
    if not line or line.startswith("#"):
        return None
    if line.startswith("export "):
        line = line[len("export "):].lstrip()
    if "=" not in line:
        raise ValueError(f".env line {line_no}: expected KEY=VALUE")
    key, raw_value = line.split("=", 1)
    key = key.strip()
    if not key:
        raise ValueError(f".env line {line_no}: empty key")
    _validate_name(key)

    value = raw_value.strip()
    if value and value[0] in {'"', "'"}:
        quote = value[0]
        if len(value) < 2 or value[-1] != quote:
            raise ValueError(f".env line {line_no}: unterminated quoted value for {key!r}")
        value = value[1:-1]
        if quote == '"':
            value = bytes(value, "utf-8").decode("unicode_escape")
    else:
        comment_at = value.find(" #")
        if comment_at != -1:
            value = value[:comment_at].rstrip()
    if not value:
        raise ValueError(f".env line {line_no}: empty value for {key!r}")
    return key, value


def parse_env_file(path: Path) -> Dict[str, str]:
    """Parse a dotenv-style file into placeholder -> secret mappings."""
    parsed: "OrderedDict[str, str]" = OrderedDict()
    for line_no, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        item = _parse_env_line(raw_line, line_no)
        if item is None:
            continue
        key, value = item
        parsed[key] = value
    if not parsed:
        raise ValueError(f"{path}: no KEY=VALUE entries found")
    return dict(parsed)


def add_env_secrets(path: Path) -> List[dict]:
    """Register every entry from a dotenv-style file as its own secret."""
    created: List[dict] = []
    for name, value in parse_env_file(path).items():
        secret_path = add_secret(name, value)
        created.append({"name": name, "bytes": len(value), "path": secret_path})
    return created


def remove_secret(name: str) -> bool:
    """Delete a registered secret. Returns True if something was removed."""
    _validate_name(name)
    path = secrets_dir() / name
    if path.exists():
        path.unlink()
        return True
    return False


def list_secrets() -> List[dict]:
    """List registered secrets (names and metadata — never values).

    Returns a list of dicts with ``name``, ``bytes``, and ``modified`` keys.
    """
    path = secrets_dir()
    if not path.exists():
        return []
    entries: List[dict] = []
    for child in sorted(path.iterdir()):
        if not child.is_file():
            continue
        try:
            st = child.stat()
        except OSError:
            continue
        entries.append(
            {
                "name": child.name,
                "bytes": st.st_size,
                "modified": int(st.st_mtime),
                "auto": child.name.startswith("auto_"),
            }
        )
    return entries


def check_permissions() -> List[str]:
    """Audit permission modes on the secrets dir and files. Returns warnings."""
    warnings: List[str] = []
    path = secrets_dir()
    if not path.exists():
        return warnings
    dir_mode = stat.S_IMODE(path.stat().st_mode)
    if dir_mode & 0o077:
        warnings.append(
            f"secrets directory {path} has mode {oct(dir_mode)}; expected 0700"
        )
    for child in path.iterdir():
        if not child.is_file():
            continue
        mode = stat.S_IMODE(child.stat().st_mode)
        if mode & 0o077:
            warnings.append(
                f"{child.name} has mode {oct(mode)}; expected 0600"
            )
    return warnings
