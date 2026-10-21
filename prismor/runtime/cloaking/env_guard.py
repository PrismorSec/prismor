"""Unprotected-entry check for env-guard.sh.

``env-guard.sh`` denies a Read or a content-reading Bash command that targets
a dotenv-style file *only while that file holds values not yet registered in
the cloak vault* — once every entry is imported (``prismor cloak add
--env-file``), the guard stands down and the existing hooks take over
(read-guard denies Reads of registered values; decloak's output scrub masks
them in Bash output).

The "is this file fully imported?" question must be answered with exactly the
same parsing the import path uses, or a file could look unprotected forever
after a successful import. That is why this lives in Python next to
``secrets_store`` instead of being re-implemented in the hook's bash: both
sides share ``_parse_env_line``.

Invoked by the hook as:

    python3 -c 'from prismor.runtime.cloaking.env_guard import main; main()' FILE...

and prints a JSON object: ``{"files": {path: [entry names...]}, "total": N}``
listing, per file, the KEY names (never values) whose values are absent from
the vault. Parse errors are treated leniently — a malformed line is skipped
rather than failing the whole file, so one odd line cannot mask real secrets
on the lines around it.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Dict, List, Set

from prismor.runtime.cloaking.secrets_store import _parse_env_line, secrets_dir

# Values shorter than this are ignored, mirroring read-guard.sh's minimum —
# tiny values ("1", "true", "dev") are config, not secrets, and matching them
# against the vault would be noise either way.
MIN_VALUE_LEN = 4


def vault_values() -> Set[str]:
    """Every registered secret value, read fresh from the vault."""
    values: Set[str] = set()
    sdir = secrets_dir()
    if not sdir.is_dir():
        return values
    for child in sdir.iterdir():
        if not child.is_file():
            continue
        try:
            values.add(child.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError):
            continue
    return values


def unprotected_entries(path: Path, vault: Set[str] | None = None) -> List[str]:
    """KEY names in ``path`` whose values are not registered in the vault."""
    if vault is None:
        vault = vault_values()
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return []
    names: List[str] = []
    for line_no, raw_line in enumerate(text.splitlines(), start=1):
        try:
            item = _parse_env_line(raw_line, line_no)
        except ValueError:
            continue
        if item is None:
            continue
        key, value = item
        if len(value) < MIN_VALUE_LEN:
            continue
        if value not in vault:
            names.append(key)
    return names


def main(argv: List[str] | None = None) -> None:
    args = sys.argv[1:] if argv is None else argv
    vault = vault_values()
    files: Dict[str, List[str]] = {}
    total = 0
    for arg in args:
        names = unprotected_entries(Path(arg), vault)
        if names:
            files[arg] = names
            total += len(names)
    print(json.dumps({"files": files, "total": total}))


_WORD = re.compile(r"[A-Za-z0-9_.~/-]+")


def local_text(command: str) -> str:
    """``command`` with every word the LOCAL shell won't touch blanked out.

    A path inside ``ssh host '<cmd>'`` (or another context-switching command's
    quoted payload) names a file on the other machine; resolving it against
    this machine's cwd denied commands that never read a local file. Uses the
    same ``is_remote_payload`` the policy engine judges remote payloads with.
    """
    try:
        from prismor.runtime.shell_context import is_remote_payload
    except Exception:
        return command
    out = list(command)
    for m in _WORD.finditer(command):
        if is_remote_payload(command, m.start(), m.end()):
            out[m.start():m.end()] = " " * (m.end() - m.start())
    return "".join(out)


def local_text_main() -> None:
    sys.stdout.write(local_text(sys.stdin.read()))


if __name__ == "__main__":
    main()
