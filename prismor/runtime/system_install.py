"""Machine-wide (system) install: one root-owned setup that governs every user.

An MDM or config-management push runs as root, so a per-user install covers
root and nobody else. A system install puts the hook configs where each agent
reads organisation policy (``/etc/claude-code/managed-settings.d/`` and
friends), and moves every file that can *weaken* screening for a user into
``/etc/prismor``: the rule selection (policy.yaml), the device identity, the
pause marker and the unlock/floor-off state. Users can read those files but
not write them, so ``prismor pause``, ``prismor unlock`` or a hand-edited
``~/.prismor/policy.yaml`` no longer switch screening off on a managed box.
Per-user working state (session store, caches, telemetry spool) stays in each
user's ``~/.prismor``.

Linux only for now. The marker is ``/etc/prismor/system.json``; nothing in
the environment can point it elsewhere, because the users it governs control
their own environment.
"""
from __future__ import annotations

import json
import os
import stat
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

SYSTEM_DIR = Path("/etc/prismor")
_MARKER = "system.json"
_SCHEMA = "prismor.runtime.system.v1"


def system_dir() -> Path:
    return SYSTEM_DIR


def marker_path() -> Path:
    return SYSTEM_DIR / _MARKER


def is_system_managed() -> bool:
    try:
        return marker_path().is_file()
    except OSError:
        return False


def policy_home() -> Path:
    """Where policy-bearing state lives: /etc/prismor on a system install,
    else the per-user Prismor home."""
    if is_system_managed():
        return SYSTEM_DIR
    from prismor.runtime.store import prismor_home
    return prismor_home()


def shared_file_mode() -> int:
    """Mode for policy-bearing files: world-readable on a system install
    (every user's hook must read them, only root may write), else private."""
    return 0o644 if is_system_managed() else 0o600


def info() -> Optional[Dict[str, Any]]:
    try:
        data = json.loads(marker_path().read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else None
    except (OSError, ValueError):
        return None


def check_supported() -> Optional[str]:
    """Why a system install can't run here, or None."""
    if not sys.platform.startswith("linux"):
        return "system installs are Linux-only for now (use --scope global per user elsewhere)"
    if os.geteuid() != 0:
        return "a system install writes under /etc; run it as root (sudo prismor setup --system)"
    return None


def unreadable_by_others(path: Path) -> Optional[Path]:
    """The first component of ``path`` other users can't reach, or None.

    The hook runs as whichever user started the agent, with root's
    interpreter. A Python under /root (pip --user, pyenv) works for root and
    fails for everyone else, and a hook that can't start fails open.
    """
    p = Path(path).resolve()
    for part in [*reversed(p.parents), p]:
        try:
            mode = part.stat().st_mode
        except OSError:
            return part
        need = stat.S_IXOTH if part != p or part.is_dir() else stat.S_IROTH
        if not mode & need:
            return part
    return None


def mkdir_public(d: Path) -> None:
    """mkdir -p with 0755 on every directory it creates. An MDM shell's umask
    077 otherwise leaves e.g. /etc/claude-code at 0700, and a user's agent then
    can't reach its managed settings and starts with no hooks at all."""
    missing = [p for p in (d, *d.parents) if not p.exists()]
    d.mkdir(parents=True, exist_ok=True)
    for p in missing:
        p.chmod(0o755)


def is_admin() -> bool:
    """Root on a system install: the machine's administrator, who may pause,
    unlock or uninstall without the terminal gate that keeps agents out."""
    return is_system_managed() and hasattr(os, "geteuid") and os.geteuid() == 0


def write_marker(*, mode: str, selected: int) -> Path:
    mkdir_public(SYSTEM_DIR)
    from prismor.runtime import __version__ as _v
    record = {
        "schema": _SCHEMA,
        "mode": mode,
        "enforced_rules": selected,
        "python": sys.executable,
        "prismor_version": _v,
        "installed_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }
    path = marker_path()
    path.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    path.chmod(0o644)
    return path


def write_shared(path: Path, text: str) -> None:
    """Write a policy-bearing file with the right mode for this install."""
    if is_system_managed():
        mkdir_public(path.parent)
    else:
        path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    try:
        path.chmod(shared_file_mode())
    except OSError:
        pass


def permission_hint(exc: BaseException) -> Optional[str]:
    """A one-line explanation when a non-root user hits a system-owned file."""
    name = getattr(exc, "filename", None) or ""
    if isinstance(exc, PermissionError) and str(name).startswith(str(SYSTEM_DIR)):
        return ("This machine has a system-wide Prismor install, so policy, pause and "
                "unlock are managed by root or your organization's console. "
                "Ask an administrator, or run the command with sudo.")
    return None
