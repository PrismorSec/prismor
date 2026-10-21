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

Linux, macOS and Windows. The marker is ``/etc/prismor/system.json`` (Linux),
``/Library/Application Support/Prismor/system.json`` (macOS) or
``C:\\ProgramData\\Prismor\\system.json`` (Windows). Nothing in the environment
can point it elsewhere, because the users it governs control their own
environment: on Windows the folder comes from the shell's known-folder API,
not from ``%ProgramData%``.
"""
from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

IS_WINDOWS = sys.platform == "win32"
IS_MAC = sys.platform == "darwin"
MAC_SUPPORT = Path("/Library/Application Support")

# FOLDERID_* from KnownFolders.h.
_FOLDERID_PROGRAM_DATA = "62AB5D82-FDC1-4DC3-A9DD-070D1D495D97"
_FOLDERID_PROGRAM_FILES = "905E63B6-C1BF-494E-B29C-65B732D3D21A"
_FOLDERID_USER_PROFILES = "0762D272-C50A-4BB0-A382-697DCD729B80"


def known_folder(guid: str) -> Path:
    """A Windows known folder from the shell API. ``%ProgramData%`` and
    friends are plain environment variables any user can repoint."""
    import ctypes
    import uuid
    from ctypes import wintypes

    class _GUID(ctypes.Structure):
        _fields_ = [("d1", wintypes.DWORD), ("d2", wintypes.WORD), ("d3", wintypes.WORD),
                    ("d4", ctypes.c_ubyte * 8)]

    u = uuid.UUID(guid)
    g = _GUID(u.fields[0], u.fields[1], u.fields[2], (ctypes.c_ubyte * 8)(*u.bytes[8:]))
    out = ctypes.c_wchar_p()
    hr = ctypes.windll.shell32.SHGetKnownFolderPath(ctypes.byref(g), 0, None, ctypes.byref(out))
    try:
        if hr != 0:
            raise OSError(f"SHGetKnownFolderPath({guid}) failed: {hr:#x}")
        return Path(out.value)
    finally:
        ctypes.windll.ole32.CoTaskMemFree(out)


PROGRAM_DATA: Optional[Path] = known_folder(_FOLDERID_PROGRAM_DATA) if IS_WINDOWS else None
PROGRAM_FILES: Optional[Path] = known_folder(_FOLDERID_PROGRAM_FILES) if IS_WINDOWS else None

if PROGRAM_DATA:
    SYSTEM_DIR = PROGRAM_DATA / "Prismor"
elif IS_MAC:
    SYSTEM_DIR = MAC_SUPPORT / "Prismor"
else:
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


def is_elevated() -> bool:
    """Root, or an elevated Administrator on Windows."""
    if IS_WINDOWS:
        import ctypes
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    return hasattr(os, "geteuid") and os.geteuid() == 0


def check_supported() -> Optional[str]:
    """Why a system install can't run here, or None."""
    if not (sys.platform.startswith("linux") or IS_WINDOWS or IS_MAC):
        return "system installs cover Linux, macOS and Windows (use --scope global per user elsewhere)"
    if not is_elevated():
        if IS_WINDOWS:
            return (f"a system install writes under {SYSTEM_DIR.parent}; run it from an elevated "
                    "(Administrator) shell or as SYSTEM")
        where = "/Library and /etc" if IS_MAC else "/etc"
        return f"a system install writes under {where}; run it as root (sudo prismor setup --system)"
    return None


def unreadable_by_others(path: Path) -> Optional[Path]:
    """The first component of ``path`` other users can't reach, or None.

    The hook runs as whichever user started the agent, with root's
    interpreter. A Python under /root (pip --user, pyenv) works for root and
    fails for everyone else, and a hook that can't start fails open.
    """
    p = Path(path).resolve()
    if IS_WINDOWS:
        # ponytail: profile check, not an ACL walk. A Python under C:\\Users
        # (per-user installer, venv in a profile) is the case that bites; an ACL
        # someone tightened by hand elsewhere would get past this.
        profiles = known_folder(_FOLDERID_USER_PROFILES).resolve()
        if p == profiles or profiles in p.parents:
            return next((q for q in (p, *p.parents) if q.parent == profiles), p)
        return None
    for part in [*reversed(p.parents), p]:
        try:
            mode = part.stat().st_mode
        except OSError:
            return part
        need = stat.S_IXOTH if part != p or part.is_dir() else stat.S_IROTH
        if not mode & need:
            return part
    return None


def lock_down(d: Path) -> None:
    """Windows: SYSTEM and Administrators full control, Users read and execute,
    nothing inherited. ProgramData lets Users *create* files in any subfolder,
    which in /etc/prismor terms means writing your own pause.json."""
    subprocess.run(
        ["icacls", str(d), "/inheritance:r", "/grant:r",
         "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F", "*S-1-5-32-545:(OI)(CI)RX"],
        check=True, capture_output=True,
    )


def mkdir_public(d: Path) -> None:
    """mkdir -p, leaving every directory it creates readable by all users and
    writable by admins only. On Linux that is 0755: an MDM shell's umask 077
    otherwise leaves e.g. /etc/claude-code at 0700, and a user's agent then
    can't reach its managed settings and starts with no hooks at all. On
    Windows it is an explicit ACL (see lock_down)."""
    missing = [p for p in (d, *d.parents) if not p.exists()]
    d.mkdir(parents=True, exist_ok=True)
    for p in missing:
        lock_down(p) if IS_WINDOWS else p.chmod(0o755)


def is_admin() -> bool:
    """The machine's administrator on a system install (root, or an elevated
    Administrator), who may pause, unlock or uninstall without the terminal
    gate that keeps agents out."""
    return is_system_managed() and is_elevated()


def write_marker(*, mode: str, selected: int) -> Path:
    mkdir_public(SYSTEM_DIR)
    if IS_WINDOWS:
        lock_down(SYSTEM_DIR)  # ours even if it already existed
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
        how = "from an Administrator shell" if IS_WINDOWS else "with sudo"
        return ("This machine has a system-wide Prismor install, so policy, pause and "
                "unlock are managed by an administrator or your organization's console. "
                f"Ask an administrator, or run the command {how}.")
    return None


def write_private(path: Path, text: str) -> None:
    """Write a file only admins can read: 0600 root, or SYSTEM + Administrators
    on Windows. For the device key, which users' hooks never need."""
    mkdir_public(path.parent)
    path.write_text(text, encoding="utf-8")
    if IS_WINDOWS:
        subprocess.run(["icacls", str(path), "/inheritance:r", "/grant:r",
                        "*S-1-5-18:F", "*S-1-5-32-544:F"], check=True, capture_output=True)
    else:
        path.chmod(0o600)


def user_prismor_homes() -> list:
    """Every local user's ~/.prismor, where their hooks spool telemetry."""
    if IS_WINDOWS:
        roots = [p for p in known_folder(_FOLDERID_USER_PROFILES).iterdir() if p.is_dir()]
    elif IS_MAC:
        # pwd on macOS lists only /etc/passwd's system accounts; people live
        # in Open Directory, with their homes under /Users.
        roots = [p for p in Path("/Users").iterdir() if p.is_dir()]
    else:
        import pwd
        roots = sorted({Path(pw.pw_dir) for pw in pwd.getpwall() if pw.pw_dir})
    return [r / ".prismor" for r in roots if (r / ".prismor").is_dir()]


def _give_back(home: Path) -> None:
    """Files the sync rewrote in a user's home go back to that user; a
    root-owned spool would stop their hooks from appending to it."""
    if IS_WINDOWS:
        return  # profile ACLs are inherited; the user keeps full control
    st = home.stat()
    for f in home.iterdir():
        if f.name.startswith(("telemetry-", "device-revoked")) or f.suffix == ".lock":
            try:
                os.chown(f, st.st_uid, st.st_gid)
            except OSError:
                pass


def sync() -> Dict[str, Any]:
    """`prismor system-sync`: the admin-side half of a system install.

    Users' hooks can't read the device key, so they never call the control
    plane. This (run as root / SYSTEM on a timer) pulls the signed org policy
    into the system folder, where their hooks verify and apply it, and uploads
    the telemetry each user's hooks spooled.
    """
    from prismor.runtime import sinks
    from prismor.runtime.enterprise import identity, remote_policy, telemetry_spool

    out: Dict[str, Any] = {"policy_pulled": False, "homes": 0, "pending_before": 0,
                           "pending_after": 0, "errors": []}
    if identity.load_identity() is None:
        out["errors"].append("not enrolled (or the key is unreadable): run `prismor enroll <TOKEN>` as admin")
        return out
    out["policy_pulled"] = remote_policy.fetch(force=True)
    saved = os.environ.get("PRISMOR_HOME")
    try:
        for home in user_prismor_homes():
            os.environ["PRISMOR_HOME"] = str(home)
            out["homes"] += 1
            before = telemetry_spool.pending_count()
            out["pending_before"] += before
            try:
                for _ in range(50):  # 500 per batch; a home far behind catches up over runs
                    if not telemetry_spool.pending_count():
                        break
                    sinks.upload_telemetry([])
            except Exception as exc:
                out["errors"].append(f"{home}: {exc}")
            out["pending_after"] += telemetry_spool.pending_count()
            _give_back(home)
    finally:
        if saved is None:
            os.environ.pop("PRISMOR_HOME", None)
        else:
            os.environ["PRISMOR_HOME"] = saved
    return out


_TASK = "Prismor System Sync"
_UNIT = "prismor-sync"
_LAUNCHD = "dev.prismor.system-sync"
_LAUNCHD_PLIST = Path("/Library/LaunchDaemons") / f"{_LAUNCHD}.plist"


def install_sync_schedule() -> str:
    """Run `system-sync` every minute as root / SYSTEM. Returns what it did."""
    cmd = [sys.executable, "-m", "prismor.runtime.cli", "system-sync", "--quiet"]
    if IS_WINDOWS:
        tr = subprocess.list2cmdline(cmd)
        subprocess.run(["schtasks", "/Create", "/TN", _TASK, "/SC", "MINUTE", "/MO", "1",
                        "/RU", "SYSTEM", "/RL", "HIGHEST", "/TR", tr, "/F"],
                       check=True, capture_output=True)
        return f"scheduled task '{_TASK}' (every minute, as SYSTEM)"
    if IS_MAC:
        import plistlib
        _LAUNCHD_PLIST.write_bytes(plistlib.dumps({
            "Label": _LAUNCHD, "ProgramArguments": cmd, "StartInterval": 60, "RunAtLoad": True,
            "StandardErrorPath": str(SYSTEM_DIR / "system-sync.log"),
        }))
        _LAUNCHD_PLIST.chmod(0o644)
        subprocess.run(["launchctl", "bootout", f"system/{_LAUNCHD}"], capture_output=True)
        subprocess.run(["launchctl", "bootstrap", "system", str(_LAUNCHD_PLIST)], check=True, capture_output=True)
        return f"LaunchDaemon {_LAUNCHD} (every minute, as root)"
    if not Path("/run/systemd/system").is_dir():
        return ("no systemd here: run `prismor system-sync --quiet` as root every minute "
                "(cron: * * * * * root " + " ".join(cmd) + ")")
    unit = Path("/etc/systemd/system")
    (unit / f"{_UNIT}.service").write_text(
        "[Unit]\nDescription=Prismor system sync (org policy pull, telemetry upload)\n\n"
        f"[Service]\nType=oneshot\nExecStart={' '.join(cmd)}\n", encoding="utf-8")
    (unit / f"{_UNIT}.timer").write_text(
        "[Unit]\nDescription=Prismor system sync every minute\n\n"
        "[Timer]\nOnBootSec=30s\nOnUnitActiveSec=60s\n\n[Install]\nWantedBy=timers.target\n",
        encoding="utf-8")
    subprocess.run(["systemctl", "daemon-reload"], check=True, capture_output=True)
    subprocess.run(["systemctl", "enable", "--now", f"{_UNIT}.timer"], check=True, capture_output=True)
    return f"systemd timer {_UNIT}.timer (every minute)"


def remove_sync_schedule() -> None:
    if IS_WINDOWS:
        subprocess.run(["schtasks", "/Delete", "/TN", _TASK, "/F"], capture_output=True)
        return
    if IS_MAC:
        subprocess.run(["launchctl", "bootout", f"system/{_LAUNCHD}"], capture_output=True)
        try:
            _LAUNCHD_PLIST.unlink()
        except OSError:
            pass
        return
    if Path("/run/systemd/system").is_dir():
        subprocess.run(["systemctl", "disable", "--now", f"{_UNIT}.timer"], capture_output=True)
    for ext in ("service", "timer"):
        try:
            (Path("/etc/systemd/system") / f"{_UNIT}.{ext}").unlink()
        except OSError:
            pass
