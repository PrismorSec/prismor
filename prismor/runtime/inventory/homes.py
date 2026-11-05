"""Local profile enumeration, including WSL homes.

Under SYSTEM, ``Path.home()`` is the service profile. Fleet scans pass
``all_users`` and read every real profile. A non-admin run scans the caller
only. WSL homes are read through ``\\\\wsl.localhost\\<Distro>\\home\\<user>``
and only for distros that are already running, so a scan never boots a VM.
"""
from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

from prismor.runtime.inventory.context import ScanContext

_SKIP_PROFILES = {"Public", "Default", "Default User", "All Users", "Shared"}


@dataclass
class Home:
    path: Path
    username: str
    os_name: str
    wsl_distro: str = ""


def _skip(name: str) -> bool:
    return name in _SKIP_PROFILES or name.startswith(".")


def local_homes(ctx: ScanContext) -> List[Home]:
    """Profiles to scan. ``ctx.profiles_root`` overrides the OS lookup (fixtures)."""
    if ctx.profiles_root is not None:
        homes: List[Home] = []
        children = sorted(p for p in Path(ctx.profiles_root).iterdir() if p.is_dir())
        for child in children:
            if _skip(child.name):
                continue
            homes.append(Home(child, child.name, ctx.os_name))
        if not ctx.all_users and homes:
            # A fixture root is an explicit set of profiles; all of them are in scope
            # only with --all-users. Without it, keep the first real profile so a
            # single-user invocation still returns something deterministic.
            return homes[:1]
        return homes

    if not ctx.all_users:
        home = Path.home()
        return [Home(home, home.name or "user", ctx.os_name)]

    roots = _profile_roots()
    homes = []
    for root in roots:
        if _skip(root.name):
            continue
        homes.append(Home(root, root.name, ctx.os_name))
    return homes


def _profile_roots() -> List[Path]:
    """Same sources as ``system_install.user_prismor_homes``, without the ``.prismor`` filter."""
    if sys.platform == "win32":
        try:
            from prismor.runtime.system_install import _FOLDERID_USER_PROFILES, known_folder
            base = known_folder(_FOLDERID_USER_PROFILES)
            return [p for p in base.iterdir() if p.is_dir()]
        except OSError:
            return []
    if sys.platform == "darwin":
        try:
            return [p for p in Path("/Users").iterdir() if p.is_dir()]
        except OSError:
            return []
    import pwd
    return sorted({Path(pw.pw_dir) for pw in pwd.getpwall() if pw.pw_dir})


def decode_wsl_output(raw: bytes) -> str:
    """``wsl.exe -l`` is UTF-16LE on some builds and UTF-8 on others."""
    if not raw:
        return ""
    if raw.startswith(b"\xff\xfe"):
        return raw[2:].decode("utf-16-le", errors="replace")
    if raw.startswith(b"\xfe\xff"):
        return raw[2:].decode("utf-16-be", errors="replace")
    if raw.startswith(b"\xef\xbb\xbf"):
        return raw[3:].decode("utf-8", errors="replace")
    sample = raw[:64]
    if sample and sample.count(b"\x00") >= max(2, len(sample) // 4):
        try:
            return raw.decode("utf-16-le")
        except UnicodeError:
            return raw.decode("utf-8", errors="replace")
    return raw.decode("utf-8", errors="replace")


def running_wsl_distros(ctx: ScanContext) -> List[str]:
    """Names of running distros. A fixture ``wsl_root`` lists directory names instead of ``wsl.exe``."""
    if ctx.wsl_root is not None:
        try:
            return sorted(p.name for p in Path(ctx.wsl_root).iterdir() if p.is_dir())
        except OSError:
            return []
    if ctx.os_name != "windows":
        return []
    if ctx.dry_run:
        return []
    try:
        # ``--running`` so a stopped distro is not started by opening its filesystem.
        # UTF-16 vs UTF-8 varies by Windows build; ``decode_wsl_output`` accepts both.
        proc = ctx.run(["wsl.exe", "-l", "--running", "-q"], timeout=15)
    except (OSError, TimeoutError):
        return []
    stdout = proc.stdout if isinstance(proc.stdout, bytes) else bytes(proc.stdout or b"")
    names = []
    for line in decode_wsl_output(stdout).splitlines():
        name = line.strip().strip("\x00")
        if name and not name.lower().startswith("windows subsystem"):
            names.append(name)
    return names


def wsl_homes(ctx: ScanContext) -> List[Home]:
    """Linux homes inside running WSL distros. Missing paths are skipped."""
    homes: List[Home] = []
    for distro in running_wsl_distros(ctx):
        if ctx.wsl_root is not None:
            base = Path(ctx.wsl_root) / distro / "home"
        else:
            base = Path(f"\\\\wsl.localhost\\{distro}\\home")
        try:
            if not base.is_dir():
                continue
            users = [p for p in base.iterdir() if p.is_dir() and not _skip(p.name)]
        except OSError:
            continue
        for user_home in users:
            homes.append(Home(user_home, user_home.name, "linux", wsl_distro=distro))
    return homes


def appdata(home: Path, ctx: ScanContext) -> Optional[Path]:
    """Per-user Roaming app data. Never the SYSTEM process environment."""
    if ctx.os_name == "windows":
        return home / "AppData" / "Roaming"
    if ctx.os_name == "darwin":
        return home / "Library" / "Application Support"
    return home / ".config"


def localappdata(home: Path, ctx: ScanContext) -> Optional[Path]:
    if ctx.os_name == "windows":
        return home / "AppData" / "Local"
    return None
