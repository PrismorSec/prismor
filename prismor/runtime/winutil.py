"""Small cross-platform helpers for Windows quirks (encoding, locks, ACLs).

Everything here is best effort and a no-op on POSIX where noted.
"""
from __future__ import annotations

import codecs
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Optional, Union

IS_WINDOWS = os.name == "nt"


def decode_bytes(data: bytes, strict: bool = False) -> str:
    """Decode file/stdin bytes BOM-aware (UTF-8/16/32, PowerShell 5.1 writes
    UTF-16), else UTF-8. Invalid bytes are replaced, or raise when ``strict``
    (secret values must never be stored with U+FFFD in them)."""
    errors = "strict" if strict else "replace"
    if data.startswith(codecs.BOM_UTF8):
        return data[3:].decode("utf-8", errors)
    if data.startswith((codecs.BOM_UTF32_LE, codecs.BOM_UTF32_BE)):
        return data.decode("utf-32", errors)
    if data.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)):
        return data.decode("utf-16", errors)
    return data.decode("utf-8", errors)


def norm_eol(data: bytes) -> bytes:
    """CRLF -> LF for text (binary left alone), so a line-ending-only edit
    (git autocrlf, a Windows editor) does not change a content hash."""
    return data if b"\0" in data else data.replace(b"\r\n", b"\n")


def read_text_file(path: Union[str, Path]) -> str:
    """Read a text file BOM-aware. Raises ``ValueError`` with a clear message
    (not a traceback-worthy OSError) when the file is missing or unreadable."""
    p = Path(path)
    try:
        return decode_bytes(p.read_bytes())
    except FileNotFoundError:
        raise ValueError(f"file not found: {p}") from None
    except IsADirectoryError:
        raise ValueError(f"not a file: {p}") from None
    except OSError as exc:
        raise ValueError(f"cannot read {p}: {exc.strerror or exc}") from None


def read_stdin_text() -> str:
    """Read all of stdin as UTF-8 regardless of the locale codec."""
    buf = getattr(sys.stdin, "buffer", None)
    if buf is None:
        return sys.stdin.read()
    return decode_bytes(buf.read())


def force_utf8_stdio() -> None:
    """Make stdout/stderr UTF-8 (``replace`` on error) so printing non-ASCII
    never raises UnicodeEncodeError under cp1252 or a redirect."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
        except Exception:
            pass


def replace_retry(src: Any, dst: Any, attempts: int = 40, delay: float = 0.01) -> None:
    """``os.replace`` that retries on Windows sharing violations
    (WinError 5 / 32 while another process holds the target)."""
    for i in range(attempts):
        try:
            os.replace(src, dst)
            return
        except PermissionError:
            if i == attempts - 1:
                raise
            time.sleep(min(delay * (i + 1), 0.1))


def _current_sid() -> str:
    """SID of the current user (``whoami /user``), or "". A SID needs no domain:
    ``USERDOMAIN`` is WORKGROUP in an ssh session but the account is MACHINE\\user."""
    try:
        out = subprocess.run(["whoami", "/user", "/fo", "csv", "/nh"], capture_output=True,
                             text=True, timeout=10, stdin=subprocess.DEVNULL).stdout
        sid = out.strip().rsplit(",", 1)[-1].strip().strip('"')
        return sid if sid.startswith("S-1-") else ""
    except Exception:
        return ""


def restrict_to_current_user(path: Union[str, Path]) -> bool:
    """Windows: drop inherited ACLs and grant only the current user.
    No-op elsewhere; never raises. Returns False if icacls did not succeed."""
    if not IS_WINDOWS:
        return True
    try:
        sid = _current_sid()
        user = os.environ.get("USERNAME")
        domain = os.environ.get("USERDOMAIN")
        whos = ([f"*{sid}"] if sid else []) + ([f"{domain}\\{user}"] if user and domain else []) + ([user] if user else [])
        perm = "(OI)(CI)F" if Path(path).is_dir() else "F"
        for who in whos:
            r = subprocess.run(
                ["icacls", str(path), "/inheritance:r", "/grant:r", f"{who}:{perm}"],
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL, timeout=10, check=False,
            )
            if r.returncode == 0:
                return True
    except Exception:
        pass
    return False
