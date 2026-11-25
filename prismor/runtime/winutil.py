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


def decode_bytes(data: bytes) -> str:
    """Decode file/stdin bytes: BOM-aware (UTF-8/16/32), else UTF-8, else
    UTF-8 with replacement. Never raises."""
    if data.startswith(codecs.BOM_UTF8):
        return data[3:].decode("utf-8", errors="replace")
    if data.startswith((codecs.BOM_UTF32_LE, codecs.BOM_UTF32_BE)):
        return data.decode("utf-32", errors="replace")
    if data.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)):
        return data.decode("utf-16", errors="replace")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("utf-8", errors="replace")


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


def restrict_to_current_user(path: Union[str, Path]) -> None:
    """Windows: drop inherited ACLs and grant only the current user.
    No-op elsewhere; never raises."""
    if not IS_WINDOWS:
        return
    try:
        user = os.environ.get("USERNAME")
        if not user:
            return
        domain = os.environ.get("USERDOMAIN")
        who = f"{domain}\\{user}" if domain else user
        subprocess.run(
            ["icacls", str(path), "/inheritance:r", "/grant:r", f"{who}:F"],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, timeout=10, check=False,
        )
    except Exception:
        pass
