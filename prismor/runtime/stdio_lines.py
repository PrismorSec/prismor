"""Line-oriented stdio for JSON-RPC servers that must answer immediately.

On Windows a blocking ``ReadFile`` on a pipe handle serialises every other
synchronous operation on that handle's file object, so a reply written while
the serve loop sits in ``sys.stdin`` is held back until the next request
arrives. We therefore (a) read stdin as bytes with ``os.read`` and, on
Windows, only call it once ``PeekNamedPipe`` says data (or EOF) is ready, and
(b) write replies as UTF-8 bytes with an explicit flush (no CRLF translation).
"""
import os
import sys
import time
from typing import Iterator


def _win_ready(fd: int) -> bool:
    """True when a read on ``fd`` will not block (data, EOF, or not a pipe)."""
    import ctypes
    import msvcrt
    from ctypes import wintypes
    avail = wintypes.DWORD(0)
    ok = ctypes.windll.kernel32.PeekNamedPipe(  # type: ignore[attr-defined]
        wintypes.HANDLE(msvcrt.get_osfhandle(fd)), None, 0, None,
        ctypes.byref(avail), None)
    # Failure = broken pipe (EOF) or not a pipe: let read() report it.
    return (not ok) or avail.value > 0


def stdin_lines(fd: int = 0) -> Iterator[str]:
    """Yield decoded lines (newline stripped) from ``fd`` until EOF."""
    buf = b""
    while True:
        if os.name == "nt":
            while not _win_ready(fd):
                time.sleep(0.005)
        try:
            chunk = os.read(fd, 65536)
        except OSError:
            chunk = b""
        if not chunk:
            if buf:
                yield buf.decode("utf-8", "replace").rstrip("\r\n")
            return
        buf += chunk
        while True:
            nl = buf.find(b"\n")
            if nl < 0:
                break
            line, buf = buf[:nl], buf[nl + 1:]
            yield line.decode("utf-8", "replace").rstrip("\r")


def write_line(text: str) -> None:
    """Write one line to stdout as UTF-8 bytes and flush immediately."""
    out = getattr(sys.stdout, "buffer", None)
    if out is None:  # stdout replaced by a text-only object (tests)
        sys.stdout.write(text + "\n")
        sys.stdout.flush()
        return
    out.write(text.encode("utf-8") + b"\n")
    out.flush()
