"""Interactive command browser behind a bare `prismor help` on a TTY.

Type to filter, arrows to move, Enter shows that command's full help, Esc quits.
POSIX only (termios); callers fall back to the static map elsewhere.
"""
from __future__ import annotations

import os
import shutil
import sys
import termios
import textwrap
import tty
from typing import Callable, Optional

_B, _D, _INV, _R = "\033[1m", "\033[2m", "\033[7m", "\033[0m"


def _key(fd: int) -> str:
    ch = os.read(fd, 1)
    if ch == b"\x1b":
        # Bare Esc vs. an arrow sequence: arrows arrive as one burst.
        import select
        if not select.select([fd], [], [], 0.03)[0]:
            return "esc"
        seq = os.read(fd, 2)
        return {b"[A": "up", b"[B": "down"}.get(seq, "")
    return {b"\r": "enter", b"\n": "enter", b"\x7f": "bs", b"\x08": "bs",
            b"\x03": "esc", b"\x10": "up", b"\x0e": "down"}.get(ch, ch.decode("utf-8", "ignore"))


def _fit(text: str, width: int) -> str:
    return text if len(text) <= width else text[: max(width - 1, 1)] + "…"


def _draw(rows, query: str, sel: int) -> None:
    cols, lines = shutil.get_terminal_size((100, 24))
    out = ["\033[H\033[J",
           f"  {_B}prismor{_R} commands   {_D}type to filter · ↑↓ move · enter details · esc quit{_R}\r\n",
           f"  › {query}\033[K\r\n\r\n"]
    detail = 5
    room = max(lines - 3 - detail - 1, 3)
    top = min(max(sel - room // 2, 0), max(len(rows) - room, 0))
    group = None
    used = 0
    for i in range(top, len(rows)):
        g, name, help_text, _ = rows[i]
        if g != group:
            if used + 2 > room:
                break
            group = g
            out.append(f"  {_D}{g}{_R}\r\n")
            used += 1
        if used >= room:
            break
        line = _fit(f"{name.ljust(18)}{help_text}", cols - 6)
        mark = f"{_INV}›" if i == sel else " "
        out.append(f" {mark} {line} {_R}\r\n")
        used += 1
    if not rows:
        out.append(f"  {_D}no commands match{_R}\r\n")
    else:
        _, name, help_text, subs = rows[sel]
        out.append(f"\033[{lines - detail + 1};1H{_D}{'─' * (cols - 1)}{_R}\r\n")
        out.append(f"  {_B}prismor {name}{_R}\r\n")
        for part in textwrap.wrap(help_text, cols - 4, max_lines=2, placeholder="…"):
            out.append(f"  {part}\r\n")
        if subs:
            out.append(f"  {_D}{_fit(' · '.join(n for n, _ in subs), cols - 4)}{_R}")
    sys.stdout.write("".join(out))
    sys.stdout.flush()


def browse(search: Callable[[str], list]) -> Optional[str]:
    """Run the picker over `search(query)` rows; returns the chosen command
    ("cloak" or "cloak add"), or None if dismissed."""
    fd = sys.stdin.fileno()
    saved = termios.tcgetattr(fd)
    query, sel = "", 0
    sys.stdout.write("\033[?1049h\033[?25l")
    try:
        tty.setraw(fd)
        while True:
            rows = search(query)
            sel = min(sel, max(len(rows) - 1, 0))
            _draw(rows, query, sel)
            k = _key(fd)
            if k == "esc":
                return None
            if k == "enter" and rows:
                return rows[sel][1]
            if k == "up":
                sel = max(sel - 1, 0)
            elif k == "down":
                sel = min(sel + 1, max(len(rows) - 1, 0))
            elif k == "bs":
                query, sel = query[:-1], 0
            elif len(k) == 1 and k.isprintable():
                query, sel = query + k, 0
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, saved)
        sys.stdout.write("\033[?25h\033[?1049l")
        sys.stdout.flush()
