"""Shared, side-effect-free terminal formatting helpers.

Pulled out of ``setup_wizard.py`` so callers that only need static box/banner
rendering (e.g. ``prismor enroll``) don't have to import that module — which
registers ``atexit``/``SIGINT``/``SIGTERM`` handlers for its interactive
wizard's alt-screen cleanup as an import-time side effect.
"""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path
from typing import List, Optional

try:
    from prismor.runtime import __version__ as _PKG_VERSION
except Exception:
    _PKG_VERSION = "0.0.0"
VERSION = f"v{_PKG_VERSION}"

RST  = "\033[0m"
BOLD = "\033[1m"
DIM  = "\033[37m"
CYAN = "\033[36m"
GRN  = "\033[32m"
YEL  = "\033[33m"
RED  = "\033[31m"
BLU  = "\033[34m"
WHT  = "\033[97m"


def w(text: str, *codes: str) -> str:
    if not codes or codes == ("",):
        return str(text)
    return "".join(codes) + str(text) + RST


def visible_len(text: str) -> int:
    return len(re.sub(r"\033\[[0-9;]*m", "", str(text)))


def pad(text: str, width: int) -> str:
    return text + " " * max(0, width - visible_len(text))


def term_width() -> int:
    try:
        return os.get_terminal_size().columns
    except Exception:
        return 80


def fit_list(items: List[str], width: int) -> str:
    """Join items with ", " within width, ending in "+N more" when some don't fit."""
    for n in range(len(items), 0, -1):
        rest = len(items) - n
        s = ", ".join(items[:n]) + (f", +{rest} more" if rest else "")
        if len(s) <= width:
            return s
    return f"{len(items)} agents"


def print_enroll_summary(
    *,
    workspace: Path,
    org: str,
    device_label: str,
    device_id: str,
    mode: Optional[str],
    agents: List[str],
    rules_active: int,
    cloak_installed: bool,
    cloak_secret_count: int,
    full_capture: bool,
) -> None:
    """Boxed confirmation printed after a successful `prismor enroll`.

    Plain ``stdout`` writes (no alt-screen, no clear) since enroll is a
    one-shot command — its output should stay in scrollback.
    """
    home = str(Path.home())
    ws_disp = str(workspace).replace(home, "~")
    W = 48

    def bdr(l: str, fill: str, r: str) -> str:
        return w(f"  {l}{fill * W}{r}", DIM)

    def row(content: str = "") -> str:
        vl = visible_len(content)
        p = " " * max(0, W - vl - 2)
        return w("  │", DIM) + " " + content + p + " " + w("│", DIM)

    VW = W - 2 - 14  # value column: box interior minus the key column

    def kv(k: str, v: str, vc: str = WHT) -> str:
        if len(v) > VW:
            v = v[:VW - 1] + "…"
        return f"{pad(w(k, DIM), 14)}{w(v, vc)}"

    tw = term_width()
    agents_str = fit_list(agents, VW) if agents else "none installed"
    lines: List[str] = [
        "",
        f"  {w('PRISMOR', BOLD, CYAN)}  {w('· ' + VERSION, DIM)}",
        w("  " + "─" * min(tw - 4, 64), DIM),
        "",
        bdr("╭", "─", "╮"),
        row(w("ENROLLED", BOLD, GRN)),
        row(),
        row(kv("Org", org)),
        row(kv("Device", f"{device_label}  ({device_id[:12]})")),
        row(kv("Project", ws_disp)),
        row(kv("Mode", mode or "not installed", GRN if mode == "enforce" else YEL)),
        row(kv("Rules", f"{rules_active} active")),
        row(kv("Agents", agents_str, WHT if agents else DIM)),
        row(kv("Cloak", "yes  (secret prevention)" if cloak_installed else "no",
                GRN if cloak_installed else DIM)),
        row(kv("Telemetry", "full capture" if full_capture else "redacted",
                YEL if full_capture else GRN)),
        row(),
        bdr("╰", "─", "╯"),
        "",
        f"  {w('Next:', CYAN, BOLD)} {w('prismor status', DIM)} · {w('prismor doctor', DIM)}",
        "",
    ]
    sys.stdout.write("\n".join(lines) + "\n")
    sys.stdout.flush()
