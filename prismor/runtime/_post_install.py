"""Post-install welcome message, shown once after `pip install prismor`.

Triggered via the immunity-agent.pth file that ships in the wheel and is
processed by Python at startup. The marker file ensures it fires exactly once,
and only in interactive (TTY) sessions so CI/scripts never see it.
"""

from __future__ import annotations


def maybe_show() -> None:
    import sys

    if not sys.stdout.isatty():
        return

    from pathlib import Path

    marker = Path.home() / ".prismor" / ".prismor_greeted"
    if marker.exists():
        return

    try:
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.touch()
    except Exception:
        return

    RST  = "\033[0m"
    BOLD = "\033[1m"
    CYAN = "\033[36m"
    DIM  = "\033[37m"

    print(
        f"\n"
        f"  {BOLD}{CYAN}prismor{RST} installed\n"
        f"\n"
        f"  Run {BOLD}prismor setup{RST} to configure runtime hooks for your AI coding agent.\n"
        f"\n"
        f"  {DIM}Interactive TUI:{RST}   prismor setup\n"
        f"  {DIM}Scripted / CI:{RST}     prismor setup --non-interactive --mode observe\n"
        f"  {DIM}All options:{RST}       prismor setup --help\n"
    )
