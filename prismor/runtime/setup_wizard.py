"""Prismor — interactive setup wizard, usable from both pip install and git clone.

This module contains the full 4-step TUI wizard and the non-interactive install path.
It is the backing implementation for ``prismor setup``.

The original wizard in ``scripts/setup.py`` continues to work for git-clone users
running ``bash ~/.prismor/scripts/init.sh``; this module is its pip-installable twin.
"""

from __future__ import annotations

import atexit
import os
import re
import shutil
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import List, Optional

# ── Constants ────────────────────────────────────────────────────────────────

try:
    from prismor.runtime import __version__ as _PKG_VERSION
except Exception:
    _PKG_VERSION = "0.0.0"
_VERSION = f"v{_PKG_VERSION}"
_BACK = object()  # sentinel for "go back"

_PKG_DIR = Path(__file__).resolve().parent
# repo_root for install_hooks: the directory CONTAINING the `prismor` package,
# i.e. two levels up from prismor/runtime/ — matching what hooks.py expects when
# it builds `repo_root / "prismor" / "runtime" / "<agent>-plugin"` and what the
# rest of the runtime uses (see discover_cli). This pointed at the package dir
# itself, one level too deep, which silently cost three things: the hook's
# PYTHONPATH fallback resolved to a directory with no importable `prismor` in
# it, the openclaw/hermes/opencode plugin paths pointed at a directory that
# does not exist, and a git-clone install never detected its own checkout, so
# it printed "run pip install --upgrade" instead of updating itself.
_REPO_ROOT = _PKG_DIR.parent.parent

# ── ANSI ─────────────────────────────────────────────────────────────────────

RST  = "\033[0m"
BOLD = "\033[1m"
DIM  = "\033[37m"
CYAN = "\033[36m"
GRN  = "\033[32m"
YEL  = "\033[33m"
RED  = "\033[31m"
BLU  = "\033[34m"
WHT  = "\033[97m"

HIDE    = "\033[?25l"
SHOW    = "\033[?25h"
ALT_ON  = "\033[?1049h"
ALT_OFF = "\033[?1049l"


def _s(*codes: str) -> str:
    return "".join(codes)


def _w(text: str, *codes: str) -> str:
    if not codes or codes == ("",):
        return str(text)
    return "".join(codes) + str(text) + RST


def _visible_len(text: str) -> int:
    return len(re.sub(r"\033\[[0-9;]*m", "", str(text)))


def _pad(text: str, width: int) -> str:
    return text + " " * max(0, width - _visible_len(text))


# ── Screen buffer ────────────────────────────────────────────────────────────

def _term_width() -> int:
    try:
        return os.get_terminal_size().columns
    except Exception:
        return 80


def _term_height() -> int:
    try:
        return os.get_terminal_size().lines
    except Exception:
        return 24


def _render(lines: List[str]) -> None:
    buf = "\033[H\033[J" + HIDE
    for line in lines:
        buf += line + "\n"
    sys.stdout.write(buf)
    sys.stdout.flush()


# ── Terminal input ───────────────────────────────────────────────────────────

try:
    import tty
    import termios
    _HAS_TTY = True
except ImportError:
    _HAS_TTY = False

_saved_attrs = None


def _raw_on() -> None:
    global _saved_attrs
    if not _HAS_TTY:
        return
    fd = sys.stdin.fileno()
    _saved_attrs = termios.tcgetattr(fd)
    tty.setcbreak(fd)


def _raw_off() -> None:
    if not _HAS_TTY or _saved_attrs is None:
        return
    try:
        termios.tcsetattr(sys.stdin.fileno(), termios.TCSADRAIN, _saved_attrs)
    except Exception:
        pass


def _cleanup() -> None:
    _raw_off()
    sys.stdout.write(ALT_OFF + SHOW)
    sys.stdout.flush()


atexit.register(_cleanup)
signal.signal(signal.SIGINT,  lambda *_: (_cleanup(), sys.exit(0)))
signal.signal(signal.SIGTERM, lambda *_: (_cleanup(), sys.exit(0)))


def _read_key() -> str:
    ch = sys.stdin.read(1)
    if ch == "\x1b":
        ch2 = sys.stdin.read(1)
        if ch2 == "[":
            ch3 = sys.stdin.read(1)
            return "ESC[" + ch3
        return ch
    return ch


_UP    = "ESC[A"
_DOWN  = "ESC[B"
_RIGHT = "ESC[C"
_LEFT  = "ESC[D"
_ENTER = "\r"
_SPACE = " "


# ── Rule loading ─────────────────────────────────────────────────────────────

def _floor_sets() -> tuple:
    """(non_overridable_ids, core_categories, self_protection_ids) from the engine.

    Imported rather than restated so the wizard's "Recommended" banding can
    never drift from what the engine actually treats as the safety floor.
    """
    try:
        from prismor.runtime.policy_engine import (
            _NON_OVERRIDABLE_RULE_IDS,
            _CORE_BLOCK_CATEGORIES,
            _SELF_PROTECTION_RULE_IDS,
        )
        return (
            set(_NON_OVERRIDABLE_RULE_IDS),
            set(_CORE_BLOCK_CATEGORIES),
            set(_SELF_PROTECTION_RULE_IDS),
        )
    except Exception:
        return set(), set(), set()


def _annotate_rules(rules: List[dict], block_categories: Optional[set] = None) -> List[dict]:
    """Tag each rule with the flags the selection screen bands on.

    ``self_protect``    — Prismor guarding itself; always on, never a choice here.
    ``floor``           — the safety floor (core rule id / core block category).
    ``default_blocked`` — a category the shipped policy blocks in enforce mode.
    ``recommended``     — what we actually advise turning on: the floor.

    Recommending the floor and nothing more is deliberate. Badging the whole
    default block set would mark ~60 of 77 rules "recommended", which is not a
    recommendation, it's a default wearing a costume.
    """
    non_over, core_cats, self_ids = _floor_sets()
    cats = block_categories if block_categories is not None else set()
    for r in rules:
        rid, cat = r.get("id", ""), r.get("category", "")
        r["self_protect"] = rid in self_ids
        r["floor"] = (rid in non_over or cat in core_cats) and not r["self_protect"]
        r["default_blocked"] = bool(cat) and cat in cats and not r["floor"] and not r["self_protect"]
        r["recommended"] = r["floor"]
    return rules


def _load_rules() -> List[dict]:
    policy = _PKG_DIR / "default_policy.yaml"
    if policy.exists():
        try:
            import yaml
            with policy.open(encoding="utf-8") as f:
                data = yaml.safe_load(f)
            rules = [
                {
                    "id":       r["id"],
                    "severity": r["severity"],
                    "title":    r.get("title", r["id"]),
                    "category": r.get("category", ""),
                    "action":   r.get("action", "warn"),
                    "on":       True,
                }
                for r in data.get("rules", [])
            ]
            block_cats = set((data.get("settings", {}) or {}).get("block_categories", []) or [])
            return _annotate_rules(rules, block_cats)
        except ImportError:
            return _parse_policy_manual(policy)
    return _default_rules()


def _parse_policy_manual(policy: Path) -> List[dict]:
    rules: List[dict] = []
    cur: dict = {}
    inside = False
    with policy.open(encoding="utf-8") as f:
        for line in f:
            s = line.strip()
            if s == "rules:":
                inside = True
                continue
            if not inside:
                continue
            if s.startswith("allowlists:") or s.startswith("settings:"):
                break
            m = re.match(r"^\s*-\s*id:\s*(.+)$", line)
            if m:
                if cur:
                    rules.append(cur)
                cur = {"id": m.group(1).strip(), "severity": "MEDIUM",
                       "title": m.group(1).strip(), "on": True}
            m2 = re.match(r"^\s*severity:\s*(\w+)", line)
            if m2 and cur:
                cur["severity"] = m2.group(1)
            m3 = re.match(r"^\s*title:\s*(.+)$", line)
            if m3 and cur:
                cur["title"] = m3.group(1).strip()
            m4 = re.match(r"^\s*category:\s*(\S+)", line)
            if m4 and cur:
                cur["category"] = m4.group(1).strip()
    if cur:
        rules.append(cur)
    return _annotate_rules(rules) if rules else _default_rules()


def _default_rules() -> List[dict]:
    D = [
        ("destructive-command",     "CRITICAL", "destructive_command",     "Blocks rm -rf /, mkfs, dd to disk, shutdown, reboot"),
        ("secret-exfiltration",     "CRITICAL", "secret_exfiltration",     "Blocks cat .env | curl, piping secrets to external hosts"),
        ("dos-resource-exhaustion", "CRITICAL", "dos_resource_exhaustion", "Blocks fork bombs, while-true loops, /dev/urandom abuse"),
        ("rce-canary",              "CRITICAL", "rce_canary",              "Blocks reverse shells, bash -i /dev/tcp, crontab injection"),
        ("privilege-escalation",    "CRITICAL", "privilege_escalation",    "Blocks chmod +s, sudoers edits, useradd, setcap"),
        ("prompt-injection",        "HIGH",     "prompt_injection",        "Detects 'ignore instructions', 'reveal system prompt' in agent I/O"),
        ("remote-execution",        "HIGH",     "remote_execution",        "Blocks curl | bash, wget | sh fetch-and-execute chains"),
        ("secret-access",           "HIGH",     "secret_access",           "Flags reads/writes to .env, .ssh/id_rsa, .aws/credentials"),
        ("suspicious-network",      "HIGH",     "network_isolation",       "Flags calls to webhook.site, ngrok, pastebin, Discord webhooks"),
        ("db-modification",         "HIGH",     "db_modification",         "Flags DROP TABLE, DELETE FROM, TRUNCATE in shell commands"),
        ("risky-write",             "MEDIUM",   "risky_write",             "Flags writes to Dockerfile, CI workflows, package.json"),
    ]
    rules = [{"id": i, "severity": s, "category": c, "title": t, "action": "block", "on": True}
             for i, s, c, t in D]
    return _annotate_rules(rules, {"secret_access", "db_modification", "prompt_injection"})


# ── Agent detection ──────────────────────────────────────────────────────────

def _detect_agents(target: Path) -> dict:
    home = Path.home()
    return {
        "claude":   shutil.which("claude") is not None or (target / ".claude").exists() or (home / ".claude").exists(),
        "cursor":   (target / ".cursor").exists() or (home / ".cursor").exists(),
        "windsurf": (target / ".windsurf").exists() or (home / ".codeium").exists(),
        "openclaw": shutil.which("openclaw") is not None or (target / ".openclaw").exists(),
        "hermes":   shutil.which("hermes") is not None or (target / ".hermes").exists(),
        "codex":    shutil.which("codex") is not None or (target / ".codex").exists() or (home / ".codex").exists(),
        "grok":     shutil.which("grok") is not None or (target / ".grok").exists() or (home / ".grok").exists(),
        "kiro":     shutil.which("kiro-cli") is not None or shutil.which("kiro") is not None or (target / ".kiro").exists() or (home / ".kiro").exists(),
        "crush":    shutil.which("crush") is not None or (target / "crush.json").exists() or (home / ".config" / "crush").exists(),
        "openhands": shutil.which("openhands") is not None or (target / ".openhands").exists() or (home / ".openhands").exists(),
        "qwen":     shutil.which("qwen") is not None or (target / ".qwen").exists() or (home / ".qwen").exists(),
        "continue": shutil.which("cn") is not None or (target / ".continue").exists() or (home / ".continue").exists(),
        "goose":    shutil.which("goose") is not None or (home / ".config" / "goose").exists(),
    }


# ── Severity colors ──────────────────────────────────────────────────────────

def _sev_color(s: str) -> str:
    s = s.upper()
    if s == "CRITICAL": return RED
    if s == "HIGH":     return YEL
    if s == "MEDIUM":   return BLU
    return DIM


def _sev_short(s: str) -> str:
    """Four-column severity tag. Spelled out rather than truncated — slicing
    MEDIUM to four characters gives "MEDI", which reads as a typo."""
    return {"CRITICAL": "CRIT", "HIGH": "HIGH", "MEDIUM": "MED ", "LOW": "LOW "}.get(
        s.upper(), (s[:4].upper() + "    ")[:4]
    )


# ── Shared UI pieces ─────────────────────────────────────────────────────────

def _header_lines(step: Optional[int] = None, total: Optional[int] = None, label: Optional[str] = None) -> List[str]:
    tw = _term_width()
    out = [
        "",
        f"  {_w('PRISMOR', BOLD, CYAN)}  {_w('· ' + _VERSION, DIM)}",
    ]
    if step and label:
        out.append(f"  {_w(f'Step {step}/{total}', DIM)}  {_w(label, BOLD)}")
    out.append(_w("  " + "─" * min(tw - 4, 64), DIM))
    out.append("")
    return out


def _control_line(items: List[tuple]) -> str:
    parts = [_w(k, BOLD, CYAN) + _w(f" {d}", DIM) for k, d in items]
    return "  " + _w(" · ", DIM).join(parts)


# ── Step 1: Enforcement Mode ─────────────────────────────────────────────────

def _step_mode(current: str = "observe", total: int = 4, extra_steps: int = 0) -> str:
    opts = [
        ("observe", "Log and warn, never block"),
        ("enforce", "Block dangerous actions in real time"),
    ]
    sel = 0 if current == "observe" else 1

    while True:
        # Choosing enforce adds the rule-selection step, so the count has to
        # follow the highlighted option — otherwise this screen says "1/5" and
        # the next one says "2/6", which reads like a bug.
        total = (5 if opts[sel][0] == "enforce" else 4) + extra_steps
        lines = _header_lines(1, total, "ENFORCEMENT MODE")
        for i, (name, desc) in enumerate(opts):
            arrow = _w("▸ ", CYAN) if i == sel else "  "
            dot   = _w("●", GRN) if i == sel else _w("○", DIM)
            nm    = _pad(_w(name, BOLD) if i == sel else _w(name, DIM), 16)
            lines.append(f"  {arrow}{dot}  {nm}{_w(desc, DIM)}")
        lines.append("")
        lines.append(_control_line([("↑↓", "select"), ("enter", "next"), ("q", "quit")]))
        _render(lines)

        key = _read_key()
        if key == _UP:               sel = (sel - 1) % len(opts)
        elif key == _DOWN:           sel = (sel + 1) % len(opts)
        elif key in (_ENTER, "\n"):  return opts[sel][0]
        elif key in ("q", "Q", "\x03"): _cleanup(); sys.exit(0)


# ── Step 2 (enforce only): Which rules block ─────────────────────────────────

def _cat_label(cat: str) -> str:
    return (cat or "other").replace("_", " ").upper()


def _selection_rows(rules: List[dict]) -> List[dict]:
    """Flatten the rule list into display rows: band headers + selectable rules.

    Order is the argument the screen is making: the floor first (these are the
    ones we think you want), then the rest of what the shipped policy blocks,
    then everything else by category.
    """
    rows: List[dict] = []
    floor = [r for r in rules if r.get("floor")]
    rec = [r for r in rules if r.get("default_blocked")]
    rest = [r for r in rules
            if not r.get("floor") and not r.get("default_blocked") and not r.get("self_protect")]

    if floor:
        rows.append({"kind": "header", "text": "RECOMMENDED — Prismor's safety floor"})
        rows.extend({"kind": "rule", "rule": r} for r in floor)
    if rec:
        rows.append({"kind": "header", "text": "ALSO BLOCKED BY THE DEFAULT POLICY"})
        rows.extend({"kind": "rule", "rule": r} for r in rec)
    for cat in sorted({r.get("category", "") for r in rest}):
        rows.append({"kind": "header", "text": _cat_label(cat)})
        rows.extend({"kind": "rule", "rule": r}
                    for r in rest if r.get("category", "") == cat)
    return rows


def _step_policy_select(rules: List[dict], step: int = 2, total: int = 5):
    """Pick which rules block. Everything starts off — enforce mode never
    guesses on the user's behalf.

    Prismor's self-protection rules are not on this screen: they are what stops
    the agent from editing the choices made here, so offering them as a choice
    would make every other choice on the screen meaningless.
    """
    for r in rules:
        r["on"] = bool(r.get("on_selected"))  # start empty unless re-entering
    rows = _selection_rows(rules)
    pick = [i for i, row in enumerate(rows) if row["kind"] == "rule"]
    n_self = sum(1 for r in rules if r.get("self_protect"))
    n_rec = sum(1 for r in rules if r.get("recommended"))
    sel = 0

    while True:
        n_on = sum(1 for r in rules if r["on"])
        head = _header_lines(step, total, "WHAT SHOULD BLOCK")
        head.append(f"  {_w('Nothing blocks until you choose it. Recommended entries are marked —', DIM)}")
        head.append(f"  {_w('they are off until you turn them on.', DIM)}")
        head.append("")
        foot = [
            "",
            f"  {_w(f'{n_on} selected', GRN if n_on else YEL)}"
            f"{_w(f'  ·  {n_rec} recommended  ·  {n_self} self-protection rules always on', DIM)}",
            "",
            _control_line([
                ("↑↓", "move"), ("space", "toggle"), ("a", "all recommended"),
                ("←", "back"), ("enter", "next"),
            ]),
        ]

        # Viewport: keep the cursor visible without redrawing the whole policy.
        avail = max(6, _term_height() - len(head) - len(foot) - 2)
        cur_row = pick[sel]
        start = max(0, min(cur_row - avail // 2, len(rows) - avail))
        window = rows[start:start + avail]

        lines = list(head)
        if start > 0:
            lines.append(_w("      ↑ more above", DIM))
        for i, row in enumerate(window, start=start):
            if row["kind"] == "header":
                lines.append(f"  {_w(row['text'], BOLD, DIM)}")
                continue
            r = row["rule"]
            arrow = _w("▸ ", CYAN) if i == cur_row else "  "
            dot = _w("●", GRN) if r["on"] else _w("○", DIM)
            sev = _w(_sev_short(r["severity"]), _sev_color(r["severity"]))
            name = _pad(_w(r["id"], BOLD) if i == cur_row else r["id"], 30)
            tag = _w(" recommended", YEL) if r.get("recommended") else ""
            lines.append(f"  {arrow}{dot} {sev} {name}{tag}")
        if start + avail < len(rows):
            lines.append(_w("      ↓ more below", DIM))
        lines.extend(foot)
        _render(lines)

        key = _read_key()
        if key == _UP:
            sel = (sel - 1) % len(pick)
        elif key == _DOWN:
            sel = (sel + 1) % len(pick)
        elif key == _SPACE:
            r = rows[pick[sel]]["rule"]
            r["on"] = not r["on"]
        elif key in ("a", "A"):
            # Toggle: a second press clears them again.
            want = not all(r["on"] for r in rules if r.get("recommended"))
            for r in rules:
                if r.get("recommended"):
                    r["on"] = want
        elif key in (_LEFT, "b", "B"):
            return _BACK
        elif key in (_ENTER, "\n"):
            for r in rules:
                r["on_selected"] = r["on"]  # remembered if the user steps back
            return rules
        elif key in ("q", "Q", "\x03"):
            _cleanup()
            sys.exit(0)


# ── Step 3: Agent Selection ──────────────────────────────────────────────────

def _can_mirror(agent_id: str, gov_entry: dict) -> bool:
    """True when setup may offer the mirror for this agent: the host supports
    replacing its built-ins AND `prismor mirror on` knows how to wire it."""
    try:
        from prismor.runtime.mirror_cli import INSTALLABLE_AGENTS
    except Exception:
        return False
    return agent_id in INSTALLABLE_AGENTS and gov_entry.get("mirror") in ("verified", "possible")


def _mirror_only_agents() -> list:
    """Coding agents Prismor can only reach through the MCP mirror."""
    try:
        from prismor.runtime.integrations.registry import load_registry, governance
        return [a.name.split(" (")[0] for a in load_registry()
                if a.kind == "coding-agent" and governance(a.id)["recommended"] == "mirror"]
    except Exception:
        return []


_MIRROR_ONLY = _mirror_only_agents()


def _step_agents(target: Path, step: int = 2, total: int = 4) -> list:
    detected = _detect_agents(target)
    agents = [
        {"name": "claude",   "label": "Claude Code", "on": detected.get("claude", False)},
        {"name": "cursor",   "label": "Cursor",      "on": detected.get("cursor", False)},
        {"name": "windsurf", "label": "Windsurf",    "on": detected.get("windsurf", False)},
        {"name": "openclaw", "label": "OpenClaw",    "on": detected.get("openclaw", False)},
        {"name": "hermes",   "label": "Hermes",      "on": detected.get("hermes", False)},
        {"name": "codex",    "label": "Codex",       "on": detected.get("codex", False)},
        {"name": "grok",     "label": "Grok Build",  "on": detected.get("grok", False)},
        {"name": "kiro",     "label": "Kiro CLI",    "on": detected.get("kiro", False)},
        {"name": "crush",     "label": "Crush",       "on": detected.get("crush", False)},
        {"name": "openhands", "label": "OpenHands",   "on": detected.get("openhands", False)},
        {"name": "qwen",      "label": "Qwen Code",   "on": detected.get("qwen", False)},
        {"name": "continue",  "label": "Continue CLI", "on": detected.get("continue", False)},
        {"name": "goose",     "label": "Goose",       "on": detected.get("goose", False)},
    ]
    if not any(a["on"] for a in agents):
        agents[0]["on"] = True
    sel = 0

    # How Prismor can reach each agent. Shown here because the two surfaces are
    # not interchangeable and the difference decides what this wizard installs:
    # hooks screen the agent's own tools in place, while the MCP mirror replaces
    # them. See docs/governance-surfaces.md.
    gov = {}
    for ag in agents:
        try:
            from prismor.runtime.integrations.registry import governance
            gov[ag["name"]] = governance(ag["name"])
        except Exception:
            gov[ag["name"]] = {"surfaces": "", "recommended": "hooks", "mirror": "unknown"}

    while True:
        lines = _header_lines(step, total, "AGENTS")
        lines.append(f"  {_w('Select agents to install Prismor hooks for:', DIM)}")
        lines.append("")
        for i, ag in enumerate(agents):
            arrow = _w("▸ ", CYAN) if i == sel else "  "
            dot   = _w("●", GRN) if ag["on"] else _w("○", DIM)
            name  = _pad(_w(ag["label"], BOLD) if i == sel else ag["label"], 18)
            tag   = _pad(_w("detected", GRN) if detected[ag["name"]] else _w("not found", DIM), 11)
            g = gov.get(ag["name"], {})
            surface = g.get("surfaces", "")
            if ag.get("mirror"):
                sfx = _w("hooks + MCP mirror", GRN)
            elif surface in ("hooks + MCP", "hooks"):
                sfx = _w("hooks", GRN)
                if _can_mirror(ag["name"], g):
                    sfx += _w("   (m: add MCP mirror)", DIM)
            elif surface == "MCP":
                sfx = _w("MCP only", YEL)
            elif surface == "not supported":
                sfx = _w("no interception", DIM)
            else:
                sfx = ""
            lines.append(f"  {arrow}{dot}  {name} {tag} {sfx}")
        # Agents with no hook protocol never appear in the list above, because
        # this wizard installs hooks. Naming them here is the difference between
        # "Prismor does not support my agent" and "Prismor reaches it a
        # different way" — without this they are silently invisible.
        if _MIRROR_ONLY:
            lines.append(f"  {_w('No hook protocol — govern these with', DIM)} "
                         f"{_w('prismor mirror on', BOLD)}{_w(':', DIM)}")
            lines.append(f"    {_w(', '.join(_MIRROR_ONLY), YEL)}")
            lines.append("")
        sel_gov = gov.get(agents[sel]["name"], {})
        if sel_gov.get("recommended") == "mirror":
            lines.append(f"  {_w('This agent has no hook protocol.', DIM)} "
                         f"{_w('Hooks cannot be installed for it —', DIM)}")
            lines.append(f"  {_w('govern it with', DIM)} {_w('prismor mirror on', BOLD)} "
                         f"{_w('(serves its built-ins over MCP instead).', DIM)}")
        elif sel_gov.get("recommended") == "none":
            lines.append(f"  {_w('No interception surface: no hooks, and its built-in tools', DIM)}")
            lines.append(f"  {_w('cannot be switched off, so an MCP mirror would be bypassable.', DIM)}")
        elif _can_mirror(agents[sel]["name"], sel_gov):
            if agents[sel].get("mirror"):
                lines.append(f"  {_w('Its built-ins will be served through Prismor over MCP', YEL)} "
                             f"{_w('— adds output redaction,', DIM)}")
                lines.append(f"  {_w('takes effect next session, undo with', DIM)} {_w('prismor mirror off', BOLD)}"
                             f"{_w('.  Press m to keep hooks only.', DIM)}")
            else:
                lines.append(f"  {_w('Hooks only — the recommended setup.', DIM)}")
                where = (_w(" (machine-wide for this agent)", YEL)
                         if sel_gov.get("scope") == "machine" else "")
                lines.append(f"  {_w('Press', DIM)} {_w('m', BOLD)} "
                             f"{_w('to also serve its built-ins over MCP', DIM)}{where}"
                             f"{_w('.', DIM)}")
        elif sel_gov.get("mirror") in ("verified", "possible"):
            lines.append(f"  {_w('Hooks are the recommended surface and are what this wizard installs.', DIM)}")
            lines.append(f"  {_w('Its built-ins can also be served over MCP — see docs/governance-surfaces.md.', DIM)}")
        else:
            lines.append(f"  {_w('Hooks are the recommended surface and are what this wizard installs.', DIM)}")
            lines.append("")
        lines.append("")
        lines.append(_control_line([
            ("↑↓", "move"), ("space", "toggle"), ("m", "MCP mirror"),
            ("←", "back"), ("enter", "next"),
        ]))
        _render(lines)

        key = _read_key()
        if key == _UP:               sel = (sel - 1) % len(agents)
        elif key == _DOWN:           sel = (sel + 1) % len(agents)
        elif key == _SPACE:          agents[sel]["on"] = not agents[sel]["on"]
        elif key in ("m", "M"):
            # Opt IN to the mirror, per agent. Off by default: hooks are the
            # recommended surface, and the mirror replaces the agent's tools,
            # which is not something a wizard should do to someone by default.
            if _can_mirror(agents[sel]["name"], gov.get(agents[sel]["name"], {})):
                agents[sel]["mirror"] = not agents[sel].get("mirror", False)
                if agents[sel]["mirror"]:
                    agents[sel]["on"] = True
        elif key in (_LEFT, "b", "B"): return _BACK  # type: ignore[return-value]
        elif key in (_ENTER, "\n"):
            chosen = [a["name"] for a in agents if a["on"]]
            if not chosen:
                chosen = ["claude"]
            mirrors = [a["name"] for a in agents if a["on"] and a.get("mirror")]
            return {"agents": chosen, "mirror": mirrors}
        elif key in ("q", "Q", "\x03"): _cleanup(); sys.exit(0)


# ── Step 3: Secret Cloaking ──────────────────────────────────────────────────

def _step_cloak(current: bool = True, step: int = 3, total: int = 4) -> bool:
    opts = [
        ("yes", "Install cloaking hooks  (recommended — prevents secret leaks to the LLM provider)"),
        ("no",  "Skip — only runtime policy hooks will be installed"),
    ]
    sel = 0 if current else 1

    while True:
        lines = _header_lines(step, total, "SECRET CLOAKING")
        lines.append(f"  {_w('Prevents real secrets from reaching model context, JSONL transcripts,', DIM)}")
        lines.append(f"  {_w('or upstream API requests. See prismor/runtime/cloaking/README.md.', DIM)}")
        lines.append("")
        for i, (name, desc) in enumerate(opts):
            arrow = _w("▸ ", CYAN) if i == sel else "  "
            dot   = _w("●", GRN) if i == sel else _w("○", DIM)
            tw = _term_width()
            max_desc = max(tw - 24, 30)
            nm = _pad(_w(name, BOLD) if i == sel else _w(name, DIM), 8)
            lines.append(f"  {arrow}{dot}  {nm}{_w(desc[:max_desc], DIM)}")
        lines.append("")
        lines.append(_control_line([
            ("↑↓", "select"), ("←", "back"), ("enter", "next"), ("q", "quit"),
        ]))
        _render(lines)

        key = _read_key()
        if key == _UP:                  sel = (sel - 1) % len(opts)
        elif key == _DOWN:              sel = (sel + 1) % len(opts)
        elif key in (_LEFT, "b", "B"):  return _BACK  # type: ignore[return-value]
        elif key in (_ENTER, "\n"):     return opts[sel][0] == "yes"
        elif key in ("q", "Q", "\x03"): _cleanup(); sys.exit(0)


# ── Step 4: Install Scope ────────────────────────────────────────────────────

def _step_scope(current: str = "project", step: int = 4, total: int = 4) -> str:
    opts = [
        ("project", "This workspace only",    "Hooks written to .claude/settings.json in the current project"),
        ("global",  "Global (all projects)",  "Hooks written to ~/.claude/settings.json — covers every workspace"),
    ]
    sel = 0 if current == "project" else 1

    while True:
        lines = _header_lines(step, total, "INSTALL SCOPE")
        lines.append(f"  {_w('Where should Prismor hooks be installed?', DIM)}")
        lines.append("")
        tw = _term_width()
        for i, (key, label, desc) in enumerate(opts):
            arrow = _w("▸ ", CYAN) if i == sel else "  "
            dot   = _w("●", GRN) if i == sel else _w("○", DIM)
            nm    = _pad(_w(label, BOLD) if i == sel else _w(label, DIM), 26)
            lines.append(f"  {arrow}{dot}  {nm}{_w(desc[:max(tw - 36, 20)], DIM)}")
        lines.append("")
        lines.append(_control_line([
            ("↑↓", "select"), ("←", "back"), ("enter", "next"), ("q", "quit"),
        ]))
        _render(lines)

        key = _read_key()
        if key == _UP:                  sel = (sel - 1) % len(opts)
        elif key == _DOWN:              sel = (sel + 1) % len(opts)
        elif key in (_LEFT, "b", "B"):  return _BACK  # type: ignore[return-value]
        elif key in (_ENTER, "\n"):     return opts[sel][0]
        elif key in ("q", "Q", "\x03"): _cleanup(); sys.exit(0)


# ── Step 6 (optional): unlock password ───────────────────────────────────────

def _step_unlock(current: bool = False, step: int = 6, total: int = 6):
    """Offer to set a password that lets the agent edit policy, briefly.

    Off by default. Without it the agent simply cannot touch Prismor's config,
    which is the safe answer; the password only exists so the alternative to
    "blocked" isn't "the human retypes the agent's work by hand".
    """
    opts = [
        ("no", "Skip — only you can change Prismor's policy, by hand"),
        ("yes", "Set a password — unlocks a 3-minute window on demand"),
    ]
    sel = 1 if current else 0

    while True:
        lines = _header_lines(step, total, "AGENT SELF-EDIT")
        lines.append(f"  {_w('Prismor blocks the agent from editing its own policy.', DIM)}")
        lines.append(f"  {_w('A password lets you hand it that ability for a few minutes:', DIM)}")
        lines.append(f"  {_w('run `prismor unlock`, and the agent can fix a rule that is', DIM)}")
        lines.append(f"  {_w('getting in the way. You can always set one up later.', DIM)}")
        lines.append("")
        for i, (name, desc) in enumerate(opts):
            arrow = _w("▸ ", CYAN) if i == sel else "  "
            dot = _w("●", GRN) if i == sel else _w("○", DIM)
            nm = _pad(_w(name, BOLD) if i == sel else _w(name, DIM), 6)
            lines.append(f"  {arrow}{dot}  {nm}{_w(desc[:max(_term_width() - 24, 30)], DIM)}")
        lines.append("")
        lines.append(_control_line([
            ("↑↓", "select"), ("←", "back"), ("enter", "next"), ("q", "quit"),
        ]))
        _render(lines)

        key = _read_key()
        if key == _UP:                  sel = (sel - 1) % len(opts)
        elif key == _DOWN:              sel = (sel + 1) % len(opts)
        elif key in (_LEFT, "b", "B"):  return _BACK
        elif key in (_ENTER, "\n"):     return opts[sel][0] == "yes"
        elif key in ("q", "Q", "\x03"): _cleanup(); sys.exit(0)


def _prompt_unlock_password() -> bool:
    """Ask for the unlock password outside the alt-screen. True if one was set."""
    import getpass
    try:
        from prismor.runtime import unlock as _unlock
    except Exception:
        return False
    print()
    print(_w("  Set your Prismor unlock password", BOLD))
    print(_w("  This is what you type to let the agent edit policy for a few", DIM))
    print(_w("  minutes. Use something other than your login password.", DIM))
    print()
    for _ in range(3):
        try:
            first = getpass.getpass("  New unlock password: ")
            if len(first) < 8:
                print(_w("  Too short — at least 8 characters.", YEL))
                continue
            if getpass.getpass("  Repeat it: ") != first:
                print(_w("  Those did not match.", YEL))
                continue
            _unlock.set_password(first)
            print(_w("  ✓ Set. Use `prismor unlock` when the agent needs it.", GRN))
            return True
        except (EOFError, KeyboardInterrupt):
            break
    print(_w("  Skipped — set one later with: prismor unlock --set-password", DIM))
    return False


# ── Confirm ──────────────────────────────────────────────────────────────────

def _step_confirm(target: Path, mode: str, rules: List[dict], agents: List[str], cloak: bool = False, scope: str = "project", unlock_pw: bool = False, mirror_agents: Optional[List[str]] = None) -> bool:
    home = str(Path.home())
    disp = str(target).replace(home, "~")
    n_on = sum(1 for r in rules if r["on"])
    n_rec = sum(1 for r in rules if r.get("recommended"))
    n_rec_on = sum(1 for r in rules if r.get("recommended") and r["on"])
    ags  = ", ".join(agents)
    mirror_agents = mirror_agents or []
    W = 48

    def bdr(l, fill, r):
        return _w(f"  {l}{fill * W}{r}", DIM)

    def row(content: str = "") -> str:
        vl = _visible_len(content)
        p = " " * max(0, W - vl - 2)
        return _w("  │", DIM) + " " + content + p + " " + _w("│", DIM)

    def kv(k: str, v: str, vc: str = WHT) -> str:
        return f"{_pad(_w(k, DIM), 14)}{_w(v, vc)}"

    while True:
        lines = _header_lines()
        lines.append(bdr("╭", "─", "╮"))
        lines.append(row(_w("READY TO INSTALL", BOLD)))
        lines.append(row())
        lines.append(row(kv("Project", disp[:30])))
        lines.append(row(kv("Mode", mode, GRN if mode == "enforce" else YEL)))
        if mode == "enforce":
            lines.append(row(kv("Blocking", f"{n_on} selected  ({n_rec_on}/{n_rec} recommended)",
                                GRN if n_on else YEL)))
            if n_on == 0:
                lines.append(row(_w("nothing blocks — Prismor will only watch", YEL)))
        else:
            lines.append(row(kv("Rules", f"{n_on}/{len(rules)} enabled")))
        lines.append(row(kv("Agents", ags)))
        lines.append(row(kv("Surface", "PreToolUse / PostToolUse hooks")))
        if mirror_agents:
            lines.append(row(kv("MCP mirror", ", ".join(mirror_agents), YEL)))
            lines.append(row(_w("built-ins served by Prismor; next session", DIM)))
        lines.append(row(kv("Cloak", "yes  (secret prevention)" if cloak else "no",
                            GRN if cloak else DIM)))
        lines.append(row(kv("Scope", "global (all projects)" if scope == "global" else "workspace only",
                            YEL if scope == "global" else GRN)))
        lines.append(row(kv("Self-edit", "password (3m window)" if unlock_pw else "blocked",
                            YEL if unlock_pw else GRN)))
        lines.append(row())
        lines.append(bdr("╰", "─", "╯"))
        lines.append("")
        lines.append(_control_line([("enter", "install"), ("←", "back"), ("q", "quit")]))
        _render(lines)

        key = _read_key()
        if key in (_ENTER, "\n"):       return True
        elif key in (_LEFT, "b", "B"):  return _BACK  # type: ignore[return-value]
        elif key in ("q", "Q", "\x03"): _cleanup(); sys.exit(0)


# ── Spinner ───────────────────────────────────────────────────────────────────

_SPIN = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]


def _spinner_run(label: str, fn) -> None:
    stop = threading.Event()

    def spin() -> None:
        i = 0
        while not stop.is_set():
            f = _SPIN[i % len(_SPIN)]
            sys.stdout.write(f"\r  {_w(f, CYAN)}  {label}   ")
            sys.stdout.flush()
            i += 1
            time.sleep(0.08)

    t = threading.Thread(target=spin, daemon=True)
    t.start()
    try:
        ok, msg = fn()
    except Exception as e:
        ok, msg = False, str(e)[:60]
    stop.set()
    t.join(timeout=0.3)
    icon = _w("✓", GRN) if ok else _w("✗", RED)
    suffix = f"  {_w(msg, DIM)}" if msg else ""
    sys.stdout.write(f"\r  {icon}  {label}{suffix}            \n")
    sys.stdout.flush()



_AGENT_CONTEXT_BLOCK = (
    "\n## Security (Prismor)\n\n"
    "This workspace is protected by Prismor. "
    "Run `prismor status` at the start of every session.\n\n"
    "Key commands:\n\n"
    "| Action | Command |\n"
    "|---|---|\n"
    "| Check protection state | `prismor status` |\n"
    "| Install packages safely | `prismor supplychain <pm> install <pkg>` |\n"
    "| Pre-check a risky command | `prismor check \"<cmd>\"` |\n"
    "| Scan for dep vulnerabilities | `prismor deps` |\n"
    "| Harden package config | `prismor supplychain harden` |\n\n"
    "Full decision tree: `.claude/skills/immunity-agent/SKILL.md`\n"
)

_AGENTS_MD_AGENTS = {"codex", "openclaw", "hermes", "copilot"}


def _write_agent_context(target: Path, agents: List[str]) -> None:
    """Write the immunity-agent command reference into agent-specific context files."""
    agent_files = {
        "cursor": target / ".cursorrules",
        "windsurf": target / ".windsurfrules",
    }
    for agent, path in agent_files.items():
        if agent not in agents:
            continue
        content = path.read_text(encoding="utf-8") if path.exists() else ""
        if "Prismor" not in content:
            path.write_text(content + _AGENT_CONTEXT_BLOCK, encoding="utf-8")

    if any(a in agents for a in _AGENTS_MD_AGENTS):
        path = target / "AGENTS.md"
        content = path.read_text(encoding="utf-8") if path.exists() else ""
        if "Prismor" not in content:
            path.write_text(content + _AGENT_CONTEXT_BLOCK, encoding="utf-8")


# ── Install ───────────────────────────────────────────────────────────────────

def _print_banner(text: str, pad: int = 3, color: str = GRN) -> None:
    """Print `text` in a box sized to the text.

    Drawing the border as a literal string is how it drifts: the rule is one
    character wide per column, and nothing checks that against the line inside
    it. Deriving both from the same width keeps the right edge where the box
    ends.
    """
    inner = _visible_len(text) + pad * 2
    print(_w("  ╭" + "─" * inner + "╮", DIM))
    print(_w("  │", DIM) + _w(" " * pad + text + " " * pad, color, BOLD) + _w("│", DIM))
    print(_w("  ╰" + "─" * inner + "╯", DIM))


def _render_selection_policy(selected: List[str]) -> str:
    """The `.prismor/policy.yaml` an enforce install writes.

    ``selection: explicit`` tells the engine this file names the blocking set in
    full, so a core rule the user did not pick observes instead of blocking.
    Prismor's own self-protection rules are unaffected — they are not a choice.
    """
    from datetime import date
    lines = [
        f"# Generated by `prismor setup` on {date.today().isoformat()}.",
        "# Safe to edit by hand; re-running setup regenerates it.",
        "#",
        "# selection: explicit  →  the rules listed below are the ones that block.",
        "#                         Anything not listed is still detected and",
        "#                         reported, it just doesn't stop the agent.",
        "#",
        "# Make an exception:  prismor allow <rule> --pattern '<literal>'",
        "# Change the set:     prismor setup",
        'version: "1.0"',
        "settings:",
        "  selection: explicit",
        "  default_mode: observe",
    ]
    if selected:
        # One line per rule, matching what `prismor allow` writes when it
        # rewrites this file — otherwise the policy changes shape the first time
        # anyone adds an exception. Two lines per rule also made a recommended
        # install 58 lines of mostly punctuation.
        lines.append("rules:")
        for rid in selected:
            lines.append(f"  - {{id: {rid}, mode: enforce}}")
    else:
        lines.append("# No rules selected — nothing blocks yet.")
        lines.append("rules: []")
    return "\n".join(lines) + "\n"


def _install_skill(target: Path):
    """Copy the bundled immunity-agent Claude skill into the workspace.

    Installs to ``<target>/.claude/skills/immunity-agent/`` (SKILL.md plus its
    docs/). Idempotent: if a SKILL.md is already present it's left untouched so
    user edits survive re-runs. Returns ``(ok, detail)`` for the spinner.
    """
    try:
        from prismor.runtime.paths import skill_manifest_path, skill_docs_dir
        skill_md = skill_manifest_path()
        docs_src = skill_docs_dir()
    except Exception as e:
        return False, str(e)[:40]
    if not skill_md.exists():
        return True, "skipped (skill not bundled)"

    dest = target / ".claude" / "skills" / "immunity-agent"
    if (dest / "SKILL.md").exists():
        return True, "already present"
    try:
        dest.mkdir(parents=True, exist_ok=True)
        shutil.copy2(skill_md, dest / "SKILL.md")
        if docs_src.exists() and docs_src.is_dir():
            docs_dest = dest / "docs"
            docs_dest.mkdir(exist_ok=True)
            for md in docs_src.glob("*.md"):
                shutil.copy2(md, docs_dest / md.name)
        return True, "installed"
    except OSError as e:
        return False, str(e)[:40]


def _do_install(target: Path, mode: str, rules: List[dict], agents: List[str], cloak: bool = False, scope: str = "project", mirror_agents: Optional[List[str]] = None) -> None:
    sys.stdout.write(ALT_OFF)
    sys.stdout.write("\033[H\033[J" + HIDE)
    sys.stdout.flush()
    print(_w("  Installing Prismor...\n", BOLD, CYAN))

    target = target.resolve()

    # 0. Register workspace
    def _register():
        try:
            from prismor.runtime.store import register_workspace
            register_workspace(target)
            return True, ""
        except Exception as e:
            return False, str(e)[:40]
    _spinner_run("Registering workspace", _register)

    # 1. Update Prismor — only for git-clone installs
    prismor_home = os.environ.get("PRISMOR_HOME")
    git_root: Optional[Path] = None
    if prismor_home:
        p = Path(prismor_home).expanduser()
        if (p / ".git").exists():
            git_root = p
    elif (_REPO_ROOT / ".git").exists():
        git_root = _REPO_ROOT

    if git_root is not None:
        def _update():
            # A clone install updates itself; a working checkout does not. Now
            # that the repo root resolves correctly, `prismor setup` run from a
            # development checkout would otherwise pull on top of whatever the
            # developer has in progress.
            dirty = subprocess.run(
                ["git", "-C", str(git_root), "status", "--porcelain"],
                capture_output=True, timeout=15,
            )
            if dirty.returncode == 0 and dirty.stdout.strip():
                return True, "skipped (local changes)"
            upstream = subprocess.run(
                ["git", "-C", str(git_root), "rev-parse", "--abbrev-ref", "@{u}"],
                capture_output=True, timeout=15,
            )
            if upstream.returncode != 0:
                return True, "skipped (no upstream branch)"
            r = subprocess.run(
                ["git", "-C", str(git_root), "pull", "--quiet"],
                capture_output=True, timeout=15,
            )
            return r.returncode == 0, "up to date" if r.returncode == 0 else "offline"
        _spinner_run("Updating Prismor", _update)
    else:
        def _pip_note():
            # `pip install --upgrade` is wrong for the pipx and uv installs the
            # README recommends; `prismor update` works whichever was used.
            return True, "run `prismor update` to upgrade"
        _spinner_run("Prismor (installed package)", _pip_note)

    # 2. Persist the rule selection.
    #
    # Enforce writes the full picture — `selection: explicit` plus one entry per
    # rule the user chose — so what blocks is legible in the file rather than
    # implied by the shipped defaults. Observe writes only disabled rules, as
    # before: it blocks nothing either way, and adding `default_mode` there would
    # switch off the compatibility bridge that makes an existing install with
    # hand-flipped enforce hooks keep blocking (see PolicyEngine.is_legacy_policy).
    selected = [r["id"] for r in rules if r["on"]]
    disabled = [r["id"] for r in rules if not r["on"]]
    if mode == "enforce":
        def _write_policy():
            d = target / ".prismor"
            d.mkdir(exist_ok=True)
            (d / "policy.yaml").write_text(_render_selection_policy(selected), encoding="utf-8")
            return True, f"{len(selected)} rule(s) enforcing"
        _spinner_run("Writing policy selection", _write_policy)
    elif disabled:
        def _write_policy():
            d = target / ".prismor"
            d.mkdir(exist_ok=True)
            txt = 'version: "1.0"\nrules:\n'
            for rid in disabled:
                txt += f"  - id: {rid}\n    enabled: false\n"
            (d / "policy.yaml").write_text(txt, encoding="utf-8")
            return True, f"{len(disabled)} disabled"
        _spinner_run("Writing policy overrides", _write_policy)

    # 3. Install hooks directly via prismor.runtime.hooks
    from prismor.runtime.hooks import install_hooks
    for agent in agents:
        def _install_hook(a: str = agent):
            try:
                install_hooks(
                    repo_root=_REPO_ROOT,
                    workspace=target,
                    agent=a,
                    scope=scope,
                    mode=mode,
                )
                return True, ""
            except Exception as e:
                return False, str(e)[:50]
        _spinner_run(f"Installing {agent} hooks", _install_hook)

    # 3a. MCP mirror — only for agents explicitly opted in on the agent screen.
    # Deliberately after hooks: if this fails the machine still has working
    # governance, whereas a mirror installed without hooks would be the only
    # control and a half-install leaves the agent with no tools at all.
    for agent in (mirror_agents or []):
        def _install_mirror(a: str = agent):
            try:
                from prismor.runtime import mirror_cli
                rc = mirror_cli.mirror_on(target, mode=mode, agent=a)
                return rc == 0, "" if rc == 0 else "see output above"
            except Exception as e:
                return False, str(e)[:50]
        _spinner_run(f"Serving {agent} built-ins over MCP", _install_mirror)

    # 3b. Cloaking hooks (opt-in — Claude Code only for now)
    if cloak and "claude" in agents:
        def _install_cloak():
            if not shutil.which("jq"):
                return False, "jq not found (brew install jq)"
            # Route through prismor/runtime/cli.py directly with the current interpreter.
            # Don't shell out to a `prismor` binary on PATH — that entry point is
            # a deprecation shim and prints a "'prismor' is deprecated" warning.
            r = subprocess.run(
                [sys.executable, str(_PKG_DIR / "cli.py"), "cloak", "install",
                 "--workspace", str(target), "--scope", scope],
                capture_output=True, timeout=30,
            )
            return r.returncode == 0, "enabled" if r.returncode == 0 else r.stderr.decode()[:40]
        _spinner_run("Installing cloaking hooks", _install_cloak)

    # 4. CLAUDE.md
    def _update_claude():
        md = target / "CLAUDE.md"
        block = (
            "\n## Security (Prismor)\n\n"
            "This workspace is protected by Prismor — runtime "
            "security hooks that monitor tool calls in real time (destructive "
            "commands, secret leaks, supply-chain risk, prompt injection).\n\n"
            "Run `prismor status` at the start of a session to check protection "
            "state. The full decision tree lives in "
            "`.claude/skills/immunity-agent/SKILL.md`.\n\n"
            "For more info: https://github.com/PrismorSec/prismor\n"
        )
        if md.exists():
            content = md.read_text(encoding="utf-8")
            if "Prismor" in content:
                return True, "already present"
            md.write_text(content + block, encoding="utf-8")
            return True, "appended"
        md.write_text(block.lstrip(), encoding="utf-8")
        return True, "created"
    _spinner_run("Updating CLAUDE.md", _update_claude)

    # 4b. Install SKILL.md for all workspaces — any agent can read it.
    _spinner_run("Installing immunity-agent skill", lambda: _install_skill(target))

    # 4c. Agent-specific context files (cursorrules, windsurfrules, AGENTS.md).
    def _write_context():
        try:
            _write_agent_context(target, agents)
            return True, ""
        except OSError as e:
            return False, str(e)[:50]
    _spinner_run("Writing agent context", _write_context)

    # 5. Feed signature verification (use prismor.runtime.paths resolver, skip shell script)
    def _verify_feed():
        try:
            from prismor.runtime.paths import feed_path, public_key_path, feed_sig_path
            fp  = feed_path()
            sig = feed_sig_path()
            pub = public_key_path()
        except ImportError:
            return True, "skipped (paths unavailable)"
        if not all(p.exists() for p in (fp, sig, pub)):
            return True, "skipped (feed not bundled)"
        # .sig file is base64-encoded; decode to raw binary first
        import base64
        sig_bytes = base64.b64decode(sig.read_bytes())

        # Prefer the `cryptography` extra — it is already how receipts are
        # verified, and it needs no external binary. Windows ships no openssl,
        # so shelling out there raised FileNotFoundError and painted a red
        # "signature mismatch"-looking failure on a perfectly good feed.
        try:
            from cryptography.exceptions import InvalidSignature
            from cryptography.hazmat.primitives.serialization import load_pem_public_key
            key = load_pem_public_key(pub.read_bytes())
            try:
                key.verify(sig_bytes, fp.read_bytes())
                return True, "verified"
            except InvalidSignature:
                return False, "signature mismatch"
        except ImportError:
            pass

        import tempfile
        with tempfile.NamedTemporaryFile(delete=False, suffix=".sig.raw") as tf:
            sig_raw = tf.name
        try:
            Path(sig_raw).write_bytes(sig_bytes)
            r = subprocess.run(
                ["openssl", "pkeyutl", "-verify", "-pubin", "-rawin",
                 "-inkey", str(pub), "-sigfile", sig_raw, "-in", str(fp)],
                capture_output=True, timeout=15,
            )
            return r.returncode == 0, "verified" if r.returncode == 0 else "signature mismatch"
        except (FileNotFoundError, OSError):
            # No openssl and no `cryptography`: say so plainly. An unverifiable
            # feed is not a failed verification, and reporting it as one trains
            # people to ignore the line that matters.
            return True, "skipped (install prismor[signing] to verify)"
        finally:
            try:
                Path(sig_raw).unlink()
            except Exception:
                pass
    _spinner_run("Verifying feed signature", _verify_feed)

    # Done — success banner
    home = str(Path.home())
    print()
    _print_banner("Prismor installed successfully!")
    print()

    def _info(k: str, v: str) -> None:
        print(f"  {_w(k + ':', GRN)}  {_w(v, DIM)}")

    _info("Hooks",      f"installed  (mode: {mode}, scope: {'global — every workspace on this machine' if scope == 'global' else 'this workspace'})")
    if "codex" in agents:
        _info("Codex",  "hooks run only after you trust them — accept the hook-trust prompt in the Codex TUI once,")
        print(f"          {_w('or pass --dangerously-bypass-hook-trust to `codex exec` for headless runs', DIM)}")
    if "claude" in agents:
        _info("Skill",  str(target / ".claude" / "skills" / "immunity-agent").replace(home, "~"))
    _info("Docs",       "https://github.com/PrismorSec/prismor")
    _info("Config",     str(target / "CLAUDE.md").replace(home, "~"))
    _info("Command",    "prismor status  ·  prismor sessions  ·  prismor check \"<cmd>\"")
    print()
    print(_w("  Quick commands:", GRN))
    print(f"    prismor status                       {_w('this workspace health check', DIM)}")
    print(f"    prismor status --all                 {_w('overview across all workspaces', DIM)}")
    print(f"    prismor sessions --findings-only     {_w('all flagged sessions by risk', DIM)}")
    print(f"    prismor check \"rm -rf /\"              {_w('pre-check a command', DIM)}")
    print(f"    prismor sweep                        {_w('scan AI tool configs for leaked secrets', DIM)}")
    print()
    sys.stdout.write(SHOW)
    sys.stdout.flush()


# ── Public API ────────────────────────────────────────────────────────────────

def run_non_interactive(
    target: Path,
    *,
    mode: str = "observe",
    agents: Optional[List[str]] = None,
    cloak: bool = False,
    scope: str = "project",
    enforce_rules: Optional[List[str]] = None,
    recommended: bool = False,
) -> None:
    """Run install without TUI. Args take precedence over env vars (resolution done by caller).

    ``enforce_rules`` / ``recommended`` are the scripted equivalent of the
    selection step: which rules block. Enforce with neither installs with
    nothing selected rather than guessing, and says so.
    """
    rules = _load_rules()
    if mode == "enforce":
        wanted = set(enforce_rules or [])
        unknown = wanted - {r["id"] for r in rules}
        for r in rules:
            r["on"] = r["id"] in wanted or (recommended and r.get("recommended", False))
        if unknown:
            print(f"[prismor] Unknown rule id(s) ignored: {', '.join(sorted(unknown))}")
    if agents is None:
        det = _detect_agents(target)
        agents = [n for n, ok in det.items() if ok] or ["claude"]
    cloak_tag = ", cloak=yes" if cloak else ""
    scope_tag = f", scope={scope}" if scope != "project" else ""
    print(f"[prismor] Non-interactive setup  (mode={mode}, agents={','.join(agents)}{cloak_tag}{scope_tag})")
    if mode == "enforce":
        n_on = sum(1 for r in rules if r["on"])
        if n_on == 0:
            print("[prismor] No rules selected — Prismor will detect and report, but block nothing.")
            print("[prismor] Pick a set with `--recommended` or `--enforce-rules id1,id2`, "
                  "or run `prismor setup` interactively.")
        else:
            print(f"[prismor] {n_on} rule(s) will block.")
    _do_install(target, mode, rules, agents, cloak=cloak, scope=scope)


def run_wizard(target: Path) -> None:
    """Run the interactive TUI wizard.

    Four steps in observe mode, five in enforce: choosing to block raises the
    question of *what* to block, and that answer is the user's to give.
    """
    sys.stdout.write(ALT_ON + HIDE)
    sys.stdout.flush()
    _raw_on()

    # In observe mode every rule stays enabled (nothing blocks regardless), so
    # the list is only read for the confirm screen's count. In enforce mode the
    # selection step below decides which of these actually block.
    rules = _load_rules()
    mode = "observe"
    agents = None
    mirror_agents = []
    cloak = True
    scope = "project"
    unlock_pw = False
    step = 1

    # The unlock window is a local affordance; on an org-managed workspace the
    # org decides whether self-edit is available at all, so don't offer it.
    try:
        from prismor.runtime.enterprise import workspace_scope as _scope
        offer_unlock = not _scope.is_managed(target)
    except Exception:
        offer_unlock = True

    try:
        while True:
            enforcing = mode == "enforce"
            total = (5 if enforcing else 4) + (1 if offer_unlock else 0)
            if step == 1:
                mode = _step_mode(mode, total=total, extra_steps=1 if offer_unlock else 0)
                step = 2 if mode == "enforce" else 3
            elif step == 2:
                result = _step_policy_select(rules, step=2, total=total)
                if result is _BACK:
                    step = 1
                    continue
                rules = result
                step = 3
            elif step == 3:
                result = _step_agents(target, step=3 if enforcing else 2, total=total)
                if result is _BACK:
                    step = 2 if enforcing else 1
                    continue
                agents = result["agents"]
                mirror_agents = result["mirror"]
                step = 4
            elif step == 4:
                result = _step_cloak(cloak, step=4 if enforcing else 3, total=total)
                if result is _BACK:
                    step = 3
                    continue
                cloak = result
                step = 5
            elif step == 5:
                result = _step_scope(scope, step=5 if enforcing else 4, total=total)
                if result is _BACK:
                    step = 4
                    continue
                scope = result
                step = 6
            elif step == 6:
                if not offer_unlock:
                    step = 7
                    continue
                result = _step_unlock(unlock_pw, step=total, total=total)
                if result is _BACK:
                    step = 5
                    continue
                unlock_pw = result
                step = 7
            elif step == 7:
                result = _step_confirm(target, mode, rules, agents, cloak=cloak,
                                       scope=scope, unlock_pw=unlock_pw,
                                       mirror_agents=mirror_agents)
                if result is _BACK:
                    step = 6 if offer_unlock else 5
                    continue
                break
    except Exception:
        rules = _load_rules()
        mode = "observe"
        agents = ["claude"]
        mirror_agents = []
        cloak = False
        scope = "project"
        unlock_pw = False

    _raw_off()
    _do_install(target, mode, rules, agents, cloak=cloak, scope=scope,
                mirror_agents=mirror_agents)
    # After the install output, so the prompt isn't competing with spinners.
    if unlock_pw:
        _prompt_unlock_password()
