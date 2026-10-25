"""Prismor — interactive setup wizard, usable from both pip install and git clone.

This module contains the full 4-step TUI wizard and the non-interactive install path.
It is the backing implementation for ``prismor setup``.

The original wizard in ``scripts/setup.py`` continues to work for git-clone users
running ``bash ~/.prismor/scripts/init.sh``; this module is its pip-installable twin.
"""

from __future__ import annotations

import atexit
import json
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

# Terminal formatting lives in tui_format, which was split out of this module so
# that non-interactive callers need not import the wizard's atexit/signal
# handlers. These are the names it took with it — aliased rather than redefined
# so the two renderings cannot drift apart.
from prismor.runtime.tui_format import (
    BLU,
    BOLD,
    CYAN,
    DIM,
    GRN,
    RED,
    VERSION,
    WHT,
    YEL,
    pad as _pad,
    term_width as _term_width,
    visible_len as _visible_len,
    w as _w,
)

# ── Constants ────────────────────────────────────────────────────────────────

_VERSION = VERSION
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

HIDE    = "\033[?25l"
SHOW    = "\033[?25h"
ALT_ON  = "\033[?1049h"
ALT_OFF = "\033[?1049l"

# Piped or captured output (an agent's Bash tool, CI logs) gets plain text: no
# colour, no cursor/screen codes, no spinner frames smeared across the log.
_PLAIN = not sys.stdout.isatty() or bool(os.environ.get("NO_COLOR"))
if _PLAIN:
    RST = BOLD = DIM = CYAN = GRN = YEL = RED = BLU = WHT = ""
    HIDE = SHOW = ALT_ON = ALT_OFF = ""


def _s(*codes: str) -> str:
    return "".join(codes)


# ── Screen buffer ────────────────────────────────────────────────────────────

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
    ``recommended``     — what we actually advise turning on: the floor, plus the
                          few overridable rules in ``_RECOMMENDED_RULE_IDS``.

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
        r["recommended"] = r["floor"] or (rid in _recommended_ids() and not r["self_protect"])
    return rules


def _recommended_ids() -> set:
    try:
        from prismor.runtime.policy_engine import _RECOMMENDED_RULE_IDS
        return set(_RECOMMENDED_RULE_IDS)
    except Exception:
        return set()


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

_AGENT_IDS = ("claude", "cursor", "windsurf", "openclaw", "hermes", "codex", "grok", "kiro",
              "crush", "openhands", "qwen", "continue", "goose", "antigravity", "copilot",
              "gemini", "opencode")


def _prismor_hook_files(target: Path) -> set:
    """Every file a Prismor hook install writes, at global and project scope."""
    from prismor.runtime import hooks
    out = set()
    for agent in _AGENT_IDS:
        for scope in ("global", "project"):
            try:
                out.add(hooks._config_path(agent, scope, target))
            except Exception:
                pass
    return out


def _holds_real_config(p: Path, ours: set) -> bool:
    """True when ``p`` exists and holds something Prismor did not write.

    Installing a global hook creates the agent's config dir (~/.codeium/windsurf/
    hooks.json, say), so a bare existence check reported the hook as proof the
    agent is installed, and coverage counted agents that were never there.
    """
    if not p.exists():
        return False
    if p.is_file():
        return p not in ours
    seen_ours = False
    for root, dirs, files in os.walk(p):
        seen_ours = seen_ours or "prismor" in dirs
        dirs[:] = [d for d in dirs if d != "prismor"]  # our plugin dirs (openclaw, hermes, goose)
        for f in files:
            if Path(root, f) not in ours and f != "prismor.js":
                return True
            seen_ours = True
    return not seen_ours  # an empty marker dir still counts, as it always has


def _detect_agents(target: Path) -> dict:
    home = Path.home()
    ours = _prismor_hook_files(target)
    found = lambda p: _holds_real_config(p, ours)
    # Coverage runs with the home dir as the workspace, where a project marker
    # is the global dir under another name: ~/.gemini is Antigravity's, which
    # made Gemini CLI look installed. Project markers only count elsewhere.
    in_project = target.resolve() != home.resolve()
    found_t = lambda p: in_project and found(p)
    return {
        "claude":   shutil.which("claude") is not None or found_t(target / ".claude") or found(home / ".claude"),
        "cursor":   found_t(target / ".cursor") or found(home / ".cursor"),
        "windsurf": found_t(target / ".windsurf") or found(home / ".codeium"),
        "openclaw": shutil.which("openclaw") is not None or found_t(target / ".openclaw") or found(home / ".openclaw"),
        "hermes":   shutil.which("hermes") is not None or found_t(target / ".hermes") or found(home / ".hermes"),
        "codex":    shutil.which("codex") is not None or found_t(target / ".codex") or found(home / ".codex"),
        "grok":     shutil.which("grok") is not None or found_t(target / ".grok") or found(home / ".grok"),
        "kiro":     shutil.which("kiro-cli") is not None or shutil.which("kiro") is not None or found_t(target / ".kiro") or found(home / ".kiro"),
        "crush":    shutil.which("crush") is not None or found_t(target / "crush.json") or found(home / ".config" / "crush"),
        "openhands": shutil.which("openhands") is not None or found_t(target / ".openhands") or found(home / ".openhands"),
        "qwen":     shutil.which("qwen") is not None or found_t(target / ".qwen") or found(home / ".qwen"),
        "continue": shutil.which("cn") is not None or found_t(target / ".continue") or found(home / ".continue"),
        "goose":    shutil.which("goose") is not None or found(home / ".config" / "goose"),
        "antigravity": shutil.which("agy") is not None or found(home / ".antigravity") or found(home / ".gemini" / "antigravity"),
        # A bare .github is in most repos, so only Copilot's own hooks dir counts.
        "copilot":  shutil.which("copilot") is not None or found_t(target / ".github" / "hooks") or found(home / ".copilot"),
        # ~/.gemini is shared with Antigravity (~/.gemini/antigravity), so look
        # for Gemini CLI's own settings file rather than the bare directory.
        "gemini":   shutil.which("gemini") is not None or found_t(target / ".gemini") or found(home / ".gemini" / "settings.json"),
        "opencode": shutil.which("opencode") is not None or found_t(target / ".opencode") or found_t(target / "opencode.json") or found(home / ".config" / "opencode"),
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
        # No "/total": the path branches (enforce adds steps, a named
        # governance mode removes one), so any total shown up front changes
        # under the user mid-wizard.
        out.append(f"  {_w(f'Step {step}', DIM)}  {_w(label, BOLD)}")
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
        # Choosing enforce adds the governance-mode and (for custom) the
        # rule-selection step, so the count has to follow the highlighted
        # option — otherwise this screen says "1/5" and the next one says
        # "2/7", which reads like a bug. Assumes custom (the worst case) since
        # no mode has been picked yet.
        total = (6 if opts[sel][0] == "enforce" else 4) + extra_steps
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


# ── Step 2 (enforce only): Governance mode ───────────────────────────────────

def _mode_bar(pct: int, width: int = 16) -> str:
    filled = max(0, min(width, round(pct / 100 * width)))
    return "█" * filled + "░" * (width - filled)


def _step_governance_mode(current: str = "custom", step: int = 2, total: int = 6):
    """Pick a named governance posture, or fall through to the rule-by-rule
    picker this wizard has always had.

    A mode (``prismor/runtime/modes.yaml``) compiles egress, tool access, tag
    rules and the sandbox together — the same six axes `custom` makes you set
    one at a time — so offering it here is the difference between "which of
    77 rules should block" and "which of three postures do you want".
    """
    try:
        from prismor.runtime.modes import load_modes, coverage, format_explain
    except Exception:
        return "custom"

    modes = load_modes()
    ids = list(modes.keys()) + ["custom"]
    sel = ids.index(current) if current in ids else len(ids) - 1
    showing_explain = False

    while True:
        if showing_explain and ids[sel] != "custom":
            text = format_explain({**modes[ids[sel]], "id": ids[sel]})
            lines = text.splitlines()
            lines.append("")
            lines.append(_control_line([("any key", "back to the list")]))
            _render(lines)
            _read_key()
            showing_explain = False
            continue

        lines = _header_lines(step, total, "GOVERNANCE MODE")
        lines.append(f"  {_w('A mode sets egress, tool access, tag rules and the sandbox together.', DIM)}")
        lines.append(f"  {_w('Pick custom to choose exactly which rules block instead.', DIM)}")
        lines.append("")
        for i, mid in enumerate(ids):
            arrow = _w("▸ ", CYAN) if i == sel else "  "
            dot   = _w("●", GRN) if i == sel else _w("○", DIM)
            if mid == "custom":
                nm = _pad(_w("custom", BOLD) if i == sel else _w("custom", DIM), 20)
                lines.append(f"  {arrow}{dot}  {nm}{_w('Pick exactly which rules block, rule by rule', DIM)}")
                if i != len(ids) - 1:
                    lines.append("")
                continue
            m = modes[mid]
            blocking, tot_rules = coverage({**m, "id": mid})
            pct = round(blocking / tot_rules * 100) if tot_rules else 0
            friction = int(m.get("friction_index", 0))
            nm = _pad(_w(mid, BOLD) if i == sel else _w(mid, DIM), 20)
            lines.append(f"  {arrow}{dot}  {nm}{_w(m.get('intent', ''), DIM)}")
            lines.append(f"  {'':25}{_w(f'coverage [{_mode_bar(pct)}] {pct:>3}%', DIM)}"
                         f"   {_w(f'friction [{_mode_bar(friction)}] {friction:>3}%', DIM)}")
            # A name, a sentence and two bars per option: run together they read
            # as one paragraph and the selected row is hard to place.
            if i != len(ids) - 1:
                lines.append("")
        lines.append("")
        lines.append(_control_line([
            ("↑↓", "select"), ("e", "explain"), ("←", "back"), ("enter", "next"),
        ]))
        _render(lines)

        key = _read_key()
        if key == _UP:               sel = (sel - 1) % len(ids)
        elif key == _DOWN:           sel = (sel + 1) % len(ids)
        elif key in ("e", "E") and ids[sel] != "custom":
            showing_explain = True
        elif key in (_LEFT, "b", "B"): return _BACK
        elif key in (_ENTER, "\n"):  return ids[sel]
        elif key in ("q", "Q", "\x03"): _cleanup(); sys.exit(0)


# ── Step 3 (enforce + custom only): Which rules block ────────────────────────

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
        {"name": "antigravity", "label": "Antigravity", "on": detected.get("antigravity", False)},
        {"name": "copilot",   "label": "GitHub Copilot", "on": detected.get("copilot", False)},
        {"name": "gemini",    "label": "Gemini CLI",  "on": detected.get("gemini", False)},
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
            tag   = _pad(_w("detected", GRN) if detected.get(ag["name"]) else _w("not found", DIM), 11)
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
        ("yes", "Install cloaking hooks   recommended"),
        ("no",  "Skip — runtime policy hooks only"),
    ]
    sel = 0 if current else 1

    while True:
        lines = _header_lines(step, total, "SECRET CLOAKING")
        lines.append(f"  {_w('Keeps real secrets out of model context, session logs and outbound', DIM)}")
        lines.append(f"  {_w('API requests — the agent sees @@SECRET:name@@ instead.', DIM)}")
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


# ── Step: LLM judge ───────────────────────────────────────────────────────────

_JUDGE_OPTS = [
    # (provider, label, default model, description)
    ("heuristic", "Heuristics only",  "",                          "no LLM; regex + structural rules decide"),
    ("claude",  "Claude Code CLI",  "claude-haiku-4-5-20251001", "your Claude login, no API key; ~20s, uncertain events only"),
    ("codex",   "Codex CLI",        "",                          "your ChatGPT login, no API key; ~8s, uncertain events only"),
    ("typesafe", "TypeSafe API",    "jev-latest",                "$TYPESAFE_API_KEY; ~0.2s, judges every text"),
    ("api",     "API key",          "",                          "OpenAI / Gemini / Anthropic key; ~1-3s, judges every text"),
    ("prismor", "Prismor API",     "",                          "1,000 free verdicts/month; no key or CLI; ~2s, judges every text"),
]


def _default_judge() -> str:
    """Pre-select the subscription the user already pays for: Claude Code, then Codex."""
    for prov in ("claude", "codex"):
        if _judge_ready(prov) == "found":
            return prov
    return "heuristic"


def _judge_ready(provider: str) -> str:
    """One-word readiness hint per provider, from what is on this host."""
    if provider == "claude":
        from prismor.runtime.semantic_guard_v2 import CLAUDE_CLI
        return "found" if os.path.exists(CLAUDE_CLI) else "not installed"
    if provider == "codex":
        from prismor.runtime.semantic_guard_v2 import CODEX_CLI
        return "found" if os.path.exists(CODEX_CLI) else "not installed"
    if provider == "api":
        keys = [k for k in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GEMINI_API_KEY", "OPENROUTER_API_KEY")
                if os.environ.get(k)]
        return keys[0] if keys else "no key in env"
    if provider == "typesafe":
        return "TYPESAFE_API_KEY" if os.environ.get("TYPESAFE_API_KEY") else "no key in env"
    if provider == "prismor":
        from prismor.runtime.enterprise.identity import is_enrolled
        # "sign in" is a to-do, not a blocker: picking it runs `prismor login`
        # at the end of the install.
        return "connected" if is_enrolled() else "sign in"
    return ""


def _read_line(prefill: str) -> str:
    """Minimal line editor for raw mode: printable chars, backspace, enter."""
    buf = list(prefill)
    while True:
        sys.stdout.write("\r\033[K  " + _w("Model: ", BOLD) + "".join(buf) + SHOW)
        sys.stdout.flush()
        key = _read_key()
        if key in (_ENTER, "\n"):
            sys.stdout.write(HIDE)
            return "".join(buf).strip()
        if key in ("\x7f", "\b"):
            if buf:
                buf.pop()
        elif key == "\x03":
            _cleanup(); sys.exit(0)
        elif key == "\x1b":
            sys.stdout.write(HIDE)
            return prefill
        elif len(key) == 1 and key.isprintable():
            buf.append(key)


def _step_judge(current: tuple = ("", ""), step: int = 4, total: int = 5):
    """Which login judges the uncertain zone of the semantic layer.

    Returns (provider, model); "" provider = heuristics only, no policy write.
    """
    want = current[0] or _default_judge()
    sel = next((i for i, o in enumerate(_JUDGE_OPTS) if o[0] == want), 0)
    while True:
        lines = _header_lines(step, total, "LLM JUDGE")
        lines.append(f"  {_w('A small model reviews what the regex layer cannot decide. CLI judges are slow,', DIM)}")
        lines.append(f"  {_w('so they only see uncertain events (score 0.30-0.75). API judges see every prompt', DIM)}")
        lines.append(f"  {_w('and tool result: a paraphrased injection scores 0 on the regexes.', DIM)}")
        lines.append("")
        tw = _term_width()
        for i, (prov, label, _m, desc) in enumerate(_JUDGE_OPTS):
            arrow = _w("▸ ", CYAN) if i == sel else "  "
            dot   = _w("●", GRN) if i == sel else _w("○", DIM)
            nm    = _pad(_w(label, BOLD) if i == sel else _w(label, DIM), 20)
            ready = _judge_ready(prov)
            tag = ""
            if ready:
                ok = ready in ("found", "connected") or ready.endswith("_KEY")
                tag = "  " + _w(f"[{ready}]", GRN if ok else YEL)
            lines.append(f"  {arrow}{dot}  {nm}{_w(desc[:max(tw - 46, 20)], DIM)}{tag}")
        lines.append("")
        lines.append(_control_line([
            ("↑↓", "select"), ("←", "back"), ("enter", "next"), ("q", "quit"),
        ]))
        _render(lines)

        key = _read_key()
        if key == _UP:                  sel = (sel - 1) % len(_JUDGE_OPTS)
        elif key == _DOWN:              sel = (sel + 1) % len(_JUDGE_OPTS)
        elif key in (_LEFT, "b", "B"):  return _BACK  # type: ignore[return-value]
        elif key in (_ENTER, "\n"):
            prov, _l, default_model, _d = _JUDGE_OPTS[sel]
            if prov in ("heuristic", "prismor"):  # no model / the server picks it
                return (prov, "")
            if prov == "api":
                from prismor.runtime.semantic_guard import default_model as _api_default
                default_model = _api_default()
            fallback = {"claude": "the Claude CLI's own default", "codex": "the Codex CLI's own default",
                        "typesafe": "jev-latest"}.get(prov, default_model or "none: set PRISMOR_SEMANTIC_MODEL")
            sys.stdout.write("\n  " + _w(f"Model id. Enter keeps what is shown; blank uses {fallback}.", DIM) + "\n")
            model = _read_line(current[1] if current[0] == prov and current[1] else default_model)
            return (prov, model)
        elif key in ("q", "Q", "\x03"): _cleanup(); sys.exit(0)


def _write_judge_setting(target: Path, provider: str, model: str) -> None:
    """Persist settings.semantic_guard.{provider,model} into .prismor/policy.yaml.

    Textual insert under an existing top-level `settings:` (keeps the file's
    comments); falls back to a YAML round-trip only when the file already has a
    semantic_guard stanza to merge into.
    """
    d = target / ".prismor"
    d.mkdir(exist_ok=True)
    path = d / "policy.yaml"
    if provider == "heuristic":
        # Written, not left unset: unset means "use whichever provider key is in
        # the environment", which is not what "no LLM" promised.
        block = "  semantic_guard:\n    mode: heuristic\n"
    else:
        block = f"  semantic_guard:\n    provider: {provider}\n    model: {json.dumps(model)}\n"
    txt = path.read_text(encoding="utf-8") if path.exists() else 'version: "1.0"\n'
    if "semantic_guard:" in txt:
        import yaml
        raw = yaml.safe_load(txt) or {}
        sg = raw.setdefault("settings", {}).setdefault("semantic_guard", {})
        if provider == "heuristic":
            sg.pop("provider", None)
            sg.pop("model", None)
            sg["mode"] = "heuristic"
        else:
            if sg.get("mode") == "heuristic":
                sg.pop("mode")
            sg["provider"], sg["model"] = provider, model
        path.write_text(yaml.safe_dump(raw, sort_keys=False), encoding="utf-8")
        return
    lines = txt.splitlines(keepends=True)
    for i, ln in enumerate(lines):
        if ln.rstrip() == "settings:":
            lines.insert(i + 1, block)
            break
    else:
        lines.append(("" if txt.endswith("\n") else "\n") + "settings:\n" + block)
    path.write_text("".join(lines), encoding="utf-8")


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
        lines.append(f"  {_w('The agent cannot edit its own policy. A password lends it that for', DIM)}")
        lines.append(f"  {_w('a few minutes via `prismor unlock`. You can set one up any time.', DIM)}")
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


def _wrap_value(value: str, width: int) -> List[str]:
    """Wrap a summary value to `width`, breaking on ", " then spaces."""
    text = str(value or "")
    if len(text) <= width:
        return [text]
    lines: List[str] = []
    rest = text
    while len(rest) > width:
        window = rest[:width + 1]
        cut = window.rfind(", ")
        cut = cut + 1 if cut > 0 else window.rfind(" ")
        if cut <= 0:
            cut = width
        lines.append(rest[:cut].rstrip())
        rest = rest[cut:].lstrip()
    if rest:
        lines.append(rest)
    return lines


# ── Confirm ──────────────────────────────────────────────────────────────────

def _step_confirm(target: Path, mode: str, rules: List[dict], agents: List[str], cloak: bool = False, scope: str = "project", unlock_pw: bool = False, mirror_agents: Optional[List[str]] = None, gov_mode: Optional[str] = None, judge: tuple = ("", "")) -> bool:
    home = str(Path.home())
    disp = str(target).replace(home, "~")
    n_on = sum(1 for r in rules if r["on"])
    n_rec = sum(1 for r in rules if r.get("recommended"))
    n_rec_on = sum(1 for r in rules if r.get("recommended") and r["on"])
    ags  = ", ".join(agents)
    mirror_agents = mirror_agents or []
    # Wide enough for the longest value we are about to print, and never wider
    # than the terminal. A fixed 48 meant a ten-agent list ran straight through
    # the right border, because the padding below floors at zero.
    W = max(48, min(_term_width() - 6, max([len(ags), len(disp)], default=0) + 18))
    KEY_W = 14
    VAL_W = W - KEY_W - 2

    def bdr(l, fill, r):
        return _w(f"  {l}{fill * W}{r}", DIM)

    def row(content: str = "") -> str:
        vl = _visible_len(content)
        p = " " * max(0, W - vl - 2)
        return _w("  │", DIM) + " " + content + p + " " + _w("│", DIM)

    def kv(k: str, v: str, vc: str = WHT) -> str:
        return f"{_pad(_w(k, DIM), KEY_W)}{_w(v, vc)}"

    def kv_rows(k: str, v: str, vc: str = WHT) -> List[str]:
        """A key and a value that may not fit on one line, as box rows.

        Wraps on commas and spaces so a long agent list continues under itself
        instead of escaping the box.
        """
        chunks = _wrap_value(v, VAL_W)
        out = [row(kv(k, chunks[0] if chunks else "", vc))]
        for extra in chunks[1:]:
            out.append(row(f"{' ' * KEY_W}{_w(extra, vc)}"))
        return out

    while True:
        lines = _header_lines()
        lines.append(bdr("╭", "─", "╮"))
        lines.append(row(_w("READY TO INSTALL", BOLD)))
        lines.append(row())
        lines.extend(kv_rows("Project", disp))
        lines.append(row(kv("Mode", mode, GRN if mode == "enforce" else YEL)))
        if mode == "enforce" and gov_mode not in (None, "custom"):
            try:
                from prismor.runtime.modes import load_modes, coverage
                m = load_modes().get(gov_mode, {})
                blocking, tot_rules = coverage({**m, "id": gov_mode})
                pct = round(blocking / tot_rules * 100) if tot_rules else 0
                friction = int(m.get("friction_index", 0))
                lines.append(row(kv("Governance", f"{gov_mode}  ({blocking}/{tot_rules} rules · "
                                    f"{pct}% coverage · {friction}% friction)", GRN)))
            except Exception:
                lines.append(row(kv("Governance", gov_mode, GRN)))
        elif mode == "enforce":
            lines.append(row(kv("Blocking", f"{n_on} selected  ({n_rec_on}/{n_rec} recommended)",
                                GRN if n_on else YEL)))
            if n_on == 0:
                lines.append(row(_w("nothing blocks — Prismor will only watch", YEL)))
        else:
            lines.append(row(kv("Rules", f"{n_on}/{len(rules)} enabled")))
        lines.extend(kv_rows("Agents", ags))
        lines.append(row(kv("Surface", "PreToolUse / PostToolUse hooks")))
        if mirror_agents:
            lines.extend(kv_rows("MCP mirror", ", ".join(mirror_agents), YEL))
            lines.append(row(_w("built-ins served by Prismor; next session", DIM)))
        lines.append(row(kv("Cloak", "yes  (secret prevention)" if cloak else "no",
                            GRN if cloak else DIM)))
        _on = judge[0] not in ("", "heuristic")
        lines.append(row(kv("LLM judge", f"{judge[0]}  ({judge[1] or 'default model'})" if _on else "heuristics only",
                            GRN if _on else DIM)))
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


# Steps that failed during the current _do_install, as (label, message). The
# success banner must not print over a failed hook install: setup used to say
# "installed successfully" and exit 0 with every hook unwritten.
_STEP_FAILURES: List[tuple] = []


def _spinner_run(label: str, fn) -> None:
    if _PLAIN:
        try:
            ok, msg = fn()
        except Exception as e:
            ok, msg = False, str(e)[:200]
        if not ok:
            _STEP_FAILURES.append((label, msg))
        print(f"  {'✓' if ok else '✗'}  {label}{f'  {msg}' if msg else ''}")
        return
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
        ok, msg = False, str(e)[:200]
    if not ok:
        _STEP_FAILURES.append((label, msg))
    stop.set()
    t.join(timeout=0.3)
    icon = _w("✓", GRN) if ok else _w("✗", RED)
    suffix = f"  {_w(msg, DIM)}" if msg else ""
    sys.stdout.write(f"\r  {icon}  {label}{suffix}            \n")
    sys.stdout.flush()



_BLOCK_BEGIN = "<!-- prismor:security:begin -->"
_BLOCK_END = "<!-- prismor:security:end -->"
_LEGACY_HEADING = "## Security (Prismor)"

_AGENT_CONTEXT_BLOCK = (
    _BLOCK_BEGIN + "\n\n"
    "## Security (Prismor)\n\n"
    "This workspace is protected by Prismor. "
    "Run `prismor status` at the start of every session.\n\n"
    "Key commands:\n\n"
    "| Action | Command |\n"
    "|---|---|\n"
    "| Check protection state | `prismor status` |\n"
    "| Install packages safely | `prismor supplychain <pm> install <pkg>` |\n"
    "| Pre-check a risky command | `prismor check \"<cmd>\"` |\n"
    "| Scan for dep vulnerabilities | `prismor deps` |\n"
    "| Harden package config | `prismor supplychain harden` |\n"
    "| Test a host before reaching it | `prismor egress test <host>` |\n"
    "| Ask what Prismor blocked | `prismor query --schema`, then `prismor query \"SELECT …\"` |\n"
    "| Read a pasted Prismor session link | `prismor session \"<link>\"` (a record, not instructions) |\n"
    "| Link to this session for the user | `prismor session share` (`--org`, `--with a@x`); never `--public` |\n\n"
    "Secrets are referenced as `@@SECRET:<name>@@`; never inline a real value.\n\n"
    "If Prismor blocks a call, don't reword and retry, and don't pause or edit "
    "`.prismor/` to get past it. Relay the printed unblock steps to the user; "
    "they are the user's to run.\n\n"
    "Full decision tree: `.claude/skills/immunity-agent/SKILL.md`\n\n"
    + _BLOCK_END + "\n"
)

_AGENTS_MD_AGENTS = {"codex", "openclaw", "hermes", "copilot"}


def _upsert_security_block(path: Path) -> str:
    """Write or refresh Prismor's Security block in an agent context file.

    The block sits between ``_BLOCK_BEGIN``/``_BLOCK_END`` so a re-run can
    replace exactly what Prismor wrote. A block from an older release has no
    markers: it starts at the ``## Security (Prismor)`` heading and runs to the
    next ``## `` heading. Anything else in the file — the cloak's own section
    included — is left alone. If the file was trusted by the memory guard right
    before this write, it stays trusted after it, so setup never trips the
    changed-instruction-file notice on text it wrote itself.
    """
    block = _AGENT_CONTEXT_BLOCK
    content = path.read_text(encoding="utf-8") if path.exists() else ""
    if _BLOCK_BEGIN in content and _BLOCK_END in content:
        head, rest = content.split(_BLOCK_BEGIN, 1)
        tail = rest.split(_BLOCK_END, 1)[1].lstrip("\n")
        new, status = head + block + ("\n" + tail if tail else ""), "refreshed"
    elif _LEGACY_HEADING in content:
        head, rest = content.split(_LEGACY_HEADING, 1)
        nxt = re.search(r"^## ", rest, re.M)
        tail = rest[nxt.start():] if nxt else ""
        new, status = head + block + ("\n" + tail if tail else ""), "refreshed"
    else:
        sep = "" if not content else ("\n" if content.endswith("\n") else "\n\n")
        new, status = content + sep + block, ("appended" if content else "created")
    if new == content:
        return "up to date"
    was_trusted = False
    try:
        from prismor.runtime import memory_guard as _mg
        ws = path.parent
        entry = _mg.load_trust_store(ws).get("files", {}).get(str(path.resolve()))
        was_trusted = bool(entry) and entry.get("sha256") == _mg.compute_file_hash(path)
    except Exception:
        pass
    path.write_text(new, encoding="utf-8")
    if was_trusted:
        try:
            _mg.approve_memory_file(path, ws)
        except Exception:
            pass
    return status


def _write_agent_context(target: Path, agents: List[str]) -> None:
    """Write the immunity-agent command reference into agent-specific context files."""
    agent_files = {
        "cursor": target / ".cursorrules",
        "windsurf": target / ".windsurfrules",
    }
    for agent, path in agent_files.items():
        if agent in agents:
            _upsert_security_block(path)
    if any(a in agents for a in _AGENTS_MD_AGENTS):
        _upsert_security_block(target / "AGENTS.md")


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
    docs/) and records the installed SKILL.md's hash in ``.prismor-bundled``.
    A re-run refreshes a copy that still matches that hash, so agents pick up
    new guidance after an upgrade; a copy the user edited is kept. A copy from
    a release that wrote no stamp is refreshed with the old one saved as
    ``SKILL.md.bak``. Returns ``(ok, detail)`` for the spinner.
    """
    import hashlib
    try:
        from prismor.runtime.paths import skill_manifest_path, skill_docs_dir
        skill_md = skill_manifest_path()
        docs_src = skill_docs_dir()
    except Exception as e:
        return False, str(e)[:40]
    if not skill_md.exists():
        return True, "skipped (skill not bundled)"

    dest = target / ".claude" / "skills" / "immunity-agent"
    current, stamp = dest / "SKILL.md", dest / ".prismor-bundled"
    sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
    detail = "installed"
    try:
        if current.exists():
            if sha(current) == sha(skill_md):
                if not stamp.exists():
                    stamp.write_text(sha(skill_md) + "\n", encoding="utf-8")
                return True, "up to date"
            recorded = stamp.read_text(encoding="utf-8").strip() if stamp.exists() else ""
            if recorded and recorded != sha(current):
                return True, "kept (edited locally; delete it and re-run setup to refresh)"
            if not recorded:
                shutil.copy2(current, dest / "SKILL.md.bak")
                detail = "refreshed (old copy saved as SKILL.md.bak)"
            else:
                detail = "refreshed"
        dest.mkdir(parents=True, exist_ok=True)
        shutil.copy2(skill_md, current)
        stamp.write_text(sha(skill_md) + "\n", encoding="utf-8")
        if docs_src.exists() and docs_src.is_dir():
            docs_dest = dest / "docs"
            docs_dest.mkdir(exist_ok=True)
            for md in docs_src.glob("*.md"):
                shutil.copy2(md, docs_dest / md.name)
        return True, detail
    except OSError as e:
        return False, str(e)[:40]


def refresh_guidance() -> List[str]:
    """Refresh the skill and Security blocks in every registered workspace that
    already has them, after an upgrade. Only touches what setup wrote."""
    from prismor.runtime.store import list_registered_workspaces
    done = []
    for ws in list_registered_workspaces():
        if not ws.is_dir():
            continue
        changed = []
        if (ws / ".claude" / "skills" / "immunity-agent" / "SKILL.md").exists():
            ok, detail = _install_skill(ws)
            if ok and detail.startswith(("refreshed", "kept")):
                changed.append(f"skill {detail}")
        for name in ("CLAUDE.md", "AGENTS.md", ".cursorrules", ".windsurfrules"):
            f = ws / name
            if f.exists() and (_BLOCK_BEGIN in (t := f.read_text(encoding="utf-8")) or _LEGACY_HEADING in t):
                if _upsert_security_block(f) == "refreshed":
                    changed.append(name)
        if changed:
            done.append(f"{ws}: {', '.join(changed)}")
    return done


def _write_selection_policy(target: Path, selected: List[str], scope: str) -> None:
    """Write the enforce selection to ``target``, and for a global install also
    to the user layer (~/.prismor/policy.yaml). A global hook evaluates each
    repo under that repo's own policy (see PolicyEngine._load), so with the
    selection only in ``target`` every other repo fell back to the defaults,
    which warn where the selection blocks."""
    text = _render_selection_policy(selected)
    d = target / ".prismor"
    d.mkdir(exist_ok=True)
    (d / "policy.yaml").write_text(text, encoding="utf-8")
    if scope == "global":
        from prismor.runtime.store import prismor_home
        user_policy = prismor_home() / "policy.yaml"
        user_policy.parent.mkdir(parents=True, exist_ok=True)
        user_policy.write_text(text, encoding="utf-8")


def _do_install(target: Path, mode: str, rules: List[dict], agents: List[str], cloak: bool = False, scope: str = "project", mirror_agents: Optional[List[str]] = None, gov_mode: Optional[str] = None, judge: tuple = ("", "")) -> None:
    _STEP_FAILURES.clear()
    if not _PLAIN:
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
    if mode == "enforce" and gov_mode not in (None, "custom"):
        def _write_policy():
            # force=True is only "overwrite whatever policy is already here" —
            # setup is the tool whose job that is. It does not skip the
            # container-runtime check: apply_mode degrades the sandbox axis on
            # a host with no Docker and reports it in `notes`.
            from prismor.runtime.modes import apply_mode, ModeError
            try:
                _, notes = apply_mode(target, gov_mode, force=True)
            except ModeError as e:
                return False, str(e)[:70]
            detail = f"mode '{gov_mode}' compiled"
            if any(n.startswith("NOTE:") for n in notes):
                detail += "  NOTE: Docker not available, sandbox skipped"
            return True, detail
        _spinner_run(f"Compiling governance mode '{gov_mode}'", _write_policy)
    elif mode == "enforce":
        def _write_policy():
            _write_selection_policy(target, selected, scope)
            where = " in every workspace" if scope == "global" else ""
            return True, f"{len(selected)} rule(s) enforcing{where}"
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

    if judge[0]:
        def _write_judge():
            _write_judge_setting(target, judge[0], judge[1])
            label = {"prismor": "Prismor API", "heuristic": "heuristics only (no LLM)"}.get(
                judge[0], f"{judge[0]} ({judge[1] or 'default model'})")
            # OpenAI, Gemini and Anthropic ids are called directly; any other
            # model goes through litellm, which the base install leaves out.
            # Without it every verdict falls back to heuristics, i.e. the judge
            # is silently off — say so here, where the user just chose it.
            if judge[0] == "api":
                import importlib.util
                from prismor.runtime.semantic_guard import default_model, direct_route
                if (not direct_route(judge[1] or default_model())
                        and importlib.util.find_spec("litellm") is None):
                    return False, "needs litellm: pip install 'prismor[semantic]'"
            return True, label
        _spinner_run("Setting LLM judge", _write_judge)

        # The Prismor API needs an account; everything else is already on the
        # machine. Run the sign-in here, after the TUI has released the terminal,
        # so the code and the browser link are readable.
        if judge[0] == "prismor":
            from prismor.runtime.enterprise.identity import is_enrolled
            if not is_enrolled():
                from prismor.runtime.enterprise import cli_login as _cli_login
                if not _cli_login.run_interactive(label=None):
                    print("  Sign in later with:  prismor login")
                    print()

    # 3. Install hooks directly via prismor.runtime.hooks
    from prismor.runtime.hooks import install_hooks
    for agent in agents:
        def _install_hook(a: str = agent):
            try:
                results = install_hooks(
                    repo_root=_REPO_ROOT,
                    workspace=target,
                    agent=a,
                    scope=scope,
                    mode=mode,
                )
                warning = next((r["loadWarning"] for r in results if r.get("loadWarning")), "")
                return (False, f"written but not active: {warning}") if warning else (True, "")
            except Exception as e:
                return False, str(e)[:200]
        _spinner_run(f"Installing {agent} hooks", _install_hook)
    if "codex" in agents:
        # Codex runs nothing until the human trusts the hooks; installed is not screened.
        from prismor.runtime.cli import codex_trust_line
        _line = codex_trust_line(target)
        if _line:
            print(f"  {_w(_line, YEL)}")
            print()

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
                return False, str(e)[:200]
        _spinner_run(f"Serving {agent} built-ins over MCP", _install_mirror)

    # 3b. Cloaking hooks (opt-in — Claude Code only for now)
    if cloak and "claude" in agents:
        def _install_cloak():
            if not shutil.which("jq"):
                hint = {"win32": "winget install jqlang.jq", "darwin": "brew install jq"}.get(
                    sys.platform, "apt install jq, or your package manager")
                return False, f"jq not found ({hint})"
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
        return True, _upsert_security_block(target / "CLAUDE.md")
    _spinner_run("Updating CLAUDE.md", _update_claude)

    # 4b. Install SKILL.md for all workspaces — any agent can read it.
    _spinner_run("Installing immunity-agent skill", lambda: _install_skill(target))

    # 4c. Agent-specific context files (cursorrules, windsurfrules, AGENTS.md).
    def _write_context():
        try:
            _write_agent_context(target, agents)
            return True, ""
        except OSError as e:
            return False, str(e)[:200]
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
        # Shared with load_feed/audit: `cryptography` first (Windows ships no
        # openssl), then openssl. A toolchain that cannot check is not a
        # failed verification -- reporting it as one trains people to ignore
        # the line that matters.
        from prismor.runtime import feed_signature as fs
        result = fs.verify_feed_file(fp, sig, pub, use_cache=False)
        if result.status == fs.VERIFIED:
            return True, "verified"
        if result.status == fs.MISMATCH:
            return False, "signature mismatch"
        if result.status == fs.MISSING:
            return False, "signature unusable"
        return True, "skipped (install prismor[signing] to verify)"
    _spinner_run("Verifying feed signature", _verify_feed)

    # A hook that was not written means the agent is not protected, whatever
    # else succeeded. Say so and exit non-zero (scripts and CI check this).
    hook_failures = [(l, m) for l, m in _STEP_FAILURES if l.startswith("Installing") and "hooks" in l]
    if hook_failures:
        print()
        print(f"  {_w('Prismor setup did not finish: these agents are NOT protected.', RED)}")
        for label, msg in hook_failures:
            print(f"    ✗ {label}: {msg}")
        print(f"  {_w('Fix the error above (often a directory you cannot write to), then run setup again.', DIM)}")
        print(f"  {_w('Check what is installed with: prismor doctor', DIM)}")
        print()
        raise SystemExit(1)

    # Done — success banner
    home = str(Path.home())
    print()
    _print_banner("Prismor installed successfully!")
    print()

    def _info(k: str, v: str) -> None:
        print(f"  {_w(k + ':', GRN)}  {_w(v, DIM)}")

    _info("Hooks",      f"installed  (mode: {mode}, scope: {'global — every workspace on this machine' if scope == 'global' else 'this workspace'})")
    if mode == "enforce" and gov_mode not in (None, "custom"):
        _info("Blocking", f"what governance mode '{gov_mode}' selects  (prismor mode show)")
    elif mode == "enforce":
        n_block = sum(1 for r in rules if r.get("on"))
        if n_block:
            _info("Blocking", f"{n_block} rule(s)")
        else:
            print(f"  {_w('Blocking:', YEL)}  {_w('none — enforce is on but no rules are opted in, so nothing is stopped yet.', YEL)}")
            print(f"             {_w('Add them: prismor setup --mode enforce --recommended', DIM)}")
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

# Env vars agent CLIs set on the shells they spawn. ponytail: a known-names
# list, not a general detector; add an agent here when it sets its own marker.
_AGENT_ENV = ("AI_AGENT", "CLAUDECODE", "CODEX_THREAD_ID", "CODEX_SANDBOX", "CURSOR_AGENT", "GEMINI_CLI")


def running_under_agent() -> bool:
    return any(os.environ.get(k) for k in _AGENT_ENV)


def print_agent_questions(target: Path) -> None:
    """What an agent sees when it runs a bare `prismor setup`: the wizard's
    choices as plain questions plus the exact command for each answer, so the
    agent asks the user instead of silently installing log-only defaults."""
    target = target.resolve()
    agents = [n for n, ok in _detect_agents(target).items() if ok] or ["claude"]
    n_rec = sum(1 for r in _load_rules() if r.get("recommended"))
    env_files = sorted(
        p.name for p in target.glob(".env*")
        if p.is_file() and not p.name.endswith((".example", ".sample", ".template"))
    )
    secrets = ", ".join(env_files) + " (values not hidden from agents yet)" if env_files else "no .env files found"
    cloak_rec = "recommended" if env_files else "optional"
    cmd = f"prismor setup --non-interactive --mode enforce --recommended --cloak --scope project --agents {','.join(agents)}"
    print(f"""Prismor setup needs a few answers from the user. Nothing has been installed yet.
Ask the user these questions, then run the command at the bottom.

Detected
  workspace  {target}
  agents     {', '.join(agents)}
  secrets    {secrets}

1. Mode: should Prismor block risky actions, or only log them?
     enforce   {f"block the {n_rec} recommended safety-floor rules".ljust(48)}--mode enforce --recommended   [recommended]
     observe   {"log only, block nothing".ljust(48)}--mode observe
2. Secret cloaking: replace secret values with @@SECRET:name@@ placeholders the agent never sees?
     yes       --cloak      [{cloak_rec}]
     no        --no-cloak
3. Scope: protect only this project, or every project on this machine?
     project   --scope project   [recommended]
     global    --scope global
4. Agents: which to protect? Detected: {', '.join(agents)}   --agents {','.join(agents)}

With the recommended answers:
  {cmd}""")
    for name in env_files:
        print(f"  prismor cloak add --env-file {name}   # imports its values as placeholders; only names are printed")
    print("""
5. Later policy changes: Prismor blocks agents from editing its own policy. To let an agent
   add rules you ask for, you approve each change with a password. The user sets it once,
   in their own terminal (it needs a keyboard, so an agent can't run it):
     prismor unlock --set-password
   Then, whenever the agent needs to edit policy:  prismor unlock   (opens a 3-minute window)""")
    print("\nPrefer the full wizard? The user can run `prismor setup` in their own terminal.")


def run_non_interactive(
    target: Path,
    *,
    mode: str = "observe",
    agents: Optional[List[str]] = None,
    cloak: bool = False,
    scope: str = "project",
    enforce_rules: Optional[List[str]] = None,
    recommended: bool = False,
    judge: tuple = ("", ""),
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
    _do_install(target, mode, rules, agents, cloak=cloak, scope=scope, judge=judge)


def run_system_install(
    *,
    repo_root: Path,
    mode: str = "observe",
    agents: Optional[List[str]] = None,
    enforce_rules: Optional[List[str]] = None,
    recommended: bool = False,
) -> None:
    """`prismor setup --system`: one root install that governs every user.

    Writes /etc/prismor (marker, rule selection, dispatcher) and each agent's
    machine-wide hook config. See system_install for what moves under /etc.
    """
    from prismor.runtime import system_install
    from prismor.runtime.hooks import SYSTEM_HOOK_PATHS, install_hooks
    import prismor

    problem = system_install.check_supported()
    if problem:
        print(f"[prismor] Can't do a system install: {problem}")
        raise SystemExit(1)
    for path in (Path(sys.executable), Path(prismor.__file__).parent):
        blocked = system_install.unreadable_by_others(path)
        if blocked is not None:
            print(f"[prismor] {blocked} is not readable by other users, so their agents could not start "
                  f"the hook and would run unscreened.")
            if system_install.IS_WINDOWS:
                print("  Install Prismor into a shared, admin-owned location instead:")
                print('    py -3 -m venv "C:\\Program Files\\Prismor"')
                print('    & "C:\\Program Files\\Prismor\\Scripts\\pip.exe" install prismor')
                print('    & "C:\\Program Files\\Prismor\\Scripts\\prismor.exe" setup --system ...')
            elif str(blocked).startswith(("/root", "/home")):
                print("  Install Prismor into a shared, root-owned location instead:")
                print("    python3 -m venv /opt/prismor && /opt/prismor/bin/pip install prismor")
                print("    sudo /opt/prismor/bin/prismor setup --system ...")
            else:  # usually a venv built under an MDM agent's umask 077
                print(f"  Make it readable, then re-run:  chmod -R a+rX {blocked}")
            raise SystemExit(1)

    if agents is None:
        agents = list(SYSTEM_HOOK_PATHS)
    skipped = [a for a in agents if a not in SYSTEM_HOOK_PATHS]
    agents = [a for a in agents if a in SYSTEM_HOOK_PATHS]
    if skipped:
        print(f"[prismor] No machine-wide hook location for: {', '.join(skipped)} (skipped; "
              f"those agents need a per-user `prismor setup --scope global`)")

    rules = _load_rules()
    selected: List[str] = []
    if mode == "enforce":
        wanted = set(enforce_rules or [])
        selected = [r["id"] for r in rules
                    if r["id"] in wanted or (recommended and r.get("recommended", False))]

    system_install.write_marker(mode=mode, selected=len(selected))
    policy = system_install.system_dir() / "policy.yaml"
    if mode == "enforce":
        system_install.write_shared(policy, _render_selection_policy(selected))
    elif policy.exists():
        policy.unlink()  # observe: a stale selection would keep blocking

    print(f"[prismor] System install  (mode={mode}, agents={','.join(agents) or 'none'})")
    failed = []
    for agent in agents:
        try:
            for r in install_hooks(repo_root=repo_root, workspace=Path("/"), agent=agent,
                                   scope="system", mode=mode):
                print(f"  ✓ {r['agent']:<8} {r['configPath']}")
        except ValueError as exc:  # e.g. an org requirements.toml we must not rewrite
            failed.append(agent)
            print(f"  ✗ {agent:<8} {exc}")
    agents = [a for a in agents if a not in failed]
    if mode == "enforce":
        print(f"  ✓ policy   {policy}  ({len(selected)} rule(s) block)" if selected else
              f"  ! policy   {policy}  (no rules selected: detects and reports, blocks nothing; "
              f"add --recommended)")
    print(f"  ✓ marker   {system_install.marker_path()}")
    # Every user's agent must reach these, whatever the directories above them
    # already were; a file it can't read leaves that agent unhooked.
    unreachable = [(p, b) for p in [*(SYSTEM_HOOK_PATHS[a] for a in agents),
                                    system_install.system_dir() / "hook-dispatch.py"]
                   if (b := system_install.unreadable_by_others(p)) is not None]
    for p, b in unreachable:
        print(f"  ✗ {p} is not readable by other users ({b}); fix with: chmod a+rX {b}")
    if unreachable or failed:
        raise SystemExit(1)
    try:
        print(f"  ✓ sync     {system_install.install_sync_schedule()}")
    except Exception as exc:  # the hooks already screen; sync only links the org
        print(f"  ! sync     could not schedule `prismor system-sync` ({exc}); run it as admin "
              "every minute so org policy and telemetry flow")
    print()
    admin = "admin" if system_install.IS_WINDOWS else "root"
    sudo = "" if system_install.IS_WINDOWS else "sudo "
    rm = (f'Remove-Item -Recurse "{system_install.system_dir()}"' if system_install.IS_WINDOWS
          else f"sudo rm -rf {system_install.system_dir()}")
    print(f"  Every user on this machine is now screened; policy, pause and unlock are {admin}-only.")
    print(f"  Link it to your org:   {sudo}prismor enroll <TOKEN>")
    print("  Check it (exit 0 = ok): prismor enroll-status")
    print(f"  Remove it:             {sudo}prismor uninstall-hooks --scope system --agent all, then {rm}")


def _wizard_steps(mode: str, gov_mode: Optional[str], offer_unlock: bool) -> List[str]:
    """The ordered, named wizard steps for the current choices.

    "confirm" is always last and unnumbered (it shows "READY TO INSTALL", not
    a "Step X/Y" of its own). Enforce inserts "governance"; "policy_select"
    only follows it while no mode is chosen yet, or "custom" was.
    """
    names = ["mode"]
    if mode == "enforce":
        names.append("governance")
        if gov_mode in (None, "custom"):
            names.append("policy_select")
    names += ["agents", "cloak", "judge", "scope"]
    if offer_unlock:
        names.append("unlock")
    names.append("confirm")
    return names


def run_wizard(target: Path) -> None:
    """Run the interactive TUI wizard.

    Four steps in observe mode. Enforce adds a governance-mode choice, and —
    only if that choice is "custom" — the rule-by-rule picker on top of it.
    """
    sys.stdout.write(ALT_ON + HIDE)
    sys.stdout.flush()
    _raw_on()

    # In observe mode every rule stays enabled (nothing blocks regardless), so
    # the list is only read for the confirm screen's count. In enforce mode
    # either a governance mode or the rule-selection step decides what blocks.
    rules = _load_rules()
    mode = "observe"
    gov_mode: Optional[str] = None  # None = not chosen yet; "custom" = rule-by-rule
    agents = None
    mirror_agents = []
    cloak = True
    judge = ("", "")
    scope = "project"
    unlock_pw = False

    # The unlock window is a local affordance; on an org-managed workspace the
    # org decides whether self-edit is available at all, so don't offer it.
    try:
        from prismor.runtime.enterprise import workspace_scope as _scope
        offer_unlock = not _scope.is_managed(target)
    except Exception:
        offer_unlock = True

    idx = 0

    try:
        while True:
            names = _wizard_steps(mode, gov_mode, offer_unlock)
            idx = min(idx, len(names) - 1)
            name = names[idx]
            total = len(names) - 1  # exclude "confirm" from the numbered count
            n = idx + 1

            if name == "mode":
                mode = _step_mode(mode, total=total, extra_steps=1 if offer_unlock else 0)
                idx += 1
            elif name == "governance":
                result = _step_governance_mode(gov_mode or "custom", step=n, total=total)
                if result is _BACK:
                    idx -= 1
                    continue
                gov_mode = result
                idx += 1
            elif name == "policy_select":
                result = _step_policy_select(rules, step=n, total=total)
                if result is _BACK:
                    idx -= 1
                    continue
                rules = result
                idx += 1
            elif name == "agents":
                result = _step_agents(target, step=n, total=total)
                if result is _BACK:
                    idx -= 1
                    continue
                agents = result["agents"]
                mirror_agents = result["mirror"]
                idx += 1
            elif name == "cloak":
                result = _step_cloak(cloak, step=n, total=total)
                if result is _BACK:
                    idx -= 1
                    continue
                cloak = result
                idx += 1
            elif name == "judge":
                result = _step_judge(judge, step=n, total=total)
                if result is _BACK:
                    idx -= 1
                    continue
                judge = result
                idx += 1
            elif name == "scope":
                result = _step_scope(scope, step=n, total=total)
                if result is _BACK:
                    idx -= 1
                    continue
                scope = result
                idx += 1
            elif name == "unlock":
                result = _step_unlock(unlock_pw, step=n, total=total)
                if result is _BACK:
                    idx -= 1
                    continue
                unlock_pw = result
                idx += 1
            elif name == "confirm":
                result = _step_confirm(target, mode, rules, agents, cloak=cloak,
                                       scope=scope, unlock_pw=unlock_pw,
                                       mirror_agents=mirror_agents, gov_mode=gov_mode,
                                       judge=judge)
                if result is _BACK:
                    idx -= 1
                    continue
                break
    except Exception:
        rules = _load_rules()
        mode = "observe"
        gov_mode = None
        agents = ["claude"]
        mirror_agents = []
        cloak = False
        judge = ("", "")
        scope = "project"
        unlock_pw = False

    _raw_off()
    _do_install(target, mode, rules, agents, cloak=cloak, scope=scope,
                mirror_agents=mirror_agents, gov_mode=gov_mode, judge=judge)
    # After the install output, so the prompt isn't competing with spinners.
    if unlock_pw:
        _prompt_unlock_password()
