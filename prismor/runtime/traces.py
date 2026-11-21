"""`prismor traces` — browse recorded sessions in the terminal.

Three levels, each a list you move through: sessions → one session's event
timeline → one event in full. Data comes from the same store calls as
``prismor sessions`` / ``prismor session``, so what is shown here is what those
print, with the same redaction already applied at record time.

``Browser`` holds the state and renders plain lines, so it is tested without a
terminal; ``run`` only blits those lines with curses.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

try:  # Windows Python ships without curses; the browser logic still loads there.
    import curses as _curses
except ImportError:  # pragma: no cover
    _curses = None


def _key(name: str) -> Any:
    return getattr(_curses, name, f"<{name}>")


K_UP, K_DOWN, K_LEFT, K_RIGHT = _key("KEY_UP"), _key("KEY_DOWN"), _key("KEY_LEFT"), _key("KEY_RIGHT")
K_PGUP, K_PGDN, K_HOME, K_END = _key("KEY_PPAGE"), _key("KEY_NPAGE"), _key("KEY_HOME"), _key("KEY_END")
K_ENTER, K_BACKSPACE = _key("KEY_ENTER"), _key("KEY_BACKSPACE")

_SEV_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
_KEYS_HELP = {
    "sessions": "↑↓ move  ⏎ open  f findings only  r reload  q quit",
    "events": "↑↓ move  ⏎ open  n next finding  esc back  q quit",
    "detail": "↑↓ scroll  esc back  q quit",
}


def _short_ts(ts: Optional[str]) -> str:
    """``2026-11-05T08:55:36.61+00:00`` → ``11-05 08:55:36``."""
    if not ts or "T" not in ts:
        return (ts or "")[:14]
    day, _, clock = ts.partition("T")
    return f"{day[5:]} {clock[:8]}"


def _one_line(text: Any, width: int) -> str:
    s = " ".join(str(text or "").split())
    return s if len(s) <= width else s[: max(0, width - 1)] + "…"


def _verdict(event: Dict[str, Any]) -> str:
    raw = event.get("raw") or {}
    decision = raw.get("decision") or (raw.get("metadata") or {}).get("decision") or {}
    if isinstance(decision, dict):
        return str(decision.get("action") or decision.get("verdict") or "")
    return str(decision or "")


def session_line(s: Dict[str, Any], width: int) -> str:
    sev = ""
    if s.get("findingsCount"):
        sev = f"{s['findingsCount']} finding{'s' if s['findingsCount'] != 1 else ''}"
    where = Path(s.get("workspacePath") or "").name or "-"
    head = f"{_short_ts(s.get('updatedAt') or s.get('startedAt'))}  {str(s.get('agent') or '?'):<8} {sev:<12} {where:<20} "
    return _one_line(head + str(s.get("sessionId") or ""), width)


def event_summary(event: Dict[str, Any]) -> str:
    """The most telling field of an event, on one line."""
    for key in ("command", "path", "url"):
        if event.get(key):
            return str(event[key])
    raw = event.get("raw") or {}
    tool = (raw.get("metadata") or {}).get("tool_name")
    content = event.get("content") or ""
    return f"{tool}: {content}" if tool and content else (content or tool or "")


def event_line(i: int, event: Dict[str, Any], flagged: Optional[str], width: int) -> str:
    mark = {"CRITICAL": "!!", "HIGH": "! ", "MEDIUM": "* ", "LOW": ". "}.get(flagged or "", "  ")
    kind = str(event.get("agentEvent") or event.get("type") or "")
    verdict = _verdict(event)
    head = f"{mark}{i:>4}  {_short_ts(event.get('ts'))[6:]}  {kind:<18} {verdict[:6]:<6} "
    return _one_line(head + event_summary(event), width)


def detail_lines(index: int, event: Dict[str, Any], findings: List[Dict[str, Any]], width: int) -> List[str]:
    out = [f"event {index}  {event.get('ts') or ''}  {event.get('agentEvent') or event.get('type') or ''}", ""]
    for f in findings:
        out.append(f"[{f.get('severity')}] {f.get('title')}  ({(f.get('enrichment') or {}).get('ruleId') or f.get('category')})")
        if f.get("evidence"):
            out.append(f"  evidence: {_one_line(f['evidence'], width - 12)}")
    if findings:
        out.append("")
    for key in ("command", "path", "url"):
        if event.get(key):
            out.append(f"{key}: {event[key]}")
    if event.get("content"):
        out += ["", "content:"] + str(event["content"]).splitlines()
    out += ["", "raw:"] + json.dumps(event.get("raw") or {}, indent=2, default=str).splitlines()
    # Wrap hard: a long line would otherwise be cut at the screen edge.
    wrapped: List[str] = []
    for line in out:
        while len(line) > width > 0:
            wrapped.append(line[:width])
            line = line[width:]
        wrapped.append(line)
    return wrapped


class Browser:
    """State machine for the three views. Keys are curses key codes or chars."""

    def __init__(self, load_sessions: Callable[[], List[Dict[str, Any]]],
                 load_session: Callable[[str], Optional[Dict[str, Any]]],
                 load_cost: Optional[Callable[[str], Dict[str, Any]]] = None) -> None:
        self._load_sessions, self._load_session, self._load_cost = load_sessions, load_session, load_cost
        self.view = "sessions"
        self.findings_only = False
        self.cursor = {"sessions": 0, "events": 0, "detail": 0}
        self.session: Optional[Dict[str, Any]] = None
        self.cost: Dict[str, Any] = {}
        self.status = ""
        self.done = False
        self.reload()

    # ── data ──────────────────────────────────────────────────────────
    def reload(self) -> None:
        self.all_sessions = self._load_sessions()
        self.cursor["sessions"] = min(self.cursor["sessions"], max(0, len(self.sessions) - 1))

    @property
    def sessions(self) -> List[Dict[str, Any]]:
        if self.findings_only:
            return [s for s in self.all_sessions if s.get("findingsCount")]
        return self.all_sessions

    @property
    def events(self) -> List[Dict[str, Any]]:
        return (self.session or {}).get("events") or []

    def findings_at(self, index: int) -> List[Dict[str, Any]]:
        return [f for f in (self.session or {}).get("findings") or [] if f.get("eventIndex") == index]

    def _worst_at(self) -> Dict[int, str]:
        worst: Dict[int, str] = {}
        for f in (self.session or {}).get("findings") or []:
            i, sev = f.get("eventIndex"), str(f.get("severity") or "")
            if isinstance(i, int) and _SEV_ORDER.get(sev, 0) > _SEV_ORDER.get(worst.get(i, ""), 0):
                worst[i] = sev
        return worst

    # ── keys ──────────────────────────────────────────────────────────
    def handle(self, key: Any, page: int = 10) -> None:
        self.status = ""
        if key in ("q", "Q"):
            self.done = True
            return
        if key in ("\x1b", 27, "b", "h", K_LEFT, K_BACKSPACE, 127, "\x7f"):
            self.view = {"detail": "events", "events": "sessions"}.get(self.view, self.view)
            return
        size = {"sessions": len(self.sessions), "events": len(self.events), "detail": 1 << 30}[self.view]
        step = {K_DOWN: 1, "j": 1, K_UP: -1, "k": -1, K_PGDN: page, " ": page, K_PGUP: -page,
                K_HOME: -(1 << 30), "g": -(1 << 30), K_END: 1 << 30, "G": 1 << 30}.get(key)
        if step is not None:
            self.cursor[self.view] = max(0, min(size - 1, self.cursor[self.view] + step))
            return
        if key in ("\n", "\r", 10, 13, K_ENTER, "l", K_RIGHT):
            self._open()
        elif key == "f" and self.view == "sessions":
            self.findings_only = not self.findings_only
            self.cursor["sessions"] = 0
        elif key == "r" and self.view == "sessions":
            self.reload()
        elif key == "n" and self.view == "events":
            later = sorted(i for i in self._worst_at() if i > self.cursor["events"])
            if later:
                self.cursor["events"] = later[0]
            else:
                self.status = "no later finding"

    def _open(self) -> None:
        if self.view == "sessions" and self.sessions:
            sid = self.sessions[self.cursor["sessions"]]["sessionId"]
            self.session = self._load_session(sid)
            if not self.session:
                self.status = f"session {sid} not found"
                return
            try:
                self.cost = self._load_cost(sid) if self._load_cost else {}
            except Exception:
                self.cost = {}
            self.view, self.cursor["events"] = "events", 0
        elif self.view == "events" and self.events:
            self.view, self.cursor["detail"] = "detail", 0

    # ── render ────────────────────────────────────────────────────────
    def render(self, height: int, width: int) -> List[str]:
        """Exactly ``height`` lines: a title, the body, a status/help footer.
        The selected row is prefixed with ``>`` (curses draws it reversed)."""
        body_h = max(1, height - 2)
        if self.view == "sessions":
            title = f"Prismor traces — {len(self.sessions)} sessions" + ("  (with findings)" if self.findings_only else "")
            rows = [session_line(s, width - 2) for s in self.sessions] or ["no sessions recorded yet"]
            body = self._window(rows, self.cursor["sessions"], body_h, select=bool(self.sessions))
        elif self.view == "events":
            s = self.session or {}
            usage = self.cost or {}
            tokens = usage.get("tokens") or {}
            spend = ""
            if tokens:
                spend = f"  {tokens.get('input', 0) + tokens.get('cache_read', 0):,} in / {tokens.get('output', 0):,} out"
            if isinstance(usage.get("usd"), (int, float)):
                spend += f"  ${usage['usd']:.2f}"
            title = _one_line(f"{s.get('agent')}  {s.get('sessionId')}  {len(self.events)} events  "
                              f"{s.get('findingsCount') or 0} findings{spend}", width)
            worst = self._worst_at()
            rows = [event_line(i, e, worst.get(i), width - 2) for i, e in enumerate(self.events)] or ["no events"]
            body = self._window(rows, self.cursor["events"], body_h, select=bool(self.events))
        else:
            i = self.cursor["events"]
            lines = detail_lines(i, self.events[i], self.findings_at(i), width - 2)
            top = self.cursor["detail"] = min(self.cursor["detail"], max(0, len(lines) - body_h))
            title = f"event {i} of {len(self.events)}"
            body = [("  " + l) for l in lines[top:top + body_h]]
        body += [""] * (body_h - len(body))
        footer = self.status or _KEYS_HELP[self.view]
        return [_one_line(title, width)] + [l[:width] for l in body[:body_h]] + [_one_line(footer, width)]

    @staticmethod
    def _window(rows: List[str], cursor: int, height: int, select: bool) -> List[str]:
        top = max(0, min(cursor - height // 2, len(rows) - height))
        return [(("> " if select and top + n == cursor else "  ") + r) for n, r in enumerate(rows[top:top + height])]


def run(workspace: Path, *, all_workspaces: bool = False, limit: int = 200) -> int:
    import sys

    from prismor.runtime.store import get_session, list_sessions
    from prismor.runtime.token_usage import session_cost

    if _curses is None:
        sys.stderr.write("prismor traces needs curses (on Windows: pip install windows-curses)\n")
        return 2
    curses = _curses
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        sys.stderr.write("prismor traces needs a terminal; use `prismor sessions` / `prismor session <id>` in scripts\n")
        return 2

    browser = Browser(lambda: list_sessions(workspace, limit, all_workspaces=all_workspaces),
                      lambda sid: get_session(workspace, sid), lambda sid: session_cost(workspace, sid))

    def loop(scr: Any) -> None:
        curses.curs_set(0)
        scr.keypad(True)
        while not browser.done:
            h, w = scr.getmaxyx()
            scr.erase()
            for y, line in enumerate(browser.render(h, w - 1)):
                attr = curses.A_BOLD if y == 0 else curses.A_DIM if y == h - 1 else 0
                if line.startswith("> "):
                    attr = curses.A_REVERSE
                try:
                    scr.addstr(y, 0, line, attr)
                except curses.error:
                    pass  # writing the bottom-right cell raises; the text is drawn
            scr.refresh()
            ch = scr.get_wch()
            browser.handle(ch, page=max(1, h - 3))

    curses.wrapper(loop)
    return 0
