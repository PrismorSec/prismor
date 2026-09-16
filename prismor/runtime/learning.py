"""Tier 3 — Session-Based Learning for Prismor.

Mines historical session data to propose new detection rules, track false
positives, and detect evasion attempts where structurally similar commands
bypass existing rules.

Usage:
    prismor learn                 # propose new rules from session history
    prismor learn --apply ID      # accept a candidate rule into project policy
"""
from __future__ import annotations

import json
import os
import re
import shlex
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from prismor.runtime.store import get_db_path, initialize_database


# ── Schema migration ───────────────────────────────────────────────────────

_LEARNING_DDL = """
CREATE TABLE IF NOT EXISTS dismissals (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    evidence TEXT,
    dismissed_at TEXT NOT NULL,
    reason TEXT
);
CREATE INDEX IF NOT EXISTS idx_dismissals_rule ON dismissals(rule_id);

CREATE TABLE IF NOT EXISTS candidate_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    proposed_at TEXT NOT NULL,
    status TEXT DEFAULT 'pending',
    rule_json TEXT NOT NULL,
    source TEXT,
    confidence REAL DEFAULT 0.5,
    support_count INTEGER DEFAULT 1,
    sample_evidence TEXT
);

CREATE TABLE IF NOT EXISTS evasion_attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    blocked_rule_id TEXT NOT NULL,
    blocked_command TEXT,
    evading_command TEXT,
    similarity_score REAL,
    detected_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_evasion_session ON evasion_attempts(session_id);

CREATE TABLE IF NOT EXISTS staged_executions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    category TEXT NOT NULL,
    created_path TEXT,
    created_origin TEXT,
    created_evidence TEXT,
    executing_command TEXT,
    detected_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_staged_session ON staged_executions(session_id);
"""


def initialize_learning_tables(connection: sqlite3.Connection) -> None:
    """Add learning tables to an existing prismor.db connection."""
    connection.executescript(_LEARNING_DDL)


# ── Command normalization ──────────────────────────────────────────────────

# Patterns for shell substitution forms
_SUBST_BACKTICK = re.compile(r"`[^`]*`")
_SUBST_DOLLAR = re.compile(r"\$\([^)]*\)")
_SUBST_BRACE = re.compile(r"\$\{[^}]*\}")
_WHITESPACE = re.compile(r"\s+")
_SHELL_SPLIT = re.compile(r"\s*(?:;|&&|\|\||[|])\s*")


def normalize_command_structure(command: str) -> str:
    """Normalize a shell command for structural comparison.

    Strips quoting, replaces substitutions with a placeholder, collapses
    whitespace, and sorts arguments within each pipeline stage.
    """
    s = command.strip()

    # Replace all substitution forms with a placeholder
    s = _SUBST_BACKTICK.sub("__SUBST__", s)
    s = _SUBST_DOLLAR.sub("__SUBST__", s)
    s = _SUBST_BRACE.sub("__SUBST__", s)

    # Strip quotes
    s = s.replace('"', "").replace("'", "")

    # Collapse whitespace
    s = _WHITESPACE.sub(" ", s).strip()

    # Tokenize on shell metacharacters and normalize each segment
    segments = _SHELL_SPLIT.split(s)
    normalized_segments = []
    for seg in segments:
        seg = seg.strip()
        if not seg:
            continue
        parts = seg.split()
        if not parts:
            continue
        # Keep the base command first, sort remaining args
        base = parts[0]
        args = sorted(parts[1:])
        normalized_segments.append(" ".join([base] + args))

    return " | ".join(normalized_segments)


def _tokenize(normalized: str) -> set:
    """Split a normalized command into a set of tokens."""
    return set(normalized.split())


def command_structural_similarity(cmd_a: str, cmd_b: str) -> float:
    """Compute Jaccard similarity between two commands after normalization.

    Returns a float between 0.0 (completely different) and 1.0 (identical).
    """
    norm_a = normalize_command_structure(cmd_a)
    norm_b = normalize_command_structure(cmd_b)

    tokens_a = _tokenize(norm_a)
    tokens_b = _tokenize(norm_b)

    if not tokens_a and not tokens_b:
        return 1.0
    if not tokens_a or not tokens_b:
        return 0.0

    intersection = tokens_a & tokens_b
    union = tokens_a | tokens_b
    return len(intersection) / len(union)


def _base_command(command: str) -> str:
    """Extract the first command name from a shell string."""
    normalized = normalize_command_structure(command)
    first_segment = normalized.split(" | ")[0] if " | " in normalized else normalized
    parts = first_segment.split()
    return parts[0] if parts else ""


# ── Dismissal tracking ─────────────────────────────────────────────────────

def record_dismissal(
    workspace: Path,
    session_id: str,
    rule_id: str,
    evidence: str,
    reason: str,
) -> None:
    """Record that a finding was dismissed or allowlisted."""
    db_path = initialize_database(workspace)
    conn = sqlite3.connect(db_path)
    try:
        initialize_learning_tables(conn)
        conn.execute(
            "INSERT INTO dismissals (session_id, rule_id, evidence, dismissed_at, reason) VALUES (?, ?, ?, ?, ?)",
            (session_id, rule_id, evidence[:4000] if evidence else "",
             datetime.now(timezone.utc).isoformat(), reason),
        )
        conn.commit()
    finally:
        conn.close()


# ── Contextual step-up: ask the human instead of denying ──────────────────

#: A host counts as known once this device has used it in this many earlier
#: sessions. On the maintainer laptop the test box had 34; a host an injected
#: page names for the first time has 0.
_KNOWN_HOST_SESSIONS = 5


def _session_tainted(workspace: Path, session_id: str) -> bool:
    """Whether untrusted content has entered this session (trifecta ledger).

    Unknown reads as tainted: context may turn a deny into a question, never
    into an allow, and never when the session's provenance is in doubt.
    """
    try:
        from prismor.runtime.trifecta import TagLedger
        return "untrusted_content" in TagLedger(workspace, session_id).seen
    except Exception:
        return True


def contextual_step_up(
    blocking: Dict[str, Any],
    event: Dict[str, Any],
    workspace: Path,
    session_id: str,
) -> Optional[str]:
    """Why a blocking shell finding should ask a human instead of denying.

    Returns the reason, or ``None`` to keep the block. Only while the
    session has seen no untrusted content, and only when every destination
    in the command is one this device has used in at least
    ``_KNOWN_HOST_SESSIONS`` earlier sessions. A URL destination is keyed
    by host plus its first path segment, so ``github.com/attacker-mirror``
    is new even though ``github.com`` is not. Then one of two must hold:

      * the finding is about the destination itself (network isolation,
        egress), so a familiar destination is exactly what it was asking
        about; or
      * the matched text sits inside the payload of ssh/docker/kubectl to
        that destination, an action on a machine the device already works
        with.

    A local action that merely shares a command line with a known-host ssh
    keeps its block. Replaying the laptop store, the test box alone was
    1,006 of 1,292 raw-IP findings; the adversarial exfil commands all
    name a collector this device has never used.
    """
    if str(event.get("type") or "") != "shell":
        return None
    command = str(event.get("command") or "")
    if not command or _session_tainted(workspace, session_id):
        return None
    try:
        from prismor.runtime.egress import extract_destinations
        dests = extract_destinations(event)
    except Exception:
        return None
    keys: Dict[str, str] = {}
    for d in dests:
        if not d.host:
            continue
        key = d.host
        if d.origin == "url":
            m = re.search(r"://[^/\s'\"]*/([^/\s'\"?#]+)", d.evidence or "")
            if m:
                key = f"{d.host}/{m.group(1)}"
        keys[key] = d.host
    if not keys:
        return None
    db_path = get_db_path(workspace)
    if not db_path.exists():
        return None
    conn = sqlite3.connect(db_path)
    try:
        counts = {
            k: conn.execute(
                "SELECT COUNT(DISTINCT session_id) FROM events "
                "WHERE session_id != ? AND command_text LIKE ?",
                (session_id, f"%{k}%"),
            ).fetchone()[0]
            for k in keys
        }
    finally:
        conn.close()
    if not all(c >= _KNOWN_HOST_SESSIONS for c in counts.values()):
        return None
    detail = ", ".join(f"{k} in {counts[k]} earlier sessions" for k in sorted(counts))

    about_destination = (
        str(blocking.get("category") or "") == "network_isolation"
        or str(blocking.get("ruleId") or "") in ("raw-ip-outbound", "egress-allowlist", "egress-deny")
    )
    if about_destination:
        return f"every destination is one this device has used before ({detail})"

    pattern = blocking.get("pattern")
    if pattern:
        try:
            from prismor.runtime.shell_context import is_remote_payload
            m = re.search(str(pattern), command, re.IGNORECASE)
            if m and is_remote_payload(command, m.start(), m.end()):
                return f"the action runs on a machine this device already works with ({detail})"
        except re.error:
            pass
    return None


def mark_ask_outcome(workspace: Path, session_id: str, command: str) -> None:
    """The human allowed an asked call and it ran: label the ``asked`` row.

    A call the human refused never reaches the post-tool hook, so its row
    stays ``asked``; the two together are the first human labels the store
    has.
    """
    db_path = get_db_path(workspace)
    if not db_path.exists() or not command:
        return
    conn = sqlite3.connect(db_path)
    try:
        initialize_learning_tables(conn)
        row = conn.execute(
            "SELECT id FROM dismissals WHERE session_id = ? AND reason = 'asked' "
            "AND substr(evidence, 1, 60) = substr(?, 1, 60) ORDER BY id DESC LIMIT 1",
            (session_id, command),
        ).fetchone()
        if row:
            conn.execute("UPDATE dismissals SET reason = 'asked_allow' WHERE id = ?", (row[0],))
            conn.commit()
    finally:
        conn.close()


# ── Evasion detection ──────────────────────────────────────────────────────

_EVASION_THRESHOLD = 0.6


def detect_evasion(
    workspace: Path,
    session_id: str,
    event: Dict[str, Any],
    current_findings: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Check if a passing shell command is structurally similar to a recently blocked one.

    Only runs when the event has no findings (it passed policy checks).
    Returns a list of HIGH-severity findings if evasion is detected.
    """
    if current_findings:
        return []

    command = event.get("command", "")
    if not command:
        return []

    base = _base_command(command)
    if not base:
        return []

    db_path = get_db_path(workspace)
    if not db_path.exists():
        return []

    conn = sqlite3.connect(db_path)
    try:
        initialize_learning_tables(conn)

        # Findings record the ordinal index of the event that triggered them
        # (event_index = position in the session's event list). Map each
        # finding back to its specific command rather than cross-joining the
        # whole session — otherwise every command in a session that has *any*
        # finding (including the current, passing one, which is snapshotted
        # into `events` before this runs) self-matches at 100%.
        finding_rows = conn.execute(
            """
            SELECT event_index, finding_id, title, category
            FROM findings
            WHERE session_id = ? AND event_index IS NOT NULL
            """,
            (session_id,),
        ).fetchall()
        if not finding_rows:
            return []

        # Ordered command texts for this session; list index == event_index.
        ordered_cmds = [
            row[0]
            for row in conn.execute(
                "SELECT command_text FROM events WHERE session_id = ? ORDER BY id ASC",
                (session_id,),
            ).fetchall()
        ]

        evasion_findings = []
        seen_blocked: set = set()
        for event_index, finding_id, title, category in finding_rows:
            if event_index is None or event_index < 0 or event_index >= len(ordered_cmds):
                continue
            blocked_cmd = ordered_cmds[event_index]
            if not blocked_cmd:
                continue
            # The current command passed policy (no findings); never compare it
            # against itself.
            if blocked_cmd == command:
                continue
            if blocked_cmd in seen_blocked:
                continue
            seen_blocked.add(blocked_cmd)

            # Must share the same base command
            if _base_command(blocked_cmd) != base:
                continue

            similarity = command_structural_similarity(command, blocked_cmd)
            if similarity >= _EVASION_THRESHOLD:
                # Record the evasion attempt
                conn.execute(
                    """
                    INSERT INTO evasion_attempts
                        (session_id, blocked_rule_id, blocked_command, evading_command, similarity_score, detected_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (session_id, finding_id, blocked_cmd[:4000], command[:4000],
                     similarity, datetime.now(timezone.utc).isoformat()),
                )
                conn.commit()

                evasion_findings.append({
                    "id": f"{session_id}:evasion-{len(evasion_findings)}",
                    "severity": "HIGH",
                    "category": category or "evasion",
                    "title": f"Possible evasion of: {title}",
                    "evidence": f"Command '{command[:200]}' is {similarity:.0%} similar to blocked '{blocked_cmd[:200]}'",
                    "ruleId": "evasion-detection",
                    "action": "block",
                })
                break  # One match is enough

        return evasion_findings
    finally:
        conn.close()


# ── Staged-execution detection (write/fetch-then-execute correlation) ────────
#
# Closes the cross-call bypass where the dangerous action is split across two
# tool calls so neither matches a single-command rule:
#   call 1:  curl -o /tmp/x.sh URL   (or  echo … > /tmp/x.sh,  or a Write tool)
#   call 2:  bash /tmp/x.sh
# We track files *created* earlier in the same session (downloads, redirects,
# tee, file_write events) and flag a later command that executes — or exfils via
# scp/rsync — one of those paths. The single-command chained form
# (`curl -o x && bash x`) is caught by also scanning the segments of one command.
#
# Safety property: created paths come ONLY from in-session events, so a
# repo-tracked script (`bash ./scripts/build.sh`) that was never written this
# session is absent from the set and never fires. We never blanket-flag "running
# a script" — only "running a script this session created".

# A path token: double-quoted, single-quoted, or a bare run of non-delimiter chars.
_PATH_TOK = r"""(?:"[^"]+"|'[^']+'|[^\s;&|<>]+)"""

# CREATED-path extractors (scanned against prior events + earlier segments).
_RE_CURL_OUT = re.compile(r"\bcurl\b[^\n]*?(?:-o|--output)\s+(" + _PATH_TOK + r")")
_RE_WGET_OUT = re.compile(r"\bwget\b[^\n]*?(?:-O|--output-document=?)\s*(" + _PATH_TOK + r")")
_RE_REDIRECT = re.compile(r"(?<![0-9&])>>?\s*(" + _PATH_TOK + r")")
_RE_TEE = re.compile(r"\btee\b\s+(?:-a\s+)?(" + _PATH_TOK + r")")

# EXECUTED-path extractors (scanned against the current command).
_INTERP = r"(?:bash|sh|zsh|ksh|dash|python3?|node|nodejs|ruby|perl|php|deno|bun)"
_RE_INTERP_EXEC = re.compile(r"\b" + _INTERP + r"\b((?:\s+-{1,2}[^\s]+)*)\s+(" + _PATH_TOK + r")")
_RE_SOURCE_EXEC = re.compile(r"(?:\bsource\b|(?:^|[;&|]\s*)\.)\s+(" + _PATH_TOK + r")")
_RE_DIRECT_EXEC = re.compile(r"(?:^|[;&|]\s*)(\./" + _PATH_TOK + r"|/" + _PATH_TOK + r")")

# EXFIL extractors (scp / rsync local-source args).
_RE_SCP = re.compile(r"\bscp\b\s+(.*)")
_RE_RSYNC = re.compile(r"\brsync\b\s+(.*)")
_RE_REMOTE_TGT = re.compile(r"^[^/\s]*@?[^/\s]*:")  # host:path / user@host:path

_NON_FILE_SINKS = {"-", "/dev/null", "/dev/stdout", "/dev/stderr", "/dev/zero", "/dev/tty"}
# Generic basenames that must NOT match across different paths on basename alone.
_GENERIC_BASENAMES = {"", "a.out", "main", "index.js", "setup.py", "__init__.py",
                      "manage.py", "app.py", "run.py", "main.py"}


def _clean_token(tok: str) -> str:
    tok = tok.strip()
    if len(tok) >= 2 and tok[0] in "\"'" and tok[-1] == tok[0]:
        tok = tok[1:-1]
    return tok


def _norm_path(tok: str) -> str:
    tok = _clean_token(tok)
    if not tok:
        return ""
    return os.path.normpath(os.path.expanduser(tok))


def _extract_created_paths(command: str) -> List[Tuple[str, str]]:
    """Return [(normalized_path, origin)] for files this command creates."""
    out: List[Tuple[str, str]] = []
    for rx, origin in (
        (_RE_CURL_OUT, "download"),
        (_RE_WGET_OUT, "download"),
        (_RE_TEE, "tee"),
        (_RE_REDIRECT, "redirect"),
    ):
        for m in rx.finditer(command):
            np = _norm_path(m.group(1))
            if np and np not in _NON_FILE_SINKS:
                out.append((np, origin))
    return out


def _extract_executed_paths(command: str) -> List[str]:
    """Return normalized file paths the command executes as code."""
    out: List[str] = []
    for m in _RE_INTERP_EXEC.finditer(command):
        flags = (m.group(1) or "").split()
        if "-m" in flags or "-c" in flags or "-e" in flags:
            continue  # module / inline-code invocation: no concrete file target
        tok = _clean_token(m.group(2))
        if not tok or tok.startswith("-") or tok in _NON_FILE_SINKS:
            continue
        np = _norm_path(tok)
        if np:
            out.append(np)
    for rx in (_RE_SOURCE_EXEC, _RE_DIRECT_EXEC):
        for m in rx.finditer(command):
            np = _norm_path(m.group(1))
            if np and np not in _NON_FILE_SINKS:
                out.append(np)
    return out


def _extract_exfil_paths(command: str) -> List[str]:
    """Return normalized local source paths handed to scp/rsync."""
    out: List[str] = []
    for rx in (_RE_SCP, _RE_RSYNC):
        m = rx.search(command)
        if not m:
            continue
        for raw in m.group(1).split():
            tok = _clean_token(raw)
            if not tok or tok.startswith("-") or _RE_REMOTE_TGT.match(tok):
                continue
            np = _norm_path(tok)
            if np and np not in _NON_FILE_SINKS:
                out.append(np)
    return out


def _paths_match(created: str, target: str) -> bool:
    if not created or not target:
        return False
    if created == target:
        return True
    bc, bt = os.path.basename(created), os.path.basename(target)
    # Basename match handles relative-vs-absolute, but only for non-generic names
    # so `python setup.py` never matches an unrelated written setup.py.
    return bool(bc) and bc == bt and bc not in _GENERIC_BASENAMES


def _match_against(target: str, created: Dict[str, str]) -> Optional[Tuple[str, str]]:
    for cp, origin in created.items():
        if _paths_match(cp, target):
            return (cp, origin)
    return None


def _build_staged(
    session_id: str, command: str, created_path: str, origin: str, exec_path: str, exfil: bool
) -> Tuple[Dict[str, Any], Tuple[str, str, str, str, str]]:
    if not exfil and origin == "download":
        # Fetch-then-execute — the genuine two-step curl|bash bypass. Legit
        # installs pipe (`curl | bash`, already blocked) or use package
        # managers; staging a download to disk then running it is the evasion
        # signature, so this blocks. Low false-positive risk.
        category, severity, action = "remote_execution", "HIGH", "block"
        title = "Fetch-then-execute: running a file downloaded earlier this session"
        verb = "executes"
    elif exfil:
        # scp/rsync of an in-session file. Common in legit deploys, so warn
        # (telemetry/learning) rather than break the workflow.
        category, severity, action = "staged_execution", "MEDIUM", "warn"
        title = "Exfiltration of in-session-generated file (scp/rsync)"
        verb = "exfiltrates"
    else:
        # Local write-then-execute. Agents write+run helper scripts constantly,
        # so warn rather than block; operators can promote `staged_execution`
        # to a block category in policy for stricter enforcement.
        category, severity, action = "staged_execution", "MEDIUM", "warn"
        title = "Staged execution: running a file created earlier this session"
        verb = "executes"
    finding = {
        "id": f"{session_id}:staged-exec-0" if session_id else "staged-exec-0",
        "severity": severity,
        "category": category,
        "title": title,
        "evidence": (
            f"Command '{command[:160]}' {verb} '{exec_path}' "
            f"(created via {origin} earlier this session)"
        ),
        "ruleId": "staged-execution",
        "action": action,
    }
    record = (category, created_path, origin, exec_path, command)
    return finding, record


def _match_command(
    command: str, created: Dict[str, str], session_id: str
) -> Optional[Tuple[Dict[str, Any], Tuple[str, str, str, str, str]]]:
    for ex in _extract_executed_paths(command):
        hit = _match_against(ex, created)
        if hit:
            return _build_staged(session_id, command, hit[0], hit[1], ex, exfil=False)
    for ex in _extract_exfil_paths(command):
        hit = _match_against(ex, created)
        if hit:
            return _build_staged(session_id, command, hit[0], hit[1], ex, exfil=True)
    return None


def _scan_intra_command(
    command: str, session_id: str
) -> Optional[Tuple[Dict[str, Any], Tuple[str, str, str, str, str]]]:
    """Catch the single-command chained form: `curl -o x && bash x`."""
    seen: Dict[str, str] = {}
    for seg in _SHELL_SPLIT.split(command):
        for ex in _extract_executed_paths(seg):
            hit = _match_against(ex, seen)
            if hit:
                return _build_staged(session_id, command, hit[0], hit[1], ex, exfil=False)
        for ex in _extract_exfil_paths(seg):
            hit = _match_against(ex, seen)
            if hit:
                return _build_staged(session_id, command, hit[0], hit[1], ex, exfil=True)
        for cp, origin in _extract_created_paths(seg):
            seen.setdefault(cp, origin)
    return None


def _persist_staged_conn(
    conn: sqlite3.Connection, session_id: str, records: List[Tuple[str, str, str, str, str]]
) -> None:
    now = datetime.now(timezone.utc).isoformat()
    for category, created_path, origin, exec_path, command in records:
        conn.execute(
            """
            INSERT INTO staged_executions
                (session_id, category, created_path, created_origin,
                 created_evidence, executing_command, detected_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (session_id, category, created_path[:1000], origin,
             exec_path[:1000], command[:4000], now),
        )
    conn.commit()


def _persist_staged(workspace: Path, session_id: str, records: List[Tuple[str, str, str, str, str]]) -> None:
    try:
        db_path = initialize_database(workspace)
        conn = sqlite3.connect(db_path)
        try:
            initialize_learning_tables(conn)
            _persist_staged_conn(conn, session_id, records)
        finally:
            conn.close()
    except Exception:
        pass  # best-effort; never break the hook


def detect_staged_execution(
    workspace: Path,
    session_id: str,
    event: Dict[str, Any],
    current_findings: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Flag a passing shell command that executes/exfils a file created earlier
    in the same session (write-then-exec, fetch-then-exec, scp of a staged file).

    Only runs when the event has no findings (it passed policy checks). Returns
    at most one HIGH-severity, action=block finding.
    """
    if current_findings:
        return []

    command = event.get("command", "")
    if not command:
        return []

    # ── Intra-command pass (no DB needed) ──
    intra = _scan_intra_command(command, session_id)
    if intra is not None:
        finding, record = intra
        _persist_staged(workspace, session_id, [record])
        return [finding]

    # ── Cross-event pass ──
    db_path = get_db_path(workspace)
    if not db_path.exists():
        return []

    conn = sqlite3.connect(db_path)
    try:
        initialize_learning_tables(conn)
        rows = conn.execute(
            "SELECT id, type, command_text, path_text FROM events "
            "WHERE session_id = ? ORDER BY id ASC",
            (session_id,),
        ).fetchall()
        # Drop the current event (highest id) — save_session_snapshot already
        # persisted it, and it would otherwise self-match.
        if rows:
            rows = rows[:-1]

        created: Dict[str, str] = {}
        for _id, etype, cmd_text, path_text in rows:
            if etype == "file_write" and path_text:
                np = _norm_path(path_text)
                if np:
                    created.setdefault(np, "write")
            elif etype == "shell" and cmd_text:
                for cp, origin in _extract_created_paths(cmd_text):
                    created.setdefault(cp, origin)

        if not created:
            return []

        result = _match_command(command, created, session_id)
        if result is None:
            return []

        finding, record = result
        _persist_staged_conn(conn, session_id, [record])
        return [finding]
    finally:
        conn.close()


# ── Pattern mining ─────────────────────────────────────────────────────────

# Sensitive command prefixes that warrant attention even without a rule match
_SENSITIVE_COMMANDS = {
    "curl", "wget", "nc", "ncat", "socat", "ssh", "scp", "rsync",
    "chmod", "chown", "chgrp", "sudo", "su", "doas",
    "docker", "podman", "kubectl",
    "pip", "pip3", "npm", "yarn", "gem", "cargo",
    "eval", "exec", "source",
    # Database clients — direct prod-DB access is exactly the kind of
    # recurring, un-ruled pattern the learning engine is meant to surface
    # (this is docs/learning.md's own worked example, which previously
    # could never actually fire). See PrismorSec/prismor#146.
    "psql", "mysql", "mysqlsh", "redis-cli", "mongosh", "sqlite3",
}


def mine_patterns(workspace: Path, min_support: int = 3) -> List[Dict[str, Any]]:
    """Find recurring command patterns across sessions that have no rule coverage.

    Returns candidate rule dicts for commands that appear >= min_support times
    and involve sensitive operations.
    """
    db_path = get_db_path(workspace)
    if not db_path.exists():
        return []

    conn = sqlite3.connect(db_path)
    try:
        # Get all shell events that have no associated finding.
        # A finding's event_index corresponds to the event's position
        # within its session (0-based row number by id order).
        rows = conn.execute(
            f"""
            SELECT e.command_text, e.session_id
            FROM events e
            WHERE e.type = 'shell'
              AND e.command_text IS NOT NULL
              AND e.command_text != ''
              AND e.session_id NOT IN ({_FIXTURE_SESSIONS_SQL})
              AND NOT EXISTS (
                  SELECT 1 FROM findings f
                  WHERE f.session_id = e.session_id
                    AND f.evidence LIKE '%' || SUBSTR(e.command_text, 1, 40) || '%'
              )
            """,
        ).fetchall()
    finally:
        conn.close()

    if not rows:
        return []

    # Group by normalized structure
    structure_groups: Dict[str, List[Tuple[str, str]]] = {}
    for cmd, sid in rows:
        norm = normalize_command_structure(cmd)
        structure_groups.setdefault(norm, []).append((cmd, sid))

    candidates = []
    for norm, entries in structure_groups.items():
        if len(entries) < min_support:
            continue

        base = _base_command(entries[0][0])
        if base not in _SENSITIVE_COMMANDS:
            continue

        # Build a candidate rule
        sample = entries[0][0]
        escaped = re.escape(base)
        candidate = {
            "id": f"learned-{base}-{len(candidates)}",
            "severity": "MEDIUM",
            "category": "learned_pattern",
            "title": f"Recurring uncovered pattern: {base} (seen {len(entries)} times)",
            "event_types": ["shell"],
            "fields": ["command"],
            "patterns": [f"(?:^|\\s|;|&|\\|){escaped}\\b"],
            "action": "warn",
            "enabled": True,
        }
        candidates.append({
            "rule": candidate,
            "source": "pattern_mining",
            "confidence": min(0.9, 0.3 + (len(entries) * 0.1)),
            "support_count": len(entries),
            "sample_evidence": sample[:500],
            "sessions": list({sid for _, sid in entries}),
        })

    return candidates


# ── False positive tracking ────────────────────────────────────────────────

# Sessions that drive Prismor itself -- its hook, its engine, its benchmarks --
# feed it attacks on purpose. Their findings are correct and must never teach
# the learner that an attack is routine. On the maintainer's own laptop these
# were 9% of sessions and half of all findings.
_FIXTURE_SESSIONS_SQL = """
    SELECT DISTINCT session_id FROM events
    WHERE type = 'shell' AND (
        command_text LIKE '%hook-dispatch%'
        OR command_text LIKE '%immunity_cli%'
        OR command_text LIKE '%PolicyEngine%'
        OR command_text LIKE '%PreToolUse%'
        OR command_text LIKE '%prismor check %'
    )
"""


def track_false_positives(workspace: Path, threshold: int = 5) -> List[Dict[str, Any]]:
    """Find rules that have been dismissed more than threshold times.

    Returns a list of dicts with rule_id, dismissal_count, and recommendation.
    Self-test sessions (see ``_FIXTURE_SESSIONS_SQL``) are excluded.
    """
    db_path = get_db_path(workspace)
    if not db_path.exists():
        return []

    conn = sqlite3.connect(db_path)
    try:
        initialize_learning_tables(conn)
        rows = conn.execute(
            f"""
            SELECT rule_id, COUNT(*) as cnt,
                   GROUP_CONCAT(DISTINCT reason) as reasons,
                   GROUP_CONCAT(evidence, '|||') as evidences
            FROM dismissals
            WHERE session_id NOT IN ({_FIXTURE_SESSIONS_SQL})
            GROUP BY rule_id
            HAVING cnt >= ?
            ORDER BY cnt DESC
            """,
            (threshold,),
        ).fetchall()
    finally:
        conn.close()

    results = []
    for rule_id, count, reasons, evidences in rows:
        sample_evidence = (evidences or "").split("|||")[:3]
        results.append({
            "rule_id": rule_id,
            "dismissal_count": count,
            "reasons": reasons,
            "sample_evidence": sample_evidence,
            "recommendation": (
                f"Rule '{rule_id}' has been dismissed {count} times. "
                "Consider lowering severity or adding an allowlist entry."
            ),
        })

    return results


# ── Rule refinement proposals ──────────────────────────────────────────────

def propose_rule_refinements(workspace: Path) -> List[Dict[str, Any]]:
    """Analyze evasion attempts and propose broader regex patterns.

    For each evasion where similarity > threshold, suggest a pattern that
    catches both the original blocked command and the evading variant.
    """
    db_path = get_db_path(workspace)
    if not db_path.exists():
        return []

    conn = sqlite3.connect(db_path)
    try:
        initialize_learning_tables(conn)
        rows = conn.execute(
            """
            SELECT blocked_rule_id, blocked_command, evading_command, similarity_score
            FROM evasion_attempts
            WHERE similarity_score >= ?
            ORDER BY detected_at DESC
            LIMIT 100
            """,
            (_EVASION_THRESHOLD,),
        ).fetchall()
    finally:
        conn.close()

    if not rows:
        return []

    # Group by blocked_rule_id
    by_rule: Dict[str, List[Tuple[str, str, float]]] = {}
    for rule_id, blocked, evading, score in rows:
        by_rule.setdefault(rule_id, []).append((blocked, evading, score))

    refinements = []
    for rule_id, attempts in by_rule.items():
        # Find common structural elements between blocked and evading commands
        blocked_norms = {normalize_command_structure(b) for b, _, _ in attempts}
        evading_norms = {normalize_command_structure(e) for _, e, _ in attempts}

        all_tokens = set()
        for n in blocked_norms | evading_norms:
            all_tokens.update(_tokenize(n))

        # The base command is the anchor for the refined pattern
        base = _base_command(attempts[0][0])
        if not base:
            continue

        refinements.append({
            "rule_id": rule_id,
            "evasion_count": len(attempts),
            "avg_similarity": sum(s for _, _, s in attempts) / len(attempts),
            "suggestion": (
                f"Broaden patterns for rule '{rule_id}' to catch shell substitution "
                f"variants (backticks, $(), ${{}}) around '{base}'. "
                f"Seen {len(attempts)} evasion attempt(s)."
            ),
            "sample_blocked": attempts[0][0][:200],
            "sample_evading": attempts[0][1][:200],
        })

    return refinements


# ── Candidate rule persistence ─────────────────────────────────────────────

def save_candidate_rules(workspace: Path, candidates: List[Dict[str, Any]]) -> int:
    """Persist mined candidate rules to the database. Returns count saved."""
    if not candidates:
        return 0

    db_path = initialize_database(workspace)
    conn = sqlite3.connect(db_path)
    try:
        initialize_learning_tables(conn)
        now = datetime.now(timezone.utc).isoformat()
        count = 0
        for c in candidates:
            conn.execute(
                """
                INSERT INTO candidate_rules
                    (proposed_at, status, rule_json, source, confidence, support_count, sample_evidence)
                VALUES (?, 'pending', ?, ?, ?, ?, ?)
                """,
                (now, json.dumps(c["rule"]), c["source"],
                 c["confidence"], c["support_count"], c.get("sample_evidence", "")),
            )
            count += 1
        conn.commit()
        return count
    finally:
        conn.close()


def list_candidate_rules(workspace: Path, status: str = "pending") -> List[Dict[str, Any]]:
    """List candidate rules by status."""
    db_path = get_db_path(workspace)
    if not db_path.exists():
        return []

    conn = sqlite3.connect(db_path)
    try:
        initialize_learning_tables(conn)
        rows = conn.execute(
            """
            SELECT id, proposed_at, status, rule_json, source, confidence, support_count, sample_evidence
            FROM candidate_rules
            WHERE status = ?
            ORDER BY confidence DESC, support_count DESC
            """,
            (status,),
        ).fetchall()
    finally:
        conn.close()

    return [
        {
            "id": row[0],
            "proposed_at": row[1],
            "status": row[2],
            "rule": json.loads(row[3]),
            "source": row[4],
            "confidence": row[5],
            "support_count": row[6],
            "sample_evidence": row[7],
        }
        for row in rows
    ]


def accept_candidate_rule(workspace: Path, candidate_id: int) -> Optional[Dict[str, Any]]:
    """Mark a candidate rule as accepted and return it for policy insertion."""
    db_path = get_db_path(workspace)
    if not db_path.exists():
        return None

    conn = sqlite3.connect(db_path)
    try:
        initialize_learning_tables(conn)
        row = conn.execute(
            "SELECT rule_json FROM candidate_rules WHERE id = ? AND status = 'pending'",
            (candidate_id,),
        ).fetchone()
        if row is None:
            return None
        conn.execute(
            "UPDATE candidate_rules SET status = 'accepted' WHERE id = ?",
            (candidate_id,),
        )
        conn.commit()
        return json.loads(row[0])
    finally:
        conn.close()


def reject_candidate_rule(workspace: Path, candidate_id: int) -> bool:
    """Mark a candidate rule as rejected."""
    db_path = get_db_path(workspace)
    if not db_path.exists():
        return False

    conn = sqlite3.connect(db_path)
    try:
        initialize_learning_tables(conn)
        cursor = conn.execute(
            "UPDATE candidate_rules SET status = 'rejected' WHERE id = ? AND status = 'pending'",
            (candidate_id,),
        )
        conn.commit()
        return cursor.rowcount > 0
    finally:
        conn.close()


# ── Report formatting ──────────────────────────────────────────────────────

_BOLD = "\033[1m"
_NC = "\033[0m"
_CYAN = "\033[0;36m"
_YELLOW = "\033[1;33m"
_GREEN = "\033[0;32m"
_DIM = "\033[37m"


def format_learning_report(
    candidates: List[Dict[str, Any]],
    false_positives: List[Dict[str, Any]],
    refinements: List[Dict[str, Any]],
) -> str:
    """Format learning results for terminal display."""
    lines: List[str] = []

    lines.append(f"\n{_BOLD}Prismor Learning Report{_NC}")
    lines.append("=" * 60)

    # Pattern mining results
    lines.append(f"\n{_CYAN}Pattern Mining — Candidate Rules{_NC}")
    if candidates:
        for c in candidates:
            rule = c["rule"]
            lines.append(
                f"  [{c.get('id', c['rule'].get('id', '?'))}] {rule['title']}"
            )
            lines.append(
                f"       Confidence: {c['confidence']:.0%}  |  "
                f"Support: {c['support_count']}  |  Source: {c['source']}"
            )
            if c.get("sample_evidence"):
                lines.append(f"       Sample: {c['sample_evidence'][:100]}")
            lines.append("")
    else:
        lines.append(f"  {_DIM}No new patterns found.{_NC}")
        lines.append("")

    # False positive tracking
    lines.append(f"{_YELLOW}False Positive Tracking{_NC}")
    if false_positives:
        for fp in false_positives:
            lines.append(f"  Rule: {fp['rule_id']}  |  Dismissed: {fp['dismissal_count']}x")
            lines.append(f"       {fp['recommendation']}")
            lines.append("")
    else:
        lines.append(f"  {_DIM}No false positive patterns detected.{_NC}")
        lines.append("")

    # Evasion refinements
    lines.append(f"{_CYAN}Evasion-Based Refinements{_NC}")
    if refinements:
        for r in refinements:
            lines.append(
                f"  Rule: {r['rule_id']}  |  "
                f"Evasions: {r['evasion_count']}  |  "
                f"Avg similarity: {r['avg_similarity']:.0%}"
            )
            lines.append(f"       {r['suggestion']}")
            lines.append("")
    else:
        lines.append(f"  {_DIM}No evasion patterns detected.{_NC}")
        lines.append("")

    # Summary
    total = len(candidates) + len(false_positives) + len(refinements)
    if total > 0:
        lines.append(f"{_GREEN}Total insights: {total}{_NC}")
        lines.append(f"Use {_BOLD}prismor learn --apply ID{_NC} to accept a candidate rule.")
    else:
        lines.append(f"{_DIM}No actionable insights. Collect more session data.{_NC}")

    lines.append("")
    return "\n".join(lines)


# ── Memory self-reinforcement ─────────────────────────────────────────────────
#
# The laundering step in a memory-poisoning chain. An agent reads untrusted
# content (a fetched page, a tool result, another agent's output), then writes
# it verbatim into an instruction file. On the next session that text is no
# longer "something the agent read" — it is the agent's own durable, implicitly
# trusted memory, and every content rule that would have scrutinized it as tool
# output has already been passed.
#
# Only a *verbatim* echo of a substantial line is flagged. A genuine summary is
# reworded; copying a long line unchanged from untrusted output into memory is
# the higher-signal case. This still fires on the legitimate "read these docs
# and record the conventions in CLAUDE.md" workflow, which is why it warns
# rather than blocks — the point is that the user gets told durable memory just
# absorbed text the agent did not author.

_SELF_REINFORCE_MIN_LEN = 40

# Event types whose content the agent did not author. `prompt` is deliberately
# absent: text the human typed is trusted, so recording it in memory is normal.
_UNTRUSTED_SOURCE_TYPES = frozenset({"tool_result", "memory", "file_read", "network"})

_INSTRUCTION_FILE_RE = re.compile(
    r"(^|/)(CLAUDE|AGENTS|GEMINI)\.md$"
    r"|(^|/)CLAUDE\.local\.md$"
    r"|(^|/)\.(cursorrules|windsurfrules)$"
    r"|(^|/)\.github/copilot-instructions\.md$"
    r"|(^|/)\.mcp\.json$",
    re.IGNORECASE,
)


def detect_memory_self_reinforcement(
    workspace: Path,
    session_id: str,
    event: Dict[str, Any],
    current_findings: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Flag a write to an agent-instruction file that echoes untrusted content
    seen earlier in the same session.

    Returns at most one MEDIUM-severity, action=warn finding.
    """
    if event.get("type") != "file_write":
        return []
    if not _INSTRUCTION_FILE_RE.search(str(event.get("path") or "")):
        return []

    candidates = [
        norm for norm in (
            _WHITESPACE.sub(" ", line).strip()
            for line in str(event.get("content") or "").splitlines()
        )
        if len(norm) >= _SELF_REINFORCE_MIN_LEN
    ]
    if not candidates:
        return []

    from prismor.runtime.store import read_session_events
    try:
        prior = read_session_events(workspace, session_id)
    except (OSError, ValueError):
        return []

    parts: List[str] = []
    for prior_event in prior:
        if prior_event.get("type") not in _UNTRUSTED_SOURCE_TYPES:
            continue
        for key in ("content", "response", "stdout"):
            value = prior_event.get(key)
            if value:
                parts.append(str(value))
    if not parts:
        return []

    haystack = _WHITESPACE.sub(" ", "\n".join(parts))
    echoed = next((line for line in candidates if line in haystack), None)
    if echoed is None:
        return []

    return [{
        "id": "memory-self-reinforcement",
        "severity": "MEDIUM",
        "category": "memory_poisoning",
        "title": "Untrusted content from this session is being written into an agent-instruction file",
        "evidence": f"path={str(event.get('path') or '')!r} echoed={echoed[:160]!r}",
        "eventIndex": 0,
        "ruleId": "memory-self-reinforcement",
        "action": "warn",
        "source": "project_memory",
    }]
