"""Developer views over the session store: what went wrong, who wrote this,
where agents keep tripping, what a session changed.

The store already holds every tool call. What it lacks for Claude is the
outcome: a failed call fires ``PostToolUseFailure``, not ``PostToolUse``, so a
failed command is a PreToolUse row with no result. The session transcript
(``transcript_path`` on every hook payload) records each result with
``is_error`` and tags hook denials with ``toolDenialKind``, so for Claude the
transcript is the source and the events table is the fallback for every other
agent (calls known, outcome not).

Everything returned here passes through the same redaction ``prismor query``
applies: these views print commands, errors and prompts.
"""

from __future__ import annotations

import difflib
import json
import re
import sqlite3
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from prismor.runtime.store import _connect_ro, locked_json_update, prismor_home

LOOP_MIN = 3        # same failing call this many times is a loop
CHURN_MIN = 5       # one file written this many times in a session
DIFF_MAX = 400      # diff lines kept per file
_WRITE_TOOLS = {"Edit", "MultiEdit", "Write", "NotebookEdit", "apply_patch"}
# A policy said no (a hook, the harness, the user), as opposed to the call failing.
# A failure the exit code hid: agents pipe through `| tail`, so the shell reports
# tail's 0 while the tests inside failed. Only unambiguous runner summaries count.
_OUTPUT_FAIL = re.compile(
    r"^(?:=+ .*\b\d+ (?:failed|errors?)\b.*=+$|ERROR collecting .*|E?\s*ImportError while importing .*"
    r"|FAILED \S+.*|Tests?:\s+\d+ failed.*|npm (?:ERR!|error) .*|.*error TS\d+:.*|error(?:\[E\d+\])?: .*"
    r"|--- FAIL: .*|FAIL\s+\S+.*|.*: command not found|Traceback \(most recent call last\):)$", re.M)
# pytest puts the cause of a failure or collection error on an `E   ...Error:` line.
_PYTEST_CAUSE = re.compile(r"^E\s+(\w+(?:Error|Exception)\b.*)$", re.M)
_DENIAL = re.compile(r"(Error: )?(Blocked|\S+ hook error|Permission to use|The user doesn't want|"
                     r"Prismor|Hook PreToolUse)", re.I)


def _db() -> Optional[sqlite3.Connection]:
    return _connect_ro(prismor_home() / "prismor.db")


def _redact(obj: Any) -> Any:
    from prismor.runtime.query import _redact_rows
    rows = [{"v": json.dumps(obj, default=str)}]
    _redact_rows(rows, None)
    return json.loads(rows[0]["v"])


def _detail(tool: str, inp: Dict[str, Any]) -> str:
    text = (inp.get("command") or inp.get("file_path") or inp.get("notebook_path") or inp.get("path")
            or inp.get("url") or inp.get("query") or inp.get("pattern") or inp.get("description")
            or (json.dumps(inp)[:200] if inp else ""))
    return " ".join(str(text).split())[:400]


def _error_line(text: str) -> str:
    """The line that names the cause: "Exit code 1" or a runner's banner alone says nothing."""
    text = re.sub(r"</?tool_use_error>", "", text or "")
    if "Traceback (most recent call last)" in text:  # the cause is the last line
        tail = [l.strip() for l in text.splitlines() if l.strip()]
        return tail[-1][:300] if tail else ""
    cause = _PYTEST_CAUSE.search(text) or _OUTPUT_FAIL.search(text)
    if cause:
        return (cause.group(1) if cause.re is _PYTEST_CAUSE else cause.group(0)).strip()[:300]
    for line in text.splitlines():
        line = line.strip()
        if line and not re.fullmatch(r"(Error: )?Exit code \d+|=+.*=+", line):
            return line[:300]
    return text.strip()[:300]


def _transcript_path(conn: sqlite3.Connection, session_id: str) -> str:
    row = conn.execute(
        "SELECT json_extract(raw_json, '$.metadata.raw.transcript_path') FROM events "
        "WHERE session_id = ? AND json_valid(raw_json) "
        "AND json_extract(raw_json, '$.metadata.raw.transcript_path') IS NOT NULL LIMIT 1",
        (session_id,),
    ).fetchone()
    return str(row[0]) if row and row[0] else ""


def _from_transcript(path: str) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    calls: Dict[str, Dict[str, Any]] = {}
    prompts: List[Dict[str, str]] = []
    branch = cwd = ""
    try:
        fh = open(path, encoding="utf-8", errors="replace")
    except OSError:
        return [], {}
    with fh:
        for line in fh:
            if '"tool_use"' not in line and '"tool_result"' not in line and '"user"' not in line:
                continue
            try:
                rec = json.loads(line)
            except ValueError:
                continue
            msg = rec.get("message") if isinstance(rec, dict) else None
            if not isinstance(msg, dict):
                continue
            branch = branch or rec.get("gitBranch") or ""
            cwd = cwd or rec.get("cwd") or ""
            content = msg.get("content")
            ts = rec.get("timestamp") or ""
            if rec.get("type") == "user" and isinstance(content, str) and not rec.get("isMeta"):
                if not content.startswith("<"):  # command echoes, task notifications
                    prompts.append({"ts": ts, "text": content[:2000]})
                continue
            if not isinstance(content, list):
                continue
            for item in content:
                if not isinstance(item, dict):
                    continue
                if item.get("type") == "tool_use":
                    inp = item.get("input") if isinstance(item.get("input"), dict) else {}
                    tool = str(item.get("name") or "")
                    calls[str(item.get("id"))] = {"id": str(item.get("id")), "ts": ts, "tool": tool,
                                                   "detail": _detail(tool, inp), "input": inp,
                                                   "error": "", "denied": False}
                elif item.get("type") == "tool_result" and str(item.get("tool_use_id")) in calls:
                    call = calls[str(item.get("tool_use_id"))]
                    body = item.get("content")
                    if isinstance(body, list):
                        body = "\n".join(str(b.get("text") or "") for b in body if isinstance(b, dict))
                    body = str(body or "")
                    if call["tool"] in _WRITE_TOOLS:  # keeps its patch; a Read's result is a whole file
                        call["result"] = rec.get("toolUseResult")
                    if item.get("is_error") in (True, "True", "true"):
                        call["error"] = body or "error"
                        call["denied"] = bool(rec.get("toolDenialKind")) or bool(_DENIAL.match(_error_line(body)))
                    elif call["tool"] == "Bash":
                        hit = _OUTPUT_FAIL.search(body)
                        if hit:
                            # The summary line names the cause, except for a traceback, whose cause is last.
                            call["error"] = body[hit.start():]
    return list(calls.values()), {"branch": branch, "prompts": prompts, "cwd": cwd}


def _from_events(conn: sqlite3.Connection, session_id: str) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    calls, prompts = [], []
    for ts, typ, cmd, path, url, raw in conn.execute(
        "SELECT ts, type, command_text, path_text, url_text, raw_json FROM events "
        "WHERE session_id = ? AND agent_event IN ('PreToolUse', 'UserPromptSubmit') ORDER BY id",
        (session_id,),
    ):
        try:
            meta = (json.loads(raw or "{}").get("metadata") or {})
        except ValueError:
            meta = {}
        if typ == "prompt":
            prompts.append({"ts": ts, "text": str((meta.get("raw") or {}).get("prompt") or "")[:2000]})
            continue
        inp = (meta.get("raw") or {}).get("tool_input") or {}
        tool = str(meta.get("tool_name") or typ)
        calls.append({"id": "", "ts": ts, "tool": tool, "input": inp if isinstance(inp, dict) else {},
                      "detail": " ".join(str(cmd or path or url or "").split())[:400],
                      "error": "", "denied": False})
    return calls, {"branch": "", "prompts": prompts}


def session_calls(session_id: str) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Every tool call of a session, oldest first, with its error when known."""
    conn = _db()
    if conn is None:
        return [], {}
    try:
        transcript = _transcript_path(conn, session_id)
        if transcript:
            calls, meta = _from_transcript(transcript)
            if calls:
                calls.sort(key=lambda c: c["ts"])
                return calls, {**meta, "source": "transcript"}
        calls, meta = _from_events(conn, session_id)
        return calls, {**meta, "source": "events"}
    finally:
        conn.close()


def _tokens_between(session_id: str, start: str, end: str) -> int:
    conn = _db()
    if conn is None:
        return 0
    try:
        row = conn.execute(
            "SELECT COALESCE(SUM(input_tokens + output_tokens + cache_read_tokens + cache_creation_tokens), 0) "
            "FROM token_usage WHERE session_id = ? AND ts >= ? AND ts <= ?",
            (session_id, start, end),
        ).fetchone()
        return int(row[0] or 0)
    finally:
        conn.close()


def _edit_pairs(call: Dict[str, Any]) -> List[Tuple[str, str]]:
    """(before, after) text of each change a write call made. A Write's
    previous content is not recorded, so it reads as all additions."""
    inp = call["input"]
    if isinstance(inp.get("edits"), list):
        return [(str(e.get("old_string") or ""), str(e.get("new_string") or ""))
                for e in inp["edits"] if isinstance(e, dict)]
    if "old_string" in inp or "new_string" in inp:
        return [(str(inp.get("old_string") or ""), str(inp.get("new_string") or ""))]
    if call["tool"] in ("Write", "NotebookEdit") or "content" in inp:
        return [("", str(inp.get("content") or inp.get("new_source") or ""))]
    return []


def _diff(pairs: List[Tuple[str, str]]) -> List[str]:
    """Unified-diff body lines (`+`, `-`, ` `), one `@@` line between changes."""
    out: List[str] = []
    for old, new in pairs:
        body = [l for l in difflib.unified_diff(old.splitlines(), new.splitlines(), lineterm="", n=2)
                if not l.startswith(("---", "+++"))]
        if body:
            out += body if body[0].startswith("@@") else ["@@"] + body
    return [("@@" if l.startswith("@@") else l) for l in out]


def _call_diff(call: Dict[str, Any], result: Any = None) -> List[str]:
    """Claude's own patch for the call (real line numbers, real removals) when
    the result carries one; otherwise a diff of the call's before/after text."""
    hunks = result.get("structuredPatch") if isinstance(result, dict) else None
    if hunks:
        out: List[str] = []
        for h in hunks:
            if isinstance(h, dict):
                out.append(f"@@ -{h.get('oldStart')},{h.get('oldLines')} +{h.get('newStart')},{h.get('newLines')} @@")
                out += [str(l) for l in h.get("lines") or []]
        return out
    if isinstance(result, dict) and result.get("type") == "create":
        return ["@@ new file"] + ["+" + l for l in str(result.get("content") or "").splitlines()]
    return _diff(_edit_pairs(call))


def _diff_stats(lines: List[str]) -> Dict[str, Any]:
    return {"added": sum(l[:1] == "+" for l in lines), "removed": sum(l[:1] == "-" for l in lines),
            "diff": lines[:DIFF_MAX], "truncated": len(lines) > DIFF_MAX}


def rca(session_id: str) -> Dict[str, Any]:
    """What went wrong in one session: first failure, loops, reverts, churn."""
    calls, meta = session_calls(session_id)
    failed = [c for c in calls if c["error"] and not c["denied"]]
    denied = [c for c in calls if c["denied"]]

    by_detail: Dict[Tuple[str, str], List[Dict[str, Any]]] = defaultdict(list)
    for c in failed:
        by_detail[(c["tool"], c["detail"])].append(c)
    loops = []
    for (tool, detail), group in by_detail.items():
        if len(group) >= LOOP_MIN:
            loops.append({"tool": tool, "detail": detail, "count": len(group),
                          "first": group[0]["ts"], "last": group[-1]["ts"],
                          "error": _error_line(group[-1]["error"]),
                          "tokens": _tokens_between(session_id, group[0]["ts"], group[-1]["ts"])})
    loops.sort(key=lambda l: -l["count"])

    # A revert is an edit that puts back exactly what an earlier edit replaced.
    reverts, done = [], defaultdict(set)
    writes: Counter = Counter()
    for c in calls:
        if c["tool"] not in _WRITE_TOOLS or c["error"]:
            continue
        path = c["detail"]
        writes[path] += 1
        for old, new in _edit_pairs(c):
            if (new, old) in done[path] and old != new:
                reverts.append({"path": path, "ts": c["ts"], "restored": new[:200]})
            done[path].add((old, new))
    churn = [{"path": p, "writes": n} for p, n in writes.most_common() if n >= CHURN_MIN]

    first = None
    if failed:
        i = calls.index(failed[0])
        first = {**_public(failed[0]), "before": [_public(c) for c in calls[max(0, i - 3):i]]}

    out = {
        "sessionId": session_id, "source": meta.get("source", ""), "branch": meta.get("branch", ""),
        "calls": len(calls), "failures": len(failed), "denied": len(denied),
        "firstFailure": first, "loops": loops, "reverts": reverts, "churn": churn,
        "failed": [_public(c) for c in failed[-30:]],
    }
    return _redact(out)


def _public(c: Dict[str, Any]) -> Dict[str, Any]:
    return {"ts": c["ts"], "tool": c["tool"], "detail": c["detail"], "error": _error_line(c["error"])}


_TEST_RUNNER = re.compile(
    r"^(?:[A-Z_][A-Z0-9_]*=\S*\s+)*(?:python3?\s+-m\s+|npx\s+|uv\s+run\s+)?"
    r"(?:pytest|jest|vitest|mocha|tox|rspec|(?:cargo|go)\s+test|(?:npm|pnpm|yarn)(?:\s+run)?\s+test|make\s+(?:test|check))(?:\s|$)")


def _runs_tests(cmd: str) -> str:
    """The step of the command that *is* a test run ("" if none), not a file or heredoc mentioning one."""
    from prismor.runtime.shell_context import heredocs
    for h in reversed(heredocs(cmd)):  # a heredoc body is data, not commands
        cmd = cmd[:h.start] + cmd[h.end:]
    return next((seg.strip() for seg in re.split(r"&&|\|\||;|\||\n", cmd) if _TEST_RUNNER.match(seg.strip())), "")


def changes(session_id: str) -> Dict[str, Any]:
    """What a session did to the repo, plus a PR description drafted from it."""
    calls, meta = session_calls(session_id)
    root = (meta.get("cwd") or "").rstrip("/") + "/"
    files: Counter = Counter()
    diffs: Dict[str, List[str]] = defaultdict(list)
    for c in calls:
        if c["tool"] in _WRITE_TOOLS and not c["error"]:
            f = c["detail"][len(root):] if root != "/" and c["detail"].startswith(root) else c["detail"]
            files[f] += 1
            diffs[f] += _call_diff(c, c.get("result"))
        elif c["tool"] == "Bash" and not c["error"]:
            for path, diff in _shell_write_diffs(str(c["input"].get("command") or ""), meta.get("cwd")):
                f = path[len(root):] if root != "/" and path.startswith(root) else path
                files[f] += 1
                diffs[f] += diff
    commands: List[str] = []
    for c in calls:
        if c["tool"] == "Bash" and not c["error"] and c["detail"] not in commands:
            commands.append(c["detail"])
    asks = [p["text"].strip().splitlines()[0][:200] for p in meta.get("prompts", []) if p["text"].strip()]
    md = ["## Summary", *([f"- {a}" for a in asks[:8]] or ["- (no prompts recorded)"]),
          "", "## Files changed",
          *([f"- `{f}` (+{_diff_stats(diffs[f])['added']} −{_diff_stats(diffs[f])['removed']})"
             for f, _ in files.most_common()] or ["- none"])]
    tests = list(dict.fromkeys(filter(None, (_runs_tests(str(c["input"].get("command") or c["detail"]))
                                             for c in calls if c["tool"] == "Bash" and not c["error"]))))
    if tests:
        md += ["", "## Tested with", *[f"- `{t[:160]}`" for t in tests[-5:]]]
    return _redact({"sessionId": session_id, "branch": meta.get("branch", ""),
                    "prompts": asks, "files": [{"path": f, "writes": n, **_diff_stats(diffs[f])} for f, n in files.most_common()],
                    "commands": commands[-40:], "prDescription": "\n".join(md)})


def _ensure_path_index() -> None:
    """Partial index for blame, built on first use rather than in the hook path:
    on a multi-GB store the one-time build takes seconds."""
    db = prismor_home() / "prismor.db"
    if not db.exists():
        return
    try:
        conn = sqlite3.connect(str(db), timeout=2)
        try:
            conn.execute("CREATE INDEX IF NOT EXISTS idx_events_write_path ON events(path_text) "
                         "WHERE type = 'file_write'")
        finally:
            conn.close()
    except sqlite3.Error:
        pass  # a busy store: blame still works, just slower


def blame(path: str, line: Optional[int] = None, limit: int = 20) -> Dict[str, Any]:
    """Which agent sessions wrote this file, newest first, with the prompt that asked.

    With a line number, only writes whose text contains that line's current
    text are kept, so the first row is the session that wrote it.
    """
    target = str(Path(path).expanduser().resolve())
    needle = ""
    _ensure_path_index()
    conn = _db()
    if conn is None:
        return {"path": target, "line": line, "text": needle, "writes": []}
    rows, seen = [], set()
    try:
        # The dashboard calls this over HTTP: only read a file an agent is on record writing.
        known = conn.execute("SELECT 1 FROM events WHERE type = 'file_write' AND path_text IN (?, ?) LIMIT 1",
                             (target, path)).fetchone()
        if line and known:
            try:
                lines = Path(target).read_text(encoding="utf-8", errors="replace").splitlines()
                needle = lines[line - 1].strip() if 0 < line <= len(lines) else ""
            except OSError:
                needle = ""
        for eid, sid, ts, raw, agent in conn.execute(
            "SELECT e.id, e.session_id, e.ts, e.raw_json, s.agent FROM events e "
            "LEFT JOIN sessions s USING(session_id) WHERE e.type = 'file_write' "
            "AND e.agent_event = 'PostToolUse' AND e.path_text IN (?, ?) ORDER BY e.id DESC LIMIT 500",
            (target, path),
        ):
            try:
                hook = (json.loads(raw or "{}").get("metadata") or {}).get("raw") or {}
            except ValueError:
                hook = {}
            inp = hook.get("tool_input") or {}
            call = hook.get("tool_use_id") or ts
            text = "\n".join(str(v) for v in (inp.get("new_string"), inp.get("content"),
                                              *[e.get("new_string") for e in inp.get("edits") or [] if isinstance(e, dict)])
                             if v)
            if (needle and len(needle) >= 4 and needle not in text) or call in seen:
                continue  # one call is logged twice when the hook is installed at two scopes
            seen.add(call)
            prompt = conn.execute(
                "SELECT json_extract(raw_json, '$.metadata.raw.prompt') FROM events WHERE session_id = ? "
                "AND type = 'prompt' AND id < ? ORDER BY id DESC LIMIT 1", (sid, eid),
            ).fetchone()
            rows.append({"ts": ts, "sessionId": sid, "agent": agent or "",
                         "prompt": str((prompt or [""])[0] or "")[:600],
                         **_diff_stats(_call_diff({"tool": str(hook.get("tool_name") or ""), "input": inp},
                                                  hook.get("tool_response")))})
            if len(rows) >= limit:
                break
        for w in _shell_writes():
            if w["path"] != target or (needle and len(needle) >= 4 and needle not in "\n".join(w["diff"])):
                continue
            prompt = conn.execute(
                "SELECT json_extract(raw_json, '$.metadata.raw.prompt') FROM events WHERE session_id = ? "
                "AND type = 'prompt' AND id < ? ORDER BY id DESC LIMIT 1", (w["sessionId"], w["id"]),
            ).fetchone()
            agent = conn.execute("SELECT agent FROM sessions WHERE session_id = ?", (w["sessionId"],)).fetchone()
            rows.append({"ts": w["ts"], "sessionId": w["sessionId"], "agent": (agent or [""])[0] or "", "via": "shell",
                         "prompt": str((prompt or [""])[0] or "")[:600], **_diff_stats(w["diff"])})
    finally:
        conn.close()
    rows.sort(key=lambda r: r["ts"] or "", reverse=True)
    return _redact({"path": target, "line": line, "text": needle, "writes": rows[:limit]})


def _shell_write_diffs(cmd: str, cwd: Optional[str]) -> List[Tuple[str, List[str]]]:
    """(path, diff) for each file a shell command writes. A heredoc's body is
    the new text; the old text was never recorded, so it reads as a rewrite."""
    from prismor.runtime.provenance import shell_paths
    from prismor.runtime.shell_context import heredocs
    base = Path(cwd) if cwd else None
    try:
        written = shell_paths(cmd, base)[1]
        docs = heredocs(cmd)
    except Exception:
        return []
    out: Dict[str, List[str]] = {}
    for h in docs:  # each heredoc feeds the file its own opener line redirects to
        opener = cmd[cmd.rfind("\n", 0, h.start) + 1:h.op_end] + cmd[h.op_end:cmd.find("\n", h.op_end)]
        for p in shell_paths(opener, base)[1] & written:
            out[p] = [f"@@ written from the shell: $ {' '.join(opener.split())[:200]}"] + \
                ["+" + l for l in cmd[h.body_start:h.body_end].splitlines()]
    for p in written - set(out):
        out[p] = [f"@@ written from the shell: $ {' '.join(cmd.split())[:200]}"]
    return [(p, d) for p, d in out.items() if "$" not in p]


SHELL_SCAN = 3000    # recent shell commands checked for file writes
_SHELL_CACHE: Dict[str, Any] = {}


def _shell_writes() -> List[Dict[str, Any]]:
    """Files written from the shell (`cat > f <<EOF`, `>>`, `tee`): agents do
    this often and it never becomes a file_write event. Parsed with the same
    scanner provenance uses, cached until the store gets a new event.

    ponytail: only the last SHELL_SCAN redirecting commands; a hook-time index if older history matters.
    """
    conn = _db()
    if conn is None:
        return []
    try:
        top = conn.execute("SELECT MAX(id) FROM events").fetchone()[0]
        if _SHELL_CACHE.get("top") == top and _SHELL_CACHE.get("db") == str(prismor_home()):
            return _SHELL_CACHE["rows"]
        rows = conn.execute(
            "SELECT id, session_id, ts, command_text, json_extract(raw_json, '$.metadata.cwd') FROM events "
            "WHERE type = 'shell' AND agent_event = 'PostToolUse' "
            "AND (command_text LIKE '%>%' OR command_text LIKE '%tee %') ORDER BY id DESC LIMIT ?",
            (SHELL_SCAN,),
        ).fetchall()
    finally:
        conn.close()
    out = []
    for eid, sid, ts, cmd, cwd in rows:
        for path, diff in _shell_write_diffs(cmd or "", cwd):
            out.append({"id": eid, "sessionId": sid, "ts": ts, "path": path, "diff": diff})
    _SHELL_CACHE.update(top=top, db=str(prismor_home()), rows=out)
    return out


def files(query: str = "", limit: int = 200) -> Dict[str, Any]:
    """Every file an agent is on record writing, most recently touched first."""
    _ensure_path_index()
    conn = _db()
    if conn is None:
        return {"files": []}
    try:
        rows = conn.execute(
            "SELECT path_text, COUNT(DISTINCT session_id), MAX(ts) FROM events "
            "WHERE type = 'file_write' AND agent_event = 'PostToolUse' AND path_text LIKE ? "
            "GROUP BY path_text ORDER BY MAX(ts) DESC LIMIT ?",
            (f"%{query}%", limit),
        ).fetchall()
    finally:
        conn.close()
    merged: Dict[str, Dict[str, Any]] = {p: {"path": p, "sids": {None}, "n": n, "last": ts} for p, n, ts in rows if p}
    for w in _shell_writes():
        if query.lower() in w["path"].lower():
            f = merged.setdefault(w["path"], {"path": w["path"], "sids": set(), "n": 0, "last": ""})
            if w["sessionId"] not in f["sids"]:
                f["sids"].add(w["sessionId"])
                f["n"] += 1  # ponytail: may double-count a session that also used Edit on the file
            f["last"] = max(f["last"], w["ts"] or "")
    out = sorted(merged.values(), key=lambda f: f["last"], reverse=True)[:limit]
    return _redact({"files": [{"path": f["path"], "sessions": f["n"], "last": f["last"]} for f in out]})


def _command_key(detail: str) -> str:
    """`cd x && FOO=1 npm test -- -k a | tail` -> `npm test`: the command, not the invocation.

    The last step of a chain is the one that ran last, so the one that failed.
    """
    cmd = re.split(r"&&|;", re.split(r"(?<!\|)\|(?!\|)", detail)[0])[-1]
    words = [w for w in cmd.split() if not re.fullmatch(r"[A-Z_][A-Z0-9_]*=\S*|\d?>&?\S*", w)]
    return " ".join(words[:3] if len(words) > 2 and words[1] == "-m" else words[:2])


def friction(workspace: Optional[str] = None, days: int = 14, max_sessions: int = 40) -> Dict[str, Any]:
    """Failures that recur across sessions: the things worth a line in AGENTS.md."""
    conn = _db()
    if conn is None:
        return {"days": days, "sessions": 0, "patterns": []}
    try:
        sids = [r[0] for r in conn.execute(
            "SELECT session_id FROM sessions WHERE updated_at >= datetime('now', ?) "
            "AND (? IS NULL OR workspace_path = ?) ORDER BY updated_at DESC LIMIT ?",
            (f"-{int(days)} days", workspace, workspace, max_sessions))]
    finally:
        conn.close()
    # ponytail: re-reads up to max_sessions transcripts per call; cache per (path, mtime) if the card gets slow.
    groups: Dict[str, Dict[str, Any]] = {}
    for sid in sids:
        calls, _ = session_calls(sid)
        for c in calls:
            if not c["error"] or c["denied"]:
                continue
            key = (_command_key(c["detail"]) if c["tool"] == "Bash" else "") or c["tool"]
            g = groups.setdefault(key, {"command": key, "tool": c["tool"], "count": 0,
                                        "sessions": set(), "errors": Counter()})
            g["count"] += 1
            g["sessions"].add(sid)
            g["errors"][_error_line(c["error"])] += 1
    patterns = []
    for g in groups.values():
        if len(g["sessions"]) < 2:
            continue
        err, _ = g["errors"].most_common(1)[0]
        patterns.append({"command": g["command"], "tool": g["tool"], "failures": g["count"],
                         "sessions": len(g["sessions"]), "error": err,
                         "agentsMd": f"- `{g['command']}` has failed in {len(g['sessions'])} sessions: {_clip(err, 160)}"})
    patterns.sort(key=lambda p: (-p["sessions"], -p["failures"]))
    return _redact({"days": days, "sessions": len(sids), "patterns": patterns[:25]})


def on_failure(payload: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """PostToolUseFailure hook: tell the agent when it is retrying the same failing call.

    Only failures reach this hook, so successful calls pay nothing. The count
    lives in one small per-session file; a loop is the same tool + input.
    """
    sid = str(payload.get("session_id") or "")
    tool = str(payload.get("tool_name") or "")
    inp = payload.get("tool_input") if isinstance(payload.get("tool_input"), dict) else {}
    if not sid:
        return None
    key = f"{tool}:{_detail(tool, inp)}"
    state = prismor_home() / "loops" / f"{re.sub(r'[^A-Za-z0-9_-]', '_', sid)}.json"
    state.parent.mkdir(parents=True, exist_ok=True)
    with locked_json_update(state) as counts:
        counts[key] = n = int(counts.get(key, 0)) + 1
    if n < LOOP_MIN:
        return None
    return {"hookSpecificOutput": {
        "hookEventName": "PostToolUseFailure",
        "additionalContext": (
            f"Prismor: this exact {tool} call has now failed {n} times in this session "
            f"({_error_line(str(payload.get('error') or ''))}). Retrying it unchanged will fail again: "
            "read the error, check the assumption behind the call, and change approach."),
    }}


def _clip(s: str, n: int = 110) -> str:
    return s if len(s) <= n else s[: n - 1] + "…"


def format_rca(r: Dict[str, Any]) -> str:
    out = [f"Session {r['sessionId']}" + (f"  (branch {r['branch']})" if r.get("branch") else ""),
           f"{r['calls']} calls · {r['failures']} failed · {r['denied']} denied"]
    if r.get("source") == "events":
        out.append("(this agent's hooks don't report outcomes; failures are unknown)")
    f = r.get("firstFailure")
    if f and not any(l["detail"] == f["detail"] for l in r.get("loops") or []):
        out += ["", "First failure", f"  {f['ts'][:19]}  {f['tool']}: {_clip(f['detail'])}", f"    → {f['error']}"]
        if f["before"]:
            out += ["  after:"] + [f"    {b['tool']}: {_clip(b['detail'], 100)}" for b in f["before"]]
    for l in r.get("loops") or []:
        spent = f", {l['tokens']:,} tokens" if l["tokens"] else ""
        out += ["", f"Loop: failed {l['count']}× ({l['first'][11:19]}–{l['last'][11:19]}{spent})",
                f"  {l['tool']}: {_clip(l['detail'])}", f"    → {l['error']}"]
    for v in r.get("reverts") or []:
        out.append(f"Reverted an earlier edit: {v['path']} at {v['ts'][11:19]}")
    for c in r.get("churn") or []:
        out.append(f"Rewritten {c['writes']}×: {c['path']}")
    if not (f or r.get("loops") or r.get("reverts") or r.get("churn")):
        out += ["", "Nothing went wrong that the record shows."]
    return "\n".join(out)


def _diff_text(lines: List[str], indent: str = "  ") -> List[str]:
    import sys
    color = sys.stdout.isatty()
    paint = {"+": "\033[32m", "-": "\033[31m", "@": "\033[36m"}
    return [indent + (paint.get(l[:1], "") + l + "\033[0m" if color and l[:1] in paint else l) for l in lines]


def format_changes(r: Dict[str, Any]) -> str:
    out = [r["prDescription"]]
    for f in r["files"]:
        out += ["", f"{f['path']}  +{f['added']} −{f['removed']}"] + _diff_text(f["diff"])
        if f.get("truncated"):
            out.append("  …")
    if r["commands"]:
        out += ["", "## Commands run", *[f"- `{_clip(c, 140)}`" for c in r["commands"]]]
    return "\n".join(out)


def format_blame(r: Dict[str, Any]) -> str:
    head = r["path"] + (f":{r['line']}  {_clip(r['text'], 80)}" if r.get("line") else "")
    if not r["writes"]:
        return head + "\nNo agent write to this " + ("line" if r.get("line") else "file") + " is on record."
    out = [head]
    for w in r["writes"]:
        out += ["", f"{w['ts'][:19]}  {w['agent'] or 'agent'}  session {w['sessionId']}  +{w['added']} −{w['removed']}",
                f"  asked: {_clip(' '.join(w['prompt'].split()), 160) or '(no prompt recorded)'}"]
        out += _diff_text(w["diff"][:20], "    ") + (["    …"] if len(w["diff"]) > 20 else [])
    return "\n".join(out)


def format_friction(r: Dict[str, Any]) -> str:
    if not r["patterns"]:
        return f"No failure repeated across the last {r['sessions']} sessions ({r['days']} days)."
    out = [f"Recurring failures, last {r['days']} days ({r['sessions']} sessions). Paste into AGENTS.md:", ""]
    return "\n".join(out + [p["agentsMd"] for p in r["patterns"]])


if __name__ == "__main__":
    assert _command_key("cd /x && FOO=1 npm test -- -k a") == "npm test"
    assert _command_key("pytest tests/a.py -q") == "pytest tests/a.py"
    assert _command_key("ls -la && python3 -m pytest -q 2>&1 | tail -40") == "python3 -m pytest"
    assert _error_line("Exit code 1\n\nModuleNotFoundError: x") == "ModuleNotFoundError: x"
    assert _error_line("Exit code 1\nTraceback (most recent call last):\n  File x\nKeyError: 'a'") == "KeyError: 'a'"
    c = {"tool": "MultiEdit", "input": {"edits": [{"old_string": "a", "new_string": "b"}]}}
    assert _edit_pairs(c) == [("a", "b")]
    assert _runs_tests("cd x && FOO=1 python3 -m pytest -q | tail") and not _runs_tests("cat tests/*.py pytest.ini")
    assert _runs_tests("cat > t.py <<'EOF'\nfrom pytest import approx\nEOF\npython3 -m pytest -q")
    assert not _runs_tests("cat > t.py <<'EOF'\npytest -q\nEOF")
    two = "cat > a.py <<'EOF'\nA\nEOF\ncat > b.py <<EOF\nB\nEOF"
    assert {p.rsplit("/", 1)[1]: d[1:] for p, d in _shell_write_diffs(two, "/r")} == {"a.py": ["+A"], "b.py": ["+B"]}
    assert _OUTPUT_FAIL.search("..F\n=== 1 failed, 2 passed in 0.1s ===")
    assert _OUTPUT_FAIL.search("ERROR collecting tests/test_x.py")
    assert _error_line("Exit code 2\n=== ERRORS ===\nERROR collecting t.py\nE   ModuleNotFoundError: No module named 'x'") \
        == "ModuleNotFoundError: No module named 'x'"
    assert not _OUTPUT_FAIL.search("grep: 0 failed lookups\nall good")
    print("ok")
