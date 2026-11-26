"""What agents on this machine may do without asking.

"Always Allow" in an agent writes a rule to a local file. This reads those
rules so they can be shown (Claude Code, Codex, Cursor CLI, Antigravity), and
lets a person at the local dashboard turn one off, turn it back on, or narrow
it from every project to one, or add an ask or deny rule. Nothing here can add
a permission the machine did not already hold, or widen one. Local only:
nothing read here is uploaded.

ponytail: allow rules only, and only these four stores. IDE-internal stores
(Cursor/Antigravity protobuf and sqlite) and session-only grants are not read.
"""
from __future__ import annotations

import ast
import hashlib
import json
import os
import re
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Tuple

MAX_RULES = 5000
MAX_PROJECTS = 200

# The dashboard serves requests on threads: a read between turn_off's two writes
# would see the rule as both off and active, and drop the saved copy.
_LOCK = threading.RLock()

# Rule text is a command or path a human approved, so it can carry a token
# nobody vaulted and no vendor pattern knows.
_INLINE_SECRET = re.compile(
    r"(?i)((?:authorization:\s*(?:bearer\s+|basic\s+|token\s+)?|bearer\s+|"
    r"(?:token|password|passwd|secret|api[_-]?key)\w*(?:=|:\s*|\s+))['\"]?)([^\s'\"):]{6,})")


def _json(path: Path) -> Dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _allow(block: Any) -> List[str]:
    allow = block.get("allow") if isinstance(block, dict) else None
    return [r for r in allow if isinstance(r, str) and r] if isinstance(allow, list) else []


def _codex_rules(path: Path) -> List[str]:
    """``prefix_rule(pattern=[...], decision="allow")`` calls. Starlark, which
    parses as Python; nothing is executed."""
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
    except (OSError, SyntaxError, ValueError):
        return []
    out = []
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and getattr(node.func, "id", "") == "prefix_rule"):
            continue
        kw = {}
        for k in node.keywords:
            try:
                kw[k.arg] = ast.literal_eval(k.value)
            except ValueError:
                pass
        pattern = kw.get("pattern")
        if kw.get("decision", "allow") != "allow" or not isinstance(pattern, list):
            continue
        out.append("prefix_rule(%s)" % " ".join(
            "|".join(map(str, p)) if isinstance(p, list) else str(p) for p in pattern))
    return out


def _claude_projects(workspace: Path) -> List[Path]:
    known = _json(Path.home() / ".claude.json").get("projects")
    paths = [Path(workspace)] + [Path(p) for p in (known if isinstance(known, dict) else {})]
    return list(dict.fromkeys(paths))[:MAX_PROJECTS]


def _raw(workspace: Path) -> List[Tuple[str, str, str, Path, str]]:
    """(agent, scope, project, file, rule) for every allow rule found."""
    home = Path.home()
    out: List[Tuple[str, str, str, Path, str]] = []

    def add(agent: str, path: Path, rules: List[str], project: str = "") -> None:
        out.extend((agent, "project" if project else "global", project, path, r) for r in rules)

    for name in ("settings.json", "settings.local.json"):
        path = home / ".claude" / name
        add("claude", path, _allow(_json(path).get("permissions")))
    for project in _claude_projects(workspace):
        if project == home or not (project / ".claude").is_dir():
            continue
        found = [(path, _allow(_json(path).get("permissions"))) for path in
                 (project / ".claude" / "settings.json", project / ".claude" / "settings.local.json")]
        # The scope check verifies the signed policy, so only pay it for a project with rules.
        if any(rules for _, rules in found):
            for path, rules in found:
                add("claude", path, rules, str(project))

    codex = Path(os.environ.get("CODEX_HOME") or home / ".codex")
    for path in sorted((codex / "rules").glob("*.rules")):
        add("codex", path, _codex_rules(path))

    path = home / ".cursor" / "cli-config.json"
    add("cursor", path, _allow(_json(path).get("permissions")))

    config = home / ".gemini" / "config"
    path = config / "config.json"
    user = _json(path).get("userSettings")
    add("antigravity", path, _allow(user.get("globalPermissionGrants") if isinstance(user, dict) else None))
    for path in sorted((config / "projects").glob("*.json")):
        data = _json(path)
        rules = _allow(data.get("permissionGrants"))
        if not rules:
            continue
        resources = data.get("projectResources")
        resources = resources.get("resources") if isinstance(resources, dict) else None
        uri = next((str(v) for r in resources or [] if isinstance(r, dict)
                    for v in [r.get("folderUri")] if v), "")
        folder = uri[7:] if uri.startswith("file://") else ""
        if folder:
            add("antigravity", path, rules, folder)
    # Global rules first: they reach furthest, so the cap must never drop them.
    out.sort(key=lambda r: r[1] != "global")
    return out[:MAX_RULES]


def _clean(texts: List[str]) -> Dict[str, str]:
    """original -> safe: secrets masked and the home directory folded, before
    the browser sees it. One vault pass over all of them, because a pass per rule
    costs seconds on a machine with a big vault."""
    from prismor.runtime.cloaking.runtime import scrub_text
    from prismor.runtime.data_boundary import classify, redact_command
    texts = list(dict.fromkeys(texts))
    if not texts:
        return {}
    sep = "\n\x1e\n"
    masked = scrub_text(sep.join(t.replace("\x1e", " ") for t in texts)).split(sep)
    if len(masked) != len(texts):  # never ship text we cannot line up with its mask
        raise ValueError("redaction changed the rule count")
    home, out = str(Path.home()), {}
    for original, text in zip(texts, masked):
        found = [m for m in classify(text, context="body") if m.kind == "secret" and not m.synthetic]
        if found:
            text, _ = redact_command(text, found)
        text = _INLINE_SECRET.sub(r"\1[REDACTED]", text)
        out[original] = text.replace(home, "~")[:300]
    return out


def rule_id(path: Path, rule: str) -> str:
    return hashlib.sha256(f"{path}\0{rule}".encode()).hexdigest()[:24]


def collect(workspace: Path) -> List[Dict[str, object]]:
    """Every allow rule, masked, with an ``id`` the change functions take."""
    with _LOCK:
        rows = _raw(workspace)
        seen = _note_seen(rows)
    safe = _clean([t for _, _, project, path, rule in rows for t in (project, str(path), rule)])
    return [{"agent": agent, "scope": scope, "project": safe[project], "source": safe[str(path)],
             "rule": safe[rule], "id": rule_id(path, rule), **seen[rule_id(path, rule)]}
            for agent, scope, project, path, rule in rows]


# --- changes, from the local dashboard only -------------------------------

def _off_file() -> Path:
    from prismor.runtime.unlock import prismor_home
    return prismor_home() / "allow-rules-off.json"


def _off_entries() -> List[Dict[str, str]]:
    data = _json(_off_file()).get("rules")
    return data if isinstance(data, list) else []


def _seen_file() -> Path:
    return _off_file().with_name("allow-rules-seen.json")


def _note_seen(rows: List[Tuple[str, str, str, Path, str]]) -> Dict[str, Dict[str, object]]:
    """id -> when this dashboard first saw the rule ("" for one already there on
    the first look: agents keep no dates), and whether the agent added it back
    after it was turned off. That stale saved copy is dropped, so a rule is
    never listed as both on and off."""
    old = _json(_seen_file()).get("rules")
    first = not isinstance(old, dict)
    old = {} if first else old
    entries = _off_entries()
    def key(e):
        return (e.get("agent"), e.get("scope"), e.get("project"), e.get("rule"))

    off = {key(e) for e in entries if not e.get("ask")}
    asks = {key(e) for e in entries if e.get("ask")}
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    seen, back, still_asks = {}, set(), set()
    for agent, scope, project, path, rule in rows:
        ident = rule_id(path, rule)
        note = dict(old.get(ident) or {"added": "" if first else now, "again": False})
        if (agent, scope, project, rule) in off:
            back.add((agent, scope, project, rule))
            note = {"added": now, "again": True}
        seen[ident] = note
        if (agent, scope, project, rule) in asks:
            still_asks.add(ident)
    if seen != old or first:
        _write(_seen_file(), json.dumps({"rules": seen}))
    if back:
        _write(_off_file(), json.dumps({"rules": [e for e in entries
                                                  if e.get("ask") or key(e) not in back]}, indent=2))
    return {i: dict(note, asks=i in still_asks) for i, note in seen.items()}


def _forget_seen(ident: str) -> None:
    """So that a rule which comes back gets a new date."""
    seen = _json(_seen_file()).get("rules")
    if isinstance(seen, dict) and seen.pop(ident, None) is not None:
        _write(_seen_file(), json.dumps({"rules": seen}))


def _write(path: Path, text: str) -> None:
    """Atomic, keeps the file mode, and writes through a symlink."""
    path = path.resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    mode = path.stat().st_mode & 0o777 if path.exists() else 0o600
    tmp = path.with_name(path.name + ".prismor-tmp")
    tmp.write_text(text, encoding="utf-8")
    os.chmod(tmp, mode)
    os.replace(tmp, path)


def _keys(agent: str, path: Path) -> List[str]:
    if agent != "antigravity":
        return ["permissions", "allow"]
    if path.parent.name == "projects":
        return ["permissionGrants", "allow"]
    return ["userSettings", "globalPermissionGrants", "allow"]


def _edit_json(agent: str, path: Path, rule: str, present: bool,
               keys: Tuple[str, ...] = ()) -> None:
    # A file we cannot parse is never rewritten: that would drop its contents.
    data = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
    keys = list(keys) or _keys(agent, path)
    node = data
    for key in keys[:-1]:
        node = node.setdefault(key, {})
    allow = [r for r in node.get(keys[-1], []) if r != rule]
    node[keys[-1]] = allow + [rule] if present else allow
    _write(path, json.dumps(data, indent=2) + "\n")


def _cut_codex(path: Path, rule: str) -> str:
    """Remove the ``prefix_rule`` statements that read as ``rule``; return them."""
    source = path.read_text(encoding="utf-8")
    lines = source.splitlines(keepends=True)
    spans = []
    for node in ast.parse(source).body:
        part = ast.get_source_segment(source, node) or ""
        probe = path.with_name(path.name + ".prismor-probe")
        _write(probe, part + "\n")
        try:
            if _codex_rules(probe) == [rule]:
                spans.append((node.lineno - 1, node.end_lineno))
        finally:
            probe.unlink()
    removed = "".join("".join(lines[a:b]) for a, b in spans)
    for a, b in reversed(spans):
        del lines[a:b]
    _write(path, "".join(lines))
    return removed


def _find(workspace: Path, ident: str) -> Tuple[str, str, str, Path, str]:
    for row in _raw(workspace):
        if rule_id(row[3], row[4]) == ident:
            return row
    raise KeyError("That rule is no longer there. Refresh the page.")


# Claude reads deny, then ask, then allow, so a rule listed here keeps prompting
# even after "don't ask again" writes the allow rule back.
_ASK = ("permissions", "ask")


def turn_off(workspace: Path, ident: str, *, always_ask: bool = False) -> None:
    with _LOCK:
        _turn_off(workspace, ident, always_ask)
        _forget_seen(ident)


def _turn_off(workspace: Path, ident: str, always_ask: bool) -> None:
    agent, scope, project, path, rule = _find(workspace, ident)
    entry = {"id": ident, "agent": agent, "scope": scope, "project": project, "file": str(path), "rule": rule}
    if always_ask:
        if agent != "claude":
            raise ValueError("Only Claude Code has an always-ask list.")
        perms = _json(path).get("permissions") or {}
        # An ask rule the person wrote themselves is theirs: "on" leaves it.
        entry["ask"] = "kept" if rule in (perms.get("ask") or []) else "added"
        _edit_json(agent, path, rule, True, _ASK)  # first: never a moment with neither
    # Kept first: a crash between the two writes must not lose the rule.
    kept = [e for e in _off_entries() if e.get("id") != ident]
    _write(_off_file(), json.dumps({"rules": kept + [entry]}, indent=2))
    if agent == "codex":
        entry["text"] = _cut_codex(path, rule)
        _write(_off_file(), json.dumps({"rules": kept + [entry]}, indent=2))
    else:
        _edit_json(agent, path, rule, False)


def turn_on(ident: str) -> None:
    """Put back a rule ``turn_off`` removed, into the same file. Nothing else."""
    entries = _off_entries()
    entry = next((e for e in entries if e.get("id") == ident), None)
    if entry is None:
        raise KeyError("That rule was not turned off here.")
    path = Path(entry["file"])
    if entry["agent"] == "codex":
        source = path.read_text(encoding="utf-8") if path.exists() else ""
        _write(path, source + ("" if source.endswith("\n") or not source else "\n") + entry.get("text", ""))
    else:
        _edit_json(entry["agent"], path, entry["rule"], True)
        if entry.get("ask") == "added":
            _edit_json(entry["agent"], path, entry["rule"], False, _ASK)
    _write(_off_file(), json.dumps({"rules": [e for e in entries if e is not entry]}, indent=2))


def targets(workspace: Path) -> Dict[str, Dict[str, Path]]:
    """agent -> {project folder -> the file a narrowed rule goes in}. Only
    projects the agent already knows; Codex and Cursor are not offered."""
    home = Path.home()
    claude = {str(p): p / ".claude" / "settings.local.json" for p in _claude_projects(workspace)
              if p != home and p.is_dir()}
    antigravity = {}
    for path in sorted((home / ".gemini" / "config" / "projects").glob("*.json")):
        resources = _json(path).get("projectResources")
        resources = resources.get("resources") if isinstance(resources, dict) else None
        for r in resources or []:
            uri = str(r.get("folderUri", "")) if isinstance(r, dict) else ""
            if uri.startswith("file://") and Path(uri[7:]) != home:
                antigravity[uri[7:]] = path
    return {"claude": claude, "antigravity": antigravity}


def narrow(workspace: Path, ident: str, project: str) -> None:
    """Move a rule from every project to one project. Never the reverse."""
    agent, scope, _, path, rule = _find(workspace, ident)
    target = targets(workspace).get(agent, {}).get(project)
    if scope != "global" or target is None:
        raise ValueError("Only an all-projects Claude or Antigravity rule can move to a project it knows.")
    _edit_json(agent, target, rule, True)  # destination first, so a failure loses nothing
    _edit_json(agent, path, rule, False)


# --- rules a person adds: ask or deny only, so nothing here can grant ---------

_RULE_SHAPE = re.compile(r"[A-Za-z_][\w-]*(\([^\n\r]+\))?\Z")


def _added_file() -> Path:
    return _off_file().with_name("allow-rules-added.json")


def _added_entries() -> List[Dict[str, str]]:
    data = _json(_added_file()).get("rules")
    return data if isinstance(data, list) else []


# Which of ask/deny each agent has, per its documentation.
ADDABLE = {"claude": ("ask", "deny"), "codex": ("ask", "deny"), "cursor": ("deny",),
           "antigravity": ("ask", "deny")}


def add_targets(workspace: Path, agent: str) -> Dict[str, Path]:
    """project ("" = every project) -> the file a new rule goes in."""
    home = Path.home()
    known = targets(workspace)
    if agent == "claude":
        return {"": home / ".claude" / "settings.json", **known["claude"]}
    if agent == "antigravity":
        return {"": home / ".gemini" / "config" / "config.json", **known["antigravity"]}
    if agent == "cursor":
        return {"": home / ".cursor" / "cli-config.json",
                **{p: Path(p) / ".cursor" / "cli.json" for p in known["claude"]}}
    if agent == "codex":  # project-level rule loading is not confirmed, so global only
        return {"": Path(os.environ.get("CODEX_HOME") or home / ".codex") / "rules" / "default.rules"}
    return {}


def _list_keys(agent: str, path: Path, kind: str) -> Tuple[str, ...]:
    return (*_keys(agent, path)[:-1], kind)


def _codex_line(kind: str, rule: str) -> str:
    words = rule.split()
    if not words or any(c in rule for c in "\"'\\()[]|&;<>$`"):
        raise ValueError("For Codex write the command's first words, such as: git push")
    decision = "prompt" if kind == "ask" else "forbidden"
    return f'prefix_rule(pattern={json.dumps(words)}, decision="{decision}")\n'


def add_rule(workspace: Path, kind: str, rule: str, project: str = "", agent: str = "claude") -> None:
    """An ``ask`` or ``deny`` rule, for every project ("") or one."""
    rule = rule.strip()
    if kind not in ADDABLE.get(agent, ()):
        raise ValueError("Only ask and deny rules can be added (Cursor: deny).")
    if len(rule) > 300 or "\n" in rule or "\r" in rule:
        raise ValueError("Write one rule on one line.")
    if agent != "codex" and not _RULE_SHAPE.match(rule):
        raise ValueError("Write Tool(pattern), such as Bash(git push *), Shell(rm) or command(git push).")
    path = add_targets(workspace, agent).get(project)
    if path is None:
        raise ValueError("That agent does not know that project.")
    with _LOCK:
        entry = {"agent": agent, "kind": kind, "rule": rule, "project": project, "file": str(path),
                 "id": rule_id(path, f"{kind}\0{rule}")}
        if agent == "codex":
            entry["text"] = _codex_line(kind, rule)
            source = path.read_text(encoding="utf-8") if path.exists() else ""
            if entry["text"] in source:
                raise ValueError("That rule is already there.")
            gap = "" if not source or source.endswith("\n") else "\n"
            _write(path, source + gap + entry["text"])
        else:
            node: Any = _json(path)
            for key in _list_keys(agent, path, kind):
                node = node.get(key) if isinstance(node, dict) else None
            if rule in (node or []):
                raise ValueError("That rule is already there.")
            _edit_json(agent, path, rule, True, _list_keys(agent, path, kind))
        kept = [e for e in _added_entries() if e.get("id") != entry["id"]]
        _write(_added_file(), json.dumps({"rules": kept + [entry]}, indent=2))


def remove_added(ident: str) -> None:
    """Take back a rule ``add_rule`` wrote. Nobody else's ask or deny rule."""
    with _LOCK:
        entries = _added_entries()
        entry = next((e for e in entries if e.get("id") == ident), None)
        if entry is None or entry.get("kind") not in ("ask", "deny"):
            raise KeyError("That rule was not added here.")
        agent, path = entry.get("agent", "claude"), Path(entry["file"])
        if agent == "codex":
            _write(path, path.read_text(encoding="utf-8").replace(entry["text"], "", 1))
        else:
            _edit_json(agent, path, entry["rule"], False, _list_keys(agent, path, entry["kind"]))
        _write(_added_file(), json.dumps({"rules": [e for e in entries if e is not entry]}, indent=2))


def added_rules() -> List[Dict[str, str]]:
    entries = _added_entries()
    safe = _clean([t for e in entries for t in (e.get("rule", ""), e.get("project", ""))])
    return [{"id": e["id"], "agent": e.get("agent", "claude"), "kind": e["kind"], "project": safe[e.get("project", "")],
             "rule": safe[e.get("rule", "")]} for e in entries]


def off_rules() -> List[Dict[str, str]]:
    entries = _off_entries()
    safe = _clean([t for e in entries for t in (e.get("rule", ""), e.get("project", ""))])
    return [{"id": e["id"], "agent": e["agent"], "scope": e.get("scope", "global"),
             "project": safe[e.get("project", "")], "rule": safe[e.get("rule", "")],
             "ask": bool(e.get("ask"))} for e in entries]
