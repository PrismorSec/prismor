"""`prismor tags` — manage tool tags + tag-rule expressions (policy as code).

Subcommands:
    list                     tools seen in recorded sessions + resolved tags + tier
    set <tool> <tag>...      write an explicit tag mapping into .prismor/policy.yaml
    rm <tool> [<tag>]        remove an explicit mapping (or one tag of it)
    rules [list]             show active rules (DSL + legacy incompatible)
    rules add "<expr>"       add a rule expression (parse-checked first)
    rules rm <n|expr>        remove a rule by index (from `rules list`) or text
    edit                     interactive wizard over tools + rules
    lint [file]              validate every rule expression; exit 1 on errors
    test [--session|--last]  dry-run rules against recorded session logs

The heavy lifting (parsing, classification, ledger) lives in ``tag_rules`` and
``trifecta``; this module is UX only.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from prismor.runtime.tag_rules import (
    CompiledRule, ParseError, compile_rule, compile_tool_tag_rules, lint_rules,
)
from prismor.runtime.trifecta import (
    TOOL_TAG_DEFAULTS, TagLedger, _matches, _tool_name, classify_tool_tags,
)

# ── small output helpers (match cli.py's ANSI style, no deps) ────────────────
_RESET = "\033[0m"
_BOLD = "\033[1m"
_DIM = "\033[2m"
_RED = "\033[31m"
_GREEN = "\033[32m"
_YELLOW = "\033[33m"
_CYAN = "\033[36m"


def _c(text: str, color: str) -> str:
    if not sys.stdout.isatty():
        return text
    return f"{color}{text}{_RESET}"


def _print_parse_error(err: ParseError) -> None:
    print(_c("invalid rule:", _RED))
    print(f"  {err.expr}")
    print(f"  {' ' * err.pos}{_c('^ ' + str(err.args[0]), _RED)}")


# ── policy file plumbing ─────────────────────────────────────────────────────

def _policy_path(workspace: Path) -> Path:
    return workspace / ".prismor" / "policy.yaml"


def _load_policy_file(workspace: Path) -> Dict[str, Any]:
    import yaml

    path = _policy_path(workspace)
    if not path.exists():
        return {}
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _save_policy_file(workspace: Path, data: Dict[str, Any]) -> None:
    import yaml

    path = _policy_path(workspace)
    path.parent.mkdir(parents=True, exist_ok=True)
    data.setdefault("version", "1.0")
    path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")


def _tt_block(data: Dict[str, Any]) -> Dict[str, Any]:
    settings = data.setdefault("settings", {})
    if not isinstance(settings, dict):
        settings = {}
        data["settings"] = settings
    tt = settings.setdefault("tool_tags", {})
    if not isinstance(tt, dict):
        tt = {}
        settings["tool_tags"] = tt
    return tt


def _effective_tool_tags(workspace: Path) -> Dict[str, Any]:
    """The merged tool_tags settings the engine actually uses (defaults +
    project override + org remote policy)."""
    try:
        from prismor.runtime.policy_engine import PolicyEngine

        return PolicyEngine(workspace=workspace).tool_tags or {}
    except Exception:
        return {}


def _org_managed_hint(workspace: Path) -> None:
    """If this device is enrolled, local edits may be overridden by org policy."""
    try:
        from prismor.runtime.enterprise.identity import load_identity

        if load_identity() is not None:
            print(_c(
                "note: this device is org-enrolled — org policy is authoritative; "
                "manage org-wide tags in the Prismor console (Tag Studio).", _DIM))
    except Exception:
        pass


# ── session log scanning ─────────────────────────────────────────────────────

def _recent_sessions(workspace: Path, limit: int) -> List[Tuple[str, Path]]:
    from prismor.runtime.store import get_sessions_dir

    sdir = get_sessions_dir(workspace)
    if not sdir.exists():
        return []
    files = sorted(sdir.glob("*.jsonl"), key=lambda p: p.stat().st_mtime,
                   reverse=True)
    return [(p.stem, p) for p in files[:limit]]


def _session_events(workspace: Path, session_id: str) -> List[Dict[str, Any]]:
    from prismor.runtime.store import read_session_events

    try:
        return read_session_events(workspace, session_id)
    except FileNotFoundError:
        return []


def _resolve_with_tier(
    event: Dict[str, Any], event_type: str, tt: Dict[str, Any]
) -> Tuple[Set[str], str]:
    """Classify like ``classify_tool_tags`` but also report WHICH tier won."""
    tool = _tool_name(event)
    mapping = tt.get("tags") or {}
    if isinstance(mapping, dict):
        explicit: Set[str] = set()
        for pat, val in mapping.items():
            if pat == tool or _matches(tool, pat, "auto"):
                explicit |= set(val if isinstance(val, list) else [val])
        if explicit:
            return explicit, "explicit"
    if tt.get("meta_tags_enabled", True):
        mt = (event.get("metadata") or {}).get("meta_tags")
        if isinstance(mt, (list, tuple)) and mt:
            return {str(t) for t in mt if t}, "_meta"
    if tt.get("defaults_enabled", True):
        d: Set[str] = set()
        for matcher, match_type, deftags in TOOL_TAG_DEFAULTS:
            if _matches(tool, matcher, match_type):
                d |= set(deftags)
        if d:
            return d, "default"
    tags = classify_tool_tags(event, event_type, set(), {
        **tt, "tags": {}, "defaults_enabled": False, "meta_tags_enabled": False,
    })
    if tags:
        return tags, "inference"
    return set(), "-"


# ── subcommand: list ─────────────────────────────────────────────────────────

def tags_list(workspace: Path, last: int = 50) -> None:
    tt = _effective_tool_tags(workspace)
    seen: Dict[str, Tuple[Set[str], str]] = {}
    # Normalized event kind per tool. A tool whose adapter has no branch for it
    # falls through to a tool_result tagged with ``unmapped_tool`` (see
    # hooks._unmapped_tool_event) — surface that as UNMAPPED so a coverage hole
    # is visible rather than looking like an ordinary tool response. Tracked
    # across every event, not just the first: one adapter mapping a tool name
    # must not mask another adapter that doesn't.
    kinds: Dict[str, Set[str]] = {}
    for sid, _ in _recent_sessions(workspace, last):
        for ev in _session_events(workspace, sid):
            tool = _tool_name(ev)
            if not tool:
                continue
            etype = str(ev.get("type") or "")
            meta = ev.get("metadata") or {}
            kinds.setdefault(tool, set()).add(
                "UNMAPPED" if meta.get("unmapped_tool") else etype
            )
            if tool in seen:
                continue
            seen[tool] = _resolve_with_tier(ev, etype, tt)
    if not seen:
        print("no tools recorded yet — run some agent sessions first")
        return
    print(_c(f"{'TOOL':36s} {'KIND':14s} {'TAGS':30s} TIER", _BOLD))
    for tool in sorted(seen):
        tags, tier = seen[tool]
        tag_s = ", ".join(sorted(tags)) if tags else _c("(untagged)", _DIM)
        tier_c = {"explicit": _GREEN, "_meta": _CYAN,
                  "default": _YELLOW}.get(tier, _DIM)
        tool_kinds = kinds.get(tool) or set()
        kind_s = ", ".join(sorted(tool_kinds)) or "-"
        kind_c = _RED if "UNMAPPED" in tool_kinds else _DIM
        print(f"{tool:36s} {_c(f'{kind_s:14s}', kind_c)} {tag_s:30s} "
              f"{_c(tier, tier_c)}")
    unmapped = sorted(t for t, k in kinds.items() if "UNMAPPED" in k and t in seen)
    if unmapped:
        print(_c(
            f"\n{len(unmapped)} of {len(seen)} tools UNMAPPED — reaching policy as "
            f"opaque tool_result, not as shell/file_write/network:",
            _RED,
        ))
        print(_c(f"  {', '.join(unmapped)}", _RED))
        print(_c("  each needs a branch in its agent's normalizer "
                 "(prismor/runtime/hooks.py)", _DIM))
    enabled = "enabled" if tt.get("enabled") else "disabled"
    print(_c(f"\ntool_tags: {enabled}, mode={tt.get('mode', 'observe')}", _DIM))


# ── subcommand: provenance ───────────────────────────────────────────────────

def tags_provenance(workspace: Path, path: Optional[str] = None) -> None:
    """Who wrote the artifacts agents are reading, and who has read them.

    The audit half of cross-agent flow control: the causal edges Prismor
    recorded, whether or not any of them tripped a rule.
    """
    from prismor.runtime import provenance

    store = provenance.store_path()
    try:
        data = json.loads(store.read_text(encoding="utf-8"))
        artifacts = data.get("artifacts") or {}
    except Exception:
        artifacts = {}
    if path:
        key = provenance.resolve(path, workspace)
        entry = artifacts.get(key)
        if not entry:
            print(f"no provenance recorded for {key}")
            return
        artifacts = {key: entry}
    if not artifacts:
        print("no artifact provenance recorded yet")
        print(_c("  agents have not written any file another agent then read, "
                 "or tool_tags is disabled", _DIM))
        return

    def _ts(entry):
        return (entry.get("writer") or {}).get("ts", 0)

    for key, entry in sorted(artifacts.items(), key=lambda kv: -_ts(kv[1])):
        writer = entry.get("writer") or {}
        readers = entry.get("readers") or []
        tags = ", ".join(entry.get("tags") or []) or _c("(none)", _DIM)
        crossed = [r for r in readers if r.get("session") != writer.get("session")]
        print(_c(key, _BOLD))
        print(f"  tags     {tags}")
        print(f"  written  {writer.get('agent', '?')}:{writer.get('session', '?')}"
              f" via {writer.get('tool') or '?'} {_c(_when(writer.get('ts')), _DIM)}")
        if not readers:
            print(_c("  read     (not read back yet)", _DIM))
        for r in readers:
            mark = _c(" cross-agent", _YELLOW) if r in crossed else ""
            print(f"  read     {r.get('agent', '?')}:{r.get('session', '?')}"
                  f" via {r.get('tool') or '?'} {_c(_when(r.get('ts')), _DIM)}{mark}")
        print()
    print(_c(f"{len(artifacts)} artifact(s) — {store}", _DIM))


def _when(ts: Any) -> str:
    if not isinstance(ts, (int, float)) or not ts:
        return ""
    import datetime

    return datetime.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M")


# ── subcommands: set / rm ────────────────────────────────────────────────────

def tags_set(workspace: Path, tool: str, tags: List[str]) -> None:
    bad = [t for t in tags if not _valid_tag(t)]
    if bad:
        print(_c(f"invalid tag(s): {', '.join(bad)} "
                 f"(allowed: [a-z0-9][a-z0-9_.-]*)", _RED))
        sys.exit(1)
    data = _load_policy_file(workspace)
    tt = _tt_block(data)
    m = tt.setdefault("tags", {})
    existing = m.get(tool)
    merged = sorted(set(
        (existing if isinstance(existing, list) else [existing] if existing else [])
    ) | set(tags))
    m[tool] = merged
    _save_policy_file(workspace, data)
    print(f"{_c('tagged', _GREEN)} {tool} -> [{', '.join(merged)}]")
    _org_managed_hint(workspace)


def _valid_tag(tag: str) -> bool:
    import re

    return bool(re.match(r"^[a-z0-9][a-z0-9_.\-]*$", tag))


def tags_rm(workspace: Path, tool: str, tag: Optional[str]) -> None:
    data = _load_policy_file(workspace)
    tt = _tt_block(data)
    m = tt.get("tags") or {}
    if tool not in m:
        print(_c(f"no explicit mapping for '{tool}' in {_policy_path(workspace)}",
                 _YELLOW))
        sys.exit(1)
    if tag is None:
        del m[tool]
        print(f"{_c('removed', _GREEN)} mapping for {tool}")
    else:
        cur = m[tool] if isinstance(m[tool], list) else [m[tool]]
        cur = [t for t in cur if t != tag]
        if cur:
            m[tool] = cur
        else:
            del m[tool]
        print(f"{_c('removed', _GREEN)} tag '{tag}' from {tool}")
    _save_policy_file(workspace, data)


# ── subcommand: rules ────────────────────────────────────────────────────────

def _active_rules(tt: Dict[str, Any]) -> List[CompiledRule]:
    return compile_tool_tag_rules(tt)


def rules_list(workspace: Path) -> None:
    tt = _effective_tool_tags(workspace)
    rules = _active_rules(tt)
    print(_c(f"{'#':>2s}  {'RULE':56s} {'ACTION':7s} SOURCE", _BOLD))
    for i, r in enumerate(rules):
        if r.source in ("incompatible", "default"):
            expr = " with ".join(sorted(r.steps[0]))
            src = "legacy" if r.source == "incompatible" else "default"
        else:
            expr = r.source
            src = "rule"
        act_c = _RED if r.action == "block" else _YELLOW
        print(f"{i:2d}  {expr:56s} {_c(r.action, act_c):16s} {_c(src, _DIM)}")
    print(_c("\nadd:  prismor tags rules add \"untrusted_content then "
             "critical_action -> block\"", _DIM))


def rules_add(workspace: Path, expr: str) -> None:
    try:
        rule = compile_rule(expr)
    except ParseError as err:
        _print_parse_error(err)
        sys.exit(1)
    data = _load_policy_file(workspace)
    tt = _tt_block(data)
    lst = tt.setdefault("rules", [])
    if expr.strip() in [str(e).strip() for e in lst]:
        print(_c("rule already present", _YELLOW))
        return
    lst.append(expr.strip())
    _save_policy_file(workspace, data)
    steps = " -> ".join("+".join(sorted(s)) for s in rule.steps)
    print(f"{_c('added', _GREEN)} [{rule.action}] {steps}")
    _org_managed_hint(workspace)


def rules_rm(workspace: Path, which: str) -> None:
    data = _load_policy_file(workspace)
    tt = _tt_block(data)
    lst = tt.get("rules") or []
    removed = None
    if which.isdigit():
        # index into the ACTIVE rule listing = local rules come first there
        # only if they are the workspace's; safer: index into the local list.
        i = int(which)
        if 0 <= i < len(lst):
            removed = lst.pop(i)
    else:
        for i, e in enumerate(lst):
            e_str = e if isinstance(e, str) else str((e or {}).get("expr", ""))
            if e_str.strip() == which.strip():
                removed = lst.pop(i)
                break
    if removed is None:
        print(_c(f"no local rule matching '{which}' in {_policy_path(workspace)} "
                 "(org/default rules can't be removed here)", _YELLOW))
        sys.exit(1)
    _save_policy_file(workspace, data)
    print(f"{_c('removed', _GREEN)} {removed}")


# ── subcommand: lint ─────────────────────────────────────────────────────────

def tags_lint(workspace: Path, file: Optional[str]) -> None:
    import yaml

    path = Path(file) if file else _policy_path(workspace)
    if not path.exists():
        print(_c(f"no policy file at {path}", _YELLOW))
        sys.exit(1)
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except Exception as exc:
        print(_c(f"YAML error: {exc}", _RED))
        sys.exit(1)
    tt = ((data.get("settings") or {}).get("tool_tags") or {})
    exprs: List[str] = []
    for entry in tt.get("rules") or []:
        if isinstance(entry, str):
            exprs.append(entry)
        elif isinstance(entry, dict) and isinstance(entry.get("expr"), str):
            exprs.append(entry["expr"])
        else:
            print(_c(f"bad rule entry (not a string or {{expr}} map): {entry!r}",
                     _RED))
            sys.exit(1)
    errors = lint_rules(exprs)
    for _, err in errors:
        _print_parse_error(err)
    ok = len(exprs) - len(errors)
    # Legacy list sanity too.
    legacy = tt.get("incompatible") or []
    bad_legacy = [s for s in legacy
                  if not isinstance(s, (list, tuple)) or len(set(s)) < 2]
    for s in bad_legacy:
        print(_c(f"legacy incompatible entry needs >=2 tags: {s!r}", _RED))
    if errors or bad_legacy:
        print(_c(f"\n{len(errors) + len(bad_legacy)} error(s), {ok} rule(s) OK",
                 _RED))
        sys.exit(1)
    print(_c(f"all good: {ok} rule expression(s), "
             f"{len(legacy)} legacy set(s)", _GREEN))


# ── subcommand: test (log replay) ────────────────────────────────────────────

class _ReplayLedger(TagLedger):
    """In-memory ledger for dry-runs: never reads or writes the real
    per-session ledger files under /trifecta/."""

    def _load(self) -> None:  # pragma: no cover - trivially empty
        pass

    def _commit(self, new_tags, index: int, tool: str) -> None:
        # Persistence seam: apply to the in-memory view only, so a replay can
        # never write into (or be polluted by) real enforcement state.
        self._apply(new_tags, index, tool)


def tags_test(
    workspace: Path,
    session: Optional[str] = None,
    last: int = 5,
    extra_rules: Optional[List[str]] = None,
    fail_on_hit: bool = False,
) -> None:
    tt = dict(_effective_tool_tags(workspace))
    if extra_rules:
        errors = lint_rules(extra_rules)
        if errors:
            for _, err in errors:
                _print_parse_error(err)
            sys.exit(1)
        tt["rules"] = list(tt.get("rules") or []) + list(extra_rules)
    rules = compile_tool_tag_rules(tt)

    if session:
        sessions = [(session, None)]
    else:
        sessions = _recent_sessions(workspace, last)
        if not sessions:
            print("no recorded sessions to replay")
            return

    total_hits = 0
    for sid, _path in sessions:
        events = _session_events(workspace, sid)
        if not events:
            continue
        ledger = _ReplayLedger(workspace, sid)
        hits: List[Dict[str, Any]] = []
        for idx, ev in enumerate(events):
            etype = str(ev.get("type") or "")
            tool = _tool_name(ev)
            tags = classify_tool_tags(ev, etype, set(), tt)
            if not tags:
                continue
            done = ledger.completes_rules(tags, rules, idx)
            if done is not None:
                hits.append({"index": idx, "tool": tool, "done": done})
                if done.get("action") == "block":
                    # a blocked call would not have executed: don't record
                    continue
            ledger.record(tags, idx, tool)
        label = _c(sid[:24], _BOLD)
        if not hits:
            print(f"{label}  {_c('clean', _GREEN)} ({len(events)} events)")
            continue
        total_hits += len(hits)
        print(f"{label}  {len(hits)} hit(s) in {len(events)} events")
        for h in hits:
            d = h["done"]
            verdict = ("WOULD BLOCK" if d.get("action") == "block"
                       else "WOULD WARN")
            v_c = _RED if d.get("action") == "block" else _YELLOW
            steps = d.get("steps") or [d["set"]]
            combo = " then ".join("+".join(s) for s in steps)
            print(f"  [{h['index']:3d}] {_c(verdict, v_c)} {h['tool']}")
            print(f"        rule: {combo}"
                  + (f"  ({d['source']})" if d.get("source") else ""))
            intro = d.get("introduced_by") or {}
            for t, info in sorted(intro.items()):
                print(_c(f"        prior: {t} by '{info.get('tool', '?')}' "
                         f"at event {info.get('index')}", _DIM))
    if total_hits:
        print(_c(f"\n{total_hits} total hit(s) — dry run only, nothing was "
                 "blocked", _BOLD))
    if fail_on_hit and total_hits:
        sys.exit(1)


# ── subcommand: edit (interactive wizard) ────────────────────────────────────

def tags_edit(workspace: Path) -> None:
    """Line-based interactive wizard: tag tools, add/remove rules, flip mode.
    Works in any terminal (no raw-tty requirement)."""
    data = _load_policy_file(workspace)
    tt_local = _tt_block(data)
    dirty = False
    while True:
        tt = _effective_tool_tags(workspace)
        # merge unsaved local edits over the effective view for display
        merged = {**tt, **{k: v for k, v in tt_local.items() if v not in (None, {})}}
        print()
        print(_c("── prismor tags: interactive ──", _BOLD))
        enabled = "on" if merged.get("enabled") else "off"
        print(f"  tool_tags: {enabled}, mode={merged.get('mode', 'observe')}"
              + (_c("  (unsaved changes)", _YELLOW) if dirty else ""))
        print("""  [1] list tools + tags     [4] add rule expression
  [2] tag a tool            [5] remove local rule
  [3] list rules            [6] toggle enabled / mode
  [s] save & exit           [q] quit without saving""")
        try:
            choice = input("> ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            return
        if choice == "1":
            tags_list(workspace)
        elif choice == "2":
            tool = input("tool name (or glob, e.g. mcp__crm__*): ").strip()
            raw = input("tags (space-separated): ").strip()
            tags = [t for t in raw.split() if t]
            if not tool or not tags:
                print(_c("need a tool and at least one tag", _YELLOW))
                continue
            bad = [t for t in tags if not _valid_tag(t)]
            if bad:
                print(_c(f"invalid tag(s): {', '.join(bad)}", _RED))
                continue
            m = tt_local.setdefault("tags", {})
            m[tool] = sorted(set(
                (m.get(tool) if isinstance(m.get(tool), list) else [])) | set(tags))
            dirty = True
            print(f"{_c('staged', _GREEN)} {tool} -> {m[tool]}")
        elif choice == "3":
            rules_list(workspace)
        elif choice == "4":
            expr = input("rule (e.g. untrusted_content then critical_action"
                         " -> block): ").strip()
            try:
                rule = compile_rule(expr)
            except ParseError as err:
                _print_parse_error(err)
                continue
            tt_local.setdefault("rules", []).append(expr)
            dirty = True
            print(f"{_c('staged', _GREEN)} [{rule.action}] {expr}")
        elif choice == "5":
            lst = tt_local.get("rules") or []
            if not lst:
                print(_c("no local rules", _YELLOW))
                continue
            for i, e in enumerate(lst):
                print(f"  [{i}] {e}")
            which = input("remove #: ").strip()
            if which.isdigit() and 0 <= int(which) < len(lst):
                removed = lst.pop(int(which))
                dirty = True
                print(f"{_c('staged removal', _GREEN)} {removed}")
        elif choice == "6":
            cur_e = bool(tt_local.get("enabled",
                                      _effective_tool_tags(workspace).get("enabled")))
            ans = input(f"enabled? [y/n] (now {'y' if cur_e else 'n'}): ").strip().lower()
            if ans in ("y", "n"):
                tt_local["enabled"] = ans == "y"
                dirty = True
            mode = input("mode [observe/enforce] (empty = keep): ").strip().lower()
            if mode in ("observe", "enforce"):
                tt_local["mode"] = mode
                dirty = True
        elif choice == "s":
            _save_policy_file(workspace, data)
            print(_c(f"saved {_policy_path(workspace)}", _GREEN))
            _org_managed_hint(workspace)
            return
        elif choice == "q":
            if dirty:
                ans = input("discard unsaved changes? [y/N]: ").strip().lower()
                if ans != "y":
                    continue
            return
