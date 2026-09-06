"""Tool-combination governance — customizable tags + forbidden combinations.

The generalized "lethal trifecta": tools carry one or more customizable **tags**,
and an org declares **incompatible** tag sets that must not co-occur within a
single session. The tool call that *completes* a forbidden combination is blocked
before it executes, from the session's prior tool-use history.

Red/blue is just the default instance: two tags ``untrusted_content`` (reads
attacker-influenceable input) and ``critical_action`` (sends / publishes /
destroys externally), with one incompatible set ``[untrusted_content,
critical_action]``. Orgs can define any tags and any N-tag combinations (e.g. a
three-condition ``[untrusted_content, private_data, external_comms]``).

This module owns the swappable *detection* (tagging + per-session ledger);
``policy_engine`` owns *enforcement* (emitting the finding). Detection can be
swapped (strict combination now, risk scoring later) without touching
enforcement.
"""
from __future__ import annotations

import fnmatch
import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

# Default tag vocabulary (the red/blue pair, in PDF language).
UNTRUSTED = "untrusted_content"
CRITICAL = "critical_action"

# ── Built-in default tagging ──────────────────────────────────────────────────
# (matcher, match_type, [tags]). Kept in sync with the enterprise premium catalog
# so the capability degrades safely to these defaults when no signed catalog /
# org override is present. Every matching entry's tags are unioned.
TOOL_TAG_DEFAULTS = [
    # untrusted-content ingest
    ("WebFetch", "exact", [UNTRUSTED]),
    ("WebSearch", "exact", [UNTRUSTED]),
    ("mcp__*__read_email", "glob", [UNTRUSTED]),
    ("mcp__*__list_emails", "glob", [UNTRUSTED]),
    ("mcp__*__read_calendar", "glob", [UNTRUSTED]),
    ("mcp__*__get_issue", "glob", [UNTRUSTED]),
    ("mcp__*__read_channel", "glob", [UNTRUSTED]),
    ("mcp__*__read_document", "glob", [UNTRUSTED]),
    ("mcp__*__*fetch*", "glob", [UNTRUSTED]),
    ("mcp__*__*scrape*", "glob", [UNTRUSTED]),
    # critical action
    ("mcp__*__send_email", "glob", [CRITICAL]),
    ("mcp__*__post_message", "glob", [CRITICAL]),
    ("mcp__*__create_pull_request", "glob", [CRITICAL]),
    ("mcp__*__upload_file", "glob", [CRITICAL]),
    ("mcp__*__execute_sql", "glob", [CRITICAL]),
    ("mcp__*__*delete*", "glob", [CRITICAL]),
    ("mcp__*__*create*", "glob", [CRITICAL]),
]

# Default incompatible set when the policy declares none (the red/blue rule).
DEFAULT_INCOMPATIBLE = [[UNTRUSTED, CRITICAL]]

# Inference fallback: event types → an implied tag.
#
# `untrusted_content` means *attacker-influenceable* input, so this set is
# deliberately narrow. Two event types that look like ingest are handled by
# their own rules below instead of living here:
#
#   file_read    Reading a file inside the workspace is the single most common
#                thing an agent does (see the corpus in tests/test_modes.py).
#                Tagging it untrusted made `untrusted_content then
#                critical_action -> block` fire on read-then-anything, which
#                ends the session on its first shell call. Only a read from
#                OUTSIDE the workspace root carries the tag — see
#                `_is_external_read`.
#   tool_result  The canonical fall-through for any tool an adapter does not
#                map (hooks._unmapped_tool_event), which locally means Grep,
#                Glob, Task, TodoWrite — none of them external ingest. Only an
#                MCP tool result is attacker-influenceable, so the tag is
#                scoped to events the normalizer marked with an mcp_server.
#
# Neither narrowing loses the tools that matter: WebFetch and WebSearch are
# tagged by name in TOOL_TAG_DEFAULTS, which resolves before inference runs.
_UNTRUSTED_EVENT_TYPES = {"memory", "subagent_spawn"}
_CRITICAL_EVENT_TYPES = {"file_write", "shell"}
_CRITICAL_FINDING_CATEGORIES = {
    "destructive_command",
    "secret_exfiltration",
    "db_modification",
    "remote_execution",
}


def _as_list(v: Any) -> List[str]:
    if isinstance(v, str):
        return [v]
    if isinstance(v, (list, tuple)):
        return [str(x) for x in v]
    return []


def _matches(tool_name: str, matcher: str, match_type: str) -> bool:
    if not tool_name:
        return False
    if match_type == "exact":
        return tool_name == matcher
    if match_type == "glob":
        return fnmatch.fnmatchcase(tool_name, matcher)
    if match_type == "regex":
        import re
        try:
            return re.search(matcher, tool_name) is not None
        except re.error:
            return False
    # A bare mapping entry with no explicit type: treat as glob if it has wildcard
    # metacharacters, else exact.
    if any(c in matcher for c in "*?["):
        return fnmatch.fnmatchcase(tool_name, matcher)
    return tool_name == matcher


def _tool_name(event: Dict[str, Any]) -> str:
    meta = event.get("metadata") or {}
    return str(meta.get("tool_name") or event.get("tool_name") or "")


def normalize_incompatible(raw: Any) -> List[Set[str]]:
    """Coerce the policy's ``incompatible`` list into a list of tag sets.
    Falls back to the default red/blue pair when unset/empty."""
    out: List[Set[str]] = []
    if isinstance(raw, (list, tuple)):
        for item in raw:
            tags = {str(t) for t in _as_list(item)}
            if len(tags) >= 2:  # a single-tag "set" can never be a combination
                out.append(tags)
    if not out:
        out = [set(s) for s in DEFAULT_INCOMPATIBLE]
    return out


# Tags derived from the egress verdict rather than from the tool's identity.
# They give the tag-rule DSL destination awareness it otherwise cannot express:
# `untrusted_content then egress.offlist -> block` stops an injected agent from
# shipping what it just read to somewhere the fleet never approved, which no
# amount of tool-name tagging can catch (the tool is a perfectly ordinary Bash).
EGRESS_OFFLIST = "egress.offlist"
EGRESS_DENIED = "egress.denied"

_EGRESS_RULE_TAGS = {
    "egress-allowlist": EGRESS_OFFLIST,
    "egress-deny": EGRESS_DENIED,
}


def egress_tags(findings: Optional[list] = None) -> Set[str]:
    """Map this event's egress + data-boundary findings to tags.

    Egress: ``egress.offlist`` / ``egress.denied``. Data boundary: ``data.<class>``
    (``data.email``, ``data.secret``, …), ``data.self`` when the datum is the
    user's own identity, and ``dest.<tier>`` (``dest.external``, ``dest.untrusted``)
    — so a tag rule can say ``untrusted_content then data.email with dest.external
    -> block``. Empty when both are off.
    """
    out: Set[str] = set()
    for f in findings or []:
        f = f or {}
        tag = _EGRESS_RULE_TAGS.get(str(f.get("ruleId") or ""))
        if tag:
            out.add(tag)
        for cls in f.get("dataClasses") or []:
            out.add(f"data.{cls}")
        if f.get("dataSubject") == "self":
            out.add("data.self")
        if f.get("destTrust"):
            out.add(f"dest.{f.get('destTrust')}")
    return out


def tool_tags_for_agent(
    tt_settings: Optional[Dict[str, Any]],
    agent_name: str,
) -> Dict[str, Any]:
    """Resolve ``settings.tool_tags`` for one agent.

    A policy attached to an agent in the control plane ships as an overlay under
    ``settings.tool_tags.agents[<agent name>]``, mirroring the shape
    ``settings.egress.agents`` already uses so the two channels behave the same
    way.

    TIGHTEN-ONLY, deliberately. The overlay may add tag mappings and rules and
    raise the mode to enforce; it can never remove a tag, drop a rule, or lower
    the mode. An agent's name is asserted by its own process — it arrives in the
    event, not from any credential — so a permissive overlay would be a way for
    a compromised agent to name itself out of the fleet's policy. Adding
    restrictions is safe under the same assumption; removing them is not.
    """
    tt = tt_settings or {}
    if not agent_name:
        return tt
    agents = tt.get("agents")
    if not isinstance(agents, dict):
        return tt
    sub = agents.get(agent_name)
    if not isinstance(sub, dict) or not sub:
        return tt

    merged = dict(tt)

    # Tag mappings union per tool, so an overlay adds tags rather than
    # replacing whatever the fleet already assigned to that tool.
    base_map = tt.get("tags") if isinstance(tt.get("tags"), dict) else {}
    over_map = sub.get("tags") if isinstance(sub.get("tags"), dict) else {}
    if over_map:
        combined = {k: list(_as_list(v)) for k, v in base_map.items()}
        for tool, val in over_map.items():
            combined[tool] = sorted(set(combined.get(tool, [])) | set(_as_list(val)))
        merged["tags"] = combined

    # Rules and legacy incompatible sets append; neither list can be shortened.
    for key in ("rules", "incompatible"):
        extra = sub.get(key)
        if isinstance(extra, (list, tuple)) and extra:
            merged[key] = list(tt.get(key) or []) + list(extra)

    # Mode escalates only. observe -> enforce is a tighten; the reverse is not.
    if str(sub.get("mode", "")).lower() == "enforce":
        merged["mode"] = "enforce"

    return merged


def _is_external_read(event: Dict[str, Any], workspace: Optional[Path]) -> bool:
    """Whether a ``file_read`` reaches outside the workspace it is scoped to.

    A read of the repo the agent was pointed at is ordinary work and carries no
    ``untrusted_content``; a read of ``~/.ssh/id_rsa``, ``/tmp/downloaded.json``,
    or another checkout is content nobody in this session vouched for.

    Unknown workspace resolves to *not external*. That is deliberate: this
    function decides whether to attach a tag that, combined with the default
    trifecta rule, denies every subsequent shell call. Guessing "untrusted"
    whenever the workspace cannot be resolved would reinstate exactly the
    session-ending behaviour this narrowing exists to remove, on the paths where
    we know the least. Detection of what the read actually touched stays with
    the secret-access rules, which match on path and never on session history.
    """
    if workspace is None:
        return False
    path = str(event.get("path") or "")
    if not path:
        return False
    try:
        root = Path(workspace).resolve()
        target = Path(path).expanduser()
        if not target.is_absolute():
            target = root / target
        # Prefix comparison rather than Path.is_relative_to: that is 3.9+ and
        # this package declares >=3.8. The separator guard is what keeps
        # /srv/apple from reading as inside /srv/app. Both sides are resolved,
        # so a symlink out of the workspace correctly reads as external.
        root_str = str(root)
        target_str = str(target.resolve())
        return not (
            target_str == root_str or target_str.startswith(root_str + os.sep)
        )
    except (OSError, ValueError):
        # Unresolvable path (broken symlink, bad bytes): treat as in-workspace
        # for the same reason as an unknown workspace.
        return False


def classify_tool_tags(
    event: Dict[str, Any],
    event_type: str,
    finding_categories: Optional[set] = None,
    tt_settings: Optional[Dict[str, Any]] = None,
    extra_tags: Optional[Set[str]] = None,
    workspace: Optional[Path] = None,
) -> Set[str]:
    """Return the set of tags for a tool call.

    Resolution: explicit org map → server-declared ``_meta`` tags → built-in
    defaults → event/finding inference. Each tier unions all matching entries;
    the first non-empty tier wins (the org admin always beats a server's
    self-declaration, which beats generic globs).

    ``extra_tags`` are unioned onto whichever tier wins rather than competing
    with it — they describe the call's *destination* (see :func:`egress_tags`),
    not its identity, so they must not suppress the tool's own tags.

    ``workspace`` scopes the file-read inference: see :func:`_is_external_read`.
    Omitted, every read counts as in-workspace.
    """
    base = _classify_base(
        event, event_type, finding_categories, tt_settings, workspace
    )
    return base | (extra_tags or set())


def _classify_base(
    event: Dict[str, Any],
    event_type: str,
    finding_categories: Optional[set] = None,
    tt_settings: Optional[Dict[str, Any]] = None,
    workspace: Optional[Path] = None,
) -> Set[str]:
    tt = tt_settings or {}
    tool_name = _tool_name(event)
    tags: Set[str] = set()

    # 1. Explicit org/catalog map: {tool_or_glob: tag | [tags]}.
    mapping = tt.get("tags") or {}
    if isinstance(mapping, dict):
        if tool_name in mapping:
            tags |= set(_as_list(mapping[tool_name]))
        for pat, val in mapping.items():
            if pat != tool_name and _matches(tool_name, pat, "auto"):
                tags |= set(_as_list(val))
    if tags:
        return tags

    # 1.5. Server-declared tags (MCP `_meta.prismor.tags`), stamped onto the
    # event by the gateway at tools/list time. Already sanitized there.
    if tt.get("meta_tags_enabled", True):
        meta_tags = (event.get("metadata") or {}).get("meta_tags")
        if isinstance(meta_tags, (list, tuple)):
            tags |= {str(t) for t in meta_tags if t}
        if tags:
            return tags

    # 2. Built-in defaults.
    if tt.get("defaults_enabled", True):
        for matcher, match_type, deftags in TOOL_TAG_DEFAULTS:
            if _matches(tool_name, matcher, match_type):
                tags |= set(deftags)
        if tags:
            return tags

    # 3. Inference (best-effort fallback).
    if tt.get("inference_enabled", True):
        fcats = finding_categories or set()
        if fcats & _CRITICAL_FINDING_CATEGORIES:
            tags.add(CRITICAL)
        if event_type == "network":
            tags.add(UNTRUSTED if event.get("response") else CRITICAL)
        elif event_type in _CRITICAL_EVENT_TYPES:
            tags.add(CRITICAL)
        elif event_type == "file_read":
            if _is_external_read(event, workspace):
                tags.add(UNTRUSTED)
        elif event_type == "tool_result":
            # Only an MCP result is remote content; a local unmapped tool is
            # not. The normalizer stamps `mcp_server`, but fall back to the tool
            # name so a hand-built or adapter-specific event still classifies.
            if event.get("mcp_server") or tool_name.startswith("mcp__"):
                tags.add(UNTRUSTED)
        elif event_type in _UNTRUSTED_EVENT_TYPES:
            tags.add(UNTRUSTED)

    return tags


def _rule_pref(match: Dict[str, Any]) -> tuple:
    """Ordering key for competing rule matches: block beats warn, then the
    larger tag set wins (clearest finding message)."""
    return (1 if match.get("action") == "block" else 0, len(match.get("set") or ()))


class TagLedger:
    """Per-session record of which tags a session has used and the tool that
    first introduced each. Persisted across hook invocations (each hook call is a
    separate process) as JSON under the central data dir, like ``_TaintStore``.
    """

    # Cap per-tag occurrence history so a chatty session can't grow the ledger
    # file unboundedly. 256 indexes per tag is far beyond any real rule depth.
    _HIST_CAP = 256

    def __init__(self, workspace: Path, session_id: str) -> None:
        safe = "".join(c if c.isalnum() or c in "._-" else "_" for c in session_id)
        from prismor.runtime.store import get_data_dir

        self._path = get_data_dir(workspace) / "trifecta" / f"{safe}.json"
        # tag -> {"index": int, "tool": str}  (first call that introduced the tag)
        self.seen: Dict[str, Dict[str, Any]] = {}
        # tag -> sorted [indexes] of every recorded occurrence (capped). Needed
        # for ordered ("then") rules; ``seen`` alone only knows first occurrence.
        self.hist: Dict[str, List[int]] = {}
        self._load()

    def _load(self) -> None:
        if not self._path.exists():
            return
        try:
            data = json.loads(self._path.read_text(encoding="utf-8"))
            s = data.get("seen")
            if isinstance(s, dict):
                self.seen = s
            h = data.get("hist")
            if isinstance(h, dict):
                self.hist = {
                    t: sorted(int(i) for i in v)
                    for t, v in h.items()
                    if isinstance(v, (list, tuple))
                }
        except Exception:
            pass
        # Pre-hist ledger files: synthesize history from first-seen so ordered
        # rules degrade to first-seen semantics instead of crashing/missing.
        for tag, info in self.seen.items():
            if tag not in self.hist and isinstance(info, dict):
                idx = info.get("index")
                if isinstance(idx, int):
                    self.hist[tag] = [idx]

    def _save(self) -> None:
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            self._path.write_text(
                json.dumps({"seen": self.seen, "hist": self.hist}, indent=2),
                encoding="utf-8",
            )
        except Exception:
            pass

    def completes(
        self, new_tags: Set[str], incompatible: List[Set[str]], current_index: int = 1 << 62
    ) -> Optional[Dict[str, Any]]:
        """If this call's ``new_tags`` complete a forbidden set that the session
        had not yet fully covered by PRIOR calls, return details of the completed
        combination; else None. The completing call is the one to block.

        Only tags introduced at an index < ``current_index`` count as prior. This
        is deliberate: the caller may re-record the current event (an idempotent
        pre-pass over session history runs before the authoritative decision), so
        the current call's own tag can already be in ``seen`` at ``current_index``
        — it must still be treated as "new", not "already seen"."""
        seen_tags = {
            t for t, info in self.seen.items()
            if isinstance(info, dict) and info.get("index", -1) < current_index
        }
        union = seen_tags | set(new_tags)
        best: Optional[Dict[str, Any]] = None
        for forbidden in incompatible:
            # Fires on every call that carries a tag of a covered forbidden set —
            # including sets already fully seen. A session that has entered the
            # forbidden state stays restricted; exempting "already complete" sets
            # would let every call after the first completion sail through (e.g.
            # a ledger populated during an observe period, or restored state).
            if forbidden <= union and (forbidden & new_tags):
                introduced = {t: self.seen[t] for t in forbidden if t in seen_tags}
                cand = {
                    "set": sorted(forbidden),
                    "this_call_tags": sorted(forbidden & set(new_tags)),
                    "introduced_by": introduced,
                }
                # Prefer the largest completed set for the clearest message.
                if best is None or len(cand["set"]) > len(best["set"]):
                    best = cand
        return best

    def completes_rules(
        self,
        new_tags: Set[str],
        rules: List[Any],
        current_index: int = 1 << 62,
    ) -> Optional[Dict[str, Any]]:
        """Generalized :meth:`completes` over compiled tag rules (see
        ``tag_rules.CompiledRule``: ``.steps`` is an ordered list of unordered
        tag sets, plus ``.action``/``.rule_id``/``.source``).

        A single-step rule reduces exactly to :meth:`completes` — including the
        "already-complete sets keep the session restricted" property. For
        ordered (multi-step) rules a greedy subsequence cursor walks ``hist``:
        each non-final step must be fully covered by occurrences strictly after
        the previous step's position; the final step must be covered by prior
        occurrences after the cursor plus this call's ``new_tags``, and this
        call must contribute at least one final-step tag (it is the call that
        gets blocked). Occurrences at index >= ``current_index`` never count as
        prior (same re-record contract as :meth:`completes`)."""
        best: Optional[Dict[str, Any]] = None
        for rule in rules:
            steps = getattr(rule, "steps", None)
            if not steps:
                continue
            final = steps[-1]
            if not (final & new_tags):
                continue
            # Walk the non-final steps as an ordered subsequence over hist.
            cursor = -1
            ok = True
            for step in steps[:-1]:
                step_pos = cursor
                for tag in step:
                    nxt = self._first_after(tag, cursor, current_index)
                    if nxt is None:
                        ok = False
                        break
                    step_pos = max(step_pos, nxt)
                if not ok:
                    break
                cursor = step_pos
            if not ok:
                continue
            # Final step: every tag covered by this call or a prior occurrence
            # after the cursor.
            for tag in final:
                if tag in new_tags:
                    continue
                if self._first_after(tag, cursor, current_index) is None:
                    ok = False
                    break
            if not ok:
                continue
            all_tags = set()
            for s in steps:
                all_tags |= s
            introduced = {
                t: self.seen[t]
                for t in all_tags
                if t in self.seen
                and isinstance(self.seen[t], dict)
                and self.seen[t].get("index", -1) < current_index
            }
            cand = {
                "set": sorted(all_tags),
                "steps": [sorted(s) for s in steps],
                "this_call_tags": sorted(final & new_tags),
                "introduced_by": introduced,
                "rule_id": getattr(rule, "rule_id", ""),
                "action": getattr(rule, "action", "block"),
                "source": getattr(rule, "source", ""),
            }
            # Prefer block over warn; among equals, the largest set for the
            # clearest message.
            if best is None or _rule_pref(cand) > _rule_pref(best):
                best = cand
        return best

    def _first_after(
        self, tag: str, after: int, current_index: int
    ) -> Optional[int]:
        """Smallest recorded occurrence index of ``tag`` with
        ``after < index < current_index``, else None."""
        for idx in self.hist.get(tag, ()):  # sorted ascending
            if idx > after and idx < current_index:
                return idx
        return None

    def _apply(self, new_tags: Set[str], index: int, tool: str) -> None:
        """Mutate the in-memory view only. The persistence seam for subclasses
        that must not touch the real ledger files (see ``tags_cli._ReplayLedger``)."""
        import bisect

        for tag in new_tags:
            prior = self.seen.get(tag)
            if not isinstance(prior, dict) or index < prior.get("index", 1 << 62):
                self.seen[tag] = {"index": index, "tool": tool}
            indexes = self.hist.setdefault(tag, [])
            if index not in indexes and len(indexes) < self._HIST_CAP:
                bisect.insort(indexes, index)

    def record(self, new_tags: Set[str], index: int, tool: str) -> None:
        """Record ``new_tags`` for this session, in memory and on disk."""
        if not new_tags:
            return
        self._commit(new_tags, index, tool)

    def _commit(self, new_tags: Set[str], index: int, tool: str) -> None:
        """Persist ``new_tags`` to the session's ledger file.

        The read-modify-write happens inside an exclusive lock and lands
        atomically, so concurrent subagents cannot drop each other's records.
        Merging into the file's *current* contents rather than writing this
        process's in-memory view is the part that matters: the in-memory copy
        was loaded before the race and may already be stale.
        """
        from prismor.runtime.store import locked_json_update

        try:
            with locked_json_update(self._path) as state:
                seen = state.get("seen")
                if not isinstance(seen, dict):
                    seen = {}
                hist = state.get("hist")
                if not isinstance(hist, dict):
                    hist = {}
                for tag in new_tags:
                    prior = seen.get(tag)
                    if not isinstance(prior, dict) or index < prior.get("index", 1 << 62):
                        seen[tag] = {"index": index, "tool": tool}
                    indexes = hist.get(tag)
                    if not isinstance(indexes, list):
                        indexes = []
                    if index not in indexes and len(indexes) < self._HIST_CAP:
                        import bisect

                        bisect.insort(indexes, index)
                    hist[tag] = indexes
                state["seen"] = seen
                state["hist"] = hist
                # Keep the in-memory view consistent with what was committed, so
                # a caller that records then re-checks sees the merged truth.
                s = state.get("seen")
                if isinstance(s, dict):
                    for tag, info in s.items():
                        if not isinstance(info, dict):
                            continue
                        prior = self.seen.get(tag)
                        if prior is None or info.get("index", 1 << 62) < prior.get("index", 1 << 62):
                            self.seen[tag] = info
                h = state.get("hist")
                if isinstance(h, dict):
                    for tag, indexes in h.items():
                        if isinstance(indexes, (list, tuple)):
                            merged = set(self.hist.get(tag, ())) | {int(i) for i in indexes}
                            self.hist[tag] = sorted(merged)[: self._HIST_CAP]
        except Exception:
            # Never break the tool call being screened over a ledger write.
            pass
