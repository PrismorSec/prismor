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

A third tag, ``untrusted_influence``, marks a critical call whose own
arguments demonstrably came from untrusted content this session read. It is
what makes the combination rules usable: "fetched a README, then pushed my own
branch" is a sequence, not an attack, and only influence separates the two.
See :class:`GramStore`.

This module owns the swappable *detection* (tagging + per-session ledger);
``policy_engine`` owns *enforcement* (emitting the finding). Detection can be
swapped (strict combination now, risk scoring later) without touching
enforcement.
"""
from __future__ import annotations

import fnmatch
import hashlib
import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

# Default tag vocabulary (the red/blue pair, in PDF language).
UNTRUSTED = "untrusted_content"
CRITICAL = "critical_action"
# Set on a critical call whose arguments carry content the session read from an
# untrusted source. Sequence alone is far too common to block on; influence is
# the part that indicates the untrusted content is steering the action.
INFLUENCE = "untrusted_influence"

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
    # Browser surfaces: the page a tab is showing is authored by whoever owns
    # the site. Tab/window metadata is not, and is deliberately absent here --
    # tagging it untrusted was a top false-positive source in the session
    # corpus replay.
    ("mcp__*__navigate", "glob", [UNTRUSTED]),
    ("mcp__*__read_page", "glob", [UNTRUSTED]),
    ("mcp__*__get_page_text", "glob", [UNTRUSTED]),
    # Inbox-shaped readers beyond the ones above.
    ("mcp__*__get_message", "glob", [UNTRUSTED]),
    ("mcp__*__get_thread", "glob", [UNTRUSTED]),
    ("mcp__*__search_threads", "glob", [UNTRUSTED]),
    ("mcp__*__list_comments", "glob", [UNTRUSTED]),
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
# Kept for the legacy `incompatible:` surface; DEFAULT_RULES is what a policy
# that declares nothing actually gets.
DEFAULT_INCOMPATIBLE = [[UNTRUSTED, CRITICAL]]

# What an org gets by turning tool_tags on and configuring nothing.
#
# The blocking rule requires INFLUENCE, not merely the sequence. Sequence alone
# fired on 213 of 391 real development sessions -- read a README, then push a
# branch -- which is not a control anyone keeps enabled. The same replay with
# influence required fired once. The sequence itself is still worth seeing, so
# it stays as a warn.
DEFAULT_RULES = [
    f"{CRITICAL} with {INFLUENCE} -> block",
    f"{UNTRUSTED} then {CRITICAL} -> warn",
]

# Inference fallback, for tools the tiers above did not name.
#
# Both halves are deliberately narrow, because a tag here feeds combination
# rules that deny a call outright. Replaying the default rule over 391 real
# development sessions showed the wide version firing on 54% of them: reads of
# the user's own transcripts and scratchpad, subagent spawns and browser tab
# metadata supplied "untrusted", while `grep`/`ls`/`find` supplied "critical"
# merely by being shell. None of those is attacker-authored input or an
# irreversible action, and a control that stops one session in two is a control
# nobody leaves on.
#
# What is inferred now:
#   untrusted   content that came back from off-machine: a network event
#               carrying a RESPONSE, or a shell command that fetches (curl,
#               wget) once its output is in hand. Requests going out are not
#               ingest. The shell half is not optional -- an agent that reaches
#               the web through Bash rather than a fetch tool is the common
#               case, not the exotic one, and without it such a session never
#               becomes untrusted and nothing it writes carries anything.
#   critical    an action the rule engine already judged irreversible or
#               externally visible (the categories below). Judgement stays with
#               the rules, which match on what the command does, not on the
#               event being a shell at all.
#
# Everything else that matters is named in TOOL_TAG_DEFAULTS or by the org, and
# resolves before inference runs. Content read from a file is handled by
# provenance instead of by the file's location: see prismor.runtime.provenance,
# which knows that /tmp/notes.md holds what another agent fetched from the web
# while ~/.claude/settings.json does not.
_CRITICAL_FINDING_CATEGORIES = {
    "destructive_command",
    "secret_exfiltration",
    "db_modification",
    "remote_execution",
    # Writes to /etc/sudoers, shell rc files, launch agents and the like. The
    # auth-file-write / persistence rules already match these paths, so the tag
    # follows their verdict rather than re-implementing the path list.
    "privilege_escalation",
    "persistence",
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


# Commands that pull content off the network. Deliberately a short list of
# fetchers rather than "anything with a URL in it": `git clone` and `pip
# install` also reach the network, but what they bring back is code the agent
# runs, which the supply-chain rules already judge, not text it reads and acts
# on.
_FETCH_RE = re.compile(
    r"(?:^|[;&|]\s*|\$\(|`)\s*(?:sudo\s+)?(?:curl|wget|http|https|xh)\b",
    re.IGNORECASE,
)


def is_network_fetch(command: str) -> bool:
    """Whether a shell command pulls content in from the network."""
    return bool(command) and _FETCH_RE.search(command) is not None


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


def classify_tool_tags(
    event: Dict[str, Any],
    event_type: str,
    finding_categories: Optional[set] = None,
    tt_settings: Optional[Dict[str, Any]] = None,
    extra_tags: Optional[Set[str]] = None,
) -> Set[str]:
    """Return the set of tags for a tool call.

    Resolution: explicit org map → server-declared ``_meta`` tags → built-in
    defaults → event/finding inference. Each tier unions all matching entries;
    the first non-empty tier wins (the org admin always beats a server's
    self-declaration, which beats generic globs).

    ``extra_tags`` are unioned onto whichever tier wins rather than competing
    with it — they describe the call's *destination* (see :func:`egress_tags`),
    not its identity, so they must not suppress the tool's own tags.

    """
    base = _classify_base(event, event_type, finding_categories, tt_settings)
    return base | (extra_tags or set())


def _classify_base(
    event: Dict[str, Any],
    event_type: str,
    finding_categories: Optional[set] = None,
    tt_settings: Optional[Dict[str, Any]] = None,
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
        if (finding_categories or set()) & _CRITICAL_FINDING_CATEGORIES:
            tags.add(CRITICAL)
        if event.get("response") and (
            event_type == "network"
            or (event_type == "shell" and is_network_fetch(str(event.get("command") or "")))
        ):
            tags.add(UNTRUSTED)

    return tags


# ── Influence: did the untrusted content actually steer this call? ───────────
#
# "Read a page, then run a command" is what a working day looks like; "read a
# page, then run a command the page dictated" is the attack. The difference is
# whether text from the untrusted content reappears in the critical call's own
# arguments.
#
# The test is a shared distinctive token 3-gram. Whole-session bag, hashed, so
# no untrusted text is persisted; the readable phrase is recovered from the
# call side (which we hold in memory) when reporting. Replayed over 391 real
# sessions this fired on 1, against 213 for sequence alone, and it still caught
# the cross-agent handoff attack in the lab -- the injected `DROP TABLE users`
# reached the database call verbatim, as injected instructions must, since a
# command the agent alters no longer does what the attacker asked.
#
# ponytail: whole-session gram bag, not per-source. Upgrade to per-artifact
# gram sets if a session needs to say WHICH untrusted source steered the call.

_GRAM_N = 3
_GRAM_TOKEN = re.compile(r"[A-Za-z0-9_./:@-]{3,}")
# Tokens too common to make a 3-gram distinctive. Small and deliberately
# boring: the n-gram does the work, this only trims the noise floor.
_GRAM_STOP = frozenset("""
the and for with that this from into out you are not have has was were will
can use used using run file files line lines error errors true false null none
http https com www github org net all any new old get set add one two
""".split())


def content_grams(text: str, limit: int = 200_000) -> Dict[str, str]:
    """Map ``{hash: readable phrase}`` for the distinctive 3-grams in ``text``.

    Hashing keeps the persisted side small and free of untrusted text; the
    readable half is only ever used for the call being screened.
    """
    if not text:
        return {}
    toks = [
        t.lower() for t in _GRAM_TOKEN.findall(text[:limit])
        if t.lower() not in _GRAM_STOP
    ]
    out: Dict[str, str] = {}
    for i in range(len(toks) - _GRAM_N + 1):
        phrase = " ".join(toks[i:i + _GRAM_N])
        out[hashlib.blake2b(phrase.encode("utf-8"), digest_size=5).hexdigest()] = phrase
    return out


def call_text(event: Dict[str, Any]) -> str:
    """The text a call is asking for -- what an injected instruction has to
    reach for the injection to have worked.

    Arguments only, never the call's own result: a critical call is screened
    before it runs, and its output would say nothing about what steered it.
    """
    parts: List[str] = []
    for key in ("command", "path", "url", "content", "query", "body"):
        val = event.get(key)
        if val:
            parts.append(str(val))
    raw = (event.get("metadata") or {}).get("raw")
    if isinstance(raw, dict):
        args = raw.get("tool_input") or raw.get("arguments") or raw.get("input")
        if args:
            try:
                parts.append(json.dumps(args, sort_keys=True))
            except Exception:
                parts.append(str(args))
    return "\n".join(parts)


class GramStore:
    """Hashed n-grams of the untrusted content one session has read, each
    remembering which source it arrived from.

    The origin is the reason to keep this rather than a plain set: when a
    critical call reuses one of these phrases, the store can say the text came
    from ``claude:s-1a2b -> /repo/plan.md``, which is the causal chain the
    block is actually about. Only the hash is persisted, so no untrusted text
    is written to disk; readable phrases come from the call being screened,
    which is already in memory.

    A sidecar to :class:`TagLedger` rather than a field on it, and loaded only
    on the two events that need it (untrusted content arriving, a critical call
    being screened), so the ordinary tool call never pays to read it.
    """

    _CAP = 5000  # ~60KB on disk; oldest grams drop first

    def __init__(self, workspace: Path, session_id: str) -> None:
        safe = "".join(c if c.isalnum() or c in "._-" else "_" for c in session_id)
        from prismor.runtime.store import get_data_dir

        self._path = get_data_dir(workspace) / "trifecta" / f"{safe}.grams.json"

    def add(self, text: str, origin: str = "", index: int = 0) -> None:
        """Record the grams of untrusted content that arrived from ``origin``."""
        grams = content_grams(text)
        if not grams:
            return
        from prismor.runtime.store import locked_json_update

        try:
            with locked_json_update(self._path) as state:
                known = state.get("grams")
                if not isinstance(known, dict):
                    known = {}
                origins = state.get("origins")
                if not isinstance(origins, list):
                    origins = []
                label = origin or "untrusted content"
                if label in origins:
                    oid = origins.index(label)
                else:
                    origins.append(label)
                    oid = len(origins) - 1
                for h in grams:
                    known.setdefault(h, [oid, index])
                if len(known) > self._CAP:
                    # dicts keep insertion order: drop the oldest grams
                    known = dict(list(known.items())[-self._CAP:])
                state["grams"] = known
                state["origins"] = origins[-64:] if len(origins) > 64 else origins
        except Exception:
            pass

    def hits(self, text: str, before: Optional[int] = None) -> Dict[str, str]:
        """``{phrase: origin}`` for text this call shares with untrusted content.

        Only content recorded at an index strictly below ``before`` counts, the
        same re-record contract :meth:`TagLedger.completes` follows and for the
        same reason: an idempotent pre-pass over session history runs before the
        authoritative decision, so this very event's content is already on disk
        by the time the call is screened. Without the bound, a tool that both
        reads untrusted content and acts -- or any post-action event whose
        result echoes its own arguments -- reports itself as steered by itself.
        """
        grams = content_grams(text)
        if not grams or not self._path.exists():
            return {}
        try:
            state = json.loads(self._path.read_text(encoding="utf-8"))
            known = state.get("grams") or {}
            origins = state.get("origins") or []
        except Exception:
            return {}
        out: Dict[str, str] = {}
        for h, phrase in grams.items():
            rec = known.get(h)
            if rec is None:
                continue
            oid, idx = (rec if isinstance(rec, list) else [rec, -1])[:2]
            if before is not None and isinstance(idx, int) and idx >= before:
                continue
            out[phrase] = (
                origins[oid] if isinstance(oid, int) and 0 <= oid < len(origins)
                else "untrusted content"
            )
        return out


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
