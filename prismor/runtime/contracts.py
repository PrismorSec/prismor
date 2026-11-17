"""Per-tool contracts — what a tool's result does to the session, and what a
call requires of it (#532).

Tags answer what a tool *is*; tag rules forbid a *sequence* of tags. Neither
can say "after this session read the private ``acme/billing`` repo it may not
post to a public issue, but may still comment on an internal ticket", because
that depends on the arguments a tool was called with and on who is allowed to
see what the session has read. A contract says both:

    tool_tags:
      contracts:
        - tool: mcp__github__get_file_contents(owner:acme, repo:billing*)
          delta: { audience: [org:acme] }
        - tool: mcp__github__create_issue
          requires: { audience_contains: [public], trust: internal }
          effects: [egress]

``delta``     how the tool's RESULT changes the session label   (post-tool)
``requires``  what the label must satisfy for the CALL to run   (pre-tool)
``effects``   side effects recorded once the call succeeds      (post-tool)

The session label has two dimensions and only ever gets more restrictive:

``audience``  the principals allowed to see what the session has read. Starts
              as ``public`` (unrestricted) and narrows by intersection.
``trust``     ``trusted`` > ``internal`` > ``untrusted``; lowers to the minimum.

Nothing here offers an operation that widens a label. :class:`SessionLabel`
stores the narrowing events themselves and folds them with a meet, so a
concurrent writer, a replay or a corrupt entry can add a restriction but never
remove one.

This module owns detection (parsing, selector matching, the label and its
store); ``policy_engine`` owns enforcement, exactly as it does for
``trifecta``. A tool with no contract produces nothing here, so the feature is
strictly additive.
"""
from __future__ import annotations

import fnmatch
import hashlib
import json
import os
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Set, Tuple

PUBLIC = "public"
TRUSTED, INTERNAL, UNTRUSTED_TRUST = "trusted", "internal", "untrusted"
#: Ascending: a label's trust only ever moves toward the front of this tuple.
TRUST_LEVELS: Tuple[str, ...] = (UNTRUSTED_TRUST, INTERNAL, TRUSTED)
_TRUST_RANK = {t: i for i, t in enumerate(TRUST_LEVELS)}

CATEGORY = "tool_contract"
RULE_PREFIX = "tool-contract:"

_FIELDS = ("tool", "args", "delta", "requires", "effects")
_DELTA_FIELDS = ("audience", "trust")
_REQUIRES_FIELDS = ("audience_contains", "trust", "effects", "no_effects")
_EFFECT_RE = re.compile(r"^[a-z0-9][a-z0-9_.\-]*$")
# A principal is an opaque name (`org:acme`, `team:billing`, `a@b.com`,
# `repo:$owner/$repo`). No whitespace or control characters: these strings can
# come from an MCP server's `_meta` and end up in a terminal.
_PRINCIPAL_RE = re.compile(r"^[^\s\x00-\x1f\x7f]{1,200}$")
_SELECTOR_RE = re.compile(r"^\s*([^()\s]+)\s*(?:\((.*)\))?\s*$", re.DOTALL)
_BIND_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_.]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)")
_MAX_LIST = 32

# Where a surface puts the structured arguments of a call. `call_args` is the
# contract-only key the gateway's result event and the LLM proxy use, so
# giving them arguments does not change what a `when:` rule reads.
_RAW_ARG_KEYS = ("tool_input", "arguments", "input", "toolInput", "toolArgs", "tool_args")
# Normalized event fields a selector may name when the tool's own argument is
# spelled differently (`Read(path:…)` where Claude's argument is `file_path`).
_EVENT_FIELDS = ("path", "url", "command", "query")
_PATH_KEYS = frozenset({"path", "file_path", "filepath", "filename", "notebook_path"})
_MISSING = object()


class ContractError(ValueError):
    """An invalid contract declaration."""


# ── principals and the label algebra ─────────────────────────────────────────

def _norm(principal: Any) -> str:
    text = str(principal).strip()
    # `Alice <alice@acme.com>` names the address, not the display name.
    m = re.search(r"<([^<>\s]+@[^<>\s]+)>", text)
    return (m.group(1) if m else text).casefold()


def _is_glob(text: str) -> bool:
    return any(c in text for c in "*?[")


class Principals:
    """The static ``tool_tags.principals`` map: principal -> its members.

    ``org:acme: [team:billing, "*@acme.com"]`` says everyone in ``team:billing``
    and every ``@acme.com`` address is inside ``org:acme``. Directory-backed
    resolution (IdP groups, channel membership) is a follow-up; v1 is this map.
    """

    def __init__(self, raw: Any = None) -> None:
        self._members: Dict[str, List[str]] = {}
        if isinstance(raw, dict):
            for key, val in raw.items():
                vals = val if isinstance(val, (list, tuple)) else [val]
                self._members[_norm(key)] = [_norm(v) for v in vals if v is not None]

    def contains(self, outer: str, inner: str, _seen: Optional[Set[str]] = None) -> bool:
        """Whether every member of ``inner`` is a member of ``outer``."""
        if outer == PUBLIC or outer == inner:
            return True
        if inner == PUBLIC:
            return False
        if _is_glob(outer) and fnmatch.fnmatchcase(inner, outer):
            return True
        seen = _seen if _seen is not None else set()
        if outer in seen:
            return False
        seen.add(outer)
        return any(self.contains(m, inner, seen) for m in self._members.get(outer, ()))

    def allows(self, audience: Iterable[str], principal: str) -> bool:
        return any(self.contains(a, principal) for a in audience)

    def meet(self, a: Iterable[str], b: Iterable[str]) -> List[str]:
        """The intersection of two audiences, as its maximal principals.

        Every element of the result is an element of ``a`` or is contained in
        one, which is the whole narrowing guarantee: a meet can drop readers
        and never add any. Two principals the map does not relate are assumed
        disjoint — unknown overlap is not overlap.
        """
        out: Set[str] = set()
        bs = list(b)
        for x in a:
            for y in bs:
                if self.contains(y, x):
                    out.add(x)
                elif self.contains(x, y):
                    out.add(y)
        return sorted(p for p in out if not any(q != p and self.contains(q, p) and not self.contains(p, q) for q in out))


def min_trust(a: str, b: str) -> str:
    return a if _TRUST_RANK.get(a, 0) <= _TRUST_RANK.get(b, 0) else b


@dataclass
class Label:
    """A session's label at one point in its history."""

    audience: List[str] = field(default_factory=lambda: [PUBLIC])
    trust: str = TRUSTED
    effects: Set[str] = field(default_factory=set)
    #: The narrowing event responsible for each dimension's current value.
    audience_since: Optional[Dict[str, Any]] = None
    trust_since: Optional[Dict[str, Any]] = None

    @property
    def restricted(self) -> bool:
        return self.audience != [PUBLIC] or self.trust != TRUSTED

    def carried(self) -> Optional[Dict[str, Any]]:
        """What an artifact this session writes should carry; None when the
        label is still the default, so an ordinary write records nothing."""
        if not self.restricted:
            return None
        return {"audience": list(self.audience), "trust": self.trust}


def narrower_or_equal(a: Label, b: Label, principals: Principals) -> bool:
    """``a`` ⊑ ``b``: no reader and no trust that ``b`` does not already have."""
    return (
        _TRUST_RANK.get(a.trust, 0) <= _TRUST_RANK.get(b.trust, 0)
        and all(principals.allows(b.audience, p) for p in a.audience)
    )


def _clean_audience(raw: Any) -> Optional[List[str]]:
    if not isinstance(raw, (list, tuple)):
        return None
    return [_norm(p) for p in raw if isinstance(p, str) and _PRINCIPAL_RE.match(p.strip())]


def fold(entries: Iterable[Dict[str, Any]], principals: Principals,
         start: Optional[Label] = None) -> Label:
    """Fold narrowing entries into a label. Meet is commutative, associative
    and idempotent, so the order entries were recorded in cannot matter."""
    label = start or Label()
    for e in entries:
        aud = _clean_audience(e.get("audience"))
        if aud is not None:
            new = principals.meet(label.audience, aud)
            if new != label.audience:
                label.audience, label.audience_since = new, e
        tr = e.get("trust")
        if tr in _TRUST_RANK and min_trust(label.trust, tr) != label.trust:
            label.trust, label.trust_since = tr, e
        for eff in e.get("effects") or ():
            if isinstance(eff, str):
                label.effects.add(eff)
    return label


class SessionLabel:
    """The persisted, narrow-only label of one session.

    Stored as the list of narrowing events rather than as a current value, for
    two reasons. The engine evaluates each event twice (an idempotent pre-pass
    over session history runs before the authoritative decision), so a check at
    index N must see only what happened before N — the same re-record contract
    ``TagLedger.completes`` follows. And a deny has to name the call that
    narrowed the label, which a bare value cannot.

    There is deliberately no method that widens: ``record`` appends a
    restriction under an exclusive lock, and :meth:`at` folds with a meet.
    """

    _CAP = 256

    def __init__(self, workspace: Path, session_id: str,
                 principals: Optional[Principals] = None) -> None:
        self.principals = principals or Principals()
        self._path = label_path(workspace, session_id)

    def _state(self) -> Dict[str, Any]:
        if not self._path.exists():
            return {}
        try:
            data = json.loads(self._path.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else {}
        except Exception:
            return {}

    def entries(self) -> List[Dict[str, Any]]:
        ents = self._state().get("entries")
        return [e for e in ents if isinstance(e, dict)] if isinstance(ents, list) else []

    def at(self, before: Optional[int] = None) -> Label:
        """The label as of events strictly before index ``before`` (all of
        them when None)."""
        state = self._state()
        base = state.get("base")
        label = fold([base], self.principals) if isinstance(base, dict) else Label()
        ents = state.get("entries")
        ents = [e for e in ents if isinstance(e, dict)] if isinstance(ents, list) else []
        ents.sort(key=lambda e: e.get("index", 0) if isinstance(e.get("index"), int) else 0)
        return fold(
            (e for e in ents
             if before is None or not isinstance(e.get("index"), int) or e["index"] < before),
            self.principals, label,
        )

    def record(self, *, index: int, key: str, tool: str, call: str = "",
               audience: Optional[Sequence[str]] = None, trust: Optional[str] = None,
               effects: Sequence[str] = (), ts: Optional[float] = None) -> None:
        """Append one narrowing event. Idempotent per ``(index, key)``."""
        if audience is None and trust is None and not effects:
            return
        entry: Dict[str, Any] = {
            "index": index, "key": key, "tool": tool, "call": call,
            "ts": int(ts if ts is not None else time.time()),
        }
        if audience is not None:
            entry["audience"] = sorted({_norm(p) for p in audience})
        if trust in _TRUST_RANK:
            entry["trust"] = trust
        if effects:
            entry["effects"] = sorted({str(e) for e in effects})
        self._commit(entry)

    def _commit(self, entry: Dict[str, Any]) -> None:
        from prismor.runtime.store import locked_json_update

        try:
            with locked_json_update(self._path) as state:
                ents = state.get("entries")
                if not isinstance(ents, list):
                    ents = []
                if any(isinstance(e, dict) and e.get("index") == entry["index"]
                       and e.get("key") == entry["key"] for e in ents):
                    return
                ents.append(entry)
                if len(ents) > self._CAP:
                    # Collapse the oldest half into one base restriction. The
                    # base always applies, so collapsing can only make an old
                    # replayed check stricter, never looser.
                    ents.sort(key=lambda e: e.get("index", 0) if isinstance(e, dict) else 0)
                    cut = len(ents) - self._CAP // 2
                    old = [e for e in ents[:cut] if isinstance(e, dict)]
                    prior = state.get("base")
                    merged = fold(([prior] if isinstance(prior, dict) else []) + old,
                                  self.principals)
                    since = merged.audience_since or merged.trust_since or old[-1]
                    state["base"] = {
                        "index": old[-1].get("index", 0), "key": "base",
                        "tool": since.get("tool", ""), "call": since.get("call", ""),
                        "ts": since.get("ts", 0),
                        "audience": merged.audience, "trust": merged.trust,
                        "effects": sorted(merged.effects),
                    }
                    ents = ents[cut:]
                state["entries"] = ents
        except Exception:
            # Never break the tool call being screened over bookkeeping.
            pass


class MemoryLabel(SessionLabel):
    """In-memory label for dry runs; never touches the session's real file."""

    def __init__(self, principals: Optional[Principals] = None) -> None:  # noqa: D401
        self.principals = principals or Principals()
        self._mem: Dict[str, Any] = {}

    def _state(self) -> Dict[str, Any]:
        return self._mem

    def _commit(self, entry: Dict[str, Any]) -> None:
        ents = self._mem.setdefault("entries", [])
        if not any(e.get("index") == entry["index"] and e.get("key") == entry["key"] for e in ents):
            ents.append(entry)


def label_path(workspace: Path, session_id: str) -> Path:
    from prismor.runtime.store import get_data_dir

    safe = "".join(c if c.isalnum() or c in "._-" else "_" for c in session_id)
    return get_data_dir(workspace) / "trifecta" / f"{safe}.label.json"


# ── contracts ────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class Contract:
    tool: str                                   # exact name or glob
    args: Tuple[Tuple[str, str], ...] = ()      # (argument, glob), declared order
    delta_audience: Optional[Tuple[str, ...]] = None
    delta_trust: Optional[str] = None
    requires_audience: Tuple[str, ...] = ()
    requires_trust: Optional[str] = None
    requires_effects: Tuple[str, ...] = ()
    forbids_effects: Tuple[str, ...] = ()
    effects: Tuple[str, ...] = ()
    source: str = "policy"                      # policy | _meta | builtin:<pack>

    @property
    def contract_id(self) -> str:
        blob = json.dumps([
            self.tool, sorted(self.args), self.delta_audience, self.delta_trust,
            sorted(self.requires_audience), self.requires_trust,
            sorted(self.requires_effects), sorted(self.forbids_effects),
            sorted(self.effects),
        ], sort_keys=True)
        return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:10]

    @property
    def selector(self) -> str:
        if not self.args:
            return self.tool
        return f"{self.tool}({', '.join(f'{k}:{v}' for k, v in self.args)})"

    @property
    def has_delta(self) -> bool:
        return self.delta_audience is not None or self.delta_trust is not None

    @property
    def has_requires(self) -> bool:
        return bool(self.requires_audience or self.requires_trust
                    or self.requires_effects or self.forbids_effects)

    def parts(self) -> List[str]:
        """Which of the three parts this contract declares, for listings."""
        return [name for name, on in (("delta", self.has_delta),
                                      ("requires", self.has_requires),
                                      ("effects", bool(self.effects))) if on]

    def matches_tool(self, tool_name: str) -> bool:
        from prismor.runtime.trifecta import _matches

        return _matches(tool_name, self.tool, "auto")

    def matches(self, tool_name: str, args: Dict[str, Any], event: Dict[str, Any],
                roots: Sequence[str] = ()) -> bool:
        if not self.matches_tool(tool_name):
            return False
        for key, pattern in self.args:
            value = lookup_arg(args, event, key)
            if value is _MISSING:
                return False
            pat = pattern.casefold()
            # Case-insensitive on purpose. `Acme/Billing` is the same repo as
            # `acme/billing`, and a selector that misses is a delta that does
            # not narrow (or a requirement that does not apply): both fail open.
            if not any(fnmatch.fnmatchcase(c.casefold(), pat)
                       for c in _candidates(value, key, roots)):
                return False
        return True


def parse_selector(text: str) -> Tuple[str, List[Tuple[str, str]]]:
    """``name(arg:glob, arg:glob)`` -> ``(name, [(arg, glob), …])``."""
    m = _SELECTOR_RE.match(text or "")
    if not m:
        raise ContractError(f"invalid tool selector '{text}' (expected name or name(arg:pattern, …))")
    args: List[Tuple[str, str]] = []
    inner = m.group(2)
    if inner is not None and inner.strip():
        for part in inner.split(","):
            key, sep, pat = part.partition(":")
            key, pat = key.strip(), pat.strip()
            if not sep or not key or not pat:
                raise ContractError(f"selector '{part.strip()}' must be arg:pattern")
            if any(k == key for k, _ in args):
                raise ContractError(f"selector names argument '{key}' twice")
            args.append((key, pat))
    return m.group(1), args


def _str_list(raw: Any, where: str, errors: List[str], *, pattern: "re.Pattern[str]",
              what: str) -> Tuple[str, ...]:
    if raw is None:
        return ()
    if isinstance(raw, str):
        raw = [raw]
    if not isinstance(raw, (list, tuple)):
        errors.append(f"{where}: must be a list of {what}s")
        return ()
    if len(raw) > _MAX_LIST:
        errors.append(f"{where}: at most {_MAX_LIST} entries")
    out: List[str] = []
    for item in raw[:_MAX_LIST]:
        if not isinstance(item, str) or not pattern.match(item.strip()):
            errors.append(f"{where}: invalid {what} {item!r}")
            continue
        out.append(item.strip())
    return tuple(out)


def parse_contract(raw: Any, source: str = "policy",
                   tool: Optional[str] = None) -> Tuple[Optional[Contract], List[str]]:
    """``(contract, errors)``. The contract is None when it cannot be used.

    ``tool`` binds a server-declared contract (which names no tool of its own)
    to the tool definition it was declared on.
    """
    errors: List[str] = []
    if not isinstance(raw, dict):
        return None, ["must be a map with a 'tool' and at least one of delta / requires / effects"]
    for key in raw:
        if key not in _FIELDS:
            errors.append(f"unknown field '{key}' (allowed: {', '.join(_FIELDS)})")

    name, sel_args = tool, []  # type: Optional[str], List[Tuple[str, str]]
    if tool is None:
        if not isinstance(raw.get("tool"), str) or not raw["tool"].strip():
            errors.append("missing 'tool'")
        else:
            try:
                name, sel_args = parse_selector(raw["tool"])
            except ContractError as exc:
                errors.append(str(exc))
    extra = raw.get("args")
    if extra is not None:
        if not isinstance(extra, dict):
            errors.append("args: must be a map of argument -> pattern")
        else:
            for k, v in extra.items():
                if isinstance(v, (dict, list)) or v is None:
                    errors.append(f"args.{k}: pattern must be a string")
                elif any(str(k) == key for key, _ in sel_args):
                    errors.append(f"args.{k}: already named in the tool selector")
                else:
                    sel_args.append((str(k), str(v)))

    delta = raw.get("delta")
    d_aud: Optional[Tuple[str, ...]] = None
    d_trust: Optional[str] = None
    if delta is not None:
        if not isinstance(delta, dict):
            errors.append("delta: must be a map")
        else:
            for key in delta:
                if key not in _DELTA_FIELDS:
                    errors.append(f"delta: unknown field '{key}' (allowed: {', '.join(_DELTA_FIELDS)})")
            if "audience" in delta:
                d_aud = _str_list(delta["audience"], "delta.audience", errors,
                                  pattern=_PRINCIPAL_RE, what="principal")
                if not d_aud:
                    errors.append("delta.audience: needs at least one principal")
                    d_aud = None
                elif any(_norm(p) == PUBLIC for p in d_aud):
                    # The one way to spell "widen": it cannot work (a meet with
                    # `public` changes nothing), so it is a mistake to surface.
                    errors.append("delta.audience: 'public' cannot widen the label "
                                  "(a delta only ever narrows)")
            if "trust" in delta:
                d_trust = delta["trust"] if delta["trust"] in _TRUST_RANK else None
                if d_trust is None:
                    errors.append(f"delta.trust: must be one of {', '.join(TRUST_LEVELS)}")
                elif d_trust == TRUSTED:
                    errors.append("delta.trust: 'trusted' cannot raise the label "
                                  "(a delta only ever lowers trust)")

    req = raw.get("requires")
    r_aud: Tuple[str, ...] = ()
    r_trust: Optional[str] = None
    r_eff: Tuple[str, ...] = ()
    r_no: Tuple[str, ...] = ()
    if req is not None:
        if not isinstance(req, dict):
            errors.append("requires: must be a map")
        else:
            for key in req:
                if key not in _REQUIRES_FIELDS:
                    errors.append(f"requires: unknown field '{key}' (allowed: {', '.join(_REQUIRES_FIELDS)})")
            r_aud = _str_list(req.get("audience_contains"), "requires.audience_contains",
                              errors, pattern=_PRINCIPAL_RE, what="principal")
            if "trust" in req:
                r_trust = req["trust"] if req["trust"] in _TRUST_RANK else None
                if r_trust is None:
                    errors.append(f"requires.trust: must be one of {', '.join(TRUST_LEVELS)}")
            r_eff = _str_list(req.get("effects"), "requires.effects", errors,
                              pattern=_EFFECT_RE, what="effect")
            r_no = _str_list(req.get("no_effects"), "requires.no_effects", errors,
                             pattern=_EFFECT_RE, what="effect")

    effects = _str_list(raw.get("effects"), "effects", errors, pattern=_EFFECT_RE, what="effect")

    if name is None:
        return None, errors
    contract = Contract(
        tool=name, args=tuple(sel_args), delta_audience=d_aud, delta_trust=d_trust,
        requires_audience=r_aud, requires_trust=r_trust, requires_effects=r_eff,
        forbids_effects=r_no, effects=effects, source=source,
    )
    if not contract.parts():
        errors.append("declares nothing: needs at least one of delta / requires / effects")
        return None, errors
    return contract, errors


def compile_contracts(raw: Any, source: str = "policy") -> List[Contract]:
    """Compile a ``contracts:`` list. An entry with any error is skipped whole
    — half a contract is not what its author wrote — and policy loading never
    crashes over one; ``prismor tags lint`` is where they surface."""
    out: List[Contract] = []
    for item in raw if isinstance(raw, (list, tuple)) else ():
        contract, errors = parse_contract(item, source)
        if contract is not None and not errors:
            out.append(contract)
    return out


def lint(tt: Any, where: str = "settings.tool_tags") -> List[str]:
    """Every problem in a tool_tags block's contract configuration."""
    errors: List[str] = []
    if not isinstance(tt, dict):
        return errors
    raw = tt.get("contracts")
    if raw is not None and not isinstance(raw, (list, tuple)):
        errors.append(f"{where}.contracts: must be a list")
    for i, item in enumerate(raw if isinstance(raw, (list, tuple)) else ()):
        for err in parse_contract(item)[1]:
            errors.append(f"{where}.contracts[{i}]: {err}")
    principals = tt.get("principals")
    if principals is not None:
        if not isinstance(principals, dict):
            errors.append(f"{where}.principals: must be a map of principal -> members")
        else:
            for key, val in principals.items():
                vals = val if isinstance(val, (list, tuple)) else [val]
                for p in [key, *vals]:
                    if not isinstance(p, str) or not _PRINCIPAL_RE.match(p.strip()):
                        errors.append(f"{where}.principals.{key}: invalid principal {p!r}")
    packs = tt.get("contract_packs")
    if packs is not None and not isinstance(packs, dict):
        errors.append(f"{where}.contract_packs: must be a map of pack -> settings")
    elif isinstance(packs, dict):
        for name in packs:
            if name not in _PACKS:
                errors.append(f"{where}.contract_packs: unknown pack '{name}' "
                              f"(known: {', '.join(sorted(_PACKS))})")
    return errors


# ── arguments, selectors and bindings ────────────────────────────────────────

def call_args(event: Dict[str, Any]) -> Dict[str, Any]:
    """The structured arguments of a call, wherever the surface put them."""
    meta = event.get("metadata")
    if not isinstance(meta, dict):
        return {}
    args = meta.get("kwargs")
    if not isinstance(args, dict):
        raw = meta.get("raw")
        if isinstance(raw, dict):
            args = next((raw[k] for k in _RAW_ARG_KEYS if isinstance(raw.get(k), dict)), None)
    if not isinstance(args, dict):
        args = meta.get("call_args")
    return args if isinstance(args, dict) else {}


def lookup_arg(args: Dict[str, Any], event: Dict[str, Any], key: str) -> Any:
    if key in args:
        return args[key]
    cur: Any = args
    for part in key.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            cur = _MISSING
            break
    if cur is _MISSING and key in _EVENT_FIELDS and event.get(key):
        return event[key]
    return cur


def _candidates(value: Any, key: str, roots: Sequence[str]) -> List[str]:
    out: List[str] = []
    for v in value if isinstance(value, (list, tuple)) else [value]:
        if isinstance(v, bool):
            out.append("true" if v else "false")
        elif isinstance(v, (str, int, float)):
            out.append(str(v))
            if key in _PATH_KEYS:
                out.extend(_path_variants(str(v), roots))
    return out


def _path_variants(text: str, roots: Sequence[str]) -> List[str]:
    """Spellings of one path a selector such as ``secrets/**`` should match:
    normalized, symlink-resolved, and relative to the workspace. Without the
    normalization ``secrets/../secrets/key`` walks past the selector."""
    forms = {text.replace("\\", "/")}
    try:
        forms.add(os.path.normpath(text).replace("\\", "/"))
        base = roots[0] if roots else ""
        full = text if os.path.isabs(os.path.expanduser(text)) or not base else os.path.join(base, text)
        forms.add(os.path.realpath(os.path.expanduser(full)).replace("\\", "/"))
    except Exception:
        pass
    out = set(forms)
    for root in roots:
        for r in {str(root), os.path.realpath(str(root))}:
            r = r.replace("\\", "/").rstrip("/")
            for p in forms:
                if r and p.casefold().startswith(r.casefold() + "/"):
                    out.add(p[len(r) + 1:])
    out |= {p[2:] for p in out if p.startswith("./")}
    return sorted(out)


def bind(template: str, args: Dict[str, Any], event: Dict[str, Any]) -> Tuple[List[str], List[str]]:
    """Resolve ``$arg`` / ``${arg.path}`` in a principal.

    Returns ``(principals, missing)``. A template that is exactly one reference
    may expand to several principals (``$to`` holding a recipient list); an
    embedded reference (``repo:$owner/$repo``) must be a scalar.
    """
    refs = [m.group(1) or m.group(2) for m in _BIND_RE.finditer(template)]
    if not refs:
        return [_norm(template)], []
    whole = _BIND_RE.fullmatch(template.strip())
    if whole:
        value = lookup_arg(args, event, refs[0])
        if isinstance(value, str):
            value = [p for p in re.split(r"[,;]", value) if p.strip()]
        if isinstance(value, (list, tuple)):
            vals = [_norm(v) for v in value if isinstance(v, (str, int, float)) and str(v).strip()]
            if vals:
                return vals, []
        return [], [refs[0]]
    missing: List[str] = []

    def _sub(m: "re.Match[str]") -> str:
        ref = m.group(1) or m.group(2)
        value = lookup_arg(args, event, ref)
        if isinstance(value, bool) or not isinstance(value, (str, int, float)) or not str(value).strip():
            missing.append(ref)
            return m.group(0)
        return str(value).strip()

    return [_norm(_BIND_RE.sub(_sub, template))], missing


# ── built-in packs ───────────────────────────────────────────────────────────
#
# Deltas only, never `requires`: a pack teaches the label what a well-known
# tool's result is, and what to do about it stays the org's decision. That is
# what keeps the packs additive -- no finding can exist until a policy
# declares a requirement.
#
# The runtime cannot see a repo's visibility or a channel's membership from a
# tool call, so v1 takes both from policy (`tool_tags.contract_packs`), the
# same way principals resolve through a static map. Lookups are a follow-up.

_GH_UGC_READ = re.compile(
    r"^(?:get|list|search|read)_.*(?:issue|pull_request|discussion|comment|review)"
    r"|^(?:issue|pull_request|discussion)_read$")
_GH_READ = re.compile(r"^(?:get|list|search|read)_|_read$")
_SLACK_READ = re.compile(
    r"(?:read|history|get|list|search|fetch).*(?:channel|message|thread|conversation|repl)"
    r"|conversations_(?:history|replies)")


def _mcp_parts(tool_name: str) -> Optional[Tuple[str, str]]:
    if not tool_name.startswith("mcp__"):
        return None
    server, sep, tool = tool_name[len("mcp__"):].rpartition("__")
    return (server, tool) if sep and server and tool else None


def _glob_map(raw: Any) -> List[Tuple[str, Optional[List[str]]]]:
    """``[glob, …]`` or ``{glob: audience}`` -> ``[(glob, audience | None)]``."""
    if isinstance(raw, dict):
        out = []
        for k, v in raw.items():
            aud = [v] if isinstance(v, str) else list(v) if isinstance(v, (list, tuple)) else None
            aud = [a for a in (aud or []) if isinstance(a, str) and _PRINCIPAL_RE.match(a.strip())]
            out.append((str(k), aud or None))
        return out
    if isinstance(raw, str):
        raw = [raw]
    return [(str(g), None) for g in raw] if isinstance(raw, (list, tuple)) else []


def _github_pack(tool_name: str, tool: str, args: Dict[str, Any], cfg: Dict[str, Any]) -> List[Contract]:
    if not _GH_READ.search(tool):
        return []
    ugc = bool(_GH_UGC_READ.search(tool))
    owner, repo = args.get("owner"), args.get("repo")
    full = ""
    if isinstance(owner, str) and isinstance(repo, str) and owner and repo:
        full = f"{owner}/{repo}"
    else:
        for key in ("repo", "repository", "repo_full_name", "full_name"):
            if isinstance(args.get(key), str) and "/" in args[key]:
                full = args[key]
                break
    if full:
        for glob, aud in _glob_map(cfg.get("private")):
            if fnmatch.fnmatchcase(full.casefold(), glob.casefold()):
                # A private repo: its readers are the audience, and what its
                # members wrote in an issue is internal, not attacker-authored.
                return [Contract(
                    tool=tool_name,
                    delta_audience=tuple(aud or [f"repo:{full.casefold()}"]),
                    delta_trust=INTERNAL if ugc else None,
                    source="builtin:github",
                )]
    # Public, or not known to be private: anyone can write an issue body.
    if ugc:
        return [Contract(tool=tool_name, delta_trust=UNTRUSTED_TRUST, source="builtin:github")]
    return []


def _slack_pack(tool_name: str, tool: str, args: Dict[str, Any], cfg: Dict[str, Any]) -> List[Contract]:
    if not _SLACK_READ.search(tool):
        return []
    globs = [g for g, _ in _glob_map(cfg.get("connect_channels"))]
    for key in ("channel", "channel_id", "channel_name", "channelId"):
        value = args.get(key)
        if not isinstance(value, str) or not value:
            continue
        name = value.lstrip("#").casefold()
        if any(fnmatch.fnmatchcase(name, g.lstrip("#").casefold()) for g in globs):
            # A Slack Connect channel has members from outside the org.
            return [Contract(tool=tool_name, delta_trust=UNTRUSTED_TRUST, source="builtin:slack")]
    return []


_PACKS: Dict[str, Callable[[str, str, Dict[str, Any], Dict[str, Any]], List[Contract]]] = {
    "github": _github_pack,
    "slack": _slack_pack,
}


def builtin_contracts(tool_name: str, args: Dict[str, Any], tt: Dict[str, Any]) -> List[Contract]:
    parts = _mcp_parts(tool_name)
    if parts is None:
        return []
    server, tool = parts[0].casefold(), parts[1].casefold()
    packs = tt.get("contract_packs") if isinstance(tt.get("contract_packs"), dict) else {}
    out: List[Contract] = []
    for name, fn in _PACKS.items():
        cfg = packs.get(name)
        if cfg is False or (isinstance(cfg, dict) and cfg.get("enabled") is False):
            continue
        if name in server:
            out.extend(fn(tool_name, tool, args, cfg if isinstance(cfg, dict) else {}))
    return out


# ── resolution ───────────────────────────────────────────────────────────────

def enabled(tt: Optional[Dict[str, Any]]) -> bool:
    return bool((tt or {}).get("contracts_enabled", True))


def _roots(event: Dict[str, Any], workspace: Optional[Path]) -> List[str]:
    cwd = (event.get("metadata") or {}).get("cwd") if isinstance(event.get("metadata"), dict) else None
    return [str(r) for r in (cwd, workspace) if r]


def meta_contracts(event: Dict[str, Any], tool_name: str) -> List[Contract]:
    raw = (event.get("metadata") or {}).get("meta_contract")
    items = raw if isinstance(raw, list) else [raw] if isinstance(raw, dict) else []
    out: List[Contract] = []
    for item in items[:8]:
        contract, errors = parse_contract(item, "_meta", tool=tool_name)
        if contract is not None and not errors:
            out.append(contract)
    return out


def resolve(event: Dict[str, Any], tt: Optional[Dict[str, Any]],
            workspace: Optional[Path] = None) -> Tuple[List[Contract], str]:
    """Every contract that governs this call, and the tier they came from.

    Same order as tags: explicit policy, then what the MCP server declared on
    the tool (``_meta.prismor.contract``), then the built-in packs. The first
    tier with a match wins; within it every match applies, which is safe to
    do because a contract can only restrict.
    """
    tt = tt or {}
    from prismor.runtime.trifecta import _tool_name

    tool = _tool_name(event)
    if not tool:
        return [], "-"
    args = call_args(event)
    roots = _roots(event, workspace)
    hit = [c for c in compile_contracts(tt.get("contracts")) if c.matches(tool, args, event, roots)]
    if hit:
        return hit, "policy"
    if tt.get("meta_contracts_enabled", True):
        hit = [c for c in meta_contracts(event, tool) if c.matches(tool, args, event, roots)]
        if hit:
            return hit, "_meta"
    if tt.get("contract_defaults_enabled", True):
        hit = builtin_contracts(tool, args, tt)
        if hit:
            return hit, "builtin"
    return [], "-"


def contracts_for_tool(tool_name: str, tt: Optional[Dict[str, Any]]) -> Tuple[List[Contract], str]:
    """Contracts that could govern ``tool_name``, ignoring argument selectors.
    For listings and coverage, where there is a tool but no call."""
    tt = tt or {}
    hit = [c for c in compile_contracts(tt.get("contracts")) if c.matches_tool(tool_name)]
    if hit:
        return hit, "policy"
    if tt.get("contract_defaults_enabled", True):
        parts = _mcp_parts(tool_name)
        if parts:
            server, tool = parts[0].casefold(), parts[1].casefold()
            if ("github" in server and _GH_UGC_READ.search(tool)) or (
                    "github" in server and _GH_READ.search(tool)
                    and (tt.get("contract_packs") or {}).get("github")):
                return [Contract(tool=tool_name, delta_trust=UNTRUSTED_TRUST,
                                 source="builtin:github")], "builtin"
            if "slack" in server and _SLACK_READ.search(tool) and (
                    (tt.get("contract_packs") or {}).get("slack")):
                return [Contract(tool=tool_name, delta_trust=UNTRUSTED_TRUST,
                                 source="builtin:slack")], "builtin"
    return [], "-"


# ── screening ────────────────────────────────────────────────────────────────

def describe_call(tool: str, contract: Optional[Contract], args: Dict[str, Any],
                  event: Dict[str, Any]) -> str:
    """``tool(acme/billing)``: the tool and the values its selector matched on.

    Selector values only. They are what the policy author already chose to
    name (an owner, a repo, a path); the rest of a call's arguments can hold
    anything, and this string is persisted and shown in deny messages.
    """
    vals: List[str] = []
    for key, _ in (contract.args if contract else ()):
        value = lookup_arg(args, event, key)
        if isinstance(value, (str, int, float)) and not isinstance(value, bool):
            vals.append(str(value)[:60])
    return f"{tool}({'/'.join(vals)})" if vals else tool


def _fmt_set(items: Iterable[str]) -> str:
    return "{" + ", ".join(sorted(items)) + "}"


def _since(entry: Optional[Dict[str, Any]]) -> str:
    if not entry:
        return ""
    when = ""
    ts = entry.get("ts")
    if isinstance(ts, (int, float)) and ts:
        when = " at " + time.strftime("%H:%M", time.localtime(ts))
    return f" since {entry.get('call') or entry.get('tool') or 'an earlier call'}{when}"


def _short(tool: str) -> str:
    parts = _mcp_parts(tool)
    return parts[1] if parts else tool


@dataclass
class Violation:
    contract: Contract
    message: str


def check_requires(contracts: Sequence[Contract], label: Label, principals: Principals,
                   tool: str, args: Dict[str, Any], event: Dict[str, Any]) -> List[Violation]:
    """Which requirements this call fails against ``label``."""
    out: List[Violation] = []
    name = _short(tool)
    for c in contracts:
        if c.requires_audience and label.audience != [PUBLIC]:
            needed: List[str] = []
            unbound: List[str] = []
            for template in c.requires_audience:
                got, missing = bind(template, args, event)
                needed.extend(got)
                unbound.extend(missing)
            lacking = [p for p in needed if not principals.allows(label.audience, p)]
            if unbound:
                # Fail closed: a recipient that cannot be read off the call
                # cannot be shown to be a valid reader of what was read.
                out.append(Violation(c, (
                    f"{name} requires audience ⊇ {_fmt_set(c.requires_audience)}, but "
                    f"argument {', '.join(sorted(set(unbound)))} is missing from the call; "
                    f"session audience is {_fmt_set(label.audience)}{_since(label.audience_since)}")))
            elif lacking:
                out.append(Violation(c, (
                    f"{name} requires audience ⊇ {_fmt_set(lacking)}; session audience is "
                    f"{_fmt_set(label.audience)}{_since(label.audience_since)}")))
        if c.requires_trust and _TRUST_RANK[label.trust] < _TRUST_RANK[c.requires_trust]:
            out.append(Violation(c, (
                f"{name} requires trust ≥ {c.requires_trust}; session trust is "
                f"{label.trust}{_since(label.trust_since)}")))
        absent = [e for e in c.requires_effects if e not in label.effects]
        if absent:
            out.append(Violation(c, (
                f"{name} requires effect(s) {_fmt_set(absent)} to have happened in this "
                f"session; recorded so far: {_fmt_set(label.effects)}")))
        present = [e for e in c.forbids_effects if e in label.effects]
        if present:
            out.append(Violation(c, (
                f"{name} is not allowed after effect(s) {_fmt_set(present)} "
                "in this session")))
    return out


def apply_result(store: SessionLabel, contracts: Sequence[Contract], *, index: int,
                 tool: str, args: Dict[str, Any], event: Dict[str, Any]) -> None:
    """Record what a completed call's contracts do to the session label."""
    for c in contracts:
        audience: Optional[List[str]] = None
        if c.delta_audience is not None:
            audience = []
            for template in c.delta_audience:
                # An unbound reference stays in the principal as written. No
                # real principal is contained in `repo:$owner/$repo`, so the
                # label fails closed, and still says which binding failed.
                audience.extend(bind(template, args, event)[0] or [_norm(template)])
        store.record(
            index=index, key=f"contract:{c.contract_id}", tool=tool,
            call=describe_call(tool, c, args, event),
            audience=audience, trust=c.delta_trust, effects=c.effects,
            ts=_event_ts(event),
        )


def inherit(store: SessionLabel, carried: Any, *, index: int, path: str,
            writer: Dict[str, Any], tool: str, event: Dict[str, Any]) -> None:
    """Narrow this session by the label(s) an artifact it read was written
    under. ``carried`` is the provenance entry's ``labels`` list."""
    for n, lab in enumerate(carried if isinstance(carried, list) else ()):
        if not isinstance(lab, dict):
            continue
        aud = _clean_audience(lab.get("audience"))
        store.record(
            index=index, key=f"artifact:{path}:{n}", tool=tool,
            call=(f"{tool}({Path(path).name}) written by "
                  f"{writer.get('agent', '?')}:{str(writer.get('session', '?'))[:8]}"),
            audience=aud,
            trust=lab.get("trust") if lab.get("trust") in _TRUST_RANK else None,
            ts=_event_ts(event),
        )


def _event_ts(event: Dict[str, Any]) -> Optional[float]:
    ts = event.get("ts")
    if isinstance(ts, (int, float)):
        return float(ts)
    if isinstance(ts, str) and ts:
        try:
            from datetime import datetime

            return datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp()
        except ValueError:
            return None
    return None


def is_failure(event: Dict[str, Any]) -> bool:
    """A post event reporting that the call did not succeed. Its result was
    never read and its side effects never happened."""
    return "fail" in str(event.get("agent_event") or "").lower()


def result_unseen(event: Dict[str, Any]) -> bool:
    """Whether this surface will never deliver the call's result as an event
    of its own. The LLM proxy screens a tool call the model *proposed*; the
    result comes back inside the next prompt, attributed to nothing. For such
    a call the delta is applied when the call is admitted, which is early but
    never late."""
    return bool((event.get("metadata") or {}).get("proposed"))


def finding_for(violations: Sequence[Violation], *, tool: str, index: int,
                session_id: str, mode: str) -> Dict[str, Any]:
    first = violations[0]
    rid = f"{RULE_PREFIX}{first.contract.contract_id}"
    fid = f"{rid}-{index}"
    return {
        "id": f"{session_id}:{fid}" if session_id else fid,
        "severity": "HIGH",
        "category": CATEGORY,
        "title": f"Tool contract: {first.message}",
        "evidence": (
            "; ".join(v.message for v in violations)
            + f"; rule: {rid} [{first.contract.selector}] ({first.contract.source})"
        ),
        "eventIndex": index,
        "ruleId": rid,
        "action": "block",
        "mode": mode,
    }
