"""Enhanced decision layer — a post-processor over the engine's findings.

Opt-in (``settings.enhanced_decisions: true`` or ``PRISMOR_ENHANCED=1``); off by
default, so a vanilla install is byte-for-byte unchanged. Four levers, each
closing a measured gap (see tests/test_enhanced.py for the attack-set gate):

  1. FAST-PATH (speed): a shell call that parses to only read-only commands with
     no substitution/redirect, or a workspace-internal Read/Grep/Glob, is allowed
     without re-tiering. Only fires when the engine found NOTHING — a read-only
     looking ``cat ~/.ssh/id_rsa`` still carries its finding.

  2. EFFECT FINDINGS (security): structured extraction of harm classes the regex
     rules miss or only warn on — recursive delete of a real dir, git history
     rewrite, running a staged/vendored script, install from a non-PyPI index,
     data egress to an unapproved host. Matches on parsed argv, skips inert
     (heredoc/quoted) text, so it adds security without adding FPs.

  3. VALUE-TAINT TRIFECTA (FP down): a ``lethal_trifecta`` block is kept only when
     a token (host/URL/base64/IP) that entered via untrusted content and was
     never in a user prompt actually reaches this action — not merely "a command
     followed a read".

  4. STEP-UP TIER (FP down): ambiguous-but-consequential actions (egress that is
     not a secret, recursive delete of a workspace path, clone from an unknown
     host) return ``step_up`` (human ask) instead of a hard block.

``evaluate()`` returns the governing ``blocking`` dict (or None) in the
contract's shape; the runtime wiring is the ~6 lines at WIRING below.
``decide()`` is the pure (verdict, rule, why) form the replay harness scores.
"""
from __future__ import annotations

import os
import re
import shlex
from typing import Any, Dict, List, Optional, Tuple

from prismor.runtime import shell_context as sc

# ── parsing ──────────────────────────────────────────────────────────────
_SEP = re.compile(r"[;\n]|&&|\|\|?|&")


def segments(cmd: str) -> List[List[str]]:
    """Best-effort word split per pipeline segment. Unparseable → one opaque
    segment flagged with a leading None, which every check treats as unsafe."""
    out: List[List[str]] = []
    for part in _SEP.split(cmd):
        part = part.strip()
        if not part:
            continue
        try:
            out.append(shlex.split(part))
        except ValueError:
            out.append([None, part])  # unbalanced quotes etc.
    return out


def _argv0(seg: List[str]) -> Optional[str]:
    for w in seg:
        if w is None:
            return None
        if "=" in w and re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", w):
            continue  # leading VAR=val assignment
        return w.rsplit("/", 1)[-1]
    return None


def is_fast_path(event: Dict[str, Any]) -> bool:
    t = event.get("type")
    tool = (event.get("metadata") or {}).get("tool_name") or ""
    if t == "file_read" or tool in ("Read", "Grep", "Glob", "NotebookRead"):
        return True
    if t != "shell":
        return False
    return sc.is_readonly_shell(event.get("command") or "")


# ── effect extraction (security) ───────────────────────────────────────────
_SECRET_REF = re.compile(r"\.env\b|id_rsa|id_ed25519|\.aws/|credentials|\.ssh/|secrets?|\.pem\b|token", re.I)
_UPLOAD_FLAG = re.compile(r"^(--data|--data-binary|--data-raw|-d|-F|--form|-T|--upload-file)$|^-X$")
_PRIVATE_HOST = re.compile(r"^(localhost|127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|::1|.*\.local|.*\.internal\.test)")
_RAW_IP = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def _hosts(seg: List[str]) -> List[str]:
    hs = []
    for w in seg:
        if not isinstance(w, str):
            continue
        m = re.search(r"https?://([^/\s:]+)", w)
        if m:
            hs.append(m.group(1))
        m = re.match(r"(?:\w+@)?([\w.-]+):", w)  # scp/git user@host:path
        if m and "." in m.group(1):
            hs.append(m.group(1))
    return hs


def _external_hosts(seg):
    return [h for h in _hosts(seg) if not _PRIVATE_HOST.match(h) or _RAW_IP.match(h)]


#: Common code forges — a clone from one of these is routine, not "untrusted".
_APPROVED_HOST = re.compile(r"(?:^|\.)(github\.com|gitlab\.com|bitbucket\.org|codeberg\.org|sr\.ht)$", re.I)
_VARREF = re.compile(r"^\$\{?([A-Za-z_]\w*)\}?$")


def _assignments(segs) -> Dict[str, str]:
    """VAR -> value for every ``VAR=value`` token across the command, so a
    ``rm -rf $DIR`` can be judged by what ``DIR`` was set to earlier."""
    out: Dict[str, str] = {}
    for seg in segs:
        for w in seg:
            if not isinstance(w, str):
                continue
            m = re.match(r"^([A-Za-z_]\w*)=(.*)$", w)
            if m:
                out[m.group(1)] = m.group(2)
    return out


def _recreated_targets(segs) -> set:
    """Paths (raw token + basename) that a later ``mkdir``/``git clone``/``gh
    repo clone`` re-creates. Deleting a dir that is immediately re-made is
    scratch-prep, not destruction."""
    out: set = set()
    for seg in segs:
        a0 = _argv0(seg)
        words = [w for w in seg if isinstance(w, str)]
        if a0 == "mkdir":
            args = [w for w in words[1:] if not w.startswith("-")]
        elif a0 == "git" and "clone" in words:
            args = [w for w in words[words.index("clone") + 1:] if not w.startswith("-")]
        elif a0 == "gh" and "clone" in words:
            args = [w for w in words if not w.startswith("-")]
        else:
            continue
        for w in args:
            out.add(w)
            out.add(os.path.basename(w))
    out.discard("")
    return out


def _resolve(t: str, assigns: Dict[str, str]) -> str:
    m = _VARREF.match(t)
    return assigns.get(m.group(1), t) if m else t


def _rm_target_is_risky(t: str, assigns: Dict[str, str], recreated: set) -> bool:
    """A recursive-delete target worth an ask: a concrete, non-system,
    non-transient, non-recreated path."""
    r = _resolve(t, assigns)
    # system/home/glob targets are the core destructive-command rule's job
    if re.match(r"^(/|~|\$HOME|\*|\.\.)($|/)", r) or r in ("/", "~"):
        return False
    if _TRANSIENT_DIR.search(r) or "mktemp" in r:
        return False
    if t in recreated or r in recreated or os.path.basename(r) in recreated:
        return False
    # an unresolved bare variable with no transient/recreate signal: don't ask
    # (too noisy — scratch vars dominate real traffic); require a concrete path
    if _VARREF.match(t) and r == t:
        return False
    return True


def _created_paths(events: List[Dict[str, Any]]) -> set:
    """basenames of files written/downloaded earlier this session."""
    out = set()
    for e in events[:-1]:
        if e.get("type") == "file_write" and e.get("path"):
            out.add(os.path.basename(e["path"]))
        c = e.get("command") or ""
        for m in re.finditer(r"(?:-o|-O|>|>>)\s*([^\s;&|]+)", c):
            out.add(os.path.basename(m.group(1)))
    out.discard("")
    return out


def effect_findings(event, events) -> List[Dict[str, Any]]:
    if event.get("type") != "shell":
        return []
    cmd = event.get("command") or ""
    out: List[Dict[str, Any]] = []

    def inert(needle: str) -> bool:
        i = cmd.find(needle)
        return i >= 0 and sc.is_inert_match(cmd, i, i + len(needle))

    segs = segments(cmd)
    assigns = _assignments(segs)   # VAR -> value, across the whole command
    recreated = _recreated_targets(segs)  # dirs re-made by a later mkdir/clone
    created = None
    for seg in segs:
        a0 = _argv0(seg)
        if a0 is None:
            continue
        words = [w for w in seg if isinstance(w, str)]
        text = " ".join(words)

        # recursive delete of a concrete target (core rule covers / /etc ~ * ..)
        if a0 in ("rm", "sudo") and re.search(r"-[A-Za-z]*r", text, re.I) and re.search(r"-[A-Za-z]*f", text, re.I):
            targets = [w for w in words[1:] if not w.startswith("-") and w != "rm"]
            risky = [t for t in targets if _rm_target_is_risky(t, assigns, recreated)]
            if risky and not inert("rm"):
                out.append(_f("enh-recursive-delete", "destructive_command", "ask",
                              f"Recursive delete of {risky[0]}"))

        # git history rewrite / forced ref move
        if a0 == "git" and not inert("git"):
            if re.search(r"\breset\s+--hard\b|\bfilter-branch\b|\bpush\b[^\n]*(--force\b|\s-f\b)|\bupdate-ref\s+-d\b|\breflog\s+expire\b", text):
                out.append(_f("enh-history-rewrite", "destructive_command", "ask",
                              "Irreversible git history rewrite"))
            # clone from an *unapproved* external host (common forges and the
            # operator's own SSH host are fine; `git push` is not a clone).
            if "clone" in words:
                untrusted = [h for h in _external_hosts(seg) if not _APPROVED_HOST.search(h)]
                if untrusted:
                    out.append(_f("enh-untrusted-clone", "dependency_risk", "ask",
                                  f"Clone from unapproved host {untrusted[0]}"))

        # install from a non-PyPI index
        if a0 in ("pip", "pip3") and "install" in words:
            m = re.search(r"(?:--index-url|--extra-index-url|-i)[=\s]+(\S+)", text)
            if m and "pypi.org" not in m.group(1) and not inert("install"):
                out.append(_f("enh-alt-index", "dependency_risk", "block",
                              f"pip install from non-PyPI index {m.group(1)[:60]}"))

        # running a script staged earlier this session (vendored / downloaded)
        if a0 in ("bash", "sh", "zsh", "source", ".") or (a0 and a0.endswith(".sh")):
            if created is None:
                created = _created_paths(events)
            runs = [w for w in words if w.endswith(".sh") or os.path.basename(w) in created]
            staged = [w for w in runs if os.path.basename(w) in created]
            vendored = [w for w in runs if re.search(r"(^|/)(vendor|vendored|third[-_]?party|node_modules)/", w)]
            if (staged or vendored) and not inert(a0):
                out.append(_f("enh-staged-exec", "remote_execution", "block",
                              f"Executes staged/vendored script {(staged or vendored)[0]}"))

        # data egress (curl/wget/scp/rsync/nc to an external host)
        if a0 in ("curl", "wget", "scp", "rsync", "nc", "ncat", "socat") and not inert(a0):
            ext = _external_hosts(seg)
            if ext and not _PRIVATE_HOST.match(ext[0]):
                uploads = a0 in ("scp", "rsync") or any(_UPLOAD_FLAG.match(w) for w in words)
                refs_secret = bool(_SECRET_REF.search(text))
                raw_ip = bool(_RAW_IP.match(ext[0]))
                if uploads or a0 in ("nc", "ncat", "socat"):
                    tier = "block" if (refs_secret or raw_ip) else "ask"
                    out.append(_f("enh-egress", "secret_exfiltration" if refs_secret else "network_isolation",
                                  tier, f"Outbound data to unapproved host {ext[0]}"))
    return out


def _f(rule, cat, tier, title):
    return {"ruleId": rule, "category": cat, "enh_tier": tier, "title": title,
            "severity": "HIGH", "mode": "enforce", "source": "enhanced"}


# ── value-taint trifecta (FP down) ───────────────────────────────────────────
_TOKEN = re.compile(r"https?://[^\s'\"]+|\b[\w.-]+\.(?:com|net|org|io|dev|test|ai|sh)\b|[A-Za-z0-9+/=]{24,}|\b\d{1,3}(?:\.\d{1,3}){3}\b")


def _tokens(text: str) -> set:
    return {m.group(0).rstrip("/.,);") for m in _TOKEN.finditer(text or "")}


def taint_confirms(event, events) -> bool:
    """True when the current action carries a token that entered via untrusted
    content (tool_result / file_read / fetched page / memory) and never appeared
    in a user prompt — the real lethal-trifecta condition."""
    untrusted, prompted = set(), set()
    for e in events[:-1]:
        body = e.get("content") or e.get("url") or ""
        if e.get("type") in ("tool_result", "file_read", "memory", "network"):
            untrusted |= _tokens(body) | ({e["url"]} if e.get("url") else set())
        if e.get("type") == "prompt":
            prompted |= _tokens(e.get("prompt") or e.get("content") or "")
    untrusted -= prompted
    if not untrusted:
        return False
    cur = _tokens((event.get("command") or "") + " " + (event.get("url") or "") + " " + (event.get("path") or ""))
    return bool(cur & untrusted)


# ── combine ──────────────────────────────────────────────────────────────
#: enh tier → contract verdict (``action`` on the blocking finding).
_TIER_ACTION = {"ask": "step_up", "block": "block"}
_RANK = {"allow": 0, "ask": 1, "block": 2}
_TRANSIENT_DIR = re.compile(r"(^|/)(build|dist|out|target|node_modules|\.cache|__pycache__|\.pytest_cache|\.next|coverage|tmp|\.tmp|venv|\.venv|scratchpad)(/|$)|\.pyc$|/tmp/|/var/tmp/|/private/tmp/|/private/var/folders/|/var/folders/")


def _governing(event, events, vanilla_findings, vanilla_block) -> Optional[Dict[str, Any]]:
    """The finding that should govern, as a dict carrying an ``enh_tier`` of
    ``ask``/``block`` — or None for allow. Shared by evaluate() and decide()."""
    # Fast path only for genuinely clean events: never when a finding exists.
    if not vanilla_findings and vanilla_block is None and is_fast_path(event):
        return None

    candidates: List[Dict[str, Any]] = []
    if vanilla_block is not None:
        rid = vanilla_block.get("ruleId") or ""
        cat = vanilla_block.get("category") or ""
        cmd = event.get("command") or ""
        if cat == "lethal_trifecta":
            # keep only if a tainted value actually reaches this action
            if taint_confirms(event, events):
                candidates.append({**vanilla_block, "enh_tier": "block",
                                   "enh_why": "value-taint confirmed"})
            # else: dropped (tag-inference FP)
        elif rid == "destructive-command" and _TRANSIENT_DIR.search(cmd) and not re.search(r"\s(/|~|\$HOME|\*)(\s|$)", cmd):
            candidates.append({**vanilla_block, "enh_tier": "ask",
                               "enh_why": "recursive delete of a transient/workspace path"})
        else:
            candidates.append({**vanilla_block, "enh_tier": "block",
                               "enh_why": "vanilla block"})

    for f in effect_findings(event, events):
        candidates.append({**f, "enh_why": f["title"]})

    if not candidates:
        return None
    return max(candidates, key=lambda f: _RANK[f["enh_tier"]])


def evaluate(event, events, vanilla_findings, vanilla_block) -> Optional[Dict[str, Any]]:
    """Return the new ``blocking`` dict (contract shape, with ``action`` =
    ``block``/``step_up``) or None to allow. Drop-in replacement for the
    ``blocking`` value at the runtime seam."""
    gov = _governing(event, events, vanilla_findings, vanilla_block)
    if gov is None:
        return None
    gov = dict(gov)
    gov["action"] = _TIER_ACTION[gov.pop("enh_tier")]
    return gov


def decide(event, events, vanilla_findings, vanilla_block) -> Tuple[str, Optional[str], str]:
    """Pure (verdict, rule_id, why) form, verdict ∈ allow|ask|block. Used by the
    replay harness; evaluate() is what the runtime wires in."""
    gov = _governing(event, events, vanilla_findings, vanilla_block)
    if gov is None:
        return "allow", None, "fast-path" if is_fast_path(event) else ""
    return gov["enh_tier"], gov.get("ruleId"), gov.get("enh_why", "")


# ── WIRING (runtime.evaluate_tool_call, just after `should_block`) ───────────
# Replace the plain `blocking = should_block(findings, event)` tail with:
#
#     blocking = should_block(findings, event)
#     if blocking is None and mode == "enforce" and getattr(engine, "is_legacy_policy", False):
#         blocking = legacy_should_block(findings, event, engine.block_categories)
#     if os.environ.get("PRISMOR_ENHANCED") == "1" or getattr(engine, "enhanced_decisions", False):
#         from prismor.runtime import enhanced
#         blocking = enhanced.evaluate(event, events, findings, blocking)
#
# `blocking` keeps the contract shape, so the observe-downgrade, audit trail and
# Decision construction downstream all work unchanged; a `step_up` action
# surfaces as an ask, a `block` action as a deny.
