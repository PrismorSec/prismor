"""prismor/runtime/server.py — local HTTP API server for the Prismor dashboard.

Serves a self-contained web dashboard and session/findings data from all
registered workspace DBs.  No external dependencies beyond the stdlib and
a single CDN link (Chart.js) loaded by the browser.

Usage (via CLI):
    python3 prismor/runtime/cli.py serve [--port 7070] [--host 127.0.0.1]

Read endpoints:
    GET /                  → self-hosted HTML dashboard
    GET /health            → {"status": "ok", "ts": "<iso>"}
    GET /api/stats         → aggregate stats for charts/KPIs
    GET /api/sessions      → paginated sessions  (?page&limit&sort&dir)
    GET /api/findings      → paginated findings  (?page&limit&agent&severity&category&q)
    GET /api/events        → paginated events    (?page&limit&verdict&agent)
    GET /api/supply-chain  → supply chain enforcement stats
    GET /api/workspaces    → registered workspaces + enrollment status
    GET /api/policy        → all policy layers for a workspace (?workspace=…)
    GET /api/agents        → agent registry merged with per-agent call stats
    POST /api/extensions/toggle → turn an extension off or on ({id, enabled})
    GET /api/docs          → bundled docs (?name=<file.md> one doc, ?q=… search)
    GET /api/query-prompt  → copy-paste prompt teaching an agent to query the store
    GET /metrics           → Prometheus text exposition (see docs/observability.md)
    GET /api/sessions/:id/control → scoped rules + recent blocks for a session
    GET /api/sessions/:id/dev → what went wrong + what changed (devlog.py)
    GET /api/files         → files agents wrote (?q=… path filter)
    GET /api/blame         → agent sessions that wrote ?path=…[&line=N], with diffs
    GET /api/hooks         → every hook run across Claude Code sessions: runs, timing, failures, sessions (?days=7)
    GET /api/friction      → failures recurring across sessions (?workspace=…&days=14)

Write endpoints (human-only — localhost):
    PUT /api/policy/global         → body: {yaml} — write ~/.prismor/policy.yaml
    PUT /api/policy/project        → body: {yaml, workspace} — write project policy
    POST /api/agents/:name         → body: {enabled?, mode?, iam_profile?}
    PATCH /api/sessions/:id/control → body: {action, workspace, …data}
    POST /api/pause                → body: {paused} — `prismor pause` / `prismor resume`
    POST /api/update               → `prismor update`
    (GET /api/runtime: versions + pause state; GET /api/changelog: notes since the installed version)

Every request passes ``_request_allowed``: no CORS, a loopback-only Host header
(DNS rebinding), same-origin only (CSRF), and a token when bound off loopback.
"""
from __future__ import annotations

import hmac
import ipaddress
import json
import os
import re
import secrets
import sys
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse, parse_qs, unquote, urlsplit

from prismor.runtime.store import (
    get_aggregate_stats,
    get_sessions_page,
    get_mcp_usage,
    get_dependency_usage,
    get_hook_stats,
    get_network_calls,
    get_findings_page,
    get_events_page,
    get_supply_chain_stats,
    get_token_stats,
    get_agents_overview,
    list_registered_workspaces,
    get_enrollment,
    read_policy_layer,
    add_egress_host,
    get_egress_config,
    get_policy_precedence,
    is_policy_editable,
    remove_egress_host,
    set_egress_option,
    write_policy_layer,
    get_policy_rule_catalog,
    set_project_rule_states,
    get_session_scoped_detail,
    update_session_control,
    initialize_database,
    _migrate_workspace_runtime_state,
    prismor_home,
)

_DASHBOARD_HTML = Path(__file__).with_name("dashboard.html")
# Chart.js, marked and the logo ship with the package: a CDN copy left the
# dashboard on its loading screen with no network (initCharts threw first).
_STATIC_DIR = Path(__file__).with_name("static")
_STATIC_TYPES = {".js": "text/javascript; charset=utf-8", ".png": "image/png"}


def _mirror_server_names(workspace: Path) -> set:
    """Names of MCP servers configured as Prismor's mirror (built-ins served
    in-process). Detected by ``mirror:true`` / ``type:mirror`` in a gateway
    config, or a command that runs ``mcp-gateway --mirror``."""
    import json as _json
    from prismor.runtime.mcp_gateway import DEFAULT_GATEWAY_CONFIG
    names: set = set()
    candidates = [workspace / ".mcp.json", DEFAULT_GATEWAY_CONFIG,
                  Path.home() / ".prismor" / "mcp-gateway.json"]
    for path in candidates:
        try:
            data = _json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        servers = data.get("mcpServers") or data.get("servers") or {}
        if not isinstance(servers, dict):
            continue
        for name, cfg in servers.items():
            if not isinstance(cfg, dict):
                continue
            if cfg.get("mirror") is True or str(cfg.get("type") or "").lower() == "mirror":
                names.add(str(name))
            args = cfg.get("args") or []
            if isinstance(args, list) and "--mirror" in [str(a) for a in args]:
                names.add(str(name))
    return names


def _mcp_server_inventory(workspace: Path):
    """One registry of the MCP servers Prismor fronts, each with its tools and
    current per-tool handling (allow / ask / deny). The mirror server lists the
    built-ins it serves (static); other servers list the tools that already
    carry a policy (exact rosters are only known once a tool is called).
    """
    from prismor.runtime.agents import load_agents_config
    from prismor.runtime.scoped_agent import discover_mcp_families
    from prismor.runtime import mirror

    cfg = load_agents_config(workspace)
    deny = set(cfg.get("global_deny_tools") or [])
    ask = set(cfg.get("global_ask_tools") or [])

    def _state(tag: str) -> str:
        return "deny" if tag in deny else ("ask" if tag in ask else "allow")

    mirror_names = _mirror_server_names(workspace)
    servers = []

    # The mirror: its tools are the built-ins, tagged by their NATIVE names
    # (that is how they reach policy), so the grid here drives the same rules
    # that screen a hooked Bash/Read. It also carries two front-of-house
    # controls: `override` (replace the native toolkit or not) and a per-tool
    # `enabled` roster (which built-ins the mirror exposes at all).
    mcfg = mirror.mirror_config(workspace)
    disabled = set(mcfg["disabled_tools"])
    # A `prismor pause` outranks the switch: the mirror is passing through
    # regardless of what the switch says, and the card must say so rather than
    # show "Governing" while nothing is being blocked.
    paused = None
    try:
        from prismor.runtime import pause as _pause
        paused = _pause.active_state()
    except Exception:
        paused = None
    paused_until = ""
    if paused and paused.get("until"):
        try:
            from datetime import datetime as _dt
            paused_until = _dt.fromtimestamp(float(paused["until"])).strftime("%H:%M")
        except Exception:
            paused_until = ""
    for name in sorted(mirror_names):
        servers.append({
            "name": name, "kind": "mirror",
            "override": mcfg["override"],
            "paused": paused is not None,
            "paused_until": paused_until,
            "paused_by_org": bool(paused and paused.get("source") == "org"),
            "tools": [{"name": t, "tag": t, "state": _state(t),
                       "enabled": t not in disabled}
                      for t in mirror.mirror_tool_names()],
        })

    # Other configured servers: name from discovery, tools = whatever already
    # has a policy under mcp__<server>__*. Tool tags for a real server are
    # namespaced, so a policy set here scopes to that one server's tool.
    seen = set(mirror_names)
    for fam in discover_mcp_families(workspace):
        # fam is "mcp__<server>__*"
        if not (fam.startswith("mcp__") and fam.endswith("__*")):
            continue
        server = fam[len("mcp__"):-len("__*")]
        if server in seen:
            continue
        seen.add(server)
        prefix = f"mcp__{server}__"
        tools = sorted({t for t in (deny | ask) if t.startswith(prefix)})
        servers.append({
            "name": server, "kind": "remote", "family": fam,
            "tools": [{"name": t[len(prefix):], "tag": t, "state": _state(t)}
                      for t in tools],
        })
    return _enrich_mcp_inventory(workspace, servers, seen)


def _enrich_mcp_inventory(workspace: Path, servers, seen):
    """Attach where each server is declared (config file, agent, transport,
    command or URL, whether it is behind the gateway) and what it has been
    doing (calls, blocks, sessions, last call, per tool) over the last week.
    Servers declared in a config but not reaching policy are appended as
    ``direct`` so the page shows coverage, not just what is governed."""
    from dataclasses import asdict
    records = []
    try:
        from prismor.runtime.discover import discover_mcp
        records = discover_mcp(workspace)
    except Exception:
        records = []
    by_name = {}
    for r in records:
        if r.is_gateway:
            continue
        by_name.setdefault(r.name.lower(), []).append(asdict(r))

    def _decl(name: str):
        return by_name.get(name.lower()) or []

    usage = {}
    try:
        usage = get_mcp_usage()
    except Exception:
        usage = {}

    for s in servers:
        decl = _decl(s["name"])
        s["declared_in"] = [{
            "source": d["source"], "agent": d["agent"], "transport": d["transport"],
            "command": " ".join(d["command"] or []), "url": d["url"],
            "managed": d["managed"], "workspace_scoped": d["workspace_scoped"],
        } for d in decl]
        s["managed"] = s["kind"] == "mirror" or any(d["managed"] for d in decl)
        s["risk"] = max((d["risk"] for d in decl), key=_RISK_RANK.get, default="none")
        s["findings"] = sorted({f for d in decl for f in (d["findings"] or [])})
        u = usage.get(s["name"]) or {}
        s["usage"] = {k: u.get(k, 0 if k in ("calls", "blocked", "sessions") else "")
                      for k in ("calls", "blocked", "sessions", "last", "lastAbs")}
        tools_seen = (u.get("tools") or {})
        have = {t["name"] for t in s["tools"]}
        prefix = "" if s["kind"] == "mirror" else f"mcp__{s['name']}__"
        for name in sorted(tools_seen):
            if name not in have:
                tag = name if s["kind"] == "mirror" else prefix + name
                s["tools"].append({"name": name, "tag": tag, "state": "allow"})
        for t in s["tools"]:
            tu = tools_seen.get(t["name"]) or {}
            t["calls"] = tu.get("calls", 0)
            t["blocked"] = tu.get("blocked", 0)
            t["last"] = tu.get("last", "")
        s["tools"].sort(key=lambda t: (-t.get("calls", 0), t["name"]))

    # Declared somewhere on this machine but not in this workspace's policy
    # families: behind the gateway (governed) or reached directly (not).
    known = {n.lower() for n in seen}
    for key, decl in sorted(by_name.items()):
        if key in known:
            continue
        known.add(key)
        name = decl[0]["name"]
        u = usage.get(name) or {}
        managed = any(d["managed"] for d in decl)
        servers.append({
            "name": name, "kind": "gateway" if managed else "direct", "tools": [],
            "declared_in": [{
                "source": d["source"], "agent": d["agent"], "transport": d["transport"],
                "command": " ".join(d["command"] or []), "url": d["url"],
                "managed": d["managed"], "workspace_scoped": d["workspace_scoped"],
            } for d in decl],
            "managed": any(d["managed"] for d in decl),
            "risk": max((d["risk"] for d in decl), key=_RISK_RANK.get, default="none"),
            "findings": sorted({f for d in decl for f in (d["findings"] or [])}),
            "usage": {"calls": u.get("calls", 0), "blocked": u.get("blocked", 0),
                      "sessions": u.get("sessions", 0), "last": u.get("last", ""), "lastAbs": u.get("lastAbs", "")},
        })
    # Only known from calls the hooks saw (a host-bundled server, or one an
    # agent registered outside any config Prismor scans).
    for name, u in sorted(usage.items(), key=lambda kv: -kv[1]["calls"]):
        if name.lower() in known:
            continue
        known.add(name.lower())
        prefix = f"mcp__{name}__"
        servers.append({
            "name": name, "kind": "seen", "declared_in": [], "managed": False,
            "risk": "none", "findings": [],
            "usage": {"calls": u["calls"], "blocked": u["blocked"], "sessions": u["sessions"],
                      "last": u["last"], "lastAbs": u["lastAbs"]},
            "tools": sorted([
                {"name": t, "tag": prefix + t, "state": _state_for_tag(prefix + t, workspace),
                 "calls": tu["calls"], "blocked": tu["blocked"], "last": tu["last"]}
                for t, tu in u["tools"].items()], key=lambda t: (-t["calls"], t["name"])),
        })
    return servers


def _state_for_tag(tag: str, workspace: Path) -> str:
    from prismor.runtime.agents import load_agents_config
    cfg = load_agents_config(workspace)
    if tag in set(cfg.get("global_deny_tools") or []):
        return "deny"
    if tag in set(cfg.get("global_ask_tools") or []):
        return "ask"
    return "allow"


_RISK_RANK = {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# -- Docs: the shipped Markdown docs, browsable from the dashboard ---------
# Two locations: the wheel bundles a subset under runtime/data/docs, a source
# checkout has the full set at the repo root.
def _docs_dir() -> Optional[Path]:
    here = Path(__file__).resolve()
    for candidate in (here.parent / "data" / "docs", here.parents[2] / "docs"):
        if candidate.is_dir():
            return candidate
    return None


def _doc_title(text: str, name: str) -> str:
    for line in text.splitlines():
        if line.startswith("# "):
            return line[2:].strip()
    return name[:-3].replace("-", " ").title()


def _docs_list(root: Path):
    out = []
    for f in sorted(root.glob("*.md")):
        try:
            head = f.read_text(encoding="utf-8", errors="replace")[:2000]
        except OSError:
            continue
        out.append({"name": f.name, "title": _doc_title(head, f.name)})
    return out


# Words that carry no meaning in a question ("why was my command blocked").
_DOC_STOPWORDS = frozenset(
    "a an and are as at be by can do does for from how i if in is it its me my of on or "
    "so that the this to was we what when where which who why will with you your prismor".split()
)
# Plain words a newcomer types, mapped to the words the docs use.
_DOC_SYNONYMS = {
    "block": ("deny", "stop"), "stop": ("block", "pause", "kill"), "deny": ("block",),
    "allow": ("exempt", "permit"), "secret": ("key", "token", "credential", "cloak"),
    "key": ("secret", "token", "credential"), "hide": ("cloak", "redact", "mask"),
    "token": ("secret", "key"), "password": ("secret", "credential"),
    "off": ("disable", "pause", "uninstall"), "disable": ("off", "pause"),
    "remove": ("uninstall", "delete"), "delete": ("remove", "purge"),
    "uninstall": ("remove",), "update": ("upgrade",), "upgrade": ("update",),
    "slow": ("timeout", "latency"), "data": ("telemetry", "store"),
    "leave": ("egress", "send", "upload"), "send": ("egress", "upload", "telemetry"),
    "privacy": ("telemetry", "data", "redact"), "start": ("install", "setup", "getting"),
    "begin": ("getting", "start"), "setup": ("install",), "install": ("setup",),
    # Getting past a block: the docs say allow, approve, exempt, unlock or pause.
    "unblock": ("allow", "approve", "exempt", "unlock", "pause"),
    "bypass": ("allow", "exempt", "unlock", "pause"), "override": ("allow", "exempt", "unlock"),
    "approve": ("approval", "allow"), "whitelist": ("allow", "allowlist"), "allowlist": ("allow",),
    "false": ("allow", "exempt"), "positive": ("allow", "exempt"),
}


def _doc_stem(word: str) -> str:
    """blocked/blocking/blocks -> block: enough for matching, not linguistics."""
    for suffix in ("ing", "ed", "es", "s"):
        if len(word) > len(suffix) + 3 and word.endswith(suffix):
            return word[: -len(suffix)]
    return word


def _doc_terms(query: str) -> List[List[str]]:
    """One group per meaningful word: the word's stem and its synonyms. A
    section matches a group if any of them appears."""
    words = [w for w in re.findall(r"[a-z0-9][a-z0-9_.-]*", query.lower()) if w not in _DOC_STOPWORDS]
    groups = []
    for w in words:
        stem = _doc_stem(w)
        groups.append(list(dict.fromkeys([stem, *_DOC_SYNONYMS.get(stem, ()), *_DOC_SYNONYMS.get(w, ())])))
    return groups


def _docs_search(root: Path, query: str, limit: int = 60):
    """Ranked search over the docs: a page scores for each query word in its
    title, its headings and its sections, so the page about the thing asked
    comes first. Filler words are dropped, words match by stem, and a few
    plain words also match the docs' own vocabulary (hide -> cloak). The
    corpus is a few dozen small files, so it is scanned per query."""
    groups = _doc_terms(query)
    if not groups:
        return []
    # "what is a hook" wants the definition first.
    define = bool(re.match(r"\s*(what\s+(is|are|does)|what's|define|meaning)\b", query.lower()))
    results = []
    for f in sorted(root.glob("*.md")):
        try:
            text = f.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        title = _doc_title(text, f.name)
        tlow = (title + " " + f.stem.replace("-", " ")).lower()
        score = sum(15 for g in groups if any(t in tlow for t in g))
        if f.name == "glossary.md" and define:
            score += 25
        # Sections: the text under each heading, scored on its own.
        sections, cur, fenced = [], {"heading": "", "line": 1, "lines": []}, False
        for i, line in enumerate(text.splitlines(), 1):
            if line.startswith("```"):
                fenced = not fenced
            if line.startswith("#") and not fenced:
                sections.append(cur)
                cur = {"heading": line.lstrip("#").strip(), "line": i, "lines": []}
            cur["lines"].append((i, line))
        sections.append(cur)
        best = []
        for sec in sections:
            body = " ".join(l for _, l in sec["lines"]).lower()
            covered = [g for g in groups if any(t in body for t in g)]
            if not covered:
                continue
            head = sec["heading"].lower()
            in_head = sum(1 for g in groups if any(t in head for t in g))
            sec_score = 3 * in_head + len(covered)
            if in_head == len(groups):
                # A heading that is the question or the term itself ("Why was
                # my command blocked?", "Hook") is the answer, not a mention.
                sec_score += 12 if len(head.split()) <= 2 * len(groups) + 1 else 8
            if len(covered) == len(groups):
                sec_score += 2 * len(groups)  # every word asked about, in one place
            best.append((sec_score, sec))
        best.sort(key=lambda x: -x[0])
        score += sum(sc for sc, _ in best[:2])
        if not score or (len(groups) > 1 and not best and score < 15 * len(groups)):
            continue
        hits = []
        for _, sec in best[:3]:
            lines = [(i, l) for i, l in sec["lines"] if l.strip() and not l.startswith("#")]
            i, line = max(lines or sec["lines"], key=lambda il: sum(1 for g in groups if any(t in il[1].lower() for t in g)))
            hits.append({"line": i, "snippet": line.strip()[:200], "section": sec["heading"]})
        full = all(any(t in tlow or any(t in " ".join(l for _, l in sec["lines"]).lower() for _, sec in best) for t in g)
                   for g in groups)
        results.append({"name": f.name, "title": title, "hits": hits, "score": score, "full": full})
    # Pages with every word asked about, when there are any; otherwise the
    # closest, so one misspelt word does not empty the list.
    if any(r["full"] for r in results):
        results = [r for r in results if r["full"]]
    for r in results:
        del r["full"]
    results.sort(key=lambda r: (-r["score"], r["title"]))
    # Pages that only mention the words in passing are noise next to the
    # page about them: keep what scores within reach of the best.
    if results:
        floor = results[0]["score"] * 0.35
        results = [r for r in results if r["score"] >= floor][:20]
    terms = sorted({t for g in groups for t in g}, key=len, reverse=True)
    for r in results:
        r["terms"] = terms
    return results[:limit]


# The workspace where the server was launched (set by run_server).
_SERVER_WORKSPACE: Optional[Path] = None

# Required on every request when bound off loopback (set by run_server).
_SERVER_TOKEN: Optional[str] = None
_TOKEN_COOKIE = "prismor_dashboard_token"


def _is_loopback(host: str) -> bool:
    host = host.strip("[]")
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _hostname(netloc: str) -> str:
    return (urlsplit("//" + netloc).hostname or "").lower()


def _revocation_state() -> Optional[dict]:
    """The device-revoked marker, or None. Never raises."""
    try:
        from prismor.runtime.enterprise import identity as _identity
        info = _identity.revoked_info()
        if not info:
            return None
        return {"at": info.get("at"), "reason": str(info.get("reason") or "")[:200]}
    except Exception:
        return None


def _effective_policy_state(workspace: Optional[Path]) -> dict:
    """What the merged policy actually does, for the header chip and badges.

    ``mode`` is "enforce" when anything blocks at all, regardless of what
    ``settings.default_mode`` says — that field is the fallback for unlisted
    rules, not a description of the policy.
    """
    try:
        from prismor.runtime.policy_engine import PolicyEngine
        engine = PolicyEngine(workspace=workspace) if workspace else PolicyEngine()
        blocking = sum(1 for r in engine.rules if engine._resolve_mode(r) == "enforce")
        return {
            "mode": "enforce" if blocking else "observe",
            "blocking": blocking,
            "total": len(engine.rules),
            "defaultMode": engine.default_mode,
            "explicitSelection": bool(getattr(engine, "explicit_selection", False)),
            "legacyBridge": bool(getattr(engine, "is_legacy_policy", False)),
        }
    except Exception:
        return {}


def _policy_write_status(result: dict) -> int:
    """HTTP status for a policy write result.

    An org-managed refusal is 403, not 400: the request was well-formed and the
    answer is "not from here", which is what lets the UI show the right banner
    instead of a validation error.
    """
    if result.get("ok"):
        return 200
    return 403 if result.get("reason") == "org_managed" else 400


_CHANGELOG_URL = "https://raw.githubusercontent.com/PrismorSec/prismor/main/CHANGELOG.md"


def _version_key(v: str) -> tuple:
    return tuple(int(x) for x in re.findall(r"\d+", v or "")[:3])


def _runtime_state() -> Dict[str, Any]:
    from prismor.runtime import __version__
    from prismor.runtime import pause as _pause
    from prismor.runtime.version_check import latest_known_version
    latest = latest_known_version()
    state = _pause.active_state() or {}
    return {
        "version": __version__,
        "latest": latest,
        "update_available": bool(latest) and _version_key(latest) > _version_key(__version__),
        "paused": bool(state),
        # An org pause can't be lifted from here, same as `prismor resume`.
        "paused_by_org": bool(state) and (_pause.org_state() or {}).get("paused") is True,
        "paused_until": state.get("until"),
    }


def _changelog_since(current: str) -> List[Dict[str, str]]:
    """Released sections of the upstream CHANGELOG newer than ``current``."""
    import urllib.request
    with urllib.request.urlopen(_CHANGELOG_URL, timeout=6) as resp:  # fixed URL  # nosec B310
        text = resp.read().decode("utf-8", "replace")
    out = []
    for block in re.split(r"(?m)^(?=## \[)", text):
        m = re.match(r"## \[(\d+\.\d+\.\d+)\][^\n]*", block)
        if m and _version_key(m.group(1)) > _version_key(current):
            out.append({"version": m.group(1), "heading": m.group(0)[3:], "body": block[m.end():].strip()})
    return out


class PrismorRequestHandler(BaseHTTPRequestHandler):
    """Minimal HTTP handler for the prismor dashboard API."""

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        pass

    def parse_request(self) -> bool:
        # One gate for every method, so a new route can't forget it.
        if not super().parse_request():
            return False
        reason = self._request_allowed()
        if reason is None:
            return True
        status, msg = reason
        self.close_connection = True  # the unread body would parse as the next request
        self._send_json({"error": msg}, status=status)
        return False

    def _request_allowed(self) -> Optional[tuple]:
        """None when the request may proceed, else (status, message).

        The API reads agent transcripts and rewrites the security policy, so a
        web page the user happens to have open must not be able to reach it.
        """
        host = self.headers.get("Host", "")
        bound = str(self.server.server_address[0])
        # DNS rebinding: an attacker's hostname resolving to 127.0.0.1 is
        # same-origin to the browser, so Origin alone can't catch it.
        if _is_loopback(bound) and not _is_loopback(_hostname(host)):
            return 403, "forbidden host"
        # CSRF / cross-origin reads. Our own page is always same-origin.
        origin = self.headers.get("Origin")
        if origin is not None and urlsplit(origin).netloc.lower() != host.lower():
            return 403, "cross-origin request refused"
        # A link to the dashboard is fine (the page can't read the result);
        # a script fetch or form post from another site is not.
        navigation = self.command == "GET" and self.headers.get("Sec-Fetch-Mode") == "navigate"
        if self.headers.get("Sec-Fetch-Site", "same-origin") not in ("same-origin", "none") and not navigation:
            return 403, "cross-site request refused"
        if _SERVER_TOKEN:
            presented = self._presented_token()
            if not presented or not hmac.compare_digest(presented, _SERVER_TOKEN):
                return 401, "dashboard token required (see the URL printed at startup)"
        return None

    def _presented_token(self) -> str:
        auth = self.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            return auth[7:]
        for part in self.headers.get("Cookie", "").split(";"):
            name, _, value = part.strip().partition("=")
            if name == _TOKEN_COOKIE:
                return value
        return parse_qs(urlparse(self.path).query).get("token", [""])[0]

    def _send_token_cookie(self) -> None:
        if _SERVER_TOKEN:
            self.send_header(
                "Set-Cookie", f"{_TOKEN_COOKIE}={_SERVER_TOKEN}; HttpOnly; SameSite=Strict; Path=/"
            )

    def _send_json(self, data: Any, status: int = 200) -> None:
        body = json.dumps(data, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_html(self, html_path: Path) -> None:
        try:
            body = html_path.read_bytes()
        except FileNotFoundError:
            self._send_json({"error": "dashboard.html not found"}, status=500)
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self._send_token_cookie()
        self.end_headers()
        self.wfile.write(body)

    def _send_static(self, name: str) -> None:
        # Bare file names only: no subdirectories, so no traversal out of static/.
        ctype = _STATIC_TYPES.get(Path(name).suffix)
        target = _STATIC_DIR / name
        if "/" in name or "\\" in name or name.startswith(".") or not ctype or not target.is_file():
            self._send_json({"error": "not found"}, status=404)
            return
        body = target.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "max-age=86400")
        self.end_headers()
        self.wfile.write(body)

    def _read_json_body(self) -> Any:
        length = int(self.headers.get("Content-Length", 0) or 0)
        if not length:
            return {}
        return json.loads(self.rfile.read(length).decode("utf-8"))

    def _resolve_workspace(self, qs: Dict[str, list]) -> Optional[Path]:
        """Resolve workspace from query param or fall back to server default."""
        ws_param = qs.get("workspace", [None])[0]
        if ws_param:
            p = Path(ws_param)
            return p if p.exists() else None
        return _SERVER_WORKSPACE

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")
        qs = parse_qs(parsed.query, keep_blank_values=False)

        def qstr(key: str, default: str = "") -> str:
            return qs.get(key, [default])[0]

        def qint(key: str, default: int = 1) -> int:
            try:
                return int(qs.get(key, [default])[0])
            except (ValueError, TypeError):
                return default

        if path in ("", "/dashboard"):
            self._send_html(_DASHBOARD_HTML)
            return

        if path.startswith("/static/"):
            self._send_static(path[len("/static/"):])
            return

        if path == "/health":
            self._send_json({"status": "ok", "ts": datetime.now(timezone.utc).isoformat()})
            return

        if path == "/metrics":
            # Prometheus text exposition, rebuilt from the store per scrape.
            # A scrape must not take the server down, but it also must not
            # report a silent zero: a failure answers 500 so the target goes
            # down in Prometheus rather than graphing a flat line.
            try:
                from prismor.runtime.metrics import render as render_metrics
                payload = render_metrics().encode("utf-8")
            except Exception as exc:
                self._send_json({"error": str(exc)}, status=500)
                return
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return

        if path == "/api/mcp-servers":
            workspace = self._resolve_workspace(qs) or Path.cwd()
            try:
                self._send_json({"servers": _mcp_server_inventory(workspace)})
            except Exception as exc:
                self._send_json({"error": str(exc)}, status=500)
            return

        if path == "/api/extensions/session":
            workspace = self._resolve_workspace(qs) or Path.cwd()
            try:
                from prismor.runtime.extensions import session_extensions
                self._send_json(session_extensions(workspace, (qs.get("id") or [""])[0]))
            except Exception as exc:
                self._send_json({"error": str(exc)}, status=500)
            return

        if path == "/api/extensions/detail":
            workspace = self._resolve_workspace(qs) or Path.cwd()
            try:
                from prismor.runtime.extensions import extension_detail
                self._send_json(extension_detail(workspace, qs.get("id") or [],
                                                 history=(qs.get("history") or [""])[0] == "1"))
            except Exception as exc:
                self._send_json({"error": str(exc)}, status=500)
            return

        if path == "/api/extensions":
            workspace = self._resolve_workspace(qs) or Path.cwd()
            try:
                from prismor.runtime.extensions import overview
                self._send_json(overview(workspace))
            except Exception as exc:
                self._send_json({"error": str(exc)}, status=500)
            return

        if path == "/api/workspaces":
            workspaces = list_registered_workspaces()
            enrollment = get_enrollment()
            primary = str(_SERVER_WORKSPACE) if _SERVER_WORKSPACE else None
            self._send_json({
                "workspaces": [str(w) for w in workspaces],
                "primary": primary,
                "home": str(prismor_home()),
                "enrollment": enrollment,
            })
            return

        if path == "/api/runtime":
            self._send_json(_runtime_state())
            return

        if path == "/api/agent-tools":
            from prismor.runtime.store import get_agent_tools
            self._send_json({"tools": get_agent_tools(qstr("name"), qint("days", 7))})
            return

        if path == "/api/approvals":
            from prismor.runtime import approvals_local
            reqs = [{k: v for k, v in r.items() if k != "fp"}
                    for r in approvals_local.list_requests() if r.get("status") == "pending"]
            self._send_json({"requests": reqs})
            return

        if path == "/api/changelog":
            from prismor.runtime import __version__
            try:
                self._send_json({"version": __version__, "releases": _changelog_since(__version__)})
            except Exception as exc:
                self._send_json({"error": f"could not fetch the changelog: {exc}"}, status=502)
            return

        if path == "/api/policy":
            workspace = self._resolve_workspace(qs)
            enrollment = get_enrollment()
            result = {
                "global": read_policy_layer("global"),
                "project": read_policy_layer("project", workspace),
                "enterprise": read_policy_layer("enterprise"),
                "precedence": get_policy_precedence(workspace),
                "enrollment": enrollment,
                "workspace": str(workspace) if workspace else None,
                "enterprise_enrolled": enrollment is not None,
                # Whether local edits survive: on an org-managed workspace the
                # signed bundle merges last, so the UI greys its controls rather
                # than accepting edits the next policy pull would revert.
                "editable": is_policy_editable(workspace),
                # What is actually in force, as opposed to what `default_mode`
                # says. A policy written by `prismor setup --mode enforce` sets
                # default_mode: observe and flips its chosen rules to enforce,
                # so reading the default alone reports "observe" for a machine
                # that is blocking.
                "effective": _effective_policy_state(workspace),
                # A device whose key the control plane rejected still has its
                # identity and its last org policy on disk, so without this the
                # page can only say "not enrolled" and leave the reader to
                # guess why the org policy it can see does not apply.
                "revoked": _revocation_state(),
            }
            self._send_json(result)
            return

        if path == "/api/policy/egress":
            workspace = self._resolve_workspace(qs)
            try:
                self._send_json(get_egress_config(workspace))
            except Exception as exc:
                self._send_json({"error": str(exc)}, status=500)
            return

        if path == "/api/policy/rules":
            workspace = self._resolve_workspace(qs)
            try:
                rules = get_policy_rule_catalog(workspace)
            except Exception as exc:
                self._send_json({"error": str(exc)}, status=500)
                return
            self._send_json({
                "rules": rules,
                "workspace": str(workspace) if workspace else None,
                # "How many rules are on" is the wrong headline for a policy
                # that names its blocking set: what a reader wants is how many
                # actually stop a call.
                "summary": {
                    "total": len(rules),
                    "blocking": sum(1 for r in rules if r.get("blocks")),
                    "reporting": sum(1 for r in rules if r.get("enabled") and not r.get("blocks")),
                    "off": sum(1 for r in rules if not r.get("enabled")),
                },
            })
            return

        if path == "/api/query-prompt":
            from prismor.runtime.query import agent_prompt, resolve_db_path
            db_path = resolve_db_path()
            self._send_json({"prompt": agent_prompt(db_path), "dbPath": str(db_path)})
            return

        if path == "/api/stats":
            try:
                days = max(1, qint("days", 7))
                stats = get_aggregate_stats(hours=days * 24)
            except Exception as exc:
                self._send_json({"error": str(exc)}, status=500)
                return
            self._send_json(stats)
            return

        if path == "/api/sessions":
            try:
                data = get_sessions_page(
                    page=qint("page", 1),
                    limit=qint("limit", 20),
                    sort=qstr("sort", "updatedAt"),
                    direction=qstr("dir", "desc"),
                    agent=qstr("agent"),
                    workspace=qstr("workspace"),
                    search=qstr("q"),
                    findings=qstr("findings"),
                    min_risk=qint("min_risk", 0),
                    since_hours=qint("since_hours", 0),
                )
            except Exception as exc:
                self._send_json({"error": str(exc)}, status=500)
                return
            self._send_json(data)
            return

        if path == "/api/findings":
            try:
                data = get_findings_page(
                    page=qint("page", 1),
                    limit=qint("limit", 25),
                    agent=qstr("agent"),
                    severity=qstr("severity"),
                    category=qstr("category"),
                    search=qstr("q"),
                    since_hours=qint("days", 0) * 24,
                )
            except Exception as exc:
                self._send_json({"error": str(exc)}, status=500)
                return
            self._send_json(data)
            return

        if path == "/api/events":
            try:
                data = get_events_page(
                    page=qint("page", 1),
                    limit=qint("limit", 30),
                    verdict=qstr("verdict"),
                    agent=qstr("agent"),
                    since_hours=qint("days", 0) * 24,
                )
            except Exception as exc:
                self._send_json({"error": str(exc)}, status=500)
                return
            self._send_json(data)
            return

        if path == "/api/docs":
            root = _docs_dir()
            if root is None:
                self._send_json({"error": "docs not bundled with this install"}, status=404)
                return
            name = qstr("name")
            if name:
                # Filename only -- never a path out of the docs directory.
                if not name.endswith(".md") or "/" in name or "\\" in name:
                    self._send_json({"error": "bad doc name"}, status=400)
                    return
                target = root / name
                if not target.is_file():
                    self._send_json({"error": "doc not found"}, status=404)
                    return
                text = target.read_text(encoding="utf-8", errors="replace")
                self._send_json({"name": name, "title": _doc_title(text, name),
                                 "markdown": text})
                return
            query = qstr("q").strip()
            if query:
                self._send_json({"query": query, "results": _docs_search(root, query)})
                return
            self._send_json({"docs": _docs_list(root)})
            return

        if path == "/api/supply-chain":
            try:
                days = max(1, qint("days", 7))
                data = get_supply_chain_stats(hours=days * 24)
            except Exception as exc:
                self._send_json({"error": str(exc)}, status=500)
                return
            self._send_json(data)
            return

        if path == "/api/network-calls":
            try:
                days = max(1, qint("days", 7))
                self._send_json(get_network_calls(hours=days * 24))
            except Exception as exc:
                self._send_json({"error": str(exc)}, status=500)
            return

        if path == "/api/hooks":
            try:
                days = max(1, qint("days", 7))
                self._send_json(get_hook_stats(hours=days * 24))
            except Exception as exc:
                self._send_json({"error": str(exc)}, status=500)
            return

        if path == "/api/dependencies":
            try:
                days = max(1, qint("days", 30))
                self._send_json(get_dependency_usage(hours=days * 24))
            except Exception as exc:
                self._send_json({"error": str(exc)}, status=500)
            return

        if path == "/api/tokens":
            try:
                session_id = (qs.get("session") or [""])[0]
                if session_id:
                    from prismor.runtime.token_usage import session_cost
                    data = {"sessionId": session_id, **session_cost(Path.cwd(), session_id)}
                    self._send_json(data)
                    return
                days = max(1, qint("days", 1))
                data = get_token_stats(hours=days * 24)
            except Exception as exc:
                self._send_json({"error": str(exc)}, status=500)
                return
            self._send_json(data)
            return

        if path == "/api/agents":
            try:
                from prismor.runtime.agents import list_agents
                from prismor.runtime.iam import list_agent_ids, load_iam_config
                workspace = _SERVER_WORKSPACE or Path.cwd()

                # Merge store stats with registry config
                store_stats = {a["name"]: a for a in get_agents_overview(qint("days", 0))}
                registry = {a.name: a for a in list_agents(workspace)}

                # Union of both — include agents seen in store but not configured yet
                all_names = sorted(set(store_stats) | set(registry))
                items = []
                for name in all_names:
                    stats = store_stats.get(name, {})
                    ctrl = registry.get(name)
                    items.append({
                        "name": name,
                        "framework": (ctrl.framework if ctrl else "") or stats.get("framework", ""),
                        "enabled": ctrl.enabled if ctrl else True,
                        "mode": ctrl.mode if ctrl else None,
                        "iam_profile": ctrl.iam_profile if ctrl else None,
                        "deny_tools": list(ctrl.deny_tools) if ctrl else [],
                        "ask_tools": list(ctrl.ask_tools) if ctrl else [],
                        "last_seen": stats.get("last_seen") or (ctrl.last_seen if ctrl else None),
                        "total_calls": stats.get("total_calls", 0),
                        "blocked_calls": stats.get("blocked_calls", 0),
                    })

                iam_profiles = list_agent_ids(load_iam_config(workspace))
                from prismor.runtime.agents import load_agents_config
                cfg = load_agents_config(workspace)
                self._send_json({"agents": items, "iam_profiles": iam_profiles,
                                 # Tool rules that apply to every agent.
                                 "global_deny_tools": list(cfg.get("global_deny_tools") or []),
                                 "global_ask_tools": list(cfg.get("global_ask_tools") or [])})
            except Exception as exc:
                self._send_json({"error": str(exc)}, status=500)
            return

        if path in ("/api/blame", "/api/friction", "/api/files"):
            from prismor.runtime import devlog
            try:
                if path == "/api/files":
                    data = devlog.files(qstr("q"), days=qint("days", 0))
                elif path == "/api/blame":
                    data = devlog.blame(qstr("path"), qint("line", 0) or None)
                else:
                    data = devlog.friction(qstr("workspace") or None, qint("days", 14))
            except Exception as exc:
                self._send_json({"error": str(exc)}, status=500)
                return
            self._send_json(data)
            return

        # The UI encodes ids (`replay:claude:<uuid>` carries colons); decode after splitting.
        parts = [unquote(p) for p in path.split("/")]
        # /api/sessions/<id>/dev → rca + changes for the session view
        if len(parts) == 5 and parts[1] == "api" and parts[2] == "sessions" and parts[4] == "dev":
            from prismor.runtime import devlog
            try:
                self._send_json({"rca": devlog.rca(parts[3]), "changes": devlog.changes(parts[3])})
            except Exception as exc:
                self._send_json({"error": str(exc)}, status=500)
            return

        # /api/sessions/<id>/control
        if len(parts) == 5 and parts[1] == "api" and parts[2] == "sessions" and parts[4] == "control":
            session_id = parts[3]
            workspace = self._resolve_workspace(qs)
            if not workspace:
                self._send_json({"error": "workspace not found"}, status=404)
                return
            try:
                detail = get_session_scoped_detail(workspace, session_id)
                self._send_json(detail)
            except Exception as exc:
                self._send_json({"error": str(exc)}, status=500)
            return

        self._send_json({"error": "not found"}, status=404)

    def do_POST(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")

        if path == "/api/refresh":
            try:
                workspace = _SERVER_WORKSPACE or Path.cwd()
                _migrate_workspace_runtime_state(workspace, prismor_home())
                initialize_database(workspace)
                sessions = get_sessions_page(page=1, limit=1, sort="updatedAt", direction="desc")
                events = get_events_page(page=1, limit=1)
                self._send_json({
                    "ok": True,
                    "workspace": str(workspace),
                    "home": str(prismor_home()),
                    "latest_session": (sessions.get("items") or [{}])[0].get("sessionId"),
                    "sessions": sessions.get("total", 0),
                    "events": events.get("total", 0),
                })
            except Exception as exc:
                self._send_json({"ok": False, "error": str(exc)}, status=500)
            return

        if path == "/api/approvals":
            # Approve or deny one blocked call, once (approvals_local.py). Agents
            # are kept off this route by prismor-self-edit; an unlock window
            # lifts that rule, so while one is open the decision has to come
            # from the terminal, as the CLI requires.
            from prismor.runtime import approvals_local, unlock
            try:
                body = self._read_json_body()
            except ValueError:
                self._send_json({"error": "invalid JSON"}, status=400)
                return
            if unlock.is_open():
                self._send_json({"error": "An unlock window is open, so approve from your terminal: "
                                          "prismor approvals approve " + str(body.get("id") or "<id>")}, status=403)
                return
            rec = approvals_local.decide(str(body.get("id") or ""), bool(body.get("approve")))
            if rec is None:
                self._send_json({"error": "No such request (it may have expired)."}, status=404)
                return
            self._send_json({"ok": True, "status": rec.get("status"), "was_waiting": bool(rec.get("was_waiting"))})
            return

        if path == "/api/policy/floor-off":
            # A pinned (safety-floor) rule off or back on. Off needs the unlock
            # password; on only tightens, so it needs nothing. See floor_off.py.
            from prismor.runtime import floor_off, unlock
            from prismor.runtime.allow import is_floor_rule
            from prismor.runtime.policy_engine import PolicyEngine, is_self_protection_rule
            try:
                body = self._read_json_body()
            except ValueError:
                self._send_json({"error": "invalid JSON"}, status=400)
                return
            rule_id = str(body.get("rule") or "")
            if not body.get("off"):
                floor_off.turn_on(rule_id)
                self._send_json({"ok": True, "rule": rule_id, "off": False})
                return
            if not is_floor_rule(rule_id):
                self._send_json({"error": f"{rule_id} is not pinned; use the normal toggle"}, status=400)
                return
            if is_self_protection_rule(rule_id):
                self._send_json({"error": "This rule guards Prismor itself and cannot be turned off. "
                                          "For a one-off change, run prismor unlock."}, status=403)
                return
            engine = PolicyEngine(workspace=self._resolve_workspace({}) or Path.cwd())
            if engine.workspace_managed or engine.remote_policy_meta:
                self._send_json({"error": "Your organization manages this workspace, so its safety floor "
                                          "can only be changed by an org admin."}, status=403)
                return
            ok, msg = unlock.verify(str(body.get("password") or ""))
            if not ok:
                self._send_json({"error": msg}, status=401)
                return
            floor_off.turn_off(rule_id, by=os.environ.get("USER", ""))
            self._send_json({"ok": True, "rule": rule_id, "off": True})
            return

        if path == "/api/pause":
            from prismor.runtime import pause as _pause
            try:
                body = self._read_json_body()
            except ValueError:
                self._send_json({"error": "invalid JSON"}, status=400)
                return
            if body.get("paused"):
                _pause.beat(agent="claude", state=_pause.set_paused(reason="paused from the dashboard"))
            elif _pause.clear_paused():
                _pause.beat_resumed(agent="claude")
            self._send_json(_runtime_state())
            return

        if path == "/api/update":
            import subprocess
            # Same path as `prismor update`, in a fresh interpreter so its
            # guidance refresh runs the new code.
            try:
                r = subprocess.run(
                    [sys.executable, "-c", "from prismor.runtime.immunity_cli import main; main()", "update"],
                    capture_output=True, text=True, timeout=600, check=False,
                )
            except subprocess.TimeoutExpired:
                self._send_json({"ok": False, "output": "update timed out after 10 minutes"}, status=504)
                return
            self._send_json({"ok": r.returncode == 0, "output": (r.stdout + r.stderr)[-4000:]},
                            status=200 if r.returncode == 0 else 500)
            return

        # POST /api/extensions/approve — a human accepts an extension after review
        if path == "/api/extensions/approve":
            length = int(self.headers.get("Content-Length", 0))
            try:
                body = json.loads(self.rfile.read(length)) if length else {}
                from prismor.runtime.extensions import approve
                ws_str = body.get("workspace")
                workspace = Path(ws_str) if ws_str else (_SERVER_WORKSPACE or Path.cwd())
                self._send_json({"ok": True, **approve(workspace, str(body.get("id") or ""))})
            except SystemExit as exc:
                self._send_json({"error": str(exc)}, status=404)
            except Exception as exc:
                self._send_json({"error": str(exc)}, status=400)
            return

        # POST /api/extensions/toggle — turn one extension off or back on
        if path == "/api/extensions/toggle":
            length = int(self.headers.get("Content-Length", 0))
            try:
                body = json.loads(self.rfile.read(length)) if length else {}
                from prismor.runtime.extensions import set_enabled
                ws_str = body.get("workspace")
                workspace = Path(ws_str) if ws_str else (_SERVER_WORKSPACE or Path.cwd())
                self._send_json({"ok": True, **set_enabled(workspace, str(body.get("id") or ""), bool(body.get("enabled")))})
            except SystemExit as exc:  # hooks not installed: nothing to wrap a hook with
                self._send_json({"error": str(exc)}, status=409)
            except Exception as exc:
                self._send_json({"error": str(exc)}, status=400)
            return

        # POST /api/tool-policy — deny/allow a tool tag at agent or global scope
        if path == "/api/tool-policy":
            length = int(self.headers.get("Content-Length", 0))
            try:
                body = json.loads(self.rfile.read(length)) if length else {}
            except Exception as exc:
                self._send_json({"error": f"invalid JSON: {exc}"}, status=400)
                return
            try:
                from prismor.runtime.agents import set_tool_policy
                ws_str = body.get("workspace")
                workspace = Path(ws_str) if ws_str else (_SERVER_WORKSPACE or Path.cwd())
                scope = body.get("scope") or "agent"
                action = body.get("action") or "deny"
                tool = body.get("tool") or ""
                agent = body.get("agent") or None
                lists = set_tool_policy(workspace, scope, tool, action, agent=agent)
                self._send_json({"ok": True, "scope": scope, "action": action,
                                 "tool": tool, "agent": agent,
                                 "deny_tools": lists["deny_tools"],
                                 "ask_tools": lists["ask_tools"]})
            except Exception as exc:
                self._send_json({"ok": False, "error": str(exc)}, status=500)
            return

        # POST /api/mcp-config — mirror roster + override switch
        if path == "/api/mcp-config":
            length = int(self.headers.get("Content-Length", 0))
            try:
                body = json.loads(self.rfile.read(length)) if length else {}
            except Exception as exc:
                self._send_json({"error": f"invalid JSON: {exc}"}, status=400)
                return
            try:
                from prismor.runtime import mirror
                ws_str = body.get("workspace")
                workspace = Path(ws_str) if ws_str else (_SERVER_WORKSPACE or Path.cwd())
                cfg = mirror.set_mirror_config(
                    workspace,
                    override=body.get("override"),
                    tool=body.get("tool"),
                    enabled=body.get("enabled"),
                )
                self._send_json({"ok": True, "override": cfg["override"],
                                 "disabled_tools": cfg["disabled_tools"]})
            except Exception as exc:
                self._send_json({"ok": False, "error": str(exc)}, status=500)
            return

        # POST /api/agents/<name> — update per-agent control settings
        if path.startswith("/api/agents/"):
            agent_name = path[len("/api/agents/"):]
            if not agent_name:
                self._send_json({"error": "agent name required"}, status=400)
                return
            length = int(self.headers.get("Content-Length", 0))
            try:
                body = json.loads(self.rfile.read(length)) if length else {}
            except Exception as exc:
                self._send_json({"error": f"invalid JSON: {exc}"}, status=400)
                return
            try:
                from prismor.runtime.agents import upsert_agent
                # Resolve the workspace from the server's perspective
                workspace = _SERVER_WORKSPACE or Path.cwd()
                # Map camelCase keys the UI sends to snake_case
                fields = {}
                if "enabled" in body:
                    fields["enabled"] = bool(body["enabled"])
                if "mode" in body:
                    fields["mode"] = body["mode"] or None
                if "iam_profile" in body or "iamProfile" in body:
                    fields["iam_profile"] = body.get("iamProfile") or body.get("iam_profile") or None
                control = upsert_agent(agent_name, workspace, **fields)
                self._send_json({
                    "name": control.name,
                    "framework": control.framework,
                    "enabled": control.enabled,
                    "mode": control.mode,
                    "iam_profile": control.iam_profile,
                    "last_seen": control.last_seen,
                })
            except Exception as exc:
                self._send_json({"error": str(exc)}, status=500)
            return

        self._send_json({"error": "not found"}, status=404)

    def do_PUT(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")

        if path == "/api/policy/global":
            try:
                body = self._read_json_body()
                content = body.get("yaml", "")
                result = write_policy_layer("global", content)
                self._send_json(result, status=_policy_write_status(result))
            except Exception as exc:
                self._send_json({"ok": False, "error": str(exc)}, status=500)
            return

        if path == "/api/policy/project":
            try:
                body = self._read_json_body()
                content = body.get("yaml", "")
                ws_str = body.get("workspace")
                workspace = Path(ws_str) if ws_str else _SERVER_WORKSPACE
                if not workspace:
                    self._send_json({"ok": False, "error": "workspace required"}, status=400)
                    return
                result = write_policy_layer("project", content, workspace)
                self._send_json(result, status=_policy_write_status(result))
            except Exception as exc:
                self._send_json({"ok": False, "error": str(exc)}, status=500)
            return

        if path == "/api/policy/egress":
            # Edit settings.egress without hand-writing YAML. Goes through the
            # same writer as every other policy edit, so an org-managed
            # workspace refuses here exactly as it does elsewhere.
            try:
                body = self._read_json_body()
                ws_str = body.get("workspace")
                workspace = Path(ws_str) if ws_str else _SERVER_WORKSPACE
                if not workspace:
                    self._send_json({"ok": False, "error": "workspace required"}, status=400)
                    return
                action = str(body.get("action") or "")
                if action == "set":
                    result = set_egress_option(workspace, str(body.get("field") or ""), body.get("value"))
                elif action == "add":
                    result = add_egress_host(
                        workspace,
                        str(body.get("host") or ""),
                        str(body.get("list") or "allow"),
                        str(body.get("reason") or ""),
                    )
                elif action == "remove":
                    result = remove_egress_host(workspace, str(body.get("host") or ""))
                else:
                    self._send_json(
                        {"ok": False, "error": "action must be set, add, or remove"}, status=400
                    )
                    return
                self._send_json(result, status=_policy_write_status(result))
            except Exception as exc:
                self._send_json({"ok": False, "error": str(exc)}, status=500)
            return

        if path == "/api/policy/rules":
            try:
                body = self._read_json_body()
                disabled = body.get("disabled", [])
                ws_str = body.get("workspace")
                workspace = Path(ws_str) if ws_str else _SERVER_WORKSPACE
                if not workspace:
                    self._send_json({"ok": False, "error": "workspace required"}, status=400)
                    return
                if not isinstance(disabled, list):
                    self._send_json({"ok": False, "error": "disabled must be a list"}, status=400)
                    return
                result = set_project_rule_states(workspace, [str(x) for x in disabled])
                self._send_json(result, status=_policy_write_status(result))
            except Exception as exc:
                self._send_json({"ok": False, "error": str(exc)}, status=500)
            return

        self._send_json({"error": "not found"}, status=404)

    def do_PATCH(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")

        # /api/sessions/<id>/control
        # The UI encodes ids (`replay:claude:<uuid>` carries colons); decode after splitting.
        parts = [unquote(p) for p in path.split("/")]
        if len(parts) == 5 and parts[1] == "api" and parts[2] == "sessions" and parts[4] == "control":
            session_id = parts[3]
            try:
                body = self._read_json_body()
                action = body.get("action", "")
                ws_str = body.get("workspace")
                workspace = Path(ws_str) if ws_str else _SERVER_WORKSPACE
                if not workspace:
                    self._send_json({"ok": False, "error": "workspace required"}, status=400)
                    return
                result = update_session_control(workspace, session_id, action, body)
                self._send_json(result, status=200 if result.get("ok") else 400)
            except Exception as exc:
                self._send_json({"ok": False, "error": str(exc)}, status=500)
            return

        self._send_json({"error": "not found"}, status=404)


class _DashboardServer(ThreadingHTTPServer):
    def handle_error(self, request: Any, client_address: Any) -> None:
        # The browser closed the socket mid-response (tab closed, poll aborted).
        if isinstance(sys.exc_info()[1], ConnectionError):
            return
        super().handle_error(request, client_address)


def _warm_dashboard_reads() -> None:
    """Pay the one-off costs before anyone opens a page: the read index, and
    the parse of recent shell commands the Files page lists."""
    from prismor.runtime import devlog
    from prismor.runtime.store import ensure_read_indexes
    for step in (ensure_read_indexes, lambda: devlog.files("")):
        try:
            step()
        except Exception:
            pass


def run_server(
    host: str = "127.0.0.1",
    port: int = 7070,
    open_browser: bool = False,
    workspace: Optional[Path] = None,
) -> None:
    """Start the prismor HTTP API server (blocks until Ctrl-C).

    ``workspace`` is optional. Runtime reads always use the single global
    Prismor home DB; when a launch workspace is available, older local state is
    imported once before serving requests.
    """
    global _SERVER_WORKSPACE, _SERVER_TOKEN
    _SERVER_WORKSPACE = workspace
    # Off loopback anyone who can reach the port could rewrite the policy.
    _SERVER_TOKEN = None if _is_loopback(host) else (
        os.environ.get("PRISMOR_DASHBOARD_TOKEN") or secrets.token_urlsafe(24)
    )
    if workspace:
        _migrate_workspace_runtime_state(workspace, prismor_home())
        initialize_database(workspace)
    threading.Thread(target=_warm_dashboard_reads, daemon=True).start()

    import errno as _errno
    while True:
        try:
            server = _DashboardServer((host, port), PrismorRequestHandler)
            break
        except OSError as exc:
            if exc.errno == _errno.EADDRINUSE:
                print(f"[prismor] port {port} in use, trying {port + 1}…", flush=True)
                port += 1
            else:
                raise

    url = f"http://{host}:{port}" + (f"/?token={_SERVER_TOKEN}" if _SERVER_TOKEN else "")
    print(f"[prismor] dashboard → {url}  (Ctrl-C to stop)  state → {prismor_home()}", flush=True)
    if open_browser:
        import webbrowser
        threading.Timer(0.4, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[prismor] server stopped", flush=True)
    finally:
        server.server_close()
