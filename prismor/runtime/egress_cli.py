"""`prismor egress` — inspect and manage the network egress policy.

Subcommands:
    show                     effective egress policy + where it came from
    report [--last N]        destinations recorded sessions actually contacted,
                             each with the verdict the current policy gives it
    test <url|command>...    dry-run one destination or shell command
    allow <host>...          add to settings.egress.allow (.prismor/policy.yaml)
    deny <host>...           add to settings.egress.deny
    rm <host>...             drop a host from both lists
    enable / disable         flip settings.egress.enabled
    mode <observe|enforce>   set the enforcement mode
    default <allow|deny>     set the no-match verdict
    request <host> --reason  ask the org's admins to allow a host (enrolled
                             devices; lands in the console's Requests tab)

The matching, extraction, and verdict logic all live in ``egress``; this module
is UX only. `report` is the intended on-ramp: turn egress on in observe, run
real sessions, then read off what to allowlist before flipping to enforce.
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from prismor.runtime.http_ua import user_agent
from prismor.runtime.egress import (
    EgressPolicy, RULE_EXPLICIT_DENY, RULE_OFF_ALLOWLIST, extract_destinations,
)

# ── output helpers (match cli.py's ANSI style, no deps) ──────────────────────
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


def _egress_block(data: Dict[str, Any]) -> Dict[str, Any]:
    settings = data.setdefault("settings", {})
    if not isinstance(settings, dict):
        settings = {}
        data["settings"] = settings
    block = settings.setdefault("egress", {})
    if not isinstance(block, dict):
        block = {}
        settings["egress"] = block
    return block


def _org_ships_egress(workspace: Path) -> bool:
    """True when the org's signed policy carries settings.egress for this
    workspace, i.e. the remote block replaces the local one wholesale."""
    try:
        return getattr(_engine(workspace), "_egress_source", "") == "remote"
    except Exception:
        return False


def _org_managed_hint(workspace: Path) -> None:
    """Say whether a local edit on an enrolled device actually takes effect.

    The org's egress block, when it ships one, replaces this file's egress
    settings entirely; when it ships none, the local file is what applies.
    Telling the user the wrong one is how a local allow "silently fails".
    """
    try:
        from prismor.runtime.enterprise.identity import load_identity

        if load_identity() is None:
            return
        if _org_ships_egress(workspace):
            print(_c(
                "note: your org's signed egress policy applies to this workspace and "
                "replaces the egress settings in this file — local allow/deny/mode "
                "edits have no effect here. To get a host allowed, ask your org:\n"
                "  prismor egress request <host> --reason \"<why>\"", _YELLOW))
        else:
            print(_c(
                "note: this device is org-enrolled, but your org currently ships no "
                "egress policy, so this file's egress settings apply. If an admin "
                "turns on egress in the console, the org's policy will replace them.",
                _DIM))
    except Exception:
        pass


def _refresh_remote() -> None:
    """Pick up a just-published org policy before reporting on it.

    `egress show`/`test` build a PolicyEngine straight from the cached bundle;
    without this they answer from a policy up to one refresh interval old,
    right after an admin said "I changed it, try again"."""
    try:
        from prismor.runtime.enterprise import remote_policy

        remote_policy.check_and_refresh(interval=0)
    except Exception:
        pass


def _engine(workspace: Path):
    from prismor.runtime.policy_engine import PolicyEngine

    return PolicyEngine(workspace=workspace)


def _entry_label(raw: Any) -> str:
    if isinstance(raw, str):
        return raw
    if isinstance(raw, dict):
        bits = [str(raw.get("host") or "")]
        if raw.get("ports"):
            bits.append("ports=" + ",".join(str(p) for p in raw["ports"]))
        if raw.get("schemes"):
            bits.append("schemes=" + ",".join(raw["schemes"]))
        if raw.get("agents"):
            bits.append("agents=" + ",".join(raw["agents"]))
        if raw.get("reason"):
            bits.append(_c(f"({raw['reason']})", _DIM))
        return " ".join(b for b in bits if b)
    return str(raw)


# ── show ─────────────────────────────────────────────────────────────────────

def egress_show(workspace: Path) -> None:
    _refresh_remote()
    engine = _engine(workspace)
    pol: EgressPolicy = engine.egress

    if not pol.enabled:
        print(_c("egress screening is DISABLED", _YELLOW))
        print(_c("\nEnable it in observe mode, run your agents, then read off what "
                 "they contacted:", _DIM))
        print("  prismor egress enable")
        print("  prismor egress report")
        _org_managed_hint(workspace)
        return

    mode = pol.mode or engine.device_mode or engine.default_mode
    mode_c = _GREEN if mode == "enforce" else _YELLOW
    print(_c("egress screening is ENABLED", _GREEN))
    print(f"  mode        {_c(str(mode), mode_c)}"
          + (_c("  (inherited)", _DIM) if not pol.mode else ""))
    print(f"  default     {_c(pol.default, _RED if pol.default == 'deny' else _DIM)}"
          + (_c("   — strict allowlist", _DIM) if pol.default == "deny" else ""))
    print(f"  private     {'allowed' if pol.allow_private else 'screened'}"
          + _c("  (cloud metadata endpoints are always screened)", _DIM))
    print(f"  source      {pol.source or 'default'}"
          + (_c("  — org-signed, authoritative", _CYAN) if pol.source == "remote" else ""))

    if pol.legacy:
        print(_c(
            "\n  Running from the deprecated settings.egress_allowlist: warn-only, "
            "never blocks.\n  Migrate with `prismor egress migrate` to get enforcement.",
            _YELLOW))

    # Labels (reasons, ports) come from the local file — only meaningful when
    # that file is what the entries were compiled from.
    raw = (((_load_policy_file(workspace).get("settings") or {}).get("egress") or {})
           if pol.source == "project" else {})
    for key, color in (("allow", _GREEN), ("deny", _RED)):
        entries = getattr(pol, key)
        print(f"\n  {_c(key, color)} ({len(entries)})")
        if not entries:
            print(_c("    (none)", _DIM))
            continue
        raw_list = raw.get(key) or []
        for i, entry in enumerate(entries):
            label = _entry_label(raw_list[i]) if i < len(raw_list) else entry.describe()
            print(f"    {label}")

    if pol.agents:
        print(f"\n  {_c('per-agent overrides', _CYAN)}")
        for name in sorted(pol.agents):
            sub = pol.agents[name]
            print(f"    {name:<24} default={sub.default} "
                  f"allow={len(sub.allow)} deny={len(sub.deny)}")

    if pol.errors:
        print(f"\n  {_c('errors', _RED)}")
        for err in pol.errors:
            print(f"    {err}")

    _org_managed_hint(workspace)


# ── test ─────────────────────────────────────────────────────────────────────

def egress_test(workspace: Path, targets: List[str], agent: str = "") -> None:
    """Dry-run destinations or whole shell commands against the live policy."""
    _refresh_remote()
    engine = _engine(workspace)
    pol = engine.egress
    if not pol.enabled:
        print(_c("egress screening is disabled — nothing would be screened.", _YELLOW))
        print(_c("Run `prismor egress enable` first.", _DIM))
        sys.exit(1)

    exit_code = 0
    for target in targets:
        # A single whitespace-free token is a bare host/URL and screens as a
        # network event; anything with a space is a shell command, even though
        # it may well contain a URL of its own.
        is_bare_target = not target.strip().split()[1:] if target.strip() else False
        event = ({"type": "network", "url": target.strip()} if is_bare_target
                 else {"type": "shell", "command": target})
        if agent:
            event["agent_name"] = agent

        dests = extract_destinations(event)
        findings = pol.evaluate(
            event, 0, agent_name=agent,
            default_mode=engine.default_mode, device_mode=engine.device_mode,
        )
        print(_c(target, _BOLD))
        if not dests:
            print(_c("  no network destination found", _DIM))
            continue
        blocked = {f.get("egressHost") for f in findings if f.get("mode") == "enforce"}
        warned = {f.get("egressHost") for f in findings if f.get("mode") != "enforce"}
        for d in dests:
            if d.host in blocked:
                verdict, color = "BLOCK", _RED
                exit_code = 1
            elif d.host in warned:
                verdict, color = "WARN", _YELLOW
            else:
                verdict, color = "allow", _GREEN
            extra = []
            if d.scheme:
                extra.append(d.scheme)
            if d.is_private and pol.allow_private:
                extra.append("private")
            suffix = _c(f"  [{', '.join(extra)}]", _DIM) if extra else ""
            print(f"  {_c(verdict, color):<18} {d.label()}{suffix}")
        for f in findings:
            if f.get("title"):
                print(_c(f"    → {f['title']}", _DIM))
    sys.exit(exit_code)


# ── report ───────────────────────────────────────────────────────────────────

def _recent_sessions(workspace: Path, limit: int) -> List[Tuple[str, Path]]:
    from prismor.runtime.store import get_sessions_dir

    sdir = get_sessions_dir(workspace)
    if not sdir.exists():
        return []
    files = sorted(sdir.glob("*.jsonl"), key=lambda p: p.stat().st_mtime, reverse=True)
    return [(p.stem, p) for p in files[:limit]]


def _session_events(workspace: Path, session_id: str) -> List[Dict[str, Any]]:
    from prismor.runtime.store import read_session_events

    try:
        return read_session_events(workspace, session_id)
    except FileNotFoundError:
        return []


def egress_report(workspace: Path, last: int = 20, fail_on_block: bool = False) -> None:
    """What did the agents on this machine actually contact?

    The intended workflow before flipping to enforce: every row is a real
    destination from a real session, with the verdict the current policy would
    give it. Anything marked BLOCK is what turning on enforcement would break.
    """
    engine = _engine(workspace)
    pol = engine.egress

    # host -> [count, first_evidence, set(ports), set(sessions)]
    seen: Dict[str, Dict[str, Any]] = {}
    sessions = _recent_sessions(workspace, last)
    if not sessions:
        print("no recorded sessions yet — run some agent sessions first")
        return

    for sid, _ in sessions:
        for ev in _session_events(workspace, sid):
            if str(ev.get("type") or "") not in ("network", "shell"):
                continue
            try:
                dests = extract_destinations(ev)
            except Exception:
                continue
            for d in dests:
                rec = seen.setdefault(d.host, {
                    "count": 0, "evidence": d.evidence, "ports": set(),
                    "sessions": set(), "dest": d,
                })
                rec["count"] += 1
                rec["sessions"].add(sid)
                if d.port:
                    rec["ports"].add(d.port)

    if not seen:
        print(f"no outbound destinations in the last {len(sessions)} session(s)")
        return

    rows: List[Tuple[str, str, Dict[str, Any]]] = []
    for host, rec in seen.items():
        if pol.enabled:
            action, _entry = pol.verdict(rec["dest"])
            if action == "allow":
                verdict = "allow"
            elif action == "warn":
                verdict = "warn"
            elif action == "deny":
                verdict = "deny"
            else:
                verdict = "off-list"
        else:
            verdict = "-"
        rows.append((host, verdict, rec))

    order = {"deny": 0, "off-list": 1, "warn": 2, "allow": 3, "-": 4}
    rows.sort(key=lambda r: (order.get(r[1], 9), -r[2]["count"], r[0]))

    print(_c(f"{'DESTINATION':<46} {'CALLS':>6}  {'PORTS':<14} VERDICT", _BOLD))
    blocked_hosts: List[str] = []
    for host, verdict, rec in rows:
        color = {"deny": _RED, "off-list": _RED, "warn": _YELLOW,
                 "allow": _GREEN}.get(verdict, _DIM)
        ports = ",".join(str(p) for p in sorted(rec["ports"])) or "-"
        print(f"{host:<46} {rec['count']:>6}  {ports:<14} {_c(verdict, color)}")
        if verdict in ("deny", "off-list"):
            blocked_hosts.append(host)

    print(_c(f"\n{len(rows)} destination(s) across {len(sessions)} session(s)", _DIM))

    if not pol.enabled:
        print(_c("\negress screening is disabled — no verdicts applied. "
                 "Enable it with `prismor egress enable`.", _YELLOW))
        return

    if blocked_hosts:
        mode = pol.mode or engine.device_mode or engine.default_mode
        would = "are being blocked" if mode == "enforce" else "would block if you flip to enforce"
        print(_c(f"\n{len(blocked_hosts)} destination(s) {would}:", _YELLOW))
        print("  prismor egress allow " + " ".join(blocked_hosts[:8]))
        if len(blocked_hosts) > 8:
            print(_c(f"  … and {len(blocked_hosts) - 8} more", _DIM))
        if fail_on_block:
            sys.exit(1)
    else:
        print(_c("\nevery recorded destination is allowed by the current policy.", _GREEN))


# ── mutation ─────────────────────────────────────────────────────────────────

def _mutate_list(workspace: Path, key: str, hosts: List[str], reason: str = "") -> None:
    from prismor.runtime.egress import EgressEntry

    data = _load_policy_file(workspace)
    block = _egress_block(data)
    current = block.setdefault(key, [])
    if not isinstance(current, list):
        current = []
        block[key] = current

    added: List[str] = []
    for host in hosts:
        try:
            EgressEntry(host, key)  # validate before writing
        except ValueError as exc:
            print(_c(f"invalid host {host!r}: {exc}", _RED))
            sys.exit(2)
        existing = {h if isinstance(h, str) else h.get("host") for h in current}
        if host in existing:
            print(_c(f"{host} already in {key}", _DIM))
            continue
        current.append({"host": host, "reason": reason} if reason else host)
        added.append(host)

    if not added:
        # Still say whether the file even applies: "already in allow" while the
        # org's policy blocks the host reads as "should work" when it cannot.
        _org_managed_hint(workspace)
        return
    # Adding a rule to a policy nobody enabled is a silent no-op — turn it on.
    if not block.get("enabled"):
        block["enabled"] = True
        print(_c("enabled egress screening (mode: observe)", _CYAN))
        block.setdefault("mode", "observe")
    _save_policy_file(workspace, data)
    color = _GREEN if key == "allow" else _RED
    print(f"{_c(key, color)}: {', '.join(added)}")
    _org_managed_hint(workspace)


def egress_allow(workspace: Path, hosts: List[str], reason: str = "") -> None:
    _mutate_list(workspace, "allow", hosts, reason)


def egress_deny(workspace: Path, hosts: List[str], reason: str = "") -> None:
    _mutate_list(workspace, "deny", hosts, reason)


def egress_rm(workspace: Path, hosts: List[str]) -> None:
    data = _load_policy_file(workspace)
    block = _egress_block(data)
    removed: List[str] = []
    for key in ("allow", "deny"):
        current = block.get(key)
        if not isinstance(current, list):
            continue
        kept = []
        for item in current:
            host = item if isinstance(item, str) else (item or {}).get("host")
            if host in hosts:
                removed.append(f"{key}:{host}")
            else:
                kept.append(item)
        block[key] = kept
    if not removed:
        print(_c("nothing removed — no matching entries", _DIM))
        return
    _save_policy_file(workspace, data)
    print(f"removed {', '.join(removed)}")
    _org_managed_hint(workspace)


def egress_set(workspace: Path, field: str, value: Any) -> None:
    data = _load_policy_file(workspace)
    block = _egress_block(data)
    block[field] = value
    if field != "enabled":
        block.setdefault("enabled", True)
    _save_policy_file(workspace, data)
    print(f"egress.{field} = {_c(str(value), _CYAN)}")
    if field == "mode" and value == "enforce":
        print(_c("calls to destinations outside the policy will now be BLOCKED. "
                 "Check `prismor egress report` first if you have not.", _YELLOW))
    _org_managed_hint(workspace)


def egress_migrate(workspace: Path) -> None:
    """Move a legacy settings.egress_allowlist into settings.egress.

    The legacy list is warn-only by design; migrating is the explicit step that
    makes it enforceable, so we land in observe mode and let the operator flip.
    """
    data = _load_policy_file(workspace)
    settings = data.get("settings") or {}
    legacy = settings.get("egress_allowlist") or []
    if not legacy:
        print("no settings.egress_allowlist in .prismor/policy.yaml — nothing to migrate")
        return
    block = _egress_block(data)
    merged = list(block.get("allow") or [])
    existing = {h if isinstance(h, str) else (h or {}).get("host") for h in merged}
    merged.extend(h for h in legacy if h not in existing)
    block["allow"] = merged
    block.setdefault("enabled", True)
    block.setdefault("mode", "observe")
    block.setdefault("default", "deny")
    settings.pop("egress_allowlist", None)
    _save_policy_file(workspace, data)
    print(f"migrated {len(legacy)} entr{'y' if len(legacy) == 1 else 'ies'} "
          f"into settings.egress.allow (default: deny, mode: observe)")
    print(_c("run `prismor egress report`, then `prismor egress mode enforce`.", _DIM))
    _org_managed_hint(workspace)


# ── request ──────────────────────────────────────────────────────────────────

def _request_host(raw: str) -> str:
    """Reduce what people paste to the host the policy matches on:
    ``https://Docs.Example.com/path?q=1`` → ``docs.example.com``."""
    from urllib.parse import urlsplit

    h = str(raw or "").strip()
    if "://" in h:
        h = urlsplit(h).hostname or h
    return h.lower().rstrip(".")


def _is_catch_all(host: str) -> bool:
    """``*`` or a CIDR that spans most of the address space."""
    if host == "*":
        return True
    if "/" in host:
        addr, _, bits = host.partition("/")
        try:
            n = int(bits)
        except ValueError:
            return False
        return n < (16 if ":" in addr else 8)
    return False


def egress_request(workspace: Path, host: str, reason: str = "") -> None:
    """Ask the org's admins to allow a destination.

    Device-authenticated POST; the console files it as a pending request in
    Policy → Requests. Approving adds the host to the egress allowlist of the
    policy that governs this device, which reaches it on the next pull. The
    developer can only ask: nothing is relaxed until an admin approves.
    """
    import json as _json
    import urllib.error
    import urllib.request

    from prismor.runtime.egress import EgressEntry
    from prismor.runtime.enterprise import identity as _identity
    from prismor.runtime.enterprise import workspace_scope as _scope

    host = _request_host(host)
    try:
        EgressEntry(host, "allow")
    except ValueError as exc:
        print(_c(f"invalid host {host!r}: {exc}", _RED))
        sys.exit(2)
    if _is_catch_all(host):
        print(_c(f"{host!r} would allow every destination — request the specific host "
                 "your agent needs (for example www.linkedin.com or *.linkedin.com).", _RED))
        sys.exit(2)
    ident = _identity.load_identity()
    if not ident:
        print("This machine is not enrolled with an org, so there is no admin to ask.")
        print(f"Allow it locally instead:  prismor egress allow {host}")
        sys.exit(1)
    if _identity.revoked_info():
        print(_c("This device was removed from its org, so the request cannot be sent.", _RED))
        print("Re-link it with: prismor enroll <token>")
        sys.exit(1)
    if not reason.strip():
        print(_c("A reason is required, so the admin can judge the request:", _YELLOW))
        print(f'  prismor egress request {host} --reason "what the agent needs it for"')
        sys.exit(2)

    base = str(ident.get("api_base") or _identity.api_base()).rstrip("/")
    payload = _json.dumps({
        "host": host,
        "reason": reason.strip()[:1000],
        "repo": _scope.detect_git_remote(workspace) or "",
    }).encode("utf-8")
    req = urllib.request.Request(
        f"{base}/api/devices/egress-requests", data=payload, method="POST",
        headers={"Content-Type": "application/json", "User-Agent": user_agent(),
                 "Authorization": f"Bearer {ident.get('device_key')}"},
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:  # fixed or operator-configured URL  # nosec B310
            body = _json.loads(resp.read().decode("utf-8") or "{}")
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", "replace")[:2000] if exc.fp else ""
        try:
            detail = _json.loads(raw).get("message") or ""
        except Exception:
            detail = ""  # an HTML error page is noise, never print it
        if exc.code == 404 and not detail:
            # A console from before egress requests existed.
            print(_c("Your org's Prismor console does not accept egress requests yet.", _YELLOW))
            print(f"Ask an admin to allow {host} under Policy → Network egress in the console.")
            sys.exit(1)
        print(_c(f"Request failed ({exc.code}): {detail or exc.reason}", _RED))
        sys.exit(1)
    except (urllib.error.URLError, ValueError, OSError) as exc:
        print(_c(f"Request failed: {exc}", _RED))
        sys.exit(1)

    if body.get("status") == "already_allowed":
        print(_c(f"{host} is already on your org's egress allowlist.", _GREEN))
        print(body.get("message") or "Your device picks it up on the next policy pull (~30s).")
        return
    print(_c(f"Requested access to {host}.", _GREEN))
    print(f"  reason: {reason.strip()}")
    print("  → It is waiting for an org admin in the Prismor console (Policy → Requests).")
    print("    Once approved it reaches this device within ~30s; until then the block stays.")
    # The console returns links matched to this person's role: everyone can
    # track their own request; admins also get the queue where it is decided.
    if body.get("trackUrl"):
        print(f"  track it:   {body['trackUrl']}")
    if body.get("reviewUrl"):
        print(f"  approve it: {body['reviewUrl']}  (you are an org admin)")
    if body.get("note"):
        print(_c(f"  note: {body['note']}", _YELLOW))
