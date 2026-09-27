"""prismor/runtime/agents.py — Named agent registry and per-agent runtime control.

An agent *name* is an instance label distinct from the framework id. Multiple
agents using the same framework ("vercel-ai") can have different names and
independent control settings.

Config resolution order (mirrors iam.py):
  1. ~/.prismor/agents.yaml          (global, user-level)
  2. .prismor/agents.yaml     (per-project, takes precedence)

Config format:
  agents:
    support-bot:
      framework: vercel-ai       # auto-filled on first discovery
      enabled: true              # false = hard block ALL calls (kill switch)
      mode: enforce              # null/absent = inherit; else "observe"/"enforce"
      iam_profile: readonly-bot  # optional — enforce this IAM profile for this agent
      last_seen: 2026-06-28T...  # auto-updated on discovery

``enabled: false`` injects a CRITICAL blocking finding so the Decision flows
through the normal should_block → telemetry path unchanged.  The caller (runtime)
is responsible for using ``control.iam_profile`` when calling check_iam.
"""
from __future__ import annotations

import json
import sys
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

def _global_agents_path() -> Path:
    """Global agents.yaml path, honoring $PRISMOR_HOME (see PrismorSec/prismor#131)."""
    from prismor.runtime.store import prismor_home
    return prismor_home() / "agents.yaml"


_PROJECT_AGENTS_FILE = "agents.yaml"

# Module-level seen-set: throttle record_seen() so we only update the YAML
# once per agent per process, not on every tool call.
_SEEN_THIS_PROCESS: set = set()
_TOOLS_SEEN_THIS_PROCESS: set = set()

# On-disk debounce for control-plane registration: 1000 short-lived processes
# must not turn into 1000 POSTs per agent per day.
_REGISTER_DEBOUNCE_SECONDS = 3600.0

# (path+mtime) → parsed config
_CONFIG_CACHE: Dict[Any, Dict[str, Any]] = {}


# ── Config I/O ────────────────────────────────────────────────────────────────

def _load_yaml(path: Path) -> Optional[Dict[str, Any]]:
    if not path.exists():
        return None
    try:
        import yaml
        return yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except Exception as exc:
        sys.stderr.write(f"[prismor/runtime/agents] failed to load {path}: {exc}\n")
        return None


def _mtime(path: Path) -> float:
    try:
        return path.stat().st_mtime
    except OSError:
        return -1.0


def load_agents_config(workspace: Optional[Path] = None) -> Dict[str, Any]:
    """Load agents config, project overrides global. (path+mtime)-memoized."""
    global_path = _global_agents_path()
    project_path = (
        workspace / ".prismor" / _PROJECT_AGENTS_FILE if workspace else None
    )
    cache_key = (
        str(global_path), _mtime(global_path),
        str(project_path) if project_path else "",
        _mtime(project_path) if project_path else -1.0,
    )
    cached = _CONFIG_CACHE.get(cache_key)
    if cached is not None:
        return cached

    config: Dict[str, Any] = {}
    global_cfg = _load_yaml(global_path)
    if global_cfg:
        config.update(global_cfg)
    if project_path is not None:
        project_cfg = _load_yaml(project_path)
        if project_cfg:
            project_agents = project_cfg.get("agents", {})
            if project_agents:
                config.setdefault("agents", {}).update(project_agents)
            # Carry project-level across-agents controls through the merge —
            # load_agents_config otherwise only pulls the ``agents`` map.
            if project_cfg.get("global_deny_tools"):
                config["global_deny_tools"] = project_cfg["global_deny_tools"]
            if project_cfg.get("global_ask_tools"):
                config["global_ask_tools"] = project_cfg["global_ask_tools"]

    _CONFIG_CACHE[cache_key] = config
    return config


# ── Data model ────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class AgentControl:
    """Per-instance control settings for one named agent."""

    name: str
    framework: str = ""
    enabled: bool = True      # False = kill switch (hard block all calls)
    mode: Optional[str] = None   # None = inherit global mode; "observe"/"enforce"
    iam_profile: Optional[str] = None  # IAM profile name to enforce for this agent
    deny_tools: tuple = ()  # tool tags blocked for this agent (per-agent + global union)
    ask_tools: tuple = ()   # tool tags requiring human approval (step_up) for this agent
    last_seen: Optional[str] = None
    # Which layer disabled the agent: "local" (agents.yaml), "org" (the signed
    # remote policy's settings.agent_controls), "both", or None when enabled.
    disabled_by: Optional[str] = None


_DEFAULT = AgentControl(name="")  # sentinel — used for agents not in the registry


def resolve_agent_control(
    name: str,
    workspace: Optional[Path] = None,
    remote_controls: Optional[Dict[str, Any]] = None,
) -> AgentControl:
    """Return the AgentControl for ``name``, merging local and org controls.

    ``remote_controls`` is the org's ``settings.agent_controls`` map from the
    VERIFIED signed policy (present only on org-managed workspaces — the
    runtime passes ``engine.agent_controls``). The merge is tighten-only:

    * ``enabled`` — local AND remote: an org kill-switch cannot be re-enabled
      locally, and a local disable holds even if the org says enabled.
    * ``mode`` — remote wins when set (the org admin is the same authority
      that sets the global mode); else local.
    * ``iam_profile`` — remote wins when set. The named profile must be
      defined in the local/project iam.yaml (remote selects among locally
      defined profiles; it doesn't ship definitions).

    Returns a permissive default (enabled=True, mode=None, iam_profile=None)
    when the agent is in neither registry, so unregistered agents are
    unaffected by the control layer.
    """
    if not name:
        return AgentControl(name=name)
    config = load_agents_config(workspace)
    entry = config.get("agents", {}).get(name) or {}
    remote = (remote_controls or {}).get(name)
    remote = remote if isinstance(remote, dict) else {}
    _global_deny = tuple(config.get("global_deny_tools") or ())
    _global_ask = tuple(config.get("global_ask_tools") or ())
    if not entry and not remote:
        # deny wins over ask: a tool on both lists is denied, never merely asked.
        _ask = tuple(t for t in _global_ask if t not in _global_deny)
        return AgentControl(name=name, deny_tools=_global_deny, ask_tools=_ask)

    local_enabled = bool(entry.get("enabled", True))
    remote_enabled = bool(remote.get("enabled", True))
    remote_mode = remote.get("mode") if remote.get("mode") in ("observe", "enforce") else None
    disabled_by = (
        "both" if not local_enabled and not remote_enabled
        else "org" if not remote_enabled
        else "local" if not local_enabled
        else None
    )
    _merged_deny = tuple(dict.fromkeys([
        *_global_deny, *(entry.get("deny_tools") or ()), *(remote.get("deny_tools") or ())
    ]))
    return AgentControl(
        name=name,
        framework=entry.get("framework", ""),
        enabled=local_enabled and remote_enabled,
        mode=remote_mode or entry.get("mode") or None,
        iam_profile=remote.get("iam_profile") or entry.get("iam_profile") or None,
        deny_tools=_merged_deny,
        # ask = union of all ask lists MINUS anything denied (deny wins).
        ask_tools=tuple(t for t in dict.fromkeys([
            *_global_ask, *(entry.get("ask_tools") or ()), *(remote.get("ask_tools") or ())
        ]) if t not in _merged_deny),
        last_seen=entry.get("last_seen"),
        disabled_by=disabled_by,
    )


def list_agents(
    workspace: Optional[Path] = None,
    remote_controls: Optional[Dict[str, Any]] = None,
) -> List[AgentControl]:
    """Return all agents known to either registry (local config + org controls).

    Each entry is the merged effective control (see resolve_agent_control), so
    the union of locally-configured and org-controlled agents is returned with
    ``disabled_by`` set to whichever layer(s) apply.
    """
    config = load_agents_config(workspace)
    names = set(config.get("agents", {}).keys())
    if isinstance(remote_controls, dict):
        names.update(remote_controls.keys())
    return [resolve_agent_control(name, workspace, remote_controls) for name in sorted(names)]


# ── Writes ────────────────────────────────────────────────────────────────────

def _write_project_config(workspace: Path, config: Dict[str, Any]) -> None:
    """Write the project agents.yaml atomically."""
    try:
        import yaml
    except ImportError:
        sys.stderr.write("[prismor/runtime/agents] PyYAML not available; cannot write agents.yaml\n")
        return
    path = workspace / ".prismor" / _PROJECT_AGENTS_FILE
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.dump(config, default_flow_style=False, sort_keys=True), encoding="utf-8")
    # Bust cache so next read picks up the change
    _CONFIG_CACHE.clear()


def upsert_agent(name: str, workspace: Path, **fields: Any) -> AgentControl:
    """Write/merge control fields for ``name`` into the project agents.yaml.

    Accepted fields: ``enabled`` (bool), ``mode`` (str|None),
    ``iam_profile`` (str|None), ``framework`` (str), ``last_seen`` (str).
    Returns the updated AgentControl.
    """
    # Load current project config (not the merged global+project, so we only
    # persist project-level overrides).
    project_path = workspace / ".prismor" / _PROJECT_AGENTS_FILE
    existing: Dict[str, Any] = {}
    if project_path.exists():
        loaded = _load_yaml(project_path)
        if loaded:
            existing = loaded

    agents = existing.setdefault("agents", {})
    entry: Dict[str, Any] = agents.get(name, {})

    ALLOWED_FIELDS = {"enabled", "mode", "iam_profile", "framework", "last_seen", "deny_tools", "ask_tools"}
    for k, v in fields.items():
        if k in ALLOWED_FIELDS:
            if v is None and k in entry:
                del entry[k]
            else:
                entry[k] = v
    agents[name] = entry
    existing["agents"] = agents

    _write_project_config(workspace, existing)
    return resolve_agent_control(name, workspace)


def record_seen(
    name: str,
    framework: str,
    workspace: Optional[Path],
    *,
    tools: Optional[List[Any]] = None,
    session_id: str = "",
) -> None:
    """Auto-register a discovered agent; best-effort, once per process per agent.

    Registers locally (project agents.yaml) and, for enrolled devices working
    in an org-managed workspace, tells the control plane the instance exists —
    so a deployed agent shows up in the org's fleet view even before it emits
    its first finding.
    """
    if not name or not workspace:
        return
    seen_key = (name, str(workspace))
    if seen_key not in _SEEN_THIS_PROCESS:
        _SEEN_THIS_PROCESS.add(seen_key)
        try:
            upsert_agent(
                name, workspace,
                framework=framework,
                last_seen=datetime.now(timezone.utc).isoformat(),
            )
        except Exception as exc:
            sys.stderr.write(f"[prismor/runtime/agents] record_seen error: {exc}\n")
    try:
        _register_remote(name, framework, workspace, tools=tools, session_id=session_id)
    except Exception:
        pass  # never let fleet bookkeeping affect the tool-call path


def _register_debounce_path() -> Path:
    from prismor.runtime.enterprise import identity as _identity
    return _identity.prismor_home() / "agent-register.json"


def _register_remote(
    name: str,
    framework: str,
    workspace: Path,
    *,
    tools: Optional[List[Any]] = None,
    session_id: str = "",
) -> None:
    """Best-effort fleet registration with the org control plane.

    Guards (all must hold): device enrolled, no revoked-key backoff, workspace
    org-managed (personal workspaces never report anything). Debounced on disk
    per instance so short-lived processes don't hammer the endpoint; the POST
    itself runs on a daemon thread so the hook hot path never waits on the
    network. Failures are silent — the control plane's ingest-side upsert is
    the safety net for anything missed here.
    """
    from prismor.runtime.enterprise import identity as _identity
    ident = _identity.load_identity()
    if not ident or _identity.revoked_backoff_active():
        return
    from prismor.runtime.enterprise import workspace_scope as _scope
    if not _scope.is_managed(workspace):
        return

    # On-disk debounce (optimistic: marked before the POST; a failed POST waits
    # out the window, which the ingest-side upsert covers).
    remote_name = name if name != framework else ""
    key = f"agent|{framework}|{remote_name}"
    now = time.time()
    path = _register_debounce_path()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            data = {}
    except (OSError, ValueError):
        data = {}
    agent_due = now - float(data.get(key, 0) or 0) >= _REGISTER_DEBOUNCE_SECONDS
    if agent_due:
        data[key] = now

    normalized_tools: List[Dict[str, str]] = []
    for raw in tools or []:
        if isinstance(raw, dict):
            tool = str(raw.get("name") or "").strip()[:160]
            source = str(raw.get("source") or "observed")
        else:
            tool = str(raw or "").strip()[:160]
            source = "declared"
        if not tool or tool == "*":
            continue
        if source not in {"observed", "scoped", "declared"}:
            source = "observed"
        process_key = (framework, remote_name, session_id, tool)
        disk_key = f"tool|{framework}|{remote_name}|{session_id[:80]}|{tool}"
        if process_key in _TOOLS_SEEN_THIS_PROCESS:
            continue
        if now - float(data.get(disk_key, 0) or 0) < _REGISTER_DEBOUNCE_SECONDS:
            _TOOLS_SEEN_THIS_PROCESS.add(process_key)
            continue
        _TOOLS_SEEN_THIS_PROCESS.add(process_key)
        data[disk_key] = now
        normalized_tools.append({"name": tool, "source": source})
    if not agent_due and not normalized_tools:
        return
    # Keep the debounce file bounded: drop entries older than a day.
    data = {k: v for k, v in data.items() if now - float(v or 0) < 86400.0}
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data), encoding="utf-8")
    except OSError:
        pass

    payload = {"agents": [{
        "name": remote_name,
        "framework": framework,
        "sessionId": session_id[:80],
        "tools": normalized_tools,
    }]}
    threading.Thread(target=_post_registration, args=(dict(ident), payload), daemon=True).start()


def _post_registration(ident: Dict[str, Any], payload: Dict[str, Any]) -> None:
    """POST the registration; swallow every failure (best-effort by design)."""
    try:
        import urllib.request
        from prismor.runtime.enterprise import identity as _identity
        base = str(ident.get("api_base") or _identity.api_base()).rstrip("/")
        req = urllib.request.Request(
            f"{base}/api/agents/register",
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {ident.get('device_key')}",
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=5):  # fixed or operator-configured URL  # nosec B310
            pass
    except Exception:
        pass


# ── Kill-switch finding ────────────────────────────────────────────────────────

def make_disabled_finding(
    name: str, session_id: str = "", disabled_by: Optional[str] = None
) -> Dict[str, Any]:
    """Return a CRITICAL blocking finding for a disabled (paused) agent.

    ``disabled_by`` names the layer that pulled the kill switch ("local",
    "org", "both") so the developer sees WHERE to go to lift it — a local
    re-enable can never lift an org-pushed pause.
    """
    if disabled_by == "org":
        evidence = f"agent '{name}' is paused by your org's control plane (signed policy)"
        remediation = f"Ask an org admin to re-enable '{name}' in the dashboard's fleet view."
    elif disabled_by == "both":
        evidence = f"agent '{name}' is paused locally AND by your org's control plane"
        remediation = (
            f"Ask an org admin to re-enable '{name}' in the dashboard, "
            f"then: prismor agents set {name} --enabled"
        )
    else:
        evidence = f"agent '{name}' is disabled in .prismor/agents.yaml"
        remediation = f"Re-enable via dashboard or: prismor agents set {name} --enabled"
    return {
        "id": f"{session_id}:agent-disabled:{name}",
        "ruleId": "agent-disabled",
        "severity": "critical",
        "category": "agent-control",
        "mode": "enforce",  # always blocks regardless of policy mode
        "title": f"[agent:{name}] Agent is paused — all tool calls blocked",
        "evidence": evidence,
        "eventIndex": 0,
        "remediation": remediation,
    }


def set_tool_policy(
    workspace: Path, scope: str, tool: str, action: str, agent: Optional[str] = None
) -> Dict[str, List[str]]:
    """Set a tool tag's handling at ``agent`` or ``global`` scope in agents.yaml.

    Three states, matching the console's per-tool control:

    * ``allow`` — the tool runs (lifts any deny/ask on it).
    * ``ask``   — the call requires human approval (a step_up finding → the
      approvals queue). Written to ``ask_tools``.
    * ``deny``  — the call is blocked. Written to ``deny_tools``.

    The three are mutually exclusive per tool: setting one clears the tool from
    the other list, so a tool is never both denied and asked (deny would win at
    eval time anyway, but keeping the lists disjoint keeps the UI honest).

    ``scope``: "global" (top-level ``global_deny_tools`` / ``global_ask_tools``,
    applied to every agent) or "agent" (``agents.<agent>.{deny,ask}_tools``).
    Returns ``{"deny_tools": [...], "ask_tools": [...]}`` for the chosen scope.
    """
    tool = (tool or "").strip()
    if not tool:
        raise ValueError("tool required")
    if action not in ("allow", "ask", "deny"):
        raise ValueError(f"action must be allow|ask|deny, got {action!r}")
    project_path = workspace / ".prismor" / _PROJECT_AGENTS_FILE
    existing: Dict[str, Any] = {}
    if project_path.exists():
        loaded = _load_yaml(project_path)
        if loaded:
            existing = loaded

    def _apply(container: Dict[str, Any], deny_key: str, ask_key: str) -> Dict[str, List[str]]:
        deny = [t for t in (container.get(deny_key) or []) if t != tool]
        ask = [t for t in (container.get(ask_key) or []) if t != tool]
        if action == "deny":
            deny.append(tool)
        elif action == "ask":
            ask.append(tool)
        # "allow" leaves the tool off both lists.
        for key, lst in ((deny_key, deny), (ask_key, ask)):
            if lst:
                container[key] = lst
            else:
                container.pop(key, None)
        return {"deny_tools": deny, "ask_tools": ask}

    if scope == "global":
        result = _apply(existing, "global_deny_tools", "global_ask_tools")
    else:
        if not agent:
            raise ValueError("agent required for agent scope")
        agents = existing.setdefault("agents", {})
        entry: Dict[str, Any] = agents.get(agent, {}) or {}
        result = _apply(entry, "deny_tools", "ask_tools")
        if entry:
            agents[agent] = entry
        else:
            agents.pop(agent, None)
        existing["agents"] = agents
    _write_project_config(workspace, existing)
    return result


def make_agent_tool_deny_finding(
    name: str, tool: str, session_id: str = "", scope_label: str = "agent",
    rule_id: str = "agent-tool-deny",
) -> Dict[str, Any]:
    """Blocking finding for a tool tag on an agent/global/org deny list."""
    return {
        "id": f"{session_id}:{rule_id}:{name}:{tool}",
        "ruleId": rule_id,
        "severity": "high",
        "category": "agent-control",  # blocks regardless of observe/enforce mode
        "mode": "enforce",
        "title": f"[agent:{name}] Tool '{tool}' is denied ({scope_label} scope)",
        "evidence": f"tool '{tool}' is on the {scope_label} deny list",
        "eventIndex": 0,
        "remediation": "Lift it from the dashboard Tool Call panel or edit .prismor/agents.yaml",
    }


def make_agent_tool_step_up_finding(
    name: str, tool: str, session_id: str = "", scope_label: str = "org",
    rule_id: str = "org-tool-step-up",
) -> Dict[str, Any]:
    """Human-approval finding for a tool an admin marked ``step_up``.

    Same shape as :func:`make_agent_tool_deny_finding` but carrying
    ``action: step_up``, which ``hooks.should_block`` ranks below block and
    above defer. Interactive agents render it as an inline ask; headless ones
    post an approval request (see enterprise.approvals) and wait. Every
    non-approval outcome still fails closed, so this is strictly softer than a
    deny and never softer than allowing the call.
    """
    return {
        "id": f"{session_id}:{rule_id}:{name}:{tool}",
        "ruleId": rule_id,
        "action": "step_up",
        "severity": "high",
        "category": "agent-control",  # applies regardless of observe/enforce
        "mode": "enforce",
        "title": f"[approval required] Tool '{tool}' needs a human decision ({scope_label} scope)",
        "evidence": f"tool '{tool}' is marked step_up on the {scope_label} policy",
        "eventIndex": 0,
        "remediation": "Approve or deny in the Prismor console (Approvals), or via Slack / your webhook",
    }


# ── Display ────────────────────────────────────────────────────────────────────

def format_agent_table(agents: List[AgentControl]) -> str:
    if not agents:
        return "  (no named agents registered)"
    lines = [
        f"  {'NAME':<20} {'FRAMEWORK':<16} {'ENABLED':<8} {'MODE':<10} {'IAM PROFILE':<18} {'SOURCE':<8}",
        "  " + "-" * 84,
    ]
    for a in agents:
        # SOURCE reflects where a disable came from (org/local/both); an enabled
        # agent shows blank so the column only draws attention to kill switches.
        source = a.disabled_by or ""
        lines.append(
            f"  {a.name:<20} {a.framework:<16} {'yes' if a.enabled else 'NO':<8} "
            f"{(a.mode or '(global)'):<10} {(a.iam_profile or ''):<18} {source:<8}"
        )
    return "\n".join(lines)
