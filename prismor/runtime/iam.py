"""Prismor IAM — named agent identity and permission profiles.

Agent identities are defined in YAML config files. Config resolution order:
  1. ~/.prismor/iam.yaml          (global, user-level)
  2. .prismor/iam.yaml     (per-project, takes precedence)

The active agent identity is set via the PRISMOR_AGENT_ID environment variable.
If unset, no IAM restrictions are applied beyond the base Prismor policy.

Trust boundary: PRISMOR_AGENT_ID is inherited by the agent being constrained, so
IAM guards cooperative/misconfigured agents, not adversarial ones. See the
``check_iam`` docstring for details and mitigations.

Config format:
  agents:
    readonly-bot:
      allowed_tools: [Read]
      deny_tools: []
      deny_network: true
      allowed_paths: ["**"]

    researcher:
      allowed_tools: [Read, WebFetch, WebSearch]
      deny_tools: [Bash, Write, Edit]
      deny_network: false
      allowed_paths: ["**"]

    code-reviewer:
      allowed_tools: [Read, Bash]
      deny_tools: [Write, Edit, WebFetch, WebSearch]
      deny_network: true
      allowed_paths: ["**"]
"""
from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

def _global_iam_path() -> Path:
    """Global iam.yaml path, honoring $PRISMOR_HOME (see PrismorSec/prismor#131)."""
    from prismor.runtime.store import prismor_home
    return prismor_home() / "iam.yaml"


_PROJECT_IAM_FILENAME = "iam.yaml"

_STARTER_CONFIG = """\
# Prismor — IAM agent identity config
# Set PRISMOR_AGENT_ID=<name> before launching an agent to apply its profile.
# Per-project overrides go in .prismor/iam.yaml

agents:
  # Read-only agent: can only inspect files, no writes or network.
  readonly-bot:
    allowed_tools: [Read]
    deny_tools: []
    deny_network: true
    allowed_paths: ["**"]

  # Research agent: can read and fetch URLs, but cannot write files.
  researcher:
    allowed_tools: [Read, WebFetch, WebSearch]
    deny_tools: [Bash, Write, Edit, MultiEdit]
    deny_network: false
    allowed_paths: ["**"]

  # Code reviewer: can read and run shell commands, but cannot write.
  code-reviewer:
    allowed_tools: [Read, Bash]
    deny_tools: [Write, Edit, MultiEdit, WebFetch, WebSearch]
    deny_network: true
    allowed_paths: ["**"]

  # Full-access agent: no IAM restrictions (still subject to base policy).
  # Remove or rename to disable unrestricted access.
  trusted-agent:
    allowed_tools: [Read, Write, Edit, MultiEdit, Bash, WebFetch, WebSearch]
    deny_tools: []
    deny_network: false
    allowed_paths: ["**"]
"""


# ── Config loading ─────────────────────────────────────────────────────────

def _load_yaml(path: Path) -> Optional[Dict[str, Any]]:
    if not path.exists():
        return None
    try:
        import yaml
        return yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except Exception as exc:
        sys.stderr.write(f"[prismor/runtime/iam] failed to load {path}: {exc}\n")
        return None


def _mtime(path: Path) -> float:
    try:
        return path.stat().st_mtime
    except OSError:
        return -1.0


# path+mtime keyed memo. Per-event hook runs are separate processes so this is
# a no-op there, but the long-lived `prismor dashboard` server calls load_iam_config
# on every request — this keeps it off the YAML parser in the hot path while
# still reloading automatically when either config file changes on disk.
_CONFIG_CACHE: Dict[Any, Dict[str, Any]] = {}


def load_iam_config(workspace: Optional[Path] = None) -> Dict[str, Any]:
    """Load IAM config. Project-level agents override global agents.

    Memoized on the (path, mtime) of both config files; a change to either
    file invalidates the cache automatically on the next call.
    """
    global_path = _global_iam_path()
    project_path = (
        workspace / ".prismor" / _PROJECT_IAM_FILENAME if workspace else None
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

    _CONFIG_CACHE[cache_key] = config
    return config


# ── Identity resolution ────────────────────────────────────────────────────

def get_active_agent_id() -> Optional[str]:
    """Return the active agent identity from PRISMOR_AGENT_ID, or None."""
    return os.environ.get("PRISMOR_AGENT_ID") or None


def resolve_agent_profile(agent_id: str, config: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Look up the permission profile for a named agent identity."""
    return config.get("agents", {}).get(agent_id)


def list_agent_ids(config: Dict[str, Any]) -> List[str]:
    return sorted(config.get("agents", {}).keys())


# ── Enforcement ────────────────────────────────────────────────────────────

_DENY_ALL_PROFILE: Dict[str, Any] = {
    "allowed_tools": ["Read"],
    "deny_tools": [],
    "deny_network": True,
    "allowed_paths": ["**"],
}

# Agent ids we've already warned about, so the unknown-identity notice prints
# once per process instead of on every tool call (the hook hot path).
_WARNED_UNKNOWN_IDS: set = set()


def _resolve_identity(
    config: Dict[str, Any], subject: Optional[Any]
) -> Optional[str]:
    """Pick the IAM identity to enforce.

    ``PRISMOR_AGENT_ID`` (the named-agent path) wins for backward compatibility.
    Otherwise, when an end-user subject is supplied, fall back to a per-user
    profile keyed ``user:<user_id>`` then a per-team profile ``team:<team_id>``
    — so a production framework agent can carry distinct IAM profiles per user
    without setting an env var per request. Returns ``None`` when nothing matches.
    """
    agent_id = get_active_agent_id()
    if agent_id:
        return agent_id
    if subject is None:
        return None
    agents = config.get("agents", {})
    user_id = getattr(subject, "user_id", None)
    team_id = getattr(subject, "team_id", None)
    if user_id and f"user:{user_id}" in agents:
        return f"user:{user_id}"
    if team_id and f"team:{team_id}" in agents:
        return f"team:{team_id}"
    return None


def _merge_remote_subject_controls(
    config: Dict[str, Any], remote: Optional[Dict[str, Any]]
) -> Dict[str, Any]:
    """Overlay org subject controls (the verified signed policy's
    ``settings.subject_controls``) onto the local IAM agents map.

    ``remote`` is keyed ``user:<id>`` / ``team:<id>`` with values
    ``{suspended: bool, deny_tools: [...]}``. Tighten-only, mirroring
    agents.resolve_agent_control: a suspension always wins (deny-all profile
    regardless of any local entry), remote deny_tools union with a local
    profile's, and a remote entry never widens what a local profile allows.
    A subject with no local profile gets an allow-all-except-denied base, so
    an org deny doesn't accidentally turn into a full allowlist.
    """
    if not isinstance(remote, dict) or not remote:
        return config
    agents = dict((config or {}).get("agents") or {})
    changed = False
    for key, ctl in remote.items():
        if not isinstance(ctl, dict) or not isinstance(key, str):
            continue
        if not (key.startswith("user:") or key.startswith("team:")):
            continue
        local = agents.get(key)
        local = dict(local) if isinstance(local, dict) else None
        if ctl.get("suspended"):
            merged: Dict[str, Any] = {
                "allowed_tools": [], "deny_tools": [], "deny_network": True,
                "allowed_paths": ["**"], "__suspended__": True,
            }
        else:
            base = local or {
                "allowed_tools": ["*"], "deny_tools": [],
                "deny_network": False, "allowed_paths": ["**"],
            }
            remote_denies = [t for t in (ctl.get("deny_tools") or []) if isinstance(t, str)]
            deny = list(dict.fromkeys(list(base.get("deny_tools") or []) + remote_denies))
            merged = {**base, "deny_tools": deny}
        # Console-resolved email/name, so a block names a person, not an id.
        if isinstance(ctl.get("label"), str) and ctl["label"].strip():
            merged["__label__"] = ctl["label"].strip()
        agents[key] = merged
        changed = True
    if not changed:
        return config
    return {**(config or {}), "agents": agents}


def check_iam(
    workspace: Optional[Path] = None,
    event: Optional[Dict[str, Any]] = None,
    session_id: str = "",
    subject: Optional[Any] = None,
    agent_profile: Optional[str] = None,
    remote_controls: Optional[Dict[str, Any]] = None,
) -> Optional[Dict[str, Any]]:
    """Check an event against the IAM profile for the active identity.

    Returns a finding dict if the event is blocked, None if allowed or if no
    identity applies. The identity is the named ``PRISMOR_AGENT_ID`` if set, else
    a per-user / per-team profile selected from ``subject`` (see
    :func:`_resolve_identity`).

    Trust boundary: the identity is selected by the ``PRISMOR_AGENT_ID``
    environment variable, which is inherited by the very agent being
    constrained. An identity that can execute commands can spawn a child
    process with the variable unset (disabling IAM) or set to a more permissive
    profile. IAM is therefore a guardrail for cooperative/misconfigured agents,
    not a sandbox against an adversarial one — pair it with a deny-all base
    policy and OS-level isolation when the threat model requires it.
    """
    if event is None:
        return None

    config = _merge_remote_subject_controls(load_iam_config(workspace), remote_controls)
    agent_id = _resolve_identity(config, subject)
    # Fall back to the per-agent IAM profile assigned in agents.yaml
    if not agent_id and agent_profile:
        agent_id = agent_profile
    if not agent_id:
        return None

    profile = resolve_agent_profile(agent_id, config)

    if profile is None:
        if agent_id not in _WARNED_UNKNOWN_IDS:
            sys.stderr.write(
                f"[prismor/runtime/iam] unknown agent identity '{agent_id}' — applying deny-all policy.\n"
                f"             Add '{agent_id}' to ~/.prismor/iam.yaml or .prismor/iam.yaml\n"
            )
            _WARNED_UNKNOWN_IDS.add(agent_id)
        profile = _DENY_ALL_PROFILE

    from prismor.runtime.scoped_agent import check_scoped_rules
    finding = check_scoped_rules(profile, event, session_id=session_id)
    if finding:
        finding["ruleId"] = "iam"
        finding["category"] = "iam"
        finding["id"] = f"{session_id}:iam:{agent_id}"
        finding["title"] = finding["title"].replace(
            "[scoped agent]", f"[iam:{agent_id}]"
        )
        # The shared scoped-rules copy says "for this session", which misleads
        # for identity-keyed profiles: a user:<id> deny follows the user across
        # every session and agent. Name the actual scope in user-facing text.
        who_id = profile.get("__label__") or agent_id[5:]
        if agent_id.startswith("user:"):
            scope = f"for user '{who_id}'"
        elif agent_id.startswith("team:"):
            scope = f"for team '{who_id}'"
        else:
            scope = f"for agent identity '{agent_id}'"
        for key in ("title", "evidence"):
            if isinstance(finding.get(key), str):
                finding[key] = finding[key].replace("for this session", scope)
        # An org suspension deserves its own copy — "not in scope" undersells
        # "an admin turned this principal off".
        if profile.get("__suspended__"):
            who = scope[4:]  # strip the "for " prefix → "user 'alice'"
            finding["title"] = f"[iam:{agent_id}] {who} is suspended by org policy"
            finding["evidence"] = f"{who} is suspended by org policy (subject_controls)"
    return finding


# ── Display ────────────────────────────────────────────────────────────────

_BOLD = "\033[1m"
_CYAN = "\033[0;36m"
_GREEN = "\033[0;32m"
_DIM = "\033[37m"
_NC = "\033[0m"


def format_iam_profile_box(agent_id: str, profile: Dict[str, Any]) -> str:
    """Format an IAM profile as an ASCII box for stderr display."""
    allowed = ", ".join(profile.get("allowed_tools", []))
    paths = ", ".join(profile.get("allowed_paths", ["**"]))
    denied = ", ".join(profile.get("deny_tools", []))
    network = "denied" if profile.get("deny_network", True) else "allowed"

    content_lines = [
        f"  agent:          {agent_id}",
        f"  allowed_tools:  [{allowed}]",
        f"  allowed_paths:  [{paths}]",
        f"  deny_tools:     [{denied}]",
        f"  deny_network:   {network}",
    ]

    max_width = max(len(line) for line in content_lines) + 4
    border = max_width + 2

    lines = []
    header = " Prismor IAM — active agent policy "
    pad = border - 2 - len(header)
    lines.append(f"{_CYAN}┌─{header}" + "─" * pad + f"┐{_NC}")
    for cl in content_lines:
        padding = border - 2 - len(cl)
        lines.append(f"{_CYAN}│{_NC}{cl}" + " " * padding + f"{_CYAN}│{_NC}")
    lines.append(f"{_CYAN}└" + "─" * border + f"┘{_NC}")
    return "\n".join(lines)


def init_global_iam() -> Path:
    """Write a starter iam.yaml to $PRISMOR_HOME/iam.yaml (default ~/.prismor) and return its path."""
    path = _global_iam_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(_STARTER_CONFIG, encoding="utf-8")
    return path


def init_project_iam(workspace: Path) -> Path:
    """Write a starter iam.yaml to .prismor/iam.yaml and return its path."""
    path = workspace / ".prismor" / _PROJECT_IAM_FILENAME
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(_STARTER_CONFIG, encoding="utf-8")
    return path
