"""Local-host AI discovery — find agents on this machine Prismor doesn't govern.

Prismor already inventories the agents that run through its hooks
(``agents.list_agents``). That misses the ones nobody wired up: a Claude Code
or Codex install sitting on the machine with no Prismor hooks, quietly making
tool calls Prismor never sees. This module sweeps the host for those.

For each supported agent it answers three questions from files already on disk:

  * **present**  — is the agent's config or CLI on this machine?
  * **governed** — are Prismor hooks wired into that config?
  * **seen**     — has the agent actually run through Prismor (in the registry)?

An agent that's present and *not* governed is the finding: shadow AI tooling
outside Prismor's coverage. The sweep is read-only and host-local. It does not
touch the network — that's a separate, heavier project. It reuses the config
locations `scanner.py` already knows and the registry `agents.py` maintains.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional

# Where each agent's presence and CLI show up, beyond the config files
# scanner.py already enumerates. Config discovery drives "present"; these add
# a CLI/state signal so an agent installed but not yet configured still counts.
#
# Home-relative only. Presence must stay a pure filesystem question: this
# report is folded into the signed attestation bundle, and a $PATH probe would
# make the same host produce different bundles under different shells.
_AGENT_CLI_MARKERS = {
    "claude": [".claude"],
    "cursor": [".cursor", ".config/Cursor"],
    "windsurf": [".codeium", ".windsurf"],
    "openclaw": [".openclaw"],
    "hermes": [".hermes"],
    "codex": [".codex"],
    "copilot": [".copilot"],
    "grok": [".grok"],
    "gemini": [".gemini"],
    "opencode": [".config/opencode"],
    "kiro": [".kiro"],
    "junie": [".junie"],
    "jetbrains-ai": [".jetbrains", ".config/JetBrains", "AppData/Roaming/JetBrains"],
    "copilot-jetbrains": [".config/github-copilot", "AppData/Local/github-copilot"],
    "roo": [".roo"],
    "aider": [".aider"],
    "trae": [".trae"],
    "kilocode": [".kilocode"],
    "antigravity": [".antigravity"],
    "factory-droid": [".factory"],
    "crush": [".config/crush"],
    "openhands": [".openhands"],
    "qwen": [".qwen"],
    "continue": [".continue"],
    "goose": [".config/goose"],
}

# Substring that marks a config as Prismor-governed. The installers write the
# dispatcher command (`prismor ... hook-dispatch`) into each agent's hook
# config, so its presence in any config file for that agent means governed.
_GOVERNED_MARKER = "prismor"


#: Bounds for scanning a directory-valued config path. Nine registry entries
#: point at a directory rather than a file (``~/.aider/``, ``.trae/rules/``,
#: ``~/.config/opencode/plugins/`` …); these keep that walk from wandering into
#: a large tree on a command that must stay fast enough to run at session start.
_DIR_SCAN_MAX_FILES = 64
_DIR_SCAN_MAX_BYTES = 512 * 1024


def _config_has_marker(path: Path) -> bool:
    """Is Prismor's dispatcher wired into this config path?

    Handles directories as well as files. Reading a directory raises
    ``IsADirectoryError``, which used to be swallowed into a ``False`` — so
    every agent whose registry path is a directory reported as ungoverned no
    matter how it was configured, and that verdict rides in the signed
    attestation bundle.
    """
    try:
        if path.is_dir():
            scanned = 0
            for child in sorted(path.rglob("*")):
                if scanned >= _DIR_SCAN_MAX_FILES:
                    break
                if not child.is_file():
                    continue
                scanned += 1
                try:
                    if child.stat().st_size > _DIR_SCAN_MAX_BYTES:
                        continue
                except OSError:
                    continue
                if _file_has_marker(child):
                    return True
            return False
        return _file_has_marker(path)
    except OSError:
        return False


def _file_has_marker(path: Path) -> bool:
    try:
        return _GOVERNED_MARKER in path.read_text(encoding="utf-8", errors="ignore").lower()
    except (OSError, UnicodeError, ValueError):
        return False


def _governed_frameworks(workspace: Optional[Path]) -> Dict[str, Dict[str, Any]]:
    """Registry view keyed by framework id: whether Prismor has seen it run."""
    out: Dict[str, Dict[str, Any]] = {}
    try:
        from prismor.runtime.agents import list_agents
        for a in list_agents(workspace):
            fw = a.framework or a.name
            entry = out.setdefault(fw, {"seen": True, "last_seen": a.last_seen})
            # keep the most recent last_seen if several instances share a framework
            if a.last_seen and (not entry["last_seen"] or a.last_seen > entry["last_seen"]):
                entry["last_seen"] = a.last_seen
    except Exception:
        pass
    return out


def _glob_candidates(pattern: Path) -> List[Path]:
    """Expand a glob-bearing config path into the files that actually exist.

    Split at the first component containing ``*`` so the fixed prefix is the
    glob root — ``Path.glob`` cannot take an absolute pattern.
    """
    parts = pattern.parts
    for index, part in enumerate(parts):
        if "*" in part:
            root = Path(*parts[:index]) if index else Path(".")
            rest = str(Path(*parts[index:]))
            try:
                return [p for p in root.glob(rest) if p.exists()]
            except (OSError, ValueError, NotImplementedError):
                return []
    return []


def _registry_config_paths(workspace: Path) -> Dict[str, List[Path]]:
    """Candidate config paths per agent, from the integration registry.

    scanner.py enumerates configs only for the six agents it parses MCP servers
    out of. The registry knows every agent Prismor can intercept, so an
    ungoverned Aider or Kiro install is visible here even though scanner has no
    parser for it. Failure to load the registry degrades to scanner-only
    coverage rather than losing the sweep entirely.
    """
    out: Dict[str, List[Path]] = {}
    try:
        from prismor.runtime.integrations.registry import load_registry
        entries = load_registry()
    except Exception:
        return out
    home = Path.home()
    for entry in entries:
        paths: List[Path] = []
        for raw in (entry.config_paths or {}).values():
            raw = str(raw)
            if raw.startswith("~"):
                # Expanded against Path.home() rather than Path.expanduser(),
                # which reads $HOME directly and so escapes a patched home.
                # Sliced rather than lstripped: lstrip takes a character set,
                # so "~/~dir" would lose the second "~" too.
                candidate = home / raw[2:] if raw.startswith("~/") else home
            elif raw.startswith("/"):
                candidate = Path(raw)
            else:
                candidate = workspace / raw
            # Several registry entries are glob patterns (amazonq's
            # ``cli-agents/*.json``, amp's ``plugins/*.ts``). Checked as
            # literals they can never exist, so those agents were undetectable.
            if "*" in str(candidate):
                paths.extend(sorted(_glob_candidates(candidate)))
            elif candidate.exists():
                paths.append(candidate)
        if paths:
            out[entry.id] = paths
    return out


def _hooked(agent: str, workspace: Path) -> bool:
    """Is a Prismor hook installed where the *installer* would have put it?

    The config paths this module discovers and the paths ``install_hooks``
    writes to are not the same set. Cursor is the clearest case: discovery
    finds ``~/.cursor/mcp.json`` (the registry lists no user-scope hook path
    for it) while the global installer writes ``~/.cursor/hooks.json``. Judging
    solely on discovered files therefore reported a freshly hooked Cursor as
    ungoverned forever — and made ``discover --fix`` claim a fix that the very
    next ``discover`` contradicted.

    Asking ``hooks.hook_installed`` settles it against the installer's own
    path table, so "governed" means the same thing on both sides. Still a pure
    filesystem read, so the attested sweep stays deterministic.
    """
    try:
        from prismor.runtime.hooks import hook_installed
    except Exception:
        return False
    for scope in ("project", "global"):
        try:
            if hook_installed(agent, scope, workspace):
                return True
        except Exception:
            continue
    return False


def _known_agent_ids() -> List[str]:
    """Every agent id worth sweeping — registry ∪ scanner ∪ CLI markers."""
    ids = set(_AGENT_CLI_MARKERS)
    try:
        from prismor.runtime.scanner import _AGENT_DISCOVERERS
        ids.update(_AGENT_DISCOVERERS)
    except Exception:
        pass
    try:
        from prismor.runtime.integrations.registry import load_registry
        # Frameworks are SDK imports inside a project, not independently
        # installed agents — `prismor agents` covers those once they report.
        ids.update(e.id for e in load_registry() if e.kind == "coding-agent")
    except Exception:
        pass
    return sorted(ids)


def discover(workspace: Optional[Path] = None) -> Dict[str, Any]:
    """Sweep this host. Returns a report::

        {
          "agents": [
            {"agent", "present", "governed", "seen",
             "last_seen", "config_paths": [...]}
          ],
          "summary": {"present", "governed", "ungoverned", "seen"}
        }

    ``ungoverned`` counts agents present on the host with no Prismor hooks —
    the shadow-AI number.
    """
    from prismor.runtime.scanner import discover_configs

    ws = workspace or Path.cwd()
    home = Path.home()
    registry = _governed_frameworks(workspace)

    # Config files present, grouped by agent (existence check — discover_configs
    # returns candidate paths whether or not they exist).
    configs_by_agent: Dict[str, List[Path]] = {}
    for entry in discover_configs(workspace=ws):
        p = entry["path"]
        if p.exists():
            configs_by_agent.setdefault(entry["agent"], []).append(p)

    for agent, paths in _registry_config_paths(ws).items():
        known = configs_by_agent.setdefault(agent, [])
        known_keys = {str(p) for p in known}
        known.extend(p for p in paths if str(p) not in known_keys)

    agents_out: List[Dict[str, Any]] = []
    for agent in _known_agent_ids():
        cfgs = configs_by_agent.get(agent, [])
        cli_present = any((home / m).exists() for m in _AGENT_CLI_MARKERS.get(agent, []))
        present = bool(cfgs) or cli_present
        governed = any(_config_has_marker(p) for p in cfgs) or _hooked(agent, ws)
        reg = registry.get(agent, {})
        agents_out.append({
            "agent": agent,
            "present": present,
            "governed": governed,
            "seen": bool(reg.get("seen")),
            "last_seen": reg.get("last_seen"),
            "config_paths": [str(p) for p in cfgs],
        })

    present = [a for a in agents_out if a["present"]]
    summary = {
        "present": len(present),
        "governed": sum(1 for a in present if a["governed"]),
        "ungoverned": sum(1 for a in present if not a["governed"]),
        "seen": sum(1 for a in agents_out if a["seen"]),
    }
    return {"agents": agents_out, "summary": summary}
