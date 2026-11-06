"""Which enforcement surfaces are actually governing this machine.

`contract.SURFACES` says what each surface IS and what it can do.
`integrations.registry.governance()` says which ones CAN reach a given agent.
This module answers the third question — which are switched on right now — by
reading the state the installers already write. It adds no state of its own.

The distinction that makes it worth having: "not governed" and "cannot be
governed" are different answers, and so is "governed by the mirror instead of
hooks". Collapsing them is how an agent Prismor deliberately does not support
gets reported as a coverage gap, and how an agent the mirror governs perfectly
well gets reported as unguarded.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List

#: Surfaces that govern one named agent. The gateway is machine-level (it
#: fronts MCP servers, not an agent's own tools) so it is reported separately.
AGENT_SURFACES = ("hook", "mirror")


def _mirror_agents(workspace: Path) -> set:
    """Agents `prismor mirror on` currently governs, per its install records."""
    out = set()
    try:
        from prismor.runtime import mirror_cli
    except Exception:
        return out
    try:
        rec = mirror_cli._read_record(workspace)  # noqa: SLF001 — same package
        if rec and rec.get("agent"):
            out.add(str(rec["agent"]))
    except Exception:
        pass
    try:
        # Codex is wired machine-wide, so its record lives outside the workspace.
        codex = mirror_cli._load_json(mirror_cli._codex_record_path())  # noqa: SLF001
        if codex.get("agent"):
            out.add(str(codex["agent"]))
    except Exception:
        pass
    return out


def resolve(workspace: Path) -> Dict[str, Dict[str, Any]]:
    """Per detected agent: which surfaces are possible, and which are on.

    ``{agent: {"possible": [...], "active": [...], "recommended": str}}``
    """
    from prismor.runtime.hooks import coverage
    from prismor.runtime.integrations.registry import governance

    mirrored = _mirror_agents(workspace)
    out: Dict[str, Dict[str, Any]] = {}
    for agent, scopes in coverage(workspace).items():
        try:
            gov = governance(agent)
        except Exception:
            gov = {"hooks": False, "mirror": "unknown", "recommended": "none"}
        possible: List[str] = []
        if gov.get("hooks"):
            possible.append("hook")
        if str(gov.get("mirror")) in ("verified", "possible"):
            possible.append("mirror")
        active: List[str] = []
        if scopes.get("project") or scopes.get("global"):
            active.append("hook")
        if agent in mirrored:
            active.append("mirror")
        out[agent] = {
            "possible": possible,
            "active": active,
            "recommended": gov.get("recommended", "none"),
            "scopes": scopes,
        }
    return out


def gateway(workspace: Path) -> Dict[str, Any]:
    """Machine-level MCP gateway state: configured upstreams and live processes."""
    from prismor.runtime.mcp_gateway import DEFAULT_GATEWAY_CONFIG, load_gateway_config

    info: Dict[str, Any] = {"configured": 0, "live": 0, "config": str(DEFAULT_GATEWAY_CONFIG)}
    try:
        if DEFAULT_GATEWAY_CONFIG.exists():
            info["configured"] = len(load_gateway_config(DEFAULT_GATEWAY_CONFIG))
    except Exception:
        pass
    try:
        from prismor.runtime import mirror_cli
        info["live"] = len(mirror_cli._live_gateways(workspace))  # noqa: SLF001
    except Exception:
        pass
    return info


def ungoverned(workspace: Path) -> List[str]:
    """Detected agents Prismor COULD govern but currently does not.

    Excludes agents with no interception surface at all — naming those is a
    support question, not a coverage gap, and listing them makes the gap count
    unactionable.
    """
    return sorted(a for a, s in resolve(workspace).items()
                  if s["possible"] and not s["active"])


def unsupported_present() -> List[str]:
    """Installed coding agents Prismor cannot intercept at all (sweep-only:
    no hooks, no mirror). Not a gap Prismor can close, but one the owner must
    see: everything such an agent runs is unscreened."""
    try:
        from prismor.runtime.integrations.registry import by_status
        return sorted(e.id for e in by_status("sweep-only")
                      if e.kind == "coding-agent" and e.sweep_dir
                      and Path(e.sweep_dir).expanduser().exists())
    except Exception:
        return []
