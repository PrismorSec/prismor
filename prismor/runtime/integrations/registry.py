"""Loader for the Prismor integration registry (``registry.yaml``).

The registry is the single source of truth for which agents and frameworks
Prismor can intercept, the surface each exposes, and how blocking works there.
Both the docs matrix generator (``scripts/gen_integration_matrix.py``) and any
runtime adapter wiring read it through this module so there is exactly one
parser and one shape.
"""
from __future__ import annotations

import sys
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    import yaml
except ImportError:  # pragma: no cover - mirrors policy_engine's hard requirement
    sys.stderr.write("FATAL: PyYAML is required to load the integration registry.\n")
    raise SystemExit(1)

_REGISTRY_PATH = Path(__file__).resolve().parent / "registry.yaml"

# Allowed enum values — kept in sync with registry.schema.json.
# multiplexer = terminal session manager that spawns other agents (e.g. Herdr) —
# not itself a coding agent or a framework, and never intercepted directly.
KINDS = frozenset({"coding-agent", "framework", "multiplexer"})
# http = language-agnostic eval-server / Vercel AI sidecar (POST /v1/evaluate)
# pass-through = no interception surface at all; wrapped agents' own hooks fire unchanged
SURFACES = frozenset({"hook-config", "sdk", "mcp", "rules-only", "http", "pass-through"})
STATUSES = frozenset({"shipped", "roadmap", "sweep-only"})
# client-side = HTTP eval-server adapters that enforce in the caller (Node/Ruby/Java/Rust)
# return-block = in-process plugin hook returns a block result (OpenClaw/Hermes before_tool_call)
BLOCKING = frozenset({"exit-2", "json-permission", "throw", "proxy-deny", "none", "client-side", "return-block"})


@dataclass(frozen=True)
class Integration:
    """One agent/framework entry from the registry."""

    id: str
    name: str
    kind: str
    surface: str
    status: str
    blocking: str
    events: List[str] = field(default_factory=list)
    config_paths: Dict[str, str] = field(default_factory=dict)
    normalizer: Optional[str] = None
    sweep_dir: Optional[str] = None
    notes: Optional[str] = None
    sources: List[str] = field(default_factory=list)
    mirror: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, raw: Dict[str, Any]) -> "Integration":
        return cls(
            id=str(raw["id"]),
            name=str(raw.get("name", raw["id"])),
            kind=str(raw.get("kind", "")),
            surface=str(raw.get("surface", "")),
            status=str(raw.get("status", "")),
            blocking=str(raw.get("blocking", "none")),
            events=list(raw.get("events") or []),
            config_paths=dict(raw.get("config_paths") or {}),
            normalizer=raw.get("normalizer"),
            sweep_dir=raw.get("sweep_dir"),
            notes=raw.get("notes"),
            sources=list(raw.get("sources") or []),
            mirror=dict(raw.get("mirror") or {}),
        )


def registry_path() -> Path:
    """Absolute path to the bundled ``registry.yaml``."""
    return _REGISTRY_PATH


@lru_cache(maxsize=4)
def _parsed(src: Path) -> Tuple[Integration, ...]:
    """Parse+cache one registry file. `get`/`by_surface`/`governance` each
    reparsed the whole YAML per call, so asking about N agents cost N parses of
    a file that ships inside the package and cannot change under a running
    process. Returns a tuple: a cached mutable list would alias across callers."""
    raw = yaml.safe_load(src.read_text(encoding="utf-8")) or {}
    return tuple(Integration.from_dict(e) for e in (raw.get("agents") or []))


def load_registry(path: Optional[Path] = None) -> List[Integration]:
    """Parse the registry into ``Integration`` objects (declaration order)."""
    return list(_parsed(path or _REGISTRY_PATH))


def get(agent_id: str, path: Optional[Path] = None) -> Optional[Integration]:
    """Return the integration with ``agent_id`` or ``None``."""
    for item in load_registry(path):
        if item.id == agent_id:
            return item
    return None


def by_surface(surface: str, path: Optional[Path] = None) -> List[Integration]:
    """All integrations exposing ``surface`` (hook-config|sdk|mcp|rules-only|http)."""
    return [i for i in load_registry(path) if i.surface == surface]


def by_status(status: str, path: Optional[Path] = None) -> List[Integration]:
    """All integrations with the given ``status`` (shipped|roadmap|sweep-only)."""
    return [i for i in load_registry(path) if i.status == status]


# ── governance surfaces ──────────────────────────────────────────────────────
#
# Prismor can sit in front of an agent two ways, and they are not equivalent:
#
#   hooks   The agent calls Prismor before (and after) each tool call and obeys
#           the verdict. The agent keeps its own tools, everything it can do is
#           screened, and there is nothing to install into the model's tool
#           list. This is the better surface wherever it exists.
#
#   mirror  Prismor serves look-alike built-ins over MCP and the agent's own
#           are switched off. Buys what a hook cannot do — the tool runs inside
#           Prismor, so output can be REDACTED rather than merely refused — but
#           it only holds while the natives stay off, so it depends on the host
#           having a way to turn them off at all.
#
# Recommendation, in order:
#   * hooks when the agent supports them (complete coverage, nothing replaced)
#   * mirror when it does not (often the only interposition point that exists)
#   * mirror alongside hooks only when result-side redaction is worth the extra
#     moving parts — it is not the default.

_MIRROR_USABLE = ("verified", "possible")


def governance(agent_id: str, path: Optional[Path] = None) -> Dict[str, Any]:
    """How Prismor can govern one agent: ``{hooks, mirror, recommended, ...}``.

    ``recommended`` is ``"hooks"``, ``"mirror"``, or ``"none"``. ``surfaces`` is
    the human-facing label: "hooks", "MCP", "hooks + MCP", or "not supported".
    """
    entry = get(agent_id, path)
    if entry is None:
        return {"hooks": False, "mirror": "unknown", "recommended": "none",
                "surfaces": "unknown", "scope": None, "disable": None, "notes": None}
    # A coding agent whose "hooks" are a plugin Prismor writes into it
    # (OpenCode, OpenClaw, Hermes Agent: surface sdk) is hooked by
    # `install-hooks` exactly like a hook-config agent. Counting only
    # hook-config told setup and `prismor coverage` OpenCode had no hook
    # protocol and could only be mirrored.
    hooks = ((entry.surface == "hook-config" and entry.status != "sweep-only")
             or (entry.surface == "sdk" and entry.kind == "coding-agent" and entry.status == "shipped"))
    mirror_status = str(entry.mirror.get("status") or "unknown")
    mirror_ok = mirror_status in _MIRROR_USABLE
    if hooks and mirror_ok:
        surfaces = "hooks + MCP"
    elif hooks:
        surfaces = "hooks"
    elif mirror_ok:
        surfaces = "MCP"
    else:
        surfaces = "not supported"
    return {
        "hooks": hooks,
        "mirror": mirror_status,
        "recommended": "hooks" if hooks else ("mirror" if mirror_ok else "none"),
        "surfaces": surfaces,
        "scope": entry.mirror.get("scope"),
        "disable": entry.mirror.get("disable"),
        "notes": entry.mirror.get("notes"),
    }
