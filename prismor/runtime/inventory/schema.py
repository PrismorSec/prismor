"""Inventory record shape, ``prismor.inventory.v1``.

One JSON object per line (NDJSON). Consumers ignore unknown fields. The JSON
Schema lives in ``docs/schema/inventory-record.v1.json``.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional

SCHEMA = "prismor.inventory.v1"

KINDS = (
    "agent", "mcp_server", "ide_extension", "browser_extension", "package",
    "model_runtime", "process", "listener", "container", "credential_ref",
    "desktop_app", "repo_artifact", "ci_workflow", "k8s_workload", "cloud_agent",
    "oauth_grant", "agent_identity", "saas_app", "network_destination",
    "lowcode_agent", "lowcode_flow", "diagnostic",
)
SURFACES = (
    "endpoint", "repo", "ci", "k8s", "cloud", "identity", "saas", "network", "lowcode",
)
GOVERNED_BY = (
    "prismor-hook", "prismor-gateway", "prismor-cloak",
    "prismor-copilot-studio-provider", "prismor-proxy", "prismor-adapter",
    "m365-agent365", "none",
)


def _opt(value: Optional[str]) -> Optional[str]:
    if value is None or value == "":
        return None
    return value


@dataclass
class Location:
    host_id: str = ""
    hostname: str = ""
    os: str = ""
    user: str = ""
    path: Optional[str] = None
    scope: str = "user"
    repo: Optional[str] = None
    ref: Optional[str] = None
    tenant_id: Optional[str] = None
    environment_id: Optional[str] = None
    account: Optional[str] = None
    region: Optional[str] = None
    project: Optional[str] = None
    namespace: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "host_id": self.host_id or "",
            "hostname": self.hostname or "",
            "os": self.os or "",
            "user": self.user or "",
            "path": _opt(self.path),
            "scope": self.scope or "user",
            "repo": _opt(self.repo),
            "ref": _opt(self.ref),
            "tenant_id": _opt(self.tenant_id),
            "environment_id": _opt(self.environment_id),
            "account": _opt(self.account),
            "region": _opt(self.region),
            "project": _opt(self.project),
            "namespace": _opt(self.namespace),
        }


@dataclass
class Governance:
    managed: bool = False
    governed_by: str = "none"
    coverable: bool = True
    mode: Optional[str] = None
    approved: Optional[bool] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "managed": bool(self.managed),
            "governed_by": self.governed_by or "none",
            "coverable": bool(self.coverable),
            "mode": _opt(self.mode),
            "approved": self.approved,
        }


@dataclass
class Risk:
    score: int = 0
    level: str = "none"
    signals: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "score": int(self.score),
            "level": self.level or "none",
            "signals": list(self.signals or []),
        }


@dataclass
class RunInfo:
    run_id: str = ""
    scanner: str = "prismor"
    scanner_version: str = ""
    collector_version: int = 1

    def to_dict(self) -> Dict[str, Any]:
        return {
            "run_id": self.run_id,
            "scanner": self.scanner,
            "scanner_version": self.scanner_version,
            "collector_version": int(self.collector_version),
        }


@dataclass
class InventoryRecord:
    """One observed AI thing. ``username`` is hashed into ``location.user`` and never serialised."""

    kind: str
    surface: str
    source: str
    name: str
    product: str = ""
    vendor: str = ""
    version: Optional[str] = None
    entity_key: str = ""
    group_id: str = ""
    record_id: str = ""
    observed_at: str = ""
    location: Location = field(default_factory=Location)
    governance: Governance = field(default_factory=Governance)
    attributes: Dict[str, Any] = field(default_factory=dict)
    risk: Risk = field(default_factory=Risk)
    evidence: List[Dict[str, str]] = field(default_factory=list)
    related: List[Dict[str, str]] = field(default_factory=list)
    run: RunInfo = field(default_factory=RunInfo)
    #: Plain username. Hashed before ``to_dict``. Never written to a sink.
    username: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema": SCHEMA,
            "record_id": self.record_id,
            "entity_key": self.entity_key,
            "group_id": self.group_id,
            "kind": self.kind,
            "surface": self.surface,
            "source": self.source,
            "product": self.product or "",
            "vendor": self.vendor or "",
            "name": self.name or "",
            "version": _opt(self.version),
            "observed_at": self.observed_at,
            "location": self.location.to_dict(),
            "governance": self.governance.to_dict(),
            "attributes": self.attributes or {},
            "risk": self.risk.to_dict(),
            "evidence": list(self.evidence or []),
            "related": list(self.related or []),
            "run": self.run.to_dict(),
        }


def to_ndjson(records: Iterable[InventoryRecord]) -> str:
    """One compact JSON object per line, including a trailing newline when non-empty."""
    lines = [json.dumps(record.to_dict(), sort_keys=True, separators=(",", ":")) for record in records]
    if not lines:
        return ""
    return "\n".join(lines) + "\n"


def diagnostic(
    source: str,
    *,
    error_code: str,
    hint: str,
    surface: str = "endpoint",
    name: str = "",
) -> InventoryRecord:
    """A collector that could not finish. No stack trace and no token."""
    return InventoryRecord(
        kind="diagnostic",
        surface=surface,
        source=source,
        name=name or error_code,
        product="",
        vendor="",
        governance=Governance(managed=False, governed_by="none", coverable=False),
        attributes={"error_code": error_code, "hint": hint},
    )
