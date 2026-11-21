"""Risk scoring v1.

Signals are additive and capped at 100. Levels: none 0, low 1–24, medium 25–49,
high 50–74, critical ≥75. ``THREAT_INTEL`` forces critical. Weights are the
initial table from the discovery plan and will be tuned with real data.
"""
from __future__ import annotations

from typing import Any, Dict, List

from prismor.runtime.inventory.schema import InventoryRecord

#: id -> weight. Negative weights exist (UNPUBLISHED_DRAFT).
WEIGHTS: Dict[str, int] = {
    "UNGOVERNED": 25,
    "REMOTE_MCP_UNMANAGED": 20,
    "WORKSPACE_SCOPED_COMMAND": 25,
    "MCP_SCHEMA_FINDING": 10,
    "UNPINNED_PACKAGE": 10,
    "SECRET_IN_CONFIG": 30,
    "AUTO_APPROVE": 20,
    "PUBLIC_BIND": 25,
    "THREAT_INTEL": 0,
    "UNKNOWN_PUBLISHER": 10,
    "BROAD_SCOPES": 25,
    "TENANT_WIDE_CONSENT": 15,
    "NO_AUTH": 30,
    "SHARED_TENANT_WIDE": 20,
    "MAKER_CREDENTIALS": 15,
    "WEB_KNOWLEDGE": 5,
    "AUTONOMOUS_TRIGGER": 15,
    "UNPUBLISHED_DRAFT": -5,
    "CI_WRITE_PERMS": 20,
}

_SCHEMA_WEIGHT = {"critical": 30, "high": 30, "medium": 20, "low": 10, "info": 10}


def _signal(signal_id: str, evidence: str, weight: int | None = None) -> Dict[str, Any]:
    return {
        "id": signal_id,
        "weight": WEIGHTS[signal_id] if weight is None else int(weight),
        "evidence": evidence,
    }


def level_for(score: int, signals: List[Dict[str, Any]]) -> str:
    if any(item.get("id") == "THREAT_INTEL" for item in signals):
        return "critical"
    if score <= 0:
        return "none"
    if score < 25:
        return "low"
    if score < 50:
        return "medium"
    if score < 75:
        return "high"
    return "critical"


def _schema_weight(severity: str) -> int:
    return _SCHEMA_WEIGHT.get((severity or "").lower(), 10)


def derive_signals(record: InventoryRecord) -> List[Dict[str, Any]]:
    """Signals implied by the record. Callers may also set ``attributes['_signals']``."""
    attrs = record.attributes or {}
    gov = record.governance
    found: List[Dict[str, Any]] = []
    seen = set()

    def add(signal_id: str, evidence: str, weight: int | None = None) -> None:
        if signal_id in seen or signal_id not in WEIGHTS:
            return
        seen.add(signal_id)
        found.append(_signal(signal_id, evidence, weight))

    explicit = attrs.get("_signals") or []
    if isinstance(explicit, list):
        for item in explicit:
            if isinstance(item, str):
                add(item, item)
            elif isinstance(item, dict) and item.get("id"):
                add(str(item["id"]), str(item.get("evidence") or item["id"]),
                    item.get("weight"))

    if record.kind != "diagnostic" and gov.coverable and not gov.managed:
        add("UNGOVERNED", "not governed by Prismor")
    if record.kind == "mcp_server" and attrs.get("remote") and not attrs.get("is_gateway"):
        if not gov.managed:
            add("REMOTE_MCP_UNMANAGED", "remote MCP server not routed through the gateway")
    if attrs.get("workspace_scoped") and attrs.get("command"):
        add("WORKSPACE_SCOPED_COMMAND",
            "repo-scoped config launches a local command")
    severity = str(attrs.get("schema_severity") or "")
    if severity:
        add("MCP_SCHEMA_FINDING", f"schema audit severity {severity}", _schema_weight(severity))
    if attrs.get("pinned") is False and attrs.get("package_id"):
        add("UNPINNED_PACKAGE", "package launcher without a version")
    if attrs.get("secret_in_config"):
        add("SECRET_IN_CONFIG", "provider key pattern in config; value not recorded")
    if attrs.get("auto_approve"):
        add("AUTO_APPROVE", "autoApprove or alwaysAllow is set")
    if attrs.get("public_bind"):
        add("PUBLIC_BIND", "listening on 0.0.0.0 or ::")
    if attrs.get("threat_intel"):
        add("THREAT_INTEL", "threat-intel match")
    if attrs.get("confidence") == "unverified" or attrs.get("unknown_publisher"):
        add("UNKNOWN_PUBLISHER", "extension or app not in the verified catalog")
    if attrs.get("broad_scopes"):
        add("BROAD_SCOPES", "OAuth grant with a write scope over Mail, Files, or Sites")
    if attrs.get("tenant_wide_consent"):
        add("TENANT_WIDE_CONSENT", "consentType=AllPrincipals")
    if attrs.get("auth_mode") in {"none", "None", "unspecified", "Unspecified"} or attrs.get("no_auth"):
        add("NO_AUTH", "low-code agent with no end-user auth")
    if attrs.get("shared_tenant_wide"):
        add("SHARED_TENANT_WIDE", "shared with everyone in the tenant")
    if attrs.get("maker_credentials"):
        add("MAKER_CREDENTIALS", "connector runs as the maker")
    if attrs.get("web_knowledge"):
        add("WEB_KNOWLEDGE", "public web knowledge source")
    if attrs.get("autonomous_trigger"):
        add("AUTONOMOUS_TRIGGER", "event-triggered or autonomous agent")
    if attrs.get("unpublished"):
        add("UNPUBLISHED_DRAFT", "never published")
    if attrs.get("ci_write_perms"):
        add("CI_WRITE_PERMS", "AI action with contents:write or pull_request_target")
    return found


def apply(record: InventoryRecord) -> InventoryRecord:
    """Fill ``record.risk`` from derived signals. Score is min(100, max(0, sum))."""
    signals = derive_signals(record)
    total = sum(int(item.get("weight") or 0) for item in signals)
    score = max(0, min(100, total))
    record.risk.score = score
    record.risk.level = level_for(score, signals)
    record.risk.signals = signals
    # The hint list is an input, not something to publish.
    if "_signals" in record.attributes:
        record.attributes = {k: v for k, v in record.attributes.items() if k != "_signals"}
    return record
