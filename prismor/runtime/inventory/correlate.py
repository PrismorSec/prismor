"""Group records that are the same thing, and link records that are related.

``group_id`` is a pure function of ``entity_key``. Cross-kind links go in
``related`` and never merge the records.
"""
from __future__ import annotations

from typing import Dict, Iterable, List
from urllib.parse import urlsplit

from prismor.runtime.discover import redact_url
from prismor.runtime.inventory.ids import group_id, registrable_domain
from prismor.runtime.inventory.schema import InventoryRecord

# CI action repo -> catalog agent id. Seeds only; unverified actions still link
# when the key is present on the record.
_CI_AGENT = {
    "anthropics/claude-code-action": "claude",
    "openai/codex-action": "codex",
    "google-github-actions/run-gemini-cli": "gemini",
}


def _add(record: InventoryRecord, other: InventoryRecord, reason: str) -> None:
    if not other.entity_key:
        return
    if other.record_id and other.record_id == record.record_id:
        return
    key = (other.entity_key, other.kind, reason)
    have = {(item.get("entity_key"), item.get("kind"), item.get("reason")) for item in record.related}
    if key in have:
        return
    record.related.append({
        "entity_key": other.entity_key,
        "kind": other.kind,
        "reason": reason,
    })


def _host_of(url: str) -> str:
    try:
        parts = urlsplit(redact_url(url))
    except Exception:
        return ""
    return (parts.hostname or "").lower()


def correlate(records: Iterable[InventoryRecord]) -> List[InventoryRecord]:
    """Assign ``group_id`` and fill ``related``. Returns the same list."""
    items = list(records)
    for record in items:
        if record.entity_key:
            record.group_id = group_id(record.entity_key)

    by_kind: Dict[str, List[InventoryRecord]] = {}
    for record in items:
        by_kind.setdefault(record.kind, []).append(record)

    for record in items:
        attrs = record.attributes or {}
        if record.kind == "lowcode_agent":
            app_id = str(attrs.get("entra_app_id") or "")
            agent_id = str(attrs.get("entra_agent_id") or "")
            for other in by_kind.get("oauth_grant", []) + by_kind.get("agent_identity", []):
                other_app = str((other.attributes or {}).get("app_id") or "")
                other_id = str((other.attributes or {}).get("id") or "")
                if app_id and other_app and app_id == other_app:
                    _add(record, other, "entra app id")
                    _add(other, record, "entra app id")
                if agent_id and other_id and agent_id == other_id:
                    _add(record, other, "entra agent id")
                    _add(other, record, "entra agent id")

        if record.kind == "mcp_server" and attrs.get("remote"):
            host = _host_of(str(attrs.get("url") or ""))
            domain = registrable_domain(host)
            if domain:
                for other in by_kind.get("network_destination", []):
                    other_domain = str((other.attributes or {}).get("domain") or other.name or "")
                    if registrable_domain(other_domain) == domain:
                        _add(record, other, "remote MCP host")
                        _add(other, record, "remote MCP host")

        package_id = str(attrs.get("package_id") or "")
        if record.kind == "mcp_server" and package_id:
            for other in by_kind.get("package", []):
                if other.entity_key == package_id or str((other.attributes or {}).get("purl") or "") == package_id:
                    _add(record, other, "installed package")
                    _add(other, record, "installed package")

        if record.kind == "credential_ref":
            provider = str(attrs.get("provider") or record.name or "")
            host_id = record.location.host_id
            user = record.location.user
            for kind in ("agent", "package"):
                for other in by_kind.get(kind, []):
                    if other.location.host_id != host_id or other.location.user != user:
                        continue
                    other_provider = str((other.attributes or {}).get("provider") or other.product or "")
                    if provider and other_provider and provider == other_provider:
                        _add(record, other, "same host provider")
                        _add(other, record, "same host provider")

        if record.kind == "ci_workflow":
            action = str(attrs.get("action") or "")
            catalog = _CI_AGENT.get(action) or str(attrs.get("agent_catalog_id") or "")
            if catalog:
                want = "agent:" + catalog
                for other in by_kind.get("agent", []):
                    if other.entity_key == want:
                        _add(record, other, "CI action catalog id")
                        _add(other, record, "CI action catalog id")

        if record.kind == "cloud_agent" and str(attrs.get("provider") or "") in {"azure-foundry", "foundry"}:
            ident = str(attrs.get("identity_id") or "")
            if ident:
                for other in by_kind.get("agent_identity", []):
                    if str((other.attributes or {}).get("id") or "") == ident:
                        _add(record, other, "foundry hosted-agent identity")
                        _add(other, record, "foundry hosted-agent identity")

    return items
