"""Shared record construction for endpoint collectors.

Paths are made home-relative here. Secret values never land on a record:
commands go through ``redact_command``, URLs through ``redact_url``, and
environment / header maps contribute names only.
"""
from __future__ import annotations

import json
import re
import shlex
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Dict, Iterable, List, Sequence

from prismor.runtime.discover import redact_command, redact_url
from prismor.runtime.inventory.ids import mcp_entity_key, package_from_command
from prismor.runtime.inventory.schema import Governance, InventoryRecord, Location

_DOCTYPE = re.compile(r"<!DOCTYPE|<!ENTITY", re.IGNORECASE)


def home_relative(path: Path, home: Path) -> str:
    """``~/...`` when ``path`` is inside ``home``. Otherwise the path is omitted's basename."""
    try:
        rel = path.resolve().relative_to(home.resolve())
    except (OSError, ValueError):
        return path.name
    text = rel.as_posix()
    return "~/" + text if text else "~"


def file_has_provider_secret(text: str) -> bool:
    """True when a known provider pattern matches. The match text is discarded."""
    try:
        from prismor.runtime.sweep import _FALLBACK_PATTERNS
    except Exception:
        return False
    for name, pattern in _FALLBACK_PATTERNS:
        if name == "generic-api-key":
            continue
        if pattern.search(text):
            return True
    return False


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def parse_jetbrains_mcp_xml(text: str) -> List[Dict[str, Any]]:
    """Read ``llm.mcpServers.xml``. Refuses DOCTYPE so entities cannot expand.

    The element shape (``McpServerCommand`` / ``programPath`` / ``arguments``)
    comes from published user configs, not from an official JetBrains schema.
    """
    if _DOCTYPE.search(text):
        raise ValueError("doctype")
    root = ET.fromstring(text)  # nosec B314
    servers: List[Dict[str, Any]] = []
    for node in root.iter():
        if _local(node.tag) != "McpServerCommand":
            continue
        opts: Dict[str, str] = {}
        env_names: List[str] = []
        for child in list(node):
            local = _local(child.tag)
            if local == "option" and child.get("name"):
                opts[str(child.get("name"))] = str(child.get("value") or "")
            if local == "env" and child.get("name"):
                env_names.append(str(child.get("name")))
            if local in {"envs", "env"}:
                for env in child.iter():
                    if _local(env.tag) == "env" and env.get("name"):
                        env_names.append(str(env.get("name")))
        program = opts.get("programPath") or opts.get("command") or ""
        arguments = opts.get("arguments") or ""
        try:
            args = shlex.split(arguments) if arguments else []
        except ValueError:
            args = [arguments] if arguments else []
        command = [program, *args] if program else list(args)
        servers.append({
            "name": opts.get("name") or "unnamed",
            "command": command,
            "url": opts.get("url") or "",
            "env_names": sorted(set(env_names)),
            "header_names": [],
            "auto_approve": False,
        })
    return servers


def _header_names(cfg: Dict[str, Any]) -> List[str]:
    names: List[str] = []
    headers = cfg.get("headers")
    if isinstance(headers, dict):
        names.extend(str(k) for k in headers.keys())
    request_init = cfg.get("requestInit")
    if isinstance(request_init, dict) and isinstance(request_init.get("headers"), dict):
        names.extend(str(k) for k in request_init["headers"].keys())
    return sorted(set(names))


def _env_names(cfg: Dict[str, Any]) -> List[str]:
    env = cfg.get("env")
    if isinstance(env, dict):
        return sorted(str(k) for k in env.keys())
    return []


def servers_from_mapping(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Pull server entries out of an MCP JSON object. Values of env/headers are dropped."""
    block = data.get("mcpServers") or data.get("mcp_servers") or data.get("servers") or {}
    if not isinstance(block, dict):
        return []
    out: List[Dict[str, Any]] = []
    for name, cfg in block.items():
        if not isinstance(cfg, dict):
            continue
        raw_command = cfg.get("command")
        if isinstance(raw_command, str):
            command = [raw_command] + [str(a) for a in cfg.get("args") or []]
        elif isinstance(raw_command, list):
            command = [str(a) for a in raw_command] + [str(a) for a in cfg.get("args") or []]
        else:
            command = []
        url = ""
        for key in ("url", "endpoint", "serverUrl", "server_url"):
            value = cfg.get(key)
            if isinstance(value, str) and value:
                url = value
                break
        auto = bool(cfg.get("autoApprove") or cfg.get("alwaysAllow"))
        out.append({
            "name": str(name),
            "command": command,
            "url": url,
            "env_names": _env_names(cfg),
            "header_names": _header_names(cfg),
            "auto_approve": auto,
        })
    return out


def read_mcp_file(path: Path) -> List[Dict[str, Any]]:
    """Parse one MCP config. Raises ``ValueError`` for a refused XML document.

    Other parse errors propagate as ``ValueError`` / ``json.JSONDecodeError``
    so the caller can yield a diagnostic instead of failing the scan.
    """
    if path.stat().st_size > 8 * 1024 * 1024:
        raise ValueError("too_large")
    text = path.read_text(encoding="utf-8", errors="replace")
    if path.suffix.lower() == ".xml":
        servers = parse_jetbrains_mcp_xml(text)
    else:
        data = json.loads(text)
        if not isinstance(data, dict):
            raise ValueError("not_object")
        servers = servers_from_mapping(data)
    secret = file_has_provider_secret(text)
    for server in servers:
        server["secret_in_config"] = secret
    return servers


def mcp_records(
    *,
    servers: Sequence[Dict[str, Any]],
    path: Path,
    home: Path,
    agent: str,
    source: str,
    username: str,
    workspace: Path,
    wsl_distro: str = "",
    os_name: str = "",
) -> Iterable[InventoryRecord]:
    from prismor.runtime.discover import _is_workspace_scoped

    for server in servers:
        command = [str(a) for a in server.get("command") or []]
        url = str(server.get("url") or "")
        redacted_cmd = redact_command(command)
        redacted_url = redact_url(url) if url else ""
        purl, pinned = package_from_command(command)
        scoped = _is_workspace_scoped(path, workspace)
        attrs: Dict[str, Any] = {
            "transport": "http" if url else "stdio",
            "command": " ".join(redacted_cmd),
            "url": redacted_url,
            "env_names": list(server.get("env_names") or []),
            "header_names": list(server.get("header_names") or []),
            "is_gateway": False,
            "workspace_scoped": scoped,
            "auto_approve": bool(server.get("auto_approve")),
            "remote": bool(url),
            "agent": agent,
            "secret_in_config": bool(server.get("secret_in_config")),
        }
        if purl:
            attrs["package_id"] = purl
            attrs["pinned"] = pinned
        if wsl_distro:
            attrs["wsl_distro"] = wsl_distro
        joined = " ".join(redacted_cmd).lower()
        if "prismor" in joined and "mcp-gateway" in joined:
            attrs["is_gateway"] = True
        yield InventoryRecord(
            kind="mcp_server",
            surface="endpoint",
            source=source,
            product=agent,
            vendor="",
            name=str(server.get("name") or "unnamed"),
            entity_key=mcp_entity_key(command, url),
            username=username,
            location=Location(
                path=home_relative(path, home),
                scope="workspace" if scoped else "user",
                os=os_name,
            ),
            governance=Governance(
                managed=bool(attrs["is_gateway"]),
                governed_by="prismor-gateway" if attrs["is_gateway"] else "none",
                coverable=not attrs["is_gateway"],
            ),
            attributes=attrs,
            evidence=[{"type": "file", "ref": home_relative(path, home)}],
        )
