"""Adapt the existing agent / MCP / credential inventories, and scan other profiles.

``discover_*`` stays the source of truth for the caller's home (governance,
gateway, Cloak). Other profiles are read directly so a SYSTEM scan does not
inherit the service account's ``APPDATA``.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable, List

from prismor.runtime.inventory.collectors import mcp_files
from prismor.runtime.inventory.context import ScanContext
from prismor.runtime.inventory.homes import Home, local_homes
from prismor.runtime.inventory.ids import agent_entity_key
from prismor.runtime.inventory.schema import (
    Governance, InventoryRecord, Location, diagnostic,
)

SURFACE = "endpoint.core"
REQUIRES = {"os": ["windows", "darwin", "linux"], "auth": None, "extras": []}

_RC_FILES = (".bashrc", ".zshrc", ".profile", ".bash_profile", ".zprofile")


def _agent_records(ctx: ScanContext, home: Home) -> Iterable[InventoryRecord]:
    """Legacy agent inventory for the caller's home only."""
    if ctx.profiles_root is not None or ctx.dry_run:
        return []
    try:
        from prismor.runtime.discover import discover_agents
        agents = discover_agents(ctx.workspace)
    except Exception:
        return []
    out: List[InventoryRecord] = []
    for agent in agents:
        out.append(InventoryRecord(
            kind="agent",
            surface="endpoint",
            source=SURFACE,
            product=agent.id,
            vendor="",
            name=agent.name,
            entity_key=agent_entity_key(agent.id),
            username=home.username,
            location=Location(
                path=mcp_files.home_relative(Path(agent.config_paths[0]), home.path) if agent.config_paths else None,
                os=ctx.os_name,
                scope="user",
            ),
            governance=Governance(
                managed=agent.managed,
                governed_by="prismor-hook" if agent.managed else "none",
                coverable=agent.coverable,
                mode=agent.mode or None,
            ),
            attributes={
                "install_kind": "cli",
                "hooks_supported": agent.coverable,
                "evidence": list(agent.evidence),
            },
            evidence=[{"type": "file", "ref": mcp_files.home_relative(Path(p), home.path)}
                      for p in agent.config_paths[:5]],
        ))
    return out


def _credential_from_legacy(ctx: ScanContext, home: Home) -> Iterable[InventoryRecord]:
    if ctx.profiles_root is not None or ctx.dry_run:
        return []
    try:
        from prismor.runtime.discover import discover_credentials
        found = discover_credentials(ctx.workspace, scan_files=True)
    except Exception:
        return []
    out = []
    for cred in found:
        out.append(_credential_record(
            provider=cred.provider,
            location_kind="env" if cred.location_kind == "env" else "config-file",
            location=cred.location if cred.location_kind == "env" else cred.location,
            managed=cred.managed,
            username=home.username,
            os_name=ctx.os_name,
        ))
    return out


def _credential_record(*, provider: str, location_kind: str, location: str, managed: bool,
                       username: str, os_name: str, wsl_distro: str = "") -> InventoryRecord:
    attrs = {
        "provider": provider,
        "location_kind": location_kind,
        "location": location,
    }
    if wsl_distro:
        attrs["wsl_distro"] = wsl_distro
    return InventoryRecord(
        kind="credential_ref",
        surface="endpoint",
        source=SURFACE,
        product=provider,
        vendor=provider,
        name=provider,
        entity_key=f"cred:{provider}:{location_kind}",
        username=username,
        location=Location(path=location if location_kind != "env" else None, os=os_name, scope="user"),
        governance=Governance(
            managed=managed,
            governed_by="prismor-cloak" if managed else "none",
            coverable=True,
        ),
        attributes=attrs,
        evidence=[{"type": location_kind, "ref": location}],
    )


def _rc_credentials(home: Home, os_name: str, wsl_distro: str = "") -> Iterable[InventoryRecord]:
    import re
    from prismor.runtime.discover import _ENV_KEY_PATTERNS
    export_name = re.compile(r"(?m)^[ \t]*export[ \t]+([A-Za-z_][A-Za-z0-9_]*)=")
    out = []
    for filename in _RC_FILES:
        path = home.path / filename
        try:
            if not path.is_file() or path.stat().st_size > 512 * 1024:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        seen = set()
        for match in export_name.finditer(text):
            var = match.group(1)
            for provider, pattern in _ENV_KEY_PATTERNS:
                if not pattern.match(var) or (provider, filename) in seen:
                    continue
                seen.add((provider, filename))
                out.append(_credential_record(
                    provider=provider,
                    location_kind="rc-file",
                    location="~/" + filename,
                    managed=False,
                    username=home.username,
                    os_name=os_name,
                    wsl_distro=wsl_distro,
                ))
    return out


def _windows_user_env(home: Home) -> Iterable[InventoryRecord]:
    """Names from a loaded HKCU/HKU Environment hive. Unloaded profiles are skipped.

    Loading ``NTUSER.DAT`` for a logged-out user is intentionally not attempted.
    """
    import sys
    if sys.platform != "win32":
        return []
    try:
        import winreg
    except ImportError:
        return []
    out = []
    try:
        from prismor.runtime.discover import _ENV_KEY_PATTERNS
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Environment") as key:
            index = 0
            while True:
                try:
                    var, _value, _typ = winreg.EnumValue(key, index)
                except OSError:
                    break
                index += 1
                # The value is intentionally discarded.
                del _value
                for provider, pattern in _ENV_KEY_PATTERNS:
                    if pattern.match(str(var)):
                        out.append(_credential_record(
                            provider=provider, location_kind="user-env", location=str(var),
                            managed=False, username=home.username, os_name="windows",
                        ))
                        break
    except OSError:
        return []
    return out


def mcp_on_home(ctx: ScanContext, home: Home, *, source: str = SURFACE,
                include_workspace: bool = True) -> Iterable[InventoryRecord]:
    """JSON MCP configs for one profile. XML is the JetBrains collector's job."""
    if ctx.dry_run:
        yield diagnostic(source, error_code="dry_run", hint=f"would read MCP configs under {home.username}",
                         surface="endpoint")
        return
    try:
        from prismor.runtime.discover import _extra_mcp_configs
        system = {"windows": "Windows", "darwin": "Darwin", "linux": "Linux"}.get(home.os_name, "Linux")
        configs = list(_extra_mcp_configs(ctx.workspace, home=home.path, system=system))
        if not include_workspace:
            kept = []
            for item in configs:
                try:
                    Path(item["path"]).resolve().relative_to(home.path.resolve())
                except (OSError, ValueError):
                    continue
                kept.append(item)
            configs = kept
        if ctx.profiles_root is None and home.path == Path.home():
            from prismor.runtime.scanner import discover_configs
            known = {str(item["path"]) for item in configs}
            for entry in discover_configs(workspace=ctx.workspace):
                if str(entry["path"]) not in known:
                    configs.append(entry)
    except Exception:
        yield diagnostic(source, error_code="mcp_list_failed", hint="could not list MCP config paths",
                         surface="endpoint")
        return
    for cfg in configs:
        path = Path(cfg["path"])
        if path.suffix.lower() == ".xml":
            continue
        agent = str(cfg.get("agent") or "unknown")
        try:
            servers = mcp_files.read_mcp_file(path)
        except OSError:
            yield diagnostic(source, error_code="permission", hint="config not readable", surface="endpoint",
                             name=agent)
            continue
        except (ValueError, json.JSONDecodeError):
            yield diagnostic(source, error_code="malformed", hint="config was not valid JSON", surface="endpoint",
                             name=agent)
            continue
        yield from mcp_files.mcp_records(
            servers=servers, path=path, home=home.path, agent=agent, source=source,
            username=home.username, workspace=ctx.workspace, wsl_distro=home.wsl_distro,
            os_name=home.os_name,
        )


def credentials_on_home(ctx: ScanContext, home: Home, *, include_process: bool) -> Iterable[InventoryRecord]:
    if ctx.dry_run:
        return []
    records: List[InventoryRecord] = []
    if include_process:
        records.extend(_credential_from_legacy(ctx, home))
    try:
        records.extend(_rc_credentials(home, home.os_name, home.wsl_distro))
    except OSError:
        pass
    if home.os_name == "windows" and include_process:
        try:
            records.extend(_windows_user_env(home))
        except OSError:
            pass
    return records


def collect(ctx: ScanContext) -> Iterable[InventoryRecord]:
    try:
        homes = local_homes(ctx)
    except OSError:
        yield diagnostic(SURFACE, error_code="permission", hint="could not list user profiles", surface="endpoint")
        return
    caller = homes[0] if homes else None
    managed: set = set()
    produced: List[InventoryRecord] = []
    if caller is not None and ctx.profiles_root is None:
        try:
            yield from _agent_records(ctx, caller)
        except OSError:
            yield diagnostic(SURFACE, error_code="permission", hint="agent inventory unreadable", surface="endpoint")
        yield from credentials_on_home(ctx, caller, include_process=True)
        managed = _governed_mcp(ctx)
    first = True
    for home in homes:
        if not (caller is not None and home.path == caller.path and ctx.profiles_root is None):
            yield from credentials_on_home(ctx, home, include_process=False)
        try:
            produced.extend(mcp_on_home(ctx, home, include_workspace=first))
        except OSError:
            yield diagnostic(SURFACE, error_code="permission", hint="profile not readable", surface="endpoint",
                             name=home.username)
        first = False
    apply_gateway(produced, managed)
    yield from produced


def _governed_mcp(ctx: ScanContext) -> set:
    """Names of gateway-managed servers, from the legacy ``discover_mcp`` sweep.

    The file parse in ``mcp_on_home`` is the inventory row. This only upgrades
    ``managed`` when the legacy sweep says the server sits behind the gateway.
    """
    if ctx.dry_run or ctx.profiles_root is not None:
        return set()
    try:
        from prismor.runtime.discover import discover_mcp
        found = discover_mcp(ctx.workspace)
    except Exception:
        return set()
    return {item.name.lower() for item in found if item.managed and not item.is_gateway}


def apply_gateway(records: List[InventoryRecord], managed_names: set) -> None:
    for record in records:
        if record.kind == "mcp_server" and record.name.lower() in managed_names and not record.attributes.get("is_gateway"):
            # A direct declaration that is also on the gateway is still a bypass
            # in the legacy sweep. Keep managed false. The attribute records the fact.
            record.attributes["also_on_gateway"] = True
