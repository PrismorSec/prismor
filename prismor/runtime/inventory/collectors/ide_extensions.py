"""VS Code-family extensions, plus a heuristic for unknown model-tool extensions.

Extension directories under ``~/.cursor`` and ``~/.windsurf`` are included.
Those two paths were not confirmed against a current vendor doc in this
change; records from them carry ``editor_path_verified: false``.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, Iterable, List

from prismor.runtime.inventory import catalog
from prismor.runtime.inventory.collectors import mcp_files
from prismor.runtime.inventory.context import ScanContext
from prismor.runtime.inventory.homes import Home, local_homes
from prismor.runtime.inventory.ids import extension_entity_key
from prismor.runtime.inventory.schema import (
    Governance, InventoryRecord, Location, diagnostic,
)

SURFACE = "endpoint.extensions"
REQUIRES = {"os": ["windows", "darwin", "linux"], "auth": None, "extras": []}

# (relative directory, editor id, path verified against a vendor doc)
_EDITORS = (
    (".vscode/extensions", "vscode", True),
    (".vscode-insiders/extensions", "vscode-insiders", True),
    (".vscode-server/extensions", "vscode-server", True),
    (".cursor/extensions", "cursor", False),
    (".windsurf/extensions", "windsurf", False),
)

_HEURISTIC_KEYS = ("languageModelTools", "chatParticipants", "mcpServerDefinitionProviders")


def _package_dirs(root: Path) -> List[Path]:
    found: List[Path] = []
    try:
        children = list(root.iterdir())
    except OSError:
        raise
    for child in children:
        if not child.is_dir():
            continue
        pkg = child / "package.json"
        if pkg.is_file():
            found.append(pkg)
    return found[:2000]


def _from_extensions_json(root: Path) -> Dict[str, str]:
    """extension id (lower) -> version, from extensions.json when present."""
    path = root / "extensions.json"
    versions: Dict[str, str] = {}
    try:
        if not path.is_file() or path.stat().st_size > 8 * 1024 * 1024:
            return versions
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return versions
    if not isinstance(data, list):
        return versions
    for item in data:
        if not isinstance(item, dict):
            continue
        ident = item.get("identifier") or {}
        ext_id = str(ident.get("id") or "")
        if ext_id:
            versions[ext_id.lower()] = str(item.get("version") or "")
    return versions


def _heuristic(contributes: dict) -> bool:
    return any(contributes.get(key) for key in _HEURISTIC_KEYS)


def scan_home(ctx: ScanContext, home: Home, *, source: str = SURFACE) -> Iterable[InventoryRecord]:
    if ctx.dry_run:
        yield diagnostic(source, error_code="dry_run", hint="would read IDE extension directories",
                         surface="endpoint", name=home.username)
        return
    for relative, editor, verified in _EDITORS:
        root = home.path.joinpath(*relative.split("/"))
        try:
            if not root.is_dir():
                continue
            versions = _from_extensions_json(root)
            packages = _package_dirs(root)
        except OSError:
            yield diagnostic(source, error_code="permission", hint="extension directory not readable",
                             surface="endpoint", name=editor)
            continue
        seen = set()
        for pkg in packages:
            try:
                if pkg.stat().st_size > 2 * 1024 * 1024:
                    continue
                meta = json.loads(pkg.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                yield diagnostic(source, error_code="malformed", hint="extension package.json was not valid JSON",
                                 surface="endpoint", name=editor)
                continue
            if not isinstance(meta, dict):
                continue
            publisher = str(meta.get("publisher") or "")
            name = str(meta.get("name") or "")
            ext_id = f"{publisher}.{name}" if publisher and name else str(meta.get("name") or pkg.parent.name)
            key = ext_id.lower()
            if key in seen:
                continue
            seen.add(key)
            entry = catalog.match_extension(ext_id)
            contributes = meta.get("contributes") if isinstance(meta.get("contributes"), dict) else {}
            if entry is None and not _heuristic(contributes):
                continue
            confidence = catalog.confidence_of(entry) if entry else "heuristic"
            version = str(meta.get("version") or versions.get(key) or "") or None
            display = str((entry or {}).get("name") or meta.get("displayName") or ext_id)
            vendor = str((entry or {}).get("vendor") or publisher)
            attrs = {
                "editor": editor,
                "extension_id": (entry or {}).get("match", {}).get("extension_id") or ext_id,
                "publisher": publisher,
                "ai_capability": (entry or {}).get("ai_capability") or "heuristic",
                "confidence": confidence,
                "editor_path_verified": verified,
                "unknown_publisher": entry is None or confidence != "catalog",
            }
            if home.wsl_distro:
                attrs["wsl_distro"] = home.wsl_distro
            if confidence == "catalog":
                attrs["unknown_publisher"] = False
            yield InventoryRecord(
                kind="ide_extension",
                surface="endpoint",
                source=source,
                product=str((entry or {}).get("id") or ext_id),
                vendor=vendor,
                name=display,
                version=version,
                entity_key=extension_entity_key(editor, attrs["extension_id"]),
                username=home.username,
                location=Location(
                    path=mcp_files.home_relative(pkg.parent, home.path),
                    os=home.os_name, scope="user",
                ),
                governance=Governance(managed=False, governed_by="none", coverable=False),
                attributes=attrs,
                evidence=[{"type": "file", "ref": mcp_files.home_relative(pkg, home.path)}],
            )


def collect(ctx: ScanContext) -> Iterable[InventoryRecord]:
    try:
        homes = local_homes(ctx)
    except OSError:
        yield diagnostic(SURFACE, error_code="permission", hint="could not list user profiles", surface="endpoint")
        return
    for home in homes:
        try:
            yield from scan_home(ctx, home)
        except OSError:
            yield diagnostic(SURFACE, error_code="permission", hint="extension profile not readable",
                             surface="endpoint", name=home.username)
