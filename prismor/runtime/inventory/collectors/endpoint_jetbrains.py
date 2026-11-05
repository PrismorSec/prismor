"""JetBrains IDEs, AI Assistant, Junie, and Copilot for JetBrains.

Plugin ids are matched against ``catalog/jetbrains_plugins.yaml``. MCP servers
declared in ``llm.mcpServers.xml`` are read here; JSON MCP configs for Junie
and Copilot are read by ``endpoint_core`` so there is one parser for JSON.
"""
from __future__ import annotations

import zipfile
from pathlib import Path
from typing import Iterable, List, Optional
from xml.etree import ElementTree as ET

from prismor.runtime.inventory import catalog
from prismor.runtime.inventory.collectors import mcp_files
from prismor.runtime.inventory.context import ScanContext
from prismor.runtime.inventory.homes import Home, local_homes
from prismor.runtime.inventory.ids import agent_entity_key, extension_entity_key
from prismor.runtime.inventory.schema import (
    Governance, InventoryRecord, Location, diagnostic,
)

SURFACE = "endpoint.jetbrains"
REQUIRES = {"os": ["windows", "darwin", "linux"], "auth": None, "extras": []}

_AGENT_BY_PLUGIN = {
    "com.intellij.ml.llm": ("jetbrains-ai", "JetBrains AI Assistant", "JetBrains"),
    "org.jetbrains.junie": ("junie", "Junie", "JetBrains"),
    "com.github.copilot": ("copilot-jetbrains", "GitHub Copilot", "GitHub"),
}


def config_roots(home: Path, os_name: str) -> List[Path]:
    if os_name == "windows":
        return [home / "AppData" / "Roaming" / "JetBrains"]
    if os_name == "darwin":
        return [home / "Library" / "Application Support" / "JetBrains"]
    return [home / ".config" / "JetBrains"]


def plugin_dirs(home: Path, os_name: str, product: Path) -> List[Path]:
    dirs = [product / "plugins"]
    if os_name == "linux":
        dirs.append(home / ".local" / "share" / "JetBrains" / product.name / "plugins")
    return dirs


def _read_plugin_xml(jar: Path) -> Optional[dict]:
    try:
        if jar.stat().st_size > 80 * 1024 * 1024:
            return None
        with zipfile.ZipFile(jar) as archive:
            name = next((n for n in archive.namelist() if n.endswith("META-INF/plugin.xml")), "")
            if not name:
                return None
            text = archive.read(name)[:256 * 1024]
    except (OSError, zipfile.BadZipFile, KeyError):
        return None
    if b"<!DOCTYPE" in text or b"<!ENTITY" in text:
        return None
    try:
        root = ET.fromstring(text)  # nosec B314
    except ET.ParseError:
        return None

    def text_of(tag: str) -> str:
        for node in root.iter():
            if node.tag.rsplit("}", 1)[-1] == tag and node.text:
                return node.text.strip()
        return ""

    plugin_id = text_of("id")
    if not plugin_id:
        return None
    return {
        "id": plugin_id,
        "name": text_of("name") or plugin_id,
        "version": text_of("version"),
        "vendor": text_of("vendor"),
    }


def _iter_plugins(home: Path, os_name: str, product: Path) -> Iterable[dict]:
    seen = set()
    for directory in plugin_dirs(home, os_name, product):
        try:
            if not directory.is_dir():
                continue
            jars = list(directory.glob("*/lib/*.jar")) + list(directory.glob("*.jar"))
        except OSError:
            continue
        for jar in jars[:500]:
            meta = _read_plugin_xml(jar)
            if not meta or meta["id"] in seen:
                continue
            seen.add(meta["id"])
            meta["jar"] = jar
            yield meta


def _agent(home: Home, *, catalog_id: str, name: str, vendor: str, ide: str,
           plugin_id: str, source: str) -> InventoryRecord:
    return InventoryRecord(
        kind="agent",
        surface="endpoint",
        source=source,
        product=catalog_id,
        vendor=vendor,
        name=name,
        entity_key=agent_entity_key(catalog_id),
        username=home.username,
        location=Location(os=home.os_name, scope="user", path=mcp_files.home_relative(
            config_roots(home.path, home.os_name)[0], home.path) if ide else None),
        governance=Governance(managed=False, governed_by="none", coverable=False),
        attributes={
            "ide": ide,
            "install_kind": "ide-plugin",
            "hooks_supported": False,
            "plugin_id": plugin_id,
        },
    )


def scan_home(ctx: ScanContext, home: Home, *, source: str = SURFACE) -> Iterable[InventoryRecord]:
    if ctx.dry_run:
        yield diagnostic(source, error_code="dry_run", hint="would read JetBrains config directories",
                         surface="endpoint", name=home.username)
        return
    emitted = set()
    try:
        roots = config_roots(home.path, home.os_name)
    except OSError:
        yield diagnostic(source, error_code="permission", hint="JetBrains config not readable",
                         surface="endpoint")
        return
    for root in roots:
        try:
            if not root.is_dir():
                continue
            products = [p for p in root.iterdir() if p.is_dir()]
        except OSError:
            yield diagnostic(source, error_code="permission", hint="JetBrains config not readable",
                             surface="endpoint")
            continue
        for product in products:
            ide = product.name
            for meta in _iter_plugins(home.path, home.os_name, product):
                entry = catalog.match_plugin(meta["id"])
                known = _AGENT_BY_PLUGIN.get(meta["id"])
                if entry is None and known is None:
                    continue
                catalog_id = known[0] if known else str(entry.get("id") if entry else meta["id"])
                display = known[1] if known else str((entry or {}).get("name") or meta["name"])
                vendor = known[2] if known else str((entry or {}).get("vendor") or meta.get("vendor") or "")
                if ("agent", catalog_id) not in emitted:
                    emitted.add(("agent", catalog_id))
                    record = _agent(home, catalog_id=catalog_id, name=display, vendor=vendor, ide=ide,
                                    plugin_id=meta["id"], source=source)
                    record.version = meta.get("version") or None
                    record.attributes["wsl_distro"] = home.wsl_distro
                    if not home.wsl_distro:
                        record.attributes.pop("wsl_distro", None)
                    yield record
                confidence = catalog.confidence_of(entry)
                ext = InventoryRecord(
                    kind="ide_extension",
                    surface="endpoint",
                    source=source,
                    product=catalog_id,
                    vendor=vendor,
                    name=display,
                    version=meta.get("version") or None,
                    entity_key=extension_entity_key("jetbrains", meta["id"]),
                    username=home.username,
                    location=Location(
                        path=mcp_files.home_relative(meta["jar"], home.path),
                        os=home.os_name, scope="user",
                    ),
                    governance=Governance(managed=False, governed_by="none", coverable=False),
                    attributes={
                        "editor": "jetbrains",
                        "extension_id": meta["id"],
                        "publisher": vendor,
                        "ai_capability": (entry or {}).get("ai_capability") or "agent",
                        "confidence": confidence,
                        "ide": ide,
                        "unknown_publisher": confidence != "catalog",
                        "wsl_distro": home.wsl_distro,
                    },
                    evidence=[{"type": "file", "ref": mcp_files.home_relative(meta["jar"], home.path)}],
                )
                if not home.wsl_distro:
                    ext.attributes.pop("wsl_distro", None)
                yield ext
            xml_path = product / "options" / "llm.mcpServers.xml"
            if xml_path.is_file():
                if ("agent", "jetbrains-ai") not in emitted:
                    emitted.add(("agent", "jetbrains-ai"))
                    yield _agent(home, catalog_id="jetbrains-ai", name="JetBrains AI Assistant",
                                 vendor="JetBrains", ide=ide, plugin_id="com.intellij.ml.llm", source=source)
                try:
                    servers = mcp_files.read_mcp_file(xml_path)
                except OSError:
                    yield diagnostic(source, error_code="permission", hint="MCP xml not readable",
                                     surface="endpoint")
                    continue
                except (ValueError, ET.ParseError):
                    yield diagnostic(source, error_code="malformed", hint="MCP xml was refused or malformed",
                                     surface="endpoint")
                    continue
                yield from mcp_files.mcp_records(
                    servers=servers, path=xml_path, home=home.path, agent="jetbrains-ai",
                    source=source, username=home.username, workspace=ctx.workspace,
                    wsl_distro=home.wsl_distro, os_name=home.os_name,
                )
    junie = home.path / ".junie"
    try:
        junie_present = junie.is_dir()
    except OSError:
        junie_present = False
    if junie_present and ("agent", "junie") not in emitted:
        emitted.add(("agent", "junie"))
        record = _agent(home, catalog_id="junie", name="Junie", vendor="JetBrains", ide="",
                        plugin_id="org.jetbrains.junie", source=source)
        record.attributes["install_kind"] = "cli"
        record.location.path = "~/.junie"
        yield record
    copilot_mcp = _copilot_mcp_path(home)
    if copilot_mcp is not None and ("agent", "copilot-jetbrains") not in emitted:
        record = _agent(home, catalog_id="copilot-jetbrains", name="GitHub Copilot", vendor="GitHub",
                        ide="", plugin_id="com.github.copilot", source=source)
        record.attributes["install_kind"] = "ide-plugin"
        yield record


def _copilot_mcp_path(home: Home) -> Optional[Path]:
    if home.os_name == "windows":
        path = home.path / "AppData" / "Local" / "github-copilot" / "intellij" / "mcp.json"
    else:
        path = home.path / ".config" / "github-copilot" / "intellij" / "mcp.json"
    try:
        return path if path.is_file() else None
    except OSError:
        return None


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
            yield diagnostic(SURFACE, error_code="permission", hint="JetBrains profile not readable",
                             surface="endpoint", name=home.username)
