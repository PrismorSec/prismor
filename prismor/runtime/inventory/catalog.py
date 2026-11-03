"""Load the YAML catalogs under ``catalog/``.

Entries with ``verified: false`` still match. Callers surface that as
``confidence: unverified``. Every entry is expected to carry a ``source_url``.
"""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

_DIR = Path(__file__).resolve().parent / "catalog"


def _load(name: str) -> List[Dict[str, Any]]:
    path = _DIR / name
    if not path.is_file():
        return []
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or []
    if not isinstance(data, list):
        return []
    return [item for item in data if isinstance(item, dict)]


@lru_cache(maxsize=1)
def ide_extensions() -> List[Dict[str, Any]]:
    return _load("ide_extensions.yaml")


@lru_cache(maxsize=1)
def jetbrains_plugins() -> List[Dict[str, Any]]:
    return _load("jetbrains_plugins.yaml")


@lru_cache(maxsize=1)
def mcp_paths() -> List[Dict[str, Any]]:
    return _load("mcp_paths.yaml")


@lru_cache(maxsize=1)
def all_entries() -> List[Dict[str, Any]]:
    return ide_extensions() + jetbrains_plugins() + mcp_paths()


def _norm(value: str) -> str:
    return (value or "").strip().lower()


def match_extension(extension_id: str) -> Optional[Dict[str, Any]]:
    want = _norm(extension_id)
    for entry in ide_extensions():
        match = entry.get("match") or {}
        if _norm(str(match.get("extension_id") or entry.get("id") or "")) == want:
            return entry
    return None


def match_plugin(plugin_id: str) -> Optional[Dict[str, Any]]:
    want = _norm(plugin_id)
    for entry in jetbrains_plugins():
        match = entry.get("match") or {}
        if _norm(str(match.get("plugin_id") or "")) == want:
            return entry
    return None


def confidence_of(entry: Optional[Dict[str, Any]]) -> str:
    if entry is None:
        return "heuristic"
    return "catalog" if entry.get("verified") else "unverified"
