"""Pinned MCP tool definitions: notice when a server changes a tool after first use.

A tool's description and schema are instructions the model follows, and the
server can change them at any time without the user seeing it — approve a
harmless ``add_numbers`` today, and tomorrow its description tells the model to
read ``~/.ssh/id_rsa`` (the MCP "rug pull"). The gateway therefore remembers a
hash of every tool definition it has listed, per server, the first time it sees
it (trust on first use), and treats a later change as unreviewed:

  * ``check`` reports ``new`` / ``same`` / ``changed`` for a definition;
  * a changed (or flagged) definition is kept as ``pending`` with a short
    preview, so a human can review it without reconnecting to the server;
  * ``approve`` pins the pending definition (``reviewed``) — only a human at a
    terminal can run it (``prismor-self-edit`` covers the command and the pin
    files).

Pins live in ``$PRISMOR_HOME/mcp-tool-pins/<hash>.json`` (0600), keyed by the
server's URL or command rather than its config name, so renaming an entry keeps
its pins and pointing a name at a different server does not inherit them.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

#: The fields of a tool definition the model reads. ``name`` is the key, and
#: ``_meta`` is server bookkeeping that may change without changing behaviour.
_DEFINITION_FIELDS = ("title", "description", "inputSchema", "outputSchema", "annotations")
PREVIEW_CHARS = 600

_lock = threading.Lock()


def definition_hash(tool: Dict[str, Any]) -> str:
    body = {k: tool.get(k) for k in _DEFINITION_FIELDS if tool.get(k) is not None}
    raw = json.dumps(body, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def definition_text(tool: Dict[str, Any]) -> str:
    """Everything in a definition the model reads as prose: the tool's name,
    title and description, and every parameter's name, title and description
    (a poisoned instruction is as effective in a parameter description, and a
    parameter called ``sidenote`` is how the stolen data leaves)."""
    parts: List[str] = [str(tool.get("name") or ""), str(tool.get("title") or ""),
                        str(tool.get("description") or "")]

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                if key in ("description", "title") and isinstance(value, str):
                    parts.append(value)
                elif key == "properties" and isinstance(value, dict):
                    parts.extend(str(k) for k in value)
                    walk(value)
                else:
                    walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk({k: tool.get(k) for k in ("inputSchema", "outputSchema", "annotations")})
    return "\n".join(p for p in parts if p)


def server_identity(url: str = "", command: Optional[List[str]] = None) -> str:
    if url:
        return url.strip().rstrip("/").lower()
    return json.dumps([str(c) for c in command or []])


def _dir() -> Path:
    from prismor.runtime.store import prismor_home
    return prismor_home() / "mcp-tool-pins"


def _path(identity: str) -> Path:
    return _dir() / (hashlib.sha256(identity.encode("utf-8")).hexdigest()[:32] + ".json")


def load(identity: str) -> Dict[str, Any]:
    try:
        data = json.loads(_path(identity).read_text(encoding="utf-8"))
    except (FileNotFoundError, ValueError, OSError):
        data = None
    if not isinstance(data, dict) or data.get("identity") != identity:
        return {"identity": identity, "tools": {}, "pending": {}}
    data.setdefault("tools", {})
    data.setdefault("pending", {})
    return data


def _save(data: Dict[str, Any]) -> None:
    path = _path(data["identity"])
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path.parent, 0o700)
    except OSError:
        pass
    tmp = path.with_suffix(f".{os.getpid()}.tmp")
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, sort_keys=True)
    os.replace(tmp, path)


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def is_reviewed(identity: str, tool: str, digest: str) -> bool:
    pin = load(identity)["tools"].get(tool) or {}
    return pin.get("hash") == digest and bool(pin.get("reviewed"))


def check(identity: str, server: str, tool: Dict[str, Any], *, flagged: str = "") -> str:
    """Compare a listed definition with its pin.

    Returns ``same``, ``new`` (pinned now), ``changed`` (kept pending), or
    ``flagged`` (a first-seen definition the scan flagged: kept pending, never
    pinned automatically).
    """
    name = str(tool.get("name") or "")
    digest = definition_hash(tool)
    with _lock:
        data = load(identity)
        data["server"] = server
        pin = data["tools"].get(name)
        if pin is not None and pin.get("hash") == digest:
            if data["pending"].pop(name, None) is not None:
                _save(data)   # changed back to what was approved
            return "same"
        if pin is None and not flagged:
            data["tools"][name] = {"hash": digest, "pinned_at": _now()}
            data["pending"].pop(name, None)
            _save(data)
            return "new"
        pending = data["pending"].get(name) or {}
        if pending.get("hash") != digest or pending.get("reason") != (flagged or "changed"):
            data["pending"][name] = {
                "hash": digest, "seen_at": _now(), "reason": flagged or "changed",
                "description": str(tool.get("description") or "")[:PREVIEW_CHARS],
            }
            _save(data)
        return "changed" if pin is not None else "flagged"


SHORT_HASH = 12


def approve(identity: str, tools: Optional[List[str]] = None) -> Dict[str, List[str]]:
    """Pin pending definitions as reviewed: all of them, or the named ones.

    A name may carry the short hash ``tools`` printed (``add@3f9c1a2b7d4e``).
    Then only that exact definition is approved: if the server changed it
    again after the human read it, it stays held (``stale``) rather than
    approving text nobody reviewed.
    """
    out: Dict[str, List[str]] = {"approved": [], "stale": [], "missing": []}
    with _lock:
        data = load(identity)
        wanted = tools or list(data["pending"])
        for item in wanted:
            name, _, short = item.partition("@")
            entry = data["pending"].get(name)
            if entry is None:
                out["missing"].append(name)
                continue
            if short and not entry["hash"].startswith(short.lower()):
                out["stale"].append(name)
                continue
            data["pending"].pop(name)
            data["tools"][name] = {"hash": entry["hash"], "pinned_at": _now(), "reviewed": True}
            out["approved"].append(name)
        if out["approved"]:
            _save(data)
    return out


def forget(identity: str) -> bool:
    try:
        _path(identity).unlink()
        return True
    except FileNotFoundError:
        return False
