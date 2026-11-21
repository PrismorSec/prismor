"""Stable ids for inventory records.

``record_id`` is stable across runs so a sink can upsert. ``entity_key`` is
the cross-surface identity. Usernames are HMAC-hashed; nothing here accepts
or returns a secret value.
"""
from __future__ import annotations

import hashlib
import hmac
import re
from pathlib import Path
from typing import List, Optional, Sequence, Tuple
from urllib.parse import urlsplit

from prismor.runtime.discover import redact_command, redact_url

_NPM_LAUNCHERS = {"npx", "npx.cmd", "npx.exe"}
_PY_LAUNCHERS = {"uvx", "uvx.exe"}
_PIPX = {"pipx", "pipx.exe"}
_DOCKER = {"docker", "docker.exe", "podman", "podman.exe"}
_FLAG_WITH_VALUE = {
    "-e", "--env", "-v", "--volume", "-p", "--publish", "--name", "--mount",
    "-w", "--workdir", "--entrypoint", "--user", "-u", "--network", "--label",
    "--hostname", "--add-host", "--env-file", "-m", "--memory", "--cpus",
}


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def record_id(source: str, kind: str, scope_key: str, natural_key: str) -> str:
    """``inv_`` + sha256(source|kind|scope_key|natural_key)[:20]."""
    raw = "|".join([source or "", kind or "", scope_key or "", natural_key or ""])
    return "inv_" + _sha256(raw)[:20]


def group_id(entity_key: str) -> str:
    """``grp_`` + sha256(entity_key)[:16]. Equal keys share a group."""
    return "grp_" + _sha256(entity_key or "")[:16]


def host_id(machine_id: str, org_salt: str, enrolled_device_id: str = "") -> str:
    """Enrolled device id when there is one, else a salted hash of the machine id."""
    if enrolled_device_id:
        return enrolled_device_id
    return "h_" + _sha256((machine_id or "") + (org_salt or ""))[:16]


def user_hash(org_salt: str, username: str) -> str:
    """``u_`` + HMAC-SHA256(org_salt, username)[:16]."""
    digest = hmac.new(
        (org_salt or "").encode("utf-8"),
        (username or "").encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return "u_" + digest[:16]


def scope_key_endpoint(host: str, user: str) -> str:
    return f"{host}+{user}"


def _basename(argv0: str) -> str:
    name = Path(str(argv0)).name.lower()
    return name


def _split_package_spec(spec: str) -> Tuple[str, Optional[str]]:
    """Return (name, version) for an npm or pypi spec. Scoped names keep their '@'."""
    spec = spec.strip()
    if not spec:
        return "", None
    if spec.startswith("@") and spec.count("@") >= 2:
        name, ver = spec.rsplit("@", 1)
        return name, ver or None
    if spec.startswith("@"):
        return spec, None
    if "==" in spec:
        name, ver = spec.split("==", 1)
        return name, ver or None
    if "@" in spec:
        name, ver = spec.rsplit("@", 1)
        return name, ver or None
    return spec, None


def _npx_spec(argv: Sequence[str]) -> Optional[str]:
    for index, arg in enumerate(argv):
        if _basename(arg) not in _NPM_LAUNCHERS:
            continue
        rest = [str(a) for a in argv[index + 1:]]
        while rest and rest[0] in {"-y", "--yes"}:
            rest = rest[1:]
        if rest and not rest[0].startswith("-"):
            return rest[0]
    return None


def _uvx_spec(argv: Sequence[str]) -> Optional[str]:
    for index, arg in enumerate(argv):
        if _basename(arg) not in _PY_LAUNCHERS:
            continue
        rest = [str(a) for a in argv[index + 1:]]
        if rest and not rest[0].startswith("-"):
            return rest[0]
    return None


def _pipx_spec(argv: Sequence[str]) -> Optional[str]:
    for index, arg in enumerate(argv):
        if _basename(arg) not in _PIPX:
            continue
        rest = [str(a) for a in argv[index + 1:]]
        if not rest or rest[0] != "run":
            continue
        rest = rest[1:]
        while rest and rest[0].startswith("-"):
            rest = rest[1:]
        if rest:
            return rest[0]
    return None


def _docker_image(argv: Sequence[str]) -> Optional[str]:
    strings = [str(a) for a in argv]
    if not strings or _basename(strings[0]) not in _DOCKER:
        return None
    if "run" not in strings:
        return None
    rest = strings[strings.index("run") + 1:]
    skip_next = False
    for arg in rest:
        if skip_next:
            skip_next = False
            continue
        if arg in _FLAG_WITH_VALUE:
            skip_next = True
            continue
        if arg.startswith("-"):
            continue
        return arg
    return None


def package_from_command(command: Sequence[str]) -> Tuple[Optional[str], bool]:
    """Return (purl, pinned). Purl has no version; ``pinned`` is whether one was declared."""
    argv = [str(a) for a in command]
    npm = _npx_spec(argv)
    if npm:
        name, ver = _split_package_spec(npm)
        if name:
            return f"pkg:npm/{name}", bool(ver)
    py = _uvx_spec(argv)
    if py:
        name, ver = _split_package_spec(py)
        if name:
            return f"pkg:pypi/{name}", bool(ver)
    pipx = _pipx_spec(argv)
    if pipx:
        name, ver = _split_package_spec(pipx)
        if name:
            return f"pkg:pypi/{name}", bool(ver)
    image = _docker_image(argv)
    if image:
        pinned = "@sha256:" in image or (":" in image and "://" not in image)
        bare = image.split("@", 1)[0]
        if ":" in bare and "://" not in bare:
            bare = bare.rsplit(":", 1)[0]
        return f"pkg:docker/{bare}", pinned
    return None, False


def _url_identity(url: str) -> str:
    """``scheme://host[:port]/first-segment`` after redaction. No query, userinfo, or secret."""
    redacted = redact_url(url)
    parts = urlsplit(redacted)
    if not parts.scheme or not parts.hostname:
        return ""
    port = f":{parts.port}" if parts.port else ""
    first = ""
    stripped = (parts.path or "").strip("/")
    if stripped:
        first = stripped.split("/", 1)[0]
        if first == "<redacted>":
            first = ""
    base = f"{parts.scheme}://{parts.hostname}{port}"
    return f"{base}/{first}" if first else base


def _command_identity(command: Sequence[str]) -> str:
    redacted = redact_command([str(a) for a in command])
    kept: List[str] = []
    for arg in redacted:
        if arg == "<redacted>" or "://" in arg:
            continue
        kept.append(arg)
    if not kept:
        kept = ["unknown"]
    digest = _sha256("\0".join(kept))[:12]
    return f"mcp:cmd:{Path(kept[0]).name}:{digest}"


def mcp_entity_key(command: Sequence[str], url: str = "") -> str:
    """Cross-surface identity for an MCP server. Package, else URL, else argv."""
    purl, _pinned = package_from_command(command)
    if purl:
        return "mcp:" + purl
    if url:
        ident = _url_identity(url)
        if ident:
            return "mcp:url:" + ident
    return _command_identity(command)


def agent_entity_key(catalog_id: str) -> str:
    return "agent:" + re.sub(r"[^a-z0-9._-]+", "-", (catalog_id or "unknown").lower()).strip("-")


def extension_entity_key(editor: str, extension_id: str) -> str:
    family = "vscode" if editor in {"vscode", "cursor", "windsurf", "vscode-insiders", "vscode-server"} else editor
    if family == "jetbrains":
        return "ext:jetbrains:" + extension_id
    return f"ext:{family}:{extension_id}"


_REGISTRABLE_MULTI = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "co.nz", "com.br",
}


def registrable_domain(host: str) -> str:
    """Best-effort registrable domain without a public-suffix list.

    Two labels, or three when the last two are a known multi-part suffix
    (``co.uk`` and the like). Enough for correlation; not a DNS authority.
    """
    host = (host or "").strip(".").lower()
    if not host or re.match(r"^\d+\.\d+\.\d+\.\d+$", host):
        return host
    labels = host.split(".")
    if len(labels) <= 2:
        return host
    tail2 = ".".join(labels[-2:])
    if tail2 in _REGISTRABLE_MULTI and len(labels) >= 3:
        return ".".join(labels[-3:])
    return tail2
