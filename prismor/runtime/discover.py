"""Shadow-AI discovery — inventory MCP servers and provider keys alongside the
host agent sweep, then diff all three against what Prismor actually governs.

``enterprise/discovery.py`` answers this question for *agents*, and its report
is folded into the signed attestation bundle. This module keeps that the single
source of truth for the agent half — it calls into it and enriches the result
rather than re-deriving presence — and adds the two surfaces it does not cover:

    agents       delegated to ``enterprise.discovery.discover``
                 governed by: prismor hooks installed in that agent's config
    mcp          scanner.discover_configs() + the desktop/IDE config paths
                 scanner does not cover (see ``_extra_mcp_configs``)
                 governed by: routed through `prismor mcp-gateway`
    credentials  provider key patterns in the environment and agent configs
                 governed by: registered with Prismor Cloak

Anything present but not governed is *shadow*. That diff is the whole product;
the inventories on their own are commodity.

There is a fourth inventory that is not part of that diff:

    webmcp       Chromium profiles with the WebMCP experiment enabled, and
                 extensions that speak the API (see ``discover_webmcp``)
                 governed by: nothing yet — reported, never scored

It is reported because a page registering tools for an in-tab agent is exactly
the ungoverned AI surface this module exists to surface, and kept out of the
coverage ratio because no surface can govern it today.

Secret handling: this module records that a credential exists, its provider,
and where it was found. It never records, returns, or logs the value — callers
render ``CredentialRecord`` directly to a terminal, so a value placed on that
record would be printed. See ``prismor/runtime/cloaking/README.md``.

The heavy lifting for MCP parsing lives in ``scanner``; for key patterns in
``sweep``; this module is inventory and diff only. ``discover_cli`` is the UX.
"""
from __future__ import annotations

import json
import os
import platform
import re
import shutil
import sys
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

# ── record types ─────────────────────────────────────────────────────────────


@dataclass
class AgentRecord:
    """One AI coding agent found on this machine."""

    id: str
    name: str
    kind: str = "coding-agent"
    managed: bool = False
    #: how the agent was found — "binary" ($PATH), "config" (config file), or both
    evidence: List[str] = field(default_factory=list)
    #: config paths that exist for this agent
    config_paths: List[str] = field(default_factory=list)
    #: hook config Prismor is installed into, when managed
    hook_path: str = ""
    mode: str = ""
    #: True when the registry has no hook surface, so it *cannot* be governed
    #: by hooks — reported separately from "unmanaged but coverable"
    coverable: bool = True

    @property
    def shadow(self) -> bool:
        return not self.managed


@dataclass
class McpRecord:
    """One MCP server declared in some agent's config."""

    name: str
    agent: str
    source: str
    transport: str = "stdio"
    #: command argv (stdio) — arguments are kept, env values are not
    command: List[str] = field(default_factory=list)
    url: str = ""
    remote: bool = False
    managed: bool = False
    #: this entry *is* the Prismor gateway rather than a server behind it
    is_gateway: bool = False
    #: declared by a file inside the workspace rather than by the user's own
    #: config — i.e. it arrived with the code. See ``_is_workspace_scoped``.
    workspace_scoped: bool = False
    risk: str = "none"
    findings: List[str] = field(default_factory=list)

    @property
    def shadow(self) -> bool:
        return not self.managed and not self.is_gateway


@dataclass
class CredentialRecord:
    """An AI-provider credential found in the environment or a config file.

    Carries no value — only provider, location, and whether Cloak knows it.
    """

    provider: str
    #: "env" or "file"
    location_kind: str
    #: env var name, or path to the file it was found in
    location: str
    managed: bool = False
    #: cloak placeholder this was matched to, when managed
    cloak_name: str = ""

    @property
    def shadow(self) -> bool:
        return not self.managed


@dataclass
class BrowserSurfaceRecord:
    """A browser-resident WebMCP capability found on this machine.

    WebMCP lets a page register tools on itself, which an agent running in the
    same tab then calls. The exchange never leaves the browser — no child
    process, no transport, no config file naming a server — so unlike every
    other record here this one has no ``managed`` flag and no ``shadow``
    property. There is nothing in front of it to be governed *by*, which makes
    it advisory inventory rather than one half of a coverage diff. See
    ``build_report`` for why it stays out of the coverage ratio.

    Carries locations and names only. Browsing history, extension storage and
    page contents are never read — the same construction as
    ``CredentialRecord``, whose fields cannot hold a secret value.
    """

    #: which browser — "chrome", "edge", "brave", "arc", …
    browser: str
    #: "flag" (the experiment is enabled) or "extension" (a WebMCP consumer)
    kind: str
    name: str
    #: path evidence — the profile or the extension bundle it was found in
    location: str
    #: profile directory name; empty for browser-wide findings like a flag
    profile: str = ""
    extension_id: str = ""
    risk: str = "none"
    findings: List[str] = field(default_factory=list)


# ── agent inventory ──────────────────────────────────────────────────────────

#: $PATH binaries that indicate an agent is installed, keyed by registry id.
#: The registry records config paths but not executable names.
_AGENT_BINARIES: Dict[str, Tuple[str, ...]] = {
    "claude": ("claude",),
    "cursor": ("cursor",),
    "windsurf": ("windsurf",),
    "openclaw": ("openclaw",),
    "hermes": ("hermes",),
    "codex": ("codex",),
    "copilot": ("copilot",),
    "grok": ("grok",),
    "gemini": ("gemini",),
    "opencode": ("opencode",),
    "aider": ("aider",),
    "kiro": ("kiro",),
    "crush": ("crush",),
    "qwen": ("qwen",),
    "goose": ("goose",),
    "continue": ("cn",),
}


def _hook_installed(agent_id: str, workspace: Path) -> Tuple[bool, str, str]:
    """Is Prismor installed into this agent's hook config?

    Returns ``(installed, path, mode)``. Mirrors the check `prismor status`
    does, across both project and user scope, so an agent hooked globally but
    not in this workspace still reads as governed.
    """
    try:
        from prismor.runtime import hooks
    except Exception:
        return False, "", ""
    if agent_id not in getattr(hooks, "_SUPPORTED_AGENTS", []):
        return False, "", ""
    for scope in ("project", "user"):
        try:
            path = hooks._config_path(agent_id, scope, workspace)
        except Exception:
            continue
        if not path.exists():
            continue
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if "prismor" not in content.lower():
            continue
        mode = ""
        if "--mode enforce" in content:
            mode = "enforce"
        elif "--mode observe" in content:
            mode = "observe"
        return True, str(path), mode
    return False, "", ""


def _registry_meta() -> Dict[str, Any]:
    """Registry entries keyed by id, for display names and hook surface."""
    try:
        from prismor.runtime.integrations import registry as _registry
        return {e.id: e for e in _registry.load_registry()}
    except Exception:
        return {}


def discover_agents(workspace: Path) -> List[AgentRecord]:
    """Inventory AI coding agents installed on this machine.

    Presence and governed-ness come from ``enterprise.discovery`` so this view
    and the signed attestation bundle can never disagree. On top of that this
    adds a $PATH probe — an agent installed via a package manager with no
    config written yet is invisible to a filesystem-only sweep — plus the
    display name, hook mode, and whether the agent has a hook surface at all.
    """
    try:
        from prismor.runtime.enterprise import discovery as _discovery
        report = _discovery.discover(workspace)
    except Exception:
        return []

    meta = _registry_meta()
    records: List[AgentRecord] = []
    for row in report.get("agents") or []:
        agent_id = str(row.get("agent") or "")
        evidence: List[str] = []
        if row.get("config_paths"):
            evidence.append("config")
        elif row.get("present"):
            evidence.append("state-dir")

        if any(shutil.which(b) for b in _AGENT_BINARIES.get(agent_id, ())):
            evidence.append("binary")

        if not evidence:
            continue

        entry = meta.get(agent_id)
        managed = bool(row.get("governed"))
        hook_path, mode = "", ""
        if managed:
            _, hook_path, mode = _hook_installed(agent_id, workspace)

        records.append(
            AgentRecord(
                id=agent_id,
                name=getattr(entry, "name", agent_id),
                kind=getattr(entry, "kind", "coding-agent") or "coding-agent",
                managed=managed,
                evidence=evidence,
                config_paths=[str(p) for p in row.get("config_paths") or []],
                hook_path=hook_path,
                mode=mode,
                # An agent with no hook surface cannot be governed by hooks, so
                # it is reported but excluded from the shadow count.
                coverable=getattr(entry, "surface", "hook-config") == "hook-config",
            )
        )
    records.sort(key=lambda r: (r.managed, r.name.lower()))
    return records


# ── MCP inventory ────────────────────────────────────────────────────────────


def _extra_mcp_configs(workspace: Path) -> List[Dict[str, Any]]:
    """MCP config locations ``scanner.discover_configs`` does not cover.

    scanner walks the six agents Prismor hooks into; MCP servers also get
    declared by desktop apps and IDE extensions that have no hook surface at
    all, which is precisely where unmanaged servers accumulate. Kept here
    rather than added to ``scanner._AGENT_DISCOVERERS`` so `prismor scan`
    behaviour is unchanged.
    """
    home = Path.home()
    system = platform.system()
    candidates: List[Tuple[str, Path]] = []

    # Claude Desktop
    if system == "Darwin":
        candidates.append(
            ("claude-desktop",
             home / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json")
        )
        vscode_user = home / "Library" / "Application Support" / "Code" / "User"
    elif system == "Windows":
        appdata = os.environ.get("APPDATA")
        if appdata:
            candidates.append(
                ("claude-desktop", Path(appdata) / "Claude" / "claude_desktop_config.json"))
        vscode_user = Path(appdata) / "Code" / "User" if appdata else None
    else:
        candidates.append(
            ("claude-desktop", home / ".config" / "Claude" / "claude_desktop_config.json"))
        vscode_user = home / ".config" / "Code" / "User"

    # VS Code (and the Cline extension's own store)
    candidates.append(("vscode", workspace / ".vscode" / "mcp.json"))
    if vscode_user:
        candidates.append(("vscode", vscode_user / "mcp.json"))
        candidates.append((
            "cline",
            vscode_user / "globalStorage" / "saoudrizwan.claude-dev" / "settings"
            / "cline_mcp_settings.json",
        ))

    # Other IDE / CLI agents that declare MCP servers but expose no hook surface
    candidates.append(("zed", home / ".config" / "zed" / "settings.json"))
    candidates.append(("gemini", home / ".gemini" / "settings.json"))
    candidates.append(("gemini", workspace / ".gemini" / "settings.json"))
    candidates.append(("continue", home / ".continue" / "config.json"))
    candidates.append(("opencode", home / ".config" / "opencode" / "opencode.json"))

    seen: Set[str] = set()
    out: List[Dict[str, Any]] = []
    for agent, path in candidates:
        if path is None or not path.exists():
            continue
        try:
            key = str(path.resolve())
        except (OSError, ValueError):
            key = str(path)
        if key in seen:
            continue
        seen.add(key)
        out.append({"agent": agent, "path": path})
    return out


def _is_workspace_scoped(path: Path, workspace: Path) -> bool:
    """Did this MCP declaration arrive with the code rather than from the user?

    A config inside the workspace — ``.mcp.json``, ``.vscode/mcp.json``,
    ``.cursor/mcp.json``, ``.gemini/settings.json`` — is part of the checkout.
    It travels in a clone, a branch, a pull request, or a dependency's example
    directory, which means whoever can land a file in the repo can name the
    command an agent will spawn, and that command inherits the developer's
    environment. Project metadata and executable authority are not the same
    thing, and only the file's location tells them apart.

    A workspace that *is* the home directory is not a checkout — everything
    would qualify and the signal would mean nothing — so it never counts.
    """
    try:
        ws = workspace.expanduser().resolve()
        home = Path.home().expanduser().resolve()
        target = path.expanduser().resolve()
    except (OSError, ValueError, RuntimeError):
        return False
    if ws == home or ws in home.parents:
        return False
    return target == ws or ws in target.parents


def _gateway_servers() -> Dict[str, Dict[str, Any]]:
    """MCP servers routed through the Prismor gateway, keyed by lowercase name.

    Returned as full specs rather than bare names because these servers have
    to be *added* to the inventory, not merely matched against it:
    ``mcp_gateway.install_gateway`` moves the ``mcpServers`` block out of
    ``.mcp.json`` and leaves only the gateway entry behind, so after a correct
    install the governed servers appear in no scanned config at all.
    """
    try:
        from prismor.runtime import mcp_gateway
    except Exception:
        return {}
    path = getattr(mcp_gateway, "DEFAULT_GATEWAY_CONFIG", None)
    if path is None or not Path(path).exists():
        return {}
    try:
        specs = mcp_gateway.load_gateway_config(Path(path))
    except Exception:
        return {}
    return {
        s.name.lower(): {
            "name": s.name,
            "command": list(s.command or []),
            "url": s.url or "",
            "transport": s.transport or ("http" if s.url else "stdio"),
            "source": str(path),
        }
        for s in specs
    }


#: Cap on a single MCP config file. Discovery is meant to be cheap enough to
#: run at session start; nothing legitimate declares servers in a bigger file.
_MAX_CONFIG_BYTES = 8 * 1024 * 1024


def _is_gateway_entry(command: Sequence[str], url: str) -> bool:
    """Does this MCP entry point at Prismor's own gateway?"""
    joined = " ".join(str(c) for c in command).lower()
    if "prismor" in joined and "mcp-gateway" in joined:
        return True
    return "prismor" in url.lower() and "gateway" in url.lower()


def discover_mcp(workspace: Path) -> List[McpRecord]:
    """Inventory every MCP server declared anywhere on this machine.

    A server is governed when it is routed through `prismor mcp-gateway`. The
    gateway entry itself is reported separately so it is not counted as its own
    shadow finding, and servers that sit *behind* the gateway are added from
    the gateway config — a correct install removes them from every config this
    would otherwise scan, so without that they would silently vanish from the
    inventory and take the coverage denominator with them.

    A server declared directly *and* registered with the gateway is a bypass,
    not a success: the direct declaration is a live path to the server that
    skips policy. Those are reported as shadow with an explicit reason.
    """
    try:
        from prismor.runtime import scanner
    except Exception:
        return []

    configs = list(scanner.discover_configs(workspace=workspace))
    configs.extend(_extra_mcp_configs(workspace))

    gateway = _gateway_servers()
    records: List[McpRecord] = []
    seen: Set[Tuple[str, str]] = set()
    declared: Set[str] = set()

    for cfg in configs:
        path = Path(cfg["path"])
        agent = str(cfg.get("agent") or "unknown")
        try:
            # scanner.parse_config reads and json.loads the whole file with no
            # cap; ~/.claude.json in particular can grow large.
            if path.stat().st_size > _MAX_CONFIG_BYTES:
                continue
            entries = scanner.parse_config(path, agent=agent)
        except Exception:
            continue
        for entry in entries:
            if entry.get("kind") == "skill":
                continue  # skills are `prismor scan`'s surface, not MCP
            name = str(entry.get("name") or "unnamed")
            key = (name.lower(), str(path))
            if key in seen:
                continue
            seen.add(key)

            server_cfg = entry.get("config")
            if not isinstance(server_cfg, dict):
                server_cfg = {}
            command, url, transport = _spec_fields(name, server_cfg)
            is_gateway = _is_gateway_entry(command, url)
            if not is_gateway:
                declared.add(name.lower())

            # Redact before the record exists, not at render time: these
            # records are also serialized to JSON and folded into reports, so
            # a value that survives construction has already escaped.
            record = McpRecord(
                name=name,
                agent=agent,
                source=str(path),
                transport=transport,
                command=redact_command(command),
                url=redact_url(url),
                remote=bool(url),
                # Never managed: reaching here means the server is reachable
                # directly from an agent's own config, which is a path around
                # the gateway whether or not the gateway also knows the name.
                managed=False,
                is_gateway=is_gateway,
                workspace_scoped=_is_workspace_scoped(path, workspace),
            )
            _score_mcp(record, entry)
            if not is_gateway and name.lower() in gateway:
                record.risk = "high"
                record.findings.insert(
                    0, "declared directly in this config while also registered "
                       "with the gateway — a live path that skips policy")
            records.append(record)

    # Servers behind the gateway that no config declares directly: governed.
    for key, spec in sorted(gateway.items()):
        if key in declared:
            continue
        records.append(
            McpRecord(
                name=spec["name"],
                agent="gateway",
                source=spec["source"],
                transport=spec["transport"],
                command=redact_command(spec["command"]),
                url=redact_url(spec["url"]),
                remote=bool(spec["url"]),
                managed=True,
            )
        )

    records.sort(key=lambda r: (r.managed or r.is_gateway, _RISK_ORDER.get(r.risk, 9),
                                r.name.lower()))
    return records


def _spec_fields(name: str, cfg: Dict[str, Any]) -> Tuple[List[str], str, str]:
    """Normalize a raw MCP server config into (command, url, transport).

    Uses ``mcp_gateway._spec_from_entry`` so discover and the gateway agree on
    what a server declaration means, falling back to the raw fields for
    malformed entries the gateway would reject outright — discovery must still
    report a server it cannot parse, since an unparseable one is not less of a
    risk than a valid one.
    """
    try:
        from prismor.runtime import mcp_gateway
        spec = mcp_gateway._spec_from_entry(name, cfg)
        return list(spec.command or []), spec.url, spec.transport
    except Exception:
        pass
    raw_command = cfg.get("command")
    if isinstance(raw_command, str):
        command = [raw_command] + [str(a) for a in cfg.get("args") or []]
    elif isinstance(raw_command, list):
        command = [str(a) for a in raw_command] + [str(a) for a in cfg.get("args") or []]
    else:
        command = []
    url = ""
    for key in ("url", "endpoint", "serverUrl", "server_url", "uri", "href"):
        value = cfg.get(key)
        if isinstance(value, str) and value:
            url = value
            break
    return command, url, ("http" if url else "stdio")


# ── redaction ────────────────────────────────────────────────────────────────

#: Query/env/flag names whose value is a credential regardless of how it looks.
_SECRETISH_KEY = re.compile(
    r"(?i)(key|token|secret|password|passwd|auth|credential|session|sig|bearer"
    r"|header|cookie|pat|pwd)")

#: Known provider prefixes, which mark a credential no matter how short it is.
#: Mirrors ``sweep._FALLBACK_PATTERNS`` — a legacy 18-char ``sk-`` key is well
#: under any generic length floor but is unambiguously a secret.
_PROVIDER_PREFIX = re.compile(
    r"(?i)^(sk-|sk-ant-|pk-|ghp_|ghs_|gho_|ghu_|ghr_|github_pat_|hf_|r8_|xox[baprs]-"
    r"|AKIA|ASIA|AIza|ya29\.|glpat-|dop_v1_|shpat_|npm_|sq0csp-|rk_live_|sk_live_)"
    r"[A-Za-z0-9_\-]{8,}$")

#: A JWT — three base64url parts. Bearer tokens on MCP endpoints are usually
#: this shape, and the dots stop the run heuristic from ever seeing them whole.
_JWT_SEGMENT = re.compile(r"^[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}$")

#: A standard-alphabet base64 blob (``+``, ``/`` and ``=`` padding).
_B64_SEGMENT = re.compile(r"^[A-Za-z0-9+/]{24,}={0,2}$")

#: Unbroken alphanumeric runs, the discriminator the length-of-whole-string
#: rule got wrong in both directions.
_ALNUM_RUN = re.compile(r"[A-Za-z0-9]+")

#: A shell/env variable name, used to tell ``NAME=value`` from a bare blob
#: that merely happens to contain ``=`` (base64 padding).
_ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_.\-]*$")

#: A run this long containing a digit is a credential; ordinary identifiers
#: break into short runs at ``-``/``_``/``.``.
_RUN_MIN = 20
#: A run with no digit at all needs to be longer before it outweighs the fact
#: that long words are common and long all-letter tokens are not. Catches
#: hex-only keys, whose "letters" are just a-f.
_RUN_MIN_NO_DIGIT = 28

_MASK = "<redacted>"


def _looks_like_token(value: str) -> bool:
    """Is this value credential-shaped?

    Judged on the longest unbroken alphanumeric *run* rather than the length of
    the whole string. Real credentials carry one long run; ordinary identifiers
    of the same total length break into short pieces at separators. That single
    change is what lets ``gpt-4o-mini-2024-07-18`` (longest run 4) and
    ``my-project-2024-rewrite`` (7) through while still catching a bare
    32-character hex key, which an earlier "must contain a letter and a digit"
    rule missed entirely because hex letters stop at ``f``.
    """
    if not value:
        return False
    if _PROVIDER_PREFIX.match(value) or _JWT_SEGMENT.match(value):
        return True
    if len(value) >= 24 and _B64_SEGMENT.match(value):
        return True
    for run in _ALNUM_RUN.findall(value):
        if len(run) < _RUN_MIN:
            continue
        if any(ch.isdigit() for ch in run) or len(run) >= _RUN_MIN_NO_DIGIT:
            return True
    return False


def _mask_segment(value: str) -> str:
    """Mask a value that looks like a credential, else return it unchanged."""
    return _MASK if _looks_like_token(value) else value


def _mask_assignment(value: str) -> str:
    """Mask the right-hand side of a ``NAME=value`` pair.

    ``docker run -e GITHUB_TOKEN=<pat>`` is the single most common way an MCP
    server receives a credential, and the whole ``NAME=value`` string matches
    no token shape because of the ``=``.
    """
    name, sep, rhs = value.partition("=")
    # Only treat this as an assignment when the left side is a real variable
    # name and something follows it. Base64 padding ("aGVs…==") otherwise
    # partitions into a name and an empty value and gets waved through as a
    # harmless assignment — so anything else falls to the whole-value check,
    # which keeps the name visible when there is one and masks the blob when
    # there is not.
    if sep and rhs.strip("=") and _ENV_NAME.match(name):
        if _SECRETISH_KEY.search(name) or _looks_like_token(rhs):
            return f"{name}={_MASK}"
        return value
    return _mask_segment(value)


def _mask_words(value: str) -> str:
    """Mask credential-shaped words inside a value that contains whitespace.

    An argv element like ``Authorization: Bearer <token>`` is one argument, and
    every pattern here is anchored, so without splitting it can never match.
    """
    if not value.strip():
        return value
    return " ".join(_mask_assignment(word) if "=" in word else _mask_segment(word)
                    for word in value.split(" "))


def redact_url(url: str) -> str:
    """Strip credentials from a URL without losing which host it points at.

    MCP servers routinely carry the caller's key in a path segment or query
    parameter, so the raw URL is a live secret. The host and shape are what
    make the finding actionable; the credential is not.
    """
    if not url:
        return url
    try:
        from urllib.parse import urlsplit, urlunsplit
        parts = urlsplit(url)
    except Exception:
        # Fail closed. A URL urlsplit rejects (a malformed IPv6 literal, say)
        # is still perfectly capable of carrying userinfo, and returning it
        # verbatim would hand back exactly the credential this exists to hide.
        return _mask_words(url.rsplit("@", 1)[-1]) if "@" in url else _mask_words(url)
    if not parts.scheme:
        return _mask_words(url)

    netloc = parts.netloc
    if "@" in netloc:  # user:pass@host
        netloc = _MASK + "@" + netloc.rsplit("@", 1)[1]

    # Split on ';' as well as '/': a path parameter (``/mcp;api_key=…``) is a
    # separate carrier that a '/'-only split leaves whole and unmatchable.
    path = "/".join(
        ";".join(_mask_assignment(param) for param in seg.split(";"))
        for seg in parts.path.split("/")
    )

    query = parts.query
    if query:
        pairs = []
        for pair in query.split("&"):
            key, sep, value = pair.partition("=")
            if sep and (_SECRETISH_KEY.search(key) or _looks_like_token(value)):
                value = _MASK
            pairs.append(f"{key}{sep}{value}")
        query = "&".join(pairs)

    fragment = _mask_segment(parts.fragment or "")
    return urlunsplit((parts.scheme, netloc, path, query, fragment))


def redact_command(command: Sequence[str]) -> List[str]:
    """Strip credential-shaped arguments from an MCP server's argv."""
    out: List[str] = []
    mask_next = False
    for raw in command:
        arg = str(raw)
        if mask_next:
            mask_next = False
            # `--api-key --verbose` — the next token is another flag, so the
            # value was omitted and masking it would hide a real argument.
            if not arg.startswith("-"):
                out.append(_MASK)
                continue
        # --api-key <value> / --token=<value>
        if arg.startswith("-"):
            flag, sep, _ = arg.partition("=")
            if _SECRETISH_KEY.search(flag):
                if sep:
                    out.append(f"{flag}={_MASK}")
                    continue
                mask_next = True
            out.append(arg)
            continue
        if "://" in arg:
            out.append(redact_url(arg))
            continue
        # Whitespace and `=` each defeat the anchored patterns, and both are
        # ordinary in real argv: `-e NAME=value`, `--header "Authorization: …"`.
        if " " in arg:
            out.append(_mask_words(arg))
        elif "=" in arg:
            out.append(_mask_assignment(arg))
        else:
            out.append(_mask_segment(arg))
    return out


_RISK_ORDER = {"high": 0, "medium": 1, "low": 2, "none": 3}
_SEVERITY_TO_RISK = {
    "critical": "high",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "info": "low",
}


def _score_mcp(record: McpRecord, entry: Dict[str, Any]) -> None:
    """Attach a risk band and reasons, via scanner's static MCP audit."""
    reasons: List[str] = []
    risk = "none"
    try:
        from prismor.runtime import scanner
        for finding in scanner.audit_mcp_schema(entry):
            title = str(finding.get("title") or finding.get("id") or "").strip()
            if title:
                # Audit titles quote config content (header names, URLs), so
                # they get the same treatment as any other echoed config.
                reasons.append(" ".join(
                    redact_url(w) if "://" in w else _mask_segment(w)
                    for w in title.split(" ")))
            band = _SEVERITY_TO_RISK.get(str(finding.get("severity", "")).lower(), "low")
            if _RISK_ORDER[band] < _RISK_ORDER[risk]:
                risk = band
    except Exception:
        pass

    # An ungoverned remote server is the shape that actually moves data off the
    # machine, so it floors at medium even when the schema audit is clean.
    if record.shadow and record.remote and _RISK_ORDER[risk] > _RISK_ORDER["medium"]:
        risk = "medium"
        reasons.append("remote MCP server not routed through the gateway")

    # Declared by the checkout, not by the user. The gateway's own entry is
    # exempt: pointing at Prismor is the governed outcome, not a risk.
    if record.workspace_scoped and not record.is_gateway:
        if record.command:
            # The dangerous half: a repo can name the executable, and the
            # spawned process inherits the developer's shell environment —
            # cloud credentials, tokens, agent config and all.
            floor, why = "high", (
                "declared by a file in this workspace — a repo-supplied command "
                "runs with your environment; approve it before use")
        else:
            floor, why = "medium", (
                "declared by a file in this workspace — the endpoint travels "
                "with the checkout; approve it before use")
        if _RISK_ORDER[risk] > _RISK_ORDER[floor]:
            risk = floor
        # Stated whether or not it moved the band: it is the reason the other
        # findings matter, since the whole file came from the checkout.
        reasons.insert(0, why)

    record.risk = risk
    record.findings = reasons[:5]


# ── credential inventory ─────────────────────────────────────────────────────

#: Environment variable names that hold AI-provider credentials. Matched on the
#: name so a key can be reported without its value ever being pattern-matched.
_ENV_KEY_PATTERNS: List[Tuple[str, re.Pattern[str]]] = [
    ("anthropic", re.compile(r"^ANTHROPIC_(API_KEY|AUTH_TOKEN)$")),
    ("openai", re.compile(r"^OPENAI_API_KEY$")),
    ("azure-openai", re.compile(r"^AZURE_OPENAI_(API_)?KEY$")),
    ("google", re.compile(r"^(GOOGLE_API_KEY|GEMINI_API_KEY)$")),
    ("mistral", re.compile(r"^MISTRAL_API_KEY$")),
    ("cohere", re.compile(r"^COHERE_API_KEY$")),
    ("groq", re.compile(r"^GROQ_API_KEY$")),
    ("perplexity", re.compile(r"^PERPLEXITY_API_KEY$")),
    ("together", re.compile(r"^TOGETHER_API_KEY$")),
    ("fireworks", re.compile(r"^FIREWORKS_API_KEY$")),
    ("deepseek", re.compile(r"^DEEPSEEK_API_KEY$")),
    ("xai", re.compile(r"^XAI_API_KEY$")),
    ("openrouter", re.compile(r"^OPENROUTER_API_KEY$")),
    ("huggingface", re.compile(r"^(HF_TOKEN|HUGGINGFACE_API_KEY)$")),
    ("replicate", re.compile(r"^REPLICATE_API_TOKEN$")),
]


def _cloak_names() -> Set[str]:
    """Placeholder names registered with Cloak (names only — never values)."""
    try:
        from prismor.runtime.cloaking import list_secrets
        return {str(s.get("name", "")).lower() for s in list_secrets()}
    except Exception:
        return set()


def _managed_by_cloak(env_name: str, cloak: Set[str]) -> Tuple[bool, str]:
    """Is this env var's credential registered with Cloak?

    Cloak placeholders are free-form names, so match the env var name directly
    and then the conventional lowercase form. A miss is reported as shadow,
    which is the safe direction: a registered key mislabelled as shadow costs
    a glance, an unregistered one silently omitted costs a leak.
    """
    if env_name.lower() in cloak:
        return True, env_name
    return False, ""


def discover_credentials(workspace: Path, *, scan_files: bool = True) -> List[CredentialRecord]:
    """Inventory AI-provider credentials, and diff against Cloak.

    Values are never read for the environment sweep — only variable names are
    inspected — and file findings record the path and provider only.
    """
    cloak = _cloak_names()
    records: List[CredentialRecord] = []

    for name in sorted(os.environ):
        for provider, pattern in _ENV_KEY_PATTERNS:
            if not pattern.match(name):
                continue
            if not (os.environ.get(name) or "").strip():
                continue
            managed, cloak_name = _managed_by_cloak(name, cloak)
            records.append(
                CredentialRecord(
                    provider=provider,
                    location_kind="env",
                    location=name,
                    managed=managed,
                    cloak_name=cloak_name,
                )
            )
            break

    if scan_files:
        records.extend(_scan_config_credentials(workspace, cloak))

    records.sort(key=lambda r: (r.managed, r.provider, r.location))
    return records


#: Config files worth checking for embedded provider keys. Deliberately a
#: fixed list rather than a tree walk — discovery must stay fast enough to run
#: on every session start, and agent credentials live in known files.
_CRED_FILES = (
    ".env",
    ".env.local",
    "mcp.json",
    ".mcp.json",
    "config.json",
    "settings.json",
    "credentials.json",
    "auth.json",
)


def _scan_config_credentials(workspace: Path, cloak: Set[str]) -> List[CredentialRecord]:
    """Look for provider keys embedded in agent config files.

    Reuses ``sweep``'s provider patterns. Matched values are discarded
    immediately — only the provider label and the path survive into the record.
    A dotenv whose every key Cloak already holds counts as governed; see
    ``_dotenv_is_vaulted``.
    """
    try:
        from prismor.runtime.sweep import _FALLBACK_PATTERNS, TOOL_DIRS
    except Exception:
        return []

    targets: List[Path] = []
    for name in _CRED_FILES:
        candidate = workspace / name
        if candidate.exists() and candidate.is_file():
            targets.append(candidate)
    for tool_dir in TOOL_DIRS.values():
        if not tool_dir.is_dir():
            continue
        for name in _CRED_FILES:
            candidate = tool_dir / name
            if candidate.exists() and candidate.is_file():
                targets.append(candidate)

    records: List[CredentialRecord] = []
    seen: Set[Tuple[str, str]] = set()
    for path in targets:
        try:
            if path.stat().st_size > 512 * 1024:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for provider, pattern in _FALLBACK_PATTERNS:
            if not pattern.search(text):
                continue
            key = (provider, str(path))
            if key in seen:
                continue
            seen.add(key)
            records.append(
                CredentialRecord(
                    provider=provider,
                    location_kind="file",
                    location=str(path),
                    managed=_dotenv_is_vaulted(path, cloak),
                )
            )
    return records


def _dotenv_is_vaulted(path: Path, cloak: Set[str]) -> bool:
    """Has Cloak taken custody of every key in this dotenv file?

    The raw value stays on disk after ``cloak add --env-file`` — importing
    vaults it and stands the env-guard down, it does not rewrite the file. So
    "a provider pattern still matches here" is not evidence of exposure once
    Cloak knows the keys, and treating it as such left credentials reading as
    shadow forever: importing them could never improve coverage, which made
    the remediation loop impossible to close.

    Every name must be registered, not merely one. A file where three keys are
    vaulted and a fourth is not is still an exposed key.
    """
    try:
        from prismor.runtime.cloaking import parse_env_file
        names = list(parse_env_file(path).keys())
    except Exception:
        # Not dotenv-shaped (a JSON/TOML agent config), or unreadable: Cloak
        # has no way to have taken custody, so this is exposure.
        return False
    if not names:
        return False
    return all(n.lower() in cloak for n in names)


# ── browser WebMCP inventory ─────────────────────────────────────────────────
#
# WebMCP (Chrome 150+, behind a flag) lets a page call
# ``document.modelContext.registerTool()``; an agent in the same tab finds
# those tools with ``getTools()`` and runs them with ``executeTool()``. Which
# tools a page offers is decided at runtime and is not observable from disk —
# a host-local sweep cannot enumerate them and does not try.
#
# What is on disk is the precondition: the experiment being enabled, and an
# extension present that speaks the API. Both are read here, and neither
# requires the browser to be running.

#: chrome://flags entries that turn the surface on. Matched as substrings
#: because the flag gets renamed between milestones while the capability it
#: gates stays the same; a stale exact string would silently stop matching.
_WEBMCP_FLAG_HINTS = ("webmcp", "web-mcp", "model-context", "modelcontext")

#: Extensions known to drive this surface, by Chrome Web Store id. This map
#: only supplies a friendly name — an unknown extension is caught by the
#: source scan below, which is the signal that actually matters.
_KNOWN_WEBMCP_EXTENSIONS = {
    "gbpdfapgefenggkahomfgkhfehlcenpd": "Model Context Tool Inspector",
}

#: The API an extension must name to use this surface at all.
_WEBMCP_SOURCE_MARKER = b"modelContext"

#: Scan ceilings. An extension bundle can be tens of megabytes of minified
#: vendor code, and `prismor discover` runs on every scheduled refresh.
_MAX_EXT_SCAN_FILES = 40
_MAX_EXT_SCAN_BYTES = 8 * 1024 * 1024


def _browser_user_data_dirs() -> List[Tuple[str, Path]]:
    """(browser label, user-data directory) for each Chromium-family browser.

    The user-data directory is the one holding ``Local State`` and the profile
    subdirectories. Only its location differs between platforms and vendors;
    everything below it is Chromium's own layout.
    """
    home = Path.home()
    system = platform.system()
    roots: List[Tuple[str, Path]] = []

    if system == "Darwin":
        base = home / "Library" / "Application Support"
        roots = [
            ("chrome", base / "Google" / "Chrome"),
            ("chrome-beta", base / "Google" / "Chrome Beta"),
            ("chrome-dev", base / "Google" / "Chrome Dev"),
            ("chrome-canary", base / "Google" / "Chrome Canary"),
            ("edge", base / "Microsoft Edge"),
            ("brave", base / "BraveSoftware" / "Brave-Browser"),
            ("chromium", base / "Chromium"),
            ("arc", base / "Arc" / "User Data"),
        ]
    elif system == "Windows":
        local = os.environ.get("LOCALAPPDATA")
        if local:
            base = Path(local)
            roots = [
                ("chrome", base / "Google" / "Chrome" / "User Data"),
                ("chrome-beta", base / "Google" / "Chrome Beta" / "User Data"),
                ("edge", base / "Microsoft" / "Edge" / "User Data"),
                ("brave", base / "BraveSoftware" / "Brave-Browser" / "User Data"),
                ("chromium", base / "Chromium" / "User Data"),
            ]
    else:
        base = home / ".config"
        roots = [
            ("chrome", base / "google-chrome"),
            ("chrome-beta", base / "google-chrome-beta"),
            ("chrome-dev", base / "google-chrome-unstable"),
            ("edge", base / "microsoft-edge"),
            ("brave", base / "BraveSoftware" / "Brave-Browser"),
            ("chromium", base / "chromium"),
        ]

    out: List[Tuple[str, Path]] = []
    for label, path in roots:
        try:
            if path.is_dir():
                out.append((label, path))
        except OSError:
            continue
    return out


def _profile_dirs(user_data: Path) -> List[Path]:
    """Profile directories inside a user-data dir, in stable order.

    ``Default`` plus ``Profile N``. Chromium's ``System Profile`` and
    ``Guest Profile`` are deliberately skipped: neither runs user extensions.
    """
    out: List[Path] = []
    try:
        entries = sorted(user_data.iterdir(), key=lambda p: p.name)
    except OSError:
        return out
    for entry in entries:
        try:
            if not entry.is_dir():
                continue
        except OSError:
            continue
        if entry.name == "Default" or entry.name.startswith("Profile "):
            out.append(entry)
    return out


def _enabled_webmcp_flags(user_data: Path) -> List[str]:
    """WebMCP-ish entries in this browser's enabled chrome://flags list.

    Entries are stored as ``flag-name@1``; the suffix selects which option of a
    multi-choice flag is active and is dropped here.
    """
    state = user_data / "Local State"
    try:
        with open(state, "r", encoding="utf-8", errors="replace") as handle:
            data = json.load(handle)
    except (OSError, ValueError):
        return []
    if not isinstance(data, dict):
        return []
    browser = data.get("browser")
    raw = browser.get("enabled_labs_experiments") if isinstance(browser, dict) else None
    if not isinstance(raw, list):
        return []

    found: List[str] = []
    for entry in raw:
        if not isinstance(entry, str):
            continue
        flag = entry.split("@", 1)[0].strip()
        lowered = flag.lower()
        if any(hint in lowered for hint in _WEBMCP_FLAG_HINTS) and flag not in found:
            found.append(flag)
    return found


def _extension_name(bundle: Path, manifest: Dict[str, Any], ext_id: str) -> str:
    """Display name for an extension, resolving a ``__MSG_key__`` placeholder.

    A localised manifest carries the message key rather than the name, so the
    default locale's catalogue is consulted. Anything unresolvable falls back
    to the extension id, which is always meaningful enough to look up.
    """
    name = manifest.get("name")
    if not isinstance(name, str) or not name.strip():
        return ext_id
    name = name.strip()
    if not (name.startswith("__MSG_") and name.endswith("__")):
        return name

    key = name[len("__MSG_"):-len("__")]
    locale = manifest.get("default_locale")
    candidates = []
    if isinstance(locale, str) and locale:
        candidates.append(locale)
    candidates.extend(["en", "en_US"])
    for candidate in candidates:
        try:
            with open(bundle / "_locales" / candidate / "messages.json",
                      "r", encoding="utf-8", errors="replace") as handle:
                messages = json.load(handle)
            entry = messages.get(key)
            if isinstance(entry, dict) and isinstance(entry.get("message"), str):
                return entry["message"].strip() or ext_id
        except (OSError, ValueError):
            continue
    return ext_id


def _reaches_page_context(manifest: Dict[str, Any]) -> bool:
    """Could this extension run script in a page at all?

    WebMCP is exposed to page context, so an extension that never gets there
    cannot be using it. Themes, dictionaries and pure devtools panels are the
    bulk of an average profile, and skipping them keeps the source scan off
    almost everything.
    """
    if manifest.get("content_scripts"):
        return True
    perms: List[Any] = []
    for key in ("permissions", "optional_permissions", "host_permissions"):
        value = manifest.get(key)
        if isinstance(value, list):
            perms.extend(value)
    lowered = {str(p).lower() for p in perms}
    return bool(lowered & {"scripting", "activetab", "tabs", "debugger"})


def _bundle_names_webmcp(bundle: Path) -> bool:
    """Does this extension's own code reference the WebMCP API?

    Bounded by file count and total bytes: a bundle is untrusted input whose
    size is chosen by whoever published it, and this runs on a schedule.
    """
    scanned_files = 0
    scanned_bytes = 0
    try:
        walker = os.walk(bundle)
    except OSError:
        return False
    for root, dirs, files in walker:
        # Sorted, because the ceilings below mean the walk can stop early and
        # os.walk hands back whatever order the filesystem keeps. Unsorted,
        # which files got scanned would vary by platform and the same bundle
        # could report a finding on one machine and not on another.
        dirs[:] = sorted(d for d in dirs if d != "_locales")
        for filename in sorted(files):
            if not filename.endswith((".js", ".mjs", ".ts", ".html")):
                continue
            if scanned_files >= _MAX_EXT_SCAN_FILES or scanned_bytes >= _MAX_EXT_SCAN_BYTES:
                return False
            path = Path(root) / filename
            try:
                blob = path.read_bytes()
            except OSError:
                continue
            scanned_files += 1
            scanned_bytes += len(blob)
            if _WEBMCP_SOURCE_MARKER in blob:
                return True
    return False


def _latest_version_dir(ext_dir: Path) -> Optional[Path]:
    """The newest installed version of an extension.

    Chromium keeps the previous version alongside the current one after an
    update, and scanning both would report the same extension twice.
    """
    try:
        versions = [p for p in ext_dir.iterdir() if p.is_dir()]
    except OSError:
        return None
    if not versions:
        return None
    return sorted(versions, key=lambda p: p.name)[-1]


def discover_webmcp(workspace: Path) -> List[BrowserSurfaceRecord]:
    """Browser-resident WebMCP capability on this machine.

    Reports two things, per Chromium-family browser: profiles with the
    experiment enabled, and installed extensions that speak the API. Both are
    read-only and neither needs the browser to be running.

    ``workspace`` is unused — the browser surface is a property of the machine,
    not of a checkout — and is accepted so this matches every other
    ``discover_*`` entry point.
    """
    records: List[BrowserSurfaceRecord] = []
    seen_extensions: Set[Tuple[str, str]] = set()

    for browser, user_data in _browser_user_data_dirs():
        for flag in _enabled_webmcp_flags(user_data):
            records.append(BrowserSurfaceRecord(
                browser=browser,
                kind="flag",
                name=flag,
                location=str(user_data / "Local State"),
                risk="medium",
                # Deliberately says "enabled", not what the flag does. Chrome
                # 152 ships two (enable-webmcp-testing, devtools-webmcp-support)
                # and only the first exposes the API to pages, so a single
                # claim about page tool registration is wrong for the other.
                findings=["WebMCP experiment enabled in this browser."],
            ))

        for profile in _profile_dirs(user_data):
            ext_root = profile / "Extensions"
            try:
                ext_dirs = sorted(ext_root.iterdir(), key=lambda p: p.name)
            except OSError:
                continue
            for ext_dir in ext_dirs:
                ext_id = ext_dir.name
                if (browser, ext_id) in seen_extensions:
                    continue
                bundle = _latest_version_dir(ext_dir)
                if bundle is None:
                    continue

                known = _KNOWN_WEBMCP_EXTENSIONS.get(ext_id)
                manifest: Dict[str, Any] = {}
                try:
                    with open(bundle / "manifest.json", "r",
                              encoding="utf-8", errors="replace") as handle:
                        loaded = json.load(handle)
                    if isinstance(loaded, dict):
                        manifest = loaded
                except (OSError, ValueError):
                    manifest = {}

                if known:
                    finding = "Known WebMCP tool inspector."
                elif _reaches_page_context(manifest) and _bundle_names_webmcp(bundle):
                    finding = "Extension code references the WebMCP API."
                else:
                    continue

                seen_extensions.add((browser, ext_id))
                records.append(BrowserSurfaceRecord(
                    browser=browser,
                    kind="extension",
                    name=known or _extension_name(bundle, manifest, ext_id),
                    location=str(bundle),
                    profile=profile.name,
                    extension_id=ext_id,
                    risk="medium",
                    findings=[finding],
                ))

    records.sort(key=lambda r: (r.browser, r.kind, r.name.lower()))
    return records


# ── report ───────────────────────────────────────────────────────────────────


def governed_context() -> Dict[str, Any]:
    """What the control plane already knows about this machine."""
    context: Dict[str, Any] = {
        "enrolled": False,
        "device_id": "",
        "org": "",
        "reported_agents": [],
    }
    try:
        from prismor.runtime.enterprise import identity
        context["enrolled"] = identity.is_enrolled()
        loaded = identity.load_identity() or {}
        context["device_id"] = str(loaded.get("device_id") or "")
        context["org"] = str(loaded.get("org_name") or loaded.get("org_id") or "")
    except Exception:
        pass
    try:
        from prismor.runtime import store
        context["reported_agents"] = [
            str(a.get("name") or "") for a in store.get_agents_overview()
        ]
    except Exception:
        pass
    return context


def build_report(workspace: Path, *, scan_files: bool = True) -> Dict[str, Any]:
    """Run every inventory and return the full shadow-AI report."""
    agents = discover_agents(workspace)
    mcp = discover_mcp(workspace)
    credentials = discover_credentials(workspace, scan_files=scan_files)
    webmcp = discover_webmcp(workspace)
    context = governed_context()

    shadow_agents = [a for a in agents if a.shadow and a.coverable]
    shadow_mcp = [m for m in mcp if m.shadow]
    shadow_creds = [c for c in credentials if c.shadow]

    coverable = [a for a in agents if a.coverable]
    governable_mcp = [m for m in mcp if not m.is_gateway]

    summary = {
        # ``agents_total`` is the coverable count, not the row count, so a
        # consumer recomputing coverage from the summary gets the number the
        # report printed. ``agents_present`` carries the row count, which
        # includes agents Prismor has no hook for.
        "agents_total": len(coverable),
        "agents_present": len(agents),
        "agents_shadow": len(shadow_agents),
        "mcp_total": len(governable_mcp),
        "mcp_shadow": len(shadow_mcp),
        "credentials_total": len(credentials),
        "credentials_shadow": len(shadow_creds),
        "high_risk_mcp": len([m for m in shadow_mcp if m.risk == "high"]),
        # Advisory only, and deliberately absent from `coverage` below. Prismor
        # has no interception point inside a browser tab, so an enabled WebMCP
        # profile is not governable surface that was skipped — it is surface
        # nothing can cover yet. Folding it into the ratio would drive the
        # number down with findings no `--fix` can clear, which is the same
        # mistake `AgentRecord.coverable` exists to avoid for agents Prismor
        # has no hook for.
        "webmcp_total": len(webmcp),
        "coverage": _coverage(len(coverable), len(shadow_agents),
                              len(governable_mcp), len(shadow_mcp),
                              len(credentials), len(shadow_creds)),
    }

    return {
        "workspace": str(workspace),
        "context": context,
        "summary": summary,
        "agents": [asdict(a) for a in agents],
        "mcp": [asdict(m) for m in mcp],
        "credentials": [asdict(c) for c in credentials],
        "webmcp": [asdict(w) for w in webmcp],
    }


def _fix_index(report: Dict[str, Any]) -> Dict[Tuple[str, str], Dict[str, Any]]:
    """Map (kind, name) -> how this finding could be remediated.

    Computed with the same planner ``--fix`` runs, so the console can never
    offer a remediation the CLI would refuse. Best-effort: if planning fails,
    findings simply report no fix rather than the whole upload failing.
    """
    out: Dict[Tuple[str, str], Dict[str, Any]] = {}
    try:
        from prismor.runtime import remediate as _remediate
        planned = _remediate.plan(report)
    except Exception:
        return out
    for action in planned.actions:
        out[(action.kind, action.target)] = {
            "fixable": action.status == "planned",
            "fix_command": action.command,
            "fix_blocked_reason": "" if action.status == "planned" else action.detail,
        }
    return out


def report_payload(report: Dict[str, Any]) -> Dict[str, Any]:
    """Flatten a report into the wire shape the control plane accepts.

    One flat ``findings`` list rather than three keyed sections: the console
    renders them in one table, and a shape change on either side of a version
    skew should cost a missing column, not a rejected report.

    Each finding also carries whether it is *fixable* and the command that
    fixes it. An admin looking at the fleet view needs to know which of a
    hundred findings a developer can clear in one command and which need a
    conversation — a list that does not distinguish them is a list nobody
    triages.
    """
    fixes = _fix_index(report)

    def _fix_for(kind: str, name: str) -> Dict[str, Any]:
        return fixes.get((kind, name),
                         {"fixable": False, "fix_command": "", "fix_blocked_reason": ""})

    findings: List[Dict[str, Any]] = []
    for agent in report.get("agents") or []:
        name = agent.get("name") or agent.get("id") or ""
        findings.append({
            "kind": "agent",
            "name": name,
            "detail": (agent.get("config_paths") or [""])[0],
            "managed": bool(agent.get("managed")),
            "coverable": bool(agent.get("coverable", True)),
            "risk": "none",
            "reasons": [],
            **_fix_for("agent", name),
        })
    for server in report.get("mcp") or []:
        if server.get("is_gateway"):
            continue  # the gateway is not an inventory item
        name = server.get("name") or ""
        findings.append({
            "kind": "mcp",
            "name": name,
            # Already redacted at record construction; see redact_url.
            "detail": server.get("url") or " ".join(server.get("command") or []),
            "managed": bool(server.get("managed")),
            "coverable": True,
            "risk": server.get("risk") or "none",
            "reasons": server.get("findings") or [],
            **_fix_for("mcp", name),
        })
    for surface in report.get("webmcp") or []:
        name = surface.get("name") or surface.get("extension_id") or ""
        findings.append({
            "kind": "browser",
            "name": name,
            "detail": surface.get("location") or "",
            # Nothing governs this surface and nothing can yet, so it reports
            # as uncoverable — the flag the console already reads to mean "not
            # a gap". A console that does not know this kind drops the row
            # (normalizeFinding enum-checks it) rather than mis-scoring it.
            "managed": False,
            "coverable": False,
            "risk": surface.get("risk") or "none",
            "reasons": surface.get("findings") or [],
            **_fix_for("browser", name),
        })
    for cred in report.get("credentials") or []:
        provider = cred.get("provider") or ""
        findings.append({
            "kind": "credential",
            "name": provider,
            "detail": cred.get("location") or "",
            "managed": bool(cred.get("managed")),
            "coverable": True,
            "risk": "none",
            "reasons": [],
            **_fix_for("credential", provider),
        })

    from prismor.runtime import __version__ as _version
    summary = dict(report.get("summary") or {})
    # How much of the shadow could be cleared by one `prismor discover --fix`.
    # The console leads with this: "31 ungoverned" is a number to despair at,
    # "31 ungoverned, 24 fixable in one command" is a number to act on.
    summary["fixable"] = sum(
        1 for f in findings if not f.get("managed") and f.get("fixable"))
    return {
        "findings": findings,
        "summary": summary,
        "cli_version": _version,
    }


def send_report(report: Dict[str, Any], *, timeout: int = 5) -> bool:
    """POST an inventory to the control plane. Returns True on success.

    Silent no-op when the device is not enrolled — discovery is useful on its
    own, and a local-only machine has nowhere to report to. Never raises: a
    control plane that is down must not fail the developer's command.
    """
    try:
        from prismor.runtime.enterprise import identity as _identity
        ident = _identity.load_identity()
        if not ident or _identity.revoked_info() is not None:
            return False
        base = str(ident.get("api_base") or _identity.api_base()).rstrip("/")
        import urllib.request
        request = urllib.request.Request(
            f"{base}/api/discovery/report",
            data=json.dumps(report_payload(report)).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {ident.get('device_key')}",
            },
            method="POST",
        )
        # Every other control-plane call sets this. Without it the request goes
        # out as bare `Python-urllib/3.x`, which the WAF in front of the
        # production console rejects with a 403 (Cloudflare 1010) — so
        # automatic reporting silently never worked against prod, while
        # working perfectly against a local server. See prismor/runtime/http_ua.
        from prismor.runtime.http_ua import user_agent as _ua
        request.add_header("User-Agent", _ua())
        with urllib.request.urlopen(request, timeout=timeout) as resp:
            return 200 <= resp.status < 300
    except Exception:
        return False


# ── automatic reporting ──────────────────────────────────────────────────────

#: How often a device re-reports its inventory unprompted.
#: Shadow AI changes at the speed of someone installing an IDE extension, so
#: daily is frequent enough to be true and rare enough to be free.
REPORT_INTERVAL = 24 * 60 * 60.0

#: Bypass for testing and for orgs that want a tighter loop.
_INTERVAL_ENV = "PRISMOR_DISCOVER_INTERVAL"


def _report_marker() -> Path:
    from prismor.runtime.enterprise import identity as _identity
    return _identity.prismor_home() / "discover-report.json"


def _report_interval() -> float:
    raw = os.environ.get(_INTERVAL_ENV, "")
    try:
        return max(0.0, float(raw)) if raw else REPORT_INTERVAL
    except ValueError:
        return REPORT_INTERVAL


def report_due(now: Optional[float] = None) -> bool:
    """Has enough time passed since the last automatic report?"""
    import time
    current = time.time() if now is None else now
    try:
        data = json.loads(_report_marker().read_text(encoding="utf-8"))
        last = float(data.get("last_report") or 0)
    except (OSError, ValueError, TypeError):
        return True
    # A clock that jumped backwards must not disable reporting until it catches
    # up, so a future timestamp counts as due.
    if last > current:
        return True
    return (current - last) >= _report_interval()


def _stamp_report(now: Optional[float] = None) -> None:
    import time
    marker = _report_marker()
    try:
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.write_text(
            json.dumps({"last_report": time.time() if now is None else now}),
            encoding="utf-8",
        )
    except OSError:
        pass


def maybe_report_background(workspace: Path) -> bool:
    """Spawn a detached inventory report if one is due. Returns True if spawned.

    Runs out-of-process on purpose. A full scan is a few hundred milliseconds
    of filesystem work — nothing on a command line, but this is called from the
    hook path, where it would be a visible stall on somebody's tool call. The
    hook pays a fork and returns; the child does the scanning and the upload.

    The marker is written *before* the spawn, not after: several hooks can fire
    at once, and a marker written by the child would let all of them decide
    they were due and start a scan each.
    """
    try:
        from prismor.runtime.enterprise import identity as _identity
        if not _identity.is_enrolled():
            return False
        if not report_due():
            return False
        _stamp_report()

        import subprocess
        subprocess.Popen(
            [sys.executable, "-m", "prismor.runtime.cli", "discover",
             "--report", "--quiet", "--workspace", str(workspace)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL,
            start_new_session=True,
        )
        return True
    except Exception:
        return False


def _coverage(agents_total: int, agents_shadow: int,
              mcp_total: int, mcp_shadow: int,
              creds_total: int, creds_shadow: int) -> Optional[int]:
    """Percentage of governable surface that Prismor actually governs.

    Returns None when nothing governable was found, so a clean machine reads
    as "nothing to govern" rather than a misleading 100%.
    """
    total = agents_total + mcp_total + creds_total
    if total == 0:
        return None
    shadow = agents_shadow + mcp_shadow + creds_shadow
    return int(round(100.0 * (total - shadow) / total))
