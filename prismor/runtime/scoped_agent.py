"""Scoped Agent — task-specific rule synthesis for Prismor.

Generates a minimal, session-scoped rule set at the start of each session
based on the user's task description. Rules are enforced alongside
policy.yaml for the duration of that session only.

The active rule set becomes:  policy.yaml (base) + scoped_agent (session-only)
"""
from __future__ import annotations

import json
import sys
from fnmatch import fnmatch
from pathlib import Path
from typing import Any, Dict, List, Optional


# ── Tool name mapping ──────────────────────────────────────────────────────
# Maps normalized event types to the tool names used in scoped rules.

_EVENT_TYPE_TO_TOOL = {
    "shell": "Bash",
    "file_read": "Read",
    "file_write": "Write",
    "network": "WebFetch",
}

_KNOWN_TOOLS = {"Read", "Write", "Edit", "MultiEdit", "Bash", "WebFetch", "WebSearch",
                "Glob", "Grep"}

# The built-in tool tags every scope is synthesised over. MCP tool families
# (``mcp__<server>__*``) are appended per machine by
# ``available_tools_for_scope``.
#
# Glob and Grep are here even though Claude Code's hook matcher never sends
# them: when the built-ins are mirrored through the MCP gateway they DO arrive
# for screening, and a tag absent from this list is denied by omission by every
# synthesised scope.
BUILTIN_SCOPE_TOOLS = ["Bash", "Read", "Edit", "MultiEdit", "Write", "Glob", "Grep",
                       "WebFetch", "WebSearch"]

#: Built-ins that ``runtime.mirror`` re-serves over MCP. A mirrored call reaches
#: the host's hook layer tagged ``mcp__<server>__Bash``, and a scope that has
#: never heard of that server denies it — while the gateway, which sees the same
#: call as a plain ``Bash``, allows it. Same call, two verdicts.
_MIRRORED_BUILTINS = frozenset({"Bash", "Read", "Write", "Edit", "MultiEdit",
                                "Glob", "Grep", "WebFetch", "WebSearch"})


def native_alias(tool: str) -> Optional[str]:
    """The built-in tag behind a mirrored MCP tool, if it is one.

    ``mcp__prismor__Bash`` -> ``Bash``. Lets a scope judge a mirrored tool as
    the tool it actually is, so switching a built-in onto the MCP transport
    does not change whether it is in scope.
    """
    if not is_mcp_tool(tool):
        return None
    bare = tool.rsplit("__", 1)[-1]
    return bare if bare in _MIRRORED_BUILTINS else None

# ── MCP tool families ──────────────────────────────────────────────────────
# MCP tools arrive under the tag ``mcp__<server>__<tool>`` (Claude Code
# rewrites ``:`` in a plugin server name — ``plugin:posthog:posthog`` — to
# ``_``, keeping hyphens). Individual tool names are only known once the agent
# calls one, so a scope names a *family* per server: ``mcp__<server>__*``.

_MCP_PREFIX = "mcp__"
_MAX_MCP_CONFIG_BYTES = 8 * 1024 * 1024


def is_mcp_tool(tool: str) -> bool:
    return isinstance(tool, str) and tool.startswith(_MCP_PREFIX)


def is_mcp_family(entry: str) -> bool:
    return is_mcp_tool(entry) and entry.endswith("__*")


def mcp_family_for_server(server: str) -> str:
    """``plugin:posthog:posthog`` → ``mcp__plugin_posthog_posthog__*``."""
    return f"{_MCP_PREFIX}{server.replace(':', '_')}__*"


def _mcp_family_tokens(family: str) -> List[str]:
    """Human-recognisable words in a family name, for keyword matching:
    ``mcp__plugin_posthog_posthog__*`` → ["posthog"] (drops "plugin"/"mcp")."""
    core = family[len(_MCP_PREFIX):-len("__*")] if is_mcp_family(family) else family
    toks = set()
    for part in core.replace("-", "_").split("_"):
        part = part.strip().lower()
        if len(part) >= 3 and part not in {"plugin", "mcp", "server", "api", "docs"}:
            toks.add(part)
    return sorted(toks)


def _tool_matches(tool: str, entries: List[str]) -> bool:
    """Exact tag match, or a glob entry (``mcp__posthog__*``) that covers it."""
    for e in entries:
        if not isinstance(e, str):
            continue
        if e == tool:
            return True
        if "*" in e and e != "*" and fnmatch(tool, e):
            return True
    return False


def _mentions_mcp(*lists: List[str]) -> bool:
    """Does any allow/deny list name an MCP tool or family?"""
    return any(is_mcp_tool(e) for lst in lists for e in (lst or []) if isinstance(e, str))


def _read_json(path: Path) -> Any:
    try:
        if path.stat().st_size > _MAX_MCP_CONFIG_BYTES:
            return None
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _mcp_server_names_in(obj: Any) -> List[str]:
    """Server names from a ``{"mcpServers": {...}}`` blob or a bare map."""
    if not isinstance(obj, dict):
        return []
    servers = obj.get("mcpServers", obj)
    if not isinstance(servers, dict):
        return []
    return [str(k) for k in servers.keys() if isinstance(k, str) and k]


def _gateway_inner_servers(spec: Any) -> List[str]:
    """Servers a ``prismor mcp-gateway`` entry fronts, or [].

    Once `prismor mcp-gateway install` runs, ``.mcp.json`` lists one server —
    ``prismor`` — and the real ones move into the gateway config. The gateway
    namespaces their tools as ``<server>__<tool>``, so the family a scope needs
    is ``mcp__prismor__filesystem__*``, not ``mcp__prismor__*``. Without this
    the only word a scope could match on is "prismor", so no ordinary prompt
    ("read it with the filesystem tool") ever widens the scope to reach them.
    """
    if not isinstance(spec, dict):
        return []
    args = [str(a) for a in spec.get("args", []) if isinstance(a, (str, int))]
    if "mcp-gateway" not in args or "--mirror" in args:
        return []
    cfg = None
    if "--config" in args:
        idx = args.index("--config")
        if idx + 1 < len(args):
            cfg = Path(args[idx + 1])
    if cfg is None:
        cfg = Path.home() / ".prismor" / "mcp-gateway.json"
    return _mcp_server_names_in(_read_json(cfg))
def _gateway_upstreams(entry, home):
    """If an MCP server entry is the Prismor mcp-gateway, return its upstream
    server names (read from the gateway config); else None. The gateway
    aggregates every upstream under ONE server name, so scoping must see
    through it to the upstreams -- otherwise the only family is
    ``mcp__<gateway>__*`` and no task prompt ever names it, so every gatewayed
    MCP tool is denied by omission.

    ``--mirror`` is not a fan-out point: it serves the agent's own built-ins
    under one family and fronts nothing, so it keeps ``mcp__<mirror>__*``.
    Expanding it would replace that family with upstreams it does not serve,
    leaving the mirrored built-ins matching no family at all — denied by
    omission, which is the failure this function exists to prevent. Same guard
    as ``_gateway_inner_servers``."""
    if not isinstance(entry, dict):
        return None
    args = entry.get("args") or []
    argv = " ".join(str(a) for a in args)
    if "mcp-gateway" not in argv or "--mirror" in args:
        return None
    cfg = None
    for i, a in enumerate(args):
        if str(a) == "--config" and i + 1 < len(args):
            cfg = Path(str(args[i + 1])); break
    if cfg is None:
        cfg = home / ".prismor" / "mcp-gateway.json"
    return _mcp_server_names_in(_read_json(cfg)) or []


def _gateway_expansion(workspace, agent, home):
    """Map each gateway family ``mcp__<gw>__*`` to its per-upstream families
    ``mcp__<gw>__<upstream>__*``, so per-server token matching still works."""
    out = {}
    def scan(mcp):
        if not isinstance(mcp, dict):
            return
        for name, entry in mcp.items():
            ups = _gateway_upstreams(entry, home)
            if ups:
                out[mcp_family_for_server(name)] = [
                    mcp_family_for_server(f"{name}__{u}") for u in ups
                ]
    try:
        scan((_read_json(workspace / ".mcp.json") or {}).get("mcpServers"))
        if agent in ("claude", "claude-code", "claude_code"):
            cfg = _read_json(home / ".claude.json")
            if isinstance(cfg, dict):
                scan(cfg.get("mcpServers"))
                projects = cfg.get("projects")
                if isinstance(projects, dict):
                    ws = str(workspace.resolve())
                    for pth, proj in projects.items():
                        if isinstance(proj, dict) and (pth == ws or ws.startswith(pth.rstrip("/") + "/")):
                            scan(proj.get("mcpServers"))
    except Exception:
        pass
    return out


def discover_mcp_families(workspace: Path, agent: str = "claude") -> List[str]:
    """Best-effort inventory of the MCP servers this agent can reach, as
    ``mcp__<server>__*`` families. Cheap on purpose (a handful of JSON reads —
    this runs on every prompt) and never raises. Servers it cannot see are
    not denied by the scope: see ``check_scoped_rules``."""
    families: List[str] = []
    seen: set = set()

    def _add(server: str) -> None:
        fam = mcp_family_for_server(server)
        if fam not in seen:
            seen.add(fam)
            families.append(fam)

    try:
        home = Path.home()
        # Workspace-level .mcp.json (Claude Code, Codex, Cursor share the shape).
        ws_cfg = _read_json(workspace / ".mcp.json")
        ws_servers = ws_cfg.get("mcpServers", ws_cfg) if isinstance(ws_cfg, dict) else {}
        for name in _mcp_server_names_in(ws_cfg):
            inner = _gateway_inner_servers(
                ws_servers.get(name) if isinstance(ws_servers, dict) else None)
            # The gateway serves no tools of its own. Registering the bare
            # family alongside the expanded ones would deny every fronted tool
            # by glob even when the specific family is allowed.
            for sub in inner:
                _add(f"{name}__{sub}")
            if not inner:
                _add(name)
        if agent in ("claude", "claude-code", "claude_code"):
            cfg = _read_json(home / ".claude.json")
            if isinstance(cfg, dict):
                for name in _mcp_server_names_in(cfg.get("mcpServers")):
                    _add(name)
                projects = cfg.get("projects")
                if isinstance(projects, dict):
                    ws = str(workspace.resolve())
                    for proj_path, proj in projects.items():
                        if isinstance(proj, dict) and (proj_path == ws or ws.startswith(proj_path.rstrip("/") + "/")):
                            for name in _mcp_server_names_in(proj.get("mcpServers")):
                                _add(name)
            # Plugin-provided servers: tag is plugin:<plugin>:<server>.
            installed = _read_json(home / ".claude" / "plugins" / "installed_plugins.json")
            plugins = installed.get("plugins") if isinstance(installed, dict) else None
            if isinstance(plugins, dict):
                for key, entries in plugins.items():
                    plugin = str(key).split("@", 1)[0]
                    for entry in entries if isinstance(entries, list) else []:
                        if not isinstance(entry, dict):
                            continue
                        scope = entry.get("scope")
                        if scope in ("project", "local") and entry.get("projectPath") not in (None, str(workspace.resolve())):
                            continue
                        install = entry.get("installPath")
                        if not install:
                            continue
                        for name in _mcp_server_names_in(_read_json(Path(install) / ".mcp.json")):
                            _add(f"plugin:{plugin}:{name}")
    except Exception:
        pass
    expansion = _gateway_expansion(workspace, agent, Path.home())
    if expansion:
        expanded = []
        for fam in families:
            expanded.extend(expansion.get(fam, [fam]))
        # de-dupe, preserve order
        seen2 = set(); families = [f for f in expanded if not (f in seen2 or seen2.add(f))]
    return families


def available_tools_for_scope(workspace: Path, agent: str = "claude") -> List[str]:
    """Built-in tool tags plus the MCP families reachable from this workspace."""
    return list(BUILTIN_SCOPE_TOOLS) + discover_mcp_families(workspace, agent)


def _resolve_tool_name(event: Dict[str, Any]) -> Optional[str]:
    """Resolve the concrete tool name for an event.

    Prefers the original tool name carried in ``metadata.tool_name`` (set by the
    hook normalizer) so deny_tools can target the specific tool that ran — e.g.
    distinguishing Edit from Write within a single file_write event, and
    allowing operators to scope arbitrary MCP tool tags such as
    ``mcp__node_repl__js`` from the dashboard. Falls back to the event-type
    mapping for synthetic events that carry no metadata (the CLI ``iam check``
    path and unit tests).
    """
    meta_tool = (event.get("metadata") or {}).get("tool_name") or ""
    if isinstance(meta_tool, str) and meta_tool.strip():
        return meta_tool.strip()
    return _EVENT_TYPE_TO_TOOL.get(event.get("type", ""))


# The tool tag a Claude Code skill invocation arrives under. Every skill shares
# it — the specific skill lives in the tool_input, not the tag.
_SKILL_TOOL = "Skill"

# Qualified skill tags are namespaced so they can never collide with a real
# tool tag, and so the console can classify them without a side-channel field.
_SKILL_PREFIX = "Skill:"

_MAX_SKILL_NAME = 120


def resolve_skill_name(event: Dict[str, Any]) -> Optional[str]:
    """Return the skill name for a ``Skill`` tool call, else None.

    Every skill invocation shares the tool tag ``Skill``; the name that says
    WHICH skill ran is only in the raw hook payload's tool_input. Without this
    the whole skill surface collapses to one undifferentiated tag.
    """
    meta = event.get("metadata") or {}
    raw = meta.get("raw")
    if not isinstance(raw, dict):
        return None
    tool_input = raw.get("tool_input") or raw.get("toolInput") or {}
    if not isinstance(tool_input, dict):
        return None
    name = tool_input.get("skill") or ""
    if not isinstance(name, str):
        return None
    return name.strip()[:_MAX_SKILL_NAME] or None


def resolve_tool_tags(event: Dict[str, Any]) -> List[str]:
    """Tool tags this event may be inventoried or denied under.

    Usually just the resolved tool name. A skill call additionally yields the
    qualified ``Skill:<name>`` tag, so an operator can deny one skill without
    denying the whole mechanism. The bare tag stays first: denying ``Skill``
    must keep blocking every skill.
    """
    base = _resolve_tool_name(event)
    if not base:
        return []
    if base == _SKILL_TOOL:
        skill = resolve_skill_name(event)
        if skill:
            return [base, f"{_SKILL_PREFIX}{skill}"]
    return [base]


# ── Rule synthesis ─────────────────────────────────────────────────────────

_SYSTEM_PROMPT = """\
You are a security policy synthesizer for an AI coding agent.
Given a task description and a list of available tools, output a minimal
JSON object that scopes the agent to only what this task genuinely requires.
Be conservative — if a tool is not clearly needed, exclude it.
Output only valid JSON, no explanation, no markdown fences.
Schema:
{
  "allowed_tools": [...],
  "allowed_paths": [...],
  "deny_tools": [...],
  "deny_network": true | false
}
Rules:
- allowed_tools: tool names the task needs (from the available list)
- allowed_paths: glob patterns for file paths the task should access
- deny_tools: tools explicitly not needed (complement of allowed)
- deny_network: true to block all network access, false to allow
- If the task involves reading/editing code, allow Read/Edit/Write for relevant paths
- If the task does NOT mention network, web, fetch, install, or download, set deny_network: true
- Always include Read in allowed_tools (agents need to read files to orient)
- Entries of the form mcp__<server>__* are MCP tool families (one per connected
  MCP server). Include a family in allowed_tools when the task needs that
  service (e.g. an analytics/PostHog task needs the *posthog* family); put the
  rest in deny_tools like any other unneeded tool.
- If the task prompt contains @@SECRET:name@@ placeholders, include Bash so shell-based secret use can go through the agent's decloak hook or `prismor cloak run`.
"""


def synthesize_scoped_rules(
    goal: str,
    available_tools: List[str],
    workspace: Path,
) -> Optional[Dict[str, Any]]:
    """Call the Anthropic API to generate scoped rules for a task.

    Returns a parsed dict on success, or falls back to static heuristics
    if the SDK is unavailable or the API call fails. Returns None only if
    the static fallback also fails (should not happen).
    """
    try:
        import anthropic  # noqa: F401
    except ImportError:
        sys.stderr.write(
            "[prismor] anthropic SDK not installed — using static scoped rules. "
            "Install with: pip3 install anthropic\n"
        )
        return _static_fallback_rules(goal, available_tools)

    import os
    api_key = os.environ.get("ANTHROPIC_API_KEY", "")
    if not api_key:
        sys.stderr.write(
            "[prismor] ANTHROPIC_API_KEY not set — using static scoped rules.\n"
        )
        return _static_fallback_rules(goal, available_tools)

    try:
        client = anthropic.Anthropic(api_key=api_key)
        response = client.messages.create(
            model="claude-haiku-4-5-20251001",
            max_tokens=300,
            temperature=0,
            system=_SYSTEM_PROMPT,
            messages=[{
                "role": "user",
                "content": f"Task: {goal}\nAvailable tools: {', '.join(available_tools)}",
            }],
        )

        text = response.content[0].text.strip()
        rules = json.loads(text)

        # Validate shape
        if not isinstance(rules.get("allowed_tools"), list):
            raise ValueError("allowed_tools must be a list")
        if not isinstance(rules.get("deny_tools"), list):
            rules["deny_tools"] = []
        if not isinstance(rules.get("allowed_paths"), list):
            rules["allowed_paths"] = ["**"]
        if "deny_network" not in rules:
            rules["deny_network"] = True

        # Clamp to the known-good available_tools list to prevent prompt injection
        # from expanding the allowed set beyond what the agent actually has.
        available_set = set(available_tools)
        rules["allowed_tools"] = [t for t in rules["allowed_tools"] if t in available_set]
        rules["deny_tools"] = [t for t in rules["deny_tools"] if t in available_set]

        rules = _apply_cloak_invariant(rules, goal)
        # Provenance: an LLM prediction, not operator intent (issue #257).
        rules["source"] = "synthesized"
        return rules

    except Exception as exc:
        sys.stderr.write(f"[prismor] scoped agent API error: {exc} — using static fallback.\n")
        return _static_fallback_rules(goal, available_tools)


def _apply_cloak_invariant(rules: Dict[str, Any], goal: str) -> Dict[str, Any]:
    """Enforce the cloaking invariant deterministically, regardless of how the
    rules were produced (LLM or static heuristic).

    A prompt that references a cloaked secret (``@@SECRET:name@@``) usually
    needs shell execution: Claude/Hermes can use their decloak hooks, while
    block-only agents such as Codex must use ``prismor cloak run``. So Bash MUST
    be allowed and network MUST be permitted whenever the goal carries a
    placeholder. The LLM path is advisory and sometimes drops Bash; this
    code-level guard makes the invariant non-negotiable so the secret-cloaking
    flow never self-blocks.
    """
    if "@@secret:" not in goal.lower():
        return rules
    allowed = [t for t in rules.get("allowed_tools", []) if t != "Bash"]
    rules["allowed_tools"] = allowed + ["Bash"]
    rules["deny_tools"] = [t for t in rules.get("deny_tools", []) if t != "Bash"]
    rules["deny_network"] = False
    return rules


# Agents whose only way to read a file is a shell command. A scope that grants
# Read but not Bash leaves them unable to do anything (verified live: Codex
# blocked on `cat README.md` after a "summarize the README" prompt).
_SHELL_ONLY_AGENTS = {
    "codex", "hermes", "goose", "openclaw", "opencode", "grok", "kiro", "crush",
    "openhands", "qwen", "continue", "copilot",
}


def apply_agent_invariants(rules: Dict[str, Any], agent: str) -> Dict[str, Any]:
    """Per-agent floor: shell-only agents always keep Bash."""
    if agent in _SHELL_ONLY_AGENTS:
        if "Bash" not in rules.get("allowed_tools", []):
            rules["allowed_tools"] = list(rules.get("allowed_tools", [])) + ["Bash"]
        rules["deny_tools"] = [t for t in rules.get("deny_tools", []) if t != "Bash"]
    return rules


def merge_scoped_rules(existing: Dict[str, Any], new: Dict[str, Any]) -> Dict[str, Any]:
    """Widen ``existing`` with rules synthesised from a later prompt.

    Sessions are conversations, not single tasks: the first prompt is often
    "what does this do?" and the third is "ok, fix it". Rules are therefore
    re-derived on every prompt and UNIONED — a later prompt can widen the
    scope, never narrow it. Once an operator has edited the scope by hand
    (dashboard or ``prismor scope edit``, which set ``operator_edited``) the
    caller must stop merging: a human-shaped scope is authoritative."""
    merged = dict(existing)
    allowed = list(dict.fromkeys(list(existing.get("allowed_tools", [])) + list(new.get("allowed_tools", []))))
    deny = [t for t in dict.fromkeys(list(existing.get("deny_tools", [])) + list(new.get("deny_tools", [])))
            if t not in allowed]
    merged["allowed_tools"] = allowed if "*" not in allowed else ["*"]
    merged["deny_tools"] = deny
    paths = list(dict.fromkeys(list(existing.get("allowed_paths", ["**"])) + list(new.get("allowed_paths", ["**"]))))
    merged["allowed_paths"] = ["**"] if "**" in paths else paths
    merged["deny_network"] = bool(existing.get("deny_network", False)) and bool(new.get("deny_network", False))
    merged["prompts_seen"] = int(existing.get("prompts_seen") or 1) + 1
    return merged


def _static_fallback_rules(goal: str, available_tools: List[str]) -> Dict[str, Any]:
    """Keyword-based heuristic fallback when no API is available."""
    goal_lower = goal.lower()

    # Start with Read + Bash always allowed. Without an LLM this heuristic
    # cannot tell "summarize the README" from "summarize, then run the tests",
    # and shell is how agents do almost anything (Codex has no Read tool at
    # all — it reads files with `cat`). Dangerous shell is the base policy's
    # job; the static scope only decides writes and network.
    # Glob and Grep ride with Read: they are read-only discovery, an agent
    # cannot orient without them, and denying them while allowing Read and
    # Bash buys nothing (the same listing is one `ls` or `grep` away).
    allowed = {"Read", "Bash", "Glob", "Grep"}
    deny_network = True

    # Detect task intent from keywords
    edit_keywords = {"edit", "fix", "refactor", "update", "change", "modify", "add", "implement", "create", "write"}
    test_keywords = {"test", "run", "execute", "build", "compile", "lint", "check"}
    network_keywords = {"fetch", "download", "install", "deploy", "push", "pull", "clone", "api", "http", "url"}
    search_keywords = {"search", "find", "grep", "look"}

    if any(kw in goal_lower for kw in edit_keywords):
        allowed.update({"Edit", "MultiEdit", "Write", "Bash"})
    if any(kw in goal_lower for kw in test_keywords):
        allowed.update({"Bash"})
    if any(kw in goal_lower for kw in network_keywords):
        allowed.update({"WebFetch", "WebSearch"})
        deny_network = False
    if any(kw in goal_lower for kw in search_keywords):
        allowed.update({"Bash"})  # for grep/find

    # MCP tool families: allow a family when the prompt names its server
    # ("query posthog for ..." → mcp__plugin_posthog_posthog__*).
    for fam in available_tools:
        if is_mcp_tool(fam) and any(tok in goal_lower for tok in _mcp_family_tokens(fam)):
            allowed.add(fam)
            deny_network = False

    deny = [t for t in available_tools if t not in allowed]

    rules = {
        "allowed_tools": sorted(allowed),
        "allowed_paths": ["**"],  # broad by default in static mode
        "deny_tools": deny,
        "deny_network": deny_network,
    }
    # Cloaked-secret placeholders always require Bash (decloak runs in shell).
    rules = _apply_cloak_invariant(rules, goal)
    # Provenance: this scope is a prediction, not operator intent. Enforcement
    # softens accordingly — see _scoped_finding (issue #257).
    rules["source"] = "synthesized"
    return rules


# ── Sidecar persistence ───────────────────────────────────────────────────

def _scoped_dir(workspace: Path) -> Path:
    from prismor.runtime.store import prismor_home

    return prismor_home() / "scoped"


def _scoped_path(workspace: Path, session_id: str) -> Path:
    safe = "".join(c if c.isalnum() or c in "._-" else "_" for c in session_id)
    return _scoped_dir(workspace) / f"{safe}.json"


def save_scoped_rules(workspace: Path, session_id: str, rules: Dict[str, Any]) -> Path:
    """Write scoped rules to a session-specific sidecar file."""
    path = _scoped_path(workspace, session_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(rules, indent=2) + "\n", encoding="utf-8")
    return path


def load_scoped_rules(workspace: Path, session_id: str) -> Optional[Dict[str, Any]]:
    """Load scoped rules for a session. Returns None if no rules exist."""
    path = _scoped_path(workspace, session_id)
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None


# What ``prismor scope clear`` leaves behind. Deleting the sidecar used to be
# the whole implementation — and the next UserPromptSubmit saw "no scope yet"
# and synthesised a fresh one, so the user was back to blocked one prompt
# later (and told, again, to run `scope clear`). A cleared session is instead
# recorded as allow-everything with auto-scoping switched off, and stays that
# way until the session ends or an operator edits it again.
CLEARED_SCOPE: Dict[str, Any] = {
    "allowed_tools": ["*"],
    "allowed_paths": ["**"],
    "deny_tools": [],
    "deny_network": False,
    "cleared": True,
    "operator_edited": True,
}


def clear_scoped_rules(workspace: Path, session_id: str) -> bool:
    """Stop scoping a session: replace its rules with ``CLEARED_SCOPE`` so the
    prompt hook does not re-synthesise them. Returns True if the session had
    a scope that was not already cleared."""
    existing = load_scoped_rules(workspace, session_id)
    had_scope = existing is not None and not existing.get("cleared")
    save_scoped_rules(workspace, session_id, dict(CLEARED_SCOPE))
    return had_scope


def is_cleared(rules: Optional[Dict[str, Any]]) -> bool:
    return bool(rules and rules.get("cleared"))


def list_scoped_sessions(workspace: Path) -> List[Dict[str, Any]]:
    """List all sessions that have active scoped rules."""
    scoped = _scoped_dir(workspace)
    if not scoped.exists():
        return []
    results = []
    for f in scoped.glob("*.json"):
        try:
            mtime = f.stat().st_mtime
            rules = json.loads(f.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
        results.append({
            "session_id": f.stem,
            "path": str(f),
            "rules": rules,
            "updated": mtime,
        })
    # Newest first — the session you are in is almost always the top one.
    results.sort(key=lambda r: r["updated"], reverse=True)
    return results


def resolve_session_ref(workspace: Path, ref: str) -> str:
    """``latest`` → the most recently updated scoped session; a unique prefix
    → the full id; anything else is returned unchanged."""
    sessions = list_scoped_sessions(workspace)
    if ref == "latest" and sessions:
        return sessions[0]["session_id"]
    hits = [s["session_id"] for s in sessions if s["session_id"].startswith(ref)]
    if len(hits) == 1:
        return hits[0]
    return ref


# ── Enforcement ────────────────────────────────────────────────────────────

def check_scoped_rules(
    rules: Dict[str, Any],
    event: Dict[str, Any],
    session_id: str = "",
) -> Optional[Dict[str, Any]]:
    """Check an event against session-scoped rules.

    Returns a finding dict if the event is blocked, None if allowed.
    """
    if rules.get("paused", False):
        return None  # prismor paused by human operator via dashboard

    # Absent `source` means a scope written before provenance was recorded (or
    # by an operator surface): keep the strict, hard-blocking behaviour. Only a
    # scope explicitly marked as machine-synthesized softens.
    _synth = str(rules.get("source") or "") == "synthesized"
    event_type = event.get("type", "")
    tool_name = _resolve_tool_name(event)

    # Tool check
    if tool_name:
        allowed = rules.get("allowed_tools", [])
        denied = rules.get("deny_tools", [])
        # A mirrored built-in answers to both tags: the MCP tag it arrived
        # under, so an operator can still deny one server's copy specifically,
        # and the native tag, so an allowlist naming "Bash" covers a Bash that
        # happens to be travelling over MCP. Checked deny-first, like the tags
        # themselves, so neither spelling can be used to slip past a deny.
        alias = native_alias(tool_name)
        tags = [tool_name] + ([alias] if alias else [])

        # deny_tools takes precedence over allowed_tools: an explicitly denied
        # tool is blocked even when a broader allow-rule would otherwise permit
        # it (e.g. allowed_tools:[Read,Edit] + deny_tools:[Write] blocks Write).
        # Entries may be globs — ``mcp__posthog__*`` covers every tool of that
        # MCP server.
        # ...except by a blanket family glob. A scope is synthesised from the
        # user's goal, which never names the mirror's server, so both the LLM
        # and the static fallback (which denies everything not allowed) put
        # ``mcp__prismor-tools__*`` in deny_tools — denying the very built-ins
        # the same scope allows by native name, leaving the agent with no tools
        # at all. A mirrored built-in is therefore judged by its native tag
        # unless the operator denied that exact MCP tag.
        if alias and _tool_matches(alias, allowed):
            denied = [e for e in denied if "*" not in str(e)]
        if any(_tool_matches(t, denied) for t in tags):
            return _scoped_finding(
                session_id,
                f"Tool '{tool_name}' is explicitly denied for this session",
                event_type,
                        _synth,
            )

        # "*" in allowed_tools = allow-all-except-denied. The dashboard writes
        # this when an operator denies a single tool for a session that had no
        # prior allowlist, so the deny does not silently turn into an allowlist
        # that blocks every other tool.
        if "*" not in allowed:
            if (is_mcp_tool(tool_name) and not _mentions_mcp(allowed, denied)
                    and not rules.get("operator_edited")):
                # An auto-synthesised scope with no opinion on MCP at all — it
                # came from a tool list that never included this server
                # (undiscovered plugin, server added mid-session). Denying tools
                # the synthesiser could not even name is not a control anyone
                # chose; the call still goes through the base policy and the
                # MCP gateway's own screening. A hand-edited scope is different:
                # a human shaped it, so its allowlist is authoritative and MCP
                # tools it does not name stay blocked.
                pass
            elif any(_tool_matches(t, allowed) for t in tags):
                pass
            elif event_type == "file_write":
                # A write may arrive as Write, Edit, or MultiEdit. Permit it only if
                # the concrete tool is allowed, or — when the event carries no
                # tool name — any write-family tool is allowed and not denied.
                write_family = ("Write", "Edit", "MultiEdit")
                permitted = [t for t in write_family if t in allowed and t not in denied]
                if not permitted:
                    return _scoped_finding(
                        session_id,
                        f"Tool '{tool_name}' is not in scope for this session",
                        event_type,
                        _synth,
                    )
            else:
                return _scoped_finding(
                    session_id,
                    f"Tool '{tool_name}' is not in scope for this session",
                    event_type,
                        _synth,
                )

    # Path check for file events
    if event_type in ("file_read", "file_write"):
        path = event.get("path", "")
        if path:
            allowed_paths = rules.get("allowed_paths", ["**"])
            if not any(fnmatch(path, pattern) for pattern in allowed_paths):
                return _scoped_finding(
                    session_id,
                    f"Path '{path}' is outside the scoped paths for this session",
                    event_type,
                        _synth,
                )

    # Network check
    if event_type == "network":
        if rules.get("deny_network", False):
            url = event.get("url", "")
            return _scoped_finding(
                session_id,
                f"Network access denied by scoped rules (url: {url[:100]})",
                event_type,
                        _synth,
            )

    return None


def _scoped_finding(
    session_id: str,
    reason: str,
    event_type: str,
    synthesized: bool = False,
) -> Dict[str, Any]:
    """Build a finding dict for a scoped rule violation.

    ``synthesized`` distinguishes a scope an LLM predicted at session start from
    one an operator authored. Both used to hard-block, which is wrong for the
    first kind: the signal there is "the synthesizer did not anticipate this
    tool", not "this call is hostile". When the prediction misses a tool the
    user's own request implies, the legitimate call is denied along with the
    attacks — measured as the only cause of blocking a legitimate action in an
    ~800-trial benchmark (issue #257).

    Synthesized misses therefore escalate (``step_up``) where a surface can ask
    a human, and degrade to a warning where none exists, rather than failing
    closed on a guess. Operator-authored denials keep hard-blocking.
    """
    return {
        "id": f"{session_id}:scoped-agent",
        "severity": "MEDIUM" if synthesized else "HIGH",
        "category": "scoped_agent",
        "title": f"[scoped agent] {reason}",
        "evidence": reason,
        "ruleId": "scoped-agent",
        "action": "step_up" if synthesized else "block",
        # Scope denials are operator intent, not observe-by-default detection —
        # they always enforce.
        "mode": "enforce",
        # Provenance, so telemetry and the console can report capability scoping
        # separately from attack recognition instead of merging the two.
        "scopeSource": "synthesized" if synthesized else "operator",
        # Honoured by the step_up path: a surface with no way to ask a human
        # warns instead of denying, rather than fail-closing on a prediction.
        "softFailOpen": bool(synthesized),
    }


# ── Display ────────────────────────────────────────────────────────────────

_BOLD = "\033[1m"
_NC = "\033[0m"
_CYAN = "\033[0;36m"
_DIM = "\033[37m"


def format_scoped_rules_box(rules: Dict[str, Any]) -> str:
    """Format scoped rules as an ASCII box. Colors only on an interactive
    terminal (honors NO_COLOR) so piped/redirected output doesn't leak raw
    ANSI escape sequences as literal text."""
    import os as _os
    _use_color = sys.stdout.isatty() and not _os.environ.get("NO_COLOR")
    _C = _CYAN if _use_color else ""
    _N = _NC if _use_color else ""
    network = "denied" if rules.get("deny_network", True) else "allowed"

    def _field(label: str, items: List[str]) -> List[str]:
        # Wrap long lists (a machine with ten MCP servers has ten families in
        # deny_tools) so the box stays terminal-width instead of one huge line.
        head = f"  {label:<15} ["
        indent = " " * len(head)
        out, cur = [], head
        for i, item in enumerate(items):
            piece = str(item) + ("," if i < len(items) - 1 else "")
            if len(cur) + len(piece) + 1 > 78 and cur.strip() not in ("", head.strip()):
                out.append(cur.rstrip())
                cur = indent + piece
            else:
                cur = cur + (" " if cur not in (head, indent) else "") + piece if cur != head else cur + piece
        out.append(cur + "]")
        return out

    content_lines = [
        *_field("allowed_tools:", rules.get("allowed_tools", [])),
        *_field("allowed_paths:", rules.get("allowed_paths", [])),
        *_field("deny_tools:", rules.get("deny_tools", [])),
        f"  deny_network:   {network}",
        "",
        "  Session-only; widened on each new prompt. Stored in $PRISMOR_HOME/scoped/.",
        "  Adjust: prismor scope show|edit <session-id>   Stop scoping: prismor scope clear <session-id>",
    ]
    if rules.get("cleared"):
        content_lines = [
            "  cleared — every tool allowed for this session; auto-scoping is off.",
            "  Re-enable by starting a new session.",
        ]

    max_width = max(len(line) for line in content_lines) + 4
    border = max_width + 2

    lines = []
    header = " scoped agent rules for this session "
    pad = border - 2 - len(header)
    lines.append(f"{_C}\u250c\u2500{header}" + "\u2500" * pad + f"\u2510{_N}")
    for cl in content_lines:
        padding = border - 2 - len(cl)
        lines.append(f"{_C}\u2502{_N}{cl}" + " " * padding + f"{_C}\u2502{_N}")
    lines.append(f"{_C}\u2514" + "\u2500" * border + f"\u2518{_N}")

    return "\n".join(lines)
