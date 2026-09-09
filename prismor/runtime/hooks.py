from __future__ import annotations

import hashlib
import json
import os
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from prismor.runtime.store import append_session_event, prismor_home

_SUPPORTED_AGENTS = [
    "claude", "cursor", "windsurf", "openclaw", "hermes", "codex", "copilot", "grok", "kiro",
    "crush", "openhands", "qwen", "continue", "goose", "opencode", "gemini",
]


class HookConfigError(Exception):
    """An agent's hook config exists but could not be parsed.

    Raised instead of a bare ``json.JSONDecodeError`` so a caller installing
    hooks without a human present can report *which* agent needs attention.
    Deliberately not swallowed into an empty config: treating an unparseable
    file as ``{}`` would overwrite whatever the developer actually had in it.
    """


def _strip_for_agent(agent: str, config: Dict[str, Any], marker: str) -> Tuple[Dict[str, Any], bool]:
    """Remove hooks whose command contains `marker`, for the given agent's config."""
    if agent == "claude":
        return _strip_claude(config, marker)
    if agent == "cursor":
        return _strip_cursor(config, marker)
    if agent == "openclaw":
        return _strip_openclaw(config, marker)
    if agent == "hermes":
        return _strip_hermes(config, marker)
    if agent == "codex":
        return _strip_codex(config, marker)
    if agent == "copilot":
        return _strip_copilot(config, marker)
    if agent == "grok":
        return _strip_grok(config, marker)
    if agent == "kiro":
        return _strip_kiro(config, marker)
    if agent == "crush":
        return _strip_crush(config, marker)
    if agent == "openhands":
        return _strip_openhands(config, marker)
    if agent == "qwen":
        return _strip_qwen(config, marker)
    if agent == "continue":
        return _strip_continue(config, marker)
    if agent == "goose":
        return _strip_goose(config, marker)
    if agent == "opencode":
        return _strip_opencode(config, marker)
    if agent == "gemini":
        return _strip_gemini(config, marker)
    return _strip_windsurf(config, marker)


def install_hooks(*, repo_root: Path, workspace: Path, agent: str, scope: str, mode: str) -> List[Dict[str, str]]:
    agents = list(_SUPPORTED_AGENTS) if agent == "all" else [agent]
    results = []
    for current_agent in agents:
        config_path = _config_path(current_agent, scope, workspace)
        config = _read_json(config_path)
        # Idempotent + auto-migrating: drop any prior hook-dispatch hook (this
        # version's, or an older one that used a prismor/runtime/cli.py path) before adding
        # the current command, so re-running install never double-dispatches.
        config, _ = _strip_for_agent(current_agent, config, "hook-dispatch")
        # Project hooks pin the workspace. Global hooks must NOT — they fire
        # from every repo on the machine, and pinning the directory setup ran
        # from attributed every other repo's sessions (and its managed/personal
        # decision) to that one directory. hook-dispatch resolves the workspace
        # from the payload's cwd instead.
        command = _dispatcher_command(
            repo_root=repo_root, workspace=workspace, agent=current_agent, mode=mode,
            pin_workspace=(scope == "project"),
        )
        if current_agent == "claude":
            config = _merge_claude(config, command, workspace, pin_workspace=(scope == "project"))
        elif current_agent == "cursor":
            config = _merge_cursor(config, command)
        elif current_agent == "openclaw":
            config = _merge_openclaw(config, command, repo_root)
        elif current_agent == "hermes":
            config = _merge_hermes(config, command, repo_root)
        elif current_agent == "codex":
            config = _merge_codex(config, command)
        elif current_agent == "copilot":
            config = _merge_copilot(config, command)
        elif current_agent == "grok":
            config = _merge_grok(config, command)
        elif current_agent == "kiro":
            config = _merge_kiro(config, command)
        elif current_agent == "crush":
            config = _merge_crush(config, command)
        elif current_agent == "openhands":
            config = _merge_openhands(config, command)
        elif current_agent == "qwen":
            config = _merge_qwen(config, command)
        elif current_agent == "continue":
            config = _merge_continue(config, command)
        elif current_agent == "goose":
            # Goose auto-discovers any plugin directory under .../plugins/<name>/
            # containing hooks/hooks.json — the plugin dir is config_path's
            # grandparent (.../plugins/prismor/hooks/hooks.json -> .../plugins/prismor/).
            config = _merge_goose(config, command, config_path.parent.parent)
        elif current_agent == "opencode":
            config = _merge_opencode(config, command, repo_root)
        elif current_agent == "gemini":
            config = _merge_gemini(config, command)
        else:
            config = _merge_windsurf(config, command, workspace)

        config_path.parent.mkdir(parents=True, exist_ok=True)
        config_path.write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")
        results.append({"agent": current_agent, "configPath": str(config_path)})
        if current_agent == "codex":
            # Codex only reads [features].hooks from the USER-level config.toml
            # -- verified live: with a project-scoped .codex/config.toml setting
            # hooks=true but the user config unavailable, hooks still never
            # dispatched. So this always targets $CODEX_HOME (Codex's own home-dir
            # override, default ~/.codex) even when scope == "project" (hooks.json
            # itself is correctly scoped).
            codex_home = Path(os.environ["CODEX_HOME"]) if os.environ.get("CODEX_HOME") else Path.home() / ".codex"
            _ensure_codex_hooks_feature_enabled(codex_home / "config.toml")
    return results


# Agents whose hook is registered as a plugin path rather than an inline
# command. _strip_openclaw / _strip_hermes / _strip_opencode use the same
# "is this one of ours" test when uninstalling.
_PLUGIN_REGISTERED_AGENTS = ("openclaw", "hermes", "opencode")


def _prismor_plugin_registered(config_text: str) -> bool:
    try:
        plugins = json.loads(config_text).get("plugins", [])
    except (json.JSONDecodeError, AttributeError):
        return False
    if not isinstance(plugins, list):
        return False
    return any(m in str(entry).lower() for entry in plugins for m in ("prismor", "warden"))


def hook_installed(agent: str, scope: str, workspace: Path) -> bool:
    """True if a Prismor PreToolUse hook is present in this agent's config at
    ``scope`` ("project" | "global"). Text-based — the dispatcher command embeds
    the stable ``hook-dispatch`` marker in every agent's config format — so it
    works regardless of the JSON/TOML shape."""
    # _config_path falls through to the Windsurf path for any agent it does
    # not recognise, so asking it about an unhookable agent (warp, trae,
    # antigravity) returns Windsurf's answer. That made every such agent
    # inherit Windsurf's hook status and report as governed, inflating the
    # coverage number with agents Prismor cannot govern at all.
    if agent not in _SUPPORTED_AGENTS:
        return False
    try:
        path = _config_path(agent, scope, workspace)
        if not path.exists():
            return False
        text = path.read_text(encoding="utf-8")
        if "hook-dispatch" in text:
            return True
        # openclaw / hermes / opencode do not take an inline command: install
        # registers a *plugin path* in config["plugins"] and writes the
        # dispatcher into the scaffolded plugin. The marker is therefore never
        # in the config file, so the text search above reported these agents as
        # unhooked forever — which made coverage() under-report them and sent
        # ensure_global_coverage re-installing them on every run.
        if agent in _PLUGIN_REGISTERED_AGENTS:
            return _prismor_plugin_registered(text)
        return False
    except Exception:
        return False


def coverage(workspace: Path) -> Dict[str, Dict[str, bool]]:
    """Per *detected* agent on this machine, whether a Prismor hook is present at
    project and global scope. A detected agent with neither is an UNGUARDED
    install — a coverage gap an enrolled device must surface (and self-heal)."""
    from prismor.runtime.setup_wizard import _detect_agents
    out: Dict[str, Dict[str, bool]] = {}
    for agent, present in _detect_agents(workspace).items():
        if not present:
            continue
        out[agent] = {
            "project": hook_installed(agent, "project", workspace),
            "global": hook_installed(agent, "global", workspace),
        }
    return out


def unguarded_agents(workspace: Path) -> List[str]:
    """Detected agents Prismor could govern but currently does not.

    Hooks are not the only surface. An agent the MCP mirror governs is not
    unguarded, and an agent with no interception surface at all (no hooks, and
    built-ins that cannot be switched off) is not a coverage gap either — it is
    unsupported, and listing it makes the gap count unactionable. Both used to
    be reported here, which sent `ensure_global_coverage` off trying to install
    hooks into agents that have no hook protocol.
    """
    try:
        from prismor.runtime.surfaces import ungoverned  # lazy: import cycle
        return ungoverned(workspace)
    except Exception:
        # Never let the richer answer break the caller: fall back to the
        # hooks-only view rather than reporting no gaps at all.
        return [a for a, s in coverage(workspace).items() if not (s["project"] or s["global"])]


def ensure_global_coverage(*, repo_root: Path, workspace: Path, mode: str = "observe") -> List[str]:
    """Self-heal: re-assert the GLOBAL hook for any detected agent that has no
    hook at all — the repair for a removed/absent hook on an enrolled device.
    Returns the agents that were (re)installed. Best-effort; never raises.

    Note this can only run when *some* Prismor code is already executing (another
    agent's hook, or the debounced policy refresh) — a machine with every hook
    removed and no Prismor invocation cannot heal itself. Global-scope install at
    enroll time is the primary guarantee; this is defense-in-depth on top."""
    repaired: List[str] = []
    try:
        gaps = unguarded_agents(workspace)
    except Exception:
        return repaired
    # Heals by installing a HOOK, so it may only act on agents that have one.
    # A mirror-only agent with nothing on is a real gap, but not one this
    # function can close — asking install_hooks for it could only ever fail.
    # Asked per agent rather than via surfaces.resolve() so this keeps using
    # unguarded_agents() as its one source of gaps (callers stub that), and so
    # it does not repeat resolve()'s filesystem scan on the refresh path; the
    # registry lookup behind governance() is cached.
    try:
        from prismor.runtime.integrations.registry import governance
        gaps = [a for a in gaps if governance(a).get("hooks")]
    except Exception:
        pass  # capability unknown: fall back to attempting every gap
    for agent in gaps:
        try:
            install_hooks(repo_root=repo_root, workspace=workspace, agent=agent, scope="global", mode=mode)
            repaired.append(agent)
        except Exception:
            pass
    return repaired


def _ensure_codex_hooks_feature_enabled(config_toml_path: Path) -> None:
    """Ensure Codex's own ``[features].hooks`` flag is set in the USER-level
    config.toml (``config_toml_path`` must always be ``~/.codex/config.toml``
    — Codex does not read this flag from a project-scoped config.toml, even
    when hooks.json itself is correctly project-scoped; verified live).

    Without it, Codex's hook dispatcher never runs at all — PreToolUse/
    PostToolUse/etc. are silently no-ops and every tool call passes straight
    through, with no error and no indication hooks aren't active. This is
    a *complete* silent bypass, verified live against codex-cli 0.142.5: a
    destructive command that should have been blocked ran and deleted the
    target file when this flag was unset. See PrismorSec/prismor#149.

    Written as a targeted text patch rather than a full TOML parse+rewrite
    so it never reformats or drops comments/sections in a config.toml that
    may carry substantial unrelated user configuration (plugins, MCP
    servers, project trust state, ...).
    """
    import re

    if not config_toml_path.exists():
        config_toml_path.parent.mkdir(parents=True, exist_ok=True)
        config_toml_path.write_text("[features]\nhooks = true\n", encoding="utf-8")
        return

    text = config_toml_path.read_text(encoding="utf-8")
    if re.search(r"^\s*hooks\s*=\s*true\s*$", text, re.MULTILINE):
        return  # Already using the modern key.

    if re.search(r"^\s*codex_hooks\s*=\s*true\s*$", text, re.MULTILINE):
        # Migrate the deprecated key name in place.
        text = re.sub(
            r"^(\s*)codex_hooks(\s*=\s*true\s*)$", r"\1hooks\2", text, flags=re.MULTILINE
        )
    elif re.search(r"^\[features\]\s*$", text, re.MULTILINE):
        text = re.sub(r"^\[features\]\s*$", "[features]\nhooks = true", text, count=1, flags=re.MULTILINE)
    else:
        if not text.endswith("\n"):
            text += "\n"
        text += "\n[features]\nhooks = true\n"

    config_toml_path.write_text(text, encoding="utf-8")


def uninstall_hooks(*, repo_root: Path, workspace: Path, agent: str, scope: str) -> List[Dict[str, Any]]:
    agents = list(_SUPPORTED_AGENTS) if agent == "all" else [agent]
    results = []
    for current_agent in agents:
        config_path = _config_path(current_agent, scope, workspace)
        removed = False
        if config_path.exists():
            config = _read_json(config_path)
            # Match the stable hook-dispatch token rather than a specific script
            # path, so uninstall removes BOTH the current immunity-routed hooks
            # and any installed by an older build (which used a prismor/runtime/cli.py path).
            marker = "hook-dispatch"
            config, removed = _strip_for_agent(current_agent, config, marker)
            if removed:
                config_path.write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")
        # Also clean up internal hook directory for openclaw / hermes
        if current_agent == "openclaw":
            internal_hook = Path.home() / ".openclaw" / "hooks" / "prismor"
            if internal_hook.exists():
                shutil.rmtree(internal_hook, ignore_errors=True)
                removed = True
        if current_agent == "hermes":
            internal_hook = Path.home() / ".hermes" / "hooks" / "prismor"
            if internal_hook.exists():
                shutil.rmtree(internal_hook, ignore_errors=True)
                removed = True
        # Claude Code also installs separate cloaking hooks (decloak.sh,
        # recloak-mcp.sh, userprompt-guard.sh). The detection-hook strip
        # above only removes entries that reference cli.py, so cloaking
        # stays behind unless we explicitly uninstall it too. Tracked
        # separately (cloak_removed) so the CLI can call this out — see
        # PrismorSec/prismor#126.
        cloak_removed = False
        if current_agent == "claude":
            try:
                from prismor.runtime.cloaking import uninstall as cloak_uninstall
                cloak_result = cloak_uninstall(workspace=workspace, scope=scope)
                if cloak_result.get("removed"):
                    removed = True
                    cloak_removed = True
            except Exception:
                # Cloaking is optional — swallow any error so detection-hook
                # removal still reports cleanly.
                pass
        results.append({
            "agent": current_agent,
            "configPath": str(config_path),
            "removed": removed,
            "cloakRemoved": cloak_removed,
        })
    return results


def _strip_prismor_scrub_wrapper(cmd: str) -> str:
    """Recover the agent's real command from Prismor's own decloak wrapper.

    The cloaking decloak hook (cloaking/hooks/decloak.sh) rewrites every Bash
    command so its output is scrubbed of secrets:
        {
        :
        <orig>

        } 2>&1 | PRISMOR_SECRETS_DIR=<dir> <scrubber>; exit ${PIPESTATUS[0]}
    Recording that wrapper verbatim clutters the dashboard and — because the
    injected PRISMOR_SECRETS_DIR path points at ~/.prismor/secrets — trips
    Prismor's own prismor-vault-access guard, blocking benign commands. Strip
    the wrapper so both storage and policy evaluation see the original command.
    Fail-safe: anything that does not match the exact wrapper shape is returned
    unchanged, so a real command that merely mentions the vault still evaluates.
    """
    if not cmd:
        return cmd
    marker = " 2>&1 | PRISMOR_SECRETS_DIR="
    i = cmd.rfind(marker)
    if i == -1:
        return cmd
    tail = cmd[i + len(marker):]
    if "scrub-stream" not in tail or "PIPESTATUS" not in tail:
        return cmd
    inner = cmd[:i].strip()
    if inner.startswith("{") and inner.endswith("}"):
        inner = inner[1:-1].strip()
        # Drop the wrapper's leading `:` guard line, matched exactly so a real
        # command that merely starts with `:` (`:> file`) is left alone.
        first, sep, rest = inner.partition("\n")
        if sep and first.strip() == ":":
            inner = rest.strip()
        if inner.endswith(";"):
            inner = inner[:-1].strip()
    return inner or cmd


# Post-tool payloads carry what the tool actually returned - the file body, the
# command output, the fetched page. The per-tool normalizers keep only the
# arguments (a Read becomes `{type: file_read, path}`), so the content layers -
# the injection rules and the semantic guard - saw nothing on exactly the events
# where untrusted text enters the session. Attach it once here, for every agent,
# instead of in each of the fifteen normalizers.
_RESULT_KEYS = ("tool_response", "toolResult", "tool_result", "response", "output", "result")
_RESULT_LIMIT = 8000


def _result_text(value: Any) -> str:
    """Best-effort text of a tool result, whatever shape the agent sent."""
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        # Claude nests a file read one level down: {"file": {"content": ...}}.
        for candidate in (value, *(v for v in value.values() if isinstance(v, dict))):
            for key in ("content", "text", "stdout", "output"):
                inner = candidate.get(key)
                if isinstance(inner, str) and inner.strip():
                    extra = candidate.get("stderr") if key == "stdout" else None
                    return inner + ("\n" + extra if isinstance(extra, str) and extra else "")
    try:
        return json.dumps(value)
    except (TypeError, ValueError):
        return str(value)


def _attach_tool_result(event: Dict[str, Any], payload: Dict[str, Any]) -> None:
    """Copy the tool's own output onto the event as ``response``, truncated.

    Pre-tool payloads carry no result, so this is a no-op there, and a
    normalizer that already set ``response`` (tool_result events) keeps its own.
    """
    if event.get("response"):
        return
    for key in _RESULT_KEYS:
        if key in payload:
            text = _result_text(payload[key]).strip()
            if text:
                event["response"] = text[:_RESULT_LIMIT]
            return


def normalize_payload(*, agent: str, payload: Dict[str, Any], workspace: Path) -> Dict[str, Any]:
    session_id = (
        payload.get("session_id")
        or payload.get("sessionId")
        or payload.get("trajectory_id")
        or payload.get("trajectoryId")
        or payload.get("execution_id")
        or payload.get("executionId")
        or _ephemeral_session_id(agent, workspace)
    )

    if agent == "claude":
        event = _normalize_claude(payload, session_id, workspace)
    elif agent == "windsurf":
        event = _normalize_windsurf(payload, session_id, workspace)
    elif agent == "openclaw":
        event = _normalize_openclaw(payload, session_id)
    elif agent == "hermes":
        event = _normalize_hermes(payload, session_id)
    elif agent == "codex":
        event = _normalize_codex(payload, session_id, workspace)
    elif agent == "copilot":
        event = _normalize_copilot(payload, session_id, workspace)
    elif agent == "grok":
        event = _normalize_grok(payload, session_id, workspace)
    elif agent == "kiro":
        event = _normalize_kiro(payload, session_id, workspace)
    elif agent == "crush":
        event = _normalize_crush(payload, session_id)
    elif agent == "openhands":
        event = _normalize_openhands(payload, session_id)
    elif agent == "qwen":
        event = _normalize_qwen(payload, session_id, workspace)
    elif agent == "continue":
        event = _normalize_continue(payload, session_id, workspace)
    elif agent == "goose":
        event = _normalize_goose(payload, session_id)
    elif agent == "opencode":
        event = _normalize_opencode(payload, session_id)
    elif agent == "gemini":
        event = _normalize_gemini(payload, session_id, workspace)
    else:
        event = _normalize_cursor(payload, session_id)
    if isinstance(event, dict) and event.get("type") == "shell" and event.get("command"):
        event["command"] = _strip_prismor_scrub_wrapper(event["command"])
    if isinstance(event, dict):
        _attach_tool_result(event, payload)
    # Which enforcement point saw this call. One agent can be governed by more
    # than one surface at a time (hooks plus the mirror), and without this the
    # telemetry cannot say which of them actually made the decision.
    if isinstance(event, dict):
        event.setdefault("metadata", {}).setdefault("surface", "hook")
    return {"sessionId": session_id, "event": event}


def _default_block_categories() -> set:
    """Return block categories from the bundled default_policy.yaml.

    Cached on first call. Falls back to a hardcoded safe default if the
    policy cannot be loaded (e.g. PyYAML missing in a minimal environment).
    """
    cached = getattr(_default_block_categories, "_cache", None)
    if cached is not None:
        return cached
    try:
        from prismor.runtime.policy_engine import PolicyEngine
        cats = set(PolicyEngine().block_categories)
    except Exception:
        cats = {
            "destructive_command", "secret_exfiltration", "secret_access",
            "remote_execution", "prompt_injection", "dos_resource_exhaustion",
            "rce_canary", "db_modification", "privilege_escalation",
            "skill_risk", "persistence", "security_bypass", "dependency_risk",
        }
    _default_block_categories._cache = cats  # type: ignore[attr-defined]
    return cats


def should_block(
    findings: List[Dict[str, Any]],
    event: Dict[str, Any],
    block_categories: set | None = None,  # legacy/no-op; kept for call-site compat
) -> Dict[str, Any] | None:
    if not _is_pre_action(str(event.get("agent_event", ""))):
        return None

    # Authoritative enforce lever is the per-finding `mode` (derived from the
    # rule's mode, else the policy's default_mode — both default to "observe").
    # A finding blocks only when its effective mode is "enforce". block_categories
    # no longer gates this (every category is observe-by-default until enforced).
    # DENY-wins precedence (block > step_up > defer > modify) is contract.strongest();
    # this function only decides which findings are ELIGIBLE to govern.
    from prismor.runtime.contract import strongest
    eligible: List[Dict[str, Any]] = []
    for finding in findings:
        # A match inside inert text (commit message, PR body, grep pattern)
        # describes an action instead of performing it -- report, never block.
        if finding.get("contextInert"):
            continue
        if str(finding.get("mode", "observe")).lower() == "enforce":
            # Reads are generally safe, so they only block for secret access —
            # except for IAM, where an operator has explicitly scoped which
            # paths/tools an identity may read, and that intent must be honored.
            if (
                event.get("type") == "file_read"
                and finding.get("category") not in ("secret_access", "iam")
            ):
                continue
            eligible.append(finding)
    return strongest(eligible)


def legacy_should_block(
    findings: List[Dict[str, Any]],
    event: Dict[str, Any],
    block_categories: set,
) -> Dict[str, Any] | None:
    """Backward-compat block decision for policies that predate per-rule
    observe/enforce (see PolicyEngine.is_legacy_policy). Replicates the original
    semantics: on a pre-action event, block a finding whose category is in the
    policy's ``block_categories`` — with the same read carve-out as the modern
    path. Only invoked by cli.py when installed with ``--mode enforce``.

    A rule that declares a reporting action (``warn``/``log``) is honored as a
    report even inside a blocking category, mirroring the carve-out
    ``PolicyEngine._resolve_mode`` already applies on the modern path. Without
    it a warn-intended rule hard-blocks purely because of the company its
    category keeps.
    """
    from prismor.runtime.contract import BLOCK, VERDICTS
    if not block_categories:
        return None
    if not _is_pre_action(str(event.get("agent_event", ""))):
        return None
    for finding in findings:
        if finding.get("contextInert"):
            continue
        if str(finding.get("action") or BLOCK).lower() not in VERDICTS:
            continue
        if finding.get("category") in block_categories:
            if (
                event.get("type") == "file_read"
                and finding.get("category") not in ("secret_access", "iam")
            ):
                continue
            return finding
    return None


def _config_path(agent: str, scope: str, workspace: Path) -> Path:
    home = Path.home()
    if scope == "project":
        if agent == "claude":
            return workspace / ".claude" / "settings.json"
        if agent == "cursor":
            return workspace / ".cursor" / "hooks.json"
        if agent == "openclaw":
            return workspace / ".openclaw" / "plugins.json"
        if agent == "hermes":
            return workspace / ".hermes" / "plugins.json"
        if agent == "codex":
            return workspace / ".codex" / "hooks.json"
        if agent == "copilot":
            return workspace / ".github" / "copilot" / "hooks.json"
        if agent == "grok":
            return workspace / ".grok" / "hooks" / "prismor.json"
        if agent == "kiro":
            return workspace / ".kiro" / "agents" / "kiro_default.json"
        if agent == "crush":
            return workspace / "crush.json"
        if agent == "openhands":
            return workspace / ".openhands" / "hooks.json"
        if agent == "qwen":
            return workspace / ".qwen" / "settings.json"
        if agent == "continue":
            return workspace / ".continue" / "settings.json"
        if agent == "goose":
            return workspace / ".agents" / "plugins" / "prismor" / "hooks" / "hooks.json"
        if agent == "opencode":
            return workspace / ".opencode" / "plugins.json"
        if agent == "gemini":
            return workspace / ".gemini" / "settings.json"
        return workspace / ".windsurf" / "hooks.json"

    if agent == "claude":
        return home / ".claude" / "settings.json"
    if agent == "cursor":
        return home / ".cursor" / "hooks.json"
    if agent == "openclaw":
        return home / ".openclaw" / "config.json"
    if agent == "hermes":
        return home / ".hermes" / "config.json"
    if agent == "codex":
        return home / ".codex" / "hooks.json"
    if agent == "copilot":
        return home / ".copilot" / "hooks.json"
    if agent == "grok":
        return home / ".grok" / "hooks" / "prismor.json"
    if agent == "kiro":
        return home / ".kiro" / "agents" / "kiro_default.json"
    if agent == "crush":
        return home / ".config" / "crush" / "crush.json"
    if agent == "openhands":
        # OpenHands only documents a project-scoped `.openhands/hooks.json`; no
        # official global path exists. Fall back to $OPENHANDS_PERSISTENCE_DIR
        # (default ~/.openhands), matching where its other global state lives,
        # for a "global"-scope install rather than erroring — unverified.
        return home / ".openhands" / "hooks.json"
    if agent == "qwen":
        return home / ".qwen" / "settings.json"
    if agent == "continue":
        return home / ".continue" / "settings.json"
    if agent == "goose":
        return home / ".agents" / "plugins" / "prismor" / "hooks" / "hooks.json"
    if agent == "opencode":
        return home / ".config" / "opencode" / "plugins.json"
    if agent == "gemini":
        return home / ".gemini" / "settings.json"
    return home / ".codeium" / "windsurf" / "hooks.json"


# Generated launcher that fixes up sys.path and hands off to the CLI. Written
# to disk rather than inlined into the hook command because every agent config
# format takes a *shell string*, and on Windows the interpreter running that
# string is cmd.exe — where a `PYTHONPATH=... python ...` prefix is not a
# variable assignment but an attempt to execute a program literally named
# `PYTHONPATH=...`. The hook then fails, hook failure is non-blocking, and
# Prismor reports installed while screening nothing. A plain
# `"python" "file" <args>` line is the one shape cmd.exe and sh agree on.
_SHIM_NAME = "hook-dispatch.py"

_SHIM_TEMPLATE = (
    "# Generated by `prismor setup` -- do not edit. Rewritten on every install.\n"
    "import sys\n"
    "\n"
    "sys.path.insert(0, {repo_root!r})\n"
    "\n"
    "from prismor.runtime.immunity_cli import main\n"
    "\n"
    "sys.exit(main())\n"
)


def _write_dispatch_shim(repo_root: Path) -> Path:
    """Write the launcher the hook command points at, and return its path.

    ``sys.path.insert`` replaces the old ``PYTHONPATH=`` shell prefix: it is
    what keeps prismor importable when the agent launcher strips user
    site-packages (Claude Code does), and it costs nothing when prismor is
    already importable from the interpreter's own site-packages.
    """
    shim = prismor_home() / _SHIM_NAME
    shim.parent.mkdir(parents=True, exist_ok=True)
    shim.write_text(_SHIM_TEMPLATE.format(repo_root=str(repo_root)), encoding="utf-8")
    return shim


def _dispatcher_command(*, repo_root: Path, workspace: Path, agent: str, mode: str, pin_workspace: bool = True) -> str:
    # Route through the prismor CLI for consistency (one canonical entry point),
    # invoked via the generated shim with the current interpreter rather than
    # the `prismor` console script, which is not reliably on PATH inside the
    # IDE/agent's hook environment.
    py = sys.executable or "python3"
    shim = _write_dispatch_shim(repo_root)
    ws_flag = f'--workspace "{workspace}" ' if pin_workspace else ""
    return f'"{py}" "{shim}" hook-dispatch --agent {agent} {ws_flag}--mode {mode}'


def _merge_claude(config: Dict[str, Any], command: str, workspace: Path, pin_workspace: bool = True) -> Dict[str, Any]:
    hooks = dict(config.get("hooks", {}))
    hooks["UserPromptSubmit"] = _merge_claude_entries(
        hooks.get("UserPromptSubmit", []),
        {"matcher": "*", "hooks": [{"type": "command", "command": command}]},
    )
    # `Task` is Claude's subagent-spawn tool. Matching it means the delegated
    # charter (subagent prompt) is scanned before the subagent runs, and the
    # spawn is recorded — otherwise a subagent is an unlogged laundering path
    # for prompt-injection/exfiltration. A subagent's *inner* tool calls fire
    # their own Pre/PostToolUse hooks (Bash/Read/...) and are already matched;
    # they arrive tagged with the payload's agent_id/agent_type (see
    # _normalize_claude) so they can be attributed to the subagent.
    hooks["PreToolUse"] = _merge_claude_entries(
        hooks.get("PreToolUse", []),
        {"matcher": "Task|Agent|Bash|Read|Edit|MultiEdit|Write|WebFetch|WebSearch|mcp__.*", "hooks": [{"type": "command", "command": command}]},
    )
    hooks["PostToolUse"] = _merge_claude_entries(
        hooks.get("PostToolUse", []),
        {"matcher": "Task|Agent|Bash|Read|Edit|MultiEdit|Write|WebFetch|WebSearch|mcp__.*", "hooks": [{"type": "command", "command": command}]},
    )
    # SessionStart carries the project-memory files (CLAUDE.md/AGENTS.md) that
    # Claude auto-loads before any tool call. Scanning them here brings their
    # directives under the same content rules as untrusted tool output so a
    # poisoned memory file is detected at session start. See issue #155.
    hooks["SessionStart"] = _merge_claude_entries(
        hooks.get("SessionStart", []),
        {"matcher": "startup|resume|clear|compact", "hooks": [{"type": "command", "command": command}]},
    )
    # Skip "Stop" hook — the payload contains the full assistant response which
    # exceeds OS argument limits (E2BIG) on long conversations. Stop fires after
    # all actions are complete so it has no security enforcement value.
    env = dict(config.get("env", {}))
    if pin_workspace:
        env["PRISMOR_WORKSPACE"] = str(workspace)
    else:
        env.pop("PRISMOR_WORKSPACE", None)
    if env:
        return {**config, "hooks": hooks, "env": env}
    cfg = {**config, "hooks": hooks}
    cfg.pop("env", None)
    return cfg


def _merge_cursor(config: Dict[str, Any], command: str) -> Dict[str, Any]:
    hooks = dict(config.get("hooks", {}))
    for event_name in [
        "beforeSubmitPrompt",
        "beforeShellCommand",
        "afterShellCommand",
        "beforeFileWrite",
        "afterFileWrite",
    ]:
        hooks[event_name] = _merge_simple_command_entries(hooks.get(event_name, []), command)
    return {**config, "version": config.get("version", 1), "hooks": hooks}


def _merge_windsurf(config: Dict[str, Any], command: str, workspace: Path) -> Dict[str, Any]:
    hooks = dict(config.get("hooks", {}))
    for event_name in [
        "pre_user_prompt",
        "pre_read_code",
        "post_read_code",
        "pre_write_code",
        "post_write_code",
        "pre_run_command",
        "post_run_command",
        "pre_mcp_tool_use",
        "post_mcp_tool_use",
        "post_cascade_response",
    ]:
        hooks[event_name] = _merge_windsurf_entries(hooks.get(event_name, []), command, workspace)
    return {**config, "hooks": hooks}


def _strip_claude(config: Dict[str, Any], marker: str) -> tuple[Dict[str, Any], bool]:
    hooks = dict(config.get("hooks", {}))
    removed = False
    for event_name in list(hooks.keys()):
        entries = hooks[event_name]
        if not isinstance(entries, list):
            continue
        cleaned = []
        for entry in entries:
            inner_hooks = entry.get("hooks", [])
            filtered = [h for h in inner_hooks if marker not in h.get("command", "")]
            if len(filtered) < len(inner_hooks):
                removed = True
            if filtered:
                cleaned.append({**entry, "hooks": filtered})
        hooks[event_name] = cleaned
    env = dict(config.get("env", {}))
    if "PRISMOR_WORKSPACE" in env:
        del env["PRISMOR_WORKSPACE"]
        removed = True
    return {**config, "hooks": hooks, "env": env}, removed


def _strip_cursor(config: Dict[str, Any], marker: str) -> tuple[Dict[str, Any], bool]:
    hooks = dict(config.get("hooks", {}))
    removed = False
    for event_name in list(hooks.keys()):
        entries = hooks[event_name]
        if not isinstance(entries, list):
            continue
        filtered = [e for e in entries if marker not in e.get("command", "")]
        if len(filtered) < len(entries):
            removed = True
        hooks[event_name] = filtered
    return {**config, "hooks": hooks}, removed


def _strip_windsurf(config: Dict[str, Any], marker: str) -> tuple[Dict[str, Any], bool]:
    hooks = dict(config.get("hooks", {}))
    removed = False
    for event_name in list(hooks.keys()):
        entries = hooks[event_name]
        if not isinstance(entries, list):
            continue
        filtered = [e for e in entries if marker not in e.get("command", "")]
        if len(filtered) < len(entries):
            removed = True
        hooks[event_name] = filtered
    return {**config, "hooks": hooks}, removed


def _merge_openclaw(config: Dict[str, Any], command: str, repo_root: Path) -> Dict[str, Any]:
    # 1. Scaffold the plugin package
    plugin_dir = repo_root / "prismor" / "runtime" / "openclaw-plugin"
    _scaffold_openclaw_plugin(plugin_dir, command)

    # 2. Register plugin path in config
    plugins = list(config.get("plugins", []))
    plugin_path = str(plugin_dir)
    if plugin_path not in plugins:
        plugins.append(plugin_path)

    # 3. Scaffold internal hook for message:received
    hooks_dir = Path.home() / ".openclaw" / "hooks" / "prismor"
    _scaffold_openclaw_internal_hook(hooks_dir, command)

    return {**config, "plugins": plugins}


def _strip_openclaw(config: Dict[str, Any], marker: str) -> tuple[Dict[str, Any], bool]:
    plugins = list(config.get("plugins", []))
    filtered = [p for p in plugins if "warden" not in p.lower() and "prismor" not in p.lower()]
    removed = len(filtered) < len(plugins)
    return {**config, "plugins": filtered}, removed


def _merge_opencode(config: Dict[str, Any], command: str, repo_root: Path) -> Dict[str, Any]:
    # 1. Scaffold the opencode plugin
    plugin_dir = repo_root / "prismor" / "runtime" / "opencode-plugin"
    _scaffold_opencode_plugin(plugin_dir, command)

    # 2. Register plugin path in opencode.json config
    plugins = list(config.get("plugins", []))
    plugin_path = str(plugin_dir)
    if plugin_path not in plugins:
        plugins.append(plugin_path)

    return {**config, "plugins": plugins}


def _strip_opencode(config: Dict[str, Any], marker: str) -> tuple[Dict[str, Any], bool]:
    plugins = list(config.get("plugins", []))
    filtered = [p for p in plugins if "prismor" not in p.lower() and "warden" not in p.lower()]
    removed = len(filtered) < len(plugins)
    return {**config, "plugins": filtered}, removed


_OPENCODE_PLUGIN_JS = """\
"use strict";

const { execSync } = require("child_process");

const PRISMOR_COMMAND = "__PRISMOR_COMMAND__";

function dispatch(payload) {
  try {
    execSync(PRISMOR_COMMAND, {
      input: JSON.stringify(payload),
      stdio: ["pipe", "pipe", "pipe"],
      timeout: 10000,
    });
  } catch (err) {
    if (err.status === 2) {
      const stderr = (err.stderr || "").toString().trim();
      throw new Error(stderr || "Blocked by Prismor");
    }
  }
}

module.exports = function ({ project, client, $, directory, worktree }) {
  return {
    "tool.execute.before": async function (input, output) {
      dispatch({
        hookEvent: "tool.execute.before",
        toolName: (input && input.tool) || "",
        toolInput: (input && (input.args || input.input)) || {},
        sessionId: (input && input.sessionId) || "",
        timestamp: Date.now(),
      });
    },
    "tool.execute.after": async function (input, output) {
      dispatch({
        hookEvent: "tool.execute.after",
        toolName: (input && input.tool) || "",
        toolInput: (input && (input.args || input.input)) || {},
        sessionId: (input && input.sessionId) || "",
        timestamp: Date.now(),
      });
    },
  };
};
"""


def _scaffold_opencode_plugin(plugin_dir: Path, command: str) -> None:
    plugin_dir.mkdir(parents=True, exist_ok=True)
    pkg = {
        "name": "@prismor/opencode-prismor",
        "version": "0.1.0",
        "description": "Prismor security hooks for OpenCode",
        "main": "index.js",
    }
    (plugin_dir / "package.json").write_text(json.dumps(pkg, indent=2) + "\n", encoding="utf-8")
    js = _OPENCODE_PLUGIN_JS.replace("__PRISMOR_COMMAND__", command)
    (plugin_dir / "index.js").write_text(js, encoding="utf-8")



_OPENCLAW_PLUGIN_JS = """\
"use strict";

const { execSync } = require("child_process");

const PRISMOR_COMMAND = "__PRISMOR_COMMAND__";

function dispatch(payload) {
  try {
    execSync(PRISMOR_COMMAND, {
      input: JSON.stringify(payload),
      stdio: ["pipe", "pipe", "pipe"],
      timeout: 10000,
    });
    return { block: false };
  } catch (err) {
    if (err.status === 2) {
      const stderr = (err.stderr || "").toString().trim();
      return { block: true, reason: stderr || "Blocked by Prismor" };
    }
    return { block: false };
  }
}

exports.before_tool_call = function (event) {
  return dispatch({
    hookEvent: "before_tool_call",
    toolName: event.toolName || "",
    toolInput: event.toolInput || {},
    sessionId: event.sessionId || "",
    agentId: event.agentId || "",
    timestamp: event.timestamp || Date.now(),
  });
};

exports.message_sending = function (event) {
  return dispatch({
    hookEvent: "message_sending",
    toolName: "__message__",
    toolInput: { content: event.content || "" },
    sessionId: event.sessionId || "",
    agentId: event.agentId || "",
    timestamp: event.timestamp || Date.now(),
  });
};
"""

_OPENCLAW_HOOK_MD = """---
event: message:received
---

Prismor prompt injection detection hook.
Scans inbound messages for prompt injection patterns.
"""

_OPENCLAW_HOOK_JS = """\
"use strict";
const { execSync } = require("child_process");

const PRISMOR_COMMAND = "__PRISMOR_COMMAND__";

module.exports = function (event) {
  var payload = {
    hookEvent: "message_received",
    toolName: "__message__",
    toolInput: {
      content: (event.context && event.context.content) || "",
      from: (event.context && event.context.from) || "",
    },
    sessionId: event.sessionKey || "",
    timestamp: event.timestamp || Date.now(),
  };
  try {
    execSync(PRISMOR_COMMAND, {
      input: JSON.stringify(payload),
      stdio: ["pipe", "pipe", "pipe"],
      timeout: 10000,
    });
  } catch (err) {
    // Internal hooks cannot block — stderr warnings still surface
  }
};
"""


def _scaffold_openclaw_plugin(plugin_dir: Path, command: str) -> None:
    plugin_dir.mkdir(parents=True, exist_ok=True)
    pkg = {
        "name": "@prismor/openclaw-prismor",
        "version": "0.1.0",
        "description": "Prismor security hooks for OpenClaw",
        "main": "index.js",
        "openclaw": {
            "hooks": {
                "before_tool_call": "./index.js",
                "message_sending": "./index.js",
            }
        },
    }
    (plugin_dir / "package.json").write_text(json.dumps(pkg, indent=2) + "\n", encoding="utf-8")
    js = _OPENCLAW_PLUGIN_JS.replace("__PRISMOR_COMMAND__", command)
    (plugin_dir / "index.js").write_text(js, encoding="utf-8")


def _scaffold_openclaw_internal_hook(hooks_dir: Path, command: str) -> None:
    hooks_dir.mkdir(parents=True, exist_ok=True)
    (hooks_dir / "HOOK.md").write_text(_OPENCLAW_HOOK_MD, encoding="utf-8")
    js = _OPENCLAW_HOOK_JS.replace("__PRISMOR_COMMAND__", command)
    (hooks_dir / "handler.js").write_text(js, encoding="utf-8")


def _merge_hermes(config: Dict[str, Any], command: str, repo_root: Path) -> Dict[str, Any]:
    # 1. Scaffold the plugin package
    plugin_dir = repo_root / "prismor" / "runtime" / "hermes-plugin"
    _scaffold_hermes_plugin(plugin_dir, command)

    # 2. Register plugin path in config
    plugins = list(config.get("plugins", []))
    plugin_path = str(plugin_dir)
    if plugin_path not in plugins:
        plugins.append(plugin_path)

    # 3. Scaffold internal hook for message:received
    hooks_dir = Path.home() / ".hermes" / "hooks" / "prismor"
    _scaffold_hermes_internal_hook(hooks_dir, command)

    return {**config, "plugins": plugins}


def _strip_hermes(config: Dict[str, Any], marker: str) -> tuple[Dict[str, Any], bool]:
    plugins = list(config.get("plugins", []))
    filtered = [p for p in plugins if "warden" not in p.lower() and "prismor" not in p.lower()]
    removed = len(filtered) < len(plugins)
    return {**config, "plugins": filtered}, removed


_HERMES_PLUGIN_JS = """\
"use strict";

const { execSync } = require("child_process");

const PRISMOR_COMMAND = "__PRISMOR_COMMAND__";

function dispatch(payload) {
  try {
    execSync(PRISMOR_COMMAND, {
      input: JSON.stringify(payload),
      stdio: ["pipe", "pipe", "pipe"],
      timeout: 10000,
    });
    return { block: false };
  } catch (err) {
    if (err.status === 2) {
      const stderr = (err.stderr || "").toString().trim();
      return { block: true, reason: stderr || "Blocked by Prismor" };
    }
    return { block: false };
  }
}

exports.before_tool_call = function (event) {
  return dispatch({
    hookEvent: "before_tool_call",
    toolName: event.toolName || "",
    toolInput: event.toolInput || {},
    sessionId: event.sessionId || "",
    gatewayId: event.gatewayId || "",
    timestamp: event.timestamp || Date.now(),
  });
};

exports.message_sending = function (event) {
  return dispatch({
    hookEvent: "message_sending",
    toolName: "__message__",
    toolInput: { content: event.content || "" },
    sessionId: event.sessionId || "",
    gatewayId: event.gatewayId || "",
    timestamp: event.timestamp || Date.now(),
  });
};
"""

_HERMES_HOOK_MD = """---
event: message:received
---

Prismor prompt injection detection hook for Hermes gateway.
Scans inbound messages for prompt injection patterns before they reach
the model.
"""

_HERMES_HOOK_JS = """\
"use strict";
const { execSync } = require("child_process");

const PRISMOR_COMMAND = "__PRISMOR_COMMAND__";

module.exports = function (event) {
  var payload = {
    hookEvent: "message_received",
    toolName: "__message__",
    toolInput: {
      content: (event.context && event.context.content) || "",
      from: (event.context && event.context.from) || "",
    },
    sessionId: event.sessionKey || "",
    timestamp: event.timestamp || Date.now(),
  };
  try {
    execSync(PRISMOR_COMMAND, {
      input: JSON.stringify(payload),
      stdio: ["pipe", "pipe", "pipe"],
      timeout: 10000,
    });
  } catch (err) {
    // Internal hooks cannot block — stderr warnings still surface
  }
};
"""


def _scaffold_hermes_plugin(plugin_dir: Path, command: str) -> None:
    plugin_dir.mkdir(parents=True, exist_ok=True)
    pkg = {
        "name": "@prismor/hermes-prismor",
        "version": "0.1.0",
        "description": "Prismor security hooks for Hermes gateway",
        "main": "index.js",
        "hermes": {
            "hooks": {
                "before_tool_call": "./index.js",
                "message_sending": "./index.js",
            }
        },
    }
    (plugin_dir / "package.json").write_text(json.dumps(pkg, indent=2) + "\n", encoding="utf-8")
    js = _HERMES_PLUGIN_JS.replace("__PRISMOR_COMMAND__", command)
    (plugin_dir / "index.js").write_text(js, encoding="utf-8")


def _scaffold_hermes_internal_hook(hooks_dir: Path, command: str) -> None:
    hooks_dir.mkdir(parents=True, exist_ok=True)
    (hooks_dir / "HOOK.md").write_text(_HERMES_HOOK_MD, encoding="utf-8")
    js = _HERMES_HOOK_JS.replace("__PRISMOR_COMMAND__", command)
    (hooks_dir / "handler.js").write_text(js, encoding="utf-8")


def _merge_copilot(config: Dict[str, Any], command: str) -> Dict[str, Any]:
    hooks = dict(config.get("hooks", {}))
    for event_name in ["PreToolUse", "PostToolUse", "UserPromptSubmitted"]:
        hooks[event_name] = _merge_simple_command_entries(hooks.get(event_name, []), command)
    return {**config, "version": config.get("version", 1), "hooks": hooks}


def _merge_codex(config: Dict[str, Any], command: str) -> Dict[str, Any]:
    hooks = dict(config.get("hooks", {}))
    hooks["UserPromptSubmit"] = _merge_claude_entries(
        hooks.get("UserPromptSubmit", []),
        {"matcher": "*", "hooks": [{"type": "command", "command": command}]},
    )
    for event_name in ["PreToolUse", "PermissionRequest", "PostToolUse"]:
        hooks[event_name] = _merge_claude_entries(
            hooks.get(event_name, []),
            {
                "matcher": "Bash|apply_patch|mcp__.*",
                "hooks": [{"type": "command", "command": command}],
            },
        )
    return {**config, "hooks": hooks}


def _merge_grok(config: Dict[str, Any], command: str) -> Dict[str, Any]:
    hooks = dict(config.get("hooks", {}))
    hooks["UserPromptSubmit"] = _merge_claude_entries(
        hooks.get("UserPromptSubmit", []),
        {"matcher": "*", "hooks": [{"type": "command", "command": command}]},
    )
    for event_name in ["PreToolUse", "PostToolUse"]:
        hooks[event_name] = _merge_claude_entries(
            hooks.get(event_name, []),
            {
                "matcher": "Bash|Read|Edit|MultiEdit|Write|WebFetch|WebSearch|mcp__.*",
                "hooks": [{"type": "command", "command": command}],
            },
        )
    return {**config, "hooks": hooks}


# Kiro CLI's built-in default agent ("kiro_default") has no on-disk config
# until one is created; whether Kiro merges a partial override with the
# built-in tool list or replaces it outright is undocumented (kiro.dev has
# no example of overriding kiro_default, only creating new named agents).
# So a *fresh* file is seeded as a fully self-contained agent -- explicit
# tools list included -- rather than a hooks-only fragment, so that even in
# a full-replace scenario the user does not silently lose default-agent
# tools the moment Prismor installs hooks. An existing file (the user's own
# customized kiro_default, or a prior Prismor install) is left otherwise
# untouched; only "hooks" is merged into it.
_KIRO_DEFAULT_TOOLS = [
    "read", "glob", "grep", "write", "shell", "aws", "web_search", "web_fetch",
    "code", "introspect", "tool_search", "delegate", "subagent", "report",
    "session", "goal", "knowledge", "thinking", "todo",
]


def _merge_kiro(config: Dict[str, Any], command: str) -> Dict[str, Any]:
    if "name" not in config:
        config = {**config, "name": "kiro_default", "tools": list(_KIRO_DEFAULT_TOOLS)}
    hooks = dict(config.get("hooks", {}))
    # No "matcher" field on an entry means Kiro applies it to every tool --
    # the broadest coverage, matching the other agents' "*"/mcp__.* matchers.
    for event_name in ["userPromptSubmit", "preToolUse", "postToolUse"]:
        hooks[event_name] = _merge_simple_command_entries(hooks.get(event_name, []), command)
    return {**config, "hooks": hooks}


def _merge_crush(config: Dict[str, Any], command: str) -> Dict[str, Any]:
    # Crush's hooks config is a flat dict of event -> list of {name, matcher,
    # command} entries (no nested "hooks" array like Claude/Codex). Verified
    # live (2026-07): only PreToolUse is actually dispatched -- there is no
    # PostToolUse/UserPromptSubmit hook surface in crush v0.86.x despite the
    # SDK schema exposing a HookConfig type generically. Matcher "" matches
    # every tool (verified: an empty-matcher rule fired for a non-bash tool).
    hooks = dict(config.get("hooks", {}))
    entries = list(hooks.get("PreToolUse", []))
    if not any(e.get("command") == command for e in entries):
        entries.append({"name": "prismor", "matcher": "", "command": command})
    hooks["PreToolUse"] = entries
    return {**config, "hooks": hooks}


def _merge_openhands(config: Dict[str, Any], command: str) -> Dict[str, Any]:
    # Same nested {matcher, hooks:[{type, command}]} shape as Claude/Codex.
    # Verified live (2026-07): PreToolUse fires and a non-zero exit blocks the
    # tool call. "*" matches every tool (docs: "*" | exact tool name | /regex/).
    hooks = dict(config.get("hooks", {}))
    hooks["PreToolUse"] = _merge_claude_entries(
        hooks.get("PreToolUse", []),
        {"matcher": "*", "hooks": [{"type": "command", "command": command, "timeout": 60}]},
    )
    hooks["UserPromptSubmit"] = _merge_claude_entries(
        hooks.get("UserPromptSubmit", []),
        {"hooks": [{"type": "command", "command": command, "timeout": 60}]},
    )
    return {**config, "hooks": hooks}


def _merge_qwen(config: Dict[str, Any], command: str) -> Dict[str, Any]:
    # Claude-Code-shaped hooks (nested matcher + hooks[]), but Qwen Code's own
    # tool ids, NOT Claude's ("run_shell_command" not "Bash" -- verified live,
    # a matcher of "Bash" silently never fires). "*" matches every tool.
    hooks = dict(config.get("hooks", {}))
    hooks["UserPromptSubmit"] = _merge_claude_entries(
        hooks.get("UserPromptSubmit", []),
        {"hooks": [{"type": "command", "command": command}]},
    )
    for event_name in ["PreToolUse", "PostToolUse"]:
        hooks[event_name] = _merge_claude_entries(
            hooks.get(event_name, []),
            {"matcher": "*", "hooks": [{"type": "command", "command": command}]},
        )
    return {**config, "hooks": hooks}


def _merge_continue(config: Dict[str, Any], command: str) -> Dict[str, Any]:
    # Continue CLI's hooks.json schema is intentionally Claude-Code-compatible
    # (same event names, same tool-name convention -- "Bash"). WARNING, verified
    # live (2026-07, cn v1.5.47): hooks configured exactly per this schema, in
    # every documented config location, did not fire in headless (`cn -p`)
    # mode for ANY event including UserPromptSubmit -- not just PreToolUse.
    # Ship anyway (interactive-mode users still benefit; the config is inert,
    # not harmful, if the headless bug is present) but never assume this is
    # actually enforcing anything without checking `cn` in the target
    # environment first. See AGENT_INTEGRATIONS.md.
    hooks = dict(config.get("hooks", {}))
    hooks["UserPromptSubmit"] = _merge_claude_entries(
        hooks.get("UserPromptSubmit", []),
        {"matcher": "*", "hooks": [{"type": "command", "command": command}]},
    )
    for event_name in ["PreToolUse", "PostToolUse"]:
        hooks[event_name] = _merge_claude_entries(
            hooks.get(event_name, []),
            {
                "matcher": "Bash|Read|Edit|MultiEdit|Write|Fetch|Search",
                "hooks": [{"type": "command", "command": command}],
            },
        )
    return {**config, "hooks": hooks}


def _merge_goose(config: Dict[str, Any], command: str, plugin_dir: Path) -> Dict[str, Any]:
    # Goose auto-discovers plugin directories containing hooks/hooks.json --
    # no central "plugins": [...] list to register, unlike OpenClaw/Hermes.
    # `config` here IS the plugin's own hooks.json; plugin.json is a static
    # manifest scaffolded once as a side effect. Verified live (2026-07,
    # goose v1.44.0): the built-in shell tool's real name is "shell", NOT
    # "developer__shell" as goose's own official docs example shows -- a
    # matcher of "developer__shell" silently never fires. ".*" matches every
    # tool and is what's used here to avoid depending on that undocumented
    # exact name for coverage.
    plugin_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = plugin_dir / "plugin.json"
    if not manifest_path.exists():
        manifest_path.write_text(
            json.dumps(
                {"name": "prismor", "version": "0.1.0", "description": "Prismor security hooks"},
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
    hooks = dict(config.get("hooks", {}))
    hooks["PreToolUse"] = _merge_claude_entries(
        hooks.get("PreToolUse", []),
        {"matcher": ".*", "hooks": [{"type": "command", "command": command, "timeout": 15}]},
    )
    hooks["UserPromptSubmit"] = _merge_claude_entries(
        hooks.get("UserPromptSubmit", []),
        {"hooks": [{"type": "command", "command": command, "timeout": 15}]},
    )
    return {**config, "hooks": hooks}


def _strip_copilot(config: Dict[str, Any], marker: str) -> tuple[Dict[str, Any], bool]:
    hooks = dict(config.get("hooks", {}))
    removed = False
    for event_name in list(hooks.keys()):
        entries = hooks[event_name]
        if not isinstance(entries, list):
            continue
        filtered = [e for e in entries if marker not in e.get("command", "")]
        if len(filtered) < len(entries):
            removed = True
        hooks[event_name] = filtered
    return {**config, "hooks": hooks}, removed


def _strip_codex(config: Dict[str, Any], marker: str) -> tuple[Dict[str, Any], bool]:
    hooks = dict(config.get("hooks", {}))
    removed = False
    for event_name in list(hooks.keys()):
        entries = hooks[event_name]
        if not isinstance(entries, list):
            continue
        cleaned = []
        for entry in entries:
            inner_hooks = entry.get("hooks", [])
            filtered = [h for h in inner_hooks if marker not in h.get("command", "")]
            if len(filtered) < len(inner_hooks):
                removed = True
            if filtered:
                cleaned.append({**entry, "hooks": filtered})
        hooks[event_name] = cleaned
    return {**config, "hooks": hooks}, removed


def _strip_grok(config: Dict[str, Any], marker: str) -> tuple[Dict[str, Any], bool]:
    hooks = dict(config.get("hooks", {}))
    removed = False
    for event_name in list(hooks.keys()):
        entries = hooks[event_name]
        if not isinstance(entries, list):
            continue
        cleaned = []
        for entry in entries:
            inner_hooks = entry.get("hooks", [])
            filtered = [h for h in inner_hooks if marker not in h.get("command", "")]
            if len(filtered) < len(inner_hooks):
                removed = True
            if filtered:
                cleaned.append({**entry, "hooks": filtered})
        hooks[event_name] = cleaned
    return {**config, "hooks": hooks}, removed


def _strip_kiro(config: Dict[str, Any], marker: str) -> tuple[Dict[str, Any], bool]:
    hooks = dict(config.get("hooks", {}))
    removed = False
    for event_name in list(hooks.keys()):
        entries = hooks[event_name]
        if not isinstance(entries, list):
            continue
        filtered = [e for e in entries if marker not in e.get("command", "")]
        if len(filtered) < len(entries):
            removed = True
        hooks[event_name] = filtered
    return {**config, "hooks": hooks}, removed


def _strip_crush(config: Dict[str, Any], marker: str) -> tuple[Dict[str, Any], bool]:
    hooks = dict(config.get("hooks", {}))
    removed = False
    for event_name in list(hooks.keys()):
        entries = hooks[event_name]
        if not isinstance(entries, list):
            continue
        filtered = [e for e in entries if marker not in e.get("command", "")]
        if len(filtered) < len(entries):
            removed = True
        hooks[event_name] = filtered
    return {**config, "hooks": hooks}, removed


def _strip_openhands(config: Dict[str, Any], marker: str) -> tuple[Dict[str, Any], bool]:
    hooks = dict(config.get("hooks", {}))
    removed = False
    for event_name in list(hooks.keys()):
        entries = hooks[event_name]
        if not isinstance(entries, list):
            continue
        cleaned = []
        for entry in entries:
            inner_hooks = entry.get("hooks", [])
            filtered = [h for h in inner_hooks if marker not in h.get("command", "")]
            if len(filtered) < len(inner_hooks):
                removed = True
            if filtered:
                cleaned.append({**entry, "hooks": filtered})
        hooks[event_name] = cleaned
    return {**config, "hooks": hooks}, removed


def _strip_qwen(config: Dict[str, Any], marker: str) -> tuple[Dict[str, Any], bool]:
    hooks = dict(config.get("hooks", {}))
    removed = False
    for event_name in list(hooks.keys()):
        entries = hooks[event_name]
        if not isinstance(entries, list):
            continue
        cleaned = []
        for entry in entries:
            inner_hooks = entry.get("hooks", [])
            filtered = [h for h in inner_hooks if marker not in h.get("command", "")]
            if len(filtered) < len(inner_hooks):
                removed = True
            if filtered:
                cleaned.append({**entry, "hooks": filtered})
        hooks[event_name] = cleaned
    return {**config, "hooks": hooks}, removed


def _strip_continue(config: Dict[str, Any], marker: str) -> tuple[Dict[str, Any], bool]:
    hooks = dict(config.get("hooks", {}))
    removed = False
    for event_name in list(hooks.keys()):
        entries = hooks[event_name]
        if not isinstance(entries, list):
            continue
        cleaned = []
        for entry in entries:
            inner_hooks = entry.get("hooks", [])
            filtered = [h for h in inner_hooks if marker not in h.get("command", "")]
            if len(filtered) < len(inner_hooks):
                removed = True
            if filtered:
                cleaned.append({**entry, "hooks": filtered})
        hooks[event_name] = cleaned
    return {**config, "hooks": hooks}, removed


def _strip_goose(config: Dict[str, Any], marker: str) -> tuple[Dict[str, Any], bool]:
    hooks = dict(config.get("hooks", {}))
    removed = False
    for event_name in list(hooks.keys()):
        entries = hooks[event_name]
        if not isinstance(entries, list):
            continue
        cleaned = []
        for entry in entries:
            inner_hooks = entry.get("hooks", [])
            filtered = [h for h in inner_hooks if marker not in h.get("command", "")]
            if len(filtered) < len(inner_hooks):
                removed = True
            if filtered:
                cleaned.append({**entry, "hooks": filtered})
        hooks[event_name] = cleaned
    return {**config, "hooks": hooks}, removed


def _unmapped_tool_event(base: Dict[str, Any], payload: Dict[str, Any]) -> Dict[str, Any]:
    """Fall-through for a tool this adapter does not map to a canonical type.

    The event still normalizes to ``tool_result`` so its payload is scanned by
    the untrusted-content rules; dropping it would be strictly worse. But a
    tool that lands here is evaluated against the handful of ``tool_result``
    rules rather than the ``shell`` / ``file_write`` / ``network`` rules its
    actual behaviour warrants — for example Claude Code's ``NotebookEdit``,
    which writes a file but reaches policy as an opaque JSON blob. That is a
    coverage hole, not coverage.

    Tagging the event makes the hole countable (``prismor tags list`` renders
    an UNMAPPED kind) instead of being silently indistinguishable from a
    genuine tool response. Deliberately does NOT change the event type: this
    is an observability signal, so it can never loosen or tighten what the
    policy engine already decides about a payload.

    A fall-through with no tool name at all (session/notification hook events)
    is not an unmapped *tool*, so it is left untagged.

    Known limitation: the ``cursor`` and ``windsurf`` adapters dispatch on the
    hook EVENT name and their payloads carry no tool identity, so their
    coverage holes cannot surface through this signal. Measuring those needs a
    separate event-name-keyed signal.
    """
    event = {**base, "type": "tool_result", "response": json.dumps(payload)}
    metadata = base.get("metadata") or {}
    tool_name = str(metadata.get("tool_name") or "")
    if tool_name:
        event["metadata"] = {**metadata, "unmapped_tool": tool_name}
    return event


def _normalize_copilot(payload: Dict[str, Any], session_id: str, workspace: Path) -> Dict[str, Any]:
    hook_event = payload.get("hookEventName") or payload.get("hook_event_name") or "unknown"
    tool_name = payload.get("toolName") or payload.get("tool_name") or ""
    # Copilot sends toolArgs as a JSON-encoded string; parse it.
    tool_args_raw = payload.get("toolArgs") or payload.get("tool_args") or "{}"
    if isinstance(tool_args_raw, str):
        try:
            tool_args: Dict[str, Any] = json.loads(tool_args_raw)
        except (json.JSONDecodeError, ValueError):
            tool_args = {"raw": tool_args_raw}
    else:
        tool_args = tool_args_raw
    base = {
        "ts": payload.get("timestamp") or datetime.now(timezone.utc).isoformat(),
        "session_id": session_id,
        "agent": "copilot",
        "agent_event": hook_event,
        "metadata": {"cwd": payload.get("cwd"), "tool_name": tool_name, "raw": payload},
    }
    if hook_event == "UserPromptSubmitted":
        return {**base, "type": "prompt", "prompt": payload.get("prompt") or tool_args.get("prompt", "")}
    if tool_name in {"ShellCommand", "run_shell_command", "Bash"}:
        return {**base, "type": "shell", "command": tool_args.get("command") or tool_args.get("cmd", "")}
    if tool_name in {"ReadFile", "read_file", "Read"}:
        return {**base, "type": "file_read", "path": tool_args.get("path") or tool_args.get("filePath", "")}
    if tool_name in {"WriteFile", "write_file", "EditFile", "Write", "Edit"}:
        return {**base, "type": "file_write", "path": tool_args.get("path") or tool_args.get("filePath", ""), "content": tool_args.get("content", "")}
    if tool_name in {"WebFetch", "web_fetch", "WebSearch"}:
        return {**base, "type": "network", "url": tool_args.get("url", "")}
    # Copilot is an approval-capable surface (inline "ask"), so MCP calls must
    # be classified like the other agents' — otherwise `mcp` guardrail rules
    # (block / step_up on mcp__server__tool) silently never fire here.
    mcp_event = _classify_mcp_event(
        base=base,
        tool_name=tool_name,
        tool_input=tool_args,
        response=payload.get("toolResult", payload.get("tool_result", payload.get("response"))),
        is_post=(hook_event == "PostToolUse"),
        workspace=workspace,
    )
    if mcp_event is not None:
        return mcp_event
    return _unmapped_tool_event(base, payload)


def _normalize_codex(payload: Dict[str, Any], session_id: str, workspace: Path) -> Dict[str, Any]:
    hook_event = payload.get("hook_event_name", "unknown")
    tool_name = payload.get("tool_name", "")
    tool_input = payload.get("tool_input", {})
    base = {
        "ts": payload.get("timestamp") or datetime.now(timezone.utc).isoformat(),
        "session_id": session_id,
        "agent": "codex",
        "agent_event": hook_event,
        "metadata": {"cwd": payload.get("cwd"), "tool_name": tool_name, "raw": payload},
    }
    if hook_event == "UserPromptSubmit":
        return {**base, "type": "prompt", "prompt": payload.get("prompt", "")}
    if tool_name == "Bash":
        return {
            **base,
            "type": "shell",
            "command": tool_input.get("command", ""),
            "stdout": payload.get("stdout", ""),
            "stderr": payload.get("stderr", ""),
        }
    if tool_name == "Read":
        return {**base, "type": "file_read", "path": tool_input.get("file_path") or tool_input.get("path", "")}
    if tool_name in {"Edit", "MultiEdit", "Write", "apply_patch"}:
        return {
            **base,
            "type": "file_write",
            "path": tool_input.get("file_path") or tool_input.get("path", ""),
            # A plain single Edit call (as opposed to MultiEdit) has shape
            # {file_path, old_string, new_string} — no "edits" list and no
            # "content" key — so new_string must be its own fallback or the
            # written text is invisible to every content-based check.
            "content": (
                _join_edits(tool_input.get("edits", []))
                or tool_input.get("content", "")
                or tool_input.get("new_string", "")
                or tool_input.get("command", "")
            ),
        }
    if tool_name in {"WebFetch", "WebSearch"}:
        return {**base, "type": "network", "url": tool_input.get("url", ""), "response": payload.get("response", "")}
    mcp_event = _classify_mcp_event(
        base=base,
        tool_name=tool_name,
        tool_input=tool_input,
        response=payload.get("tool_response", payload.get("response")),
        is_post=(hook_event == "PostToolUse"),
        workspace=workspace,
    )
    if mcp_event is not None:
        return mcp_event
    return _unmapped_tool_event(base, payload)


def _normalize_grok(payload: Dict[str, Any], session_id: str, workspace: Path) -> Dict[str, Any]:
    hook_event = payload.get("hookEventName") or payload.get("hook_event_name") or "unknown"
    tool_name = payload.get("toolName") or payload.get("tool_name") or ""
    tool_input = payload.get("toolInput") or payload.get("tool_input") or {}
    base = {
        "ts": payload.get("timestamp") or datetime.now(timezone.utc).isoformat(),
        "session_id": session_id,
        "agent": "grok",
        "agent_event": hook_event,
        "metadata": {"cwd": payload.get("cwd"), "tool_name": tool_name, "raw": payload},
    }
    if hook_event == "UserPromptSubmit":
        return {**base, "type": "prompt", "prompt": payload.get("prompt", "")}
    if tool_name == "Bash":
        return {
            **base,
            "type": "shell",
            "command": tool_input.get("command", ""),
            "stdout": payload.get("stdout", ""),
            "stderr": payload.get("stderr", ""),
        }
    if tool_name == "Read":
        return {**base, "type": "file_read", "path": tool_input.get("file_path") or tool_input.get("path", "")}
    if tool_name in {"Edit", "MultiEdit", "Write"}:
        return {
            **base,
            "type": "file_write",
            "path": tool_input.get("file_path") or tool_input.get("path", ""),
            "content": (
                _join_edits(tool_input.get("edits", []))
                or tool_input.get("content", "")
                or tool_input.get("new_string", "")
            ),
        }
    if tool_name in {"WebFetch", "WebSearch"}:
        return {**base, "type": "network", "url": tool_input.get("url", ""), "response": payload.get("response", "")}
    mcp_event = _classify_mcp_event(
        base=base,
        tool_name=tool_name,
        tool_input=tool_input,
        response=payload.get("toolResponse", payload.get("response")),
        is_post=(hook_event == "PostToolUse"),
        workspace=workspace,
    )
    if mcp_event is not None:
        return mcp_event
    return _unmapped_tool_event(base, payload)


def _normalize_kiro(payload: Dict[str, Any], session_id: str, workspace: Path) -> Dict[str, Any]:
    hook_event = payload.get("hook_event_name", "unknown")
    tool_name = payload.get("tool_name", "")
    tool_input = payload.get("tool_input", {})
    base = {
        "ts": payload.get("timestamp") or datetime.now(timezone.utc).isoformat(),
        "session_id": session_id,
        "agent": "kiro",
        "agent_event": hook_event,
        "metadata": {"cwd": payload.get("cwd"), "tool_name": tool_name, "raw": payload},
    }
    if hook_event == "userPromptSubmit":
        return {**base, "type": "prompt", "prompt": payload.get("prompt", "")}
    # Kiro's canonical tool names are snake_case (execute_bash, fs_read,
    # fs_write, use_aws); it also accepts camelCase/short aliases (shell,
    # read, write, aws) depending on how the calling agent config lists
    # its tools, so match on either form.
    if tool_name in {"shell", "execute_bash", "execute_cmd"}:
        return {**base, "type": "shell", "command": tool_input.get("command", "")}
    if tool_name in {"read", "fs_read", "fsRead"}:
        return {**base, "type": "file_read", "path": tool_input.get("path", "")}
    if tool_name in {"write", "fs_write", "fsWrite"}:
        # fs_write's documented shape is {"operations": [{"mode": ..., "path": ...}]}
        # rather than a flat {path, content} -- the exact per-mode content field
        # is not documented, so this is a best-effort extraction from the first
        # operation with several fallback field names.
        ops = tool_input.get("operations") or []
        first_op = ops[0] if ops and isinstance(ops[0], dict) else {}
        path = tool_input.get("path") or first_op.get("path", "")
        content = (
            tool_input.get("content")
            or first_op.get("content")
            or first_op.get("text")
            or first_op.get("newText", "")
        )
        return {**base, "type": "file_write", "path": path, "content": content}
    if tool_name in {"web_fetch", "web_search"}:
        return {**base, "type": "network", "url": tool_input.get("url", "")}
    return _unmapped_tool_event(base, payload)


def _normalize_crush(payload: Dict[str, Any], session_id: str) -> Dict[str, Any]:
    # Verified live payload shape (2026-07, crush v0.86.x):
    # {"event": "PreToolUse", "session_id", "cwd", "tool_name": "bash",
    #  "tool_input": {"command": ..., "description": ...}}
    hook_event = payload.get("event", "unknown")
    tool_name = payload.get("tool_name", "")
    tool_input = payload.get("tool_input", {}) or {}
    base = {
        "ts": payload.get("timestamp") or datetime.now(timezone.utc).isoformat(),
        "session_id": session_id,
        "agent": "crush",
        "agent_event": hook_event,
        "metadata": {"cwd": payload.get("cwd"), "tool_name": tool_name, "raw": payload},
    }
    if tool_name == "bash":
        return {**base, "type": "shell", "command": tool_input.get("command", "")}
    if tool_name == "view":
        return {**base, "type": "file_read", "path": tool_input.get("path", "")}
    if tool_name in {"write", "edit", "multiedit"}:
        return {
            **base,
            "type": "file_write",
            "path": tool_input.get("path") or tool_input.get("file_path", ""),
            "content": tool_input.get("content") or tool_input.get("new_string", ""),
        }
    if tool_name in {"fetch", "download", "sourcegraph"}:
        return {**base, "type": "network", "url": tool_input.get("url", "")}
    return _unmapped_tool_event(base, payload)


def _normalize_openhands(payload: Dict[str, Any], session_id: str) -> Dict[str, Any]:
    # Verified live payload shape (2026-07, openhands v1.21.0). Field name is
    # "event_type" -- NOT "hook_event_name" like the Claude/Codex-family
    # agents -- and the shell tool's name is "terminal", not "execute_bash".
    hook_event = payload.get("event_type") or payload.get("hook_event_name", "unknown")
    tool_name = payload.get("tool_name", "")
    tool_input = payload.get("tool_input", {}) or {}
    base = {
        "ts": payload.get("timestamp") or datetime.now(timezone.utc).isoformat(),
        "session_id": session_id,
        "agent": "openhands",
        "agent_event": hook_event,
        "metadata": {"cwd": payload.get("working_dir"), "tool_name": tool_name, "raw": payload},
    }
    if hook_event == "UserPromptSubmit":
        return {**base, "type": "prompt", "prompt": payload.get("message") or payload.get("prompt", "")}
    if tool_name == "terminal":
        return {**base, "type": "shell", "command": tool_input.get("command", "")}
    if tool_name == "file_editor":
        return {
            **base,
            "type": "file_write",
            "path": tool_input.get("path", ""),
            "content": tool_input.get("content") or tool_input.get("new_str", ""),
        }
    if tool_name in {"web_fetch", "web_search"}:
        return {**base, "type": "network", "url": tool_input.get("url", "")}
    return _unmapped_tool_event(base, payload)


def _normalize_qwen(payload: Dict[str, Any], session_id: str, workspace: Path) -> Dict[str, Any]:
    # Same field-naming convention as Claude/Codex (hook_event_name, tool_name,
    # tool_input) but Qwen Code's own tool ids -- verified live (2026-07,
    # qwen-code v0.20.1): "run_shell_command", not "Bash".
    hook_event = payload.get("hook_event_name", "unknown")
    tool_name = payload.get("tool_name", "")
    tool_input = payload.get("tool_input", {}) or {}
    base = {
        "ts": payload.get("timestamp") or datetime.now(timezone.utc).isoformat(),
        "session_id": session_id,
        "agent": "qwen",
        "agent_event": hook_event,
        "metadata": {"cwd": payload.get("cwd"), "tool_name": tool_name, "raw": payload},
    }
    if hook_event == "UserPromptSubmit":
        return {**base, "type": "prompt", "prompt": payload.get("prompt", "")}
    if tool_name == "run_shell_command":
        return {**base, "type": "shell", "command": tool_input.get("command", "")}
    if tool_name == "read_file":
        return {**base, "type": "file_read", "path": tool_input.get("file_path") or tool_input.get("path", "")}
    if tool_name in {"write_file", "edit", "replace"}:
        return {
            **base,
            "type": "file_write",
            "path": tool_input.get("file_path") or tool_input.get("path", ""),
            "content": tool_input.get("content") or tool_input.get("new_string", ""),
        }
    if tool_name in {"web_fetch", "web_search"}:
        return {**base, "type": "network", "url": tool_input.get("url", "")}
    mcp_event = _classify_mcp_event(
        base=base,
        tool_name=tool_name,
        tool_input=tool_input,
        response=payload.get("tool_response", payload.get("response")),
        is_post=(hook_event == "PostToolUse"),
        workspace=workspace,
    )
    if mcp_event is not None:
        return mcp_event
    return _unmapped_tool_event(base, payload)


def _normalize_continue(payload: Dict[str, Any], session_id: str, workspace: Path) -> Dict[str, Any]:
    # Continue CLI's hooks payload is intentionally Claude-Code-compatible
    # (same field names AND tool-name convention -- "Bash", "Read", "Edit",
    # ...). NOTE: hooks were not observed to fire at all in headless (`cn -p`)
    # mode in live testing (2026-07, cn v1.5.47) -- this normalizer may never
    # actually receive a payload in that mode. See _merge_continue.
    hook_event = payload.get("hook_event_name", "unknown")
    tool_name = payload.get("tool_name", "")
    tool_input = payload.get("tool_input", {}) or {}
    base = {
        "ts": payload.get("timestamp") or datetime.now(timezone.utc).isoformat(),
        "session_id": session_id,
        "agent": "continue",
        "agent_event": hook_event,
        "metadata": {"cwd": payload.get("cwd"), "tool_name": tool_name, "raw": payload},
    }
    if hook_event == "UserPromptSubmit":
        return {**base, "type": "prompt", "prompt": payload.get("prompt", "")}
    if tool_name == "Bash":
        return {**base, "type": "shell", "command": tool_input.get("command", "")}
    if tool_name == "Read":
        return {**base, "type": "file_read", "path": tool_input.get("file_path") or tool_input.get("path", "")}
    if tool_name in {"Edit", "MultiEdit", "Write"}:
        return {
            **base,
            "type": "file_write",
            "path": tool_input.get("file_path") or tool_input.get("path", ""),
            "content": (
                _join_edits(tool_input.get("edits", []))
                or tool_input.get("content", "")
                or tool_input.get("new_string", "")
            ),
        }
    if tool_name in {"Fetch", "Search"}:
        return {**base, "type": "network", "url": tool_input.get("url", "")}
    mcp_event = _classify_mcp_event(
        base=base,
        tool_name=tool_name,
        tool_input=tool_input,
        response=payload.get("tool_response", payload.get("response")),
        is_post=(hook_event == "PostToolUse"),
        workspace=workspace,
    )
    if mcp_event is not None:
        return mcp_event
    return _unmapped_tool_event(base, payload)


def _normalize_goose(payload: Dict[str, Any], session_id: str) -> Dict[str, Any]:
    # Verified live payload shape (2026-07, goose v1.44.0): field name is
    # "event" (not "hook_event_name"), and the built-in shell tool's real
    # name is "shell" -- NOT "developer__shell" as goose's own official docs
    # example shows. See _merge_goose.
    hook_event = payload.get("event", "unknown")
    tool_name = payload.get("tool_name", "")
    tool_input = payload.get("tool_input", {}) or {}
    base = {
        "ts": payload.get("timestamp") or datetime.now(timezone.utc).isoformat(),
        "session_id": session_id,
        "agent": "goose",
        "agent_event": hook_event,
        "metadata": {"cwd": payload.get("working_dir"), "tool_name": tool_name, "raw": payload},
    }
    if hook_event == "UserPromptSubmit":
        return {**base, "type": "prompt", "prompt": payload.get("message", "")}
    if tool_name == "shell":
        return {**base, "type": "shell", "command": tool_input.get("command", "")}
    if tool_name == "write":
        return {**base, "type": "file_write", "path": tool_input.get("path", ""), "content": tool_input.get("content", "")}
    if tool_name == "edit":
        return {
            **base,
            "type": "file_write",
            "path": tool_input.get("path", ""),
            "content": tool_input.get("after", ""),
        }
    return _unmapped_tool_event(base, payload)


def _merge_claude_entries(entries: List[Dict[str, Any]], new_entry: Dict[str, Any]) -> List[Dict[str, Any]]:
    next_entries = list(entries)
    new_commands = {hook.get("command") for hook in new_entry.get("hooks", [])}
    existing = next((entry for entry in next_entries if entry.get("matcher") == new_entry["matcher"]), None)
    if existing is None:
        # No entry has today's exact matcher, but an older install may already
        # carry our command(s) under a now-stale (narrower) matcher — e.g. a
        # matcher widened to add "Task|Agent" for subagent coverage. Widen that
        # entry's matcher in place rather than appending a duplicate: two
        # entries with the same command would fire the dispatcher twice per
        # tool call. An entry is only ever a migration target if it already
        # runs one of *our* commands — an entry for someone else's tool/command
        # is left untouched.
        existing = next(
            (entry for entry in next_entries if any(h.get("command") in new_commands for h in entry.get("hooks", []))),
            None,
        )
        if existing is None:
            next_entries.append(new_entry)
            return next_entries
        existing["matcher"] = new_entry["matcher"]

    existing_commands = {hook.get("command") for hook in existing.get("hooks", [])}
    for hook in new_entry["hooks"]:
        if hook.get("command") not in existing_commands:
            existing.setdefault("hooks", []).append(hook)
    return next_entries


def _merge_simple_command_entries(entries: List[Dict[str, Any]], command: str) -> List[Dict[str, Any]]:
    next_entries = list(entries)
    if not any(entry.get("command") == command for entry in next_entries):
        next_entries.append({"command": command})
    return next_entries


def _merge_windsurf_entries(entries: List[Dict[str, Any]], command: str, workspace: Path) -> List[Dict[str, Any]]:
    next_entries = list(entries)
    if not any(entry.get("command") == command for entry in next_entries):
        next_entries.append(
            {
                "command": command,
                "show_output": False,
                "working_directory": str(workspace),
            }
        )
    return next_entries


def _read_json(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (ValueError, OSError) as exc:
        # Never fall back to {}: this value is merged and written straight back
        # out, so an unparseable config would be silently replaced by one
        # containing nothing but Prismor's own hook.
        raise HookConfigError(f"{path} is not valid JSON: {exc}") from exc


# ── MCP tool-call classification ─────────────────────────────────────────────
# MCP tool calls arrive as opaque tool names (``mcp__<server>__<tool>``) and
# would otherwise fall through to a generic ``tool_result`` event — bypassing
# the egress allowlist, taint tracking, and clean injection scanning. The
# helpers below resolve the backing server's transport from the agent's MCP
# config and re-shape the event so the existing policy rules apply:
#   • remote (HTTP/SSE) tool *calls*  -> ``network`` event (egress + taint +
#     secret-in-URL/args rules)
#   • tool *responses*                -> clean ``tool_result`` (injection scan)

_MCP_REMOTE_TRANSPORTS = {
    "http", "https", "sse", "streamable-http", "streamable_http",
    "streamablehttp", "ws", "wss", "websocket",
}
_MCP_URL_KEYS = ("url", "endpoint", "serverUrl", "server_url", "uri", "href")

# Per-workspace cache of {server_name_lower: {"url", "transport", "remote"}}.
_mcp_index_cache: Dict[str, Dict[str, Dict[str, Any]]] = {}


def _mcp_endpoint_meta(cfg: Dict[str, Any]) -> Dict[str, Any]:
    """Extract endpoint metadata from a single MCP server config."""
    url = ""
    if isinstance(cfg, dict):
        for k in _MCP_URL_KEYS:
            v = cfg.get(k)
            if isinstance(v, str) and v.strip():
                url = v.strip()
                break
        transport = str(cfg.get("type") or cfg.get("transport") or "").lower()
    else:
        transport = ""
    return {"url": url, "transport": transport,
            "remote": bool(url) or transport in _MCP_REMOTE_TRANSPORTS}


def _mcp_server_index(workspace: Path) -> Dict[str, Dict[str, Any]]:
    """Build (and cache) a name->endpoint map from all discovered MCP configs."""
    key = str(workspace)
    cached = _mcp_index_cache.get(key)
    if cached is not None:
        return cached
    index: Dict[str, Dict[str, Any]] = {}
    try:
        from prismor.runtime.scanner import discover_configs, parse_config
        for cfg in discover_configs(workspace=workspace):
            for entry in parse_config(cfg["path"], agent=cfg["agent"]):
                nm = str(entry.get("name", "")).lower()
                if nm:
                    index[nm] = _mcp_endpoint_meta(entry.get("config") or {})
    except Exception:
        pass
    _mcp_index_cache[key] = index
    return index


def _parse_mcp_tool(tool_name: str) -> Optional[Tuple[str, str]]:
    """Parse ``mcp__<server>__<tool>`` into (server, tool); None if not MCP."""
    if not tool_name or not tool_name.startswith("mcp__"):
        return None
    server, _, tool = tool_name[len("mcp__"):].partition("__")
    return server, tool


def _extract_mcp_response_text(response: Any) -> str:
    """Flatten an MCP tool response into plain text for injection scanning.

    Handles the common content-block shapes (``[{"type":"text","text":...}]``,
    ``{"content":[...]}``) and falls back to a JSON dump.
    """
    if response is None:
        return ""
    if isinstance(response, str):
        return response
    parts: List[str] = []

    def _walk(node: Any) -> None:
        if isinstance(node, str):
            parts.append(node)
        elif isinstance(node, dict):
            text = node.get("text")
            if isinstance(text, str):
                parts.append(text)
            else:
                for v in node.values():
                    _walk(v)
        elif isinstance(node, list):
            for item in node:
                _walk(item)

    _walk(response)
    joined = "\n".join(p for p in parts if p)
    if joined:
        return joined
    try:
        return json.dumps(response, default=str)
    except Exception:
        return str(response)


def _classify_mcp_event(
    *,
    base: Dict[str, Any],
    tool_name: str,
    tool_input: Any,
    response: Any,
    is_post: bool,
    workspace: Path,
) -> Optional[Dict[str, Any]]:
    """Re-shape an MCP tool call/response into a policy-aware event.

    Returns ``None`` when ``tool_name`` is not an MCP tool, so callers fall
    through to their default classification.
    """
    parsed = _parse_mcp_tool(tool_name)
    if parsed is None:
        return None
    server, mcp_tool = parsed
    meta = _mcp_server_index(workspace).get(server.lower(), {})
    url = meta.get("url", "")
    remote = bool(meta.get("remote"))
    mcp_meta = {"mcp_server": server, "mcp_tool": mcp_tool}

    if is_post:
        # Tool output is untrusted remote content — scan it as a tool_result
        # so the prompt-injection rules and HTML sanitizer apply cleanly.
        event = {**base, "type": "tool_result",
                 "response": _extract_mcp_response_text(response), **mcp_meta}
        if url:
            event["url"] = url
        return event

    # Pre-call. Serialize arguments so secret-in-args detection can see them.
    try:
        args_text = json.dumps(tool_input, default=str)
    except Exception:
        args_text = str(tool_input)

    if remote and url:
        # Route through the network path: egress allowlist, raw-IP, suspicious
        # destination, secret-in-URL, taint escalation, and (via outbound_payload)
        # enrolled-secret-in-arguments checks all apply.
        return {**base, "type": "network", "url": url,
                "outbound_payload": args_text, **mcp_meta}

    # Local stdio MCP server: keep arguments visible to injection rules.
    return {**base, "type": "tool_result", "response": args_text, **mcp_meta}


import re as _re

# Project-memory / agent-instruction files auto-loaded by the agent at session
# start. Their directives are trusted implicitly by the model, so Prismor treats
# them as an untrusted content source (issue #155). CLAUDE.md/AGENTS.md were the
# original two; every entry below is an equally auto-loaded instruction surface
# for *some* agent, so scanning only the first two left the rest unguarded (#153).
#
# Two shapes, handled differently by _discover_memory_files:
#   - bare basenames, looked up directly in each search directory
#   - globs, expanded relative to a search directory (rule/agent directories
#     hold many files, and the set is not known ahead of time)
_MEMORY_BASENAMES: Tuple[str, ...] = (
    "CLAUDE.md",
    "CLAUDE.local.md",
    "AGENTS.md",
    "GEMINI.md",
    ".cursorrules",
    ".windsurfrules",
    ".clinerules",
)
_MEMORY_GLOBS: Tuple[str, ...] = (
    ".claude/rules/*.md",
    ".claude/agents/*.md",
    ".cursor/rules/*.mdc",
    ".github/copilot-instructions.md",
    ".devin/rules/*.md",
    ".windsurf/rules/*.md",
    ".roo/rules/*.md",
    ".augment/rules/*.md",
    "**/.github/copilot-instructions.md",
)
_MEMORY_PATH_PATTERNS: Tuple[str, ...] = _MEMORY_BASENAMES + _MEMORY_GLOBS
# Cap total scanned memory content so a huge memory file can't blow the OS
# argument limit / telemetry payload. Detection patterns fire on the leading
# directive-shaped text; a truncated tail is acceptable — and now flagged, via
# the `truncated` metadata field, so an oversized file is itself a signal.
_MEMORY_SCAN_LIMIT = 64_000
_MEMORY_SCAN_LIMIT_MIN = 4_096
_MEMORY_SCAN_LIMIT_MAX = 4_194_304
# Cap the number of files a single scan opens. The rule/agent globs can expand
# without bound in a large repo, and SessionStart is on the interactive path.
_MEMORY_MAX_FILES = 64

# Invisible / formatting codepoints that carry no meaning in an instruction file
# but do hide text from a human reviewer — the TrapDoor technique. Structural
# signal only: presence is reported as metadata, the content is still scanned
# normally (and _fold_confusables strips these before the rescan).
#
# Deliberately EXCLUDES U+200D (ZWJ), which is load-bearing in emoji sequences,
# and every CJK/Hangul codepoint that renders as real text. The Hangul fillers
# (U+115F/U+1160), Braille blank (U+2800), Hangul filler (U+3164) and halfwidth
# Hangul filler (U+FFA0) ARE included: they live in CJK blocks but render as
# nothing, which is exactly what makes them useful for hiding a directive.
_INVISIBLE_CONTROL_RE = _re.compile(
    "[\u202a-\u202e"    # bidi embedding/override controls (Trojan Source)
    "\u2066-\u2069"    # bidi isolates
    "\u200b\u200c\u200e\u200f"  # ZWSP, ZWNJ, LRM, RLM -- NOT U+200D (ZWJ),
                                  # which is load-bearing in emoji sequences
    "\u2060-\u2064"    # word joiner + invisible operators
    "\ufeff\u00ad\u180e"  # BOM, soft hyphen, Mongolian vowel separator
    "\ufff0-\ufffb"    # unassigned + interlinear annotation controls
    "\u115f\u1160\u2800\u3164\uffa0"  # blank-rendering CJK/Braille fillers
    "]"
)


def _memory_scan_limit() -> int:
    """Byte cap for a single project-memory scan.

    Defaults to ``_MEMORY_SCAN_LIMIT`` and is overridable with
    ``PRISMOR_MEMORY_SCAN_LIMIT`` for repos whose instruction files legitimately
    run long. Clamped to [4KiB, 4MiB]; an unparseable value falls back to the
    default rather than failing the hook.
    """
    raw = os.environ.get("PRISMOR_MEMORY_SCAN_LIMIT")
    if not raw:
        return _MEMORY_SCAN_LIMIT
    try:
        value = int(raw.strip())
    except (TypeError, ValueError):
        return _MEMORY_SCAN_LIMIT
    return max(_MEMORY_SCAN_LIMIT_MIN, min(_MEMORY_SCAN_LIMIT_MAX, value))


def _instructions_loaded_paths() -> set:
    """Instruction-file paths the agent itself reported loading, if it tells us.

    Claude Code's InstructionsLoaded hook data names the files actually pulled
    into context, which is authoritative in a way glob discovery can never be —
    it covers imports, user-level config and any location Prismor doesn't know
    to look. Feature-detected and purely ADDITIVE: this is unioned with glob
    discovery, and an environment that doesn't publish the data yields an empty
    set, leaving behaviour exactly as it was.

    Read from ``PRISMOR_INSTRUCTIONS_LOADED`` (a JSON array of paths, or an
    os.pathsep-separated list) or from a JSON file named by
    ``PRISMOR_INSTRUCTIONS_LOADED_FILE``. Best-effort; never raises.
    """
    raw = os.environ.get("PRISMOR_INSTRUCTIONS_LOADED", "")
    if not raw:
        path_env = os.environ.get("PRISMOR_INSTRUCTIONS_LOADED_FILE", "")
        if not path_env:
            return set()
        try:
            raw = Path(path_env).read_text(encoding="utf-8", errors="replace")
        except Exception:
            return set()

    raw = raw.strip()
    if not raw:
        return set()

    entries: List[Any] = []
    if raw[0] in "[{":
        try:
            parsed = json.loads(raw)
        except Exception:
            return set()
        if isinstance(parsed, dict):
            parsed = parsed.get("paths") or parsed.get("files") or []
        if isinstance(parsed, list):
            entries = parsed
    else:
        entries = [p for p in raw.split(os.pathsep) if p]

    out: set = set()
    for entry in entries:
        if isinstance(entry, dict):
            entry = entry.get("path") or entry.get("file") or ""
        if isinstance(entry, str) and entry.strip():
            out.add(entry.strip())
    return out


def _discover_memory_files(workspace: Path) -> List[Path]:
    """Enumerate the instruction files an agent auto-loads for ``workspace``.

    Searches the workspace and its three nearest ancestors (project-scoped
    memory) plus the user's ~/.claude directory (global memory), matching every
    entry in ``_MEMORY_PATH_PATTERNS``, and unions in anything the agent
    reported loading itself (see ``_instructions_loaded_paths``).

    Recursive (``**``) globs are expanded ONLY under the workspace itself —
    running one against an ancestor would walk large parts of the filesystem on
    the interactive SessionStart path. Returns at most ``_MEMORY_MAX_FILES``
    paths, de-duplicated by resolved target and stable in search order.
    """
    search_dirs: List[Path] = []
    try:
        ws = workspace.resolve()
        search_dirs.append(ws)
        search_dirs.extend(ws.parents[:3])
    except Exception:
        ws = workspace
        search_dirs.append(workspace)
    search_dirs.append(Path.home() / ".claude")

    seen: set = set()
    found: List[Path] = []

    def _add(candidate: Path) -> bool:
        """Record ``candidate`` if it's a new, readable file. False when full."""
        if len(found) >= _MEMORY_MAX_FILES:
            return False
        try:
            if not candidate.is_file():
                return True
            resolved = candidate.resolve()
        except Exception:
            return True
        if resolved in seen:
            return True
        seen.add(resolved)
        found.append(candidate)
        return len(found) < _MEMORY_MAX_FILES

    for directory in search_dirs:
        for pattern in _MEMORY_PATH_PATTERNS:
            if "*" not in pattern:
                if not _add(directory / pattern):
                    return found
                continue
            if pattern.startswith("**") and directory != ws:
                continue
            try:
                matches = directory.glob(pattern)
            except Exception:
                continue
            try:
                for match in matches:
                    if not _add(match):
                        return found
            except Exception:
                # A permission error mid-walk must not lose the files already
                # discovered, nor abort the remaining patterns.
                continue

    for reported in _instructions_loaded_paths():
        if not _add(Path(reported)):
            return found

    return found


def _read_memory_file(path: Path) -> Optional[str]:
    """Read one instruction file, or None if it can't be read.

    Decoding is lossy-but-total (``errors="replace"``) so a file with a stray
    non-UTF-8 byte is still scanned rather than silently skipped — a scan that
    drops a file is a detection gap, which is worse than imperfect bytes.
    """
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return None


def _read_project_memory(workspace: Path) -> Dict[str, Any]:
    """Collect the instruction-file content the agent loads at session start.

    Returns the concatenated text, the list of files it came from, and:

    ``truncated``
        the combined content hit the scan limit, so a tail went unscanned
    ``has_invisible_controls``
        some file contains invisible/zero-width codepoints (computed over each
        file's FULL text, before truncation, so a payload hidden past the limit
        still raises the flag)
    ``digests``
        per-file content fingerprint (``scanner.text_fingerprint``), used by
        the drift check in ``runtime.evaluate_tool_call``
        (``scanner.check_memory_drift``) — computed over the untruncated
        per-file text so a change past the scan limit is still caught.

    Best-effort throughout: unreadable files are skipped rather than failing the
    hook.
    """
    parts: List[str] = []
    files: List[str] = []
    digests: Dict[str, str] = {}
    has_invisible = False

    discovered = _discover_memory_files(workspace)
    for candidate in discovered:
        text = _read_memory_file(candidate)
        if text is None:
            continue
        if not has_invisible and _INVISIBLE_CONTROL_RE.search(text):
            has_invisible = True
        files.append(str(candidate))
        parts.append(f"# {candidate}\n{text}")
        try:
            from prismor.runtime.scanner import text_fingerprint
            digests[str(candidate)] = text_fingerprint(text)
        except Exception:
            pass

    limit = _memory_scan_limit()
    joined = "\n\n".join(parts)
    content = joined[:limit]
    return {
        "content": content,
        "files": files,
        "digests": digests,
        "truncated": len(joined) > limit or len(discovered) >= _MEMORY_MAX_FILES,
        "has_invisible_controls": has_invisible,
    }


def _normalize_claude(payload: Dict[str, Any], session_id: str, workspace: Path) -> Dict[str, Any]:
    hook_event = payload.get("hook_event_name", "unknown")
    tool_name = payload.get("tool_name", "")
    tool_input = payload.get("tool_input", {})
    base = {
        "ts": payload.get("timestamp") or datetime.now(timezone.utc).isoformat(),
        "session_id": session_id,
        "agent": "claude",
        "agent_event": hook_event,
        "metadata": {
            "cwd": payload.get("cwd"),
            "tool_name": tool_name,
            # Claude tags tool calls made *inside* a spawned subagent with the
            # subagent's id/persona. These are absent on main-agent calls, so
            # promoting them here lets telemetry attribute an action to the
            # subagent that took it instead of flattening it into the parent.
            "subagent_id": payload.get("agent_id"),
            "subagent_type": payload.get("agent_type"),
            "raw": payload,
        },
    }
    if hook_event == "SessionStart":
        # payload["cwd"] is the live directory of *this* session, sent by
        # Claude on every hook call. `workspace` is whatever was configured
        # at `install-hooks` time (often a fixed dir for --scope user
        # installs) — falling back to it when cwd is absent, but preferring
        # cwd means the scan actually covers the project the agent is
        # running in, not wherever hooks happened to be installed from. See
        # PrismorSec/prismor#155 follow-up: a user-scope install pointed at
        # $HOME meant every session's memory scan silently read $HOME's
        # CLAUDE.md instead of the real project's, regardless of cwd.
        raw_cwd = payload.get("cwd")
        memory_root = Path(raw_cwd) if raw_cwd else workspace
        memory = _read_project_memory(memory_root)
        base["metadata"]["memory_files"] = memory["files"]
        # Structural facts about the scan itself, matched directly by the
        # memory-invisible-text / memory-oversized-instruction-file rules (#153).
        base["metadata"]["truncated"] = memory["truncated"]
        base["metadata"]["has_invisible_controls"] = memory["has_invisible_controls"]
        # Per-file content fingerprints for the drift check in
        # runtime.evaluate_tool_call (scanner.check_memory_drift).
        base["metadata"]["memory_digests"] = memory["digests"]
        # Integrity check (#154): verify instruction files against TOFU baseline.
        # Runs after content scanning — integrity findings supplement, never
        # replace, the content-based rules above. All integrity actions are
        # warn-level; mismatches feed the counter-instruction in cli.py.
        _read_entries = [{"path": p} for p in memory.get("files", [])]
        if _read_entries:
            from prismor.runtime.memory_guard import verify_memory_files
            _integrity_findings = verify_memory_files(_read_entries, memory_root)
            base.setdefault("integrity_findings", []).extend(_integrity_findings)
        return {**base, "type": "memory", "content": memory["content"]}
    if hook_event == "UserPromptSubmit":
        return {**base, "type": "prompt", "prompt": payload.get("prompt", "")}
    if tool_name in {"Task", "Agent"}:
        # Subagent-spawn (named "Task" in the hook matcher, surfaced as "Agent"
        # in newer Claude payloads). The delegated charter (prompt + description) is
        # untrusted instruction text that will drive an autonomous agent, so it
        # is scanned by the same content rules as a user prompt / tool output
        # (see _UNTRUSTED_CONTENT_ALIASES in policy_engine.py). subagent_type
        # names the persona being launched.
        return {
            **base,
            "type": "subagent_spawn",
            "subagent_type": tool_input.get("subagent_type", ""),
            "description": tool_input.get("description", ""),
            "prompt": tool_input.get("prompt", ""),
        }
    if tool_name == "Bash":
        return {**base, "type": "shell", "command": tool_input.get("command", ""), "stdout": payload.get("stdout", ""), "stderr": payload.get("stderr", "")}
    if tool_name == "Read":
        return {**base, "type": "file_read", "path": tool_input.get("file_path") or tool_input.get("path", "")}
    if tool_name in {"Edit", "MultiEdit", "Write"}:
        return {
            **base,
            "type": "file_write",
            "path": tool_input.get("file_path") or tool_input.get("path", ""),
            # A plain single Edit call (as opposed to MultiEdit) has shape
            # {file_path, old_string, new_string} — no "edits" list and no
            # "content" key — so new_string must be its own fallback or the
            # written text is invisible to every content-based check.
            "content": (
                _join_edits(tool_input.get("edits", []))
                or tool_input.get("content", "")
                or tool_input.get("new_string", "")
            ),
        }
    if tool_name in {"WebFetch", "WebSearch"}:
        return {**base, "type": "network", "url": tool_input.get("url", ""), "response": payload.get("response", "")}
    mcp_event = _classify_mcp_event(
        base=base,
        tool_name=tool_name,
        tool_input=tool_input,
        response=payload.get("tool_response", payload.get("response")),
        is_post=(hook_event == "PostToolUse"),
        workspace=workspace,
    )
    if mcp_event is not None:
        return mcp_event
    return _unmapped_tool_event(base, payload)


def _normalize_windsurf(payload: Dict[str, Any], session_id: str, workspace: Path) -> Dict[str, Any]:
    hook_event = payload.get("agent_action_name", "unknown")
    tool_info = payload.get("tool_info", {})
    base = {
        "ts": payload.get("timestamp") or datetime.now(timezone.utc).isoformat(),
        "session_id": session_id,
        "agent": "windsurf",
        "agent_event": hook_event,
        "metadata": {"execution_id": payload.get("execution_id"), "raw": payload},
    }
    if hook_event == "pre_user_prompt":
        return {**base, "type": "prompt", "prompt": tool_info.get("prompt", "")}
    if "run_command" in hook_event:
        return {**base, "type": "shell", "command": tool_info.get("command", ""), "stdout": tool_info.get("stdout", ""), "stderr": tool_info.get("stderr", "")}
    if "read_code" in hook_event:
        return {**base, "type": "file_read", "path": tool_info.get("file_path", "")}
    if "write_code" in hook_event:
        return {**base, "type": "file_write", "path": tool_info.get("file_path", ""), "content": _join_edits(tool_info.get("edits", []))}
    if "mcp_tool_use" in hook_event:
        server = str(tool_info.get("server") or tool_info.get("server_name") or "")
        tool = str(tool_info.get("tool") or tool_info.get("tool_name") or tool_info.get("name") or "")
        synthetic = f"mcp__{server}__{tool}" if server else f"mcp__{tool}__{tool}"
        mcp_event = _classify_mcp_event(
            base=base,
            tool_name=synthetic,
            tool_input=tool_info.get("arguments") or tool_info.get("args") or tool_info.get("input") or {},
            response=tool_info.get("result") or tool_info.get("response") or tool_info.get("output"),
            is_post=hook_event.startswith("post"),
            workspace=workspace,
        )
        if mcp_event is not None:
            # Windsurf configs may carry the endpoint inline on the call.
            if mcp_event.get("type") == "network" and not mcp_event.get("url"):
                inline = str(tool_info.get("url") or tool_info.get("endpoint") or "")
                if inline:
                    mcp_event["url"] = inline
            return mcp_event
    return _unmapped_tool_event(base, payload)


def _normalize_cursor(payload: Dict[str, Any], session_id: str) -> Dict[str, Any]:
    hook_event = (
        payload.get("hook_event_name")
        or payload.get("hookEventName")
        or payload.get("event_name")
        or payload.get("eventName")
        or payload.get("event")
        or "unknown"
    )
    base = {
        "ts": payload.get("timestamp") or datetime.now(timezone.utc).isoformat(),
        "session_id": session_id,
        "agent": "cursor",
        "agent_event": hook_event,
        "metadata": {"raw": payload},
    }
    if "prompt" in hook_event.lower():
        return {**base, "type": "prompt", "prompt": payload.get("prompt") or payload.get("message", "")}
    if "shell" in hook_event.lower():
        return {**base, "type": "shell", "command": payload.get("command") or payload.get("commandLine") or ""}
    if "write" in hook_event.lower():
        return {**base, "type": "file_write", "path": payload.get("path") or payload.get("filePath") or "", "content": payload.get("content", "")}
    if "read" in hook_event.lower():
        return {**base, "type": "file_read", "path": payload.get("path") or payload.get("filePath") or ""}
    return _unmapped_tool_event(base, payload)


def _normalize_hermes(payload: Dict[str, Any], session_id: str) -> Dict[str, Any]:
    hook_event = payload.get("hookEvent", "before_tool_call")
    tool_name = payload.get("toolName", "")
    tool_input = payload.get("toolInput", {})
    base = {
        "ts": payload.get("timestamp") or datetime.now(timezone.utc).isoformat(),
        "session_id": session_id,
        "agent": "hermes",
        "agent_event": hook_event,
        # tool_name is what `prismor tags list` / tag-rule classification key
        # off (trifecta._tool_name); omitting it made every hermes tool
        # invisible to tool-tagging and to the unmapped-tool signal.
        "metadata": {
            "gatewayId": payload.get("gatewayId"),
            "tool_name": tool_name,
            "raw": payload,
        },
    }
    if hook_event == "message_received":
        return {**base, "type": "prompt", "prompt": tool_input.get("content", "")}
    if hook_event == "message_sending":
        return {**base, "type": "tool_result", "response": tool_input.get("content", "")}
    if tool_name in {"Bash", "shell", "exec"}:
        return {**base, "type": "shell", "command": tool_input.get("command", "")}
    if tool_name in {"FileRead", "Read", "read"}:
        return {**base, "type": "file_read", "path": tool_input.get("file_path") or tool_input.get("path", "")}
    if tool_name in {"FileWrite", "FileEdit", "Write", "Edit", "write"}:
        return {**base, "type": "file_write", "path": tool_input.get("file_path") or tool_input.get("path", ""), "content": tool_input.get("content", "")}
    if tool_name in {"WebFetch", "WebSearch", "web_search", "browser"}:
        return {**base, "type": "network", "url": tool_input.get("url", "")}
    return _unmapped_tool_event(base, payload)


def _normalize_openclaw(payload: Dict[str, Any], session_id: str) -> Dict[str, Any]:
    hook_event = payload.get("hookEvent", "before_tool_call")
    tool_name = payload.get("toolName", "")
    tool_input = payload.get("toolInput", {})
    base = {
        "ts": payload.get("timestamp") or datetime.now(timezone.utc).isoformat(),
        "session_id": session_id,
        "agent": "openclaw",
        "agent_event": hook_event,
        # See the hermes adapter: tool_name must be recorded here or the tool
        # is invisible to tag classification and the unmapped-tool signal.
        "metadata": {
            "agentId": payload.get("agentId"),
            "tool_name": tool_name,
            "raw": payload,
        },
    }
    if hook_event == "message_received":
        return {**base, "type": "prompt", "prompt": tool_input.get("content", "")}
    if hook_event == "message_sending":
        return {**base, "type": "tool_result", "response": tool_input.get("content", "")}
    if tool_name in {"Bash", "shell", "exec"}:
        return {**base, "type": "shell", "command": tool_input.get("command", "")}
    if tool_name in {"FileRead", "Read", "read"}:
        return {**base, "type": "file_read", "path": tool_input.get("file_path") or tool_input.get("path", "")}
    if tool_name in {"FileWrite", "FileEdit", "Write", "Edit", "write"}:
        return {**base, "type": "file_write", "path": tool_input.get("file_path") or tool_input.get("path", ""), "content": tool_input.get("content", "")}
    if tool_name in {"WebFetch", "WebSearch", "web_search", "browser"}:
        return {**base, "type": "network", "url": tool_input.get("url", "")}
    return _unmapped_tool_event(base, payload)


def _normalize_opencode(payload: Dict[str, Any], session_id: str) -> Dict[str, Any]:
    hook_event = payload.get("hookEvent", "tool.execute.before")
    tool_name = payload.get("toolName", "")
    tool_input = payload.get("toolInput", {})
    base = {
        "ts": payload.get("timestamp") or datetime.now(timezone.utc).isoformat(),
        "session_id": session_id,
        "agent": "opencode",
        "agent_event": hook_event,
        "metadata": {"raw": payload},
    }
    if tool_name in {"bash", "shell", "exec", "terminal", "Bash"}:
        return {**base, "type": "shell", "command": tool_input.get("command", "")}
    if tool_name in {"read", "file_read", "FileRead", "Read"}:
        return {**base, "type": "file_read", "path": tool_input.get("file_path") or tool_input.get("path", "")}
    if tool_name in {"write", "edit", "file_write", "FileWrite", "Write", "Edit"}:
        return {**base, "type": "file_write", "path": tool_input.get("file_path") or tool_input.get("path", ""), "content": tool_input.get("content", "")}
    if tool_name in {"fetch", "search", "web_fetch", "web_search", "browser"}:
        return {**base, "type": "network", "url": tool_input.get("url", "")}
    return {**base, "type": "tool_result", "response": json.dumps(payload)}


# ── Gemini CLI adapter ────────────────────────────────────────────────────────
#
# Gemini CLI (google-gemini/gemini-cli) uses the same Claude-style nested hook
# config shape:
#
#   settings.json -> {"hooks": {"BeforeTool": [{"matcher": "...", "hooks":
#                       [{"type": "command", "name": "prismor", "command": "..."}]}]}}
#
# Config locations:
#   project:  <workspace>/.gemini/settings.json
#   global:   ~/.gemini/settings.json
#
# Blocking: exit 2 blocks the tool call; stderr is surfaced to the user as the
# rejection reason. Same convention as Claude Code / Codex / Grok.
#
# Not yet verified against a live `gemini` binary. Built from the public
# Gemini CLI hooks documentation at https://geminicli.com/docs/hooks/reference/
# and the Google Developers Blog launch post. Before relying on this in
# `enforce` mode, run `gemini` and confirm a deliberately blocked command is
# actually denied end-to-end.


def _strip_gemini(config: Dict[str, Any], marker: str) -> tuple[Dict[str, Any], bool]:
    """Remove Prismor hook entries from a Gemini CLI settings.json config.

    Gemini CLI uses the same nested Claude-shape hook entries
    (list of {matcher, hooks:[{type, command}]} per event), so the
    strip logic mirrors _strip_claude but operates on Gemini's event names.
    """
    hooks = dict(config.get("hooks", {}))
    removed = False
    for event_name in list(hooks.keys()):
        entries = hooks[event_name]
        if not isinstance(entries, list):
            continue
        cleaned = []
        for entry in entries:
            inner_hooks = entry.get("hooks", [])
            filtered = [h for h in inner_hooks if marker not in h.get("command", "")]
            if len(filtered) < len(inner_hooks):
                removed = True
            if filtered:
                cleaned.append({**entry, "hooks": filtered})
        hooks[event_name] = cleaned
    return {**config, "hooks": hooks}, removed


def _merge_gemini(config: Dict[str, Any], command: str) -> Dict[str, Any]:
    """Inject Prismor hooks into a Gemini CLI settings.json config.

    Hooks three event types:
      BeforeTool   -- pre-action; exit-2 blocks the tool call.
      AfterTool    -- post-action; recorded for session audit.
      SessionStart -- scans project-memory files (GEMINI.md / AGENTS.md) on
                      session open, same as the Claude Code SessionStart hook.

    Matcher covers all built-in Gemini CLI tools plus MCP tools
    (mcp__<server>__<tool> namespace).
    """
    hooks = dict(config.get("hooks", {}))
    # BeforeTool is the only blocking event: exit-2 from the hook stops
    # the tool call before execution. AfterTool fires after and is
    # recorded for audit only.
    for event_name in ["BeforeTool", "AfterTool"]:
        hooks[event_name] = _merge_claude_entries(
            hooks.get(event_name, []),
            {
                "matcher": "run_shell_command|read_file|write_file|replace_in_file|web_fetch|web_search|mcp__.*",
                "hooks": [{"type": "command", "name": "prismor", "command": command}],
            },
        )
    # SessionStart: scan project-memory files (GEMINI.md / AGENTS.md) for
    # injected directives at the start of every session, same rationale as
    # the Claude Code SessionStart hook (see PrismorSec/prismor#155).
    hooks["SessionStart"] = _merge_claude_entries(
        hooks.get("SessionStart", []),
        {
            "matcher": "*",
            "hooks": [{"type": "command", "name": "prismor", "command": command}],
        },
    )
    return {**config, "hooks": hooks}


def _normalize_gemini(payload: Dict[str, Any], session_id: str, workspace: Path) -> Dict[str, Any]:
    """Translate a Gemini CLI hook stdin payload into a Prismor event.

    Gemini CLI sends JSON on stdin with these fields:
      hook_event_name  -- "BeforeTool" | "AfterTool" | "SessionStart" | ...
      tool_name        -- built-in tool name or mcp__<server>__<tool>
      tool_input       -- dict of tool arguments
      session_id       -- stable session identifier
      transcript_path  -- path to the session transcript file
      cwd              -- working directory at hook-dispatch time
      timestamp        -- ISO-8601 string

    Built-in tool names and their Prismor event-type mappings:
      run_shell_command  -> shell     (field: command)
      read_file          -> file_read (fields: absolute_path, file_path, path)
      write_file         -> file_write (fields: file_path, content)
      replace_in_file    -> file_write (fields: file_path, diff)
      web_fetch          -> network   (field: url)
      web_search         -> network   (field: query)
    """
    hook_event = payload.get("hook_event_name", "unknown")
    tool_name = payload.get("tool_name", "")
    tool_input = payload.get("tool_input", {})
    base = {
        "ts": payload.get("timestamp") or datetime.now(timezone.utc).isoformat(),
        "session_id": session_id,
        "agent": "gemini",
        "agent_event": hook_event,
        "metadata": {
            "cwd": payload.get("cwd"),
            "tool_name": tool_name,
            "transcript_path": payload.get("transcript_path"),
            "raw": payload,
        },
    }

    if hook_event == "SessionStart":
        # Scan project-memory files (GEMINI.md / AGENTS.md) for injected
        # directives, same as the Claude Code SessionStart hook.
        raw_cwd = payload.get("cwd")
        memory_root = Path(raw_cwd) if raw_cwd else workspace
        memory = _read_project_memory(memory_root)
        base["metadata"]["memory_files"] = memory["files"]
        base["metadata"]["memory_digests"] = memory["digests"]
        return {**base, "type": "memory", "content": memory["content"]}

    if hook_event in {"BeforeAgent", "AfterAgent"}:
        return {**base, "type": "prompt", "prompt": payload.get("prompt", "")}

    if tool_name == "run_shell_command":
        return {
            **base,
            "type": "shell",
            "command": tool_input.get("command", ""),
            "stdout": payload.get("stdout", ""),
            "stderr": payload.get("stderr", ""),
        }

    if tool_name == "read_file":
        return {
            **base,
            "type": "file_read",
            # Gemini CLI exposes the path as "absolute_path" on read_file
            # and falls back to "file_path" / generic "path" for consistency.
            "path": (
                tool_input.get("absolute_path")
                or tool_input.get("file_path")
                or tool_input.get("path", "")
            ),
        }

    if tool_name in {"write_file", "replace_in_file"}:
        return {
            **base,
            "type": "file_write",
            "path": (
                tool_input.get("file_path")
                or tool_input.get("absolute_path")
                or tool_input.get("path", "")
            ),
            # replace_in_file sends a unified diff in "diff"; write_file
            # sends the full file body in "content".
            "content": tool_input.get("content") or tool_input.get("diff", ""),
        }

    if tool_name == "web_fetch":
        return {
            **base,
            "type": "network",
            "url": tool_input.get("url", ""),
            "response": payload.get("response", ""),
        }

    if tool_name == "web_search":
        return {
            **base,
            "type": "network",
            # web_search has no URL; use the query string so policy rules
            # that match on `url` can still inspect the search terms.
            "url": tool_input.get("query", ""),
        }

    mcp_event = _classify_mcp_event(
        base=base,
        tool_name=tool_name,
        tool_input=tool_input,
        response=payload.get("tool_response", payload.get("response")),
        is_post=(hook_event == "AfterTool"),
        workspace=workspace,
    )
    if mcp_event is not None:
        return mcp_event

    return _unmapped_tool_event(base, payload)

def _ephemeral_session_id(agent: str, workspace: Path) -> str:
    digest = hashlib.sha1(f"{agent}:{workspace}:{os.getpid()}".encode("utf-8")).hexdigest()[:12]
    return f"{agent}-{digest}"

def _join_edits(edits: List[Dict[str, Any]]) -> str:
    return "\n".join(edit.get("new_string") or edit.get("newText") or "" for edit in edits if isinstance(edit, dict))


def _is_pre_action(agent_event: str) -> bool:
    lower = agent_event.lower()
    return (
        lower.startswith("pre")
        or lower.startswith("before")
        or agent_event in {"PreToolUse", "UserPromptSubmit", "PermissionRequest"}
    )
