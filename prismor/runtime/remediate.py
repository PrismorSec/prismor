"""Turn a shadow-AI finding into the action that governs it.

``prismor discover`` answers "what is running that Prismor does not govern".
This module answers the only follow-up that matters: make it governed.

There is exactly one way to govern an agent Prismor is not hooked into, and it
is not to constrain it — every enforcement surface in the runtime (egress
screening, the Docker sandbox, tool denies, kill switches) sits downstream of a
hook payload, so an unhooked agent produces no event and nothing to act on.
Governing shadow AI therefore means *eliminating the shadow*: install the hook,
move the MCP server behind the gateway, vault the key.

Three levers, one per surface:

    agent       hooks.install_hooks          — shadow agent becomes governed
    mcp         mcp_gateway.install_gateway  — servers move behind the gateway
    credential  cloaking.add_env_secrets     — the key becomes a placeholder

Everything this module cannot fix is reported as *skipped with a reason*, never
silently dropped. A remediation tool that quietly does less than it claims is
worse than one that does nothing, because the report is what the operator then
believes.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

#: Filenames ``cloaking.parse_env_file`` can actually read. The credential
#: sweep also flags keys inside JSON/TOML agent configs, which are real
#: findings but not importable by the dotenv parser.
_DOTENV_NAMES = (".env", ".env.local", ".env.development", ".env.production")

FIXABLE_KINDS = ("agent", "mcp", "credential")


@dataclass
class Remediation:
    """One attempted (or declined) fix."""

    kind: str            # agent | mcp | credential
    target: str          # agent name, server name, or provider
    #: planned | fixed | skipped | failed
    status: str
    detail: str = ""
    #: the command a human would run to do this by hand
    command: str = ""
    #: machine-readable subject of the action — the agent id, or the path to
    #: the config/dotenv file. Kept separate from ``detail`` so applying a plan
    #: never has to parse a sentence written for a human.
    subject: str = ""

    @property
    def ok(self) -> bool:
        return self.status == "fixed"


@dataclass
class RemediationPlan:
    """What ``--fix`` would do, before it does any of it."""

    actions: List[Remediation] = field(default_factory=list)

    @property
    def fixable(self) -> List[Remediation]:
        return [a for a in self.actions if a.status == "planned"]

    @property
    def skipped(self) -> List[Remediation]:
        return [a for a in self.actions if a.status == "skipped"]


def _is_dotenv(path: str) -> bool:
    name = Path(path).name
    return name in _DOTENV_NAMES or name.startswith(".env")


def _why_not_migratable(path: Path) -> Optional[str]:
    """Reason this config cannot be moved behind the gateway, or None.

    Read-only, so planning stays pure. The check is the file's *shape*: a
    migration rewrites a file the developer owns, so an unrecognised layout
    must mean "leave it alone", never "guess". Zed's ``context_servers`` and
    Codex's TOML are the live examples.
    """
    if path.suffix.lower() == ".toml":
        return "a TOML config the gateway migration cannot rewrite; move it by hand"
    if not path.exists():
        return "the file no longer exists"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (ValueError, OSError):
        return "the file could not be parsed as JSON; move it by hand"
    if not isinstance(data, dict):
        return "the file is not a JSON object"
    try:
        from prismor.runtime.mcp_gateway import _MCP_BLOCK_KEYS
    except Exception:
        _MCP_BLOCK_KEYS = ("mcpServers", "servers")
    if not any(isinstance(data.get(k), dict) and data.get(k) for k in _MCP_BLOCK_KEYS):
        return ("its servers are not under a recognised mcpServers/servers block; "
                "move it by hand")
    return None


# ── planning ─────────────────────────────────────────────────────────────────


def plan(report: Dict[str, Any], *, kinds: Iterable[str] = FIXABLE_KINDS) -> RemediationPlan:
    """Decide what is fixable, without touching anything.

    Separated from ``apply`` so the CLI can show the operator exactly what is
    about to happen to their machine before it happens — this writes to agent
    config files, and a surprise there is expensive to unpick.
    """
    wanted = set(kinds)
    out = RemediationPlan()

    if "agent" in wanted:
        for agent in report.get("agents") or []:
            if agent.get("managed"):
                continue
            name = str(agent.get("name") or agent.get("id") or "")
            agent_id = str(agent.get("id") or "")
            if not agent.get("coverable", True):
                out.actions.append(Remediation(
                    kind="agent", target=name, status="skipped",
                    detail="Prismor has no hook for this agent — it cannot be governed here",
                ))
                continue
            out.actions.append(Remediation(
                kind="agent", target=name, status="planned",
                detail=f"install the global hook for {agent_id}",
                command=f"prismor install-hooks --agent {agent_id} --scope global",
                subject=agent_id,
            ))

    if "mcp" in wanted or "mcp_unused" in wanted:
        # Decided per source FILE, not per server: one migration moves every
        # server in a file, and the answer to "can this be migrated" is a
        # property of the file's shape.
        verdicts: Dict[str, Optional[str]] = {}
        for server in report.get("mcp") or []:
            if server.get("managed") or server.get("is_gateway"):
                continue
            name = str(server.get("name") or "")
            source = str(server.get("source") or "")
            if server.get("rarely_used") and "mcp_unused" in wanted:
                # Every session starts it and almost none use it: take it out
                # of the user-level config rather than govern it in place.
                out.actions.append(Remediation(
                    kind="mcp_unused", target=name, status="planned",
                    detail=(f"remove from {source} — {server.get('running')} copies, "
                            f"{server.get('rss_mb')} MB, called in {server.get('sessions_used')} "
                            f"of {server.get('sessions_total')} sessions (backup kept)"),
                    command=f"claude mcp remove {name} -s user",
                    subject=source,
                ))
                continue
            if "mcp" not in wanted:
                continue
            if source not in verdicts:
                verdicts[source] = _why_not_migratable(Path(source))
            reason = verdicts[source]
            if reason:
                out.actions.append(Remediation(
                    kind="mcp", target=name, status="skipped",
                    detail=f"declared in {source} — {reason}",
                ))
                continue
            out.actions.append(Remediation(
                kind="mcp", target=name, status="planned",
                detail=f"move behind the Prismor MCP gateway ({Path(source).name})",
                command="prismor mcp-gateway install --all",
                subject=source,
            ))

    if "credential" in wanted:
        for cred in report.get("credentials") or []:
            if cred.get("managed"):
                continue
            provider = str(cred.get("provider") or "")
            location = str(cred.get("location") or "")
            if cred.get("location_kind") != "file":
                out.actions.append(Remediation(
                    kind="credential", target=provider, status="skipped",
                    detail=f"set in the environment as {location} — export it from a "
                           f"cloaked .env, or register it with `prismor cloak add`",
                ))
                continue
            if not _is_dotenv(location):
                out.actions.append(Remediation(
                    kind="credential", target=provider, status="skipped",
                    detail=f"embedded in {location}, which is not a dotenv file — "
                           f"move the value into .env or cloak it by hand",
                ))
                continue
            out.actions.append(Remediation(
                kind="credential", target=provider, status="planned",
                detail=f"import every key from {location} into Cloak",
                command=f"prismor cloak add --env-file {location}",
                subject=location,
            ))

    return out


# ── applying ─────────────────────────────────────────────────────────────────


def _agent_id_for(report: Dict[str, Any], display_name: str) -> str:
    for agent in report.get("agents") or []:
        if str(agent.get("name") or "") == display_name:
            return str(agent.get("id") or "")
    return display_name


def apply(
    report: Dict[str, Any],
    *,
    repo_root: Path,
    workspace: Path,
    mode: str = "observe",
    kinds: Iterable[str] = FIXABLE_KINDS,
    plan_obj: Optional[RemediationPlan] = None,
) -> List[Remediation]:
    """Carry out every fixable action. Returns one result per attempted action.

    Each lever is isolated: a failure on one agent must not abandon the rest,
    because a partial fix that reports honestly is more useful than an
    all-or-nothing run that leaves the operator guessing which half landed.
    """
    todo = (plan_obj or plan(report, kinds=kinds))
    results: List[Remediation] = list(todo.skipped)

    #: source file -> the Remediation produced by migrating it. One migration
    #: moves every server in that file, so it must run once per FILE and the
    #: outcome be attributed to each server it covered — migrating per server
    #: would re-run against an already-rewritten file.
    migrated: Dict[str, Remediation] = {}
    dotenv_done: set = set()

    # Removals first: a gateway migration of the same file must not carry a
    # server that is about to be removed.
    for action in sorted(todo.fixable, key=lambda a: a.kind != "mcp_unused"):
        if action.kind == "mcp_unused":
            results.append(_remove_unused_mcp(action))
            continue
        if action.kind == "agent":
            results.append(_fix_agent(report, action, repo_root=repo_root,
                                      workspace=workspace, mode=mode))
        elif action.kind == "mcp":
            prior = migrated.get(action.subject)
            if prior is not None:
                results.append(Remediation(
                    kind="mcp", target=action.target, status=prior.status,
                    detail=prior.detail, command=action.command,
                    subject=action.subject))
                continue
            outcome = _fix_mcp(action)
            migrated[action.subject] = outcome
            results.append(outcome)
        elif action.kind == "credential":
            path = action.subject
            if path in dotenv_done:
                results.append(Remediation(
                    kind="credential", target=action.target, status="fixed",
                    detail=f"imported from {path}", command=action.command,
                    subject=path))
                continue
            outcome = _fix_credential(action, path=path)
            if outcome.ok:
                dotenv_done.add(path)
            results.append(outcome)

    return results


def _fix_agent(report: Dict[str, Any], action: Remediation, *,
               repo_root: Path, workspace: Path, mode: str) -> Remediation:
    agent_id = action.subject or _agent_id_for(report, action.target)
    try:
        from prismor.runtime.hooks import install_hooks, HookConfigError
    except Exception as exc:  # pragma: no cover - import guard
        return Remediation(kind="agent", target=action.target, status="failed",
                           detail=f"could not load the hook installer: {exc}",
                           command=action.command)
    try:
        # Global scope: the point is to govern the agent wherever it runs, not
        # only in whichever directory `discover` happened to be invoked from.
        install_hooks(repo_root=repo_root, workspace=workspace,
                      agent=agent_id, scope="global", mode=mode)
    except HookConfigError as exc:
        return Remediation(kind="agent", target=action.target, status="failed",
                           detail=f"{exc} — fix the file, then re-run",
                           command=action.command)
    except Exception as exc:
        return Remediation(kind="agent", target=action.target, status="failed",
                           detail=str(exc), command=action.command)
    return Remediation(kind="agent", target=action.target, status="fixed",
                       detail=f"global hook installed ({mode} mode)",
                       command=action.command)


def _fix_mcp(action: Remediation) -> Remediation:
    """Migrate the config file this server was declared in.

    Keyed on the file rather than the workspace, so a server declared in
    Claude Desktop or Cursor is governed too — discovery reports those, and
    before this they were found and then left in place.
    """
    try:
        from prismor.runtime.mcp_gateway import migrate_config
    except Exception as exc:  # pragma: no cover - import guard
        return Remediation(kind="mcp", target=action.target, status="failed",
                           detail=f"could not load the gateway installer: {exc}",
                           command=action.command, subject=action.subject)
    try:
        result = migrate_config(Path(action.subject))
    except Exception as exc:
        return Remediation(kind="mcp", target=action.target, status="failed",
                           detail=str(exc), command=action.command,
                           subject=action.subject)
    status = {"migrated": "fixed", "skipped": "skipped"}.get(result.status, "failed")
    return Remediation(kind="mcp", target=action.target, status=status,
                       detail=result.detail, command=action.command,
                       subject=action.subject)


def _remove_unused_mcp(action: Remediation) -> Remediation:
    """Delete one server from the top-level server block of the file it was
    found in. The file is copied to ``<file>.prismor-<time>.bak`` first and
    re-read just before the write, since agents rewrite these files while
    they run."""
    import os
    import shutil
    import time
    path = Path(action.subject)
    done = lambda status, detail: Remediation(  # noqa: E731
        kind="mcp_unused", target=action.target, status=status, detail=detail,
        command=action.command, subject=action.subject)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return done("failed", f"could not read {path}: {exc}")
    block = next((data[k] for k in ("mcpServers", "servers")
                  if isinstance(data.get(k), dict) and action.target in data[k]), None)
    if block is None:
        return done("skipped", f"not in the top-level server block of {path} "
                               f"(declared per project?) — remove it with `{action.command}`")
    backup = Path(f"{path}.prismor-{time.strftime('%Y%m%d-%H%M%S')}.bak")
    try:
        shutil.copy2(path, backup)
        del block[action.target]
        tmp = path.with_name(path.name + ".prismor-tmp")
        tmp.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
        os.chmod(tmp, path.stat().st_mode & 0o777)
        os.replace(tmp, path)
    except OSError as exc:
        return done("failed", f"could not write {path}: {exc}")
    return done("fixed", f"removed from {path} (backup: {backup}). New sessions no longer "
                         f"start it; to use it in one project, copy its entry from the backup "
                         f"into that project's .mcp.json")


def _fix_credential(action: Remediation, *, path: str) -> Remediation:
    try:
        from prismor.runtime.cloaking import add_env_secrets
    except Exception as exc:  # pragma: no cover - import guard
        return Remediation(kind="credential", target=action.target, status="failed",
                           detail=f"could not load Cloak: {exc}", command=action.command)
    try:
        created = add_env_secrets(Path(path))
    except Exception as exc:
        return Remediation(kind="credential", target=action.target, status="failed",
                           detail=str(exc), command=action.command)
    # Names only — a count and the placeholder names, never a value.
    return Remediation(
        kind="credential", target=action.target, status="fixed",
        detail=f"{len(created)} key(s) imported from {path}; reference them as "
               f"@@SECRET:<name>@@",
        command=action.command,
    )


def summarize(results: List[Remediation]) -> Dict[str, int]:
    out = {"fixed": 0, "skipped": 0, "failed": 0}
    for r in results:
        if r.status in out:
            out[r.status] += 1
    return out
