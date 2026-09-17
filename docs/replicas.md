# Governing Replicas cloud workspaces

[Replicas](https://docs.replicas.dev) runs coding agents (Claude Code, Codex,
Cursor, OpenCode and others) inside disposable cloud VMs. Nothing on the
Replicas side needs to change to govern them: a Replicas *environment* can run
a shell script at workspace boot, and that is enough to install Prismor and
hook the agents before the first prompt arrives.

This page is the recipe that was verified live against a Replicas workspace on
2026-09-16, plus the things that went wrong on the way to it.

## The start hook

Open **Environments → Global** in the Replicas app, click the pencil beside
**Start hook**, and paste:

```bash
#!/bin/bash
# Prismor: install once per workspace, hook every agent, block the recommended rule set.
python3 -m venv "$HOME/.prismor-venv" && "$HOME/.prismor-venv/bin/pip" install -q prismor 2>&1 | tail -2
mkdir -p "$HOME/.local/bin" && ln -sf "$HOME/.prismor-venv/bin/prismor" "$HOME/.local/bin/prismor"
export PATH="$HOME/.local/bin:$PATH"
prismor setup --non-interactive --mode enforce --recommended --agents claude,codex
prismor status
```

Click **Test** — Replicas runs the script in a throwaway sandbox and shows the
output in about ten seconds — then **Save**. Every workspace created from then
on boots with Prismor hooks installed, and `prismor status` in the hook log
shows what was wired:

```text
Hooks:     claude, codex  (enforce, project + global)
Rules:     81 active
```

The Global environment applies to every workspace in the organization. To
govern only some repositories, put the same script on the team environment
bound to them, or in the repository's own `replicas.json` under `startHook`.

## What it looks like from the agent

With the hook in place, a Claude Code session in the workspace that tries a
blocked command gets the Prismor verdict back as the tool result and moves on:

```text
PreToolUse:Bash hook error: ["/home/user/.prismor-venv/bin/python3" "/home/user/.prismor/hook-dispatch.py" ...]
touch /tmp/f && chmod u+s /tmp/f

To unblock (for the human at the keyboard — an agent running these is blocked unless `prismor unlock` ...):
privilege-escalation is a floor rule ...
```

![A Replicas workspace where Claude Code's setuid chmod was refused by the Prismor PreToolUse hook](replicas/blocked.jpg)

Copying `~/.claude/settings.json` is refused the same way; `echo hello` runs.
The verdicts land in `prismor sessions --findings-only` inside the workspace,
and on the console if the workspace is enrolled.

## Things that bit during verification

**`--recommended` is not optional in a script.** `--mode enforce` on its own
installs with *nothing* blocking except Prismor's self-protection rules — that
is the explicit opt-in floor described in [Choosing what
blocks](cli-reference.md#choosing-what-blocks). The first version of this hook
left it out: a `chmod u+s` was flagged CRITICAL in the session log and then ran
anyway. Pass `--recommended`, or `--enforce-rules id1,id2` for a hand-picked set.

**The image has no `pipx`, and `pip` is PEP 668 locked.** A plain `pip install
--user` fails with "externally-managed-environment". A venv under `$HOME`
sidesteps both; nothing else on the box is touched.

**`prismor` is not on the agent's PATH.** The hook script's `export PATH` does
not reach the agent's shell, and `~/.bashrc` is not sourced by a non-interactive
Bash tool. Enforcement is unaffected — the installed hook calls the venv's
Python by absolute path — but an agent told to run `prismor status` will get
"command not found" unless it uses `~/.local/bin/prismor`.

**Hooks land at both scopes.** The start hook runs with the home directory as
its working directory, so `setup` writes the hooks at project scope *and*
global scope and every tool call is screened twice. Harmless, but it doubles
finding counts. Run `prismor uninstall-hooks --agent claude --scope project`
at the end of the hook if that matters to you.

**Codex is hooked but not trusted.** Codex only runs hooks a human has accepted
in an interactive session, and nobody opens a terminal in a Replicas VM. Until
Codex grows a non-interactive trust path, Codex sessions there are unscreened.
Claude Code has no such step.

**Warm pools.** If the environment has a warm pool, put the `pip install` line
in the *warm* hook so it happens once per pool build, and keep `setup` and any
`prismor enroll` in the *start* hook. Enrolling in the warm hook would bake one
device identity into every snapshot in the pool.

## Enrolling the workspaces

Everything above is the open-source runtime on its own. To see the fleet on the
console, add an enrollment step to the start hook and hand it the token through
a Replicas environment variable:

```bash
prismor enroll "$PRISMOR_ENROLL_TOKEN"
```

Set `PRISMOR_WORKSPACE_SCOPE=managed` in the same environment; a fresh VM
usually has a cloned repository with a remote, but when it does not, the
workspace resolves as personal and reports nothing (see
[connecting-to-the-platform.md](connecting-to-the-platform.md)). Every Replicas
workspace is a short-lived VM, so per-workspace enrollment fills the fleet with
one-shot devices; the deviceless `PRISMOR_AGENT_KEY` path, one key per Replicas
environment, is the better fit.

## What this does not cover

Replicas *plugins* (its Stripe, Salesforce, Linear and similar connectors) are
called from TypeScript through the Replicas SDK, not through an MCP server.
The hook sees the `Bash` call that launched the script, not the write inside
it. Replicas' static egress IP is network-level allowlisting and stacks with
Prismor's per-call [egress rules](network-isolation.md) rather than replacing
them.
