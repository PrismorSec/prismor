# Governing agents that run in a hosted VM

Codex cloud, Claude Code on the web, Cursor cloud agents, the Copilot coding
agent, OpenHands Cloud, Replicas: the agent runs on a machine you never log
into. `prismor setup` on your laptop does nothing for it.

Two facts decide how Prismor gets there.

**Every hosted platform runs a script of yours before the agent starts.** That
is where Prismor gets installed.

**Most of them load hooks only from the cloned repo.** Claude Code on the web
reads the repo's `.claude/settings.json` and nothing from a home directory; the
Copilot coding agent reads only `.github/hooks/*.json`; Cursor cloud agents read
the repo's `.cursor/hooks.json`. A hook config that a setup script writes into
`$HOME` is ignored there. So the hook config has to be *committed*, and the
command `prismor install-hooks` normally writes cannot be: it embeds this
machine's interpreter, a shim under this machine's `~/.prismor`, and this
checkout's path.

## The recipe

**1. On your machine, write a hook config that is safe to commit.**

```bash
prismor setup --mode enforce --recommended          # writes .prismor/policy.yaml
prismor install-hooks --agent claude --scope project --mode enforce --portable
git add .claude/settings.json .prismor/policy.yaml && git commit -m "Govern cloud agent sessions"
```

`--portable` writes a command with no machine-specific path in it. It looks for
`prismor` on `PATH`, then at `~/.local/bin/prismor`, at the moment the hook
fires. It needs `sh`, so it is for Linux and macOS agents, which is every hosted
VM. Repeat `install-hooks` for each agent you run in the cloud (`codex`,
`cursor`, `copilot`, `openhands`, ...).

**2. In the platform's setup script, install the binary.** Nothing else.

```bash
python3 -m venv "$HOME/.prismor-venv" && "$HOME/.prismor-venv/bin/pip" install -q prismor
mkdir -p "$HOME/.local/bin" && ln -sf "$HOME/.prismor-venv/bin/prismor" "$HOME/.local/bin/prismor"
```

A venv because hosted images tend to have no `pipx` and a PEP 668 locked `pip`.
The symlink because the agent's shell usually does not inherit the setup
script's `PATH`, and `~/.bashrc` is not sourced by a non-interactive tool shell.

**3. Set `PRISMOR_HOOK_REQUIRED=1` in the cloud environment's variables.**

If `prismor` is not found when a hook fires, the hook warns on stderr and lets
the call through. That keeps a teammate who cloned the repo without Prismor
installed from being locked out of their own editor, but in a cloud VM it means
a failed setup script is a silently unscreened agent. With
`PRISMOR_HOOK_REQUIRED` set, a missing binary blocks every tool call instead.

## Where each platform takes the setup script

| Platform | Setup script goes in | Hook config the cloud agent loads |
|---|---|---|
| Claude Code on the web | Environment dialog, "Setup script" (runs as root, snapshotted) | Repo `.claude/settings.json`, org server-managed settings |
| Cursor cloud agents | `.cursor/environment.json` `install` / `start` | Repo `.cursor/hooks.json`, dashboard team hooks |
| Copilot coding agent | `.github/workflows/copilot-setup-steps.yml` | Repo `.github/hooks/*.json` |
| OpenHands Cloud | `.openhands/setup.sh` | Repo `.openhands/hooks.json` |
| Codex cloud | Settings → Environments → Setup script | See below |
| Replicas | Environment start hook | Home or repo: a stock CLI with a normal `$HOME`, so plain `prismor setup` in the start hook also works |

Most of these snapshot the VM after the script runs. Install there; run
`prismor enroll` per boot, never in the snapshotted step, or one device identity
is cloned into every VM cut from it.

If the platform turns the agent's network off after setup (Codex cloud does by
default), the local rules still block; the hosted judge and console telemetry
cannot be reached until you allow their hosts.

## Codex

Codex runs a hook only after a human has accepted it in an interactive session.
The acceptance is a per-hook record in `~/.codex/config.toml`, and a trusted
project plus `[features] hooks = true` is not a substitute: with both set,
`codex exec` ran a command the committed hook blocks, and only
`codex exec --dangerously-bypass-hook-trust` made the hook fire. In a hosted VM
nobody can accept the prompt and you do not control how `codex` is launched, so
**hooks do not gate Codex in a hosted environment today.** `prismor status`
says so when it sees untrusted Codex hooks. Where you do control the invocation
(your own CI, your own container), pass the flag.

## What was verified

- Replicas: on the real platform, Claude Code, blocks returned as tool results.
- Claude Code with project settings only, OpenHands CLI headless, and Codex CLI:
  a committed `--portable` config in a fresh VM, before and after the setup
  script, with a live model.
- The other platforms' behaviour above is from their documentation.
