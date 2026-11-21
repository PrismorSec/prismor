# Prismor Sandbox

Prismor's policy engine decides whether a shell command may run. The sandbox decides what that command, and every process it starts, can touch while it runs. It uses the sandbox the OS already ships: Seatbelt on macOS, bubblewrap on Linux. Commands keep using your real toolchain (`npm`, `.venv`, `cargo`, `git`), and each one starts about 10 ms slower. Windows is not supported yet (see [Platforms](#platforms)).

```bash
prismor sandbox on
```

That's the only step. You don't add a new file, learn a new policy language or launch your agent differently. Every limit comes from the `.prismor/policy.yaml` you already have: `settings.sandbox` sets the files and network mode, and `settings.egress` sets which hosts are reachable.

## Why

Prismor judges what the agent asks to run. An allowed `npm install` is harmless as text, but its dependencies' postinstall scripts run with your full user account. They can read `~/.aws/credentials`, write a git hook that runs the next time you commit, or post your `.env` to a host nobody has heard of. The hook never sees any of that, because those scripts aren't tool calls. With the sandbox on, the OS holds them to the same limits as the command the agent typed.

## How a command flows

```
 Agent: Bash "npm install left-padder"
        │
        ▼
 ┌───────────────────────────────────────────────────────────────┐
 │ 1 · Prismor hook (policy engine)                              │
 │     rules, IAM, egress, supply chain ... → allow              │
 │     rewrite:  prismor sandbox run 3<<'__PRISMOR_SANDBOX_…__'  │
 │               npm install left-padder                         │
 │               __PRISMOR_SANDBOX_…__                           │
 └───────────────────────────────────────────────────────────────┘
        │  the command rides fd 3, never a process's argv
        ▼
 ┌───────────────────────────────────────────────────────────────┐
 │ 2 · macOS sandbox (Seatbelt), built from policy.yaml          │
 │     write   project, tmp, package caches                      │
 │     locked  .git/hooks .prismor .claude .vscode .mcp.json ... │
 │     hidden  ~/.aws ~/.kube ~/.docker ~/.netrc vault ...       │
 │     network loopback only (+ port 22 for git over SSH)        │
 │                                                               │
 │     npm install ──► postinstall.js                            │
 │                       ├─ read ~/.aws/credentials   ✗ EPERM    │
 │                       ├─ write .git/hooks/pre-commit ✗ EPERM  │
 │                       └─ POST x.attacker.io ─────┐            │
 └──────────────────────────────────────────────────│────────────┘
                                                    ▼
                  ┌───────────────────────────────────────────────┐
                  │ 3 · Egress proxy (loopback, inside the runner) │
                  │     registry.npmjs.org  ✓ on the allowlist     │
                  │     x.attacker.io       ✗ 403, logged          │
                  └───────────────────────────────────────────────┘
```

What the agent and you see in the command's output:

```
added 1 package in 2s
Error: EPERM: operation not permitted, open '/Users/you/.aws/credentials'
[prismor] sandbox: blocked x.attacker.io:443 (not on the egress allowlist)
```

The install still finishes, because the package itself downloaded from an allowed registry. Both attempts fail. The `[prismor] sandbox:` line is part of the tool output, so it's recorded with the session in the dashboard.

## Try it before you turn it on

`try` runs one command sandboxed, whatever the workspace setting is. If the command fails, it says why:

```
$ prismor sandbox try -- npm test
[prismor] sandbox Seatbelt (macOS): writes: project, tmp, package caches · credential stores hidden · network through the egress allowlist
...
[prismor] exited 1 inside the sandbox. An "Operation not permitted" above means it touched a path the sandbox does not allow: add it to settings.sandbox.writable, or see docs/sandbox.md for rings.
```

Run your usual build, test and dev commands through `try`. Once they pass, run `prismor sandbox on`. Seatbelt has no "log what you would block" mode, so `try` is how you preview the sandbox.

## Check what it's doing

```
$ prismor sandbox status

  PRISMOR  sandbox status
  ──────────────────────────────────────────────────

  Sandbox:      on (enforce)
  Engine:       Seatbelt (macOS)
  Files:        enforced — writes: project, tmp, package caches
  Credentials:  enforced — cloud, registry and Prismor key stores hidden
  Network:      enforced — HTTP(S) through the proxy (egress allowlist on); direct ports 22
```

`prismor sandbox check` prints a single PASS or FAIL for the engine. `prismor sandbox off` turns the sandbox off and leaves the rest of the block alone, so turning it back on later restores the same settings.

## Rings

A ring sets the workspace mount and the network mode together. If you set `network` or `workspace_mount` explicitly, that value wins over the ring.

| Ring | Project | Network | Use it for |
|---|---|---|---|
| `0` | read-only | none | review and inspection agents |
| `1` | writable | none | builds and tests that need no network |
| `2` (default) | writable | HTTP(S) through the egress allowlist, plus `direct_ports` | everyday coding agents |
| `3` | writable | open | work that needs raw sockets (databases, JVM tools that ignore proxy variables) |

In ring 2, the proxy follows your `settings.egress` exactly, the same way the hook does:

- **Allowlist off:** HTTP(S) can reach any host. Anything that bypasses the proxy is still refused.
- **Allowlist on in observe mode:** off-list hosts are let through and logged.
- **Allowlist on in enforce mode:** off-list hosts are blocked.

To hold commands to an allowlist:

```bash
prismor egress enable
prismor egress default deny
prismor egress allow registry.npmjs.org pypi.org files.pythonhosted.org github.com
prismor egress mode enforce
```

`prismor egress enable` starts the allowlist in observe mode, so off-list hosts are only logged until you run `prismor egress mode enforce`. Run `prismor egress report` first to see which hosts your commands reach.

## Configuration

```yaml
# .prismor/policy.yaml
settings:
  sandbox:
    enabled: true
    mode: enforce          # observe = configured, not confining
    ring: "2"
    writable: [../shared-cache]   # extra writable paths (relative = from the project root)
    hide: [.env, ~/.ssh]          # extra unreadable paths
    direct_ports: [22]            # ring 2 only: TCP ports reachable directly
```

The built-in lists:

| List | Paths |
|---|---|
| Writable | the project root (the git root above the agent's cwd), temp dirs, package caches (`~/.cache`, `~/Library/Caches`, `~/.npm`, `~/.yarn`, pnpm, bun, `~/.cargo/registry`, `~/go/pkg/mod`, Gradle, Maven) |
| Locked (read-only, even inside the project) | `.prismor`, `.git/hooks`, `.claude`, `.codex`, `.cursor`, `.gemini`, `.vscode`, `.github/hooks`, `.mcp.json`; in home: `~/.prismor`, `~/.ssh`, `~/.gnupg`, shell startup files, `~/.gitconfig`, LaunchAgents, autostart |
| Hidden (not readable) | `~/.aws`, `~/.azure`, `~/.config/gcloud`, `~/.kube`, `~/.docker`, `~/.netrc`, `~/.pypirc`, the cloak vault, Prismor's signing and pause keys |
| Unreachable sockets | Docker, Colima and OrbStack daemon sockets |

`.env` and `~/.ssh` stay readable by default, because dev servers load `.env` and `git push` reads your SSH key. Add them to `hide` for agents that don't need them. A bare `prismor status`, `prismor check` or `prismor query` runs outside the sandbox, because those commands read and write `~/.prismor`. `prismor supplychain` runs inside it, because it starts package managers.

## With Cloak

Claude Code runs PreToolUse hooks in parallel and keeps whichever rewrite finishes last, so the sandbox and the cloak hook can't both rewrite the same command. When the cloak hook is installed, it does both jobs, in this order:

```
 decloak.sh rewrite (one hook, one rewrite)
 ┌────────────────────────────────────────────────────────────┐
 │ scrub wrapper          ← masks secrets in output (outside) │
 │  └ placeholder resolve ← reads the vault (outside)         │
 │     └ prismor sandbox run 3<<'…'  ← OS sandbox starts here │
 │        └ your command  ← vault hidden, writes limited      │
 └────────────────────────────────────────────────────────────┘
```

Placeholders resolve, and output is scrubbed, outside the sandbox, where the vault is readable. The command itself runs inside the sandbox, where the vault is hidden. The resolved value reaches the command through a heredoc, never through argv. Hook-dispatch tells the cloak hook which projects have the sandbox on, through `~/.prismor/sandbox/active.tsv`. You don't need to configure anything.

## Platforms

On macOS, everything above is enforced by Seatbelt.

On Linux, bubblewrap (`apt install bubblewrap`) enforces the same file and credential limits, with these differences:

- **Network.** Ring 2 runs the command in its own network namespace with loopback only. A bridge carries the proxy into it, and each new host is screened as a Prismor `network` event, so it shows in the session trail. `direct_ports` has no effect.
- **More credential stores are hidden by default.** For example, `~/.ssh`, `~/.gnupg`, `~/.npmrc` and `~/.config/gh` cannot be read.
- **Protected paths must exist.** bubblewrap can only make an existing path read-only.
- **Ubuntu 23.10 and later** block unprivileged user namespaces by default (`kernel.apparmor_restrict_unprivileged_userns=1`). bubblewrap cannot start until an admin adds an AppArmor profile for it. `prismor sandbox check` says so.

## When the sandbox can't confine a command

In enforce mode a shell command runs inside the sandbox or it does not run. When Prismor can't confine a command, it blocks the command and runs nothing. These are the cases:

- The engine is missing or can't start (no `bwrap`, an AppArmor block, `sandbox-exec` fails).
- The OS has no sandbox (Windows).
- The agent already runs inside its own sandbox, and Seatbelt can't nest inside it.
- The agent's hooks can't rewrite a command (Codex and Qwen Code without `PRISMOR_REWRITE_AUTO_APPROVE=1`, Copilot CLI, OpenCode).
- With Cloak installed, the sandbox settings for the project just changed. One call is blocked, and the agent is told to run it again.

The agent sees this message:

```text
Prismor sandbox: BLOCKED. The sandbox is on in enforce mode, but it cannot confine this command here: the sandbox engine is not available (bwrap not found). Nothing ran.
Only a person can change this, in their own terminal. The agent cannot:
  - see what is wrong and fix it:      prismor sandbox check
  - or run commands without the sandbox: prismor sandbox off
```

A bare `cd` and read-only `prismor` commands (`prismor status`, `prismor check`) still run, so the agent can tell you what is wrong.

Only a person can turn the sandbox off. `prismor sandbox off` refuses to run without a terminal (an agent's shell has none), unless a `prismor unlock` window is open. The `prismor-self-edit` rule also blocks an agent that runs `prismor sandbox off` in any form, or writes the Cloak sandbox index. Inside the sandbox, `.prismor/` is read-only, so the policy file can't be changed from a command either.

`settings.sandbox.mode: observe` keeps the old behavior: the runner says so on stderr and runs the command unconfined. Policy screening still applies. `prismor mode apply` on a host with no engine sets the mode's sandbox to `observe`, so a mode never blocks every command by accident.

## Agents

The hook rewrite works on agents whose PreToolUse hook can rewrite input: Claude Code, Gemini CLI and Grok. Codex and Qwen Code need `PRISMOR_REWRITE_AUTO_APPROVE=1`, because their rewrite also approves the call. On other agents, an enforced sandbox blocks their shell commands, because it cannot wrap them. Use `mode: observe` there, or run commands yourself through `prismor sandbox run -- <command>`.

## Known limits

- **`cd` doesn't carry over.** A bare `cd dir` is left unwrapped so the agent's shell still changes directory. Inside a wrapped command, `cd` only lasts for that command.
- **The agent shell's own functions and aliases aren't available.** Each command runs in a fresh `$SHELL -c`.
- **macOS refuses setuid programs** (`sudo`, `ps`, `top`) inside Seatbelt.
- **Trusted daemons act outside the sandbox.** The Docker socket is blocked, but `open`, `osascript` and `launchctl` on macOS can still ask other processes to act for the command. The policy engine screens those commands by text.
- **DNS lookups still work in ring 2**, so data can leak through DNS queries at a few bytes per lookup.
- **Clients that ignore proxy variables can't reach the network in ring 2.** Add their port to `direct_ports`, or use ring 3.
- **An existing corporate `HTTPS_PROXY` isn't chained yet.** Use ring 3 behind one.
- **Background processes** that outlive the command lose the egress proxy when the command exits.
- **Denials show up in the command's output**, not as separate dashboard events.
