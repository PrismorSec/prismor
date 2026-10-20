# Glossary

Plain-English meanings of the words Prismor and its dashboard use. Each entry
links to the page that covers it in depth. New to Prismor? Start with
[Getting started](getting-started.md).

## Agent

An AI coding assistant that can take actions on your computer, such as Claude
Code, Codex, Cursor or Copilot. Prismor watches what agents do. Each agent
registers itself the first time it runs in a project Prismor protects. See
[Dashboard: Agents tab](dashboard.md#agents-tab).

## Allow / warn / block

The three basic outcomes of a check. **Allow** means the action runs.
**Warn** means it runs, but a finding is recorded so you can see it. **Block**
means it is stopped before it runs, and the agent is told why. A rule only
blocks in enforce mode. See [Rule actions](prismor-runtime.md#rule-actions).

## Audit trail

A tamper-evident record of every action an agent took through Prismor, kept in
`~/.prismor/audit/`. Each record is linked to the one before it and signed, so
an edited or deleted record shows up when you run `prismor trail verify`. See
[Signed audit trail](audit-trail.md).

## Cloak / secret cloaking

A way to keep real passwords and API keys out of the agent's view. You store a
secret once with `prismor cloak add <name>`, and the agent only sees a
placeholder such as `@@SECRET:name@@`. The real value is filled in when a
command runs and scrubbed from the output. See [Sweep and Cloak](sweep-and-cloak.md).

## Egress

Network traffic leaving your machine, such as an agent fetching a web page or
sending data to an API. Prismor's egress policy is a list of hosts agents may
or may not contact. See [Network isolation](network-isolation.md).

## Enforce mode

The setting where Prismor stops actions that match a blocking rule, before
they run. Compare [observe mode](#observe-mode). See [Modes](modes.md).

## Extension

Anything that adds instructions or code to an agent from outside: a skill, a
plugin, a hook command or an MCP server. Prismor keeps a list of them and flags
new or changed ones until someone reviews them. See [Extension ledger](extensions.md).

## Finding

A record that a rule matched an action. A finding has a severity (critical,
high, medium or low) and does not always mean something was blocked: in
observe mode, or for warn-only rules, the action still ran. See
[Dashboard](dashboard.md).

## Hook

A small command an agent runs at set moments, which lets Prismor see and judge
what the agent is about to do. `prismor setup` or `prismor install-hooks`
installs them. The main moments, using Claude Code's names:

- **PreToolUse**: just before a tool call runs. This is where Prismor can block.
- **PostToolUse**: just after a tool call, with its result.
- **UserPromptSubmit**: when you send the agent a message.
- **SessionStart**: when a new agent session begins.

Other agents use their own names for the same moments. See
[Governance surfaces](governance-surfaces.md).

## Inherit (global)

An agent setting on the dashboard's **Agents** page. `inherit (global)` means
the agent follows the mode set by policy (organization, project or global)
instead of its own observe or enforce override. See [Dashboard: Agents tab](dashboard.md#agents-tab).

## MCP server

A separate program that gives an agent extra tools, for example to talk to
GitHub or a database. MCP stands for Model Context Protocol. Prismor can sit in
front of MCP servers and check each call. See [MCP gateway](mcp-gateway.md).

## Mode

A named security setup that sets many options at once. Prismor ships three:
`dev-safe`, `trusted-workspace` and `regulated-airgap`. "Mode" is also used for
the simpler choice between observe and enforce. See [Modes](modes.md).

## Observe mode

The setting where Prismor checks and records every action and reports anything
risky, but blocks nothing. A safe way to start. Compare
[enforce mode](#enforce-mode). See [Modes](modes.md).

## Pause

Temporarily stops Prismor from blocking, while it keeps checking and
recording. `prismor pause` lasts 24 hours by default; `prismor resume` ends it
early. See [Pause and resume](pause-and-login.md).

## Pinned rule

A rule shown with a lock on the **Policy Control** page. It belongs to
Prismor's core safety floor or its self-protection rules, so you cannot turn
it off for a project. See [Making exceptions](cli-reference.md#making-exceptions).

## Plugin

A bundle that adds features to an agent, installed with the agent's own
plugin command. Prismor lists plugins as one kind of
[extension](#extension). See [Extension ledger](extensions.md).

## Policy

The full set of rules and settings Prismor applies. Your project's version is
the file `.prismor/policy.yaml`. It sits on top of Prismor's defaults, and an
organization's policy can sit on top of both. See
[Policy layers and exemptions](policy-layers-and-exemptions.md).

## Risk score

A number from 0 to 100 for a session. It goes up with each finding, more for
serious ones, and stops at 100. Use it to sort sessions and look at the
riskiest first. See [Dashboard](dashboard.md).

## Rule

One check in the policy, for example "do not read `.env` files". A rule has an
id, a severity and an action (block, warn and so on). See
[Policy engine](prismor-runtime.md#policy-engine).

## Rules fired

A dashboard count of every time a rule matched an action in the selected
period, whether or not it blocked anything. One action can fire several rules.
See [Dashboard](dashboard.md).

## Scope / scoped agent / clear scope

At the start of a session, Prismor reads your first message and builds a small
set of extra rules for that task only. This is the session's **scope**, and the
feature is called the **scoped agent**. **Clear scope** (on the **Sessions**
page, or `prismor scope clear <id>`) removes those session rules; your project
and global policy still apply. See [Scoped agent](scoped-agent.md).

## Session

One run of an agent, from start to finish. Prismor records every action in a
session, so you can replay it later with `prismor session <id>` or on the
**Sessions** page. See [Dashboard](dashboard.md#drilling-in-sessions-and-session).

## Skill

A file of instructions, usually named `SKILL.md`, that an agent reads and
follows. Because it can tell an agent what to do, Prismor tracks skills and
flags new or changed ones. See [Skill scanner](skill-scanner.md) and
[Extension ledger](extensions.md).

## Supply chain

The packages and libraries your project installs from places like npm and
PyPI. A bad package can run harmful code when installed. Prismor checks
installs before they run. See [Supply chain](supply-chain.md).

## Tool call

A single action an agent takes, such as running a shell command, reading a
file, writing a file or fetching a web page. Prismor checks each tool call.
See [Prismor](prismor-runtime.md).

## Tool tag

A label that says what a tool does, such as `untrusted_content` (it reads
outside input) or `critical_action` (it sends, publishes or deletes). Tag
rules then forbid risky combinations, such as reading untrusted content and
then acting on it. See [Tool tags](tool-tags.md).

## Turn

In a session timeline, one turn is one message you sent and everything the
agent did in response, until your next message. See [Dashboard](dashboard.md).

## Workspace

A project folder Prismor protects. Each one is registered when you install
hooks in it, so the dashboard can show all of them together. A workspace can be
personal or, on an enrolled machine, org-managed. See
[Dashboard: where the data lives](dashboard.md#where-the-data-lives) and
[Connecting to the platform](connecting-to-the-platform.md).
