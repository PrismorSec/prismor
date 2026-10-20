# Getting started

This page is for you if you have just installed Prismor, or are about to, and
want to know what it does and how to use it day to day. You do not need to be
a security expert.

## What Prismor does

AI coding agents such as Claude Code, Codex, Cursor and Copilot run commands,
read and write files, and reach out to the internet for you. Prismor sits
between the agent and your computer. It checks each of those actions against a
set of rules before it runs, and keeps a record of everything the agent did.

Depending on how you set it up, Prismor either just records risky actions or
stops them. Everything it records stays on your machine unless you connect it
to an organization yourself (see [FAQ](faq.md#what-data-leaves-my-machine)).

## Install

The quickest way is with pip:

```bash
pip install prismor
```

On macOS and Linux you can also use the install script, which picks the right
method for your system:

```bash
curl -sSL https://prismor.dev/install | sh
```

On Windows, use pip. Other options (installing from a git checkout, or letting
your agent install it through `SKILL.md`) are covered in
[Installation](installation.md).

## First run: `prismor setup`

Run the setup wizard from inside a project folder:

```bash
prismor setup
```

The wizard asks you a few questions:

- **Mode.** Whether Prismor should only watch (`observe`) or also block
  (`enforce`). See [Observe vs enforce](#observe-vs-enforce) below.
- **What blocks.** If you pick enforce, you choose which rules are allowed to
  block. Nothing is selected at first. Press `a` to take the recommended set.
- **Agents.** Which coding agents on your machine Prismor should watch.
- **Secret cloaking.** Whether to hide your API keys and passwords from the
  agent (see [cloak](glossary.md#cloak--secret-cloaking)).
- **Unlock password.** An optional password you type when you want to let the
  agent change Prismor's own settings for a few minutes.

When it finishes, check that everything is wired up:

```bash
prismor status
```

`status` shows whether the hooks are installed, which mode you are in, and the
one thing you should do next.

> **Using Codex?** Codex will not run Prismor until you trust its hooks once.
> Open `codex` in the project and accept the hook-trust prompt. Until you do,
> nothing is checked. `prismor status` tells you if this step is still missing.

> **Asked your agent to install it?** When an agent runs `prismor setup`, there
> is no screen for the wizard. Setup prints the questions instead, the agent
> asks you, then runs the matching command.

## Open the dashboard

```bash
prismor dashboard
```

This starts a small web page on your own computer at `http://127.0.0.1:7070`
and opens it in your browser. Only your machine can reach it. Stop it with
`Ctrl+C` in the terminal.

If the dashboard says no workspaces are registered, Prismor has not seen any
agent activity yet. Install hooks in a project (with `prismor setup`), use your
agent for a bit, then click **Refresh**.

To fill the dashboard with what your agents did *before* you installed
Prismor, replay their saved history:

```bash
prismor analyze-history --since 90d
```

These past sessions are marked as reconstructed. A finding there means a rule
would have matched, not that anything was blocked at the time.

## A tour of the dashboard

The pages are listed in the sidebar on the left.

- **Overview.** The summary screen: what needs attention, how busy your agents
  have been, which rules fired, where agents connected to on the internet, and
  where they keep failing. Start here.
- **Sessions.** Every agent run, one row each. Open one to see what the agent
  did step by step. For a live session you can pause Prismor or clear its
  session scope from here.
- **Files.** Every file an agent wrote, and the session that changed it. Use it
  to answer "which agent edited this, and why?"
- **Agents.** Each coding agent Prismor has seen. You can switch one off
  entirely, or give it its own mode (observe or enforce) instead of the global
  one.
- **Policy Control.** The rules, and whether each one blocks or only reports.
  You can turn rules on and off and edit the list of websites agents may
  contact. Some rules are pinned and cannot be turned off.
- **MCP Servers.** The MCP servers (add-on tool servers) your agents use, where
  each is configured, and whether Prismor is checking its calls.
- **Extensions.** Skills, plugins, hooks, MCP servers, secrets and packages
  your agents used. New or changed items are flagged until someone reviews
  them.
- **Fleet.** A preview of the organization-wide view, which is part of Prismor
  Enterprise. On a personal install it shows no real data.
- **Docs.** These documentation pages, searchable, without leaving the
  dashboard. They work offline.

More detail on each page is in [Dashboard](dashboard.md).

## Observe vs enforce

Prismor has two basic settings.

- **Observe** means "watch and write it down." Every action is checked and
  recorded, and anything risky shows up as a finding. Nothing is stopped. This
  is a good way to start, because it never gets in your way.
- **Enforce** means "watch, write it down, and stop the risky ones." Rules you
  chose to block will refuse the action before it runs, and the agent is told
  why.

A good path is to start in observe, look at the dashboard for a few days, then
switch to enforce once you know what would be blocked. You can preview a
stricter setup without blocking anything:

```bash
prismor mode apply dev-safe --observe
```

[Modes](modes.md) explains the three ready-made postures (`dev-safe`,
`trusted-workspace`, `regulated-airgap`) and what each one does and does not
protect.

## Where to go next

- [FAQ and troubleshooting](faq.md): blocked commands, pausing, uninstalling,
  privacy.
- [Glossary](glossary.md): plain-English meanings of the words Prismor uses.
- [Installation](installation.md): every install method, including Windows.
- [Modes](modes.md): the three ready-made security postures.
- [Dashboard](dashboard.md): the dashboard and session commands in depth.
- [CLI reference](cli-reference.md): every `prismor` command.
