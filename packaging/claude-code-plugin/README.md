# Prismor for Claude Code

Prismor is open-source runtime security for AI coding agents. This plugin connects Claude Code to the Prismor CLI on your machine. Every prompt you send and every tool call Claude makes is checked against your Prismor policy before it runs, and each session is written to a local audit trail you can review in the Prismor dashboard.

## What it does

- Checks shell commands, file reads and writes, web fetches, subagent launches, skills and MCP tool calls against your policy.
- Flags destructive commands, reads of secret files such as `.env`, risky package installs and outbound requests to hosts you have not allowed.
- Scans project memory files such as `CLAUDE.md` at session start for injected instructions.
- Records each session locally so you can see what Claude did and why something was flagged.

The plugin starts in **observe mode**: it records and warns but does not block. To block risky actions, run `prismor setup` and choose enforce mode.

## Requirements

Install the Prismor CLI before enabling the plugin. It needs Python 3.8 or newer.

```bash
pip install prismor
prismor setup
```

Then add the plugin in Claude Code:

```
/plugin install prismor --marketplace PrismorSec/prismor
```

If the `prismor` command is not on your `PATH`, Claude Code shows a hook error and the tool call runs unscreened.

## What runs and what is sent

The plugin contains no code of its own beyond one shell script. That script runs `prismor hook-dispatch`, passing the hook event Claude Code provides on standard input. Everything else is done by the Prismor CLI you installed.

By default the CLI works locally. Policy checks, session logs and the dashboard all run and are stored on your machine under `~/.prismor`. The CLI makes network requests only in these cases:

- **Package checks.** When Claude installs a package, Prismor looks up the package name and version on [OSV.dev](https://osv.dev) and on its registry (PyPI or npm) to score its risk.
- **Prismor console.** If you run `prismor login` or enroll the device with your organization, policy and redacted session events are exchanged with `www.prismor.dev`.
- **Optional AI checks.** If you turn on the semantic guard or hosted judge, the text being checked is sent to the model provider you configure.

The plugin does not read credentials from your environment, store personal data outside your machine, or send data anywhere else.

## Learn more

- Source and documentation: https://github.com/PrismorSec/prismor
- Website: https://prismor.dev
- Security policy: https://github.com/PrismorSec/prismor/blob/main/SECURITY.md
- Privacy: https://prismor.dev/privacy

Licensed under Apache 2.0.
