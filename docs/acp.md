# ACP proxy: agents hosted by Zed, JetBrains and other ACP editors

Editors that speak the [Agent Client Protocol](https://agentclientprotocol.com)
(Zed, JetBrains IDEs, Neovim's CodeCompanion, Emacs' agent-shell, …) launch
their coding agent as a subprocess and talk JSON-RPC to it over stdio. The
agent asks the editor to read and write files (`fs/read_text_file`,
`fs/write_text_file`), to run commands (`terminal/create`), and to ask the
person at the keyboard before a risky step (`session/request_permission`).

`prismor acp` sits on that pipe. The editor launches it in place of the agent,
and it launches the agent:

```
editor  ⇄  prismor acp  ⇄  claude-agent-acp / codex-acp / gemini --acp / …
```

## Set up

Wrap the agent command your editor already runs. Everything after `--` is the
agent, unchanged.

**Zed** (`settings.json`):

```json
{
  "agent_servers": {
    "Claude (Prismor)": {
      "type": "custom",
      "command": "prismor",
      "args": ["acp", "--", "npx", "-y", "@agentclientprotocol/claude-agent-acp"]
    }
  }
}
```

**JetBrains** (`~/.jetbrains/acp.json`) uses the same `agent_servers` shape:

```json
{
  "agent_servers": {
    "Codex (Prismor)": {
      "command": "prismor",
      "args": ["acp", "--", "npx", "-y", "@agentclientprotocol/codex-acp"]
    }
  }
}
```

**Neovim (CodeCompanion)** and **Emacs (agent-shell)** take a command list for
each ACP adapter. Put `prismor`, `acp`, `--` in front of it. Working
configurations for both are under [Tested with](#tested-with).

Any other ACP client works the same way: wherever it takes the agent's
command, give it `prismor acp -- <that command>`.

If the editor starts agents with a minimal environment (some SDK clients do),
pass `PRISMOR_HOME` and, if you use cloaking, `PRISMOR_SECRETS_DIR` in the
agent entry's `env`.

## What is screened

| ACP message | Prismor sees it as | When policy says no |
|---|---|---|
| `session/new`, `session/load` | `SessionStart`: project-memory scan (CLAUDE.md / AGENTS.md / GEMINI.md) | Reported in the editor's thread |
| `session/prompt` (editor → agent) | `UserPromptSubmit`: recorded for session context | Recorded only |
| `terminal/create` | `PreToolUse`, shell | JSON-RPC error back to the agent; the editor never runs it |
| `fs/write_text_file` | `PreToolUse`, file write | JSON-RPC error back to the agent |
| `fs/read_text_file` | `PreToolUse`, file read (`.env`, keys, …) | JSON-RPC error back to the agent |
| `session/request_permission` | `PermissionRequest`, shaped from the call's `kind` and `rawInput` | Answered `reject` without asking the human; the reason appears in the thread |
| `fs/read_text_file` result | `PostToolUse`, tool result (injection, secrets) | Cloak-masked; on an injection, returned to the agent as an error |
| `terminal/output` result | `PostToolUse`, tool result | Redacted; on an injection, the output is replaced with a notice |
| `tool_call` / `tool_call_update` (the agent's own tools) | `PostToolUse`, observed after the fact | Recorded; the thread is told when policy would have refused it |

Calls reach the rules under their native names (`Bash`, `Read`, `Write`), so
everything written for hooked agents (allowlists, `prismor allow`, custom
rules) applies unchanged. `sh -c "<script>"` is screened as the script.

**Step-up.** A rule with `action: step_up` on a terminal or file call becomes a
permission prompt in the editor's own dialog (`Allow once` / `Reject`). On an
agent's own permission request, the proxy passes the request through but removes
`Always allow`, so the next call of the same kind is asked again.

**Cloaking.** `@@SECRET:name@@` in a `terminal/create` (command, args, env) is
resolved just before the editor runs it, and an unknown placeholder fails closed.
Raw secret values in terminal output and file reads come back to the agent as
placeholders. File reads are masked with cloak placeholders only, because those
can be reversed: when the agent writes the edited file back, the placeholders
the proxy masked out of *that file* become the real values again. A
data-boundary mask can't be reversed and would end up in the user's file. A
write never resolves any other placeholder, so it can't be used to copy a secret
into a new file.

Note that the editor runs the resolved command, so it may show the real value
in its own terminal view. The model never sees it.

**Pause.** `prismor pause` lifts enforcement here as it does for hooks. Calls are
still evaluated and logged, and cloak masking keeps running.

## Coverage: what the proxy cannot see

The proxy only sees what crosses the pipe. Agents differ a lot in what they
route through the editor, and in practice most run their own tools:

| Agent (tested version) | Runs Bash/edits through the editor? | What the proxy can enforce |
|---|---|---|
| `claude-agent-acp` 0.93 | No: in-process | The permission request, when Claude asks. Claude does not ask for read-only commands, or for tools allow-listed in `~/.claude/settings.json` |
| `codex-acp` 2.2 | No: in-process | Permission requests, when Codex asks. Its own reviewer auto-approves many |
| an agent that implements fs/terminal via the client | Yes | Everything in the table above |

For tools the agent runs itself, the proxy does what it can after the fact: it
follows the agent's `tool_call` updates, screens each completed call and its
output in observe mode, writes them to the session ledger (so taint and
crossover rules see them), and tells the person in the editor when policy would
have refused a call it could not stop. **To enforce on in-process tools, keep
the agent's native Prismor hooks installed** (`prismor setup`). The proxy and
the hooks layer cleanly. If the hooks already record those calls, run
`prismor acp --no-audit -- …` so they are not recorded twice.

Tools an agent runs without reporting them to the editor at all (some run a
built-in web fetch that way) are invisible here. Only the agent's own hooks, the
[LLM proxy](llm-proxy.md) or the [mirror](mcp-gateway.md#mirrored-built-ins---mirror-prismor-mirror)
can govern those.

On start the proxy logs which client capabilities the editor offered, for
example:

```
[prismor-acp] governing claude-agent-acp (mode=enforce); editor offers: fs.readTextFile, fs.writeTextFile, terminal
```

An editor that does not offer `terminal` makes every agent run its commands
in-process. If an agent calls a client method anyway, the proxy answers
method-not-found itself rather than forwarding it. Some editors (CodeCompanion)
never answer an unadvertised call, and the agent's turn would hang.

Neovim (CodeCompanion), override the ACP adapter's command:

```lua
require("codecompanion").setup({
  adapters = { acp = { claude_prismor = function()
    return require("codecompanion.adapters").extend("claude_code", {
      commands = { default = { "prismor", "acp", "--", "claude-agent-acp" } },
    })
  end } },
  interactions = { chat = { adapter = "claude_prismor" } },
})
```

## Options

```
prismor acp [--mode enforce|observe] [--workspace PATH] [--no-audit] -- <agent command…>
```

- `--mode`: `enforce` (default) refuses what policy refuses; `observe` relays
  everything and logs what it would have refused.
- `--workspace`: policy and session store to use. Without it, each ACP session
  uses its own `cwd` from `session/new`.
- `--no-audit`: skip the after-the-fact screening of in-process tool calls.

The proxy exits with the agent's exit code. Its own diagnostics go to stderr,
which editors keep in their agent log (in Zed: `dev: open acp logs`).

## Tested with

| Client | Offers | Verified |
|---|---|---|
| Zed 1.24.2 | fs read/write, terminal | `.env` read and `curl … \| sh` terminal refused, with the error shown in the thread; write and terminal relayed through Zed's buffers and terminal; injected file withheld; Claude's `curl … \| sh` permission refused without a prompt; `touch` reached Zed's Yes/No prompt |
| Emacs agent-shell 0.87.10 | fs read/write (no terminal) | Same Claude permission split, with the notice in the buffer; fake-agent `.env` read refused; in-process fetch output flagged |
| Neovim 0.12.6 + CodeCompanion.nvim (8611841) | fs read/write (no terminal) | Claude permission split with the notice in the chat; fake-agent `.env` read and `curl … \| sh` refused; injected README withheld |
| acpx 0.19.6 | fs read/write, terminal | Refusals before acpx ran anything; Claude permission split |
| Python ACP SDK 0.12.1 | as configured | The proxy's own messages (notices, step-up prompts) pass the SDK's schema validation; cloak round trip; step-up approve and reject |

Emacs (agent-shell), set the Claude command:

```elisp
(setq agent-shell-anthropic-claude-acp-command
      '("prismor" "acp" "--" "claude-agent-acp"))
```

Agents: `claude-agent-acp` 0.93 and `codex-acp` 2.2 (both run their tools
in-process, see [Coverage](#coverage-what-the-proxy-cannot-see)), plus a
scripted agent that exercises every client method.
