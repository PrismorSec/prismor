# Governance surfaces

Prismor can sit in front of an agent several ways. They are not interchangeable,
and picking the wrong one is the difference between complete coverage and a
control the model can walk around.

All of them reach the same verdict on the same action — they share one policy
engine through the [decision contract](decision-contract.md). What differs is
where they can intercept and what they can do there:

| surface | what it governs | refuse | rewrite input | redact output |
|---|---|:--:|:--:|:--:|
| **Hooks** | an agent's entire tool surface | yes | Claude/Qwen only | no |
| **MCP gateway** | every MCP server behind one connector | yes | yes | yes |
| **Mirror** | the agent's own built-ins, served over MCP | yes | yes | yes |
| **SDK adapters** | in-process framework agents | yes | no | no |
| **eval-server** | non-Python callers and external proxies | yes | yes | yes |
| **LLM proxy** | the agent's model traffic, including agents with no hooks | yes | yes | yes |
| **Inference hook** | a hosted transcript-turn channel | yes | no | no |

Run `prismor surfaces` to see which of these are switched on for each agent
detected on this machine, and which are possible but off.

The rest of this page is about the two that govern a coding agent on a
developer's machine, where the choice is a real decision. For the others:
adapters ship with each framework (see `docs/frameworks-overview.md`), the
eval-server is documented in the [decision contract](decision-contract.md), the
LLM proxy in [the LLM proxy page](llm-proxy.md), and the inference-hook channel
in `docs/inference-hook.md`.

One note on the LLM proxy, because it is the only surface that does not need
the agent's cooperation: every other row requires something to be hooked,
wired, or imported. The proxy requires only that model traffic pass through a
URL you control, which makes it the fallback for an agent that supports none of
the others — and the reason to reach for it *last* when the agent does, since a
hook sees tool calls the model never routes through an API.

## Hooks vs the MCP mirror

**Hooks (`PreToolUse` / `PostToolUse`).** The agent calls Prismor before each
tool call and obeys the verdict. The agent keeps its own tools; nothing is
replaced; everything it can do is screened, including tools Prismor has no
mirror for. Installed by `prismor setup` or `prismor install-hooks`.

**The MCP mirror (`prismor mirror on`).** Prismor serves look-alike built-ins
(`Bash`, `Read`, `Write`, `Edit`, `Glob`, `Grep`, `WebFetch`) over MCP and the agent's own
are switched off. The tool then runs *inside* Prismor, which buys the one thing
a hook structurally cannot do: the output can be **repaired** instead of merely
refused, so a hardcoded credential in ordinary source is redacted before the
model sees it rather than the whole file being blocked.

## Which to use

**Hooks, wherever the agent has them.** They cover the agent's entire tool
surface, they do not depend on the host offering a way to disable its built-ins,
and there is nothing in the model's tool list to go wrong. `prismor setup`
installs hooks, and the agent screen marks each agent's available surfaces.

**The mirror when there are no hooks.** For agents with no hook protocol, MCP is
the only interposition point that exists — without it Prismor cannot see the
agent at all.

**Both, only deliberately.** Hooks plus the mirror is supported and is what
gives you result-side redaction on a hook-capable agent, at the cost of more
moving parts: two layers screen the same call, and they only stay consistent
when both run the same Prismor build (`prismor mirror status` warns when they
do not). Prefer hooks alone unless you specifically want redaction.

Mirroring is bypassable wherever the host cannot switch its built-ins off — the
model simply calls the real `Bash` instead. Those agents are marked "no" below,
and Prismor does not offer a mirror for them rather than implying a control that
is not there.

## Coverage

| Agent | Hooks | Mirror | Recommended | Mirror scope | Notes |
|---|---|---|---|---|---|
| Aider | no | no | — |  | no MCP support at all |
| Amazon Q Developer CLI (AWS) | yes | yes | **hooks** | machine | from docs, not live-tested |
| Amp (Sourcegraph spinoff) | no | yes | **MCP mirror** | machine |  |
| Auggie CLI (Augment Code) | yes | yes | **hooks** | machine |  |
| Claude Code | yes | yes (verified) | **hooks** | project |  |
| Codex (OpenAI) | yes | yes (verified) | **hooks** | machine | user-level config only; mirrored calls need a sandbox mode that permits them |
| Continue CLI | yes | unknown | **hooks** |  |  |
| Crush (Charmbracelet) | yes | yes | **hooks** | project |  |
| Cursor | yes | yes | **hooks** | project | accepted in config, not runtime-verified |
| Devin CLI (Cognition AI) | yes | yes | **hooks** | machine | not runtime-verified |
| Factory Droid | yes | yes | **hooks** | machine | not persistent, so it cannot be enforced from config |
| Gemini CLI (Google) | yes | yes | **hooks** | machine | from docs, not live-tested |
| GitHub Copilot CLI | yes | no | **hooks** |  | per-command deny only, no first-class disablement |
| Google Antigravity | no | no | — |  | no disablement mechanism found |
| Goose (Agentic AI Foundation) | yes | yes | **hooks** | machine | seven separate extensions to turn off |
| Grok Build (xAI) | yes | yes | **hooks** | machine | flags exist, not runtime-verified |
| Hermes (NousResearch gateway) | yes | unknown | **hooks** |  |  |
| Kilocode | no | yes | **MCP mirror** | project |  |
| Kimi Code (Moonshot AI) | yes | yes | **hooks** | machine |  |
| Kiro CLI (AWS) | yes | yes | **hooks** | project | from docs, not live-tested |
| OpenClaw | yes | unknown | **hooks** |  |  |
| OpenCode | no | yes | **MCP mirror** | project |  |
| OpenHands | yes | no | **hooks** |  | include_default_tools is SDK-only, not exposed by the CLI |
| Pi Coding Agent | yes | yes | **hooks** | machine | MCP itself is a third-party adapter, not first-party |
| Qwen Code (Alibaba) | yes | yes | **hooks** | machine | from docs, not live-tested |
| Trae / Trae CN (ByteDance) | no | no | — |  | GUI only; disablement inferred, never confirmed |
| Warp (Agent Mode) | no | no | — |  | no native-tool removal, only ask/allow friction tiers |
| Windsurf (Codeium Cascade) | yes | unknown | **hooks** |  |  |

"Mirror scope" is where the switch applies, and it follows what the host
supports, not a Prismor preference. Claude Code keeps MCP servers and tool
permissions per project, so `prismor mirror on` governs one project. Codex reads
its MCP servers and feature flags only from the user-level config, so mirroring
it is machine-wide — the command says so before it changes anything.

## Choosing at setup time

`prismor setup` installs **hooks**. On the agent screen each agent shows the
surfaces available to it, and for agents where Prismor can wire the mirror,
`m` toggles it on for that agent:

```
  > *  Claude Code       detected    hooks   (m: add MCP mirror)
    *  Codex             detected    hooks
    o  OpenHands         not found   hooks

  No hook protocol - govern these with prismor mirror on:
    OpenCode, Amp, Kilocode
```

The mirror is **off by default and stays off unless you ask for it**: it
replaces the agent's own tools, which is not something a wizard should do to
someone silently. Choosing hooks only is the recommended setup and needs no
action. The confirm screen names both, so you can see what is about to be
installed before anything is written.

Wired hosts today are **Claude Code** (per project), **Codex** (machine-wide) and **OpenCode** (per project).
Other agents in the table can be mirrored by hand with `prismor mcp-gateway
--mirror`; the one-command setup lands per host as each is verified against a
real session, because a half-wired host leaves the agent with no tools at all.

`prismor setup --non-interactive` never installs the mirror -- there is no
screen to opt in on, so it stays hooks-only. Use `prismor mirror on` for that
case.

## Practical notes

- **Hooks are what `prismor setup` installs.** The mirror is a separate,
  explicit step: `prismor mirror on`, and `prismor mirror off` to undo exactly
  what it did.
- **Turning the mirror on renames the tools** to `mcp__prismor-tools__<Tool>`.
  Prismor records them under their native names so existing rules, allowlists
  and console filters keep matching, but anything outside Prismor that keys on
  the literal tool name (a host-side permission rule, for instance) needs the
  new name. `prismor mirror on` migrates the ones it owns.
- **`prismor pause` covers both surfaces.** It suspends enforcement for hooks
  and the gateway together, and auto-resumes after 24h.
- **Secret masking is not enforcement** and keeps running while paused, on both
  surfaces.

See [MCP Gateway](mcp-gateway.md#mirrored-built-ins---mirror-prismor-mirror) for
the mirror's mechanics and the exact per-host setup it performs.
