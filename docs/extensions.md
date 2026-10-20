# Extension Ledger

A skill, a plugin, a hook command, an MCP server: each one is something that
arrived on the machine from somewhere and now puts instructions or code into
your agent. Most of them are installed by a command no hook ever sees
(`claude plugin install`, `npx skills add`, a teammate's setup script), so the
first time a security tool hears about them is when the agent is already
following them.

The extension ledger is one inventory for all of them, with four questions
answered per entry:

| Question | How it is answered |
|---|---|
| Where is it, where did it come from | Paths are read from the agent's own registries (`installed_plugins.json`, `known_marketplaces.json`, the `hooks` and `enabledPlugins` keys of `settings.json`, MCP configs). Origin is the git remote and commit when there is one. |
| Who installed it | The session that ran the install command, or `out-of-band` when nothing Prismor governs did it. |
| What can it do | Static capabilities: `runs_code`, `declares_hooks`, `network`, `remote_instructions` (it tells the agent to go read instructions from a remote host). |
| What did it cause | Which sessions invoked it, which remote documents they then fetched, and whether those documents changed since. |

```bash
prismor extensions list                 # everything, exit 1 if anything is NEW or CHANGED
prismor extensions list --kind hook     # skill | plugin | hook | mcp
prismor extensions why vendor-ai       # the chain for one extension
prismor extensions approve <id>         # accept after review
```

```
  [    NEW] skill  vendor-ai
            id: skill:~/.claude/plugins/cache/vendor/vendor/1.2.0/skills/vendor-ai/SKILL.md
            origin: vendor-ai/skills@65a39f393687
            installed by: out-of-band
            can: remote_instructions
            hosts: docs.vendor-ai.dev
```

The first sync on a machine records what is already there as the baseline.
After that, every new or changed extension is written once to the
[signed audit trail](audit-trail.md) as a `record_type: "extension"` record, and
named to the agent at session start until a human approves it.

## Turning an extension off

Every plugin, skill, MCP server and third-party hook has an **On** switch in the
dashboard (Extensions, on each kind's tab and on the extension's own page).
Each kind is switched off where it can really be switched off:

| Kind | What "off" does | Takes effect |
|---|---|---|
| Plugin | Turned off in the agent's own config. Claude Code: `false` under `enabledPlugins` in `~/.claude/settings.json`, the same switch as `claude plugin disable`. Codex: `enabled = false` under `[plugins."<id>"]` in `~/.codex/config.toml` (only that line is edited). Its skills, hooks and MCP servers do not load. | New sessions |
| Skill | Prismor blocks the agent from using it (rule `extension-disabled`), in observe mode too: Claude's `Skill` call, and any command or file read that touches the skill's folder (Codex reads skills with `cat`), including `~/` and wildcard spellings of the path. | Next call |
| MCP server | Prismor blocks the agent's calls to any of the server's tools. Servers in Codex's `config.toml` (`[mcp_servers.<name>]`) are listed alongside the JSON configs. | Next call |
| Hook | The one hook is routed through `prismor exec-hook`, which skips it (exit 0, no output). Turning it back on restores the original entry byte for byte, so the hash Codex trusted it by matches again. Hooks are read from Claude's settings and from Codex's `hooks.json`. | Next run |

### Per agent

Verified end to end with each agent's own CLI (October 2026, model
`gpt-5.6-luna`), switching each extension off and on through the dashboard's
call and checking the agent's behaviour:

| Agent | Plugins | Skills | MCP servers | Hooks |
|---|---|---|---|---|
| Claude Code | `enabledPlugins` | `Skill` call, folder reads | `mcp__server__tool` | settings.json |
| Codex | `[plugins."<id>"] enabled` in config.toml | folder reads (`cat`) | config.toml `[mcp_servers]` | hooks.json |
| goose | (its plugin hooks are listed one by one) | `load_skill`, folder reads | config.yaml `extensions`; `<ext>__<tool>` calls, Code Mode (`execute_typescript`) and the model's own `manage_extensions enable` are blocked | `~/.agents/plugins/*/hooks/hooks.json` |
| OpenHands | n/a | `invoke_skill`, folder reads (relative paths too) | `~/.openhands/mcp.json`; off sets the server's own `"enabled": false` | `.openhands/hooks.json` |
| Hermes | `plugins.enabled` / `plugins.disabled` via `hermes plugins` | `skill_view`, `read_file`, folder reads | config.yaml `mcp_servers` | n/a |
| OpenClaw | `plugins.entries.<id>.enabled` via `openclaw plugins` | `read`, `exec`, folder reads | no MCP client in 2026.3 | n/a |

Known limits: OpenHands sends MCP calls by bare tool name, so a session that
was already running when its server was turned off can still call it until it
restarts (new sessions never load the server). goose's own `enabled: false` on
an extension is not used, because the model can switch it back on itself;
Prismor blocks the calls instead.

The list of what is off is kept in the ledger (`~/.prismor/extensions.json`),
so it applies on the whole machine. Each switch is written to the signed audit
trail as `extension_disabled` / `extension_enabled`, and every skipped hook run
as `hook_skipped`. A skill or hook inside a plugin that is off shows as off, and
turns back on with the plugin. Prismor's own hooks are not extensions and have
no switch.

Skills and MCP servers stay installed while off: the agent may still see them
listed and try them, and Prismor stops the call. Blocking a skill's folder is a
match on the command: a command that finds the file without naming its path
(`find ~ -name SKILL.md | xargs cat`) is not caught. Turn off the plugin it ships
in, or remove the skill, when that matters. To remove one entirely, use the
agent's own command (`claude mcp remove <name>`, deleting the skill folder).

## Sessions are attached to what they ran under

An investigation starts from a session: someone sees a tool call and asks what
told the agent to do that. So the attachment runs both ways.

- Every session records the skills it loaded, the MCP servers whose tools it
  called, and the third-party hooks that were registered while it ran.
- Every tool call an extension caused carries that extension: the skill load
  itself, a fetch to a host the skill named, a call to an MCP server's tool. The
  tag is an id, a name and a review flag, so it survives redacted telemetry and
  is written into the signed trail record as `extension_id`.
- A finding raised while the session runs under an extension nobody has
  reviewed carries `unreviewedExtensions`.

### Three levels, one ledger

The session is the grain. The other two levels are sums of it.

| Level | Question it answers |
|---|---|
| Session | What did this run load, and which calls did each extension cause? |
| Agent | What can this agent load, what have its sessions actually used, and what has it never used? |
| Device | What is installed on this machine, where did it come from, and who installed it? |

Each ledger row records which agents load it, taken from where it lives on disk
(`claude`, `codex`, `gemini`, `cursor`, or `any` for the shared `.agents/`
directory). Each session records the agent that ran it. A skill, plugin or MCP
server that no recorded session has loaded is marked never used. An MCP server
that a session calls but that no config file describes, such as one brought by a
browser extension, a hosted connector or a plugin, is recorded the first time it
is used, as `installed by: observed` and unreviewed. Hooks are not,
because they run whether or not anything uses them.

The session page has an "Extensions in this session" panel: each extension with
its origin, who installed it, the calls it caused in that session, the documents
it sent the agent to read, and a review button. The Extensions tab opens on the
by-session view, with by-agent and installed views beside it. The agent page
carries the same rollup for that agent.

## Installs

An install the agent runs itself (`claude plugin install`, `npx skills add`,
`claude mcp add`, `gemini extensions install`) raises the warn-level finding
`extension-install`, and whatever appears afterward is attributed to that
session. Add the rule to your enforce list to require approval instead.

An install nobody governed is caught by the registry check: one `stat` per
registry file on each prompt, and a full sync only when something moved.

## Untrusted text gets a grain of salt, not a wall

Blocking reads makes a skill useless and teaches people to turn enforcement
off. The ledger takes the other route: reading is allowed and recorded, and
what was read does not get to steer.

**Scope.** A [session scope](scoped-agent.md) is synthesized from the user's
prompt and never sees a skill's body, so it used to deny the very fetches a
skill's instructions depend on. When the agent loads a skill, the hosts that
skill names become readable for that session, and nothing else changes. Skill
text can never add a tool, a path or an outbound send. Only the user's prompt
grants those. A scope a human edited is left alone.

**Remote documents.** For hosts a loaded skill sent the agent to, each document
is pinned by hash, so a change between sessions is recorded as
`remote_ref_drift`. Both the raw document and the summary the model was shown
run through the prompt-injection rules. The agent is told once per host that the
content is reference material and what it must not do on its say-so. Set
`PRISMOR_EXT_PIN=0` to skip the second request pinning needs.

## Third-party hooks

A plugin's hooks are code that runs on every tool call, outside anything an
agent hook can observe. They are inventoried with the script hash and every
host named in the directory they ship in, which is usually where a telemetry
endpoint lives.

To record each run, route them through Prismor:

```bash
prismor extensions wrap-hooks      # each third-party hook run becomes a hook_executed record
prismor extensions unwrap-hooks    # restore the originals
```

A plugin update restores its own `hooks.json`. Set `PRISMOR_WRAP_HOOKS=1` to
re-apply the wrapper at every session start. Wrapping records execution. It does
not sandbox the hook.
