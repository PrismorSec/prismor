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
