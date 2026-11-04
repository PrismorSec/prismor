# Event types: how a tool call is judged

*What Prismor turns each tool call into before any rule runs, which rules each
type gets, and what "Unclassified" means on the console. Companion to
[docs/enterprise-tool-access.md](enterprise-tool-access.md) and
[docs/tool-tags.md](tool-tags.md).*

---

## One event shape for every agent

Claude Code calls its shell tool `Bash`. Codex calls it `exec_command`, Cursor
calls it `run_terminal_cmd`, and a LangChain agent might call it `terminal`. Each one
sends its arguments in a different shape. Prismor maps every call to one
**event type** and copies the value that matters into one **field**:

| Event type | Console label | Field rules read | Typical tools |
|---|---|---|---|
| `shell` | Shell command | `command` | Bash, PowerShell, `exec_command`, `run_terminal_cmd`, SDK tools with a `command`/`cmd`/`script`/`code` argument |
| `file_read` | File read | `path` | Read, `read_file`, `view`, an upload (it reads a local file) |
| `file_write` | File write | `path` (+ `content`) | Edit, Write, `apply_patch`, `write_file` |
| `network` | Network | `url` (+ `outbound_payload`) | WebFetch, `fetch`, browser `navigate`, a remote MCP server |
| `subagent_spawn` | Subagent | `content` | Agent/Task, OpenAI handoffs, CrewAI delegation |
| `tool_result` | Unclassified | `response` | Local (stdio) MCP tools, skills, any tool Prismor can't place |
| `prompt` | — | `prompt` | The user's prompt |

Rules are written against the type, not the tool name. `destructive-command`
says "on `shell`, look at `command`", so it covers every agent above without
listing their tool names. **That is why one policy applies across all agents.**

## "Unclassified" (`tool_result`)

A call is Unclassified when the tool name and its arguments don't say what it
does. Its arguments are serialized to JSON and put in `response`.

It is not skipped. It still gets:

- **Tool access by name.** The Allowed/Denied toggle and `tool_denies` match the
  exact tool name (`mcp__github__create_issue`, `Skill:wiki-query`, `Monitor`).
- **The content rules.** These read text and match any type:

  | Rule | Looks for |
  |---|---|
  | `prompt-injection` | instruction override, system-prompt extraction, covert exfiltration |
  | `prompt-injection-hidden` | injection hidden in HTML comments or invisible elements |
  | `bulk-pii-exfiltration` | requests to export whole datasets of personal data |
  | `pii-exposure` | SSNs, card numbers, US phone numbers |
  | `model-manipulation` | overriding model parameters, tampering with tool definitions |
  | `skill-self-persist` | text telling the agent to persist and auto-update from a URL |

- **Everything that isn't type-specific:** tag rules ([tool-tags.md](tool-tags.md)),
  rules with the `mcp` event type, the LLM judge when enabled, and cloak's
  secret scan.

What it does **not** get is the action rules: every rule on `shell`,
`file_read`, `file_write` and `network`, which is most of the policy. Those rules
read `command`, `path` or `url`, and an Unclassified call leaves them empty.

So a local MCP tool called `run` with `{"cmd": "rm -rf ~"}` is allowed unless its
name is denied or its text trips a content rule. `destructive-command` never
sees it.

**Unclassified is not an error.** For a tool that only returns data, it is the
right type. It is a gap when the tool runs commands, touches files or calls
URLs.

## Correcting a type ("Judged as")

On the console, open an agent's Tool access panel. Each tool shows
**Judged as** with the type its latest call got:

- **(as reported)** is what the runtime decided.
- **Amber** means an admin corrected it. **"was X"** shows the original type.
- **Rose** means Unclassified.
- An org-wide correction shows as **"X (org-wide)"** and is read-only on the
  agent page.

Picking a type ships a signed `classify` entry in `settings.tool_denies`.
Before policy runs, the runtime retypes that tool's calls:

- It fills the new type's field from the call's arguments:
  - `command`/`cmd`/`script`/`code` → `command`
  - `path`/`file_path`/`file_name`/… → `path`
  - a URL argument → `url`
- The original text moves to `content`, so the content rules still see it.
- The event records `metadata.type_override` (`from`, `to`, `tool`, `scope`) for
  the audit trail.

A device, agent or session correction beats an org-wide one.
Choosing "(as reported)" removes this scope's correction. Runtimes older than
the release that added `classify` ignore the entry.

The same entry over the API:

```http
POST /api/admin/tool-policy
{"orgId":"<org>","tool":"mcp__acme__run","action":"classify","type":"shell","scope":"agent","scopeId":"checkout-bot"}
```

## Finding out for yourself

The rules that apply to a type, with titles:

```bash
prismor policy export | jq -r '.rules[] | select(.event_types|index("tool_result")) | "\(.id)\t\(.title)"'
```

How many rules each type gets:

```bash
prismor policy export | jq -r '[.rules[].event_types[]] | group_by(.) | map("\(.[0]) \(length)") | .[]'
```

What type your recent calls got:

```bash
prismor query "SELECT ts, type, coalesce(json_extract(raw_json,'$.tool_name'), json_extract(raw_json,'$.metadata.tool_name'), json_extract(raw_json,'$.mcp_tool')) AS tool FROM events ORDER BY ts DESC LIMIT 20"
```
