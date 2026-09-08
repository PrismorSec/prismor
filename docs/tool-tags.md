# Tool Tags & Tag Rules (policy as code)

Every tool an agent can call — built-in, shell, or MCP — carries zero or more
**tags** describing what it does: `untrusted_content` (reads
attacker-influenceable input), `critical_action` (sends / publishes / destroys
externally), or any tag you define (`private_data`, `external_comms`, …).
**Tag rules** then declare which tag combinations must never complete — the
classic "lethal trifecta" (read untrusted content, then act externally) is just
the default rule.

The call that *completes* a forbidden combination is blocked before it
executes. Everything is observable first (`mode: observe`), then enforceable.

Two things make this hold up outside a demo:

- **Influence.** Reading a page and later running a command is what a working
  day looks like; the default rule blocks only when the command's own arguments
  reuse text from what was read. See [Influence](#influence-what-separates-a-sequence-from-an-attack).
- **Provenance.** A session is not the boundary. Tags follow the files agents
  write to each other, so an agent acting on another agent's output inherits
  what that agent had read. See [Cross-agent flow](#cross-agent-flow).

## How a tool gets its tags (precedence)

| Tier | Source | Who controls it |
|------|--------|-----------------|
| 1 | Explicit map — `tool_tags.tags` in policy (exact, glob, or regex) | You / org admin |
| 2 | Server-declared — `_meta.prismor.tags` on the MCP tool definition, read by `prismor mcp-gateway` | MCP server author |
| 3 | Built-in defaults — well-known tools (`WebFetch`, `mcp__*__send_email`, …) | Prismor |
| 4 | Inference — a network response is untrusted; a call the rules judged destructive is critical | Prismor |

The first non-empty tier wins, so an admin's explicit tag always beats a
server's self-declaration, which beats generic globs. Nothing is ever left
completely untagged unless you disable tiers 3–4.

Check what resolved where:

```console
$ prismor tags list
TOOL                        TAGS                 TIER
Bash                        (untagged)           -
WebFetch                    untrusted_content    default
mcp__crm__read_customers    private_data         _meta
mcp__Gmail__send_email      critical_action      explicit
```

Inference is deliberately thin. Being a shell call, a file write, or an MCP
result is not by itself evidence of anything: replaying the old, wider
inference over 391 real development sessions blocked 213 of them, because
`grep` counted as critical for being shell and the agent's own transcripts
counted as untrusted for sitting outside the workspace. What a tool *is* comes
from tiers 1–3; what a call *does* comes from the rule engine's own verdict
(`destructive_command`, `remote_execution`, `privilege_escalation`, …).

### Declaring tags from an MCP server (`_meta`)

If you author an MCP server, self-declare tags on each tool definition and the
gateway picks them up automatically — no spreadsheet, no manual mapping:

```json
{
  "name": "read_customers",
  "inputSchema": { "type": "object" },
  "_meta": { "prismor": { "tags": ["private_data"] } }
}
```

Also honored: `_meta.tags` and `annotations["prismor/tags"]`. Tags are
sanitized (lowercase, `[a-z0-9][a-z0-9_.-]*`, max 8) — a server can suggest
tags but can never override the org map or inject arbitrary strings.
Disable the tier with `meta_tags_enabled: false`.

## The rule language

One rule per line. Three keywords. That's the whole grammar:

```
rule    :=  TAG ( then|with TAG )*  [ -> block|warn ]
```

- **`with`** — unordered co-occurrence: both tags appearing anywhere in the
  session is enough.
- **`then`** — ordered sequence: the left step must occur *before* the right.
- **`-> block`** (default) or **`-> warn`** — warn logs the finding but never
  blocks, even in enforce mode.
- The call completing the **final step** is the one blocked/warned.
- `not`, `or`, `within`, `count` are reserved for future use.

```yaml
settings:
  tool_tags:
    enabled: true
    mode: enforce            # observe (log only) | enforce (terminal block)
    tags:
      mcp__Gmail__read_email: [untrusted_content]
      mcp__Gmail__send_email: [critical_action]
      mcp__crm__*: [private_data]
    rules:
      - "untrusted_content then critical_action -> block"
      - "untrusted_content then private_data then external_comms -> block"
      - "web_read with secrets_access -> warn"
```

More examples:

```
untrusted_content with critical_action -> block    # either order
untrusted_content then critical_action -> block    # read first, act later
untrusted_content with private_data then external_comms -> block
customer_pii then external_comms                   # implicit -> block
```

### `with` vs `then`, concretely

Session: `send_email` (critical) → `read_email` (untrusted) → `send_email`.

- `untrusted_content with critical_action` fires at call **2** — both tags now
  co-occur, order irrelevant.
- `untrusted_content then critical_action` allows calls 1–2 and fires at call
  **3** — the first critical action *after* untrusted content entered the
  session. Ordered rules cut false positives when a critical-first pattern is
  normal for your agents.

### Backward compatibility (guaranteed)

The pre-existing form keeps working forever and can be mixed with `rules:`:

```yaml
    incompatible:                       # same as "a with b -> block"
      - [untrusted_content, critical_action]
```

Both compile to the same internal representation. A policy with only
`incompatible` behaves byte-for-byte as before; if *neither* list is set, the
default red/blue pair applies. Old runtimes simply ignore an unknown `rules:`
key — there is no fleet flag day.

## Influence: what separates a sequence from an attack

`untrusted_content then critical_action` describes an afternoon of ordinary
work as accurately as it describes an attack. What distinguishes them is
whether the untrusted content is *steering* the action:

```
fetched a changelog, then pushed your own branch     sequence     ordinary
fetched a page, then ran the command the page named  influence    attack
```

Prismor tags the second case `untrusted_influence`: the critical call's own
arguments reuse a distinctive phrase (a token 3-gram) from untrusted content
the session read. This is why an injected instruction is catchable at all — the
attacker's command has to reach the tool call more or less verbatim, or it
stops doing what the attacker asked.

So the shipped defaults are:

```yaml
rules:
  - "critical_action with untrusted_influence -> block"   # act on what was read
  - "untrusted_content then critical_action -> warn"      # the sequence itself
```

Replayed over 423 real development sessions with provenance active, the
shipped defaults block 4 and warn on 144. The same corpus under the old rule
blocked 213. The 4 are an upper bound: the replay approximates the critical
side with a regex, and the real rule engine is narrower still -- it tags
`psql ... DROP TABLE` critical but not `git push`, `npm publish` or `kubectl
apply`, so with only the engine's own verdicts the corpus blocks none.

The finding names the source, not just the fact:

```
Forbidden tool combination: 'mcp__prod__execute_sql' completes [critical_action, untrusted_influence]
  call adds tag(s) ['critical_action', 'untrusted_influence'];
  via: claude:s-1a2b -> /repo/shared/handoff.md -> codex:s-9f3e;
  reuses text from claude:s-1a2b -> /repo/shared/handoff.md: ['drop table users']
```

Set `influence_enabled: false` for the older, blunter behaviour (any sequence
blocks).

Known limits:

- It is a phrase match, so a generic phrase appearing both in a fetched page
  and in, say, a commit message can produce a false block. Four times in 423
  sessions, on phrases like "single tool call".
- It only fires on calls the engine already judges critical. An injected
  `npm publish` is not blocked, because nothing tags `npm publish` critical.
  Widening that set widens the blocking surface with it, so tag the tools you
  actually care about (`tool_tags.tags`) rather than relying on inference.

## Cross-agent flow

Agents that never exchange a message still communicate whenever one writes a
file another reads. The filesystem is the protocol, and per-agent permissions
cannot see it:

```
        internet                          production
            |                                  ^
            v                                  |
       [ agent A ]  --write-->  plan.md  --read-->  [ agent B ]
     (no prod access)                          (no internet access)
```

Neither agent holds both capabilities; the pair does.

![Agent A fetches a poisoned release page and writes a handoff note; agent B, in a separate session, reads the note and its database call is blocked, with the evidence naming the chain from A through the file to B](tool-tags/cross-agent-block.png)

Prismor defines an agent-to-agent interaction without reference to any
agent-to-agent protocol:

> B communicated with A when B consumed state whose provenance includes A.

A write records which session wrote the file and what that session was
carrying; a read hands those tags to the reading session, which turns the
cross-agent case into the in-session one the rules above already govern. The
reader also picks up two tags of its own:

| Tag | Meaning |
|-----|---------|
| `via.artifact` | this call is reading a file another session wrote |
| `from.<agent>` | ...written by that agent |

which lets a policy be stricter about crossing an agent boundary than about the
content itself, with no new grammar:

```yaml
rules:
  - "via.artifact then critical_action -> warn"        # approve handoffs
  - "data.secret with via.artifact -> redact"          # never hand a credential on
  - "from.research-agent then critical_action -> block"
```

Shell-only agents are covered on both sides, and both halves are needed. A
fetch marks its target file untrusted *and* makes the fetching session
untrusted, so the note that session writes next carries the tag; redirects,
`tee`, output flags and `cp`/`mv` destinations are recorded as writes, and
arguments that exist as files count as reads. Running the two-agent handoff
with live agents is what found this: Codex reaches the web through Bash, so
with only the file half the downloaded page was marked and the handoff note
written from it was not, and the injected instruction reached the second agent
intact.

Inspect what was recorded:

![prismor tags provenance listing the handoff file, its untrusted_content tag, the claude session that wrote it and the codex session that read it, marked cross-agent](tool-tags/provenance.png)

Every cross-agent read also emits an observe-mode `provenance` finding
(ruleId `cross-agent-flow`), so the causal edge is in the console whether or not
a rule fires.

Limits, deliberately:

- **Same machine.** The store lives under `$PRISMOR_HOME`, shared by every
  agent on the device. Carrying edges between machines needs the control plane.
- **Hooked writes only.** An editor, or an agent Prismor is not installed in
  front of, writes without leaving a record.
- **Session granularity.** A session that read something untrusted marks
  everything it writes afterwards, not only the bytes derived from that read.
  The influence check is what keeps this coarseness from causing false blocks.

The same handoff with a page that is not hostile goes through untouched, and
is still recorded:

![The same four-step handoff run against a benign page: every call allowed, with a note that the work goes through and the handoff is on the record either way](tool-tags/benign-handoff.png)

The whole sequence as an animation: [demo.gif](tool-tags/demo.gif).

Disable with `provenance_enabled: false`.

## CLI

```console
$ prismor tags list                  # tools seen + resolved tags + tier
$ prismor tags provenance [PATH]     # who wrote what other agents are reading
$ prismor tags set 'mcp__crm__*' private_data
$ prismor tags rm  'mcp__crm__*'
$ prismor tags rules                 # active rules (DSL + legacy + default)
$ prismor tags rules add "untrusted_content then critical_action -> block"
$ prismor tags rules rm 0
$ prismor tags edit                  # interactive wizard
$ prismor tags lint                  # validate every rule expression
```

Invalid expressions fail with a caret diagnostic:

```console
$ prismor tags rules add "a then not b"
invalid rule:
  a then not b
         ^ 'not' is reserved for future use
```

### Test rules against real session logs (dry run)

Before enforcing anything, replay your recorded sessions through a candidate
ruleset. Nothing is blocked and no enforcement state is touched:

```console
$ prismor tags test --last 10
demo-session-1  2 hit(s) in 3 events
  [  2] WOULD BLOCK mcp__Gmail__send_email
        rule: untrusted_content then critical_action
        prior: untrusted_content by 'mcp__Gmail__read_email' at event 0

$ prismor tags test --rule "private_data then external_comms -> warn"   # what-if
$ prismor tags test --session <id> --fail-on-hit                        # CI gate
```

Recommended rollout: `mode: observe` → watch findings / `tags test` → tighten
tags → flip to `enforce`. An enforce block is terminal and non-overridable
(part of Prismor's safety floor).

## Semantics reference

- Any number of same-tag calls is always allowed; only *completing* a
  forbidden combination fires.
- A session that has entered the forbidden state stays restricted — every
  later call carrying a final-step tag keeps firing.
- A blocked call never executes, so its tags do not enter the session ledger
  (one denied call can't "use up" the rule).
- `warn` rules log a `lethal_trifecta` finding but never block — even under a
  device-level enforce override.
- Findings: category `lethal_trifecta`; ruleId `tool-category-crossover`
  (legacy/default rules) or `tag-rule:<id>` (expression rules). Both are part
  of the non-overridable enforcement floor.
- Per-session state lives under the Prismor data dir in `trifecta/<session>.json`;
  `prismor tags test` uses an in-memory replay ledger and never touches it.
- Influence grams live beside it in `trifecta/<session>.grams.json`, hashed —
  untrusted text is never written to disk. Artifact provenance is device-wide,
  in `provenance.json`.
- Grams carry the event index that recorded them, and only content from
  strictly earlier events counts: the session pre-pass has already written this
  event's own content by the time the call is screened, so without the bound a
  call would report itself as steered by itself.
- Tags that describe a *call* (`critical_action`, `untrusted_influence`,
  `egress.*`, `dest.*`) never travel with an artifact; content tags
  (`untrusted_content`, `data.*`, and your own) do.
- `prismor setup` regenerates `.prismor/policy.yaml`. Keep a hand-written
  `tool_tags` block in the org policy, or re-add it after running setup.
