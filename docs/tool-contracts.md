# Tool Contracts

[Tool tags](tool-tags.md) say what a tool *is*, and tag rules forbid a
*sequence* of tags. That covers integrity ("untrusted text steering a critical
call"). It leaves two things unsaid:

- **Confidentiality.** "After this session reads the private `acme/billing`
  repo it may not post to a public issue, but it may still comment on an
  internal ticket."
- **Arguments.** `get_file_contents` on a public repo and on a private one are
  the same tool with the same tags. Real policy depends on the argument.

A **contract** says both. It is declared per tool, optionally narrowed by
argument selectors, and has three parts:

| Field | Meaning | Applied |
|---|---|---|
| `delta` | How the tool's **result** changes the session label | After the call succeeds |
| `requires` | What the session label must satisfy for the **call** to run | Before the call |
| `effects` | Side effects recorded once the call succeeds (`egress`, `write.prod`, …) | After the call succeeds; later contracts can require or forbid them |

```yaml
settings:
  tool_tags:
    enabled: true
    mode: enforce                # observe (report only) | enforce
    contracts:
      # Private repo reads narrow the audience to the org.
      - tool: mcp__github__get_file_contents(owner:acme, repo:billing*)
        delta: { audience: [org:acme] }
      # Public repo reads lower trust (anyone can write an issue body).
      - tool: mcp__github__get_issue(owner:*, repo:*)
        delta: { trust: untrusted }
      # Public writes need an unrestricted audience and trusted input.
      - tool: mcp__github__create_issue
        requires: { audience_contains: [public], trust: internal }
        effects: [egress]
      # The recipient must already be a valid reader of everything read so far.
      - tool: mcp__gmail__send_email
        requires: { audience_contains: [$to] }
        effects: [egress]
    principals:
      org:acme: [team:billing, "*@acme.com"]
```

A tool with no contract behaves exactly as it did before: nothing is checked,
nothing is recorded, and tags and tag rules decide as they always have.

## The session label

Every session carries a label with two dimensions.

- **audience** — the principals allowed to see what the session has read. It
  starts as `public` (unrestricted). Reading narrows it by intersection: read
  `org:acme` then `team:billing`, and the audience is `team:billing`.
- **trust** — `trusted` > `internal` > `untrusted`. Reading lowers it to the
  minimum seen.

The label **only ever gets more restrictive** within a session. There is no
`delta` value that widens it (`audience: [public]` and `trust: trusted` are
rejected by `prismor tags lint`), and nothing in a tool result, prompt or model
output can either. The label is stored as the list of narrowing events and
folded with an intersection, so even a hand-edited entry can add a restriction
and never remove one.

See the label of a session and what narrowed it:

```console
$ prismor tags label
s-1a2b3c
  audience  {org:acme} since mcp__github__get_file_contents(acme/billing) at 14:02
  trust     trusted
  effects   {}
```

### Principals

A principal is a name: `org:acme`, `team:billing`, `repo:acme/website`,
`bob@acme.com`. `public` is everyone. `tool_tags.principals` is a static map
from a principal to what is inside it — other principals, or address globs:

```yaml
principals:
  org:acme: [team:billing, team:eng, "*@acme.com"]
  team:eng: [team:infra]
```

Membership is transitive. Two principals the map does not relate are assumed
to share no readers: reading `org:acme` and then `org:other` leaves an
audience nobody is in. Resolving principals through an IdP or channel
membership is a follow-up; v1 is this map.

## Selectors

`tool:` is a tool name or glob, optionally followed by argument selectors:

```
mcp__github__get_file_contents(owner:acme, repo:billing*)
mcp__*__send_email(to:*@partner.example)
Read(path:secrets/**)
```

- Every selector must match. An argument the call does not carry does not
  match, so `get_issue(owner:*, repo:*)` means "a call that names both".
- Patterns are globs, matched case-insensitively (`Acme/Billing` is the same
  repo). A list-valued argument matches if any element does.
- A dotted name reads into nested arguments (`params.repo`).
- `path`, `url`, `command` and `query` fall back to the normalized event when
  the tool spells its argument differently (Claude's `Read` takes `file_path`).
  Paths are normalized and symlink-resolved, and also matched relative to the
  workspace, so `secrets/../secrets/key` does not walk past `secrets/**`.
- For a pattern the inline form cannot hold (a comma, a parenthesis), use the
  map form: `args: { query: "*(internal)*" }`.

`Read`, `Write` and `Edit` selectors work on hooked calls and on
mirrored ones (`prismor mirror`) alike: both report the same native event.

## `requires`

| Key | Passes when |
|---|---|
| `audience_contains: [p, …]` | every listed principal is in the session audience |
| `trust: internal` | session trust is at least that level |
| `effects: [e, …]` | each effect has been recorded in this session |
| `no_effects: [e, …]` | none of them has |

`audience_contains: [public]` means "the session has read nothing restricted".
A principal may bind a call argument with `$arg` (or `${arg.path}`):
`audience_contains: [$to]` checks every recipient, whether `to` is one address,
a list, or a comma-separated string, and `"repo:$owner/$repo"` builds one from
two arguments. If the argument is missing from the call, the requirement
fails once the audience is restricted — a recipient that cannot be read off
the call cannot be shown to be a valid reader.

A deny names the rule, the label, and the call that narrowed it:

```
Tool contract: create_issue requires audience ⊇ {public}; session audience is
{org:acme} since mcp__github__get_file_contents(acme/billing) at 14:02
  rule: tool-contract:3f9c1a2b7d [mcp__github__create_issue] (policy)
```

### Letting one call through

The label cannot be reset from inside a session. A human can approve a single
call from their own terminal; the label stays where it is and every other
contract still applies:

```bash
prismor allow tool-contract:<id> \
  --pattern '{"tool":"mcp__github__create_issue","arguments":{"owner":"acme","repo":"website","title":"Approved"}}' \
  --expires 30m --yes
```

`--pattern` is the complete call, as for [tag rules](tool-tags.md#allow-one-known-good-call).
A blanket allowlist (`rule_ids: ["*"]`, a match-anything pattern) does not
apply to contracts, and an org-managed workspace needs an admin exemption.

## `delta` and `effects`

Both are applied when the call's **result** arrives, because that is when the
model has seen it. A call that was blocked, or that failed, changes nothing.

`delta.audience` may bind arguments too: `audience: ["repo:$owner/$repo"]`.

The LLM proxy screens a tool call the model *proposed* and never sees its
result as an event of its own (it returns inside the next prompt). There the
delta is applied when the call is admitted.

## How a tool gets its contract

The same order as tags. The first tier with a match wins; within it every
matching contract applies, which is safe because a contract can only restrict.

| Tier | Source | Who controls it |
|---|---|---|
| 1 | `tool_tags.contracts` in policy | You / org admin |
| 2 | `_meta.prismor.contract` on the MCP tool definition, read by `prismor mcp-gateway` | MCP server author |
| 3 | Built-in packs for well-known tools | Prismor |
| – | No contract: tags and tag rules only, as before | |

A per-agent overlay (`tool_tags.agents.<name>.contracts`) appends to the fleet
list. It cannot remove a contract, and it cannot change `principals`.

### Declaring a contract from an MCP server

```json
{
  "name": "read_customers",
  "inputSchema": { "type": "object" },
  "_meta": { "prismor": { "contract": { "delta": { "audience": ["org:acme"] } } } }
}
```

The contract applies to the tool it is declared on (a `tool` key is ignored),
goes through the same validation as a policy contract, and is dropped whole if
any part of it is invalid. A server may not declare `effects`: they satisfy
`requires.effects`, so only policy can record them. Disable the tier with
`meta_contracts_enabled: false`.

### Built-in packs

The packs declare `delta` only. They teach the label what a well-known tool's
result is; what to require is your decision, so a pack can never block
anything by itself. Disable them with `contract_defaults_enabled: false`.

Prismor cannot see a repo's visibility or a channel's membership from a tool
call, so the packs take both from policy:

```yaml
contract_packs:
  github:
    private:                       # owner/repo globs
      "acme/billing*": [team:billing]
      "acme/*": []                 # default audience: repo:<owner>/<repo>
  slack:
    connect_channels: ["C0EXT*", "partner-*"]
```

| Pack | Call | Delta |
|---|---|---|
| GitHub | any read of a repo listed under `private` | `audience` → the mapped principals, or `repo:<owner>/<repo>` |
| GitHub | reading issues, PRs, comments, reviews, discussions in a `private` repo | also `trust: internal` |
| GitHub | reading them anywhere else | `trust: untrusted` |
| Slack | reading a channel listed under `connect_channels` | `trust: untrusted` |

A write contract that pairs with the GitHub pack:

```yaml
contracts:
  - tool: mcp__github__create_issue
    requires: { audience_contains: ["repo:$owner/$repo"] }
```

A session that has read `acme/billing` can still file an issue in
`acme/billing`, and nowhere else.

## Across agents

A file a session writes carries that session's label, so a note written after
reading `team:billing` hands that audience to whoever reads it next — the
[cross-agent flow](tool-tags.md#cross-agent-flow) tags already follow, with the
same rules: another writer's label stays alongside, a session rewriting its
own file replaces what it said before, and re-reading your own file teaches
you nothing.

```console
$ prismor tags provenance handoff.md
```

Labels travel at session granularity: everything a restricted session writes
is restricted, whether or not the text shows it. A paraphrase leaks as well as
a quote does. Per-file-version labels are a follow-up.

Disable with `provenance_enabled: false`.

## Testing contracts in CI

`prismor policy test` takes multi-step cases that share one session:

```yaml
tests:
  - name: private repo content can't reach a public issue
    steps:
      - { tool: mcp__github__get_file_contents, args: { owner: acme, repo: billing } }
      - { tool: mcp__github__create_issue, args: { repo: acme/website }, expect: block }
      - { tool: mcp__linear__save_comment, args: { issueId: ENG-1 }, expect: pass }
```

A step that is not blocked is taken to have run, so its `delta` and `effects`
apply to the steps after it. `expect` defaults to `pass`; `expect_rule` checks
the rule id.

## CLI

```console
$ prismor tags contracts          # contracts in the effective policy, with ids
$ prismor tags label [SESSION]    # a session's label and what narrowed it
$ prismor tags list               # gains a CONTRACT column
$ prismor tags lint               # validates contracts too
$ prismor tags coverage [--json]  # per MCP server: contract / tags only / neither
```

`tags lint` fails on an unknown field, an invalid value and a `delta` that
tries to widen the label, and warns when a contract's selector matches no tool
seen on this machine (recorded sessions and gateway listings).

`tags coverage` takes its servers from `prismor discover`, the gateway's tool
listings and recorded sessions:

```console
$ prismor tags coverage
SERVER                       TOOLS  CONTRACT  TAGS ONLY  NEITHER
github                          12         5          4        3
linear                           6         1          2        3
```

## Reference

- Findings: category `tool_contract`, ruleId `tool-contract:<id>`. The id is a
  hash of the contract, so it is stable until the contract changes.
- Mode follows `tool_tags.mode`. In `observe` a violation is reported and the
  label still narrows.
- State lives beside the tag ledger in `trifecta/<session>.label.json`.
  It holds tool names, the argument values a contract's selector named, and
  principals; never the rest of a call's arguments, and never tool output.
- Limits: surfaces that never deliver a result event (other than the LLM
  proxy) cannot apply a `delta`; the evaluation server keeps no per-session
  event order, so session state (tag rules and contracts alike) does not
  accumulate there; writes made outside a hooked agent carry no label; labels
  do not cross machines.
