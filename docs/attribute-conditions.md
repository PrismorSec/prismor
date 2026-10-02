# Attribute conditions (`when:`)

A rule's patterns say *what the call looks like*. `when:` says *who is making
it, against what, with which arguments*. A rule fires only when its patterns
match **and** its `when:` expression holds.

```yaml
rules:
  - id: refund-cap
    title: Refunds of 500 or more need the finance role
    severity: HIGH
    category: custom-authz
    event_types: [shell]
    fields: [tool_name]
    patterns: ['^refund_order$']
    when: "args.amount >= 500 and 'finance' not in principal.roles"
    action: block
    mode: enforce
```

This is attribute-based access control for agent tool calls. The same rule
governs an SDK adapter, the eval-server, the MCP gateway and the proxy, because
they all go through one [decision contract](decision-contract.md).

## What an expression can read

| Path | Value | Comes from |
|---|---|---|
| `principal.id` | end-user id | the resolved [subject](iam.md) |
| `principal.team`, `principal.org` | team / org id | subject |
| `principal.roles` | list of roles | **verified identity token only**; empty otherwise |
| `principal.claims.*` | token claims | verified identity token only |
| `principal.verified` | `true` for a verified token or an enrolled device | subject source |
| `principal.source` | `jwt`, `device`, `explicit`, `context`, `env`, `anonymous` | subject |
| `args.*` | the tool call's arguments | adapter / eval-server `arguments`, or a hook's `tool_input` |
| `resource.kind`, `resource.id`, `resource.attr.*` | the call's target | `resource` on the eval-server body or `evaluate_tool_call(resource=...)` |
| `tool.name` | tool name | `metadata.tool_name` |

A caller can *name* a user (`subject: "user:alice"`) but cannot grant itself a
role: roles and claims come only from a verified identity. A rule that denies
unless a role is present therefore stays a deny for every unverified caller.

## Grammar

| | |
|---|---|
| Logic | `and`, `or`, `not`, parentheses |
| Comparison | `==` `!=` `<` `<=` `>` `>=` (chainable: `100 < args.amount <= 1000`) |
| Membership | `x in list`, `x not in list`; on a string, substring match |
| Literals | strings, numbers, `true`/`false`/`null` (or `True`/`False`/`None`), lists |
| Paths | `args.amount`, `args['dry-run']`, `args.items[0]` (non-negative integer index) |
| Function | `has(path)` — whether the path exists |

Anything else is rejected when the policy loads, including calls, arithmetic
and names outside the four roots. The expression is parsed into a checked tree
and never passed to Python's `eval`, so a signed org policy cannot carry code.

## Missing attributes fire the rule

If the event has no such path (`args.amount` on a call without an `amount`), or
the comparison mixes types (`900 > 'x'`), the expression **holds** and the rule
fires. An adapter that forgets to send arguments must not turn a guard off.

Guard optional fields with `has()`:

```yaml
when: "has(args.amount) and args.amount >= 500"
```

## Rules without patterns

A rule with `when:` may leave out `patterns`. It then fires on every event of
its `event_types` for which `when:` holds:

```yaml
  - id: unverified-callers-read-only
    title: Unverified callers may not use write tools
    severity: HIGH
    category: custom-authz
    event_types: [shell, file_write, network]
    when: "not principal.verified and tool.name in ['delete_doc', 'refund_order', 'send_email']"
    action: block
    mode: enforce
```

A patternless rule whose `when:` does not parse is disabled (it would otherwise
match everything), and `prismor policy validate` / the console refuse to save
it. A rule that has patterns and a broken `when:` keeps firing on its patterns.

## Recipes

**Owner-only actions**

```yaml
patterns: ['^(delete|share)_doc$']
fields: [tool_name]
when: "resource.attr.owner != principal.id"
```

**Amount cap by role**

```yaml
when: "args.amount >= 500 and 'finance' not in principal.roles"
```

**Only verified users in production**

```yaml
when: "resource.attr.env == 'prod' and not principal.verified"
```

**Allowed currencies**

```yaml
when: "args.currency not in ['USD', 'EUR', 'GBP']"
```

## Core rules

`when:` can only narrow a rule, so it is refused on core protections (the
non-overridable floor and the core block categories), the same as `condition:`.

## `when:` and `condition:`

`condition:` combines named *pattern groups*, so it is about the text
(`"exfil_verb and secret_ref"`). `when:` reads *attributes*. A rule may use
both; it then fires when the condition holds and `when:` holds.

## Sending attributes

**eval-server**

```bash
curl -s localhost:7071/v1/evaluate -d '{
  "tool_name": "refund_order",
  "arguments": {"order": "o-1", "amount": 900},
  "subject": "user:bob",
  "resource": {"kind": "order", "id": "o-1", "attr": {"owner": "alice"}}
}'
```

**Python**

```python
from prismor.runtime.runtime import evaluate_tool_call

evaluate_tool_call(event=event, workspace=ws, agent="sdk",
                   resource={"kind": "order", "id": "o-1", "attr": {"owner": "alice"}})
```

Hook-based agents (Claude Code, Codex, Cursor) need nothing extra: their
`tool_input` is available as `args`.

## Testing

`prismor policy test` takes `type: tool` cases:

```yaml
tests:
  - name: support agent cannot refund 900
    type: tool
    tool: refund_order
    args: {amount: 900}
    principal: {id: bob, roles: [support], verified: true}
    expect: block
    expect_rule: refund-cap
  - name: finance can
    type: tool
    tool: refund_order
    args: {amount: 900}
    principal: {id: carol, roles: [finance], verified: true}
    expect: pass
```

`prismor check --explain` prints a matched rule's `when:`.
