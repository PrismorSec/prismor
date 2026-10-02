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
role: roles and claims come only from a
[verified identity token](identity-verification.md). A rule that denies
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

## Named conditions

Conditions you use in several rules can be named once in `settings.conditions`
and referenced by name, the way a derived role is defined once and reused:

```yaml
settings:
  conditions:
    is_finance: "'finance' in principal.roles"
    is_owner: "resource.attr.owner == principal.id"

rules:
  - id: refund-cap
    # ...
    when: "args.amount >= 500 and not is_finance"
  - id: owner-only-delete
    # ...
    when: "not (is_owner or is_finance)"
```

A named condition reads the same four roots as `when:`. It cannot refer to
other names, so there are no cycles. Names merge per name across policy layers:
the signed org policy can redefine `is_finance` without erasing a project's
other names. A missing attribute inside a named condition fails toward
detection, exactly as it does inline.

## Explaining a decision

Ask the eval-server for a trace with `"explain": true`:

```json
"explain": {
  "rules": [
    {"rule_id": "refund-cap", "layer": "remote", "mode": "enforce",
     "when": "args.amount >= 500 and not is_finance", "when_holds": false, "fired": false}
  ],
  "policy_version": 14,
  "identity": "verified",
  "subject_source": "jwt",
  "decided_by": null
}
```

Every rule whose patterns matched is listed, including the ones a `when:` then
switched off, so "why didn't my rule fire?" has an answer. In Python, pass
`evaluate_tool_call(..., explain=True)` and read `Decision.explain`.

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

### Suites: fixtures and per-principal expectations

Name your principals and resources once, and assert one call for several
callers in a single test. A matrix row is named `test [principal]`.

```yaml
fixtures:                      # or a sibling policy-fixtures.yaml, shared by every suite in the directory
  principals:
    bob:   {id: bob, roles: [support], verified: true}
    carol: {id: carol, roles: [finance], verified: true}
    anon:  {}
  resources:
    alices_order: {kind: order, id: o-1, attr: {owner: alice}}
tests:
  - name: refunds over 500
    tool: refund_order
    args: {amount: 900}
    resource: alices_order
    expect: {bob: block, carol: pass, anon: block}
    expect_rule: refund-cap
  - name: not yet
    skip: true
    skip_reason: waiting on the roles claim
```

```bash
prismor policy test                                 # .prismor/policy-tests.yaml
prismor policy test --policy policies/bot.yaml      # a policy file, with its own tests: if it has them
prismor policy test --filter '*[carol]' --json
```

A policy file can carry its own `tests:` and `fixtures:`; the engine ignores
both keys. The console stores a policy's tests this way and runs them before
publishing.

### In CI

```yaml
- uses: PrismorSec/prismor/.github/actions/policy-test@main
  with:
    policy: policies/support-bot.yaml   # optional
```

The job fails on any mismatch. The action installs the prismor source from the
ref you pin, so the CLI always matches the action; pass
`prismor-version: "==X.Y.Z"` to use a PyPI release instead.
