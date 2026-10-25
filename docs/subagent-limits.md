# Limiting subagents

An agent that launches subagents hands them its authority. Three limits keep
that bounded:

- **how many** subagents an agent may launch in a session;
- **how long** a subagent's delegation lasts;
- **what data** an agent may hand a subagent.

The first two are ordinary [`when:` rules](attribute-conditions.md). The third is
part of the [data boundary](data-boundary.md). All three work in Claude Code,
Codex and the SDK adapters, and a subagent is also held to its parent's
controls (see [a subagent's policy](subagents.md#a-subagents-policy)).

## Cap how many subagents an agent launches

```yaml
rules:
  - id: max-five-subagents
    severity: HIGH
    category: custom-authz
    title: An agent may launch at most five subagents per session
    event_types: [shell, network, file_read, file_write, subagent_spawn]
    when: "subagent.number > 5"
    action: block
    mode: enforce
```

`subagent.number` says which of its parent's subagents a call comes from: 1
for the first, 2 for the second. On the call that launches a subagent, it is
the number the new subagent would get.

- **Claude Code:** the sixth `Agent`/`Task` launch is blocked, so the subagent
  never starts. The first five keep working.
- **Codex and the SDK adapters:** there is no separate launch call, so a
  subagent gets its number when it first acts. Every call from the sixth
  subagent is blocked; the first five are unaffected.
- **A refused launch doesn't count.** A launch blocked by any rule takes no
  number, so a cap of five always allows five working subagents.

Numbers are counted per parent, per session. For an SDK subagent, the session
is the main agent's: frameworks often give each agent run its own session id,
and Prismor counts a subagent under the main agent's call that launched it.

Two calls that launch subagents at the same instant can both read the same
number, so a cap can be exceeded by the number of launches running in
parallel.

## Let a delegation expire

```yaml
  - id: subagent-expiry
    severity: HIGH
    category: custom-authz
    title: A subagent may run for at most 15 minutes
    event_types: [shell, network, file_read, file_write]
    when: "subagent.age > 900"
    action: block
    mode: enforce
```

`subagent.age` is the number of seconds since the subagent's first allowed call. Once it
passes the limit, the subagent's calls are blocked and it has to report back.
The parent can launch a new subagent, which starts again at 0.

Combine it with the subagent's type to give long-running work more time:

```yaml
when: "subagent.age > 900 and subagent.type != 'migration-runner'"
```

## Screen what an agent hands a subagent

A subagent works from what its parent gives it. When that includes a customer's
email address or an API key, the subagent can pass it on with tools the parent
never used. `settings.data_boundary.handoffs` sets what may be handed over,
per data class:

```yaml
settings:
  data_boundary:
    enabled: true
    mode: enforce
    handoffs:
      secret: block
      card: block
      ssn: block
      email: warn
      per_subagent:            # exceptions by subagent type
        billing:
          card: allow
          email: allow
```

Actions are `allow`, `observe`, `warn`, `step_up` (ask the person), and `block`.
`redact` acts as `step_up`, because what is handed over is not rewritten. The
classes, and the test values that never count (`user@example.com`, test card
numbers), are the same as for [outbound calls](data-boundary.md). Without a
`handoffs` block, nothing is screened.

What counts as a handoff:

| Where | What is screened |
|---|---|
| Claude Code | the prompt and description of an `Agent`/`Task` launch |
| OpenAI Agents SDK | the input to an agent used as a tool (`as_tool`) |
| Google ADK | the arguments to an `AgentTool` |
| BeeAI | the input to a `HandoffTool` |
| Vercel AI SDK | tools listed in `handoffs: { ask_researcher: "researcher" }` |
| eval-server callers | calls sent with `"handoff_to": "<subagent type>"` |

A blocked handoff is reported as `secret-to-subagent` or `pii-to-subagent`.
The block message tells the agent to hand over a reference (a record id, a
file path) instead of the value, or names the `per_subagent` entry that would
allow it.

Not covered: OpenAI Agents SDK handoffs (`transfer_to_…`) pass the whole
conversation rather than a single argument, and agents that frameworks run
from your own tool code (Mastra, Pydantic AI, AG2 and others). Screen those
with a rule on the launching tool's arguments.

## Delegation records

Each allowed launch and each subagent's first call writes one line to
`~/.prismor/subagents/<session>.delegations.jsonl`:

```json
{"kind": "spawn", "type": "Explore", "parent": "claude", "number": 1, "ts": 1792897411.4}
{"kind": "start", "id": "ae56191f56f58fcbc", "type": "Explore", "parent": "claude", "chain": [], "number": 1, "ts": 1792897415.2}
```

`spawn` is a Claude Code launch. `start` is a subagent's first allowed call,
and its `ts` is where `subagent.age` counts from. Records are kept where the
call is evaluated. [Hosted evaluation](hosted-evaluation.md) keeps none, so
caps and expiry don't apply there: every subagent reads as number 1 with age
0.

## Try it

Write the cap rule into a test home and send two launches through the hook:

```bash
export PRISMOR_HOME=$(mktemp -d)
cat > "$PRISMOR_HOME/policy.yaml" <<'EOF'
version: "1.0"
rules:
  - id: one-subagent
    severity: HIGH
    category: custom-authz
    title: Launch at most one subagent per session
    event_types: [subagent_spawn]
    when: "subagent.number > 1"
    action: block
    mode: enforce
EOF
for i in 1 2; do
  echo '{"hook_event_name":"PreToolUse","session_id":"try-1","cwd":"'$PWD'","tool_name":"Agent","tool_input":{"subagent_type":"Explore","prompt":"look around"}}' \
    | prismor hook-dispatch --agent claude --mode enforce
done
```

The first launch passes silently. The second prints `Launch at most one
subagent per session`.

See also: [Subagents](subagents.md) · [Attribute conditions](attribute-conditions.md) · [Data boundary](data-boundary.md).
