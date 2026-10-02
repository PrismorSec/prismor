# The decision contract

Prismor screens agents in several places. It decides in one.

Every enforcement point — a coding-agent hook, the MCP gateway, a mirrored
built-in, an SDK adapter, the evaluation server, the inference-hook channel —
normalizes what it saw into a single event shape and hands it to
`evaluate_tool_call`, which runs the policy engine and returns a `Decision`.
The surfaces differ only in how they discover a tool call and how they render a
refusal. That is what makes one policy govern all of them, and why a rule you
write for Claude Code also covers a tool call arriving over MCP.

The contract lives in [`prismor/runtime/contract.py`](../prismor/runtime/contract.py).
It imports nothing else from Prismor, so it can be read on its own — or vendored
into a proxy that wants to ask Prismor for a verdict.

```
hooks   MCP gateway   mirror   SDK adapters   eval-server   inference-hook
  └────────┴─────────────┴──────────┴──────────────┴──────────────┘
                              │  normalized event
                              ▼
              runtime.evaluate_tool_call()  ──▶  Decision
              scoped rules · cloak guard · IAM · exemptions · sinks
                              │
                              ▼
              policy_engine.PolicyEngine.evaluate()
              YAML rules · egress · data boundary · semantic guard · taint
```

## The event

A normalized event describes one thing an agent is about to do (or just did).

```python
{
  "ts": "2026-08-20T22:04:11Z",
  "session_id": "abc123",
  "agent": "claude",           # framework / host id
  "agent_event": "PreToolUse", # pre-action events are the refusable ones
  "type": "shell",
  "command": "rm -rf /",       # the value field, chosen by `type`
  "metadata": {
    "tool_name": "Bash",
    "surface": "hook",         # which enforcement point saw it
    "cwd": "/home/u/project",
    "kwargs": {"command": "rm -rf /"},  # optional: raw arguments, read as `args.*`
    "resource": {"kind": "doc", "id": "d-1", "attr": {"owner": "alice"}},
                               # optional: the call's target, read as `resource.*`
  },
}
```

`kwargs` and `resource` feed [attribute conditions](attribute-conditions.md).
Both are additive; the contract version is unchanged. A caller that passes
`explain=True` also gets `Decision.explain`, a trace of the rules that matched
(see [explaining a decision](attribute-conditions.md#explaining-a-decision)).

### Event types and their value field

Each type names the field carrying the value rules match against:

| `type` | value field |
|---|---|
| `shell` | `command` |
| `file_read` | `path` |
| `file_write` | `path` |
| `network` | `url` |
| `prompt` | `prompt` |
| `tool_result` | `response` |
| `memory` | `content` |
| `text` | `content` |
| `skill_manifest` | `content` |
| `subagent_spawn` | `content` |
| `ui_action` | `control_label` |

For the text-bearing types the engine folds `prompt` / `response` / `content` /
`stdout` / `stderr` into one `combined_text` blob, so a category rule fires
whichever key a surface used. **Field-scoped rules do not**: a rule declaring
`fields: [response]` reads that key alone. That makes the choice of key a real
compatibility surface rather than a style preference — write the one in the
table.

`validate_event(event)` returns a list of problems (empty means valid). It is
advisory and deliberately not on the hot path: a mis-shaped event should still
be screened, just with fewer matching rules. Use it in tests and when bringing
up a new surface, so a mistake shows up as a failed assertion rather than a
silently missing rule hit.

## The decision

```python
Decision(
  allow=False,
  verdict="block",         # allow | block | step_up | defer | modify
  transform=None,          # named input transform, for `modify`
  rule_id="destructive-command",
  reason="[CRITICAL] Blocks rm -rf / …",
  findings=[...],          # everything detected, including non-blocking
  blocking={...},          # the finding that governs
)
```

`allow` says whether the call may proceed unchanged. `verdict` says what the
surface is being asked to *do*:

| verdict | meaning |
|---|---|
| `allow` | proceed |
| `block` | refuse |
| `step_up` | get a human to approve first |
| `defer` | escalate to the deeper semantic evaluator, then allow or block |
| `modify` | rewrite the input via `transform`, then proceed |

`verdict` and `transform` derive from `blocking` rather than duplicating it, so
a caller that clears `blocking` (the hook path does this when a deferred check
adjudicates ALLOW) cannot leave a stale verdict behind.

### Two rules every surface follows

**Fail closed.** A surface that cannot honor its verdict refuses. If a policy
says `modify` and the host offers no way to rewrite tool input, the call is
blocked — never quietly allowed. The one deliberate exception is documented in
`cli.py`: a `data_boundary` verdict degrades to a warning on hosts that can
neither rewrite nor ask, because turning "redact my email before sending" into
a hard block on Codex is the false positive that policy was tuned to avoid.

**Deny wins.** When several enforce-mode findings fire on one event, the
strongest verdict governs — `block` > `step_up` > `defer` > `modify` — not
whichever the engine surfaced first. An unrecognized action on an enforce
finding ranks as `block`: the author said "enforce", and the safe reading of
"enforce plus a verdict we do not understand" is stop.

## The surfaces

`contract.SURFACES` is the registry. Capabilities are facts about where the
surface sits, not preferences:

| surface | refuse | rewrite input | redact output |
|---|:--:|:--:|:--:|
| `hook` — coding-agent hooks | yes | yes¹ | no² |
| `mcp-gateway` — MCP servers | yes | yes | yes |
| `mirror` — mirrored built-ins | yes | yes | yes |
| `sdk-adapter` — framework SDKs | yes | no | no |
| `eval-server` — HTTP PDP | yes | yes | yes |
| `inference-hook` — hosted channel | yes | no | no |

¹ Claude/Qwen PreToolUse only. ² A pre-action hook sees the request, never the
response; Claude's PostToolUse stream is scrubbed by a separate shell path.

That "redact output" column is the whole argument for the mirror: a hook can
only refuse a file read, while a surface that carries the response can hand back
the file with the credential masked.

## Result redaction

Surfaces that see tool output share one implementation,
[`prismor/runtime/redaction.py`](../prismor/runtime/redaction.py): cloak
secrets first (an exact-value swap), then data-boundary classification.

Redaction is best-effort by contract — it never raises and never fails a call
closed. Pre-call policy has already had its say and the result scan still gets a
vote; turning a masking failure into a refusal would trade a small leak for an
outage, which is the wrong trade on the critical path of every call an agent
makes.

`cloaking/hooks/scrub-stream.sh` does the same job for Claude's PostToolUse
stream. It stays shell because that path cannot afford a Python start-up per
call, so the two are kept in parity by test rather than by shared code.

## Asking Prismor from outside Python

`prismor eval-server` is the decision point for anything that is not Python — a
TypeScript or Go adapter, or a proxy that already carries the traffic and wants
a verdict for it.

```bash
prismor eval-server --port 7071 --workspace /path/to/repo
```

```bash
# Discover the contract the server implements
curl -s localhost:7071/v1/contract

# Ask about a tool call
curl -s -X POST localhost:7071/v1/evaluate \
  -H 'Content-Type: application/json' \
  -d '{"tool_name":"Bash","arguments":{"command":"rm -rf /"},"event_type":"shell"}'
# → {"allow": false, "verdict": "block", "rule_id": "destructive-command", ...}

# Or post a canonical event directly, when you have already normalized
curl -s -X POST localhost:7071/v1/evaluate \
  -H 'Content-Type: application/json' \
  -d '{"event":{"type":"shell","command":"rm -rf /","agent_event":"PreToolUse"}}'
```

Prefer the `event` form when a field must stay addressable. The
`tool_name` + `arguments` form joins every argument value into one string, which
is fine for regex matching but loses the distinction between a `file_write`'s
path and its content.

Bind beyond localhost only with `--api-key` (or `PRISMOR_EVAL_KEY`): anyone who
can reach the port can otherwise evaluate against your policy.

## Adding a surface

1. Translate the host's payload into a canonical event; assert
   `validate_event(event) == []` in a test.
2. Set `metadata.surface` so telemetry can attribute the decision.
3. Call `evaluate_tool_call`. On a multi-tenant server pass `persist=False` and
   `register_agent=False` — otherwise every tenant's agents land in one
   inventory file and a disk write joins the request path.
4. Render the `Decision`, honoring every verdict you can and failing closed on
   the ones you cannot.
5. Add it to `contract.SURFACES` and to the corpus in
   `tests/test_surface_conformance.py`.

## Conformance

[`tests/test_surface_conformance.py`](../tests/test_surface_conformance.py)
takes one action, shapes it through each surface's own normalizer, and asserts
they reach the same verdict on the same rule. Building the events with one
shared helper would prove nothing — the point is that independently written
normalizers still land on the same event.

That test is not ceremony. Writing it turned up a real drift: the evaluation
server mapped `prompt` and `tool_result` to `content` while every other surface
wrote `prompt` and `response`. Category rules were unaffected (the engine folds
all five text fields together), but a rule scoped to `fields: [response]`
silently never matched an event that arrived that way.
