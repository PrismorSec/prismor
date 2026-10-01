# Governing an n8n agent

n8n builds agents that Prismor cannot hook. There is no hook protocol, no place
to import an SDK adapter, and its MCP client speaks HTTP rather than the stdio
transport `prismor mcp-gateway` serves. The workflow also runs inside a
container, so the machine-level surfaces that govern a local coding agent never
see it.

The [LLM proxy](llm-proxy.md) is the surface for exactly this case. It needs
nothing from the agent except that its model traffic pass through a URL you
control — which for n8n is one field on a credential. The canvas does not
change, the workflow does not know Prismor is there, and every tool call the
model proposes is judged before n8n executes it.

![The n8n canvas: a chat trigger feeding an AI Agent with an OpenAI chat model, memory and a tool](n8n/canvas.png)

## Start the proxy

```bash
prismor proxy --mode enforce --host 0.0.0.0
```

`--host 0.0.0.0` is what makes the proxy reachable from inside the n8n
container; on the default loopback bind, `host.docker.internal` cannot reach it.
Bind beyond loopback only on a network you trust, or put TLS in front of it.
Start in `--mode observe` first if you want to see verdicts before they bite.

Check it is up:

```console
$ curl -s http://127.0.0.1:7080/health
{"status": "ok", "surface": "llm-proxy", "mode": "enforce"}
```

## Point n8n at it

In n8n, open **Credentials → your OpenAI account** and set **Base URL**:

```
http://host.docker.internal:7080/v1
```

![The OpenAI credential in n8n with its Base URL pointed at the Prismor proxy](n8n/credential.png)

That is the whole integration. Leave the API key as it is — with no virtual
keys configured the proxy relays whatever credential the client sent, so
nothing else needs re-plumbing. n8n's **Test** button should come back green;
if it reports "Couldn't connect with these settings" you are on a Prismor older
than 1.45.2, where the credential check was routed to the wrong provider.

From inside the container, confirm the hop:

```console
$ docker exec n8n wget -qO- http://host.docker.internal:7080/health
{"status": "ok", "surface": "llm-proxy", "mode": "enforce"}
```

Running n8n outside Docker? Use `http://127.0.0.1:7080/v1` instead. On Linux,
`host.docker.internal` resolves only if the container was started with
`--add-host=host.docker.internal:host-gateway`, which cannot be added to a
running container. Rather than recreate n8n, use the bridge gateway address
wherever this page says `host.docker.internal`:

```console
$ docker network inspect bridge --format '{{range .IPAM.Config}}{{.Gateway}}{{end}}'
172.17.0.1
```

### Give n8n a key of its own

Relaying the credential is fine on a laptop, but it leaves the real provider key
in n8n's credential store. A virtual key takes it back out: n8n holds a
throwaway string and the proxy swaps in the real credential on the way upstream.

`$PRISMOR_HOME/proxy.json` — `~/.prismor/proxy.json` unless you moved it:

```json
{
  "default_upstream": "openai",
  "keys": {
    "pk_n8n_local": { "subject": "n8n-prod", "upstream": "openai" }
  }
}
```

There is no `upstreams` block because the built-in `openai` upstream already
points at `https://api.openai.com` and reads the real key from `OPENAI_API_KEY`
in the proxy's own environment. Set the n8n credential's API key to
`pk_n8n_local`, restart the proxy, and the banner should read `virtual keys: 1`
rather than `auth pass-through (no virtual keys configured)` — that line is how
you know the file was found, and no other path is consulted.

`subject` is what the workflow's records are attributed to, so the trail reads
`n8n-prod` rather than `anonymous`. Cutting n8n off is then deleting that one
key and restarting, with nothing else that uses the real credential touched; an
unrecognised key is refused at the proxy with `401` and never reaches the
provider. [The LLM proxy](llm-proxy.md) has the full schema.

## What it screens

Two things, on opposite sides of each turn.

**The outbound prompt.** The system message and every chat message are
flattened into one event and evaluated, then cloak-masked on the way out, so a
credential the workflow pulled into context does not land in OpenAI's logs.

**The tool calls the model proposed.** This is the part a text filter cannot
do. A proposed tool call is reshaped into the same `shell` / `file_read` /
`file_write` / `network` event a Bash hook produces and run through the same
policy — so a rule that stops a command at the hook layer also stops the model
from *proposing* it inside n8n, with no second rule to write.

Ordinary work is untouched. Asking the HR agent a question it has a tool for
returns the tool's answer:

```console
$ curl -s -X POST 'http://localhost:5678/webhook-test/<webhook-id>/chat' \
    -H 'Content-Type: application/json' \
    -d '{"action":"sendMessage","sessionId":"demo","chatInput":"How many annual leave days do I get?"}'
{"output":"You are entitled to 24 days of paid annual leave per calendar year,
which is accrued monthly. You can carry over up to 5 unused days to the next
year. All leave requests should be submitted to your manager at least 7 days
in advance."}
```

Give an agent a shell tool and ask it to install something the usual way, and
the tool call is refused before n8n runs it. The agent answers with the reason,
and the tool node never executes — note that `Bash` carries no check mark in
the run below:

![An n8n ops agent whose proposed shell command was blocked by Prismor, with the Bash node unexecuted](n8n/denied.png)

Denied calls are replaced rather than deleted on purpose: an agent handed a
silent no-op simply tries again, while one told why it was refused stops.

### Name tools so they can be judged

That block happens because the proposed call is recognisable as a shell
command. Prismor reshapes a proposed tool call by its name and arguments — a
tool called `Bash` taking a `command` becomes the same `shell` event a Bash
hook produces, and the shell rules apply to it unchanged. A tool whose
arguments do not carry that shape falls back to a generic payload event, which
is still screened for injection and secrets but is not a shell command as far
as the shell rules are concerned.

n8n's Code Tool takes a single free-text `query` by default, which is exactly
that weaker case. Turn on **Specify Input Schema** and give the tool the
argument it really takes:

```json
{
  "type": "object",
  "properties": {
    "command": { "type": "string", "description": "The shell command line to run" }
  },
  "required": ["command"]
}
```

The schema is worth setting on any tool that wraps a real capability —
executing a command, reading a file, calling a host. It is what lets one rule
table cover the hook layer and the proxy at once, instead of two.

## Keep it running

Running both under compose, with a volume for the identity and session store
and your SIEM wired in, is [deploy-docker.md](deploy-docker.md). By hand, on
the host:

The proxy is a long-lived server, so run it under whatever supervises your
other services. On macOS, a launch agent is enough:

```xml
<!-- ~/Library/LaunchAgents/dev.prismor.proxy.plist -->
<key>ProgramArguments</key>
<array>
  <string>/path/to/prismor</string>
  <string>proxy</string>
  <string>--mode</string><string>enforce</string>
  <string>--host</string><string>0.0.0.0</string>
  <string>--agent-name</string><string>n8n-hr-agent</string>
</array>
<key>RunAtLoad</key><true/>
<key>KeepAlive</key><true/>
```

`--agent-name` registers this proxy as a named agent instance, which is what
gives you the per-agent kill switch and per-agent policy in the console.

To stop enforcing without unwiring anything, `prismor pause` drops to observe
for 24 hours and `prismor resume` restores it. To remove the proxy from the
path entirely, set the credential's **Base URL** back to empty and put the real
API key back.

## Where the verdicts show up

Each governed turn is a session of its own, under the name the surface reports,
readable in `prismor dashboard` and — once the machine is enrolled — in the
console. On the box running the proxy, the audit trail is the fastest look,
one line per decision, allowed and blocked alike:

```console
$ prismor --workspace ~/.prismor/surfaces/proxy trail show
[0] 2026-09-15T07:10:33 · allowed   n8n-prod  llm_request  ...list what is in the temp fo
[1] 2026-09-15T07:10:33 · allowed   n8n-prod  Bash         ls -la /tmp
[2] 2026-09-15T07:10:33 · allowed   n8n-prod  llm_request  ...do a full cleanup of the di
[3] 2026-09-15T07:10:33 ✗ blocked   n8n-prod  Bash         rm -rf / --no-preserve-root
```

The `--workspace` is not optional: the proxy keeps its policy and its sessions
in `$PRISMOR_HOME/surfaces/proxy`, and `prismor sessions` run from anywhere
else reads a different workspace. Each entry is chained to the one before it by
hash, so the log cannot be quietly edited after the fact.

This is also the dry run. In `--mode observe` a decision that would have
blocked is recorded as `warned` with the rules that matched, so a day of
ordinary work tells you what enforcement will cost before it costs it. If real
work is in that list, narrow the rule rather than the mode: `prismor
--workspace ~/.prismor/surfaces/proxy allow` writes the smallest exception for
a block that just happened, and `policy edit` toggles rules wholesale. The session view shows the turn as policy saw it and lets you apply a
rule for that tool to this session, this agent, or every agent, which is the
fastest way to tune a policy you are still deciding on. Screenshots and the
sink configuration are in [deploy-docker.md](deploy-docker.md).

## When it does not work

| Symptom | Cause | Fix |
|---|---|---|
| n8n's **Test** cannot connect | proxy bound to loopback | restart it with `--host 0.0.0.0` |
| `host.docker.internal` unreachable | Linux Docker without the host-gateway alias | use the bridge gateway IP |
| **Unauthorized** in n8n | the key n8n sends is not in `keys` | check `proxy.json`, and that the banner says `virtual keys: 1` |
| banner says `auth pass-through` | `proxy.json` is not at `$PRISMOR_HOME/proxy.json` | move it there; nowhere else is read |
| every call is refused | the proxy was pointed at a repo whose `CLAUDE.md` quotes attack strings | drop `--workspace`; the default is deliberately neutral |
| an edit to policy or `proxy.json` does nothing | both are read once, at startup | restart the proxy |
| `curl` prints nothing at all | `-s` also hides connection errors | use `curl -sS` |

## What this does not cover

The proxy sees only what the workflow routes through a model API. An n8n node
that runs a command or calls an API on its own — an Execute Command node, an
HTTP Request node the agent never asked the model about — is invisible to it,
because nothing about that step ever reaches the proxy. Nor does it stop a tool
the agent decides to call for reasons of its own after the turn is allowed: the
verdict covers the call the model proposed, not what the node then does with
it.

It is the widest net by deployment and the narrowest by visibility. Where a
real hook is available, run hooks; the proxy is the surface for agents that
offer nothing else, and n8n is one of them.

See [Governance Surfaces](governance-surfaces.md) for the full comparison,
and [the LLM proxy](llm-proxy.md) for virtual keys, streaming behaviour and
the failure modes.
