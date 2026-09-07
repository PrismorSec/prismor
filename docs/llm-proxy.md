# The LLM proxy

`prismor proxy` puts Prismor on the agent's model traffic. It is the only
enforcement surface that does not need the agent's cooperation: every other one
requires something to be hooked, wired, or imported, and this one requires only
that requests to the model pass through a URL you control.

```bash
prismor proxy --mode enforce

# then point an agent at it
ANTHROPIC_BASE_URL=http://127.0.0.1:7080 claude
OPENAI_BASE_URL=http://127.0.0.1:7080/v1 codex
```

`GET /health` reports the surface and mode. Requests on unknown paths are
forwarded untouched, so provider handshakes and `/v1/models` keep working.

![The proxy denying a proposed tool call, buffered and streamed](llm-proxy/enforce.png)

The same run as an animation: [demo.gif](llm-proxy/demo.gif).

## What it screens

Two things, on opposite sides of the request.

**The outbound prompt.** The system prompt and every message are flattened into
one `prompt` event and evaluated. Whatever survives is then cloak-masked on the
way out, so a live credential the agent pulled into its context does not land in
a third party's logs. Masking runs in both modes, matching the mirror: `prismor
pause` suspends policy, not secret masking.

**The tool calls the model proposed.** This is the part that distinguishes the
proxy from a text filter. A `tool_use` block in the response is not treated as
prose — it is reshaped by `mirror.shape_call_event` into the same `shell` /
`file_read` / `file_write` / `network` event a Bash hook produces, then run
through the same `evaluate_tool_call`. A rule that stops a command at the hook
layer therefore also stops the model from *proposing* that command here, with
no second rule to write and no second place for the two to disagree. A tool the
proxy has never heard of falls back to the generic payload event rather than
being waved through.

Denied calls are replaced, not deleted: the turn keeps a text block explaining
the refusal. An agent handed a silent no-op simply tries again; one told why
stops.

## Streaming

Refusing after the client has already read the bytes is not enforcement. Text
deltas stream through as they arrive. A `tool_use` content block is held from
its `content_block_start` until its `content_block_stop`, evaluated whole, and
then either released verbatim or replaced with a refusal at the same content
block index. The client never receives a complete tool call that policy denies.
The cost is that tool arguments arrive in one burst instead of streaming in.

The same rule covers both provider dialects: Anthropic content blocks and
OpenAI `tool_calls` deltas are folded into one holdback path.

## Virtual keys

With `keys` configured, a client presents a Prismor key and the proxy swaps in
the real provider credential on the way upstream. The agent never holds a
provider key, so revoking its access is an edit to one file rather than a
rotation across every machine that ever ran it. An unrecognized key is refused
with `401` — it does not fall back to pass-through.

With no `keys` configured the proxy relays whatever credential the client sent.
That is the local-developer mode: it governs behavior without asking anyone to
re-plumb credentials first.

`$PRISMOR_HOME/proxy.json`:

```json
{
  "upstreams": {
    "anthropic": {
      "base_url": "https://api.anthropic.com",
      "api_key_env": "ANTHROPIC_API_KEY",
      "auth_header": "x-api-key",
      "fallback": ["bedrock"]
    }
  },
  "keys": {
    "psk_live_example": {"subject": "user:alice", "upstream": "anthropic"}
  }
}
```

The real credential is read from the environment variable named by
`api_key_env`. Never put a provider key in this file.

`fallback` names upstreams to try when the primary fails to connect or returns
5xx, for buffered requests.

## Workspace

The proxy reads policy and stores its sessions in `$PRISMOR_HOME/surfaces/proxy`
unless `--workspace` says otherwise, and it does not scan instruction files
(`CLAUDE.md`, `AGENTS.md`) near that directory at all. Both follow from what
this surface is: a long-lived server governing an agent it does not host,
usually in another container. The files beside its own workspace describe the
machine it runs on, not the traffic it judges -- and a security project's
instruction file quotes the attack strings its own rules match, as does the one
$PRISMOR_HOME ships, so scanning them refused every request with
`source: project_memory`, benign traffic included. That is not a weaker check;
it is a check on the wrong subject. `--workspace` still points the proxy at a
specific repo's policy for anyone who means it.

## Governing n8n (and other hosted builders)

There is a full walkthrough with screenshots in [n8n.md](n8n.md). The short
version:


n8n runs its agents inside a container and offers no hook, no MCP client for a
stdio server, and no SDK to import -- the exact case this surface exists for.
Point the OpenAI credential's **Base URL** at the proxy and change nothing else
on the canvas:

```bash
prismor proxy --mode enforce --host 0.0.0.0            # reachable from the container
# n8n -> Credentials -> OpenAi account -> Base URL:
#   http://host.docker.internal:7080/v1
```

Every turn is then screened, and a tool the model proposes is judged before n8n
executes it. Bind beyond loopback only on a trusted network, or put TLS in
front.

## Running it as a service

It is a long-lived server, so it wants a supervisor, a volume for
`$PRISMOR_HOME`, and somewhere for its findings to go.
[deploy-docker.md](deploy-docker.md) has an image, a compose file that stands
it up beside n8n, and the sink and enrollment configuration that make its
sessions visible in the console.

## Modes and failure

`--mode observe` (default) evaluates and logs but never blocks. `--mode enforce`
blocks. An engine *error* refuses in enforce mode and forwards in observe mode,
matching the MCP gateway: a broken engine must not become a silent allow.

## When to use it, and when not to

Reach for the proxy when the agent supports nothing else — no hooks, no MCP, no
SDK adapter. It is the widest net by deployment, and the narrowest by
visibility: it sees only what the agent routes through a model API. An agent
that runs a shell command without asking the model first is invisible to it,
which a hook would catch. Where both are available, run hooks; the proxy is the
fallback and the second layer, not the replacement.

See [governance surfaces](governance-surfaces.md) for the full comparison and
[the decision contract](decision-contract.md) for the event and verdict shapes
every surface shares.
