# Hosted proxy

`https://proxy.prismor.dev` is the [LLM proxy](./llm-proxy.md) run by Prismor.
Point a model client at it with an agent key, and every prompt and every tool
call the model proposes runs through your org's policy before your app sees
it. Nothing is installed next to the workload.

## Set it up

In the console: **Agents → Connect an agent → Any app (hosted proxy)**. Name the
agent, pick a policy (or keep the org policy), and mint the key. The console
shows a snippet per provider with the key filled in, and **Test connection**
sends a harmless prompt and a destructive command through the proxy with the
new key: the first should be allowed, the second blocked, and both land in a
session you can open.

Each request carries two credentials:

- your **provider key**, where the client always sends it, relayed upstream
  untouched and never stored by Prismor;
- your **Prismor agent key**, in an `X-Prismor-Key` header.

```bash
# Claude Code
export ANTHROPIC_BASE_URL=https://proxy.prismor.dev
export ANTHROPIC_CUSTOM_HEADERS="X-Prismor-Key: <agent key>"
```

```python
# Anthropic SDK
Anthropic(base_url="https://proxy.prismor.dev", default_headers={"X-Prismor-Key": key})
# OpenAI SDK
OpenAI(base_url="https://proxy.prismor.dev/v1", default_headers={"X-Prismor-Key": key})
# Google Gen AI SDK
genai.Client(http_options=types.HttpOptions(base_url="https://proxy.prismor.dev", headers={"X-Prismor-Key": key}))
```

An agent with no model client to swap can ask before each tool call instead:
`POST /v1/evaluate` with `Authorization: Bearer <agent key>` returns
`{"allow": …, "reason": …}`, and `POST /v1/events` records events without
blocking.

## Which clients work

A client works as-is if it lets you set **both** the base URL and an extra
request header. One that takes only a base URL and a single key can't send the
agent key alongside the provider key; for those, store the provider key with
Prismor ([below](#prismor-held-provider-keys)).

| Client | Base URL | Extra header | Hosted proxy |
| --- | --- | --- | --- |
| Anthropic API (SDKs, curl) | `base_url` | `default_headers` | Works. Blocks verified buffered and streamed |
| Google Gen AI SDK (Gemini) | `HttpOptions.base_url` | `HttpOptions.headers` | Works. Blocks verified buffered and streamed (`gemini-3.1-flash-lite`) |
| OpenAI SDK (Python, TypeScript) | `base_url` / `baseURL` | `default_headers` / `defaultHeaders` | Works. Blocks verified buffered and streamed (Python) |
| Claude Code | `ANTHROPIC_BASE_URL` | `ANTHROPIC_CUSTOM_HEADERS` | Should work; not yet run against the hosted proxy |
| Codex CLI | `model_providers.<id>.base_url` | `model_providers.<id>.http_headers` | Should work; not yet run against the hosted proxy |
| Vercel AI SDK | `createOpenAI({ baseURL })` | `headers` | Should work; not yet run against the hosted proxy |
| LangChain | `base_url` | `default_headers` | Should work; not yet run against the hosted proxy |
| ElevenLabs Custom LLM | Server URL | Request headers | Should work; `prismor elevenlabs connect` targets the self-run proxy today |
| n8n, Capy, and other base-URL-plus-key settings | yes | no | With a [Prismor-held provider key](#prismor-held-provider-keys). Verified with an OpenAI client sending only the agent key |

"Should work" means the client documents both settings, but nobody has run it
against `proxy.prismor.dev` yet.

## Prismor-held provider keys

For a client that takes only a base URL and one key, an admin stores the
provider key with Prismor. The client then sends the **agent key as its API
key**, and the hosted proxy swaps in the stored provider key on the way
upstream. The app never holds a provider key, and revoking the agent key cuts
it off.

In the console: **Devices → the key icon on the agent key → Provider key**.
Pick Anthropic, OpenAI or Gemini and paste the key. It is encrypted at rest,
shown afterwards only by its last four characters, and released only to the
hosted proxy, never to a caller holding the agent key. Replace or remove it on
the same card; a change reaches the proxy within 60 seconds.

```bash
# n8n → Credentials → OpenAI account
#   Base URL: https://proxy.prismor.dev/v1
#   API Key:  <agent key>
```

The proxy recognizes the agent key wherever a client puts its API key:
`Authorization: Bearer`, `x-api-key`, `x-goog-api-key`, or Gemini's `?key=`.
Sent this way with no provider key stored, a request gets a `401` that says so.

## Limits

- The proxy's idle timeout is 15 minutes, so a single streamed response can't
  run longer than that.
- An agent key's revocation reaches the proxy within 60 seconds.
- Bedrock and Vertex upstreams, which need cloud credentials rather than an API
  key, are only available on a self-run proxy.
