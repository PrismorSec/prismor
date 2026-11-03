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
agent key alongside the provider key; for those, run the proxy yourself with
[virtual keys](./llm-proxy.md#virtual-keys).

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
| n8n, Capy, and other base-URL-plus-key settings | yes | no | Self-run proxy with [virtual keys](./llm-proxy.md#virtual-keys) |

"Should work" means the client documents both settings, but nobody has run it
against `proxy.prismor.dev` yet.

## Limits

- The proxy's idle timeout is 15 minutes, so a single streamed response can't
  run longer than that.
- An agent key's revocation reaches the proxy within 60 seconds.
- Bedrock and Vertex upstreams, which need cloud credentials rather than an API
  key, are only available on a self-run proxy.
