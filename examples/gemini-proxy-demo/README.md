# Gemini through `prismor proxy`

Two demos of the same thing: `prismor proxy` on Google Gen AI traffic, with the
SDK's own `base_url` as the only integration point.

## `demo.py` — offline, no key

```
python examples/gemini-proxy-demo/demo.py
```

Runs a stub Gemini upstream, the proxy in enforce mode, and a client, in one
process. No API key, no network, no `google-genai` install. Shows a benign
`functionCall` released verbatim and a destructive one replaced before the
client sees it, buffered and streaming.

## `streamlit_app.py` — real API, real UI

```
pip install streamlit google-genai
prismor proxy --mode enforce --port 7099 --workspace .
PRISMOR_PROXY=http://127.0.0.1:7099 GEMINI_API_KEY=... streamlit run examples/gemini-proxy-demo/streamlit_app.py
```

A chat UI whose only Prismor-aware line is the `base_url` on the client. The
prompt is screened and cloak-masked on the way out: paste a live credential
into the chat and the model answers about a `@@SECRET:...@@` placeholder.

`PRISMOR_PROXY` defaults to `http://127.0.0.1:7080`.

## Ports

The proxy defaults to 7080, and `demo.py` hardcodes it. A machine already
running a proxy there (a long-lived one under a LaunchAgent, say) will end up
with two listeners bound at once — the OS permits it, and requests land on
whichever, under the wrong workspace and policy. Check with
`lsof -nP -iTCP:7080 -sTCP:LISTEN` and pass `--port` if it is taken.
