# ChatGPT

The ChatGPT desktop app has two modes, and Prismor reaches them differently.

| Mode | Where it runs | What Prismor does |
|---|---|---|
| Codex (local projects) | On the machine, through the Codex runtime inside the app | Screens prompts and tool calls before they run, with the Codex hooks. Same as the Codex CLI. |
| ChatGPT (chat) | On OpenAI's servers | Screens each message after it is sent, from the ChatGPT Enterprise compliance logs. Nothing is blocked. |

## Codex mode

The ChatGPT app for macOS is the Codex app: it ships its own Codex runtime,
which reads `~/.codex/hooks.json` and `/etc/codex/requirements.toml` like the
CLI does. A Prismor install that covers Codex covers the app's Codex mode
too, including the turns the app starts on its own in a project folder. To make
the hooks mandatory, so a user cannot switch them off or bypass them from a
project, use a [system install](system-install.md): it adds Prismor to Codex's
`requirements.toml` as managed hooks with `[features].hooks = true` pinned.

## ChatGPT mode

Chat messages go straight to OpenAI and any tools they use run there, so no
hook on the machine sees them. On **ChatGPT Enterprise and Edu**, OpenAI
publishes every message through the Compliance Logs Platform, and
`prismor chatgpt-logs sync` reads those logs:

```bash
export OPENAI_COMPLIANCE_API_KEY=...   # the workspace's Compliance API key
prismor chatgpt-logs sync --workspace-id <ChatGPT workspace id>
```

Each run pulls the `CONVERSATION_MESSAGE` logs published since the last run
(the first run starts 24 hours back; `--since-hours` changes that, up to the
30 days OpenAI keeps). It screens what each person typed as a prompt and what
the model wrote as untrusted content, with the policy of the workspace it runs
in, and reports to the console under the `chatgpt` agent:

- one session per conversation, at the time each message was sent;
- the sender's email as the user, so per-user views work;
- findings such as pasted credentials, card numbers and prompt injection in
  model output, always as observed: the message was already sent.

Credentials found in a message are masked before anything is screened or
reported. The cursor is kept in `~/.prismor/chatgpt-logs/`, so a scheduled run
picks up where the last one stopped. Run it every 15 minutes from cron or a
systemd timer on an enrolled machine, or with an agent key
(`PRISMOR_AGENT_KEY`), the same way as any other headless Prismor workload.

The compliance key can read every conversation in the workspace. It stays on
the machine that runs the sync; the console never receives it.

## Limits

- **Enterprise and Edu only.** ChatGPT Business, Plus and free accounts have
  no compliance logs, so their chat mode cannot be reported.
- **After the fact.** Logs arrive minutes after the message. Prismor reports
  what policy says about a message; it cannot stop one.
- **Chat messages only.** Agent mode and Codex cloud tasks also run on
  OpenAI's servers; their logs are not read yet.
