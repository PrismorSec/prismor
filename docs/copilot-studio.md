# Microsoft Copilot Studio

Copilot Studio can call an external threat detection provider before an agent
runs a tool, and skip the tool when the provider says to block it. The
eval-server can be that provider. Each tool call a Copilot Studio agent plans
is checked against your Prismor policy, together with the user's message and
the outputs of the tools that ran before it, and Prismor answers allow or
block before the tool runs.

This works with agents that use generative orchestration. Copilot Studio
sends the planned tool, its input values, the user's message, the chat history
and the outputs of earlier tools in the same plan. Prismor screens the earlier
outputs as untrusted content, so an instruction planted in an email or web
page an earlier tool returned blocks the call that acts on it.

Run with your org's agent key and the server takes its tenant allowlist from
the console (**Integrations → Microsoft Copilot Studio**), and every decision
shows up in the console under the Copilot Studio agent, user and conversation
that made it.

## Endpoints

The base URL is `https://<your host>/copilot-studio`. Copilot Studio adds
`?api-version=...` (live tenants send `2025-09-01`). Prismor accepts any
version and ignores fields it does not know.

| Endpoint | |
|---|---|
| `POST {base}/validate` | connection check: `{"isSuccessful": true, "status": "OK"}` |
| `POST {base}/analyze-tool-execution` | one planned tool call: `{"blockAction": false}`, or `true` with `reasonCode`, `reason` and `diagnostics` |

A block looks like this:

```json
{
    "blockAction": true,
    "reasonCode": 2,
    "reason": "Detects instruction override, system-prompt extraction, and covert exfiltration in agent I/O",
    "diagnostics": "{\"rule\": \"prompt-injection\", \"severity\": \"HIGH\", \"category\": \"prompt_injection\"}"
}
```

The user sees Copilot Studio's own message: *This action was blocked by threat
detection tools.* `diagnostics` is a JSON string, as the contract requires. A
malformed request (for example, no `toolDefinition`) gets `400` and a missing
or bad token gets `401`, both in the error shape
`{"errorCode": 400, "message": "...", "httpStatus": 400}`. A token from an app
or tenant that is not on your allowlist gets `403`.

### Reason codes

| `reasonCode` | Category |
|---|---|
| 1 | credential in the arguments, secret exfiltration |
| 2 | prompt injection |
| 3 | data boundary, personal data |
| 4 | network egress |
| 5 | tool combination ([tool tags](tool-tags.md)) |
| 6 | destructive action, database change |
| 7 | remote code execution |
| 8 | agent control, IAM |
| 99 | any other rule |
| 100 | evaluation timed out or failed, and the fail posture blocked |

## How a request maps to Prismor

| Copilot Studio | Prismor |
|---|---|
| `toolDefinition.name` | the tool (`tool.name`, matched by `fields: [tool_name]` rules). This is the internal name, not the one Copilot Studio shows: Outlook's *Send an email (V2)* arrives as `send_email_v2` |
| `inputValues` | the arguments (`args.*`), and their JSON text in `response`. Connectors nest them one level (`emailMessage.send_email_v2_to`); Prismor lifts the inner keys too, so `args.send_email_v2_to` works |
| `plannerContext.previousToolsOutputs` | one `tool_result` event per output, screened before the call |
| `plannerContext.userMessage` and the user turns of `chatHistory` | `prompt` events, screened once per turn (see below) |
| `conversationMetadata.agent.name` | the agent name in the console |
| `conversationMetadata.conversationId` | the session, so a conversation's tool calls group together |
| `conversationMetadata.user.id` | the subject, `user:<id>` |
| `agent.tenantId`, `environmentId`, `channelId`, `version` | event metadata |

Every request is evaluated on its own. Copilot Studio sends the earlier
outputs of the plan with each step, so Prismor keeps no state between calls
beyond a per-process note of which user turns it has already screened, and
writes nothing to disk for a request.

The policy is the eval-server's workspace policy plus your org policy, the
same layers that govern every other surface. A request cannot choose a
workspace.

### The user's message

The user's message and the earlier user turns in the chat history are
screened once per turn, not on every tool call the turn causes. How they are
judged depends on who your agent's users are:

| `user_messages` | |
|---|---|
| `user` (default) | an employee talking to an internal agent. The text is screened as a user prompt: an injection attempt is recorded, and does not block |
| `untrusted` | a public or customer-facing agent. The text is screened like tool output: an injection attempt blocks every tool call in that turn, even when your policy only observes `prompt-injection` |

Set it in the console (**Who talks to your agents: Employees / The public**)
or with `PRISMOR_COPILOT_STUDIO_USER_MESSAGES`.

### Allowed email domains

List your company's domains in the console (**Allowed email domains**) and
any connector call that addresses someone else is blocked: Outlook's
`send_email_v2_to/cc/bcc`, `to`, `cc`, `bcc`, `recipients` and meeting
attendees. Subdomains count as the domain (`eu.contoso.com` is `contoso.com`).
An address that only appears in a message body is not a recipient and does
not block. The block is reported to the console as
`copilot-studio-recipient-outside-domains`. Without the console, use
`PRISMOR_COPILOT_STUDIO_ALLOWED_EMAIL_DOMAINS`.

## What blocks out of the box

With the default policy:

- **Injection in an earlier tool's output.** A previous output that tries to
  override the agent's instructions blocks the next tool call in that plan.
- **A credential in the arguments.** A live-looking API key (GitHub, Stripe,
  AWS and the other vendors Cloak knows) in `inputValues` blocks, because it
  is about to leave through the connector. Placeholder and example keys pass.
- **Injection in the user's message**, when `user_messages` is `untrusted`.

If your policy enforces only the rules you picked (a policy with its own
`mode: enforce` rules), make sure `prompt-injection` is among them, or
injections are recorded but not blocked.

The default policy does **not** know who your customers are, so a call such as
an email to an outside address is allowed until you set allowed email domains
(above). For finer control, write a rule; in the console, under Policies:

```yaml
# .prismor/policy.yaml in the eval-server's workspace, or your org policy
rules:
  - id: copilot-email-outside-domain
    title: Email recipient outside the company domain
    severity: HIGH
    category: data_boundary
    event_types: [tool_result]
    fields: [response]
    # any address that is not at contoso.com, in a call to Outlook's send tool
    patterns: ['[\w.+-]+@(?!contoso\.com\b)[\w-]+(\.[\w-]+)+']
    when: "tool.name == 'send_email_v2'"
    action: block
    mode: enforce
```

The `when:` clause limits the rule to the call itself. An external address
that only appears in an earlier tool's output is not a recipient, so it does
not trip the rule. Match the internal tool name (`send_email_v2`), not the
display name: a rule written for `Send an email (V2)` never fires. See
[attribute conditions](attribute-conditions.md) for rules over `args.*` and
`tool.name`.

The LLM judge ([semantic guard](semantic-guard.md)) does not run on this
surface, because it cannot answer inside Copilot Studio's one-second window.

## Try it without Copilot Studio

`prismor copilot-studio test` screens requests in the exact shape a live
tenant sends (an Outlook *Send an email (V2)* call) against a workspace's
policy:

```bash
prismor copilot-studio test --workspace ./my-policy
ALLOW  clean        176ms
ALLOW  external      55ms
BLOCK  credential    56ms  Credential in tool arguments (github key)
ALLOW  injection     54ms

prismor copilot-studio test --workspace ./my-policy --user-messages untrusted --sample injection
BLOCK  injection     26ms  Detects instruction override, system-prompt extraction, and covert exfiltration in agent I/O
```

The first call loads the policy, so it is slower; the server does that at
startup.

Or run the endpoints locally without auth. The no-auth switch works only when
the server listens on localhost:

```bash
export PRISMOR_COPILOT_STUDIO_INSECURE_NO_AUTH=1
prismor eval-server --port 7071 --workspace ./my-policy
curl -s -X POST 'http://localhost:7071/copilot-studio/validate?api-version=2025-05-01'
{"isSuccessful": true, "status": "OK"}
```

## Set it up

You need, in order: a public HTTPS host for the server, an Entra app with a
federated credential, the provider turned on in Power Platform, and the server
running with your org's agent key.

### 1. Get the values

```bash
prismor copilot-studio setup --tenant <tenant id> --endpoint https://security.contoso.com/copilot-studio
```

It prints the application ID URI, the federated credential (issuer, the
encoded subject, audience) and the Power Platform values. The subject is the
step people get wrong by hand: it is your tenant GUID in little-endian byte
form and the endpoint URL, each base64url-encoded without padding.

### 2. Register the Entra app

1. Entra admin center → **App registrations → New registration**, single
   tenant. Note the application (client) id.
2. **Expose an API**: set the application ID URI to your endpoint's origin
   (`https://security.contoso.com`). The host must be a **verified custom
   domain** of the tenant (Entra → Custom domain names). A host on a domain
   you do not own (`*.sslip.io`, a tunnel) is rejected.
3. **Certificates & secrets → Federated credentials → Add credential**,
   scenario *Other issuer*, with the issuer, subject and audience from step 1.

No client secret is created: Copilot Studio exchanges the federated
credential for a token. Microsoft's `Create-CopilotWebhookApp.ps1`
(PowerShell Gallery) does steps 1–3 too.

### 3. Turn it on in Power Platform

1. Power Platform admin center → **Security → Threat detection → Additional
   threat detection**.
2. Pick the environment and choose **Set up**.
3. Tick **Allow Copilot Studio to share data with a threat detection
   partner**, then enter the app (client) id and the endpoint
   (`https://security.contoso.com/copilot-studio`).
4. Set the error behavior to **Block the query**, so a provider that cannot be
   reached blocks the tool rather than letting it run.
5. **Save**. Saving calls `/validate`; it must return 200.

Repeat for each environment whose agents you want covered.

### 4. Connect it to your org and run it

In the console, **Integrations → Microsoft Copilot Studio**: add the tenant id
and the app id, choose how user messages are treated, list your email domains,
and create an agent key. Everything after this point is managed there: the
allowlist, the user-message setting, the email domains, and the org policy
(rules, which ones enforce) under Policies. Changes reach the server within
about 30 seconds, and its blocks show up under that agent and conversation.
Then run the server with that key:

```bash
pip install 'prismor[identity]'                       # token verification
export PRISMOR_AGENT_KEY=<agent key from the console>
export PRISMOR_COPILOT_STUDIO_AUDIENCE=https://security.contoso.com
prismor eval-server --host 0.0.0.0 --port 7071 --workspace /srv/prismor
```

Behind your TLS reverse proxy or load balancer, or in a container
([deploy with Docker](deploy-docker.md)). The server pulls your org policy,
including the tenant and app allowlist, and reports every decision to the
console. Without the console, set the allowlist with environment variables:

| Variable | |
|---|---|
| `PRISMOR_COPILOT_STUDIO_AUDIENCE` | the token audience: your endpoint's origin, the application ID URI. Setting it turns the endpoints on |
| `PRISMOR_COPILOT_STUDIO_ALLOWED_APP_IDS` | comma-separated Entra app (client) ids allowed to call, added to the console's |
| `PRISMOR_COPILOT_STUDIO_ALLOWED_TENANTS` | comma-separated tenant ids, added to the console's. Empty everywhere means any tenant whose token is valid and comes from an allowed app |
| `PRISMOR_COPILOT_STUDIO_USER_MESSAGES` | `user` (default) or `untrusted`; overrides the console |
| `PRISMOR_COPILOT_STUDIO_ALLOWED_EMAIL_DOMAINS` | comma-separated domains, added to the console's. A recipient outside them blocks |
| `PRISMOR_COPILOT_STUDIO_BUDGET_MS` | evaluation budget, default `800` |
| `PRISMOR_COPILOT_STUDIO_FAIL_OPEN` | `1` allows a call whose evaluation timed out or failed. Default is to block it |
| `PRISMOR_COPILOT_STUDIO_INSECURE_NO_AUTH` | `1` skips auth; ignored unless the server is bound to localhost |

The console's settings arrive as `settings.copilot_studio` in the signed org
policy. The same key in a repo or local policy file is ignored, because it
decides whose tokens the server trusts. These endpoints use their own Entra
auth and do not need `--api-key`, which still protects `/v1/evaluate`.

### How requests are authenticated

Copilot Studio sends an Entra ID bearer token. Prismor accepts it only when:

- it is RS256-signed by a key from
  `https://login.microsoftonline.com/{tenant}/discovery/v2.0/keys` (unsigned
  and HMAC tokens are refused),
- its issuer is `https://login.microsoftonline.com/{tenant}/v2.0` (or the v1
  form `https://sts.windows.net/{tenant}/`),
- its audience is the configured audience, it has not expired, and
- its `appid` (or `azp`) is on the app allowlist, and its `tid` on the tenant
  allowlist if one is set.

Signing keys are cached for ten minutes.

## Limits

- **Tool calls only.** Copilot Studio calls the provider before a tool runs.
  An agent's own text replies, including answers drawn from its knowledge
  sources, are not sent, so Prismor cannot screen them.
- **One second.** Copilot Studio treats a reply slower than one second as
  allow (or applies your error behavior). Prismor answers in tens of
  milliseconds once warm, loads the policy at startup, and stops waiting at
  `PRISMOR_COPILOT_STUDIO_BUDGET_MS`, replying with the fail posture so a slow
  evaluation never becomes a silent allow.
- **Generative orchestration only.** Agents that use classic topics do not
  call the provider.
- **Per environment.** The provider is configured per Power Platform
  environment; a new environment is not covered until an admin turns it on.
- **Credits.** Agents only run in an environment with Copilot Studio
  capacity: a license, or a pay-as-you-go billing plan linked to an Azure
  subscription in the same tenant.
- **Preview.** The feature is in preview in Copilot Studio, and the contract
  may change.
