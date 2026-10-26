# Microsoft 365 Copilot

`prismor m365-copilot pull` brings Microsoft 365 Copilot activity into the
console: who used Copilot, in which app, through which agent, whether it
had web search on, and what it read. It covers Copilot chat in Teams, Word,
Outlook, Excel, PowerPoint and the web, and the agents people build in
Copilot's Agent Builder.

It observes; it cannot block. Microsoft 365 Copilot gives no third party a
hook before a tool runs, so the only record of what it did is the Microsoft
365 audit log. Prismor reads that log through the Office 365 Management
Activity API and reports each Copilot interaction as an observed event.

To block tool calls, build the agent in Copilot Studio and use
[Copilot Studio threat detection](copilot-studio.md). An Agent Builder agent
can be copied to Copilot Studio.

| | Copilot Studio | Microsoft 365 Copilot |
|---|---|---|
| Agents | Copilot Studio agents | Copilot chat, Agent Builder agents |
| How | Copilot Studio calls Prismor before each tool | Prismor reads the audit log |
| Blocks | Yes, before the tool runs | No, observe only |
| Delay | None | Minutes to hours |

## What the console shows

One event per Copilot interaction, at the time it happened (not when it was
imported):

| Console field | From the audit record |
|---|---|
| Agent | `m365-copilot`, named after the Agent Builder agent, or "Microsoft 365 Copilot (Teams)" for plain chat |
| Subject | The user (`UserId`) |
| Session | One per Copilot conversation (`ConversationId`, the id in the Copilot URL) |
| Tool | The app: Teams, Word, Outlook, Office... (`AppHost`), with the client (`AppIdentity`, e.g. `Copilot.M365Copilot.WebChat`) in metadata |
| Metadata | Plugins enabled (web search is `BingWebSearch`; enabled, not necessarily used), number of items read, how many carried a sensitivity label, item types, models |

The audit record holds no prompt or response text, so neither does the
console.

Microsoft's own detections become findings:

| Record field | Rule | Category | Severity |
|---|---|---|---|
| `Messages[].JailbreakDetected` | `m365-copilot-jailbreak` | `prompt_injection` | HIGH |
| `AccessedResources[].XPIADetected` | `m365-copilot-xpia` | `prompt_injection` | HIGH |

An interaction with neither flag is reported as one `m365-copilot-interaction`
finding (category `audit`, severity info), so plain usage shows up too.
Every finding is in observe mode.

## Set it up

You need a Global Administrator for steps 1 and 2.

### 1. Turn on audit

Audit is on by default in most tenants. Check in the
[Microsoft Purview portal](https://purview.microsoft.com/audit/auditsearch):
if **Audit > Search** offers **Start recording user and admin activity**,
click it.

If the button doesn't take (the page keeps saying it is "having trouble
figuring out if activity is being recorded"), turn it on from Exchange Online
PowerShell. This is common in new and developer tenants:

```powershell
Install-Module ExchangeOnlineManagement -Scope CurrentUser
Connect-ExchangeOnline
Enable-OrganizationCustomization        # "already enabled" is fine
Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true
```

An hour later, check it held:

```powershell
Get-AdminAuditLogConfig | Format-List UnifiedAuditLogIngestionEnabled
```

It must read `True`. Use Exchange Online PowerShell, not Security & Compliance
PowerShell, which always reports `False`. After it turns on, the Management
Activity API can take up to a day to accept the tenant.

### 2. Register an Entra app

In the [Entra admin center](https://entra.microsoft.com), go to
**App registrations > New registration** and create a single-tenant app with
no redirect URI. Then:

1. **API permissions > Add a permission > Office 365 Management APIs >
   Application permissions > ActivityFeed.Read**, then **Grant admin
   consent**.
2. **Certificates & secrets > New client secret.** Copy the value.
3. From **Overview**, note the **Application (client) ID** and the
   **Directory (tenant) ID**.

Keep the secret in [Prismor Cloak](sweep-and-cloak.md) instead of a shell
profile:

```bash
pbpaste | prismor cloak add m365_audit_secret
```

### 3. Run the import

Run it where the events should be reported from: with the org's agent key
(any machine), or on an enrolled device.

```bash
export PRISMOR_AGENT_KEY=...                       # from the console
export PRISMOR_M365_TENANT_ID=<directory (tenant) id>
export PRISMOR_M365_CLIENT_ID=<application (client) id>
export PRISMOR_M365_CLIENT_SECRET=<client secret>
prismor m365-copilot pull --once --dry-run         # check access; reports nothing
prismor m365-copilot pull                          # import every 5 minutes
```

For cron, use `--once` and a schedule of 5 to 15 minutes. Each pass resumes
where the last one stopped, so overlapping or missed runs neither duplicate
nor drop records.

## Command

```
prismor m365-copilot pull [--once] [--interval 300] [--since-hours N]
                          [--workspace DIR] [--dry-run] [--json]
```

| Flag | Effect |
|---|---|
| `--once` | One pass, then exit. Exits 2 on an API or settings error. |
| `--interval` | Seconds between passes when looping (default 300). |
| `--since-hours` | How far back the first pass looks (default 24, at most 7 days, the API's retention). Later passes resume from the cursor. |
| `--dry-run` | Count records without reporting them, and leave the cursor alone. |
| `--json` | Print each pass's counts as JSON. |
| `--workspace` | Workspace whose policy and sinks receive the events. |

Each pass prints `blobs` (content files read), `records` (all audit
records in them), `copilot` (Copilot interactions) and `flagged` (with a
jailbreak or XPIA flag).

The read position lives in `$PRISMOR_HOME/m365-audit-cursor.json`. Delete it
to re-read the last `--since-hours`.

| Variable | Value |
|---|---|
| `PRISMOR_M365_TENANT_ID` | Directory (tenant) ID |
| `PRISMOR_M365_CLIENT_ID` | Application (client) ID |
| `PRISMOR_M365_CLIENT_SECRET` | The app's client secret |

## Troubleshooting

| Message | Cause and fix |
|---|---|
| `set PRISMOR_M365_...` | A setting is missing. The message names it. |
| `oauth2/v2.0/token -> HTTP 400/401` | Wrong tenant ID, client ID or secret, or the secret expired. |
| `subscriptions/start -> HTTP 401/403` | `ActivityFeed.Read` is missing or has no admin consent. |
| `Tenant <id> does not exist` | Audit is not on for the tenant yet. Follow step 1 and check `UnifiedAuditLogIngestionEnabled` reads `True`, then allow up to a day. |
| `blobs: 0` for hours after setup | Normal at first: content appears only for activity after the subscription started, and the first files can take up to 12 hours. |
| `copilot: 0` while other records arrive | No one has used Copilot since the subscription started, or the users have no Copilot access. |

Signing in to Exchange Online PowerShell with `-Device` fails with error
530035 in tenants that use security defaults, which block device-code sign-in.
Sign in without `-Device`, from a machine with a browser.

## Limits

- **Observe only.** Nothing here sits on Copilot's path, so nothing can be
  blocked, and the console's kill switch and pause don't apply.
- **Late.** Records reach the audit log minutes to hours after the
  interaction.
- **No content.** The audit record has no prompt or response text, so text
  rules (secrets, data boundary, injection patterns) can't run on it. The
  findings are Microsoft's own jailbreak and XPIA flags.
- **Seven days back.** The API keeps content for 7 days, so a gap longer than
  that loses records.
