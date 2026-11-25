# Sweep and Cloak

Sweep and Cloak are complementary. Cloak prevents secrets from entering model
context in the first place. Sweep cleans up anything that already leaked into AI
tool caches.

<img width="1820" height="796" alt="image" src="https://github.com/user-attachments/assets/68137da9-5e7a-4228-b55a-ec50b5cabd51" />

---

## Cloak

Cloak works at the tool boundary. You register a real secret once under a
placeholder (`@@SECRET:name@@`). Agents with mutation/scrub hooks, such as
Claude Code and Hermes, substitute the real value only at execution time and
scrub it back out of captured output before the model sees it. Block-only agents
such as Codex use `prismor cloak run -- <command>` for the same local
decloak/execute/scrub path; direct placeholder execution is blocked in enforce
mode. Pasted secrets are intercepted automatically.

### Setup (once)

Two layers — install both, they're complementary:

```bash
prismor cloak install                                  # prevention: cloak secrets at the tool boundary
prismor install-hooks --agent claude --mode enforce    # enforcement: block direct reads of the vault
```

Cloak alone keeps secrets out of context. The enforce-mode monitor is what stops
an agent from simply opening the vault files directly — so you want both.

### Everyday use

You mostly do nothing. The flow is automatic:

- **Paste a secret into chat** → it's detected, vaulted, and your prompt is
  blocked once. The sanitized version is stashed; send any follow-up (e.g.
  `go`) and it is loaded automatically. The model then sees only
  `@@SECRET:auto_xxxx@@`.
- **The model emits a raw secret in a command, file, or MCP call** → the call is
  denied, the value is vaulted, and the model is told to use the placeholder.
- **The model uses a placeholder** → Claude/Hermes hooks substitute and scrub
  automatically; in Codex, run the command through `prismor cloak run -- ...`.

Register a secret deliberately (value read from stdin, never argv):

```bash
prismor cloak add stripe_key                 # reference anywhere as @@SECRET:stripe_key@@
prismor cloak add aws_prod --from-file ~/.keys/aws
prismor cloak add --env-file .env            # import each KEY=VALUE as @@SECRET:KEY@@
prismor cloak list                           # placeholder names only — never values
prismor cloak status
prismor cloak run -- <command>               # Codex-safe decloak + execute + scrub
```

### From a secret manager

If the secret already lives in 1Password, Okta Privileged Access, AWS
AgentCore Identity, HashiCorp Vault or OpenBao, Infisical or AWS Secrets
Manager, fetch it from there instead of pasting it. The value is
written to the vault like any other secret, so every hook works unchanged;
only the reference is kept, in `$PRISMOR_HOME/secret-sources.json`.

```bash
prismor cloak add openai --from-ref op://Engineering/OpenAI/credential
prismor cloak add stripe --from-ref 'okta-pam://acme/<resource_group>/<project>/<secret_id>#api_key'
prismor cloak add github --from-ref agentcore://us-east-1/dev-cli/github
prismor cloak add db --from-ref 'vault://secret/apps/web#db_password'
prismor cloak add sentry --from-ref infisical://<project_id>/prod/SENTRY_DSN
prismor cloak add stripe-live --from-ref 'aws-sm://eu-west-1/prod/stripe#secret_key'
prismor cloak list                           # shows where each one came from
prismor cloak sync                           # fetch them all again after a rotation
```

| Reference | Fetched with | Needs |
|---|---|---|
| `op://vault/item[/section]/field[?attribute=…]` | `op read -n` | The 1Password CLI, signed in through the desktop app, or `OP_SERVICE_ACCOUNT_TOKEN` / Connect in the environment. |
| `okta-pam://team/resource_group/project/secret_id[#field]` | Service token, then plain-text reveal | `PRISMOR_OKTA_PAM_URL` (`https://<org>.pam.okta.com`), and a service user's `PRISMOR_OKTA_PAM_KEY_ID` / `PRISMOR_OKTA_PAM_KEY_SECRET`. The user needs a role and security policy that allow plain-text reveal. `#field` picks one key of a multi-field secret. |
| `agentcore://region/workload_identity/api_key_provider` | `GetWorkloadAccessToken`, then `GetResourceApiKey` | `boto3`, AWS credentials allowed `bedrock-agentcore:GetWorkloadAccessToken` and `GetResourceApiKey`, and a workload identity you created (one linked to Runtime or Gateway cannot be used from a laptop). |
| `vault://mount/path[#field]`, `openbao://mount/path[#field]` | KV v2 read, then KV v1 if that path is not KV v2 | `VAULT_ADDR` and `VAULT_TOKEN` (or the token `vault login` writes to `~/.vault-token`); `VAULT_NAMESPACE` for Enterprise namespaces. `openbao://` reads `BAO_ADDR` / `BAO_TOKEN` first. The address must be `https://`, or `http://` to localhost. `#field` picks one key; a secret with one key needs none. |
| `infisical://project_id/environment[/folder…]/NAME` | Universal Auth login, then `GET /api/v3/secrets/raw` | A machine identity's `INFISICAL_UNIVERSAL_AUTH_CLIENT_ID` / `INFISICAL_UNIVERSAL_AUTH_CLIENT_SECRET`, or an access token in `INFISICAL_TOKEN`. `INFISICAL_API_URL` for a self-hosted instance (default `https://app.infisical.com`). |
| `aws-sm://region/secret_id[#field]` | `GetSecretValue` | `boto3` and AWS credentials allowed `secretsmanager:GetSecretValue` (and `kms:Decrypt` for a customer-managed key). `#field` picks one key of a JSON secret; a plain-string secret is used as is. Binary secrets are not supported. |

A fetch that takes longer than `PRISMOR_SECRET_SOURCE_TIMEOUT` seconds
(default 20, e.g. a locked 1Password app) fails without writing anything.
`sync` keeps the last good value of any source it can't reach and exits 1, so
one locked manager never empties the vault.

Adding a `--from-ref` secret is a person's job: it decides which real secret a
placeholder unlocks, so `prismor-self-edit` blocks an agent running
`cloak add --from-ref` or editing `secret-sources.json`. An agent may run
`prismor cloak sync`.

### From your org console

On an enrolled machine, an org admin can hold a secret in the console instead
of asking each person to add it. In the console, go to **Secrets & PII → Org
vault**, add the secret and pick who gets it: every device in the org, or
selected people, devices and agent keys. The value is write-only: nobody can
read it back from the console.

The console seals the value to each device's own X25519 key
(`$PRISMOR_HOME/seal_key.pem`, made on first sync) and signs the list with the
policy key. The device checks the signature and that the list is for this
device and org, opens each secret and writes it into the local vault. Agents
use it as `@@SECRET:<name>@@` like any other vaulted secret.

```bash
prismor cloak sync     # also syncs the org vault on an enrolled machine
prismor cloak list     # org secrets show "from org vault, v<N>"
```

You do not need to run `sync`: the policy check the hooks already make (about
every 30 seconds while an agent works) notices a change and syncs. A rotation
replaces the local copy on the next check. A deleted secret, or one whose access
was removed, is deleted from the device on the next check. A process that
already read the value keeps it, so rotate the key at its provider when it must
stop working.

If this machine already has its own secret with the same name, the local one
wins. The console shows a conflict for that device until one of them is renamed.
`cloak remove` on an org secret deletes the local copy, but the next sync
brings it back unless an admin removes access in the console.

### Bind a secret to its hosts

The scrubber removes the value from output, also in base64, hex, URL-encoded
and reversed form. A custom encoding (XOR, the value split into parts) still
gets past it. To stop a deliberate leak, bind the secret to the hosts it is
for:

```bash
prismor cloak add STRIPE_API_KEY --host api.stripe.com
prismor cloak hosts STRIPE_API_KEY api.stripe.com '*.stripe.com'   # change
prismor cloak hosts STRIPE_API_KEY --any                           # remove the binding
prismor cloak list   # shows "only to api.stripe.com"
```

A bound secret is resolved only into a `curl`, `wget`, `http` or `xh` call
whose URLs all go to one of its hosts. Prismor refuses any other use before
it resolves the value: `echo`, `base64`, a pipe into another program, a
redirect to a file, an env var, a proxy, `--resolve`/`--connect-to`, a curl
config file, or a client binary in your home, the working folder or a temp
folder. The same check runs for `prismor cloak run`.

Changing or removing a binding needs a terminal, and agents are blocked from
`prismor cloak hosts`, so an agent can not widen its own access.

For an org vault secret, the admin sets the hosts in the console (**Only send
it to**). The device applies them on the next sync. `cloak hosts` refuses org
vault secrets.

Limits:

- A bound secret can not be used in an env var, a shell script or an SDK app.
  Leave secrets for those unbound.
- A client binary in a folder your user can write outside your home (for
  example a Homebrew prefix) is trusted.
- Devices on a runtime older than this feature ignore the hosts of org vault
  secrets.

### Custom detection patterns

Built-in patterns cover Stripe, GitHub, AWS, Google, Slack, GitLab, and JWTs.
Add your org's token formats:

```bash
prismor cloak pattern add 'mycorp_[0-9a-f]{32}'
prismor cloak pattern list
prismor cloak pattern remove 'mycorp_[0-9a-f]{32}'
```

Patterns are POSIX regex, validated on add, and apply to both the paste guard and
the tool-call guard.

### Best practices

- **Run both layers.** `cloak install` without the enforce-mode monitor leaves the
  vault readable by a determined or prompt-injected agent.
- **Reference, never inline.** Use `@@SECRET:name@@` in commands and files. Don't
  ask the model to hardcode a live secret — store the placeholder or an env-var
  reference instead.
- **Protect the vault directory.** `~/.prismor/secrets/` is plaintext on disk
  (file permissions are its only guard; on Windows Prismor drops inherited ACLs with `icacls` when it creates the directory, best effort). Exclude it from git, backups, and sync
  (Time Machine, iCloud, Dropbox). Add a Claude `permissions.deny` rule for
  `Read(~/.prismor/secrets/**)` for defense in depth.
- **`/clear` after any suspected leak.** If the model ever saw a raw value, it can
  still echo it from memory — hooks can't filter assistant prose.
- **Don't fight a false positive — bypass it.** Prefix a prompt with `!!allow ` to
  discuss a secret format without auto-cloaking.

### Threat model

| Scenario | Covered? |
|---|---|
| Secret in a pasted prompt | ✅ auto-vaulted, prompt re-sanitized |
| Raw secret in a command / file write / MCP arg | ✅ denied + vaulted |
| Model using a placeholder | ✅ resolved locally, output scrubbed |
| Model re-encoding a resolved value (base64, hex, reversed) | ✅ scrubbed in those forms |
| Model sending a value off with a custom encoding or to another host | ✅ **only for a secret bound to its hosts** |
| Agent directly reading a vault file | ✅ **only with the enforce-mode monitor** |
| Secret with no recognizable shape (hand-typed, freshly generated) | ⚠️ may not match a pattern |
| Model narrating a value it already saw | ❌ use `/clear` |
| Anything running as your user, off-agent | ❌ OS file permissions only |

Bottom line: in normal placeholder-based use with both layers installed, the AI
never sees vault contents. The vault is not encrypted at rest — the protection
against a *direct read* is the runtime monitor and file permissions, not the
cloaking hooks alone.

### What the console sees

Every catch is counted. Each cloak hook appends one line to
`~/.prismor/cloak_events.jsonl`. On its next tool call, the Prismor hook drains
that file and sends each line to your configured sinks as a finding. On an
enrolled device the finding lands in the console's Secrets page.

| Rule id | When |
|---|---|
| `cloak-prompt` | a secret pasted in a prompt was vaulted and the prompt sanitized |
| `cloak-prompt-file` | a prompt `@`-mentioned a file holding a registered secret (blocked) |
| `cloak-tool-input` | a raw secret in a command, file write or MCP arg was vaulted (denied) |
| `cloak-read` | a Read of a file holding a registered secret was blocked |
| `cloak-output` / `cloak-mcp-output` | a registered value was scrubbed from command or MCP output |
| `cloak-command` | a `@@SECRET:name@@` placeholder was resolved at execution |

A line carries the vault **name** (`auto_<hash>` or the name you registered),
the pattern that matched, the session id and the tool. It never carries the
value. Redactions arrive with `redaction_applied: true` and
`data_classes: ["secret"]`. PII findings (`pii-ner`) carry their entity types in
`data_classes`, and are marked redacted when `settings.pii` is `redact` +
`enforce`.

---

## Sweep

Sweep scans the local config directories of Claude, Cursor, Windsurf, Codex, and
others for secrets that have already leaked. It finds API keys, tokens, and
credentials, then lets you redact or delete them. Redacted values are saved to an
AES-256 encrypted vault so you can restore them if needed.

```bash
prismor sweep                     # dry run — shows what's exposed, no changes
prismor sweep --redact            # redact in place, save originals to vault
prismor sweep --clean             # delete files containing secrets (vault backup first)
prismor sweep --restore --all     # restore all secrets from vault
prismor sweep --restore --file <path>  # restore one file
prismor sweep --show-vault        # inspect vault contents (requires passphrase)
prismor sweep --purge             # redact with no vault backup (no recovery)
```

Run `prismor sweep` dry first; if something looks like a false positive, check
the cloak pattern list before reaching for `--purge`.

---

## See also

- [`prismor/runtime/cloaking/README.md`](../prismor/runtime/cloaking/README.md) — full implementation details
- [Secret leak guards](secret-leak-guards.md) — the vault-flow check, token-store rules and the publish gate
- [PII detection](pii.md) — optional Presidio pass for names and other personal data Cloak does not vault
- [Prismor](prismor-runtime.md) — the enforce-mode monitor that closes the vault-read gap
- [Canary](canary.md) — honeytokens for detecting recon attempts
- [CLI Reference](cli-reference.md) — all commands at a glance
