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

If the secret already lives in 1Password, Okta Privileged Access or AWS
AgentCore Identity, fetch it from there instead of pasting it. The value is
written to the vault like any other secret, so every hook works unchanged;
only the reference is kept, in `$PRISMOR_HOME/secret-sources.json`.

```bash
prismor cloak add openai --from-ref op://Engineering/OpenAI/credential
prismor cloak add stripe --from-ref 'okta-pam://acme/<resource_group>/<project>/<secret_id>#api_key'
prismor cloak add github --from-ref agentcore://us-east-1/dev-cli/github
prismor cloak list                           # shows where each one came from
prismor cloak sync                           # fetch them all again after a rotation
```

| Reference | Fetched with | Needs |
|---|---|---|
| `op://vault/item[/section]/field[?attribute=…]` | `op read -n` | The 1Password CLI, signed in through the desktop app, or `OP_SERVICE_ACCOUNT_TOKEN` / Connect in the environment. |
| `okta-pam://team/resource_group/project/secret_id[#field]` | Service token, then plain-text reveal | `PRISMOR_OKTA_PAM_URL` (`https://<org>.pam.okta.com`), and a service user's `PRISMOR_OKTA_PAM_KEY_ID` / `PRISMOR_OKTA_PAM_KEY_SECRET`. The user needs a role and security policy that allow plain-text reveal. `#field` picks one key of a multi-field secret. |
| `agentcore://region/workload_identity/api_key_provider` | `GetWorkloadAccessToken`, then `GetResourceApiKey` | `boto3`, AWS credentials allowed `bedrock-agentcore:GetWorkloadAccessToken` and `GetResourceApiKey`, and a workload identity you created (one linked to Runtime or Gateway cannot be used from a laptop). |

A fetch that takes longer than `PRISMOR_SECRET_SOURCE_TIMEOUT` seconds
(default 20, e.g. a locked 1Password app) fails without writing anything.
`sync` keeps the last good value of any source it can't reach and exits 1, so
one locked manager never empties the vault.

Adding a `--from-ref` secret is a person's job: it decides which real secret a
placeholder unlocks, so `prismor-self-edit` blocks an agent running
`cloak add --from-ref` or editing `secret-sources.json`. An agent may run
`prismor cloak sync`.

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
  (file permissions are its only guard). Exclude it from git, backups, and sync
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
| Agent directly reading a vault file | ✅ **only with the enforce-mode monitor** |
| Secret with no recognizable shape (hand-typed, freshly generated) | ⚠️ may not match a pattern |
| Model narrating a value it already saw | ❌ use `/clear` |
| Anything running as your user, off-agent | ❌ OS file permissions only |

Bottom line: in normal placeholder-based use with both layers installed, the AI
never sees vault contents. The vault is not encrypted at rest — the protection
against a *direct read* is the runtime monitor and file permissions, not the
cloaking hooks alone.

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
- [PII detection](pii.md) — optional Presidio pass for names and other personal data Cloak does not vault
- [Prismor](prismor-runtime.md) — the enforce-mode monitor that closes the vault-read gap
- [Canary](canary.md) — honeytokens for detecting recon attempts
- [CLI Reference](cli-reference.md) — all commands at a glance
