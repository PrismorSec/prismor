# Prismor Cloak

**Prevention layer for secrets in AI coding agents.** Keeps real secret values out of the model's context, the on-disk JSONL transcript, and the upstream LLM API — while still letting the agent use those secrets to execute local tool calls.

Complements `prismor sweep` (post-hoc disk-residue cleanup) by stopping leaks at the tool boundary in real time.

---

## How it works

You enroll a real secret once under a human-readable placeholder:

```bash
prismor cloak add stripe_key    # value read from stdin, never argv
```

From that point on, the model refers to the secret as `@@SECRET:stripe_key@@`. When the agent emits a tool call containing that placeholder, Prismor's `PreToolUse` hook:

1. Substitutes the placeholder with the real value in the command that is actually executed locally.
2. Wraps the command so its captured stdout/stderr passes through `scrub-stream.sh`, which masks the real value *back* to the placeholder before Claude Code records it.

The wrap in step 2 is applied to **every** `Bash` command once any secret is registered — not only commands that referenced a placeholder. So a value a command reads out of a file (`grep KEY .env`, `source .env; echo $KEY`, `cat config`, an HTTP response body) is masked too, closing the leak path where a raw secret enters context without ever passing through a placeholder. The scrubber reads the vault itself at runtime, so no secret value is embedded in the wrapped command string.

Result: the real secret is resident only inside the hook process and the local subprocess. The model, the JSONL transcript (`~/.claude/projects/<cwd>/*.jsonl`), and every upstream API request see only the placeholder.

```
            ┌──────────────────────────────── real value never here ──┐
            │                                                          │
User ──► Claude API ──► tool_use("@@SECRET:stripe_key@@")               │
                             │                                          │
                             ▼                                          │
                    PreToolUse hook                                     │
                    decloak + wrap                                      │
                             │                                          │
                             ▼                                          │
                 bash -c "( real cmd ) 2>&1 | sed s|REAL|@@...|g"       │
                             │                                          │
                             ▼                                          │
                  captured stdout (scrubbed) ──► tool_result ◄──────────┘
```

---

## Install

From inside a project:

```bash
prismor cloak install
```

This merges the hook entries into `.claude/settings.json` (preserving any Prismor runtime-monitor hooks already there):

| Event | Matcher | Script | Purpose |
|---|---|---|---|
| `PreToolUse` | `Bash\|Write\|Edit\|MultiEdit\|mcp__.*` | `secret-guard.sh` | Detect raw secrets in tool input, vault + deny |
| `PreToolUse` | `Read\|Grep\|Edit\|MultiEdit` | `read-guard.sh` | Deny a Read, a content-mode Grep, or an Edit (its result echoes nearby lines) of a file that holds a registered secret |
| `PreToolUse` | `Read\|Bash\|Grep` | `env-guard.sh` | Deny content access to a dotenv file until its entries are imported into the vault |
| `PreToolUse` | `Bash` | `decloak.sh` | Substitute placeholders, wrap output through `scrub-stream.sh` |
| `PostToolUse` | `mcp__.*` | `recloak-mcp.sh` | Scrub real values from MCP responses |
| `UserPromptSubmit` | — | `userprompt-guard.sh` | Soft-block + auto-cloak pasted secrets |
| `Stop` (opt) | — | `sweep-on-stop.sh` | Dry-run sweep for residue (off by default) |

`secret-guard.sh` is registered *before* `decloak.sh` so it scans the model's
original input; it is also order-independent because it skips any value already
present in the vault (see below).

Flags:

```bash
prismor cloak install --scope user           # install globally in ~/.claude
prismor cloak install --no-userprompt-guard  # skip the paste-detection hook
prismor cloak install --no-secret-guard      # skip the tool-call detect-and-block hook
prismor cloak install --no-env-guard         # skip the unimported-.env bootstrap guard
prismor cloak install --sweep-on-stop        # add the Stop-hook sweep
```

### The bootstrap gap (`env-guard.sh`)

`read-guard.sh` and the decloak output scrub only protect values **already
registered** in the vault. Without `env-guard.sh`, the very first thing an
agent does in a fresh workspace — `cat .env` or `Read(.env)` — leaks every
secret before any of them has a placeholder.

`env-guard.sh` denies content access (built-in `Read`, a content-mode `Grep`,
or a Bash command that names the file) to a dotenv-style file (`.env`,
`.env.*`, `*.env`, `.envrc`) **while it holds values missing from the vault**,
and the deny reason is itself the fix. The Bash check tokenizes the command
(`env_guard.env_reads`) and is deny-by-default: any command naming such a file
counts as reading it — however the command name is quoted or spelled, through
a glob, a variable, a symlink, `$(...)`, or after a `cd` anywhere in the
command — except metadata and write forms (`ls`, `stat`, `test -f`, `wc`,
`>> .env`, `git add`) and the presence checks below:

```
prismor cloak add --env-file .env
```

That command parses the file in the CLI process and registers every entry as
its own `@@SECRET:name@@` placeholder — only names and byte counts are ever
printed, so the values never enter model context. Once every entry is
imported, the guard stands down for plain viewers (`cat`, `head`, `grep` ...)
and the registration-based hooks take over. A Bash command that sends a vaulted
env file anywhere else (piped into a non-viewer, redirected to a file,
uploaded, `git add`ed, sourced, re-encoded) is still denied: the output scrub
only sees the tool output, so the real values would leave unredacted.
secret-guard likewise denies a raw vaulted value in a Write, Edit or MCP call,
since decloak only runs for Bash.
The unimported-entry check runs through the same parser the importer uses
(`env_guard.py` → `secrets_store._parse_env_line`), so guard and importer can
never disagree about what "fully imported" means.

Deliberately allowed even before import: `prismor cloak …` commands (the
ingestion path), append-only writes (`echo KEY=@@SECRET:KEY@@ >> .env`), and
presence checks (`grep -q '^KEY=' .env`). Example/sample/template env files
are exempt — reading those is how an agent learns which keys a project needs.

Uninstall leaves unrelated Claude Code settings untouched:

```bash
prismor cloak uninstall
```

---

## Managing secrets

```bash
# Register — value is read from stdin (or hidden prompt if interactive)
prismor cloak add stripe_key          # prompts you to paste the value
printf '%s' "$(cat ~/.keys/stripe)" | prismor cloak add stripe_key
prismor cloak add aws_prod --from-file ~/.keys/aws
prismor cloak add --env-file .env     # imports each KEY=VALUE as @@SECRET:KEY@@

# List registered placeholder names — NEVER shows values
prismor cloak list

# Delete a registered secret (any tool call still referencing it will fail closed)
prismor cloak remove stripe_key

# Show install state
prismor cloak status

# Codex-safe execution path: resolves placeholders locally and scrubs output
prismor cloak run -- curl https://api.example.com -H "Authorization: Bearer @@SECRET:api_key@@"
```

Secrets live under `$PRISMOR_HOME/secrets/` (default `~/.prismor/secrets/`) with the directory at `0700` and each file at `0600`. The directory should be **excluded from backups and sync** (Time Machine, iCloud, Dropbox). Override the location with `PRISMOR_SECRETS_DIR`.

### Writing the literal placeholder syntax (escape form)

`decloak.sh` runs over the whole Bash command string and fails closed on any
`@@SECRET:name@@` it cannot resolve. That is correct for execution, but it also
fires when you are merely *writing about* the syntax — a doc, a commit message,
or a test fixture. To write the literal placeholder, escape the colon with a
backslash:

```bash
git commit -m "docs: explain the @@SECRET\:name@@ placeholder form"
```

The placeholder regex skips `@@SECRET\:name@@` (a name may not contain a
backslash) and no substitution touches it, so the escaped text is emitted
verbatim and the guard does not fire. Fail-closed stays the default: a real,
unresolved placeholder is still denied.

**The backslash is part of what you write.** Nothing rewrites it on the way
out, so the commit message above lands as `docs: explain the @@SECRET\:name@@
placeholder form` — backslash included. The escape lets you write *about* the
syntax through Bash; it does not produce the unescaped literal. When a file
must contain the exact unescaped text (a fixture asserting on the real
placeholder, say), build it in-process rather than through a Bash command
string — in Python, `"@@" + "SECRET:" + name + "@@"` never reaches the hook.

---

## The user-prompt boundary

`UserPromptSubmit` hooks cannot *rewrite* a prompt in Claude Code — they can only block or add context. When you paste a prompt containing a recognizable secret (Stripe key, GitHub PAT, AWS access key, Slack token, GitLab PAT, JWT, …), the `userprompt-guard.sh` hook:

1. Detects the secret via conservative, known-prefix regex.
2. Auto-registers it under a deterministic hashed name (`auto_<8-hex>`) in `$PRISMOR_SECRETS_DIR`.
3. Blocks the submission with a message that shows the **sanitized** prompt, and stashes that sanitized prompt under `$PRISMOR_HOME/prompt_stash/<session_id>` (mode 0600).
4. On your **next clean message in the same session** (anything — `go`, a clarification, `!!allow …`) it reloads the stash as `additionalContext` and deletes it, so the model receives the sanitized request without you re-pasting anything. If you paste the sanitized text yourself, the stash is simply dropped. Stashes older than 30 minutes (`PRISMOR_PROMPT_STASH_TTL`) are discarded rather than injected into an unrelated conversation.

The original prompt was *not* transmitted to the upstream API. Image attachments on the blocked prompt are not carried over — re-attach them on the follow-up.

**Bypass:** prefix any prompt with `!!allow ` to skip detection for a single message (useful when you are deliberately discussing a secret format in prose).

---

## The tool-call boundary (detect-and-block)

`userprompt-guard.sh` only covers what *you* paste. But the model can introduce
a raw secret on its own — by generating one, reading it out of a file, or
copying a value from earlier output into a command, a file write, or an MCP
argument. `secret-guard.sh` (a `PreToolUse` hook) closes that gap.

When the model emits a tool call whose input matches a secret pattern, the hook:

1. **Vaults** the raw value under a deterministic `auto_<hash>` name — *unless
   that exact value is already in the vault* (so a value `decloak.sh` just
   substituted, or any manually-registered secret, is recognized as legitimate
   and passes through untouched).
2. **Denies** the call with a reason that names the `@@SECRET:auto_xxxx@@`
   placeholder to use instead — and never echoes the raw value.

The raw secret therefore never executes, is never written to a file, and never
reaches the transcript or the upstream API. The model sees the deny reason and
retries with the placeholder, which `decloak.sh` resolves for `Bash`. For
`Write`/`Edit`/MCP the placeholder (or an env-var reference) is what gets
stored — you should not be hardcoding live secrets into files anyway.

```
model emits raw  sk_live_…  in a Bash command
        │
        ▼
  secret-guard.sh  ── value already in vault?  ── yes ─► allow (no-op)
        │ no
        ▼
  vault as auto_<hash>  +  DENY("use @@SECRET:auto_<hash>@@ instead")
        │
        ▼
  model retries with the placeholder ──► decloak.sh substitutes & runs
```

Because of the vault check, install order between `secret-guard.sh` and
`decloak.sh` does not matter and retries are idempotent.

---

## Configurable detection patterns

Both guards detect secrets from a shared, file-based pattern set:

* **Built-in** — `builtin_patterns.txt` (shipped in this module): conservative,
  known-prefix credential formats (Stripe, GitHub, AWS, Google, Slack, GitLab,
  JWT). This is the single source of truth shared by the bash hooks and the
  Python CLI — no duplicated regex.
* **Custom** — `$PRISMOR_HOME/cloak_patterns.txt` (override with
  `$PRISMOR_CLOAK_PATTERNS`): your org-specific token formats.

Manage custom patterns — one POSIX ERE per line — with:

```bash
prismor cloak pattern list                       # show built-in + custom patterns
prismor cloak pattern add 'mycorp_[0-9a-f]{32}'  # validated, appended to custom file
prismor cloak pattern remove 'mycorp_[0-9a-f]{32}'
```

`add` rejects an uncompilable regex; built-in patterns cannot be removed.

---

## What this does *not* protect

Enumerated honestly so you know what to layer on top:

1. **Hand-typed secrets shorter than ~16 chars.** No prefix, too short for entropy heuristics, indistinguishable from benign text.
2. **Secrets generated mid-turn** (`openssl rand`, `aws iam create-access-key`, `ssh-keygen`). The `sed`-wrap scrubber only knows about values already in `$PRISMOR_SECRETS_DIR`, so a freshly minted value flows through the *generating* command's output unscrubbed. `secret-guard.sh` does catch it on the *next* tool call if the value matches a known pattern (e.g. a generated `AKIA…` reused in a later command) — but a value with no recognizable shape still slips through.
3. **The secrets directory itself**, if committed, synced, or backed up without exclusion. Treat it as a single point of failure.
4. **Built-in `Read` / `Grep` / `Edit` of secret-bearing files.** `PostToolUse` can only rewrite MCP tool output, not built-in tools, so a Read, a content-mode Grep, or an Edit result snippet cannot be scrubbed after the fact. `read-guard.sh` (a `PreToolUse:Read` hook, on by default) closes this by *denying* a Read whose target file contains a registered secret and directing the model to the `@@SECRET:name@@` placeholder instead. Disable with `prismor cloak install --no-read-guard` if a deny is too strict for your workflow.
5. **Codex hook mutation.** Codex hooks can block, but cannot rewrite Bash commands or scrub Bash output. In Codex enforce mode, Prismor blocks commands containing `@@SECRET:name@@` so placeholders do not execute literally. Use `prismor cloak run -- <command>` for a first-class decloak + execute + scrub path.
6. **Encoded or transformed output, and the exit code.** The scrubbers match a registered value verbatim (plus its JSON-escaped form for MCP output). A command that prints it base64-encoded, reversed, split, or one byte per call through its exit status (`exit $(printf %d "'${v:0:1}")`) is not masked.
7. **Assistant-side narration.** If the model already saw a real value (through paste, Read, or a command that bypassed the wrapper), it can echo the value in prose. Hooks cannot filter assistant text. Use `/clear` immediately after any suspected leak.

For residue that slips through despite all of the above, run:

```bash
prismor sweep            # dry-run scan
prismor sweep --redact   # scan + encrypted-vault redact
```

---

## Layering with Prismor runtime monitor

Cloak and Prismor's runtime monitor coexist on the same `.claude/settings.json`. Install order does not matter; each feature merges its own matcher blocks and uninstall strips only its own entries. Recommended combination:

```bash
prismor install-hooks --agent claude --mode enforce   # policy enforcement
prismor cloak install                                 # secret prevention
```

Then on a cadence (or via the opt-in `--sweep-on-stop` flag above):

```bash
prismor sweep --redact
```

---

## Files shipped in this module

```
prismor/runtime/cloaking/
├── __init__.py             # public API re-exports
├── installer.py            # install/uninstall settings.json merger
├── secrets_store.py        # add/list/remove operations on $PRISMOR_SECRETS_DIR
├── env_guard.py            # unimported-entry check shared with env-guard.sh
├── patterns.py             # built-in + custom detection-pattern management
├── builtin_patterns.txt    # single source of truth for detection regexes
├── hooks/
│   ├── _patterns.sh        # shared bash loader (sourced by the guards)
│   ├── decloak.sh          # PreToolUse:Bash — placeholder substitution + output scrub
│   ├── scrub-stream.sh     # stdin filter — masks registered secrets in command output
│   ├── read-guard.sh       # PreToolUse:Read|Grep|Edit|MultiEdit — deny content of secret-bearing files
│   ├── env-guard.sh        # PreToolUse:Read|Bash|Grep — deny access to unimported .env files
│   ├── secret-guard.sh     # PreToolUse — detect raw secrets, vault + deny
│   ├── recloak-mcp.sh      # PostToolUse:mcp__.*
│   ├── userprompt-guard.sh # UserPromptSubmit soft-block
│   └── sweep-on-stop.sh    # Stop (opt-in)
└── README.md               # this file
```

Hook scripts are pure bash and depend only on `jq`. No Python startup cost on
the hot path — the one exception is `env-guard.sh`, which shells out to
`env_guard.py` only after it has already found an existing dotenv-style file
in the tool input (so the common case stays bash-only), because the
unimported-entry check must share the importer's parser.
