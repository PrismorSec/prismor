# Policy Packs

A policy pack is a set of Prismor rules kept in a GitHub repository, so a team
can share one rule set across machines and repos without an enrolled org. You
install a pack with one command. Prismor pins it to a commit SHA, locks the
hash of every file, and can check an Ed25519 signature.

Packs can only **add** rules or **tighten** built-in rules. A pack cannot
disable a rule, loosen a rule, add an allowlist or change settings. It cannot
touch the safety floor, the self-protection rules or the signed org policy.

## Commands

```
prismor policy pack add <owner>/<repo>[@<ref>] [--path <dir>] [--key pub.pem] [--require-signature]
prismor policy pack list
prismor policy pack show <name>
prismor policy pack update [<name>] [--yes]
prismor policy pack remove <name>
```

- `add` turns the tag, branch or SHA (by default, the repo's default branch)
  into a commit SHA. It downloads that exact commit over HTTPS from
  `codeload.github.com`, validates the pack and installs it. `--path` names the
  directory in the repo that holds `prismor-pack.yaml`.
- `update` resolves the stored ref again and prints the rule ids that the new
  commit adds (`+`) or removes (`-`). It asks before it applies the change.
  `--yes` applies without asking. A pinned key and `--require-signature` stay
  in force.
- `list` marks a pack as `signed`, `unsigned` or `TAMPERED`.
- `show` prints the lock entry (repo, ref, sha, fetch time, file hashes) and
  the rule ids.

## Pack format

```
my-pack/
  prismor-pack.yaml     # manifest
  rules.yaml            # one or more policy files (version + rules only)
  SHA256SUMS            # optional, for signing
  SHA256SUMS.sig        # optional, base64 detached Ed25519 over SHA256SUMS
```

```yaml
# prismor-pack.yaml
name: acme-baseline          # [a-z0-9._-], becomes the install name
version: 1.0.0
description: Acme's shared rules
min_prismor: 1.70.0          # optional; older Prismor refuses the pack
policies: [rules.yaml]       # optional; default is every *.yaml in the directory
```

Each policy file uses the normal policy format (`version: "1.0"` and `rules:`),
with these restrictions:

| Entry | Allowed |
|---|---|
| A new rule under an id that no built-in rule uses | Yes. It must be a complete rule that is valid under `policy_schema.json`. |
| `mode: enforce` on a built-in rule | Yes |
| A higher `severity` on a built-in rule | Yes |
| `add_patterns` on a built-in rule | Yes |
| Any other key on a built-in rule (for example `enabled`, `patterns`, `action`, `disable_patterns`), or a full redefinition | No. The id collides with a built-in rule. |
| Any entry on a floor or self-protection rule | No |
| An id that another pack already defines | No |
| `settings:` or `allowlists:` | No |

`add` refuses a pack that breaks these restrictions. If a pack file changes
on disk after installation, Prismor checks it again at load time. Prismor then
ignores each entry that breaks a restriction and reports it.

## Precedence

From lowest to highest:

```
built-in defaults -> policy packs -> user / system -> project -> org (signed) -> repo exemption
```

`prismor policy show` prints this order and the loaded packs. On a rule that a
pack tightened, the finding's `policyLayer` is `pack`. Your own user and project
policy files sit above packs, so they can still change a pack rule on your
machine. A signed org policy is applied last. The safety floor stays in force
at every layer.

## Integrity

Prismor stores packs under the Prismor policy home: `~/.prismor/packs/<name>/`,
or `/etc/prismor/packs/` on a system install. It also writes
`packs/packs.lock.json`, which records the repo, ref, resolved SHA, the sha256
of each file and the fetch time.

Each time the policy loads, Prismor checks every pack file against the lock. If
a file is missing or its hash does not match, Prismor does not load the pack.
It writes a warning to stderr, `prismor doctor` reports a `policy pack`
warning, and `pack list` shows `TAMPERED`. To restore the pack, run
`prismor policy pack update <name>`.

## Signatures

To sign a pack, list its files in `SHA256SUMS` and sign that file:

```
sha256sum prismor-pack.yaml rules.yaml > SHA256SUMS
openssl pkeyutl -sign -inkey signing-key.pem -rawin -in SHA256SUMS | base64 > SHA256SUMS.sig
```

Install it with the public key:

```
prismor policy pack add acme/policies@v1 --key acme-pub.pem --require-signature
```

Prismor checks the signature with the same Ed25519 verifier that it uses for the
signed org policy. Each file in the pack must be listed in `SHA256SUMS` with a
matching hash. Prismor pins the key in the lockfile, so `update` uses the same
key. `--require-signature` refuses an unsigned pack, or a pack that has no key
to verify against.

## Self-protection

Adding, updating or removing a pack is a policy change. An agent cannot do it
from a tool call. The `prismor-self-edit` rule blocks `prismor policy pack
add|update|remove`. The self-protection rules also block shell writes and file
writes to the pack store. Read-only commands (`pack list`, `pack show`) and
reads of the store stay available. To let an agent manage packs, a human opens
a [`prismor unlock`](cli-reference.md#making-exceptions) window.
