# Signed Audit Trail

Every tool call an agent makes through Prismor lands in a local,
hash-chained, Ed25519-signed audit trail. Allowed, warned, blocked, escalated:
all of them get a record.

```
~/.prismor/audit/trail.jsonl    one JSON record per action, append-only
~/.prismor/audit/chain.json     chain head {seq, last_hash}
```

Each record links to the one before it (`prev_hash`) and is hashed over **all**
of its fields, then signed with the device's Ed25519 key at
`~/.prismor/receipt_signing_key.pem` (the same key that signs telemetry
receipts). Edit a record, reorder two, or delete one, and the recomputed chain
no longer matches. Rewriting the whole history means re-signing every record,
and that needs the private key. Re-sign with a fresh key instead and
verification still catches it, because it pins to the device key.

Signing needs the optional `cryptography` extra:

```bash
pip install "prismor[signing]"
```

Without it, records are still hash-chained but unsigned.

> This page covers the **local** trail, which hashes every field of every
> record. The records a device *reports* are a narrower format with a different
> integrity model — the chain there covers seven fields and not the timestamp.
> If you are writing a verifier for exported records, see
> [Signed Telemetry Receipts](telemetry-receipts.md).

## What a record captures

| Field | Meaning |
|---|---|
| `ts` | ISO-8601 UTC timestamp (covered by the hash, unlike the telemetry chain) |
| `device_id`, `agent`, `agent_name`, `subject` | who: device, framework, agent instance, human principal |
| `agent_version`, `prismor_version` | versions in play |
| `session_id`, `workspace`, `phase` | where: session, repo, pre/post tool-use |
| `event_type`, `tool_name`, `input_summary`, `evidence_hash` | what: the (secret-scrubbed) inputs and sources invoked |
| `agent_stated_intent` | the agent's own description of the action (e.g. the Bash `description` param) |
| `verdict`, `rules`, `reason`, `mode`, `eval_ms` | why: the policy decision in human-readable terms |
| `seq`, `prev_hash`, `hash`, `signature`, `signing_key_id` | the chain + signature |

Extension lifecycle events get their own records too (`record_type: "extension"`):
`extension_installed`, `extension_changed`, `extension_invoked`, `remote_ref_drift`,
`remote_ref_flagged` and `hook_executed`. An install is the one part of an agent's
supply chain no tool call passes through. See [Extension Ledger](extensions.md).

Human approvals get their own records (`record_type: "approval"`). The
headless approval path (`await_step_up`) writes the outcome, one of
`approved`, `denied`, `expired`, `timeout`, or `request_failed`, along with the
approval id. On interactive agents, an approved step-up shows up as the next
`post` record for the tool that ran.

> "Reasoning" here means the policy engine's rationale plus whatever the agent
> said it was doing at the hook boundary. Hooks never see the model's
> chain-of-thought, so the trail can't record it.

## Commands

```bash
prismor trail verify              # re-walk the chain: hashes, linkage, seq, signatures
prismor trail verify --json       # machine-readable report (exit 1 on any problem)
prismor trail verify --pubkey B64 # pin to an out-of-band copy of the device pubkey
prismor trail show --last 50      # human-readable recent records
prismor trail checkpoint          # signed chain head, for anchoring elsewhere
```

`verify` reports one of three outcomes. `ok` means the chain checks out.
`gaps` means records are missing; a crash and a deletion look identical from
here, and an anchored checkpoint is what tells them apart. `tampered` covers a
hash mismatch, broken linkage, reset chain state, an invalid signature, or a
record signed by a foreign key.

## Anchoring (what makes truncation provable)

Local verification catches edits and mid-log deletions on its own. What it
can't catch is the trail and its chain state getting rewound together. So
export a signed checkpoint every so often, somewhere the agent can't reach:

```bash
prismor trail checkpoint --out /path/outside/the/machine/head.json
```

A private git remote, another host, a ticket. Any later `verify` whose head
`seq` sits below an anchored checkpoint proves the trail was truncated.
Enrolled devices also anchor finding receipts server-side through telemetry.

## Configuration

| Env var | Effect |
|---|---|
| `PRISMOR_AUDIT_TRAIL=0` | disable the trail |
| `PRISMOR_AUDIT_STRICT=1` | fail closed: block the action if its record can't be written. Default is best-effort, where a failed append shows up as a verifiable seq gap |

## Threat model, honestly

The trail is **tamper-evident**, not tamper-proof. The signing key lives on
the same machine, and anything running as your uid can read it. Three layers
narrow that gap in practice:

1. The `audit-trail-tampering` policy rule (CRITICAL, non-overridable) blocks
   agent commands that touch `~/.prismor/audit/`, the signing key, or the
   telemetry chain state.
2. Signatures pin the history to the device key. An attacker who can't read
   the key can't forge records, and re-signing with another key changes
   `signing_key_id`.
3. Anchored checkpoints make rewinds provable.

The next step is a signer service that holds the key outside the agent's
reach, in a container or under a separate uid. That's planned, not built.
