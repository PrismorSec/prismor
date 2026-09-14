# Attestation Bundle

An attestation bundle is one signed JSON file that captures this machine's
governance posture at a moment in time. It bundles what Prismor already tracks:

- **Agent inventory**: every agent Prismor governs on this host (name,
  framework, enforce/observe mode, last seen)
- **Host discovery**: agents found on the machine and whether each one runs
  under Prismor hooks (see [Host discovery](#host-discovery))
- **Posture findings**: the full `prismor audit` sweep across hooks, policy,
  cloaking, permissions, feed signature, egress, network, and sandbox
- **Framework coverage**: which compliance-framework controls the active policy
  covers (see [Framework coverage](#framework-coverage))
- **Audit-trail anchor**: the signed head of the [signed audit
  trail](audit-trail.md), tying the bundle to the tamper-evident action log

The whole thing gets a SHA-256 content hash and an Ed25519 signature. Hand the
file to an auditor and they re-verify it with one command, on their own machine,
without touching yours.

Signing needs the optional `cryptography` extra:

```bash
pip install "prismor[signing]"
```

Without it the bundle is still assembled and hashed, just unsigned.

## What's in a bundle

| Field | Meaning |
|---|---|
| `schema` | `prismor.attestation.v1`, the version an auditor verifies against |
| `generated_at` | ISO-8601 UTC timestamp |
| `device_id`, `prismor_version` | which machine and which Prismor built it |
| `agents` | the governed-agent inventory |
| `discovery` | host sweep: agents present and whether each is governed |
| `audit_findings` | posture findings from `prismor audit` |
| `framework_coverage` | which compliance-framework controls the active policy covers |
| `trail_checkpoint` | signed audit-trail head (`seq`, `hash`) |
| `content_hash` | SHA-256 over the JCS-canonical bundle body |
| `signature`, `signing_pubkey`, `signing_key_id` | the Ed25519 signature |

The body is canonicalized with [RFC 8785 (JCS)](https://www.rfc-editor.org/rfc/rfc8785)
before signing. That matters for auditors: a verifier written in any language
can reproduce the exact bytes Prismor signed, so re-verification doesn't depend
on Python.

## Commands

```bash
prismor attest                        # print a fresh bundle to stdout
prismor attest --out evidence.json    # write it to a file
prismor attest verify evidence.json   # re-check hash + signature
prismor attest verify evidence.json --pubkey B64   # pin an out-of-band signer key
prismor attest verify evidence.json --json         # machine-readable report
prismor attest coverage               # framework-control coverage of active policy
```

Building a bundle is read-only. It runs the audit, reads the inventory, grabs
the current trail head, and signs the result. Nothing on disk changes except the
file you asked for with `--out`.

## Host discovery

`prismor discover` sweeps this machine for AI running outside Prismor's reach —
shadow AI. It covers three surfaces, each diffed against the governed set that
actually applies to it:

| Surface | Governed when |
|---|---|
| Coding agents | Prismor's hook dispatcher is wired into the agent's config |
| MCP servers | the server is routed through `prismor mcp-gateway` |
| Provider keys | the credential is registered with [Cloak](sweep-and-cloak.md) |

It also reports a fourth, [the browser](#the-browser-surface), which nothing
governs yet and which is therefore left out of the score.

```
  PRISMOR  discover   ~/src/acme

  AGENTS
    governed               Claude Code  (enforce)
    SHADOW                 Gemini CLI (Google)
    no coverage            Warp (Agent Mode)  (Prismor has no hook for this agent)

  MCP SERVERS
    SHADOW                 context7  [cursor]  medium
      https://mcp.context7.com/mcp
      · MCP server 'context7' has a hardcoded secret in headers ('CONTEXT7_API_KEY')

  PROVIDER KEYS
    SHADOW                 anthropic  ANTHROPIC_API_KEY

  BROWSER (WebMCP)
    no coverage            Shopping Copilot  [chrome]  Default
      …/Chrome/Default/Extensions/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/3.1.4
      · Extension code references the WebMCP API.

  ──────────────────────────────────────────────────────────
  Coverage:  42%  of discovered AI surface is governed
  Shadow:    1 agent(s), 1 MCP server(s), 1 key(s)
  Browser:   1 WebMCP surface(s)  — not covered by any surface, not scored
```

Pass a section (`agents`, `mcp`, `keys`, `webmcp`) to limit the report, `--json`
for the machine-readable form, and `--fail-on-shadow` to exit non-zero in CI.

### The browser surface

[WebMCP](https://github.com/webmachinelearning/webmcp) (Chrome 150+, behind a
flag) lets a page register tools on itself with
`document.modelContext.registerTool()`, which an agent running in the same tab
finds and calls. Nothing about that exchange touches a config file or a child
process, so it is invisible to the three surfaces above — and a page offering a
`transfer-funds` tool to an in-tab agent would otherwise leave a machine reading
100% covered.

Which tools a page exposes is decided at runtime and cannot be read off disk. A
host-local sweep does not pretend otherwise; what it reports is the
precondition:

| Reported | Read from |
|---|---|
| Profiles with the experiment enabled | `Local State` → `browser.enabled_labs_experiments` |
| Extensions that speak the API | the extension bundle's own JavaScript |

Both are read-only and neither needs the browser to be running. Chrome and its
channels, Edge, Brave, Chromium and Arc are all covered. Locations and names
only — browsing history, extension storage and page contents are never read.

**These findings stay out of the coverage score.** Prismor has no interception
point inside a browser tab, so an enabled profile is not governable surface that
was skipped; it is surface nothing can cover yet. Scoring it would drive the
number down with findings no `--fix` can clear, which is why the section has no
`--fix` and reports as uncoverable — the same treatment an agent with no hook
surface gets.

### Governing what it finds

`prismor discover --fix` acts on the report: it installs the global hook for
every unmanaged agent, moves the workspace's MCP servers behind the gateway,
and imports dotenv provider keys into Cloak. It shows the plan, states what it
cannot fix and why, and asks before writing to your config files — `--yes`
skips the prompt, `--fix-mode enforce` installs in enforce rather than observe.

Every finding an enrolled device reports also carries whether it is fixable,
the command that fixes it, and — when it is not — the reason. The console uses
that to separate *"a developer clears this in one command"* from *"this needs a
decision"*, which is the difference between a list that gets triaged and one
that gets ignored. The verdicts come from the same planner `--fix` runs, so the
console can never offer a remediation the CLI would refuse.

There is a hard limit worth understanding. Prismor cannot constrain an agent it
has not hooked: egress screening, the sandbox, tool denies and kill switches all
act on a hook payload, and an unhooked agent never produces one. So `--fix`
governs by *eliminating* the shadow rather than policing it, and an agent with
no hook surface at all — Warp, Trae, Antigravity — is reported as unfixable
instead of quietly skipped.

On an enrolled device this inventory also reaches your organization console,
where it becomes a fleet-wide Shadow AI view. `prismor enroll` seeds it, and
the runtime refreshes it once a day from a detached background scan — set
`PRISMOR_DISCOVER_INTERVAL` (seconds) to change the cadence, or run
`prismor discover --report` to push one immediately. Reporting is gated on the
managed workspace, like telemetry: a personal repo never reports what is
installed on your machine, and an unenrolled device reports nothing at all.

An agent counts as **present** when its config or install directory exists, and
agents Prismor has no hook for are shown as *no coverage* and left out of the
shadow count — nothing was skipped, so counting them would inflate the number.
The agent half of this report lands in every bundle under `discovery`, so an
auditor sees not just what Prismor governs but what it doesn't.

Credential-shaped values are redacted before they reach output. An MCP endpoint
often carries the caller's key in a path segment or query parameter, so the raw
URL is itself a secret; those are masked at the point the record is built, which
means the JSON output is as safe as the terminal one. Findings under `keys`
record the provider and the location only — never a value.

This is host-local and read-only. It doesn't scan the network or probe other
machines. Finding AI across a fleet is a bigger job for a separate tool; here
the question is narrower and answerable from local files: on this box, is
anything running outside Prismor's reach?

## Framework coverage

`prismor attest coverage` shows which compliance-framework controls the active
policy covers, and the same data rides inside every bundle under
`framework_coverage`:

```
  PRISMOR  framework coverage  (19/19 controls across 4 frameworks)

  OWASP Top 10 for LLM Applications  6/6
    ✓ LLM01          Prompt Injection  (prompt-injection, prompt-injection-hidden)
    ✓ LLM02          Sensitive Information Disclosure  (secret-exfiltration, ...)
    ...
```

A control counts as covered when at least one policy rule mapped to it is
active. Disable the last rule behind a control and it flips to uncovered, so
the report tracks your real posture rather than a static claim. The mapping
lives in plain YAML under `prismor/runtime/checklists/`: one pack per framework
(control IDs and titles) plus `crosswalk.v1.yaml` tying Prismor rule IDs to
control IDs. Fork a pack, add a rule to the crosswalk, and it flows into the
next bundle.

Four frameworks ship today: OWASP Top 10 for LLM Applications, OWASP Agentic AI
Threats, NIST AI RMF, and the EU AI Act high-risk obligations. Coverage is a
statement about what Prismor enforces at the tool boundary. It is not a legal
compliance opinion, and Prismor is one control among the many a full program
needs.

## Handing a bundle to an auditor

Say you're closing out a compliance review. You run:

```bash
prismor attest --out q3-evidence.json
```

and send `q3-evidence.json` to the auditor. On their machine, they run:

```bash
prismor attest verify q3-evidence.json
```

A clean bundle prints:

```
✓ attestation verified — schema prismor.attestation.v1, generated 2026-07-11T18:24:31
  signed by key id 18ea124a3b10e500
```

Edit a single field of the file and re-verify, and the content hash no longer
matches:

```
✗ attestation FAILED — schema prismor.attestation.v1, generated 2026-07-11T18:24:31
  ✗ content_hash mismatch — the bundle body was altered
```

Verify exits non-zero on any failure, so it drops straight into CI or a
compliance script.

### Pinning the signer

By default `verify` trusts the public key embedded in the bundle. That catches
tampering, but not a bundle forged wholesale by someone with a different key. An
auditor who has your device's public key out of band (from enrollment, or a
key you published) pins it:

```bash
prismor attest verify q3-evidence.json --pubkey <your-device-pubkey>
```

Now a bundle signed by any other key is rejected, even if its own hash and
signature are internally consistent.

## What this is and isn't

The bundle is signed, re-verifiable evidence of *what Prismor was enforcing*,
*which agents it saw*, and *which framework controls that enforcement covers*.
An auditor can trust the file came from your device and hasn't been touched.

Read the coverage as a map of Prismor's runtime controls onto framework
language, not as a certification. A full NIST AI RMF or EU AI Act program has
obligations Prismor never touches: data governance, model documentation, human
oversight processes, legal review. Prismor attests to the slice it enforces at
the tool boundary. Wider framework packs (ISO/IEC 42001, HIPAA-for-AI) and
per-control evidence links are the next additions to the crosswalk.
