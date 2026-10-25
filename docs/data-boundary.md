# Data Boundary

An agent following third-party documentation (a setup guide, a `SKILL.md`)
will run whatever the doc says, including commands that send the user's email,
phone number or credentials to a service the user never approved.
[Egress](network-isolation.md) decides *whether a host may be contacted*. The
data boundary decides *what may be sent there*.

A finding needs both halves: a **real** sensitive value and an **external or
untrusted** destination. Either half alone passes silently: an email to your
own staging box, a `user@example.com` test fixture sent anywhere, or a
`{"prompt": "a sunset"}` payload to a brand-new API.

Implementation: [`prismor/runtime/data_boundary.py`](../prismor/runtime/data_boundary.py).

## What it looks at

Outbound shell commands (`curl`, `wget`, `httpie` and other HTTP clients, plus
vendor CLIs) and web tool calls. For each one it finds the destination and the
data being sent: URL parameters, request bodies, `-d @file` uploads, headers.

**Data classes:** `email`, `phone`, `ssn`, `card`, `iban`, `secret`, and
`file` (a file upload).

**Test values don't count.** Emails at `example.com`/`example.org`/… or under
`.test`/`.invalid`/`.example`, 555 phone numbers, and the well-known test card
numbers (`4111111111111111`, `4242424242424242`, …) are treated as synthetic
and never produce a finding.

**Destination tiers**, resolved in order:

| Tier | What it covers |
|---|---|
| `internal` | Loopback, RFC 1918 addresses, `.local` |
| `trusted` | `trusted_domains`, your git remotes, package registries, a vendor's own CLI talking to that vendor |
| `untrusted` | Hosts your egress policy explicitly denies |
| `external` | Everything else |
| `unknown` | A CLI whose destination can't be read from its arguments; screened per `unknown_cli`, and treated as `external` when the binary was installed in this session or that vendor's docs were just fetched (the "follow the SKILL.md" shape) |

Three things escalate the action one rung:

- sending **your own** email or phone (git `user.email`, the enrolment email,
  `self_identity`) to anything but an internal or trusted host;
- sending `bulk_threshold` (default 10) or more distinct values of one class;
- for an `observe`/`warn` action after the session fetched a doc: the doc's
  own host, a host contacted for the first time, or a destination that can't
  be determined.

**Secrets are vendor-aware.** A Stripe key sent to `api.stripe.com` is fine; the
same key sent anywhere else is a `secret-to-non-vendor` finding.

## Default policy

It ships enabled, in observe mode: findings appear in `prismor sessions`, the
dashboard and the console, and nothing blocks until you set `mode: enforce`.
[Governance modes](modes.md) set it for you.

```yaml
settings:
  data_boundary:
    enabled: true
    mode: observe            # observe | enforce
    trusted_domains: []      # e.g. ["*.mycorp.com", "api.openai.com"]
    classes:                 # action per class, per destination tier
      email:  {external: warn, untrusted: step_up, unknown: observe}
      phone:  {external: warn, untrusted: step_up, unknown: observe}
      ssn:    {trusted: warn, external: block, untrusted: block, unknown: warn}
      card:   {trusted: warn, external: block, untrusted: block, unknown: warn}
      iban:   {trusted: warn, external: step_up, untrusted: block, unknown: warn}
      secret: {trusted: warn, external: block, untrusted: block, unknown: warn}
      file:   {external: warn, untrusted: step_up, unknown: observe}
    per_domain:              # per-class carve-outs for known vendors
      "*.sendgrid.com": {email: allow}
      "*.twilio.com":   {email: allow, phone: allow}
      # … about 30 transactional-mail, CRM, auth and cloud vendors ship allowed
    bulk_threshold: 10
    self_identity: []        # extra emails/phones that mean "me"
    self_identity_auto: true # also git user.email and the enrolment email
    unknown_cli: observe
```

**Actions:** `allow` (silent), `observe` (finding, never blocks), `warn`
(finding, never blocks), `step_up` (inline approval), `redact` (rewrite the
call with the value masked; for a CLI flag value it falls back to `step_up`,
since dropping a required flag breaks the command), `block`. Only `step_up`,
`redact` and `block` act, and only when the data boundary (or the device) is in
enforce mode.

## Handing data to a subagent

`handoffs` screens what an agent hands a subagent: a Claude Code launch prompt,
an agent used as a tool, an ADK `AgentTool`. Each data class gets an action,
with overrides by subagent type:

```yaml
data_boundary:
  enabled: true
  handoffs:
    secret: block
    email: warn
    per_subagent:
      billing: {email: allow}
```

Nothing is screened without a `handoffs` block. See
[Limiting subagents](subagent-limits.md#screen-what-an-agent-hands-a-subagent).

## Findings

| Rule id | When |
|---|---|
| `secret-to-non-vendor` | A credential sent anywhere but its own vendor (CRITICAL) |
| `bulk-pii-outbound` | `bulk_threshold` or more distinct values of one class in one call |
| `self-identity-to-external` | Your own email or phone |
| `pii-to-untrusted` | Email, phone, SSN, card or IBAN to a host your egress policy denies |
| `pii-to-external` | Any other send of those classes whose action isn't `allow`: an external or unknown destination, or a trusted one for SSN, card and IBAN |
| `file-upload-to-external` | A local file upload (`-d @file`, `-F field=@file`) carrying no other sensitive value, when the `file` action isn't `allow` |
| `secret-to-subagent` / `pii-to-subagent` | A credential, or email, phone, SSN, card or IBAN, handed to a subagent, when `handoffs` sets an action for it |

Evidence is always masked (`53*******47`): the value itself is never stored.

## Making an exception

When sending the data is intended, say so in policy rather than turning the
feature off:

- **A host you own or trust:** add it to `trusted_domains`.
- **One class to one vendor:** add a `per_domain` entry, e.g.
  `"api.acme.com": {email: allow}`.
- **A different posture for one class:** change its row under `classes`.

Each block message names the host and the class, and these edits go in
`.prismor/policy.yaml`. An agent can't make them itself unless you open an
unlock window (`prismor unlock`).

See also: [Network Isolation](network-isolation.md) · [Policy layers and exemptions](policy-layers-and-exemptions.md) · [Governance modes](modes.md).
