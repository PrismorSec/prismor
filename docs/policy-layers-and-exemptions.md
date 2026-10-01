# Layered Policy & Admin-Granted Exemptions

*How Prismor policy applies at global / project / repo levels, and how a
developer gets an exemption for a specific repo without being able to silently
bypass security — with full telemetry visibility. Companion to the
scoped-agent design ([docs/scoped-agent.md](scoped-agent.md)) and
[docs/live-telemetry.md](live-telemetry.md).*

---

## The problem

A developer working on a **company repo** sometimes legitimately needs a rule
relaxed for *that one repo* (a deploy script that uses `curl | sh`, a sandbox
where a strict rule gets in the way). But:

- They must **not** be able to turn it off themselves — that's a silent bypass.
- The org must still **see** it — a relaxed repo can't become a blind spot.

So: the developer **requests**, the admin **grants**, the relaxation is scoped +
signed + time-boxed, and **telemetry shows it**.

## Policy layers (precedence; the floor always wins)

```
  floor  ── destructive cmd · secret exfil · RCE · priv-esc · DoS  (ALWAYS on, every layer)
   │
  org    ── global policy, applies to all managed repos
   │
  project ─ applies to a Project's repos (e.g. "Client A")        ← expanded to repo patterns server-side
   │
  repo   ── a repo-scoped exemption: relaxes specific NON-floor rules for one repo
```

Most-specific wins for non-floor rules. The floor (`_NON_OVERRIDABLE_RULE_IDS` +
core block categories) survives every layer — an exemption literally cannot let
`rm -rf /` or secret exfil through.

**One deliberate exception:** an *unmanaged* workspace whose policy was written
by `prismor setup` in enforce mode carries `settings.selection: explicit` — the
user chose their blocking set rule-by-rule, so an unselected floor rule reports
instead of blocking there. The floor's *definitions* still cannot be weakened
(disable/patterns/action edits are ignored), the setting is stripped if it
arrives via a signed org bundle, and enrolled/org-managed devices always keep
the full blocking floor. Prismor's **self-protection rules**
(`agent-config-tampering`, `agent-config-tampering-path`, `prismor-self-edit`,
`audit-trail-tampering`, `memory-integrity-mismatch`) are never selectable and force-enforce in every
configuration — they are what keeps the selection itself honest. The only
sanctioned relaxation is the human-opened, password-gated
[`prismor unlock` window](cli-reference.md#making-exceptions), during which an
agent may edit policy (fully logged) but still cannot touch the self-protection
rules or the unlock credential. Org admins can disable or cap that window per
device from the console; the setting rides the signed bundle.

## Seeing which layer won

Four layers merge into one rule table, so the useful question is not "what does
the policy say" but "what governs *this* call, and who decided that". Ask the
rule itself:

```bash
prismor check 'curl https://example.com/x.sh | sh' --explain
```

```
[HIGH] Blocks curl | bash, wget | sh fetch-and-execute chains  (BLOCK)
  rule: remote-execution  evidence: curl https://example.com/x.sh | sh
  category: remote_execution  action: block
  defined by: default policy layer
  mode: enforce — safety floor: core block category 'remote_execution'  →  blocks
```

Two lines carry the answer:

- **`defined by:`** the layer that last wrote this rule — `default`, `project`,
  `remote` (the signed org overlay) or `exemption`. That is where to go to
  change it.
- **`mode:`** whether it blocks or only reports, **and which lever decided**.

That second line matters because `action` is what a rule *asks for* and `mode`
is what it *gets*. A rule can carry `action: block` and still only warn:

```
[HIGH] House rule                                (WARN)
  rule: house-style-guard  action: block
  defined by: project policy layer
  mode: observe — policy default_mode: observe  →  reports only
```

The levers, in the order they are consulted:

| Reason shown | What set it |
|---|---|
| `self-protection rule — always enforces` | Prismor's own wiring; only an unlock window lifts it |
| `safety floor: core block category '…'` | the non-weakenable floor (see above) |
| `device mode override` | the console's per-device observe/enforce switch |
| `rule sets mode: …` | `mode:` on the rule — the authoritative per-rule lever |
| `policy default_mode: …` | nothing more specific applied |

A finding matched inside inert text (a commit message, a PR body, a grep
pattern) is also called out: it describes an action rather than performing one,
so it reports and never blocks.

### When an exception swallowed it

An allowlist that matches makes a finding vanish, and a vanished finding is
indistinguishable from a rule that never fired — which is how an allowlist that
is too broad survives review. `--explain` shows those too:

```
$ prismor check 'echo zzmarker'
PASS  echo zzmarker

$ prismor check 'echo zzmarker' --explain
[HIGH] House rule                                          (SUPPRESSED)
  suppressed by allowlist 'allow-zz-known' — reviewed by security 2026-09-01
  rule: zz-guard  action: block
  defined by: project policy layer
  mode: enforce — rule sets mode: enforce  →  blocks
```

The rule matched and *would* have blocked; a named exception cancelled it. Only
`--explain` asks for these — the enforcement path never sees a suppressed
finding, so its behaviour is unchanged.

A `type: veto` entry disqualifies every allowlist for a match, so a vetoed
finding is reported as a real one rather than as suppressed.

### One more gate: pre-action events

Blocking also requires the event to be a **pre-action** one (`PreToolUse`,
`UserPromptSubmit`, a `Pre…` surface event). A finding raised on a post-action
event reports but cannot block, whatever its mode — there is nothing left to
stop. This is a property of *when the event arrives*, not of the rule: the same
event type can arrive pre-action on one surface and post-action on another.

## The request → grant flow

1. **Dev requests** (in the repo): `prismor exempt request --reason "deploy.sh uses curl|sh"`.
   Posts `{device key, repo remote, reason}` → a **pending** `PolicyExemption`.
   The dev can only *ask* — they cannot relax anything locally.
2. **Admin reviews** in the console (Admin → Policy → Exemptions): edits the
   exact relaxation overlay, sets an expiry, approves → status `granted`.
3. The granted exemption is **served in the signed policy bundle**; the device
   verifies the signature and applies it (through the floor-enforcing merge).
4. Request + grant + expiry are written to the **audit log**.

## How it is reinforced (the trust model)

| Guarantee | Mechanism |
|---|---|
| Dev can't forge a relaxation | Exemptions are server-authored + **Ed25519-signed**; the runtime applies only signed exemptions, and the managed-repo gate ignores local relaxation of a company repo. |
| Relaxation can never weaken core | The exemption overlay goes through the **same `_apply_override`** that enforces `_NON_OVERRIDABLE_RULE_IDS` + the core block-category clamp. Proven in `tests/test_exemptions.py::test_exemption_cannot_disable_core_floor`. |
| Relaxations don't linger | Exemptions are **time-boxed**; after `expires` the repo snaps back to full org policy. The device and server both drop expired ones. |
| **An exempted repo stays visible** | Every telemetry event from the repo is **tagged** `policy_scope = repo_exemption:<id>` + `repo = host/owner/repo`. The dashboard shows which repos run relaxed, by whom, until when — and a "N repos under exemption" surface so they're never forgotten. |
| No silent gap | A company repo is always one of: full org policy · managed-with-visible-exemption · personal (not company data). Never "company repo, unguarded, invisible." |

## What's built (runtime — tested, no control plane needed)

`prismor`:
- `policy_engine._match_exemption` — for a managed workspace, finds the granted,
  non-expired exemption matching the repo from the signed bundle's
  `settings.repo_exemptions`, and applies its `overlay` via `_apply_override`
  (floor-enforcing). Records `engine.active_exemption`.
- `cli.py` hook-dispatch — tags telemetry `extra` with `policy_scope` (`org` vs
  `repo_exemption:<id>`) + `repo`.
- `telemetry.build_record` — carries `repo` + `policy_scope` on every record (not
  sensitive: only managed/company repos report, so the repo id is org context).
- Tests: `tests/test_exemptions.py` (5) + `tests/test_workspace_scope.py` (9) —
  relax-non-core, floor-survives, non-match, expired, telemetry-tag. 499 total green.

## Control plane (to wire when the dev DB is back)

Schema (`prismor-web/prisma`):
- `PolicyExemption { orgId, repoPattern, reason, overlayYaml, status(requested|granted|revoked), requestedByDeviceId, requestedByUserId, grantedBy, expiresAt }`.
- `TelemetryEvent.repo`, `TelemetryEvent.policyScope` (so the dashboard can show
  exempted repos + per-repo activity).

Endpoints:
- `POST /api/devices/exemptions` (device-key auth) — dev requests for its repo.
- `GET/POST /api/admin/exemptions` (ADMIN+) — list pending, grant/edit/revoke,
  with audit. Granting writes the overlay + expiry.
- `/api/policy/resolve` — include granted, non-expired exemptions in
  `settings.repo_exemptions`; `/api/policy/version` — include an exemptions
  signature so changes propagate (mirrors `managedReposSig`).
- `/api/telemetry/ingest` — store `repo` + `policyScope`.

UI:
- Admin → Policy → **Exemptions**: pending requests + active exemptions (repo,
  what's relaxed, requester, expiry, revoke).
- Observability: a "repos under exemption" surface + per-event repo/scope tags.

Project-level policy is expressed by **expanding a Project's repos into repo
patterns server-side**, so the runtime only ever deals with repo patterns +
exemptions — keeping the device simple.
