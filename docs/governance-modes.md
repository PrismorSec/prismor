# Governance modes

Prismor ships with a working policy out of the box, but "working" is not the
same as "right for what your agent does". A CI runner and a research agent that
reads the open web need almost opposite settings, and configuring either by hand
means setting six independent axes — enforcement fallback, egress allowlist,
tool access, tag rules, sandbox ring, step-up gates — each in a different place
with its own default. Six chances to get it subtly wrong, and the failure is
silent: a policy that *looks* configured but leaves `egress.default: allow`
reads the same as one that does not.

A **mode** is a named posture that sets all of them at once and compiles into
the same `.prismor/policy.yaml` and `.prismor/agents.yaml` the engine already
reads. There is no separate enforcement path — `PolicyEngine` does not know
modes exist.

```bash
prismor mode list                  # the catalogue, with coverage and friction
prismor mode explain production-ops  # the trade, including what it does NOT stop
prismor mode apply production-ops  # compile it into .prismor/policy.yaml
prismor mode apply dev-safe --dry-run   # print it without writing
prismor mode show                  # what this workspace is running, and any drift
```

## The catalogue

Nine modes along two axes. Four are graded by **how much friction you accept**,
and are directly comparable — same question, different answers:

| Mode | For | Coverage | Friction |
|---|---|---|---|
| `audit-only` | Onboarding, measuring what an agent actually does | 0% | 0% |
| `dev-safe` | Daily GitHub-centric feature work | 28% | 40% |
| `trusted-workspace` | Trusted internal repos, broad autonomy | 34% | 25% |
| `regulated-airgap` | Regulated repos; no network, no shell | 100% | 90% |

Five are shaped by **what the agent does for a living**. Their coverage numbers
are not comparable with each other — each is scored against a different job:

| Mode | The control it exists for |
|---|---|
| `ci-agent` | Unattended pipeline: nothing can prompt a human, so ambiguity blocks. Deny-by-default egress over registries and VCS. |
| `web-research` | Every fetched page is hostile input. Bounds what a session may *do* after an untrusted read, by sequence rather than by pattern. |
| `regulated-data` | Screens what an outbound call *carries*, not only where it goes. Regulated identifiers cannot leave. |
| `production-ops` | The handful of irreversible verbs — destroy, terminate, drop, force-push — against production-named targets. |
| `oss-maintainer` | Supply-chain integrity and contributor content treated as instructions. Deliberately the quietest mode here. |

Coverage is computed from the live ruleset, so it tracks the policy instead of
drifting into a marketing number. `friction_index` is an operator judgement —
measured against a routine-work control set it has held up within a few points
(`dev-safe` 40 claimed / 38 measured, `regulated-airgap` 90 / 92).

Reading the trade: `trusted-workspace` has *higher* coverage and *lower*
friction than `dev-safe`, which is the real shape of the trade rather than a
scoring artifact. `dev-safe` spends its budget on a narrow egress allowlist,
which is blunt. `trusted-workspace` spends it on targeted gates around secrets
and installs — broader protection, less friction, valid only if you actually
trust what is in the repo.

## The one thing to get right first

**Start at `audit-only` unless you already know your traffic.**

Every enforcing mode contains guesses — a list of hosts a build "should" reach,
an environment naming convention, a set of vendors. Adopting `regulated-airgap`
or `ci-agent` cold, with a guessed allowlist, produces an agent that cannot work
and a team that turns Prismor off. That failure mode is much more common than
being under-protected.

```bash
prismor mode apply audit-only
# ... a week of real work ...
prismor egress report          # the destinations your agents ACTUALLY contacted
prismor sessions               # what was screened, and which rules were noisy
prismor mode apply ci-agent    # then paste the real hosts in
```

## Customizing one

A compiled policy is safe to hand-edit; `prismor mode show` reports drift rather
than fighting it. The general moves:

**Promote or demote a single rule.** A sparse entry that names an existing rule
id merges field by field — you do not restate its patterns.

```yaml
rules:
  - id: risky-write
    mode: observe        # keep the finding, stop it blocking
  - id: db-modification
    mode: enforce
```

**Carve out one path instead of disabling a rule.** An allowlist is narrower,
auditable, and can expire.

```yaml
allowlists:
  - id: allow-security-fixtures
    rule_ids: ["prompt-injection", "skill-encoded-payload"]
    patterns: ["tests/fixtures/attacks/"]
    reason: "adversarial corpus — these strings are the test input"
    expires: "2027-01-01T00:00:00Z"
```

**Add patterns to an existing rule** rather than redefining it:

```yaml
rules:
  - id: secret-access
    add_patterns:
      - 'internal-signing-key\.pem$'
```

To make a change permanent across re-applies, edit the mode instead: everything
above is expressible in `prismor/runtime/modes.yaml`, and a mode may declare any
`settings` key, an `enforce_extra` list of rules to promote, and verbatim
`rules` entries (including demotions and rules of its own).

Validate and test what you changed:

```bash
prismor policy validate .prismor/policy.yaml
prismor check "kubectl --context prod-eu delete pod api-1"   # dry-run one command
prismor policy test                     # declarative cases
prismor tags lint .prismor/policy.yaml  # if you edited tool_tags.rules
```

## Things worth knowing before you edit

**`tool_tags.inference_enabled` changes what a combination rule means.** It
defaults to **true**, and tags every `shell`/`file_write` event
`critical_action` and every `file_read` `untrusted_content`. So
`untrusted_content then critical_action -> block` does not mean "read a hostile
page, then send an email" — it means *no command may follow a read*. Every mode
here sets it `false` for that reason. If you write your own, do the same and
tag your consequential tools explicitly.

**`default_mode: enforce` promotes broad warn-rules wholesale.**
`network-exfil-tool` matches any `curl -d`, `git-remote-hijack` matches any
forced push. Under enforce they block routine work — a POST to a host your own
allowlist names, a `--force-with-lease` on a feature branch. The enforcing modes
demote these explicitly and let the precise control (egress list, data boundary,
a narrower rule) do the work.

**The safety floor is not yours to turn off.** Core rules (`rm -rf /`, reverse
shells, secret exfiltration, privilege escalation, and anything that tampers
with Prismor's own wiring) enforce regardless of `default_mode`,
`enabled: false`, or an allowlist — `audit-only` included. A custom rule you
give a core category (`destructive_command`, `rce_canary`, …) inherits that
behaviour, so tune it with `enabled: false` while you measure.

**Lists replace, `egress` and `data_boundary` maps merge.** Writing
`egress.allow` gives you exactly the list you wrote — it does not append. But
`data_boundary: {mode: enforce}` keeps the shipped `per_domain` vendor
carve-outs beneath it. The cloud-metadata `egress.deny` entries are injected
into every egress-enabled mode at compile time, so a mode cannot drop them by
omission.

**The bundled OWASP test pack assumes default egress.** `prismor policy test`
with no `.prismor/policy-tests.yaml` falls back to
`templates/policy-tests-owasp.yaml`, which expects a permissive network. Under a
deny-by-default mode several of its `warn` cases come back as `block`, because
egress refuses the destination before the rule verdict matters. That is the mode
working — write your own cases once you have adopted one.

**The scoped-agent layer is not part of your mode, and it can block on its
own.** [Scoped Agent](scoped-agent.md) synthesizes a per-session tool/path
allowance from your first prompt, and it denies by omission — a tool the scope
did not name is refused for the rest of the session, whatever the policy says.
Measured: the modes alone allowed 47/47 routine actions, and adding a first user
prompt dropped that to 42/47, every one blocked by `scoped-agent` (a research
prompt whose synthesized scope denied `WebFetch`). If a mode behaves and
something still gets refused, read the rule id in the block — if it says
`scoped-agent`, that is
[#257](https://github.com/PrismorSec/prismor/issues/257), not your policy.

**An org policy outranks your file.** On an org-managed workspace the signed
remote policy is merged after yours and can tighten anything here. A mode is the
right shape for a *project* policy; it is not a way to opt out of a fleet
policy.

## Adding a mode

Modes are data: [`prismor/runtime/modes.yaml`](../prismor/runtime/modes.yaml),
one entry per posture, no Python to change. A useful one:

- names a real, recognisable job or a real point on the friction curve,
- sets `default_mode` explicitly,
- states `residual_risk` — what it does **not** stop. Never omit it; a mode
  that claims no downside is a mode nobody should trust,
- explains *why* each axis is set the way it is, not what the keys are called,
- and adds a behaviour assertion to
  [`tests/test_modes.py`](../tests/test_modes.py) for the one control it exists
  for, plus an over-block guard for the routine work it must not break. A mode
  that silently stops working is worse than no mode.
