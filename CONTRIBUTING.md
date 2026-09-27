# Contributing to Prismor

Thanks for wanting to contribute. Prismor is a security package for AI coding agents, so a change here can affect what gets blocked, what gets logged, and what leaks. This document tells you how to make a change that gets merged quickly.

Read [`CODE_OF_CONDUCT.md`](./CODE_OF_CONDUCT.md) first. It applies everywhere this project operates. For roles, approvals, and how decisions get made, see [`GOVERNANCE.md`](./GOVERNANCE.md).

---

## The one rule that matters most

**Solve the problem with the fewest lines that fit the design we already have.**

Most code in this repo — and probably most code in your PR — is written with an AI agent. That is fine and expected. But it changes what review has to optimize for.

An agent will cheerfully generate 400 lines of new abstraction for a problem an existing YAML rule solves in six. It will invent a parallel config loader, a second pattern registry, a new base class. Each of those is code someone has to review, secure, and maintain forever. Generation is cheap now. Review attention and security surface are not.

So the order of preference is:

| Rank | Approach | Cost to you |
|------|----------|-------------|
| 1 | **Change configuration.** A new rule in `default_policy.yaml`, a new registry entry, a new pattern. Zero new Python. | Best. Fastest merge. |
| 2 | **Extend an existing module by following its pattern.** Add the next `_merge_<agent>` / `_strip_<agent>` pair, register another named transform. | Good. Usually a small diff. |
| 3 | **Modify an existing abstraction** so it covers your case too. | Fine, if the change stays narrow. |
| 4 | **Introduce a new framework, module, or abstraction.** | Last resort. You must justify it in the PR. |

Options 1–3 are not suggestions to try before you are "allowed" to do option 4. They are where nearly every real change in this repo belongs. **Reach for option 4 only after you can explain, specifically, why 1–3 do not work** — not "it felt cleaner," but "the existing rule engine has no hook for X because Y."

**Smaller diffs get merged faster.** That is a plain statement of how this repo operates, not a motivational slogan. A 20-line PR that reuses the policy engine will be reviewed the day it lands. A 600-line PR that reimplements it will sit while someone works out what it changed about the security posture.

**This is not code golf.** Fewer lines means less new surface area — not clever one-liners, not stripped error handling, not deleted comments. A readable 30-line change beats an unreadable 12-line one every time. What we are cutting is *invented structure*, not clarity.

---

## Before you write code: check whether the seam already exists

Prismor is deliberately built so most new behavior is configuration, not code. Check this table before you add a file.

| If you want to… | Do this, not a new module | Reference |
|---|---|---|
| Add or change a detection rule | Add a rule to [`prismor/runtime/default_policy.yaml`](./prismor/runtime/default_policy.yaml). **Detection patterns never go in Python.** | [AGENTS.md](./AGENTS.md#when-editing-prismor) |
| Change what blocks vs. warns | `settings.block_categories`, or the rule's `action` (`block`, `warn`, `log`, `step_up`, `modify`, `defer`) | [`policy_schema.json`](./prismor/runtime/policy_schema.json) |
| Gate an action on a human | Set the rule's `action: step_up` — do not build a new approval path | [docs/prismor-runtime.md](./docs/prismor-runtime.md#rule-actions) |
| Support a new coding agent / IDE | Add a `_merge_<agent>` + `_strip_<agent>` pair in [`hooks.py`](./prismor/runtime/hooks.py), following the dozen-plus adapters already there | [AGENT_INTEGRATIONS.md](./AGENT_INTEGRATIONS.md) |
| Register a new integration | Add an entry to [`prismor/runtime/integrations/registry.yaml`](./prismor/runtime/integrations/registry.yaml) | `bash scripts/verify_registry.sh` |
| Rewrite tool input before it runs | Register a named transform with `@register(...)` in [`transforms.py`](./prismor/runtime/transforms.py) and reference it from a `action: modify` rule | [`transforms.py`](./prismor/runtime/transforms.py) |
| Map a finding to advisory types | Extend `CATEGORY_TO_FEED_TYPES` in [`feed.py`](./prismor/runtime/feed.py) | [AGENTS.md](./AGENTS.md#advisory-feed) |
| Change severity in a specific context | `severity_on_write` / `severity_on_manifest` on the rule | [`policy_schema.json`](./prismor/runtime/policy_schema.json) |
| Turn a rule off for one project | `.prismor/policy.yaml` with `enabled: false` — do not delete the default rule | [docs/policy-layers-and-exemptions.md](./docs/policy-layers-and-exemptions.md) |

If your change is a new rule in YAML, you may not need to touch Python at all. That is the ideal PR.

---

## Areas with extra rules

Some parts of this repo are security-critical or machine-generated. Changes there are held to a higher bar.

**Do not hand-edit these:**

- [`advisories/`](./advisories/) — the signed threat feed. Use the pipeline scripts. Run `bash scripts/verify_feed.sh` to check signature integrity.
- Anything that would commit a private key, a real secret, or premium feed content. CI (`oss-guard.yml`) fails the build if you do.

**Handle with care:**

- [`prismor/runtime/cloaking/`](./prismor/runtime/cloaking/) — the secret-prevention layer. Never print, log, serialize, or narrate a real secret value. Use the `@@SECRET:<name>@@` placeholder form in code, tests, examples, and prose. Hook scripts are pure bash + `jq`; keep Python out of the hot path. Read [the cloaking README](./prismor/runtime/cloaking/README.md) before touching it.
- [`prismor/runtime/policies.py`](./prismor/runtime/policies.py) — legacy hardcoded patterns, kept only for backward compatibility with tests. Do not add to it.
- Security guidance in markdown is **product logic**, not documentation. `SKILL.md`, `AGENTS.md`, and `docs/` are consumed by agents. Keep them consistent with runtime behavior.

**Never:**

- Weaken a guardrail to make automation easier.
- Add examples that normalize `curl … | bash`, destructive shell commands, or secret exfiltration.
- Put real credentials in fixtures, tests, or docs.

The full list lives in [AGENTS.md](./AGENTS.md#allowed-vs-disallowed-behavior). If you are using an AI agent to write your patch, point it at `AGENTS.md` — that file exists for exactly that purpose.

---

## Development setup

```bash
git clone https://github.com/PrismorSec/prismor
cd prismor
python3 -m pip install -r requirements.txt -r pipeline/requirements.txt
python3 -m pip install pytest
```

You also need `jq` — the cloaking hooks are shell-only.

```bash
brew install jq          # macOS
sudo apt-get install jq  # Debian/Ubuntu
```

## Testing

Run the smallest relevant check while iterating, then the full gate before you open the PR.

```bash
# The security regression suite — same entrypoint CI uses
bash scripts/run_security_tests.sh

# Full test suite
python3 -m pytest tests/ -q

# Lint + SAST — same gates CI runs
python3 -m pip install ruff bandit
ruff check --select E9,F63,F7,F82 .
bandit -r prismor adapters -ll -q

# If you changed a policy rule
prismor policy validate prismor/runtime/default_policy.yaml
prismor check "rm -rf /"
prismor policy show

# If you changed an integration
bash scripts/verify_registry.sh

# If you changed the feed pipeline
bash scripts/verify_feed.sh
```

Cloaking changes need a round-trip check in a scratch workspace — see [AGENTS.md](./AGENTS.md#verification) for the exact commands.

**New behavior needs a test.** A new detection rule needs a test that proves it fires, and ideally one that proves it does not fire on the benign lookalike. False positives make people turn the tool off, which is its own security failure.

## What CI checks

Every push and PR runs:

| Workflow | What it enforces |
|---|---|
| `oss-guard.yml` | No signing keys, secrets, or premium feed content in the public repo |
| `security-regression.yml` | Cloaking + policy suite, and integration registry consistency |
| `static-analysis.yml` | `ruff` (syntax errors, undefined names) and `bandit` SAST (medium severity and up) |

All must pass. A `bandit` finding is fixed, not suppressed; `# nosec` is only for a deliberate case, with the reason on the same line. If `oss-guard` fails, stop and check what you committed before pushing again.

---

## Pull requests

Open PRs against `main`. One logical change per PR — if you fixed a bug and also renamed twelve variables, split it.

The PR body is filled in from [`.github/pull_request_template.md`](./.github/pull_request_template.md) automatically. Please actually fill it in. It asks for:

1. **The problem** — what is broken or missing, concretely. What happens today.
2. **Prior art you checked** — which existing rule, module, or pattern you looked at first, and either how you reused it, or specifically why it was not enough (partial coverage, wrong layer, no hook for your case). "I didn't check" is a valid answer only if you then go check.
3. **The solution, in 3–4 bullets** — what your change does, at a level someone can grasp without reading the diff.
4. **The deep dive** — how it actually works. Control flow, the tricky case, what you decided not to do.
5. **A file table** — every changed file, and why that file had to change.

That structure exists because it front-loads the two things a reviewer needs: *did you reuse what we have*, and *what is the smallest thing that changed*. A PR that answers both gets reviewed fast.

**Commit messages** follow the existing convention — `type(scope): summary`, e.g. `feat(hooks): add Gemini CLI adapter`, `fix(deps): clear Dependabot alerts`, `security: close memory-poisoning gaps`. Look at `git log` for the house style.

## Reporting bugs and security issues

- **Regular bugs and feature ideas** — open a GitHub issue. Include what you ran, what you expected, and what happened.
- **Security vulnerabilities in Prismor itself** — do not open a public issue. See [`SECURITY.md`](./SECURITY.md) for how to report privately and what response times to expect.
- **Code of Conduct concerns** — contact@prismor.dev.

## License

By contributing, you agree that your contributions are licensed under the [Apache License 2.0](./LICENSE), the same license that covers this project.
