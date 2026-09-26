# Prismor Governance

This document describes how the Prismor open-source project is run: who makes decisions, how those decisions get made, and how someone moves from first PR to maintainer.

It covers the public repository at [github.com/PrismorSec/prismor](https://github.com/PrismorSec/prismor) and the community spaces listed in the [Code of Conduct](./CODE_OF_CONDUCT.md#scope). For how to make a change, see [`CONTRIBUTING.md`](./CONTRIBUTING.md). For behavior, see [`CODE_OF_CONDUCT.md`](./CODE_OF_CONDUCT.md).

---

## Principles

- **Open by default.** Design discussion, review, and decisions happen in public issues, pull requests, and discussions. Security embargoes are the one exception.
- **Security posture outranks velocity.** Prismor decides what AI agents are allowed to do. A change that weakens a default, widens what gets through, or touches secret handling gets more scrutiny than one that adds a feature, regardless of who wrote it.
- **Reuse over invention.** Most changes belong in configuration or an existing seam. Reviewers are expected to push back on new abstractions when options 1–3 of the [contribution ladder](./CONTRIBUTING.md#the-one-rule-that-matters-most) would have covered.
- **Merit, not affiliation.** Roles are earned through sustained, high-quality contribution and review. Employment at Prismor does not grant a role by itself, and not being employed there does not exclude anyone.
- **Tooling-neutral.** Contributions written with AI agents are held to the same bar as any other, no higher and no lower.

---

## Roles

Prismor has four roles. Each one includes everything the role before it can do.

| Role | Who | Can do |
|---|---|---|
| **Contributor** | Anyone who opens an issue, PR, discussion, or review | Propose changes, review others' work, triage by commenting |
| **Triager** | Contributors granted triage permission | Label, assign, close duplicates, and route issues and PRs |
| **Reviewer** | Trusted contributors for one or more areas | Give an approving review that counts toward merge in their area |
| **Maintainer** | Owners of the project's direction | Merge, cut releases, sign the advisory feed, change governance, grant roles |

### Contributor

No sign-up required. Follow the [Code of Conduct](./CODE_OF_CONDUCT.md) and [`CONTRIBUTING.md`](./CONTRIBUTING.md). Contributions are licensed under [Apache 2.0](./LICENSE).

### Triager

Triagers keep the issue tracker usable. Any maintainer can grant triage permission to a contributor who has been helpful in issues for a few weeks. It carries no merge rights.

### Reviewer

Reviewers are trusted to judge changes in a specific area, for example `hooks` / agent adapters, `cloaking`, the policy engine, the proxy, or the feed pipeline.

**To become a reviewer**, a contributor should have:

- Several merged, non-trivial PRs in the area
- A track record of useful reviews on other people's PRs in that area
- Familiarity with the area's security invariants (see [Security-sensitive areas](#security-sensitive-areas))

A maintainer nominates the candidate in a GitHub issue. The nomination passes with approval from one other maintainer and no maintainer objection within 7 days. Contributors may nominate themselves.

**Responsibilities:** respond to review requests in their area within a reasonable time (aim for a first response within 3 working days), and hold the line on the contribution ladder.

### Maintainer

Maintainers set direction and are accountable for what ships.

**To become a maintainer**, a reviewer should have:

- Been an active reviewer for at least 3 months
- Shown good judgment across more than one area, including at least one security-sensitive area
- Demonstrated they will say no to a change that weakens a default, even a popular one

Nomination is by an existing maintainer in a GitHub issue. It passes with approval from a **majority of maintainers** and no **blocking objection** within 14 days.

**Responsibilities:**

- Review and merge PRs; keep `main` releasable
- Cut releases and sign the advisory feed (see [Releases and the advisory feed](#releases-and-the-advisory-feed))
- Handle private security reports and coordinate disclosure
- Enforce the Code of Conduct
- Mentor reviewers and grow the maintainer group

### Stepping down and inactivity

Anyone may step down from a role at any time by opening a PR against [Current maintainers and reviewers](#current-maintainers-and-reviewers). They move to **Emeritus** and are thanked.

A reviewer or maintainer who has not reviewed, merged, or participated in project decisions for 6 months may be moved to Emeritus by a majority of the other maintainers, after a private check-in. Emeritus members can return through a lighter process: one maintainer's nomination and no objection within 7 days.

Roles may also be removed for a Code of Conduct violation, handled under the [enforcement process](./CODE_OF_CONDUCT.md#enforcement).

---

## Decision making

### Lazy consensus

Most decisions are made by **lazy consensus** in the relevant PR or issue: a proposal is accepted if no reviewer or maintainer objects after reasonable time to look at it. Silence is consent. An objection must include a reason and, where possible, an alternative.

### Merging a PR

A PR can merge when:

1. CI is green, including `oss-guard` and `security-regression` (see [What CI checks](./CONTRIBUTING.md#what-ci-checks))
2. It has the approvals required for the area it touches:

| Change touches | Required approvals |
|---|---|
| Docs, examples, tests only | 1 reviewer or maintainer |
| General code | 1 reviewer for the area, or 1 maintainer |
| A [security-sensitive area](#security-sensitive-areas) | 1 maintainer, plus a second reviewer or maintainer |
| This document, the Code of Conduct, or the license | Majority of maintainers |

An author cannot count their own approval. When the author is a maintainer, a security-sensitive change still needs a second approver.

### Larger changes

A change that adds a new subsystem, a new public CLI surface, a new governance surface, or changes default policy behavior should start as a **GitHub issue labeled `proposal`** before significant code is written. The issue should state the problem, what existing seam was considered, and the smallest design that works. It is accepted by lazy consensus among maintainers after at least 7 days open.

### When consensus fails

If a disagreement can't be resolved in the thread, any maintainer can call a vote in the issue. Each maintainer has one vote. A **simple majority** of maintainers decides, except:

- Changes to this document require a **two-thirds** majority of maintainers.
- Adding or removing a maintainer requires a majority, with the person in question not voting.

If votes are tied, the proposal fails and the status quo stands.

---

## Security-sensitive areas

Changes to these paths follow the stricter approval rule above:

- [`prismor/runtime/cloaking/`](./prismor/runtime/cloaking/) — secret prevention. Real secret values are never printed, logged, or committed; use the `@@SECRET:<name>@@` placeholder form.
- [`prismor/runtime/policies.py`](./prismor/runtime/policies.py), [`default_policy.yaml`](./prismor/runtime/default_policy.yaml), and the policy engine — anything that changes what is blocked, warned, or allowed by default.
- [`prismor/runtime/hooks.py`](./prismor/runtime/hooks.py) and the hook dispatcher — the enforcement path.
- [`pipeline/`](./pipeline/), [`keys/`](./keys/), and the signing scripts — the threat feed supply chain.
- Anything under [`.github/workflows/`](./.github/workflows/) — CI is a security control here.

[`advisories/`](./advisories/) is never hand-edited. It is produced by the pipeline and signed; see [`CLAUDE.md`](./CLAUDE.md#working-in-this-repo).

---

## Releases and the advisory feed

- Only maintainers cut releases to PyPI and npm, via the release workflows.
- Only maintainers hold feed signing keys. Keys never enter the public repository; `oss-guard` enforces this.
- A release that weakens a default policy must say so in [`CHANGELOG.md`](./CHANGELOG.md) under its own heading, not buried in a list.

## Security response

Vulnerabilities in Prismor are reported privately through GitHub's security advisory tab, never in a public issue. Maintainers triage reports, coordinate a fix in a private fork, and publish an advisory when the fix ships. Discussion of an embargoed issue stays private until then; this is the one exception to working in the open.

---

## The open-source project and Prismor, the company

Prismor OSS is developed primarily by Prismor, which also offers commercial products built on it. To keep that relationship clear:

- Everything in this repository is Apache 2.0 and governed by this document.
- Commercial features and premium feed content live outside this repository. `oss-guard` checks that they don't leak in.
- A feature is not removed from, or held back from, the open-source project for commercial reasons without a public proposal under [Larger changes](#larger-changes).
- Prismor employees follow the same review and approval rules as everyone else.

---

## Current maintainers and reviewers

| Name | GitHub | Role | Areas |
|---|---|---|---|
| Arnav | [@Ar9av](https://github.com/Ar9av) | Maintainer | All |

**Emeritus:** none yet.

To change this list, open a PR against this section following the process above.

---

## Changes to this document

Changes to `GOVERNANCE.md` are made by pull request and require a two-thirds majority of maintainers, with the PR open for at least 7 days.

This document was inspired by the [Kubernetes community governance](https://github.com/kubernetes/community/blob/main/governance.md), scaled down for a project of Prismor's size.
