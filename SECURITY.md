# Security Policy

## Reporting a vulnerability

Do not open a public issue for a vulnerability in Prismor itself. Report it privately, either way works:

- **GitHub:** [open a private advisory](https://github.com/PrismorSec/prismor/security/advisories/new) from the repository's Security tab.
- **Email:** contact@prismor.dev, with `SECURITY` in the subject.

Include what you ran, what happened, and the Prismor version (`prismor --version`). A proof of concept helps, but a clear description is enough.

## What to expect

- **Acknowledgement** within 48 hours.
- **Critical** vulnerabilities: a fixed release within 7 days of the report.
- **High and medium** severity: a fixed release within 30 days.

Fixes ship as a normal release with a `CHANGELOG.md` entry that describes the issue and credits the reporter, unless you ask not to be named.

## Supported versions

Only the latest release on [PyPI](https://pypi.org/project/prismor/) receives security fixes. Upgrade with `pip install -U prismor`.

## Scope

In scope: the `prismor` runtime and CLI, its hooks and cloaking layer, the SDK adapters in `adapters/`, and the signed advisory feed in `advisories/`.

A bypass of a policy rule counts: if an agent can run something a rule is meant to block, or read a secret the cloaking layer is meant to hide, report it here.
