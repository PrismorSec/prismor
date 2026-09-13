# Security Policy

Prismor is a security utility for AI coding agents. We treat vulnerabilities in this repository and our runtime components with the highest priority.

---

## Supported Versions

Only the latest active minor release line receives security updates and vulnerability patches.

| Version | Supported | Notes                                     |
| ------- | --------- | ----------------------------------------- |
| 1.x     | Yes       | Actively supported with security updates. |
| < 1.0   | No        | Legacy / pre-release — no longer patched. |

We recommend users and downstream integrators always update to the latest release of `prismor` from PyPI or GitHub.

---

## Reporting a Vulnerability

If you discover a security vulnerability in Prismor, please **do not open a public GitHub issue or discuss it publicly**. Instead, report it through one of the private channels below:

### 1. GitHub Private Vulnerability Reporting (Preferred)
Submit a report privately via GitHub:
**[Report a vulnerability](https://github.com/PrismorSec/prismor/security/advisories/new)**

### 2. Email
Send an encrypted or private email to:
**security@prismor.dev**

Please include:
- A clear description of the vulnerability and its potential impact.
- Step-by-step reproduction instructions or a minimal Proof of Concept (PoC).
- The affected version(s), platform/OS, and agent environment (e.g., Claude Code, Cursor, Gemini CLI).
- Any proposed remediation or patch, if available.

---

## Our Response Process & SLA

When you submit a vulnerability report:

1. **Acknowledgment**: We will acknowledge receipt of your report within **48 hours**.
2. **Triage & Assessment**: We will assess the severity and impact within **5 business days** and keep you updated on progress.
3. **Fix & Verification**: A patch will be developed and verified in a private security advisory branch.
4. **Coordinated Disclosure**: We will coordinate with you on the release date and credit your contribution in the security advisory and release notes.

We kindly ask that you maintain responsible disclosure and give us reasonable time to release a patch before making any information public.

---

## Scope & Out-of-Scope

### In Scope
- Vulnerabilities that allow bypassing runtime policy enforcement without authorization.
- Secret leaks or failures in the secret cloaking prevention layer (`@@SECRET:...@@`).
- Flaws in memory guard integrity or prompt-injection defense mechanisms.
- Remote Code Execution (RCE) or Privilege Escalation vulnerabilities in runtime hooks and adapters.

### Out of Scope
- Attacks requiring physical access to an unlocked, root-compromised machine.
- Social engineering attacks against project maintainers.
- Denial of Service attacks against public demonstration endpoints without functional exploitability.

Thank you for helping keep Prismor and the AI agent ecosystem safe!
