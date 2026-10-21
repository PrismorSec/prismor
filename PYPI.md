# Prismor

> _formerly **Immunity Agent**_

Runtime security for AI coding agents. Policy enforcement, secret prevention, supply-chain blocking, and session auditing — all running locally on your machine.

---

## What it does

AI coding agents execute shell commands, read files, call APIs, and install packages autonomously. Prismor sits between the agent and the operating system to:

- **Block dangerous actions** before they run — destructive commands, privilege escalation, reverse shells, secret exfiltration
- **Intercept package installs** and score them for supply-chain risk before they touch your disk
- **Prevent secrets from reaching the model** — register a secret under a placeholder name; Prismor resolves it locally through supported hooks or `prismor cloak run`
- **Log every tool call** to a local SQLite store for session review and auditing
- **Keep a tamper-evident audit trail** where every action is hash-chained and Ed25519-signed, so `prismor trail verify` catches edited, deleted, or rewritten history
- **Find shadow AI on the host** with `prismor discover`, flagging any agent installed on the machine that runs without Prismor hooks
- **Hand auditors a signed evidence bundle** with `prismor attest`, packaging posture, agent inventory, host discovery, framework-control coverage (OWASP LLM/Agentic, NIST AI RMF, EU AI Act), and the trail anchor into one file anyone re-verifies with `prismor attest verify`

Supports Claude Code, Cursor, Windsurf, and more.

---

## Install

```bash
pip install prismor
```

Requires Python ≥ 3.8 and PyYAML (installed automatically).

---

## Quick start

**Install Prismor hooks into your project** (enforces policy on every agent tool call):

```bash
prismor install-hooks --agent claude --workspace . --mode observe
```

Start in `observe` mode to log would-be blocks without interrupting the agent. Switch to `enforce` when ready:

```bash
prismor install-hooks --agent claude --workspace . --mode enforce
```

**Wrap your package manager** to score installs before they run:

```bash
prismor supplychain npm install express
prismor supplychain pip install requests
prismor supplychain cargo add serde
```

**Check a command against policy** before running it:

```bash
prismor check "rm -rf /"
# BLOCK  destructive_command  CRITICAL
```

**Audit your workspace** security posture:

```bash
prismor audit
```

**Scan AI tool configs** for leaked secrets:

```bash
prismor sweep
```

**Launch the self-hosted dashboard** (reads from local SQLite, no cloud):

```bash
prismor dashboard   # opens http://127.0.0.1:7070 in your browser
```

---

## Detection coverage

Prismor ships with 90+ rules (`prismor policy show` lists them) covering the [OWASP Top 10 for LLM Applications](https://genai.owasp.org/llm-top-10/):

| Category | Severity | What it catches |
|---|---|---|
| Destructive command | CRITICAL | `rm -rf /`, `mkfs`, `dd` to disk |
| Secret exfiltration | CRITICAL | `cat .env \| curl`, piping credentials outbound |
| RCE canary | CRITICAL | Reverse shells, `bash -i /dev/tcp` |
| Privilege escalation | CRITICAL | `chmod +s`, sudoers edits, `useradd` |
| Remote execution | HIGH | `curl \| bash`, `wget \| sh` |
| Secret access | HIGH | Reads of `.env`, `.aws/credentials`, `.ssh/id_rsa` |
| Path traversal | HIGH | `../../etc/passwd`, `/proc/self/environ` |
| DB modification | HIGH | `DROP TABLE`, `DELETE FROM` in shell commands |
| Prompt injection | HIGH | `ignore instructions`, `reveal system prompt` |
| Risky write | MEDIUM | Edits to Dockerfile, CI workflows, `package.json` |

Rules are defined in YAML and fully customizable per-project.

---

## Supply chain enforcement

The `prismor` CLI wraps your package manager and evaluates every install against live threat intelligence before it runs. Packages are scored on age, maintainer count, install scripts, and known IOCs. Ships with IOC coverage for recent attacks including the **AntV hijacked-maintainer attack** (May 2026) and the **mini-shai-hulud** campaign (May 2026).

```
prismor supplychain npm install @tanstack/react-router
  BLOCK  score 100  @tanstack/react-router
         42 @tanstack/* packages compromised via CI/CD cache poisoning
```

Verdicts: `< 30` allow · `30–59` warn · `≥ 60` block. IOC matches always block.

---

## Secret cloaking

Register a secret under a placeholder name:

```bash
prismor cloak add stripe_key
# prompts for the value — never stored in shell history
prismor cloak add --env-file .env
# imports each KEY=VALUE entry as @@SECRET:KEY@@
```

Reference it in agent instructions:

```
Run: curl https://api.stripe.com -H "Authorization: Bearer @@SECRET:stripe_key@@"
```

Claude/Hermes cloaking can substitute the real value at execution time and scrub echoed values before they return to the model. Codex hooks are block-only, so Prismor blocks literal placeholder execution there; use the Prismor-owned runner instead:

```bash
prismor cloak run -- curl https://api.stripe.com -H "Authorization: Bearer @@SECRET:stripe_key@@"
```

---

## Modes

| Mode | Behaviour |
|---|---|
| `observe` | Logs all findings, never blocks. Good for the first 24–48 h on a new workspace. |
| `enforce` | Blocks dangerous actions in real time before the agent executes them. |

---

## Links

- **Repository**: https://github.com/PrismorSec/prismor
- **Docs**: https://www.prismor.dev/docs
- **Dashboard**: https://www.prismor.dev
