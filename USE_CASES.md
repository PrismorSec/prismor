# Prismor Use Cases

Real workflows, with the commands and config that make them work.

---

## Contents

- [Developer: Governing a Coding Agent Session](#developer-governing-a-coding-agent-session)
- [Security Engineer: Onboarding a Team in Observe Mode](#security-engineer-onboarding-a-team-in-observe-mode)
- [Platform Team: Governing Production LangChain Pipelines](#platform-team-governing-production-langchain-pipelines)
- [Security Team: Shadow AI Discovery Across the Org](#security-team-shadow-ai-discovery-across-the-org)
- [Compliance Team: Generating an Attestation Bundle](#compliance-team-generating-an-attestation-bundle)
- [Admin: Step-Up Approval for High-Stakes Operations](#admin-step-up-approval-for-high-stakes-operations)
- [Developer: Debugging a Block](#developer-debugging-a-block)
- [Multi-Agent Pipeline: Per-User Attribution with IAM](#multi-agent-pipeline-per-user-attribution-with-iam)

---

## Developer: Governing a Coding Agent Session

**Scenario:** You're using Claude Code to work on a data pipeline. The task involves reading a third-party config file and pushing changes to a staging database. You want Prismor running so that secret reads and outbound writes to unexpected hosts get flagged before they execute.

**Setup (one time per machine):**

```bash
pip install prismor
prismor setup
prismor install-hooks --agent claude --scope user --mode observe
```

Start observe mode first. You'll see every tool call Prismor would have blocked, without anything actually being blocked. This builds your baseline.

After a few sessions, check what Prismor found:

```bash
prismor status
prismor dashboard
```

Flip specific rules to enforce when the findings look accurate:

```yaml
# .prismor/policy.yaml
rules:
  - id: secret-access
    mode: enforce
  - id: outbound-write-untrusted-host
    mode: enforce
```

```bash
prismor install-hooks --agent claude --scope project --mode enforce
```

From this point, any tool call that matches those rules gets blocked before the agent executes it. Claude Code receives a DENY response and stops the action.

**What Prismor catches in a typical session:**

| Tool call | Rule triggered | Default action |
|-----------|---------------|----------------|
| `cat .env` inside a debug task | `secret-access` | block |
| `pip install` of a package with a known IOC | `supply-chain` | block |
| `curl` to an IP address (raw, no hostname) | `egress-raw-ip` | block |
| Shell command following a suspicious file read | `untrusted-content + critical-action tag combo` | block |

See [docs/prismor-runtime.md](docs/prismor-runtime.md) for the full rule schema.

---

## Security Engineer: Onboarding a Team in Observe Mode

**Scenario:** Your team of 12 engineers is already running Claude Code and Cursor. You want visibility into what the agents are doing before you roll out enforcement. The goal is a two-week baseline period before flipping any rules.

**Roll out to all agents, observe only:**

```bash
# Install for Claude Code across all team machines (run on each machine, or script via MDM)
prismor install-hooks --agent all --scope user --mode observe
```

Each engineer's agent sessions now get logged locally. After a week, pull the dashboard:

```bash
prismor dashboard
```

The findings view shows which rules would have fired and how often. Check for patterns:

- Rules firing frequently on a legitimate workflow? Those are false positives — add an allowlist entry in your shared `.prismor/policy.yaml` before enforcing.
- Rules that have never fired in two weeks? Likely low-signal for your specific stack — keep in observe, deprioritize.
- Rules that fire on exactly the patterns you're worried about? Move those to enforce first.

**Shared policy for the team:**

Commit `.prismor/policy.yaml` to your repo. Every engineer picks it up on their next session:

```yaml
# .prismor/policy.yaml
settings:
  default_mode: observe

rules:
  - id: secret-access
    mode: enforce
  - id: destructive-rm-rf
    mode: enforce
  - id: supply-chain
    mode: enforce

allowlists:
  - id: allow-test-env
    rule_ids: ["secret-access"]
    patterns: ["\\.env\\.test$"]
    reason: "Test env has no real secrets"
```

See [docs/policy-layers-and-exemptions.md](docs/policy-layers-and-exemptions.md) for org/project/repo layer precedence.

---

## Platform Team: Governing Production LangChain Pipelines

**Scenario:** Your team runs customer-facing LangChain agents in production. Each agent handles a different customer's data. You need per-user attribution (so audit trails name a customer, not a generic service account) and you want the same policy rules that govern your dev machines to apply in production.

**Install the LangChain adapter:**

```bash
pip install "prismor[langchain]"
```

**Wrap your existing agent with `use_subject`:**

```python
from prismor.frameworks.langchain import use_subject

# Before: runs without attribution
response = agent.invoke({"input": user_query})

# After: each tool call is attributed to the customer
with use_subject(f"user:{customer_id}"):
    response = agent.invoke({"input": user_query})
```

Every tool call the agent makes inside that context block carries the customer's identity through the policy evaluation. If the same customer triggers a block, the finding in the dashboard names them, not the service account.

**Per-user IAM profiles:**

If customer A should only be able to read their own data partition, define that in `.prismor/iam.yaml`:

```yaml
subjects:
  - id: "user:customer-a"
    allowed_tools: [read_file, query_db]
    deny_tools: [write_file, send_email]
    data_scope:
      prefix: "/data/customer-a/"
```

A tool call from `customer-a` that tries to read `/data/customer-b/` gets blocked by the IAM check before the tool executes.

See [docs/frameworks-overview.md](docs/frameworks-overview.md) for the full framework adapter list (14 SDKs).

---

## Security Team: Shadow AI Discovery Across the Org

**Scenario:** You've rolled out Prismor to your known agents. Before the next audit, you want to find any AI agents running on developer machines that don't have Prismor hooks installed — and any MCP servers that weren't approved.

**Run the discovery sweep:**

```bash
prismor discover
```

This scans the local machine for:
- AI coding agents (Claude Code, Cursor, Codex, Windsurf, and others) running without Prismor hooks
- MCP server configs (`.mcp.json` and agent-specific equivalents) pointing to ungoverned servers
- Agent framework packages installed without a corresponding Prismor adapter

Output:

```
Shadow AI Report — 2026-08-13

Coding agents found:    4
  Governed:             3 (Claude Code, Cursor, Codex)
  Ungoverned:           1 (Windsurf — no hooks installed)

MCP servers found:      6
  In allowlist:         4
  Not in allowlist:     2 (github-mcp v1.2.0, notion-mcp v0.9.1)

Framework packages:     2
  With adapter:         1 (langchain — prismor[langchain] installed)
  Without adapter:      1 (crewai — no adapter found)

Coverage:               71%
```

For the ungoverned Windsurf install:

```bash
prismor install-hooks --agent windsurf --scope user --mode observe
```

For the ungoverned MCP servers, scan them first:

```bash
prismor scan --scope user
```

This checks every configured MCP server and installed skill for risky patterns: cleartext `http://` transport, bare-IP endpoints, endpoints that aren't on your egress allowlist, literal tokens in `headers`/`env`, and changes to a server's tool schemas since the last scan. To screen every call the agent makes to a server, put it behind the gateway:

```bash
prismor mcp-gateway install        # this workspace's .mcp.json
prismor mcp-gateway install --all  # every MCP config on the machine
```

`prismor discover --fix` does the same for everything `discover` found, after showing you the plan.

See [docs/skill-scanner.md](docs/skill-scanner.md) and [docs/attestation-bundle.md](docs/attestation-bundle.md#host-discovery).

---

## Compliance Team: Generating an Attestation Bundle

**Scenario:** Your SOC 2 audit is in three weeks. The auditor needs evidence that your AI agent deployments have governance controls in place, mapped to specific control requirements. You need a signed, verifiable artifact that covers OWASP, NIST AI RMF, and SOC 2.

**Generate the bundle:**

```bash
prismor attest --out prismor-attestation-2026-08-13.json
```

This packages:
- Current policy posture (which rules are in observe vs. enforce)
- Agent inventory (which agents are governed, which are ungoverned)
- Host discovery results
- Audit trail anchor (the Ed25519-signed hash chain head from your session logs)
- Framework coverage table (OWASP LLM Top 10, OWASP Agentic AI Top 10, NIST AI RMF, EU AI Act, SOC 2, ISO 42001)

Output: `prismor-attestation-2026-08-13.json` (without `--out` the bundle is printed to stdout). It is signed with your local Ed25519 key when `prismor[signing]` is installed (`pip install 'prismor[signing]'`); without it the bundle is unsigned and `attest verify` fails.

**Give it to the auditor:**

The auditor runs:

```bash
prismor attest verify prismor-attestation-2026-08-13.json
```

If the file was tampered with after generation, verification fails. If it passes, the auditor has a verified snapshot of your agent governance posture at that point in time.

**Reconstruct history before Prismor was installed:**

If your agents were running before Prismor was deployed, use transcript ingest to replay historical session logs through the current policy:

```bash
prismor analyze-history
```

This finds on-disk session transcripts from supported agents and replays them through the live policy engine, so the dashboard is populated and you can show what enforcement would have blocked. Use `--coverage` to identify sessions that ran with no monitoring at all.

See [docs/attestation-bundle.md](docs/attestation-bundle.md) and [docs/transcript-ingest.md](docs/transcript-ingest.md).

---

## Admin: Step-Up Approval for High-Stakes Operations

**Scenario:** Your agents can write to production databases and push code. You want any agent that tries to do those things to pause and surface the action to a human before it runs. The rule should apply across all agents, project-level policies cannot override it.

**Define a non-bypassable step-up rule:**

```yaml
# .prismor/policy.yaml (committed to the repo; overridable by the org control plane)
rules:
  - id: prod-db-write-step-up
    severity: CRITICAL
    category: db_access
    title: Require approval before production database writes
    event_types: [shell, tool]
    patterns: ["psql.*prod", "mysql.*production", "INSERT.*prod_"]
    action: step_up
    mode: enforce
    bypassable: false

  - id: code-push-step-up
    severity: HIGH
    category: vcs
    title: Require approval before pushing to main or release branches
    event_types: [shell]
    patterns: ["git push.*main", "git push.*release"]
    action: step_up
    mode: enforce
    bypassable: false
```

`bypassable: false` means developers cannot create an exception for this rule from the interactive block prompt. The only path to an allow is admin approval from the dashboard or control plane.

**What the developer sees in Claude Code:**

When the agent tries to run `psql prod-db`, Claude Code shows an inline approval request before the command executes. The agent is paused. If the admin approves from the dashboard, the command runs. If they deny or don't respond within the timeout, the command is blocked.

For agents that don't support inline approval (anything other than Claude Code and GitHub Copilot), the call fails closed to block. The agent receives DENY, and the blocked call appears in the dashboard approval queue for an admin to review.

**Pause enforcement without disabling logging:**

During an incident, if you need to let an agent proceed without blocking while you investigate:

```bash
prismor pause          # suspends enforcement only; observe-mode logging continues
prismor pause-hard     # same, but no auto-resume: stays paused until `prismor resume`
```

Both keep the audit trail while removing the block. `prismor pause` auto-resumes after 24h (`--for 2h` to change it), so prefer it for most incidents.

See [docs/prismor-runtime.md](docs/prismor-runtime.md) for the full `action` reference.

---

## Developer: Debugging a Block

**Scenario:** Prismor blocked a tool call you expected to succeed. You need to understand which rule fired, why, and whether to fix the rule or fix the code.

**Check recent blocks:**

```bash
prismor status
```

Or open the dashboard:

```bash
prismor dashboard
```

The findings view shows the tool call, the rule that matched, the pattern that triggered it, and the full command input.

**Check the health of every Prismor subsystem:**

```bash
prismor doctor
```

This checks hooks, policy signature, enrollment status, telemetry sink, and the session store. If something is misconfigured, `doctor` names it and gives you the fix command.

**Add an allowlist entry for a false positive:**

If the block was a false positive — your build process runs a command that looks like a known-bad pattern but is legitimate for your project — add it to the allowlist:

```yaml
# .prismor/policy.yaml
allowlists:
  - id: allow-build-cleanup
    rule_ids: ["destructive-rm-rf"]
    patterns: ["rm -rf ./dist", "rm -rf ./build"]
    reason: "Standard build artifact cleanup"
```

The allowlist entry is scoped to this project. It does not affect other projects or other rules.

**Inspect the session forensics:**

```bash
prismor session <session-id>
prismor rca <session-id>
```

`session` shows every tool call in the session as a sequence, with inputs, policy verdicts and timestamps; `rca` adds the first failure, retry loops and reverted edits. `prismor trail show --last 50` renders the most recent signed audit-trail records. Use it to reconstruct what the agent was doing when the block fired.

```bash
prismor trail verify
```

Verifies the hash chain on the session log. If the log was modified after the fact, this fails.

---

## Multi-Agent Pipeline: Per-User Attribution with IAM

**Scenario:** You're building a multi-tenant agentic system where several sub-agents collaborate on tasks: one agent retrieves customer data, another transforms it, a third calls an external API. Each sub-agent should run under the identity of the customer whose task it's processing, with permissions scoped to that customer's data.

**Assign identities to each agent:**

```yaml
# .prismor/iam.yaml
subjects:
  - id: "agent:retriever"
    allowed_tools: [read_file, query_db]
    data_scope:
      prefix: "/data/{customer_id}/"

  - id: "agent:transformer"
    allowed_tools: [read_file, write_file]
    data_scope:
      prefix: "/data/{customer_id}/"

  - id: "agent:api-caller"
    allowed_tools: [http_get, http_post]
    deny_patterns:
      - "https://(?!api\\.approved-partner\\.com).*"
```

**Wrap each sub-agent with its identity:**

```python
from prismor.frameworks.openai_agents import use_subject

async def run_pipeline(customer_id: str, task: str):
    with use_subject(f"agent:retriever", context={"customer_id": customer_id}):
        data = await retriever_agent.run(task)

    with use_subject(f"agent:transformer", context={"customer_id": customer_id}):
        result = await transformer_agent.run(data)

    with use_subject(f"agent:api-caller"):
        await api_agent.run(result)
```

Each agent's tool calls are evaluated against its declared profile. `agent:retriever` cannot call `http_post`. `agent:api-caller` cannot write files. A cross-agent pivot — where a compromised retriever agent tries to call the external API — hits the `allow_tools` check and gets blocked.

Every finding in the dashboard names the specific agent identity that triggered it, not the service account the process runs under.

See [docs/iam.md](docs/iam.md) for the full identity schema and session management options.

---

## Further Reading

- [Prismor Runtime](docs/prismor-runtime.md) — policy engine, rule schema, CLI reference
- [Framework Adapters](docs/frameworks-overview.md) — production framework integration (14 SDKs)
- [MCP Gateway](docs/mcp-gateway.md) — protocol-level enforcement for MCP tool servers
- [Supply Chain](docs/supply-chain.md) — package scoring, IOC matching, lockdown hardening
- [Attestation Bundle](docs/attestation-bundle.md) — signed compliance artifacts and host discovery
- [Layered Policy](docs/policy-layers-and-exemptions.md) — org / project / repo precedence and non-overridable rules
- [Dashboard](docs/dashboard.md) — session forensics, findings, token breakdown
