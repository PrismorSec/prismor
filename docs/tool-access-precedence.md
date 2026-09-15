# Tool access precedence

*Which layer wins when the org dashboard, a local `.prismor/agents.yaml`, and
a session's synthesized scope disagree about whether an agent may call a
specific tool. Companion to [docs/enterprise-tool-access.md](enterprise-tool-access.md)
and [docs/policy-layers-and-exemptions.md](policy-layers-and-exemptions.md).*

---

## The rule

**Org policy is authoritative.** An admin's decision on `prismor.dev` (Admin →
Connections → an agent's Tool access panel) always wins over a developer's
local `.prismor/agents.yaml` deny list and over a session's synthesized scope
(`prismor scope edit`, the scoped-agent allowlist, the dashboard's MCP Servers
toggles):

```
  kill switch  ── agent paused (local OR org) ── ALWAYS blocks, no override
   │
  org deny     ── admin denied this tool          ── ALWAYS blocks
   │
  org allow    ── admin explicitly allowed this tool ── overrides local deny_tools
   │                                                     AND session scope for
   │                                                     this tool
  local        ── .prismor/agents.yaml deny_tools, session-scoped allowlist
```

- The **kill switch** (an agent paused, either locally or by the org) is the
  one condition nothing can override. It blocks *every* tool for that agent,
  not just one.
- An **org deny** for a tool always blocks, regardless of what a local file
  says.
- An **org allow** is a real override, not just "no deny exists." Toggling a
  tool to "Allowed" on the dashboard writes a signed rule that lifts a local
  `.prismor/agents.yaml` deny and a session's scoped-agent restriction for
  that exact tool. It does **not** lift a *different* org-level deny (that's
  a separate admin decision) and it never resurrects a killed-switched agent.
- **Local restrictions** (the per-agent deny list, a synthesized session
  scope) are the default floor for a single machine or session when the org
  hasn't spoken. They no longer silently out-rank the org once an admin makes
  an explicit call.

This only applies to *tool access* (allow/deny a specific tool tag). The
non-overridable **security floor** — destructive commands, secret
exfiltration, RCE, privilege escalation, DoS, tool-category crossover — is a
different, always-on layer that no admin action can weaken; see
[docs/policy-layers-and-exemptions.md](policy-layers-and-exemptions.md).

## Why this changed

Earlier, the dashboard's "Allowed" badge meant only *"no org-level deny
exists for this tool"* — it said nothing about local state. An admin could
toggle a tool to "Allowed" and watch the agent still get blocked, because a
developer's local `.prismor/agents.yaml` deny or a stale session scope was
still in effect and nothing could lift it remotely. That made the org console
look broken and put the developer's local toggle in charge of a decision that
should belong to the org.

## How it's enforced (runtime)

Both deny and allow rows for a tool ship in the same signed list
(`settings.tool_denies`, entries disambiguated by `action: "deny" | "allow"`)
so they arrive and expire together — see `resolveToolDenies` in
`prismor-web/lib/tool-policy.ts`.

On-device, `prismor/runtime/runtime.py::evaluate_tool_call`:

1. Evaluates the local per-agent kill switch, the local `deny_tools` list, the
   session's scoped-agent rules, and the org's own tool denies — same as
   before.
2. Then applies any matching **org tool-allow** entry: it drops findings with
   `ruleId in ("agent-tool-deny", "scoped-agent")` for the tool the current
   event is about. It does not touch the kill switch (`ruleId
   "agent-disabled"`), a different `ruleId "org-tool-deny"` finding, or a
   scoped-agent finding about a *different* concern (path or network access —
   only the tool-name check is lifted).

Set from the console:

```http
POST /api/admin/tool-policy
Content-Type: application/json

{"orgId":"<org>","tool":"mcp__github__create_issue","action":"allow","scope":"agent","scopeId":"checkout-bot"}
```

`scope` may be `org`, `agent`, `device`, or `session` — same scoping as tool
denies. Tests: `prismor/tests/test_org_tool_denies.py`
(`test_org_allow_overrides_local_agent_deny`,
`test_org_allow_overrides_session_scoped_deny`,
`test_org_allow_does_not_lift_kill_switch`,
`test_org_allow_does_not_lift_scoped_network_denial`).
