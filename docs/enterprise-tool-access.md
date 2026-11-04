# Enterprise tool access inventory

Managed Prismor runtimes register tool capabilities with the control plane at
the existing device-authenticated endpoint:

```http
POST /api/agents/register
Authorization: Bearer <device key>
Content-Type: application/json

{
  "agents": [{
    "framework": "openai-agents",
    "name": "checkout-bot",
    "sessionId": "session-123",
    "tools": [
      {"name": "read_order", "source": "declared"},
      {"name": "mcp__github__create_issue", "source": "declared"}
    ]
  }]
}
```

`source` is `declared` for an SDK roster, `scoped` for a synthesized session
allowlist, or `observed` for a protected tool call. Coding-agent hooks report
the current tool plus every exact tool in the active session scope. SDK
adapters can put their complete roster in `metadata.available_tools` on an
evaluation event. HTTP SDK clients send the same list as top-level
`available_tools` to `POST /v1/evaluate`.

Admins read the effective inventory with:

```http
GET /api/admin/tool-capabilities?orgId=<org>&agentId=<agent>
GET /api/admin/tool-capabilities?orgId=<org>&agentId=<agent>&sessionId=<session>
```

Each result identifies internal versus MCP tools, the MCP server name,
discovery sources, sessions, and whether signed policy currently allows or
denies delivery. It also carries the event type the tool's latest call was
judged as (`eventType`) and any admin correction (`classifiedAs`). See
[docs/event-types.md](event-types.md).

Grant and revoke use the existing policy endpoint:

```http
POST /api/admin/tool-policy
Content-Type: application/json

{"orgId":"<org>","tool":"mcp__github__create_issue","action":"deny","scope":"agent","scopeId":"checkout-bot"}
```

Use `action: "allow"` with the same tool and scope to lift that deny. Scope may
be `org`, `agent`, `device`, or `session`. The change is included in signed
policy and enforced on-device before the MCP or internal tool receives a call.

`action: "allow"` is more than lifting a deny: it ships as an explicit org
override that also beats a LOCAL restriction (a developer's
`.prismor/agents.yaml` deny, or a session's synthesized scope) for that same
tool — org policy is the most-preferred authority for tool access. See
[docs/tool-access-precedence.md](tool-access-precedence.md) for the full
precedence order and why it doesn't touch the agent kill switch or a
different org-level deny.
