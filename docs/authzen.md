# AuthZEN

The eval-server answers the OpenID **AuthZEN Authorization API 1.0**, so an API
gateway, an identity platform or a SaaS app that already speaks AuthZEN can ask
Prismor for a decision with no Prismor adapter.

```bash
prismor eval-server --port 7071 --api-key "$KEY"   # add --identity-* to verify end users
```

| Endpoint | |
|---|---|
| `POST /access/v1/evaluation` | one decision |
| `POST /access/v1/evaluations` | a batch, with top-level defaults and `options.evaluations_semantic` (`execute_all`, `deny_on_first_deny`, `permit_on_first_permit`) |
| `GET /.well-known/authzen-configuration` | PDP metadata |

`X-Request-ID` is echoed back. A denial is `200` with `"decision": false`; a
malformed request is `400`; a missing or wrong API key is `401`.

## How a request maps to a tool call

| AuthZEN | Prismor |
|---|---|
| `action.name` | the tool (`tool.name`, matched by `fields: [tool_name]` rules) |
| `action.properties` | the tool's arguments (`args.*`) |
| `resource.type` / `id` / `properties` | `resource.kind` / `id` / `attr.*` |
| `subject.type` + `id` | the asserted user, `"<type>:<id>"` |
| `context.event_type`, `agent_name`, `session_id`, `explain` | optional |

```bash
curl -s localhost:7071/access/v1/evaluation \
  -H "Authorization: Bearer $KEY" \
  -H "X-Prismor-Identity: Bearer $USER_JWT" \
  -d '{"subject": {"type": "user", "id": "bob"},
       "action": {"name": "refund_order", "properties": {"amount": 900}},
       "resource": {"type": "order", "id": "o-1", "properties": {"owner": "alice"}}}'
```

```json
{"decision": false,
 "context": {"verdict": "block", "rule_id": "refund-cap",
             "reason": "[HIGH] Refunds of 500 or more need finance", "subject": {"user_id": "bob", "source": "jwt", "roles": ["support"]}}}
```

## Roles never come from `subject.properties`

AuthZEN lets a caller describe the subject however it likes. Prismor does not
read `subject.properties` as principal attributes: that would let any caller
grant itself `admin`. Roles and claims come only from the end user's token in
`X-Prismor-Identity` ([identity verification](identity-verification.md)); when
a valid token is present it also replaces the asserted `subject.id`.

The policy that judges an AuthZEN request is always the server's own: unlike
`/v1/evaluate`, the request cannot name a workspace.

`"context": {"explain": true}` returns the [decision trace](attribute-conditions.md#explaining-a-decision)
under `context.explain`.
