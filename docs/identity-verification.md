# Verified end-user identity

A deployed agent serves many people, and Prismor attributes each tool call to
the end user it acts for. By default that user is **asserted**: the caller
says `subject: "user:alice"` and Prismor believes it. That is enough for
attribution and dashboards. It is not enough for authorization, because any
caller can claim to be anyone.

With identity verification on, the caller sends the user's token from your
identity provider. Prismor verifies it and takes the user, team and roles from
its claims. Rules can then trust `principal.*` (see
[attribute conditions](attribute-conditions.md)).

Prismor does not log anyone in. Okta, Auth0, Entra ID, Cognito, WorkOS, Clerk or
any OIDC provider issues the token. Prismor checks it on every tool call.

```
user ──login──▶ IdP ──JWT──▶ your app ──tool call + JWT──▶ Prismor ──▶ allow / block
                                                            │
                                         verify signature (JWKS), iss, aud, exp
                                         principal = {id, team, roles} from claims
```

## Configure

**From the console (managed agents).** On the SSO page, under *End-user
identity for agents*, set the issuer, audience, JWKS URL (or let it be
discovered from the issuer) and claim mapping, choose a mode, and use *Test a
token* to see the principal a real token maps to. The config ships to devices
inside the signed policy as `settings.identity`. A policy can override only the
mode (`settings.identity.mode` in its YAML), so you can require it in the
support bot's policy and leave it on observe everywhere else.

**From the eval-server (no console).**

```bash
pip install 'prismor[identity]'
prismor eval-server \
  --identity-issuer https://acme.okta.com/oauth2/default \
  --identity-audience api://support-bot \
  --identity-jwks https://acme.okta.com/oauth2/default/v1/keys \
  --identity-roles-claim groups \
  --identity-mode require
```

A signed org policy, when present, overrides these flags.

`settings.identity` is **ignored in project and local policy files**. Whoever
names the issuer decides who can mint users and roles, so only the signed org
policy, or the operator starting the eval-server, may set it.

| Key | | |
|---|---|---|
| `mode` | `off` · `observe` · `require` | default `off` |
| `issuer` | required | must equal the token's `iss` |
| `audience` | required, string or list | the token's `aud` must contain one |
| `jwks_uri` | required | the IdP's signing keys; cached 10 minutes |
| `user_claim` | default `sub` | becomes `principal.id` |
| `team_claim` | optional | becomes `principal.team` |
| `roles_claim` | optional | list, or space/comma-separated string → `principal.roles` |

Accepted algorithms are RS*, PS*, ES* and EdDSA. `alg: none` and HMAC tokens
are rejected, which closes the "public key used as an HMAC secret" attack.
`exp`, `iss` and `aud` are required, with 60 seconds of clock leeway.

## Send the token

**eval-server / any HTTP client.** Use the `X-Prismor-Identity` header.
`Authorization` stays reserved for the eval-server's own API key.

```bash
curl -s localhost:7071/v1/evaluate \
  -H "X-Prismor-Identity: Bearer $USER_JWT" \
  -d '{"tool_name": "refund_order", "arguments": {"amount": 900}}'
```

**Python adapters.**

```python
from prismor.openai import use_subject

with use_subject(token=user_jwt):
    Runner.run_sync(agent, prompt)
```

Or call `evaluate_tool_call(..., identity_token=user_jwt)` directly.

**Vercel AI SDK.**

```ts
const tools = prismorTools({ refund_order }, { identityToken: userJwt });
```

Pass the user's own token, the one your app received from the IdP for this
request. Never pass a service account token: every call would then run as that
service account.

## Modes, and calls without a token

| | token valid | token invalid | no token |
|---|---|---|---|
| `off` | ignored | ignored | asserted subject, as before |
| `observe` | verified subject | asserted subject, event tagged `identity: invalid: …` | asserted subject, tagged `identity: missing` |
| `require` | verified subject | **blocked** (`identity-unverified`) | **blocked**, except a coding agent on an enrolled device |

`principal.verified` tells rules which case they are in. It is true for a
verified token. It is also true for an enrolled device acting through its own
coding-agent hook (Claude Code, Codex, Cursor), because enrollment already
proves that machine's identity, so turning on `require` never breaks developers'
agents. An SDK adapter or eval-server running on an enrolled host does **not**
inherit the device's identity: it serves other people, and needs their token.

**Roles never come from an asserted subject.** `subject: "user:carol"` names a
user but carries no roles or claims. A rule like
`'finance' not in principal.roles` therefore stays a deny for every unverified
caller, even in `off` mode.

The `identity-unverified` block is a control-plane decision: it blocks even in
observe mode, and rule exemptions do not apply to it.

### Rolling out

1. Turn on `observe`. Nothing is blocked.
2. In the console, open recent events: the end user shows as "verified token" or "not verified", so you can find the agents and callers
   that do not send a token yet. Fix them.
3. Switch the agents that serve end users to `require` through their policy
   binding.

## User exemptions

A rule exemption scoped to a user (granted from the console's event view) used
to match any call whose asserted subject named that user. With identity
verification in `observe` or `require`, a `user` exemption applies only to a
**verified** subject, so `subject: "user:alice"` no longer unlocks Alice's
exemptions for anyone else.

## Threat model

Identity verification covers:
- a caller impersonating another user or claiming a role,
- forged, expired, replayed-after-expiry or wrong-audience tokens,
- algorithm confusion (`none`, HMAC-with-public-key),
- a repository's policy file pointing Prismor at an attacker's issuer.

It does not cover:
- a compromised application that holds a real user's valid token (that is the
  user, as far as any verifier can tell),
- token revocation before `exp` (keep token lifetimes short),
- an unhooked agent that never calls Prismor (see
  [governance surfaces](governance-surfaces.md)).

## Telemetry

A verified subject reaches telemetry with `source: "jwt"` and its roles. The
event metadata carries `identity: verified | device | missing | invalid: <reason>`.
The token itself is never stored or sent anywhere.
