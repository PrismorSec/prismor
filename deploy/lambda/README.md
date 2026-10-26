# Prismor-hosted evaluation on AWS Lambda

One Lambda function per org runs the eval-server (`prismor.runtime.lambda_handler`)
behind a Function URL. The org's agents point at it with `PRISMOR_EVAL_URL` and
`PRISMOR_EVAL_KEY` (Python) or `evalUrl` / `apiKey` (TypeScript), so they need
no Python sidecar. The function holds the org's agent key, so it pulls the org's
signed policy and reports every call to the org. See
[docs/hosted-evaluation.md](../../docs/hosted-evaluation.md) for the user side.

## Build and push the image

From the repo root:

```bash
AWS_REGION=us-east-1
ACCOUNT=$(aws sts get-caller-identity --query Account --output text)
REPO=$ACCOUNT.dkr.ecr.$AWS_REGION.amazonaws.com/prismor-eval

aws ecr create-repository --repository-name prismor-eval >/dev/null 2>&1 || true
aws ecr get-login-password | docker login --username AWS --password-stdin "${REPO%/*}"
# Lambda rejects OCI manifests with build attestations ("image manifest ... media
# type ... is not supported"), which current Docker pushes by default.
docker buildx build --platform linux/amd64 --provenance=false --sbom=false \
  -f deploy/lambda/Dockerfile -t "$REPO:latest" --push .
```

## Execution role (once)

```bash
aws iam create-role --role-name prismor-eval-lambda \
  --assume-role-policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}'
aws iam attach-role-policy --role-name prismor-eval-lambda \
  --policy-arn arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole
```

The function needs nothing else from AWS: it talks to prismor.dev over HTTPS.

## Provision an org

```bash
IMAGE_URI=$REPO:latest \
ROLE_ARN=arn:aws:iam::$ACCOUNT:role/prismor-eval-lambda \
PRISMOR_AGENT_KEY=prism_agent_... \
  ./deploy/lambda/provision.sh acme
```

It creates `prismor-eval-acme` (1024 MB, 15 s timeout) with a Function URL
(`auth-type NONE`, with both `lambda:InvokeFunctionUrl` and a URL-only
`lambda:InvokeFunction` permission, which AWS requires for a public URL; the bearer key is enforced in code, and a function without
`PRISMOR_EVAL_KEY` refuses every evaluation) and prints `PRISMOR_EVAL_URL` and a
new `PRISMOR_EVAL_KEY` once. Hand both to the org. Rerunning it updates the code
and rotates the key.

Sizing: 1024 MB gives the policy engine enough CPU that a warm call is fast.
Lambda bills per request and per GB-second, and an idle function costs nothing.
Set provisioned concurrency only for an org that cannot accept a cold start.

## Check it

```bash
curl -s "$PRISMOR_EVAL_URL/health"                       # 200
curl -s -o /dev/null -w '%{http_code}\n' -X POST "$PRISMOR_EVAL_URL/v1/evaluate" \
  -H 'content-type: application/json' -d '{"tool_name":"run_shell","arguments":{"command":"ls"},"event_type":"shell"}'   # 401 without the key
```

A 403 on every path, `/health` included, means the `lambda:InvokeFunction`
permission is missing (rerun `provision.sh`).

## Permissions for whoever deploys

- `ecr:CreateRepository`, `ecr:GetAuthorizationToken`, `ecr:BatchCheckLayerAvailability`,
  `ecr:InitiateLayerUpload`, `ecr:UploadLayerPart`, `ecr:CompleteLayerUpload`, `ecr:PutImage`
- `lambda:CreateFunction`, `lambda:UpdateFunctionCode`, `lambda:UpdateFunctionConfiguration`,
  `lambda:GetFunction`, `lambda:CreateFunctionUrlConfig`, `lambda:GetFunctionUrlConfig`,
  `lambda:AddPermission`, `lambda:GetPolicy`
- `iam:PassRole` on the execution role (and `iam:CreateRole` / `iam:AttachRolePolicy` once)
- `logs:*` is not needed by the deployer; the execution role writes the function's logs.

## What runs where

`PRISMOR_HOME` and the workspace live in `/tmp`, Lambda's only writable
directory, so session memory (cross-call checks) lasts as long as a warm instance.
Spooled telemetry is uploaded before each response returns, because a frozen
instance can be reclaimed at any time.

---

# Hosted MCP endpoints on Lambda

The same pattern serves hosted MCP endpoints ("Spin up MCP instance" in the
console's MCP Hub): **one function per org**, `prismor-mcp-<orgId>`, built from
`deploy/lambda/Dockerfile.mcp` and running `prismor.runtime.lambda_mcp_handler`.
It replaces the Cloudflare edge in `PrismorSec/prismor-fleet`.

```
agent ── POST <function URL>/mcp/<key> ──▶ lambda_mcp_handler
                                             │ resolve key: GET <console>/api/mcp/fleet/resolve
                                             ▼
                                  prismor mcp-gateway (one process per key, warm)
                                             │ policy, result screening, telemetry,
                                             ▼ signed policy pull, kill switch
                                  the endpoint's registry servers (remote, npx, uvx)
```

- **Any key of the org works** on its function: an endpoint key or a person's
  grant on it. The control plane decides, so revoking a key or an endpoint takes
  effect within `HOSTED_MCP_RESOLVE_TTL` (30s). A key from another org is refused
  (`PRISMOR_ORG_ID`), and a key never resolved fails closed if the control plane
  is down.
- **Servers** come from the registry. Remote (HTTPS) servers are called from
  the function; `npx` / `uvx` servers run inside it (Node 22, uv and git are in the
  image). Browser servers (Playwright, Puppeteer) are skipped: run those in a
  local `prismor mcp-gateway`.
- **State**: each key's runtime state (session ledger, policy cache) lives in
  `/tmp`. With `HOSTED_MCP_STATE_BUCKET` set it is snapshotted to S3 after each
  request and restored by the next instance, so a session survives cold starts. A
  workspace `policy.yaml` is never saved or restored: endpoints follow only the
  org's signed policy.

## Build and release

The release workflow's `lambda-images` job pushes `prismor-eval:<version>` and
`prismor-mcp:<version>` to ECR on every `v*` tag, after an emulator smoke test,
once `vars.AWS_LAMBDA_ROLE_ARN`, `vars.AWS_REGION` and `vars.ECR_REGISTRY` are
set. Point the console at an exact version, never `:latest`:

```
HOSTED_MCP_IMAGE_URI=<account>.dkr.ecr.<region>.amazonaws.com/prismor-mcp:1.68.0
```

By hand: `docker buildx build --platform linux/amd64 --provenance=false --sbom=false -f deploy/lambda/Dockerfile.mcp -t "$REPO:$VERSION" --push .`

## Function settings (the console sets these when it provisions)

| | |
|---|---|
| Memory / ephemeral storage | 2048 MB / 2048 MB (`npx` installs land in `/tmp`) |
| Timeout | 300 s (one MCP call; the handler stops waiting 3 s before the deadline) |
| Function URL | `AuthType: NONE`. The key in the path is the credential |
| Env | `PRISMOR_WEB_URL`, `PRISMOR_ORG_ID`, optional `HOSTED_MCP_STATE_BUCKET` / `HOSTED_MCP_STATE_PREFIX` |
| Execution role | `AWSLambdaBasicExecutionRole`, plus `s3:GetObject` / `s3:PutObject` on `<bucket>/mcp-state/*` if state is on |

## Cold starts and concurrency

A cold instance starts the key's gateway on the first request (about 1 s), and
its `npx` / `uvx` servers on the first `tools/list` (about 10 s while packages
download). A warm instance reuses all of it (`tools/list` about 0.4 s). MCP clients
send requests concurrently (Claude Code opens a stream and posts at once), and
Lambda answers concurrent requests from separate instances, so a busy org can
pay the cold start more than once. Use provisioned concurrency on that org's
function if it matters.

## Checking a function

```bash
curl -s "$URL/health"                                         # {"ok": true, "version": "1.68.0"}
curl -s -X POST "$URL/mcp/not-a-key" -d '{}'                  # 403 invalid or revoked instance key
```

## Moving off the Cloudflare edge (mcp.prismor.dev)

Existing endpoint URLs point at `https://mcp.prismor.dev/mcp/<key>` and their
keys were shown only once, so they can't simply be reissued.

1. Deploy with `HOSTED_MCP_IMAGE_URI` set. New endpoints and grants get
   `<org function URL>/mcp/<key>`. Old URLs keep working on the Cloudflare edge.
2. Make old URLs reach Lambda without changing them: in the Cloudflare Worker,
   resolve the key (`/api/mcp/fleet/resolve` returns `org_id`) and proxy
   `POST /mcp/<key>` to that org's function URL, instead of starting a container.
3. When the Worker has served nothing but proxying for a while, point
   `mcp.prismor.dev` at the proxy only, delete the Durable Object/container
   deployment, and archive `PrismorSec/prismor-fleet`.
