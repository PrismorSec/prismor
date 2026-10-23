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
docker build --platform linux/amd64 -f deploy/lambda/Dockerfile -t "$REPO:latest" .
docker push "$REPO:latest"
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
(`auth-type NONE`; the bearer key is enforced in code, and a function without
`PRISMOR_EVAL_KEY` refuses every evaluation) and prints `PRISMOR_EVAL_URL` and a
new `PRISMOR_EVAL_KEY` once. Hand both to the org. Rerunning it updates the code
and rotates the key.

Sizing: 1024 MB gives the policy engine enough CPU that a warm call is fast.
Lambda bills per request and per GB-second, and an idle function costs nothing.
Set provisioned concurrency only for an org that cannot accept a cold start.

## Permissions for whoever deploys

- `ecr:CreateRepository`, `ecr:GetAuthorizationToken`, `ecr:BatchCheckLayerAvailability`,
  `ecr:InitiateLayerUpload`, `ecr:UploadLayerPart`, `ecr:CompleteLayerUpload`, `ecr:PutImage`
- `lambda:CreateFunction`, `lambda:UpdateFunctionCode`, `lambda:UpdateFunctionConfiguration`,
  `lambda:GetFunction`, `lambda:CreateFunctionUrlConfig`, `lambda:GetFunctionUrlConfig`,
  `lambda:AddPermission`
- `iam:PassRole` on the execution role (and `iam:CreateRole` / `iam:AttachRolePolicy` once)
- `logs:*` is not needed by the deployer; the execution role writes the function's logs.

## What runs where

`PRISMOR_HOME` and the workspace live in `/tmp`, Lambda's only writable
directory, so session memory (cross-call checks) lasts as long as a warm instance.
Spooled telemetry is uploaded before each response returns, because a frozen
instance can be reclaimed at any time.
