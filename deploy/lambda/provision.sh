#!/usr/bin/env bash
# Create (or update) one org's hosted-evaluation function and print its URL.
#
#   PRISMOR_AGENT_KEY=prism_agent_... ./deploy/lambda/provision.sh acme
#
# Needs: IMAGE_URI (the pushed image), ROLE_ARN (a basic Lambda execution role),
# and AWS credentials with the permissions listed in deploy/lambda/README.md.
# Prints the function URL and a freshly generated eval key, once; give both to
# the org (PRISMOR_EVAL_URL / PRISMOR_EVAL_KEY) and keep the key nowhere else.
set -euo pipefail
ORG="${1:?usage: provision.sh <org-slug>}"
: "${PRISMOR_AGENT_KEY:?set PRISMOR_AGENT_KEY to the agent key of the org}"
: "${IMAGE_URI:?set IMAGE_URI to the pushed prismor-eval image}"
: "${ROLE_ARN:?set ROLE_ARN to a Lambda execution role}"
FN="prismor-eval-${ORG}"
EVAL_KEY="$(openssl rand -hex 32)"
ENV="Variables={PRISMOR_AGENT_KEY=${PRISMOR_AGENT_KEY},PRISMOR_EVAL_KEY=${EVAL_KEY}}"

if aws lambda get-function --function-name "$FN" >/dev/null 2>&1; then
  aws lambda update-function-code --function-name "$FN" --image-uri "$IMAGE_URI" >/dev/null
  aws lambda wait function-updated --function-name "$FN"
  aws lambda update-function-configuration --function-name "$FN" --environment "$ENV" >/dev/null
else
  aws lambda create-function --function-name "$FN" --package-type Image --code "ImageUri=$IMAGE_URI" \
    --role "$ROLE_ARN" --memory-size 1024 --timeout 15 --architectures x86_64 \
    --environment "$ENV" >/dev/null
  aws lambda wait function-active --function-name "$FN"
  aws lambda create-function-url-config --function-name "$FN" --auth-type NONE >/dev/null
  aws lambda add-permission --function-name "$FN" --statement-id public-url \
    --action lambda:InvokeFunctionUrl --principal '*' --function-url-auth-type NONE >/dev/null
fi
# A public Function URL also needs lambda:InvokeFunction, limited to calls that
# come through the URL. Without it every request, /health included, gets a 403
# from AWS before reaching the function. Idempotent: skipped if already granted.
if ! aws lambda get-policy --function-name "$FN" --query Policy --output text 2>/dev/null | grep -q public-url-invoke; then
  aws lambda add-permission --function-name "$FN" --statement-id public-url-invoke \
    --action lambda:InvokeFunction --principal '*' --invoked-via-function-url >/dev/null
fi
URL="$(aws lambda get-function-url-config --function-name "$FN" --query FunctionUrl --output text)"
echo "PRISMOR_EVAL_URL=${URL%/}"
echo "PRISMOR_EVAL_KEY=${EVAL_KEY}"
