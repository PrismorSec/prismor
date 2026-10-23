# Prismor-hosted evaluation on AWS Lambda (one function per org).
# Build from the repo root:  docker build -f deploy/lambda/Dockerfile -t prismor-eval .
FROM public.ecr.aws/lambda/python:3.12

COPY . /tmp/src
RUN pip install --no-cache-dir /tmp/src && rm -rf /tmp/src

# The org's identity and the bearer key come from the function's environment
# (PRISMOR_AGENT_KEY, PRISMOR_EVAL_KEY); see deploy/lambda/README.md.
CMD ["prismor.runtime.lambda_handler.handler"]
