# Prismor as a service: the governance surfaces that front an agent you cannot
# hook -- the LLM proxy, and the evaluation server non-Python SDKs call.
#
# Build from the repo root so the source tree is in context:
#   docker build -f packaging/docker/Dockerfile -t prismor .
FROM python:3.12-slim

# curl is here for the container HEALTHCHECK below, nothing else.
RUN apt-get update \
 && apt-get install -y --no-install-recommends curl \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . /src
RUN pip install --no-cache-dir . \
 && rm -rf /src

# $PRISMOR_HOME holds the device identity, the policy and the session logs. It
# is a volume in compose: without one, every restart is a new unenrolled device
# and the audit trail starts over.
ENV PRISMOR_HOME=/var/lib/prismor \
    PRISMOR_PROXY_PORT=7080 \
    PRISMOR_PROXY_MODE=enforce
RUN useradd --create-home --uid 10001 prismor \
 && mkdir -p "$PRISMOR_HOME" \
 && chown -R prismor:prismor "$PRISMOR_HOME"
USER prismor
WORKDIR /var/lib/prismor

EXPOSE 7080
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s \
  CMD curl -fsS "http://127.0.0.1:${PRISMOR_PROXY_PORT}/health" || exit 1

COPY --chown=prismor:prismor packaging/docker/entrypoint.sh /usr/local/bin/prismor-entrypoint
ENTRYPOINT ["/usr/local/bin/prismor-entrypoint"]
CMD ["proxy"]
