# Prismor as a service: the governance surfaces that front an agent you cannot
# hook -- the LLM proxy, and the evaluation server non-Python SDKs call.
#
# Published on every release as ghcr.io/prismorsec/prismor. To build it
# yourself, build from the repo root so the source tree is in context:
#   docker build -f packaging/docker/Dockerfile -t prismor .

# The source tree only ever exists in this stage. Copying it into the image
# and deleting it in a later step would not remove it: the COPY layer ships
# regardless, with whatever else was in the checkout. Only the wheel crosses.
FROM python:3.12-slim AS build
WORKDIR /src
COPY . .
RUN pip wheel --no-cache-dir --no-deps --wheel-dir /dist .

FROM python:3.12-slim

# curl is here for the container HEALTHCHECK below, nothing else.
RUN apt-get update \
 && apt-get install -y --no-install-recommends curl \
 && rm -rf /var/lib/apt/lists/*

RUN --mount=from=build,source=/dist,target=/dist \
    pip install --no-cache-dir /dist/*.whl

# $PRISMOR_HOME holds the device identity, the policy and the session logs. It
# is a volume in compose: without one, every restart is a new unenrolled device
# and the audit trail starts over. Unbuffered, or the surfaces' startup lines --
# including the warnings -- never reach `docker logs`. An image is upgraded by
# pulling a new tag, so the PyPI update check is only noise here.
ENV PRISMOR_HOME=/var/lib/prismor \
    PRISMOR_PROXY_PORT=7080 \
    PRISMOR_PROXY_MODE=enforce \
    PYTHONUNBUFFERED=1 \
    PRISMOR_NO_UPDATE_CHECK=1
RUN useradd --create-home --uid 10001 prismor \
 && mkdir -p "$PRISMOR_HOME" \
 && chown -R prismor:prismor "$PRISMOR_HOME"
USER prismor
WORKDIR /var/lib/prismor

EXPOSE 7080 7071
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s \
  CMD ["/usr/local/bin/prismor-entrypoint", "healthcheck"]

COPY --chown=prismor:prismor packaging/docker/entrypoint.sh /usr/local/bin/prismor-entrypoint
ENTRYPOINT ["/usr/local/bin/prismor-entrypoint"]
CMD ["proxy"]
