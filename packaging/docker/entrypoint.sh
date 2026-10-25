#!/bin/sh
# Enroll (once, if a token is present) and start the requested surface.
#
# Enrollment is what puts this container's sessions in the console. It is
# deliberately not fatal: a proxy that refuses to start because the control
# plane is unreachable would take the agent down with it, and local policy
# still applies unenrolled.
set -eu

# HEALTHCHECK runs this beside PID 1 without its arguments or env, so the port
# is read from the surface's own command line: probing a fixed port marks
# eval-server unhealthy forever. A one-shot command has no port and no health.
if [ "${1:-}" = healthcheck ]; then
  port=$(tr '\0' '\n' < /proc/1/cmdline | sed -n '/^--port$/{n;p;q;}')
  [ -z "$port" ] && exit 0
  exec curl -fsS -o /dev/null "http://127.0.0.1:${port}/health"
fi

if [ -n "${PRISMOR_ENROLL_TOKEN:-}" ] && [ ! -f "${PRISMOR_HOME}/identity.json" ]; then
  echo "[prismor] enrolling this container..."
  prismor enroll "${PRISMOR_ENROLL_TOKEN}" \
    ${PRISMOR_DEVICE_LABEL:+--label "${PRISMOR_DEVICE_LABEL}"} \
    || echo "[prismor] enrollment failed - continuing with local policy only"
fi

# A container has no git remote to claim, so without this the workspace reads
# as personal and nothing reaches the org. See docs/headless.
export PRISMOR_WORKSPACE_SCOPE="${PRISMOR_WORKSPACE_SCOPE:-managed}"

case "${1:-proxy}" in
  proxy)
    shift 2>/dev/null || true
    exec prismor proxy \
      --host 0.0.0.0 \
      --port "${PRISMOR_PROXY_PORT:-7080}" \
      --mode "${PRISMOR_PROXY_MODE:-enforce}" \
      --workspace "${PRISMOR_HOME}" \
      ${PRISMOR_AGENT_NAME:+--agent-name "${PRISMOR_AGENT_NAME}"} \
      "$@"
    ;;
  eval-server)
    shift
    # In a container it always binds 0.0.0.0, where the CLI only warns about a
    # missing key -- and that warning is easy to never see. Refuse instead.
    case " $* " in *" --api-key "*|*" --api-key="*) ;; *)
      if [ -z "${PRISMOR_EVAL_KEY:-}" ]; then
        echo "[prismor] eval-server needs PRISMOR_EVAL_KEY (or --api-key): it is reachable by anything that can reach this container" >&2
        exit 64
      fi ;;
    esac
    exec prismor eval-server \
      --host 0.0.0.0 \
      --port "${PRISMOR_EVAL_PORT:-7071}" \
      --workspace "${PRISMOR_HOME}" \
      "$@"
    ;;
  *)
    exec prismor "$@"
    ;;
esac
