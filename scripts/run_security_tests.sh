#!/usr/bin/env bash
# Prismor — security regression suite.
#
# Single entrypoint for the cloaking + policy tests, run identically in CI
# (.github/workflows/security-regression.yml) and locally. These lock the
# adversarial scenarios the live benchmark exercises — secret scrubbing, the
# Read / @file guards, and the destructive/remote-exec/exfil/injection policy
# rules — so a change to a hook or a rule can never silently regress them.
#
# Usage:  bash scripts/run_security_tests.sh
# Exits non-zero on the first failure. Requires jq (the cloak hooks are shell).
set -uo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

if ! command -v jq >/dev/null 2>&1; then
  echo "FATAL: jq is required (the cloaking hooks are shell-only)." >&2
  exit 1
fi

fail=0

# ── Cloaking hook regression (script-style tests, exit 1 on failure) ───────
# Each file guards its own $PRISMOR_HOME, so they are safe to run anywhere.
for t in \
  tests/test_cloak_output_scrub.py \
  tests/test_cloak_atfile_guard.py \
  ; do
  if [[ -f "$t" ]]; then
    echo "── $t ──"
    python3 "$t" || fail=1
  fi
done

# ── Policy + detect-and-block regression (pytest) ──────────────────────────
# Also covers the boundary controls a rule change cannot see: egress name
# resolution (a hostname must not hide the address it dials), the gateway's
# pre-connect screen (discovery reaches the network before any tool call), the
# repo-local MCP classification, and the published receipt schema (its verifier
# is executed straight out of the docs, so the spec cannot drift from the code).
pytest_targets=()
for t in \
  tests/test_policies.py \
  tests/test_cloak_secret_guard.py \
  tests/test_egress_resolve.py \
  tests/test_mcp_gateway_connect_guard.py \
  tests/test_discover_workspace_mcp.py \
  tests/test_telemetry_receipt_schema.py \
  tests/test_dogfood_configs.py \
  ; do
  [[ -f "$t" ]] && pytest_targets+=("$t")
done

if [[ ${#pytest_targets[@]} -gt 0 ]]; then
  echo "── pytest: ${pytest_targets[*]} ──"
  python3 -m pytest "${pytest_targets[@]}" -q || fail=1
fi

if [[ "$fail" -ne 0 ]]; then
  echo ""
  echo "SECURITY REGRESSION FAILED — a cloaking/policy guarantee regressed." >&2
  exit 1
fi
echo ""
echo "All security regression checks passed."
