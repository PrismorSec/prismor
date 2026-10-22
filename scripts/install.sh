#!/usr/bin/env sh
set -e

# Prismor installer
# Usage: curl -sSL https://prismor.dev/install | sh

# The `prismor` distribution owns the console entry points (prismor, immunity,
# prismor). Installing the legacy `immunity-agent` shim instead makes pipx
# refuse ("No apps associated with package") and leaves nothing on PATH.
PACKAGE="prismor"

echo "Installing Prismor..."

install_pipx() {
    if command -v apt-get >/dev/null 2>&1; then
        sudo apt-get install -y pipx
    elif command -v brew >/dev/null 2>&1; then
        brew install pipx
    elif command -v dnf >/dev/null 2>&1; then
        sudo dnf install -y pipx
    elif command -v pacman >/dev/null 2>&1; then
        sudo pacman -S --noconfirm python-pipx
    else
        echo "Error: Could not install pipx. Install it manually from https://pipx.pypa.io and re-run."
        exit 1
    fi
}

pipx_install() {
    pipx install "$PACKAGE"
    # Make sure pipx's bin dir (~/.local/bin) is on PATH for new shells.
    pipx ensurepath >/dev/null 2>&1 || true
}

try_pip_install() {
    local pip_cmd="$1"
    output=$($pip_cmd install "$PACKAGE" 2>&1)
    if echo "$output" | grep -q "externally-managed-environment"; then
        return 1
    fi
    echo "$output"
    return 0
}

# A prior install (an old easy_install script, a stale `immunity-agent` pipx
# venv, a different pip target earlier on PATH, ...) can leave a `prismor`
# entry on PATH that does NOT point at the version this script just
# installed. pipx/pip both exit 0 in that case and only print a warning
# that's easy to scroll past, so verify explicitly rather than trusting the
# exit code — see https://github.com/PrismorSec/prismor/issues/123.
verify_prismor_on_path() {
    local get_version_cmd="$1"
    local resolved expected_version actual_version

    resolved="$(command -v prismor 2>/dev/null || true)"
    if [ -z "$resolved" ]; then
        # Normal on a first install before ~/.local/bin is on PATH — pipx
        # already warned about this above. Not the bug we're guarding
        # against, so don't hard-fail: just let the closing hint below cover it.
        return 0
    fi

    expected_version="$($get_version_cmd 2>/dev/null | awk -F': ' '/^Version:/{print $2}')"
    actual_version="$("$resolved" --version 2>/dev/null | awk '{print $NF}')"

    if [ -n "$expected_version" ] && [ "$expected_version" != "$actual_version" ]; then
        echo ""
        echo "⚠️  'prismor' on your PATH ($resolved) reports version '$actual_version',"
        echo "    not the '$expected_version' just installed. Something else on PATH is"
        echo "    shadowing the new install — check for a stale binary ahead of it"
        echo "    (e.g. an old easy_install script, or a leftover immunity-agent/warden"
        echo "    install) and remove it, then open a new shell and re-check 'prismor --version'."
        return 1
    fi
    return 0
}

# 1. pipx already available — preferred path
if command -v pipx >/dev/null 2>&1; then
    pipx_install
    VERSION_CHECK_CMD="pipx runpip $PACKAGE show $PACKAGE"
# 2. pip available — try it; fall back to pipx if externally managed
elif command -v pip >/dev/null 2>&1; then
    if try_pip_install pip; then
        VERSION_CHECK_CMD="pip show $PACKAGE"
    else
        echo "pip blocked by externally-managed environment. Installing pipx..."
        install_pipx
        pipx_install
        VERSION_CHECK_CMD="pipx runpip $PACKAGE show $PACKAGE"
    fi
# 3. pip3 available — same logic
elif command -v pip3 >/dev/null 2>&1; then
    if try_pip_install pip3; then
        VERSION_CHECK_CMD="pip3 show $PACKAGE"
    else
        echo "pip3 blocked by externally-managed environment. Installing pipx..."
        install_pipx
        pipx_install
        VERSION_CHECK_CMD="pipx runpip $PACKAGE show $PACKAGE"
    fi
else
    echo "Error: Python pip not found. Install Python from https://python.org and try again."
    exit 1
fi

echo ""
if ! verify_prismor_on_path "$VERSION_CHECK_CMD"; then
    exit 1
fi
# Anonymous install count: one GET with OS, CPU arch, installer and version —
# no IDs, no IP forwarding. Runs only after a verified install, can never fail
# or delay it (3s cap, errors swallowed). Opt out: PRISMOR_NO_TELEMETRY=1 or
# DO_NOT_TRACK=1.
ping_install() {
    if [ -n "${PRISMOR_NO_TELEMETRY:-}" ] || [ -n "${DO_NOT_TRACK:-}" ]; then
        return 0
    fi
    command -v curl >/dev/null 2>&1 || return 0
    _v="$($VERSION_CHECK_CMD 2>/dev/null | awk -F': ' '/^Version:/{print $2}')"
    curl -fsS -m 3 -o /dev/null \
        "https://prismor.dev/api/i?os=$(uname -s)&arch=$(uname -m)&m=${VERSION_CHECK_CMD%% *}&v=$_v" \
        >/dev/null 2>&1 || true
}
ping_install || true

echo "Run 'prismor setup' to get started (open a new shell if the command is not found)."
