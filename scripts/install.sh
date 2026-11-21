#!/usr/bin/env sh
set -e

# Prismor installer
# Usage: curl -sSL https://prismor.dev/install | sh

# The `prismor` distribution owns the console entry points (prismor, immunity,
# prismor). Installing the legacy `immunity-agent` shim instead makes pipx
# refuse ("No apps associated with package") and leaves nothing on PATH.
PACKAGE="prismor"

# ── Output ────────────────────────────────────────────────────────────────────
# pip, pipx and apt each print a screenful of their own; none of it tells the
# user what happened or what to do next. Their output goes to a log file and
# the terminal gets one line per step instead. On failure the log tail is
# printed, so nothing is lost.
#
# Colour, spinner and the wordmark only when stdout is a terminal (piping into
# sh keeps stdout on the terminal, so the curl one-liner still gets them). CI
# logs and NO_COLOR get plain lines.
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ] && [ "${TERM:-}" != "dumb" ]; then
    FANCY=1
    BOLD=$(printf '\033[1m'); DIM=$(printf '\033[2m'); RST=$(printf '\033[0m')
    GRN=$(printf '\033[32m'); YEL=$(printf '\033[33m'); RED=$(printf '\033[31m')
    CYN=$(printf '\033[36m')
else
    FANCY=""
    BOLD=""; DIM=""; RST=""; GRN=""; YEL=""; RED=""; CYN=""
fi

case "${LC_ALL:-}${LC_CTYPE:-}${LANG:-}" in
    *UTF-8*|*utf-8*|*UTF8*|*utf8*) UTF=1 ;;
    *) UTF="" ;;
esac
if [ -n "$UTF" ]; then OK="✓"; BAD="✗"; else OK="ok"; BAD="x"; fi
WARN="!"

# Terminal width, so nothing below runs past the right edge. Under
# `curl | sh` stdin is the pipe, not the terminal, so ask the tty directly;
# $COLUMNS is a shell variable that is not exported to `sh`. Logs get 80.
COLS=""
if [ -n "$FANCY" ]; then
    COLS="$(stty size </dev/tty 2>/dev/null | awk '{print $2}')" || COLS=""
    case "$COLS" in ''|*[!0-9]*|0) COLS="$(tput cols 2>/dev/null)" || COLS="" ;; esac
fi
case "$COLS" in ''|*[!0-9]*|0) COLS=80 ;; esac
[ "$COLS" -ge 20 ] || COLS=20

LOG="$(mktemp "${TMPDIR:-/tmp}/prismor-install.XXXXXX")"

say() { printf '%s\n' "$*"; }

# para INDENT TEXT - TEXT word-wrapped to the terminal, every line at INDENT.
# fold counts colour codes as characters, so a coloured line breaks a little
# early, never late.
para() {
    _ind="$1"; shift
    _pad="$(printf "%${_ind}s" "")"
    printf '%s\n' "$*" | fold -s -w "$((COLS - _ind - 1))" | sed "s/^/$_pad/"
}

# dpara INDENT TEXT - para, dimmed. The colour goes around the wrapped block
# rather than inside the text, so fold measures only what is visible.
dpara() { printf '%s' "$DIM"; para "$@"; printf '%s' "$RST"; }

# mark SYMBOL TEXT - "  SYMBOL TEXT", wrapped with a hanging indent.
mark() {
    _m="$1"; shift
    printf '%s\n' "$*" | fold -s -w "$((COLS - 5))" | {
        _p="  $_m "
        while IFS= read -r _l; do printf '%s%s\n' "$_p" "$_l"; _p="    "; done
    }
}
ok()   { mark "$GRN$OK$RST" "$*"; }
warn() { mark "$YEL$WARN$RST" "$*"; }

fail() {
    mark "$RED$BAD" "$*$RST"
    if [ -s "$LOG" ]; then
        say ""
        dpara 2 "Last lines of the install log:"
        # Hard fold: log lines (URLs, wheel names) often have no spaces.
        tail -n 15 "$LOG" | fold -w "$((COLS - 5))" | sed 's/^/    /'
        say ""
        para 2 "Full log: $LOG"
    fi
    para 2 "Other ways to install: ${CYN}https://prismor.dev/docs/installation${RST}"
    exit 1
}

# spin LABEL CMD... - run CMD with its output in the log, showing LABEL with a
# spinner while it runs. Returns CMD's exit status and prints nothing when it
# finishes, so the caller says what actually happened (ok/warn/fail).
spin() {
    _label="$1"; shift
    if [ -z "$FANCY" ]; then
        say "  $_label..."
        _st=0; "$@" >>"$LOG" 2>&1 || _st=$?
        return $_st
    fi
    # `\r` only returns to the start of the current row: a label that wrapped
    # would leave a trail of half-drawn frames, so it has to fit on one line.
    _max=$((COLS - 5))
    if [ "${#_label}" -gt "$_max" ]; then _label="$(printf '%s' "$_label" | cut -c1-"$_max")"; fi
    "$@" >>"$LOG" 2>&1 &
    _pid=$!
    _i=0
    printf '\033[?25l'
    while kill -0 "$_pid" 2>/dev/null; do
        if [ -n "$UTF" ]; then
            case $((_i % 10)) in
                0) _f="⠋" ;; 1) _f="⠙" ;; 2) _f="⠹" ;; 3) _f="⠸" ;; 4) _f="⠼" ;;
                5) _f="⠴" ;; 6) _f="⠦" ;; 7) _f="⠧" ;; 8) _f="⠇" ;; *) _f="⠏" ;;
            esac
        else
            case $((_i % 4)) in 0) _f="|" ;; 1) _f="/" ;; 2) _f="-" ;; *) _f="\\" ;; esac
        fi
        printf '\r  %s%s%s %s' "$CYN" "$_f" "$RST" "$_label"
        _i=$((_i + 1))
        sleep 0.08
    done
    _st=0; wait "$_pid" || _st=$?
    printf '\r\033[K\033[?25h'
    return $_st
}

# Put the cursor back if the user hits Ctrl-C mid-spinner.
trap '[ -n "$FANCY" ] && printf "\033[?25h"' EXIT
trap 'exit 130' INT TERM

# ── Install ───────────────────────────────────────────────────────────────────

as_root() {
    if [ "$(id -u)" = "0" ]; then "$@"; else sudo "$@"; fi
}

install_pipx() {
    if command -v brew >/dev/null 2>&1; then
        spin "Installing pipx with Homebrew" brew install pipx || fail "Could not install pipx with Homebrew"
    elif command -v apt-get >/dev/null 2>&1 || command -v dnf >/dev/null 2>&1 || command -v pacman >/dev/null 2>&1; then
        # Ask for the sudo password up front, in the open. Behind the spinner
        # the prompt would go to the log and the install would sit there.
        if [ "$(id -u)" != "0" ]; then
            dpara 2 "pipx comes from your system package manager, which needs sudo."
            sudo -v || fail "sudo is needed to install pipx"
        fi
        if command -v apt-get >/dev/null 2>&1; then
            # Without `update` first, a fresh or long-idle machine has no
            # package lists and `install pipx` fails with "Unable to locate".
            spin "Installing pipx with apt" as_root sh -c \
                'apt-get update -q && DEBIAN_FRONTEND=noninteractive apt-get install -y -q pipx' \
                || fail "Could not install pipx with apt"
        elif command -v dnf >/dev/null 2>&1; then
            spin "Installing pipx with dnf" as_root dnf install -y pipx || fail "Could not install pipx with dnf"
        else
            spin "Installing pipx with pacman" as_root pacman -S --noconfirm python-pipx || fail "Could not install pipx with pacman"
        fi
    else
        fail "Could not install pipx. Install it from https://pipx.pypa.io and re-run."
    fi
    ok "pipx installed"
}

pipx_install() {
    # --force: a re-run upgrades instead of stopping at "already installed".
    spin "Installing prismor with pipx" pipx install --force "$PACKAGE" || fail "pipx could not install prismor"
    METHOD="pipx"
    VERSION_CHECK_CMD="pipx runpip $PACKAGE show $PACKAGE"
    BIN_DIR="$(pipx environment --value PIPX_BIN_DIR 2>/dev/null || true)"
    [ -n "$BIN_DIR" ] || BIN_DIR="$HOME/.local/bin"
    # Make sure pipx's bin dir is on PATH for new shells.
    pipx ensurepath >>"$LOG" 2>&1 || true
}

# pip_install PIP - returns 2 when pip refuses with externally-managed-
# environment (PEP 668), so the caller can fall back to pipx.
pip_install() {
    _pip="$1"
    _mark=$(wc -l <"$LOG")
    if spin "Installing prismor with $_pip" "$_pip" install --upgrade "$PACKAGE"; then
        METHOD="$_pip"
        VERSION_CHECK_CMD="$_pip show $PACKAGE"
        # A --user install lands in <user-base>/bin, which is often not on
        # PATH (~/.local/bin on Linux, ~/Library/Python/3.x/bin on macOS).
        BIN_DIR=""
        _loc="$("$_pip" show "$PACKAGE" 2>/dev/null | awk -F': ' '/^Location:/{print $2}')"
        if [ -n "$PY" ]; then
            _ub="$("$PY" -m site --user-base 2>/dev/null || true)"
            case "$_loc" in "$_ub"/*) BIN_DIR="$_ub/bin" ;; esac
        fi
        return 0
    fi
    if tail -n +"$((_mark + 1))" "$LOG" | grep -q "externally-managed-environment"; then
        return 2
    fi
    fail "pip could not install prismor"
}

say ""
if [ "$COLS" -ge $((28 + ${#LOG})) ]; then
    printf '  %sInstalling Prismor%s  %slog: %s%s\n' "$BOLD" "$RST" "$DIM" "$LOG" "$RST"
else
    say "  ${BOLD}Installing Prismor${RST}"
    dpara 2 "log: $LOG"
fi
say ""

PY="$(command -v python3 || command -v python || true)"
if [ -n "$PY" ]; then
    ok "Python $("$PY" -c 'import platform; print(platform.python_version())' 2>/dev/null)"
fi

# 1. pipx already available - preferred path
if command -v pipx >/dev/null 2>&1; then
    pipx_install
# 2. pip / pip3 - try it; fall back to pipx if externally managed
elif PIP="$(command -v pip || command -v pip3)"; then
    PIP="$(basename "$PIP")"
    _st=0; pip_install "$PIP" || _st=$?
    if [ "$_st" = "2" ]; then
        warn "$PIP is managed by your OS (PEP 668), using pipx instead"
        install_pipx
        pipx_install
    fi
else
    fail "Python pip not found. Install Python from https://python.org and try again."
fi

INSTALLED_VERSION="$($VERSION_CHECK_CMD 2>/dev/null | awk -F': ' '/^Version:/{print $2}')"
ok "prismor ${INSTALLED_VERSION} installed ${DIM}(${METHOD})${RST}"

# A prior install (an old easy_install script, a stale `immunity-agent` pipx
# venv, a different pip target earlier on PATH, ...) can leave a `prismor`
# entry on PATH that does NOT point at the version this script just
# installed. pipx/pip both exit 0 in that case and only print a warning
# that's easy to scroll past, so verify explicitly rather than trusting the
# exit code — see https://github.com/PrismorSec/prismor/issues/123.
verify_prismor_on_path() {
    resolved="$(command -v prismor 2>/dev/null || true)"
    if [ -z "$resolved" ]; then
        # Normal on a first install before the bin dir is on PATH. Not the
        # bug we're guarding against; the next steps below cover it.
        return 0
    fi

    actual_version="$("$resolved" --version 2>/dev/null | awk '{print $NF}')"

    if [ -n "$INSTALLED_VERSION" ] && [ "$INSTALLED_VERSION" != "$actual_version" ]; then
        say ""
        mark "$RED$BAD$RST" "'prismor' on your PATH ($resolved) reports version '$actual_version'," \
            "not the '$INSTALLED_VERSION' just installed. Something else on PATH is" \
            "shadowing the new install — check for a stale binary ahead of it" \
            "(e.g. an old easy_install script, or a leftover immunity-agent/warden" \
            "install) and remove it, then open a new shell and re-check 'prismor --version'."
        return 1
    fi
    return 0
}

if ! verify_prismor_on_path; then
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
    curl -fsS -m 3 -o /dev/null \
        "https://prismor.dev/api/i?os=$(uname -s)&arch=$(uname -m)&m=${VERSION_CHECK_CMD%% *}&v=$INSTALLED_VERSION" \
        >/dev/null 2>&1 || true
}
ping_install || true

# ── Done ──────────────────────────────────────────────────────────────────────

# Wordmark, shaded top to bottom through the site's hero wash: peach, rose,
# lilac, ice, sky (xterm-256 colours, which every terminal still in use has).
# The big one is 57 columns with its indent, the ASCII one 38; below that the
# name is just set in bold.
wordmark() {
    [ -n "$FANCY" ] || return 0
    say ""
    if [ -n "$UTF" ] && [ "$COLS" -ge 60 ]; then
        _n=0
        while IFS= read -r _line; do
            case $_n in
                0) _c=216 ;; 1) _c=217 ;; 2) _c=218 ;; 3) _c=183 ;; 4) _c=153 ;; *) _c=117 ;;
            esac
            printf '  \033[1;38;5;%sm%s\033[0m\n' "$_c" "$_line"
            _n=$((_n + 1))
        done <<'ART'
██████╗ ██████╗ ██╗███████╗███╗   ███╗ ██████╗ ██████╗
██╔══██╗██╔══██╗██║██╔════╝████╗ ████║██╔═══██╗██╔══██╗
██████╔╝██████╔╝██║███████╗██╔████╔██║██║   ██║██████╔╝
██╔═══╝ ██╔══██╗██║╚════██║██║╚██╔╝██║██║   ██║██╔══██╗
██║     ██║  ██║██║███████║██║ ╚═╝ ██║╚██████╔╝██║  ██║
╚═╝     ╚═╝  ╚═╝╚═╝╚══════╝╚═╝     ╚═╝ ╚═════╝ ╚═╝  ╚═╝
ART
    elif [ "$COLS" -ge 40 ]; then
        printf '\033[1;38;5;218m'
        cat <<'ART'
   ___ ___ ___ ___ __  __  ___  ___
  | _ \ _ \_ _/ __|  \/  |/ _ \| _ \
  |  _/   /| |\__ \ |\/| | (_) |   /
  |_| |_|_\___|___/_|  |_|\___/|_|_\
ART
        printf '\033[0m'
    else
        printf '  \033[1;38;5;218mP R I S M O R\033[0m\n'
    fi
}

# Next steps, as "group|number|command|description" rows. Laid out in one awk
# pass so both groups share a column: side by side when the longest command
# and description fit the terminal, otherwise each description goes under
# its command.
STEPS=""
add() { STEPS="${STEPS}$1|$2|$3|$4
"; }

N=1
if ! command -v prismor >/dev/null 2>&1 && [ -n "${BIN_DIR:-}" ]; then
    # This shell read PATH before the install, so `prismor` is not found here
    # yet, even where a new terminal would find it.
    add "Next steps" "$N" "export PATH=\"$(printf '%s' "$BIN_DIR" | sed "s|^$HOME|\$HOME|"):\$PATH\"" "put prismor on PATH in this shell"
    N=$((N + 1))
fi
add "Next steps" "$N" "prismor setup"     "pick your agents and what to block"; N=$((N + 1))
add "Next steps" "$N" "prismor status"    "check the hooks are live";           N=$((N + 1))
add "Next steps" "$N" "prismor dashboard" "watch every agent action, locally"
add "When you're ready" "" "prismor cloak add --env-file .env" "keep secrets out of the model"
add "When you're ready" "" "prismor enroll <token>"            "connect to your team's console"
add "When you're ready" "" "prismor --help"                    "every command"

render_steps() {
    printf '%s' "$STEPS" | awk -F'|' -v cols="$COLS" -v b="$BOLD" -v d="$DIM" -v r="$RST" -v c="$BOLD$CYN" '
        { g[NR] = $1; n[NR] = $2; cmd[NR] = $3; desc[NR] = $4
          if (length($3) > cw) cw = length($3)
          if (length($4) > dw) dw = length($4) }
        # wrap(text, indent): text word-wrapped to the terminal at indent.
        function wrap(t, ind,    pad, out, line, nw, wd, j) {
            pad = sprintf("%" ind "s", ""); out = ""; line = ""
            nw = split(t, wd, " ")
            for (j = 1; j <= nw; j++) {
                if (line != "" && ind + length(line) + 1 + length(wd[j]) >= cols) {
                    out = out pad d line r "\n"; line = wd[j]
                } else line = (line == "") ? wd[j] : line " " wd[j]
            }
            return out pad d line r "\n"
        }
        END {
            # "  N  command  description", kept one column clear of the edge.
            wide = (2 + 1 + 2 + cw + 2 + dw < cols)
            for (i = 1; i <= NR; i++) {
                if (g[i] != g[i - 1]) printf "\n  %s%s%s\n\n", b, g[i], r
                num = (n[i] == "") ? " " : n[i]
                if (wide) {
                    # Padding by hand: "%*s" is not in every awk (macOS).
                    pad = ""; for (k = length(cmd[i]); k < cw; k++) pad = pad " "
                    printf "  %s%s%s  %s%s%s%s  %s%s%s\n", d, num, r, c, cmd[i], r, pad, d, desc[i], r
                } else if (5 + length(cmd[i]) < cols) {
                    printf "  %s%s%s  %s%s%s\n%s", d, num, r, c, cmd[i], r, wrap(desc[i], 5)
                } else {
                    # Too long even on its own line: give it the full width
                    # rather than wrap a command someone will copy.
                    printf "  %s%s%s\n%s%s%s%s\n", d, num, r, wrap(desc[i], 5), c, cmd[i], r
                }
            }
        }'
}

wordmark
say ""
if [ "$COLS" -ge 70 ]; then
    say "  ${BOLD}Prismor ${INSTALLED_VERSION} is installed.${RST} ${DIM}Runtime security for your AI agents.${RST}"
else
    printf '%s' "$BOLD"; para 2 "Prismor ${INSTALLED_VERSION} is installed."; printf '%s' "$RST"
    dpara 2 "Runtime security for your AI agents."
fi
render_steps
say ""
DOCS="https://prismor.dev/docs"; GH="https://github.com/PrismorSec/prismor"
if [ "$COLS" -ge 84 ]; then
    say "  ${DIM}Docs${RST}  $DOCS    ${DIM}GitHub${RST}  $GH"
elif [ "$COLS" -ge 49 ]; then
    say "  ${DIM}Docs${RST}    $DOCS"
    say "  ${DIM}GitHub${RST}  $GH"
elif [ "$COLS" -ge 41 ]; then
    say "  $DOCS"
    say "  $GH"
elif [ "$COLS" -ge 33 ]; then
    say "  ${DOCS#https://}"
    say "  ${GH#https://}"
else
    say "${DOCS#https://}"
    say "${GH#https://}"
fi
say ""
