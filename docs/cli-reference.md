# CLI Reference

Every capability in the toolkit is reachable through the single `prismor`
command. This page is the **map**: it lists every command, what it does, and
links to the dedicated deep-dive doc for that capability.

```
prismor <command> [options...]
prismor <domain> <action> [options...]
prismor --help               # the same map, in your terminal
prismor help                 # browse it interactively: type to filter, enter for details
prismor help <command>       # help for one command (same as prismor <command> --help)
prismor help <word>          # search commands and sub-commands, e.g. prismor help secret
```

There are two shapes:

- **Top-level commands** — `prismor status`, `prismor audit`, `prismor check …`
- **Domains** that take an action — `prismor cloak add …`, `prismor canary plant …`

`immunity` is a deprecated drop-in alias for `prismor`; it forwards everything
unchanged and prints a migration notice. Use `prismor`.

---

## Quick start

| Command | What it does | Deep dive |
|---|---|---|
| `prismor setup` | Interactive onboarding wizard: pick mode, choose which rules block, select agents, enable cloaking, choose install scope, set the unlock password. | [Onboarding](#onboarding--lifecycle) |
| `prismor status` | One-shot health check: workspace, hooks, mode, cloak, latest session, next action. | [Dashboard & sessions](dashboard.md) |
| `prismor audit` | Full security-posture audit across every subsystem. `--fix` auto-remediates. | [Prismor](prismor-runtime.md#security-audit) |
| `prismor --help` | The full command map. | — |

---

## The command map

```
prismor
│
├─ Get started
│   ├─ setup                  Interactive onboarding wizard (TUI)
│   ├─ status [--all]         Health check (this workspace / all workspaces)
│   ├─ doctor                 Health-check every subsystem (hooks, policy, signature, telemetry)
│   ├─ discover [section]     Sweep host for ungoverned agents, MCP servers, keys (--fix to govern them)
│   ├─ dashboard              Local web dashboard (127.0.0.1:7070, opens browser)
│   ├─ login                  Connect this machine to the Prismor API (hosted judge)
│   ├─ update                 Self-update check / upgrade
│   ├─ docs [name]            Print a bundled doc page, or list them
│   ├─ install-hooks          Wire Prismor hooks into an agent/IDE
│   ├─ uninstall-hooks        Remove hooks
│   └─ surfaces               Which enforcement surfaces (hooks, mirror, gateway) are active
│
├─ Day to day
│   ├─ check                  Pre-check a command or path against policy
│   ├─ approvals              Approve or deny one blocked action, once
│   ├─ allow <rule>           Make an exception to a rule that blocked you
│   ├─ pause / pause-hard     Suspend local enforcement (24h / until resume); observe stays on
│   ├─ resume                 Resume enforcement
│   ├─ unlock / lock          Open/close the agent self-edit window (password)
│   └─ mode <action>          list · explain · apply · show — whole-posture templates
│
├─ Policy & scoping
│   ├─ policy <action>        init · validate · show · export · edit · test
│   ├─ tags <action>          list · set · rm · rules · provenance · edit · lint · test
│   ├─ scope <action>         Session-scoped, task-specific rules
│   ├─ iam <action>           Named agent identities / permission profiles
│   ├─ egress <action>        show · report · test · allow · deny · mode · request — network egress policy
│   ├─ agents <action>        Named agent instances — list · show · set (kill-switch, mode, IAM)
│   └─ learn                  Mine session history for new rules
│
├─ Secrets
│   ├─ cloak <action>         install · add · list · remove · status · run · pattern
│   ├─ sweep                  Find & vault leaked secrets on disk
│   └─ canary <action>        Plant & manage honeytoken tripwires
│
├─ Scanning & audit
│   ├─ audit                  Full posture audit (--fix to remediate)
│   ├─ audit judge            LLM judge reviews a sample of ALLOWED calls after the fact
│   ├─ scan                   Scan MCP servers & skills for risk
│   ├─ deps                   Check project deps vs. threat feed
│   ├─ skills <action>        audit · approve — installed SKILL.md baselines
│   ├─ extensions <action>    list · why · approve · wrap-hooks — what puts instructions or code into the agent
│   ├─ memory <action>        status · trust · verify · scan · approve · sign · unsign — instruction-file integrity
│   ├─ semantic-check         Hybrid LLM prompt-injection guard
│   └─ supplychain <action>   npm/pip/pnpm/uv/cargo/go/gem/composer/mvn install gate · harden
│
├─ Enforcement surfaces
│   ├─ mirror <action>        on · off · status · passthrough — governed built-ins over MCP
│   ├─ mcp-gateway [action]   serve · install · uninstall — one MCP connector in front of all servers
│   ├─ acp -- <agent…>        ACP stdio proxy — agents hosted by Zed, JetBrains and other ACP editors
│   ├─ proxy                  LLM/A2A proxy — screens model traffic and proposed tool calls
│   ├─ elevenlabs <action>    status · connect · disconnect — ElevenLabs voice agents via the proxy
│   ├─ sandbox <action>       status · check · on · off · run — Docker command sandbox
│   ├─ inference-hook <action> serve · test · secret — Claude Inference Hooks AI security server
│   └─ eval-server            HTTP evaluation endpoint for non-Python adapters
│
├─ Sessions & evidence
│   ├─ sessions / session     List / show stored sessions (session <id> --changes: files touched)
│   ├─ analyze                Run the engine over a JSONL session
│   ├─ analyze-history       Reconstruct past agent activity from on-disk transcripts
│   ├─ tokens                 Token usage and estimated cost
│   ├─ trail <action>         verify · show · checkpoint — signed audit trail
│   ├─ attest [verify|coverage]  Evidence bundle + framework coverage
│   ├─ query                  Read-only SQL over the local session store
│   ├─ rca [session]          What went wrong in a session
│   ├─ blame <path[:line]>    Which agent session wrote this file or line
│   └─ friction               Failures that recur across sessions, as AGENTS.md lines
│
└─ Org enrollment
    ├─ enroll <token>         Enroll this machine against your org's control plane
    ├─ enroll-status          Show enrollment + applied policy version
    ├─ workspace <action>     Show/set whether this workspace is org-managed or personal
    ├─ exempt <action>        Request an admin exemption for this repo
    └─ logout                 Un-enroll (remove device identity + cached policy)
```

---

## Onboarding & lifecycle

| Command | Key flags | Description |
|---|---|---|
| `prismor setup [DIR]` | `--non-interactive`, `--mode`, `--enforce-rules`, `--recommended`, `--agents`, `--cloak/--no-cloak`, `--judge <claude\|codex\|api\|prismor>`, `--judge-model`, `--system` | Interactive wizard (or scripted with flags / `PRISMOR_MODE`, `PRISMOR_CLOAK`, `PRISMOR_JUDGE`, `PRISMOR_JUDGE_MODEL` env vars). Picks mode, chooses which rules block, selects agents, enables cloaking, picks which login judges uncertain events (see [Semantic Guard](semantic-guard.md)), and optionally sets an unlock password. See [Choosing what blocks](#choosing-what-blocks). `--system` (Linux/macOS as root, Windows elevated) installs once for every user on the machine; see [System install](system-install.md). |
| `prismor install-hooks` | `--agent <name\|all>` (required), `--mode <observe\|enforce>`, `--scope <project\|user\|global\|system>` (default project), `--portable` | Writes hook config for the chosen agent so Prismor sees tool calls. Without hooks, nothing is monitored. `--portable` writes a command with no machine-specific paths, so the file can be committed and cloned onto a hosted agent's VM — see [cloud-agents.md](cloud-agents.md). |
| `prismor uninstall-hooks` | `--agent <name\|all>`, `--scope` (`system` removes a [system install](system-install.md)'s hooks, as root) | Removes Prismor hooks for an agent. For `claude`/`all`, this also removes cloaking hooks (`prismor cloak install`) — secrets are no longer protected at the tool boundary until you reinstall with `prismor cloak install`. |
| `prismor status` | `--workspace`, `--all`, `--days N`, `--perf [N]`, `--json` | Health check: hooks, mode, cloak state, latest session, and the single next action. Run this first every session. `--all` shows every registered workspace. `--perf` reports hook latency (p50/p95 by agent and event, slowest stages and rules) over the last N calls (default 500); `--json` with it for raw output. |
| `prismor doctor` | `--json`, `--self-test` | Inspect hook configuration, launcher files, policy, enrollment, telemetry, and chain state. Optionally probe recognized dispatchers. Exits non-zero when a check fails. |
| `prismor surfaces` | — | Which enforcement surface governs each agent on this machine (hooks, MCP mirror, gateway), and which agents nothing governs. |
| `prismor login` | `--no-browser`, `--label`, `--api-base`, `--force`, `--set-judge` | Sign in and connect this machine to the Prismor API, which gives you the hosted semantic judge (1,000 free verdicts a month). `--set-judge` also sets `semantic_guard.provider: prismor` for this workspace. See [Semantic Guard](semantic-guard.md). |
| `prismor update` | `--check` | Check for (or install) a newer prismor release. |
| `prismor info` | `--workspace` | _Deprecated_ alias of `status`. |

Agent → config matrix and per-agent details: [AGENT_INTEGRATIONS.md](../AGENT_INTEGRATIONS.md).
Modes (`observe` vs `enforce`): [Prismor](prismor-runtime.md).

Hook health checks are passive: they parse registered agents' hook configurations
and inspect recognized launchers for missing interpreters and dispatcher files.
By default they never run a configured command. `configured` does not establish that imports
succeed, that the client loaded its hooks, or that a tool call was blocked.
Portable/custom launchers and registered plugins remain explicitly unverified.
Doctor's JSON `ok` means no check failed; review warning entries as well.
Dispatcher entries under unregistered event names, or without any registered
pre-action tool event, fail the wiring check. Recognized generated project
launchers must target the inspected workspace (resolved symlinks are accepted).
Global and portable launchers are not required to pin that workspace. These
checks do not validate every matcher, optional event or client-specific schema.

`prismor doctor --self-test` additionally runs recognized generated dispatcher
scripts through their configured interpreter, with a temporary home and workspace
and no inherited Prismor settings or credentials. It verifies imports and synthetic
Claude-protocol allow/block responses, with a timeout on each subprocess. The
synthetic commands are evaluated, never executed. Modified dispatcher scripts,
custom launchers, portable wrappers, and plugins are skipped with a warning.
This verifies the shared dispatcher, not each client's protocol or the current
workspace policy. Client loading, trust, and actual invocation still require a
live client check. Disposable state is not an OS sandbox.
The probe uses Python's isolated mode (`-I`); dependencies available only through
user-site packages or `PYTHONPATH` are excluded and can fail the import probe.

Cursor reinstall and uninstall remove recognized Prismor launchers, not other
tools whose command text mentions `hook-dispatch`. Legacy event keys are removed
only when cleanup removes their last entry. Third-party entries and unrelated
settings are preserved; custom wrappers that cannot be recognized remain for
manual inspection.

### Choosing what blocks

`observe` reports everything and blocks nothing, so setup leaves every rule on.

`enforce` asks which rules should block, and starts with **none of them
selected** — including the safety floor, which is marked *recommended* rather
than assumed. Nothing blocks until you choose it. Press `a` on that screen to
take the recommended set.

The choice is written to `.prismor/policy.yaml` as `settings.selection:
explicit` plus one entry per rule, so what blocks is legible in the file rather
than implied by the defaults. Scripted installs say the same thing with
`--recommended` or `--enforce-rules id1,id2`; `--mode enforce` with neither
installs with nothing blocking and tells you so.

Two things the selection does not reach:

- **Prismor's self-protection rules** always block. They are what stops the
  agent editing the choices above, so offering them as a checkbox would make
  every other checkbox decorative.
- **Org-managed workspaces** keep the full safety floor. `selection: explicit`
  is honored only for a locally-authored policy on an unmanaged machine, and is
  ignored if it arrives in a signed org bundle.

### Governance modes

Picking six policy axes rule by rule is how a policy ends up subtly wrong. A
**mode** is a named posture that sets all six at once — enforcement fallback,
egress allowlist, tool access, tag rules, sandbox ring, and step-up gates — and
compiles them into the same `.prismor/policy.yaml` and `.prismor/agents.yaml`
the engine already reads. There is no separate mode enforcement path.

```
prismor mode list                    # the three, with coverage and friction
prismor mode explain dev-safe        # the trade — including what it does NOT stop
prismor mode apply dev-safe          # compile it (--dry-run to preview first)
prismor mode apply dev-safe --observe # same posture, nothing blocks
prismor mode show                    # active mode, and whether it has drifted
```

#### What each mode covers

Coverage and rule counts are **computed from the live ruleset** by `prismor mode
list`, not hardcoded here — they move as rules are added. Friction is likewise
**measured**, not estimated: `tests/test_modes.py` runs a benign corpus of
ordinary developer commands through each compiled mode and pins the declared
`friction_index` to the share it interrupts. The figures below are from a
91-rule policy.

| | `dev-safe` | `trusted-workspace` | `regulated-airgap` |
|---|---|---|---|
| **Rules blocking** | 26/91 | 28/91 | 91/91 |
| **Coverage** | 29% | 31% | 100% |
| **Friction** | 9% | 9% | 90% |
| **Intended for** | daily development | trusted internal repos | regulated / PII |

Prismor's self-protection rules always enforce in every mode — a mode cannot be
used as cover for disabling Prismor.

**Axis by axis**

| Axis | `dev-safe` | `trusted-workspace` | `regulated-airgap` |
|---|---|---|---|
| `settings.default_mode` | observe | observe | **enforce** |
| Rule selector | floor + 3 | floor + 7 | all |
| Egress default | **deny** | **deny** | **deny** |
| Egress allowlist | JS, Python, Rust, Go, JVM, GitHub, container registries, test binaries, docs, LLM APIs | + cloud provider APIs | **empty** |
| Private / loopback | allowed | allowed | **blocked** |
| Tools denied | — | — | Bash, WebFetch, WebSearch |
| Tools gated (HITL) | — | — | Write, Edit |
| Commands denied | `sudo` `su` `chmod +s` | `sudo` `chmod +s` `su` | — (no shell at all) |
| Commands auto-approved | read-only inspection + non-mutating `git` | same | — |
| Commands gated | npm/pip/cargo install | npm/pip/cargo/gem install | — |
| Tag rules | 1 (block) | 2 (block) | 3 (block) |
| Untrusted-content sources | web + MCP ingest | web + MCP ingest | web + MCP ingest |
| Data boundary | **enforce** | **enforce** | **enforce** |
| Sandbox ring | enforce, net allowlist, RO root | observe, bridge, RW root | enforce, net none, RO root, noexec tmpfs |

The three extras in `dev-safe` are the supply-chain rules:
`dependency-confusion`, `pkg-install-from-url`, `pkg-suspicious-name`.
`trusted-workspace` adds the secret rules on top: `secret-access`,
`credential-aggregation`, `credential-staging`, `claude-credential-access`.

**Two things worth knowing before you adopt one.**

A rule listed in `enforce_extra` that declares `action: warn` becomes a hard
block, because `contract.VERDICT_RANK` reads "enforce + a verdict we do not
understand" as stop. That is why installing from a private index URL is denied
rather than prompted under both safe modes — deliberate, and stated in each
mode's residual risk.

`untrusted_content` means *externally sourced*: a web fetch, a search result, an
MCP tool result, or a file read from outside the workspace root. Reading a file
in your own repository is not untrusted ingest, and a mode that turns tag
enforcement on must say so explicitly — `compile_mode` refuses a mode that
enables `tool_tags` without declaring `tool_tags.inference_enabled`. Inheriting
the default there tags every workspace read as untrusted, which turns
`untrusted_content then critical_action -> block` into "read anything, then do
anything" and denies every call after the session's first read.

#### Containment is opt-in

Adopting a mode does not start routing your shell commands through Docker.
`dev-safe` and `trusted-workspace` both ship `sandbox.enabled: false`: they
compile a sandbox configuration (ring, network, mounts, limits) and leave it
switched off, so the mode changes what may run without changing where it runs.

```bash
prismor sandbox on      # containment on, using the settings the mode compiled
prismor sandbox off     # back to running on the host
prismor sandbox status  # what is configured, and whether Docker can back it
```

Only the field flips, so an off/on round trip keeps the ring, network and
limits the mode chose. `regulated-airgap` is the exception and ships its
sandbox on — containment is what that posture *is*.

Once it is on, a missing container runtime matters. `cli.py` **blocks** a shell
call outright when an enforcing sandbox has no runtime behind it — it does not
silently run unsandboxed — so `mode apply` preflights and degrades the sandbox
axis to `observe` rather than leaving every command to fail one at a time. The
rest of the posture (rules, egress, tag rules) still lands, and `mode show`
re-checks at read time to catch a runtime that disappeared *after* the mode was
applied. `regulated-airgap` enforces a sandbox but denies the Bash tool, so no
shell event ever reaches the sandbox gate and it too runs without Docker.

**Known limitation:** the sandbox gate is wired for the Claude adapter only. On
other agents the sandbox axis is not applied, even though `mode explain` still
describes it.

#### Previewing a posture

`--observe` compiles any mode with nothing enforcing — same rules, same
findings, no verdict blocks:

```
prismor mode apply dev-safe --observe
```

This answers "what would this posture stop?", which is the question worth asking
before adopting one. `mode show` reports a preview build as such and never
claims it is the enforcing article. Tool deny/ask lists are skipped in a preview
build, because `agents.yaml` has no observe tier and writing them would enforce
the one axis the flag promises not to.

`mode explain` always prints a **residual risk** paragraph. `dev-safe` allows
`api.github.com`, so an injected agent can still paste a `.env` into a public
issue comment; `regulated-airgap` is tight enough that the realistic failure is
somebody running `uninstall-hooks` to get through the afternoon. A mode that
claimed no downside would be the one not to trust.

Applying a mode overwrites `.prismor/policy.yaml` (keeping a `.bak`), and
refuses outright if that file was not generated by a mode — pass `--force` once
you have looked at what you are replacing. Hand-editing afterwards is fine;
`mode show` then reports drift rather than claiming a posture the file no
longer has.

### Making exceptions

Often you don't want an exception at all, just "yes, run that, this once". A
block carries a request id for exactly that:

```
prismor approvals                  # what is waiting
prismor approvals approve 4c3e28   # that exact call, once
prismor approvals deny 4c3e28
```

The approval covers the same agent making the same tool call with the same
input in the same workspace. The first call it lets through spends it, and it
lapses after 30 minutes if nothing uses it. `approve` tells you whether the
agent is still waiting (it carries on by itself) or you have to go back and tell
it to retry. Set `PRISMOR_APPROVAL_WAIT=30` to make Claude Code and Codex hold
the blocked call open for that many seconds (at most 45, which keeps it under
the hook timeout). Approving inside that window lets the original call run,
with no retry. Not offered for self-protection rules or on org-managed
workspaces. `approve` needs a terminal, so an agent cannot approve its own
call, even inside an unlock window.

When a rule blocks something it should not, the block prints the command that
fixes it:

```
prismor allow secret-exfiltration --pattern 'curl -F f=@.env'   # just this case
prismor allow secret-exfiltration --observe                     # keep the rule, stop it blocking
prismor allow secret-exfiltration --off --yes                    # off in this workspace
prismor allow --list                                             # what you have added
prismor allow --undo allow-secret-exfiltration                   # remove one
```

Add `--expires 30m` to make an exception temporary — it lapses instead of
quietly becoming permanent policy.

**These are for the human at the keyboard.** An agent that runs them is blocked,
along with every other route to Prismor's own config: the policy file, the
dashboard's write API, and the unlock credential. To hand the agent that
ability for a few minutes, run `prismor unlock` and enter your password
(`prismor unlock --set-password` if you have not set one). Inside the window the
agent can adjust policy; it still cannot touch the self-protection rules or the
password itself, and the window closes on its own.

### Let your agent create or edit policy

You can have your agent (Claude Code, Codex, Cursor, ...) write a policy for
you, or change one, as long as you open the door first:

```
prismor unlock              # asks for your password; 3 minutes by default
prismor unlock --for 15m    # longer, up to an hour (or your org's cap)
```

Then ask the agent for what you want ("block curl to anything but our API",
"stop flagging `git push` in this repo"). Inside the window it can edit
`.prismor/policy.yaml`, run `prismor policy init` to scaffold one, and run
`prismor allow`. Every change is logged. It still cannot relax the
self-protection rules, read or change the unlock password, or extend its own
window. `prismor lock` closes the window early; `prismor unlock --status` shows
how long is left. Check the result with `prismor policy show`.

An unhooked agent — one running through a framework Prismor does not see — is
outside all of this, the same as every other Prismor control.

---

## Runtime protection

| Command | Key flags | Description |
|---|---|---|
| `prismor check "<value>"` | `--type <command\|read\|write>`, `--explain`, `--from-log`, `--suggest-allowlist` | Dry-run a command or file path against the active policy. Returns ALLOW / WARN / BLOCK + reason without executing. Exit `2`=block, `1`=warn, `0`=clean. |
| `prismor semantic-check [TEXT]` | `--mode <hybrid\|heuristic\|api>`, `--provider <claude\|codex\|api\|prismor>`, `--model`, `--json`, `--cli-path` | Run the semantic prompt-injection guard on text or stdin. See [Semantic Guard](semantic-guard.md). |
| `prismor allow <rule>` | `--pattern`, `--expires`, `--observe`, `--off`, `--yes`, `--reason`, `--list`, `--undo`, `--workspace` | Make an exception to a rule that blocked you, narrowest first. With no `--pattern` it uses the text of the most recent block for that rule. `--observe` keeps the rule but stops it blocking; `--off` disables it for the workspace (needs `--yes`). Refuses self-protection rules, refuses to turn a floor rule off, and refuses everything where an org's signed policy governs. See [Making exceptions](#making-exceptions). |
| `prismor approvals [list\|approve <id>\|deny <id>]` | `--all`, `--json` | One-shot human approval for a blocked action: the identical call runs once. Needs a terminal. See [Making exceptions](#making-exceptions). |
| `prismor unlock` | `--for`, `--status`, `--set-password`, `--system-password`, `--forget`, `--workspace` | Open a short window (default 3 minutes) in which the agent may edit Prismor's own policy. Asks for your unlock password; needs a terminal. `--system-password` verifies against your operating-system account instead of storing a Prismor one. |
| `prismor lock` | — | Close the self-edit window early. |
| `prismor pause` | `--for DURATION` (default `24h`), `--reason` | Suspend local enforcement: tool calls are still screened and logged (observe), but nothing blocks. Auto-resumes after `--for` (`30m`, `2h`, `1d`). The reason is shown in the console next to the device. Agents cannot run it. See [Pause and resume](pause-and-login.md). |
| `prismor pause-hard` | `--reason` | Same as `pause`, with no auto-resume: enforcement stays off until `prismor resume`. |
| `prismor resume` | — | Resume enforcement after `pause` / `pause-hard`. |
| `prismor policy init` | `--workspace` | Scaffold `.prismor/policy.yaml`. |
| `prismor policy show` | `--workspace` | Print active rules after merging defaults + project overrides. |
| `prismor policy export` | `--json`, `--output PATH`, `--workspace` | Print the effective merged policy as stable, sorted JSON — patterns already resolved and disabled rules dropped — for non-Python consumers and for committing/diffing. |
| `prismor policy edit` | `--workspace` | Interactive TUI to toggle rules on/off. |
| `prismor policy validate <file>` | — | Static-validate a policy YAML file. |
| `prismor policy test` | `--file` | Run declarative policy tests (falls back to the bundled OWASP LLM starter pack). Cases are `type: command`, `read`, `write`, or `tool` (with `tool`, `args`, `principal`, `resource` for [`when:` rules](attribute-conditions.md)); `fixtures:` and `expect: {principal: verdict}` matrices, `skip`. Flags: `--policy FILE`, `--filter PATTERN`, `--json`. |
| `prismor sandbox <status\|check\|on\|off\|run>` | `--workspace` | Docker-backed command sandbox: show config, check the backend, turn it on or off for this workspace, or run one command isolated. See [Docker sandbox](docker.md). |
| `prismor egress show` | `--workspace` | Effective network egress policy, its mode, and which layer (default / project / org) set it. See [Network Isolation](network-isolation.md). |
| `prismor egress report` | `--last N`, `--fail-on-block`, `--workspace` | Every destination recorded sessions actually contacted, with the verdict the current policy gives it. The on-ramp before flipping to enforce; `--fail-on-block` gates CI. |
| `prismor egress test <target>...` | `--agent <name>`, `--workspace` | Dry-run a URL, host, or whole shell command against the policy. Exit `1` if anything would be blocked. |
| `prismor egress allow <host>...` | `--reason`, `--workspace` | Add hosts, wildcards, IPs, or CIDRs to `settings.egress.allow` (`egress deny` / `egress rm` for the others). |
| `prismor egress mode <observe\|enforce>` | `--workspace` | Flip enforcement (`egress default <allow\|deny>` sets the no-match verdict; `egress enable` / `disable` toggle screening). |
| `prismor mirror on` | `--mode <enforce\|observe>`, `--agent <claude\|codex\|opencode\|claude-desktop>`, `--allow-tools`, `--workspace` | Serve `Bash`/`Read`/`Write`/`Edit`/`Glob`/`Grep`/`WebFetch` through Prismor instead of Claude Code's own: registers the `prismor-tools` MCP server and denies the native tools in `.claude/settings.json` (backups as `*.pre-mirror.bak`, nothing else touched). Also trusts the server for this project and carries your existing tool permissions onto the mirrored names — without those the agent boots with no tools at all. `--allow-tools` pre-allows the whole roster for headless runs. Verifies the server starts before denying anything. Takes effect on the next session. `--agent codex` and `--agent claude-desktop` wire those hosts machine-wide instead; the desktop app has no deny-list, so there the mirror adds governed tools without removing the app's own. Claude Code keeps its native `WebFetch` (already hook-screened, and it summarises the page); OpenCode's is disabled too, so a session started without plugins (`opencode --pure`) still fetches through Prismor. See [MCP Gateway](mcp-gateway.md#mirrored-built-ins---mirror-prismor-mirror). |
| `prismor mirror off` | `--workspace` | Undo exactly what `on` did — the agent uses its native tools again from the next session. |
| `prismor mirror status` | `--workspace` | Where the mirror is configured, whether it is governing / passing through / paused, its tool roster, live gateway processes. |
| `prismor mirror passthrough <on\|off>` | `--workspace` | Runtime switch, no restart: `on` runs mirrored built-ins ungoverned (logged, not blocked or redacted). `prismor pause` does the same for hooks + gateway together, with auto-resume. |
| `prismor mcp-gateway [serve]` | `--config` (default `~/.prismor/mcp-gateway.json`), `--upstream`, `--server name=<url\|command>`, `--mode <observe\|enforce>` (default observe), `--namespace <plain\|none>`, `--mirror`, `--workspace`, `--session-id`, `--identity-issuer`/`--identity-audience`/`--identity-jwks`/`--identity-mode`/`--identity-user-claim`/`--identity-team-claim`/`--identity-roles-claim` | One stdio MCP server in front of every server in `--config`. Each `tools/call` is policy-evaluated before it is forwarded, and each response is injection-scanned before the model sees it. Tools are namespaced `<server>__<tool>`. See [MCP Gateway](mcp-gateway.md). |
| `prismor mcp-gateway install` | `--all`, `--mode` (default enforce) | Move this workspace's `.mcp.json` servers behind the gateway (backup kept). The entry it writes pins `--mode enforce` unless you pass `--mode observe`. `--all` migrates every MCP config on the machine (Claude Desktop, Cursor, VS Code, …). `uninstall` restores the backup. |
| `prismor acp -- <agent command…>` | `--mode <enforce\|observe>` (default enforce), `--workspace`, `--no-audit` | Stdio proxy for Agent Client Protocol editors (Zed, JetBrains, CodeCompanion, agent-shell). Put it in front of the agent in the editor's `agent_servers` entry. It screens `terminal/create`, `fs/*` and `session/request_permission` before the editor carries them out, redacts and scans what comes back, resolves `@@SECRET:…@@` placeholders, and turns `step_up` into the editor's own permission prompt. Tools the agent runs in-process are audited after the fact but can only be enforced by its native hooks. See [ACP proxy](acp.md). |
| `prismor egress migrate` | `--workspace` | Convert a legacy warn-only `settings.egress_allowlist` into an enforceable `settings.egress`. |
| `prismor egress request <host>` | `--reason` (required), `--workspace` | Enrolled devices: ask your org's admins to allow a host. Lands in the console under Policy → Requests; approving adds it to the egress allowlist of the policy governing your device. See [Network Isolation](network-isolation.md#when-your-agent-is-blocked-request-access). |
| `prismor tags list` | `--last N`, `--workspace` | Tools seen in recent sessions + resolved tags + which tier resolved them (explicit / `_meta` / default / inference). See [Tool Tags](tool-tags.md). |
| `prismor tags set <tool> <tag>...` | `--workspace` | Tag a tool or glob in `.prismor/policy.yaml` (`tags rm` removes). |
| `prismor tags rules [add\|rm]` | `--workspace` | List, add, or remove tag-rule expressions, e.g. `"untrusted_content then critical_action -> block"`. Adds are parse-checked with caret diagnostics. |
| `prismor tags edit` | `--workspace` | Interactive wizard: tag tools, author rules, flip mode. |
| `prismor tags lint [file]` | `--workspace` | Validate every rule expression in a policy file. Exit `1` on errors. |
| `prismor tags test` | `--session <id>`, `--last N`, `--rule "<expr>"`, `--fail-on-hit` | Dry-run tag rules against recorded session logs: prints WOULD BLOCK / WOULD WARN per call, touches no enforcement state. `--rule` adds what-if candidates. |

### eval-server

| Command | Key flags | Description |
|---|---|---|
| `prismor eval-server` | `--port` (default 7071), `--host` (default 127.0.0.1), `--workspace`, `--api-key`, `--identity-issuer`/`--identity-audience`/`--identity-jwks`/`--identity-mode` ([identity verification](identity-verification.md)) | HTTP evaluation endpoint (`POST /v1/evaluate`) so non-Python adapters (Vercel AI SDK, anything HTTP) get the same policy pipeline. See [Frameworks overview](frameworks-overview.md) and [Vercel AI SDK](frameworks-vercel-ai.md). |

### proxy

| Command | Key flags | Description |
|---|---|---|
| `prismor proxy` | `--port` (default 7080), `--host` (default 127.0.0.1), `--mode <observe\|enforce>`, `--workspace`, `--config`, `--session-id`, `--agent-name`, `--judge typesafe\|prismor\|api\|claude\|codex`, `--judge-budget-ms` | The LLM lane: sits in front of Anthropic, OpenAI-compatible and Google Gen AI endpoints so an agent Prismor cannot hook is still governed. Point the client at it with `ANTHROPIC_BASE_URL`, `OPENAI_BASE_URL`, or `genai.Client(http_options=types.HttpOptions(base_url=...))` — nothing else about the agent changes. The outbound prompt is screened and cloak-masked; every proposed tool call (`tool_use` / `tool_calls` / `functionCall`) is reshaped into the event a `Bash` hook produces and run through the same policy; streamed tool calls are held until they can be judged. See [LLM proxy](llm-proxy.md). |

### elevenlabs

| Command | Key flags | Description |
|---|---|---|
| `prismor elevenlabs status` | — | Every agent in the ElevenLabs workspace: its LLM, whether `prismor proxy` governs it, and whether a backup LLM could route around it. Reads `ELEVENLABS_API_KEY`. |
| `prismor elevenlabs connect` | `<agent_id>…` or `--all`, `--proxy-url` (public https; env `PRISMOR_PROXY_PUBLIC_URL`), `--model` (default `gpt-5.6-luna`), `--upstream` (default `openai`), `--config`, `--turn-timeout` (default 8s), `--refusal-text`, `--sequential-screening`, `--keep-backup-llm` | Point agents' Custom LLM at the proxy with a per-agent virtual key (stored as an ElevenLabs workspace secret, with `body` rules that adapt ElevenLabs' request to the model), disable the backup LLM, and thread each call into one Prismor session. Re-run with a new URL to re-point. Restart the proxy afterwards. See [ElevenLabs](elevenlabs.md). |
| `prismor elevenlabs disconnect` | `<agent_id>…` or `--all`, `--config` | Restore the LLM settings `connect` replaced, delete the secret, drop the virtual key. |

### inference-hook

| Command | Key flags | Description |
|---|---|---|
| `prismor inference-hook serve` | `--host`, `--port` (7072), `--signing-secret`, `--previous-signing-secret`, `--fail-open`, `--mode enforce|observe|shadow`, `--allow-unsigned`, `--api-key`, `--config`, `--workspace`, `-v` | Run the AI security server for [Claude Inference Hooks](inference-hook.md): Anthropic POSTs each governed prompt (claude.ai, Claude Code, Cowork) as a signed frame; Prismor evaluates the transcript and returns `{action: allow|deny}`. Fail-closed by default; any path is the endpoint; `GET /health`. |
| `prismor inference-hook test` | `--url`, `--secret`, `--sample clean|pci|secret|injection|config-test|all`, `--frame file.json`, `--unsigned`, `--bearer`, `--expect`, `--json` | Send Standard-Webhooks-signed sample frames to a server (or evaluate in-process with no `--url`) and print the verdicts. Exit 0 allow · 1 deny · 2 error/mismatch. |
| `prismor inference-hook secret` | — | Print a fresh `whsec_` secret for local end-to-end runs. |

`prismor inference-hook-server` remains as an alias for `serve`.

Full policy model, rule schema, and the default rule list: [Prismor](prismor-runtime.md).

---

## Visibility

| Command | Key flags | Description |
|---|---|---|
| `prismor audit` | `--fix`, `--json`, `--workspace` | Posture audit across hooks, policy, cloak, permissions, feed, network, supply chain. `--fix` applies safe remediations. |
| `prismor audit judge` | `--since 24h`, `--sample 0.05`, `--max 50`, `--dry-run`, `--json`, `--workspace` | Has the configured LLM judge review a deterministic sample of tool calls the rules ALLOWED, after the fact, from the local store. Results go to the `judge_audit` table; flagged calls are printed and sent as one content-free `judge_audit` record each. Never blocks. Exits 2 when no judge is configured. See [Semantic Guard](semantic-guard.md#auditing-allowed-calls). |
| `prismor aibom` | `--format <cyclonedx\|markdown>`, `-o FILE`, `--workspace` | AI bill of materials as CycloneDX 1.6: agents (and whether Prismor governs them), models used in the last 30 days, MCP servers, plugins, skills, third-party hooks and instruction files, with SHA-256, origin, capabilities and drift (`new`/`changed`/`approved`). Leaves out credentials, contents and prompts; paths are home-relative and URLs redacted, so it can be shared. |
| `prismor scan` | `--agent`, `--scope <all\|project\|user>`, `--json`, `--workspace` | Scan installed MCP servers and skills for dangerous patterns. See [Skill Scanner](skill-scanner.md). |
| `prismor extensions [list\|why\|approve\|wrap-hooks\|unwrap-hooks]` | `--kind`, `--json`, `--workspace` | Inventory of skills, plugins, third-party hooks and MCP servers with origin, installer, capabilities and the documents they caused to be fetched. See [Extension Ledger](extensions.md). |
| `prismor skills audit` | `--json`, `--workspace` | Scan every installed `SKILL.md`: what it instructs, its TOFU baseline, remote fetches. Exit `1` if a skill is new, changed or flagged. The `immunity-agent` skill that setup installs shows as `bundled` while it matches the packaged copy. |
| `prismor skills approve <file>` | `--workspace` | Accept a new or changed skill after you have reviewed it. |
| `prismor memory <status\|trust\|verify\|scan\|approve\|sign\|unsign>` | — | Instruction-file integrity for CLAUDE.md, AGENTS.md and friends: TOFU baselines (`trust`, `approve` after a reviewed change), read-only `verify`, content `scan` for memory-poisoning directives, and Ed25519 `sign`/`unsign` (requires `PRISMOR_MEMORY_SIGNED_MODE=1`). See [Memory integrity](memory-integrity.md). |
| `prismor deps` | `--json`, `--workspace`, `--offline` | Match exact dependency versions against OSV.dev, the signed advisory feed and the bundled IOC list, plus lockfile integrity. `--offline` skips OSV. See [Supply Chain](supply-chain.md). |
| `prismor analyze [FILE]` | `--input`, `--json`, `--sarif` | Run the engine over a JSONL session (or the most recent one). SARIF output feeds GitHub Code Scanning. |
| `prismor analyze-history` | `--agent`, `--since`, `--max-events`, `--no-persist`, `--strict`, `--semantic`, `--json` | Sweep this machine for agent transcripts, replay them through the live policy engine, and report what the current policy **would have blocked** vs warned. Backfills the dashboard with history from before install. `--strict` exits non-zero if a non-empty transcript yields no events; `--semantic` re-enables the semantic guard (off during sweeps so it can't fire an LLM call per event across all history). See [Transcript Ingest](transcript-ingest.md). |
| `prismor analyze-history --coverage` | `--json` | Show sessions that ran with no live Prismor record — activity that executed ungoverned. |
| `prismor analyze-history --show <rule>` | — | List the individual tool calls behind one rule id. |
| `prismor analyze-history --export-corpus <dir>` | — | Write redacted, labelled rule fixtures (positives + negatives) from real usage. |
| `prismor sessions` | `--findings-only`, `--global`, `--limit`, `--json`, `--shared` | List stored sessions, optionally only flagged ones, optionally across all workspaces. `--shared` lists sessions teammates shared with you (needs `prismor login`). |
| `prismor session <id>` | `--json`, `--changes`, `--remote`, `--limit` | Drill into one session's tool-call trace + findings. `--changes` lists the files it wrote (as diffs), the commands it ran, and a drafted PR description. `--remote` reads the session from your org's console (implied by a pasted link); `--limit N` caps it to the last N events (default 400). See [Dev insights](dev-insights.md). |
| `prismor session share [SESSION]` | `--org`, `--with <emails>`, `--public` | Share a session (default: this workspace's latest) as a console link. `--org` lets anyone in your org open it, `--with` adds named teammates, `--public` makes it readable by anyone with the link without sign-in. `--public` is for you to run, not your agent. Needs `prismor login`. |
| `prismor rca [session]` | `--workspace`, `--json` | What went wrong in a session (default: the latest): the first failure with the calls before it, retry loops, reverted edits. See [Dev insights](dev-insights.md). |
| `prismor blame <path[:line]>` | `--workspace`, `--json` | Which agent session wrote this file or line, and what that session was asked. |
| `prismor friction` | `--days`, `--all`, `--workspace`, `--json` | Failures that recur across sessions, grouped by command and printed as AGENTS.md lines. |
| `prismor tokens` | `--session ID`, `--hours N` (default 24), `--all`, `--workspace`, `--json` | Token usage and where it is going; `--session` gives one session's usage and estimated cost (Claude Code, Codex). |
| `prismor trail verify` | `--pubkey`, `--json` | Verify the signed audit trail end-to-end: recompute hashes, prev-hash linkage, seq gaps, Ed25519 signatures. Exit non-zero on anything but a clean chain. See [Signed Audit Trail](audit-trail.md). |
| `prismor trail show` | `--last N` | Render recent audit-trail records (verdict, agent, tool, input). |
| `prismor trail checkpoint` | `--out FILE` | Export a signed chain-head checkpoint for anchoring outside the machine. |
| `prismor attest` | `--out FILE`, `--workspace` | Build an evidence bundle (Ed25519-signed when `prismor[signing]` is installed; unsigned otherwise, and `attest verify` then fails): posture findings, agent inventory, and the trail anchor in one file. See [Attestation Bundle](attestation-bundle.md). |
| `prismor attest verify <bundle>` | `--pubkey`, `--json` | Re-verify a bundle's content hash and signature. `--pubkey` pins an out-of-band signer key. Exit non-zero on failure. |
| `prismor attest coverage` | `--json`, `--workspace` | Show which compliance-framework controls the active policy covers (OWASP LLM/Agentic, NIST AI RMF, EU AI Act). |
| `prismor discover [all\|agents\|mcp\|keys]` | `--fix`, `--yes`, `--fix-mode`, `--json`, `--report`, `--no-file-scan`, `--fail-on-shadow`, `--workspace` | Sweep this host for the AI surface running outside Prismor's coverage (shadow AI): agents without hooks, MCP servers not routed through the gateway, and provider keys not registered with Cloak. Ends with a coverage score. Pass a section to limit the report; `--fail-on-shadow` exits 1 for CI; `--report` sends the inventory to your organization console for the fleet-wide Shadow AI view (enrolled devices only, and a no-op otherwise). `--fix` governs what it found — hooks the unmanaged agents, moves MCP servers behind the gateway (any config declaring `mcpServers`/`servers`, not just the workspace's), imports dotenv keys into Cloak — printing the plan and asking first (`--yes` to skip the prompt, `--fix-mode enforce` to install in enforce). Without `--fix` it is read-only; credential-shaped values in MCP URLs and argv are redacted before they reach output. On an enrolled device each reported finding also carries whether it is fixable and the command that fixes it, so the console can show what is actionable today. See [Host discovery](attestation-bundle.md#host-discovery). |
| `prismor status --all` | `--days N` | Terminal overview of every registered workspace. See [Dashboard](dashboard.md). |
| `prismor dashboard` | `--port`, `--host`, `--no-open` | Local web dashboard at `http://127.0.0.1:7070` (opens a browser tab). See [Dashboard](dashboard.md). |
| `prismor query "SQL"` | `--schema`, `--path`, `--workspace`, `--limit`, `--format json\|jsonl\|table` | Read-only SQL over the local session store (SELECT/WITH/EXPLAIN only, output redacted). See [Query your data](query-your-data.md). |
| `prismor docs [NAME]` | | Print a bundled doc page in the terminal, or list them. |
| `prismor serve` | `--port`, `--host`, `--no-open` | _Deprecated_ alias of `dashboard --no-open` (headless server only). |

---

## Secret prevention

| Command | Key flags | Description |
|---|---|---|
| `prismor cloak install` | `--scope`, `--no-userprompt-guard`, `--no-secret-guard`, `--no-read-guard`, `--no-env-guard`, `--sweep-on-stop` | Install cloaking hooks so real secrets stay out of model context. `--no-read-guard` skips the hook that denies reading files containing a registered secret; `--no-env-guard` skips the one that denies reading `.env`-style files not yet imported with `prismor cloak add --env-file`. |
| `prismor cloak add <name>` | `--from-file` | Register a secret under a placeholder. Value read from stdin / hidden prompt — never argv. |
| `prismor cloak add --env-file .env` | — | Import every `KEY=VALUE` entry from a dotenv file as `@@SECRET:KEY@@`. |
| `prismor cloak list` | — | List registered placeholder names (never values). |
| `prismor cloak remove <name>` | — | Delete a registered secret. |
| `prismor cloak status` | `--scope` | Show whether cloaking hooks are installed + secret count. |
| `prismor cloak run -- <command>` | — | Run a command with `@@SECRET:name@@` placeholders resolved locally and stdout/stderr scrubbed. Use this for Codex, whose hooks are block-only. |
| `prismor cloak pattern <list\|add\|remove>` | — | Manage the secret-detection regexes. |
| `prismor sweep` | `--redact`, `--clean`, `--restore`, `--show-vault`, `--purge` | Find secrets already leaked into AI tool configs and vault/redact them. |

Design, setup, best practices, and threat model: [Sweep & Cloak](sweep-and-cloak.md).

---

## Identity & scoping

| Command | Key flags | Description |
|---|---|---|
| `prismor iam init` | `--scope <global\|project>` | Scaffold an `iam.yaml` of agent identities. |
| `prismor iam list` | — | List defined identities; marks the active `PRISMOR_AGENT_ID`. |
| `prismor iam show <agent>` | — | Show one identity's permission profile. |
| `prismor iam check <agent> --value "<v>"` | `--type <command\|read\|write\|network>` | Test whether an identity may perform an action. |
| `prismor scope show [id\|latest]` | — | Show session-scoped rules (all, or one session; `latest` or a unique id prefix). |
| `prismor scope list` | — | List sessions with active scoped rules. |
| `prismor scope edit <id\|latest>` | — | Edit a session's scoped rules in `$EDITOR` (freezes auto-widening for that session). |
| `prismor scope clear <id>` | — | Remove a session's scoped rules. |
| `prismor agents list` | — | List every named agent instance seen (the adapter's `name=`), with framework + control state. |
| `prismor agents show <name>` | — | Show one named agent's control settings (enabled, mode, IAM profile, last seen). |
| `prismor agents set <name>` | `--enabled/--disabled`, `--mode <observe\|enforce>`, `--iam-profile <p>` | Per-agent runtime control: kill-switch, mode override, forced IAM profile. Config lives in `agents.yaml`. |
| `prismor canary plant <path>` | `--type <aws\|ssh\|env\|generic>`, `--webhook`, `--force` | Plant a honeytoken credential tripwire. |
| `prismor canary list` | — | List planted canaries (markers redacted). |
| `prismor canary status` | — | Summary of canaries by type. |
| `prismor canary remove <id\|path>` | — | Remove a canary. |

Deep dives: [IAM](iam.md) · [Scoped Agent](scoped-agent.md) · [Canary](canary.md).

---

## Adaptive defense

| Command | Key flags | Description |
|---|---|---|
| `prismor learn` | `--min-support`, `--fp-threshold`, `--json` | Mine session history for repeated blocked / near-miss patterns and propose new rules. |
| `prismor learn --candidates` | — | List pending candidate rules. |
| `prismor learn --apply <id>` | — | Accept a candidate into project policy. |
| `prismor learn --reject <id>` | — | Reject a candidate. |

Deep dive: [Learning](learning.md).

---

## Enterprise / org

| Command | Key flags | Description |
|---|---|---|
| `prismor enroll <token>` | `--token`, `--token-file`, `--label`, `--api-base` | Exchange a single-use org token (minted in the dashboard) for this machine's device identity; pulls the signed org policy. `--token-file` (or `$PRISMOR_ENROLL_TOKEN`) keeps a fleet token out of `ps` and shell history. |
| `prismor enroll-status` | — | Show enrollment state, device label, and the applied policy version. Exits 1 when the machine is not enrolled or its key was revoked or refused, so an MDM compliance script can use it; an unreachable control plane still exits 0. |
| `prismor workspace [managed\|personal\|auto]` | — | With no argument, shows whether this workspace is org-managed (org policy + telemetry) or personal (local-only). Pass `managed`/`personal`/`auto` to set it. Org-claimed repos can't be downgraded, and `personal` is ignored entirely when the org policy sets `allow_personal_workspaces: false`. |
| `prismor exempt request` | `--reason` | Ask an org admin to relax specific non-floor rules for this repo; served back in the signed policy. |
| `prismor logout` | — | Un-enroll: removes the device identity and cached remote policy. Local protection stays on. |

Deep dive: [Connecting to the platform](connecting-to-the-platform.md) · [Policy layers & exemptions](policy-layers-and-exemptions.md).

---

## Supply chain

| Command | Description |
|---|---|
| `prismor supplychain npm install <pkg>` | Score `<pkg>` (age, maintainers, install scripts, IOC match) and block if dangerous before npm runs. |
| `prismor supplychain pip install <pkg>` | Same gate for PyPI. |
| `prismor supplychain <pnpm\|yarn\|uv\|cargo\|go\|gem\|bundle\|composer\|mvn> …` | Same gate per ecosystem (`gem install`, `bundle add`, `composer require`, `mvn dependency:get`). Non-install commands pass through transparently. |
| `prismor supplychain harden [--dry-run] [PATH]` | Write hardening settings into package-manager configs: npm `ignore-scripts`, `save-exact`, `audit`; Yarn `--ignore-scripts` / `enableScripts: false`; pip `no-input`; Cargo `[net]` retry and `git-fetch-with-cli`. |

Scoring table, IOC feed, ecosystem support: [Supply Chain](supply-chain.md).

---

## Environment variables

| Variable | Used by | Effect |
|---|---|---|
| `PRISMOR_MODE` | `setup --non-interactive` | Default enforcement mode (`observe` / `enforce`). |
| `PRISMOR_HOOK_REQUIRED` | a `--portable` hook | When set, a hook that cannot find `prismor` blocks the tool call instead of warning and allowing. Set it on hosted agent environments. |
| `PRISMOR_CLOAK` | `setup --non-interactive` | Enable cloaking (`1`/`true`/`yes`/`on`). |
| `PRISMOR_WORKSPACE` | all commands | Override the resolved workspace path. |
| `PRISMOR_AGENT_ID` | `iam` | Active agent identity for IAM enforcement. See [IAM](iam.md). |
| `PRISMOR_ENVIRONMENT` | telemetry | Deployment environment label on every event (`prod`, `staging`, `ci`...). Lowercase `[a-z0-9_-]`, max 40; invalid values are dropped. |
| `PRISMOR_RELEASE` | telemetry | Agent release label on every event (git sha, app version). Printable, no whitespace, max 64; invalid values are dropped. |
| `PRISMOR_APPROVAL_WAIT` | hooks (Claude Code, Codex) | Seconds a blocked call waits for `prismor approvals approve` before it is denied (max 45, default 0). |
| `PRISMOR_SWEEP_PASS` | `sweep` | Vault passphrase for non-interactive runs. |
| `EDITOR` | `scope edit` | Editor for scoped-rule editing. |

---

## See also

- [Governance surfaces](governance-surfaces.md) — hooks vs the MCP mirror, per agent

- [Prismor](prismor-runtime.md) — policy engine, session logs, audit, modes
- [Supply Chain](supply-chain.md) — install-time enforcement and scoring
- [Network Isolation](network-isolation.md) — egress allowlists, raw-IP detection
- [Skill Scanner](skill-scanner.md) — MCP + skill risk scanning
- [Sweep & Cloak](sweep-and-cloak.md) — secret prevention
- [Semantic Guard](semantic-guard.md) — LLM-assisted injection defense
- [Canary](canary.md) · [IAM](iam.md) · [Scoped Agent](scoped-agent.md) · [Learning](learning.md) · [Dashboard](dashboard.md)
- [Docker & Containers](docker.md) · [Architecture](architecture.md)
