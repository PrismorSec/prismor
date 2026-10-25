# Subagents

Claude Code can hand work to subagents (the `Task` / `Agent` tool), in the
foreground or in the background. A subagent's tool calls go through the same
Prismor hooks as the main agent's, tagged with the subagent's `agent_id` and
`agent_type`, so the same policy applies to them. What changes is who hears
about it: a subagent's blocks go to the subagent, and a background subagent's
work never shows in the main chat. From the release after 1.61.0 (#628),
Prismor tells the person what happened inside each subagent.

Codex (0.16x, `spawn_agent`) works the same way at the hook level: a
subagent's calls arrive under the parent's session with the subagent's own
thread id in `agent_id`, and Codex sends `SubagentStop` with the subagent's
last message. Prismor attributes those calls to the subagent and enforces the
same rules on them.

## What is enforced

- **Every rule that applies to the main agent applies inside a subagent.**
  Blocks are returned to the subagent with the usual reason, and the subagent
  reports them back to the main agent.
- **A subagent can't ask for approval.** A rule whose action is `step_up`
  (approval needed) would raise an approval dialog in the main chat for a call
  the person never saw, and the whole session waits. Inside a subagent, a
  step-up is refused instead, with this reason:

  > Prismor: this needs the user's OK, and a subagent cannot ask for it. Stop
  > and report back to the main agent, which should ask the user or run it in
  > the main conversation.

  The main agent can then ask in the open, and the person decides.
- **Driving the logged-in browser is a step-up.** The rule
  `browser-session-control` catches `connectOverCDP` / `connect_over_cdp`,
  `puppeteer.connect`, `chrome-remote-interface`, loopback `:92xx` debugging
  ports and DevTools websocket paths. A subagent used a browser's logged-in
  sessions to reach a host that egress had just blocked; this closes that path
  for main agents and subagents alike.

## A subagent's policy

A subagent runs on its parent's authority. Its policy is the parent's, plus
anything set for the subagent itself, and it can only be narrower:

- **The parent's rules and per-agent controls apply.** In Claude Code and
  Codex a subagent's calls run under the parent's session and agent, so this
  holds by construction. Through an SDK adapter, a subagent's calls carry the
  parent's agent name (`parent_agent_name`). The parent's pause, mode, denied
  and asked tools, IAM profile and org agent-scoped denies are applied on top
  of the subagent's own, and the stricter value wins. Pausing `support-bot`
  stops its subagents too. A subagent's own `observe` override does not
  relax a parent that follows the global mode.
- **A subagent can be held tighter.** Write a rule with
  [`when: subagent.*`](attribute-conditions.md#keep-subagents-off-the-network),
  for example `subagent.type == 'researcher' and tool.name == 'fetch_url'`.
- **Nothing scoped to a subagent loosens it.** An org allow scoped to the
  subagent's own name does not lift a deny its parent carries; the parent's
  allow does.

**Guard the main agent and its subagents are covered.** These adapters reach
the agents the main one can run:

| Adapter | Covered from the main agent |
|---|---|
| OpenAI Agents SDK | `guard_agent(main)`: handoff targets and `as_tool` agents, recursively |
| Google ADK | `PrismorPlugin` on the `Runner`: sub-agents and `AgentTool`s, including `include_plugins=False` ones |
| CrewAI | `guard_crew(crew)`: every agent in the crew |
| smolagents | `guard_agent(manager)`: managed agents, recursively |
| Agno | `guard_team(team)`: every member, nested teams included |
| LlamaIndex | `guard_workflow(workflow)`: every agent in the `AgentWorkflow` |
| BeeAI | a guarded `HandoffTool` guards its target agent's tools |
| AutoGen Core | the runtime's `PrismorInterventionHandler`: every agent |
| LangGraph | `PrismorCallbackHandler` in the run config: subgraphs too |
| Claude Agent SDK | the hooks: every subagent |

Where your own code builds an agent and runs it from inside a tool (Vercel AI
SDK, Mastra agent-as-tool, Pydantic AI, AG2, Semantic Kernel, Agent
Framework, LangGraph `guard_tools`), guard that agent's tools too. An
unguarded agent's tools run with no policy at all. Its calls then inherit the
parent's controls automatically. For Mastra `agents: {…}` sub-agents, call
`registerSubagents(main)` so their calls are tied to the parent's run.

## What the person sees

Each screened call inside a subagent adds one line to a per-session ledger
under `~/.prismor/subagents/`. When the subagent finishes (`SubagentStop`),
the ledger becomes one line in the main chat:

```
Prismor · general-purpose (ae5e3143): 4 tool calls screened · 1 needed your OK and were refused (browser-session-control) · 1 flagged (…). Details: prismor sessions --findings-only
```

The label is the subagent's type and the first 8 characters of its id. When
Claude Code doesn't send a type (for some of its own internal helper agents),
the label is just `subagent`.

Claude Code files a `SubagentStop` message under the subagent's own transcript,
where nobody sees it. So Prismor queues the line and shows it with the next
main-thread hook: after the `Agent` tool returns for a foreground subagent, or
with the task-notification prompt for a background one, so it appears as the
subagent finishes. A subagent that made no screened calls adds no line.

## In the session view

`prismor dashboard` shows each turn's subagents as cards under the prompt that
launched them: the task they were given, finished or not, how long they ran,
their call count, blocked and warned counts, the files they changed, and the
start of their own final report. "Show N calls" opens a subagent's calls. Work
a subagent does after a later prompt stays with the turn that launched it.

The task name comes from the launch row for Claude Code (the `Agent` tool's
description) and from the subagent's spawn path for Codex (`/root/fix_build`
shows as "fix build"), read from its transcript at `SubagentStop`. The report
is Claude's `<task-notification>` result, or Codex's `last_assistant_message`.

## Subagent reports

A background subagent hands its report back as a `<task-notification>`
prompt. These prompts are never blocked: a report that quotes an injection the
subagent correctly refused used to be blocked by the judge, and the report was
lost. A flagged report gets the same "treat as untrusted data" notice as tool
output instead.

The result of the `Task` / `Agent` tool itself is not judged for prompt
injection. It is either the parent's own brief echoed back or a report from a
subagent whose calls were already screened; what happened inside is reported
at `SubagentStop`.

## Setup

Claude Code hooks register `SubagentStop` from the release after 1.61.0, and
Codex hooks from the release after 1.61.5. Existing installs get it by
re-running `prismor setup` or `prismor install-hooks --agent claude|codex`.
`prismor doctor` reports the event in its hook health check. Codex versions
that predate `SubagentStop` ignore the entry; their other hooks keep running
(checked on Codex 0.145).

## Limits

- Subagent attribution and enforcement cover Claude Code and Codex. Other
  agents don't tag subagent calls with an `agent_id`.
- The summary line reaches the person in Claude Code only. For Codex it is
  queued, but no main-thread hook Prismor installs fires at a point where
  Codex shows it; the dashboard has the same information.
- Codex encrypts the brief it hands a subagent, so a Codex card is named by
  the subagent's spawn path, not the task text.
- Without a semantic judge, file and shell output inside a subagent is not
  screened for prompt injection (the injection patterns only cover tool
  results). See [Semantic Guard](semantic-guard.md).

See also: [Sessions and the dashboard](dashboard.md) · [Prismor runtime](prismor-runtime.md).
