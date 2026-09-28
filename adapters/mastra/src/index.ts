/**
 * Prismor adapter for Mastra (TypeScript).
 *
 * Wraps a tool's `execute` function directly so every call is evaluated by
 * the Prismor eval-server (`prismor eval-server`) before the tool body
 * runs. A denied call throws PrismorBlocked; Mastra's tool-execution step
 * catches the thrown error and feeds it back to the model as the tool's
 * result, so the conversation continues with the denial visible. A thin
 * wrapper over prismor-sdk's PrismorClient.
 *
 * WHY NOT `processOutputStep`: Mastra's own type docs describe
 * `processOutputStep` as running "after each LLM response, before tool
 * execution," with an injected `abort()` to deny. This was tried first and
 * is **not reliable** in `@mastra/core` as tested (2026-07, v0.x): calling
 * `abort()` from `processOutputStep` throws a workflow-level error, but the
 * tool's `execute` function still runs anyway — confirmed with timestamped
 * logging showing `execute` firing after `abort()` was called. Wrapping
 * `execute` directly, the same pattern the CrewAI/LangChain adapters use,
 * is what actually prevents the tool body from running, verified live.
 *
 * Quick start:
 *   const agent = new Agent({
 *     name: "ops", model: openai("gpt-4o-mini"),
 *     tools: { run_shell: prismorTool("run_shell", runShell, { mode: "enforce" }) },
 *   });
 */
import { PrismorClient, PrismorBlocked, useSubject } from "prismor-sdk";
import type { PrismorClientOptions, PrismorDecision } from "prismor-sdk";

export { PrismorBlocked, PrismorClient, useSubject };
export type { PrismorDecision };

/**
 * Options for the Mastra wrapper: every PrismorClient option (evalUrl, apiKey,
 * subject, failMode, timeoutMs, workspace, agentName, eventType, sessionId,
 * budget, onPolicyBlock, raiseOnBlock, …). `agent` defaults to "mastra" and
 * `mode` to "enforce".
 */
export type PrismorMastraOptions = PrismorClientOptions;

/**
 * Wrap a single Mastra tool (the object returned by `createTool({...})`) so
 * every call to its `execute` function is evaluated by Prismor first. A
 * denied call throws `PrismorBlocked`, which Mastra's tool-execution step
 * catches and feeds back to the model as the tool's result.
 */
export function prismorTool<T extends { execute?: (...args: any[]) => any }>(
  toolName: string,
  tool: T,
  opts: PrismorMastraOptions = {},
): T {
  if (!tool.execute || (tool as any).__prismor_guarded__) return tool;
  // enforce stays this package's default: it shipped that way, and moving an
  // existing user from blocking to logging is not a refactor's call to make.
  const client = new PrismorClient({
    ...opts,
    agent: opts.agent ?? "mastra",
    mode: opts.mode ?? "enforce",
  });
  return {
    ...tool,
    execute: client.guard(tool.execute.bind(tool), { toolName }),
    __prismor_guarded__: true,
  } as T;
}

/** Wrap every tool in a record — mirrors the Python adapters' guard_tools([...]). */
export function prismorTools<T extends Record<string, { execute?: (...args: any[]) => any }>>(
  tools: T,
  opts: PrismorMastraOptions = {},
): T {
  return Object.fromEntries(
    Object.entries(tools).map(([name, t]) => [name, prismorTool(name, t, opts)]),
  ) as T;
}
