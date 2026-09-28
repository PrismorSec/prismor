/**
 * Prismor adapter for the Vercel AI SDK (and LangChain JS / LangGraph JS).
 *
 * A thin wrapper over prismor-sdk's PrismorClient: wraps a tool's `execute`
 * (or a LangChain tool's `invoke`) so the Prismor eval-server
 * (`prismor eval-server`) evaluates every call before the tool body runs. A
 * denied call throws PrismorBlocked by default; pass `onPolicyBlock` to hand
 * the model something else instead, or `raiseOnBlock: false` for the denial
 * string. Results are masked through the eval-server before the model sees
 * them.
 *
 * Quick start:
 *   const tools = prismorTools({ run_shell, search_web });
 *   // in your request handler — attribute every tool call to the caller:
 *   await useSubject(`user:${userId}`, () =>
 *     generateText({ model, tools, prompt }));
 */
import { PrismorClient, PrismorBlocked, useSubject } from "prismor-sdk";
import type { PrismorClientOptions, PrismorDecision } from "prismor-sdk";

export { PrismorBlocked, PrismorClient, useSubject };
export type { PrismorDecision };

/**
 * Options for the wrappers: every PrismorClient option (evalUrl, apiKey,
 * subject, mode, failMode, timeoutMs, workspace, agentName, eventType,
 * sessionId, budget, onPolicyBlock, raiseOnBlock, …). `agent` defaults to
 * "vercel-ai" and `mode` to "observe".
 */
export type PrismorOptions = PrismorClientOptions;

/** One client per wrapped tool, so each tool keeps its own session id unless `sessionId` is passed. */
function clientFor(opts: PrismorOptions): PrismorClient {
  return new PrismorClient({ ...opts, agent: opts.agent ?? "vercel-ai" });
}

/**
 * Wrap a single Vercel AI SDK tool so every call is evaluated by Prismor
 * before the tool body executes.
 *
 * @param toolName  The key name under which this tool is registered (used in telemetry).
 * @param tool      The tool object returned by the `tool()` helper.
 * @param opts      Prismor options (evalUrl, subject, mode, failMode, …).
 */
export function prismorTool<
  T extends { execute?: (...args: any[]) => any },
>(toolName: string, tool: T, opts: PrismorOptions = {}): T {
  if (!tool.execute) return tool;
  return { ...tool, execute: clientFor(opts).guard(tool.execute, { toolName }) } as T;
}

/**
 * Wrap every tool in a record — the idiomatic Vercel AI SDK pattern.
 *
 * @example
 * const tools = prismorTools({ run_shell, search_web });
 * await useSubject(`user:${userId}`, () =>
 *   generateText({ model, tools, prompt }));
 */
export function prismorTools<
  T extends Record<string, { execute?: (...args: any[]) => any }>,
>(tools: T, opts: PrismorOptions = {}): T {
  return Object.fromEntries(
    Object.entries(tools).map(([name, t]) => [name, prismorTool(name, t, opts)]),
  ) as T;
}

// ── LangChain JS / LangGraph JS ──────────────────────────────────────────────

/** A LangChain JS StructuredTool-like object (also what LangGraph's ToolNode calls). */
interface LangChainToolLike {
  name?: string;
  invoke: (input: any, config?: any) => any;
}

/** Extract the argument record from a ToolNode-style ToolCall or raw args input. */
function langChainArgs(input: any): Record<string, unknown> {
  if (input && typeof input === "object") {
    // LangGraph's ToolNode invokes tools with the full ToolCall object
    // ({ name, args, id, type: "tool_call" }); direct callers pass raw args.
    if (input.type === "tool_call" && typeof input.args === "object" && input.args !== null) {
      return input.args as Record<string, unknown>;
    }
    return input as Record<string, unknown>;
  }
  return { input };
}

/**
 * Guard a LangChain JS / LangGraph JS tool so every `invoke()` is evaluated by
 * Prismor first. Works on anything StructuredTool-shaped — `tool(fn, {...})`
 * from `@langchain/core/tools`, and therefore the tools LangGraph's
 * `createReactAgent` / `ToolNode` execute. The same tool object is returned
 * with its `invoke` wrapped in place, so graphs already holding a reference
 * are covered too.
 *
 * A denied call throws PrismorBlocked. LangGraph's ToolNode catches tool
 * errors by default (`handleToolErrors: true`) and feeds the message back to
 * the model as a ToolMessage, so the run recovers gracefully.
 */
export function prismorLangChainTool<T extends LangChainToolLike>(
  tool: T,
  opts: PrismorOptions = {},
): T {
  if ((tool as any).__prismor_guarded__) return tool;
  (tool as any).invoke = clientFor(opts).guard(tool.invoke.bind(tool), {
    toolName: tool.name || "tool",
    args: langChainArgs,
  });
  (tool as any).__prismor_guarded__ = true;
  return tool;
}

/**
 * Guard a list of LangChain JS / LangGraph JS tools in one call — mirrors the
 * Python adapters' `guard_tools([...])`. Returns the same array.
 *
 * @example
 * import { prismorLangChainTools, useSubject } from "prismor-warden";
 * const tools = prismorLangChainTools([run_shell, fetch_url]);
 * const agent = createReactAgent({ llm, tools });
 * await useSubject(`user:${userId}`, () => agent.invoke({ messages }));
 */
export function prismorLangChainTools<T extends LangChainToolLike>(
  tools: T[],
  opts: PrismorOptions = {},
): T[] {
  return tools.map((t) => prismorLangChainTool(t, opts));
}
