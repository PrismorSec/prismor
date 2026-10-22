/**
 * Prismor adapter for Mastra (TypeScript).
 *
 * Wraps a tool's `execute` function directly so every call is evaluated by
 * the Prismor eval-server (`prismor eval-server`) before the tool body
 * runs. A denied call throws PrismorBlocked; Mastra's tool-execution step
 * catches the thrown error and feeds it back to the model as the tool's
 * result, so the conversation continues with the denial visible.
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

export interface PrismorMastraOptions {
  /** URL of the running eval-server. Default: http://127.0.0.1:7071 */
  evalUrl?: string;
  /** Bearer token sent as `Authorization` to the eval-server. Default: PRISMOR_EVAL_KEY env var. */
  apiKey?: string;
  /** Subject for per-user attribution: "user:alice". Default: PRISMOR_SUBJECT env var. */
  subject?: string;
  /** "enforce" blocks denied calls; "observe" logs only. Default: "enforce" */
  mode?: "enforce" | "observe";
  /** What to do when the eval-server cannot answer. Default: "closed" in enforce, "open" in observe. */
  failMode?: "open" | "closed";
  /** Max milliseconds to wait for the eval-server. Default: 10000 */
  timeoutMs?: number;
  /** Workspace path forwarded to the policy engine. Default: process.cwd() */
  workspace?: string;
  /** Framework identifier for telemetry. Default: "mastra" */
  agent?: string;
  /** Per-instance agent name for the console's per-agent row and controls. Example: "support-bot". */
  agentName?: string;
}

interface PrismorDecision {
  allow: boolean;
  reason: string | null;
}

export class PrismorBlocked extends Error {
  constructor(reason: string) {
    super(`⛔ Prismor blocked this tool call: ${reason}`);
    this.name = "PrismorBlocked";
  }
}

const FAIL_OPEN: PrismorDecision = { allow: true, reason: null };

function resolveOpts(opts: PrismorMastraOptions): Required<PrismorMastraOptions> {
  const mode = opts.mode ?? "enforce";
  return {
    evalUrl: opts.evalUrl ?? "http://127.0.0.1:7071",
    apiKey: opts.apiKey ?? (typeof process !== "undefined" ? process.env.PRISMOR_EVAL_KEY ?? "" : ""),
    subject: opts.subject ?? (typeof process !== "undefined" ? process.env.PRISMOR_SUBJECT ?? "" : ""),
    mode,
    failMode: opts.failMode ?? (mode === "enforce" ? "closed" : "open"),
    timeoutMs: opts.timeoutMs ?? 10_000,
    workspace: opts.workspace ?? (typeof process !== "undefined" ? process.cwd() : "."),
    agent: opts.agent ?? "mastra",
    agentName: opts.agentName ?? "",
  };
}

function timeoutSignal(ms: number): AbortSignal | undefined {
  if (typeof AbortSignal !== "undefined" && typeof AbortSignal.timeout === "function") {
    return AbortSignal.timeout(ms);
  }
  return undefined;
}

async function evaluateToolCall(
  toolName: string,
  args: unknown,
  resolved: Required<PrismorMastraOptions>,
  sessionId: string,
): Promise<PrismorDecision> {
  try {
    const res = await fetch(`${resolved.evalUrl}/v1/evaluate`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...(resolved.apiKey ? { Authorization: `Bearer ${resolved.apiKey}` } : {}),
        ...(resolved.agentName ? { "X-Prismor-Agent-Name": resolved.agentName } : {}),
      },
      body: JSON.stringify({
        tool_name: toolName,
        arguments: args && typeof args === "object" ? args : { value: args },
        event_type: "shell",
        agent: resolved.agent,
        agent_name: resolved.agentName,
        mode: resolved.mode,
        session_id: sessionId,
        subject: resolved.subject,
        workspace: resolved.workspace,
      }),
      signal: timeoutSignal(resolved.timeoutMs),
    });
    if (!res.ok) {
      return resolved.failMode === "closed"
        ? { allow: false, reason: `eval-server HTTP ${res.status} — failing closed` }
        : FAIL_OPEN;
    }
    return (await res.json()) as PrismorDecision;
  } catch (err) {
    return resolved.failMode === "closed"
      ? { allow: false, reason: `eval-server unavailable (${(err as Error).message}) — failing closed` }
      : FAIL_OPEN;
  }
}

let _sessionCounter = 0;
function newSessionId(): string {
  const pid = typeof process !== "undefined" ? process.pid : 0;
  return `mastra-${pid}-${++_sessionCounter}`;
}

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
  const resolved = resolveOpts(opts);
  const sid = newSessionId();
  const original = tool.execute.bind(tool);

  const guarded = async (inputData: unknown, ...rest: any[]) => {
    const decision = await evaluateToolCall(toolName, inputData, resolved, sid);
    if (!decision.allow) {
      throw new PrismorBlocked(decision.reason ?? "policy violation");
    }
    return original(inputData, ...rest);
  };

  return { ...tool, execute: guarded, __prismor_guarded__: true } as T;
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
