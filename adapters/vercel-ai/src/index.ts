/**
 * Prismor adapter for the Vercel AI SDK.
 *
 * Wraps tool `execute` functions to call the Prismor eval-server
 * (prismor eval-server) before the tool body runs. A denied call
 * throws PrismorBlocked (enforce mode) or logs and proceeds (observe mode).
 *
 * Quick start:
 *   const tools = prismorTools({ run_shell, search_web });
 *   // in your request handler — attribute every tool call to the caller:
 *   await useSubject(`user:${userId}`, () =>
 *     generateText({ model, tools, prompt }));
 */

export interface PrismorOptions {
  /** URL of the running eval-server. Default: http://127.0.0.1:7071 */
  evalUrl?: string;
  /**
   * Bearer token sent as `Authorization` to the eval-server — required when
   * the server runs with --api-key / PRISMOR_EVAL_KEY (hosted / non-localhost
   * mode). Default: the PRISMOR_EVAL_KEY environment variable.
   */
  apiKey?: string;
  /**
   * Subject for per-user attribution: "user:alice" or "user=alice;team=data".
   * Resolved per call, in priority order: this option, then the ambient
   * useSubject() context, then the PRISMOR_SUBJECT environment variable —
   * mirroring the Python runtime's resolve_subject().
   */
  subject?: string;
  /** "enforce" blocks denied calls; "observe" logs only. Default: "observe" */
  mode?: "enforce" | "observe";
  /**
   * What to do when the eval-server cannot answer (unreachable, non-2xx,
   * timeout). "closed" blocks the tool call; "open" allows it with a warning.
   * Default: "closed" in enforce mode, "open" in observe mode — an enforced
   * suspension must hold even when the sidecar is down, while observe-mode
   * monitoring must never break the app.
   */
  failMode?: "open" | "closed";
  /** Max milliseconds to wait for the eval-server. Default: 10000 */
  timeoutMs?: number;
  /** Workspace path forwarded to the policy engine. Default: process.cwd() */
  workspace?: string;
  /** Framework identifier (e.g. "vercel-ai"). Default: "vercel-ai" */
  agent?: string;
  /**
   * Per-instance agent name — used for the dashboard kill-switch and per-agent
   * mode/IAM controls. Distinct from `agent` (the framework). Example: "support-bot".
   * Default: same as `agent`.
   */
  agentName?: string;
  /**
   * Map tool argument keys to a Prismor event type.
   * Default: "shell" (args serialised to command string).
   * Use "network" for URL-fetching tools, "file_write" for file-writing tools.
   */
  eventType?: "shell" | "network" | "file_write" | "file_read" | "tool_result";
}

export interface PrismorDecision {
  allow: boolean;
  reason: string | null;
  findings: unknown[];
  blocking: unknown | null;
  subject: { user_id: string | null; team_id: string | null } | null;
}

export class PrismorBlocked extends Error {
  decision: PrismorDecision;
  constructor(reason: string, decision: PrismorDecision) {
    super(`Blocked by Prismor: ${reason}`);
    this.name = "PrismorBlocked";
    this.decision = decision;
  }
}

const FAIL_OPEN_DECISION: PrismorDecision = {
  allow: true, reason: null, findings: [], blocking: null, subject: null,
};

/**
 * Print a one-line stderr note for findings observe mode is hiding.
 *
 * The eval-server never blocks an enforce-rated finding when the caller's
 * mode is "observe" - that's the whole point of observe mode - but it also
 * means observe mode gives zero visibility into what would be blocked if the
 * caller flipped to enforce. Call this after every evaluate() so "observe"
 * doesn't mean "silent."
 */
function logObserveFindings(decision: PrismorDecision, mode: string, toolName: string): void {
  if (mode !== "observe" || !decision.allow) return; // actually blocked: the adapter reports that
  const findings = (decision.findings ?? []) as Array<Record<string, unknown>>;
  const wouldBlock = findings.filter((f) => String(f?.mode ?? "observe").toLowerCase() === "enforce");
  for (const f of wouldBlock) {
    const severity = f.severity ?? "high";
    const title = f.title ?? "policy violation";
    console.warn(`[prismor] observe (${toolName}): would block in enforce mode - [${severity}] ${title}`);
  }
}

// ── Ambient subject context ──────────────────────────────────────────────────

interface SubjectStorage {
  run<T>(subject: string, fn: () => T): T;
  getStore(): string | undefined;
}

// AsyncLocalStorage exists on Node and on the major edge runtimes (Vercel Edge,
// Cloudflare with nodejs_compat). Loaded lazily so merely importing this module
// never fails on a runtime without it — only useSubject() itself requires it.
let _subjectStorage: SubjectStorage | null | undefined;

function subjectStorage(): SubjectStorage | null {
  if (_subjectStorage !== undefined) return _subjectStorage;
  try {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const { AsyncLocalStorage } = require("node:async_hooks");
    _subjectStorage = new AsyncLocalStorage() as SubjectStorage;
  } catch {
    _subjectStorage = null;
  }
  return _subjectStorage;
}

/**
 * Attribute every Prismor-guarded tool call inside `fn` to `subject` — the
 * multi-tenant path for one deployed agent serving many users. Wrap the body
 * of your request handler:
 *
 *   const tools = prismorTools({ run_shell });          // guard once, at module scope
 *   await useSubject(`user:${userId}`, () =>            // per request
 *     generateText({ model, tools, prompt }));
 *
 * The subject propagates through async calls (AsyncLocalStorage), so parallel
 * requests with different users cannot bleed into each other. An explicit
 * `subject` option on prismorTools() takes precedence over this context.
 *
 * Throws when the runtime has no AsyncLocalStorage: silently dropping the
 * subject would let a user's calls escape their per-user policy. Pass the
 * `subject` option per request instead on such runtimes.
 */
export function useSubject<T>(subject: string, fn: () => T): T {
  const storage = subjectStorage();
  if (!storage) {
    throw new Error(
      "[prismor] useSubject() requires AsyncLocalStorage, which this runtime does not provide. " +
      "Pass prismorTools(tools, { subject }) per request instead.",
    );
  }
  return storage.run(subject, fn);
}

function resolveSubject(explicit: string): string {
  if (explicit) return explicit;
  const ambient = subjectStorage()?.getStore();
  if (ambient) return ambient;
  if (typeof process !== "undefined" && process.env && process.env.PRISMOR_SUBJECT) {
    return process.env.PRISMOR_SUBJECT;
  }
  return "";
}

// ── Evaluation ───────────────────────────────────────────────────────────────

/** Resolve an eval-server failure according to failMode. */
function onEvalFailure(
  detail: string,
  opts: Required<PrismorOptions>,
): PrismorDecision {
  if (opts.failMode === "closed") {
    console.error(`[prismor] eval-server unavailable (${detail}) — failing closed`);
    return {
      allow: false,
      reason: `eval-server unavailable (${detail}) — failing closed`,
      findings: [],
      blocking: null,
      subject: null,
    };
  }
  console.warn(`[prismor] eval-server unavailable (${detail}) — failing open`);
  return FAIL_OPEN_DECISION;
}

function timeoutSignal(ms: number): AbortSignal | undefined {
  if (typeof AbortSignal !== "undefined" && typeof AbortSignal.timeout === "function") {
    return AbortSignal.timeout(ms);
  }
  return undefined;
}

async function evaluate(
  toolName: string,
  args: Record<string, unknown>,
  opts: Required<PrismorOptions>,
  sessionId: string,
): Promise<PrismorDecision> {
  const subject = resolveSubject(opts.subject);
  let res: Response;
  try {
    res = await fetch(`${opts.evalUrl}/v1/evaluate`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...(opts.apiKey ? { Authorization: `Bearer ${opts.apiKey}` } : {}),
        ...(subject ? { "X-Prismor-Subject": subject } : {}),
        ...(opts.agentName ? { "X-Prismor-Agent-Name": opts.agentName } : {}),
      },
      body: JSON.stringify({
        tool_name: toolName,
        arguments: args,
        event_type: opts.eventType,
        agent: opts.agent,
        agent_name: opts.agentName,
        mode: opts.mode,
        session_id: sessionId,
        subject,
        workspace: opts.workspace,
      }),
      signal: timeoutSignal(opts.timeoutMs),
    });
  } catch (err) {
    // eval-server unreachable (not started, crashed, network error, timeout) —
    // `fetch` throws for connection failures rather than resolving with a bad
    // status, so it needs its own catch alongside the !res.ok branch below.
    return onEvalFailure((err as Error).message, opts);
  }

  if (!res.ok) {
    return onEvalFailure(`HTTP ${res.status}`, opts);
  }
  return res.json() as Promise<PrismorDecision>;
}

/**
 * Mask cloaked secrets and data-boundary values in a tool's return value before
 * the model sees it — the result-side step the Python adapters run in-process.
 * Best effort: any failure returns the value unchanged, never fails the call.
 */
async function redactResult(value: unknown, opts: Required<PrismorOptions>): Promise<unknown> {
  if (value === undefined || value === null) return value;
  try {
    const res = await fetch(`${opts.evalUrl}/v1/redact`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...(opts.apiKey ? { Authorization: `Bearer ${opts.apiKey}` } : {}),
      },
      body: JSON.stringify({ result: value, workspace: opts.workspace }),
      signal: timeoutSignal(opts.timeoutMs),
    });
    if (!res.ok) return value;
    const body = (await res.json()) as { result?: unknown; redacted?: boolean };
    return body && body.redacted && "result" in body ? body.result : value;
  } catch {
    return value;
  }
}

function resolveOpts(opts: PrismorOptions): Required<PrismorOptions> {
  const agent = opts.agent ?? "vercel-ai";
  const mode = opts.mode ?? "observe";
  return {
    evalUrl: opts.evalUrl ?? "http://127.0.0.1:7071",
    apiKey: opts.apiKey
      ?? (typeof process !== "undefined" && process.env ? process.env.PRISMOR_EVAL_KEY ?? "" : ""),
    subject: opts.subject ?? "",
    mode,
    failMode: opts.failMode ?? (mode === "enforce" ? "closed" : "open"),
    timeoutMs: opts.timeoutMs ?? 10_000,
    workspace: opts.workspace ?? process.cwd(),
    agent,
    agentName: opts.agentName ?? agent,
    eventType: opts.eventType ?? "shell",
  };
}

let _sessionCounter = 0;
function sessionId(): string {
  return `vercel-ai-${process.pid}-${++_sessionCounter}`;
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
  const resolved = resolveOpts(opts);
  const sid = sessionId();
  const original = tool.execute;

  const guarded = async (args: Record<string, unknown>, ctx: unknown) => {
    const decision = await evaluate(toolName, args, resolved, sid);
    logObserveFindings(decision, resolved.mode, toolName);
    if (!decision.allow) {  // honor the runtime decision (incl. org kill-switch), not the app-passed mode
      throw new PrismorBlocked(decision.reason ?? "policy violation", decision);
    }
    return redactResult(await original(args, ctx), resolved);
  };

  return { ...tool, execute: guarded };
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
  const resolved = resolveOpts(opts);
  const sid = sessionId();
  const toolName = tool.name || "tool";
  const original = tool.invoke.bind(tool);

  (tool as any).invoke = async (input: any, config?: any) => {
    const decision = await evaluate(toolName, langChainArgs(input), resolved, sid);
    logObserveFindings(decision, resolved.mode, toolName);
    if (!decision.allow) {  // honor the runtime decision (incl. org kill-switch), not the app-passed mode
      throw new PrismorBlocked(decision.reason ?? "policy violation", decision);
    }
    return redactResult(await original(input, config), resolved);
  };
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
