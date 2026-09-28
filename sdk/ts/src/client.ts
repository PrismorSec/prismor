/**
 * PrismorClient — check, enforce and redact tool calls through the eval-server.
 *
 * Every check is `POST /v1/evaluate` on the local eval-server, which runs the
 * same policy pipeline as the coding-agent hooks and answers with
 * `Decision.as_dict()`. The client renders that verdict; it never decides.
 *
 * Fail-closed rules the client keeps:
 *  - `Decision.allow` is honored as-is. The runtime has already folded the
 *    requested mode and any org control (kill-switch, forced enforce) into it,
 *    so the client never re-derives a verdict from its own `mode`.
 *  - When the eval-server cannot answer, enforce mode blocks (an enforced
 *    suspension must hold even when the sidecar is down) and observe mode
 *    allows with a warning; `failMode` overrides either default.
 */
import { resolveSubject } from "./subject";
import { PrismorBlocked } from "./types";
import type {
  BlockContext,
  CheckOptions,
  GuardOptions,
  PrismorClientOptions,
  PrismorContract,
  PrismorDecision,
  PrismorEventType,
  PrismorFailMode,
  PrismorMode,
} from "./types";

const FAIL_OPEN_DECISION: PrismorDecision = {
  allow: true, reason: null, findings: [], blocking: null, subject: null, verdict: "allow",
};

const DENIAL_PREFIX = "⛔ Prismor blocked this tool call: ";

interface ResolvedOptions {
  evalUrl: string;
  apiKey: string;
  workspace: string;
  agent: string;
  agentName: string;
  mode: PrismorMode;
  failMode: PrismorFailMode;
  timeoutMs: number;
  subject: string;
  eventType: PrismorEventType;
  budget: unknown;
  metadata: Record<string, unknown> | undefined;
  onPolicyBlock: PrismorClientOptions["onPolicyBlock"];
  raiseOnBlock: boolean;
  fetch: PrismorClientOptions["fetch"];
}

function env(name: string): string | undefined {
  return typeof process !== "undefined" && process.env ? process.env[name] : undefined;
}

let _sessionCounter = 0;
function newSessionId(agent: string): string {
  const pid = typeof process !== "undefined" ? process.pid : 0;
  return `${agent}-${pid}-${++_sessionCounter}`;
}

/**
 * Print a one-line stderr note for findings observe mode is hiding.
 *
 * The eval-server never blocks an enforce-rated finding when the caller's
 * mode is "observe" - that's the whole point of observe mode - but it also
 * means observe mode gives zero visibility into what would be blocked if the
 * caller flipped to enforce. Runs after every check() so "observe" doesn't
 * mean "silent."
 */
function logObserveFindings(decision: PrismorDecision, mode: PrismorMode, toolName: string): void {
  if (mode !== "observe" || !decision.allow) return; // actually blocked: the caller reports that
  const findings = decision.findings ?? [];
  const wouldBlock = findings.filter((f) => String(f?.mode ?? "observe").toLowerCase() === "enforce");
  for (const f of wouldBlock) {
    const severity = f.severity ?? "high";
    const title = f.title ?? "policy violation";
    console.warn(`[prismor] observe (${toolName}): would block in enforce mode - [${severity}] ${title}`);
  }
}

/** Resolve an eval-server failure according to failMode. */
function onEvalFailure(detail: string, failMode: PrismorFailMode): PrismorDecision {
  if (failMode === "closed") {
    console.error(`[prismor] eval-server unavailable (${detail}) — failing closed`);
    return {
      allow: false,
      reason: `eval-server unavailable (${detail}) — failing closed`,
      findings: [],
      blocking: null,
      subject: null,
      verdict: "block",
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

/** The eval-server wants an object of arguments; anything else is wrapped as `{ value }`. */
function normalizeArgs(args: unknown): Record<string, unknown> {
  return args !== null && typeof args === "object" && !Array.isArray(args)
    ? (args as Record<string, unknown>)
    : { value: args };
}

/**
 * One configured entry point to check, enforce and redact tool calls.
 *
 * Construct once per agent (or per guarded tool); `check()` is safe to call
 * concurrently. The subject is resolved per call, so a client created at
 * module scope still attributes each request to the user inside
 * `useSubject()`.
 */
export class PrismorClient {
  /** Session the calls are recorded under. */
  readonly sessionId: string;
  readonly mode: PrismorMode;
  readonly agent: string;
  private readonly o: ResolvedOptions;

  constructor(opts: PrismorClientOptions = {}) {
    const agent = opts.agent ?? "sdk";
    const mode = opts.mode ?? "observe";
    this.o = {
      evalUrl: opts.evalUrl ?? "http://127.0.0.1:7071",
      apiKey: opts.apiKey ?? env("PRISMOR_EVAL_KEY") ?? "",
      workspace: opts.workspace ?? (typeof process !== "undefined" ? process.cwd() : ""),
      agent,
      agentName: opts.agentName ?? agent,
      mode,
      failMode: opts.failMode ?? (mode === "enforce" ? "closed" : "open"),
      timeoutMs: opts.timeoutMs ?? 10_000,
      subject: opts.subject ?? "",
      eventType: opts.eventType ?? "shell",
      budget: opts.budget,
      metadata: opts.metadata,
      onPolicyBlock: opts.onPolicyBlock,
      raiseOnBlock: opts.raiseOnBlock ?? true,
      fetch: opts.fetch,
    };
    this.sessionId = opts.sessionId ?? newSessionId(agent);
    this.mode = mode;
    this.agent = agent;
  }

  /** The injected fetch, else the global one — looked up at call time so a stub installed later still applies. */
  private fetchImpl(): typeof globalThis.fetch {
    return this.o.fetch ?? fetch;
  }

  private authHeaders(): Record<string, string> {
    return this.o.apiKey ? { Authorization: `Bearer ${this.o.apiKey}` } : {};
  }

  /**
   * Evaluate one tool call. Never throws on a policy denial; a transport
   * failure resolves through `failMode`. `decision.allow` says whether the
   * call may proceed; `verdict`, `rule_id`, `reason` and `findings` say why.
   */
  async check(toolName: string, args: unknown, overrides: CheckOptions = {}): Promise<PrismorDecision> {
    const o = this.o;
    const subject = resolveSubject(overrides.subject ?? o.subject);
    const sessionId = overrides.sessionId ?? this.sessionId;
    const metadata: Record<string, unknown> = { ...(o.metadata ?? {}), ...(overrides.metadata ?? {}) };
    const budget = overrides.budget !== undefined ? overrides.budget : o.budget;
    if (budget !== undefined) metadata.budget = budget;

    const body: Record<string, unknown> = {
      tool_name: toolName,
      arguments: normalizeArgs(args),
      event_type: overrides.eventType ?? o.eventType,
      agent: o.agent,
      agent_name: o.agentName,
      mode: o.mode,
      session_id: sessionId,
      subject,
      workspace: o.workspace,
    };
    if (Object.keys(metadata).length > 0) body.metadata = metadata;

    let res: Response;
    try {
      res = await this.fetchImpl()(`${o.evalUrl}/v1/evaluate`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...this.authHeaders(),
          ...(subject ? { "X-Prismor-Subject": subject } : {}),
          ...(o.agentName ? { "X-Prismor-Agent-Name": o.agentName } : {}),
        },
        body: JSON.stringify(body),
        signal: timeoutSignal(o.timeoutMs),
      });
    } catch (err) {
      // eval-server unreachable (not started, crashed, network error, timeout) —
      // `fetch` throws for connection failures rather than resolving with a bad
      // status, so it needs its own catch alongside the !res.ok branch below.
      return onEvalFailure((err as Error).message, o.failMode);
    }
    if (!res.ok) {
      return onEvalFailure(`HTTP ${res.status}`, o.failMode);
    }
    const decision = (await res.json()) as PrismorDecision;
    logObserveFindings(decision, o.mode, toolName);
    return decision;
  }

  /**
   * Render a denied call. `onPolicyBlock` decides when set (its return value
   * is the tool result; exceptions propagate). Otherwise throw
   * `PrismorBlocked` when `raiseOnBlock` (the default), else return the
   * denial string the model sees.
   */
  async onBlocked(decision: PrismorDecision, ctx: BlockContext): Promise<unknown> {
    const reason = decision.reason ?? "policy violation";
    if (this.o.onPolicyBlock) return await this.o.onPolicyBlock(decision, ctx);
    if (this.o.raiseOnBlock) throw new PrismorBlocked(reason, decision);
    return DENIAL_PREFIX + reason;
  }

  /**
   * Mask cloaked secrets and data-boundary values in a tool's return value
   * before the model sees it — `POST /v1/redact`, the result-side step the
   * Python client runs in-process. Best effort: any failure returns the value
   * unchanged and never fails the call.
   */
  async redact(value: unknown): Promise<unknown> {
    if (value === undefined || value === null) return value;
    try {
      const res = await this.fetchImpl()(`${this.o.evalUrl}/v1/redact`, {
        method: "POST",
        headers: { "Content-Type": "application/json", ...this.authHeaders() },
        body: JSON.stringify({ result: value, workspace: this.o.workspace }),
        signal: timeoutSignal(this.o.timeoutMs),
      });
      if (!res.ok) return value;
      const body = (await res.json()) as { result?: unknown; redacted?: boolean };
      return body && body.redacted && "result" in body ? body.result : value;
    } catch {
      return value;
    }
  }

  /**
   * Wrap a tool function: check → (denied) onBlocked | run → redact.
   *
   * The first call argument is what gets evaluated unless `opts.args` says
   * otherwise (LangChain's ToolCall envelope, for example). The wrapper is
   * always async.
   */
  guard<F extends (...args: any[]) => any>(
    fn: F,
    opts: GuardOptions,
  ): (...args: Parameters<F>) => Promise<Awaited<ReturnType<F>> | unknown> {
    const extract = opts.args ?? ((...callArgs: any[]) => callArgs[0]);
    return async (...callArgs: Parameters<F>) => {
      const args = extract(...callArgs);
      const decision = await this.check(opts.toolName, args, { eventType: opts.eventType });
      if (!decision.allow) { // honor the runtime decision (incl. org kill-switch), not the app-passed mode
        return this.onBlocked(decision, {
          toolName: opts.toolName, args: normalizeArgs(args), sessionId: this.sessionId,
        });
      }
      return this.redact(await fn(...callArgs));
    };
  }

  /** `GET /health` → `{status, ts}`. Throws on a non-2xx response. */
  async health(): Promise<{ status: string; ts: string }> {
    const res = await this.fetchImpl()(`${this.o.evalUrl}/health`, { signal: timeoutSignal(this.o.timeoutMs) });
    if (!res.ok) throw new Error(`[prismor] eval-server health check failed: HTTP ${res.status}`);
    return (await res.json()) as { status: string; ts: string };
  }

  /** `GET /v1/contract` → the event shape and verdict vocabulary the server speaks. Throws on a non-2xx response. */
  async contract(): Promise<PrismorContract> {
    const res = await this.fetchImpl()(`${this.o.evalUrl}/v1/contract`, { signal: timeoutSignal(this.o.timeoutMs) });
    if (!res.ok) throw new Error(`[prismor] eval-server contract fetch failed: HTTP ${res.status}`);
    return (await res.json()) as PrismorContract;
  }
}
