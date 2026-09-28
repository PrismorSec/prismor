/**
 * Options, wire types and the error class for prismor-sdk.
 *
 * The decision shape mirrors `Decision.as_dict()` in
 * prismor/runtime/contract.py — the eval-server's response is that dict.
 */

export type PrismorMode = "enforce" | "observe";
export type PrismorFailMode = "open" | "closed";
export type PrismorEventType = "shell" | "network" | "file_write" | "file_read" | "tool_result" | "prompt";

/** One policy finding as the eval-server reports it. The keys the SDK reads are typed; the rest is open. */
export interface PrismorFinding {
  ruleId?: string;
  category?: string;
  severity?: string;
  title?: string;
  mode?: string;
  action?: string;
  [key: string]: unknown;
}

/** `Subject.as_dict()` on the wire. */
export interface PrismorSubject {
  source?: string;
  user_id?: string | null;
  team_id?: string | null;
  org_id?: string | null;
  [key: string]: unknown;
}

/**
 * `Decision.as_dict()` — the full wire shape of `POST /v1/evaluate`.
 * Synthetic fail-open / fail-closed decisions omit `contract_version`.
 */
export interface PrismorDecision {
  allow: boolean;
  reason: string | null;
  findings: PrismorFinding[];
  blocking: Record<string, unknown> | null;
  subject: PrismorSubject | null;
  contract_version?: string;
  verdict?: "allow" | "block" | "step_up" | "defer" | "modify";
  transform?: string | null;
  rule_id?: string | null;
}

/** What `onPolicyBlock` receives about the denied call. */
export interface BlockContext {
  toolName: string;
  args: Record<string, unknown>;
  sessionId: string;
}

export interface PrismorClientOptions {
  /** URL of the running eval-server. Default: http://127.0.0.1:7071 */
  evalUrl?: string;
  /**
   * Bearer token sent as `Authorization` — required when the server runs with
   * --api-key / PRISMOR_EVAL_KEY. Default: the PRISMOR_EVAL_KEY environment variable.
   */
  apiKey?: string;
  /** Workspace path forwarded to the policy engine. Default: process.cwd() */
  workspace?: string;
  /** Framework / agent id for telemetry and heartbeat tagging. Default: "sdk" */
  agent?: string;
  /** Per-instance agent name (dashboard kill-switch, per-agent controls). Default: same as `agent`. */
  agentName?: string;
  /** "enforce" blocks denied calls; "observe" logs only. Default: "observe" */
  mode?: PrismorMode;
  /**
   * What to do when the eval-server cannot answer (unreachable, non-2xx,
   * timeout). "closed" blocks the tool call; "open" allows it with a warning.
   * Default: "closed" in enforce mode, "open" in observe mode — an enforced
   * suspension must hold even when the sidecar is down, while observe-mode
   * monitoring must never break the app.
   */
  failMode?: PrismorFailMode;
  /** Max milliseconds to wait for the eval-server. Default: 10000 */
  timeoutMs?: number;
  /**
   * Subject for per-user attribution: "user:alice" or "user=alice;team=data".
   * Resolved per call: this option, then the ambient useSubject() context,
   * then the PRISMOR_SUBJECT environment variable.
   */
  subject?: string;
  /** Session the calls are recorded under. Default: `${agent}-${pid}-${n}`, generated per client. */
  sessionId?: string;
  /** Prismor event type the arguments are matched as. Default: "shell" */
  eventType?: PrismorEventType;
  /**
   * Free-form, JSON-serialisable value sent as `metadata.budget` on every
   * event (session store, audit trail, telemetry). No built-in rule enforces it.
   */
  budget?: unknown;
  /** Extra metadata merged into the event by the eval-server (its own keys win). */
  metadata?: Record<string, unknown>;
  /**
   * Called on a denial; its return value becomes the tool's result. Takes
   * precedence over `raiseOnBlock`. Exceptions it throws propagate.
   */
  onPolicyBlock?: (decision: PrismorDecision, ctx: BlockContext) => unknown | Promise<unknown>;
  /** Throw PrismorBlocked on a denial (default: true); false returns the denial string instead. */
  raiseOnBlock?: boolean;
  /** Injectable fetch, for tests and custom transports. Default: the global fetch, resolved at call time. */
  fetch?: typeof globalThis.fetch;
}

/** Per-call overrides for `check()`. */
export type CheckOptions = Pick<PrismorClientOptions, "eventType" | "subject" | "sessionId" | "budget" | "metadata">;

export interface GuardOptions {
  /** Name the call is evaluated and recorded under. */
  toolName: string;
  eventType?: PrismorEventType;
  /** Extract the evaluated arguments from the wrapped function's call arguments. Default: the first argument. */
  args?: (...callArgs: any[]) => unknown;
}

/** `GET /v1/contract`: the event shape and verdict vocabulary the server speaks. */
export interface PrismorContract {
  contract_version: string;
  event_types: Record<string, string>;
  verdicts: string[];
  verdict_rank: Record<string, number>;
  pre_action_events: string[];
  surfaces: Array<Record<string, unknown>>;
}

/** Thrown by `guard()` / `onBlocked()` on a denial when `raiseOnBlock` is true. */
export class PrismorBlocked extends Error {
  readonly decision: PrismorDecision;
  constructor(reason: string, decision: PrismorDecision) {
    super(`Blocked by Prismor: ${reason}`);
    this.name = "PrismorBlocked";
    this.decision = decision;
  }
}
