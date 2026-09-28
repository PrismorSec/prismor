"use strict";
/**
 * Tests for prismor-sdk's PrismorClient. No live eval-server — fetch is
 * injected (or the global one stubbed) so these run standalone. Build first:
 * the suite imports ../dist/index.js.
 */
const test = require("node:test");
const assert = require("node:assert/strict");
const { PrismorClient, PrismorBlocked, useSubject, resolveSubject } = require("../dist/index.js");

const ALLOW = { contract_version: "1", allow: true, verdict: "allow", transform: null, rule_id: null, reason: null, findings: [], blocking: null, subject: null };
const DENY = { contract_version: "1", allow: false, verdict: "block", transform: null, rule_id: "destructive-command", reason: "[CRITICAL] destructive-command", findings: [{ mode: "enforce", severity: "critical", title: "destructive" }], blocking: { action: "block", ruleId: "destructive-command" }, subject: null };

/** An injectable fetch that records every request and answers /v1/evaluate with `decide()`. */
function recording(requests, decide = () => ALLOW, redact = () => ({ redacted: false })) {
  return async (url, init = {}) => {
    const u = String(url);
    const req = { url: u, method: init.method, headers: init.headers ?? {}, body: init.body ? JSON.parse(init.body) : null, signal: init.signal };
    requests.push(req);
    if (u.endsWith("/v1/redact")) return { ok: true, json: async () => redact(req) };
    if (u.endsWith("/health")) return { ok: true, json: async () => ({ status: "ok", ts: "now" }) };
    if (u.endsWith("/v1/contract")) return { ok: true, json: async () => ({ contract_version: "1", event_types: {}, verdicts: [], verdict_rank: {}, pre_action_events: [], surfaces: [] }) };
    return { ok: true, json: async () => decide(req) };
  };
}

function capture(method, fn) {
  const original = console[method];
  const lines = [];
  console[method] = (...args) => lines.push(args.join(" "));
  return Promise.resolve(fn(lines)).finally(() => { console[method] = original; });
}

const evaluateRequests = (requests) => requests.filter((r) => r.url.endsWith("/v1/evaluate"));

// ── check(): request shape ──────────────────────────────────────────────────

test("check() posts the documented body with the defaults", async () => {
  const requests = [];
  const client = new PrismorClient({ fetch: recording(requests) });
  const decision = await client.check("run_shell", { command: "ls" });
  assert.deepEqual(decision, ALLOW);
  const [req] = evaluateRequests(requests);
  assert.equal(req.method, "POST");
  assert.equal(req.url, "http://127.0.0.1:7071/v1/evaluate");
  assert.deepEqual(req.body, {
    tool_name: "run_shell", arguments: { command: "ls" }, event_type: "shell", agent: "sdk", agent_name: "sdk",
    mode: "observe", session_id: client.sessionId, subject: "", workspace: process.cwd(),
  });
  assert.equal("metadata" in req.body, false);
  assert.equal(req.headers["Content-Type"], "application/json");
  assert.equal("Authorization" in req.headers, false);
  assert.equal("X-Prismor-Subject" in req.headers, false);
  assert.equal(req.headers["X-Prismor-Agent-Name"], "sdk");
});

test("check() sends the auth, subject and agent-name headers and body fields", async () => {
  const requests = [];
  const client = new PrismorClient({ fetch: recording(requests), apiKey: "prism_eval_secret", subject: "user:alice", agent: "vercel-ai", agentName: "support-bot", workspace: "/srv/app" });
  await client.check("run_shell", { command: "ls" });
  const [req] = evaluateRequests(requests);
  assert.equal(req.headers["Authorization"], "Bearer prism_eval_secret");
  assert.equal(req.headers["X-Prismor-Subject"], "user:alice");
  assert.equal(req.headers["X-Prismor-Agent-Name"], "support-bot");
  assert.equal(req.body.subject, "user:alice");
  assert.equal(req.body.agent, "vercel-ai");
  assert.equal(req.body.agent_name, "support-bot");
  assert.equal(req.body.workspace, "/srv/app");
});

test("apiKey falls back to PRISMOR_EVAL_KEY", async () => {
  const requests = [];
  process.env.PRISMOR_EVAL_KEY = "prism_env_key";
  try {
    await new PrismorClient({ fetch: recording(requests) }).check("t", {});
    assert.equal(evaluateRequests(requests)[0].headers["Authorization"], "Bearer prism_env_key");
  } finally {
    delete process.env.PRISMOR_EVAL_KEY;
  }
});

test("budget is sent as metadata.budget and metadata passes through", async () => {
  const requests = [];
  const client = new PrismorClient({ fetch: recording(requests), budget: { max_calls: 5 }, metadata: { tenant: "acme" } });
  await client.check("t", {});
  assert.deepEqual(evaluateRequests(requests)[0].body.metadata, { tenant: "acme", budget: { max_calls: 5 } });
});

test("sessionId option is honored; the default is <agent>-<pid>-<n> and unique per client", async () => {
  const a = new PrismorClient({ fetch: recording([]) });
  const b = new PrismorClient({ fetch: recording([]), agent: "vercel-ai" });
  const c = new PrismorClient({ fetch: recording([]), sessionId: "conv-42" });
  assert.match(a.sessionId, /^sdk-\d+-\d+$/);
  assert.match(b.sessionId, /^vercel-ai-\d+-\d+$/);
  assert.notEqual(a.sessionId, b.sessionId);
  assert.equal(c.sessionId, "conv-42");
  const requests = [];
  await new PrismorClient({ fetch: recording(requests), sessionId: "conv-42" }).check("t", {});
  assert.equal(evaluateRequests(requests)[0].body.session_id, "conv-42");
});

test("check() overrides apply to that call only", async () => {
  const requests = [];
  const client = new PrismorClient({ fetch: recording(requests), budget: 1 });
  await client.check("t", {}, { eventType: "network", subject: "user:carol", sessionId: "s-2", budget: 9, metadata: { trace_id: "t-1" } });
  await client.check("t", {});
  const [first, second] = evaluateRequests(requests);
  assert.equal(first.body.event_type, "network");
  assert.equal(first.body.subject, "user:carol");
  assert.equal(first.body.session_id, "s-2");
  assert.deepEqual(first.body.metadata, { trace_id: "t-1", budget: 9 });
  assert.equal(second.body.event_type, "shell");
  assert.equal(second.body.subject, "");
  assert.equal(second.body.session_id, client.sessionId);
  assert.deepEqual(second.body.metadata, { budget: 1 });
});

test("non-object and array args are wrapped as {value}", async () => {
  const requests = [];
  const client = new PrismorClient({ fetch: recording(requests) });
  await client.check("t", "rm -rf /");
  await client.check("t", ["a", "b"]);
  await client.check("t", null);
  const bodies = evaluateRequests(requests).map((r) => r.body.arguments);
  assert.deepEqual(bodies, [{ value: "rm -rf /" }, { value: ["a", "b"] }, { value: null }]);
});

test("check() never throws on allow:false and preserves the full wire decision", async () => {
  const client = new PrismorClient({ fetch: recording([], () => DENY), mode: "enforce" });
  const decision = await client.check("run_shell", { command: "rm -rf /" });
  assert.equal(decision.allow, false);
  assert.equal(decision.verdict, "block");
  assert.equal(decision.rule_id, "destructive-command");
  assert.equal(decision.contract_version, "1");
});

// ── failMode ────────────────────────────────────────────────────────────────

test("enforce mode fails closed when fetch throws", async () => {
  await capture("error", async (lines) => {
    const client = new PrismorClient({ fetch: async () => { throw new TypeError("fetch failed"); }, mode: "enforce" });
    const decision = await client.check("t", {});
    assert.equal(decision.allow, false);
    assert.match(decision.reason, /failing closed/);
    assert.equal(decision.verdict, "block");
    assert.equal(lines.length, 1);
  });
});

test("enforce mode fails closed on a non-2xx response", async () => {
  await capture("error", async () => {
    const client = new PrismorClient({ fetch: async () => ({ ok: false, status: 503 }), mode: "enforce" });
    const decision = await client.check("t", {});
    assert.equal(decision.allow, false);
    assert.match(decision.reason, /HTTP 503/);
  });
});

test("observe mode fails open when fetch throws", async () => {
  await capture("warn", async (lines) => {
    const client = new PrismorClient({ fetch: async () => { throw new TypeError("fetch failed"); } });
    const decision = await client.check("t", {});
    assert.equal(decision.allow, true);
    assert.equal(lines.length, 1);
    assert.match(lines[0], /failing open/);
  });
});

test("failMode overrides the mode default in both directions", async () => {
  const boom = async () => { throw new TypeError("fetch failed"); };
  await capture("warn", async () => {
    assert.equal((await new PrismorClient({ fetch: boom, mode: "enforce", failMode: "open" }).check("t", {})).allow, true);
  });
  await capture("error", async () => {
    assert.equal((await new PrismorClient({ fetch: boom, mode: "observe", failMode: "closed" }).check("t", {})).allow, false);
  });
});

test("a hung eval-server times out after timeoutMs and follows failMode", async () => {
  await capture("error", async () => {
    const hung = (_url, init) => new Promise((_resolve, reject) => {
      init.signal.addEventListener("abort", () => reject(init.signal.reason));
    });
    const client = new PrismorClient({ fetch: hung, mode: "enforce", timeoutMs: 30 });
    const decision = await client.check("t", {});
    assert.equal(decision.allow, false);
  });
});

// ── guard() and block handling ──────────────────────────────────────────────

test("guard() throws PrismorBlocked carrying the decision and never runs the tool", async () => {
  let ran = false;
  const client = new PrismorClient({ fetch: recording([], () => DENY), mode: "enforce" });
  const run = client.guard(async () => { ran = true; }, { toolName: "run_shell" });
  await assert.rejects(() => run({ command: "rm -rf /" }), (err) => {
    assert.ok(err instanceof PrismorBlocked);
    assert.equal(err.name, "PrismorBlocked");
    assert.equal(err.message, "Blocked by Prismor: [CRITICAL] destructive-command");
    assert.equal(err.decision.rule_id, "destructive-command");
    return true;
  });
  assert.equal(ran, false);
});

test("guard() with onPolicyBlock returns the callback's value as the tool result", async () => {
  let ran = false;
  const seen = {};
  const client = new PrismorClient({
    fetch: recording([], () => DENY), mode: "enforce", raiseOnBlock: true,
    onPolicyBlock: (decision, ctx) => { Object.assign(seen, { decision, ctx }); return `denied: ${decision.reason}`; },
  });
  const run = client.guard(async () => { ran = true; }, { toolName: "run_shell" });
  assert.equal(await run({ command: "rm -rf /" }), "denied: [CRITICAL] destructive-command");
  assert.equal(ran, false);
  assert.deepEqual(seen.ctx, { toolName: "run_shell", args: { command: "rm -rf /" }, sessionId: client.sessionId });
  assert.equal(seen.decision.allow, false);
});

test("guard() propagates an exception thrown by onPolicyBlock", async () => {
  const client = new PrismorClient({ fetch: recording([], () => DENY), onPolicyBlock: () => { throw new Error("app aborts"); } });
  await assert.rejects(() => client.guard(async () => "x", { toolName: "t" })({}), /app aborts/);
});

test("guard() with raiseOnBlock: false returns the denial string", async () => {
  const client = new PrismorClient({ fetch: recording([], () => DENY), raiseOnBlock: false });
  assert.equal(await client.guard(async () => "x", { toolName: "t" })({}), "⛔ Prismor blocked this tool call: [CRITICAL] destructive-command");
});

test("guard() passes the tool result through /v1/redact", async () => {
  const requests = [];
  const client = new PrismorClient({
    fetch: recording(requests, () => ALLOW, (req) => ({ result: req.body.result.replace("sk_live_x", "[REDACTED:secret]"), redacted: true })),
    workspace: "/srv/app",
  });
  const read = client.guard(async () => "STRIPE=sk_live_x", { toolName: "read" });
  assert.equal(await read({}), "STRIPE=[REDACTED:secret]");
  const redactReq = requests.find((r) => r.url.endsWith("/v1/redact"));
  assert.deepEqual(redactReq.body, { result: "STRIPE=sk_live_x", workspace: "/srv/app" });
});

test("redact() returns the value unchanged on error, non-2xx and redacted:false", async () => {
  assert.equal(await new PrismorClient({ fetch: async () => { throw new Error("down"); } }).redact("plain"), "plain");
  assert.equal(await new PrismorClient({ fetch: async () => ({ ok: false, status: 500 }) }).redact("plain"), "plain");
  assert.equal(await new PrismorClient({ fetch: async () => ({ ok: true, json: async () => ({ result: "changed", redacted: false }) }) }).redact("plain"), "plain");
});

test("redact() skips null and undefined without a request", async () => {
  const requests = [];
  const client = new PrismorClient({ fetch: recording(requests) });
  assert.equal(await client.redact(null), null);
  assert.equal(await client.redact(undefined), undefined);
  assert.equal(requests.length, 0);
});

test("guard() args extractor selects the evaluated arguments", async () => {
  const requests = [];
  const client = new PrismorClient({ fetch: recording(requests) });
  const invoke = client.guard(async (input) => input.args.command, {
    toolName: "run_shell", args: (input) => (input && input.type === "tool_call" ? input.args : input),
  });
  assert.equal(await invoke({ type: "tool_call", args: { command: "echo hi" }, id: "1" }), "echo hi");
  assert.deepEqual(evaluateRequests(requests)[0].body.arguments, { command: "echo hi" });
});

test("guard() eventType is sent as event_type", async () => {
  const requests = [];
  const client = new PrismorClient({ fetch: recording(requests) });
  await client.guard(async () => "ok", { toolName: "fetch_url", eventType: "network" })({ url: "https://example.com" });
  assert.equal(evaluateRequests(requests)[0].body.event_type, "network");
});

// ── subjects ────────────────────────────────────────────────────────────────

test("useSubject() attributes calls inside its scope, in the body and the header", async () => {
  const requests = [];
  const client = new PrismorClient({ fetch: recording(requests) });
  await useSubject("user:alice", () => client.check("t", {}));
  const [req] = evaluateRequests(requests);
  assert.equal(req.body.subject, "user:alice");
  assert.equal(req.headers["X-Prismor-Subject"], "user:alice");
});

test("explicit subject beats useSubject(); PRISMOR_SUBJECT is the last fallback", async () => {
  const requests = [];
  const pinned = new PrismorClient({ fetch: recording(requests), subject: "user:pinned" });
  await useSubject("user:alice", () => pinned.check("t", {}));
  assert.equal(evaluateRequests(requests)[0].body.subject, "user:pinned");
  process.env.PRISMOR_SUBJECT = "user:envuser";
  try {
    await new PrismorClient({ fetch: recording(requests) }).check("t", {});
    assert.equal(evaluateRequests(requests)[1].body.subject, "user:envuser");
    assert.equal(resolveSubject(), "user:envuser");
    assert.equal(resolveSubject("user:explicit"), "user:explicit");
  } finally {
    delete process.env.PRISMOR_SUBJECT;
  }
});

test("concurrent useSubject() scopes do not bleed", async () => {
  const requests = [];
  const client = new PrismorClient({
    fetch: async (url, init) => {
      if (String(url).endsWith("/v1/redact")) return { ok: true, json: async () => ({ redacted: false }) };
      requests.push(JSON.parse(init.body));
      await new Promise((r) => setTimeout(r, 5)); // force interleaving
      return { ok: true, json: async () => ALLOW };
    },
  });
  const users = ["alice", "bob", "carol", "dave"];
  await Promise.all(users.map((u) => useSubject(`user:${u}`, async () => {
    for (let i = 0; i < 5; i++) await client.check("t", { who: u });
  })));
  assert.equal(requests.length, 20);
  for (const req of requests) assert.equal(req.subject, `user:${req.arguments.who}`);
});

// ── observe-mode visibility ─────────────────────────────────────────────────

test("observe mode warns once per enforce-rated finding; enforce mode and blocked calls stay silent", async () => {
  const findings = [{ mode: "enforce", severity: "high", title: "exfil" }, { mode: "observe", title: "note" }];
  const allowWithFindings = { ...ALLOW, findings };
  await capture("warn", async (lines) => {
    await new PrismorClient({ fetch: recording([], () => allowWithFindings) }).check("t", {});
    assert.equal(lines.length, 1);
    assert.match(lines[0], /observe \(t\): would block in enforce mode - \[high\] exfil/);
  });
  await capture("warn", async (lines) => {
    await new PrismorClient({ fetch: recording([], () => allowWithFindings), mode: "enforce" }).check("t", {});
    await new PrismorClient({ fetch: recording([], () => ({ ...DENY, findings })) }).check("t", {});
    assert.equal(lines.length, 0);
  });
});

// ── health / contract ───────────────────────────────────────────────────────

test("health() and contract() GET their endpoints", async () => {
  const requests = [];
  const client = new PrismorClient({ fetch: recording(requests), evalUrl: "http://sidecar:7071" });
  assert.deepEqual(await client.health(), { status: "ok", ts: "now" });
  assert.equal((await client.contract()).contract_version, "1");
  assert.deepEqual(requests.map((r) => r.url), ["http://sidecar:7071/health", "http://sidecar:7071/v1/contract"]);
});

test("health() and contract() throw on a non-2xx response", async () => {
  const client = new PrismorClient({ fetch: async () => ({ ok: false, status: 502 }) });
  await assert.rejects(() => client.health(), /HTTP 502/);
  await assert.rejects(() => client.contract(), /HTTP 502/);
});

test("the default fetch is the global fetch, resolved at call time", async () => {
  const client = new PrismorClient(); // constructed before the stub exists
  const original = globalThis.fetch;
  const requests = [];
  globalThis.fetch = recording(requests);
  try {
    assert.deepEqual(await client.check("t", {}), ALLOW);
    assert.equal(evaluateRequests(requests).length, 1);
  } finally {
    globalThis.fetch = original;
  }
});
