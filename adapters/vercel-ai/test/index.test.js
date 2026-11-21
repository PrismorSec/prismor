"use strict";
/**
 * Tests for the Vercel AI SDK adapter. No live eval-server — global fetch is
 * stubbed so these run standalone. Covers:
 *  - failMode semantics: enforce fails CLOSED when the eval-server is
 *    unavailable (a suspended user must stay suspended); observe — the
 *    default mode — fails open, and failMode overrides either default.
 *    Supersedes the fail-open contract from PrismorSec/prismor#136, which
 *    observe mode keeps.
 *  - useSubject(): ambient per-request attribution, explicit-option precedence,
 *    PRISMOR_SUBJECT fallback, and no bleed across concurrent requests.
 */
const test = require("node:test");
const assert = require("node:assert/strict");
const { prismorTools, prismorTool, useSubject, useSession, PrismorBlocked } = require("../dist/index.js");

function withMockFetch(impl, fn) {
  const original = globalThis.fetch;
  globalThis.fetch = impl;
  return Promise.resolve(fn()).finally(() => {
    globalThis.fetch = original;
  });
}

const ALLOW = { allow: true, reason: null, findings: [], blocking: null, subject: null };

/** Mock fetch that records each request body and allows everything. */
function recordingFetch(requests) {
  return async (url, init) => {
    if (String(url).endsWith("/v1/redact")) return { ok: true, json: async () => ({ redacted: false }) };
    requests.push({ body: JSON.parse(init.body), headers: init.headers });
    return { ok: true, json: async () => ALLOW };
  };
}

test("allows the call when the eval-server returns allow: true", async () => {
  await withMockFetch(
    async () => ({ ok: true, json: async () => ALLOW }),
    async () => {
      const run_shell = { execute: async ({ command }) => `ran: ${command}` };
      const tools = prismorTools({ run_shell });
      const result = await tools.run_shell.execute({ command: "echo hi" });
      assert.equal(result, "ran: echo hi");
    },
  );
});

test("throws PrismorBlocked when the eval-server denies the call", async () => {
  await withMockFetch(
    async () => ({ ok: true, json: async () => ({ allow: false, reason: "blocked for testing", findings: [], blocking: null, subject: null }) }),
    async () => {
      const run_shell = { execute: async () => "should not run" };
      const tools = prismorTools({ run_shell });
      await assert.rejects(
        () => tools.run_shell.execute({ command: "rm -rf /" }),
        PrismorBlocked,
      );
    },
  );
});

// ── failMode ────────────────────────────────────────────────────────────────

test("enforce mode fails CLOSED on a non-2xx response", async () => {
  await withMockFetch(
    async () => ({ ok: false, status: 503 }),
    async () => {
      const run_shell = { execute: async () => "should not run" };
      const tools = prismorTools({ run_shell }, { mode: "enforce" });
      await assert.rejects(
        () => tools.run_shell.execute({ command: "rm -rf /" }),
        PrismorBlocked,
      );
    },
  );
});

test("enforce mode fails CLOSED when fetch itself rejects", async () => {
  await withMockFetch(
    async () => {
      throw new TypeError("fetch failed");
    },
    async () => {
      const run_shell = { execute: async () => "should not run" };
      const tools = prismorTools({ run_shell }, { mode: "enforce" });
      await assert.rejects(
        () => tools.run_shell.execute({ command: "rm -rf /" }),
        PrismorBlocked,
      );
    },
  );
});

test("observe mode fails open when the eval-server is unreachable — #136 contract", async () => {
  await withMockFetch(
    async () => {
      throw new TypeError("fetch failed");
    },
    async () => {
      const run_shell = { execute: async ({ command }) => `ran: ${command}` };
      const tools = prismorTools({ run_shell }, { mode: "observe" });
      const result = await tools.run_shell.execute({ command: "rm -rf /" });
      assert.equal(result, "ran: rm -rf /");
    },
  );
});

test("failMode: 'open' overrides the enforce-mode default", async () => {
  await withMockFetch(
    async () => {
      throw new TypeError("fetch failed");
    },
    async () => {
      const run_shell = { execute: async ({ command }) => `ran: ${command}` };
      const tools = prismorTools({ run_shell }, { failMode: "open" });
      const result = await tools.run_shell.execute({ command: "echo hi" });
      assert.equal(result, "ran: echo hi");
    },
  );
});

test("failMode: 'closed' overrides the observe-mode default", async () => {
  await withMockFetch(
    async () => {
      throw new TypeError("fetch failed");
    },
    async () => {
      const run_shell = { execute: async () => "should not run" };
      const tools = prismorTools({ run_shell }, { mode: "observe", failMode: "closed" });
      await assert.rejects(
        () => tools.run_shell.execute({ command: "echo hi" }),
        PrismorBlocked,
      );
    },
  );
});

test("a hung eval-server times out and follows failMode", async () => {
  await withMockFetch(
    (_url, init) =>
      new Promise((_resolve, reject) => {
        init.signal.addEventListener("abort", () => reject(init.signal.reason));
      }),
    async () => {
      const run_shell = { execute: async () => "should not run" };
      const tools = prismorTools({ run_shell }, { mode: "enforce", timeoutMs: 30 });
      await assert.rejects(
        () => tools.run_shell.execute({ command: "echo hi" }),
        PrismorBlocked,
      );
    },
  );
});

// ── useSubject / subject resolution ─────────────────────────────────────────

test("useSubject() attributes calls made inside its scope", async () => {
  const requests = [];
  await withMockFetch(recordingFetch(requests), async () => {
    const run_shell = { execute: async ({ command }) => `ran: ${command}` };
    const tools = prismorTools({ run_shell });
    await useSubject("user:alice", () => tools.run_shell.execute({ command: "echo hi" }));
    assert.equal(requests.length, 1);
    assert.equal(requests[0].body.subject, "user:alice");
    assert.equal(requests[0].headers["X-Prismor-Subject"], "user:alice");
  });
});

test("subject is resolved per call, not at wrap time", async () => {
  const requests = [];
  await withMockFetch(recordingFetch(requests), async () => {
    const run_shell = { execute: async () => "ok" };
    const tools = prismorTools({ run_shell }); // wrapped once, outside any subject
    await useSubject("user:alice", () => tools.run_shell.execute({ command: "a" }));
    await useSubject("user:bob", () => tools.run_shell.execute({ command: "b" }));
    assert.deepEqual(
      requests.map((r) => r.body.subject),
      ["user:alice", "user:bob"],
    );
  });
});

test("explicit subject option takes precedence over useSubject()", async () => {
  const requests = [];
  await withMockFetch(recordingFetch(requests), async () => {
    const run_shell = { execute: async () => "ok" };
    const tools = prismorTools({ run_shell }, { subject: "user:pinned" });
    await useSubject("user:alice", () => tools.run_shell.execute({ command: "a" }));
    assert.equal(requests[0].body.subject, "user:pinned");
  });
});

test("PRISMOR_SUBJECT env is the fallback when no option or context is set", async () => {
  const requests = [];
  process.env.PRISMOR_SUBJECT = "user:envuser";
  try {
    await withMockFetch(recordingFetch(requests), async () => {
      const run_shell = { execute: async () => "ok" };
      const tools = prismorTools({ run_shell });
      await tools.run_shell.execute({ command: "a" });
      assert.equal(requests[0].body.subject, "user:envuser");
    });
  } finally {
    delete process.env.PRISMOR_SUBJECT;
  }
});

test("no subject → no subject field or header sent", async () => {
  const requests = [];
  await withMockFetch(recordingFetch(requests), async () => {
    const run_shell = { execute: async () => "ok" };
    const tools = prismorTools({ run_shell });
    await tools.run_shell.execute({ command: "a" });
    assert.equal(requests[0].body.subject, "");
    assert.equal("X-Prismor-Subject" in requests[0].headers, false);
  });
});

test("concurrent requests with different subjects do not bleed", async () => {
  const requests = [];
  await withMockFetch(
    async (url, init) => {
      if (String(url).endsWith("/v1/redact")) return { ok: true, json: async () => ({ redacted: false }) };
      requests.push(JSON.parse(init.body));
      await new Promise((r) => setTimeout(r, 5)); // force interleaving
      return { ok: true, json: async () => ALLOW };
    },
    async () => {
      const run_shell = { execute: async ({ command }) => command };
      const tools = prismorTools({ run_shell });
      const users = ["alice", "bob", "carol", "dave"];
      await Promise.all(
        users.map((u) =>
          useSubject(`user:${u}`, async () => {
            for (let i = 0; i < 5; i++) {
              await tools.run_shell.execute({ command: u });
            }
          }),
        ),
      );
      for (const req of requests) {
        assert.equal(req.subject, `user:${req.arguments.command}`);
      }
      assert.equal(requests.length, 20);
    },
  );
});

test("apiKey option sends Authorization header", async () => {
  const requests = [];
  await withMockFetch(recordingFetch(requests), async () => {
    const run_shell = { execute: async () => "ok" };
    const tools = prismorTools({ run_shell }, { apiKey: "prism_eval_secret" });
    await tools.run_shell.execute({ command: "a" });
    assert.equal(requests[0].headers["Authorization"], "Bearer prism_eval_secret");
  });
});

test("no apiKey → no Authorization header", async () => {
  const requests = [];
  await withMockFetch(recordingFetch(requests), async () => {
    const run_shell = { execute: async () => "ok" };
    const tools = prismorTools({ run_shell });
    await tools.run_shell.execute({ command: "a" });
    assert.equal("Authorization" in requests[0].headers, false);
  });
});

test("a tool with no execute() is returned unchanged", () => {
  const noop = {};
  const wrapped = prismorTool("noop", noop);
  assert.equal(wrapped, noop);
});

// ── LangChain JS / LangGraph JS ─────────────────────────────────────────────

const { prismorLangChainTool, prismorLangChainTools } = require("../dist/index.js");

function fakeLcTool(name) {
  return {
    name,
    async invoke(input, _config) {
      const args = input && input.type === "tool_call" ? input.args : input;
      return `ran ${name}: ${JSON.stringify(args)}`;
    },
  };
}

test("langchain: guarded invoke() sends tool name and args to the eval-server", async () => {
  const requests = [];
  await withMockFetch(recordingFetch(requests), async () => {
    const [tool] = prismorLangChainTools([fakeLcTool("fetch_url")]);
    const out = await tool.invoke({ url: "https://example.com" });
    assert.equal(out, 'ran fetch_url: {"url":"https://example.com"}');
    assert.equal(requests[0].body.tool_name, "fetch_url");
    assert.deepEqual(requests[0].body.arguments, { url: "https://example.com" });
  });
});

test("langchain: ToolCall-shaped input (LangGraph ToolNode) unwraps args for evaluation", async () => {
  const requests = [];
  await withMockFetch(recordingFetch(requests), async () => {
    const tool = prismorLangChainTool(fakeLcTool("run_shell"));
    const call = { name: "run_shell", args: { command: "echo hi" }, id: "1", type: "tool_call" };
    await tool.invoke(call);
    assert.deepEqual(requests[0].body.arguments, { command: "echo hi" });
  });
});

test("langchain: denied invoke() throws PrismorBlocked and never runs the tool", async () => {
  await withMockFetch(
    async () => ({ ok: true, json: async () => ({ allow: false, reason: "nope", findings: [], blocking: null, subject: null }) }),
    async () => {
      let ran = false;
      const tool = prismorLangChainTool({ name: "run_shell", invoke: async () => { ran = true; } });
      await assert.rejects(() => tool.invoke({ command: "rm -rf /" }), PrismorBlocked);
      assert.equal(ran, false);
    },
  );
});

test("langchain: useSubject() attributes guarded invoke() calls", async () => {
  const requests = [];
  await withMockFetch(recordingFetch(requests), async () => {
    const tool = prismorLangChainTool(fakeLcTool("fetch_url"));
    await useSubject("user:alice", () => tool.invoke({ url: "https://a.com" }));
    await useSubject("user:bob", () => tool.invoke({ url: "https://b.com" }));
    assert.deepEqual(requests.map((r) => r.body.subject), ["user:alice", "user:bob"]);
  });
});

test("langchain: guarding twice is a no-op", async () => {
  const requests = [];
  await withMockFetch(recordingFetch(requests), async () => {
    const tool = prismorLangChainTool(prismorLangChainTool(fakeLcTool("fetch_url")));
    await tool.invoke({ url: "https://a.com" });
    assert.equal(requests.length, 1);
  });
});

// ── Result-side redaction ────────────────────────────────────────────────────

test("tool results are masked through /v1/redact before the model sees them", async () => {
  await withMockFetch(
    async (url, init) => String(url).endsWith("/v1/redact")
      ? { ok: true, json: async () => ({ result: JSON.parse(init.body).result.replace("sk_live_x", "[REDACTED:secret]"), redacted: true }) }
      : { ok: true, json: async () => ALLOW },
    async () => {
      const read = { execute: async () => "STRIPE=sk_live_x" };
      const tools = prismorTools({ read });
      assert.equal(await tools.read.execute({}), "STRIPE=[REDACTED:secret]");
    },
  );
});

test("redaction failure returns the original result (never fails the call)", async () => {
  await withMockFetch(
    async (url) => { if (String(url).endsWith("/v1/redact")) throw new Error("down"); return { ok: true, json: async () => ALLOW }; },
    async () => {
      const read = { execute: async () => "plain" };
      assert.equal(await prismorTools({ read }).read.execute({}), "plain");
    },
  );
});

test("identityToken is sent as X-Prismor-Identity, never in the body", async () => {
  const requests = [];
  await withMockFetch(recordingFetch(requests), async () => {
    const run_shell = { execute: async ({ command }) => `ran: ${command}` };
    const tools = prismorTools({ run_shell }, { identityToken: "eyJ.test.sig" });
    await tools.run_shell.execute({ command: "echo hi" });
    assert.equal(requests[0].headers["X-Prismor-Identity"], "Bearer eyJ.test.sig");
    assert.equal(JSON.stringify(requests[0].body).includes("eyJ.test.sig"), false);
  });
});

test("langchain: tools report under the langchain framework id, not vercel-ai", async () => {
  const requests = [];
  await withMockFetch(recordingFetch(requests), async () => {
    const { prismorLangChainTool } = require("../dist/index.js");
    const t = prismorLangChainTool({ name: "run_shell", invoke: async () => "ok" }, { agentName: "support-langgraph-js" });
    await t.invoke({ command: "echo hi" });
  });
  assert.equal(requests[0].body.agent, "langchain");
  assert.equal(requests[0].body.agent_name, "support-langgraph-js");
});

test("a toolset run inside another agent's tool reports as a subagent", async () => {
  const requests = [];
  await withMockFetch(recordingFetch(requests), async () => {
    const fetch_url = { execute: async ({ url }) => `fetched ${url}` };
    const researcherTools = prismorTools({ fetch_url }, { agentName: "researcher" });
    const ask_researcher = {
      // A subagent: this tool runs another agent, which calls its own tools.
      execute: async ({ q }) => researcherTools.fetch_url.execute({ url: q }, { toolCallId: "inner-1" }),
    };
    const mainTools = prismorTools({ fetch_url, ask_researcher }, { agentName: "support-bot" });
    await mainTools.fetch_url.execute({ url: "https://a.test" }, { toolCallId: "c1" });
    await mainTools.ask_researcher.execute({ q: "https://b.test" }, { toolCallId: "c2" });
  });
  const by = (n) => requests.filter((r) => r.body.tool_name === n);
  assert.equal(by("fetch_url")[0].body.subagent, undefined);          // main agent
  assert.equal(by("ask_researcher")[0].body.subagent, undefined);     // main agent launching it
  const { root, ...sub } = by("fetch_url")[1].body.subagent;
  assert.deepEqual(sub, { id: "support-bot:c2", type: "researcher", parent: "support-bot", depth: 1, chain: ["support-bot"] });
  assert.equal(root, by("ask_researcher")[0].body.session_id);  // counted in the launching call's session
});

test("a subagent of a subagent reports depth 2 and its chain", async () => {
  const requests = [];
  await withMockFetch(recordingFetch(requests), async () => {
    const lookup = { execute: async () => "found" };
    const summTools = prismorTools({ lookup }, { agentName: "summarizer" });
    const resTools = prismorTools({
      ask_summarizer: { execute: async () => summTools.lookup.execute({}, { toolCallId: "s1" }) },
    }, { agentName: "researcher" });
    const mainTools = prismorTools({
      ask_researcher: { execute: async () => resTools.ask_summarizer.execute({}, { toolCallId: "r1" }) },
    }, { agentName: "support-bot" });
    await mainTools.ask_researcher.execute({}, { toolCallId: "m1" });
  });
  const { root, ...sub } = requests.find((r) => r.body.tool_name === "lookup").body.subagent;
  assert.equal(root, requests.find((r) => r.body.tool_name === "ask_researcher").body.session_id);
  assert.deepEqual(sub, { id: "researcher:r1", type: "summarizer", parent: "researcher",
                          depth: 2, chain: ["support-bot", "researcher"] });
});

test("langgraph js: a call inside an agent subgraph is a subagent; a lone ReAct agent is not", async () => {
  const requests = [];
  await withMockFetch(recordingFetch(requests), async () => {
    const { prismorLangChainTool } = require("../dist/index.js");
    const t = prismorLangChainTool({ name: "fetch_url", invoke: async () => "ok" });
    // Shapes from a live @langchain/langgraph 1.5 run.
    await t.invoke({ url: "a" }, { metadata: { langgraph_checkpoint_ns: "tools:84a9" } });
    await t.invoke({ url: "b" }, { metadata: { langgraph_checkpoint_ns: "researcher:a730|tools:cd9a" } });
  });
  assert.equal(requests[0].body.subagent, undefined);
  assert.deepEqual(requests[1].body.subagent, { id: "researcher:a730", type: "researcher" });
});

test("a tool listed in handoffs sends handoff_to", async () => {
  const requests = [];
  await withMockFetch(recordingFetch(requests), async () => {
    const tools = prismorTools({ ask_researcher: { execute: async () => "ok" }, other: { execute: async () => "ok" } },
      { agentName: "support-bot", handoffs: { ask_researcher: "researcher" } });
    await tools.ask_researcher.execute({ q: "x" }, { toolCallId: "h1" });
    await tools.other.execute({}, { toolCallId: "h2" });
  });
  assert.equal(requests[0].body.handoff_to, "researcher");
  assert.equal(requests[1].body.handoff_to, undefined);
});

// ── Sessions: one per request, not one per process ──────────────────────────
// Tools are wrapped once at module scope, so before useSession() every user's
// calls on a long-running server shared the toolset's single session.

test("one module-scope toolset, two concurrent requests: each request is its own session", async () => {
  const requests = [];
  await withMockFetch(recordingFetch(requests), async () => {
    const tools = prismorTools({ a: { execute: async () => "a" }, b: { execute: async () => "b" } });
    const turn = (user) => useSubject(`user:${user}`, async () => {
      await tools.a.execute({}, {});
      await new Promise((r) => setTimeout(r, 5));
      await tools.b.execute({}, {});
    });
    await Promise.all([turn("alice"), turn("bob")]);
  });
  const byUser = (u) => new Set(requests.filter((r) => r.body.subject === `user:${u}`).map((r) => r.body.session_id));
  assert.equal(byUser("alice").size, 1, "alice's two calls share one session");
  assert.equal(byUser("bob").size, 1, "bob's two calls share one session");
  assert.notDeepEqual([...byUser("alice")], [...byUser("bob")], "alice and bob are different sessions");
});

test("useSession() groups calls under the caller's own conversation id, across tools", async () => {
  const requests = [];
  await withMockFetch(recordingFetch(requests), async () => {
    const tools = prismorTools({ a: { execute: async () => "a" }, b: { execute: async () => "b" } });
    await useSession("chat:42", async () => {
      await useSubject("user:alice", () => tools.a.execute({}, {}));  // an open session is kept
      await tools.b.execute({}, {});
    });
  });
  assert.deepEqual(requests.map((r) => r.body.session_id), ["chat:42", "chat:42"]);
});

test("outside any request scope a toolset keeps one session for all its tools", async () => {
  const requests = [];
  await withMockFetch(recordingFetch(requests), async () => {
    const tools = prismorTools({ a: { execute: async () => "a" }, b: { execute: async () => "b" } });
    await tools.a.execute({}, {});
    await tools.b.execute({}, {});
  });
  assert.equal(new Set(requests.map((r) => r.body.session_id)).size, 1);
});
