"use strict";
/**
 * Tests for the Mastra adapter. No live eval-server — global fetch is
 * stubbed so these run standalone.
 */
const test = require("node:test");
const assert = require("node:assert/strict");
const { prismorTool, prismorTools, PrismorBlocked, registerSubagents } = require("../dist/index.js");

function withMockFetch(impl, fn) {
  const original = globalThis.fetch;
  globalThis.fetch = impl;
  return Promise.resolve(fn()).finally(() => {
    globalThis.fetch = original;
  });
}

const ALLOW = { allow: true, reason: null };
const DENY = { allow: false, reason: "policy violation: destructive command" };

test("allows the call when the eval-server returns allow: true", async () => {
  await withMockFetch(
    async () => ({ ok: true, json: async () => ALLOW }),
    async () => {
      const runShell = { execute: async (input) => `ran: ${input.command}` };
      const guarded = prismorTool("run_shell", runShell);
      const result = await guarded.execute({ command: "echo hi" });
      assert.equal(result, "ran: echo hi");
    },
  );
});

test("throws PrismorBlocked and never calls the original execute when denied", async () => {
  await withMockFetch(
    async () => ({ ok: true, json: async () => DENY }),
    async () => {
      let called = false;
      const runShell = { execute: async () => { called = true; return "should not run"; } };
      const guarded = prismorTool("run_shell", runShell);
      await assert.rejects(() => guarded.execute({ command: "rm -rf /" }), PrismorBlocked);
      assert.equal(called, false);
    },
  );
});

test("enforce mode fails closed when the eval-server is unreachable", async () => {
  await withMockFetch(
    async () => { throw new Error("connection refused"); },
    async () => {
      const runShell = { execute: async () => "should not run" };
      const guarded = prismorTool("run_shell", runShell, { mode: "enforce" });
      await assert.rejects(() => guarded.execute({ command: "echo hi" }), PrismorBlocked);
    },
  );
});

test("observe mode fails open when the eval-server is unreachable", async () => {
  await withMockFetch(
    async () => { throw new Error("connection refused"); },
    async () => {
      const runShell = { execute: async (input) => `ran: ${input.command}` };
      const guarded = prismorTool("run_shell", runShell, { mode: "observe" });
      const result = await guarded.execute({ command: "echo hi" });
      assert.equal(result, "ran: echo hi");
    },
  );
});

test("prismorTools wraps every tool in a record", async () => {
  await withMockFetch(
    async () => ({ ok: true, json: async () => ALLOW }),
    async () => {
      const tools = {
        run_shell: { execute: async (input) => `shell: ${input.command}` },
        read_file: { execute: async (input) => `file: ${input.path}` },
      };
      const guarded = prismorTools(tools);
      assert.equal(await guarded.run_shell.execute({ command: "echo hi" }), "shell: echo hi");
      assert.equal(await guarded.read_file.execute({ path: "/tmp/x" }), "file: /tmp/x");
    },
  );
});

test("does not double-wrap an already-guarded tool", async () => {
  await withMockFetch(
    async () => ({ ok: true, json: async () => ALLOW }),
    async () => {
      const runShell = { execute: async (input) => `ran: ${input.command}` };
      const once = prismorTool("run_shell", runShell);
      const twice = prismorTool("run_shell", once);
      assert.equal(once.execute, twice.execute);
    },
  );
});

test("agentName is sent so the console can name and control this agent", async () => {
  const bodies = [];
  await withMockFetch(
    async (url, init) => { bodies.push(JSON.parse(init.body)); return { ok: true, json: async () => ALLOW }; },
    async () => {
      const guarded = prismorTool("run_shell", { execute: async () => "ok" }, { agentName: "support-mastra" });
      await guarded.execute({ command: "echo hi" });
    },
  );
  assert.equal(bodies[0].agent, "mastra");
  assert.equal(bodies[0].agent_name, "support-mastra");
});

test("sub-agents report as subagents of a registered parent's run; alone they are main", async () => {
  const bodies = [];
  await withMockFetch(
    async (url, init) => { bodies.push(JSON.parse(init.body)); return { ok: true, json: async () => ALLOW }; },
    async () => {
      // Shapes from a live @mastra/core 1.79 run: ctx.agent.agentId names the running agent.
      const fetchUrl = prismorTool("fetch_url", { execute: async () => "ok" });
      const main = registerSubagents({
        id: "support-bot",
        // Mastra runs the sub-agent from inside the parent's generate().
        async generate() {
          await fetchUrl.execute({ url: "a" }, { agent: { agentId: "support-bot", toolCallId: "c1" } });
          await fetchUrl.execute({ url: "b" }, { agent: { agentId: "researcher", toolCallId: "c2" } });
        },
      });
      await main.generate("go");
      // The sub-agent run on its own: no parent, the main agent.
      await fetchUrl.execute({ url: "c" }, { agent: { agentId: "researcher", toolCallId: "c3" } });
      // Agent as tool: another agent run from inside a guarded tool.
      const inner = prismorTool("fetch_url", { execute: async () => "ok" }, { agentName: "writer" });
      const askWriter = prismorTool("ask_writer", { execute: async () => inner.execute({ url: "d" }) });
      await askWriter.execute({ q: "x" }, { agent: { agentId: "support-bot", toolCallId: "c4" } });
    },
  );
  assert.equal(bodies[0].subagent, undefined);
  assert.equal(bodies[1].subagent.type, "researcher");
  assert.equal(bodies[1].subagent.parent, "support-bot");
  assert.equal(bodies[2].subagent, undefined);
  assert.equal(bodies[3].subagent, undefined); // ask_writer itself, called by the main agent
  assert.deepEqual(bodies[4].subagent, { id: "support-bot:c4", type: "writer", parent: "mastra" });
});
