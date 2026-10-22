"use strict";
/**
 * Tests for the Mastra adapter. No live eval-server — global fetch is
 * stubbed so these run standalone.
 */
const test = require("node:test");
const assert = require("node:assert/strict");
const { prismorTool, prismorTools, PrismorBlocked } = require("../dist/index.js");

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
