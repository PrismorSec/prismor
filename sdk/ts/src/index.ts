/**
 * prismor-sdk — the Prismor client for TypeScript/JavaScript agents.
 *
 *   import { PrismorClient, PrismorBlocked, useSubject } from "prismor-sdk";
 *
 *   const client = new PrismorClient({ mode: "enforce" });
 *   const runShell = client.guard(async ({ command }) => exec(command), { toolName: "run_shell" });
 *
 * Every check is a POST to the local eval-server (`prismor eval-server`),
 * which runs the same policy pipeline as the coding-agent hooks. The client
 * never talks to the control plane. See docs/sdk-clients.md.
 */
export { PrismorClient } from "./client";
export { PrismorBlocked } from "./types";
export { useSubject, resolveSubject } from "./subject";
export type {
  BlockContext,
  CheckOptions,
  GuardOptions,
  PrismorClientOptions,
  PrismorContract,
  PrismorDecision,
  PrismorEventType,
  PrismorFailMode,
  PrismorFinding,
  PrismorMode,
  PrismorSubject,
} from "./types";
