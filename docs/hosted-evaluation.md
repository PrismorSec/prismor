# Hosted evaluation (enterprise)

Agents normally check each tool call against policy on their own machine: the
Python adapters run the policy engine in-process, and other languages call a
`prismor eval-server` sidecar. On the enterprise plan, Prismor can run that
evaluator for you. Your agents point at it, install nothing extra, and every call
is checked against your org's policy and shows up in the console.

## Connect an agent

Prismor gives you a URL and an eval key for your org.

**Python** (every adapter: OpenAI Agents, LangChain/LangGraph, CrewAI, Google ADK,
Agent Framework, LlamaIndex, smolagents, AG2, ...):

```bash
export PRISMOR_EVAL_URL=https://<your-org>.lambda-url.us-east-1.on.aws
export PRISMOR_EVAL_KEY=...
```

No code change: every adapter calls the hosted evaluator once these are set.
`PRISMOR_EVAL_TIMEOUT` (seconds, default 5) bounds each call.

**TypeScript** (`@prismor/vercel-ai`, `@prismor/mastra`):

```ts
prismorTools(tools, {
  evalUrl: process.env.PRISMOR_EVAL_URL,
  apiKey: process.env.PRISMOR_EVAL_KEY,
  agentName: "checkout-bot",
});
```

**Any language:** `POST {PRISMOR_EVAL_URL}/v1/evaluate` with
`Authorization: Bearer <eval key>`; the request and response are the eval-server's
([sdk-integration.md](sdk-integration.md)).

The agent does not need `PRISMOR_AGENT_KEY`: the hosted evaluator holds your
org's key, pulls its signed policy and reports each call. Calls are recorded once,
on the evaluator; the agent's machine writes nothing.

## What changes compared with running it yourself

- **Tool arguments go to Prismor.** Commands, paths and payloads are sent to the
  hosted evaluator before anything is redacted. Running the evaluator yourself
  keeps them on your infrastructure.
- **Each tool call makes a network round trip** to the evaluator.
- **If the evaluator cannot be reached, `enforce` fails closed** (the call is
  refused with a reason naming the endpoint) and `observe` fails open.
- **Checks that read the agent's own machine do not run**: resolving the script a
  command executes, reading the files it names, and workspace scope. Rules on the
  command text, tools, egress, IAM and the semantic judge all apply.
- **Cross-call memory** (taint from an earlier call in the session) lasts while
  the evaluator instance stays warm.

To keep tool arguments on your own infrastructure, run `prismor eval-server`
yourself and point the same variables at it.

Operators: deployment is in [deploy/lambda/README.md](../deploy/lambda/README.md).
