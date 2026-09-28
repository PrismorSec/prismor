/** Ambient subject context (multi-tenant attribution). */

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
 *   const client = new PrismorClient();                 // once, at module scope
 *   await useSubject(`user:${userId}`, () =>            // per request
 *     generateText({ model, tools, prompt }));
 *
 * The subject propagates through async calls (AsyncLocalStorage), so parallel
 * requests with different users cannot bleed into each other. An explicit
 * `subject` option takes precedence over this context.
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
      "Pass the `subject` option per request instead.",
    );
  }
  return storage.run(subject, fn);
}

/** Explicit subject, else the ambient useSubject() one, else PRISMOR_SUBJECT, else "". */
export function resolveSubject(explicit?: string): string {
  if (explicit) return explicit;
  const ambient = subjectStorage()?.getStore();
  if (ambient) return ambient;
  if (typeof process !== "undefined" && process.env && process.env.PRISMOR_SUBJECT) {
    return process.env.PRISMOR_SUBJECT;
  }
  return "";
}
