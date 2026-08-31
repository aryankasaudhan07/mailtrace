/**
 * Per-request owner context.
 *
 * Cases, the content-hash idempotency index and the M7 correlation index are
 * all scoped to the user who created them, so two accounts never see or
 * cross-correlate each other's mail. Most store calls take `owner` explicitly,
 * but the M7 analyzer reaches the indicator index through the uniform
 * `(caseId, email)` analyzer signature and has no owner to pass. We carry the
 * owner for the duration of `analyzeAndStore` in an AsyncLocalStorage so those
 * calls resolve the right namespace without changing the analyzer contract.
 *
 * Anything running outside an owner scope (tests, ad-hoc calls) falls back to a
 * single shared `__default__` namespace — isolated, deterministic, and never
 * mixed with a real user's data.
 */
import { AsyncLocalStorage } from 'node:async_hooks';

export const DEFAULT_OWNER = '__default__';

const als = new AsyncLocalStorage<string>();

/** Run `fn` with `owner` as the ambient owner for every store call it makes. */
export function runAsOwner<T>(owner: string, fn: () => T): T {
  return als.run(owner || DEFAULT_OWNER, fn);
}

/** The ambient owner, or the shared default namespace when none is set. */
export function currentOwner(): string {
  return als.getStore() ?? DEFAULT_OWNER;
}
