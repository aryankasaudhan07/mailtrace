/**
 * The analyzer framework (ported from app/analyzers/base.py):
 * a registry and a safe concurrent runner.
 *
 * Every analyzer is an async function (caseId, email) => Evidence[]. It never
 * throws into the caller, never returns a score, and never reads another
 * analyzer's output. runAll enforces that: a lane that times out or throws
 * becomes UNAVAILABLE / ERROR evidence, and the request still completes.
 */

import { Analyzer, errorEvidence, unavailable, type Evidence } from '../schemas/evidence';
import type { ParsedEmail } from '../schemas/email';

export const DEFAULT_TIMEOUT_MS = 12_000;

export type AnalyzerFn = (caseId: string, email: ParsedEmail) => Promise<Evidence[]>;

const REGISTRY = new Map<Analyzer, AnalyzerFn>();

/** Register an analyzer's entry point. Re-registering an id replaces it. */
export function register(id: Analyzer, fn: AnalyzerFn): void {
  REGISTRY.set(id, fn);
}

export function registry(): Map<Analyzer, AnalyzerFn> {
  return new Map(REGISTRY);
}

class LaneTimeout extends Error {}

async function runOne(
  id: Analyzer,
  fn: AnalyzerFn,
  caseId: string,
  email: ParsedEmail,
  timeoutMs: number,
): Promise<Evidence[]> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new LaneTimeout()), timeoutMs);
  });
  try {
    return await Promise.race([fn(caseId, email), timeout]);
  } catch (e) {
    if (e instanceof LaneTimeout) {
      return [unavailable(caseId, id, 'lane_timeout', `exceeded ${(timeoutMs / 1000).toFixed(0)}s`)];
    }
    const err = e as Error;
    return [errorEvidence(caseId, id, err?.name || 'Error', err?.message || String(e))];
  } finally {
    if (timer) clearTimeout(timer);
  }
}

/** Run every registered analyzer concurrently and flatten the evidence. */
export async function runAll(
  caseId: string,
  email: ParsedEmail,
  timeoutMs: number = DEFAULT_TIMEOUT_MS,
): Promise<Evidence[]> {
  const reg = registry();
  if (reg.size === 0) {
    console.error('no analyzers registered -- did you import the analyzers barrel?');
    return [];
  }
  const results = await Promise.all(
    [...reg.entries()].map(([id, fn]) => runOne(id, fn, caseId, email, timeoutMs)),
  );
  return results.flat();
}
