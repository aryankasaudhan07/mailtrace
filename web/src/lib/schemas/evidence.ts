/**
 * THE CONTRACT (ported from app/schemas/evidence.py).
 *
 * Every analyzer emits a list of Evidence records and nothing else. No analyzer
 * returns a score or a verdict, and no analyzer reads another's output. The
 * scorer (lib/scoring/engine.ts) is the only component that reads the full
 * evidence set and decides what it means.
 *
 * The wire shape is snake_case, identical to the Python API, so the ported
 * frontend consumes it unchanged.
 */

export enum Analyzer {
  M1_INGEST = 'M1',
  M2_HEADERS = 'M2',
  M3_AUTH = 'M3',
  M4_CONTENT = 'M4',
  M5_NETWORK = 'M5',
  M6_DOMAIN = 'M6',
  M7_GRAPH = 'M7',
}

/**
 * The four states an analyzer may report. UNAVAILABLE is load-bearing: when a
 * lane cannot run (no network, rate limited, timeout) it says so rather than
 * throwing, and the scorer lowers confidence instead of failing the request.
 */
export enum Status {
  TRIGGERED = 'TRIGGERED',
  CLEAR = 'CLEAR',
  UNAVAILABLE = 'UNAVAILABLE',
  ERROR = 'ERROR',
}

export interface Evidence {
  case_id: string;
  analyzer: Analyzer;
  /** Stable snake_case key. MUST exist in weights.yaml. */
  signal: string;
  status: Status;
  /** This analyzer's certainty in its own observation, 0..1. Deterministic checks report 1.0. */
  confidence: number;
  /** Human-readable specifics; printed verbatim in the forensic report. */
  detail: Record<string, unknown>;
  /** Exactly what the source returned; for later audit, never rendered. */
  raw: Record<string, unknown>;
  observed_at: string;
}

// ---- convenience constructors: use these, not object literals directly ----

export function triggered(
  caseId: string,
  analyzer: Analyzer,
  signal: string,
  detail: Record<string, unknown> = {},
  confidence = 1.0,
  raw: Record<string, unknown> = {},
): Evidence {
  return {
    case_id: caseId, analyzer, signal, status: Status.TRIGGERED,
    confidence, detail, raw, observed_at: new Date().toISOString(),
  };
}

export function clear(
  caseId: string,
  analyzer: Analyzer,
  signal: string,
  detail: Record<string, unknown> = {},
): Evidence {
  return {
    case_id: caseId, analyzer, signal, status: Status.CLEAR,
    confidence: 1.0, detail, raw: {}, observed_at: new Date().toISOString(),
  };
}

/** Use on timeout, rate limit, or missing intel database. */
export function unavailable(
  caseId: string,
  analyzer: Analyzer,
  signal: string,
  reason: string,
): Evidence {
  return {
    case_id: caseId, analyzer, signal, status: Status.UNAVAILABLE,
    confidence: 0.0, detail: { reason }, raw: {}, observed_at: new Date().toISOString(),
  };
}

/** An analyzer that broke: a bug, not a verdict. Ignored by the score. */
export function errorEvidence(
  caseId: string,
  analyzer: Analyzer,
  errType: string,
  message: string,
): Evidence {
  return {
    case_id: caseId, analyzer, signal: 'lane_error', status: Status.ERROR,
    confidence: 0.0, detail: { error: errType, message: message.slice(0, 500) },
    raw: {}, observed_at: new Date().toISOString(),
  };
}
