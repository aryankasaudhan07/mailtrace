/**
 * What the scorer returns (ported from app/schemas/verdict.py).
 * The only place a number becomes a judgement.
 */

import type { Analyzer } from './evidence';

export enum Band {
  BENIGN = 'BENIGN', // 1-25 (clean)
  SUSPICIOUS = 'SUSPICIOUS', // 26-50
  HIGH_RISK = 'HIGH_RISK', // 51-75
  CRITICAL = 'CRITICAL', // 76-100
}

export function bandFromScore(score: number): Band {
  if (score >= 76) return Band.CRITICAL;
  if (score >= 51) return Band.HIGH_RISK;
  if (score >= 26) return Band.SUSPICIOUS;
  return Band.BENIGN;
}

/** One line of the explanation. The UI ranks these by |points|. */
export interface Contribution {
  signal: string;
  analyzer: Analyzer;
  weight: number;
  confidence: number;
  points: number;
  label: string;
  rationale: string;
  detail: Record<string, unknown>;
}

export interface Verdict {
  case_id: string;
  score: number; // 0..100
  band: Band;
  confidence: number; // 0..1, separate from score
  scorer_version: string;
  contributions: Contribution[];
  lanes_unavailable: Analyzer[];
  suppressed_negatives: string[];
  suppressed_by: string[];
  summary: string;
}
