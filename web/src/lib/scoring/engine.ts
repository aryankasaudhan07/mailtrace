/**
 * The scoring engine (ported from app/scoring/engine.py).
 * The only component that turns evidence into a verdict.
 *
 * Deterministic, versioned, fully explainable. Additive with a cap:
 *   score = clamp(sum(weight * confidence) for every TRIGGERED signal, 0, 100)
 */

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { load as loadYaml } from 'js-yaml';
import { Analyzer, Status, type Evidence } from '../schemas/evidence';
import { Band, bandFromScore, type Contribution, type Verdict } from '../schemas/verdict';

interface SignalRule {
  weight: number;
  analyzer: string;
  label?: string;
  rationale?: string;
}

interface WeightsDoc {
  version: string;
  signals: Record<string, SignalRule>;
  confidence_penalty_per_unavailable_lane?: number;
  suppress_negatives_when_any_triggered?: string[];
  identity_credits?: string[];
  identity_credit_suppressors?: string[];
}

export interface Rules {
  version: string;
  signals: Record<string, SignalRule>;
  unavailablePenalty: number;
  suppressors: Set<string>;
  /** M8 legitimacy credits: negative signals that use their own suppressor set. */
  identityCredits: Set<string>;
  /** Only these (sender-forgery / money-diversion) signals cancel identity credits. */
  identitySuppressors: Set<string>;
}

let _cached: Rules | null = null;

export function loadRules(): Rules {
  if (_cached) return _cached;
  const here = dirname(fileURLToPath(import.meta.url));
  // dev/test: source tree; the file sits next to this module.
  const doc = loadYaml(readFileSync(join(here, 'weights.yaml'), 'utf-8')) as WeightsDoc;
  _cached = {
    version: doc.version,
    signals: doc.signals,
    unavailablePenalty: doc.confidence_penalty_per_unavailable_lane ?? 0.15,
    suppressors: new Set(doc.suppress_negatives_when_any_triggered ?? []),
    identityCredits: new Set(doc.identity_credits ?? []),
    identitySuppressors: new Set(doc.identity_credit_suppressors ?? []),
  };
  return _cached;
}

/** Python's round() uses banker's rounding (half to even); replicate for parity. */
function pyRound(x: number): number {
  const floor = Math.floor(x);
  const diff = x - floor;
  if (diff < 0.5) return floor;
  if (diff > 0.5) return floor + 1;
  return floor % 2 === 0 ? floor : floor + 1; // exactly .5 -> nearest even
}

const round2 = (x: number): number => Math.round(x * 100) / 100;

export function scoreCase(caseId: string, evidence: Evidence[], rules: Rules = loadRules()): Verdict {
  let contributions: Contribution[] = [];
  const unavailableLanes = new Set<Analyzer>();
  let rawTotal = 0;
  const seen = new Map<string, number>(); // a signal firing twice keeps the strongest instance

  // First pass: is any deception signal present? If so, negative weights are
  // suppressed. A compromised mailbox produces a perfectly valid aligned DKIM
  // signature, so credit for good authentication must never cancel out evidence
  // of forgery. See docs/THREAT-MODEL.md section 7.1.
  const triggeredSignals = new Set(
    evidence.filter((e) => e.status === Status.TRIGGERED).map((e) => e.signal),
  );
  const suppressing = [...triggeredSignals].filter((s) => rules.suppressors.has(s)).sort();
  // Identity credits (established/aged sender) are cancelled only by sender-forgery
  // / money-diversion signals, NOT by content heuristics: an aged, widely-registered
  // address stays legit even if the body reads "urgent" -- it stops being legit only
  // when the message proves the sender is forged or is diverting money.
  const identitySuppressing = [...triggeredSignals].filter((s) => rules.identitySuppressors.has(s)).sort();
  const suppressed: string[] = [];

  for (const ev of evidence) {
    if (ev.status === Status.UNAVAILABLE) {
      unavailableLanes.add(ev.analyzer);
      continue;
    }
    if (ev.status !== Status.TRIGGERED) continue;

    const rule = rules.signals[ev.signal];
    if (!rule) {
      // An analyzer invented a signal not in weights.yaml -- loud, not silent.
      console.warn(
        `signal ${ev.signal} from ${ev.analyzer} is not in weights.yaml v${rules.version} -- not scored`,
      );
      continue;
    }

    const weight = Math.trunc(rule.weight);

    if (weight < 0) {
      const blocked = rules.identityCredits.has(ev.signal)
        ? identitySuppressing.length > 0
        : suppressing.length > 0;
      if (blocked) {
        if (!suppressed.includes(ev.signal)) suppressed.push(ev.signal);
        continue;
      }
    }

    const points = weight * ev.confidence;

    const prior = seen.get(ev.signal);
    if (prior !== undefined && Math.abs(prior) >= Math.abs(points)) continue;
    if (prior !== undefined) {
      rawTotal -= prior;
      contributions = contributions.filter((c) => c.signal !== ev.signal);
    }

    seen.set(ev.signal, points);
    rawTotal += points;

    contributions.push({
      signal: ev.signal,
      analyzer: ev.analyzer,
      weight,
      confidence: ev.confidence,
      points: round2(points),
      label: rule.label ?? ev.signal,
      rationale: (rule.rationale ?? '').trim(),
      detail: ev.detail,
    });
  }

  const score = Math.max(0, Math.min(100, pyRound(rawTotal)));
  const band = bandFromScore(score);

  let confidence = 1.0 - rules.unavailablePenalty * unavailableLanes.size;
  confidence = Math.max(0.0, Math.min(1.0, round2(confidence)));

  contributions.sort((a, b) => Math.abs(b.points) - Math.abs(a.points));

  const lanesUnavailable = [...unavailableLanes].sort();

  return {
    case_id: caseId,
    score,
    band,
    confidence,
    scorer_version: rules.version,
    contributions,
    lanes_unavailable: lanesUnavailable,
    suppressed_negatives: suppressed,
    suppressed_by: suppressing,
    summary: summarize(band, contributions, unavailableLanes, suppressed),
  };
}

function summarize(
  band: Band,
  contributions: Contribution[],
  unavailable: Set<Analyzer>,
  suppressed: string[],
): string {
  if (!contributions.length) {
    if (unavailable.size) {
      return 'No conclusion: every analyzer that could have produced a finding was unavailable.';
    }
    return 'No fraud indicators detected across all analyzers.';
  }
  const top = contributions.filter((c) => c.points > 0).slice(0, 3).map((c) => c.label);
  if (!top.length) return 'No fraud indicators detected; authentication checks passed.';

  let lead = `Assessed ${band.replace('_', ' ').toLowerCase()}, driven by: ${top.join('; ')}.`;
  if (unavailable.size) {
    const lanes = [...unavailable].map((a) => a.valueOf()).sort().join(', ');
    lead += ` Confidence reduced: ${unavailable.size} analyzer lane(s) unavailable (${lanes}).`;
  }
  if (suppressed.length) {
    lead +=
      ' Note: this message authenticated correctly, but that credit was withheld because ' +
      'deception indicators were also present -- a compromised or attacker-owned domain signs validly too.';
  }
  return lead;
}
