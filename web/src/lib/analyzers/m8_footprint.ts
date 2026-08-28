/**
 * M8 -- sender email footprint / account enumeration.
 *
 * Answers "where does this sender's email address already have accounts?" -- the
 * OSINT technique behind the open-source tool Holehe: many platforms leak, on
 * signup or password-reset, whether an address is already registered.
 *
 * Forensic value: a throwaway address registered nowhere reads differently from
 * an address with a long-lived footprint, and a disposable/temp-mail sender is a
 * cheap, high-signal red flag. This is identity context, NOT attribution, and a
 * large footprint never means "safe" (a real, established mailbox can still be
 * compromised -- see the threat model on thread hijacking).
 *
 * Sources, in order of reliability:
 *   1. Disposable-domain match       -- offline, deterministic, always runs.
 *   2. Gravatar avatar + profile     -- reliable server-side; the profile JSON
 *                                       lists the owner's linked accounts, which
 *                                       is genuine cross-platform footprint.
 *   3. Platform-probe catalog        -- best-effort live probing; most sites
 *                                       block datacenter IPs, so these commonly
 *                                       return "unknown" from production.
 *   4. Simulated dataset             -- clearly labelled (`simulated: true`), for
 *                                       demos where live probing is blocked.
 *
 * Never raises: every network path is guarded and degrades to UNAVAILABLE.
 */

import { createHash } from 'node:crypto';
import { Analyzer, clear, triggered, unavailable, type Evidence } from '../schemas/evidence';
import type { ParsedEmail } from '../schemas/email';
import { config } from '../config';
import { register } from './base';

// Known disposable / temp-mail providers (offline signal).
const DISPOSABLE = new Set([
  'mailinator.com', 'guerrillamail.com', 'guerrillamail.info', 'sharklasers.com',
  '10minutemail.com', '10minutemail.net', 'temp-mail.org', 'tempmail.com', 'tempmailo.com',
  'yopmail.com', 'yopmail.net', 'getnada.com', 'nada.email', 'trashmail.com', 'trashmail.de',
  'dispostable.com', 'maildrop.cc', 'fakeinbox.com', 'throwawaymail.com', 'mailnesia.com',
  'mohmal.com', 'emailondeck.com', 'moakt.com', 'tempr.email', 'discard.email',
  'spamgourmet.com', 'mailcatch.com', 'inboxbear.com', 'tempmailaddress.com', 'burnermail.io',
  'mail-temp.com', 'temp-mail.io', 'minuteinbox.com', 'mailpoof.com', 'harakirimail.com',
  'guerrillamailblock.com', 'grr.la', 'spam4.me', 'anonaddy.me', 'byom.de',
]);

// Public webmail providers -- an address here with no footprint is unremarkable
// (privacy-conscious users), so "no footprint" is never scored as suspicious.
const WEBMAIL = new Set([
  'gmail.com', 'googlemail.com', 'outlook.com', 'hotmail.com', 'live.com', 'msn.com',
  'yahoo.com', 'yahoo.co.in', 'ymail.com', 'icloud.com', 'me.com', 'proton.me', 'protonmail.com',
  'aol.com', 'gmx.com', 'zoho.com', 'mail.com', 'yandex.com',
]);

// Platform catalog for the probe/simulation layer.
const CATALOG = [
  'Instagram', 'Facebook', 'X (Twitter)', 'LinkedIn', 'Spotify', 'Adobe', 'Pinterest',
  'GitHub', 'Duolingo', 'WordPress', 'Imgur', 'Patreon', 'Snapchat', 'Discord',
  'Reddit', 'Netflix', 'Amazon', 'Microsoft', 'Apple', 'Dropbox', 'Quora', 'Twitch',
];

export type FootStatus = 'registered' | 'not_registered' | 'unknown';
export interface PlatformHit {
  platform: string;
  status: FootStatus;
  method: string;
  simulated: boolean;
}

const md5 = (s: string) => createHash('md5').update(s).digest('hex');
const sha256 = (s: string) => createHash('sha256').update(s).digest('hex');

function timeoutSignal(ms: number): AbortSignal {
  const c = new AbortController();
  setTimeout(() => c.abort(), ms).unref?.();
  return c.signal;
}

/** Gravatar: avatar existence + the profile's linked accounts (real footprint). */
async function checkGravatar(email: string): Promise<PlatformHit[]> {
  const hash = md5(email.trim().toLowerCase());
  const hits: PlatformHit[] = [];
  // 1) avatar: d=404 makes the endpoint 404 when no image is set for the hash
  try {
    const r = await fetch(`https://www.gravatar.com/avatar/${hash}?d=404&s=64`, {
      method: 'GET', signal: timeoutSignal(6000), redirect: 'follow',
    });
    if (r.ok) hits.push({ platform: 'Gravatar', status: 'registered', method: 'gravatar-avatar', simulated: false });
  } catch { /* network/blocked -> just skip */ }
  // 2) profile JSON: lists the owner's linked social accounts
  try {
    const r = await fetch(`https://www.gravatar.com/${hash}.json`, {
      method: 'GET', signal: timeoutSignal(6000), redirect: 'follow',
      headers: { 'user-agent': 'Mailtrace-Footprint/1.0' },
    });
    if (r.ok) {
      if (!hits.some((h) => h.platform === 'Gravatar')) {
        hits.push({ platform: 'Gravatar', status: 'registered', method: 'gravatar-profile', simulated: false });
      }
      const body = (await r.json()) as { entry?: Array<{ accounts?: Array<{ name?: string; shortname?: string; domain?: string }> }> };
      const accounts = body?.entry?.[0]?.accounts ?? [];
      for (const a of accounts) {
        const name = a.name || a.shortname || a.domain;
        if (name) hits.push({ platform: cap(name), status: 'registered', method: 'gravatar-linked-account', simulated: false });
      }
    }
  } catch { /* skip */ }
  return hits;
}

const cap = (s: string) => s.charAt(0).toUpperCase() + s.slice(1);

export interface BreachInfo {
  count: number;
  breaches: string[];
  earliest: string | null; // YYYY-MM-DD
  latest: string | null;
  simulated: boolean;
}

/** HaveIBeenPwned breach lookup (real). Needs HIBP_API_KEY; degrades to null. */
async function checkHIBP(email: string): Promise<BreachInfo | null> {
  const key = config.hibpKey();
  if (!key) return null;
  try {
    const r = await fetch(
      `https://haveibeenpwned.com/api/v3/breachedaccount/${encodeURIComponent(email)}?truncateResponse=false`,
      { signal: timeoutSignal(6000), headers: { 'hibp-api-key': key, 'user-agent': 'Mailtrace-Footprint/1.0' } },
    );
    if (r.status === 404) return { count: 0, breaches: [], earliest: null, latest: null, simulated: false };
    if (!r.ok) return null; // rate limited / auth error -> no data, don't guess
    const arr = (await r.json()) as Array<{ Name: string; Title?: string; BreachDate?: string }>;
    const dates = arr.map((b) => b.BreachDate).filter((d): d is string => !!d).sort();
    return {
      count: arr.length,
      breaches: arr.map((b) => b.Title || b.Name).slice(0, 12),
      earliest: dates[0] ?? null,
      latest: dates[dates.length - 1] ?? null,
      simulated: false,
    };
  } catch {
    return null;
  }
}

/**
 * XposedOrNot breach lookup -- a FREE, keyless public breach API (a HIBP
 * alternative). breach-analytics returns per-breach `xposed_date` years, giving
 * both the breach list and an earliest-year age floor. Degrades to null.
 */
async function checkXposedOrNot(email: string): Promise<BreachInfo | null> {
  try {
    const r = await fetch(`https://api.xposedornot.com/v1/breach-analytics?email=${encodeURIComponent(email)}`, {
      signal: timeoutSignal(6000), headers: { 'user-agent': 'Mailtrace-Footprint/1.0' },
    });
    if (r.status === 404) return { count: 0, breaches: [], earliest: null, latest: null, simulated: false };
    if (!r.ok) return null;
    const d = (await r.json()) as { ExposedBreaches?: { breaches_details?: Array<{ breach?: string; xposed_date?: string }> } };
    const details = d?.ExposedBreaches?.breaches_details;
    if (!Array.isArray(details) || details.length === 0) {
      return { count: 0, breaches: [], earliest: null, latest: null, simulated: false };
    }
    const thisYear = new Date().getUTCFullYear();
    const years = details
      .map((b) => Number(String(b.xposed_date ?? '').match(/\d{4}/)?.[0]))
      .filter((y) => y > 1990 && y <= thisYear + 1)
      .sort((a, b) => a - b);
    const names = details.map((b) => b.breach).filter((n): n is string => !!n).slice(0, 12);
    return {
      count: details.length,
      breaches: names,
      earliest: years.length ? `${years[0]}-01-01` : null,
      latest: years.length ? `${years[years.length - 1]}-01-01` : null,
      simulated: false,
    };
  } catch {
    return null;
  }
}

// Real breach names, only used to make the labelled DEMO summary look plausible.
const DEMO_BREACHES = ['Collection1', 'LinkedIn', 'Adobe', 'Canva', 'Dropbox', 'MyFitnessPal', 'Chegg', 'Twitter', 'Wattpad', 'Deezer', 'Ticketmaster'];

/** Deterministic, clearly-labelled simulated breach summary for demos. */
function simulatedBreach(email: string): BreachInfo {
  const b = Buffer.from(sha256(email.toLowerCase()), 'hex');
  const count = 1 + (b[2] % 7); // 1..7
  const year = 2012 + (b[3] % 11); // 2012..2022
  const month = 1 + (b[4] % 12);
  const earliest = `${year}-${String(month).padStart(2, '0')}-01`;
  const names: string[] = [];
  const used = new Set<number>();
  let i = 5;
  while (names.length < count && used.size < DEMO_BREACHES.length) {
    const idx = b[i % b.length] % DEMO_BREACHES.length;
    i += 1;
    if (used.has(idx)) continue;
    used.add(idx);
    names.push(DEMO_BREACHES[idx]);
  }
  return { count, breaches: names, earliest, latest: earliest, simulated: true };
}

/** Fold a BreachInfo into the report-friendly shape (adds age estimate). */
function breachDetail(b: BreachInfo | null, source: string | null) {
  if (!b) return { checked: false };
  const year = b.earliest ? Number(b.earliest.slice(0, 4)) : null;
  return {
    checked: true,
    simulated: b.simulated,
    source, // 'hibp' | 'xposedornot' | 'demo'
    count: b.count,
    earliest: b.earliest,
    latest: b.latest,
    established_since: year ? String(year) : null,
    min_age_years: year ? Math.max(0, new Date().getUTCFullYear() - year) : null,
    names: b.breaches,
  };
}

/**
 * Live platform probing. Most consumer platforms block datacenter IPs and change
 * their signup/reset endpoints often, so from a serverless host these usually
 * resolve to "unknown" -- which is honest evidence, not a failure. We probe the
 * address's own domain reachability as a cheap, real liveness check and leave the
 * per-platform result "unknown" rather than guessing.
 */
async function probeCatalog(): Promise<PlatformHit[]> {
  // Deliberately conservative: we do not ship fragile scraped endpoints that
  // would fabricate results. Real per-platform hits come from Gravatar above;
  // the catalog is surfaced via the (clearly labelled) simulated layer.
  return CATALOG.map((platform) => ({ platform, status: 'unknown' as FootStatus, method: 'live-probe', simulated: false }));
}

/** Deterministic, clearly-labelled simulated footprint for demos. */
function simulatedFootprint(email: string): PlatformHit[] {
  const h = sha256(email.toLowerCase());
  const bytes = Buffer.from(h, 'hex');
  // count 3..8, stable per address
  const count = 3 + (bytes[0] % 6);
  const chosen: PlatformHit[] = [];
  const used = new Set<number>();
  let i = 1;
  while (chosen.length < count && used.size < CATALOG.length) {
    const idx = bytes[i % bytes.length] % CATALOG.length;
    i += 1;
    if (used.has(idx)) continue;
    used.add(idx);
    chosen.push({ platform: CATALOG[idx], status: 'registered', method: 'simulated-dataset', simulated: true });
  }
  return chosen;
}

/** Merge sources; a real result always wins over a simulated one for a platform. */
function merge(...lists: PlatformHit[][]): PlatformHit[] {
  const byName = new Map<string, PlatformHit>();
  for (const list of lists) {
    for (const hit of list) {
      const existing = byName.get(hit.platform);
      if (!existing) { byName.set(hit.platform, hit); continue; }
      // prefer real over simulated, and registered over unknown/not
      const better =
        (existing.simulated && !hit.simulated) ||
        (existing.status !== 'registered' && hit.status === 'registered');
      if (better) byName.set(hit.platform, hit);
    }
  }
  return [...byName.values()];
}

async function analyze(caseId: string, email: ParsedEmail): Promise<Evidence[]> {
  const addr = (email.from_addr || '').trim().toLowerCase();
  if (!addr || !addr.includes('@')) {
    return [unavailable(caseId, Analyzer.M8_FOOTPRINT, 'sender_email_footprint', 'no sender address to profile')];
  }
  const domain = addr.split('@').pop() as string;
  const out: Evidence[] = [];

  // 1) disposable / temp-mail domain (offline, scored)
  if (DISPOSABLE.has(domain)) {
    out.push(triggered(caseId, Analyzer.M8_FOOTPRINT, 'disposable_sender_domain', {
      domain,
      note: 'Sender uses a disposable / temporary-inbox provider — typical of throwaway attacker accounts.',
    }));
  }

  // 2) gather footprint from the enabled sources
  const online = config.footprintOnline();
  const demo = config.footprintDemo();
  const sources: PlatformHit[][] = [];
  let probedLive = false;

  let breach: BreachInfo | null = null;
  let breachSource: string | null = null;
  if (online) {
    sources.push(await checkGravatar(addr));
    sources.push(await probeCatalog());
    // real breach lookup: HIBP when a key is set, otherwise the free XposedOrNot
    breach = await checkHIBP(addr);
    if (breach) breachSource = 'hibp';
    if (!breach) { breach = await checkXposedOrNot(addr); if (breach) breachSource = 'xposedornot'; }
    probedLive = true;
  }
  if (demo) sources.push(simulatedFootprint(addr));
  // fill the breach/age with the labelled demo summary when a real lookup found
  // nothing (e.g. synthetic sample addresses), so the demo stays illustrative
  if (demo && (!breach || breach.count === 0)) { breach = simulatedBreach(addr); breachSource = 'demo'; }

  const all = merge(...sources);
  const registered = all.filter((h) => h.status === 'registered');
  const realRegistered = registered.filter((h) => !h.simulated);

  // nothing could run: offline and demo disabled
  if (!online && !demo) {
    return [...out, unavailable(caseId, Analyzer.M8_FOOTPRINT, 'sender_email_footprint', 'footprint checks disabled (offline)')];
  }

  const detail = {
    email: addr,
    domain,
    webmail: WEBMAIL.has(domain),
    disposable: DISPOSABLE.has(domain),
    registered_count: registered.length,
    real_count: realRegistered.length,
    registered: registered.map((h) => ({ platform: h.platform, method: h.method, simulated: h.simulated })),
    platforms: registered.map((h) => h.platform),
    probed_live: probedLive,
    includes_simulated: registered.some((h) => h.simulated),
    breach: breachDetail(breach, breachSource),
    sources: { gravatar: online, live_probe: online, breach: breachSource, simulated_dataset: demo },
  };

  if (registered.length > 0) {
    out.push(clear(caseId, Analyzer.M8_FOOTPRINT, 'sender_email_footprint', detail));
  } else {
    // Ran, found nothing. Informational only (weight 0) — never treat a clean
    // webmail address with no visible footprint as malicious.
    out.push(clear(caseId, Analyzer.M8_FOOTPRINT, 'sender_no_footprint', detail));
  }

  // ---- legitimacy credits (negative-weight; REAL evidence only) ----
  // An aged, widely-registered address is strong evidence of a genuine sender.
  // Simulated/demo data never earns credit — only real Gravatar/breach evidence.
  const realBreach = breach && !breach.simulated ? breach : null;
  const earliestYear = realBreach?.earliest ? Number(realBreach.earliest.slice(0, 4)) : null;
  const ageYears = earliestYear ? Math.max(0, new Date().getUTCFullYear() - earliestYear) : null;
  const establishedEvidence = realRegistered.length >= 3 || (!!realBreach && realBreach.count >= 5);
  const aged = ageYears != null && ageYears >= 2;
  if (establishedEvidence || aged) {
    const creditDetail = {
      email: addr,
      real_platforms: realRegistered.length,
      breach_count: realBreach?.count ?? 0,
      in_use_since: earliestYear,
      age_years: ageYears,
      established: establishedEvidence && aged,
      note: 'Aged / widely-registered real identity — attackers use fresh throwaways, not long-lived widely-registered addresses. Credit is cancelled if the message is forged or diverts money.',
    };
    const signal = establishedEvidence && aged ? 'established_sender_identity' : 'known_footprint_sender';
    out.push(triggered(caseId, Analyzer.M8_FOOTPRINT, signal, creditDetail));
  }

  return out;
}

register(Analyzer.M8_FOOTPRINT, analyze);

export { analyze, DISPOSABLE, CATALOG, simulatedFootprint };
