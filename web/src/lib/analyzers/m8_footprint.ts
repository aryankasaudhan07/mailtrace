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
 * Sources are ALL REAL -- no simulated/demo data:
 *   1. Disposable-domain match  -- offline, deterministic, always runs.
 *   2. Gravatar                 -- avatar existence + the profile's linked social
 *                                  accounts (genuine cross-platform footprint).
 *   3. Data-breach records      -- HIBP (with key) or the free XposedOrNot: a
 *                                  breach on a platform is proof the address had
 *                                  an account there (in the LinkedIn breach ->
 *                                  had a LinkedIn account). Combolists / data
 *                                  brokers are filtered out. Also gives the age
 *                                  floor ("in use since <earliest breach year>").
 *   4. Live account-existence   -- REAL Holehe-style probes of platforms whose
 *      probes                      public signup/reset endpoints answer honestly
 *                                  (Chess.com, Spotify, Duolingo, WordPress,
 *                                  Adobe, Plurk).
 *
 * LinkedIn / Instagram / X / Threads / Quora hard-block automated checks
 * (429 / anti-bot / login required) and cannot be probed from a server -- that is
 * a real limitation of every tool, not a shortcut. From a datacenter IP (Vercel)
 * even the working probes may be blocked and return "unknown".
 *
 * Never raises: every network path is guarded and degrades to UNAVAILABLE.
 */

import { createHash } from 'node:crypto';
import { Analyzer, clear, triggered, type Evidence } from '../schemas/evidence';
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

// Breach "names" that are combolists / data brokers / infostealer dumps, NOT a
// single platform the address was registered on -- excluded from the platform list.
const BREACH_AGGREGATORS = [
  'collection', 'antipublic', 'exploit', 'onliner', 'verifications', 'peopledatalabs',
  'people data labs', 'pdl', 'data enrichment', 'dataenrichment', 'breachcompilation',
  'breach compilation', 'pemiblanc', 'spambot', 'combolist', 'combo list', 'stealer',
  'redline', 'raccoon', 'scraped', 'unverified', 'pentester', 'naz.api', 'nazapi',
];
const isAggregatorBreach = (name: string) => {
  const n = name.toLowerCase();
  return BREACH_AGGREGATORS.some((a) => n.includes(a));
};

export type FootStatus = 'registered' | 'not_registered' | 'unknown';
export interface PlatformHit {
  platform: string;
  status: FootStatus;
  method: string;
  simulated: boolean;
}

const md5 = (s: string) => createHash('md5').update(s).digest('hex');

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

const BROWSER_UA =
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36';

/**
 * REAL account-enumeration probes (the Holehe technique): hit each platform's
 * public signup/reset endpoint and read whether the email is already registered.
 * Only platforms that answer a datacenter request are here -- LinkedIn / Instagram
 * / X / Threads / Quora hard-block automated checks (429 / anti-bot / login
 * required) and simply cannot be checked from a server. Each probe is guarded and
 * degrades to 'unknown'.
 */
interface LiveProbe { name: string; check: (email: string) => Promise<FootStatus>; }

const LIVE_PROBES: LiveProbe[] = [
  {
    name: 'Chess.com',
    check: async (email) => {
      const r = await fetch(`https://www.chess.com/callback/email/available?email=${encodeURIComponent(email)}`,
        { signal: timeoutSignal(6000), headers: { 'user-agent': BROWSER_UA } });
      if (!r.ok) return 'unknown';
      const d = (await r.json()) as { isEmailAvailable?: boolean };
      if (typeof d.isEmailAvailable !== 'boolean') return 'unknown';
      return d.isEmailAvailable ? 'not_registered' : 'registered';
    },
  },
  {
    name: 'Spotify',
    check: async (email) => {
      const r = await fetch(`https://spclient.wg.spotify.com/signup/public/v1/account?validate=1&email=${encodeURIComponent(email)}`,
        { signal: timeoutSignal(6000), headers: { 'user-agent': BROWSER_UA } });
      if (!r.ok) return 'unknown';
      const d = (await r.json()) as { status?: number; errors?: { email?: string } };
      if (d.errors?.email || d.status === 20) return 'registered';
      if (d.status === 1) return 'not_registered';
      return 'unknown';
    },
  },
  {
    name: 'Duolingo',
    check: async (email) => {
      const r = await fetch(`https://www.duolingo.com/2017-06-30/users?email=${encodeURIComponent(email)}`,
        { signal: timeoutSignal(6000), headers: { 'user-agent': BROWSER_UA } });
      if (!r.ok) return 'unknown';
      const d = (await r.json()) as { users?: unknown[] };
      if (!Array.isArray(d.users)) return 'unknown';
      return d.users.length > 0 ? 'registered' : 'not_registered';
    },
  },
  {
    name: 'WordPress',
    check: async (email) => {
      const r = await fetch(`https://public-api.wordpress.com/rest/v1.1/users/${encodeURIComponent(email)}/auth-options`,
        { signal: timeoutSignal(6000), headers: { 'user-agent': BROWSER_UA } });
      const d = (await r.json().catch(() => null)) as { error?: string } | null;
      if (!d) return 'unknown';
      if (d.error === 'unknown_user') return 'not_registered';
      if (r.ok && !d.error) return 'registered';
      return 'unknown';
    },
  },
  {
    name: 'Adobe',
    check: async (email) => {
      const r = await fetch('https://auth.services.adobe.com/signin/v2/users/accounts', {
        method: 'POST', signal: timeoutSignal(6000),
        headers: { 'user-agent': BROWSER_UA, 'content-type': 'application/json', 'x-ims-clientid': 'adobedotcom2' },
        body: JSON.stringify({ username: email }),
      });
      if (!r.ok) return 'unknown';
      const d = (await r.json().catch(() => null)) as unknown[] | null;
      if (!Array.isArray(d)) return 'unknown';
      return d.length > 0 ? 'registered' : 'not_registered';
    },
  },
  {
    name: 'Plurk',
    check: async (email) => {
      const r = await fetch('https://www.plurk.com/Users/isEmailFound', {
        method: 'POST', signal: timeoutSignal(6000),
        headers: { 'user-agent': BROWSER_UA, 'content-type': 'application/x-www-form-urlencoded' },
        body: `email=${encodeURIComponent(email)}`,
      });
      if (!r.ok) return 'unknown';
      const t = (await r.text()).trim().toLowerCase();
      if (t === 'true') return 'registered';
      if (t === 'false') return 'not_registered';
      return 'unknown';
    },
  },
];

/** Run every live probe concurrently; a thrown/blocked probe becomes 'unknown'. */
async function runLiveProbes(email: string): Promise<PlatformHit[]> {
  const settled = await Promise.allSettled(
    LIVE_PROBES.map(async (p) => ({ platform: p.name, status: await p.check(email).catch((): FootStatus => 'unknown') })),
  );
  return settled.map((s, i) => ({
    platform: LIVE_PROBES[i].name,
    status: s.status === 'fulfilled' ? s.value.status : 'unknown',
    method: 'live-probe',
    simulated: false,
  }));
}

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
      breaches: arr.map((b) => b.Title || b.Name).slice(0, 50),
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
    const names = details.map((b) => b.breach).filter((n): n is string => !!n).slice(0, 50);
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

/**
 * Turn REAL breach names into platform registrations. A breach on a platform is
 * hard proof the address had an account there (the address is in the LinkedIn
 * breach => it had a LinkedIn account). Combolists / data-broker dumps are
 * excluded -- they aren't a single platform.
 */
function breachPlatforms(names: string[]): PlatformHit[] {
  const out: PlatformHit[] = [];
  const seen = new Set<string>();
  for (const raw of names) {
    const name = raw.trim();
    if (!name || isAggregatorBreach(name)) continue;
    const key = name.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    out.push({ platform: name, status: 'registered', method: 'breach-record', simulated: false });
  }
  return out;
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
/** Merge sources; de-duplicates a platform seen from more than one source. */
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
    // No address to profile. M8 stays NEUTRAL (CLEAR, weight 0) rather than
    // UNAVAILABLE, so a missing footprint never adds points nor lowers confidence.
    return [clear(caseId, Analyzer.M8_FOOTPRINT, 'sender_no_footprint', { reason: 'no sender address to profile' })];
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

  // 2) gather footprint from REAL sources only (no simulated/demo data):
  //    Gravatar (avatar + linked accounts) and data-breach records, where a
  //    breach on a platform is proof the address had an account there.
  const online = config.footprintOnline();
  const sources: PlatformHit[][] = [];

  let breach: BreachInfo | null = null;
  let breachSource: string | null = null;
  let probeResults: PlatformHit[] = [];
  if (online) {
    // run Gravatar, breach lookup and the live platform probes concurrently
    const [grav, hibp, probes] = await Promise.all([
      checkGravatar(addr),
      checkHIBP(addr),
      runLiveProbes(addr),
    ]);
    sources.push(grav);
    probeResults = probes;
    // real breach lookup: HIBP when a key is set, otherwise the free XposedOrNot
    breach = hibp;
    if (breach) breachSource = 'hibp';
    if (!breach) { breach = await checkXposedOrNot(addr); if (breach) breachSource = 'xposedornot'; }
    if (breach && breach.breaches.length) sources.push(breachPlatforms(breach.breaches));
    // live-probe hits (real account-existence confirmations)
    sources.push(probes.filter((p) => p.status === 'registered'));
  }

  // No network to check the footprint. M8 stays NEUTRAL (CLEAR, weight 0) rather
  // than UNAVAILABLE: not finding a footprint must never add points nor lower
  // confidence -- the absence of a credit is the only effect. (Disposable ran above.)
  if (!online) {
    return [...out, clear(caseId, Analyzer.M8_FOOTPRINT, 'sender_no_footprint', { reason: 'footprint check needs network access' })];
  }

  const registered = merge(...sources).filter((h) => h.status === 'registered');

  const detail = {
    email: addr,
    domain,
    webmail: WEBMAIL.has(domain),
    disposable: DISPOSABLE.has(domain),
    registered_count: registered.length,
    real_count: registered.length,
    registered: registered.map((h) => ({ platform: h.platform, method: h.method, simulated: false })),
    platforms: registered.map((h) => h.platform),
    probed_live: true,
    includes_simulated: false,
    // full live-probe transparency: what was checked and the real result
    probes: probeResults.map((p) => ({ platform: p.platform, status: p.status })),
    breach: breachDetail(breach, breachSource),
    sources: { gravatar: online, breach: breachSource, live_probe: online },
  };

  if (registered.length > 0) {
    out.push(clear(caseId, Analyzer.M8_FOOTPRINT, 'sender_email_footprint', detail));
  } else {
    // Ran, found nothing. Informational only (weight 0) — never treat a clean
    // webmail address with no visible footprint as malicious.
    out.push(clear(caseId, Analyzer.M8_FOOTPRINT, 'sender_no_footprint', detail));
  }

  // ---- legitimacy credits (negative-weight; all evidence is real) ----
  // An aged, widely-registered address is strong evidence of a genuine sender.
  const realBreach = breach && breach.count > 0 ? breach : null;
  const earliestYear = realBreach?.earliest ? Number(realBreach.earliest.slice(0, 4)) : null;
  const ageYears = earliestYear ? Math.max(0, new Date().getUTCFullYear() - earliestYear) : null;
  const anyRealFootprint = registered.length >= 1 || !!realBreach; // any confirmed real account
  const establishedEvidence = registered.length >= 3 || (!!realBreach && realBreach.count >= 5);
  const aged = ageYears != null && ageYears >= 2;
  if (anyRealFootprint || aged) {
    const strong = establishedEvidence && aged;
    const creditDetail = {
      email: addr,
      real_platforms: registered.length,
      breach_count: realBreach?.count ?? 0,
      in_use_since: earliestYear,
      age_years: ageYears,
      established: strong,
      note: 'Real, confirmed account footprint — a throwaway attack address is registered nowhere. Credit is cancelled if the message is forged or diverts money.',
    };
    const signal = strong ? 'established_sender_identity' : 'known_footprint_sender';
    out.push(triggered(caseId, Analyzer.M8_FOOTPRINT, signal, creditDetail));
  }

  return out;
}

register(Analyzer.M8_FOOTPRINT, analyze);

export { analyze, DISPOSABLE, breachPlatforms };
