/**
 * Shared settings, caches and band presentation for the extension.
 *
 * Everything the worker and the UI both need lives here so there is one
 * definition of each storage key. Imported by the service worker (module) and
 * by the popup/onboarding pages.
 *
 * Note on bands: the four names come from the Verdict contract and are decided
 * only by the backend's scorer. This file maps a band that has already been
 * decided onto a colour and a label. It must never derive a band from a score —
 * that is the scorer's job, and a local copy of the thresholds is how copies
 * drift apart (app/schemas/verdict.py and web/src/lib/schemas/verdict.ts
 * already disagree by one point at each boundary).
 */

export const DEFAULTS = {
  // Mailtrace backend session (shared with the read-receipt feature).
  base: 'https://mailtrace-zeta.vercel.app',
  token: '',
  email: '',
  trackingOn: true,

  // Gmail inbox scanning.
  scanOn: false,
  pollSeconds: 15,
  gmailAddress: '',
  historyId: '', // Gmail history cursor; '' means "not baselined yet"
  lastScanAt: 0,
  lastError: '',
};

const SCORED_MAX = 100; // records kept for the popup list
const SEEN_MAX = 600; // message ids kept for de-duplication

export async function getState() {
  const s = await chrome.storage.local.get(DEFAULTS);
  return { ...DEFAULTS, ...s };
}

export async function setState(patch) {
  await chrome.storage.local.set(patch);
}

/**
 * Band -> how we show it. `risk` mirrors web/src/spa/api.js so the extension
 * and the web UI never label the same verdict differently.
 */
export const BANDS = {
  CRITICAL: { label: 'Critical', risk: 'CRITICAL', fg: '#7f1d1d', bg: 'rgba(185,28,28,.14)', dot: '#b91c1c', rank: 4 },
  HIGH_RISK: { label: 'High Risk', risk: 'HIGH RISK', fg: '#9a3412', bg: 'rgba(194,65,12,.14)', dot: '#c2410c', rank: 3 },
  SUSPICIOUS: { label: 'Suspicious', risk: 'MEDIUM RISK', fg: '#854d0e', bg: 'rgba(161,98,7,.16)', dot: '#a16207', rank: 2 },
  BENIGN: { label: 'Clean', risk: 'LOW RISK', fg: '#0e7a57', bg: 'rgba(14,122,87,.12)', dot: '#0e7a57', rank: 1 },
};

export const UNKNOWN_BAND = { label: 'Unscored', risk: 'UNKNOWN', fg: '#57534e', bg: 'rgba(0,0,0,.06)', dot: '#a8a29e', rank: 0 };

export const bandStyle = (band) => BANDS[band] || UNKNOWN_BAND;

// ---------------------------------------------------------------------------
// Scored records
//
// chrome.storage has no compare-and-swap and the worker can run several
// analyses at once, so every read-modify-write goes through this queue.
// ---------------------------------------------------------------------------

let chain = Promise.resolve();

function serialize(fn) {
  const run = chain.then(fn, fn);
  chain = run.catch(() => {});
  return run;
}

export async function getScored() {
  const { scored } = await chrome.storage.local.get({ scored: [] });
  return scored;
}

export async function getSeen() {
  const { seen } = await chrome.storage.local.get({ seen: [] });
  return seen;
}

/** True if this Gmail message id has already been queued or scored. */
export async function markSeen(msgId) {
  return serialize(async () => {
    const { seen } = await chrome.storage.local.get({ seen: [] });
    if (seen.includes(msgId)) return false;
    seen.push(msgId);
    await chrome.storage.local.set({ seen: seen.slice(-SEEN_MAX) });
    return true;
  });
}

export async function unmarkSeen(msgId) {
  return serialize(async () => {
    const { seen } = await chrome.storage.local.get({ seen: [] });
    await chrome.storage.local.set({ seen: seen.filter((id) => id !== msgId) });
  });
}

// ---------------------------------------------------------------------------
// Retry queue
//
// The Gmail history cursor only moves forward, so a message that fails to
// analyze is never reported again — "leave it unseen and let the next poll
// re-find it" does not work. Failed ids are parked here instead and re-tried
// explicitly, a bounded number of times.
// ---------------------------------------------------------------------------

const RETRY_MAX_TRIES = 4;

/** Park a message for another attempt. Returns false once it's out of tries. */
export async function pushRetry(msgId) {
  return serialize(async () => {
    const { retry } = await chrome.storage.local.get({ retry: [] });
    const found = retry.find((r) => r.id === msgId);
    const tries = (found?.tries ?? 0) + 1;
    if (tries > RETRY_MAX_TRIES) {
      await chrome.storage.local.set({ retry: retry.filter((r) => r.id !== msgId) });
      return false;
    }
    const next = [...retry.filter((r) => r.id !== msgId), { id: msgId, tries }];
    await chrome.storage.local.set({ retry: next });
    return true;
  });
}

/** Hand back up to `limit` parked ids, removing them from the queue. */
export async function takeRetries(limit) {
  return serialize(async () => {
    const { retry } = await chrome.storage.local.get({ retry: [] });
    const take = retry.slice(0, limit);
    await chrome.storage.local.set({ retry: retry.slice(take.length) });
    return take.map((r) => r.id);
  });
}

export async function retryDepth() {
  const { retry } = await chrome.storage.local.get({ retry: [] });
  return retry.length;
}

// ---------------------------------------------------------------------------
// In-flight claims
//
// An MV3 worker can be evicted mid-batch. Ids are marked seen (and pulled off
// the retry queue) before analysis, so without a durable record of "claimed but
// not finished" an eviction would leave those messages seen, unscored, absent
// from the retry queue and invisible in the UI — silently dropped, because the
// de-dup gate skips them on the next pass.
//
// A claim is written before the attempt and released only once the outcome is
// durable: a stored record, or a slot in the retry queue.
// ---------------------------------------------------------------------------

export async function claimInflight(msgIds) {
  return serialize(async () => {
    const { inflight } = await chrome.storage.local.get({ inflight: [] });
    await chrome.storage.local.set({ inflight: [...new Set([...inflight, ...msgIds])] });
  });
}

export async function releaseInflight(msgId) {
  return serialize(async () => {
    const { inflight } = await chrome.storage.local.get({ inflight: [] });
    await chrome.storage.local.set({ inflight: inflight.filter((id) => id !== msgId) });
  });
}

/**
 * Claims left over from a previous worker generation.
 *
 * Only one scan runs per worker instance, so anything still claimed when a scan
 * starts belongs to a worker that died. Clears and returns them so the caller
 * can requeue.
 */
export async function reclaimInflight() {
  return serialize(async () => {
    const { inflight } = await chrome.storage.local.get({ inflight: [] });
    if (inflight.length) await chrome.storage.local.set({ inflight: [] });
    return inflight;
  });
}

/** Insert or replace a record, newest first. */
export async function putScored(record) {
  return serialize(async () => {
    const { scored } = await chrome.storage.local.get({ scored: [] });
    const next = [record, ...scored.filter((r) => r.msgId !== record.msgId)].slice(0, SCORED_MAX);
    await chrome.storage.local.set({ scored: next });
    return next;
  });
}

export async function clearScored() {
  return serialize(async () => {
    await chrome.storage.local.set({ scored: [], seen: [], retry: [], inflight: [] });
  });
}

/** Worst band still unacknowledged, for the toolbar badge. */
export function worstUnread(scored) {
  let worst = null;
  let count = 0;
  for (const r of scored) {
    if (r.acked || !r.band || r.band === 'BENIGN') continue;
    count += 1;
    const s = bandStyle(r.band);
    if (!worst || s.rank > bandStyle(worst).rank) worst = r.band;
  }
  return { band: worst, count };
}

export async function ackAll() {
  return serialize(async () => {
    const { scored } = await chrome.storage.local.get({ scored: [] });
    await chrome.storage.local.set({ scored: scored.map((r) => ({ ...r, acked: true })) });
  });
}
