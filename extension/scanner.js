/**
 * The inbox scan pipeline.
 *
 *   Gmail history cursor -> new INBOX message ids -> raw bytes
 *     -> POST /api/cases -> verdict -> chrome.storage -> badge
 *
 * The extension deliberately does no scoring and no parsing. It ships raw bytes
 * to the configured backend and renders the band that backend's scorer returned;
 * display labels (subject / sender) are read back from GET /api/cases/{id}
 * rather than parsed locally.
 *
 * Which scorer that is depends on the backend URL: the FastAPI surface runs
 * app/scoring/engine.py, the Next.js one runs web/src/lib/scoring/engine.ts.
 * Those two disagree by a point at each band boundary, which is a pre-existing
 * discrepancy between the two implementations — not something this client
 * introduces or can paper over.
 */

import { getProfile, getRawMessage, getToken, listNewInboxMessages, GmailError } from './gmail.js';
import {
  bandStyle,
  claimInflight,
  getScored,
  getState,
  markSeen,
  pushRetry,
  putScored,
  reclaimInflight,
  releaseInflight,
  setState,
  takeRetries,
  unmarkSeen,
  worstUnread,
} from './store.js';

// The Next.js backend allows 60 analyses/min/user (each runs seven lanes plus
// DNS/RDAP). Capping the batch keeps a burst of mail from tripping that.
const MAX_PER_SCAN = 10;
const CONCURRENCY = 2;

// A manual backfill is allowed to exceed one batch — it chunks into MAX_PER_SCAN
// groups instead. Held below the 60/min budget so it can't rate-limit itself.
const MAX_BACKFILL = 50;

let scanning = false;

// ---------------------------------------------------------------------------
// Mailtrace backend
// ---------------------------------------------------------------------------

async function analyzeBytes(bytes, filename) {
  const { base, token } = await getState();
  if (!token) throw transient(new Error('Sign in to Mailtrace in the extension popup first.'), false);

  const form = new FormData();
  // Content-type is left to fetch so it can set the multipart boundary.
  form.append('file', new Blob([bytes], { type: 'message/rfc822' }), filename);

  const res = await fetch(base.replace(/\/$/, '') + '/api/cases', {
    method: 'POST',
    headers: { authorization: 'Bearer ' + token },
    body: form,
  });
  const data = await res.json().catch(() => null);

  if (!res.ok) {
    const msg = data?.detail || `analyze failed (${res.status})`;
    // 429 and 5xx are worth another pass; 4xx means this message will never
    // analyze and retrying it forever would block the queue.
    throw transient(new Error(msg), res.status === 429 || res.status >= 500);
  }
  return data; // { case_id, filename, sha256, verdict }
}

/** Subject/sender for the list, taken from the backend's parse of the message. */
async function fetchLabels(caseId) {
  const { base, token } = await getState();
  try {
    const res = await fetch(`${base.replace(/\/$/, '')}/api/cases/${encodeURIComponent(caseId)}`, {
      headers: { authorization: 'Bearer ' + token },
    });
    if (!res.ok) return {};
    const d = await res.json();
    return { subject: d.subject, from: d.from_addr, fromName: d.from_display_name };
  } catch {
    return {}; // a missing label is cosmetic; the verdict still stands
  }
}

function transient(err, isTransient) {
  err.transient = Boolean(isTransient);
  return err;
}

// ---------------------------------------------------------------------------
// One message
// ---------------------------------------------------------------------------

async function scoreMessage(msgId) {
  const msg = await getRawMessage(msgId);

  let result;
  try {
    result = await analyzeBytes(msg.bytes, `gmail-${msgId}.eml`);
  } catch (e) {
    // Carry the thread id so a failure can still be shown against the right
    // conversation rather than looking like a message we never scanned.
    e.threadId = msg.threadId;
    throw e;
  }

  const v = result?.verdict || {};
  const labels = await fetchLabels(result.case_id);

  await putScored({
    msgId,
    threadId: msg.threadId,
    caseId: result.case_id,
    subject: labels.subject || '(no subject)',
    from: labels.from || '',
    fromName: labels.fromName || '',
    score: typeof v.score === 'number' ? v.score : null,
    band: v.band || null,
    // Kept and displayed because score and confidence are different states —
    // see the confidence field docs in app/schemas/verdict.py.
    confidence: typeof v.confidence === 'number' ? v.confidence : null,
    scorerVersion: v.scorer_version || '',
    summary: v.summary || '',
    top: (v.contributions || [])
      .filter((c) => c.points > 0)
      .sort((a, b) => b.points - a.points)
      .slice(0, 3)
      .map((c) => c.label),
    // Why the confidence is what it is, and why good authentication did not
    // pull the score down. Dropping these leaves a partial verdict looking
    // identical to a complete one.
    lanesUnavailable: v.lanes_unavailable || [],
    suppressedNegatives: v.suppressed_negatives || [],
    suppressedBy: v.suppressed_by || [],
    receivedAt: msg.internalDate,
    at: Date.now(),
    acked: false,
  });
}

async function pool(ids, worker) {
  const queue = [...ids];
  const runners = Array.from({ length: Math.min(CONCURRENCY, queue.length) }, async () => {
    for (let id = queue.shift(); id !== undefined; id = queue.shift()) await worker(id);
  });
  await Promise.all(runners);
}

/** Returns how many actually came back with a verdict. */
async function scoreAll(ids) {
  let scored = 0;
  let failed = 0;
  // Durable "claimed but unfinished" marker, so an eviction mid-batch leaves a
  // trace to requeue instead of a hole.
  await claimInflight(ids);
  await pool(ids, async (msgId) => {
    try {
      await scoreMessage(msgId);
      scored += 1;
    } catch (e) {
      failed += 1;
      const isTransient = e?.transient || e instanceof TypeError; // TypeError == fetch/network
      // The history cursor has already moved past this id, so a retry has to be
      // queued explicitly; there is no second chance from Gmail.
      if (isTransient && (await pushRetry(msgId))) {
        await releaseInflight(msgId); // now durable in the retry queue
        return;
      }
      await putScored({
        msgId,
        threadId: e?.threadId || null, // present when the failure was in analysis, not the fetch
        subject: '(could not analyze)',
        band: null,
        score: null,
        error: String(e?.message || e),
        at: Date.now(),
        acked: true,
      });
    }
    await releaseInflight(msgId);
  });
  return { scored, failed };
}

// ---------------------------------------------------------------------------
// Badge
// ---------------------------------------------------------------------------

export async function refreshBadge() {
  const scored = await getScored();
  const { band, count } = worstUnread(scored);
  await chrome.action.setBadgeText({ text: count ? String(count) : '' });
  if (!count) {
    await chrome.action.setTitle({ title: 'Mailtrace' });
    return;
  }
  await chrome.action.setBadgeBackgroundColor({ color: bandStyle(band).dot });

  // The badge is a bare count, so the tooltip carries the qualifier: a verdict
  // reached with lanes offline should not read the same as a complete one.
  const worstRec = scored.find((r) => r.band === band && !r.acked);
  const pct = worstRec?.confidence != null ? Math.round(worstRec.confidence * 100) : null;
  const qualifier = pct != null && pct < 100 ? ` at ${pct}% confidence` : '';
  await chrome.action.setTitle({
    title: `Mailtrace — ${count} message(s) need attention (worst: ${bandStyle(band).label}${qualifier})`,
  });
}

// ---------------------------------------------------------------------------
// Scan
// ---------------------------------------------------------------------------

/** Move the cursor to "now" so we only score mail that arrives from here on. */
async function baseline() {
  const { historyId, address } = await getProfile();
  await setState({ historyId, gmailAddress: address, lastError: '' });
  return historyId;
}

/**
 * Score everything that landed in the inbox since the last scan, plus anything
 * parked by an earlier failure.
 *
 * Safe to call from any trigger; overlapping calls collapse into one. `force`
 * is for the popup's explicit Refresh, which should work even while the
 * automatic scan is paused.
 */
export async function scanOnce({ force = false } = {}) {
  if (scanning) return { ok: true, skipped: 'already scanning' };
  scanning = true;
  try {
    const st = await getState();
    if (!st.scanOn && !force) return { ok: true, skipped: 'scanning off' };
    if (!st.token) return { ok: false, error: 'Sign in to Mailtrace first.' };

    if (!st.historyId) {
      await baseline();
      await setState({ lastScanAt: Date.now() });
      return { ok: true, baselined: true, scored: 0 };
    }

    const { ids, historyId, resync } = await listNewInboxMessages(st.historyId);
    if (resync) {
      await baseline();
      await setState({ lastScanAt: Date.now() });
      return { ok: true, baselined: true, scored: 0 };
    }

    // Anything still claimed belongs to a worker that was evicted mid-batch.
    // Requeue it before taking retries so it goes back in the normal rotation.
    for (const id of await reclaimInflight()) await pushRetry(id);

    // Failed-and-parked ids go first; they are already past the cursor, so
    // nothing else will re-offer them.
    const retries = await takeRetries(MAX_PER_SCAN);

    // markSeen is the de-dup gate: it returns false for ids already handled,
    // which matters because Gmail can report the same add on two cursors.
    const fresh = [];
    for (const id of ids) if (await markSeen(id)) fresh.push(id);

    const room = Math.max(0, MAX_PER_SCAN - retries.length);
    const batch = [...retries, ...fresh.slice(0, room)];
    // Anything over the cap goes back to unseen so the next tick re-finds it
    // from the same history window.
    const deferred = fresh.slice(room);
    for (const id of deferred) await unmarkSeen(id);

    const { scored, failed } = batch.length ? await scoreAll(batch) : { scored: 0, failed: 0 };

    await setState({
      // Holding the cursor back while ids are deferred is what lets the next
      // tick see them again.
      historyId: deferred.length ? st.historyId : (historyId || st.historyId),
      lastScanAt: Date.now(),
      lastError: '',
    });
    await refreshBadge();
    return { ok: true, scored, failed, pending: deferred.length };
  } catch (e) {
    const error = String(e?.message || e);
    await setState({ lastError: error, lastScanAt: Date.now() });
    return { ok: false, error, needsConsent: e instanceof GmailError && e.needsConsent };
  } finally {
    scanning = false;
  }
}

/**
 * Score a message obtained from the Gmail web session instead of the API.
 *
 * Same backend call and same verdict handling as the OAuth path; the only
 * difference is provenance, which is recorded on the record. `dkimSafe` false
 * means the bytes came out of HTML and DKIM re-verification in M3 cannot be
 * trusted — surfaced, not hidden, because a wrong DKIM result is worse than
 * none.
 */
export async function analyzeSessionMessage({ b64, decimal, fidelity, dkimSafe }) {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i += 1) bytes[i] = bin.charCodeAt(i);

  const msgId = 'session-' + decimal;
  try {
    const result = await analyzeBytes(bytes, `gmail-${decimal}.eml`);
    const v = result?.verdict || {};
    const labels = await fetchLabels(result.case_id);
    await putScored({
      msgId,
      threadId: null, // the session path has no API thread id
      caseId: result.case_id,
      subject: labels.subject || '(no subject)',
      from: labels.from || '',
      fromName: labels.fromName || '',
      score: typeof v.score === 'number' ? v.score : null,
      band: v.band || null,
      confidence: typeof v.confidence === 'number' ? v.confidence : null,
      scorerVersion: v.scorer_version || '',
      summary: v.summary || '',
      top: (v.contributions || []).filter((c) => c.points > 0).sort((a, b) => b.points - a.points).slice(0, 3).map((c) => c.label),
      lanesUnavailable: v.lanes_unavailable || [],
      suppressedNegatives: v.suppressed_negatives || [],
      suppressedBy: v.suppressed_by || [],
      source: 'session',
      fidelity,
      dkimTrustworthy: Boolean(dkimSafe),
      at: Date.now(),
      acked: false,
    });
    await refreshBadge();
    return { ok: true, caseId: result.case_id, band: v.band, score: v.score, dkimSafe: Boolean(dkimSafe) };
  } catch (e) {
    return { ok: false, error: String(e?.message || e) };
  }
}

/**
 * Score the most recent inbox messages regardless of the cursor.
 *
 * The normal flow only looks forward, which means a freshly connected mailbox
 * shows nothing until new mail arrives. This backfills on demand so the feature
 * can be demonstrated and tested immediately.
 *
 * `count` is a number of messages to *consider*, not a page size: Gmail returns
 * at most 100 ids per page, and the analysis runs in MAX_PER_SCAN chunks, so
 * both are handled here rather than silently truncating the request.
 */
export async function scanRecent(count = 25) {
  if (scanning) return { ok: false, error: 'A scan is already running.' };
  scanning = true;
  try {
    const st = await getState();
    if (!st.token) return { ok: false, error: 'Sign in to Mailtrace first.' };

    const want = Math.max(1, Math.min(Number(count) || 25, MAX_BACKFILL));
    const token = await getToken({ interactive: false });

    // Page through the id list until we have `want` of them (or run out of mail).
    const found = [];
    let pageToken = '';
    while (found.length < want) {
      const qs = new URLSearchParams({
        labelIds: 'INBOX',
        maxResults: String(Math.min(want - found.length, 100)),
      });
      if (pageToken) qs.set('pageToken', pageToken);
      const res = await fetch(`https://gmail.googleapis.com/gmail/v1/users/me/messages?${qs}`, {
        headers: { authorization: 'Bearer ' + token },
      });
      if (!res.ok) return { ok: false, error: `Gmail list failed (${res.status})` };
      const data = await res.json();
      for (const m of data.messages || []) found.push(m.id);
      pageToken = data.nextPageToken || '';
      if (!pageToken || !(data.messages || []).length) break;
    }

    const ids = [];
    for (const id of found) if (await markSeen(id)) ids.push(id);
    if (!st.historyId) await baseline();

    // Chunk so a 50-message backfill still respects the per-batch cap.
    let scored = 0;
    let failed = 0;
    for (let i = 0; i < ids.length; i += MAX_PER_SCAN) {
      const r = await scoreAll(ids.slice(i, i + MAX_PER_SCAN));
      scored += r.scored;
      failed += r.failed;
    }
    await refreshBadge();
    // "skipped" is mail we had already scored, the common case on a second press.
    return { ok: true, scored, failed, considered: found.length, skipped: found.length - ids.length };
  } catch (e) {
    return { ok: false, error: String(e?.message || e), needsConsent: e instanceof GmailError && e.needsConsent };
  } finally {
    scanning = false;
  }
}
