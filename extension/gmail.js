/**
 * Gmail access: OAuth consent + the three REST calls we need.
 *
 * Why the API and not the DOM: Mailtrace's verdict rests on `Received:` hop
 * reconstruction and on M3 re-verifying DKIM against the original bytes. Gmail's
 * rendered DOM exposes neither, and anything we re-serialize ourselves breaks
 * the signature. `messages.get?format=raw` returns the untouched RFC 5322
 * message, which is the only input the backend parser is specified against.
 *
 * Scope is `gmail.readonly` — the narrowest scope that still returns a full
 * message body. `gmail.metadata` omits the body, so M4 (content) would go dark.
 */

const GMAIL = 'https://gmail.googleapis.com/gmail/v1/users/me';
const REVOKE = 'https://oauth2.googleapis.com/revoke';
const REQUIRED_SCOPE = 'https://www.googleapis.com/auth/gmail.readonly';

/** Set by whoever edits the manifest; see extension/README.md. */
export function clientIdConfigured() {
  const id = chrome.runtime.getManifest().oauth2?.client_id || '';
  return Boolean(id) && !id.startsWith('REPLACE_WITH');
}

export class GmailError extends Error {
  constructor(message, { needsConsent = false, needsSetup = false, status = 0 } = {}) {
    super(message);
    this.needsConsent = needsConsent;
    this.needsSetup = needsSetup;
    this.status = status;
  }
}

/**
 * Ask Chrome for a Gmail access token.
 *
 * `interactive: true` is what actually shows the Google account chooser and the
 * consent screen, so it must only be called from a user gesture (the onboarding
 * page or the popup). The background poll always uses `interactive: false` and
 * treats a miss as "not connected" rather than popping a window under the user.
 */
export async function getToken({ interactive }) {
  if (!clientIdConfigured()) {
    throw new GmailError(
      'This build has no Google OAuth client ID yet. See extension/README.md → "Connect Gmail".',
      { needsSetup: true },
    );
  }

  let result;
  try {
    result = await chrome.identity.getAuthToken({ interactive, scopes: [REQUIRED_SCOPE] });
  } catch (e) {
    const msg = String(e?.message || e);
    // Chrome reports "not granted or revoked" both for a fresh install and for
    // a user who revoked access in their Google account.
    throw new GmailError(friendlyAuthError(msg), { needsConsent: true });
  }

  // Chrome 106+ resolves to an object; older builds resolve to a bare string.
  const token = typeof result === 'string' ? result : result?.token;
  const granted = (typeof result === 'object' && result?.grantedScopes) || null;
  if (!token) throw new GmailError('Google did not return an access token.', { needsConsent: true });

  // The consent screen lets the user un-tick the Gmail box; without this check
  // that shows up much later as an opaque 403 from the API.
  if (granted && !granted.includes(REQUIRED_SCOPE)) {
    await forgetToken(token);
    throw new GmailError('Gmail read access was not granted. Re-connect and leave the Gmail permission checked.', {
      needsConsent: true,
    });
  }
  return token;
}

function friendlyAuthError(msg) {
  if (/not signed in|no account/i.test(msg)) return 'Sign in to Chrome with the Google account you want to scan, then try again.';
  if (/revoked|not granted/i.test(msg)) return 'Gmail access has not been granted yet.';
  if (/canceled|closed|user rejected/i.test(msg)) return 'Gmail permission was declined.';
  if (/bad client id|invalid client/i.test(msg)) return 'The Google OAuth client ID in the manifest does not match this extension ID. See extension/README.md.';
  return msg;
}

async function forgetToken(token) {
  try {
    await chrome.identity.removeCachedAuthToken({ token });
  } catch {
    /* already gone */
  }
}

/** True when a token can be minted silently, i.e. consent is still in place. */
export async function isConnected() {
  if (!clientIdConfigured()) return false;
  try {
    await getToken({ interactive: false });
    return true;
  } catch {
    return false;
  }
}

/** Drop local consent and tell Google to invalidate the grant. */
export async function disconnect() {
  let token = null;
  try {
    token = await getToken({ interactive: false });
  } catch {
    /* nothing cached */
  }
  if (token) {
    await forgetToken(token);
    try {
      await fetch(`${REVOKE}?token=${encodeURIComponent(token)}`, { method: 'POST' });
    } catch {
      // Offline revoke failure still leaves the local cache cleared, which is
      // what stops this extension reading mail.
    }
  }
  try {
    await chrome.identity.clearAllCachedAuthTokens();
  } catch {
    /* not available in every channel */
  }
}

/**
 * Authenticated GET against the Gmail API.
 *
 * A 401 means the cached token went stale, which is routine — Chrome hands out
 * ~1h tokens. Drop it and mint a fresh one once before giving up.
 */
async function apiGet(path, { retry = true } = {}) {
  const token = await getToken({ interactive: false });
  const res = await fetch(GMAIL + path, { headers: { authorization: 'Bearer ' + token } });

  if (res.status === 401 && retry) {
    await forgetToken(token);
    return apiGet(path, { retry: false });
  }
  if (res.status === 403) {
    const body = await res.json().catch(() => null);
    const reason = body?.error?.message || 'Gmail API returned 403.';
    throw new GmailError(
      /insufficient|scope/i.test(reason)
        ? 'Gmail read permission is missing. Re-connect Gmail and keep the permission checked.'
        : reason,
      { needsConsent: /insufficient|scope/i.test(reason), status: 403 },
    );
  }
  if (!res.ok) {
    const body = await res.json().catch(() => null);
    throw new GmailError(body?.error?.message || `Gmail API ${res.status}`, { status: res.status });
  }
  return res.json();
}

/** Mailbox address plus the current history cursor. */
export async function getProfile() {
  const p = await apiGet('/profile');
  return { address: p.emailAddress, historyId: String(p.historyId) };
}

/**
 * Inbox messages added since `startHistoryId`.
 *
 * Returns `{ resync: true }` when Gmail has expired the cursor (it keeps only a
 * limited window of history); the caller then re-baselines from the profile
 * rather than trying to back-fill an unbounded amount of old mail.
 */
export async function listNewInboxMessages(startHistoryId, { maxPages = 5 } = {}) {
  const ids = [];
  let pageToken = '';
  let historyId = startHistoryId;

  for (let page = 0; page < maxPages; page += 1) {
    const qs = new URLSearchParams({
      startHistoryId,
      historyTypes: 'messageAdded',
      labelId: 'INBOX',
      maxResults: '100',
    });
    if (pageToken) qs.set('pageToken', pageToken);

    let data;
    try {
      data = await apiGet('/history?' + qs.toString());
    } catch (e) {
      if (e instanceof GmailError && e.status === 404) return { ids: [], historyId: null, resync: true };
      throw e;
    }

    for (const h of data.history || []) {
      for (const added of h.messagesAdded || []) {
        const m = added.message;
        if (!m?.id) continue;
        const labels = m.labelIds || [];
        // history already filters to INBOX, but a message can arrive labelled
        // SENT (mail you sent to yourself) or as a draft — neither is inbound.
        if (labels.includes('SENT') || labels.includes('DRAFT')) continue;
        ids.push(m.id);
      }
    }

    if (data.historyId) historyId = String(data.historyId);
    pageToken = data.nextPageToken || '';
    if (!pageToken) break;
  }

  return { ids: [...new Set(ids)], historyId, resync: false };
}

const b64urlToBytes = (s) => {
  const b64 = s.replace(/-/g, '+').replace(/_/g, '/');
  const bin = atob(b64 + '='.repeat((4 - (b64.length % 4)) % 4));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i += 1) out[i] = bin.charCodeAt(i);
  return out;
};

/** The original message bytes, exactly as Gmail received them. */
export async function getRawMessage(id) {
  const m = await apiGet(`/messages/${encodeURIComponent(id)}?format=raw`);
  if (!m.raw) throw new GmailError('Gmail returned no raw body for this message.');
  return {
    id: m.id,
    threadId: m.threadId,
    labelIds: m.labelIds || [],
    internalDate: m.internalDate ? Number(m.internalDate) : null,
    bytes: b64urlToBytes(m.raw),
  };
}
