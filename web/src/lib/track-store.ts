/**
 * Storage for the Gmail open-tracking extension.
 *
 * A "track" is one sent email carrying an invisible 1x1 pixel. When the
 * recipient's mail client loads the pixel we append an open event. Same two
 * backends as the case store (Vercel KV in prod, in-memory otherwise) and the
 * same per-owner scoping: the list of your tracked mail is keyed by your email.
 *
 * The pixel endpoint is hit by the RECIPIENT (no auth, no owner), so recordOpen
 * and registerTrack both upsert-merge: whichever lands first creates the record,
 * the other fills in its half. That way an open is never lost even in the rare
 * case the recipient opens before the async register call completes.
 */

export type OpenEvent = { at: string; ua: string; ip: string };

export type TrackRecord = {
  id: string;
  owner: string;
  subject: string;
  to: string;
  created_at: string;
  opens: OpenEvent[];
  count: number;
  last_open: string | null;
};

function useKv(): boolean {
  return Boolean(process.env.KV_REST_API_URL || process.env.KV_URL);
}

// ---- in-memory backend -----------------------------------------------------
const memTracks = new Map<string, TrackRecord>();
const memTrackOrder = new Map<string, string[]>(); // owner -> ids, newest last

export function __resetTrackStore(): void {
  memTracks.clear();
  memTrackOrder.clear();
}

const TRACK_KEY = (id: string) => `track:${id}`;
const TRACK_LIST = (owner: string) => `tracks:index:${owner}`;

async function kvClient() {
  return (await import('@vercel/kv')).kv;
}

function blank(id: string): TrackRecord {
  return { id, owner: '', subject: '', to: '', created_at: new Date().toISOString(), opens: [], count: 0, last_open: null };
}

/** Register (or update the metadata of) a tracked email for `owner`. */
export async function registerTrack(id: string, owner: string, subject: string, to: string): Promise<TrackRecord> {
  if (useKv()) {
    const kv = await kvClient();
    const existing = (await kv.get<TrackRecord>(TRACK_KEY(id))) ?? blank(id);
    const isNew = !existing.owner;
    const rec: TrackRecord = { ...existing, owner, subject, to, created_at: existing.owner ? existing.created_at : new Date().toISOString() };
    await kv.set(TRACK_KEY(id), rec);
    if (isNew) {
      await kv.lrem(TRACK_LIST(owner), 0, id);
      await kv.lpush(TRACK_LIST(owner), id);
    }
    return rec;
  }
  const existing = memTracks.get(id) ?? blank(id);
  const isNew = !existing.owner;
  const rec: TrackRecord = { ...existing, owner, subject, to };
  memTracks.set(id, rec);
  if (isNew) {
    const list = memTrackOrder.get(owner) ?? [];
    list.push(id);
    memTrackOrder.set(owner, list);
  }
  return rec;
}

/** Append an open event (upserts a bare record if the pixel fires first). */
export async function recordOpen(id: string, open: OpenEvent): Promise<void> {
  if (useKv()) {
    const kv = await kvClient();
    const rec = (await kv.get<TrackRecord>(TRACK_KEY(id))) ?? blank(id);
    rec.opens.push(open);
    rec.count = rec.opens.length;
    rec.last_open = open.at;
    await kv.set(TRACK_KEY(id), rec);
    return;
  }
  const rec = memTracks.get(id) ?? blank(id);
  rec.opens.push(open);
  rec.count = rec.opens.length;
  rec.last_open = open.at;
  memTracks.set(id, rec);
}

export async function getTrack(id: string): Promise<TrackRecord | null> {
  if (useKv()) return (await (await kvClient()).get<TrackRecord>(TRACK_KEY(id))) ?? null;
  return memTracks.get(id) ?? null;
}

/** `owner`'s tracked emails, newest first. */
export async function listTracks(owner: string, limit = 200): Promise<TrackRecord[]> {
  if (useKv()) {
    const kv = await kvClient();
    const ids = (await kv.lrange<string>(TRACK_LIST(owner), 0, limit - 1)) ?? [];
    const recs = await Promise.all(ids.map((id) => kv.get<TrackRecord>(TRACK_KEY(id))));
    return recs.filter((r): r is TrackRecord => r !== null);
  }
  const ids = memTrackOrder.get(owner) ?? [];
  return [...ids].reverse().slice(0, limit).map((id) => memTracks.get(id)!).filter(Boolean);
}
