/**
 * Persistence layer. Serverless is stateless, so the in-memory case store and
 * M7's correlation index of the Python app can't survive across invocations.
 *
 * Two backends behind one interface:
 *   - Vercel KV (Redis) when KV_REST_API_URL is set (production on Vercel)
 *   - in-memory Maps otherwise (dev, tests, single-process)
 *
 * The M7 indicator index maps `${kind}:${value}` -> set of case ids.
 */

export type Indicators = Record<string, Set<string>>;

function useKv(): boolean {
  return Boolean(process.env.KV_REST_API_URL || process.env.KV_URL);
}

// ---- in-memory backend -----------------------------------------------------
const memIndicators = new Map<string, Set<string>>();
const memCases = new Map<string, StoredCase>();
const memOrder: string[] = []; // case ids, newest last
const memSha = new Map<string, string>(); // sha256 -> case id (idempotency)

/** Test/dev helper: clear the in-memory index and cases. */
export function __resetStore(): void {
  memIndicators.clear();
  memCases.clear();
  memOrder.length = 0;
  memSha.clear();
}

// ---- content-hash idempotency ----------------------------------------------
// Analyzing the same bytes must yield the same case/verdict every time (and must
// not self-correlate as a campaign with its own prior uploads).
export async function caseIdBySha(sha: string): Promise<string | null> {
  if (useKv()) {
    const { kv } = await import('@vercel/kv');
    return ((await kv.get(`sha:${sha}`)) as string | null) ?? null;
  }
  return memSha.get(sha) ?? null;
}

export async function indexSha(sha: string, caseId: string): Promise<void> {
  if (useKv()) {
    const { kv } = await import('@vercel/kv');
    await kv.set(`sha:${sha}`, caseId);
  } else {
    memSha.set(sha, caseId);
  }
}

// ---- case storage ----------------------------------------------------------
// Opaque to the store; the case-service owns the shape. Must be JSON-serializable
// (no Buffers) so it round-trips through KV.
export type StoredCase = Record<string, unknown> & { case_id: string; analyzed_at: string };

const CASE_KEY = (id: string) => `case:${id}`;
const CASE_LIST = 'cases:index'; // KV sorted set / list of ids

export async function saveCase(rec: StoredCase): Promise<void> {
  if (useKv()) {
    const { kv } = await import('@vercel/kv');
    await kv.set(CASE_KEY(rec.case_id), rec);
    // Overwriting an existing case (re-analysis) must not add a second list
    // entry -- drop any prior occurrence before pushing.
    await kv.lrem(CASE_LIST, 0, rec.case_id);
    await kv.lpush(CASE_LIST, rec.case_id);
  } else {
    const isNew = !memCases.has(rec.case_id);
    memCases.set(rec.case_id, rec);
    if (isNew) memOrder.push(rec.case_id);
  }
}

export async function getCase(id: string): Promise<StoredCase | null> {
  if (useKv()) {
    const { kv } = await import('@vercel/kv');
    return (await kv.get<StoredCase>(CASE_KEY(id))) ?? null;
  }
  return memCases.get(id) ?? null;
}

export async function listCases(limit = 200): Promise<StoredCase[]> {
  if (useKv()) {
    const { kv } = await import('@vercel/kv');
    const ids = (await kv.lrange<string>(CASE_LIST, 0, limit - 1)) ?? [];
    const recs = await Promise.all(ids.map((id) => kv.get<StoredCase>(CASE_KEY(id))));
    return recs.filter((r): r is StoredCase => r !== null);
  }
  return [...memOrder].reverse().slice(0, limit).map((id) => memCases.get(id)!).filter(Boolean);
}

// ---- indicator index (M7) --------------------------------------------------

/** Count, per prior case, how many of these indicators it shares. */
export async function findRelatedCases(indicators: Indicators): Promise<Record<string, number>> {
  const related: Record<string, number> = {};
  const kv = useKv() ? (await import('@vercel/kv')).kv : null;

  for (const [kind, values] of Object.entries(indicators)) {
    for (const value of values) {
      const key = `${kind}:${value}`;
      const members = kv
        ? ((await kv.smembers(`ind:${key}`)) as string[] | null) ?? []
        : [...(memIndicators.get(key) ?? [])];
      for (const cid of members) related[cid] = (related[cid] ?? 0) + 1;
    }
  }
  return related;
}

/** Every stored indicator as flat edges: {case_id, kind, value}. Powers the graph. */
export async function allIndicators(): Promise<Array<{ case_id: string; kind: string; value: string }>> {
  const out: Array<{ case_id: string; kind: string; value: string }> = [];
  const split = (key: string) => {
    const i = key.indexOf(':');
    return { kind: key.slice(0, i), value: key.slice(i + 1) };
  };
  if (useKv()) {
    const { kv } = await import('@vercel/kv');
    const keys = (await kv.keys('ind:*')) ?? [];
    for (const full of keys) {
      const { kind, value } = split(full.slice('ind:'.length));
      const members = ((await kv.smembers(full)) as string[] | null) ?? [];
      for (const cid of members) out.push({ case_id: cid, kind, value });
    }
  } else {
    for (const [key, set] of memIndicators) {
      const { kind, value } = split(key);
      for (const cid of set) out.push({ case_id: cid, kind, value });
    }
  }
  return out;
}

/** Record this case's indicators for future correlation. */
export async function storeIndicators(caseId: string, indicators: Indicators): Promise<void> {
  const kv = useKv() ? (await import('@vercel/kv')).kv : null;

  for (const [kind, values] of Object.entries(indicators)) {
    for (const value of values) {
      const key = `${kind}:${value}`;
      if (kv) {
        await kv.sadd(`ind:${key}`, caseId);
      } else {
        let set = memIndicators.get(key);
        if (!set) {
          set = new Set();
          memIndicators.set(key, set);
        }
        set.add(caseId);
      }
    }
  }
}
