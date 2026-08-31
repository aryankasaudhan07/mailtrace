/** Small helpers for Route Handlers. */
import { HttpError, verifyToken } from './auth';

/** Identify the caller from the Bearer token, or 401. Cases and all derived
 *  views are scoped to this identity so accounts never see each other's data. */
export function requireUser(req: Request): string {
  const token = (req.headers.get('authorization') || '').replace(/^Bearer\s+/i, '').trim();
  const email = token ? verifyToken(token) : null;
  if (!email) throw new HttpError(401, 'Not authenticated');
  return email;
}

export const json = (data: unknown, status = 200) =>
  new Response(JSON.stringify(data), { status, headers: { 'content-type': 'application/json' } });

export const notFound = (msg = 'case not found') => json({ detail: msg }, 404);

/** Wrap a handler so thrown HttpError -> {detail} with its status; else 500. */
export async function guard(fn: () => Promise<Response>): Promise<Response> {
  try {
    return await fn();
  } catch (e) {
    if (e instanceof HttpError) return json({ detail: e.message }, e.status);
    return json({ detail: (e as Error).message ?? 'internal error' }, 500);
  }
}
