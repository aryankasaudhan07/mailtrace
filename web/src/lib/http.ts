/** Small helpers for Route Handlers. */
import { HttpError } from './auth';

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
