/**
 * Authentication (ported from app/api/auth.py).
 * PBKDF2-HMAC-SHA256 passwords, HMAC-signed tokens, and two-step OTP flows for
 * both password reset and account creation. Users/OTPs persist to Vercel KV when
 * configured, else in-memory (dev/tests). Demo admin seeded on first use.
 */

import { pbkdf2Sync, randomBytes, randomInt, createHmac, timingSafeEqual } from 'node:crypto';

const TTL = 60 * 60 * 12; // 12h tokens
const ITER = 200_000;
const OTP_TTL = 600; // 10 min
const OTP_LEN = 6;

const secret = () => process.env.AUTH_SECRET || 'dev-insecure-secret-change-me';
const useKv = () => Boolean(process.env.KV_REST_API_URL || process.env.KV_URL);

export interface User { name: string; role: string; salt: string; hash: string }
export interface PublicUser { email: string; name: string; role: string }

const memUsers = new Map<string, User>();
const memOtp = new Map<string, { code: string; exp: number }>();
const memPending = new Map<string, { code: string; exp: number; name: string; password: string }>();
let seeded = false;

function hashPw(password: string, salt: string): string {
  return pbkdf2Sync(password, Buffer.from(salt, 'hex'), ITER, 32, 'sha256').toString('hex');
}

async function kvClient() {
  return (await import('@vercel/kv')).kv;
}

async function seed(): Promise<void> {
  if (seeded) return;
  seeded = true;
  const admin = 'admin@mailtrace.io';
  if (await getUser(admin)) return;
  const salt = randomBytes(16).toString('hex');
  await putUser(admin, { name: 'Admin User', role: 'Administrator', salt, hash: hashPw('demo1234', salt) });
}

async function getUser(email: string): Promise<User | null> {
  if (useKv()) return ((await (await kvClient()).hget('auth:users', email)) as User | null) ?? null;
  return memUsers.get(email) ?? null;
}
async function putUser(email: string, u: User): Promise<void> {
  if (useKv()) await (await kvClient()).hset('auth:users', { [email]: u });
  else memUsers.set(email, u);
}

function eq(a: string, b: string): boolean {
  const ba = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  return ba.length === bb.length && timingSafeEqual(ba, bb);
}

function b64url(s: string): string {
  return Buffer.from(s).toString('base64url');
}

export function signToken(email: string): string {
  const payload = b64url(JSON.stringify({ sub: email, exp: Math.floor(Date.now() / 1000) + TTL }));
  const sig = createHmac('sha256', secret()).update(payload).digest('hex');
  return `${payload}.${sig}`;
}

export function verifyToken(token: string): string | null {
  const [payload, sig] = token.split('.', 2);
  if (!payload || !sig) return null;
  const expect = createHmac('sha256', secret()).update(payload).digest('hex');
  if (!eq(sig, expect)) return null;
  try {
    const data = JSON.parse(Buffer.from(payload, 'base64url').toString());
    if ((data.exp ?? 0) < Date.now() / 1000) return null;
    return data.sub as string;
  } catch {
    return null;
  }
}

const pub = (email: string, u: User): PublicUser => ({ email, name: u.name, role: u.role ?? 'Analyst' });
const norm = (e: string) => e.toLowerCase().trim();

export async function login(email: string, password: string): Promise<{ token: string; user: PublicUser }> {
  await seed();
  const e = norm(email);
  const u = await getUser(e);
  if (!u || !eq(hashPw(password, u.salt), u.hash)) throw new HttpError(401, 'Invalid email or password');
  return { token: signToken(e), user: pub(e, u) };
}

export async function me(token: string): Promise<PublicUser> {
  await seed();
  const email = token ? verifyToken(token) : null;
  const u = email ? await getUser(email) : null;
  if (!email || !u) throw new HttpError(401, 'Not authenticated');
  return pub(email, u);
}

export async function updateProfile(token: string, patch: { name?: string }): Promise<PublicUser> {
  await seed();
  const email = token ? verifyToken(token) : null;
  const u = email ? await getUser(email) : null;
  if (!email || !u) throw new HttpError(401, 'Not authenticated');
  const name = (patch.name ?? '').trim();
  if (!name) throw new HttpError(400, 'Display name cannot be empty');
  await putUser(email, { ...u, name });
  return pub(email, (await getUser(email)) as User);
}

// --- OTP helpers ------------------------------------------------------------
function newOtp(): string {
  return String(randomInt(0, 1_000_000)).padStart(OTP_LEN, '0');
}

async function otpResponse(otp: string, sent: boolean, detail: string) {
  const resp: Record<string, unknown> = { sent };
  if (sent) { resp.message = 'A verification code has been emailed to you.'; return resp; }
  resp.demo_otp = otp;
  resp.message = detail === 'not_configured'
    ? 'Email not configured — showing the code for the demo.'
    : 'Email send failed — showing the code for the demo.';
  if (detail !== 'not_configured') resp.smtp_error = detail;
  return resp;
}

async function sendOtpEmail(to: string, otp: string, purpose: string): Promise<{ sent: boolean; detail: string }> {
  const host = process.env.SMTP_HOST || 'smtp.gmail.com';
  const user = process.env.SMTP_USER;
  // Gmail shows App Passwords as 'abcd efgh ijkl mnop' — accept any spacing/dashes.
  const pass = (process.env.SMTP_PASSWORD || process.env.SMTP_PASS || '').replace(/[\s-]/g, '');
  const from = process.env.MAIL_FROM || process.env.SMTP_FROM || user;
  if (!user || !pass) return { sent: false, detail: 'not_configured' };
  if (!from) return { sent: false, detail: 'smtp_needs_sender (set MAIL_FROM)' };
  const port = Number(process.env.SMTP_PORT || 587);
  try {
    const { createTransport } = await import('nodemailer');
    const transport = createTransport({
      host,
      port,
      secure: port === 465, // 465 = implicit TLS; 587 = STARTTLS
      auth: { user, pass },
      connectionTimeout: 10_000,
      greetingTimeout: 10_000,
      socketTimeout: 15_000,
    });
    await transport.sendMail({
      from: `"Mailtrace" <${from}>`,
      to,
      subject: `Your Mailtrace code to ${purpose}`,
      text: `Your Mailtrace verification code is: ${otp}\n\nUse it to ${purpose}. It expires in 10 minutes.`,
    });
    return { sent: true, detail: '' };
  } catch (e) {
    // Never raise: a failed send is evidence, and the caller falls back to demo_otp.
    const err = e as Error & { code?: string };
    return { sent: false, detail: err.code ? `smtp ${err.code}` : err.name };
  }
}

async function putOtp(email: string, code: string): Promise<void> {
  const exp = Date.now() / 1000 + OTP_TTL;
  if (useKv()) await (await kvClient()).set(`otp:${email}`, code, { ex: OTP_TTL });
  else memOtp.set(email, { code, exp });
}
/** KV round-trips values as JSON, so a code stored as "029048" comes back as the
 *  number 29048 — coerce to string and re-pad so leading zeros survive. */
function norm6(v: unknown): string | null {
  if (v === null || v === undefined) return null;
  return String(v).trim().padStart(OTP_LEN, '0');
}
async function takeOtp(email: string): Promise<string | null> {
  if (useKv()) return norm6(await (await kvClient()).get(`otp:${email}`));
  const r = memOtp.get(email);
  if (!r || r.exp < Date.now() / 1000) return null;
  return norm6(r.code);
}

// --- password reset ---------------------------------------------------------
export async function resetRequest(email: string) {
  await seed();
  const e = norm(email);
  if (!(await getUser(e))) throw new HttpError(404, 'No account found with that email');
  const otp = newOtp();
  await putOtp(e, otp);
  const { sent, detail } = await sendOtpEmail(e, otp, 'reset your password');
  return otpResponse(otp, sent, detail);
}

export async function resetVerify(email: string, otp: string, password: string) {
  await seed();
  const e = norm(email);
  const code = await takeOtp(e);
  if (!code) throw new HttpError(400, 'Code expired or not requested — request a new one');
  if (!eq(code, String(otp).trim())) throw new HttpError(400, 'Incorrect code');
  const u = await getUser(e);
  if (!u) throw new HttpError(404, 'No account found with that email');
  if (password.length < 6) throw new HttpError(400, 'New password must be at least 6 characters');
  const salt = randomBytes(16).toString('hex');
  await putUser(e, { ...u, salt, hash: hashPw(password, salt) });
  if (!useKv()) memOtp.delete(e);
  return { token: signToken(e), user: pub(e, await getUser(e) as User) };
}

// --- account creation (two-step OTP) ----------------------------------------
export async function registerRequest(email: string, password: string, name?: string) {
  await seed();
  const e = norm(email);
  if (!e.includes('@') || password.length < 6) throw new HttpError(400, 'Valid email and a 6+ char password required');
  if (await getUser(e)) throw new HttpError(409, 'An account with that email already exists');
  const otp = newOtp();
  const rec = { code: otp, exp: Date.now() / 1000 + OTP_TTL, name: name || e.split('@')[0], password };
  if (useKv()) await (await kvClient()).set(`pending:${e}`, rec, { ex: OTP_TTL });
  else memPending.set(e, rec);
  const { sent, detail } = await sendOtpEmail(e, otp, 'verify your new account');
  return otpResponse(otp, sent, detail);
}

export async function registerVerify(email: string, otp: string) {
  await seed();
  const e = norm(email);
  let rec: { code: string; exp: number; name: string; password: string } | null;
  if (useKv()) rec = ((await (await kvClient()).get(`pending:${e}`)) as typeof rec) ?? null;
  else { const m = memPending.get(e); rec = m && m.exp >= Date.now() / 1000 ? m : null; }
  if (!rec) throw new HttpError(400, 'Code expired or not requested — start again');
  if (!eq(rec.code, String(otp).trim())) throw new HttpError(400, 'Incorrect code');
  if (await getUser(e)) throw new HttpError(409, 'An account with that email already exists');
  const salt = randomBytes(16).toString('hex');
  await putUser(e, { name: rec.name, role: 'Analyst', salt, hash: hashPw(rec.password, salt) });
  if (!useKv()) memPending.delete(e);
  return { token: signToken(e), user: pub(e, await getUser(e) as User) };
}

export class HttpError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

/** test/dev helper */
export function __resetAuth(): void {
  memUsers.clear();
  memOtp.clear();
  memPending.clear();
  seeded = false;
}
