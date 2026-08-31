/**
 * M1 -- ingestion and normalization (ported from app/ingest/parser.py).
 *
 * Takes raw RFC 5322 bytes and produces the one canonical ParsedEmail every
 * downstream analyzer reads. Two things are load-bearing:
 *   1. `headers` preserves original order AND duplicates -- Received: headers are
 *      prepended by each MTA, so their order IS the transmission path.
 *   2. `rawBytes` is kept because DKIM verification (M3) must hash the original
 *      bytes -- any re-serialization breaks the signature.
 */

import { createHash } from 'node:crypto';
import { simpleParser } from 'mailparser';
import type { Attachment, ExtractedUrl, ParsedEmail } from '../schemas/email';

// Conservative: rather miss an exotic URL than corrupt the header block.
const URL_RE = /https?:\/\/[^\s<>"'\)\]\},]+/gi;
const ANCHOR_RE = /<a\s[^>]*href\s*=\s*["']?([^"'\s>]+)["']?[^>]*>([\s\S]*?)<\/a>/gi;
const TAG_RE = /<[^>]+>/g;

const SHORTENERS = new Set([
  'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly',
  'rebrand.ly', 'cutt.ly', 'shorturl.at', 'tiny.cc', 'rb.gy', 's.id',
  'lnkd.in', 'bl.ink', 'shorte.st', 'adf.ly', 't.ly',
]);

function hostOf(url: string): string {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch {
    return '';
  }
}

function sha256(buf: Buffer): string {
  return createHash('sha256').update(buf).digest('hex');
}

// --- security-vendor URL rewriter un-wrapping --------------------------------
// Attackers harvest and re-mail vendor-rewritten links (stacked several deep), so
// an un-decoded report names the SECURITY VENDOR's domain as the destination.
// Decode back to the real URL before it is stored, displayed or analyzed.
function unwrapOnce(url: string): string {
  let p: URL;
  try { p = new URL(url); } catch { return url; }
  const host = p.hostname.toLowerCase();
  const fromParam = (name: string, ppEncoded = false): string | null => {
    let v = p.searchParams.get(name);
    if (!v) return null;
    if (ppEncoded) v = v.replace(/-/g, '%').replace(/_/g, '/'); // Proofpoint v2 encoding
    try { v = decodeURIComponent(v); } catch { /* keep as-is */ }
    return /^https?:\/\//i.test(v) ? v : null;
  };
  // query-param based rewriters
  if (/(^|\.)safelinks\.protection\.outlook\.com$/.test(host)) return fromParam('url') ?? url; // Microsoft Safe Links
  if (/(^|\.)urldefense\.proofpoint\.com$/.test(host)) return fromParam('u', true) ?? url;      // Proofpoint v2
  if (/(^|\.)linkprotect\.cudasvc\.com$/.test(host)) return fromParam('a') ?? url;              // Barracuda
  if (/\.zscaler\.(net|com)$/.test(host)) return fromParam('url') ?? url;                        // Zscaler
  if (/(^|\.)clicktime\.symantec\.com$/.test(host)) return fromParam('u') ?? url;               // Symantec/Broadcom
  if (/(^|\.)clean\.mx$|(^|\.)inky\.com$/.test(host)) return fromParam('url') ?? fromParam('u') ?? url;
  if (/(^|\.)google\.com$/.test(host) && p.pathname === '/url') return fromParam('q') ?? fromParam('url') ?? url;
  // Proofpoint v3: https://urldefense.com/v3/__REAL__;...
  if (/(^|\.)urldefense\.com$/.test(host)) {
    const m = url.match(/\/v3\/__(.+?)__;/);
    if (m) { try { return decodeURIComponent(m[1]); } catch { return m[1]; } }
  }
  // Cisco Secure Web: https://secure-web.cisco.com/<hash>/<encoded-real-url>
  if (/(^|\.)secure-web\.cisco\.com$/.test(host)) {
    const m = p.pathname.match(/\/[^/]+\/(https?%3a%2f%2f.+)$/i);
    if (m) { try { return decodeURIComponent(m[1]); } catch { /* keep */ } }
  }
  // Mimecast protect links are opaque (no embedded URL) — left as-is.
  return url;
}

function unwrapUrl(url: string): string {
  let u = url;
  for (let i = 0; i < 5 && u; i++) { // stacked rewriters
    const next = unwrapOnce(u);
    if (next === u) break;
    u = next;
  }
  return u;
}

// --- SVG active-content extraction -------------------------------------------
// An image/svg+xml part is XML, not a raster: pull out <script>, event handlers,
// javascript: / data: hrefs. Matches a broad script-type allowlist including the
// deprecated application/ecmascript. Returned capped; empty => benign SVG.
const SVG_SCRIPT_RE = /<script\b[^>]*>[\s\S]*?<\/script\s*>|<script\b[^>]*\/>/gi;
const SVG_HANDLER_RE = /\son[a-z]+\s*=\s*("[^"]*"|'[^']*'|[^\s>]+)/gi;
const SVG_JSHREF_RE = /(?:xlink:href|href|src)\s*=\s*("|')?\s*(javascript:|data:[^"'>\s]*script)[^"'>\s]*/gi;
function extractSvgActive(a: { filename?: string | null; contentType?: string | null; content?: Buffer | unknown }): string[] {
  const ct = (a.contentType || '').toLowerCase();
  const name = (a.filename || '').toLowerCase();
  const isSvg = ct.includes('svg') || name.endsWith('.svg') || name.endsWith('.svgz');
  if (!isSvg || !Buffer.isBuffer(a.content)) return [];
  let text: string;
  try { text = (a.content as Buffer).toString('utf-8'); } catch { return []; }
  if (!/<svg[\s>]/i.test(text)) return [];
  const hits: string[] = [];
  for (const re of [SVG_SCRIPT_RE, SVG_HANDLER_RE, SVG_JSHREF_RE]) {
    for (const m of text.matchAll(re)) {
      hits.push(m[0].replace(/\s+/g, ' ').trim().slice(0, 200));
      if (hits.length >= 10) return hits;
    }
  }
  return hits;
}

export async function parseEmail(raw: Buffer): Promise<ParsedEmail> {
  const msg = await simpleParser(raw, { skipTextLinks: true });

  // Preserve order + duplicates from the raw header block.
  const headers: Array<[string, string]> = (msg.headerLines ?? []).map(({ line }) => {
    const idx = line.indexOf(':');
    if (idx === -1) return [line.trim(), ''] as [string, string];
    return [line.slice(0, idx).trim(), line.slice(idx + 1).trim()] as [string, string];
  });

  const fromAddr = msg.from?.value?.[0]?.address?.trim().toLowerCase() || null;
  const fromDisplay = msg.from?.value?.[0]?.name?.trim() || null;
  const replyTo = firstAddr(msg.replyTo) ;
  const returnPath =
    (getHeader(headers, 'return-path') || '').replace(/^<|>$/g, '').trim().toLowerCase() || null;
  const toAddrs = addrList(msg.to);

  const bodyHtml = typeof msg.html === 'string' ? msg.html : null;
  let bodyText = (msg.text || '').trim();
  if (!bodyText && bodyHtml) {
    bodyText = bodyHtml.replace(TAG_RE, ' ').replace(/\s+/g, ' ').trim();
  }

  const attachments: Attachment[] = (msg.attachments ?? []).map((a) => {
    const active = extractSvgActive(a);
    return {
      filename: a.filename ?? null,
      content_type: a.contentType ?? null,
      size_bytes: a.size ?? (a.content ? a.content.length : 0),
      sha256: a.content ? sha256(a.content as Buffer) : '',
      ...(active.length ? { active_content: active } : {}),
    };
  });

  return {
    sha256: sha256(raw),
    rawBytes: raw,
    headers,
    message_id: (msg.messageId || '').trim() || null,
    subject: msg.subject ?? null,
    date: msg.date ? msg.date.toISOString() : null,
    from_display_name: fromDisplay,
    from_addr: fromAddr,
    reply_to: replyTo,
    return_path: returnPath,
    to_addrs: toAddrs,
    body_text: bodyText,
    body_html: bodyHtml,
    urls: extractUrls(bodyText, bodyHtml),
    attachments,
  };
}

// mailparser's address objects are AddressObject | AddressObject[]; normalize.
type AddrLike = { value?: Array<{ address?: string; name?: string }> } | undefined;

function firstAddr(a: AddrLike | AddrLike[]): string | null {
  const obj = Array.isArray(a) ? a[0] : a;
  return obj?.value?.[0]?.address?.trim().toLowerCase() || null;
}

function addrList(a: AddrLike | AddrLike[]): string[] {
  const obj = Array.isArray(a) ? a[0] : a;
  return (obj?.value ?? []).map((v) => v.address?.trim().toLowerCase()).filter(Boolean) as string[];
}

function getHeader(headers: Array<[string, string]>, name: string): string | null {
  const low = name.toLowerCase();
  const hit = headers.find(([k]) => k.toLowerCase() === low);
  return hit ? hit[1] : null;
}

function extractUrls(bodyText: string, bodyHtml: string | null): ExtractedUrl[] {
  const found = new Map<string, ExtractedUrl>();

  const add = (rawUrl: string, display: string | null = null, mismatched = false): void => {
    const url = unwrapUrl(rawUrl.trim().replace(/[.,;:)\]]+$/, '')); // decode vendor rewriters -> real destination
    if (!url || found.has(url)) return;
    const host = hostOf(url);
    found.set(url, {
      url,
      domain: host || null,
      display_text: display,
      is_shortened: SHORTENERS.has(host),
      mismatched_anchor: mismatched,
    });
  };

  if (bodyHtml) {
    for (const m of bodyHtml.matchAll(ANCHOR_RE)) {
      const href = unwrapUrl(m[1]);
      const text = m[2].replace(TAG_RE, '').replace(/\s+/g, ' ').trim();
      if (!href.toLowerCase().startsWith('http')) continue;
      const hrefHost = hostOf(href);
      let mismatch = false;
      for (const tm of text.matchAll(URL_RE)) {
        const textHost = hostOf(tm[0]);
        if (textHost && hrefHost && textHost !== hrefHost) mismatch = true;
      }
      add(href, text || null, mismatch);
    }
  }

  for (const m of (bodyText || '').matchAll(URL_RE)) add(m[0]);

  return [...found.values()];
}
