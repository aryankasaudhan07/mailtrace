/**
 * The canonical parsed-email object and the relay-hop model
 * (ported from app/schemas/email.py).
 *
 * M1 (ingestion) is the only thing that builds a ParsedEmail. Everything
 * downstream reads it and never re-parses raw bytes -- except M3, which needs
 * the original bytes for DKIM verification, so we keep them on the object.
 */

/** Where a hop sits relative to the trust boundary. */
export enum HopTrust {
  TRUSTED = 'TRUSTED', // our infrastructure or an authenticated provider
  BOUNDARY = 'BOUNDARY', // the earliest trustworthy hop -- report this origin
  UNVERIFIED = 'UNVERIFIED', // below the boundary; attacker could have written it
}

/** One Received: header, parsed. */
export interface Hop {
  seq: number; // 0 = bottom of the header block = claimed origin
  raw: string;
  from_host: string | null;
  from_ip: string | null;
  by_host: string | null;
  by_ip: string | null;
  protocol: string | null;
  timestamp: string | null; // ISO
  trust: HopTrust;
  anomalies: string[];
  geo: Record<string, unknown> | null;
}

export interface Attachment {
  filename: string | null;
  content_type: string | null;
  size_bytes: number;
  sha256: string;
  /** Active content extracted from an SVG attachment (scripts / event handlers /
   *  javascript: or data: hrefs). Empty/absent for benign or non-SVG parts. */
  active_content?: string[];
}

export interface ExtractedUrl {
  url: string;
  domain: string | null;
  display_text: string | null;
  is_shortened: boolean;
  /** True when the visible link text names a different domain than the href. */
  mismatched_anchor: boolean;
}

export interface ParsedEmail {
  sha256: string;
  /** Original raw bytes; kept for M3 DKIM. Never serialized to the wire. */
  rawBytes: Buffer;
  /** Ordered exactly as they appeared, duplicates preserved -- order is evidence. */
  headers: Array<[string, string]>;
  message_id: string | null;
  subject: string | null;
  date: string | null; // ISO
  from_display_name: string | null;
  from_addr: string | null;
  reply_to: string | null;
  return_path: string | null;
  to_addrs: string[];
  body_text: string;
  body_html: string | null;
  urls: ExtractedUrl[];
  attachments: Attachment[];
}

/** All values for a header name, in original order. Case-insensitive. */
export function headerValues(email: ParsedEmail, name: string): string[] {
  const low = name.toLowerCase();
  return email.headers.filter(([k]) => k.toLowerCase() === low).map(([, v]) => v);
}

export function firstHeader(email: ParsedEmail, name: string): string | null {
  const vals = headerValues(email, name);
  return vals.length ? vals[0] : null;
}
