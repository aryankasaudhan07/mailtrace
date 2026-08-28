/**
 * Per-case forensic PDF report (pdf-lib, serverless-safe — fonts are embedded
 * from base64, no files read from disk).
 *
 * Visual language follows the "Clean Bold" performance-report style: warm cream
 * paper, dark-teal headings, a single coral data-accent, the Archivo typeface,
 * a KPI stat column, a score donut, coral bar charts and a row of mini
 * donut-gauges for analyzer coverage. Every forensic detail is preserved:
 * verdict, summary, message, scored findings, authentication, relay trace,
 * IOCs and coverage.
 *
 * pdf-lib has no chart primitives — every graphic is drawn by hand.
 */

import { PDFDocument, StandardFonts, rgb, LineCapStyle, type PDFFont, type PDFPage } from 'pdf-lib';
import fontkit from '@pdf-lib/fontkit';
import type { CaseRecord } from './case-service';
import { caseArtifacts } from './case-service';
import { ARCHIVO_REGULAR_B64, ARCHIVO_BOLD_B64, ARCHIVO_BLACK_B64, bytes } from './fonts/archivo';

type Col = ReturnType<typeof rgb>;

const A4 = { w: 595.28, h: 841.89 };
const MARGIN = 46;
const CONTENT_W = A4.w - MARGIN * 2;

// palette (from the reference template)
const PAPER = rgb(0.973, 0.945, 0.906);
const INK = rgb(0.149, 0.22, 0.227); // dark teal — titles & headings
const CORAL = rgb(0.882, 0.361, 0.224); // primary data accent
const TEAL2 = rgb(0.2, 0.42, 0.38); // "good" / clean
const WARN = rgb(0.85, 0.62, 0.13); // suspicious
const DEEP = rgb(0.75, 0.22, 0.17); // critical
const MUTED = rgb(0.52, 0.49, 0.44);
const SAND = rgb(0.9, 0.86, 0.8);
const WHITE = rgb(1, 1, 1);
const tint = (c: Col, a: number) => rgb(1 - (1 - c.red) * a, 1 - (1 - c.green) * a, 1 - (1 - c.blue) * a);

function bandColor(band: string): Col {
  return band === 'CRITICAL' ? DEEP : band === 'HIGH_RISK' ? CORAL : band === 'SUSPICIOUS' ? WARN : TEAL2;
}

const TYPE: Record<string, [string, string]> = {
  payment_diversion_intent: ['BEC', 'Payment diversion'], executive_impersonation: ['Impersonation', 'Authority abuse'],
  credential_harvest_intent: ['Phishing', 'Credential theft'], classifier_phishing_high: ['Phishing', 'Credential theft'],
  brand_lookalike_domain: ['Impersonation', 'Brand abuse'], fake_reply: ['BEC', 'Fake reply thread'],
  hidden_text_mismatch: ['Content injection', 'AI-assistant manipulation'], forged_received_hop: ['Spoofing', 'Sender forgery'],
  private_ip_in_public_chain: ['Spoofing', 'Header forgery'], spf_fail_hard: ['Spoofing', 'Auth failure'],
  dmarc_fail_strict: ['Spoofing', 'Policy violation'], origin_anonymized: ['Evasion', 'Origin concealment'],
  campaign_infrastructure_reuse: ['Campaign', 'Coordinated attack'], reply_to_domain_mismatch: ['BEC', 'Reply diversion'],
};

export async function buildReportPdf(rec: CaseRecord): Promise<Uint8Array> {
  const doc = await PDFDocument.create();
  doc.registerFontkit(fontkit);
  const font = await doc.embedFont(bytes(ARCHIVO_REGULAR_B64), { subset: true });
  const bold = await doc.embedFont(bytes(ARCHIVO_BOLD_B64), { subset: true });
  const black = await doc.embedFont(bytes(ARCHIVO_BLACK_B64), { subset: true });
  const mono = await doc.embedFont(StandardFonts.Courier);

  const v = rec.verdict;
  const band = v.band.replace('_', ' ');
  const bc = bandColor(v.band);
  const conf = Math.round(v.confidence * 100);
  const id8 = rec.case_id.slice(0, 8).toUpperCase();

  let page: PDFPage = doc.addPage([A4.w, A4.h]);
  let y = 0;
  let pageNo = 0;

  // ---------- primitives ----------
  const measure = (s: string, size: number, f: PDFFont) => f.widthOfTextAtSize(s, size);
  const centre = (s: string, cx: number, yy: number, size: number, f: PDFFont, color: Col) =>
    page.drawText(s, { x: cx - measure(s, size, f) / 2, y: yy, size, font: f, color });
  const ellip = (s: string, size: number, f: PDFFont, maxW: number) => {
    if (measure(s, size, f) <= maxW) return s;
    let t = s;
    while (t.length > 1 && measure(t + '...', size, f) > maxW) t = t.slice(0, -1);
    return t + '...';
  };
  const wrap = (s: string, size: number, f: PDFFont, maxW: number): string[] => {
    const out: string[] = [];
    for (const raw of (s || '').split('\n')) {
      let line = '';
      for (const word of raw.split(/\s+/)) {
        const t = line ? `${line} ${word}` : word;
        if (measure(t, size, f) > maxW && line) { out.push(line); line = word; } else line = t;
      }
      out.push(line);
    }
    return out;
  };

  const bg = () => page.drawRectangle({ x: 0, y: 0, width: A4.w, height: A4.h, color: PAPER });
  const footer = () => {
    page.drawLine({ start: { x: MARGIN, y: 34 }, end: { x: A4.w - MARGIN, y: 34 }, thickness: 0.5, color: SAND });
    page.drawText('MAILTRACE', { x: MARGIN, y: 23, size: 7.5, font: black, color: CORAL });
    page.drawText('Email Threat Intelligence', { x: MARGIN + measure('MAILTRACE', 7.5, black) + 7, y: 23, size: 7, font, color: MUTED });
    const r = `Case ${id8}  ·  page ${pageNo}`;
    page.drawText(r, { x: A4.w - MARGIN - measure(r, 7, font), y: 23, size: 7, font, color: MUTED });
  };
  const newPage = () => { footer(); page = doc.addPage([A4.w, A4.h]); pageNo += 1; bg(); y = A4.h - MARGIN; };
  const need = (h: number) => { if (y - h < 46) newPage(); };

  const para = (s: string, o: { size?: number; f?: PDFFont; color?: Col; x?: number; gap?: number } = {}) => {
    const { size = 9.5, f = font, color = INK, x = MARGIN, gap = 4 } = o;
    for (const ln of wrap(s, size, f, A4.w - MARGIN - x)) {
      need(size + gap);
      page.drawText(ln, { x, y: y - size, size, font: f, color });
      y -= size + gap;
    }
  };
  const heading = (s: string) => {
    need(32); y -= 15;
    page.drawRectangle({ x: MARGIN, y: y - 10, width: 4, height: 13, color: CORAL });
    page.drawText(s, { x: MARGIN + 12, y: y - 10, size: 12, font: bold, color: INK });
    y -= 14;
    page.drawLine({ start: { x: MARGIN, y }, end: { x: A4.w - MARGIN, y }, thickness: 1, color: SAND });
    y -= 10;
  };
  const kv = (k: string, val: string, f: PDFFont = font) => {
    need(15);
    page.drawText(k, { x: MARGIN, y: y - 9, size: 8.5, font, color: MUTED });
    for (const ln of wrap(val || '—', 9.5, f, CONTENT_W - 132)) {
      page.drawText(ln, { x: MARGIN + 132, y: y - 9, size: 9.5, font: f, color: INK });
      y -= 13;
    }
    y -= 2;
  };
  // ring gauge: thick stroked arc = frac of a full turn, on a light track
  const ring = (cx: number, cy: number, r: number, thick: number, frac: number, col: Col, track = SAND) => {
    page.drawCircle({ x: cx, y: cy, size: r, borderColor: track, borderWidth: thick });
    const f = Math.min(1, Math.max(0, frac));
    if (f <= 0) return;
    const steps = Math.max(2, Math.round(72 * f));
    const a0 = Math.PI / 2;
    let prev: { x: number; y: number } | null = null;
    for (let i = 0; i <= steps; i++) {
      const a = a0 - 2 * Math.PI * f * (i / steps);
      const p = { x: cx + r * Math.cos(a), y: cy + r * Math.sin(a) };
      if (prev) page.drawLine({ start: prev, end: p, thickness: thick, color: col, lineCap: LineCapStyle.Round });
      prev = p;
    }
  };

  // data
  const pos = v.contributions.filter((c) => c.points > 0).sort((a, b) => b.points - a.points);
  const [cat, intent] = (pos[0] && TYPE[pos[0].signal]) || (pos.length ? ['Suspicious', 'Undetermined'] : ['Clean', 'None detected']);
  const barSev = (p: number) => (p >= 25 ? DEEP : p >= 15 ? CORAL : p >= 8 ? WARN : TEAL2);

  // ================= PAGE 1 — cover / executive =================
  pageNo = 1; bg();

  // brand kicker
  let ty = A4.h - 58;
  page.drawText('MAILTRACE', { x: MARGIN, y: ty, size: 12, font: black, color: CORAL });
  page.drawText('EMAIL THREAT INTELLIGENCE', { x: MARGIN + measure('MAILTRACE', 12, black) + 9, y: ty + 1, size: 7.5, font: bold, color: MUTED });
  ty -= 34;
  // hero title
  page.drawText('Email Threat', { x: MARGIN, y: ty - 26, size: 31, font: black, color: INK });
  page.drawText('Forensic Report', { x: MARGIN, y: ty - 58, size: 31, font: black, color: INK });
  const sub = `Case ${id8}   ·   Analyzed ${new Date(rec.analyzed_at || Date.now()).toISOString().slice(0, 16).replace('T', ' ')} UTC`;
  page.drawText(sub, { x: MARGIN, y: ty - 78, size: 9.5, font, color: MUTED });

  // KPI stat column (right)
  const kx = A4.w - MARGIN - 158;
  const kpis: Array<[string, string, Col]> = [
    ['THREAT SCORE', `${v.score}/100`, CORAL],
    ['RISK BAND', band, bc],
    ['ANALYSIS CONFIDENCE', `${conf}%`, TEAL2],
  ];
  let ky = A4.h - 58;
  for (const [lab, val, col] of kpis) {
    page.drawText(lab, { x: kx, y: ky, size: 8, font: bold, color: MUTED });
    page.drawText(val, { x: kx, y: ky - 23, size: 20, font: black, color: col });
    ky -= 48;
  }

  y = A4.h - 214;
  page.drawLine({ start: { x: MARGIN, y }, end: { x: A4.w - MARGIN, y }, thickness: 1, color: SAND });
  y -= 6;

  // ---- grid: classification donut (left) | driver bar chart (right) ----
  const gridTop = y;
  const leftW = CONTENT_W * 0.4;
  const rightX = MARGIN + CONTENT_W * 0.46;

  page.drawText('Threat classification', { x: MARGIN, y: gridTop - 12, size: 11, font: bold, color: INK });
  const dcx = MARGIN + leftW * 0.42, dcy = gridTop - 76;
  ring(dcx, dcy, 34, 10, v.score / 100, bc);
  centre(`${v.score}`, dcx, dcy - 5, 21, black, bc);
  centre('SCORE', dcx, dcy - 21, 7, bold, MUTED);
  page.drawText(cat, { x: MARGIN, y: gridTop - 132, size: 15, font: black, color: INK });
  page.drawText(ellip(`Attack intent: ${intent}`, 9, font, leftW + 20), { x: MARGIN, y: gridTop - 148, size: 9, font, color: MUTED });

  page.drawText('What drove this verdict', { x: rightX, y: gridTop - 12, size: 11, font: bold, color: INK });
  let by = gridTop - 32;
  if (!pos.length) {
    page.drawText('No positive indicators — assessed clean.', { x: rightX, y: by, size: 9, font, color: MUTED });
    by -= 16;
  } else {
    const maxP = Math.max(...pos.map((c) => c.points));
    const lblW = 150, barMaxW = A4.w - MARGIN - rightX - lblW - 26;
    for (const c of pos.slice(0, 6)) {
      const cc = barSev(c.points);
      page.drawText(ellip(c.label, 7.5, bold, lblW - 4), { x: rightX, y: by, size: 7.5, font: bold, color: INK });
      const bw = Math.max(3, (c.points / maxP) * barMaxW);
      page.drawRectangle({ x: rightX + lblW, y: by - 1, width: barMaxW, height: 8, color: tint(CORAL, 0.14) });
      page.drawRectangle({ x: rightX + lblW, y: by - 1, width: bw, height: 8, color: cc });
      page.drawText(`+${c.points.toFixed(0)}`, { x: rightX + lblW + barMaxW + 5, y: by, size: 8, font: bold, color: cc });
      by -= 16;
    }
  }
  y = Math.min(gridTop - 158, by) - 8;

  // ---- risk-level scale ----
  page.drawText('RISK LEVEL', { x: MARGIN, y: y - 8, size: 7.5, font: bold, color: MUTED });
  y -= 18;
  const segs: Array<[string, Col]> = [['Clean', TEAL2], ['Suspicious', WARN], ['High risk', CORAL], ['Critical', DEEP]];
  const segW = CONTENT_W / 4, barH = 10;
  segs.forEach(([lbl, col], i) => {
    page.drawRectangle({ x: MARGIN + i * segW, y: y - barH, width: segW - 2, height: barH, color: tint(col, 0.5) });
    centre(lbl, MARGIN + i * segW + segW / 2, y - barH - 11, 7, font, MUTED);
  });
  const mkX = MARGIN + Math.min(1, v.score / 100) * CONTENT_W;
  page.drawCircle({ x: mkX, y: y - barH / 2, size: 6.5, color: bc, borderColor: WHITE, borderWidth: 2 });
  y -= barH + 28;

  // ---- analyzer coverage: mini donut-gauges (echoes template gauge row) ----
  page.drawText('Analysis coverage', { x: MARGIN, y: y - 10, size: 11, font: bold, color: INK });
  y -= 26;
  const lanes: Array<[string, string]> = [['M2', 'Header & relay'], ['M3', 'Authentication'], ['M4', 'Content (AI)'], ['M5', 'Network & geo'], ['M6', 'Domain'], ['M7', 'Correlation'], ['M8', 'Email footprint']];
  const unavail = new Set(v.lanes_unavailable as unknown as string[]);
  const gW = CONTENT_W / lanes.length;
  for (let i = 0; i < lanes.length; i++) {
    const [id, name] = lanes[i];
    const ok = !unavail.has(id);
    const gcx = MARGIN + gW * (i + 0.5), gcy = y - 20;
    ring(gcx, gcy, 16, 5, ok ? 1 : 0, ok ? CORAL : SAND, tint(TEAL2, 0.18));
    centre(id, gcx, gcy - 4, 9, black, ok ? INK : MUTED);
    centre(ellip(name, 6.5, font, gW - 6), gcx, y - 46, 6.5, font, MUTED);
    centre(ok ? 'ran' : 'unavailable', gcx, y - 55, 6.5, bold, ok ? TEAL2 : WARN);
  }
  y -= 70;

  // ---- summary ----
  heading('Summary');
  para(v.summary, { size: 10, color: INK, gap: 5 });
  if (v.suppressed_negatives?.length) {
    y -= 2;
    para(`Note: this message authenticated correctly (${v.suppressed_negatives.join(', ')}), but that credit was withheld because deception indicators were also present — a compromised or attacker-owned domain signs validly too.`,
      { size: 8.5, color: WARN, gap: 3 });
  }

  // ================= PAGE 2+ — details =================
  // message
  heading('Message');
  kv('Subject', rec.subject || '—');
  kv('From', rec.from_addr || '—');
  kv('Reply-To', rec.reply_to || '—');
  kv('Return-Path', rec.return_path || '—');
  kv('Message-ID', rec.message_id || '—', mono);
  kv('Date', rec.date ? new Date(rec.date).toUTCString() : '—');
  kv('Size', `${(rec.size_bytes / 1024).toFixed(1)} KB  ·  ${rec.body_format}`);
  const dom = (a: string | null) => (a && a.includes('@') ? a.split('@').pop()!.toLowerCase() : null);
  const aligned = !(dom(rec.reply_to) && dom(rec.from_addr) && dom(rec.reply_to) !== dom(rec.from_addr));
  need(26);
  page.drawRectangle({ x: MARGIN, y: y - 20, width: CONTENT_W, height: 20, color: tint(aligned ? TEAL2 : DEEP, 0.12) });
  page.drawCircle({ x: MARGIN + 12, y: y - 10, size: 3.5, color: aligned ? TEAL2 : DEEP });
  page.drawText(aligned ? 'From / Reply-To domains are aligned.' : 'From / Reply-To domains DIFFER — a reply would divert to another domain.',
    { x: MARGIN + 24, y: y - 13, size: 9, font: bold, color: aligned ? TEAL2 : DEEP });
  y -= 26;

  // detailed findings
  heading('Detailed findings');
  if (!pos.length) para('No positive threat indicators — the message was assessed clean.', { color: MUTED });
  for (const c of pos) {
    need(24);
    page.drawText(`+${c.points.toFixed(0)}`, { x: MARGIN, y: y - 9, size: 9.5, font: black, color: barSev(c.points) });
    page.drawText(c.label, { x: MARGIN + 30, y: y - 9, size: 9.5, font: bold, color: INK });
    const tag = `[${c.analyzer}]`;
    page.drawText(tag, { x: A4.w - MARGIN - measure(tag, 8, font), y: y - 9, size: 8, font, color: MUTED });
    y -= 13;
    if (c.rationale) para(c.rationale, { size: 8.5, color: MUTED, x: MARGIN + 30, gap: 3 });
    y -= 4;
  }

  // authentication badges
  heading('Email authentication');
  const has = (sig: string) => rec.evidence.some((e) => e.signal === sig && e.status === 'TRIGGERED');
  const auth: Array<[string, string, Col]> = [
    ['SPF', has('spf_fail_hard') ? 'FAIL' : 'PASS / n/e', has('spf_fail_hard') ? DEEP : TEAL2],
    ['DKIM', has('dkim_fail') ? 'FAIL' : has('dkim_valid_aligned') ? 'PASS' : 'NOT SIGNED', has('dkim_fail') ? DEEP : has('dkim_valid_aligned') ? TEAL2 : MUTED],
    ['DMARC', has('dmarc_fail_strict') ? 'FAIL' : 'PASS / n/e', has('dmarc_fail_strict') ? DEEP : TEAL2],
  ];
  need(52);
  const bw3 = (CONTENT_W - 24) / 3;
  auth.forEach(([name, status, col], i) => {
    const bx = MARGIN + i * (bw3 + 12);
    page.drawRectangle({ x: bx, y: y - 44, width: bw3, height: 44, color: tint(col, 0.1), borderColor: tint(col, 0.5), borderWidth: 1 });
    page.drawRectangle({ x: bx, y: y - 44, width: 4, height: 44, color: col });
    page.drawText(name, { x: bx + 14, y: y - 20, size: 10, font: bold, color: INK });
    page.drawText(status, { x: bx + 14, y: y - 37, size: 12, font: black, color: col });
  });
  y -= 52;
  para('n/e = not enforced. Authentication is a weak signal alone: the most damaging attacks (thread hijacking from a compromised mailbox) pass SPF, DKIM and DMARC by construction.', { size: 8, color: MUTED, gap: 3 });

  // sender email footprint (M8)
  const foot = rec.evidence.find((e) => e.signal === 'sender_email_footprint');
  const footDetail = (foot?.detail ?? {}) as {
    platforms?: string[]; registered?: Array<{ platform: string; method: string; simulated: boolean }>;
    disposable?: boolean; includes_simulated?: boolean; real_count?: number;
  };
  const platforms = footDetail.registered ?? [];
  const breach = (footDetail as { breach?: { checked?: boolean; established_since?: string | null; min_age_years?: number | null; count?: number; names?: string[]; simulated?: boolean; source?: string } }).breach;
  const breachSrc = ({ hibp: 'HaveIBeenPwned', xposedornot: 'XposedOrNot', demo: 'demo data' } as Record<string, string>)[breach?.source ?? ''] ?? 'breach data';
  if (foot || rec.evidence.some((e) => e.signal === 'sender_no_footprint')) {
    heading('Sender email footprint');
    if (breach?.checked) {
      const since = breach.established_since ? `In use since ${breach.established_since} or earlier${breach.min_age_years != null ? ` (~${breach.min_age_years}y old)` : ''}` : 'Age unknown';
      const br = `${breach.count ?? 0} known breach${breach.count === 1 ? '' : 'es'}${breach.names?.length ? `: ${breach.names.join(', ')}` : ''}`;
      para(`${since}  ·  ${br}  (source: ${breachSrc})`, { size: 8.5, color: INK, gap: 4 });
      y -= 2;
    }
    if (platforms.length) {
      para(`This address is registered on ${platforms.length} platform(s):`, { size: 9, color: INK, gap: 4 });
      y -= 2;
      const cols = 2, colW = (CONTENT_W - 16) / cols;
      need(Math.ceil(platforms.length / cols) * 16 + 4);
      platforms.forEach((p, i) => {
        const px = MARGIN + (i % cols) * (colW + 16);
        if (i % cols === 0 && i > 0) y -= 16;
        const dotCol = p.simulated ? MUTED : TEAL2;
        page.drawCircle({ x: px + 4, y: y - 8, size: 3, color: dotCol });
        const label = p.platform + (p.simulated ? '  (demo)' : '');
        page.drawText(ellip(label, 8.5, bold, colW - 20), { x: px + 14, y: y - 11, size: 8.5, font: bold, color: INK });
      });
      y -= 18;
      if (footDetail.includes_simulated) para('Entries marked (demo) are from the labelled simulated dataset; the rest are live results (Gravatar / linked accounts).', { size: 7.5, color: MUTED, gap: 3 });
    } else {
      para('No public account footprint found for this sender address.', { size: 9, color: MUTED, gap: 3 });
    }
    para('Footprint is identity context, not attribution — a large footprint never means the message is safe.', { size: 7.5, color: MUTED, gap: 3 });
  }

  // relay trace timeline
  heading('Relay trace & trust boundary');
  const boundary = rec.hops.find((h) => h.trust === 'BOUNDARY');
  para(`Authenticated origin: ${boundary?.from_ip ?? 'none — no hop could be authenticated'}. The bottom-most hop is attacker-forgeable; we report the earliest hop we can authenticate and mark everything below it UNVERIFIED.`,
    { size: 8.5, color: MUTED, gap: 3 });
  y -= 4;
  const lineX = MARGIN + 8, rowH = 30;
  need(rec.hops.length * rowH + 6);
  rec.hops.forEach((h, i) => {
    const ry = y - 6;
    const tc = h.trust === 'BOUNDARY' ? CORAL : h.trust === 'TRUSTED' ? TEAL2 : WARN;
    if (h.trust === 'BOUNDARY') page.drawRectangle({ x: MARGIN, y: ry - 20, width: CONTENT_W, height: 26, color: tint(CORAL, 0.08) });
    if (i < rec.hops.length - 1) page.drawLine({ start: { x: lineX, y: ry }, end: { x: lineX, y: ry - rowH }, thickness: 1.5, color: SAND });
    page.drawCircle({ x: lineX, y: ry, size: h.trust === 'BOUNDARY' ? 6 : 4.5, color: tc, borderColor: PAPER, borderWidth: 1.5 });
    page.drawText(`#${h.seq}`, { x: lineX + 16, y: ry - 4, size: 8, font: bold, color: MUTED });
    page.drawText(h.from_ip || '—', { x: lineX + 40, y: ry - 4, size: 9, font: mono, color: INK });
    page.drawText(ellip(h.by_host || '—', 8, font, 190), { x: lineX + 150, y: ry - 4, size: 8, font, color: MUTED });
    const tl = h.trust === 'BOUNDARY' ? 'TRUST BOUNDARY' : h.trust;
    page.drawText(tl, { x: A4.w - MARGIN - measure(tl, 8, bold), y: ry - 4, size: 8, font: bold, color: tc });
    y -= rowH;
  });

  // IOCs
  const art = caseArtifacts(rec);
  heading('Indicators of compromise (IOCs)');
  const list = (label: string, items: string[]) => {
    if (!items.length) return;
    need(16);
    page.drawText(label, { x: MARGIN, y: y - 9, size: 9, font: bold, color: INK });
    y -= 13;
    for (const it of items) para(`- ${it}`, { size: 8.5, color: INK, x: MARGIN + 10, gap: 3, f: mono });
    y -= 3;
  };
  list('IP addresses', art.ips.map((i) => `${i.ip}  (hop ${i.hop}, ${i.trust})`));
  list('Domains', art.domains);
  list('URLs', art.urls.map((u) => `${u.url}${u.mismatched ? '  [anchor mismatch]' : u.shortened ? '  [shortener]' : ''}`));
  list('Sender addresses', art.emails);
  list('Attachments', art.attachments.map((a) => `${a.filename || 'unnamed'}  (${a.content_type || '?'}, ${((a.size_bytes || 0) / 1024).toFixed(1)} KB)  sha256:${(a.sha256 || '').slice(0, 24)}...`));
  if (!art.ips.length && !art.domains.length && !art.urls.length && !art.attachments.length) para('No IOCs extracted.', { color: MUTED });

  footer();
  return doc.save();
}
