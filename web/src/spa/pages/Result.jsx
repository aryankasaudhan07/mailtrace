import { useEffect, useState } from 'react'
import { useParams, Link } from 'react-router-dom'
import {
  Anchor, ShieldAlert, ShieldCheck, Link2, Paperclip, Mail, Globe, FileText, FileWarning,
  Fingerprint, Network, FileSearch, Loader2, CheckCircle2, AlertTriangle, ArrowRight,
} from 'lucide-react'
import PageHead from '../components/PageHead.jsx'
import ScoreGauge from '../components/ScoreGauge.jsx'
import { api, bandInfo, classify } from '../api.js'
import './result.css'

// classification -> category + attack intent, for the Classification card
const CLASS_DETAIL = {
  'Business Email Compromise': ['BEC', 'Payment diversion'],
  'Credential Phishing': ['Phishing', 'Credential theft'],
  Phishing: ['Phishing', 'Credential theft'],
  'Executive Impersonation': ['Impersonation', 'Authority abuse'],
  'Brand Impersonation': ['Impersonation', 'Brand abuse'],
  'Prompt Injection': ['Content injection', 'AI-assistant manipulation'],
  'Header Forgery': ['Spoofing', 'Sender forgery'],
  'Thread Hijack': ['BEC', 'Conversation hijack'],
  'Anonymized Origin': ['Evasion', 'Origin concealment'],
  'Known Campaign': ['Campaign', 'Coordinated attack'],
  'Suspicious Email': ['Suspicious', 'Undetermined'],
  Clean: ['Clean', 'None detected'],
}

// analyzer lane -> friendly name for Analysis coverage
const LANES = [
  ['M2', 'Header & relay'], ['M3', 'Authentication'], ['M4', 'Content analysis'],
  ['M5', 'Network & geo'], ['M6', 'Domain intel'], ['M7', 'Correlation'],
  ['M8', 'Email footprint'],
]

const SIG_ICON = {
  reply_to_domain_mismatch: Mail, fake_reply: Mail,
  dmarc_fail_strict: ShieldAlert, spf_fail_hard: ShieldAlert, dkim_fail: ShieldAlert, dkim_missing: ShieldAlert,
  links_no_text: Link2, obfuscated_url: Link2,
  hidden_text_mismatch: FileWarning, obfuscated_text: FileWarning,
  payment_diversion_intent: FileText, credential_harvest_intent: FileText, classifier_phishing_high: FileText,
  executive_impersonation: Fingerprint,
  brand_lookalike_domain: Globe, domain_age_lt_30d: Globe, domain_no_mx: Globe,
  domain_does_not_resolve: Globe, origin_anonymized: Globe, origin_datacenter_hosted: Globe,
  forged_received_hop: FileSearch, private_ip_in_public_chain: FileSearch, timestamp_regression: FileSearch,
  chain_discontinuity: FileSearch, rdns_mismatch: FileSearch, message_id_domain_divergence: FileSearch,
  campaign_infrastructure_reuse: Network,
}
const impactOf = (p) => (p >= 15 ? ['High impact', 'crit'] : p >= 8 ? ['Medium impact', 'med'] : ['Low impact', 'low'])
const domainOf = (addr) => (addr && addr.includes('@') ? addr.split('@').pop().toLowerCase() : null)
const RISKY_ATT = /\.(html?|svg|js|vbs|exe|scr|jar|hta|iso|zip|rar|docm|xlsm)$/i

export default function Result() {
  const { id } = useParams()
  const [data, setData] = useState(null)
  const [err, setErr] = useState(null)

  useEffect(() => {
    let ok = true
    Promise.all([api.getCase(id), api.artifacts(id)])
      .then(([c, a]) => ok && setData({ c, art: a }))
      .catch((x) => ok && setErr(String(x.message || x)))
    return () => { ok = false }
  }, [id])

  if (err) return <div><PageHead title="Analysis Result" back={{ to: '/analyze', label: 'Back' }} /><div className="card err-banner">Could not load case: {err}</div></div>
  if (!data) return <div><PageHead title="Analysis Result" /><div className="card center"><Loader2 className="spin" /> Loading…</div></div>

  const { c, art } = data
  const v = c.verdict
  const info = bandInfo(v.band)
  const contribs = v.contributions || []
  const positive = contribs.filter((x) => x.points > 0).sort((a, b) => b.points - a.points)
  const cls = classify(contribs)
  const [category, intent] = CLASS_DETAIL[cls] || CLASS_DETAIL['Suspicious Email']
  const conf = Math.round((v.confidence || 0) * 100)

  const unavailable = new Set(v.lanes_unavailable || [])
  const done = LANES.filter(([m]) => !unavailable.has(m)).length

  // sender-domain alignment
  const fromD = domainOf(c.from_addr)
  const replyD = domainOf(c.reply_to)
  const returnD = domainOf(c.return_path)
  const replyMis = replyD && fromD && replyD !== fromD
  const returnMis = returnD && fromD && returnD !== fromD
  const aligned = !replyMis && !returnMis

  const urls = art.urls || []
  const atts = art.attachments || []

  return (
    <div>
      <PageHead title="Analysis Result" back={{ to: '/analyze', label: 'Back to Analyze' }}
        actions={<Link to={`/forensic/${id}`} className="btn ghost"><FileSearch size={16} /> Forensic View</Link>} />

      {/* ---- row 1: score / classification / coverage ---- */}
      <div className="res-r1">
        <div className="card">
          <div className="card-title">Threat score</div>
          <div className="score-row">
            <ScoreGauge score={v.score} band={v.band} size={172} />
            <div className="summary">
              <p className="muted score-desc">{v.summary}</p>
              <div className="scale">
                <div className="scale-bar">
                  <span className="seg benign" /><span className="seg med" /><span className="seg high" /><span className="seg crit" />
                  <span className="scale-mark" style={{ left: `${Math.min(100, Math.max(0, v.score))}%`, borderColor: `var(--${info.key})` }} />
                </div>
                <div className="scale-nums"><span>0</span><span>25</span><span>50</span><span>75</span><span>100</span></div>
              </div>
            </div>
          </div>
        </div>

        <div className="card classify">
          <div className="card-title">Classification</div>
          <div className="class-head">
            <div className={'class-ic ' + info.key}><Anchor size={26} /></div>
            <div>
              <div className="class-name">{cls}</div>
              <div className="muted small">Confidence <b style={{ color: 'var(--low)' }}>{conf}%</b></div>
            </div>
          </div>
          <div className="class-meta">
            <div><div className="dim">Category</div><div className="mv">{category}</div></div>
            <div><div className="dim">Attack intent</div><div className="mv">{intent}</div></div>
          </div>
          <div className="class-verdict"><span className="dim">Verdict</span><span className={'badge ' + info.key}>{info.risk}</span></div>
        </div>

        <div className="card">
          <div className="card-title">Analysis coverage</div>
          <div className="cov-head">
            <div className={'cov-badge ' + (done === LANES.length ? 'ok' : 'warn')}>
              {done === LANES.length ? <ShieldCheck size={24} /> : <AlertTriangle size={24} />}
            </div>
            <div>
              <div className="cov-count">{done}/{LANES.length} <span className={done === LANES.length ? 'ok-t' : 'warn-t'}>checks complete</span></div>
              <div className="muted small">{done === LANES.length ? 'All analysis modules executed' : `${LANES.length - done} lane(s) unavailable — confidence reduced`}</div>
            </div>
          </div>
          <div className="cov-grid">
            {LANES.map(([m, name]) => {
              const ran = !unavailable.has(m)
              return (
                <div className="cov-item" key={m}>
                  {ran ? <CheckCircle2 size={15} style={{ color: 'var(--low)' }} /> : <AlertTriangle size={15} style={{ color: 'var(--med)' }} />}
                  <span className={ran ? '' : 'muted'}>{name}</span>
                </div>
              )
            })}
          </div>
        </div>
      </div>

      {/* ---- row 2: top evidence / (sender identity + summary) ---- */}
      <div className="res-r2">
        <div className="card">
          <div className="card-title">Top evidence</div>
          {positive.length ? (
            <div className="ev-grid">
              {positive.slice(0, 4).map((x) => {
                const Icon = SIG_ICON[x.signal] || FileWarning
                const [imp, tone] = impactOf(x.points)
                return (
                  <div className="ev-card" key={x.signal}>
                    <div className={'ev-ic ' + tone}><Icon size={18} /></div>
                    <div className="ev-body">
                      <div className="ev-head"><span className="ev-title">{x.label}</span><span className={'ev-pts ' + tone}>+{x.points.toFixed(0)}</span></div>
                      <div className="muted ev-desc">{(x.rationale || x.detail?.explanation || '').split('. ')[0]}</div>
                      <span className={'badge ' + tone}>{imp}</span>
                    </div>
                  </div>
                )
              })}
            </div>
          ) : <div className="muted center" style={{ padding: 24 }}>No threat indicators — message assessed clean.</div>}
        </div>

        <div className="res-r2-side">
          <div className="card">
            <div className="card-title">Sender identity</div>
            <div className="sid-rows">
              <SidRow label="From" value={c.from_addr} bad={false} />
              <SidRow label="Reply-To" value={c.reply_to} bad={replyMis} />
              <SidRow label="Return-Path" value={c.return_path} bad={returnMis} />
            </div>
            <div className={'sid-note ' + (aligned ? 'ok' : 'bad')}>
              {aligned ? <CheckCircle2 size={15} /> : <AlertTriangle size={15} />}
              {aligned ? 'Sender domains are aligned.' : 'Sender domains are not aligned.'}
            </div>
          </div>

          <div className="card">
            <div className="card-title">Email summary</div>
            <div className="inforows">
              <Row k="Subject" v={c.subject || '—'} />
              <Row k="Received" v={c.received_at ? new Date(c.received_at).toLocaleString() : '—'} />
              <Row k="Size" v={c.size_bytes ? `${(c.size_bytes / 1024).toFixed(1)} KB` : '—'} />
              <Row k="Format" v={c.body_format} />
              <Row k="Message ID" v={c.message_id || '—'} mono />
            </div>
          </div>
        </div>
      </div>

      {/* ---- row 3: URL analysis / attachments ---- */}
      <div className="res-r3">
        <div className="card">
          <div className="card-title">URL analysis ({urls.length})</div>
          {urls.length ? (
            <div className="tscroll"><table className="url-tbl">
              <thead><tr><th>Displayed</th><th>Destination</th><th>Verdict</th><th>Risk</th></tr></thead>
              <tbody>
                {urls.slice(0, 8).map((u, i) => {
                  const bad = u.mismatched
                  const verdict = bad ? 'Malicious' : u.shortened ? 'Suspicious' : 'Clean'
                  const [rl, tone] = bad ? ['High', 'crit'] : u.shortened ? ['Medium', 'med'] : ['Low', 'low']
                  return (
                    <tr key={i}>
                      <td className="u-disp">{u.display || u.domain || '—'}</td>
                      <td className="u-dest" title={u.url}>{u.url}</td>
                      <td><span className={'badge ' + tone}>{verdict}</span></td>
                      <td><span className={'badge ' + tone}>{rl}</span></td>
                    </tr>
                  )
                })}
              </tbody>
            </table></div>
          ) : <div className="muted center" style={{ padding: 20 }}>No URLs in this message.</div>}
        </div>

        <div className="card">
          <div className="card-title">Attachments ({atts.length})</div>
          {atts.length ? (
            <div className="att-list">
              {atts.map((a, i) => {
                const risky = RISKY_ATT.test(a.filename || '')
                return (
                  <div className="att-row" key={i}>
                    <div className={'att-ic ' + (risky ? 'crit' : 'low')}><Paperclip size={16} /></div>
                    <div className="att-main">
                      <div className="att-name" title={a.filename}>{a.filename || 'unnamed'}</div>
                      <div className="muted small">{a.content_type || 'unknown'} · {a.size_bytes ? `${(a.size_bytes / 1024).toFixed(1)} KB` : '—'}</div>
                    </div>
                    <span className={'badge ' + (risky ? 'crit' : 'low')}>{risky ? 'High' : 'Low'}</span>
                  </div>
                )
              })}
            </div>
          ) : <div className="muted center" style={{ padding: 20 }}>No attachments.</div>}
          <Link to={`/forensic/${id}`} className="violet-link att-more">Full forensic breakdown <ArrowRight size={14} /></Link>
        </div>
      </div>

      {/* ---- row 4: sender email footprint (M8) ---- */}
      {c.footprint && (
        <div className="card" style={{ marginTop: 20 }}>
          <div className="card-title" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <Fingerprint size={17} /> Sender email footprint
          </div>
          <div className="muted small" style={{ marginTop: -8, marginBottom: 14 }}>
            Platforms where <b>{c.footprint.email || c.from_addr}</b> appears to be registered — identity context, not attribution. A large footprint never means the message is safe.
          </div>
          {c.footprint.disposable && (
            <div className="sid-note bad" style={{ marginBottom: 14 }}>
              <AlertTriangle size={15} /> Disposable / temporary-inbox sender domain — typical of throwaway attacker accounts.
            </div>
          )}
          {c.footprint.registered_count > 0 ? (
            <>
              <div className="fp-grid">
                {c.footprint.registered.map((p, i) => (
                  <span className={'fp-chip' + (p.simulated ? ' sim' : '')} key={i} title={p.method}>
                    <span className="fp-dot" />{p.platform}{p.simulated && <em>demo</em>}
                  </span>
                ))}
              </div>
              {c.footprint.includes_simulated && (
                <div className="muted small" style={{ marginTop: 12 }}>
                  Chips marked <b>demo</b> come from the labelled simulated dataset; the rest are live results (Gravatar profile / linked accounts).
                </div>
              )}
            </>
          ) : (
            <div className="muted center" style={{ padding: 18 }}>No public account footprint found for this address.</div>
          )}
        </div>
      )}
    </div>
  )
}

function SidRow({ label, value, bad }) {
  return (
    <div className="sid-row">
      <span className="dim">{label}</span>
      <span className="sid-val" title={value || ''}>{value || '—'}</span>
      {value && (bad
        ? <AlertTriangle size={14} style={{ color: 'var(--crit)', flexShrink: 0 }} />
        : <CheckCircle2 size={14} style={{ color: 'var(--low)', flexShrink: 0 }} />)}
    </div>
  )
}

function Row({ k, v, mono }) {
  return (
    <div className="inforow"><span className="dim">{k}</span><span className={'infoval' + (mono ? ' mono' : '')}>{v}</span></div>
  )
}
