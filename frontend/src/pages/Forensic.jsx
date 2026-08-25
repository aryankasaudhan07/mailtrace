import { useEffect, useState } from 'react'
import { useParams, Link } from 'react-router-dom'
import {
  Loader2, Download, Globe, Link2, Paperclip, AtSign, Hash, FileText,
  CheckCircle2, XCircle, Send, Server, Inbox, ShieldCheck,
} from 'lucide-react'
import PageHead from '../components/PageHead.jsx'
import { api } from '../api.js'
import './forensic.css'

const TABS = ['Overview', 'Headers', 'URLs', 'Domains', 'IPs', 'Attachments', 'Raw']
const TRUST = { BOUNDARY: 'violet', TRUSTED: 'low', UNVERIFIED: 'med' }

export default function Forensic() {
  const { id } = useParams()
  const [d, setD] = useState(null)
  const [err, setErr] = useState(null)
  const [tab, setTab] = useState('Overview')

  useEffect(() => {
    let ok = true
    Promise.all([api.getCase(id), api.headers(id), api.evidence(id), api.trace(id), api.artifacts(id)])
      .then(([c, h, e, t, a]) => ok && setD({ c, headers: h.headers, ev: e.records, hops: t.hops, boundary: t.boundary_seq, art: a }))
      .catch((x) => ok && setErr(String(x.message || x)))
    return () => { ok = false }
  }, [id])

  if (err) return <div><PageHead title="Forensic Analysis" /><div className="card err-banner">Could not load: {err}</div></div>
  if (!d) return <div><PageHead title="Forensic Analysis" /><div className="card center"><Loader2 className="spin" /> Loading…</div></div>

  const { c, headers, ev, hops, art } = d
  const trig = (sig) => ev.find((r) => r.signal === sig && r.status === 'TRIGGERED')
  const clear = (sig) => ev.find((r) => r.signal === sig && r.status === 'CLEAR')
  const authStatus = (fail, ...clears) => trig(fail) ? 'fail' : clears.some(clear) || clear('auth_verification_passed') ? 'pass' : 'skip'
  const auth = {
    SPF: authStatus('spf_fail_hard'),
    DKIM: trig('dkim_fail') ? 'fail' : trig('dkim_valid_aligned') ? 'pass' : 'skip',
    DMARC: authStatus('dmarc_fail_strict'),
  }

  return (
    <div>
      <PageHead title="Forensic Analysis" back={{ to: `/result/${id}`, label: 'Back to Result' }}
        actions={<a className="btn ghost" href={`/api/cases/${id}/report/text`} target="_blank" rel="noreferrer"><Download size={16} /> Report</a>} />

      <div className="tabbar">
        {TABS.map((t) => {
          const n = t === 'URLs' ? art.urls.length : t === 'Domains' ? art.domains.length
            : t === 'IPs' ? art.ips.length : t === 'Attachments' ? art.attachments.length : null
          return (
            <button key={t} className={'tab' + (tab === t ? ' on' : '')} onClick={() => setTab(t)}>
              {t}{n != null && <span className="tab-n">{n}</span>}
            </button>
          )
        })}
      </div>

      {tab === 'Overview' && (
        <div className="fo-grid">
          <div className="fo-main">
            <div className="card">
              <div className="card-title">Email Headers</div>
              <pre className="rawhdr">{headers.slice(0, 14).map((h) => `${h.name}: ${h.value}`).join('\n')}</pre>
            </div>
            <IndicatorCounts art={art} c={c} ev={ev} />
          </div>
          <div className="fo-side">
            <div className="card">
              <div className="card-title">Summary</div>
              <SummaryRows c={c} art={art} ev={ev} auth={auth} />
            </div>
            <div className="card">
              <div className="card-title">Email Timeline</div>
              <Timeline hops={hops} />
            </div>
          </div>
          <div className="card fo-auth">
            <div className="card-title">Authentication Results</div>
            <div className="authrow">
              <AuthCard name="SPF" full="Sender Policy Framework" status={auth.SPF} />
              <AuthCard name="DKIM" full="DomainKeys Identified Mail" status={auth.DKIM} />
              <AuthCard name="DMARC" full="Domain-based Auth, Reporting & Conformance" status={auth.DMARC} />
            </div>
          </div>
        </div>
      )}

      {tab === 'Headers' && (
        <div className="card">
          <div className="card-title">Raw Headers ({headers.length})</div>
          <div className="hdrlist">
            {headers.map((h, i) => (
              <div className="hdrline" key={i}>
                <span className="hdr-k mono">{h.name}</span>
                <span className="hdr-v mono">{h.value}</span>
                {h.trust && <span className={'badge ' + (TRUST[h.trust] || 'med')}>{h.trust}</span>}
              </div>
            ))}
          </div>
        </div>
      )}

      {tab === 'URLs' && <IocTable title="URLs" icon={Link2} rows={art.urls.map((u) => [u.url, u.mismatched ? 'Anchor mismatch' : u.shortened ? 'Shortened' : u.domain])} cols={['URL', 'Note']} />}
      {tab === 'Domains' && <IocTable title="Domains" icon={Globe} rows={art.domains.map((x) => [x])} cols={['Domain']} />}
      {tab === 'IPs' && <IocTable title="IP Addresses" icon={Server} rows={art.ips.map((x) => [x.ip, `hop ${x.hop}`, x.trust])} cols={['IP', 'Position', 'Trust']} badge={2} />}
      {tab === 'Attachments' && (
        <div className="card">
          <div className="card-title">Attachments ({art.attachments.length})</div>
          {art.attachments.length ? art.attachments.map((a, i) => {
            const exe = /octet-stream|msdownload|\.exe|\.scr|\.js$/.test((a.content_type || '') + (a.filename || ''))
            return (
              <div className="att" key={i}>
                <div className={'att-ic ' + (exe ? 'crit' : 'low')}><FileText size={20} /></div>
                <div className="att-body"><div style={{ fontWeight: 600 }}>{a.filename || '(unnamed)'}</div>
                  <div className="muted" style={{ fontSize: '.8rem' }}>{(a.size_bytes / 1024).toFixed(1)} KB · {a.content_type}</div>
                  <div className="dim mono" style={{ fontSize: '.72rem', marginTop: 2 }}>{a.sha256.slice(0, 32)}…</div></div>
                <span className={'badge ' + (exe ? 'crit' : 'benign')}>{exe ? 'High-risk type' : 'No scan'}</span>
              </div>
            )
          }) : <div className="muted center">No attachments.</div>}
        </div>
      )}
      {tab === 'Raw' && (
        <div className="card"><div className="card-title">Raw Message</div>
          <pre className="rawhdr" style={{ maxHeight: 600 }}>{art.raw || '(unavailable)'}</pre></div>
      )}
    </div>
  )
}

function SummaryRows({ c, art, auth }) {
  const rows = [
    ['Received hops', art.ips.length], ['Message ID', c.message_id ? 1 : 0],
    ['Return path', c.return_path ? 1 : 0], ['SPF result', auth.SPF], ['DKIM result', auth.DKIM], ['DMARC result', auth.DMARC],
  ]
  const tone = (v) => v === 'fail' ? 'crit' : v === 'pass' ? 'benign' : v === 'skip' ? 'med' : null
  return (
    <div className="inforows">
      {rows.map(([k, v], i) => (
        <div className="inforow" key={i}><span className="dim">{k}</span>
          {tone(v) ? <span className={'badge ' + tone(v)}>{v === 'skip' ? 'n/a' : v}</span> : <b>{v}</b>}</div>
      ))}
    </div>
  )
}

function Timeline({ hops }) {
  const stamped = hops.filter((h) => h.timestamp)
  const items = [
    { icon: Send, label: 'Origin sent', t: stamped[0]?.timestamp },
    { icon: Server, label: 'Relayed', t: stamped[Math.floor(stamped.length / 2)]?.timestamp },
    { icon: Inbox, label: 'Delivered', t: stamped[stamped.length - 1]?.timestamp },
  ]
  return (
    <div className="timeline">
      {items.map(({ icon: Icon, label, t }, i) => (
        <div className="tl-item" key={i}>
          <div className="tl-ic"><Icon size={15} /></div>
          <div><div style={{ fontWeight: 600, fontSize: '.88rem' }}>{label}</div>
            <div className="dim" style={{ fontSize: '.78rem' }}>{t ? new Date(t).toLocaleString() : '—'}</div></div>
        </div>
      ))}
    </div>
  )
}

function IndicatorCounts({ art, c, ev }) {
  const headerIssues = ev.filter((r) => r.analyzer === 'M2' && r.status === 'TRIGGERED').length
  const items = [
    [Globe, 'IP Addresses', art.ips.length, 'var(--info)'], [Globe, 'Domains', art.domains.length, 'var(--high)'],
    [Link2, 'URLs', c.url_count, 'var(--violet)'], [AtSign, 'Email Addresses', art.emails.length, 'var(--low)'],
    [Hash, 'Hashes', art.hashes.length, 'var(--info)'], [Paperclip, 'Attachments', c.attachment_count, 'var(--med)'],
  ]
  return (
    <div className="card">
      <div className="card-title">Extracted Indicators</div>
      <div className="ioc-counts">
        {items.map(([Icon, label, n, color], i) => (
          <div className="ioc-count" key={i}>
            <Icon size={17} style={{ color }} /><span>{label}</span><b>{n}</b>
          </div>
        ))}
      </div>
    </div>
  )
}

function AuthCard({ name, full, status }) {
  const ok = status === 'pass', skip = status === 'skip'
  const Icon = ok ? CheckCircle2 : skip ? ShieldCheck : XCircle
  const tone = ok ? 'low' : skip ? 'med' : 'crit'
  return (
    <div className="authcard-f">
      <div className={'auth-ic ' + tone}><Icon size={22} /></div>
      <div><div style={{ fontWeight: 650 }}>{name}</div><div className="dim" style={{ fontSize: '.78rem' }}>{full}</div>
        <div style={{ color: `var(--${tone === 'low' ? 'low' : tone === 'med' ? 'med' : 'crit'})`, fontSize: '.82rem', fontWeight: 600, marginTop: 3 }}>
          {ok ? 'Passed' : skip ? 'Not enforced' : 'Failed'}</div></div>
    </div>
  )
}

function IocTable({ title, icon: Icon, rows, cols }) {
  return (
    <div className="card">
      <div className="card-title" style={{ display: 'flex', alignItems: 'center', gap: 8 }}><Icon size={17} /> {title} ({rows.length})</div>
      {rows.length ? (
        <table className="breakdown"><thead><tr>{cols.map((c) => <th key={c}>{c}</th>)}</tr></thead>
          <tbody>{rows.map((r, i) => <tr key={i}>{r.map((cell, j) => <td key={j} className={j === 0 ? 'mono' : 'muted'}>{cell}</td>)}</tr>)}</tbody>
        </table>
      ) : <div className="muted center">None extracted.</div>}
    </div>
  )
}
