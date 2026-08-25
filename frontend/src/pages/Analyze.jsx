import { useState, useRef } from 'react'
import { useNavigate } from 'react-router-dom'
import { UploadCloud, FileText, Loader2, Zap, ShieldAlert, Landmark, ShieldCheck } from 'lucide-react'
import PageHead from '../components/PageHead.jsx'
import { api } from '../api.js'
import './analyze.css'

const SAMPLES = [
  { file: 'phishing.eml', label: 'Phishing attack', icon: ShieldAlert, tone: 'crit', desc: 'PayPal credential-harvest lookalike' },
  { file: 'bec.eml', label: 'BEC / wire fraud', icon: Landmark, tone: 'high', desc: 'Injected hop + payment diversion' },
  { file: 'benign.eml', label: 'Benign control', icon: ShieldCheck, tone: 'benign', desc: 'Legitimate committee email' },
]

export default function Analyze() {
  const nav = useNavigate()
  const [file, setFile] = useState(null)
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState(null)
  const [drag, setDrag] = useState(false)
  const inputRef = useRef()

  async function run(f) {
    setBusy(true); setErr(null)
    try {
      const res = await api.analyze(f)
      nav(`/result/${res.case_id}`)
    } catch (e) {
      setErr(String(e.message || e)); setBusy(false)
    }
  }

  async function loadSample(name) {
    setBusy(true); setErr(null)
    try {
      const blob = await (await fetch(`/samples/${name}`)).blob()
      await run(new File([blob], name, { type: 'message/rfc822' }))
    } catch (e) { setErr(String(e.message || e)); setBusy(false) }
  }

  const onDrop = (e) => {
    e.preventDefault(); setDrag(false)
    const f = e.dataTransfer.files?.[0]
    if (f) setFile(f)
  }

  return (
    <div>
      <PageHead title="Analyze Email" subtitle="Upload a raw .eml message for full threat analysis" />

      {err && <div className="card err-banner">Analysis failed: {err}</div>}

      <div className="analyze-grid">
        <div className="card">
          <div className="card-title">Upload message</div>
          <div
            className={'dropzone' + (drag ? ' drag' : '') + (busy ? ' busy' : '')}
            onDragOver={(e) => { e.preventDefault(); setDrag(true) }}
            onDragLeave={() => setDrag(false)}
            onDrop={onDrop}
            onClick={() => !busy && inputRef.current.click()}
          >
            <input ref={inputRef} type="file" accept=".eml,.msg,message/rfc822" hidden
              onChange={(e) => setFile(e.target.files?.[0] || null)} />
            {busy ? (
              <><Loader2 className="spin" size={40} /><div className="dz-t">Running 7 analyzers…</div>
                <div className="muted">Parsing headers, verifying SPF/DKIM/DMARC, scoring content</div></>
            ) : file ? (
              <><FileText size={40} color="var(--violet)" /><div className="dz-t">{file.name}</div>
                <div className="muted">{(file.size / 1024).toFixed(1)} KB · ready to analyze</div></>
            ) : (
              <><UploadCloud size={40} color="var(--text-3)" />
                <div className="dz-t">Drop an .eml file here</div>
                <div className="muted">or click to browse</div></>
            )}
          </div>
          <button className="btn" disabled={!file || busy} style={{ width: '100%', marginTop: 16, padding: 13, opacity: (!file || busy) ? .5 : 1 }}
            onClick={() => file && run(file)}>
            <Zap size={17} /> Analyze Email
          </button>
        </div>

        <div className="card">
          <div className="card-title">Or try a sample</div>
          <div className="samples">
            {SAMPLES.map(({ file: f, label, icon: Icon, tone, desc }) => (
              <button key={f} className="sample" disabled={busy} onClick={() => loadSample(f)}>
                <div className={'sample-ic ' + tone}><Icon size={20} /></div>
                <div className="sample-body">
                  <div className="sample-t">{label}</div>
                  <div className="muted" style={{ fontSize: '.8rem' }}>{desc}</div>
                </div>
                <span className={'badge ' + tone}>demo</span>
              </button>
            ))}
          </div>
          <p className="muted" style={{ fontSize: '.82rem', marginTop: 16, lineHeight: 1.5 }}>
            Samples are synthetic. Every verdict below is produced live by the real analyzers —
            header forensics, SPF/DKIM/DMARC re-verification, NLP content analysis, network &
            domain intelligence, and campaign correlation.
          </p>
        </div>
      </div>
    </div>
  )
}
