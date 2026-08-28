import { useEffect, useRef, useState, useMemo } from 'react'
import { Search, PanelLeftClose, PanelLeftOpen } from 'lucide-react'
import PageHead from '../components/PageHead.jsx'
import { api, bandInfo } from '../api.js'
import './graph.css'

// Entity node types -> label + colour (canvas can't read CSS vars per-frame).
const TYPES = [
  { key: 'case', label: 'Email', color: '#7551ff' },
  { key: 'domain', label: 'Sender domain', color: '#e15c39' },
  { key: 'ip', label: 'IP address', color: '#3965ff' },
  { key: 'alias', label: 'Alias', color: '#01b574' },
  { key: 'infra', label: 'Infrastructure', color: '#e0a020' },
  { key: 'hash', label: 'Attachment', color: '#8a8fa3' },
]
const COLOR = Object.fromEntries(TYPES.map((t) => [t.key, t.color]))
const LABEL = Object.fromEntries(TYPES.map((t) => [t.key, t.label]))
const SEL_KEY = 'mt_graph_sel'
const AUTO_ALL_MAX = 40 // if there are at most this many emails, select all by default

export default function Graph() {
  const wrapRef = useRef(null)
  const canvasRef = useRef(null)
  const stRef = useRef({ pos: new Map(), drag: null, raf: 0 })
  const [cases, setCases] = useState([])
  const [sel, setSel] = useState(null) // Set of case_ids, null until initialised
  const [data, setData] = useState(null)
  const [hidden, setHidden] = useState(() => new Set())
  const [hover, setHover] = useState(null)
  const [q, setQ] = useState('')
  const [panel, setPanel] = useState(true)

  // load the email list (for the picker); refresh periodically to catch new mail
  useEffect(() => {
    let alive = true
    const load = () => api.listCases(5000).then((r) => { if (alive) setCases(r.items || []) }).catch(() => {})
    load()
    const t = setInterval(load, 12000)
    return () => { alive = false; clearInterval(t) }
  }, [])

  // initialise the selection once cases arrive (from localStorage, else a default)
  useEffect(() => {
    if (sel !== null || !cases.length) return
    const ids = cases.map((c) => c.case_id)
    let init
    try {
      const saved = JSON.parse(localStorage.getItem(SEL_KEY) || 'null')
      if (Array.isArray(saved)) init = saved.filter((id) => ids.includes(id))
    } catch { /* ignore */ }
    if (!init || !init.length) init = ids.length <= AUTO_ALL_MAX ? ids : ids.slice(0, 25)
    setSel(new Set(init))
  }, [cases, sel])

  // fetch the graph for the selected emails (debounced) + live poll
  useEffect(() => {
    if (sel === null) return
    try { localStorage.setItem(SEL_KEY, JSON.stringify([...sel])) } catch { /* ignore */ }
    let alive = true
    const ids = [...sel]
    const load = () => {
      if (!ids.length) { setData({ nodes: [], links: [] }); return }
      api.graphEntities(ids).then((g) => { if (alive) setData(g) }).catch(() => { if (alive) setData({ nodes: [], links: [] }) })
    }
    const debounce = setTimeout(load, 250)
    const poll = setInterval(load, 8000)
    return () => { alive = false; clearTimeout(debounce); clearInterval(poll) }
  }, [sel])

  // build simulation + render loop
  useEffect(() => {
    if (!data) return
    const wrap = wrapRef.current
    const canvas = canvasRef.current
    if (!wrap || !canvas) return
    const st = stRef.current
    const ctx = canvas.getContext('2d')
    const dpr = Math.min(2, window.devicePixelRatio || 1)

    const shown = data.nodes.filter((n) => !hidden.has(n.type))
    const idset = new Set(shown.map((n) => n.id))
    const N = shown.map((n) => {
      const p = st.pos.get(n.id)
      const w = wrap.clientWidth || 800, h = wrap.clientHeight || 500
      return {
        ...n, vx: 0, vy: 0,
        x: p?.x ?? w / 2 + (Math.random() - 0.5) * 320,
        y: p?.y ?? h / 2 + (Math.random() - 0.5) * 320,
        r: n.type === 'case' ? 7 + Math.min(10, (n.score || 0) / 12) : 5,
      }
    })
    const byId = new Map(N.map((n) => [n.id, n]))
    const L = data.links
      .filter((l) => idset.has(l.source) && idset.has(l.target))
      .map((l) => ({ ...l, s: byId.get(l.source), t: byId.get(l.target) }))
      .filter((l) => l.s && l.t)

    const resize = () => {
      const w = wrap.clientWidth, h = wrap.clientHeight
      canvas.width = w * dpr; canvas.height = h * dpr
      canvas.style.width = `${w}px`; canvas.style.height = `${h}px`
      st.W = w; st.H = h
    }
    resize()
    const ro = new ResizeObserver(resize); ro.observe(wrap)
    const textColor = getVar('--text') || '#1b2559'
    const fit = (text, maxw) => {
      let t = String(text)
      while (t.length > 4 && ctx.measureText(t).width > maxw) t = t.slice(0, -2)
      return t.length < String(text).length ? `${t}…` : t
    }
    const restLen = (l) => (l.rel === 'reply-chain' ? 120 : l.rel === 'domain' ? 42 : 78)

    const draw = () => {
      const { W, H } = st
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0)
      ctx.clearRect(0, 0, W, H)
      for (const l of L) {
        ctx.beginPath(); ctx.moveTo(l.s.x, l.s.y); ctx.lineTo(l.t.x, l.t.y)
        if (l.rel === 'reply-chain') { ctx.strokeStyle = 'rgba(117,81,255,0.6)'; ctx.setLineDash([5, 4]); ctx.lineWidth = 1.7 }
        else if (l.rel === 'origin') { ctx.strokeStyle = 'rgba(1,181,116,0.55)'; ctx.setLineDash([]); ctx.lineWidth = 1.5 }
        else { ctx.strokeStyle = 'rgba(130,140,170,0.28)'; ctx.setLineDash([]); ctx.lineWidth = 1 }
        ctx.stroke()
      }
      ctx.setLineDash([])
      for (const n of N) {
        ctx.beginPath(); ctx.fillStyle = COLOR[n.type] || '#888'
        ctx.arc(n.x, n.y, n.r, 0, 7); ctx.fill()
        if (n.type === 'case') { ctx.strokeStyle = '#fff'; ctx.lineWidth = 1.5; ctx.stroke() }
      }
      ctx.font = '11px ui-sans-serif, system-ui, sans-serif'; ctx.fillStyle = textColor
      for (const n of N) if (n.type === 'case') ctx.fillText(fit(n.label, 96), n.x + n.r + 3, n.y + 3)
    }
    const tick = () => {
      const { W, H } = st
      for (let i = 0; i < N.length; i++) {
        const a = N[i]
        for (let j = i + 1; j < N.length; j++) {
          const b = N[j]
          let dx = a.x - b.x, dy = a.y - b.y
          let d2 = dx * dx + dy * dy || 0.01
          if (d2 < 40000) {
            const d = Math.sqrt(d2), f = 1500 / d2, ux = dx / d, uy = dy / d
            a.vx += ux * f; a.vy += uy * f; b.vx -= ux * f; b.vy -= uy * f
          }
        }
      }
      for (const l of L) {
        const a = l.s, b = l.t
        let dx = b.x - a.x, dy = b.y - a.y
        const d = Math.sqrt(dx * dx + dy * dy) || 0.01
        const f = (d - restLen(l)) * 0.02, ux = dx / d, uy = dy / d
        a.vx += ux * f; a.vy += uy * f; b.vx -= ux * f; b.vy -= uy * f
      }
      for (const n of N) { n.vx += (W / 2 - n.x) * 0.002; n.vy += (H / 2 - n.y) * 0.002 }
      for (const n of N) {
        if (n === st.drag) continue
        n.vx *= 0.86; n.vy *= 0.86
        n.x += Math.max(-24, Math.min(24, n.vx)); n.y += Math.max(-24, Math.min(24, n.vy))
        st.pos.set(n.id, { x: n.x, y: n.y })
      }
      draw()
      st.raf = requestAnimationFrame(tick)
    }
    st.raf = requestAnimationFrame(tick)

    const pick = (mx, my) => {
      for (let i = N.length - 1; i >= 0; i--) {
        const n = N[i]
        if ((mx - n.x) ** 2 + (my - n.y) ** 2 <= (n.r + 3) ** 2) return n
      }
      return null
    }
    const onMove = (e) => {
      const r = canvas.getBoundingClientRect(), mx = e.clientX - r.left, my = e.clientY - r.top
      if (st.drag) { st.drag.x = mx; st.drag.y = my; st.pos.set(st.drag.id, { x: mx, y: my }); return }
      const n = pick(mx, my)
      canvas.style.cursor = n ? 'pointer' : 'default'
      setHover(n ? { node: n, x: e.clientX, y: e.clientY } : null)
    }
    const onDown = (e) => { const r = canvas.getBoundingClientRect(); const n = pick(e.clientX - r.left, e.clientY - r.top); if (n) st.drag = n }
    const onUp = () => { st.drag = null }
    canvas.addEventListener('mousemove', onMove)
    canvas.addEventListener('mousedown', onDown)
    window.addEventListener('mouseup', onUp)

    return () => {
      cancelAnimationFrame(st.raf); ro.disconnect()
      canvas.removeEventListener('mousemove', onMove)
      canvas.removeEventListener('mousedown', onDown)
      window.removeEventListener('mouseup', onUp)
    }
  }, [data, hidden])

  const counts = {}
  for (const n of (data?.nodes || [])) counts[n.type] = (counts[n.type] || 0) + 1
  const toggleType = (k) => setHidden((h) => { const n = new Set(h); n.has(k) ? n.delete(k) : n.add(k); return n })

  const toggleSel = (id) => setSel((s) => { const n = new Set(s); n.has(id) ? n.delete(id) : n.add(id); return n })
  const filtered = useMemo(() => {
    const needle = q.trim().toLowerCase()
    if (!needle) return cases
    return cases.filter((c) => `${c.subject || ''} ${c.from_addr || ''}`.toLowerCase().includes(needle))
  }, [cases, q])
  const setAll = (ids) => setSel(new Set(ids))
  const selCount = sel ? sel.size : 0

  return (
    <div>
      <PageHead title="Graph" subtitle="Relationship graph — sender domains, IPs, aliases, reply chains and shared infrastructure" />

      <div className="card graph-card">
        <div className="graph-layout">
          {panel && (
            <aside className="graph-picker">
              <div className="gp-head">
                <span>Emails <b>{selCount}</b> / {cases.length}</span>
                <button className="gp-x" onClick={() => setPanel(false)} title="Hide panel"><PanelLeftClose size={16} /></button>
              </div>
              <div className="gp-search">
                <Search size={14} />
                <input placeholder="Filter emails…" value={q} onChange={(e) => setQ(e.target.value)} />
              </div>
              <div className="gp-actions">
                <button onClick={() => setAll(cases.map((c) => c.case_id))}>Select all</button>
                <button onClick={() => setAll([])}>None</button>
                <button onClick={() => setAll(cases.slice(0, 25).map((c) => c.case_id))}>Recent 25</button>
              </div>
              <div className="gp-list">
                {filtered.length === 0 && <div className="gp-empty">No emails match.</div>}
                {filtered.map((c) => {
                  const info = bandInfo(c.band)
                  return (
                    <label className="gp-item" key={c.case_id}>
                      <input type="checkbox" checked={sel ? sel.has(c.case_id) : false} onChange={() => toggleSel(c.case_id)} />
                      <span className={'gp-dot ' + info.key} />
                      <span className="gp-subj" title={c.subject}>{c.subject || '(no subject)'}</span>
                      <span className="gp-score">{c.score}</span>
                    </label>
                  )
                })}
              </div>
            </aside>
          )}

          <div className="graph-main">
            <div className="graph-legend">
              {!panel && (
                <button className="gleg gp-open" onClick={() => setPanel(true)}><PanelLeftOpen size={14} /> Select emails</button>
              )}
              {TYPES.map((t) => (
                <button key={t.key} className={'gleg' + (hidden.has(t.key) ? ' off' : '')} onClick={() => toggleType(t.key)}>
                  <span className="gdot" style={{ background: t.color }} />{t.label}<b>{counts[t.key] || 0}</b>
                </button>
              ))}
            </div>
            <div className="graph-canvas-wrap" ref={wrapRef}>
              <canvas ref={canvasRef} />
              {!data && <div className="graph-loading">Loading graph…</div>}
              {data && !data.nodes.length && (
                <div className="graph-loading">{selCount === 0 ? 'No emails selected — tick some in the panel to build the graph.' : 'No cases yet — analyze an email to build the graph.'}</div>
              )}
            </div>
          </div>
        </div>
      </div>

      {hover && (
        <div className="graph-tip" style={{ left: hover.x + 14, top: hover.y + 14 }}>
          <div className="gtip-type" style={{ color: COLOR[hover.node.type] }}>{LABEL[hover.node.type]}</div>
          <div className="gtip-label">{hover.node.label}</div>
          {hover.node.type === 'case' && <div className="gtip-meta">Score {hover.node.score} · {String(hover.node.band || '').replace('_', ' ')}</div>}
        </div>
      )}
    </div>
  )
}

function getVar(name) {
  try { return getComputedStyle(document.documentElement).getPropertyValue(name).trim() } catch { return '' }
}
