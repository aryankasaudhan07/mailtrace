import { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { Moon, Sun, ChevronLeft, Search, User } from 'lucide-react'
import { useAuth } from '../auth.jsx'
import { getTheme, toggleTheme } from '../theme.js'

export default function PageHead({ title, subtitle, back, actions, crumb = 'Pages' }) {
  const { user } = useAuth() || {}
  const nav = useNavigate()
  const [dark, setDark] = useState(getTheme() === 'dark')
  const [q, setQ] = useState('')
  const flip = () => setDark(toggleTheme() === 'dark')
  const search = (e) => {
    e.preventDefault()
    nav(q.trim() ? `/history?q=${encodeURIComponent(q.trim())}` : '/history')
  }

  return (
    <div className="pagehead">
      <div className="pagehead-left">
        <div className="crumb">{crumb} <span>/ {title}</span></div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <h1>{title}</h1>
          {back && <Link to={back.to} className="back"><ChevronLeft size={16} />{back.label}</Link>}
        </div>
        {subtitle && <div className="sub">{subtitle}</div>}
      </div>

      <div className="topbar-pill">
        {actions}
        <form className="searchpill" onSubmit={search}>
          <button type="submit" className="searchpill-btn" aria-label="Search"><Search size={16} /></button>
          <input placeholder="Search messages…" value={q} onChange={(e) => setQ(e.target.value)} />
        </form>
        <button className="iconbtn round" onClick={flip} title="Toggle theme">
          {dark ? <Sun size={18} /> : <Moon size={18} />}
        </button>
        <button className="avatar sm" onClick={() => nav('/settings')} title={user?.name || 'Profile'}>
          <User size={18} />
        </button>
      </div>
    </div>
  )
}
