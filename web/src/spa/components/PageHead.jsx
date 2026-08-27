import { useState } from 'react'
import { Link } from 'react-router-dom'
import { Moon, Sun, Bell, ChevronLeft, Search, User, Info } from 'lucide-react'
import { useAuth } from '../auth.jsx'
import { getTheme, toggleTheme } from '../theme.js'

export default function PageHead({ title, subtitle, back, actions, crumb = 'Pages' }) {
  const { user } = useAuth() || {}
  const [dark, setDark] = useState(getTheme() === 'dark')
  const flip = () => setDark(toggleTheme() === 'dark')

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
        <div className="searchpill"><Search size={16} /><input placeholder="Search" /></div>
        <button className="iconbtn round" onClick={flip} title="Toggle theme">
          {dark ? <Sun size={18} /> : <Moon size={18} />}
        </button>
        <button className="iconbtn round"><Bell size={18} /><span className="dot">3</span></button>
        <button className="iconbtn round"><Info size={18} /></button>
        <div className="avatar sm"><User size={18} /></div>
      </div>
    </div>
  )
}
