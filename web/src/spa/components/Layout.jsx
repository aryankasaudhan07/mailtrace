import { useState, useEffect } from 'react'
import { NavLink, Outlet, useNavigate, useLocation } from 'react-router-dom'
import {
  LayoutGrid, MailSearch, History, FileText, ShieldAlert, Share2,
  MapPin, Settings, HelpCircle, LogOut, ShieldCheck, Mail, Menu, X,
} from 'lucide-react'
import { useAuth } from '../auth.jsx'
import './layout.css'

const NAV = [
  { to: '/', label: 'Dashboard', icon: LayoutGrid, end: true },
  { to: '/analyze', label: 'Analyze Email', icon: MailSearch },
  { to: '/history', label: 'History', icon: History },
  { to: '/reports', label: 'Reports', icon: FileText },
  { to: '/threat-intel', label: 'Threat Intelligence', icon: ShieldAlert },
  { to: '/graph', label: 'Graph', icon: Share2 },
  { to: '/geolocation', label: 'Geolocation', icon: MapPin },
  { to: '/settings', label: 'Settings', icon: Settings },
  { to: '/help', label: 'Help', icon: HelpCircle },
]

export default function Layout() {
  const nav = useNavigate()
  const loc = useLocation()
  const { logout } = useAuth()
  const [open, setOpen] = useState(false)
  const doLogout = () => { logout(); nav('/login') }
  // close the mobile drawer whenever the route changes
  useEffect(() => { setOpen(false) }, [loc.pathname])
  // lock body scroll while the drawer is open
  useEffect(() => {
    document.body.style.overflow = open ? 'hidden' : ''
    return () => { document.body.style.overflow = '' }
  }, [open])

  return (
    <div className="shell">
      <header className="mobilebar">
        <button className="hamb" onClick={() => setOpen(true)} aria-label="Open menu"><Menu size={22} /></button>
        <div className="brand-badge sm"><Mail size={17} /></div>
        <span className="mobilebar-title">Email Threat Intelligence</span>
      </header>

      {open && <div className="scrim" onClick={() => setOpen(false)} />}

      <aside className={'sidebar' + (open ? ' open' : '')}>
        <div className="brand">
          <div className="brand-badge"><Mail size={20} /></div>
          <div className="brand-text">Email Threat<br />Intelligence</div>
          <button className="drawer-close" onClick={() => setOpen(false)} aria-label="Close menu"><X size={20} /></button>
        </div>

        <nav className="nav">
          {NAV.map(({ to, label, icon: Icon, end }) => (
            <NavLink key={to} to={to} end={end}
              className={({ isActive }) => 'nav-item' + (isActive ? ' active' : '')}>
              <Icon size={18} /><span>{label}</span>
            </NavLink>
          ))}
        </nav>

        <div className="sidecard">
          <ShieldCheck size={22} color="var(--low)" />
          <div>
            <div className="sidecard-title">System Status</div>
            <div className="muted" style={{ fontSize: '.78rem' }}>All systems operational</div>
            <div style={{ color: 'var(--low)', fontSize: '.78rem', fontWeight: 600 }}>No active issues</div>
          </div>
        </div>

        <button className="logout" onClick={doLogout}>
          <LogOut size={18} /><span>Logout</span>
        </button>
      </aside>

      <main className="main"><Outlet /></main>
    </div>
  )
}
