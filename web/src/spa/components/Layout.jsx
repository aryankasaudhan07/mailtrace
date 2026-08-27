import { NavLink, Outlet, useNavigate } from 'react-router-dom'
import {
  LayoutGrid, MailSearch, History, FileText, ShieldAlert,
  MapPin, Settings, HelpCircle, LogOut, ShieldCheck, Mail,
} from 'lucide-react'
import { useAuth } from '../auth.jsx'
import './layout.css'

const NAV = [
  { to: '/', label: 'Dashboard', icon: LayoutGrid, end: true },
  { to: '/analyze', label: 'Analyze Email', icon: MailSearch },
  { to: '/history', label: 'History', icon: History },
  { to: '/reports', label: 'Reports', icon: FileText },
  { to: '/threat-intel', label: 'Threat Intelligence', icon: ShieldAlert },
  { to: '/geolocation', label: 'Geolocation', icon: MapPin },
  { to: '/settings', label: 'Settings', icon: Settings },
  { to: '/help', label: 'Help & Support', icon: HelpCircle },
]

export default function Layout() {
  const nav = useNavigate()
  const { logout } = useAuth()
  const doLogout = () => { logout(); nav('/login') }
  return (
    <div className="shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-badge"><Mail size={20} /></div>
          <div className="brand-text">Email Threat<br />Intelligence</div>
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
