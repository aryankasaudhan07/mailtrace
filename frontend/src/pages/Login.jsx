import { useNavigate } from 'react-router-dom'
import { useState } from 'react'
import {
  Mail, Cpu, MapPin, Scale, ShieldCheck, User, Lock, Eye, EyeOff, ArrowRight, Clock, Loader2,
} from 'lucide-react'
import { useAuth } from '../auth.jsx'
import './login.css'

const FEATURES = [
  { icon: Cpu, title: 'AI Threat Detection', text: 'Identify phishing, malware & advanced email threats' },
  { icon: MapPin, title: 'Geolocation Intelligence', text: 'Trace origin and network location of suspicious emails' },
  { icon: Scale, title: 'Forensic Analysis', text: 'Extract IOCs and digital forensic evidence' },
  { icon: ShieldCheck, title: 'Proactive Security', text: 'Stop threats before they reach you' },
]

const COPY = {
  login:    { title: 'Welcome Back',   sub: 'Sign in to your Email Threat Intelligence Platform', cta: 'Sign In' },
  register: { title: 'Create Account', sub: 'Set up your analyst account to get started',          cta: 'Create Account' },
  reset:    { title: 'Reset Password', sub: 'Set a new password for your account',                  cta: 'Reset Password' },
}

export default function Login() {
  const nav = useNavigate()
  const { login, register, resetPassword } = useAuth()
  const [mode, setMode] = useState('login')
  const [show, setShow] = useState(false)
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState(null)
  const [form, setForm] = useState({ email: '', password: '', name: '' })
  const set = (k) => (e) => setForm((f) => ({ ...f, [k]: e.target.value }))
  const go = (m) => { setMode(m); setErr(null) }

  const submit = async (e) => {
    e.preventDefault(); setBusy(true); setErr(null)
    try {
      if (mode === 'login') await login(form.email, form.password)
      else if (mode === 'register') await register(form.email, form.password, form.name)
      else await resetPassword(form.email, form.password)
      nav('/')
    } catch (x) { setErr(String(x.message || x)); setBusy(false) }
  }

  const c = COPY[mode]
  return (
    <div className="login">
      <header className="login-top">
        <div className="brand"><div className="brand-badge"><Mail size={18} /></div><b>Email Threat Intelligence</b></div>
        <div className="login-top-right">
          <span className="online"><i /> System Online</span>
          <span className="dim"><Clock size={13} /> {new Date().toLocaleString()}</span>
        </div>
      </header>

      <div className="login-body">
        <section className="hero">
          <h1><span className="grad">AI-Powered</span> Email Threat Detection, Geolocation &amp; Forensic Intelligence Platform</h1>
          <p className="hero-sub">Analyze. Detect. Investigate.<br />Smarter Email Security for a Safer Tomorrow.</p>
          <div className="orb"><div className="orb-shield"><Mail size={44} /></div><div className="ring r1" /><div className="ring r2" /></div>
          <div className="features">
            {FEATURES.map(({ icon: Icon, title, text }) => (
              <div className="feature" key={title}>
                <div className="feature-ic"><Icon size={20} /></div>
                <div><div className="feature-t">{title}</div><div className="feature-x">{text}</div></div>
              </div>
            ))}
          </div>
        </section>

        <section className="authwrap">
          <form className="authcard" onSubmit={submit}>
            <div className="auth-badge"><Mail size={26} /></div>
            <h2>{c.title}</h2>
            <p className="dim" style={{ textAlign: 'center', marginTop: -4 }}>{c.sub}</p>

            {err && <div className="auth-err">{err}</div>}

            {mode === 'register' && (
              <label className="field"><User size={17} />
                <input placeholder="Full name" value={form.name} onChange={set('name')} autoComplete="name" /></label>
            )}
            <label className="field"><User size={17} />
              <input type="email" placeholder="Email address" value={form.email} onChange={set('email')}
                autoComplete="email" required /></label>
            <label className="field"><Lock size={17} />
              <input type={show ? 'text' : 'password'} placeholder={mode === 'reset' ? 'New password' : 'Password'}
                value={form.password} onChange={set('password')}
                autoComplete={mode === 'login' ? 'current-password' : 'new-password'} required />
              <button type="button" className="eye" onClick={() => setShow((s) => !s)}>{show ? <EyeOff size={17} /> : <Eye size={17} />}</button>
            </label>

            {mode === 'login' && (
              <div className="auth-row">
                <label className="remember"><input type="checkbox" /> Remember me</label>
                <a className="violet-link" onClick={() => go('reset')}>Forgot password?</a>
              </div>
            )}

            <button className="btn" type="submit" disabled={busy} style={{ width: '100%', padding: 13, opacity: busy ? .7 : 1 }}>
              {busy ? <Loader2 size={17} className="spin" /> : <>{c.cta} <ArrowRight size={17} /></>}
            </button>

            <div className="or"><span>or</span></div>

            {mode === 'login' && (
              <p className="dim" style={{ textAlign: 'center' }}>
                Don't have an account? <a className="violet-link" onClick={() => go('register')}>Create Account</a>
              </p>
            )}
            {mode === 'register' && (
              <p className="dim" style={{ textAlign: 'center' }}>
                Already have an account? <a className="violet-link" onClick={() => go('login')}>Sign In</a>
              </p>
            )}
            {mode === 'reset' && (
              <p className="dim" style={{ textAlign: 'center' }}>
                Remembered it? <a className="violet-link" onClick={() => go('login')}>Back to sign in</a>
              </p>
            )}
          </form>
        </section>
      </div>
      <footer className="login-foot"><Mail size={15} color="var(--violet)" /> Securing Emails. Protecting You.</footer>
    </div>
  )
}
