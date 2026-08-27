import { createContext, useContext, useEffect, useState } from 'react'
import { Navigate, useLocation } from 'react-router-dom'
import { api, getToken, setToken } from './api.js'

const AuthCtx = createContext(null)
export const useAuth = () => useContext(AuthCtx)

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null)
  const [ready, setReady] = useState(false)

  useEffect(() => {
    if (!getToken()) { setReady(true); return }
    api.me().then((r) => setUser(r.user)).catch(() => setToken(null)).finally(() => setReady(true))
  }, [])

  const login = async (email, password) => {
    const r = await api.login(email, password)
    setToken(r.token); setUser(r.user); return r.user
  }
  const registerRequest = (email, password, name) => api.registerRequest(email, password, name)
  const registerVerify = async (email, otp) => {
    const r = await api.registerVerify(email, otp)
    setToken(r.token); setUser(r.user); return r.user
  }
  const resetRequest = (email) => api.resetRequest(email)
  const resetVerify = async (email, otp, password) => {
    const r = await api.resetVerify(email, otp, password)
    setToken(r.token); setUser(r.user); return r.user
  }
  const logout = () => { setToken(null); setUser(null) }

  return <AuthCtx.Provider value={{ user, ready, login, registerRequest, registerVerify, resetRequest, resetVerify, logout }}>{children}</AuthCtx.Provider>
}

export function RequireAuth({ children }) {
  const { user, ready } = useAuth()
  const loc = useLocation()
  if (!ready) return <div style={{ display: 'grid', placeItems: 'center', height: '100vh', color: 'var(--text-3)' }}>Loading…</div>
  if (!user) return <Navigate to="/login" replace state={{ from: loc.pathname }} />
  return children
}
