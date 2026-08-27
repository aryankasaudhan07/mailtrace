import { Routes, Route, Navigate } from 'react-router-dom'
import { AuthProvider, RequireAuth } from './auth.jsx'
import Layout from './components/Layout.jsx'
import Login from './pages/Login.jsx'
import Dashboard from './pages/Dashboard.jsx'
import Analyze from './pages/Analyze.jsx'
import Result from './pages/Result.jsx'
import Forensic from './pages/Forensic.jsx'
import Geolocation from './pages/Geolocation.jsx'
import HistoryPage from './pages/History.jsx'
import Reports from './pages/Reports.jsx'
import ThreatIntel from './pages/ThreatIntel.jsx'
import Settings from './pages/Settings.jsx'
import Help from './pages/Help.jsx'

export default function App() {
  return (
    <AuthProvider>
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route element={<RequireAuth><Layout /></RequireAuth>}>
          <Route path="/" element={<Dashboard />} />
          <Route path="/analyze" element={<Analyze />} />
          <Route path="/result/:id" element={<Result />} />
          <Route path="/forensic/:id" element={<Forensic />} />
          <Route path="/history" element={<HistoryPage />} />
          <Route path="/reports" element={<Reports />} />
          <Route path="/threat-intel" element={<ThreatIntel />} />
          <Route path="/geolocation" element={<Geolocation />} />
          <Route path="/settings" element={<Settings />} />
          <Route path="/help" element={<Help />} />
        </Route>
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </AuthProvider>
  )
}
