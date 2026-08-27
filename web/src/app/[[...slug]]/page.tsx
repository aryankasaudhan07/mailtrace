'use client';

// Mounts the existing React Router SPA (all 11 pages reused verbatim) as a
// client-only app. Next serves this catch-all for every non-/api path; React
// Router handles client-side navigation. API calls are same-origin to /api.
import { useEffect, useState } from 'react';
import { BrowserRouter } from 'react-router-dom';
import App from '@/spa/App.jsx';
import { initTheme } from '@/spa/theme.js';

export default function SpaEntry() {
  const [ready, setReady] = useState(false);
  useEffect(() => {
    initTheme();
    setReady(true);
  }, []);
  if (!ready) return null; // avoid SSR/window access; mount after hydration
  return (
    <BrowserRouter>
      <App />
    </BrowserRouter>
  );
}
