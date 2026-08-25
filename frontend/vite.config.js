import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// The FastAPI backend runs on :8000. Proxy /api (and the WS stream) to it so the
// app uses same-origin relative paths and there's no CORS in dev.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      '/api': { target: 'http://localhost:8000', changeOrigin: true, ws: true },
      '/live': { target: 'http://localhost:8000', changeOrigin: true },
    },
  },
})
