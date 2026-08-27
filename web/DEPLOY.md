# Deploying Mailtrace (Next.js) to Vercel

The whole app — UI **and** backend — is this one Next.js project in `web/`.
API logic lives in Route Handlers under `src/app/api/*` (Node.js runtime); the
React dashboard is mounted as a client SPA under the catch-all route.

## 1. Import the repo into Vercel
- Vercel → **Add New → Project** → import this GitHub repo.
- **Root Directory: `web`** (important — the Next app is in the subfolder).
- Framework preset: **Next.js** (auto-detected). Build/output settings: defaults.

## 2. Add a Vercel KV store (required for persistence)
Serverless functions are stateless, so cases and M7 correlation need external
state:
- Vercel → **Storage → Create → KV** → connect it to this project.
- This auto-injects `KV_REST_API_URL` / `KV_REST_API_TOKEN`. No code changes.
- Without KV the app still runs, but each request is a fresh in-memory store
  (cases won't persist and campaigns won't correlate across requests).

## 3. Environment variables (Project → Settings → Environment Variables)
| Key | Needed for | Notes |
|---|---|---|
| `AUTH_SECRET` | sessions | **Set a long random value.** |
| `GEMINI_API_KEY` | M4 AI | Optional; heuristic fallback otherwise. |
| `BREVO_API_KEY` + `MAIL_FROM` | OTP email | Optional; demo-code fallback otherwise. Use Brevo (HTTP API) — SMTP is blocked on serverless. |
| `TRUSTED_MX_HOSTS` / `TRUSTED_MX_CIDRS` | M2 trust boundary | Set to your real receiving MX. |

## 4. Network intel (M5 / geolocation)
The 65 MB GeoLite2-City mmdb is too large to bundle in a serverless function, so
it is **not** deployed by default:
- `/api/geo` automatically falls back to the free **ipwho.is** online lookup
  (country-level) — no config needed.
- The **M5** analyzer lane reports `UNAVAILABLE` without local intel (one lane
  down → slightly lower confidence; everything else still works).
- To enable offline M5, add the intel files to the function bundle (e.g. via a
  build step that fetches the smaller GeoLite2-Country db + Tor/datacenter lists)
  and point `INTEL_DIR` at them.

## 5. Deploy
Push to the connected branch → Vercel builds and deploys. First load boots the
seeded demo admin (`admin@mailtrace.io` / `demo1234`).

## Local development
```bash
cd web
npm install
npm run dev        # http://localhost:3000  (UI + /api same-origin)
npm test           # vitest — parity suite for the analyzers/scorer
```
`INTEL_DIR` defaults to `../intel` locally, so a checkout with the mmdb present
gets full offline M5 in dev.
