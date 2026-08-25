# Deploying Mailtrace to Render

Mailtrace ships as **one Docker image** that serves both the API and the React
UI from a single origin — so on Render it's a single free web service with one
public HTTPS URL. No CORS, no separate frontend host.

## What's in the repo for this

| File | Purpose |
|---|---|
| `Dockerfile.render` | Multi-stage build: Node builds the UI → Python serves API **and** UI |
| `render.yaml` | Render blueprint (one web service, health check, secret slots) |
| `app/main.py` | Serves the built UI from `frontend_dist/` when present; falls back to `index.html` for client routes |

## Steps

1. **Push this repo to GitHub** (Render deploys from a git repo).

2. **Create the service from the blueprint**
   - Render dashboard → **New +** → **Blueprint**
   - Pick your repo → Render reads `render.yaml` → **Apply**
   - It builds `Dockerfile.render` and boots the service. First build ~3–5 min.

3. **(Optional) add live-feature secrets** — dashboard → your service → **Environment**:
   - `GEMINI_API_KEY` — enables M4's live NLP content analysis (else heuristic)
   - `ABUSEIPDB_KEY` — enables live IP reputation (else offline heuristic)
   - Without them the app still runs fully; it just uses offline fallbacks.

4. **Open the URL** Render gives you (e.g. `https://mailtrace.onrender.com`):
   - App → `/`
   - API docs (Swagger) → `/docs`
   - Live campaign graph → `/live`
   - Sign in with the seeded demo account **`admin@mailtrace.io` / `demo1234`**

That's it — `git push` after that auto-deploys (`autoDeploy: true`).

## Known limitations on the free tier (and fixes)

- **Cold starts.** Free services sleep after ~15 min idle; the first request then
  takes ~30–60 s to wake. Fine for a demo; upgrade the instance to avoid it.
- **Geolocation without the MaxMind DB.** The 62 MB `GeoLite2-City.mmdb` is not
  committed (licence + repo hygiene), so a fresh deploy has no city/coords and
  M5 degrades gracefully (Tor/VPN/DC still work if those small lists are present).
  To enable full geo in production, attach a **Render Disk** mounted at
  `/srv/intel` and upload the databases (run `scripts/fetch_intel.sh` with your
  MaxMind key), or bake them into a private image.
- **Ephemeral auth store.** New accounts live in `.auth_store.json` on the
  container's disk and reset on redeploy; the demo user re-seeds every boot. For
  persistent accounts, attach a Render Disk (or move the store to Postgres — the
  code already supports `DATABASE_URL` when `FIXTURE_MODE=0`).
- **In-memory analyses.** `FIXTURE_MODE=1` keeps cases in memory (they clear on
  restart). Set `FIXTURE_MODE=0` + a `DATABASE_URL` (Render Postgres) for
  persistence.

## Other hosts

The same `Dockerfile.render` runs unchanged on any container host that injects
`$PORT` (Railway, Fly.io, Cloud Run, a VPS). Only `render.yaml` is
Render-specific.
