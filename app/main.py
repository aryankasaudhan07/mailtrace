"""
Mailtrace API entry point.

Run locally without Docker:
    FIXTURE_MODE=1 uvicorn app.main:app --reload
Then open http://localhost:8000/docs
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

import app.analyzers  # noqa: F401  -- import registers every analyzer
from app.api import auth, campaigns, cases, insights, stream
from app.config import settings
from app.db.session import init_db
from app.scoring.engine import load_rules

# Initialize database on startup
init_db()

logging.basicConfig(level=settings().log_level)

app = FastAPI(
    title="Mailtrace",
    description="Email threat detection, geolocation and forensic intelligence.",
    version="0.1.0",
)

# CORS. In the single-container deploy the UI is same-origin so this is unused;
# for a split frontend, set ALLOWED_ORIGINS (comma-separated) in the environment.
_origins = os.environ.get("ALLOWED_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173")
app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in _origins.split(",") if o.strip()],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router)
app.include_router(cases.router)
app.include_router(campaigns.router)
app.include_router(insights.router)
app.include_router(stream.router)

_STATIC = Path(__file__).parent / "static"


@app.get("/live", tags=["meta"], include_in_schema=False)
async def live_graph() -> FileResponse:
    """The live campaign-graph dashboard. Stopgap page until the React app lands."""
    return FileResponse(
        _STATIC / "live_graph.html",
        media_type="text/html",
        headers={"Cache-Control": "no-store, must-revalidate"},
    )


@app.get("/api/health", tags=["meta"])
async def health() -> dict:
    from app.analyzers.base import registry

    rules = load_rules()
    cfg = settings()
    return {
        "status": "ok",
        "fixture_mode": cfg.fixture_mode,
        "scorer_version": rules.version,
        "signals_defined": len(rules.signals),
        "analyzers_registered": sorted(a.value for a in registry()),
        # Boolean only -- never the credentials. Lets us confirm OTP email is
        # wired without exposing any secret.
        "smtp_configured": bool(cfg.smtp_user and cfg.smtp_password),
    }


# ---- Serve the built React app (single-container deploy) --------------------
# Only active when frontend_dist/ exists (produced by Dockerfile.render). Local
# dev and docker-compose serve the UI from Vite, so this stays dormant there.
_DIST = Path(__file__).resolve().parents[1] / "frontend_dist"
if _DIST.is_dir():
    app.mount("/assets", StaticFiles(directory=_DIST / "assets"), name="assets")

    @app.get("/{full_path:path}", include_in_schema=False)
    async def spa(full_path: str) -> FileResponse:
        # API/live/docs routes are registered above and take precedence. Anything
        # else serves the matching static file, or index.html for client routes.
        candidate = (_DIST / full_path).resolve()
        if full_path and candidate.is_file() and _DIST in candidate.parents:
            return FileResponse(candidate)
        return FileResponse(_DIST / "index.html")
