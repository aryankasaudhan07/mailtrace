"""
Mailtrace API entry point.

Run locally without Docker:
    FIXTURE_MODE=1 uvicorn app.main:app --reload
Then open http://localhost:8000/docs
"""

from __future__ import annotations

import logging

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

import app.analyzers  # noqa: F401  -- import registers every analyzer
from app.api import campaigns, cases, stream
from app.config import settings
from app.scoring.engine import load_rules

logging.basicConfig(level=settings().log_level)

app = FastAPI(
    title="Mailtrace",
    description="Email threat detection, geolocation and forensic intelligence.",
    version="0.1.0",
)

# Vite dev server. Tighten before anything leaves localhost.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(cases.router)
app.include_router(campaigns.router)
app.include_router(stream.router)


@app.get("/api/health", tags=["meta"])
async def health() -> dict:
    from app.analyzers.base import registry

    rules = load_rules()
    return {
        "status": "ok",
        "fixture_mode": settings().fixture_mode,
        "scorer_version": rules.version,
        "signals_defined": len(rules.signals),
        "analyzers_registered": sorted(a.value for a in registry()),
    }
