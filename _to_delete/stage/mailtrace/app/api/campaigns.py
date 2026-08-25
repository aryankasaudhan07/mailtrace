"""Campaign graph endpoint. Track E."""

from __future__ import annotations

import json
from pathlib import Path
from uuid import UUID

from fastapi import APIRouter, HTTPException

from app.config import settings

router = APIRouter(prefix="/api/campaigns", tags=["campaigns"])
FIXTURES = Path(__file__).resolve().parents[2] / "fixtures"


@router.get("/{campaign_id}/graph")
async def campaign_graph(campaign_id: UUID) -> dict:
    if settings().fixture_mode:
        return json.loads((FIXTURES / "campaign_graph.json").read_text(encoding="utf-8"))
    # TODO-E: NetworkX connected components over the indicators table.
    raise HTTPException(501, "M7 not implemented yet (Track E)")
