"""
The case endpoints. Six of the ten.

In FIXTURE_MODE these serve fixtures/*.json so Track F can build the whole
dashboard before a single analyzer exists. POST /api/cases is real either way:
it parses the upload and runs the scorer in-process, so the end-to-end path
works on day one.
"""

from __future__ import annotations

import json
from pathlib import Path
from uuid import UUID, uuid4

from fastapi import APIRouter, File, HTTPException, UploadFile

from app.analyzers import run_all
from app.analyzers.m2_headers import parse_hops
from app.config import settings
from app.ingest.parser import parse_email
from app.scoring.engine import score_case

router = APIRouter(prefix="/api/cases", tags=["cases"])

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures"

# In-memory store so the skeleton runs with no Postgres. Track A replaces this
# with the SQLAlchemy models in phase 2. Deliberately trivial -- do not build on it.
_MEM: dict[UUID, dict] = {}


def _fixture(name: str) -> dict:
    path = FIXTURES / f"{name}.json"
    if not path.exists():
        raise HTTPException(500, f"fixture {name}.json missing")
    return json.loads(path.read_text(encoding="utf-8"))


@router.post("", status_code=201)
async def create_case(file: UploadFile = File(...)) -> dict:
    """
    Upload a raw .eml (or .msg) and get a verdict.

    Returns immediately in the skeleton. Once Celery is wired in (phase 4) this
    returns 202 with just the case_id and the verdict arrives over /api/stream.
    """
    raw = await file.read()
    if not raw:
        raise HTTPException(400, "empty upload")

    case_id = uuid4()
    email = parse_email(raw)
    evidence = await run_all(case_id, email)
    verdict = score_case(case_id, evidence)

    _MEM[case_id] = {
        "email": email,
        "hops": parse_hops(email),
        "evidence": evidence,
        "verdict": verdict,
    }
    return {
        "case_id": str(case_id),
        "filename": file.filename,
        "sha256": email.sha256,
        "verdict": verdict.model_dump(mode="json"),
    }


@router.get("")
async def list_cases(limit: int = 50, band: str | None = None) -> dict:
    if settings().fixture_mode and not _MEM:
        return _fixture("case_list")
    items = [
        {
            "case_id": str(cid),
            "subject": rec["email"].subject,
            "from_addr": rec["email"].from_addr,
            "score": rec["verdict"].score,
            "band": rec["verdict"].band.value,
            "confidence": rec["verdict"].confidence,
        }
        for cid, rec in _MEM.items()
        if band is None or rec["verdict"].band.value == band
    ]
    return {"total": len(items), "items": items[:limit]}


@router.get("/{case_id}")
async def get_case(case_id: UUID) -> dict:
    rec = _MEM.get(case_id)
    if rec is None:
        if settings().fixture_mode:
            return _fixture("case_detail")
        raise HTTPException(404, "case not found")
    e = rec["email"]
    return {
        "case_id": str(case_id),
        "sha256": e.sha256,
        "subject": e.subject,
        "from_addr": e.from_addr,
        "from_display_name": e.from_display_name,
        "reply_to": e.reply_to,
        "message_id": e.message_id,
        "url_count": len(e.urls),
        "attachment_count": len(e.attachments),
        "verdict": rec["verdict"].model_dump(mode="json"),
    }


@router.get("/{case_id}/trace")
async def get_trace(case_id: UUID) -> dict:
    """
    NOTE: until TODO-A lands, every hop reports trust=UNVERIFIED and an empty
    `anomalies` list, because resolve_trust_boundary is what writes those fields
    back onto the Hop objects. The evidence records are already correct -- it is
    only the per-hop annotation the UI reads that is still blank. Fixing this is
    part of phase 3.
    """
    rec = _MEM.get(case_id)
    if rec is None:
        if settings().fixture_mode:
            return _fixture("case_trace")
        raise HTTPException(404, "case not found")
    return {
        "case_id": str(case_id),
        "hops": [h.model_dump(mode="json") for h in rec["hops"]],
        "boundary_seq": next(
            (h.seq for h in rec["hops"] if h.trust.value == "BOUNDARY"), None
        ),
    }


@router.get("/{case_id}/evidence")
async def get_evidence(case_id: UUID) -> dict:
    rec = _MEM.get(case_id)
    if rec is None:
        if settings().fixture_mode:
            return _fixture("case_evidence")
        raise HTTPException(404, "case not found")
    return {
        "case_id": str(case_id),
        "records": [ev.model_dump(mode="json") for ev in rec["evidence"]],
    }


@router.get("/{case_id}/headers")
async def get_headers(case_id: UUID) -> dict:
    rec = _MEM.get(case_id)
    if rec is None:
        raise HTTPException(404, "case not found")
    hops_by_raw = {h.raw: h for h in rec["hops"]}
    return {
        "case_id": str(case_id),
        "headers": [
            {
                "name": k,
                "value": v,
                "hop": hops_by_raw[v].seq if v in hops_by_raw else None,
                "trust": hops_by_raw[v].trust.value if v in hops_by_raw else None,
            }
            for k, v in rec["email"].headers
        ],
    }


@router.get("/{case_id}/report")
async def get_report(case_id: UUID) -> dict:
    # TODO-E: WeasyPrint -> StreamingResponse(media_type="application/pdf")
    raise HTTPException(501, "M10 not implemented yet (Track E)")


@router.post("/{case_id}/verdict", status_code=201)
async def override_verdict(case_id: UUID, body: dict) -> dict:
    # TODO-E: write to audit_log with hash chaining. NEVER update the case row
    # in place -- an override is a new record, not an edit.
    raise HTTPException(501, "analyst override not implemented yet (Track E)")
