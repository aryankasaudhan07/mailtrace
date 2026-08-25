"""
The case endpoints. Six of the ten.

In FIXTURE_MODE these serve fixtures/*.json so Track F can build the whole
dashboard before a single analyzer exists. POST /api/cases is real either way:
it parses the upload and runs the scorer in-process, so the end-to-end path
works on day one.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID, uuid4

from fastapi import APIRouter, File, HTTPException, UploadFile
from sqlalchemy import select

from app.analyzers import run_all
from app.analyzers.m2_headers import parse_hops, resolve_trust_boundary
from app.api import events
from app.config import settings
from app.db.models import Case, EvidenceRow, Indicator, Message
from app.db.session import get_session
from app.forensics.reporter import export_report_text, generate_forensic_report
from app.graph.relationships import build_campaign_graph, get_case_relationships
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

    # Resolve the trust boundary so /trace shows real per-hop trust levels.
    hops = parse_hops(email)
    cfg = settings()
    resolve_trust_boundary(hops, cfg.trusted_hosts, cfg.trusted_cidrs)

    _MEM[case_id] = {
        "email": email,
        "hops": hops,
        "evidence": evidence,
        "verdict": verdict,
        "analyzed_at": datetime.now(timezone.utc),
        "filename": file.filename,
    }

    # Store in database (for M7 indicator tracking)
    try:
        session = get_session()
        case = Case(
            id=case_id,
            status="SCORED",
            score=verdict.score,
            band=verdict.band.value,
            confidence=verdict.confidence,
            scorer_version=verdict.scorer_version,
        )
        session.add(case)

        msg = Message(
            case_id=case_id,
            sha256=email.sha256,
            raw_bytes=email.raw_bytes,
            from_addr=email.from_addr,
            from_display_name=email.from_display_name,
            reply_to=email.reply_to,
            subject=email.subject,
            message_id=email.message_id,
        )
        session.add(msg)

        # Store evidence
        for ev in evidence:
            ev_row = EvidenceRow(
                case_id=case_id,
                analyzer=ev.analyzer.value,
                signal=ev.signal,
                status=ev.status.value,
                confidence=ev.confidence,
                detail=ev.detail,
                raw=ev.model_dump(mode="json"),
            )
            session.add(ev_row)

        session.commit()
    except Exception as e:
        # Log but don't fail the request
        import logging
        logging.warning(f"Failed to store case in DB: {e}")
    finally:
        session.close()

    # Push the scored case to every live dashboard over /api/stream.
    events.publish(
        {
            "type": "case_scored",
            "case": {
                "case_id": str(case_id),
                "subject": email.subject,
                "from_addr": email.from_addr,
                "score": verdict.score,
                "band": verdict.band.value,
                "confidence": verdict.confidence,
                "indicators": _case_indicators(case_id),
            },
        }
    )

    return {
        "case_id": str(case_id),
        "filename": file.filename,
        "sha256": email.sha256,
        "verdict": verdict.model_dump(mode="json"),
    }


def _case_indicators(case_id: UUID) -> list[dict]:
    """Indicators M7 stored for this case -- the graph edges for the dashboard."""
    session = get_session()
    try:
        rows = session.execute(
            select(Indicator.kind, Indicator.value).where(Indicator.case_id == case_id)
        ).all()
        return [{"kind": kind, "value": value} for kind, value in rows]
    except Exception:
        return []
    finally:
        session.close()


@router.get("")
async def list_cases(limit: int = 200, band: str | None = None) -> dict:
    if settings().fixture_mode and not _MEM:
        return _fixture("case_list")
    items = [
        {
            "case_id": str(cid),
            "subject": rec["email"].subject or rec.get("filename") or "(no subject)",
            "from_addr": rec["email"].from_addr,
            "score": rec["verdict"].score,
            "band": rec["verdict"].band.value,
            "confidence": rec["verdict"].confidence,
            "analyzed_at": rec.get("analyzed_at").isoformat() if rec.get("analyzed_at") else None,
            "attachments": len(rec["email"].attachments),
            "urls": len(rec["email"].urls),
        }
        for cid, rec in _MEM.items()
        if band is None or rec["verdict"].band.value == band
    ]
    items.sort(key=lambda x: x["analyzed_at"] or "", reverse=True)
    return {"total": len(items), "items": items[:limit]}


@router.get("/{case_id}")
async def get_case(case_id: UUID) -> dict:
    rec = _MEM.get(case_id)
    if rec is None:
        if settings().fixture_mode:
            return _fixture("case_detail")
        raise HTTPException(404, "case not found")
    e = rec["email"]
    stamped = [h.timestamp for h in rec["hops"] if h.timestamp]
    size = len(e.raw_bytes) if getattr(e, "raw_bytes", None) else None
    return {
        "case_id": str(case_id),
        "sha256": e.sha256,
        "subject": e.subject,
        "from_addr": e.from_addr,
        "from_display_name": e.from_display_name,
        "reply_to": e.reply_to,
        "return_path": e.return_path,
        "to_addr": getattr(e, "to_addr", None),
        "message_id": e.message_id,
        "size_bytes": size,
        "body_format": "HTML" if getattr(e, "body_html", None) else "Plain text",
        "received_at": max(stamped).isoformat() if stamped else None,
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


@router.get("/{case_id}/artifacts")
async def get_artifacts(case_id: UUID) -> dict:
    """Extracted IOCs for the forensic view: IPs, domains, URLs, emails, hashes, files."""
    rec = _MEM.get(case_id)
    if rec is None:
        raise HTTPException(404, "case not found")
    email = rec["email"]
    ips, seen = [], set()
    for h in rec["hops"]:
        if h.from_ip and h.from_ip not in seen:
            seen.add(h.from_ip)
            ips.append({"ip": h.from_ip, "hop": h.seq, "trust": h.trust.value})
    from_domain = email.from_addr.split("@")[-1].lower() if email.from_addr else None
    domains = sorted({u.domain for u in email.urls if u.domain} | ({from_domain} if from_domain else set()))
    urls = [
        {"url": u.url, "domain": u.domain, "shortened": u.is_shortened,
         "mismatched": u.mismatched_anchor}
        for u in email.urls
    ]
    emails = sorted({a for a in (email.from_addr, email.reply_to, email.return_path) if a})
    atts = [
        {"filename": a.filename, "content_type": a.content_type,
         "size_bytes": a.size_bytes, "sha256": a.sha256}
        for a in email.attachments
    ]
    raw = ""
    if getattr(email, "raw_bytes", None):
        raw = email.raw_bytes.decode("utf-8", "replace")[:20000]
    return {
        "case_id": str(case_id),
        "ips": ips, "domains": domains, "urls": urls, "emails": emails,
        "hashes": [a["sha256"] for a in atts], "attachments": atts, "raw": raw,
    }


@router.get("/{case_id}/report")
async def get_forensic_report(case_id: UUID) -> dict:
    """Generate comprehensive forensic report for investigation."""
    report = generate_forensic_report(case_id)
    if "error" in report:
        raise HTTPException(404, report["error"])
    return report


@router.get("/{case_id}/report/text")
async def get_forensic_report_text(case_id: UUID) -> dict:
    """Export forensic report as human-readable text."""
    report = generate_forensic_report(case_id)
    if "error" in report:
        raise HTTPException(404, report["error"])
    text = export_report_text(report)
    return {"case_id": str(case_id), "report": text}


@router.get("/{case_id}/relationships")
async def get_case_graph(case_id: UUID) -> dict:
    """Get relationship graph showing linked infrastructure and campaigns."""
    return get_case_relationships(case_id)


@router.get("/graph/live")
async def get_live_graph() -> dict:
    """
    The full case <-> indicator graph, for seeding the live dashboard.

    Nodes are cases (with verdicts) and indicators; an edge means M7 extracted
    that indicator from that case. Two cases sharing an indicator node is the
    visual definition of a campaign.
    """
    session = get_session()
    try:
        case_rows = session.execute(
            select(Case.id, Case.score, Case.band, Case.confidence)
        ).all()
        msg_rows = session.execute(select(Message.case_id, Message.subject, Message.from_addr)).all()
        meta = {cid: {"subject": subj, "from_addr": frm} for cid, subj, frm in msg_rows}
        ind_rows = session.execute(
            select(Indicator.case_id, Indicator.kind, Indicator.value)
        ).all()
    finally:
        session.close()

    cases = [
        {
            "case_id": str(cid),
            "score": score,
            "band": band,
            "confidence": confidence,
            **meta.get(cid, {}),
        }
        for cid, score, band, confidence in case_rows
    ]
    edges = [
        {"case_id": str(cid), "kind": kind, "value": value} for cid, kind, value in ind_rows
    ]
    return {"cases": cases, "edges": edges}


@router.get("/graph/campaigns")
async def get_campaign_clusters() -> dict:
    """Get all detected campaign clusters based on infrastructure reuse."""
    clusters = build_campaign_graph()
    return {
        "cluster_count": len(clusters),
        "clusters": [
            {
                "cluster_id": c.cluster_id,
                "size": c.size,
                "cases": [str(cid) for cid in c.cases],
                "core_indicators": {k: list(v) for k, v in c.core_indicators.items()},
                "cohesion_score": f"{c.score:.2f}",
            }
            for c in clusters.values()
        ],
    }


@router.post("/{case_id}/verdict", status_code=201)
async def override_verdict(case_id: UUID, body: dict) -> dict:
    # TODO-E: write to audit_log with hash chaining. NEVER update the case row
    # in place -- an override is a new record, not an edit.
    raise HTTPException(501, "analyst override not implemented yet (Track E)")
