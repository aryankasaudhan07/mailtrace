"""Forensic report generation for investigations and law enforcement."""
from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID

from app.db.models import Case, EvidenceRow, Message
from app.db.session import get_session


def generate_forensic_report(case_id: UUID) -> dict:
    """Generate comprehensive forensic report for a case."""
    session = get_session()
    try:
        case = session.query(Case).filter(Case.id == case_id).first()
        if not case:
            return {"error": "Case not found"}

        message = session.query(Message).filter(Message.case_id == case_id).first()
        evidence_rows = (
            session.query(EvidenceRow).filter(EvidenceRow.case_id == case_id).all()
        )

        # Chain of custody
        chain_of_custody = {
            "case_id": str(case_id),
            "created_at": case.received_at.isoformat() if case.received_at else None,
            "email_sha256": message.sha256 if message else None,
            "investigator": "System",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        # Executive summary
        band_severity = {
            "BENIGN": "Low Risk",
            "SUSPICIOUS": "Medium Risk",
            "HIGH_RISK": "High Risk",
            "CRITICAL": "Critical Risk",
        }

        summary = {
            "verdict": {
                "score": case.score,
                "band": case.band,
                "severity": band_severity.get(case.band, "Unknown"),
                "confidence": f"{case.confidence * 100:.0f}%" if case.confidence else "N/A",
            },
            "email_metadata": {
                "from": message.from_addr if message else None,
                "subject": message.subject if message else None,
                "message_id": message.message_id if message else None,
                "date": message.from_addr if message else None,
            },
        }

        # Evidence breakdown
        evidence_by_analyzer = {}
        for ev in evidence_rows:
            if ev.analyzer not in evidence_by_analyzer:
                evidence_by_analyzer[ev.analyzer] = []
            evidence_by_analyzer[ev.analyzer].append(
                {
                    "signal": ev.signal,
                    "status": ev.status,
                    "confidence": f"{ev.confidence * 100:.0f}%",
                    "detail": ev.detail,
                }
            )

        # Risk factors
        risk_factors = []
        for analyzer_id, signals in evidence_by_analyzer.items():
            triggered = [s for s in signals if s["status"] == "TRIGGERED"]
            if triggered:
                risk_factors.extend(
                    [
                        {
                            "analyzer": f"M{analyzer_id[-1]}",
                            "signal": s["signal"],
                            "confidence": s["confidence"],
                        }
                        for s in triggered[:3]
                    ]
                )

        # Recommendations
        recommendations = []
        if case.score >= 75:
            recommendations.extend([
                "Block sender email address and domain",
                "Alert mail admins to monitor for related messages",
                "Consider forwarding to law enforcement if financial fraud suspected",
            ])
        elif case.score >= 50:
            recommendations.extend([
                "Flag for analyst review",
                "Isolate any attached files for malware analysis",
                "Check if similar emails received from other senders",
            ])
        else:
            recommendations.append("Monitor for escalation patterns")

        return {
            "chain_of_custody": chain_of_custody,
            "summary": summary,
            "evidence": evidence_by_analyzer,
            "risk_factors": risk_factors,
            "recommendations": recommendations,
            "report_generated": datetime.now(timezone.utc).isoformat(),
        }
    finally:
        session.close()


def export_report_text(report: dict) -> str:
    """Export forensic report as human-readable text."""
    lines = [
        "=" * 80,
        "FORENSIC ANALYSIS REPORT",
        "=" * 80,
        "",
        f"Case ID: {report['chain_of_custody']['case_id']}",
        f"Generated: {report['report_generated']}",
        f"Email SHA256: {report['chain_of_custody']['email_sha256']}",
        "",
        "VERDICT",
        "-" * 80,
        f"Score: {report['summary']['verdict']['score']}/100 ({report['summary']['verdict']['severity']})",
        f"Confidence: {report['summary']['verdict']['confidence']}",
        "",
        "SENDER INFORMATION",
        "-" * 80,
        f"From: {report['summary']['email_metadata']['from']}",
        f"Subject: {report['summary']['email_metadata']['subject']}",
        f"Message-ID: {report['summary']['email_metadata']['message_id']}",
        "",
        "RISK FACTORS",
        "-" * 80,
    ]

    for factor in report["risk_factors"][:10]:
        lines.append(f"  • {factor['analyzer']}: {factor['signal']} ({factor['confidence']})")

    lines.extend([
        "",
        "RECOMMENDATIONS",
        "-" * 80,
    ])
    for i, rec in enumerate(report["recommendations"], 1):
        lines.append(f"  {i}. {rec}")

    lines.extend(["", "=" * 80])
    return "\n".join(lines)
