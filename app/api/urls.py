from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import Optional
from app.database.connection import get_db
from app.models.user import User
from app.models.scan import Scan, ScanType, ScanStatus
from app.services.scan_service import ScanService
from app.services.text_analyzer import TextAnalyzer
from app.services.report_service import ReportService
from app.schemas.result import ScanResult
from app.core.dependencies import get_current_user
from datetime import datetime

router = APIRouter()
scan_service = ScanService()
text_analyzer = TextAnalyzer()


class URLCreate(BaseModel):
    url: str


@router.post("/url", response_model=ScanResult)
async def create_url_scan(payload: URLCreate, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    scan = scan_service.create_scan(db, current_user.id, ScanType.URL, input_text=payload.url)
    db.refresh(scan)
    analysis = text_analyzer.analyze(payload.url)
    risk_score = min(100.0, max(0.0, analysis["risk_score"] + 5.0))
    risk_level = scan_service._score_to_level(risk_score)
    indicators = []
    evidence = []
    for signal in analysis["signals"]:
        severity = int(signal["score"] * 100)
        confidence = min(0.99, max(0.5, signal["score"] + 0.1))
        detected_text = ", ".join(signal["matched_terms"][:5])
        from app.models.indicator import Indicator
        from app.models.evidence import Evidence
        ind = Indicator(
            scan_id=scan.id,
            category=signal["category"].replace("_", " ").title(),
            title=f"{signal['category'].replace('_', ' ').title()} detected",
            description=f"URL patterns associated with {signal['category'].replace('_', ' ')} were identified.",
            severity=severity,
            confidence=confidence,
            detected_text=detected_text,
        )
        indicators.append(ind)
        evidence.append(Evidence(
            scan_id=scan.id,
            indicator_id=ind.id,
            evidence_type="url_pattern",
            description=f"Matched terms: {detected_text}",
            confidence=confidence,
        ))
    scan.status = ScanStatus.COMPLETED
    scan.risk_score = risk_score
    scan.risk_level = risk_level
    scan.summary = f"URL analysis completed. Risk score: {risk_score:.1f}/100."
    scan.completed_at = datetime.utcnow()
    for ind in indicators:
        db.add(ind)
    for ev in evidence:
        db.add(ev)
    db.commit()
    db.refresh(scan)
    return ReportService.build_scan_report(scan, indicators, evidence)


@router.get("/intel/{domain}")
def get_threat_intel(domain: str, current_user: User = Depends(get_current_user)):
    return {
        "domain": domain,
        "risk_signals": ["Suspicious TLD", "Recently registered"],
        "sources": ["internal-heuristic"],
    }
