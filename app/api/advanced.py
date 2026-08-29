from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from datetime import datetime
import uuid
from app.database.connection import get_db
from app.models.user import User
from app.models.scan import Scan
from app.models.indicator import Indicator
from app.models.evidence import Evidence
from app.models.advanced import (
    ScamDNA,
    ThreatTimeline,
    SafetyCoachSession,
    ScreenshotIntelligence,
    Report,
)
from app.schemas.advanced import (
    ScamDNAOut,
    EvidenceOut,
    ThreatTimelineOut,
    ThreatCategoryStatOut,
    SimilarityMatchOut,
    ReportOut,
    SafetyCoachSessionOut,
    SafetyCoachChatRequest,
    SafetyCoachChatResponse,
    ScreenshotIntelligenceOut,
    ExplainableRiskOut,
)
from app.services.advanced_analysis import AdvancedAnalysisService
from app.core.dependencies import get_current_user

router = APIRouter()
advanced_service = AdvancedAnalysisService()


@router.get("/scans/{scan_id}/dna", response_model=ScamDNAOut)
def get_scam_dna(scan_id: str, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == uuid.UUID(scan_id), Scan.user_id == current_user.id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    dna = db.query(ScamDNA).filter(ScamDNA.scan_id == scan.id).first()
    if not dna:
        raise HTTPException(status_code=404, detail="Scam DNA not found")
    return ScamDNAOut.model_validate(dna)


@router.get("/scans/{scan_id}/evidence", response_model=list[EvidenceOut])
def get_evidence(scan_id: str, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == uuid.UUID(scan_id), Scan.user_id == current_user.id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    evidence = db.query(Evidence).filter(Evidence.scan_id == scan.id).all()
    return [EvidenceOut.model_validate(e) for e in evidence]


@router.get("/scans/{scan_id}/timeline", response_model=ThreatTimelineOut)
def get_threat_timeline(scan_id: str, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == uuid.UUID(scan_id), Scan.user_id == current_user.id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    timeline = db.query(ThreatTimeline).filter(ThreatTimeline.scan_id == scan.id).first()
    if not timeline:
        raise HTTPException(status_code=404, detail="Timeline not found")
    return ThreatTimelineOut.model_validate(timeline)


@router.get("/dashboard/advanced", response_model=dict)
def get_advanced_dashboard(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    dashboard = advanced_service.get_personal_threat_dashboard(db, current_user.id)
    category_stats = advanced_service.get_category_analytics(db, current_user.id)
    return {
        "dashboard": dashboard,
        "category_stats": [
            {
                "category": stat.category.value,
                "count": stat.count,
                "total_risk": stat.total_risk,
            }
            for stat in category_stats
        ],
    }


@router.get("/scans/{scan_id}/explainable-risk", response_model=ExplainableRiskOut)
def get_explainable_risk(scan_id: str, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == uuid.UUID(scan_id), Scan.user_id == current_user.id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    indicators = db.query(Indicator).filter(Indicator.scan_id == scan.id).all()
    evidence = db.query(Evidence).filter(Evidence.scan_id == scan.id).all()

    risk_breakdown = {}
    confidence_levels = {}
    contribution_analysis = {}
    evidence_mapping = []

    total_severity = sum(ind.severity for ind in indicators) if indicators else 1

    for ind in indicators:
        risk_breakdown[ind.category] = ind.severity
        confidence_levels[ind.category] = ind.confidence
        contribution = (ind.severity / total_severity) * 100 if total_severity > 0 else 0
        contribution_analysis[ind.category] = round(contribution, 1)

    for ev in evidence:
        evidence_mapping.append({
            "evidence_id": str(ev.id),
            "type": ev.evidence_type,
            "description": ev.description,
            "confidence": ev.confidence,
        })

    overall_confidence = sum(confidence_levels.values()) / len(confidence_levels) if confidence_levels else 0.0

    return ExplainableRiskOut(
        scan_id=scan.id,
        risk_breakdown=risk_breakdown,
        confidence_levels=confidence_levels,
        contribution_analysis=contribution_analysis,
        evidence_mapping=evidence_mapping,
        overall_confidence=round(overall_confidence, 2),
    )


@router.post("/safety-coach/sessions", response_model=SafetyCoachSessionOut)
def create_coach_session(current_user: User = Depends(get_current_user), db: Session = Depends(get_db), scan_id: Optional[str] = None):
    scan_uuid = uuid.UUID(scan_id) if scan_id else None
    session = advanced_service.create_safety_coach_session(db, current_user.id, scan_uuid)
    return SafetyCoachSessionOut.model_validate(session)


@router.post("/safety-coach/sessions/{session_id}/chat", response_model=SafetyCoachChatResponse)
async def chat_with_coach(session_id: str, request: SafetyCoachChatRequest, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    session = db.query(SafetyCoachSession).filter(
        SafetyCoachSession.id == uuid.UUID(session_id),
        SafetyCoachSession.user_id == current_user.id,
    ).first()
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    scan_context = ""
    if session.scan_id:
        scan = db.query(Scan).filter(Scan.id == session.scan_id).first()
        if scan:
            scan = db.query(Scan).filter(Scan.id == session.scan_id).first()
            indicators = db.query(Indicator).filter(Indicator.scan_id == session.scan_id).all()
            scan_context = f"Scan type: {scan.scan_type.value}, Risk: {scan.risk_level}, Score: {scan.risk_score}. "
            scan_context += f"Indicators: {', '.join(i.category for i in indicators)}."

    system_prompt = (
        "You are ScamShield Safety Coach. Your role is to help users understand scan results, "
        "recommend protective actions, explain risks in simple terms, suggest verification methods, "
        "and provide safety education. Be concise, practical, and reassuring."
    )
    user_prompt = f"{scan_context}\n\nUser question: {request.message}"

    response_text = await advanced_service.ai_service.chat(user_prompt, system_prompt=system_prompt)

    advanced_service.add_coach_message(db, session.id, "user", request.message)
    advanced_service.add_coach_message(db, session.id, "assistant", response_text)

    suggestions = [
        "Verify sender through official channels",
        "Never share sensitive credentials",
        "Report suspicious messages",
    ]
    safety_tips = [
        "Enable two-factor authentication",
        "Keep software updated",
        "Be skeptical of urgent requests",
    ]

    return SafetyCoachChatResponse(message=response_text, suggestions=suggestions, safety_tips=safety_tips)


@router.get("/scans/{scan_id}/screenshot-intelligence", response_model=ScreenshotIntelligenceOut)
def get_screenshot_intelligence(scan_id: str, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == uuid.UUID(scan_id), Scan.user_id == current_user.id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    intel = db.query(ScreenshotIntelligence).filter(ScreenshotIntelligence.scan_id == scan.id).first()
    if not intel:
        return ScreenshotIntelligenceOut(
            scan_id=scan.id,
            ocr_text=None,
            suspicious_areas=[],
            bounding_boxes=[],
            visual_overlay_path=None,
            detected_buttons=[],
            detected_warnings=[],
            payment_requests=[],
            created_at=datetime.utcnow(),
        )
    return ScreenshotIntelligenceOut.model_validate(intel)


@router.get("/reports/{scan_id}", response_model=ReportOut)
def get_report(scan_id: str, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == uuid.UUID(scan_id), Scan.user_id == current_user.id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    report = db.query(Report).filter(Report.scan_id == scan.id).first()
    if not report:
        report = advanced_service.generate_report(db, scan.id, current_user.id)
    return ReportOut.model_validate(report)


@router.post("/scans/{scan_id}/similarity", response_model=list[SimilarityMatchOut])
def get_similar_scans(scan_id: str, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == uuid.UUID(scan_id), Scan.user_id == current_user.id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    if not scan.input_text:
        return []

    matches = advanced_service.calculate_similarity(db, scan.id, scan.input_text)
    return [SimilarityMatchOut.model_validate(m) for m in matches]
