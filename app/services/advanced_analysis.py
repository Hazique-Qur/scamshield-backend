import uuid
import json
import hashlib
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from sqlalchemy.orm import Session
from app.models.scan import Scan, RiskLevel
from app.models.advanced import (
    ScamDNA,
    ThreatTimeline,
    ThreatCategoryStat,
    SimilarityMatch,
    Report,
    SafetyCoachSession,
    ScreenshotIntelligence,
    ThreatCategory,
)
from app.models.indicator import Indicator
from app.models.evidence import Evidence
from app.services.ai_service import AIService
from app.core.config import settings


class AdvancedAnalysisService:
    def __init__(self):
        self.ai_service = AIService()

    def generate_scam_dna(self, db: Session, scan_id: uuid.UUID, text: str, indicators: List[Indicator]) -> ScamDNA:
        text_lower = text.lower() if text else ""
        urgency_keywords = ["urgent", "immediately", "asap", "now", "today", "limited time", "expires", "hurry", "verify immediately", "account suspended"]
        financial_keywords = ["payment", "pay", "money", "transfer", "bank", "account", "wire", "bitcoin", "crypto", "refund", "processing fee", "claim reward"]
        credential_keywords = ["password", "login", "verify account", "confirm identity", "ssn", "pin", "credentials", "otp", "verification code"]
        impersonation_keywords = ["bank", "government", "irs", "microsoft", "apple", "google", "official", "representative", "paypal", "netflix", "support"]
        manipulation_keywords = ["gift", "reward", "congratulations", "winner", "selected", "lucky", "exclusive"]
        social_keywords = ["friend", "family", "relative", "emergency", "help me", "stranded"]
        tgtb_keywords = ["free", "winner", "prize", "lottery", "million", "inheritance", "investment opportunity", "no risk"]

        def score_keywords(keywords):
            return sum(1 for kw in keywords if kw in text_lower) / len(keywords) * 100

        urgency = min(100, score_keywords(urgency_keywords) + (15 if "!!!" in text or "!!" in text else 0))
        financial_pressure = min(100, score_keywords(financial_keywords) + (10 if any(c.isdigit() for c in text) else 0))
        credential_requests = min(100, score_keywords(credential_keywords) * 1.5)
        impersonation = min(100, score_keywords(impersonation_keywords) * 1.2)
        manipulation = min(100, score_keywords(manipulation_keywords) * 1.3)
        suspicious_language = min(100, (urgency + financial_pressure + credential_requests) / 3)
        social_engineering = min(100, score_keywords(social_keywords) * 1.4)
        too_good_to_be_true = min(100, score_keywords(tgtb_keywords) * 1.5)

        for ind in indicators:
            category = ind.category.lower()
            conf = float(ind.confidence or 0.5)
            boost = int(conf * 40)
            if "urgency" in category:
                urgency = min(100, urgency + boost)
            elif "financial" in category or "payment" in category:
                financial_pressure = min(100, financial_pressure + boost)
            elif "credential" in category or "login" in category or "otp" in category:
                credential_requests = min(100, credential_requests + boost)
            elif "impersonation" in category:
                impersonation = min(100, impersonation + boost)
            elif "social" in category:
                social_engineering = min(100, social_engineering + boost)
            elif "reward" in category or "prize" in category or "winner" in category:
                too_good_to_be_true = min(100, too_good_to_be_true + boost)
            elif "suspicious" in category or "url" in category:
                suspicious_language = min(100, suspicious_language + boost)

        if urgency == 0 and financial_pressure == 0 and credential_requests == 0 and impersonation == 0 and manipulation == 0 and social_engineering == 0 and too_good_to_be_true == 0:
            if indicators:
                urgency = 20
                financial_pressure = 20
                credential_requests = 20
                suspicious_language = 20

        overall_risk = (urgency + financial_pressure + credential_requests + impersonation + manipulation + suspicious_language + social_engineering + too_good_to_be_true) / 8

        dna = ScamDNA(
            scan_id=scan_id,
            urgency=round(urgency, 1),
            financial_pressure=round(financial_pressure, 1),
            credential_requests=round(credential_requests, 1),
            impersonation=round(impersonation, 1),
            manipulation=round(manipulation, 1),
            suspicious_language=round(suspicious_language, 1),
            social_engineering=round(social_engineering, 1),
            too_good_to_be_true=round(too_good_to_be_true, 1),
            overall_risk=round(overall_risk, 1),
        )
        db.add(dna)
        db.commit()
        db.refresh(dna)
        return dna

    def generate_threat_timeline(self, db: Session, scan_id: uuid.UUID, risk_level: RiskLevel, indicators: List[Indicator]) -> ThreatTimeline:
        categories = [ind.category.lower() for ind in indicators]
        has_urgency = any("urgency" in c or "immediate" in c for c in categories)
        has_trust = any("impersonation" in c or "official" in c or "bank" in c or "government" in c for c in categories)
        has_financial = any("financial" in c or "payment" in c for c in categories)
        has_credential = any("credential" in c or "login" in c or "otp" in c for c in categories)

        stages = [
            {"name": "Message Received", "risk": 10, "description": "Initial contact established via image or message.", "order": 0},
        ]
        if has_trust:
            stages.append({"name": "Trust Building", "risk": 25, "description": "Attacker uses impersonation to establish credibility.", "order": 1})
        if has_urgency:
            stages.append({"name": "Urgency Creation", "risk": 45, "description": "Pressure tactics introduced to force quick action.", "order": 2})
        if has_credential:
            stages.append({"name": "Credential Request", "risk": 65, "description": "Request for sensitive information or login details.", "order": 3})
        if has_financial:
            stages.append({"name": "Financial Extraction", "risk": 85, "description": "Final stage: request for payment or transfer.", "order": 4})
        if risk_level in [RiskLevel.HIGH_RISK, RiskLevel.CRITICAL]:
            stages.append({"name": "Data Exfiltration", "risk": 95, "description": "Attacker has obtained or is attempting to obtain sensitive data.", "order": 5})

        overall_risk = sum(s["risk"] for s in stages) / len(stages) if stages else 0

        timeline = ThreatTimeline(
            scan_id=scan_id,
            stages=stages,
            current_stage=min(len(stages) - 1, max(0, len(stages) - 2 if risk_level == RiskLevel.SUSPICIOUS else len(stages) - 1)),
            overall_risk=round(overall_risk, 1),
        )
        db.add(timeline)
        db.commit()
        db.refresh(timeline)
        return timeline

    def create_evidence(self, db: Session, scan_id: uuid.UUID, indicator: Indicator, text: str) -> Evidence:
        highlighted = text[:200] if text else ""
        evidence = Evidence(
            scan_id=scan_id,
            indicator_id=indicator.id,
            evidence_type="text_pattern",
            description=indicator.description,
            confidence=indicator.confidence,
            highlighted_text=highlighted,
            source_location="message_body",
        )
        db.add(evidence)
        db.commit()
        db.refresh(evidence)
        return evidence

    def update_category_stats(self, db: Session, user_id: uuid.UUID, category: ThreatCategory, risk_score: float):
        stat = db.query(ThreatCategoryStat).filter(
            ThreatCategoryStat.user_id == user_id,
            ThreatCategoryStat.category == category,
        ).first()

        if not stat:
            stat = ThreatCategoryStat(user_id=user_id, category=category, count=1, total_risk=risk_score)
            db.add(stat)
        else:
            stat.count += 1
            stat.total_risk += risk_score
            stat.last_updated = datetime.utcnow()

        db.commit()
        db.refresh(stat)
        return stat

    def get_category_analytics(self, db: Session, user_id: uuid.UUID) -> List[ThreatCategoryStat]:
        return db.query(ThreatCategoryStat).filter(ThreatCategoryStat.user_id == user_id).all()

    def calculate_similarity(self, db: Session, scan_id: uuid.UUID, text: str) -> List[SimilarityMatch]:
        scan_hash = hashlib.md5(text.encode()).hexdigest()
        similar_scans = db.query(Scan).filter(Scan.id != scan_id).limit(50).all()

        matches = []
        for other in similar_scans:
            if other.input_text:
                other_hash = hashlib.md5(other.input_text.encode()).hexdigest()
                similarity = self._jaccard_similarity(scan_hash, other_hash)
                if similarity > 0.3:
                    match = SimilarityMatch(
                        scan_id=scan_id,
                        similar_scan_id=other.id,
                        similarity_score=round(similarity, 2),
                        match_type="content",
                    )
                    db.add(match)
                    matches.append(match)

        db.commit()
        return matches[:10]

    def _jaccard_similarity(self, hash1: str, hash2: str) -> float:
        if not hash1 or not hash2:
            return 0.0
        set1 = set(hash1[:16])
        set2 = set(hash2[:16])
        intersection = len(set1 & set2)
        union = len(set1 | set2)
        return intersection / union if union > 0 else 0.0

    def create_safety_coach_session(self, db: Session, user_id: uuid.UUID, scan_id: Optional[uuid.UUID] = None) -> SafetyCoachSession:
        session = SafetyCoachSession(
            user_id=user_id,
            scan_id=scan_id,
            messages=[],
        )
        db.add(session)
        db.commit()
        db.refresh(session)
        return session

    def add_coach_message(self, db: Session, session_id: uuid.UUID, role: str, content: str) -> SafetyCoachSession:
        session = db.query(SafetyCoachSession).filter(SafetyCoachSession.id == session_id).first()
        if not session:
            return None

        messages = session.messages or []
        messages.append({
            "role": role,
            "content": content,
            "timestamp": datetime.utcnow().isoformat(),
        })
        session.messages = messages[-20:]
        session.updated_at = datetime.utcnow()
        db.commit()
        db.refresh(session)
        return session

    def generate_report(self, db: Session, scan_id: uuid.UUID, user_id: uuid.UUID) -> Report:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            raise ValueError("Scan not found")

        indicators = db.query(Indicator).filter(Indicator.scan_id == scan_id).all()
        evidence = db.query(Evidence).filter(Evidence.scan_id == scan_id).all()
        dna = db.query(ScamDNA).filter(ScamDNA.scan_id == scan_id).first()
        timeline = db.query(ThreatTimeline).filter(ThreatTimeline.scan_id == scan_id).first()

        content = {
            "scan_summary": {
                "id": str(scan.id),
                "type": scan.scan_type.value,
                "status": scan.status.value,
                "risk_score": scan.risk_score,
                "risk_level": scan.risk_level.value if scan.risk_level else None,
                "created_at": scan.created_at.isoformat() if scan.created_at else None,
                "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
            },
            "scam_dna": {
                "urgency": dna.urgency if dna else 0,
                "financial_pressure": dna.financial_pressure if dna else 0,
                "credential_requests": dna.credential_requests if dna else 0,
                "impersonation": dna.impersonation if dna else 0,
                "manipulation": dna.manipulation if dna else 0,
                "suspicious_language": dna.suspicious_language if dna else 0,
                "social_engineering": dna.social_engineering if dna else 0,
                "too_good_to_be_true": dna.too_good_to_be_true if dna else 0,
                "overall_risk": dna.overall_risk if dna else 0,
            } if dna else None,
            "risk_breakdown": {
                ind.category: {"score": ind.severity, "confidence": ind.confidence}
                for ind in indicators
            },
            "evidence": [
                {
                    "type": ev.evidence_type,
                    "description": ev.description,
                    "confidence": ev.confidence,
                    "highlighted_text": ev.highlighted_text,
                }
                for ev in evidence
            ],
            "timeline": timeline.stages if timeline else [],
            "recommendations": [
                "Do not send money or credentials.",
                "Verify through official channels.",
                "Treat this as suspicious until proven otherwise.",
            ],
            "ai_conclusion": scan.summary or "Analysis completed.",
        }

        report = Report(
            scan_id=scan_id,
            user_id=user_id,
            title=f"ScamShield Report - {scan.scan_type.value} Scan",
            content=content,
            format="json",
        )
        db.add(report)
        db.commit()
        db.refresh(report)
        return report

    def detect_language(self, text: str) -> str:
        urdu_chars = set("ابپتٹثجچحخدڈذرڑزژسشصضطظعغفقکگلمنوےھ")
        roman_urdu_words = ["kya", "hai", "nahi", "haan", "bhai", "aap", "main", "ka", "ki", "ke", "mein", "par", "se"]
        
        text_lower = text.lower()
        urdu_count = sum(1 for c in text if c in urdu_chars)
        roman_count = sum(1 for w in roman_urdu_words if w in text_lower)
        
        if urdu_count > len(text) * 0.3:
            return "ur"
        elif roman_count >= 3:
            return "roman_ur"
        return "en"

    def get_personal_threat_dashboard(self, db: Session, user_id: uuid.UUID) -> Dict[str, Any]:
        total_scans = db.query(Scan).filter(Scan.user_id == user_id).count()
        high_risk = db.query(Scan).filter(Scan.user_id == user_id, Scan.risk_level == RiskLevel.HIGH_RISK).count()
        critical = db.query(Scan).filter(Scan.user_id == user_id, Scan.risk_level == RiskLevel.CRITICAL).count()
        safe = db.query(Scan).filter(Scan.user_id == user_id, Scan.risk_level == RiskLevel.SAFE).count()

        thirty_days_ago = datetime.utcnow() - timedelta(days=30)
        recent_scans = db.query(Scan).filter(Scan.user_id == user_id, Scan.created_at >= thirty_days_ago).count()

        avg_risk = db.query(Scan).filter(Scan.user_id == user_id, Scan.risk_score.is_not(None)).with_entities(Scan.risk_score).all()
        avg = sum(r[0] for r in avg_risk) / len(avg_risk) if avg_risk else 0.0

        weekly_data = []
        for i in range(7):
            day_start = datetime.utcnow() - timedelta(days=i+1)
            day_end = datetime.utcnow() - timedelta(days=i)
            count = db.query(Scan).filter(Scan.user_id == user_id, Scan.created_at >= day_start, Scan.created_at < day_end).count()
            weekly_data.append({"day": i + 1, "count": count})

        return {
            "total_scans": total_scans,
            "high_risk_scans": high_risk + critical,
            "critical_scans": critical,
            "safe_scans": safe,
            "recent_scans_30d": recent_scans,
            "average_risk": round(avg, 1),
            "threat_growth_rate": round((recent_scans / total_scans * 100) if total_scans > 0 else 0, 1),
            "weekly_analysis": weekly_data,
        }
