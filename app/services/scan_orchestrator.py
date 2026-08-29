import os
import uuid
from datetime import datetime
from sqlalchemy.orm import Session
from app.models.scan import Scan, ScanType, ScanStatus, RiskLevel
from app.models.indicator import Indicator
from app.models.evidence import Evidence
from app.services.risk_engine import RiskEngine
from app.services.ai_service import AIService
from app.services.image_analyzer import ImageAnalyzer
from app.core.config import settings
from app.storage.validation import validate_image_upload


class ScanOrchestrator:
    def __init__(self):
        self.risk_engine = RiskEngine()
        self.ai_service = AIService()
        self.image_analyzer = ImageAnalyzer()

    def create_scan(self, db: Session, user_id, scan_type: ScanType, input_text: str | None = None) -> Scan:
        scan = Scan(user_id=user_id, scan_type=scan_type, status=ScanStatus.PROCESSING, input_text=input_text)
        db.add(scan)
        db.commit()
        db.refresh(scan)
        return scan

    async def process_text(self, db: Session, scan: Scan) -> dict:
        return await self.risk_engine.analyze_text(scan.input_text or "", scan.id, db=db)

    async def process_image(self, db: Session, scan: Scan, image_path: str) -> dict:
        return await self.risk_engine.analyze_image(image_path, scan.id, db=db)

    def apply_result(self, db: Session, scan: Scan, result: dict) -> Scan:
        scan.status = result["status"]
        scan.risk_score = result["risk_score"]
        scan.risk_level = result["risk_level"]
        scan.summary = result["summary"]
        scan.completed_at = datetime.utcnow()
        scan.ml_analysis = result.get("ml_analysis")
        scan.dl_analysis = result.get("dl_analysis")
        for ind in result.get("indicators", []):
            db.add(ind)
        for ev in result.get("evidence", []):
            db.add(ev)
        db.commit()
        db.refresh(scan)
        return scan

    def get_scan(self, db: Session, scan_id: str, user_id):
        from uuid import UUID
        try:
            scan_uuid = UUID(scan_id)
        except ValueError:
            return None
        return db.query(Scan).filter(Scan.id == scan_uuid, Scan.user_id == user_id).first()

    def list_scans(self, db: Session, user_id, page: int = 1, limit: int = 20, scan_type: str | None = None, risk_level: str | None = None):
        query = db.query(Scan).filter(Scan.user_id == user_id)
        if scan_type:
            query = query.filter(Scan.scan_type == ScanType(scan_type))
        if risk_level:
            try:
                query = query.filter(Scan.risk_level == RiskLevel(risk_level))
            except ValueError:
                pass
        total = query.count()
        scans = query.order_by(Scan.created_at.desc()).offset((page - 1) * limit).limit(limit).all()
        return scans, total

    def delete_scan(self, db: Session, scan_id: str, user_id):
        from uuid import UUID
        try:
            scan_uuid = UUID(scan_id)
        except ValueError:
            return False
        scan = db.query(Scan).filter(Scan.id == scan_uuid, Scan.user_id == user_id).first()
        if not scan:
            return False
        db.delete(scan)
        db.commit()
        return True

    def get_dashboard_summary(self, db: Session, user_id) -> dict:
        total_scans = db.query(Scan).filter(Scan.user_id == user_id).count()
        high_risk = db.query(Scan).filter(Scan.user_id == user_id, Scan.risk_level == RiskLevel.HIGH_RISK).count()
        critical = db.query(Scan).filter(Scan.user_id == user_id, Scan.risk_level == RiskLevel.CRITICAL).count()
        safe = db.query(Scan).filter(Scan.user_id == user_id, Scan.risk_level == RiskLevel.SAFE).count()
        avg_score = db.query(Scan).filter(Scan.user_id == user_id, Scan.risk_score.is_not(None)).with_entities(Scan.risk_score).all()
        avg = sum(r[0] for r in avg_score) / len(avg_score) if avg_score else 0.0
        recent = db.query(Scan).filter(Scan.user_id == user_id).order_by(Scan.created_at.desc()).limit(5).all()
        return {
            "total_scans": total_scans,
            "high_risk_scans": high_risk + critical,
            "safe_scans": safe,
            "average_risk": round(avg, 1),
            "recent_scans": [
                {
                    "id": str(s.id),
                    "scan_type": s.scan_type.value,
                    "status": s.status.value,
                    "risk_score": s.risk_score,
                    "risk_level": s.risk_level.value if s.risk_level else None,
                    "created_at": s.created_at.isoformat() if s.created_at else None,
                }
                for s in recent
            ],
        }
