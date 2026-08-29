from datetime import datetime
from app.models.scan import Scan, ScanType, ScanStatus, RiskLevel
from app.models.indicator import Indicator
from app.models.evidence import Evidence


class ReportService:
    @staticmethod
    def build_scan_report(scan: Scan, indicators: list[Indicator], evidence: list[Evidence]) -> dict:
        return {
            "scan_id": str(scan.id),
            "risk_score": scan.risk_score,
            "risk_level": scan.risk_level.value if scan.risk_level else None,
            "summary": scan.summary,
            "indicators": [
                {
                    "id": str(ind.id),
                    "category": ind.category,
                    "title": ind.title,
                    "description": ind.description,
                    "severity": ind.severity,
                    "confidence": ind.confidence,
                    "detected_text": ind.detected_text,
                }
                for ind in indicators
            ],
            "evidence": [
                {
                    "id": str(ev.id),
                    "evidence_type": ev.evidence_type,
                    "description": ev.description,
                    "confidence": ev.confidence,
                }
                for ev in evidence
            ],
            "recommendations": [
                "Do not send money or credentials.",
                "Verify the sender through an independently obtained official contact method.",
                "Treat this message as suspicious until proven otherwise.",
            ],
        }
