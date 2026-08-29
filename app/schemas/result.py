from pydantic import BaseModel
from typing import Optional
from app.models.scan import RiskLevel
from app.models.indicator import Indicator
from app.models.evidence import Evidence


class IndicatorOut(BaseModel):
    id: str
    category: str
    title: str
    description: str
    severity: int
    confidence: float
    detected_text: Optional[str]

    class Config:
        from_attributes = True


class EvidenceOut(BaseModel):
    id: str
    evidence_type: str
    description: str
    confidence: float

    class Config:
        from_attributes = True


class ScanResult(BaseModel):
    scan_id: str
    risk_score: Optional[float]
    risk_level: Optional[RiskLevel]
    summary: Optional[str]
    indicators: list[IndicatorOut] = []
    evidence: list[EvidenceOut] = []
    recommendations: list[str] = []
