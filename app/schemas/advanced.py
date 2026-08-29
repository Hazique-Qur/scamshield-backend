from pydantic import BaseModel, Field
from datetime import datetime
from typing import Optional, List, Dict, Any
import uuid
from app.models.advanced import ThreatCategory


class ScamDNAOut(BaseModel):
    scan_id: uuid.UUID
    urgency: float
    financial_pressure: float
    credential_requests: float
    impersonation: float
    manipulation: float
    suspicious_language: float
    social_engineering: float
    too_good_to_be_true: float
    overall_risk: float
    created_at: datetime

    class Config:
        from_attributes = True


class EvidenceOut(BaseModel):
    id: uuid.UUID
    scan_id: uuid.UUID
    evidence_type: str
    description: str
    confidence: float
    highlighted_text: Optional[str]
    source_location: Optional[str]
    created_at: datetime

    class Config:
        from_attributes = True


class ThreatTimelineStage(BaseModel):
    name: str
    risk: float
    description: str
    order: int


class ThreatTimelineOut(BaseModel):
    scan_id: uuid.UUID
    stages: List[ThreatTimelineStage]
    current_stage: int
    overall_risk: float
    created_at: datetime

    class Config:
        from_attributes = True


class ThreatCategoryStatOut(BaseModel):
    category: ThreatCategory
    count: int
    total_risk: float
    last_updated: datetime

    class Config:
        from_attributes = True


class SimilarityMatchOut(BaseModel):
    scan_id: uuid.UUID
    similar_scan_id: Optional[uuid.UUID]
    similarity_score: float
    match_type: str
    created_at: datetime

    class Config:
        from_attributes = True


class ReportOut(BaseModel):
    id: uuid.UUID
    scan_id: uuid.UUID
    title: str
    format: str
    content: Dict[str, Any]
    created_at: datetime

    class Config:
        from_attributes = True


class SafetyCoachMessage(BaseModel):
    role: str
    content: str
    timestamp: datetime


class SafetyCoachSessionOut(BaseModel):
    id: uuid.UUID
    messages: List[SafetyCoachMessage]
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class SafetyCoachChatRequest(BaseModel):
    message: str
    scan_id: Optional[uuid.UUID] = None


class SafetyCoachChatResponse(BaseModel):
    message: str
    suggestions: List[str] = []
    safety_tips: List[str] = []


class ScreenshotIntelligenceOut(BaseModel):
    scan_id: uuid.UUID
    ocr_text: Optional[str]
    suspicious_areas: List[Dict[str, Any]]
    bounding_boxes: List[Dict[str, Any]]
    visual_overlay_path: Optional[str]
    detected_buttons: List[Dict[str, Any]]
    detected_warnings: List[Dict[str, Any]]
    payment_requests: List[Dict[str, Any]]
    created_at: datetime

    class Config:
        from_attributes = True


class ExplainableRiskOut(BaseModel):
    scan_id: uuid.UUID
    risk_breakdown: Dict[str, float]
    confidence_levels: Dict[str, float]
    contribution_analysis: Dict[str, float]
    evidence_mapping: List[Dict[str, Any]]
    overall_confidence: float
