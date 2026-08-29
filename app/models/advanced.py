from sqlalchemy import Column, String, Text, Float, Enum, DateTime, ForeignKey, Integer, Boolean, func, JSON
from sqlalchemy.dialects.postgresql import UUID
import uuid
import enum
from app.database.connection import Base


class ThreatCategory(str, enum.Enum):
    PHISHING = "PHISHING"
    BANKING_SCAM = "BANKING_SCAM"
    JOB_SCAM = "JOB_SCAM"
    PRIZE_SCAM = "PRIZE_SCAM"
    CRYPTO_SCAM = "CRYPTO_SCAM"
    SOCIAL_ENGINEERING = "SOCIAL_ENGINEERING"
    IMPERSONATION = "IMPERSONATION"
    URGENCY_SCAM = "URGENCY_SCAM"
    ROMANCE_SCAM = "ROMANCE_SCAM"
    OTHER = "OTHER"


class ScamDNA(Base):
    __tablename__ = "scam_dna"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.id"), nullable=False, unique=True)
    urgency = Column(Float, nullable=False, default=0.0)
    financial_pressure = Column(Float, nullable=False, default=0.0)
    credential_requests = Column(Float, nullable=False, default=0.0)
    impersonation = Column(Float, nullable=False, default=0.0)
    manipulation = Column(Float, nullable=False, default=0.0)
    suspicious_language = Column(Float, nullable=False, default=0.0)
    social_engineering = Column(Float, nullable=False, default=0.0)
    too_good_to_be_true = Column(Float, nullable=False, default=0.0)
    overall_risk = Column(Float, nullable=False, default=0.0)
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class ThreatTimeline(Base):
    __tablename__ = "threat_timelines"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.id"), nullable=False, unique=True)
    stages = Column(JSON, nullable=False, default=[])
    current_stage = Column(Integer, nullable=False, default=0)
    overall_risk = Column(Float, nullable=False, default=0.0)
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class ThreatCategoryStat(Base):
    __tablename__ = "threat_category_stats"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    category = Column(Enum(ThreatCategory), nullable=False)
    count = Column(Integer, nullable=False, default=0)
    total_risk = Column(Float, nullable=False, default=0.0)
    last_updated = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class SimilarityMatch(Base):
    __tablename__ = "similarity_matches"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.id"), nullable=False)
    similar_scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.id"), nullable=True)
    similarity_score = Column(Float, nullable=False)
    match_type = Column(String, nullable=False, default="content")
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class Report(Base):
    __tablename__ = "reports"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.id"), nullable=False, unique=True)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    title = Column(String, nullable=False)
    content = Column(JSON, nullable=False)
    format = Column(String, nullable=False, default="json")
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class SafetyCoachSession(Base):
    __tablename__ = "safety_coach_sessions"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.id"), nullable=True)
    messages = Column(JSON, nullable=False, default=[])
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class ScreenshotIntelligence(Base):
    __tablename__ = "screenshot_intelligence"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.id"), nullable=False, unique=True)
    ocr_text = Column(Text, nullable=True)
    suspicious_areas = Column(JSON, nullable=True, default=[])
    bounding_boxes = Column(JSON, nullable=True, default=[])
    visual_overlay_path = Column(String, nullable=True)
    detected_buttons = Column(JSON, nullable=True, default=[])
    detected_warnings = Column(JSON, nullable=True, default=[])
    payment_requests = Column(JSON, nullable=True, default=[])
    created_at = Column(DateTime(timezone=True), server_default=func.now())
