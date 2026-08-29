from sqlalchemy import Column, String, Text, Float, Enum, DateTime, ForeignKey, func, JSON
from sqlalchemy.dialects.postgresql import UUID
import uuid
import enum
from app.database.connection import Base


class ScanType(str, enum.Enum):
    TEXT = "TEXT"
    IMAGE = "IMAGE"
    URL = "URL"
    EMAIL = "EMAIL"


class ScanStatus(str, enum.Enum):
    PENDING = "PENDING"
    PROCESSING = "PROCESSING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class RiskLevel(str, enum.Enum):
    SAFE = "SAFE"
    SUSPICIOUS = "SUSPICIOUS"
    HIGH_RISK = "HIGH_RISK"
    CRITICAL = "CRITICAL"


class Scan(Base):
    __tablename__ = "scans"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    scan_type = Column(Enum(ScanType), nullable=False)
    status = Column(Enum(ScanStatus), nullable=False, default=ScanStatus.PENDING)
    input_text = Column(Text, nullable=True)
    file_url = Column(String, nullable=True)
    risk_score = Column(Float, nullable=True)
    risk_level = Column(Enum(RiskLevel), nullable=True)
    summary = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    completed_at = Column(DateTime(timezone=True), nullable=True)
    ml_analysis = Column(JSON, nullable=True)
    dl_analysis = Column(JSON, nullable=True)
