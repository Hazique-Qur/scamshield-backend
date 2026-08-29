from sqlalchemy import Column, String, Text, Float, DateTime, ForeignKey, func
from sqlalchemy.dialects.postgresql import UUID
import uuid
from app.database.connection import Base


class Evidence(Base):
    __tablename__ = "evidence"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.id"), nullable=False)
    indicator_id = Column(UUID(as_uuid=True), ForeignKey("indicators.id"), nullable=True)
    evidence_type = Column(String, nullable=False)
    description = Column(Text, nullable=False)
    confidence = Column(Float, nullable=False)
    highlighted_text = Column(Text, nullable=True)
    source_location = Column(String, nullable=True)
    location_data = Column(String, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
