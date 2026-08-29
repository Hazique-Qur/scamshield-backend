from sqlalchemy import Column, String, Text, Integer, Float, DateTime, ForeignKey, func
from sqlalchemy.dialects.postgresql import UUID
import uuid
from app.database.connection import Base


class Indicator(Base):
    __tablename__ = "indicators"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.id"), nullable=False)
    category = Column(String, nullable=False)
    title = Column(String, nullable=False)
    description = Column(Text, nullable=False)
    severity = Column(Integer, nullable=False)
    confidence = Column(Float, nullable=False)
    detected_text = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
