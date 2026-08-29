from pydantic import BaseModel, Field
from datetime import datetime
from typing import Optional, Union, Dict, Any
import uuid
from app.models.scan import ScanType, ScanStatus, RiskLevel


class ScanCreate(BaseModel):
    scan_type: ScanType
    input_text: Optional[str] = None
    url: Optional[str] = Field(None, alias="url")


class ScanOut(BaseModel):
    id: Union[str, uuid.UUID]
    scan_type: ScanType
    status: ScanStatus
    input_text: Optional[str]
    file_url: Optional[str]
    risk_score: Optional[float]
    risk_level: Optional[RiskLevel]
    summary: Optional[str]
    created_at: datetime
    completed_at: Optional[datetime]
    ml_analysis: Optional[Dict[str, Any]] = None
    dl_analysis: Optional[Dict[str, Any]] = None

    class Config:
        from_attributes = True
