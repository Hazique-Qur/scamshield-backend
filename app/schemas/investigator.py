from pydantic import BaseModel
from typing import Optional, List, Union
from datetime import datetime
import uuid


class ConversationCreate(BaseModel):
    scan_id: str
    title: Optional[str] = None


class ConversationOut(BaseModel):
    id: Union[str, uuid.UUID]
    scan_id: Union[str, uuid.UUID]
    title: str
    created_at: datetime

    class Config:
        from_attributes = True


class MessageOut(BaseModel):
    id: Union[str, uuid.UUID]
    role: str
    content: str
    created_at: datetime

    class Config:
        from_attributes = True


class MessageCreate(BaseModel):
    message: str


class ChatResponse(BaseModel):
    message: str
    evidence_references: List[str] = []
