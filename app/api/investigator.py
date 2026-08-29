from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
import uuid
from app.database.connection import get_db
from app.models.user import User
from app.models.scan import Scan
from app.models.conversation import Conversation
from app.models.message import Message, MessageRole
from app.schemas.investigator import ConversationCreate, ConversationOut, MessageCreate, MessageOut, ChatResponse
from app.services.ai_service import AIService
from app.core.dependencies import get_current_user
from datetime import datetime

router = APIRouter()
ai_service = AIService()


@router.post("/conversations", response_model=ConversationOut)
def create_conversation(payload: ConversationCreate, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == uuid.UUID(payload.scan_id), Scan.user_id == current_user.id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    conversation = Conversation(user_id=current_user.id, scan_id=scan.id, title=payload.title or f"Investigator: {scan.scan_type.value}")
    db.add(conversation)
    db.commit()
    db.refresh(conversation)
    return ConversationOut.model_validate(conversation)


@router.post("/conversations/{conversation_id}/messages", response_model=ChatResponse)
async def send_message(conversation_id: str, payload: MessageCreate, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    conversation = db.query(Conversation).filter(Conversation.id == uuid.UUID(conversation_id), Conversation.user_id == current_user.id).first()
    if not conversation:
        raise HTTPException(status_code=404, detail="Conversation not found")
    scan = db.query(Scan).filter(Scan.id == conversation.scan_id).first()
    context = ""
    if scan:
        context = f"Scan summary: {scan.summary or 'No summary'}"
    system_prompt = (
        "You are ScamShield AI Investigator. Help the user understand why a message or screenshot is suspicious. "
        "Do not claim scientific certainty. Reference evidence when available. Be concise and practical."
    )
    user_prompt = f"{context}\n\nUser question: {payload.message}"
    response_text = await ai_service.chat(user_prompt, system_prompt=system_prompt)
    message = Message(conversation_id=conversation.id, role=MessageRole.USER, content=payload.message)
    db.add(message)
    assistant_message = Message(conversation_id=conversation.id, role=MessageRole.ASSISTANT, content=response_text)
    db.add(assistant_message)
    conversation.updated_at = datetime.utcnow()
    db.commit()
    return ChatResponse(message=response_text, evidence_references=[])
