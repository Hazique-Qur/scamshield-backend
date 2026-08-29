from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from pydantic import BaseModel
from app.database.connection import get_db
from app.models.user import User
from app.ml.inference import InferenceEngine
from app.core.dependencies import get_current_user

router = APIRouter()
inference_engine = InferenceEngine()


class MLScoreRequest(BaseModel):
    text: str


class MLScoreResponse(BaseModel):
    risk_score: float


@router.post("/score", response_model=MLScoreResponse)
def ml_score(payload: MLScoreRequest, current_user: User = Depends(get_current_user)):
    score = inference_engine.score(payload.text)
    return MLScoreResponse(risk_score=score)
