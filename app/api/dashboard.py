from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.database.connection import get_db
from app.models.user import User
from app.schemas.auth import UserOut
from app.services.scan_service import ScanService
from app.services.scan_orchestrator import ScanOrchestrator
from app.core.dependencies import get_current_user

router = APIRouter()


@router.get("/summary")
def get_dashboard_summary(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    scan_orchestrator = ScanOrchestrator()
    return scan_orchestrator.get_dashboard_summary(db, current_user.id)
