from fastapi import APIRouter, Depends, HTTPException, status, UploadFile, File, BackgroundTasks, Form, Request
from sqlalchemy.orm import Session
from typing import Optional
from app.database.connection import get_db
from app.models.user import User
from app.models.scan import Scan, ScanType, ScanStatus
from app.models.indicator import Indicator
from app.models.evidence import Evidence
from app.schemas.scan import ScanCreate, ScanOut
from app.schemas.result import ScanResult, IndicatorOut, EvidenceOut
from app.schemas.investigator import ConversationCreate, ConversationOut, MessageCreate, MessageOut, ChatResponse
from app.services.scan_orchestrator import ScanOrchestrator
from app.services.file_storage import FileStorage
from app.services.report_service import ReportService
from app.services.image_analyzer import ImageAnalyzer
from app.storage.validation import validate_image_upload
from app.core.dependencies import get_current_user
from app.core.config import settings

router = APIRouter()
scan_orchestrator = ScanOrchestrator()
file_storage = FileStorage()
image_analyzer = ImageAnalyzer()


@router.post("/text", response_model=ScanOut)
async def create_text_scan(payload: ScanCreate, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    scan = scan_orchestrator.create_scan(db, current_user.id, ScanType.TEXT, payload.input_text)
    result = await scan_orchestrator.process_text(db, scan)
    scan_orchestrator.apply_result(db, scan, result)
    db.refresh(scan)
    return ScanOut.model_validate(scan)


@router.get("/{scan_id}", response_model=ScanResult)
def get_scan(scan_id: str, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    scan = scan_orchestrator.get_scan(db, scan_id, current_user.id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    indicators = db.query(Indicator).filter(Indicator.scan_id == scan.id).all()
    evidence = db.query(Evidence).filter(Evidence.scan_id == scan.id).all()
    return ReportService.build_scan_report(scan, indicators, evidence)


@router.post("/image", response_model=ScanOut)
async def create_image_scan(request: Request, file: UploadFile = File(...), current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    scan = scan_orchestrator.create_scan(db, current_user.id, ScanType.IMAGE)
    db.refresh(scan)
    try:
        content, ext = validate_image_upload(file)
        image_path = await file_storage.save_from_bytes(content, filename=f"{scan.id}{ext}")
        result = await scan_orchestrator.process_image(db, scan, image_path)
        scan_orchestrator.apply_result(db, scan, result)
    except Exception as exc:
        scan.status = ScanStatus.FAILED
        db.commit()
        raise HTTPException(status_code=500, detail=str(exc))
    return ScanOut.model_validate(scan)


@router.post("/url", response_model=ScanOut)
async def create_url_scan(payload: dict, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    url = payload.get("url", "")
    scan = scan_orchestrator.create_scan(db, current_user.id, ScanType.URL, input_text=url)
    db.refresh(scan)
    return ScanOut.model_validate(scan)


@router.get("", response_model=list[ScanOut])
def list_scans(page: int = 1, limit: int = 20, scan_type: Optional[str] = None, risk_level: Optional[str] = None, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    scans, _ = scan_orchestrator.list_scans(db, current_user.id, page=page, limit=limit, scan_type=scan_type, risk_level=risk_level)
    return [ScanOut.model_validate(s) for s in scans]


@router.delete("/{scan_id}")
def delete_scan(scan_id: str, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    ok = scan_orchestrator.delete_scan(db, scan_id, current_user.id)
    if not ok:
        raise HTTPException(status_code=404, detail="Scan not found")
    return {"status": "deleted"}
