import re
import hashlib
from pathlib import Path
from fastapi import UploadFile, HTTPException
from app.core.config import settings

ALLOWED_IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".webp", ".bmp"}
MAX_FILE_SIZE = 10 * 1024 * 1024


def validate_image_upload(upload: UploadFile):
    filename = upload.filename or ""
    ext = Path(filename).suffix.lower()
    if ext not in ALLOWED_IMAGE_EXTENSIONS:
        raise HTTPException(status_code=400, detail=f"Unsupported file type: {ext}")
    content = upload.file.read()
    upload.file.seek(0)
    if len(content) > MAX_FILE_SIZE:
        raise HTTPException(status_code=400, detail="File too large")
    return content, ext


def sha256_of_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
