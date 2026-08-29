import os
import uuid
from pathlib import Path
from fastapi import UploadFile
from app.core.config import settings


class FileStorage:
    def __init__(self):
        self.base_dir = Path(settings.storage_dir)
        self.base_dir.mkdir(parents=True, exist_ok=True)

    async def save(self, upload: UploadFile, subdir: str = "uploads") -> str:
        dest_dir = self.base_dir / subdir
        dest_dir.mkdir(parents=True, exist_ok=True)
        ext = Path(upload.filename or "file").suffix or ".bin"
        filename = f"{uuid.uuid4().hex}{ext}"
        dest_path = dest_dir / filename
        content = await upload.read()
        with open(dest_path, "wb") as f:
            f.write(content)
        return str(dest_path)

    async def save_from_bytes(self, content: bytes, filename: str, subdir: str = "uploads") -> str:
        dest_dir = self.base_dir / subdir
        dest_dir.mkdir(parents=True, exist_ok=True)
        dest_path = dest_dir / filename
        with open(dest_path, "wb") as f:
            f.write(content)
        return str(dest_path)
