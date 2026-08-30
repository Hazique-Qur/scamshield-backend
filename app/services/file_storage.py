import os
import uuid
from pathlib import Path
from fastapi import UploadFile
from app.core.config import settings


class FileStorage:
    def __init__(self):
        self.base_dir = Path(settings.storage_dir)
        self._ready = False

    def _ensure(self):
        if self._ready:
            return
        try:
            self.base_dir.mkdir(parents=True, exist_ok=True)
            self._ready = True
        except OSError:
            fallback = Path("/tmp") / "scamshield-storage"
            fallback.mkdir(parents=True, exist_ok=True)
            self.base_dir = fallback
            self._ready = True

    async def save(self, upload: UploadFile, subdir: str = "uploads") -> str:
        self._ensure()
        dest_dir = self.base_dir / subdir
        try:
            dest_dir.mkdir(parents=True, exist_ok=True)
        except OSError:
            dest_dir = Path("/tmp") / "scamshield-storage" / subdir
            dest_dir.mkdir(parents=True, exist_ok=True)
        ext = Path(upload.filename or "file").suffix or ".bin"
        filename = f"{uuid.uuid4().hex}{ext}"
        dest_path = dest_dir / filename
        content = await upload.read()
        with open(dest_path, "wb") as f:
            f.write(content)
        return str(dest_path)

    async def save_from_bytes(self, content: bytes, filename: str, subdir: str = "uploads") -> str:
        self._ensure()
        dest_dir = self.base_dir / subdir
        try:
            dest_dir.mkdir(parents=True, exist_ok=True)
        except OSError:
            dest_dir = Path("/tmp") / "scamshield-storage" / subdir
            dest_dir.mkdir(parents=True, exist_ok=True)
        dest_path = dest_dir / filename
        with open(dest_path, "wb") as f:
            f.write(content)
        return str(dest_path)
