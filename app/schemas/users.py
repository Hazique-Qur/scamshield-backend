from pydantic import BaseModel
from typing import Optional
from datetime import datetime


class UserSettingsOut(BaseModel):
    theme: str
    notifications: bool

    class Config:
        from_attributes = True


class UserSettingsUpdate(BaseModel):
    theme: Optional[str] = None
    notifications: Optional[bool] = None
