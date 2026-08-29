from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from app.database.connection import get_db
from app.models.user import User
from app.models.user_settings import UserSettings
from app.schemas.users import UserSettingsOut, UserSettingsUpdate
from app.core.dependencies import get_current_user

router = APIRouter()


@router.get("/settings", response_model=UserSettingsOut)
def get_settings(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    settings_obj = db.query(UserSettings).filter(UserSettings.user_id == current_user.id).first()
    if not settings_obj:
        settings_obj = UserSettings(user_id=current_user.id)
        db.add(settings_obj)
        db.commit()
        db.refresh(settings_obj)
    return UserSettingsOut.model_validate(settings_obj)


@router.put("/settings", response_model=UserSettingsOut)
def update_settings(payload: UserSettingsUpdate, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    settings_obj = db.query(UserSettings).filter(UserSettings.user_id == current_user.id).first()
    if not settings_obj:
        settings_obj = UserSettings(user_id=current_user.id)
        db.add(settings_obj)
    if payload.theme is not None:
        settings_obj.theme = payload.theme
    if payload.notifications is not None:
        settings_obj.notifications = payload.notifications
    db.commit()
    db.refresh(settings_obj)
    return UserSettingsOut.model_validate(settings_obj)
