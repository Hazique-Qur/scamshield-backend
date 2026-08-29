import os
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from app.api import auth, scans, investigator, dashboard, users
from app.api import advanced as advanced_routes
from app.database.connection import engine
from app.database.base import Base
from app.models import user, scan, indicator, evidence, conversation, message, user_settings, advanced

Base.metadata.create_all(bind=engine)

limiter = Limiter(key_func=get_remote_address)
app = FastAPI(title="ScamShield API", version="0.1.0")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

cors_origins = os.getenv("CORS_ORIGINS", "http://localhost:3000,http://localhost:3001").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins if cors_origins != ["*"] else ["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router, prefix="/api/v1/auth")
app.include_router(scans.router, prefix="/api/v1/scans")
app.include_router(investigator.router, prefix="/api/v1/investigator")
app.include_router(dashboard.router, prefix="/api/v1/dashboard")
app.include_router(users.router, prefix="/api/v1/users")
app.include_router(advanced_routes.router, prefix="/api/v1/advanced")


@app.get("/health")
def health():
    return {"status": "ok"}
