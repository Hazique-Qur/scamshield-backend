from pydantic_settings import BaseSettings
import os


class Settings(BaseSettings):
    database_url: str = "sqlite:///./scamshield.db"
    secret_key: str = "change-me-in-production"
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 60
    storage_dir: str = "./storage"
    max_upload_size: int = 10 * 1024 * 1024
    ai_provider: str = "mock"
    gemini_api_key: str = ""
    openai_api_key: str = ""
    ollama_base_url: str = "http://localhost:11434"

    class Config:
        env_file = ".env"


settings = Settings()

if os.getenv("VERCEL"):
    settings.storage_dir = "/tmp/scamshield-storage"
elif settings.storage_dir.startswith("./"):
    settings.storage_dir = os.path.abspath(settings.storage_dir)
