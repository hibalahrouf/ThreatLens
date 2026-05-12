"""
MASVS Audit Copilot — Core Configuration
Pydantic Settings loaded from environment variables / .env file.
"""

from pydantic_settings import BaseSettings
from typing import Optional


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    # ─── App ───
    APP_NAME: str = "MASVS Audit Copilot"
    DEBUG: bool = False
    API_HOST: str = "0.0.0.0"
    API_PORT: int = 8000

    # ─── Database ───
    DATABASE_URL: str = "postgresql://masvs_user:masvs_secret_2024@localhost:5432/masvs_copilot"

    # ─── Redis ───
    REDIS_URL: str = "redis://localhost:6379/0"

    # ─── MobSF ───
    MOBSF_URL: str = "http://localhost:8080"
    MOBSF_API_KEY: str = ""

    # ─── MinIO ───
    MINIO_ENDPOINT: str = "localhost:9000"
    MINIO_ACCESS_KEY: str = "minioadmin"
    MINIO_SECRET_KEY: str = "minioadmin"
    MINIO_BUCKET: str = "masvs-uploads"
    MINIO_USE_SSL: bool = False

    # ─── JWT ───
    JWT_SECRET: str = "change-me-to-a-strong-random-secret-key"
    JWT_ALGORITHM: str = "HS256"
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    JWT_REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # ─── LLM ───
    LLM_PROVIDER: str = "ollama"  # openai | ollama
    OPENAI_API_KEY: Optional[str] = None
    OLLAMA_URL: str = "http://host.docker.internal:11434"

    SLACK_WEBHOOK_URL: Optional[str] = None
    TEAMS_WEBHOOK_URL: Optional[str] = None
    JIRA_BASE_URL: Optional[str] = None
    JIRA_PROJECT_KEY: Optional[str] = None
    JIRA_USER_EMAIL: Optional[str] = None
    JIRA_API_TOKEN: Optional[str] = None

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = True
        extra = "ignore"


settings = Settings()
