"""Centralized Application Configuration for CodeSentinel.

Reads configuration settings from environment variables and an optional local .env file.
Follows secure configuration practices: no secrets are hard-coded or logged.
"""

from typing import Optional
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # Application Baseline Settings
    APP_ENV: str = "development"
    LOG_LEVEL: str = "info"
    BACKEND_PORT: int = 8000

    # LLM Configuration (Groq Primary API & Ollama Fallback)
    GROQ_API_KEY: Optional[str] = None
    GROQ_MODEL: str = "llama3-70b-8192"
    OLLAMA_BASE_URL: str = "http://localhost:11434"
    OLLAMA_MODEL: str = "codellama"

    # GitHub Integration & Webhook Credentials
    GITHUB_TOKEN: Optional[str] = None
    GITHUB_WEBHOOK_SECRET: Optional[str] = None
    GITHUB_API_BASE_URL: str = "https://api.github.com"
    GITHUB_API_VERSION: str = "2022-11-28"

    # Database & Cache Connection Strings
    DATABASE_URL: Optional[str] = None
    REDIS_URL: Optional[str] = None

    # External Notifications
    SLACK_WEBHOOK_URL: Optional[str] = None

    # Vector Store & RAG Storage Path
    CHROMA_DB_PATH: str = "./data/chroma"

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=True
    )


# Application Settings Instance Singleton
settings = Settings()
