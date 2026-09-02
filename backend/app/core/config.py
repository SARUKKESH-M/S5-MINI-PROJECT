"""Centralized Application Configuration for CodeSentinel.

Reads configuration settings from environment variables and an optional local .env file.
Follows secure configuration practices: no secrets are hard-coded or logged.
"""

from typing import Dict, List, Optional, Tuple
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # Application Baseline Settings
    APP_ENV: str = "development"
    DEBUG: bool = False
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

    # Security Hardening Baseline Settings
    MAX_REQUEST_SIZE_BYTES: int = 10 * 1024 * 1024  # 10 MB maximum request payload size
    ALLOWED_ORIGINS: str = "http://localhost:3000,http://127.0.0.1:3000,http://localhost:8000,http://127.0.0.1:8000"
    ENABLE_SECURITY_HEADERS: bool = True

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=True
    )

    def get_safe_config_summary(self) -> Dict[str, Optional[object]]:
        """
        Returns a dictionary representation of current settings with all sensitive
        credentials, tokens, secrets, and connection strings masked as '[REDACTED]'.
        """
        sensitive_keys = {
            "GROQ_API_KEY",
            "GITHUB_TOKEN",
            "GITHUB_WEBHOOK_SECRET",
            "DATABASE_URL",
            "REDIS_URL",
            "SLACK_WEBHOOK_URL",
        }
        summary: Dict[str, Optional[object]] = {}
        for key in type(self).model_fields.keys():
            val = getattr(self, key)
            if key in sensitive_keys:
                summary[key] = "[REDACTED]" if val else None
            else:
                summary[key] = val
        return summary

    def validate_security_configuration(self) -> Tuple[bool, List[str]]:
        """
        Validates settings for security hazards.

        Returns:
            Tuple of (is_valid: bool, errors: list of error descriptions)
        """
        errors: List[str] = []

        # 1. Enforce debug restriction in production environment
        if self.APP_ENV.lower() == "production" and self.DEBUG:
            errors.append("DEBUG mode must be False when APP_ENV is 'production'")

        # 2. Enforce valid port range
        if not (1 <= self.BACKEND_PORT <= 65535):
            errors.append(f"BACKEND_PORT must be between 1 and 65535, got {self.BACKEND_PORT}")

        # 3. Enforce safe request size limit
        if self.MAX_REQUEST_SIZE_BYTES < 1024:
            errors.append(f"MAX_REQUEST_SIZE_BYTES must be at least 1024 bytes, got {self.MAX_REQUEST_SIZE_BYTES}")

        # 4. Verify no secret fields contain dummy default values
        sensitive_fields = ["GROQ_API_KEY", "GITHUB_TOKEN", "GITHUB_WEBHOOK_SECRET", "DATABASE_URL", "REDIS_URL", "SLACK_WEBHOOK_URL"]
        for field in sensitive_fields:
            val = getattr(self, field, None)
            if val and any(unsafe in str(val).lower() for unsafe in ["password", "secret123", "dummy", "placeholder", "your_token"]):
                errors.append(f"Security field '{field}' contains an unsafe placeholder or default credential")

        return len(errors) == 0, errors


# Application Settings Instance Singleton
settings = Settings()
