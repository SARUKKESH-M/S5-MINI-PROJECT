"""
CodeSentinel — Step 6T-6: Platform Health & Readiness Checks

Provides comprehensive health, readiness, and component diagnostics for CodeSentinel.
Ensures zero secrets, tokens, database credentials, or private paths are exposed.
"""

import os
from pathlib import Path
from typing import Any, Dict

try:
    from backend.app.core.config import settings
except ImportError:
    from app.core.config import settings


def get_platform_health() -> Dict[str, Any]:
    """
    Returns platform health status dictionary.

    Status categories: 'healthy', 'degraded', 'unavailable', 'misconfigured'.
    """
    checks: Dict[str, Dict[str, str]] = {}
    is_misconfigured = False
    is_degraded = False

    # 1. Configuration Validity Check
    try:
        valid_cfg, cfg_errs = settings.validate_security_configuration()
        if valid_cfg:
            checks["configuration"] = {"status": "healthy", "details": "Configuration settings valid"}
        else:
            checks["configuration"] = {"status": "misconfigured", "details": f"Config issues: {len(cfg_errs)}"}
            is_misconfigured = True
    except Exception as e:
        checks["configuration"] = {"status": "misconfigured", "details": "Validation failure"}
        is_misconfigured = True

    # 2. Security Controls Check
    try:
        max_size = getattr(settings, "MAX_REQUEST_SIZE_BYTES", 0)
        sec_hdr = getattr(settings, "ENABLE_SECURITY_HEADERS", True)
        if max_size >= 1024 and sec_hdr:
            checks["security_controls"] = {"status": "healthy", "details": "Payload limits and security headers active"}
        else:
            checks["security_controls"] = {"status": "degraded", "details": "Suboptimal security configuration"}
            is_degraded = True
    except Exception:
        checks["security_controls"] = {"status": "degraded", "details": "Check error"}
        is_degraded = True

    # 3. Vector Store / RAG Storage Check
    try:
        chroma_path = Path(getattr(settings, "CHROMA_DB_PATH", "./data/chroma")).resolve()
        if chroma_path.parent.exists() or chroma_path.exists():
            checks["vector_store"] = {"status": "healthy", "details": "RAG storage directory accessible"}
        else:
            checks["vector_store"] = {"status": "degraded", "details": "RAG storage path missing"}
            is_degraded = True
    except Exception:
        checks["vector_store"] = {"status": "degraded", "details": "Vector store path check error"}
        is_degraded = True

    # 4. LLM Service Configuration Check (Redacted)
    try:
        groq_set = bool(getattr(settings, "GROQ_API_KEY", None))
        ollama_url = getattr(settings, "OLLAMA_BASE_URL", "http://localhost:11434")
        if groq_set or ollama_url:
            checks["llm_service"] = {"status": "healthy", "details": "LLM primary/fallback configured"}
        else:
            checks["llm_service"] = {"status": "degraded", "details": "No LLM credentials set"}
            is_degraded = True
    except Exception:
        checks["llm_service"] = {"status": "degraded", "details": "LLM check error"}
        is_degraded = True

    # 5. Security Gate Module Check
    try:
        from backend.analysis.security_gate import evaluate_security_gate
        checks["security_gate"] = {"status": "healthy", "details": "Security gate module loaded"}
    except Exception:
        checks["security_gate"] = {"status": "degraded", "details": "Security gate import failure"}
        is_degraded = True

    # Compute overall status
    if is_misconfigured:
        overall = "misconfigured"
    elif is_degraded:
        overall = "degraded"
    else:
        overall = "healthy"

    return {
        "status": overall,
        "service": "CodeSentinel",
        "version": "1.0.0",
        "environment": getattr(settings, "APP_ENV", "development"),
        "checks": checks
    }


def get_platform_readiness() -> Dict[str, Any]:
    """
    Returns platform readiness status dictionary.
    Ready if application is fully configured and ready to accept security scan traffic.
    """
    health = get_platform_health()
    overall = health["status"]
    is_ready = overall in ("healthy", "degraded")  # Degraded system can still process static AST requests

    return {
        "ready": is_ready,
        "status": overall,
        "service": "CodeSentinel",
        "timestamp_ready": is_ready
    }
