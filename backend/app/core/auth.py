"""Authentication and Authorization Dependency Injection Layer for CodeSentinel.

Implements:
1. HttpOnly SameSite cookie session management.
2. get_current_user() - Validates active session and retrieves user.
3. require_active_user() - Enforces account is ACTIVE (rejects DISABLED accounts with HTTP 403).
4. require_admin_user() - Enforces account has ADMIN role.
"""

from typing import Optional
from fastapi import Depends, HTTPException, Request, Response, status

try:
    from backend.analysis.storage.models import (
        UserPublicResponse,
        UserRecord,
        UserRole,
        UserStatus,
    )
    from backend.analysis.storage.store import AnalysisStore
    from backend.app.core.config import settings
except ImportError:
    from analysis.storage.models import (
        UserPublicResponse,
        UserRecord,
        UserRole,
        UserStatus,
    )
    from analysis.storage.store import AnalysisStore
    from app.core.config import settings


def get_store() -> AnalysisStore:
    """Helper to instantiate default AnalysisStore."""
    return AnalysisStore()


def get_cookie_security_flags() -> dict:
    """Resolve secure, samesite, and httponly flags based on environment."""
    env = (getattr(settings, "APP_ENV", "development") or "development").strip().lower()
    configured_secure = getattr(settings, "SESSION_COOKIE_SECURE", None)
    is_secure = (env == "production") if configured_secure is None else bool(configured_secure)
    samesite = getattr(settings, "SESSION_COOKIE_SAMESITE", "lax") or "lax"
    max_age = getattr(settings, "SESSION_EXPIRE_SECONDS", 86400 * 7)

    return {
        "httponly": True,
        "secure": is_secure,
        "samesite": samesite,
        "max_age": max_age,
        "path": "/",
    }


def set_session_cookie(response: Response, session_id: str) -> None:
    """Set hardened HttpOnly session cookie on the response."""
    cookie_name = getattr(settings, "SESSION_COOKIE_NAME", "codesentinel_session")
    flags = get_cookie_security_flags()

    response.set_cookie(
        key=cookie_name,
        value=session_id,
        httponly=flags["httponly"],
        secure=flags["secure"],
        samesite=flags["samesite"],
        max_age=flags["max_age"],
        path=flags["path"],
    )


def clear_session_cookie(response: Response) -> None:
    """Clear session cookie on logout."""
    cookie_name = getattr(settings, "SESSION_COOKIE_NAME", "codesentinel_session")
    flags = get_cookie_security_flags()

    response.delete_cookie(
        key=cookie_name,
        path=flags["path"],
        httponly=flags["httponly"],
        secure=flags["secure"],
        samesite=flags["samesite"],
    )


def extract_session_id(request: Request) -> Optional[str]:
    """Extract session ID from HttpOnly cookie or Authorization Bearer header."""
    cookie_name = getattr(settings, "SESSION_COOKIE_NAME", "codesentinel_session")
    session_id = request.cookies.get(cookie_name)
    if session_id and session_id.strip():
        return session_id.strip()

    # Fallback to Authorization: Bearer <session_id> for headless/testing/cross-origin clients
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        token = auth_header[7:].strip()
        if token:
            return token

    return None


def get_current_user(request: Request) -> UserRecord:
    """FastAPI dependency to retrieve the authenticated user from the active session.

    Raises:
        HTTPException: HTTP 401 if session is missing, invalid, or expired.
    """
    if not getattr(settings, "AUTH_ENFORCED", True):
        return UserRecord(
            user_id="usr_system_bypass",
            google_sub=None,
            email="system@codesentinel.internal",
            full_name="System Test User",
            profile_picture=None,
            role=UserRole.ADMIN.value,
            status=UserStatus.ACTIVE.value,
            created_at="2026-01-01T00:00:00+00:00",
            updated_at="2026-01-01T00:00:00+00:00",
        )

    session_id = extract_session_id(request)
    if not session_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required. Please sign in.",
        )

    store = get_store()
    user = store.get_session_user(session_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session is invalid or has expired.",
        )

    return user


def require_active_user(user: UserRecord = Depends(get_current_user)) -> UserRecord:
    """FastAPI dependency to enforce account is in ACTIVE status.

    Raises:
        HTTPException: HTTP 403 if account is DISABLED.
    """
    if not user.is_active():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is disabled. Contact system administrator.",
        )
    return user


def require_admin_user(user: UserRecord = Depends(require_active_user)) -> UserRecord:
    """FastAPI dependency to enforce account has ADMIN privileges.

    Raises:
        HTTPException: HTTP 403 if account is not an ADMIN.
    """
    if not user.is_admin():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Administrative privileges required.",
        )
    return user


def user_to_public_response(user: UserRecord) -> UserPublicResponse:
    """Convert internal UserRecord to safe public response model (excluding audit secrets)."""
    return UserPublicResponse(
        user_id=user.user_id,
        email=user.email,
        full_name=user.full_name,
        profile_picture=user.profile_picture,
        role=user.role,
        status=user.status,
        created_at=user.created_at,
        last_login=user.last_login,
    )
