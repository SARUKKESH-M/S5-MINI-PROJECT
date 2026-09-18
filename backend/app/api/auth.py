"""FastAPI Router for CodeSentinel Authentication APIs.

Provides:
- POST /auth/google - Public exchange of Google ID token for authenticated session.
- GET /auth/me      - Authenticated endpoint returning current active user profile.
- POST /auth/logout - Authenticated endpoint terminating current session and clearing cookie.
"""

from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, Field

try:
    from backend.analysis.storage.models import (
        UserPublicResponse,
        UserRecord,
        UserStatus,
    )
    from backend.analysis.storage.store import AnalysisStore
    from backend.app.core.auth import (
        clear_session_cookie,
        extract_session_id,
        get_store,
        require_active_user,
        set_session_cookie,
        user_to_public_response,
    )
    from backend.app.core.config import settings
    from backend.app.core.google_auth import verify_google_identity
except ImportError:
    from analysis.storage.models import (
        UserPublicResponse,
        UserRecord,
        UserStatus,
    )
    from analysis.storage.store import AnalysisStore
    from app.core.auth import (
        clear_session_cookie,
        extract_session_id,
        get_store,
        require_active_user,
        set_session_cookie,
        user_to_public_response,
    )
    from app.core.config import settings
    from app.core.google_auth import verify_google_identity

router = APIRouter(tags=["Authentication"])


class GoogleAuthRequest(BaseModel):
    """Payload for Google authentication exchange."""
    id_token: Optional[str] = Field(None, description="Google OpenID Connect ID token")
    credential: Optional[str] = Field(None, description="Alternative alias for Google ID token (GIS)")


@router.post("/auth/google")
def google_auth_endpoint(auth_req: GoogleAuthRequest, response: Response):
    """Authenticate via Google OpenID Connect token.

    Verifies Google identity claims, enforces CodeSentinel authorization,
    binds first-time identity to pre-authorized accounts, and establishes
    a hardened HttpOnly session.
    """
    raw_token = auth_req.id_token or auth_req.credential
    if not raw_token or not raw_token.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Google id_token or credential is required.",
        )

    # 1. Verify Google identity token
    google_claims = verify_google_identity(raw_token.strip())

    store = get_store()

    # 2. Look up user by verified google_sub
    user = store.get_user_by_google_sub(google_claims.sub)
    if user:
        if user.email != google_claims.email:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Google identity mismatch with registered email address.",
            )

    # 3. If not found by google_sub, look up by normalized email (Pre-Authorization lifecycle)
    if not user:
        user_by_email = store.get_user_by_email(google_claims.email)
        if user_by_email:
            if user_by_email.google_sub is None:
                # First Google login for pre-authorized user or seeded root admin: bind identity
                try:
                    user = store.bind_google_identity(
                        user_id=user_by_email.user_id,
                        google_sub=google_claims.sub,
                        full_name=google_claims.name,
                        profile_picture=google_claims.picture,
                    )
                except ValueError as bind_err:
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail=str(bind_err),
                    ) from bind_err
            elif user_by_email.google_sub != google_claims.sub:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Account is bound to a different Google identity.",
                )
            else:
                user = user_by_email

    # 4. If no authorized CodeSentinel account exists, deny access
    if not user:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account not authorized. Contact system administrator.",
        )

    # 5. Check if account is DISABLED
    if not user.is_active():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is disabled. Contact system administrator.",
        )

    # 6. Record successful authentication timestamp
    updated_user = store.record_successful_login(user.user_id)
    active_user = updated_user or user

    # 7. Create server-side session
    session_id = store.create_session(
        user_id=active_user.user_id,
        expires_seconds=getattr(settings, "SESSION_EXPIRE_SECONDS", 86400 * 7),
    )

    # 8. Set HttpOnly session cookie
    set_session_cookie(response, session_id)

    # 9. Return public profile and session token (for headless/client token support)
    return {
        "status": "success",
        "user": user_to_public_response(active_user),
        "session_token": session_id,
    }


@router.get("/auth/me")
def get_current_user_profile(user: UserRecord = Depends(require_active_user)):
    """Retrieve current authenticated user profile and roles."""
    return {
        "status": "success",
        "user": user_to_public_response(user),
    }


@router.post("/auth/logout")
def logout_endpoint(request: Request, response: Response):
    """Terminate current user session, revoke server-side token, and clear cookies."""
    session_id = extract_session_id(request)
    if session_id:
        store = get_store()
        store.revoke_session(session_id)

    clear_session_cookie(response)

    return {
        "status": "success",
        "message": "Logged out successfully.",
    }
